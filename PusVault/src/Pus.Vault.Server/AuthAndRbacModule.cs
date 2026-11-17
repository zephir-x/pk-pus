using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using Pus.Vault.Common;

namespace Pus.Vault.Server
{
    /// <summary>
    /// Represents a single user account stored in config/users.json (passwords stored only as PBKDF2 hashes).
    /// </summary>
    public class UserAccountRecord
    {
        [JsonPropertyName("username")]
        public string Username { get; set; } = string.Empty;

        [JsonPropertyName("passwordHashBase64")]
        public string PasswordHashBase64 { get; set; } = string.Empty;

        [JsonPropertyName("saltBase64")]
        public string SaltBase64 { get; set; } = string.Empty;

        [JsonPropertyName("iterations")]
        public int Iterations { get; set; } = 600_000;

        [JsonPropertyName("role")]
        public string Role { get; set; } = "READ_ONLY";
    }

    /// <summary>
    /// Represents an active authenticated session on the server.
    /// </summary>
    public class AuthenticatedSessionInfo
    {
        public string Username { get; init; } = string.Empty;
        public string SessionToken { get; init; } = string.Empty;
        public string HmacSecretBase64 { get; init; } = string.Empty;
        public string Role { get; init; } = string.Empty;
    }

    /// <summary>
    /// Handles user authentication (PBKDF2-HMAC-SHA256), per-account/IP brute-force backoff,
    /// session token issuance, and Role-Based Access Control (RBAC).
    /// </summary>
    public class AuthAndRbacModule
    {
        public const string RoleReadWrite = "READ_WRITE";
        public const string RoleReadOnly = "READ_ONLY";

        private readonly Dictionary<string, UserAccountRecord> _users = new(StringComparer.Ordinal);
        private readonly Dictionary<string, (int FailedCount, DateTime LockoutUntilUtc)> _backoffTracker = new(StringComparer.Ordinal);
        private readonly object _authLock = new();

        /// <summary>
        /// Loads user accounts from config/users.json. Throws if the file is missing or invalid.
        /// </summary>
        public AuthAndRbacModule(string usersFilePath)
        {
            if (!File.Exists(usersFilePath))
            {
                throw new FileNotFoundException(
                    $"User configuration file not found at '{usersFilePath}'. Provision accounts first.",
                    usersFilePath);
            }

            string json = File.ReadAllText(usersFilePath);
            var records = JsonSerializer.Deserialize<List<UserAccountRecord>>(json)
                          ?? throw new InvalidDataException("User configuration file is empty or invalid.");

            foreach (UserAccountRecord record in records)
            {
                if (string.IsNullOrWhiteSpace(record.Username) ||
                    string.IsNullOrWhiteSpace(record.PasswordHashBase64) ||
                    string.IsNullOrWhiteSpace(record.SaltBase64) ||
                    record.Iterations < 600_000 ||
                    (record.Role != RoleReadWrite && record.Role != RoleReadOnly))
                {
                    throw new InvalidDataException($"Invalid account configuration for user '{record.Username}'.");
                }

                _users[record.Username] = record;
            }
        }

        /// <summary>
        /// Helper method to create config/users.json with PBKDF2-HMAC-SHA256 hashes (600,000 iterations)
        /// for initial 'admin' (READ_WRITE) and 'reader' (READ_ONLY) accounts.
        /// </summary>
        public static void ProvisionUsersFile(string usersFilePath, string adminPassword, string readerPassword)
        {
            string? dir = Path.GetDirectoryName(usersFilePath);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var (adminHash, adminSalt, adminIter) = PvspCryptoHelper.HashPasswordPbkdf2(adminPassword, 600_000);
            var (readerHash, readerSalt, readerIter) = PvspCryptoHelper.HashPasswordPbkdf2(readerPassword, 600_000);

            var accounts = new List<UserAccountRecord>
            {
                new()
                {
                    Username = "admin",
                    PasswordHashBase64 = adminHash,
                    SaltBase64 = adminSalt,
                    Iterations = adminIter,
                    Role = RoleReadWrite
                },
                new()
                {
                    Username = "reader",
                    PasswordHashBase64 = readerHash,
                    SaltBase64 = readerSalt,
                    Iterations = readerIter,
                    Role = RoleReadOnly
                }
            };

            string json = JsonSerializer.Serialize(accounts, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(usersFilePath, json);

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                File.SetUnixFileMode(usersFilePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }

        /// <summary>
        /// Verifies login credentials and serverNonceEcho. Applies exponential backoff per username and client IP.
        /// Returns a generic failure status on any mismatch to prevent username enumeration.
        /// </summary>
        public bool TryAuthenticate(
            string username,
            string password,
            string expectedServerNonce,
            string providedServerNonceEcho,
            string clientIp,
            out AuthenticatedSessionInfo? sessionInfo)
        {
            sessionInfo = null;
            DateTime now = DateTime.UtcNow;

            lock (_authLock)
            {
                // Check if either the client IP or the target username is currently under brute-force lockout
                if (IsLockedOut($"ip:{clientIp}", now) || IsLockedOut($"user:{username}", now))
                {
                    return false;
                }
            }

            // Verify one-time serverNonceEcho (case-insensitive HEX comparison)
            bool nonceMatches = !string.IsNullOrEmpty(expectedServerNonce) &&
                                string.Equals(expectedServerNonce, providedServerNonceEcho, StringComparison.OrdinalIgnoreCase);

            bool passwordValid = false;
            string assignedRole = RoleReadOnly;

            if (_users.TryGetValue(username, out UserAccountRecord? userRecord))
            {
                passwordValid = PvspCryptoHelper.VerifyPasswordPbkdf2(
                    password,
                    userRecord.PasswordHashBase64,
                    userRecord.SaltBase64,
                    userRecord.Iterations);
                assignedRole = userRecord.Role;
            }
            else
            {
                // Perform a dummy PBKDF2 computation so non-existent usernames take the same time as real ones
                PvspCryptoHelper.HashPasswordPbkdf2("dummy_timing_mitigation_password", 600_000);
            }

            lock (_authLock)
            {
                if (!nonceMatches || !passwordValid)
                {
                    RegisterFailedAttempt($"ip:{clientIp}", now);
                    RegisterFailedAttempt($"user:{username}", now);
                    return false;
                }

                // Clear failed counters upon successful login
                _backoffTracker.Remove($"ip:{clientIp}");
                _backoffTracker.Remove($"user:{username}");

                sessionInfo = new AuthenticatedSessionInfo
                {
                    Username = username,
                    SessionToken = PvspCryptoHelper.GenerateSessionToken(),
                    HmacSecretBase64 = PvspCryptoHelper.GenerateHmacSecretBase64(),
                    Role = assignedRole
                };

                return true;
            }
        }

        /// <summary>
        /// Checks whether the given role is allowed to execute the requested DATA_REQ action.
        /// READ_WRITE can execute SET, GET, LIST, DELETE.
        /// READ_ONLY can only execute GET and LIST.
        /// </summary>
        public static bool IsActionAuthorized(string role, string action)
        {
            if (role == RoleReadWrite)
            {
                return action is "SET" or "GET" or "LIST" or "DELETE";
            }

            if (role == RoleReadOnly)
            {
                return action is "GET" or "LIST";
            }

            return false;
        }

        private bool IsLockedOut(string key, DateTime now)
        {
            if (_backoffTracker.TryGetValue(key, out var entry) && entry.LockoutUntilUtc > now)
            {
                return true;
            }

            return false;
        }

        private void RegisterFailedAttempt(string key, DateTime now)
        {
            _backoffTracker.TryGetValue(key, out var current);
            int nextCount = current.FailedCount + 1;

            // Apply progressive lockout after 3 failed attempts across connections (2s, 4s, 8s, max 30s)
            DateTime lockoutUntil = DateTime.MinValue;
            if (nextCount >= 3)
            {
                int delaySeconds = Math.Min(30, 1 << Math.Min(5, nextCount - 2));
                lockoutUntil = now.AddSeconds(delaySeconds);
            }

            _backoffTracker[key] = (nextCount, lockoutUntil);
        }
    }
}