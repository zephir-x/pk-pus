using System;
using System.Buffers.Binary;
using System.IO;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Pus.Vault.Common
{
    /// <summary>
    /// Provides cryptographic operations for PVSP v1.0:
    /// Canonical HMAC-SHA256, CSPRNG token generation, PBKDF2 password hashing, and Custom CA X.509 validation.
    /// </summary>
    public static class PvspCryptoHelper
    {
        // Constant ASCII prefix for canonical HMAC input
        private static readonly byte[] HmacContextPrefix = Encoding.ASCII.GetBytes("PVSP-HMAC-v1");

        // OID for Extended Key Usage: TLS Web Server Authentication (serverAuth)
        private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";

        /// <summary>
        /// Generates a 16-byte cryptographically random serverNonce encoded as 32 uppercase HEX characters.
        /// </summary>
        public static string GenerateServerNonceHex()
        {
            byte[] nonceBytes = RandomNumberGenerator.GetBytes(16);
            return Convert.ToHexString(nonceBytes);
        }

        /// <summary>
        /// Generates a cryptographically random sessionToken (32 CSPRNG bytes = 256-bit entropy, 64 lowercase HEX chars).
        /// </summary>
        public static string GenerateSessionToken()
        {
            byte[] tokenBytes = RandomNumberGenerator.GetBytes(32);
            return Convert.ToHexString(tokenBytes).ToLowerInvariant();
        }

        /// <summary>
        /// Generates a 32-byte cryptographically random HMAC session key encoded as Base64.
        /// </summary>
        public static string GenerateHmacSecretBase64()
        {
            byte[] keyBytes = RandomNumberGenerator.GetBytes(32);
            return Convert.ToBase64String(keyBytes);
        }

        /// <summary>
        /// Builds the exact length-prefixed binary buffer for HMAC-SHA256 calculation:
        /// ASCII("PVSP-HMAC-v1") || version(u8) || msgType(u8) || msgId(u32 BE) ||
        /// tokenLen(u32 BE) || UTF8(token) || actionLen(u32 BE) || UTF8(action) ||
        /// keyPresent(u8) || [keyLen(u32 BE) || UTF8(key)] ||
        /// valuePresent(u8) || [valueLen(u32 BE) || UTF8(value)] || timestamp(i64 BE)
        /// </summary>
        public static byte[] BuildCanonicalHmacInput(
            byte version,
            PvspMessageType messageType,
            uint messageId,
            string sessionToken,
            string action,
            string? key,
            string? value,
            long timestamp)
        {
            using var ms = new MemoryStream();
            Span<byte> intBuffer = stackalloc byte[8];

            // 1. ASCII("PVSP-HMAC-v1")
            ms.Write(HmacContextPrefix);

            // 2. version (uint8) and messageType (uint8)
            ms.WriteByte(version);
            ms.WriteByte((byte)messageType);

            // 3. messageId (uint32, Big-Endian)
            BinaryPrimitives.WriteUInt32BigEndian(intBuffer[..4], messageId);
            ms.Write(intBuffer[..4]);

            // 4. sessionTokenLength (uint32, Big-Endian) + UTF-8(sessionToken)
            byte[] tokenBytes = Encoding.UTF8.GetBytes(sessionToken);
            BinaryPrimitives.WriteUInt32BigEndian(intBuffer[..4], (uint)tokenBytes.Length);
            ms.Write(intBuffer[..4]);
            ms.Write(tokenBytes);

            // 5. actionLength (uint32, Big-Endian) + UTF-8(action)
            byte[] actionBytes = Encoding.UTF8.GetBytes(action);
            BinaryPrimitives.WriteUInt32BigEndian(intBuffer[..4], (uint)actionBytes.Length);
            ms.Write(intBuffer[..4]);
            ms.Write(actionBytes);

            // 6. keyPresent (uint8: 0 or 1) + optional keyLength & UTF-8(key)
            if (key != null)
            {
                ms.WriteByte(1);
                byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                BinaryPrimitives.WriteUInt32BigEndian(intBuffer[..4], (uint)keyBytes.Length);
                ms.Write(intBuffer[..4]);
                ms.Write(keyBytes);
            }
            else
            {
                ms.WriteByte(0);
            }

            // 7. valuePresent (uint8: 0 or 1) + optional valueLength & UTF-8(value)
            if (value != null)
            {
                ms.WriteByte(1);
                byte[] valueBytes = Encoding.UTF8.GetBytes(value);
                BinaryPrimitives.WriteUInt32BigEndian(intBuffer[..4], (uint)valueBytes.Length);
                ms.Write(intBuffer[..4]);
                ms.Write(valueBytes);
            }
            else
            {
                ms.WriteByte(0);
            }

            // 8. timestamp (int64, Big-Endian)
            BinaryPrimitives.WriteInt64BigEndian(intBuffer, timestamp);
            ms.Write(intBuffer);

            return ms.ToArray();
        }

        /// <summary>
        /// Computes the 64-character lowercase HEX HMAC-SHA256 signature for a DATA_REQ message.
        /// </summary>
        public static string ComputeDataReqHmacHex(
            string hmacSecretBase64,
            uint messageId,
            DataReqPayload payload,
            byte version = PvspConstants.ProtocolVersion)
        {
            byte[] secretKeyBytes = Convert.FromBase64String(hmacSecretBase64);
            byte[] canonicalInput = BuildCanonicalHmacInput(
                version,
                PvspMessageType.DataReq,
                messageId,
                payload.SessionToken,
                payload.Action,
                payload.Key,
                payload.Value,
                payload.Timestamp);

            byte[] macBytes = HMACSHA256.HashData(secretKeyBytes, canonicalInput);
            return Convert.ToHexString(macBytes).ToLowerInvariant();
        }

        /// <summary>
        /// Verifies the HMAC-SHA256 signature of a DATA_REQ message in constant time (FixedTimeEquals).
        /// </summary>
        public static bool VerifyDataReqHmac(
            string hmacSecretBase64,
            uint messageId,
            DataReqPayload payload,
            byte version = PvspConstants.ProtocolVersion)
        {
            // HMAC field must be exactly 64 lowercase hexadecimal characters (32 bytes)
            if (string.IsNullOrEmpty(payload.Hmac) || payload.Hmac.Length != 64)
                return false;

            foreach (char c in payload.Hmac)
            {
                bool isLowerHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
                if (!isLowerHex)
                    return false;
            }

            byte[] providedMacBytes;
            try
            {
                providedMacBytes = Convert.FromHexString(payload.Hmac);
            }
            catch (FormatException)
            {
                return false;
            }

            byte[] secretKeyBytes = Convert.FromBase64String(hmacSecretBase64);
            byte[] canonicalInput = BuildCanonicalHmacInput(
                version,
                PvspMessageType.DataReq,
                messageId,
                payload.SessionToken,
                payload.Action,
                payload.Key,
                payload.Value,
                payload.Timestamp);

            byte[] expectedMacBytes = HMACSHA256.HashData(secretKeyBytes, canonicalInput);

            // Constant-time comparison prevents timing side-channel attacks
            return CryptographicOperations.FixedTimeEquals(providedMacBytes, expectedMacBytes);
        }

        /// <summary>
        /// Computes a SHA-256 digest of raw payload bytes (used to detect identical duplicate requests in a session).
        /// </summary>
        public static byte[] ComputeSha256Digest(byte[] data)
        {
            return SHA256.HashData(data);
        }

        /// <summary>
        /// Hashes a password using PBKDF2-HMAC-SHA256 with a 16-byte random salt and >= 600,000 iterations.
        /// </summary>
        public static (string HashBase64, string SaltBase64, int Iterations) HashPasswordPbkdf2(
            string password,
            int iterations = 600_000)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password),
                salt,
                iterations,
                HashAlgorithmName.SHA256,
                outputLength: 32);

            return (Convert.ToBase64String(hash), Convert.ToBase64String(salt), iterations);
        }

        /// <summary>
        /// Verifies a plaintext password against a stored PBKDF2-HMAC-SHA256 hash and salt in constant time.
        /// </summary>
        public static bool VerifyPasswordPbkdf2(string password, string storedHashBase64, string storedSaltBase64, int iterations)
        {
            if (iterations < 600_000)
                return false;

            byte[] salt = Convert.FromBase64String(storedSaltBase64);
            byte[] expectedHash = Convert.FromBase64String(storedHashBase64);

            byte[] actualHash = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password),
                salt,
                iterations,
                HashAlgorithmName.SHA256,
                outputLength: expectedHash.Length);

            return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
        }

        /// <summary>
        /// Validates the Server's X.509 certificate against our Custom Root CA (ca.crt),
        /// checking hostname/SAN match, expiration date, and EKU serverAuth (1.3.6.1.5.5.7.3.1).
        /// </summary>
        public static bool ValidateServerCertificateCustomCa(
            X509Certificate? certificate,
            X509Chain? chain,
            SslPolicyErrors sslPolicyErrors,
            string caCertPath)
        {
            if (certificate == null || chain == null)
                return false;

            // Reject immediately if hostname/IP does not match certificate SAN (RemoteCertificateNameMismatch)
            if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
                return false;

            if (!File.Exists(caCertPath))
                return false;

            using var serverCert = new X509Certificate2(certificate);

            // Check that the certificate contains the Extended Key Usage (EKU) for Server Authentication (serverAuth)
            bool hasServerAuthEku = false;
            foreach (X509Extension ext in serverCert.Extensions)
            {
                if (ext is X509EnhancedKeyUsageExtension ekuExt)
                {
                    foreach (Oid oid in ekuExt.EnhancedKeyUsages)
                    {
                        if (oid.Value == ServerAuthOid)
                        {
                            hasServerAuthEku = true;
                            break;
                        }
                    }
                }
            }

            if (!hasServerAuthEku)
                return false;

            // Configure the chain to trust ONLY our Custom Root CA (ca.crt)
            using var customCa = new X509Certificate2(caCertPath);
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Clear();
            chain.ChainPolicy.CustomTrustStore.Add(customCa);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            return chain.Build(serverCert);
        }
    }
}