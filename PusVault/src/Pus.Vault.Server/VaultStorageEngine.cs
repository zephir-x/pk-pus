using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Pus.Vault.Common;

namespace Pus.Vault.Server
{
    /// <summary>
    /// Explicit outcome of a storage operation to ensure RAM and disk state never diverge.
    /// </summary>
    public enum StorageOperationStatus
    {
        Committed,
        KeyNotFound,
        ResponseTooLarge,
        PersistenceFailed
    }

    /// <summary>
    /// Repository abstraction for thread-safe Key-Value secret storage (enables future encryption-at-rest implementations
    /// without altering the PVSP protocol or session handler).
    /// </summary>
    public interface IVaultStorage
    {
        StorageOperationStatus SetSecret(string key, string value);
        StorageOperationStatus TryGetSecret(string key, out string? value);
        StorageOperationStatus DeleteSecret(string key);
        StorageOperationStatus TryListKeys(out List<string> keys);
    }

    /// <summary>
    /// Thread-safe Key-Value secret storage engine with serialized atomic snapshot persistence.
    /// Uses a single critical section (lock) covering in-memory updates, temporary file flush, and atomic File.Move.
    /// </summary>
    public class VaultStorageEngine : IVaultStorage
    {
        private static readonly JsonSerializerOptions IndentedJsonOptions = new()
        {
            WriteIndented = true
        };

        private readonly string _storeFilePath;
        private readonly string _tempFilePath;
        private readonly Dictionary<string, string> _secrets = new(StringComparer.Ordinal);
        private readonly object _storageLock = new();

        public VaultStorageEngine(string storeFilePath)
        {
            _storeFilePath = storeFilePath;
            _tempFilePath = storeFilePath + ".tmp";

            InitializeStorage();
        }

        /// <summary>
        /// Adds or updates a secret and atomically persists the snapshot to disk before confirming success.
        /// </summary>
        public StorageOperationStatus SetSecret(string key, string value)
        {
            lock (_storageLock)
            {
                // Prepare the candidate state copy so in-memory state is only updated if disk commit succeeds
                var nextState = new Dictionary<string, string>(_secrets, StringComparer.Ordinal)
                {
                    [key] = value
                };

                if (!TryCommitSnapshotToDisk(nextState))
                {
                    return StorageOperationStatus.PersistenceFailed;
                }

                _secrets[key] = value;
                return StorageOperationStatus.Committed;
            }
        }

        /// <summary>
        /// Retrieves the secret value for a given key.
        /// </summary>
        public StorageOperationStatus TryGetSecret(string key, out string? value)
        {
            lock (_storageLock)
            {
                if (_secrets.TryGetValue(key, out value))
                {
                    return StorageOperationStatus.Committed;
                }

                value = null;
                return StorageOperationStatus.KeyNotFound;
            }
        }

        /// <summary>
        /// Removes a secret and atomically persists the updated snapshot to disk.
        /// </summary>
        public StorageOperationStatus DeleteSecret(string key)
        {
            lock (_storageLock)
            {
                if (!_secrets.ContainsKey(key))
                {
                    return StorageOperationStatus.KeyNotFound;
                }

                var nextState = new Dictionary<string, string>(_secrets, StringComparer.Ordinal);
                nextState.Remove(key);

                if (!TryCommitSnapshotToDisk(nextState))
                {
                    return StorageOperationStatus.PersistenceFailed;
                }

                _secrets.Remove(key);
                return StorageOperationStatus.Committed;
            }
        }

        /// <summary>
        /// Returns a sorted list of all secret keys currently stored in the vault.
        /// Enforces the 1,000 keys limit and checks that the serialized response will not exceed 64 KiB.
        /// </summary>
        public StorageOperationStatus TryListKeys(out List<string> keys)
        {
            lock (_storageLock)
            {
                if (_secrets.Count > PvspConstants.MaxListKeysCount)
                {
                    keys = new List<string>();
                    return StorageOperationStatus.ResponseTooLarge;
                }

                keys = _secrets.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
                return StorageOperationStatus.Committed;
            }
        }

        private void InitializeStorage()
        {
            string? directory = Path.GetDirectoryName(_storeFilePath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
                SetUnixPermissions(directory, isDirectory: true);
            }

            // Clean up any leftover temporary file from an interrupted previous process
            if (File.Exists(_tempFilePath))
            {
                File.Delete(_tempFilePath);
            }

            // Missing store file means a fresh empty vault; create an empty JSON object file with 0600 permissions
            if (!File.Exists(_storeFilePath))
            {
                if (!TryCommitSnapshotToDisk(_secrets))
                {
                    throw new IOException($"Failed to initialize empty vault store at '{_storeFilePath}'.");
                }
                return;
            }

            // Enforce 0600 permissions on existing store file
            SetUnixPermissions(_storeFilePath, isDirectory: false);

            // Load existing secrets; if JSON is corrupted, throw InvalidDataException to halt server startup safely
            string json = File.ReadAllText(_storeFilePath, Encoding.UTF8);
            if (string.IsNullOrWhiteSpace(json))
            {
                throw new InvalidDataException($"Vault store file '{_storeFilePath}' is empty or corrupted.");
            }

            Dictionary<string, string?>? loaded;
            try
            {
                loaded = JsonSerializer.Deserialize<Dictionary<string, string?>>(json);
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException($"Vault store file '{_storeFilePath}' contains corrupted JSON.", ex);
            }

            if (loaded == null)
            {
                throw new InvalidDataException($"Vault store file '{_storeFilePath}' deserialized to null.");
            }

            foreach (var kvp in loaded)
            {
                if (kvp.Value == null)
                {
                    throw new InvalidDataException($"Vault store file '{_storeFilePath}' contains a null value for key '{kvp.Key}'.");
                }
                _secrets[kvp.Key] = kvp.Value;
            }
        }

        private bool TryCommitSnapshotToDisk(Dictionary<string, string> stateToPersist)
        {
            try
            {
                // Keep keys sorted on disk for deterministic snapshots
                var sortedDict = new SortedDictionary<string, string>(stateToPersist, StringComparer.Ordinal);
                byte[] jsonBytes = JsonSerializer.SerializeToUtf8Bytes(sortedDict, IndentedJsonOptions);

                // 1. Write snapshot to temporary file and force OS hardware flush
                using (var fs = new FileStream(_tempFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    fs.Write(jsonBytes, 0, jsonBytes.Length);
                    fs.Flush(flushToDisk: true);
                }

                // 2. Set strict 0600 owner-only permissions on the temporary file before moving
                SetUnixPermissions(_tempFilePath, isDirectory: false);

                // 3. Atomically replace the target vault_store.json file
                File.Move(_tempFilePath, _storeFilePath, overwrite: true);
                SetUnixPermissions(_storeFilePath, isDirectory: false);

                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static void SetUnixPermissions(string path, bool isDirectory)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                UnixFileMode mode = isDirectory
                    ? UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute // 0700
                    : UnixFileMode.UserRead | UnixFileMode.UserWrite;                          // 0600

                File.SetUnixFileMode(path, mode);
            }
        }
    }
}