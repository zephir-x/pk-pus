using System;
using System.IO;
using System.Threading.Tasks;
using Pus.Vault.Server;
using Xunit;

namespace Pus.Vault.Tests
{
    public class ServerStorageAndAuthTests : IDisposable
    {
        private readonly string _tempDir;

        public ServerStorageAndAuthTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "pus_vault_tests_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_tempDir);
        }

        [Fact]
        public void VaultStorage_ShouldPersistAcrossRestarts_AndRejectCorruptedJson()
        {
            string storePath = Path.Combine(_tempDir, "data", "vault_store.json");

            // 1. Start engine, store a secret, and simulate server restart
            var engine1 = new VaultStorageEngine(storePath);
            Assert.Equal(StorageOperationStatus.Committed, engine1.SetSecret("DB_PASS", "SuperSecret123"));

            var engine2 = new VaultStorageEngine(storePath);
            Assert.Equal(StorageOperationStatus.Committed, engine2.TryGetSecret("DB_PASS", out string? val));
            Assert.Equal("SuperSecret123", val);

            // 2. Corrupt the JSON file on disk and verify the engine refuses to start on broken state
            File.WriteAllText(storePath, "{corrupted_json_without_closing_brace");
            Assert.Throws<InvalidDataException>(() => new VaultStorageEngine(storePath));
        }

        [Fact]
        public async Task VaultStorage_ShouldRemainConsistent_UnderConcurrentWrites()
        {
            string storePath = Path.Combine(_tempDir, "data", "concurrent_store.json");
            var engine = new VaultStorageEngine(storePath);

            // Run 20 concurrent SET operations from multiple threads
            Task[] tasks = new Task[20];
            for (int i = 0; i < 20; i++)
            {
                int index = i;
                tasks[i] = Task.Run(() =>
                {
                    var status = engine.SetSecret($"KEY_{index}", $"VAL_{index}");
                    Assert.Equal(StorageOperationStatus.Committed, status);
                });
            }

            await Task.WhenAll(tasks);

            // Verify all 20 keys were persisted properly
            var reloadedEngine = new VaultStorageEngine(storePath);
            Assert.Equal(StorageOperationStatus.Committed, reloadedEngine.TryListKeys(out var keys));
            Assert.Equal(20, keys.Count);
        }

        [Fact]
        public void AuthAndRbac_ShouldVerifyPbkdf2Passwords_EnforceRoles_AndLockoutBruteForce()
        {
            string usersPath = Path.Combine(_tempDir, "config", "users.json");
            AuthAndRbacModule.ProvisionUsersFile(usersPath, "AdminPass!123", "ReaderPass!123");

            var auth = new AuthAndRbacModule(usersPath);

            // Valid admin login
            bool adminOk = auth.TryAuthenticate("admin", "AdminPass!123", "AABBCC", "AABBCC", "127.0.0.1", out var adminSession);
            Assert.True(adminOk);
            Assert.NotNull(adminSession);
            Assert.Equal(AuthAndRbacModule.RoleReadWrite, adminSession!.Role);
            Assert.True(AuthAndRbacModule.IsActionAuthorized(adminSession.Role, "SET"));
            Assert.True(AuthAndRbacModule.IsActionAuthorized(adminSession.Role, "DELETE"));

            // Valid reader login -> READ_ONLY cannot SET or DELETE
            bool readerOk = auth.TryAuthenticate("reader", "ReaderPass!123", "112233", "112233", "127.0.0.1", out var readerSession);
            Assert.True(readerOk);
            Assert.Equal(AuthAndRbacModule.RoleReadOnly, readerSession!.Role);
            Assert.True(AuthAndRbacModule.IsActionAuthorized(readerSession.Role, "GET"));
            Assert.False(AuthAndRbacModule.IsActionAuthorized(readerSession.Role, "SET"));
            Assert.False(AuthAndRbacModule.IsActionAuthorized(readerSession.Role, "DELETE"));

            // 3 failed attempts from IP 10.0.0.99 should trigger temporary brute-force lockout
            for (int i = 0; i < 3; i++)
            {
                Assert.False(auth.TryAuthenticate("admin", "WrongPassword", "AA", "AA", "10.0.0.99", out _));
            }

            // Even with valid password, the 4th immediate attempt from locked-out IP is rejected
            Assert.False(auth.TryAuthenticate("admin", "AdminPass!123", "AA", "AA", "10.0.0.99", out _));
        }

        public void Dispose()
        {
            if (Directory.Exists(_tempDir))
            {
                Directory.Delete(_tempDir, recursive: true);
            }
        }
    }
}