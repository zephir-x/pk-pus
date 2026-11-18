using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Pus.Vault.Client;
using Pus.Vault.Common;
using Pus.Vault.Server;
using Xunit;

namespace Pus.Vault.Tests
{
    public class PvspEndToEndSessionTests : IDisposable
    {
        private readonly string _tempDir;
        private readonly string _certsDir;
        private readonly string _caCertPath;
        private readonly string _serverCertPath;
        private readonly string _serverKeyPath;
        private readonly string _usersPath;
        private readonly string _storePath;
        private readonly string _logsDir;

        public PvspEndToEndSessionTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "pus_vault_e2e_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_tempDir);

            _certsDir = FindCertsDirectory();
            _caCertPath = Path.Combine(_certsDir, "ca.crt");
            _serverCertPath = Path.Combine(_certsDir, "server.crt");
            _serverKeyPath = Path.Combine(_certsDir, "server.key");

            _usersPath = Path.Combine(_tempDir, "config", "users.json");
            _storePath = Path.Combine(_tempDir, "data", "vault_store.json");
            _logsDir = Path.Combine(_tempDir, "logs");

            AuthAndRbacModule.ProvisionUsersFile(_usersPath, "AdminSecret!1", "ReaderSecret!1");
        }

        [Fact]
        public async Task ClientEngine_ShouldExecuteFullCrudLifecycle_Ping_AndEnforceRbac()
        {
            var auth = new AuthAndRbacModule(_usersPath);
            var storage = new VaultStorageEngine(_storePath);
            var logger = new SecurityAuditLogger(_logsDir);

            using var cts = new CancellationTokenSource();
            using var listener = new SocketConnectionListener(0, _serverCertPath, _serverKeyPath, auth, storage, logger);
            listener.StartListening();
            Task serverTask = listener.AcceptLoopAsync(cts.Token);

            // 1. Admin session: Login -> SET -> GET -> LIST -> PING -> DELETE -> BYE
            using (var adminClient = new PvspClientEngine("localhost", listener.BoundPort, _caCertPath))
            {
                var loginRes = await adminClient.ConnectAndLoginAsync("admin", "AdminSecret!1");
                Assert.True(loginRes.Success);
                Assert.Equal("READ_WRITE", adminClient.AssignedRole);

                var setRes = await adminClient.ExecuteDataRequestAsync("SET", "STRIPE_API_KEY", "sk_live_999");
                Assert.True(setRes.IsSuccess);

                var getRes = await adminClient.ExecuteDataRequestAsync("GET", "STRIPE_API_KEY");
                Assert.True(getRes.IsSuccess);
                Assert.Equal("sk_live_999", getRes.Value);

                var listRes = await adminClient.ExecuteDataRequestAsync("LIST");
                Assert.True(listRes.IsSuccess);
                Assert.Contains("STRIPE_API_KEY", listRes.Keys!);

                Assert.True(await adminClient.SendPingAsync());

                // 2. Reader session in parallel: GET succeeds, SET and DELETE fail with 203 ERR_FORBIDDEN
                using (var readerClient = new PvspClientEngine("localhost", listener.BoundPort, _caCertPath))
                {
                    var readerLogin = await readerClient.ConnectAndLoginAsync("reader", "ReaderSecret!1");
                    Assert.True(readerLogin.Success);
                    Assert.Equal("READ_ONLY", readerClient.AssignedRole);

                    var readerGet = await readerClient.ExecuteDataRequestAsync("GET", "STRIPE_API_KEY");
                    Assert.True(readerGet.IsSuccess);
                    Assert.Equal("sk_live_999", readerGet.Value);

                    var readerSet = await readerClient.ExecuteDataRequestAsync("SET", "HACK_KEY", "123");
                    Assert.False(readerSet.IsSuccess);
                    Assert.Equal(PvspErrorCodes.Forbidden, readerSet.ErrorCode);

                    var readerDel = await readerClient.ExecuteDataRequestAsync("DELETE", "STRIPE_API_KEY");
                    Assert.False(readerDel.IsSuccess);
                    Assert.Equal(PvspErrorCodes.Forbidden, readerDel.ErrorCode);

                    await readerClient.DisconnectAsync();
                }

                var delRes = await adminClient.ExecuteDataRequestAsync("DELETE", "STRIPE_API_KEY");
                Assert.True(delRes.IsSuccess);

                var getMissing = await adminClient.ExecuteDataRequestAsync("GET", "STRIPE_API_KEY");
                Assert.False(getMissing.IsSuccess);
                Assert.Equal(PvspErrorCodes.KeyNotFound, getMissing.ErrorCode);

                await adminClient.DisconnectAsync();
            }

            cts.Cancel();
            await serverTask;
        }

        [Fact]
        public async Task ClientEngine_Diagnostics_ShouldTriggerExpectedSecurityAndFramingErrors()
        {
            var auth = new AuthAndRbacModule(_usersPath);
            var storage = new VaultStorageEngine(_storePath);
            var logger = new SecurityAuditLogger(_logsDir);

            using var cts = new CancellationTokenSource();
            using var listener = new SocketConnectionListener(0, _serverCertPath, _serverKeyPath, auth, storage, logger);
            listener.StartListening();
            Task serverTask = listener.AcceptLoopAsync(cts.Token);

            // Test T-05: Corrupted HMAC -> 204 ERR_INVALID_HMAC
            using (var client = new PvspClientEngine("localhost", listener.BoundPort, _caCertPath))
            {
                await client.ConnectAndLoginAsync("admin", "AdminSecret!1");
                var hmacRes = await client.SendDiagnosticCorruptedHmacAsync();
                Assert.False(hmacRes.IsSuccess);
                Assert.Equal(PvspErrorCodes.InvalidHmac, hmacRes.ErrorCode);
            }

            // Test T-06: Expired Timestamp Replay -> 301 ERR_REPLAY_DETECTED
            using (var client = new PvspClientEngine("localhost", listener.BoundPort, _caCertPath))
            {
                await client.ConnectAndLoginAsync("admin", "AdminSecret!1");
                var replayRes = await client.SendDiagnosticReplayTimestampAsync();
                Assert.False(replayRes.IsSuccess);
                Assert.Equal(PvspErrorCodes.ReplayDetected, replayRes.ErrorCode);
            }

            // Test T-08: Corrupted Magic Bytes -> 100 ERR_BAD_MAGIC
            using (var client = new PvspClientEngine("localhost", listener.BoundPort, _caCertPath))
            {
                await client.ConnectAndLoginAsync("admin", "AdminSecret!1");
                var magicRes = await client.SendDiagnosticBadMagicAsync();
                Assert.False(magicRes.IsSuccess);
                Assert.Equal(PvspErrorCodes.BadMagic, magicRes.ErrorCode);
            }

            cts.Cancel();
            await serverTask;
        }

        [Fact]
        public async Task ClientEngine_ShouldAutoReconnectOnGet_AfterServerRestart()
        {
            var auth = new AuthAndRbacModule(_usersPath);
            var storage = new VaultStorageEngine(_storePath);
            var logger = new SecurityAuditLogger(_logsDir);

            // Start Server instance #1
            using var cts1 = new CancellationTokenSource();
            var listener1 = new SocketConnectionListener(0, _serverCertPath, _serverKeyPath, auth, storage, logger);
            listener1.StartListening();
            int port = listener1.BoundPort;
            Task serverTask1 = listener1.AcceptLoopAsync(cts1.Token);

            // Configure fast backoff delays (100ms, 200ms, 400ms) so the test executes quickly
            var fastBackoff = new[] { TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(200), TimeSpan.FromMilliseconds(400) };
            using var client = new PvspClientEngine("localhost", port, _caCertPath, TimeSpan.FromSeconds(2), fastBackoff);

            await client.ConnectAndLoginAsync("admin", "AdminSecret!1");
            Assert.True((await client.ExecuteDataRequestAsync("SET", "DB_HOST", "10.0.0.5")).IsSuccess);

            // Simulate sudden network / server crash
            cts1.Cancel();
            listener1.Dispose();
            await serverTask1;

            // Restart Server instance #2 on the exact same TCP port shortly after
            using var cts2 = new CancellationTokenSource();
            using var listener2 = new SocketConnectionListener(port, _serverCertPath, _serverKeyPath, auth, storage, logger);
            listener2.StartListening();
            Task serverTask2 = listener2.AcceptLoopAsync(cts2.Token);

            // Issue GET: client detects broken socket, runs Auto-Reconnect (HELLO -> AUTH), and retries GET automatically
            var getAfterReconnect = await client.ExecuteDataRequestAsync("GET", "DB_HOST");
            Assert.True(getAfterReconnect.IsSuccess);
            Assert.Equal("10.0.0.5", getAfterReconnect.Value);

            await client.DisconnectAsync();
            cts2.Cancel();
            await serverTask2;
        }

        private static string FindCertsDirectory()
        {
            DirectoryInfo? dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir != null)
            {
                string candidate = Path.Combine(dir.FullName, "certs");
                if (Directory.Exists(candidate) && File.Exists(Path.Combine(candidate, "ca.crt")))
                {
                    return candidate;
                }
                dir = dir.Parent;
            }
            throw new DirectoryNotFoundException("Could not locate 'certs/' directory.");
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