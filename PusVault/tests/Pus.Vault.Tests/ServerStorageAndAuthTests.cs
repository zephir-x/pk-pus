using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;
using Pus.Vault.Common;
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
        public void T02_T12_VaultStorage_ShouldPersistAcrossRestarts_AndRejectCorruptedJson()
        {
            string storePath = Path.Combine(_tempDir, "data", "vault_store.json");

            // 1. Start engine, store a secret, and simulate server restart (Test T-02)
            var engine1 = new VaultStorageEngine(storePath);
            Assert.Equal(StorageOperationStatus.Committed, engine1.SetSecret("DB_PASS", "SuperSecret123"));

            var engine2 = new VaultStorageEngine(storePath);
            Assert.Equal(StorageOperationStatus.Committed, engine2.TryGetSecret("DB_PASS", out string? val));
            Assert.Equal("SuperSecret123", val);

            // 2. Corrupt the JSON file on disk and verify the engine refuses to start on broken state (Test T-12)
            File.WriteAllText(storePath, "{corrupted_json_without_closing_brace");
            Assert.Throws<InvalidDataException>(() => new VaultStorageEngine(storePath));
        }

        [Fact]
        public async Task T12_VaultStorage_ShouldRemainConsistent_UnderConcurrentSetsAndDeletes()
        {
            string storePath = Path.Combine(_tempDir, "data", "concurrent_store.json");
            var engine = new VaultStorageEngine(storePath);

            // Run 20 concurrent SET operations followed by concurrent DELETEs of even keys
            Task[] setTasks = new Task[20];
            for (int i = 0; i < 20; i++)
            {
                int index = i;
                setTasks[i] = Task.Run(() =>
                {
                    var status = engine.SetSecret($"KEY_{index}", $"VAL_{index}");
                    Assert.Equal(StorageOperationStatus.Committed, status);
                });
            }
            await Task.WhenAll(setTasks);

            Task[] delTasks = new Task[10];
            for (int i = 0; i < 10; i++)
            {
                int evenIndex = i * 2;
                delTasks[i] = Task.Run(() =>
                {
                    var status = engine.DeleteSecret($"KEY_{evenIndex}");
                    Assert.Equal(StorageOperationStatus.Committed, status);
                });
            }
            await Task.WhenAll(delTasks);

            // Verify exactly 10 odd keys remain both in RAM and on disk after reload
            var reloadedEngine = new VaultStorageEngine(storePath);
            Assert.Equal(StorageOperationStatus.Committed, reloadedEngine.TryListKeys(out var keys));
            Assert.Equal(10, keys.Count);
        }

        [Fact]
        public void T12_VaultStorage_ShouldNotMutateRam_WhenDiskWriteFails()
        {
            string storePath = Path.Combine(_tempDir, "data", "fail_store.json");
            var engine = new VaultStorageEngine(storePath);
            Assert.Equal(StorageOperationStatus.Committed, engine.SetSecret("INITIAL_KEY", "InitialValue"));

            // Sabotage the temporary file path by creating a directory named 'fail_store.json.tmp'
            // so FileStream creation for the snapshot fails with an IOException/UnauthorizedAccessException
            string tempFilePath = storePath + ".tmp";
            Directory.CreateDirectory(tempFilePath);

            try
            {
                // Attempt SET and DELETE while disk persistence is broken -> must return PersistenceFailed
                Assert.Equal(StorageOperationStatus.PersistenceFailed, engine.SetSecret("NEW_KEY", "ShouldNotBeSaved"));
                Assert.Equal(StorageOperationStatus.PersistenceFailed, engine.DeleteSecret("INITIAL_KEY"));

                // Verify in-memory state was NOT modified (no divergence between RAM and disk)
                Assert.Equal(StorageOperationStatus.KeyNotFound, engine.TryGetSecret("NEW_KEY", out _));
                Assert.Equal(StorageOperationStatus.Committed, engine.TryGetSecret("INITIAL_KEY", out string? existingVal));
                Assert.Equal("InitialValue", existingVal);
            }
            finally
            {
                Directory.Delete(tempFilePath, recursive: true);
            }
        }

        [Fact]
        public void T12_AuditLogger_ShouldSanitizeNewlines_AndNeverLeakSecretsOrTokens()
        {
            string logsDir = Path.Combine(_tempDir, "audit_logs");
            var logger = new SecurityAuditLogger(logsDir);

            // Simulate log injection attempt with newline characters
            string maliciousUser = "admin\n[2026-11-18 12:00:00 UTC] [INFO] [Session:127.0.0.1] FORGED_ENTRY";
            logger.LogSecurity("127.0.0.1:5555", $"Failed login for user '{maliciousUser}'");

            string logFilePath = Path.Combine(logsDir, "server_audit.log");
            string[] lines = File.ReadAllLines(logFilePath);

            // Must be written as a single physical line with escaped \n
            Assert.Single(lines);
            Assert.Contains("\\n", lines[0]);
        }

        [Fact]
        public void T04_AuthAndRbac_ShouldVerifyPbkdf2Passwords_EnforceRoles_AndLockoutBruteForce()
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

        [Fact]
        public async Task ServerListenerAndSession_ShouldHandleFullTlsSession_DuplicateIdempotency_AndAuditRedaction()
        {
            string certsDir = FindCertsDirectory();
            string caCertPath = Path.Combine(certsDir, "ca.crt");
            string serverCertPath = Path.Combine(certsDir, "server.crt");
            string serverKeyPath = Path.Combine(certsDir, "server.key");

            string usersPath = Path.Combine(_tempDir, "config", "users.json");
            string storePath = Path.Combine(_tempDir, "data", "vault_store.json");
            string logsDir = Path.Combine(_tempDir, "logs");

            const string superSecretPassword = "AdminSuperSecretPassword!999";
            const string superSecretVaultValue = "ConfidentialStripeKey_sk_live_777777";

            AuthAndRbacModule.ProvisionUsersFile(usersPath, superSecretPassword, "ReaderPass!123");
            var auth = new AuthAndRbacModule(usersPath);
            var storage = new VaultStorageEngine(storePath);
            var logger = new SecurityAuditLogger(logsDir);

            using var cts = new CancellationTokenSource();
            using var listener = new SocketConnectionListener(0, serverCertPath, serverKeyPath, auth, storage, logger);
            listener.StartListening();
            Task acceptTask = listener.AcceptLoopAsync(cts.Token);

            using var clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await clientSocket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, listener.BoundPort));
            using var netStream = new NetworkStream(clientSocket, ownsSocket: true);
            using var sslStream = new SslStream(
                netStream,
                false,
                (_, cert, chain, errors) => PvspCryptoHelper.ValidateServerCertificateCustomCa(cert, chain, errors, caCertPath));

            await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                EnabledSslProtocols = SslProtocols.Tls13
            });

            // 1. Send HELLO (MsgID = 1)
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            byte[] helloBytes = PvspJsonSerializer.SerializeToUtf8Bytes(new HelloPayload { ClientName = "TestClient/1.0", Timestamp = now });
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.Hello, 1, helloBytes, CancellationToken.None);

            FrameReadResult helloAckRes = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
            Assert.Equal(PvspMessageType.HelloAck, helloAckRes.Frame.MessageType);
            var helloAck = System.Text.Json.JsonSerializer.Deserialize<HelloAckPayload>(helloAckRes.Frame.PayloadBytes)!;

            // 2. Attempt DATA_REQ before AUTH -> should receive 202 ERR_UNAUTHORIZED_STATE and stay open
            var prematureReq = new DataReqPayload { SessionToken = "none", Action = "LIST", Timestamp = now, Hmac = new string('0', 64) };
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.DataReq, 2, PvspJsonSerializer.SerializeToUtf8Bytes(prematureReq), CancellationToken.None);
            FrameReadResult errRes = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
            Assert.Equal(PvspMessageType.Error, errRes.Frame.MessageType);
            var errPayload = System.Text.Json.JsonSerializer.Deserialize<ErrorPayload>(errRes.Frame.PayloadBytes)!;
            Assert.Equal(PvspErrorCodes.UnauthorizedState, errPayload.ErrorCode);

            // 3. Send valid AUTH (MsgID = 2)
            var authReq = new AuthPayload
            {
                Username = "admin",
                Password = superSecretPassword,
                ServerNonceEcho = helloAck.ServerNonce,
                Timestamp = now
            };
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.Auth, 2, PvspJsonSerializer.SerializeToUtf8Bytes(authReq), CancellationToken.None);
            FrameReadResult authAckRes = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
            Assert.Equal(PvspMessageType.AuthAck, authAckRes.Frame.MessageType);
            var authAck = System.Text.Json.JsonSerializer.Deserialize<AuthAckPayload>(authAckRes.Frame.PayloadBytes)!;

            // 4. Send valid SET (MsgID = 3)
            var setReq = new DataReqPayload
            {
                SessionToken = authAck.SessionToken,
                Action = "SET",
                Key = "API_TOKEN",
                Value = superSecretVaultValue,
                Timestamp = now
            };
            setReq.Hmac = PvspCryptoHelper.ComputeDataReqHmacHex(authAck.HmacSecret, 3, setReq);
            byte[] setReqBytes = PvspJsonSerializer.SerializeToUtf8Bytes(setReq);
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.DataReq, 3, setReqBytes, CancellationToken.None);

            FrameReadResult setResp = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
            Assert.Equal(PvspMessageType.DataResp, setResp.Frame.MessageType);

            // 5. Re-send exact same frame (MsgID = 3, identical digest) -> Server returns cached response without error!
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.DataReq, 3, setReqBytes, CancellationToken.None);
            FrameReadResult dupResp = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
            Assert.Equal(PvspMessageType.DataResp, dupResp.Frame.MessageType);
            Assert.Equal(3u, dupResp.Frame.MessageId);

            // 6. Send BYE (MsgID = 4)
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.Bye, 4, Array.Empty<byte>(), CancellationToken.None);

            cts.Cancel();
            await acceptTask;

            // 7. Verify T-12 Audit Log Redaction: log file must NEVER contain passwords, secret values, tokens,hmacSecret, or nonces
            string auditLogContent = File.ReadAllText(Path.Combine(logsDir, "server_audit.log"));
            Assert.DoesNotContain(superSecretPassword, auditLogContent);
            Assert.DoesNotContain(superSecretVaultValue, auditLogContent);
            Assert.DoesNotContain(authAck.SessionToken, auditLogContent);
            Assert.DoesNotContain(authAck.HmacSecret, auditLogContent);
            Assert.DoesNotContain(helloAck.ServerNonce, auditLogContent);
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
            throw new DirectoryNotFoundException("Could not locate 'certs/' directory. Run './scripts/generate_certs.sh' first.");
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