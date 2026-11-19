using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
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
        public void T02_T12_VaultStorage_ShouldPersistAcrossRestarts_AndRejectCorruptedOrNullValueJson()
        {
            string storePath = Path.Combine(_tempDir, "data", "vault_store.json");

            // 1. Start engine via IVaultStorage interface, store a secret, and simulate server restart (Test T-02)
            IVaultStorage engine1 = new VaultStorageEngine(storePath);
            Assert.Equal(StorageOperationStatus.Committed, engine1.SetSecret("DB_PASS", "SuperSecret123"));

            IVaultStorage engine2 = new VaultStorageEngine(storePath);
            Assert.Equal(StorageOperationStatus.Committed, engine2.TryGetSecret("DB_PASS", out string? val));
            Assert.Equal("SuperSecret123", val);

            // 2. Corrupt the JSON file on disk and verify the engine refuses to start on broken state (Test T-12)
            File.WriteAllText(storePath, "{corrupted_json_without_closing_brace");
            Assert.Throws<InvalidDataException>(() => new VaultStorageEngine(storePath));

            // 3. Write a JSON object containing a null secret value and verify startup rejects it cleanly (Priority 2)
            File.WriteAllText(storePath, "{\"NULL_KEY\": null}");
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
        public void T12_AuditLogger_ShouldSanitizeNewlinesAndControlChars_AndNeverLeakSecretsOrTokens()
        {
            string logsDir = Path.Combine(_tempDir, "audit_logs");
            var logger = new SecurityAuditLogger(logsDir);

            // Simulate log injection attempt with newline, carriage return, tab, and ANSI ESC sequence
            string maliciousUser = "admin\r\n\t\x1b[31m[2026-11-18 12:00:00 UTC] [INFO] FORGED_ENTRY\x1b[0m";
            logger.LogSecurity("127.0.0.1:5555", $"Failed login for user '{maliciousUser}'");

            string logFilePath = Path.Combine(logsDir, "server_audit.log");
            string[] lines = File.ReadAllLines(logFilePath);

            // Must be written as a single physical line with escaped \r, \n, \t, and \u001b
            Assert.Single(lines);
            Assert.Contains("\\r", lines[0], StringComparison.Ordinal);
            Assert.Contains("\\n", lines[0], StringComparison.Ordinal);
            Assert.Contains("\\t", lines[0], StringComparison.Ordinal);
            Assert.Contains("\\u001b", lines[0], StringComparison.Ordinal);
            Assert.DoesNotContain("\x1b", lines[0], StringComparison.Ordinal);
        }

        [Fact]
        public void T04_AuthAndRbac_ShouldVerifyPbkdf2Passwords_StrictNonceCase_EnforceRoles_AndLockoutBruteForce()
        {
            string usersPath = Path.Combine(_tempDir, "config", "users.json");
            AuthAndRbacModule.ProvisionUsersFile(usersPath, "AdminPass!123", "ReaderPass!123");

            var auth = new AuthAndRbacModule(usersPath);

            // Strict ordinal constant-time serverNonceEcho check: case mismatch must be rejected
            Assert.False(auth.TryAuthenticate("admin", "AdminPass!123", "AABBCC", "aabbcc", "127.0.0.2", out _));
            Assert.False(auth.TryAuthenticate("admin", "AdminPass!123", "AABBCC", "WRONG0", "127.0.0.3", out _));

            // Valid admin login
            bool adminOk = auth.TryAuthenticate("admin", "AdminPass!123", "AABBCC", "AABBCC", "127.0.0.1", out var adminSession);
            Assert.True(adminOk);
            Assert.NotNull(adminSession);
            Assert.Equal(AuthAndRbacModule.RoleReadWrite, adminSession!.Role);
            Assert.Equal(64, adminSession.SessionToken.Length); // 256-bit CSPRNG hex token
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
        public async Task T04_SessionHandler_ShouldRejectWrongNonce_AndCloseConnectionAfter3FailedAuthAttempts()
        {
            string usersPath = Path.Combine(_tempDir, "config", "users_3auth.json");
            string storePath = Path.Combine(_tempDir, "data", "store_3auth.json");
            string logsDir = Path.Combine(_tempDir, "logs_3auth");

            AuthAndRbacModule.ProvisionUsersFile(usersPath, "AdminPass!123", "ReaderPass!123");
            var auth = new AuthAndRbacModule(usersPath);
            var storage = new VaultStorageEngine(storePath);
            var logger = new SecurityAuditLogger(logsDir);

            var (clientStream, serverStream) = InMemoryDuplexStream.CreatePair();
            using (clientStream)
            using (serverStream)
            {
                var handler = new ClientSessionHandler(serverStream, "127.0.0.1:4100", "127.0.0.1", auth, storage, logger);
                Task sessionTask = handler.RunSessionAsync(CancellationToken.None);

                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.Hello, 1,
                    PvspJsonSerializer.SerializeToUtf8Bytes(new HelloPayload { ClientName = "AuthProbe/1.0", Timestamp = now }), CancellationToken.None);
                var helloAck = JsonSerializer.Deserialize<HelloAckPayload>((await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None)).Frame.PayloadBytes)!;

                // Attempt 1: wrong serverNonceEcho -> 201 ERR_AUTH_FAILED (connection stays open)
                var badNonce = new AuthPayload { Username = "admin", Password = "AdminPass!123", ServerNonceEcho = new string('0', 32), Timestamp = now };
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.Auth, 2, PvspJsonSerializer.SerializeToUtf8Bytes(badNonce), CancellationToken.None);
                var err1 = JsonSerializer.Deserialize<ErrorPayload>((await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None)).Frame.PayloadBytes)!;
                Assert.Equal(PvspErrorCodes.AuthFailed, err1.ErrorCode);

                // Attempt 2: lowercase serverNonceEcho mismatch -> 201 ERR_AUTH_FAILED (connection stays open)
                var lowerNonce = new AuthPayload { Username = "admin", Password = "AdminPass!123", ServerNonceEcho = helloAck.ServerNonce.ToLowerInvariant(), Timestamp = now };
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.Auth, 3, PvspJsonSerializer.SerializeToUtf8Bytes(lowerNonce), CancellationToken.None);
                var err2 = JsonSerializer.Deserialize<ErrorPayload>((await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None)).Frame.PayloadBytes)!;
                Assert.Equal(PvspErrorCodes.AuthFailed, err2.ErrorCode);

                // Attempt 3: wrong password -> 201 ERR_AUTH_FAILED AND server closes session immediately
                var badPass = new AuthPayload { Username = "admin", Password = "WrongPassword!", ServerNonceEcho = helloAck.ServerNonce, Timestamp = now };
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.Auth, 4, PvspJsonSerializer.SerializeToUtf8Bytes(badPass), CancellationToken.None);
                var err3 = JsonSerializer.Deserialize<ErrorPayload>((await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None)).Frame.PayloadBytes)!;
                Assert.Equal(PvspErrorCodes.AuthFailed, err3.ErrorCode);

                await sessionTask;
                // Closing server stream signals EOF to client
                serverStream.Dispose();
                FrameReadResult eofRes = await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None);
                Assert.True(eofRes.IsEof);
            }
        }

        [Fact]
        public async Task T11_SessionHandler_ShouldEnforce64KiBListLimit_KeyAndValueLimits_AndControlFrameRules()
        {
            string usersPath = Path.Combine(_tempDir, "config", "users_t11_ext.json");
            string storePath = Path.Combine(_tempDir, "data", "store_t11_ext.json");
            string logsDir = Path.Combine(_tempDir, "logs_t11_ext");

            // Pre-populate 600 keys of 120 chars each (<= 1,000 keys, but serialized LIST JSON > 64 KiB)
            Directory.CreateDirectory(Path.GetDirectoryName(storePath)!);
            var wideKeysDict = new Dictionary<string, string>();
            for (int i = 0; i < 600; i++)
            {
                wideKeysDict[$"K{i:D4}_" + new string('A', 114)] = "v";
            }
            File.WriteAllText(storePath, JsonSerializer.Serialize(wideKeysDict));

            AuthAndRbacModule.ProvisionUsersFile(usersPath, "AdminPass!123", "ReaderPass!123");
            var auth = new AuthAndRbacModule(usersPath);
            var storage = new VaultStorageEngine(storePath);
            var logger = new SecurityAuditLogger(logsDir);

            var (clientStream, serverStream) = InMemoryDuplexStream.CreatePair();
            using (clientStream)
            using (serverStream)
            {
                var handler = new ClientSessionHandler(serverStream, "127.0.0.1:4200", "127.0.0.1", auth, storage, logger);
                Task sessionTask = handler.RunSessionAsync(CancellationToken.None);

                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.Hello, 1,
                    PvspJsonSerializer.SerializeToUtf8Bytes(new HelloPayload { ClientName = "T11Ext/1.0", Timestamp = now }), CancellationToken.None);
                var helloAck = JsonSerializer.Deserialize<HelloAckPayload>((await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None)).Frame.PayloadBytes)!;

                var authReq = new AuthPayload { Username = "admin", Password = "AdminPass!123", ServerNonceEcho = helloAck.ServerNonce, Timestamp = now };
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.Auth, 2, PvspJsonSerializer.SerializeToUtf8Bytes(authReq), CancellationToken.None);
                var authAck = JsonSerializer.Deserialize<AuthAckPayload>((await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None)).Frame.PayloadBytes)!;

                // 1. LIST with <= 1,000 keys whose serialized JSON exceeds 64 KiB -> 108 ERR_RESPONSE_TOO_LARGE
                var listReq = new DataReqPayload { SessionToken = authAck.SessionToken, Action = "LIST", Timestamp = now };
                listReq.Hmac = PvspCryptoHelper.ComputeDataReqHmacHex(authAck.HmacSecret, 3, listReq);
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.DataReq, 3, PvspJsonSerializer.SerializeToUtf8Bytes(listReq), CancellationToken.None);
                var err108 = JsonSerializer.Deserialize<ErrorPayload>((await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None)).Frame.PayloadBytes)!;
                Assert.Equal(PvspErrorCodes.ResponseTooLarge, err108.ErrorCode);

                // 2. SET with invalid key format (space & slash) -> 106 ERR_INVALID_PAYLOAD
                var badKeyReq = new DataReqPayload { SessionToken = authAck.SessionToken, Action = "SET", Key = "bad key/path", Value = "ok", Timestamp = now, Hmac = new string('a', 64) };
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.DataReq, 4, PvspJsonSerializer.SerializeToUtf8Bytes(badKeyReq), CancellationToken.None);
                var errBadKey = JsonSerializer.Deserialize<ErrorPayload>((await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None)).Frame.PayloadBytes)!;
                Assert.Equal(PvspErrorCodes.InvalidPayload, errBadKey.ErrorCode);

                // 3. SET with oversized value (32,769 bytes > 32 KiB MaxValueBytes) -> 106 ERR_INVALID_PAYLOAD
                var hugeValReq = new DataReqPayload { SessionToken = authAck.SessionToken, Action = "SET", Key = "VALID_KEY", Value = new string('V', PvspConstants.MaxValueBytes + 1), Timestamp = now, Hmac = new string('a', 64) };
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.DataReq, 5, PvspJsonSerializer.SerializeToUtf8Bytes(hugeValReq), CancellationToken.None);
                var errHugeVal = JsonSerializer.Deserialize<ErrorPayload>((await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None)).Frame.PayloadBytes)!;
                Assert.Equal(PvspErrorCodes.InvalidPayload, errHugeVal.ErrorCode);

                // 4. PING with non-empty payload -> 106 ERR_INVALID_PAYLOAD
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.Ping, 6, Encoding.UTF8.GetBytes("junk"), CancellationToken.None);
                var errPingPayload = JsonSerializer.Deserialize<ErrorPayload>((await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None)).Frame.PayloadBytes)!;
                Assert.Equal(PvspErrorCodes.InvalidPayload, errPingPayload.ErrorCode);

                // 5. BYE with non-empty payload -> 106 ERR_INVALID_PAYLOAD (connection stays open)
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.Bye, 7, Encoding.UTF8.GetBytes("junk"), CancellationToken.None);
                var errByePayload = JsonSerializer.Deserialize<ErrorPayload>((await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None)).Frame.PayloadBytes)!;
                Assert.Equal(PvspErrorCodes.InvalidPayload, errByePayload.ErrorCode);

                // 6. Unsolicited PONG from client in AUTHENTICATED state -> 202 ERR_UNAUTHORIZED_STATE
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.Pong, 8, Array.Empty<byte>(), CancellationToken.None);
                var errPong = JsonSerializer.Deserialize<ErrorPayload>((await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None)).Frame.PayloadBytes)!;
                Assert.Equal(PvspErrorCodes.UnauthorizedState, errPong.ErrorCode);

                // 7. Valid PING (MsgID=9) -> proves session remained alive and monotonic sequence stayed in sync!
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.Ping, 9, Array.Empty<byte>(), CancellationToken.None);
                FrameReadResult pongRes = await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None);
                Assert.Equal(PvspMessageType.Pong, pongRes.Frame.MessageType);
                Assert.Equal(9u, pongRes.Frame.MessageId);

                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.Bye, 10, Array.Empty<byte>(), CancellationToken.None);
                await sessionTask;
            }
        }

        [Fact]
        public async Task SessionHandler_ShouldEnforceAuthenticatedIdleTimeout_With105ErrorAndClose()
        {
            string usersPath = Path.Combine(_tempDir, "config", "users_idle.json");
            string storePath = Path.Combine(_tempDir, "data", "store_idle.json");
            string logsDir = Path.Combine(_tempDir, "logs_idle");

            AuthAndRbacModule.ProvisionUsersFile(usersPath, "AdminPass!123", "ReaderPass!123");
            var auth = new AuthAndRbacModule(usersPath);
            var storage = new VaultStorageEngine(storePath);
            var logger = new SecurityAuditLogger(logsDir);

            var (clientStream, serverStream) = InMemoryDuplexStream.CreatePair();
            using (clientStream)
            using (serverStream)
            {
                var handler = new ClientSessionHandler(
                    serverStream, "127.0.0.1:4300", "127.0.0.1", auth, storage, logger,
                    helloTimeout: TimeSpan.FromSeconds(2),
                    authTimeout: TimeSpan.FromSeconds(2),
                    idleTimeout: TimeSpan.FromMilliseconds(250));
                Task sessionTask = handler.RunSessionAsync(CancellationToken.None);

                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.Hello, 1,
                    PvspJsonSerializer.SerializeToUtf8Bytes(new HelloPayload { ClientName = "IdleProbe/1.0", Timestamp = now }), CancellationToken.None);
                var helloAck = JsonSerializer.Deserialize<HelloAckPayload>((await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None)).Frame.PayloadBytes)!;

                var authReq = new AuthPayload { Username = "admin", Password = "AdminPass!123", ServerNonceEcho = helloAck.ServerNonce, Timestamp = now };
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.Auth, 2, PvspJsonSerializer.SerializeToUtf8Bytes(authReq), CancellationToken.None);
                FrameReadResult authAckRes = await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None);
                Assert.Equal(PvspMessageType.AuthAck, authAckRes.Frame.MessageType);

                // Stay silent past 250ms idleTimeout -> server must emit 105 ERR_TIMEOUT and close session
                FrameReadResult timeoutRes = await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None);
                Assert.Equal(PvspMessageType.Error, timeoutRes.Frame.MessageType);
                var err = JsonSerializer.Deserialize<ErrorPayload>(timeoutRes.Frame.PayloadBytes)!;
                Assert.Equal(PvspErrorCodes.Timeout, err.ErrorCode);

                await sessionTask;
            }
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
            var helloAck = JsonSerializer.Deserialize<HelloAckPayload>(helloAckRes.Frame.PayloadBytes)!;

            // 2. Attempt DATA_REQ before AUTH (MsgID = 2) -> should receive 202 ERR_UNAUTHORIZED_STATE and stay open
            var prematureReq = new DataReqPayload { SessionToken = "none", Action = "LIST", Timestamp = now, Hmac = new string('0', 64) };
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.DataReq, 2, PvspJsonSerializer.SerializeToUtf8Bytes(prematureReq), CancellationToken.None);
            FrameReadResult errRes = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
            Assert.Equal(PvspMessageType.Error, errRes.Frame.MessageType);
            var errPayload = JsonSerializer.Deserialize<ErrorPayload>(errRes.Frame.PayloadBytes)!;
            Assert.Equal(PvspErrorCodes.UnauthorizedState, errPayload.ErrorCode);

            // 3. Send valid AUTH with next monotonic MsgID = 3
            var authReq = new AuthPayload
            {
                Username = "admin",
                Password = superSecretPassword,
                ServerNonceEcho = helloAck.ServerNonce,
                Timestamp = now
            };
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.Auth, 3, PvspJsonSerializer.SerializeToUtf8Bytes(authReq), CancellationToken.None);
            FrameReadResult authAckRes = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
            Assert.Equal(PvspMessageType.AuthAck, authAckRes.Frame.MessageType);
            var authAck = JsonSerializer.Deserialize<AuthAckPayload>(authAckRes.Frame.PayloadBytes)!;

            // 4. Send valid SET (MsgID = 4)
            var setReq = new DataReqPayload
            {
                SessionToken = authAck.SessionToken,
                Action = "SET",
                Key = "API_TOKEN",
                Value = superSecretVaultValue,
                Timestamp = now
            };
            setReq.Hmac = PvspCryptoHelper.ComputeDataReqHmacHex(authAck.HmacSecret, 4, setReq);
            byte[] setReqBytes = PvspJsonSerializer.SerializeToUtf8Bytes(setReq);
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.DataReq, 4, setReqBytes, CancellationToken.None);

            FrameReadResult setResp = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
            Assert.Equal(PvspMessageType.DataResp, setResp.Frame.MessageType);

            // 5. Re-send exact same frame (MsgID = 4, identical digest) -> Server returns cached response without error!
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.DataReq, 4, setReqBytes, CancellationToken.None);
            FrameReadResult dupResp = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
            Assert.Equal(PvspMessageType.DataResp, dupResp.Frame.MessageType);
            Assert.Equal(4u, dupResp.Frame.MessageId);

            // 6. Send BYE (MsgID = 5)
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.Bye, 5, Array.Empty<byte>(), CancellationToken.None);

            cts.Cancel();
            await acceptTask;

            // 7. Verify T-12 Audit Log Redaction: log file must NEVER contain passwords, secret values, tokens, hmacSecret, or nonces
            string auditLogContent = File.ReadAllText(Path.Combine(logsDir, "server_audit.log"));
            Assert.DoesNotContain(superSecretPassword, auditLogContent);
            Assert.DoesNotContain(superSecretVaultValue, auditLogContent);
            Assert.DoesNotContain(authAck.SessionToken, auditLogContent);
            Assert.DoesNotContain(authAck.HmacSecret, auditLogContent);
            Assert.DoesNotContain(helloAck.ServerNonce, auditLogContent);
        }

        [Fact]
        public async Task Priority1_SessionHandler_ShouldRejectExtremeTimestamps_WithoutOverflowException()
        {
            string usersPath = Path.Combine(_tempDir, "config", "users_p1_ts.json");
            string storePath = Path.Combine(_tempDir, "data", "store_p1_ts.json");
            string logsDir = Path.Combine(_tempDir, "logs_p1_ts");

            AuthAndRbacModule.ProvisionUsersFile(usersPath, "AdminPass!123", "ReaderPass!123");
            var auth = new AuthAndRbacModule(usersPath);
            var storage = new VaultStorageEngine(storePath);
            var logger = new SecurityAuditLogger(logsDir);

            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            long[] extremeTimestamps =
            {
                long.MinValue,
                unchecked(now - long.MinValue),
                long.MaxValue
            };

            foreach (long ts in extremeTimestamps)
            {
                var (clientStream, serverStream) = InMemoryDuplexStream.CreatePair();
                using (clientStream)
                using (serverStream)
                {
                    var handler = new ClientSessionHandler(serverStream, "127.0.0.1:1000", "127.0.0.1", auth, storage, logger);
                    Task sessionTask = handler.RunSessionAsync(CancellationToken.None);

                    byte[] helloBytes = PvspJsonSerializer.SerializeToUtf8Bytes(new HelloPayload
                    {
                        ClientName = "OverflowProbe/1.0",
                        Timestamp = ts
                    });
                    await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.Hello, 1, helloBytes, CancellationToken.None);

                    FrameReadResult errRes = await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None);
                    Assert.Equal(PvspMessageType.Error, errRes.Frame.MessageType);
                    var err = JsonSerializer.Deserialize<ErrorPayload>(errRes.Frame.PayloadBytes)!;
                    Assert.Equal(PvspErrorCodes.ReplayDetected, err.ErrorCode);

                    await sessionTask;
                }
            }
        }

        [Fact]
        public async Task Priority1_SessionHandler_ShouldEnforceAbsoluteHelloAndAuthDeadlines_AgainstInvalidFrameSpam()
        {
            string usersPath = Path.Combine(_tempDir, "config", "users_p1_deadline.json");
            string storePath = Path.Combine(_tempDir, "data", "store_p1_deadline.json");
            string logsDir = Path.Combine(_tempDir, "logs_p1_deadline");

            AuthAndRbacModule.ProvisionUsersFile(usersPath, "AdminPass!123", "ReaderPass!123");
            var auth = new AuthAndRbacModule(usersPath);
            var storage = new VaultStorageEngine(storePath);
            var logger = new SecurityAuditLogger(logsDir);

            // Phase 1 (TLS_CONNECTED): continuous 104 ERR_INVALID_JSON spam must NOT extend absolute HELLO deadline
            {
                var (clientStream, serverStream) = InMemoryDuplexStream.CreatePair();
                using (clientStream)
                using (serverStream)
                {
                    var handler = new ClientSessionHandler(
                        serverStream, "127.0.0.1:2001", "127.0.0.1", auth, storage, logger,
                        helloTimeout: TimeSpan.FromMilliseconds(350),
                        authTimeout: TimeSpan.FromMilliseconds(350),
                        idleTimeout: TimeSpan.FromSeconds(5));
                    Task sessionTask = handler.RunSessionAsync(CancellationToken.None);

                    bool sawTimeout = false;
                    uint msgId = 1;
                    for (int i = 0; i < 15; i++)
                    {
                        await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.Hello, msgId++, Encoding.UTF8.GetBytes("{bad"), CancellationToken.None);
                        FrameReadResult res = await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None);
                        if (res.IsEof)
                        {
                            break;
                        }

                        var err = JsonSerializer.Deserialize<ErrorPayload>(res.Frame.PayloadBytes)!;
                        if (err.ErrorCode == PvspErrorCodes.Timeout)
                        {
                            sawTimeout = true;
                            break;
                        }

                        Assert.Equal(PvspErrorCodes.InvalidJson, err.ErrorCode);
                        await Task.Delay(90);
                    }

                    Assert.True(sawTimeout, "Expected 105 ERR_TIMEOUT once absolute HELLO deadline elapsed despite 104 spam.");
                    await sessionTask;
                }
            }

            // Phase 2 (HANDSHAKED): continuous 202 ERR_UNAUTHORIZED_STATE spam must NOT extend absolute AUTH deadline
            {
                var (clientStream, serverStream) = InMemoryDuplexStream.CreatePair();
                using (clientStream)
                using (serverStream)
                {
                    var handler = new ClientSessionHandler(
                        serverStream, "127.0.0.1:2002", "127.0.0.1", auth, storage, logger,
                        helloTimeout: TimeSpan.FromSeconds(2),
                        authTimeout: TimeSpan.FromMilliseconds(350),
                        idleTimeout: TimeSpan.FromSeconds(5));
                    Task sessionTask = handler.RunSessionAsync(CancellationToken.None);

                    long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    byte[] helloBytes = PvspJsonSerializer.SerializeToUtf8Bytes(new HelloPayload { ClientName = "DeadlineProbe/1.0", Timestamp = now });
                    await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.Hello, 1, helloBytes, CancellationToken.None);
                    FrameReadResult ack = await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None);
                    Assert.Equal(PvspMessageType.HelloAck, ack.Frame.MessageType);

                    bool sawTimeout = false;
                    uint msgId = 2;
                    for (int i = 0; i < 15; i++)
                    {
                        var premature = new DataReqPayload { SessionToken = "none", Action = "LIST", Timestamp = now, Hmac = new string('0', 64) };
                        await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.DataReq, msgId++, PvspJsonSerializer.SerializeToUtf8Bytes(premature), CancellationToken.None);
                        FrameReadResult res = await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None);
                        if (res.IsEof)
                        {
                            break;
                        }

                        var err = JsonSerializer.Deserialize<ErrorPayload>(res.Frame.PayloadBytes)!;
                        if (err.ErrorCode == PvspErrorCodes.Timeout)
                        {
                            sawTimeout = true;
                            break;
                        }

                        Assert.Equal(PvspErrorCodes.UnauthorizedState, err.ErrorCode);
                        await Task.Delay(90);
                    }

                    Assert.True(sawTimeout, "Expected 105 ERR_TIMEOUT once absolute AUTH deadline elapsed despite 202 spam.");
                    await sessionTask;
                }
            }
        }

        [Fact]
        public async Task Priority1_SessionHandler_ShouldAdvanceSequenceIdOnNonClosingErrors_AndPreventDuplicateCachePoisoning()
        {
            string usersPath = Path.Combine(_tempDir, "config", "users_p1_seq.json");
            string storePath = Path.Combine(_tempDir, "data", "store_p1_seq.json");
            string logsDir = Path.Combine(_tempDir, "logs_p1_seq");

            AuthAndRbacModule.ProvisionUsersFile(usersPath, "AdminPass!123", "ReaderPass!123");
            var auth = new AuthAndRbacModule(usersPath);
            var storage = new VaultStorageEngine(storePath);
            var logger = new SecurityAuditLogger(logsDir);

            var (clientStream, serverStream) = InMemoryDuplexStream.CreatePair();
            using (clientStream)
            using (serverStream)
            {
                var handler = new ClientSessionHandler(serverStream, "127.0.0.1:3001", "127.0.0.1", auth, storage, logger);
                Task sessionTask = handler.RunSessionAsync(CancellationToken.None);

                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                // 1. Broken JSON HELLO (MsgID=1) -> 104 ERR_INVALID_JSON (consumes MsgID=1)
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.Hello, 1, Encoding.UTF8.GetBytes("{broken"), CancellationToken.None);
                var err104 = JsonSerializer.Deserialize<ErrorPayload>((await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None)).Frame.PayloadBytes)!;
                Assert.Equal(PvspErrorCodes.InvalidJson, err104.ErrorCode);

                // 2. Oversized unknown field HELLO (MsgID=2) -> 106 ERR_INVALID_PAYLOAD (consumes MsgID=2, never reflects field name, <= 512 B)
                string evilField = "EVIL_FIELD_" + new string('Z', 650);
                byte[] badFieldBytes = Encoding.UTF8.GetBytes($"{{\"clientName\":\"Probe/1.0\",\"timestamp\":{now},\"{evilField}\":1}}");
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.Hello, 2, badFieldBytes, CancellationToken.None);
                var err106 = JsonSerializer.Deserialize<ErrorPayload>((await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None)).Frame.PayloadBytes)!;
                Assert.Equal(PvspErrorCodes.InvalidPayload, err106.ErrorCode);
                Assert.DoesNotContain("EVIL_FIELD_", err106.Message);
                Assert.True(Encoding.UTF8.GetByteCount(err106.Message) <= PvspConstants.MaxErrorMessageBytes);

                // 3. Valid HELLO (MsgID=3) and AUTH (MsgID=4)
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.Hello, 3, PvspJsonSerializer.SerializeToUtf8Bytes(new HelloPayload { ClientName = "Probe/1.0", Timestamp = now }), CancellationToken.None);
                var helloAck = JsonSerializer.Deserialize<HelloAckPayload>((await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None)).Frame.PayloadBytes)!;

                var authReq = new AuthPayload { Username = "admin", Password = "AdminPass!123", ServerNonceEcho = helloAck.ServerNonce, Timestamp = now };
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.Auth, 4, PvspJsonSerializer.SerializeToUtf8Bytes(authReq), CancellationToken.None);
                var authAck = JsonSerializer.Deserialize<AuthAckPayload>((await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None)).Frame.PayloadBytes)!;

                // 4. Valid SET (MsgID=5) -> DATA_RESP cached for MsgID=5
                var setReq = new DataReqPayload
                {
                    SessionToken = authAck.SessionToken,
                    Action = "SET",
                    Key = "SEQ_KEY",
                    Value = "SafeValue",
                    Timestamp = now
                };
                setReq.Hmac = PvspCryptoHelper.ComputeDataReqHmacHex(authAck.HmacSecret, 5, setReq);
                byte[] setReqBytes = PvspJsonSerializer.SerializeToUtf8Bytes(setReq);
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.DataReq, 5, setReqBytes, CancellationToken.None);
                FrameReadResult setResp = await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None);
                Assert.Equal(PvspMessageType.DataResp, setResp.Frame.MessageType);

                // 5. Out-of-sequence invalid JSON DATA_REQ (MsgID=99) -> 104 ERR_INVALID_JSON; MUST NOT jump sequence ID or poison duplicate cache!
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.DataReq, 99, Encoding.UTF8.GetBytes("{corrupt"), CancellationToken.None);
                FrameReadResult strayErrRes = await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None);
                Assert.Equal(PvspMessageType.Error, strayErrRes.Frame.MessageType);
                Assert.Equal(PvspErrorCodes.InvalidJson, JsonSerializer.Deserialize<ErrorPayload>(strayErrRes.Frame.PayloadBytes)!.ErrorCode);

                // 6. Re-send exact duplicate SET (MsgID=5) -> MUST still receive cached DATA_RESP (not poisoned 104 error!)
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.DataReq, 5, setReqBytes, CancellationToken.None);
                FrameReadResult dupResp = await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None);
                Assert.Equal(PvspMessageType.DataResp, dupResp.Frame.MessageType);
                Assert.Equal(5u, dupResp.Frame.MessageId);

                // 7. Valid GET (MsgID=6) -> confirms monotonic counter stayed at 5 and advances cleanly to 6
                var getReq = new DataReqPayload
                {
                    SessionToken = authAck.SessionToken,
                    Action = "GET",
                    Key = "SEQ_KEY",
                    Timestamp = now
                };
                getReq.Hmac = PvspCryptoHelper.ComputeDataReqHmacHex(authAck.HmacSecret, 6, getReq);
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.DataReq, 6, PvspJsonSerializer.SerializeToUtf8Bytes(getReq), CancellationToken.None);
                FrameReadResult getResp = await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None);
                Assert.Equal(PvspMessageType.DataResp, getResp.Frame.MessageType);
                var getPayload = JsonSerializer.Deserialize<DataRespPayload>(getResp.Frame.PayloadBytes)!;
                Assert.Equal("SafeValue", getPayload.Value);

                // 8. Unsupported action with control characters (MsgID=7) -> 107 ERR_INVALID_ACTION without reflecting raw action
                var badActionReq = new DataReqPayload
                {
                    SessionToken = authAck.SessionToken,
                    Action = "HACK\nDROP",
                    Timestamp = now,
                    Hmac = new string('a', 64)
                };
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.DataReq, 7, PvspJsonSerializer.SerializeToUtf8Bytes(badActionReq), CancellationToken.None);
                var err107 = JsonSerializer.Deserialize<ErrorPayload>((await PvspFrameCodec.ReadFrameAsync(clientStream, CancellationToken.None)).Frame.PayloadBytes)!;
                Assert.Equal(PvspErrorCodes.InvalidAction, err107.ErrorCode);
                Assert.DoesNotContain("HACK", err107.Message);
                Assert.DoesNotContain("\n", err107.Message);
                Assert.True(Encoding.UTF8.GetByteCount(err107.Message) <= PvspConstants.MaxErrorMessageBytes);

                // 9. Clean BYE (MsgID=8)
                await PvspFrameCodec.WriteFrameAsync(clientStream, PvspMessageType.Bye, 8, Array.Empty<byte>(), CancellationToken.None);
                await sessionTask;
            }
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

        private sealed class InMemoryDuplexStream : Stream
        {
            private readonly ChannelReader<byte[]> _reader;
            private readonly ChannelWriter<byte[]> _writer;
            private byte[] _currentChunk = Array.Empty<byte>();
            private int _currentOffset;

            private InMemoryDuplexStream(ChannelReader<byte[]> reader, ChannelWriter<byte[]> writer)
            {
                _reader = reader;
                _writer = writer;
            }

            public static (InMemoryDuplexStream Client, InMemoryDuplexStream Server) CreatePair()
            {
                var c2s = Channel.CreateUnbounded<byte[]>();
                var s2c = Channel.CreateUnbounded<byte[]>();
                return (new InMemoryDuplexStream(s2c.Reader, c2s.Writer), new InMemoryDuplexStream(c2s.Reader, s2c.Writer));
            }

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => true;
            public override long Length => throw new NotSupportedException();
            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                while (_currentOffset >= _currentChunk.Length)
                {
                    if (!await _reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
                    {
                        return 0;
                    }

                    if (_reader.TryRead(out byte[]? nextChunk))
                    {
                        _currentChunk = nextChunk;
                        _currentOffset = 0;
                    }
                }

                int toCopy = Math.Min(buffer.Length, _currentChunk.Length - _currentOffset);
                _currentChunk.AsMemory(_currentOffset, toCopy).CopyTo(buffer);
                _currentOffset += toCopy;
                return toCopy;
            }

            public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (buffer.Length > 0)
                {
                    _writer.TryWrite(buffer.ToArray());
                }
                return ValueTask.CompletedTask;
            }

            public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
            public override void Flush() { }
            public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
            public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    _writer.TryComplete();
                }
                base.Dispose(disposing);
            }
        }
    }
}