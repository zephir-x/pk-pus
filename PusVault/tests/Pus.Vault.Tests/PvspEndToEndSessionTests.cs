using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Pus.Vault.Client;
using Pus.Vault.Common;
using Pus.Vault.Server;
using Xunit;
using Xunit.Abstractions;

namespace Pus.Vault.Tests
{
    public class PvspEndToEndSessionTests : IDisposable
    {
        private readonly ITestOutputHelper _output;
        private readonly string _tempDir;
        private readonly string _certsDir;
        private readonly string _caCertPath;
        private readonly string _serverCertPath;
        private readonly string _serverKeyPath;
        private readonly string _usersPath;
        private readonly string _storePath;
        private readonly string _logsDir;

        public PvspEndToEndSessionTests(ITestOutputHelper output)
        {
            _output = output;
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
        public async Task T01_T04_ClientEngine_ShouldExecuteFullCrudLifecycle_Ping_AndEnforceRbac()
        {
            var auth = new AuthAndRbacModule(_usersPath);
            var storage = new VaultStorageEngine(_storePath);
            var logger = new SecurityAuditLogger(_logsDir);

            using var cts = new CancellationTokenSource();
            using var listener = new SocketConnectionListener(0, _serverCertPath, _serverKeyPath, auth, storage, logger);
            listener.StartListening();
            Task serverTask = listener.AcceptLoopAsync(cts.Token);

            // 1. Admin session: Login -> SET -> GET -> LIST -> PING -> DELETE -> BYE (Test T-01)
            using (var adminClient = new PvspClientEngine("localhost", listener.BoundPort, _caCertPath))
            {
                var loginRes = await adminClient.ConnectAndLoginAsync("admin", "AdminSecret!1");
                Assert.True(loginRes.Success);
                Assert.Equal("READ_WRITE", adminClient.AssignedRole);

                var setRes = await adminClient.ExecuteDataRequestAsync("SET", "STRIPE_API_KEY", "sk_live_999");
                Assert.True(setRes.IsSuccess);

                // Verify change is immediately persisted in vault_store.json on disk
                Assert.Contains("STRIPE_API_KEY", File.ReadAllText(_storePath));

                var getRes = await adminClient.ExecuteDataRequestAsync("GET", "STRIPE_API_KEY");
                Assert.True(getRes.IsSuccess);
                Assert.Equal("sk_live_999", getRes.Value);

                var listRes = await adminClient.ExecuteDataRequestAsync("LIST");
                Assert.True(listRes.IsSuccess);
                Assert.Contains("STRIPE_API_KEY", listRes.Keys!);

                Assert.True(await adminClient.SendPingAsync());

                // 2. Reader session in parallel: GET succeeds, SET and DELETE fail with 203 ERR_FORBIDDEN (Test T-04)
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
        public async Task T03_TlsHandshake_ShouldThrowAuthenticationException_OnUntrustedCa_WrongSan_AndMissingServerAuthEku()
        {
            var auth = new AuthAndRbacModule(_usersPath);
            var storage = new VaultStorageEngine(_storePath);
            var logger = new SecurityAuditLogger(_logsDir);

            // Case 1: Untrusted CA against production server cert
            {
                using var cts = new CancellationTokenSource();
                using var listener = new SocketConnectionListener(0, _serverCertPath, _serverKeyPath, auth, storage, logger);
                listener.StartListening();
                Task serverTask = listener.AcceptLoopAsync(cts.Token);

                using RSA rogueKey = RSA.Create(2048);
                var req = new CertificateRequest("CN=Untrusted_Root_CA", rogueKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                using X509Certificate2 rogueCa = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(10));
                string rogueCaPath = Path.Combine(_tempDir, "untrusted_ca.crt");
                File.WriteAllText(rogueCaPath, rogueCa.ExportCertificatePem());

                using (var untrustedClient = new PvspClientEngine("localhost", listener.BoundPort, rogueCaPath))
                {
                    await Assert.ThrowsAsync<AuthenticationException>(() =>
                        untrustedClient.ConnectAndLoginAsync("admin", "AdminSecret!1"));
                }

                cts.Cancel();
                await serverTask;
            }

            // Generate a dedicated ephemeral CA for live Wrong-SAN and Missing-EKU TLS handshake tests
            using RSA testCaKey = RSA.Create(2048);
            var testCaReq = new CertificateRequest("CN=E2E_Test_CA", testCaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            testCaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            testCaReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            using X509Certificate2 testCaCert = testCaReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(10));
            string testCaPath = Path.Combine(_tempDir, "e2e_test_ca.crt");
            File.WriteAllText(testCaPath, testCaCert.ExportCertificatePem());

            // Case 2: Live Wrong SAN / hostname mismatch (cert has DNS:wrong.example.local, client connects to 127.0.0.1)
            {
                using RSA leafKey = RSA.Create(2048);
                var leafReq = new CertificateRequest("CN=wrong.example.local", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                var sanBuilder = new SubjectAlternativeNameBuilder();
                sanBuilder.AddDnsName("wrong.example.local");
                leafReq.CertificateExtensions.Add(sanBuilder.Build());
                leafReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
                using X509Certificate2 wrongSanCert = leafReq.Create(testCaCert, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(5), Guid.NewGuid().ToByteArray());

                string certPath = Path.Combine(_tempDir, "wrong_san.crt");
                string keyPath = Path.Combine(_tempDir, "wrong_san.key");
                File.WriteAllText(certPath, wrongSanCert.ExportCertificatePem());
                File.WriteAllText(keyPath, leafKey.ExportPkcs8PrivateKeyPem());

                using var cts = new CancellationTokenSource();
                using var listener = new SocketConnectionListener(0, certPath, keyPath, auth, storage, logger);
                listener.StartListening();
                Task serverTask = listener.AcceptLoopAsync(cts.Token);

                using (var client = new PvspClientEngine("127.0.0.1", listener.BoundPort, testCaPath))
                {
                    await Assert.ThrowsAsync<AuthenticationException>(() =>
                        client.ConnectAndLoginAsync("admin", "AdminSecret!1"));
                }

                cts.Cancel();
                await serverTask;
            }

            // Case 3: Live Missing EKU serverAuth (cert has valid SAN localhost/127.0.0.1, trusted CA, but only clientAuth EKU)
            {
                using RSA leafKey = RSA.Create(2048);
                var leafReq = new CertificateRequest("CN=localhost", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                var sanBuilder = new SubjectAlternativeNameBuilder();
                sanBuilder.AddDnsName("localhost");
                sanBuilder.AddIpAddress(IPAddress.Loopback);
                leafReq.CertificateExtensions.Add(sanBuilder.Build());
                leafReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, false)); // clientAuth ONLY
                using X509Certificate2 missingEkuCert = leafReq.Create(testCaCert, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(5), Guid.NewGuid().ToByteArray());

                string certPath = Path.Combine(_tempDir, "no_eku.crt");
                string keyPath = Path.Combine(_tempDir, "no_eku.key");
                File.WriteAllText(certPath, missingEkuCert.ExportCertificatePem());
                File.WriteAllText(keyPath, leafKey.ExportPkcs8PrivateKeyPem());

                using var cts = new CancellationTokenSource();
                using var listener = new SocketConnectionListener(0, certPath, keyPath, auth, storage, logger);
                listener.StartListening();
                Task serverTask = listener.AcceptLoopAsync(cts.Token);

                using (var client = new PvspClientEngine("localhost", listener.BoundPort, testCaPath))
                {
                    await Assert.ThrowsAsync<AuthenticationException>(() =>
                        client.ConnectAndLoginAsync("admin", "AdminSecret!1"));
                }

                cts.Cancel();
                await serverTask;
            }
        }

        [Fact]
        public async Task T05_T06_T08_Diagnostics_ShouldTriggerExpectedSecurityAndFramingErrors()
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

            // Test T-08: Corrupted Magic Bytes -> 100 ERR_BAD_MAGIC (with active msgId encoded in header)
            using (var client = new PvspClientEngine("localhost", listener.BoundPort, _caCertPath))
            {
                await client.ConnectAndLoginAsync("admin", "AdminSecret!1");
                var magicRes = await client.SendDiagnosticBadMagicAsync();
                Assert.False(magicRes.IsSuccess);
                Assert.Equal(PvspErrorCodes.BadMagic, magicRes.ErrorCode);
            }

            cts.Cancel();
            await serverTask;

            string auditLog = File.ReadAllText(Path.Combine(_logsDir, "server_audit.log"));
            Assert.Contains("[SECURITY]", auditLog);
            Assert.Contains("HMAC verification failed", auditLog);
            Assert.Contains("Replay detected", auditLog);
            Assert.Contains("Framing error 100", auditLog);
        }

        [Fact]
        public async Task T05_LiveServer_1ByteHmacMutation_ShouldReturn204_LogSecurity_AndCloseSocket()
        {
            var auth = new AuthAndRbacModule(_usersPath);
            var storage = new VaultStorageEngine(_storePath);
            var logger = new SecurityAuditLogger(_logsDir);

            using var cts = new CancellationTokenSource();
            using var listener = new SocketConnectionListener(0, _serverCertPath, _serverKeyPath, auth, storage, logger);
            listener.StartListening();
            Task serverTask = listener.AcceptLoopAsync(cts.Token);

            using (var sslStream = await ConnectRawTlsClientAsync(listener.BoundPort))
            {
                var authAck = await CompleteRawHandshakeAsync(sslStream);
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                var req = new DataReqPayload
                {
                    SessionToken = authAck.SessionToken,
                    Action = "LIST",
                    Timestamp = now
                };
                string validHmac = PvspCryptoHelper.ComputeDataReqHmacHex(authAck.HmacSecret, 3, req);
                // Mutate exactly 1 character in the computed 64-char HMAC
                char flipped = validHmac[0] == 'a' ? 'b' : 'a';
                req.Hmac = flipped + validHmac[1..];

                await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.DataReq, 3, PvspJsonSerializer.SerializeToUtf8Bytes(req), CancellationToken.None);
                FrameReadResult errRes = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
                Assert.Equal(PvspMessageType.Error, errRes.Frame.MessageType);
                Assert.Equal(3u, errRes.Frame.MessageId);
                var err = JsonSerializer.Deserialize<ErrorPayload>(errRes.Frame.PayloadBytes)!;
                Assert.Equal(PvspErrorCodes.InvalidHmac, err.ErrorCode);

                // Verify server immediately closed the TLS/TCP socket after sending 204
                FrameReadResult eofRes = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
                Assert.True(eofRes.IsEof);
            }

            cts.Cancel();
            await serverTask;

            string auditLog = File.ReadAllText(Path.Combine(_logsDir, "server_audit.log"));
            Assert.Contains("[SECURITY]", auditLog);
            Assert.Contains("HMAC verification failed", auditLog);
        }

        [Fact]
        public async Task T06_Server_ShouldRejectMsgIdZero_OldMessageId_Gap_AndModifiedDuplicate_With301AndClose()
        {
            var auth = new AuthAndRbacModule(_usersPath);
            var storage = new VaultStorageEngine(_storePath);
            var logger = new SecurityAuditLogger(_logsDir);

            using var cts = new CancellationTokenSource();
            using var listener = new SocketConnectionListener(0, _serverCertPath, _serverKeyPath, auth, storage, logger);
            listener.StartListening();
            Task serverTask = listener.AcceptLoopAsync(cts.Token);

            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            // 1. MsgID = 0 -> 301 ERR_REPLAY_DETECTED + server closes socket
            using (var sslStream = await ConnectRawTlsClientAsync(listener.BoundPort))
            {
                byte[] helloBytes = PvspJsonSerializer.SerializeToUtf8Bytes(new HelloPayload { ClientName = "PusVault-CLI/1.0", Timestamp = now });
                await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.Hello, 0, helloBytes, CancellationToken.None);

                FrameReadResult errRes = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
                Assert.Equal(PvspErrorCodes.ReplayDetected, JsonSerializer.Deserialize<ErrorPayload>(errRes.Frame.PayloadBytes)!.ErrorCode);
                Assert.True((await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None)).IsEof);
            }

            // 2. Sequence gap (HELLO=1 -> AUTH=5) -> 301 ERR_REPLAY_DETECTED + server closes socket
            using (var sslStream = await ConnectRawTlsClientAsync(listener.BoundPort))
            {
                byte[] helloBytes = PvspJsonSerializer.SerializeToUtf8Bytes(new HelloPayload { ClientName = "PusVault-CLI/1.0", Timestamp = now });
                await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.Hello, 1, helloBytes, CancellationToken.None);
                var helloAck = JsonSerializer.Deserialize<HelloAckPayload>((await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None)).Frame.PayloadBytes)!;

                var authPayload = new AuthPayload { Username = "admin", Password = "AdminSecret!1", ServerNonceEcho = helloAck.ServerNonce, Timestamp = now };
                await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.Auth, 5, PvspJsonSerializer.SerializeToUtf8Bytes(authPayload), CancellationToken.None);

                FrameReadResult errRes = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
                Assert.Equal(PvspErrorCodes.ReplayDetected, JsonSerializer.Deserialize<ErrorPayload>(errRes.Frame.PayloadBytes)!.ErrorCode);
                Assert.True((await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None)).IsEof);
            }

            // 3. Old Message ID (HELLO=1, AUTH=2, LIST=3, then LIST=2) -> 301 ERR_REPLAY_DETECTED + server closes socket
            using (var sslStream = await ConnectRawTlsClientAsync(listener.BoundPort))
            {
                var authAck = await CompleteRawHandshakeAsync(sslStream);

                var list3 = new DataReqPayload { SessionToken = authAck.SessionToken, Action = "LIST", Timestamp = now };
                list3.Hmac = PvspCryptoHelper.ComputeDataReqHmacHex(authAck.HmacSecret, 3, list3);
                await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.DataReq, 3, PvspJsonSerializer.SerializeToUtf8Bytes(list3), CancellationToken.None);
                Assert.Equal(PvspMessageType.DataResp, (await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None)).Frame.MessageType);

                var listOld2 = new DataReqPayload { SessionToken = authAck.SessionToken, Action = "LIST", Timestamp = now };
                listOld2.Hmac = PvspCryptoHelper.ComputeDataReqHmacHex(authAck.HmacSecret, 2, listOld2);
                await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.DataReq, 2, PvspJsonSerializer.SerializeToUtf8Bytes(listOld2), CancellationToken.None);

                FrameReadResult errRes = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
                Assert.Equal(PvspErrorCodes.ReplayDetected, JsonSerializer.Deserialize<ErrorPayload>(errRes.Frame.PayloadBytes)!.ErrorCode);
                Assert.True((await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None)).IsEof);
            }

            // 4. Duplicate Message ID with modified payload digest (LIST=3, then GET=3) -> 301 ERR_REPLAY_DETECTED + server closes socket
            using (var sslStream = await ConnectRawTlsClientAsync(listener.BoundPort))
            {
                var authAck = await CompleteRawHandshakeAsync(sslStream);

                var list3 = new DataReqPayload { SessionToken = authAck.SessionToken, Action = "LIST", Timestamp = now };
                list3.Hmac = PvspCryptoHelper.ComputeDataReqHmacHex(authAck.HmacSecret, 3, list3);
                await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.DataReq, 3, PvspJsonSerializer.SerializeToUtf8Bytes(list3), CancellationToken.None);
                Assert.Equal(PvspMessageType.DataResp, (await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None)).Frame.MessageType);

                var tampered3 = new DataReqPayload { SessionToken = authAck.SessionToken, Action = "GET", Key = "ANY", Timestamp = now };
                tampered3.Hmac = PvspCryptoHelper.ComputeDataReqHmacHex(authAck.HmacSecret, 3, tampered3);
                await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.DataReq, 3, PvspJsonSerializer.SerializeToUtf8Bytes(tampered3), CancellationToken.None);

                FrameReadResult errRes = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
                Assert.Equal(PvspErrorCodes.ReplayDetected, JsonSerializer.Deserialize<ErrorPayload>(errRes.Frame.PayloadBytes)!.ErrorCode);
                Assert.True((await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None)).IsEof);
            }

            cts.Cancel();
            await serverTask;
        }

        [Fact]
        public async Task T08_LiveServer_ShouldRejectAllFramingErrors_100_101_102_103_AndCloseConnection()
        {
            var auth = new AuthAndRbacModule(_usersPath);
            var storage = new VaultStorageEngine(_storePath);
            var logger = new SecurityAuditLogger(_logsDir);

            using var cts = new CancellationTokenSource();
            using var listener = new SocketConnectionListener(0, _serverCertPath, _serverKeyPath, auth, storage, logger);
            listener.StartListening();
            Task serverTask = listener.AcceptLoopAsync(cts.Token);

            // 1. 100 ERR_BAD_MAGIC (with explicit MsgID = 7 echoed back)
            using (var sslStream = await ConnectRawTlsClientAsync(listener.BoundPort))
            {
                byte[] hdr = PvspFrameCodec.EncodeFrame(PvspMessageType.Ping, 7);
                hdr[0] = 0x00;
                hdr[1] = 0x00;
                await sslStream.WriteAsync(hdr);
                await sslStream.FlushAsync();

                FrameReadResult res = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
                Assert.Equal(PvspMessageType.Error, res.Frame.MessageType);
                Assert.Equal(7u, res.Frame.MessageId);
                Assert.Equal(PvspErrorCodes.BadMagic, JsonSerializer.Deserialize<ErrorPayload>(res.Frame.PayloadBytes)!.ErrorCode);
                Assert.True((await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None)).IsEof);
            }

            // 2. 101 ERR_UNSUPPORTED_VERSION
            using (var sslStream = await ConnectRawTlsClientAsync(listener.BoundPort))
            {
                byte[] hdr = PvspFrameCodec.EncodeFrame(PvspMessageType.Hello, 1);
                hdr[2] = 0x02;
                await sslStream.WriteAsync(hdr);
                await sslStream.FlushAsync();

                FrameReadResult res = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
                Assert.Equal(PvspErrorCodes.UnsupportedVersion, JsonSerializer.Deserialize<ErrorPayload>(res.Frame.PayloadBytes)!.ErrorCode);
                Assert.True((await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None)).IsEof);
            }

            // 3. 102 ERR_UNKNOWN_MSG_TYPE
            using (var sslStream = await ConnectRawTlsClientAsync(listener.BoundPort))
            {
                byte[] hdr = PvspFrameCodec.EncodeFrame(PvspMessageType.Hello, 1);
                hdr[3] = 0x99;
                await sslStream.WriteAsync(hdr);
                await sslStream.FlushAsync();

                FrameReadResult res = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
                Assert.Equal(PvspErrorCodes.UnknownMsgType, JsonSerializer.Deserialize<ErrorPayload>(res.Frame.PayloadBytes)!.ErrorCode);
                Assert.True((await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None)).IsEof);
            }

            // 4. 103 ERR_PAYLOAD_TOO_LARGE (12-byte header declaring 70,000 B, 0 payload bytes transmitted)
            using (var sslStream = await ConnectRawTlsClientAsync(listener.BoundPort))
            {
                byte[] hdr = PvspFrameCodec.EncodeFrame(PvspMessageType.DataReq, 1);
                BinaryPrimitives.WriteUInt32BigEndian(hdr.AsSpan(8, 4), 70000u);
                await sslStream.WriteAsync(hdr);
                await sslStream.FlushAsync();

                FrameReadResult res = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
                Assert.Equal(PvspErrorCodes.PayloadTooLarge, JsonSerializer.Deserialize<ErrorPayload>(res.Frame.PayloadBytes)!.ErrorCode);
                Assert.True((await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None)).IsEof);
            }

            cts.Cancel();
            await serverTask;
        }

        [Fact]
        public async Task T07_LiveServer_ShouldReassembleFragmentedHello_3BytesEvery50ms()
        {
            var auth = new AuthAndRbacModule(_usersPath);
            var storage = new VaultStorageEngine(_storePath);
            var logger = new SecurityAuditLogger(_logsDir);

            using var cts = new CancellationTokenSource();
            using var listener = new SocketConnectionListener(0, _serverCertPath, _serverKeyPath, auth, storage, logger);
            listener.StartListening();
            Task serverTask = listener.AcceptLoopAsync(cts.Token);

            using var sslStream = await ConnectRawTlsClientAsync(listener.BoundPort);

            // Build exact 56-byte HELLO payload (total frame = 68 bytes) and drip-feed 3 bytes every 50 ms
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            byte[] helloPayload = PvspJsonSerializer.SerializeToUtf8Bytes(new HelloPayload { ClientName = "PusVault-CLI/1.0", Timestamp = now });
            Assert.Equal(56, helloPayload.Length);

            byte[] fullFrame = PvspFrameCodec.EncodeFrame(PvspMessageType.Hello, 1, helloPayload);
            for (int offset = 0; offset < fullFrame.Length; offset += 3)
            {
                int chunkSize = Math.Min(3, fullFrame.Length - offset);
                await sslStream.WriteAsync(fullFrame.AsMemory(offset, chunkSize));
                await sslStream.FlushAsync();
                await Task.Delay(50);
            }

            FrameReadResult ackRes = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
            Assert.Equal(PvspMessageType.HelloAck, ackRes.Frame.MessageType);
            Assert.Equal(1u, ackRes.Frame.MessageId);

            cts.Cancel();
            await serverTask;
        }

        [Fact]
        public async Task T09_T02_ClientEngine_ShouldAutoReconnectOnGet_AfterServerRestart()
        {
            var auth = new AuthAndRbacModule(_usersPath);
            var storage = new VaultStorageEngine(_storePath);
            var logger = new SecurityAuditLogger(_logsDir);

            using var cts1 = new CancellationTokenSource();
            var listener1 = new SocketConnectionListener(0, _serverCertPath, _serverKeyPath, auth, storage, logger);
            listener1.StartListening();
            int port = listener1.BoundPort;
            Task serverTask1 = listener1.AcceptLoopAsync(cts1.Token);

            var fastBackoff = new[] { TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(200), TimeSpan.FromMilliseconds(400) };
            using var client = new PvspClientEngine("localhost", port, _caCertPath, TimeSpan.FromSeconds(2), fastBackoff);

            await client.ConnectAndLoginAsync("admin", "AdminSecret!1");
            Assert.True((await client.ExecuteDataRequestAsync("SET", "DB_HOST", "10.0.0.5")).IsSuccess);

            // Simulate sudden server crash
            cts1.Cancel();
            listener1.Dispose();
            await serverTask1;

            // Restart Server instance #2 on the same TCP port loading persisted vault_store.json
            var storageReloaded = new VaultStorageEngine(_storePath);
            using var cts2 = new CancellationTokenSource();
            using var listener2 = new SocketConnectionListener(port, _serverCertPath, _serverKeyPath, auth, storageReloaded, logger);
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

        [Fact]
        public async Task T09_ClientEngine_ShouldNotRetrySetMutation_WhenConnectionDropsAfterSend()
        {
            using var serverCert = X509Certificate2.CreateFromPemFile(_serverCertPath, _serverKeyPath);
            using var listenSocket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp)
            {
                DualMode = true
            };
            listenSocket.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
            listenSocket.Listen(5);
            int port = ((IPEndPoint)listenSocket.LocalEndPoint!).Port;

            Task fakeServerTask = Task.Run(async () =>
            {
                using Socket s1 = await listenSocket.AcceptAsync();
                using var ns1 = new NetworkStream(s1, ownsSocket: true);
                using var ssl1 = new SslStream(ns1, false);
                await ssl1.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = serverCert,
                    EnabledSslProtocols = SslProtocols.Tls13
                });

                // 1. Read HELLO -> send HELLO_ACK
                await PvspFrameCodec.ReadFrameAsync(ssl1, CancellationToken.None);
                var helloAck = new HelloAckPayload { ServerVersion = "Fake/1.0", ServerNonce = new string('A', 32), Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() };
                await PvspFrameCodec.WriteFrameAsync(ssl1, PvspMessageType.HelloAck, 1, PvspJsonSerializer.SerializeToUtf8Bytes(helloAck), CancellationToken.None);

                // 2. Read AUTH -> send AUTH_ACK
                await PvspFrameCodec.ReadFrameAsync(ssl1, CancellationToken.None);
                var authAck = new AuthAckPayload { SessionToken = PvspCryptoHelper.GenerateSessionToken(), HmacSecret = PvspCryptoHelper.GenerateHmacSecretBase64(), Role = "READ_WRITE" };
                await PvspFrameCodec.WriteFrameAsync(ssl1, PvspMessageType.AuthAck, 2, PvspJsonSerializer.SerializeToUtf8Bytes(authAck), CancellationToken.None);

                // 3. Read SET DATA_REQ and abruptly crash the server (close client + listener sockets without replying!)
                await PvspFrameCodec.ReadFrameAsync(ssl1, CancellationToken.None);
                s1.Close();
                listenSocket.Close();
            });

            var fastBackoff = new[] { TimeSpan.FromMilliseconds(50), TimeSpan.FromMilliseconds(50), TimeSpan.FromMilliseconds(50) };
            using var client = new PvspClientEngine("localhost", port, _caCertPath, TimeSpan.FromSeconds(1), fastBackoff, tlsHandshakeTimeout: TimeSpan.FromSeconds(1));

            var login = await client.ConnectAndLoginAsync("admin", "AdminSecret!1");
            Assert.True(login.Success);

            ClientOperationResult setRes = await client.ExecuteDataRequestAsync("SET", "CRITICAL_KEY", "Val1");
            Assert.False(setRes.IsSuccess);
            Assert.True(setRes.IsUnknownMutationOutcome);

            await fakeServerTask;
        }

        [Fact]
        public async Task T09_ClientEngine_SendPing_ShouldTearDownStaleTransportAndRecoverViaAutoReconnect()
        {
            using var serverCert = X509Certificate2.CreateFromPemFile(_serverCertPath, _serverKeyPath);
            using var listenSocket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp)
            {
                DualMode = true
            };
            listenSocket.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
            listenSocket.Listen(5);
            int port = ((IPEndPoint)listenSocket.LocalEndPoint!).Port;

            using var stallRelease = new CancellationTokenSource();

            Task fakeServerTask = Task.Run(async () =>
            {
                Socket s1 = await listenSocket.AcceptAsync();
                Task holdFirstConn = Task.Run(async () =>
                {
                    using (s1)
                    using (var ns1 = new NetworkStream(s1, ownsSocket: true))
                    using (var ssl1 = new SslStream(ns1, false))
                    {
                        await ssl1.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                        {
                            ServerCertificate = serverCert,
                            EnabledSslProtocols = SslProtocols.Tls13
                        });

                        await PvspFrameCodec.ReadFrameAsync(ssl1, CancellationToken.None);
                        var helloAck1 = new HelloAckPayload { ServerVersion = "Fake/1.0", ServerNonce = new string('A', 32), Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() };
                        await PvspFrameCodec.WriteFrameAsync(ssl1, PvspMessageType.HelloAck, 1, PvspJsonSerializer.SerializeToUtf8Bytes(helloAck1), CancellationToken.None);

                        await PvspFrameCodec.ReadFrameAsync(ssl1, CancellationToken.None);
                        var authAck1 = new AuthAckPayload { SessionToken = PvspCryptoHelper.GenerateSessionToken(), HmacSecret = PvspCryptoHelper.GenerateHmacSecretBase64(), Role = "READ_WRITE" };
                        await PvspFrameCodec.WriteFrameAsync(ssl1, PvspMessageType.AuthAck, 2, PvspJsonSerializer.SerializeToUtf8Bytes(authAck1), CancellationToken.None);

                        await PvspFrameCodec.ReadFrameAsync(ssl1, CancellationToken.None);
                        try { await Task.Delay(Timeout.Infinite, stallRelease.Token); } catch (OperationCanceledException) { }
                    }
                });

                using (Socket s2 = await listenSocket.AcceptAsync())
                using (var ns2 = new NetworkStream(s2, ownsSocket: true))
                using (var ssl2 = new SslStream(ns2, false))
                {
                    await ssl2.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificate = serverCert,
                        EnabledSslProtocols = SslProtocols.Tls13
                    });

                    await PvspFrameCodec.ReadFrameAsync(ssl2, CancellationToken.None);
                    var helloAck2 = new HelloAckPayload { ServerVersion = "Fake/1.0", ServerNonce = new string('B', 32), Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() };
                    await PvspFrameCodec.WriteFrameAsync(ssl2, PvspMessageType.HelloAck, 1, PvspJsonSerializer.SerializeToUtf8Bytes(helloAck2), CancellationToken.None);

                    await PvspFrameCodec.ReadFrameAsync(ssl2, CancellationToken.None);
                    var authAck2 = new AuthAckPayload { SessionToken = PvspCryptoHelper.GenerateSessionToken(), HmacSecret = PvspCryptoHelper.GenerateHmacSecretBase64(), Role = "READ_WRITE" };
                    await PvspFrameCodec.WriteFrameAsync(ssl2, PvspMessageType.AuthAck, 2, PvspJsonSerializer.SerializeToUtf8Bytes(authAck2), CancellationToken.None);

                    FrameReadResult ping2 = await PvspFrameCodec.ReadFrameAsync(ssl2, CancellationToken.None);
                    Assert.Equal(PvspMessageType.Ping, ping2.Frame.MessageType);
                    await PvspFrameCodec.WriteFrameAsync(ssl2, PvspMessageType.Pong, ping2.Frame.MessageId, Array.Empty<byte>(), CancellationToken.None);

                    s2.Close();
                }

                listenSocket.Close();
                stallRelease.Cancel();
                await holdFirstConn;
            });

            var fastBackoff = new[] { TimeSpan.FromMilliseconds(50), TimeSpan.FromMilliseconds(50), TimeSpan.FromMilliseconds(50) };
            using var client = new PvspClientEngine("localhost", port, _caCertPath, TimeSpan.FromMilliseconds(300), fastBackoff);

            var login = await client.ConnectAndLoginAsync("admin", "AdminSecret!1");
            Assert.True(login.Success);

            bool recovered = await client.SendPingAsync();
            Assert.True(recovered);
            Assert.True(client.IsAuthenticated);

            await fakeServerTask;

            bool afterShutdown = await client.SendPingAsync();
            Assert.False(afterShutdown);
            Assert.False(client.IsAuthenticated);
        }

        [Fact]
        public async Task T10_RateLimiter_ShouldAllow20Requests_AndRejectRemainingWith429()
        {
            var auth = new AuthAndRbacModule(_usersPath);
            var storage = new VaultStorageEngine(_storePath);
            var logger = new SecurityAuditLogger(_logsDir);

            using var cts = new CancellationTokenSource();
            using var listener = new SocketConnectionListener(0, _serverCertPath, _serverKeyPath, auth, storage, logger);
            listener.StartListening();
            Task serverTask = listener.AcceptLoopAsync(cts.Token);

            using (var client = new PvspClientEngine("localhost", listener.BoundPort, _caCertPath))
            {
                await client.ConnectAndLoginAsync("admin", "AdminSecret!1");

                for (int i = 1; i <= 20; i++)
                {
                    var okRes = await client.ExecuteDataRequestAsync("LIST");
                    Assert.True(okRes.IsSuccess);
                }

                for (int i = 21; i <= 25; i++)
                {
                    var limitedRes = await client.ExecuteDataRequestAsync("LIST");
                    Assert.False(limitedRes.IsSuccess);
                    Assert.Equal(PvspErrorCodes.RateLimit, limitedRes.ErrorCode);
                }

                await client.DisconnectAsync();
            }

            cts.Cancel();
            await serverTask;
        }

        [Fact]
        public async Task T10_LoadTest_50ConcurrentSessions_ShouldMeetLatencyTargetAndReportPercentiles()
        {
            var auth = new AuthAndRbacModule(_usersPath);
            var storage = new VaultStorageEngine(_storePath);
            var logger = new SecurityAuditLogger(_logsDir);

            storage.SetSecret("BENCH_KEY", "BenchSecretValue123");

            int recordServerMetrics = 0;
            var serverGetMs = new ConcurrentBag<double>();
            var serverSetMs = new ConcurrentBag<double>();

            void OnServerDataReq(string action, double elapsedMs)
            {
                if (Volatile.Read(ref recordServerMetrics) == 0)
                    return;

                if (action == "GET") serverGetMs.Add(elapsedMs);
                else if (action == "SET") serverSetMs.Add(elapsedMs);
            }

            // Use production defaults: maxConcurrentSessions = 64, maxConcurrentHandshakes = 32
            using var cts = new CancellationTokenSource();
            using var listener = new SocketConnectionListener(
                0, _serverCertPath, _serverKeyPath, auth, storage, logger,
                maxConcurrentSessions: 64,
                maxConcurrentHandshakes: 32,
                onDataReqCompleted: OnServerDataReq);
            listener.StartListening();
            Task serverTask = listener.AcceptLoopAsync(cts.Token);

            const int sessionCount = 50;
            var clients = new List<PvspClientEngine>(sessionCount);

            try
            {
                // 1. Connect and authenticate 50 concurrent sessions (warm-up TLS + PBKDF2 handshakes under default handshake limit 32)
                Task[] loginTasks = new Task[sessionCount];
                for (int i = 0; i < sessionCount; i++)
                {
                    var c = new PvspClientEngine("localhost", listener.BoundPort, _caCertPath);
                    clients.Add(c);
                    loginTasks[i] = Task.Run(async () =>
                    {
                        var res = await c.ConnectAndLoginAsync("admin", "AdminSecret!1");
                        Assert.True(res.Success, res.Message);
                    });
                }
                await Task.WhenAll(loginTasks);

                // Warm-up pass (1 GET per session, excluded from metrics)
                await Task.WhenAll(clients.Select(c => c.ExecuteDataRequestAsync("GET", "BENCH_KEY")));

                Volatile.Write(ref recordServerMetrics, 1);

                // 2. Measured GET pass: 50 concurrent active sessions each executing 4 sequential GETs (200 samples)
                var rttGetMs = new ConcurrentBag<double>();
                Task[] getTasks = clients.Select(client => Task.Run(async () =>
                {
                    for (int req = 0; req < 4; req++)
                    {
                        var sw = Stopwatch.StartNew();
                        ClientOperationResult res = await client.ExecuteDataRequestAsync("GET", "BENCH_KEY");
                        sw.Stop();

                        Assert.True(res.IsSuccess, res.Message);
                        Assert.Equal("BenchSecretValue123", res.Value);
                        rttGetMs.Add(sw.Elapsed.TotalMilliseconds);
                    }
                })).ToArray();
                await Task.WhenAll(getTasks);

                // 3. Measured SET pass while all 50 sessions stay active: each active session executes 1 sequential persisted SET (50 samples)
                var rttSetMs = new List<double>(sessionCount);
                for (int i = 0; i < sessionCount; i++)
                {
                    var sw = Stopwatch.StartNew();
                    ClientOperationResult res = await clients[i].ExecuteDataRequestAsync("SET", $"BENCH_SET_{i:D2}", $"Value_{i:D2}");
                    sw.Stop();

                    Assert.True(res.IsSuccess, res.Message);
                    rttSetMs.Add(sw.Elapsed.TotalMilliseconds);
                }

                Volatile.Write(ref recordServerMetrics, 0);

                var (getRttAvg, getRttP50, getRttP95) = ComputeStats(rttGetMs);
                var (getSrvAvg, getSrvP50, getSrvP95) = ComputeStats(serverGetMs);
                var (setRttAvg, setRttP50, setRttP95) = ComputeStats(rttSetMs);
                var (setSrvAvg, setSrvP50, setSrvP95) = ComputeStats(serverSetMs);

                _output.WriteLine($"[T-10 BENCHMARK REPORT] Environment: {RuntimeInformation.OSDescription} | {RuntimeInformation.FrameworkDescription} | CPUs: {Environment.ProcessorCount}");
                _output.WriteLine($"[T-10 BENCHMARK REPORT] Active Sessions: {sessionCount} (maxSessions=64, maxHandshakes=32)");
                _output.WriteLine($"[T-10 BENCHMARK REPORT] GET (n={rttGetMs.Count}, concurrent) Client RTT  -> Avg: {getRttAvg:F2} ms | p50: {getRttP50:F2} ms | p95: {getRttP95:F2} ms");
                _output.WriteLine($"[T-10 BENCHMARK REPORT] GET (n={serverGetMs.Count}, concurrent) Server Time -> Avg: {getSrvAvg:F2} ms | p50: {getSrvP50:F2} ms | p95: {getSrvP95:F2} ms (Target Avg < 15.00 ms)");
                _output.WriteLine($"[T-10 BENCHMARK REPORT] SET (n={rttSetMs.Count}, sequential) Client RTT  -> Avg: {setRttAvg:F2} ms | p50: {setRttP50:F2} ms | p95: {setRttP95:F2} ms");
                _output.WriteLine($"[T-10 BENCHMARK REPORT] SET (n={serverSetMs.Count}, sequential) Server Time -> Avg: {setSrvAvg:F2} ms | p50: {setSrvP50:F2} ms | p95: {setSrvP95:F2} ms (Target Avg < 15.00 ms)");

                Assert.Equal(200, rttGetMs.Count);
                Assert.Equal(200, serverGetMs.Count);
                Assert.Equal(50, rttSetMs.Count);
                Assert.Equal(50, serverSetMs.Count);

                Assert.True(getSrvAvg < 15.0, $"Expected GET average server processing time < 15 ms, got {getSrvAvg:F2} ms.");
                Assert.True(setSrvAvg < 15.0, $"Expected SET average server processing time < 15 ms, got {setSrvAvg:F2} ms.");
            }
            finally
            {
                foreach (var c in clients)
                {
                    await c.DisconnectAsync();
                    c.Dispose();
                }
                cts.Cancel();
                await serverTask;
            }
        }

        [Fact]
        public async Task T11_LiveServer_ShouldEnforceAllValidationCodes_104_106_107_108_AndKeepSessionAlive()
        {
            var auth = new AuthAndRbacModule(_usersPath);
            var logger = new SecurityAuditLogger(_logsDir);

            // Pre-populate storage with 1,001 keys directly in file to trigger 108 ERR_RESPONSE_TOO_LARGE on LIST (> 1,000 keys)
            Directory.CreateDirectory(Path.GetDirectoryName(_storePath)!);
            var hugeDict = new Dictionary<string, string>();
            for (int i = 0; i < 1001; i++)
            {
                hugeDict[$"KEY_{i:D4}"] = "v";
            }
            File.WriteAllText(_storePath, JsonSerializer.Serialize(hugeDict));
            var storage = new VaultStorageEngine(_storePath);

            using var cts = new CancellationTokenSource();
            using var listener = new SocketConnectionListener(0, _serverCertPath, _serverKeyPath, auth, storage, logger);
            listener.StartListening();
            Task serverTask = listener.AcceptLoopAsync(cts.Token);

            using var sslStream = await ConnectRawTlsClientAsync(listener.BoundPort);
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            // 1. Send broken JSON syntax in HELLO (MsgID=1) -> 104 ERR_INVALID_JSON (connection stays open, consumes MsgID=1)
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.Hello, 1, Encoding.UTF8.GetBytes("{broken_json"), CancellationToken.None);
            FrameReadResult res104 = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
            Assert.Equal(PvspErrorCodes.InvalidJson, JsonSerializer.Deserialize<ErrorPayload>(res104.Frame.PayloadBytes)!.ErrorCode);

            // 2. Send unknown field in HELLO (MsgID=2) -> 106 ERR_INVALID_PAYLOAD (connection stays open, consumes MsgID=2)
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.Hello, 2, Encoding.UTF8.GetBytes("{\"clientName\":\"Pus\",\"timestamp\":123,\"unknown\":1}"), CancellationToken.None);
            FrameReadResult res106 = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
            Assert.Equal(PvspErrorCodes.InvalidPayload, JsonSerializer.Deserialize<ErrorPayload>(res106.Frame.PayloadBytes)!.ErrorCode);

            // 3. Complete valid HELLO (MsgID=3) and AUTH (MsgID=4)
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.Hello, 3, PvspJsonSerializer.SerializeToUtf8Bytes(new HelloPayload { ClientName = "Pus/1.0", Timestamp = now }), CancellationToken.None);
            var helloAck = JsonSerializer.Deserialize<HelloAckPayload>((await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None)).Frame.PayloadBytes)!;

            var authReq = new AuthPayload { Username = "admin", Password = "AdminSecret!1", ServerNonceEcho = helloAck.ServerNonce, Timestamp = now };
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.Auth, 4, PvspJsonSerializer.SerializeToUtf8Bytes(authReq), CancellationToken.None);
            var authAck = JsonSerializer.Deserialize<AuthAckPayload>((await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None)).Frame.PayloadBytes)!;

            // 4. Send DATA_REQ with action="LIST" but including a 'key' field (MsgID=5) -> 107 ERR_INVALID_ACTION (connection stays open, consumes MsgID=5)
            var invalidActionReq = new DataReqPayload { SessionToken = authAck.SessionToken, Action = "LIST", Key = "UNEXPECTED_KEY", Timestamp = now, Hmac = new string('a', 64) };
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.DataReq, 5, PvspJsonSerializer.SerializeToUtf8Bytes(invalidActionReq), CancellationToken.None);
            FrameReadResult res107 = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
            Assert.Equal(PvspErrorCodes.InvalidAction, JsonSerializer.Deserialize<ErrorPayload>(res107.Frame.PayloadBytes)!.ErrorCode);

            // 5. Send valid LIST (MsgID=6) when vault has 1,001 keys (> 1,000 limit) -> 108 ERR_RESPONSE_TOO_LARGE
            var listReq = new DataReqPayload { SessionToken = authAck.SessionToken, Action = "LIST", Timestamp = now };
            listReq.Hmac = PvspCryptoHelper.ComputeDataReqHmacHex(authAck.HmacSecret, 6, listReq);
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.DataReq, 6, PvspJsonSerializer.SerializeToUtf8Bytes(listReq), CancellationToken.None);
            FrameReadResult res108 = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
            Assert.Equal(PvspErrorCodes.ResponseTooLarge, JsonSerializer.Deserialize<ErrorPayload>(res108.Frame.PayloadBytes)!.ErrorCode);

            cts.Cancel();
            await serverTask;
        }

        [Fact]
        public async Task LiveServer_ShouldEnforceTlsHandshakeTimeout_KeepAliveWorker_Ipv6Loopback_AndStructuredClientLogs()
        {
            var auth = new AuthAndRbacModule(_usersPath);
            var storage = new VaultStorageEngine(_storePath);
            var logger = new SecurityAuditLogger(_logsDir);

            using var cts = new CancellationTokenSource();
            using var listener = new SocketConnectionListener(
                0, _serverCertPath, _serverKeyPath, auth, storage, logger,
                tlsHandshakeTimeout: TimeSpan.FromMilliseconds(350),
                idleTimeout: TimeSpan.FromMilliseconds(750));
            listener.StartListening();
            Task serverTask = listener.AcceptLoopAsync(cts.Token);

            // 1. TLS Handshake timeout: connect raw TCP socket and send zero bytes -> server closes socket cleanly
            using (var rawSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                await rawSocket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, listener.BoundPort));
                using var readCts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                byte[] probe = new byte[1];
                int bytesRead = await rawSocket.ReceiveAsync(probe, SocketFlags.None, readCts.Token);
                Assert.Equal(0, bytesRead);
            }

            // 2. Native IPv6 (::1) Dual-Stack connection + KeepAliveWorker keeping session alive past 750ms idleTimeout + structured UTC logs
            var capturedLogs = new ConcurrentQueue<string>();
            using (var ipv6Client = new PvspClientEngine("::1", listener.BoundPort, _caCertPath))
            {
                ipv6Client.OnDiagnosticLog = msg => capturedLogs.Enqueue(msg);

                var loginRes = await ipv6Client.ConnectAndLoginAsync("admin", "AdminSecret!1");
                Assert.True(loginRes.Success, loginRes.Message);

                Assert.True((await ipv6Client.ExecuteDataRequestAsync("SET", "IPV6_SECRET", "SuperSecretIpv6Value!")).IsSuccess);

                using var keepAlive = new KeepAliveWorker(
                    ipv6Client,
                    keepAliveInterval: TimeSpan.FromMilliseconds(220),
                    pollInterval: TimeSpan.FromMilliseconds(50));
                keepAlive.Start();

                // Sleep well beyond the 750ms server idleTimeout -> KeepAliveWorker PINGs must keep session alive
                await Task.Delay(1150);

                var getRes = await ipv6Client.ExecuteDataRequestAsync("GET", "IPV6_SECRET");
                Assert.True(getRes.IsSuccess, getRes.Message);
                Assert.Equal("SuperSecretIpv6Value!", getRes.Value);

                await keepAlive.StopAsync();
                await ipv6Client.DisconnectAsync();
            }

            cts.Cancel();
            await serverTask;

            // Verify structured UTC client logs format and secret/password redaction
            string allClientLogs = string.Join("\n", capturedLogs);
            Assert.Contains("UTC]", allClientLogs);
            Assert.Contains("[Session:::1:", allClientLogs);
            Assert.DoesNotContain("AdminSecret!1", allClientLogs);
            Assert.DoesNotContain("SuperSecretIpv6Value!", allClientLogs);

            // Verify server logged TLS handshake timeout
            string serverAudit = File.ReadAllText(Path.Combine(_logsDir, "server_audit.log"));
            Assert.Contains("TLS handshake timed out.", serverAudit);
        }

        private async Task<SslStream> ConnectRawTlsClientAsync(int port)
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port));
            var netStream = new NetworkStream(socket, ownsSocket: true);
            var sslStream = new SslStream(
                netStream,
                false,
                (_, cert, chain, errors) => PvspCryptoHelper.ValidateServerCertificateCustomCa(cert, chain, errors, _caCertPath));

            await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                EnabledSslProtocols = SslProtocols.Tls13
            });

            return sslStream;
        }

        private static async Task<AuthAckPayload> CompleteRawHandshakeAsync(SslStream sslStream)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.Hello, 1,
                PvspJsonSerializer.SerializeToUtf8Bytes(new HelloPayload { ClientName = "RawProbe/1.0", Timestamp = now }), CancellationToken.None);
            var helloAck = JsonSerializer.Deserialize<HelloAckPayload>((await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None)).Frame.PayloadBytes)!;

            var authReq = new AuthPayload { Username = "admin", Password = "AdminSecret!1", ServerNonceEcho = helloAck.ServerNonce, Timestamp = now };
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.Auth, 2, PvspJsonSerializer.SerializeToUtf8Bytes(authReq), CancellationToken.None);
            FrameReadResult authAckRes = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
            Assert.Equal(PvspMessageType.AuthAck, authAckRes.Frame.MessageType);
            return JsonSerializer.Deserialize<AuthAckPayload>(authAckRes.Frame.PayloadBytes)!;
        }

        private static (double Avg, double P50, double P95) ComputeStats(IEnumerable<double> samples)
        {
            double[] sorted = samples.OrderBy(x => x).ToArray();
            if (sorted.Length == 0)
                return (0, 0, 0);

            double avg = sorted.Average();
            double p50 = sorted[(int)((sorted.Length - 1) * 0.50)];
            double p95 = sorted[(int)((sorted.Length - 1) * 0.95)];
            return (avg, p50, p95);
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
            for (int attempt = 0; attempt < 5; attempt++)
            {
                try
                {
                    if (Directory.Exists(_tempDir))
                    {
                        Directory.Delete(_tempDir, recursive: true);
                    }
                    break;
                }
                catch (IOException)
                {
                    Thread.Sleep(50);
                }
            }
        }
    }
}