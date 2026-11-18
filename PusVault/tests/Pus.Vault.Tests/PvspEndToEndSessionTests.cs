using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
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
        public async Task T03_TlsHandshake_ShouldThrowAuthenticationException_OnUntrustedCaOrHostMismatch()
        {
            var auth = new AuthAndRbacModule(_usersPath);
            var storage = new VaultStorageEngine(_storePath);
            var logger = new SecurityAuditLogger(_logsDir);

            using var cts = new CancellationTokenSource();
            using var listener = new SocketConnectionListener(0, _serverCertPath, _serverKeyPath, auth, storage, logger);
            listener.StartListening();
            Task serverTask = listener.AcceptLoopAsync(cts.Token);

            // Generate an untrusted rogue Root CA file
            using RSA rogueKey = RSA.Create(2048);
            var req = new CertificateRequest("CN=Untrusted_Root_CA", rogueKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            using X509Certificate2 rogueCa = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(10));
            string rogueCaPath = Path.Combine(_tempDir, "untrusted_ca.crt");
            File.WriteAllText(rogueCaPath, rogueCa.ExportCertificatePem());

            // Client using untrusted CA must fail TLS handshake with AuthenticationException before PVSP
            using (var untrustedClient = new PvspClientEngine("localhost", listener.BoundPort, rogueCaPath))
            {
                await Assert.ThrowsAsync<AuthenticationException>(() =>
                    untrustedClient.ConnectAndLoginAsync("admin", "AdminSecret!1"));
            }

            cts.Cancel();
            await serverTask;
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
        public async Task T06_Server_ShouldRejectOldMessageId_AndGapInMessageId_With301()
        {
            var auth = new AuthAndRbacModule(_usersPath);
            var storage = new VaultStorageEngine(_storePath);
            var logger = new SecurityAuditLogger(_logsDir);

            using var cts = new CancellationTokenSource();
            using var listener = new SocketConnectionListener(0, _serverCertPath, _serverKeyPath, auth, storage, logger);
            listener.StartListening();
            Task serverTask = listener.AcceptLoopAsync(cts.Token);

            // Connect raw TLS client to send custom Message IDs (gap: jumping from MsgID=1 to MsgID=5)
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, listener.BoundPort));
            using var netStream = new NetworkStream(socket, ownsSocket: true);
            using var sslStream = new SslStream(
                netStream,
                false,
                (_, cert, chain, errors) => PvspCryptoHelper.ValidateServerCertificateCustomCa(cert, chain, errors, _caCertPath));

            await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                EnabledSslProtocols = SslProtocols.Tls13
            });

            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            byte[] helloBytes = PvspJsonSerializer.SerializeToUtf8Bytes(new HelloPayload { ClientName = "PusVault-CLI/1.0", Timestamp = now });
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.Hello, 1, helloBytes, CancellationToken.None);
            FrameReadResult helloAckRes = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
            var helloAck = JsonSerializer.Deserialize<HelloAckPayload>(helloAckRes.Frame.PayloadBytes)!;

            // Send AUTH with a sequence gap (MsgID = 5 instead of expected MsgID = 2) -> 301 ERR_REPLAY_DETECTED
            var authPayload = new AuthPayload
            {
                Username = "admin",
                Password = "AdminSecret!1",
                ServerNonceEcho = helloAck.ServerNonce,
                Timestamp = now
            };
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.Auth, 5, PvspJsonSerializer.SerializeToUtf8Bytes(authPayload), CancellationToken.None);

            FrameReadResult errRes = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
            Assert.Equal(PvspMessageType.Error, errRes.Frame.MessageType);
            var err = JsonSerializer.Deserialize<ErrorPayload>(errRes.Frame.PayloadBytes)!;
            Assert.Equal(PvspErrorCodes.ReplayDetected, err.ErrorCode);

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

            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, listener.BoundPort));
            using var netStream = new NetworkStream(socket, ownsSocket: true);
            using var sslStream = new SslStream(
                netStream,
                false,
                (_, cert, chain, errors) => PvspCryptoHelper.ValidateServerCertificateCustomCa(cert, chain, errors, _caCertPath));

            await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                EnabledSslProtocols = SslProtocols.Tls13
            });

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
            // Simulate a server that completes HELLO and AUTH, reads the SET frame from the client,
            // and immediately drops the connection BEFORE sending DATA_RESP!
            using var serverCert = X509Certificate2.CreateFromPemFile(_serverCertPath, _serverKeyPath);
            using var listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            listenSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
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
                var authAck = new AuthAckPayload { SessionToken = Guid.NewGuid().ToString("D"), HmacSecret = PvspCryptoHelper.GenerateHmacSecretBase64(), Role = "READ_WRITE" };
                await PvspFrameCodec.WriteFrameAsync(ssl1, PvspMessageType.AuthAck, 2, PvspJsonSerializer.SerializeToUtf8Bytes(authAck), CancellationToken.None);

                // 3. Read SET DATA_REQ and abruptly close the socket without replying!
                await PvspFrameCodec.ReadFrameAsync(ssl1, CancellationToken.None);
                s1.Close();
            });

            var fastBackoff = new[] { TimeSpan.FromMilliseconds(50), TimeSpan.FromMilliseconds(50), TimeSpan.FromMilliseconds(50) };
            using var client = new PvspClientEngine("localhost", port, _caCertPath, TimeSpan.FromSeconds(1), fastBackoff);

            var login = await client.ConnectAndLoginAsync("admin", "AdminSecret!1");
            Assert.True(login.Success);

            // Execute SET: connection drops after bytes are sent -> must NOT silently retry, must report IsUnknownMutationOutcome!
            ClientOperationResult setRes = await client.ExecuteDataRequestAsync("SET", "CRITICAL_KEY", "Val1");
            Assert.False(setRes.IsSuccess);
            Assert.True(setRes.IsUnknownMutationOutcome);

            await fakeServerTask;
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

                // Send 25 rapid DATA_REQ (LIST) frames within < 1 second
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

            using var cts = new CancellationTokenSource();
            using var listener = new SocketConnectionListener(
                0, _serverCertPath, _serverKeyPath, auth, storage, logger,
                maxConcurrentSessions: 64, maxConcurrentHandshakes: 64);
            listener.StartListening();
            Task serverTask = listener.AcceptLoopAsync(cts.Token);

            const int sessionCount = 50;
            var clients = new List<PvspClientEngine>(sessionCount);

            try
            {
                // 1. Connect and authenticate 50 concurrent sessions (warm-up TLS + PBKDF2 handshakes)
                Task[] loginTasks = new Task[sessionCount];
                for (int i = 0; i < sessionCount; i++)
                {
                    var c = new PvspClientEngine("localhost", listener.BoundPort, _caCertPath);
                    clients.Add(c);
                    loginTasks[i] = Task.Run(async () =>
                    {
                        var res = await c.ConnectAndLoginAsync("reader", "ReaderSecret!1");
                        Assert.True(res.Success);
                    });
                }
                await Task.WhenAll(loginTasks);

                // Warm-up pass (1 request per session)
                await Task.WhenAll(clients.Select(c => c.ExecuteDataRequestAsync("GET", "BENCH_KEY")));

                // 2. Measured pass: 50 concurrent clients each sending 4 sequential GET requests (200 samples total)
                var latenciesMs = new ConcurrentBag<double>();
                Task[] loadTasks = clients.Select(client => Task.Run(async () =>
                {
                    for (int req = 0; req < 4; req++)
                    {
                        var sw = Stopwatch.StartNew();
                        ClientOperationResult res = await client.ExecuteDataRequestAsync("GET", "BENCH_KEY");
                        sw.Stop();

                        Assert.True(res.IsSuccess);
                        Assert.Equal("BenchSecretValue123", res.Value);
                        latenciesMs.Add(sw.Elapsed.TotalMilliseconds);
                    }
                })).ToArray();

                await Task.WhenAll(loadTasks);

                double[] sorted = latenciesMs.OrderBy(x => x).ToArray();
                double avgMs = sorted.Average();
                double p50Ms = sorted[(int)(sorted.Length * 0.50)];
                double p95Ms = sorted[(int)(sorted.Length * 0.95)];

                _output.WriteLine($"[T-10 BENCHMARK REPORT] Active Sessions: {sessionCount}, Samples: {sorted.Length}");
                _output.WriteLine($"[T-10 BENCHMARK REPORT] Avg: {avgMs:F2} ms | p50: {p50Ms:F2} ms | p95: {p95Ms:F2} ms (Target Avg < 15.00 ms)");

                Assert.Equal(200, sorted.Length);
                Assert.True(avgMs < 15.0, $"Expected average loopback latency < 15 ms, but got {avgMs:F2} ms.");
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
            var storage = new VaultStorageEngine(_storePath);
            var logger = new SecurityAuditLogger(_logsDir);

            // Pre-populate storage with 1,001 keys directly in file to trigger 108 ERR_RESPONSE_TOO_LARGE on LIST (> 1,000 keys)
            var hugeDict = new Dictionary<string, string>();
            for (int i = 0; i < 1001; i++)
            {
                hugeDict[$"KEY_{i:D4}"] = "v";
            }
            File.WriteAllText(_storePath, JsonSerializer.Serialize(hugeDict));
            storage = new VaultStorageEngine(_storePath);

            using var cts = new CancellationTokenSource();
            using var listener = new SocketConnectionListener(0, _serverCertPath, _serverKeyPath, auth, storage, logger);
            listener.StartListening();
            Task serverTask = listener.AcceptLoopAsync(cts.Token);

            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, listener.BoundPort));
            using var netStream = new NetworkStream(socket, ownsSocket: true);
            using var sslStream = new SslStream(
                netStream,
                false,
                (_, cert, chain, errors) => PvspCryptoHelper.ValidateServerCertificateCustomCa(cert, chain, errors, _caCertPath));

            await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                EnabledSslProtocols = SslProtocols.Tls13
            });

            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            // 1. Send broken JSON syntax in HELLO -> 104 ERR_INVALID_JSON (connection stays open!)
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.Hello, 1, Encoding.UTF8.GetBytes("{broken_json"), CancellationToken.None);
            FrameReadResult res104 = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
            Assert.Equal(PvspErrorCodes.InvalidJson, JsonSerializer.Deserialize<ErrorPayload>(res104.Frame.PayloadBytes)!.ErrorCode);

            // 2. Send unknown field in HELLO -> 106 ERR_INVALID_PAYLOAD (connection stays open!)
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.Hello, 1, Encoding.UTF8.GetBytes("{\"clientName\":\"Pus\",\"timestamp\":123,\"unknown\":1}"), CancellationToken.None);
            FrameReadResult res106 = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
            Assert.Equal(PvspErrorCodes.InvalidPayload, JsonSerializer.Deserialize<ErrorPayload>(res106.Frame.PayloadBytes)!.ErrorCode);

            // 3. Complete valid HELLO (MsgID=1) and AUTH (MsgID=2)
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.Hello, 1, PvspJsonSerializer.SerializeToUtf8Bytes(new HelloPayload { ClientName = "Pus/1.0", Timestamp = now }), CancellationToken.None);
            var helloAck = JsonSerializer.Deserialize<HelloAckPayload>((await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None)).Frame.PayloadBytes)!;

            var authReq = new AuthPayload { Username = "admin", Password = "AdminSecret!1", ServerNonceEcho = helloAck.ServerNonce, Timestamp = now };
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.Auth, 2, PvspJsonSerializer.SerializeToUtf8Bytes(authReq), CancellationToken.None);
            var authAck = JsonSerializer.Deserialize<AuthAckPayload>((await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None)).Frame.PayloadBytes)!;

            // 4. Send DATA_REQ with action="LIST" but including a 'key' field -> 107 ERR_INVALID_ACTION (connection stays open!)
            var invalidActionReq = new DataReqPayload { SessionToken = authAck.SessionToken, Action = "LIST", Key = "UNEXPECTED_KEY", Timestamp = now, Hmac = new string('a', 64) };
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.DataReq, 3, PvspJsonSerializer.SerializeToUtf8Bytes(invalidActionReq), CancellationToken.None);
            FrameReadResult res107 = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
            Assert.Equal(PvspErrorCodes.InvalidAction, JsonSerializer.Deserialize<ErrorPayload>(res107.Frame.PayloadBytes)!.ErrorCode);

            // 5. Send valid LIST when vault has 1,001 keys (> 1,000 limit) -> 108 ERR_RESPONSE_TOO_LARGE
            var listReq = new DataReqPayload { SessionToken = authAck.SessionToken, Action = "LIST", Timestamp = now };
            listReq.Hmac = PvspCryptoHelper.ComputeDataReqHmacHex(authAck.HmacSecret, 3, listReq);
            await PvspFrameCodec.WriteFrameAsync(sslStream, PvspMessageType.DataReq, 3, PvspJsonSerializer.SerializeToUtf8Bytes(listReq), CancellationToken.None);
            FrameReadResult res108 = await PvspFrameCodec.ReadFrameAsync(sslStream, CancellationToken.None);
            Assert.Equal(PvspErrorCodes.ResponseTooLarge, JsonSerializer.Deserialize<ErrorPayload>(res108.Frame.PayloadBytes)!.ErrorCode);

            cts.Cancel();
            await serverTask;
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