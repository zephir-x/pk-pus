using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Pus.Vault.Server
{
    /// <summary>
    /// Low-level TCP Dual-Stack (IPv6 + IPv4-mapped) socket listener that wraps accepted client sockets
    /// in TLS 1.3 SslStream and dispatches them to ClientSessionHandler instances.
    /// </summary>
    public class SocketConnectionListener : IDisposable
    {
        private readonly int _port;
        private readonly X509Certificate2 _serverCertificate;
        private readonly AuthAndRbacModule _authModule;
        private readonly IVaultStorage _storageEngine;
        private readonly SecurityAuditLogger _logger;
        private readonly SemaphoreSlim _activeSessionsSemaphore;
        private readonly SemaphoreSlim _handshakeSemaphore;
        private readonly ConcurrentDictionary<Task, byte> _activeSessionTasks = new();

        private readonly TimeSpan _tlsHandshakeTimeout;
        private readonly TimeSpan? _helloTimeout;
        private readonly TimeSpan? _authTimeout;
        private readonly TimeSpan? _idleTimeout;
        private readonly Action<string, double>? _onDataReqCompleted;

        private Socket? _listenSocket;

        public int BoundPort { get; private set; }

        public SocketConnectionListener(
            int port,
            string serverCertPath,
            string serverKeyPath,
            AuthAndRbacModule authModule,
            IVaultStorage storageEngine,
            SecurityAuditLogger logger,
            int maxConcurrentSessions = 64,
            int maxConcurrentHandshakes = 32,
            TimeSpan? tlsHandshakeTimeout = null,
            TimeSpan? helloTimeout = null,
            TimeSpan? authTimeout = null,
            TimeSpan? idleTimeout = null,
            Action<string, double>? onDataReqCompleted = null)
        {
            _port = port;
            _authModule = authModule;
            _storageEngine = storageEngine;
            _logger = logger;
            _activeSessionsSemaphore = new SemaphoreSlim(maxConcurrentSessions, maxConcurrentSessions);
            _handshakeSemaphore = new SemaphoreSlim(maxConcurrentHandshakes, maxConcurrentHandshakes);

            _tlsHandshakeTimeout = tlsHandshakeTimeout ?? TimeSpan.FromSeconds(10);
            _helloTimeout = helloTimeout;
            _authTimeout = authTimeout;
            _idleTimeout = idleTimeout;
            _onDataReqCompleted = onDataReqCompleted;

            // Load the server's X.509 PEM certificate and private key
            _serverCertificate = X509Certificate2.CreateFromPemFile(serverCertPath, serverKeyPath);
        }

        /// <summary>
        /// Binds the raw Dual-Stack IPv6/IPv4 TCP socket and begins listening for incoming connections.
        /// </summary>
        public void StartListening()
        {
            // Create a low-level IPv6 stream socket with DualMode enabled to accept both IPv6 and IPv4 clients
            _listenSocket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp)
            {
                DualMode = true
            };

            _listenSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _listenSocket.Bind(new IPEndPoint(IPAddress.IPv6Any, _port));
            _listenSocket.Listen(backlog: 128);

            BoundPort = ((IPEndPoint)_listenSocket.LocalEndPoint!).Port;
            _logger.LogInfo("SERVER", $"Listening on Dual-Stack TCP [::]:{BoundPort} (TLS 1.3 enforced, Cert={_serverCertificate.Subject}).");
        }

        /// <summary>
        /// Main accept loop that accepts raw TCP sockets, spawns isolated asynchronous client session tasks,
        /// and awaits all active session tasks upon graceful server shutdown.
        /// </summary>
        public async Task AcceptLoopAsync(CancellationToken cancellationToken)
        {
            if (_listenSocket == null)
            {
                StartListening();
            }

            while (!cancellationToken.IsCancellationRequested)
            {
                Socket clientSocket;
                try
                {
                    clientSocket = await _listenSocket!.AcceptAsync(cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }

                // Track each spawned client task so graceful shutdown waits for all sessions to finish logging
                Task sessionTask = Task.Run(() => HandleAcceptedSocketAsync(clientSocket, cancellationToken));
                _activeSessionTasks.TryAdd(sessionTask, 0);
                _ = sessionTask.ContinueWith(t => _activeSessionTasks.TryRemove(t, out _), TaskContinuationOptions.ExecuteSynchronously);
            }

            // Wait for all active session handlers to complete their cleanup and final log writes
            if (!_activeSessionTasks.IsEmpty)
            {
                await Task.WhenAll(_activeSessionTasks.Keys);
            }
        }

        private async Task HandleAcceptedSocketAsync(Socket clientSocket, CancellationToken cancellationToken)
        {
            string remoteEndpoint = clientSocket.RemoteEndPoint?.ToString() ?? "unknown";
            string clientIp = (clientSocket.RemoteEndPoint as IPEndPoint)?.Address.ToString() ?? "unknown";

            // Check concurrent session limit immediately
            if (!await _activeSessionsSemaphore.WaitAsync(TimeSpan.Zero, CancellationToken.None))
            {
                _logger.LogWarn(remoteEndpoint, "Connection rejected: maximum concurrent sessions limit reached.");
                clientSocket.Close();
                return;
            }

            try
            {
                clientSocket.NoDelay = true;
                using var networkStream = new NetworkStream(clientSocket, ownsSocket: true);
                using var sslStream = new SslStream(networkStream, leaveInnerStreamOpen: false);

                // Enforce concurrent TLS handshake limit AND a strict total deadline covering both queue wait and TLS handshake
                using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                handshakeCts.CancelAfter(_tlsHandshakeTimeout);

                await _handshakeSemaphore.WaitAsync(handshakeCts.Token);
                try
                {
                    var sslOptions = new SslServerAuthenticationOptions
                    {
                        ServerCertificate = _serverCertificate,
                        ClientCertificateRequired = false,
                        EnabledSslProtocols = SslProtocols.Tls13,
                        CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                    };

                    await sslStream.AuthenticateAsServerAsync(sslOptions, handshakeCts.Token);
                }
                finally
                {
                    _handshakeSemaphore.Release();
                }

                _logger.LogInfo(remoteEndpoint, $"TLS 1.3 handshake completed (Cipher={sslStream.NegotiatedCipherSuite}).");

                var sessionHandler = new ClientSessionHandler(
                    sslStream,
                    remoteEndpoint,
                    clientIp,
                    _authModule,
                    _storageEngine,
                    _logger,
                    _helloTimeout,
                    _authTimeout,
                    _idleTimeout,
                    _onDataReqCompleted);

                await sessionHandler.RunSessionAsync(cancellationToken);
            }
            catch (AuthenticationException ex)
            {
                _logger.LogSecurity(remoteEndpoint, $"TLS handshake rejected: {ex.Message}");
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                _logger.LogWarn(remoteEndpoint, "TLS handshake timed out.");
            }
            catch (OperationCanceledException)
            {
                // Normal server shutdown cancellation
            }
            catch (Exception ex)
            {
                _logger.LogError(remoteEndpoint, $"Connection error: {ex.Message}");
            }
            finally
            {
                try
                {
                    _activeSessionsSemaphore.Release();
                }
                catch (ObjectDisposedException)
                {
                    // Semaphore was already disposed during graceful or sudden server shutdown
                }

                try
                {
                    clientSocket.Close();
                }
                catch
                {
                    // Ignore socket disposal errors
                }
            }
        }

        public void Dispose()
        {
            try
            {
                _listenSocket?.Close();
                _listenSocket?.Dispose();
            }
            catch
            {
                // Ignore
            }

            _serverCertificate.Dispose();
            _activeSessionsSemaphore.Dispose();
            _handshakeSemaphore.Dispose();
        }
    }
}