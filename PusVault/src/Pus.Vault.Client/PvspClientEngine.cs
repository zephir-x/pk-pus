using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Pus.Vault.Common;

namespace Pus.Vault.Client
{
    /// <summary>
    /// High-level result of a client vault operation (GET, SET, LIST, DELETE).
    /// </summary>
    public class ClientOperationResult
    {
        public bool IsSuccess { get; init; }
        public bool IsUnknownMutationOutcome { get; init; }
        public int ErrorCode { get; init; }
        public string ErrorName { get; init; } = string.Empty;
        public string Message { get; init; } = string.Empty;
        public string? Value { get; init; }
        public List<string>? Keys { get; init; }
    }

    /// <summary>
    /// Manages the client-side TCP socket, TLS 1.3 SslStream, serialized frame writer/reader queue,
    /// Message ID sequence counter, canonical HMAC signing, and reactive Auto-Reconnect with Exponential Backoff.
    /// </summary>
    public class PvspClientEngine : IDisposable
    {
        private readonly string _host;
        private readonly int _port;
        private readonly string _caCertPath;
        private readonly TimeSpan _requestTimeout;
        private readonly TimeSpan[] _backoffDelays;

        // Single semaphore serializing all request-response cycles over the SslStream
        private readonly SemaphoreSlim _ioLock = new(1, 1);

        private Socket? _socket;
        private SslStream? _sslStream;

        // Per-connection state (reset on every new TCP/TLS connection)
        private uint _nextMessageId = 1;
        private string _sessionToken = string.Empty;
        private string _hmacSecretBase64 = string.Empty;
        private string _assignedRole = string.Empty;

        // In-memory credentials kept strictly for the process lifetime to allow Auto-Reconnect
        private string? _cachedUsername;
        private string? _cachedPassword;

        private int _requestInFlightFlag;

        public bool IsAuthenticated => !string.IsNullOrEmpty(_sessionToken) && _sslStream != null;
        public string AssignedRole => _assignedRole;
        public DateTime LastActivityUtc { get; private set; } = DateTime.UtcNow;
        public bool IsRequestInFlight => Volatile.Read(ref _requestInFlightFlag) == 1;

        // Optional callback for logging reconnect/diagnostic events to the console
        public Action<string>? OnDiagnosticLog { get; set; }

        public PvspClientEngine(
            string host,
            int port,
            string caCertPath,
            TimeSpan? requestTimeout = null,
            TimeSpan[]? customBackoffDelays = null)
        {
            _host = host;
            _port = port;
            _caCertPath = caCertPath;
            _requestTimeout = requestTimeout ?? TimeSpan.FromSeconds(5);
            _backoffDelays = customBackoffDelays ?? new[]
            {
                TimeSpan.FromSeconds(1),
                TimeSpan.FromSeconds(2),
                TimeSpan.FromSeconds(4)
            };
        }

        /// <summary>
        /// Establishes a new TCP + TLS 1.3 connection and performs the two-step HELLO -> AUTH login handshake.
        /// </summary>
        public async Task<(bool Success, string Message, int ErrorCode)> ConnectAndLoginAsync(
            string username,
            string password,
            CancellationToken ct = default)
        {
            await _ioLock.WaitAsync(ct);
            try
            {
                Volatile.Write(ref _requestInFlightFlag, 1);
                var result = await EstablishSessionInternalAsync(username, password, ct);
                if (result.Success)
                {
                    _cachedUsername = username;
                    _cachedPassword = password;
                }
                return result;
            }
            finally
            {
                Volatile.Write(ref _requestInFlightFlag, 0);
                _ioLock.Release();
            }
        }

        /// <summary>
        /// Executes a vault CRUD request (SET, GET, LIST, DELETE) signed with canonical HMAC-SHA256.
        /// Automatically reconnects and retries ONLY for idempotent read actions (GET and LIST).
        /// For SET and DELETE, if the connection drops after sending, returns UnknownMutationOutcome.
        /// </summary>
        public async Task<ClientOperationResult> ExecuteDataRequestAsync(
            string action,
            string? key = null,
            string? value = null,
            CancellationToken ct = default)
        {
            await _ioLock.WaitAsync(ct);
            try
            {
                Volatile.Write(ref _requestInFlightFlag, 1);

                if (!IsAuthenticated)
                {
                    return new ClientOperationResult
                    {
                        IsSuccess = false,
                        Message = "Not authenticated. Please run 'login <username>' first."
                    };
                }

                // If Message ID reached uint32.MaxValue, specification requires re-establishing the session first
                if (_nextMessageId == uint.MaxValue)
                {
                    bool rotated = await TryAutoReconnectInternalAsync(ct);
                    if (!rotated)
                    {
                        return new ClientOperationResult
                        {
                            IsSuccess = false,
                            Message = "Failed to rotate session after reaching Message ID limit."
                        };
                    }
                }

                bool requestBytesSentToWire = false;

                try
                {
                    return await SendDataReqCoreAsync(action, key, value, () => requestBytesSentToWire = true, ct);
                }
                catch (Exception ex) when (IsTransientNetworkFailure(ex, ct))
                {
                    Log($"Connection lost during {action} ({ex.Message}). Starting Auto-Reconnect...");

                    bool reconnected = await TryAutoReconnectInternalAsync(ct);
                    
                    // If a mutation (SET or DELETE) was already written to the stream before the failure,
                    // we must NOT silently retry it because the server may have already committed it.
                    bool isSafeReadAction = action is "GET" or "LIST";
                    if (!isSafeReadAction && requestBytesSentToWire)
                    {
                        return new ClientOperationResult
                        {
                            IsSuccess = false,
                            IsUnknownMutationOutcome = true,
                            Message = reconnected
                                ? $"Connection dropped after sending '{action}'. Outcome is UNKNOWN (session was restored, but mutation was not retried; verify with 'get' or 'list')."
                                : $"Connection dropped after sending '{action}' and Auto-Reconnect failed. Outcome is UNKNOWN."
                        };
                    }

                    if (!reconnected)
                    {
                        return new ClientOperationResult
                        {
                            IsSuccess = false,
                            Message = "Connection lost and Auto-Reconnect failed after 3 attempts."
                        };
                    }

                    // Safe to automatically retry GET / LIST (or a mutation that failed before writing to wire)
                    Log($"Auto-Reconnect succeeded. Retrying safe operation '{action}' in new session...");
                    try
                    {
                        return await SendDataReqCoreAsync(action, key, value, () => { }, ct);
                    }
                    catch (Exception retryEx)
                    {
                        return new ClientOperationResult
                        {
                            IsSuccess = false,
                            Message = $"Operation failed after reconnect: {retryEx.Message}"
                        };
                    }
                }
            }
            finally
            {
                Volatile.Write(ref _requestInFlightFlag, 0);
                _ioLock.Release();
            }
        }

        /// <summary>
        /// Sends a PING (0x07) frame and awaits a PONG (0x08) response with the matching Message ID.
        /// </summary>
        public async Task<bool> SendPingAsync(CancellationToken ct = default)
        {
            await _ioLock.WaitAsync(ct);
            try
            {
                if (!IsAuthenticated || _sslStream == null)
                    return false;

                Volatile.Write(ref _requestInFlightFlag, 1);

                uint msgId = _nextMessageId++;
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(_requestTimeout);

                await PvspFrameCodec.WriteFrameAsync(_sslStream, PvspMessageType.Ping, msgId, Array.Empty<byte>(), timeoutCts.Token);
                LastActivityUtc = DateTime.UtcNow;

                FrameReadResult resp = await PvspFrameCodec.ReadFrameAsync(_sslStream, timeoutCts.Token);
                LastActivityUtc = DateTime.UtcNow;

                return !resp.IsEof &&
                       resp.HeaderReadComplete &&
                       resp.FramingErrorCode == 0 &&
                       resp.Frame.MessageType == PvspMessageType.Pong &&
                       resp.Frame.MessageId == msgId;
            }
            catch
            {
                return false;
            }
            finally
            {
                Volatile.Write(ref _requestInFlightFlag, 0);
                _ioLock.Release();
            }
        }

        /// <summary>
        /// Sends a graceful BYE (0x09) frame and closes the underlying TLS stream and TCP socket.
        /// </summary>
        public async Task DisconnectAsync(bool clearCachedCredentials = true, CancellationToken ct = default)
        {
            await _ioLock.WaitAsync(ct);
            try
            {
                if (_sslStream != null && IsAuthenticated)
                {
                    try
                    {
                        uint msgId = _nextMessageId++;
                        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                        await PvspFrameCodec.WriteFrameAsync(_sslStream, PvspMessageType.Bye, msgId, Array.Empty<byte>(), timeoutCts.Token);
                    }
                    catch
                    {
                        // Ignore errors while closing
                    }
                }

                CloseTransportInternal();

                if (clearCachedCredentials)
                {
                    _cachedUsername = null;
                    _cachedPassword = null;
                }
            }
            finally
            {
                _ioLock.Release();
            }
        }
        
        // DIAGNOSTIC HARNESS METHODS (Only exposed when --diagnostics flag is active)

        /// <summary>
        /// Diagnostic test helper: sends a DATA_REQ frame with a deliberately corrupted HMAC signature
        /// to demonstrate server-side 204 ERR_INVALID_HMAC detection.
        /// </summary>
        public async Task<ClientOperationResult> SendDiagnosticCorruptedHmacAsync(CancellationToken ct = default)
        {
            await _ioLock.WaitAsync(ct);
            try
            {
                if (!IsAuthenticated || _sslStream == null)
                    return new ClientOperationResult { IsSuccess = false, Message = "Must be authenticated first." };

                uint msgId = _nextMessageId++;
                var req = new DataReqPayload
                {
                    SessionToken = _sessionToken,
                    Action = "LIST",
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    Hmac = new string('f', 64) // Forged invalid 64-char hex HMAC
                };

                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(_requestTimeout);

                byte[] payloadBytes = PvspJsonSerializer.SerializeToUtf8Bytes(req);
                await PvspFrameCodec.WriteFrameAsync(_sslStream, PvspMessageType.DataReq, msgId, payloadBytes, timeoutCts.Token);

                FrameReadResult resp = await PvspFrameCodec.ReadFrameAsync(_sslStream, timeoutCts.Token);
                CloseTransportInternal(); // Server closes connection on 204 ERR_INVALID_HMAC
                return ParseServerResponse(resp, msgId);
            }
            finally
            {
                _ioLock.Release();
            }
        }

        /// <summary>
        /// Diagnostic test helper: sends a DATA_REQ frame with an expired timestamp (-120 seconds)
        /// to demonstrate server-side 301 ERR_REPLAY_DETECTED detection.
        /// </summary>
        public async Task<ClientOperationResult> SendDiagnosticReplayTimestampAsync(CancellationToken ct = default)
        {
            await _ioLock.WaitAsync(ct);
            try
            {
                if (!IsAuthenticated || _sslStream == null)
                    return new ClientOperationResult { IsSuccess = false, Message = "Must be authenticated first." };

                uint msgId = _nextMessageId++;
                var req = new DataReqPayload
                {
                    SessionToken = _sessionToken,
                    Action = "LIST",
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 120 // Outside +/- 30s window
                };
                req.Hmac = PvspCryptoHelper.ComputeDataReqHmacHex(_hmacSecretBase64, msgId, req);

                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(_requestTimeout);

                byte[] payloadBytes = PvspJsonSerializer.SerializeToUtf8Bytes(req);
                await PvspFrameCodec.WriteFrameAsync(_sslStream, PvspMessageType.DataReq, msgId, payloadBytes, timeoutCts.Token);

                FrameReadResult resp = await PvspFrameCodec.ReadFrameAsync(_sslStream, timeoutCts.Token);
                CloseTransportInternal(); // Server closes connection on 301 ERR_REPLAY_DETECTED
                return ParseServerResponse(resp, msgId);
            }
            finally
            {
                _ioLock.Release();
            }
        }

        /// <summary>
        /// Diagnostic test helper: sends a binary header with corrupted Magic Bytes (0x0000 instead of 0x5053)
        /// to demonstrate server-side 100 ERR_BAD_MAGIC detection.
        /// </summary>
        public async Task<ClientOperationResult> SendDiagnosticBadMagicAsync(CancellationToken ct = default)
        {
            await _ioLock.WaitAsync(ct);
            try
            {
                if (_sslStream == null)
                    return new ClientOperationResult { IsSuccess = false, Message = "Not connected." };

                uint msgId = _nextMessageId++;
                byte[] badHeader = new byte[PvspConstants.HeaderSize];
                badHeader[0] = 0x00; // Invalid Magic Byte 1
                badHeader[1] = 0x00; // Invalid Magic Byte 2
                badHeader[2] = PvspConstants.ProtocolVersion;
                badHeader[3] = (byte)PvspMessageType.Ping;

                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(_requestTimeout);

                await _sslStream.WriteAsync(badHeader, timeoutCts.Token);
                await _sslStream.FlushAsync(timeoutCts.Token);

                FrameReadResult resp = await PvspFrameCodec.ReadFrameAsync(_sslStream, timeoutCts.Token);
                CloseTransportInternal();
                return ParseServerResponse(resp, msgId);
            }
            finally
            {
                _ioLock.Release();
            }
        }
        
        // INTERNAL CONNECTION, HANDSHAKE & AUTO-RECONNECT LOGIC

        private async Task<(bool Success, string Message, int ErrorCode)> EstablishSessionInternalAsync(
            string username,
            string password,
            CancellationToken ct)
        {
            CloseTransportInternal();

            try
            {
                // 1. Resolve target IP and connect using a raw TCP Socket (supports both IPv4 and IPv6)
                IPAddress targetIp = await ResolveHostAddressAsync(_host, ct);
                _socket = new Socket(targetIp.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
                {
                    NoDelay = true
                };

                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                connectCts.CancelAfter(_requestTimeout);
                await _socket.ConnectAsync(new IPEndPoint(targetIp, _port), connectCts.Token);

                // 2. Wrap the raw Socket in NetworkStream and SslStream enforcing TLS 1.3 and Custom CA validation
                var netStream = new NetworkStream(_socket, ownsSocket: true);
                _sslStream = new SslStream(
                    netStream,
                    leaveInnerStreamOpen: false,
                    (_, cert, chain, errors) => PvspCryptoHelper.ValidateServerCertificateCustomCa(cert, chain, errors, _caCertPath));

                var sslOptions = new SslClientAuthenticationOptions
                {
                    TargetHost = _host,
                    EnabledSslProtocols = SslProtocols.Tls13,
                    CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck
                };

                await _sslStream.AuthenticateAsClientAsync(sslOptions, connectCts.Token);

                // Reset per-connection Message ID counter to 1
                _nextMessageId = 1;

                // 3. Send HELLO (0x01) with MsgID = 1
                uint helloId = _nextMessageId++;
                var helloPayload = new HelloPayload
                {
                    ClientName = "PusVault-CLI/1.0",
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                };

                using var helloCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                helloCts.CancelAfter(_requestTimeout);

                await PvspFrameCodec.WriteFrameAsync(
                    _sslStream,
                    PvspMessageType.Hello,
                    helloId,
                    PvspJsonSerializer.SerializeToUtf8Bytes(helloPayload),
                    helloCts.Token);

                FrameReadResult helloAckResult = await PvspFrameCodec.ReadFrameAsync(_sslStream, helloCts.Token);
                if (helloAckResult.IsEof || !helloAckResult.HeaderReadComplete)
                {
                    CloseTransportInternal();
                    return (false, "Server closed connection during HELLO handshake.", 0);
                }

                if (helloAckResult.Frame.MessageType == PvspMessageType.Error)
                {
                    var err = JsonSerializer.Deserialize<ErrorPayload>(helloAckResult.Frame.PayloadBytes);
                    CloseTransportInternal();
                    return (false, $"HELLO failed ({err?.ErrorCode} {err?.ErrorName}): {err?.Message}", err?.ErrorCode ?? 0);
                }

                if (helloAckResult.Frame.MessageType != PvspMessageType.HelloAck || helloAckResult.Frame.MessageId != helloId)
                {
                    CloseTransportInternal();
                    return (false, "Unexpected response type or Message ID during HELLO_ACK.", 0);
                }

                var helloAck = JsonSerializer.Deserialize<HelloAckPayload>(helloAckResult.Frame.PayloadBytes)!;

                // 4. Send AUTH (0x03) with MsgID = 2 and serverNonceEcho
                uint authId = _nextMessageId++;
                var authPayload = new AuthPayload
                {
                    Username = username,
                    Password = password,
                    ServerNonceEcho = helloAck.ServerNonce,
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                };

                using var authCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                authCts.CancelAfter(_requestTimeout);

                await PvspFrameCodec.WriteFrameAsync(
                    _sslStream,
                    PvspMessageType.Auth,
                    authId,
                    PvspJsonSerializer.SerializeToUtf8Bytes(authPayload),
                    authCts.Token);

                FrameReadResult authAckResult = await PvspFrameCodec.ReadFrameAsync(_sslStream, authCts.Token);
                if (authAckResult.IsEof || !authAckResult.HeaderReadComplete)
                {
                    CloseTransportInternal();
                    return (false, "Server closed connection during AUTH handshake.", 0);
                }

                if (authAckResult.Frame.MessageType == PvspMessageType.Error)
                {
                    var err = JsonSerializer.Deserialize<ErrorPayload>(authAckResult.Frame.PayloadBytes);
                    CloseTransportInternal();
                    return (false, $"Authentication rejected ({err?.ErrorCode} {err?.ErrorName}): {err?.Message}", err?.ErrorCode ?? 0);
                }

                if (authAckResult.Frame.MessageType != PvspMessageType.AuthAck || authAckResult.Frame.MessageId != authId)
                {
                    CloseTransportInternal();
                    return (false, "Unexpected response type or Message ID during AUTH_ACK.", 0);
                }

                var authAck = JsonSerializer.Deserialize<AuthAckPayload>(authAckResult.Frame.PayloadBytes)!;
                _sessionToken = authAck.SessionToken;
                _hmacSecretBase64 = authAck.HmacSecret;
                _assignedRole = authAck.Role;
                LastActivityUtc = DateTime.UtcNow;

                return (true, $"Authenticated as '{username}' (Role: {_assignedRole}).", 0);
            }
            catch (AuthenticationException ex)
            {
                CloseTransportInternal();
                throw new AuthenticationException($"TLS 1.3 Certificate validation failed: {ex.Message}", ex);
            }
            catch (Exception ex)
            {
                CloseTransportInternal();
                return (false, $"Connection failed: {ex.Message}", 0);
            }
        }

        private async Task<ClientOperationResult> SendDataReqCoreAsync(
            string action,
            string? key,
            string? value,
            Action onWrittenToWire,
            CancellationToken ct)
        {
            if (_sslStream == null)
            {
                throw new IOException("TLS stream is not connected.");
            }

            uint msgId = _nextMessageId++;
            var reqPayload = new DataReqPayload
            {
                SessionToken = _sessionToken,
                Action = action,
                Key = key,
                Value = value,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            };

            reqPayload.Hmac = PvspCryptoHelper.ComputeDataReqHmacHex(_hmacSecretBase64, msgId, reqPayload);
            byte[] payloadBytes = PvspJsonSerializer.SerializeToUtf8Bytes(reqPayload);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(_requestTimeout);

            await PvspFrameCodec.WriteFrameAsync(_sslStream, PvspMessageType.DataReq, msgId, payloadBytes, timeoutCts.Token);
            onWrittenToWire();
            LastActivityUtc = DateTime.UtcNow;

            FrameReadResult respResult = await PvspFrameCodec.ReadFrameAsync(_sslStream, timeoutCts.Token);
            if (respResult.IsEof || !respResult.HeaderReadComplete)
            {
                throw new IOException("Remote server closed the connection before sending a complete response frame.");
            }

            LastActivityUtc = DateTime.UtcNow;
            return ParseServerResponse(respResult, msgId);
        }

        private ClientOperationResult ParseServerResponse(FrameReadResult respResult, uint expectedMsgId)
        {
            if (respResult.FramingErrorCode != 0)
            {
                CloseTransportInternal();
                return new ClientOperationResult
                {
                    IsSuccess = false,
                    ErrorCode = respResult.FramingErrorCode,
                    Message = $"Received malformed frame from server: {respResult.FramingErrorMessage}"
                };
            }

            if (respResult.Frame.MessageType == PvspMessageType.Error)
            {
                var err = JsonSerializer.Deserialize<ErrorPayload>(respResult.Frame.PayloadBytes);
                int code = err?.ErrorCode ?? PvspErrorCodes.InternalServer;

                if (PvspErrorCodes.ShouldCloseConnection(code))
                {
                    CloseTransportInternal();
                }

                return new ClientOperationResult
                {
                    IsSuccess = false,
                    ErrorCode = code,
                    ErrorName = err?.ErrorName ?? PvspErrorCodes.GetName(code),
                    Message = err?.Message ?? "Unknown server error."
                };
            }

            if (respResult.Frame.MessageType != PvspMessageType.DataResp || respResult.Frame.MessageId != expectedMsgId)
            {
                return new ClientOperationResult
                {
                    IsSuccess = false,
                    Message = $"Unexpected response frame type ({respResult.Frame.MessageType}) or mismatched Message ID."
                };
            }

            var dataResp = JsonSerializer.Deserialize<DataRespPayload>(respResult.Frame.PayloadBytes)!;
            return new ClientOperationResult
            {
                IsSuccess = true,
                Message = $"OK ({dataResp.Action})",
                Value = dataResp.Value,
                Keys = dataResp.Keys
            };
        }

        private async Task<bool> TryAutoReconnectInternalAsync(CancellationToken ct)
        {
            CloseTransportInternal();

            if (string.IsNullOrEmpty(_cachedUsername) || string.IsNullOrEmpty(_cachedPassword))
            {
                return false;
            }

            for (int attempt = 0; attempt < _backoffDelays.Length; attempt++)
            {
                TimeSpan delay = _backoffDelays[attempt];
                Log($"Auto-Reconnect attempt {attempt + 1}/{_backoffDelays.Length} in {delay.TotalSeconds:0.#}s...");
                await Task.Delay(delay, ct);

                try
                {
                    var (success, msg, _) = await EstablishSessionInternalAsync(_cachedUsername, _cachedPassword, ct);
                    if (success)
                    {
                        Log("Auto-Reconnect successful: new TLS 1.3 session established and authenticated.");
                        return true;
                    }
                    Log($"Auto-Reconnect attempt {attempt + 1} failed: {msg}");
                }
                catch (Exception ex)
                {
                    Log($"Auto-Reconnect attempt {attempt + 1} error: {ex.Message}");
                }
            }

            return false;
        }

        private static bool IsTransientNetworkFailure(Exception ex, CancellationToken callerToken)
        {
            if (callerToken.IsCancellationRequested)
                return false;

            return ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException;
        }

        private static async Task<IPAddress> ResolveHostAddressAsync(string host, CancellationToken ct)
        {
            if (IPAddress.TryParse(host, out IPAddress? parsedIp))
            {
                return parsedIp;
            }

            IPAddress[] addresses = await Dns.GetHostAddressesAsync(host, ct);
            if (addresses.Length == 0)
            {
                throw new SocketException((int)SocketError.HostNotFound);
            }

            return addresses[0];
        }

        private void CloseTransportInternal()
        {
            _sessionToken = string.Empty;
            _hmacSecretBase64 = string.Empty;
            _assignedRole = string.Empty;

            try { _sslStream?.Close(); _sslStream?.Dispose(); } catch { }
            try { _socket?.Close(); _socket?.Dispose(); } catch { }

            _sslStream = null;
            _socket = null;
        }

        private void Log(string message) => OnDiagnosticLog?.Invoke(message);

        public void Dispose()
        {
            CloseTransportInternal();
            _cachedUsername = null;
            _cachedPassword = null;
            _ioLock.Dispose();
        }
    }
}