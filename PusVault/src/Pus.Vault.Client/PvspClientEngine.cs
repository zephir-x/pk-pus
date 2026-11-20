using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Pus.Vault.Common;

namespace Pus.Vault.Client
{
    /// <summary>
    /// Represents the outcome of a high-level client vault operation (SET, GET, LIST, DELETE, PING).
    /// </summary>
    public class ClientOperationResult
    {
        public bool IsSuccess { get; init; }
        public int ErrorCode { get; init; }
        public string ErrorName { get; init; } = string.Empty;
        public string Message { get; init; } = string.Empty;
        public string? Value { get; init; }
        public List<string>? Keys { get; init; }
        public bool IsUnknownMutationOutcome { get; init; }
    }

    /// <summary>
    /// Core networking and PVSP v1.0 protocol engine for the PUS-Vault Client.
    /// Uses raw System.Net.Sockets.Socket wrapped in SslStream (TLS 1.3 + Custom Root CA),
    /// serialized by a single I/O SemaphoreSlim so CLI commands and background Keep-Alive PING never interleave.
    /// </summary>
    public class PvspClientEngine : IDisposable
    {
        private readonly string _host;
        private readonly int _port;
        private readonly string _caCertPath;
        private readonly TimeSpan _requestTimeout;
        private readonly TimeSpan _tlsHandshakeTimeout;
        private readonly TimeSpan[] _backoffDelays;

        private readonly SemaphoreSlim _ioLock = new(1, 1);
        private readonly object _stateLock = new();

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

        private bool _isRequestInFlight;
        private DateTime _lastActivityUtc = DateTime.UtcNow;

        public bool IsAuthenticated => !string.IsNullOrEmpty(_sessionToken) && _sslStream != null;
        public string AssignedRole => _assignedRole;

        public DateTime LastActivityUtc
        {
            get { lock (_stateLock) { return _lastActivityUtc; } }
            private set { lock (_stateLock) { _lastActivityUtc = value.ToUniversalTime(); } }
        }

        public bool IsRequestInFlight
        {
            get { lock (_stateLock) { return _isRequestInFlight; } }
            private set { lock (_stateLock) { _isRequestInFlight = value; } }
        }

        // Optional callback for structured client diagnostic/session logs
        public Action<string>? OnDiagnosticLog { get; set; }

        public PvspClientEngine(
            string host,
            int port,
            string caCertPath,
            TimeSpan? requestTimeout = null,
            TimeSpan[]? customBackoffDelays = null,
            TimeSpan? tlsHandshakeTimeout = null)
        {
            _host = host;
            _port = port;
            _caCertPath = caCertPath;
            _requestTimeout = requestTimeout ?? TimeSpan.FromSeconds(5);
            _tlsHandshakeTimeout = tlsHandshakeTimeout ?? TimeSpan.FromSeconds(10);
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
                IsRequestInFlight = true;
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
                IsRequestInFlight = false;
                _ioLock.Release();
            }
        }

        /// <summary>
        /// Executes a vault CRUD request (SET, GET, LIST, DELETE) signed with canonical HMAC-SHA256.
        /// Automatically reconnects and retries ONLY for idempotent read actions (GET and LIST).
        /// For SET and DELETE, if the connection drops once transmission has started, returns UnknownMutationOutcome.
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
                IsRequestInFlight = true;

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
                    Log("INFO", "Message ID counter reached uint32.MaxValue. Rotating session via Auto-Reconnect...");
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

                bool requestWriteStarted = false;

                try
                {
                    return await SendDataReqCoreAsync(action, key, value, () => requestWriteStarted = true, ct);
                }
                catch (Exception ex) when (IsTransientNetworkFailure(ex, ct))
                {
                    Log("WARN", $"Connection lost during {action} ({ex.Message}). Starting Auto-Reconnect...");

                    bool reconnected = await TryAutoReconnectInternalAsync(ct);

                    // Once a mutation (SET or DELETE) write has begun, we must NOT silently retry it
                    // because partial/complete bytes may already have reached the server and committed.
                    bool isSafeReadAction = action is "GET" or "LIST";
                    if (!isSafeReadAction && requestWriteStarted)
                    {
                        Log("WARN", $"Mutation '{action}' outcome is UNKNOWN after transport drop; skipping automatic retry.");
                        return new ClientOperationResult
                        {
                            IsSuccess = false,
                            IsUnknownMutationOutcome = true,
                            Message = reconnected
                                ? $"Connection dropped after initiating '{action}'. Outcome is UNKNOWN (session was restored, but mutation was not retried; verify with 'get' or 'list')."
                                : $"Connection dropped after initiating '{action}' and Auto-Reconnect failed. Outcome is UNKNOWN."
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

                    // Safe to automatically retry GET / LIST (or a mutation that failed before initiating write)
                    Log("INFO", $"Auto-Reconnect succeeded. Retrying safe operation '{action}' in new session...");
                    try
                    {
                        return await SendDataReqCoreAsync(action, key, value, () => { }, ct);
                    }
                    catch (Exception retryEx)
                    {
                        Log("ERROR", $"Operation '{action}' failed after reconnect: {retryEx.Message}");
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
                IsRequestInFlight = false;
                _ioLock.Release();
            }
        }

        /// <summary>
        /// Sends a PING (0x07) frame and awaits a PONG (0x08) response with the matching Message ID.
        /// Upon timeout, EOF, or protocol mismatch, closes the broken transport and runs Auto-Reconnect recovery.
        /// </summary>
        public async Task<bool> SendPingAsync(CancellationToken ct = default)
        {
            await _ioLock.WaitAsync(ct);
            try
            {
                if (!IsAuthenticated || _sslStream == null)
                    return false;

                IsRequestInFlight = true;

                try
                {
                    if (await SendPingCoreAsync(ct))
                        return true;

                    Log("WARN", "PING received EOF, malformed frame, or mismatched PONG. Closing transport and starting Auto-Reconnect...");
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    return false;
                }
                catch (Exception ex)
                {
                    Log("WARN", $"PING failed ({ex.Message}). Closing broken transport and starting Auto-Reconnect...");
                }

                // Always tear down a timed-out or broken stream so late PONG frames cannot desynchronize future requests
                CloseTransportInternal();

                if (ct.IsCancellationRequested)
                    return false;

                bool reconnected = await TryAutoReconnectInternalAsync(ct);
                if (!reconnected)
                    return false;

                try
                {
                    if (await SendPingCoreAsync(ct))
                        return true;
                }
                catch (Exception ex)
                {
                    Log("ERROR", $"PING verification failed after Auto-Reconnect: {ex.Message}");
                }

                CloseTransportInternal();
                return false;
            }
            finally
            {
                IsRequestInFlight = false;
                _ioLock.Release();
            }
        }

        private async Task<bool> SendPingCoreAsync(CancellationToken ct)
        {
            if (_sslStream == null)
                return false;

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
                   resp.Frame.MessageId == msgId &&
                   resp.Frame.PayloadLength == 0;
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
                        Log("INFO", $"Sent BYE (MsgID={msgId}) and closing TLS/TCP session.");
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

                Log("INFO", $"Sending diagnostic corrupted-HMAC DATA_REQ (MsgID={msgId}).");
                byte[] payloadBytes = PvspJsonSerializer.SerializeToUtf8Bytes(req);
                await PvspFrameCodec.WriteFrameAsync(_sslStream, PvspMessageType.DataReq, msgId, payloadBytes, timeoutCts.Token);

                FrameReadResult resp = await PvspFrameCodec.ReadFrameAsync(_sslStream, timeoutCts.Token);
                CloseTransportInternal(); // Server closes connection on 204 ERR_INVALID_HMAC
                return ParseServerResponse(resp, msgId, "LIST");
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

                Log("INFO", $"Sending diagnostic expired-timestamp DATA_REQ (MsgID={msgId}).");
                byte[] payloadBytes = PvspJsonSerializer.SerializeToUtf8Bytes(req);
                await PvspFrameCodec.WriteFrameAsync(_sslStream, PvspMessageType.DataReq, msgId, payloadBytes, timeoutCts.Token);

                FrameReadResult resp = await PvspFrameCodec.ReadFrameAsync(_sslStream, timeoutCts.Token);
                CloseTransportInternal(); // Server closes connection on 301 ERR_REPLAY_DETECTED
                return ParseServerResponse(resp, msgId, "LIST");
            }
            finally
            {
                _ioLock.Release();
            }
        }

        /// <summary>
        /// Diagnostic test helper: sends a binary header with corrupted Magic Bytes (0x0000 instead of 0x5053)
        /// while preserving the active Big-Endian Message ID in bytes 4..7 to demonstrate 100 ERR_BAD_MAGIC detection.
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
                BinaryPrimitives.WriteUInt32BigEndian(badHeader.AsSpan(4, 4), msgId);
                BinaryPrimitives.WriteUInt32BigEndian(badHeader.AsSpan(8, 4), 0);

                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(_requestTimeout);

                Log("INFO", $"Sending diagnostic invalid-magic header (MsgID={msgId}).");
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
                connectCts.CancelAfter(_tlsHandshakeTimeout);
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
                Log("INFO", $"TLS 1.3 handshake succeeded (Cipher={_sslStream.NegotiatedCipherSuite}).");

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
                if (helloAckResult.IsEof || !helloAckResult.HeaderReadComplete || helloAckResult.FramingErrorCode != 0)
                {
                    CloseTransportInternal();
                    return (false, "Server closed connection or sent malformed frame during HELLO handshake.", helloAckResult.FramingErrorCode);
                }

                if (helloAckResult.Frame.MessageType == PvspMessageType.Error)
                {
                    TryDeserializePayload<ErrorPayload>(helloAckResult.Frame.PayloadBytes, out var err);
                    CloseTransportInternal();
                    return (false, $"HELLO failed ({err?.ErrorCode} {err?.ErrorName}): {err?.Message ?? "Malformed error payload."}", err?.ErrorCode ?? 0);
                }

                if (helloAckResult.Frame.MessageType != PvspMessageType.HelloAck || helloAckResult.Frame.MessageId != helloId)
                {
                    CloseTransportInternal();
                    return (false, "Unexpected response type or Message ID during HELLO_ACK.", 0);
                }

                if (!TryDeserializePayload<HelloAckPayload>(helloAckResult.Frame.PayloadBytes, out var helloAck) ||
                    string.IsNullOrEmpty(helloAck!.ServerNonce))
                {
                    CloseTransportInternal();
                    Log("ERROR", "Received malformed HELLO_ACK payload from server.");
                    return (false, "Received malformed HELLO_ACK payload from server.", 0);
                }

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
                if (authAckResult.IsEof || !authAckResult.HeaderReadComplete || authAckResult.FramingErrorCode != 0)
                {
                    CloseTransportInternal();
                    return (false, "Server closed connection or sent malformed frame during AUTH handshake.", authAckResult.FramingErrorCode);
                }

                if (authAckResult.Frame.MessageType == PvspMessageType.Error)
                {
                    TryDeserializePayload<ErrorPayload>(authAckResult.Frame.PayloadBytes, out var err);
                    CloseTransportInternal();
                    Log("SECURITY", $"Authentication rejected for user '{username}' (Code={err?.ErrorCode ?? 0}).");
                    return (false, $"Authentication rejected ({err?.ErrorCode} {err?.ErrorName}): {err?.Message ?? "Malformed error payload."}", err?.ErrorCode ?? 0);
                }

                if (authAckResult.Frame.MessageType != PvspMessageType.AuthAck || authAckResult.Frame.MessageId != authId)
                {
                    CloseTransportInternal();
                    return (false, "Unexpected response type or Message ID during AUTH_ACK.", 0);
                }

                if (!TryDeserializePayload<AuthAckPayload>(authAckResult.Frame.PayloadBytes, out var authAck) ||
                    string.IsNullOrEmpty(authAck!.SessionToken) ||
                    string.IsNullOrEmpty(authAck.HmacSecret) ||
                    string.IsNullOrEmpty(authAck.Role))
                {
                    CloseTransportInternal();
                    Log("ERROR", "Received malformed AUTH_ACK payload from server.");
                    return (false, "Received malformed AUTH_ACK payload from server.", 0);
                }

                // Validate that hmacSecret decodes cleanly to a 32-byte key
                try
                {
                    if (Convert.FromBase64String(authAck.HmacSecret).Length != 32)
                    {
                        CloseTransportInternal();
                        Log("ERROR", "Received AUTH_ACK with invalid hmacSecret length.");
                        return (false, "Received AUTH_ACK with invalid hmacSecret length.", 0);
                    }
                }
                catch (FormatException)
                {
                    CloseTransportInternal();
                    Log("ERROR", "Received AUTH_ACK with invalid Base64 hmacSecret.");
                    return (false, "Received AUTH_ACK with invalid Base64 hmacSecret.", 0);
                }

                _sessionToken = authAck.SessionToken;
                _hmacSecretBase64 = authAck.HmacSecret;
                _assignedRole = authAck.Role;
                LastActivityUtc = DateTime.UtcNow;

                Log("INFO", $"Authenticated as '{username}' (Role={_assignedRole}).");
                return (true, $"Authenticated as '{username}' (Role: {_assignedRole}).", 0);
            }
            catch (AuthenticationException ex)
            {
                CloseTransportInternal();
                Log("SECURITY", $"TLS 1.3 certificate validation failed: {ex.Message}");
                throw new AuthenticationException($"TLS 1.3 Certificate validation failed: {ex.Message}", ex);
            }
            catch (Exception ex)
            {
                CloseTransportInternal();
                Log("ERROR", $"Connection failed: {ex.Message}");
                return (false, $"Connection failed: {ex.Message}", 0);
            }
        }

        private async Task<ClientOperationResult> SendDataReqCoreAsync(
            string action,
            string? key,
            string? value,
            Action onWriteStarted,
            CancellationToken ct)
        {
            if (_sslStream == null)
            {
                throw new IOException("TLS stream is not connected.");
            }

            uint msgId = _nextMessageId;
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

            // Prevent sending oversized JSON payloads (e.g., if JSON escaping expanded a large secret past 64 KiB)
            if (payloadBytes.Length > PvspConstants.MaxPayloadSize)
            {
                return new ClientOperationResult
                {
                    IsSuccess = false,
                    ErrorCode = PvspErrorCodes.PayloadTooLarge,
                    ErrorName = PvspErrorCodes.GetName(PvspErrorCodes.PayloadTooLarge),
                    Message = $"Serialized request payload ({payloadBytes.Length} B) exceeds the 64 KiB protocol limit."
                };
            }

            _nextMessageId++;

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(_requestTimeout);

            // Flag transmission as initiated BEFORE writing to SslStream so failures during WriteAsync/FlushAsync
            // never cause a silent retry of potentially transmitted SET/DELETE mutations.
            onWriteStarted();
            await PvspFrameCodec.WriteFrameAsync(_sslStream, PvspMessageType.DataReq, msgId, payloadBytes, timeoutCts.Token);
            LastActivityUtc = DateTime.UtcNow;

            FrameReadResult respResult = await PvspFrameCodec.ReadFrameAsync(_sslStream, timeoutCts.Token);
            if (respResult.IsEof || !respResult.HeaderReadComplete)
            {
                throw new IOException("Remote server closed the connection before sending a complete response frame.");
            }

            LastActivityUtc = DateTime.UtcNow;
            return ParseServerResponse(respResult, msgId, action);
        }

        private ClientOperationResult ParseServerResponse(FrameReadResult respResult, uint expectedMsgId, string? expectedAction = null)
        {
            if (respResult.IsEof || !respResult.HeaderReadComplete)
            {
                CloseTransportInternal();
                return new ClientOperationResult
                {
                    IsSuccess = false,
                    Message = "Server closed connection without sending a complete response frame."
                };
            }

            if (respResult.FramingErrorCode != 0)
            {
                CloseTransportInternal();
                Log("ERROR", $"Received malformed frame from server (Code={respResult.FramingErrorCode}): {respResult.FramingErrorMessage}");
                return new ClientOperationResult
                {
                    IsSuccess = false,
                    ErrorCode = respResult.FramingErrorCode,
                    Message = $"Received malformed frame from server: {respResult.FramingErrorMessage}"
                };
            }

            if (respResult.Frame.MessageType == PvspMessageType.Error)
            {
                if (respResult.Frame.MessageId != expectedMsgId && respResult.Frame.MessageId != 0)
                {
                    CloseTransportInternal();
                    Log("ERROR", $"Protocol desynchronization on ERROR: expected MsgID={expectedMsgId} (or 0), got {respResult.Frame.MessageId}.");
                    return new ClientOperationResult
                    {
                        IsSuccess = false,
                        Message = "Received ERROR frame with mismatched Message ID."
                    };
                }

                if (!TryDeserializePayload<ErrorPayload>(respResult.Frame.PayloadBytes, out var err))
                {
                    CloseTransportInternal();
                    Log("ERROR", "Received ERROR frame with malformed JSON payload.");
                    return new ClientOperationResult
                    {
                        IsSuccess = false,
                        ErrorCode = PvspErrorCodes.InternalServer,
                        ErrorName = PvspErrorCodes.GetName(PvspErrorCodes.InternalServer),
                        Message = "Received malformed ERROR payload from server."
                    };
                }

                int code = err!.ErrorCode != 0 ? err.ErrorCode : PvspErrorCodes.InternalServer;

                if (PvspErrorCodes.ShouldCloseConnection(code))
                {
                    CloseTransportInternal();
                }

                return new ClientOperationResult
                {
                    IsSuccess = false,
                    ErrorCode = code,
                    ErrorName = string.IsNullOrEmpty(err.ErrorName) ? PvspErrorCodes.GetName(code) : err.ErrorName,
                    Message = string.IsNullOrEmpty(err.Message) ? "Unknown server error." : err.Message
                };
            }

            if (respResult.Frame.MessageType != PvspMessageType.DataResp || respResult.Frame.MessageId != expectedMsgId)
            {
                CloseTransportInternal();
                Log("ERROR", $"Protocol desynchronization: expected DATA_RESP MsgID={expectedMsgId}, got {respResult.Frame.MessageType} MsgID={respResult.Frame.MessageId}.");
                return new ClientOperationResult
                {
                    IsSuccess = false,
                    Message = $"Unexpected response frame type ({respResult.Frame.MessageType}) or mismatched Message ID."
                };
            }

            if (!TryDeserializePayload<DataRespPayload>(respResult.Frame.PayloadBytes, out var dataResp) ||
                !string.Equals(dataResp!.Status, "OK", StringComparison.Ordinal) ||
                (expectedAction != null && !string.Equals(dataResp.Action, expectedAction, StringComparison.Ordinal)))
            {
                CloseTransportInternal();
                Log("ERROR", "Received DATA_RESP frame with invalid status, action, or malformed JSON payload.");
                return new ClientOperationResult
                {
                    IsSuccess = false,
                    Message = "Received invalid DATA_RESP payload from server."
                };
            }

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
                Log("INFO", $"Auto-Reconnect attempt {attempt + 1}/{_backoffDelays.Length} in {delay.TotalSeconds:0.#}s...");
                await Task.Delay(delay, ct);

                try
                {
                    var (success, msg, _) = await EstablishSessionInternalAsync(_cachedUsername, _cachedPassword, ct);
                    if (success)
                    {
                        Log("INFO", "Auto-Reconnect successful: new TLS 1.3 session established and authenticated.");
                        return true;
                    }
                    Log("WARN", $"Auto-Reconnect attempt {attempt + 1} failed: {msg}");
                }
                catch (Exception ex)
                {
                    Log("ERROR", $"Auto-Reconnect attempt {attempt + 1} error: {ex.Message}");
                }
            }

            return false;
        }

        private static bool TryDeserializePayload<T>(byte[] payloadBytes, out T? result) where T : class
        {
            result = null;
            if (payloadBytes == null || payloadBytes.Length == 0)
                return false;

            try
            {
                result = JsonSerializer.Deserialize<T>(payloadBytes);
                return result != null;
            }
            catch (JsonException)
            {
                return false;
            }
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

        private void Log(string level, string message)
        {
            var handler = OnDiagnosticLog;
            if (handler == null)
                return;

            string timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
            string safeMessage = SanitizeLogMessage(message);
            handler($"[{timestamp} UTC] [{level}] [Session:{_host}:{_port}] {safeMessage}");
        }

        private static string SanitizeLogMessage(string? input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            var sb = new StringBuilder(input.Length);
            foreach (char c in input)
            {
                if (c == '\r') sb.Append("\\r");
                else if (c == '\n') sb.Append("\\n");
                else if (c == '\t') sb.Append("\\t");
                else if (char.IsControl(c)) sb.Append($"\\u{(int)c:x4}");
                else sb.Append(c);
            }
            return sb.ToString();
        }

        public void Dispose()
        {
            CloseTransportInternal();
            _cachedUsername = null;
            _cachedPassword = null;
            _ioLock.Dispose();
        }
    }
}