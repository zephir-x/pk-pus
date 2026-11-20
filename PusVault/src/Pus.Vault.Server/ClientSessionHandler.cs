using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Pus.Vault.Common;

namespace Pus.Vault.Server
{
    /// <summary>
    /// Manages the stateful lifecycle of a single connected client session over an authenticated TLS 1.3 stream.
    /// Enforces the PVSP state machine, absolute phase deadlines, write timeouts, anti-replay rules, sliding-window rate limits, and RBAC.
    /// </summary>
    public class ClientSessionHandler
    {
        // Allowed JSON fields per message type
        private static readonly HashSet<string> HelloFields = new(StringComparer.Ordinal) { "clientName", "timestamp" };
        private static readonly HashSet<string> AuthFields = new(StringComparer.Ordinal) { "username", "password", "serverNonceEcho", "timestamp" };
        private static readonly HashSet<string> DataReqAllowedFields = new(StringComparer.Ordinal) { "sessionToken", "action", "key", "value", "timestamp", "hmac" };
        private static readonly HashSet<string> DataReqRequiredFields = new(StringComparer.Ordinal) { "sessionToken", "action", "timestamp", "hmac" };

        private readonly Stream _stream;
        private readonly string _clientEndpoint;
        private readonly string _clientIp;
        private readonly AuthAndRbacModule _authModule;
        private readonly IVaultStorage _storageEngine;
        private readonly SecurityAuditLogger _logger;
        private readonly Action<string, double>? _onDataReqCompleted;

        // Configurable timeouts (defaulting to specification values: 10s HELLO, 15s AUTH, 60s Idle, 5s Write)
        private readonly TimeSpan _helloTimeout;
        private readonly TimeSpan _authTimeout;
        private readonly TimeSpan _idleTimeout;
        private readonly TimeSpan _writeTimeout = TimeSpan.FromSeconds(5);

        // Session state fields
        private PvspSessionState _state = PvspSessionState.TlsConnected;
        private DateTime _phaseDeadlineUtc;
        private string _serverNonce = string.Empty;
        private int _failedAuthAttemptsInSession;
        private AuthenticatedSessionInfo? _authenticatedSession;

        // Strictly monotonic sequence number state
        private uint _lastAcceptedMessageId;

        // Isolated deduplication cache strictly for the most recent authenticated DATA_REQ
        private uint _lastDataReqMessageId;
        private byte[]? _lastDataReqDigest;
        private byte[]? _lastDataReqResponseFrameBytes;

        // Sliding window rate limiter: max 20 DATA_REQ per 10 seconds
        private readonly Queue<DateTime> _dataReqTimestamps = new();

        public ClientSessionHandler(
            Stream stream,
            string clientEndpoint,
            string clientIp,
            AuthAndRbacModule authModule,
            IVaultStorage storageEngine,
            SecurityAuditLogger logger,
            TimeSpan? helloTimeout = null,
            TimeSpan? authTimeout = null,
            TimeSpan? idleTimeout = null,
            Action<string, double>? onDataReqCompleted = null)
        {
            _stream = stream;
            _clientEndpoint = clientEndpoint;
            _clientIp = clientIp;
            _authModule = authModule;
            _storageEngine = storageEngine;
            _logger = logger;
            _onDataReqCompleted = onDataReqCompleted;

            _helloTimeout = helloTimeout ?? TimeSpan.FromSeconds(10);
            _authTimeout = authTimeout ?? TimeSpan.FromSeconds(15);
            _idleTimeout = idleTimeout ?? TimeSpan.FromSeconds(60);
        }

        /// <summary>
        /// Main loop processing incoming PVSP frames for the connected client until session closure.
        /// Enforces absolute deadlines for TLS_CONNECTED (HELLO) and HANDSHAKED (AUTH) phases,
        /// and resets the AUTHENTICATED idle deadline only upon receiving a valid authenticated frame.
        /// </summary>
        public async Task RunSessionAsync(CancellationToken serverShutdownToken)
        {
            _logger.LogInfo(_clientEndpoint, "Session entered TLS_CONNECTED state.");
            _phaseDeadlineUtc = DateTime.UtcNow + _helloTimeout;

            try
            {
                while (_state != PvspSessionState.Closed && !serverShutdownToken.IsCancellationRequested)
                {
                    TimeSpan remaining = _phaseDeadlineUtc - DateTime.UtcNow;
                    if (remaining <= TimeSpan.Zero)
                    {
                        _logger.LogWarn(_clientEndpoint, $"Session deadline exceeded in state {_state}.");
                        await SendErrorAndCloseAsync(0, PvspErrorCodes.Timeout, $"Session deadline exceeded in state {_state}.");
                        break;
                    }

                    using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(serverShutdownToken);
                    timeoutCts.CancelAfter(remaining);

                    FrameReadResult readResult;
                    try
                    {
                        readResult = await PvspFrameCodec.ReadFrameAsync(_stream, timeoutCts.Token);
                    }
                    catch (OperationCanceledException) when (!serverShutdownToken.IsCancellationRequested)
                    {
                        _logger.LogWarn(_clientEndpoint, $"Session timed out in state {_state}.");
                        await SendErrorAndCloseAsync(0, PvspErrorCodes.Timeout, $"Session deadline exceeded in state {_state}.");
                        break;
                    }

                    // Clean EOF or incomplete header/payload disconnect -> close without sending PVSP response
                    if (readResult.IsEof || !readResult.HeaderReadComplete)
                    {
                        _logger.LogInfo(_clientEndpoint, "Client disconnected cleanly or mid-frame.");
                        _state = PvspSessionState.Closed;
                        break;
                    }

                    // Fatal binary framing error (100 BadMagic, 101 Version, 102 UnknownType, 103 PayloadTooLarge)
                    if (readResult.FramingErrorCode != 0)
                    {
                        _logger.LogSecurity(_clientEndpoint, $"Framing error {readResult.FramingErrorCode}: {readResult.FramingErrorMessage}");
                        await SendErrorAndCloseAsync(readResult.Frame.MessageId, readResult.FramingErrorCode, readResult.FramingErrorMessage);
                        break;
                    }

                    await ProcessValidFrameAsync(readResult.Frame, serverShutdownToken);
                }
            }
            catch (OperationCanceledException) when (serverShutdownToken.IsCancellationRequested)
            {
                // Clean server shutdown requested
            }
            catch (OperationCanceledException)
            {
                // Write timeout expired (e.g., slow-reader client stopped consuming TCP data)
                _logger.LogWarn(_clientEndpoint, "Write timed out while sending response to client. Closing session.");
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
                _logger.LogInfo(_clientEndpoint, $"Transport connection closed: {ex.Message}");
            }
            catch (Exception ex)
            {
                _logger.LogError(_clientEndpoint, $"Unexpected session exception: {ex.Message}");
            }
            finally
            {
                _authenticatedSession = null;
                ClearDuplicateCache();
                _state = PvspSessionState.Closed;
                _logger.LogInfo(_clientEndpoint, "Session closed and resources released.");
            }
        }

        private async Task ProcessValidFrameAsync(PvspFrame frame, CancellationToken ct)
        {
            // Handle BYE (0x09) in any active state: must have empty payload and valid sequence ID
            if (frame.MessageType == PvspMessageType.Bye)
            {
                if (frame.PayloadLength != 0)
                {
                    ConsumeNonClosingErrorSequenceId(frame.MessageId);
                    await SendErrorAsync(frame.MessageId, PvspErrorCodes.InvalidPayload, "BYE frame must have an empty payload (PayloadLength = 0).", ct);
                    return;
                }

                if (!ValidateAndAdvanceSequenceId(frame, isDataReq: false, out _, out _, out int seqErrCode, out string seqErrMsg))
                {
                    await SendErrorAndCloseAsync(frame.MessageId, seqErrCode, seqErrMsg);
                    return;
                }

                _logger.LogInfo(_clientEndpoint, $"Rcv MsgID={frame.MessageId} Type=BYE -> Closing session.");
                _state = PvspSessionState.Closed;
                return;
            }

            // State Machine Dispatch
            switch (_state)
            {
                case PvspSessionState.TlsConnected:
                    if (frame.MessageType != PvspMessageType.Hello)
                    {
                        ConsumeNonClosingErrorSequenceId(frame.MessageId);
                        await SendErrorAsync(frame.MessageId, PvspErrorCodes.UnauthorizedState, "Client must send HELLO (0x01) first in TLS_CONNECTED state.", ct);
                        return;
                    }
                    await HandleHelloAsync(frame, ct);
                    break;

                case PvspSessionState.Handshaked:
                    if (frame.MessageType != PvspMessageType.Auth)
                    {
                        ConsumeNonClosingErrorSequenceId(frame.MessageId);
                        await SendErrorAsync(frame.MessageId, PvspErrorCodes.UnauthorizedState, "Client must complete AUTH handshake before sending other frames.", ct);
                        return;
                    }
                    await HandleAuthAsync(frame, ct);
                    break;

                case PvspSessionState.Authenticated:
                    if (frame.MessageType == PvspMessageType.Ping)
                    {
                        await HandlePingAsync(frame, ct);
                    }
                    else if (frame.MessageType == PvspMessageType.DataReq)
                    {
                        await HandleDataReqAsync(frame, ct);
                    }
                    else
                    {
                        ConsumeNonClosingErrorSequenceId(frame.MessageId);
                        await SendErrorAsync(frame.MessageId, PvspErrorCodes.UnauthorizedState, $"Message type {frame.MessageType} is not allowed in AUTHENTICATED state.", ct);
                    }
                    break;
            }
        }

        private async Task HandleHelloAsync(PvspFrame frame, CancellationToken ct)
        {
            if (frame.PayloadLength == 0)
            {
                ConsumeNonClosingErrorSequenceId(frame.MessageId);
                await SendErrorAsync(frame.MessageId, PvspErrorCodes.InvalidPayload, "HELLO requires a non-empty JSON payload.", ct);
                return;
            }

            if (!PvspJsonSerializer.TryParseStrictJsonObject(frame.PayloadBytes, HelloFields, HelloFields, out var fields, out int errCode, out string errMsg))
            {
                ConsumeNonClosingErrorSequenceId(frame.MessageId);
                await SendErrorAsync(frame.MessageId, errCode, errMsg, ct);
                return;
            }

            if (!PvspJsonSerializer.TryGetStringField(fields, "clientName", PvspConstants.MaxClientNameBytes, allowEmpty: false, out string clientName, out string fieldErr) ||
                !PvspJsonSerializer.TryGetInt64Field(fields, "timestamp", out long timestamp, out fieldErr))
            {
                ConsumeNonClosingErrorSequenceId(frame.MessageId);
                await SendErrorAsync(frame.MessageId, PvspErrorCodes.InvalidPayload, fieldErr, ct);
                return;
            }

            if (!ValidateAndAdvanceSequenceId(frame, isDataReq: false, out _, out _, out int seqErrCode, out string seqErrMsg))
            {
                await SendErrorAndCloseAsync(frame.MessageId, seqErrCode, seqErrMsg);
                return;
            }

            if (!IsTimestampFresh(timestamp))
            {
                _logger.LogSecurity(_clientEndpoint, $"Replay detected in HELLO: timestamp {timestamp} outside +/-30s window.");
                await SendErrorAndCloseAsync(frame.MessageId, PvspErrorCodes.ReplayDetected, "HELLO timestamp is outside the allowed +/- 30s window.");
                return;
            }

            _serverNonce = PvspCryptoHelper.GenerateServerNonceHex();
            _state = PvspSessionState.Handshaked;
            _phaseDeadlineUtc = DateTime.UtcNow + _authTimeout;

            var ackPayload = new HelloAckPayload
            {
                ServerVersion = "PusVault-Server/1.0",
                ServerNonce = _serverNonce,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            };

            byte[] ackBytes = PvspJsonSerializer.SerializeToUtf8Bytes(ackPayload);
            await WriteFrameWithTimeoutAsync(PvspMessageType.HelloAck, frame.MessageId, ackBytes, ct);
            _logger.LogInfo(_clientEndpoint, $"Rcv MsgID={frame.MessageId} Type=HELLO Client={clientName} -> Sent HELLO_ACK.");
        }

        private async Task HandleAuthAsync(PvspFrame frame, CancellationToken ct)
        {
            if (frame.PayloadLength == 0)
            {
                ConsumeNonClosingErrorSequenceId(frame.MessageId);
                await SendErrorAsync(frame.MessageId, PvspErrorCodes.InvalidPayload, "AUTH requires a non-empty JSON payload.", ct);
                return;
            }

            if (!PvspJsonSerializer.TryParseStrictJsonObject(frame.PayloadBytes, AuthFields, AuthFields, out var fields, out int errCode, out string errMsg))
            {
                ConsumeNonClosingErrorSequenceId(frame.MessageId);
                await SendErrorAsync(frame.MessageId, errCode, errMsg, ct);
                return;
            }

            if (!PvspJsonSerializer.TryGetStringField(fields, "username", PvspConstants.MaxUsernameBytes, allowEmpty: false, out string username, out string fieldErr) ||
                !PvspJsonSerializer.TryGetStringField(fields, "password", PvspConstants.MaxPasswordBytes, allowEmpty: false, out string password, out fieldErr) ||
                !PvspJsonSerializer.TryGetStringField(fields, "serverNonceEcho", 32, allowEmpty: false, out string nonceEcho, out fieldErr) ||
                !PvspJsonSerializer.TryGetInt64Field(fields, "timestamp", out long timestamp, out fieldErr))
            {
                ConsumeNonClosingErrorSequenceId(frame.MessageId);
                await SendErrorAsync(frame.MessageId, PvspErrorCodes.InvalidPayload, fieldErr, ct);
                return;
            }

            if (!ValidateAndAdvanceSequenceId(frame, isDataReq: false, out _, out _, out int seqErrCode, out string seqErrMsg))
            {
                await SendErrorAndCloseAsync(frame.MessageId, seqErrCode, seqErrMsg);
                return;
            }

            if (!IsTimestampFresh(timestamp))
            {
                _logger.LogSecurity(_clientEndpoint, $"Replay detected in AUTH: timestamp {timestamp} outside +/-30s window.");
                await SendErrorAndCloseAsync(frame.MessageId, PvspErrorCodes.ReplayDetected, "AUTH timestamp is outside the allowed +/- 30s window.");
                return;
            }

            if (!_authModule.TryAuthenticate(username, password, _serverNonce, nonceEcho, _clientIp, out var sessionInfo))
            {
                _failedAuthAttemptsInSession++;
                _logger.LogSecurity(_clientEndpoint, $"Authentication failed for user '{username}' (attempt {_failedAuthAttemptsInSession}/3).");

                if (_failedAuthAttemptsInSession >= 3)
                {
                    await SendErrorAndCloseAsync(frame.MessageId, PvspErrorCodes.AuthFailed, "Authentication failed (3 attempts exhausted). Closing connection.");
                }
                else
                {
                    await SendErrorAsync(frame.MessageId, PvspErrorCodes.AuthFailed, "Invalid credentials or serverNonceEcho.", ct);
                }
                return;
            }

            // Consume one-time serverNonce so it can never be reused
            _serverNonce = string.Empty;
            _authenticatedSession = sessionInfo;
            _state = PvspSessionState.Authenticated;
            _phaseDeadlineUtc = DateTime.UtcNow + _idleTimeout;

            var authAck = new AuthAckPayload
            {
                SessionToken = sessionInfo!.SessionToken,
                HmacSecret = sessionInfo.HmacSecretBase64,
                Role = sessionInfo.Role
            };

            byte[] ackBytes = PvspJsonSerializer.SerializeToUtf8Bytes(authAck);
            await WriteFrameWithTimeoutAsync(PvspMessageType.AuthAck, frame.MessageId, ackBytes, ct);
            _logger.LogInfo(_clientEndpoint, $"Rcv MsgID={frame.MessageId} Type=AUTH User={username} Role={sessionInfo.Role} -> Status=AUTHENTICATED.");
        }

        private async Task HandlePingAsync(PvspFrame frame, CancellationToken ct)
        {
            if (frame.PayloadLength != 0)
            {
                ConsumeNonClosingErrorSequenceId(frame.MessageId);
                await SendErrorAsync(frame.MessageId, PvspErrorCodes.InvalidPayload, "PING frame must have an empty payload (PayloadLength = 0).", ct);
                return;
            }

            if (!ValidateAndAdvanceSequenceId(frame, isDataReq: false, out _, out _, out int seqErrCode, out string seqErrMsg))
            {
                await SendErrorAndCloseAsync(frame.MessageId, seqErrCode, seqErrMsg);
                return;
            }

            _phaseDeadlineUtc = DateTime.UtcNow + _idleTimeout;
            await WriteFrameWithTimeoutAsync(PvspMessageType.Pong, frame.MessageId, Array.Empty<byte>(), ct);
            _logger.LogInfo(_clientEndpoint, $"Rcv MsgID={frame.MessageId} Type=PING -> Sent PONG.");
        }

        private async Task HandleDataReqAsync(PvspFrame frame, CancellationToken ct)
        {
            long processingStartTimestamp = _onDataReqCompleted != null ? Stopwatch.GetTimestamp() : 0;

            // Step 1 & 2: Framing is already verified; now validate UTF-8 and JSON syntax
            if (frame.PayloadLength == 0)
            {
                ConsumeNonClosingErrorSequenceId(frame.MessageId);
                await SendErrorAsync(frame.MessageId, PvspErrorCodes.InvalidPayload, "DATA_REQ requires a non-empty JSON payload.", ct);
                return;
            }

            if (!PvspJsonSerializer.TryParseStrictJsonObject(frame.PayloadBytes, DataReqAllowedFields, DataReqRequiredFields, out var fields, out int errCode, out string errMsg))
            {
                ConsumeNonClosingErrorSequenceId(frame.MessageId);
                await SendErrorAsync(frame.MessageId, errCode, errMsg, ct);
                return;
            }

            // Step 3: Validate field types and length limits
            if (!PvspJsonSerializer.TryGetStringField(fields, "sessionToken", PvspConstants.MaxSessionTokenBytes, allowEmpty: false, out string token, out string fieldErr) ||
                !PvspJsonSerializer.TryGetStringField(fields, "action", 16, allowEmpty: false, out string action, out fieldErr) ||
                !PvspJsonSerializer.TryGetInt64Field(fields, "timestamp", out long timestamp, out fieldErr) ||
                !PvspJsonSerializer.TryGetStringField(fields, "hmac", 128, allowEmpty: false, out string hmac, out fieldErr))
            {
                ConsumeNonClosingErrorSequenceId(frame.MessageId);
                await SendErrorAsync(frame.MessageId, PvspErrorCodes.InvalidPayload, fieldErr, ct);
                return;
            }

            string? key = null;
            if (fields.ContainsKey("key"))
            {
                if (!PvspJsonSerializer.TryGetStringField(fields, "key", PvspConstants.MaxKeyBytes, allowEmpty: false, out string parsedKey, out fieldErr) ||
                    !PvspJsonSerializer.IsValidSecretKeyFormat(parsedKey))
                {
                    ConsumeNonClosingErrorSequenceId(frame.MessageId);
                    await SendErrorAsync(frame.MessageId, PvspErrorCodes.InvalidPayload, "Invalid 'key' format or length (max 128 ASCII chars: alphanumeric, '_', '-', '.').", ct);
                    return;
                }
                key = parsedKey;
            }

            string? value = null;
            if (fields.ContainsKey("value"))
            {
                if (!PvspJsonSerializer.TryGetStringField(fields, "value", PvspConstants.MaxValueBytes, allowEmpty: true, out string parsedVal, out fieldErr))
                {
                    ConsumeNonClosingErrorSequenceId(frame.MessageId);
                    await SendErrorAsync(frame.MessageId, PvspErrorCodes.InvalidPayload, fieldErr, ct);
                    return;
                }
                value = parsedVal;
            }

            // Validate action and allowed combination of key/value fields
            if (action is not ("SET" or "GET" or "LIST" or "DELETE"))
            {
                ConsumeNonClosingErrorSequenceId(frame.MessageId);
                await SendErrorAsync(frame.MessageId, PvspErrorCodes.InvalidAction, "Unsupported action. Allowed actions: SET, GET, LIST, DELETE.", ct);
                return;
            }

            if ((action == "LIST" && (key != null || value != null)) ||
                (action is "GET" or "DELETE" && (key == null || value != null)) ||
                (action == "SET" && (key == null || value == null)))
            {
                ConsumeNonClosingErrorSequenceId(frame.MessageId);
                await SendErrorAsync(frame.MessageId, PvspErrorCodes.InvalidAction, $"Invalid combination of 'key'/'value' fields for action '{action}'.", ct);
                return;
            }

            // Step 5: Check Message ID sequence and duplicate request digest
            if (!ValidateAndAdvanceSequenceId(frame, isDataReq: true, out bool isDuplicate, out byte[] currentDigest, out int seqErrCode, out string seqErrMsg))
            {
                _logger.LogSecurity(_clientEndpoint, $"Sequence/Replay error on MsgID={frame.MessageId}: {seqErrMsg}");
                await SendErrorAndCloseAsync(frame.MessageId, seqErrCode, seqErrMsg);
                return;
            }

            if (isDuplicate && _lastDataReqResponseFrameBytes != null)
            {
                if (!IsTimestampFresh(timestamp))
                {
                    _logger.LogSecurity(_clientEndpoint, $"Replay detected on duplicate DATA_REQ MsgID={frame.MessageId}: timestamp {timestamp} outside +/-30s window.");
                    await SendErrorAndCloseAsync(frame.MessageId, PvspErrorCodes.ReplayDetected, "Request timestamp is outside the allowed +/- 30s window.");
                    return;
                }

                if (!CheckRateLimit())
                {
                    _logger.LogWarn(_clientEndpoint, $"Rate limit exceeded on duplicate DATA_REQ (max 20 DATA_REQ / 10s) on MsgID={frame.MessageId}.");
                    await SendErrorAsync(frame.MessageId, PvspErrorCodes.RateLimit, "Rate limit exceeded: maximum 20 DATA_REQ per 10 seconds.", ct);
                    return;
                }

                _phaseDeadlineUtc = DateTime.UtcNow + _idleTimeout;
                _logger.LogWarn(_clientEndpoint, $"Duplicate MsgID={frame.MessageId} with identical digest -> Re-sending cached response.");
                await WriteRawWithTimeoutAsync(_lastDataReqResponseFrameBytes, ct);
                return;
            }

            // Step 6: Check timestamp freshness window (+/- 30s)
            if (!IsTimestampFresh(timestamp))
            {
                _logger.LogSecurity(_clientEndpoint, $"Replay detected on DATA_REQ MsgID={frame.MessageId}: timestamp {timestamp} outside +/-30s window.");
                await SendErrorAndCloseAsync(frame.MessageId, PvspErrorCodes.ReplayDetected, "Request timestamp is outside the allowed +/- 30s window.");
                return;
            }

            // Step 7: Verify canonical HMAC-SHA256 in constant time
            var reqDto = new DataReqPayload
            {
                SessionToken = token,
                Action = action,
                Key = key,
                Value = value,
                Timestamp = timestamp,
                Hmac = hmac
            };

            if (_authenticatedSession == null ||
                !PvspCryptoHelper.VerifyDataReqHmac(_authenticatedSession.HmacSecretBase64, frame.MessageId, reqDto))
            {
                _logger.LogSecurity(_clientEndpoint, $"HMAC verification failed on MsgID={frame.MessageId} Action={action}. Terminating session.");
                await SendErrorAndCloseAsync(frame.MessageId, PvspErrorCodes.InvalidHmac, "Message integrity check failed (HMAC-SHA256 mismatch). Closing session.");
                return;
            }

            // Step 8: Verify active sessionToken binding
            if (!string.Equals(token, _authenticatedSession.SessionToken, StringComparison.Ordinal))
            {
                _logger.LogSecurity(_clientEndpoint, $"Session token mismatch on MsgID={frame.MessageId}.");
                await SendErrorAsync(frame.MessageId, PvspErrorCodes.UnauthorizedState, "Invalid sessionToken for current connection.", ct);
                return;
            }

            // Valid authenticated DATA_REQ received -> reset idle timeout
            _phaseDeadlineUtc = DateTime.UtcNow + _idleTimeout;

            // Step 9: Enforce Role-Based Access Control (RBAC)
            if (!AuthAndRbacModule.IsActionAuthorized(_authenticatedSession.Role, action))
            {
                _logger.LogSecurity(_clientEndpoint, $"RBAC Forbidden: User={_authenticatedSession.Username} Role={_authenticatedSession.Role} attempted {action}.");
                await SendErrorAsync(frame.MessageId, PvspErrorCodes.Forbidden, $"Insufficient permissions: role {_authenticatedSession.Role} cannot execute {action}.", ct, cacheDigest: currentDigest);
                return;
            }

            // Step 10: Enforce Sliding Window Rate Limit (20 DATA_REQ per 10 seconds)
            if (!CheckRateLimit())
            {
                _logger.LogWarn(_clientEndpoint, $"Rate limit exceeded (max 20 DATA_REQ / 10s) on MsgID={frame.MessageId}.");
                await SendErrorAsync(frame.MessageId, PvspErrorCodes.RateLimit, "Rate limit exceeded: maximum 20 DATA_REQ per 10 seconds.", ct, cacheDigest: currentDigest);
                return;
            }

            // Step 11: Execute storage operation
            await ExecuteVaultActionAsync(frame.MessageId, action, key, value, currentDigest, processingStartTimestamp, ct);
        }

        private async Task ExecuteVaultActionAsync(
            uint messageId,
            string action,
            string? key,
            string? value,
            byte[] requestDigest,
            long processingStartTimestamp,
            CancellationToken ct)
        {
            long nowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            DataRespPayload respPayload;

            switch (action)
            {
                case "SET":
                    var setStatus = _storageEngine.SetSecret(key!, value!);
                    if (setStatus != StorageOperationStatus.Committed)
                    {
                        _logger.LogError(_clientEndpoint, $"Storage commit failed during SET on MsgID={messageId}.");
                        await SendErrorAsync(messageId, PvspErrorCodes.InternalServer, "Failed to persist secret to storage.", ct, cacheDigest: requestDigest);
                        return;
                    }
                    respPayload = new DataRespPayload { Status = "OK", Action = "SET", Key = key, Timestamp = nowUnix };
                    break;

                case "GET":
                    var getStatus = _storageEngine.TryGetSecret(key!, out string? secretValue);
                    if (getStatus == StorageOperationStatus.KeyNotFound)
                    {
                        await SendErrorAsync(messageId, PvspErrorCodes.KeyNotFound, "Requested secret key does not exist.", ct, cacheDigest: requestDigest);
                        return;
                    }
                    respPayload = new DataRespPayload { Status = "OK", Action = "GET", Key = key, Value = secretValue, Timestamp = nowUnix };
                    break;

                case "DELETE":
                    var delStatus = _storageEngine.DeleteSecret(key!);
                    if (delStatus == StorageOperationStatus.KeyNotFound)
                    {
                        await SendErrorAsync(messageId, PvspErrorCodes.KeyNotFound, "Requested secret key does not exist.", ct, cacheDigest: requestDigest);
                        return;
                    }
                    if (delStatus != StorageOperationStatus.Committed)
                    {
                        await SendErrorAsync(messageId, PvspErrorCodes.InternalServer, "Failed to persist deletion to storage.", ct, cacheDigest: requestDigest);
                        return;
                    }
                    respPayload = new DataRespPayload { Status = "OK", Action = "DELETE", Key = key, Timestamp = nowUnix };
                    break;

                case "LIST":
                    var listStatus = _storageEngine.TryListKeys(out List<string> keys);
                    if (listStatus == StorageOperationStatus.ResponseTooLarge)
                    {
                        await SendErrorAsync(messageId, PvspErrorCodes.ResponseTooLarge, "LIST response exceeds maximum key count limit.", ct, cacheDigest: requestDigest);
                        return;
                    }
                    respPayload = new DataRespPayload { Status = "OK", Action = "LIST", Keys = keys, Timestamp = nowUnix };
                    break;

                default:
                    await SendErrorAsync(messageId, PvspErrorCodes.InvalidAction, "Unsupported action.", ct);
                    return;
            }

            byte[] respBytes = PvspJsonSerializer.SerializeToUtf8Bytes(respPayload);
            if (respBytes.Length > PvspConstants.MaxPayloadSize)
            {
                await SendErrorAsync(messageId, PvspErrorCodes.ResponseTooLarge, "Serialized response payload exceeds 64 KiB limit.", ct, cacheDigest: requestDigest);
                return;
            }

            byte[] encodedFrame = PvspFrameCodec.EncodeFrame(PvspMessageType.DataResp, messageId, respBytes);
            CacheDuplicateResponse(messageId, requestDigest, encodedFrame);

            await WriteRawWithTimeoutAsync(encodedFrame, ct);

            if (_onDataReqCompleted != null)
            {
                double elapsedMs = Stopwatch.GetElapsedTime(processingStartTimestamp).TotalMilliseconds;
                _onDataReqCompleted(action, elapsedMs);
            }

            _logger.LogInfo(_clientEndpoint, $"Rcv MsgID={messageId} Type=DATA_REQ Action={action} -> Status=OK");
        }

        private bool ValidateAndAdvanceSequenceId(
            PvspFrame frame,
            bool isDataReq,
            out bool isDuplicate,
            out byte[] currentDigest,
            out int errorCode,
            out string errorMessage)
        {
            isDuplicate = false;
            currentDigest = PvspCryptoHelper.ComputeSha256Digest(frame.PayloadBytes);
            errorCode = 0;
            errorMessage = string.Empty;

            // Message ID 0 is strictly reserved
            if (frame.MessageId == 0)
            {
                errorCode = PvspErrorCodes.ReplayDetected;
                errorMessage = "Message ID 0 is reserved and invalid.";
                return false;
            }

            // Check if this is a retry of the exact last authenticated DATA_REQ in the current session
            if (isDataReq &&
                _lastDataReqMessageId > 0 &&
                _lastDataReqMessageId == _lastAcceptedMessageId &&
                frame.MessageId == _lastDataReqMessageId)
            {
                if (_lastDataReqDigest != null &&
                    _lastDataReqResponseFrameBytes != null &&
                    CryptographicOperations.FixedTimeEquals(currentDigest, _lastDataReqDigest))
                {
                    isDuplicate = true;
                    return true;
                }

                errorCode = PvspErrorCodes.ReplayDetected;
                errorMessage = "Duplicate Message ID received with modified payload digest.";
                return false;
            }

            if (_lastAcceptedMessageId == uint.MaxValue)
            {
                errorCode = PvspErrorCodes.ReplayDetected;
                errorMessage = "Message ID counter exhausted for this session; reconnect required.";
                return false;
            }

            uint expectedId = _lastAcceptedMessageId + 1;
            if (frame.MessageId != expectedId)
            {
                errorCode = PvspErrorCodes.ReplayDetected;
                errorMessage = $"Out-of-sequence Message ID: expected {expectedId}, got {frame.MessageId}.";
                return false;
            }

            _lastAcceptedMessageId = frame.MessageId;
            ClearDuplicateCache();
            return true;
        }

        /// <summary>
        /// Advances the sequence counter when a non-closing validation/state error (104, 106, 107, 202)
        /// carries the exact next expected Message ID so the client can continue seamlessly with ID + 1,
        /// without allowing out-of-sequence jumps or poisoning the DATA_REQ duplicate cache.
        /// </summary>
        private void ConsumeNonClosingErrorSequenceId(uint messageId)
        {
            if (_lastAcceptedMessageId < uint.MaxValue && messageId == _lastAcceptedMessageId + 1)
            {
                _lastAcceptedMessageId = messageId;
                ClearDuplicateCache();
            }
        }

        private void CacheDuplicateResponse(uint messageId, byte[] requestDigest, byte[] encodedResponseFrame)
        {
            _lastDataReqMessageId = messageId;
            _lastDataReqDigest = requestDigest;
            _lastDataReqResponseFrameBytes = encodedResponseFrame;
        }

        private void ClearDuplicateCache()
        {
            _lastDataReqMessageId = 0;
            _lastDataReqDigest = null;
            _lastDataReqResponseFrameBytes = null;
        }

        private static bool IsTimestampFresh(long clientTimestamp)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            long minAllowed = now - PvspConstants.TimestampWindowSeconds;
            long maxAllowed = now + PvspConstants.TimestampWindowSeconds;
            return clientTimestamp >= minAllowed && clientTimestamp <= maxAllowed;
        }

        private bool CheckRateLimit()
        {
            DateTime now = DateTime.UtcNow;
            DateTime windowStart = now.AddSeconds(-10);

            while (_dataReqTimestamps.Count > 0 && _dataReqTimestamps.Peek() < windowStart)
            {
                _dataReqTimestamps.Dequeue();
            }

            if (_dataReqTimestamps.Count >= 20)
            {
                return false;
            }

            _dataReqTimestamps.Enqueue(now);
            return true;
        }

        private async Task WriteFrameWithTimeoutAsync(PvspMessageType messageType, uint messageId, byte[] payloadBytes, CancellationToken ct)
        {
            using var writeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            writeCts.CancelAfter(_writeTimeout);
            await PvspFrameCodec.WriteFrameAsync(_stream, messageType, messageId, payloadBytes, writeCts.Token);
        }

        private async Task WriteRawWithTimeoutAsync(byte[] encodedFrame, CancellationToken ct)
        {
            using var writeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            writeCts.CancelAfter(_writeTimeout);
            await _stream.WriteAsync(encodedFrame, writeCts.Token);
            await _stream.FlushAsync(writeCts.Token);
        }

        private async Task SendErrorAsync(
            uint messageId,
            int errorCode,
            string message,
            CancellationToken ct,
            byte[]? cacheDigest = null)
        {
            var errPayload = new ErrorPayload
            {
                ErrorCode = errorCode,
                ErrorName = SanitizeAndTruncateUtf8(PvspErrorCodes.GetName(errorCode), PvspConstants.MaxErrorNameBytes),
                Message = SanitizeAndTruncateUtf8(message, PvspConstants.MaxErrorMessageBytes),
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            };

            byte[] errBytes = PvspJsonSerializer.SerializeToUtf8Bytes(errPayload);
            byte[] encodedFrame = PvspFrameCodec.EncodeFrame(PvspMessageType.Error, messageId, errBytes);

            if (cacheDigest != null)
            {
                CacheDuplicateResponse(messageId, cacheDigest, encodedFrame);
            }

            await WriteRawWithTimeoutAsync(encodedFrame, ct);
        }

        private async Task SendErrorAndCloseAsync(uint messageId, int errorCode, string message)
        {
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await SendErrorAsync(messageId, errorCode, message, cts.Token);
            }
            catch
            {
                // Ignore write errors when already closing a broken/timed-out connection
            }
            finally
            {
                _state = PvspSessionState.Closed;
            }
        }

        private static string SanitizeAndTruncateUtf8(string input, int maxUtf8Bytes)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            var sb = new StringBuilder(input.Length);
            foreach (char c in input)
            {
                if (!char.IsControl(c))
                {
                    sb.Append(c);
                }
            }

            string cleaned = sb.ToString();
            while (Encoding.UTF8.GetByteCount(cleaned) > maxUtf8Bytes && cleaned.Length > 0)
            {
                cleaned = cleaned[..^1];
            }

            return cleaned;
        }
    }
}