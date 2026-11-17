using System;

namespace Pus.Vault.Common
{
    /// <summary>
    /// Defines global protocol constants and field byte limits.
    /// </summary>
    public static class PvspConstants
    {
        // First 2 bytes of every PVSP frame: 0x50 ('P') and 0x53 ('S') -> 0x5053 in Big-Endian
        public const ushort MagicBytes = 0x5053;

        // Current protocol version (1 byte: 0x01)
        public const byte ProtocolVersion = 0x01;

        // Fixed binary header size is always 12 bytes
        public const int HeaderSize = 12;

        // Maximum allowed JSON payload size is 64 KiB (65,536 bytes)
        public const uint MaxPayloadSize = 65536;

        // Field length limits in UTF-8 bytes
        public const int MaxClientNameBytes = 64;
        public const int MaxUsernameBytes = 64;
        public const int MaxPasswordBytes = 256;
        public const int MaxSessionTokenBytes = 128;
        public const int MaxKeyBytes = 128;
        public const int MaxValueBytes = 32768;
        public const int MaxErrorNameBytes = 64;
        public const int MaxErrorMessageBytes = 512;
        public const int MaxListKeysCount = 1000;

        // Anti-replay timestamp window: +/- 30 seconds
        public const long TimestampWindowSeconds = 30;
    }

    /// <summary>
    /// Defines the 1-byte Message Type identifiers.
    /// </summary>
    public enum PvspMessageType : byte
    {
        Hello = 0x01,     // Client -> Server: Initial greeting
        HelloAck = 0x02,  // Server -> Client: Greeting confirmation + serverNonce
        Auth = 0x03,      // Client -> Server: Login credentials + serverNonceEcho
        AuthAck = 0x04,   // Server -> Client: Login success + sessionToken + hmacSecret + role
        DataReq = 0x05,   // Client -> Server: Vault CRUD request (SET, GET, LIST, DELETE)
        DataResp = 0x06,  // Server -> Client: Vault CRUD response
        Ping = 0x07,      // Client -> Server: Keep-alive check (empty payload)
        Pong = 0x08,      // Server -> Client: Keep-alive response (empty payload)
        Bye = 0x09,       // Client -> Server: Graceful session close (empty payload)
        Error = 0xFF      // Server -> Client: Protocol or application error
    }

    /// <summary>
    /// Defines the stateful session phases on the server.
    /// </summary>
    public enum PvspSessionState
    {
        Disconnected,
        TlsConnected,
        Handshaked,
        Authenticated,
        Closed
    }

    /// <summary>
    /// Defines all numerical error codes and their symbolic names.
    /// </summary>
    public static class PvspErrorCodes
    {
        // 1xx - Framing and format errors
        public const int BadMagic = 100;
        public const int UnsupportedVersion = 101;
        public const int UnknownMsgType = 102;
        public const int PayloadTooLarge = 103;
        public const int InvalidJson = 104;
        public const int Timeout = 105;
        public const int InvalidPayload = 106;
        public const int InvalidAction = 107;
        public const int ResponseTooLarge = 108;

        // 2xx - Authentication, state, and security errors
        public const int AuthFailed = 201;
        public const int UnauthorizedState = 202;
        public const int Forbidden = 203;
        public const int InvalidHmac = 204;

        // 3xx - Freshness and sequence errors
        public const int ReplayDetected = 301;
        public const int DuplicateMsg = 302;

        // 4xx - Business logic and rate limit errors
        public const int KeyNotFound = 404;
        public const int RateLimit = 429;

        // 5xx - Internal server errors
        public const int InternalServer = 500;

        /// <summary>
        /// Converts a numeric error code into its official symbolic name from the specification.
        /// </summary>
        public static string GetName(int errorCode) => errorCode switch
        {
            BadMagic => "ERR_BAD_MAGIC",
            UnsupportedVersion => "ERR_UNSUPPORTED_VERSION",
            UnknownMsgType => "ERR_UNKNOWN_MSG_TYPE",
            PayloadTooLarge => "ERR_PAYLOAD_TOO_LARGE",
            InvalidJson => "ERR_INVALID_JSON",
            Timeout => "ERR_TIMEOUT",
            InvalidPayload => "ERR_INVALID_PAYLOAD",
            InvalidAction => "ERR_INVALID_ACTION",
            ResponseTooLarge => "ERR_RESPONSE_TOO_LARGE",
            AuthFailed => "ERR_AUTH_FAILED",
            UnauthorizedState => "ERR_UNAUTHORIZED_STATE",
            Forbidden => "ERR_FORBIDDEN",
            InvalidHmac => "ERR_INVALID_HMAC",
            ReplayDetected => "ERR_REPLAY_DETECTED",
            DuplicateMsg => "ERR_DUPLICATE_MSG",
            KeyNotFound => "ERR_KEY_NOT_FOUND",
            RateLimit => "ERR_RATE_LIMIT",
            _ => "ERR_INTERNAL_SERVER"
        };

        /// <summary>
        /// Determines whether a given error code must immediately terminate the TCP/TLS connection.
        /// </summary>
        public static bool ShouldCloseConnection(int errorCode) => errorCode switch
        {
            BadMagic or UnsupportedVersion or UnknownMsgType or PayloadTooLarge or Timeout or InvalidHmac or ReplayDetected => true,
            _ => false
        };
    }
}