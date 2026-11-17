using System;
using System.Buffers.Binary;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Pus.Vault.Common
{
    /// <summary>
    /// Represents a complete PVSP frame (12-byte binary header + raw UTF-8 JSON payload bytes).
    /// </summary>
    public class PvspFrame
    {
        public ushort Magic { get; set; } = PvspConstants.MagicBytes;
        public byte Version { get; set; } = PvspConstants.ProtocolVersion;
        public PvspMessageType MessageType { get; set; }
        public uint MessageId { get; set; }
        public uint PayloadLength { get; set; }
        public byte[] PayloadBytes { get; set; } = Array.Empty<byte>();
    }

    /// <summary>
    /// Result of reading a PVSP frame from the stream.
    /// </summary>
    public class FrameReadResult
    {
        public bool IsEof { get; set; }
        public bool HeaderReadComplete { get; set; }
        public int FramingErrorCode { get; set; }
        public string FramingErrorMessage { get; set; } = string.Empty;
        public PvspFrame Frame { get; set; } = new();
    }

    /// <summary>
    /// Encodes and decodes 12-byte Big-Endian binary headers and handles TCP stream framing via ReadExactly.
    /// </summary>
    public static class PvspFrameCodec
    {
        /// <summary>
        /// Encodes a 12-byte binary header in Network Byte Order (Big-Endian) and combines it with the payload.
        /// Header layout:
        /// [0..1] Magic Bytes (0x5053)
        /// [2]    Version (0x01)
        /// [3]    Message Type
        /// [4..7] Message ID (uint32, Big-Endian)
        /// [8..11] Payload Length (uint32, Big-Endian)
        /// </summary>
        public static byte[] EncodeFrame(PvspMessageType messageType, uint messageId, byte[]? payloadBytes = null)
        {
            payloadBytes ??= Array.Empty<byte>();
            uint payloadLen = (uint)payloadBytes.Length;

            // Allocate a single buffer for the 12-byte header + N-byte payload
            byte[] frameBuffer = new byte[PvspConstants.HeaderSize + payloadLen];

            // Bytes [0..1]: Magic Bytes (0x5053 -> 'P', 'S') in Big-Endian
            BinaryPrimitives.WriteUInt16BigEndian(frameBuffer.AsSpan(0, 2), PvspConstants.MagicBytes);

            // Byte [2]: Protocol Version (0x01)
            frameBuffer[2] = PvspConstants.ProtocolVersion;

            // Byte [3]: Message Type
            frameBuffer[3] = (byte)messageType;

            // Bytes [4..7]: Message ID (uint32, Big-Endian)
            BinaryPrimitives.WriteUInt32BigEndian(frameBuffer.AsSpan(4, 4), messageId);

            // Bytes [8..11]: Payload Length (uint32, Big-Endian)
            BinaryPrimitives.WriteUInt32BigEndian(frameBuffer.AsSpan(8, 4), payloadLen);

            // Bytes [12..N]: Copy JSON payload bytes if present
            if (payloadLen > 0)
            {
                Buffer.BlockCopy(payloadBytes, 0, frameBuffer, PvspConstants.HeaderSize, (int)payloadLen);
            }

            return frameBuffer;
        }

        /// <summary>
        /// Writes a complete PVSP frame to the stream and flushes it.
        /// </summary>
        public static async Task WriteFrameAsync(
            Stream stream,
            PvspMessageType messageType,
            uint messageId,
            byte[]? payloadBytes,
            CancellationToken cancellationToken)
        {
            byte[] rawFrame = EncodeFrame(messageType, messageId, payloadBytes);
            await stream.WriteAsync(rawFrame, cancellationToken);
            await stream.FlushAsync(cancellationToken);
        }

        /// <summary>
        /// Reads a complete PVSP frame from the stream using the ReadExactly loop.
        /// Validates the 12-byte header BEFORE allocating memory for the payload to prevent DoS attacks.
        /// </summary>
        public static async Task<FrameReadResult> ReadFrameAsync(Stream stream, CancellationToken cancellationToken)
        {
            var result = new FrameReadResult();
            byte[] headerBuffer = new byte[PvspConstants.HeaderSize];

            // Step 1: Read exactly 12 bytes of the binary header
            int headerBytesRead = await ReadExactlyLoopAsync(stream, headerBuffer, PvspConstants.HeaderSize, cancellationToken);

            // If 0 bytes were read, the remote peer cleanly closed the connection (EOF)
            if (headerBytesRead == 0)
            {
                result.IsEof = true;
                return result;
            }

            // If stream closed mid-header (1..11 bytes), we cannot even send an ERROR frame back
            if (headerBytesRead < PvspConstants.HeaderSize)
            {
                result.HeaderReadComplete = false;
                return result;
            }

            result.HeaderReadComplete = true;

            // Step 2: Decode fields from Big-Endian (Network Byte Order)
            ushort magic = BinaryPrimitives.ReadUInt16BigEndian(headerBuffer.AsSpan(0, 2));
            byte version = headerBuffer[2];
            byte rawType = headerBuffer[3];
            uint messageId = BinaryPrimitives.ReadUInt32BigEndian(headerBuffer.AsSpan(4, 4));
            uint payloadLength = BinaryPrimitives.ReadUInt32BigEndian(headerBuffer.AsSpan(8, 4));

            result.Frame.Magic = magic;
            result.Frame.Version = version;
            result.Frame.MessageId = messageId;
            result.Frame.PayloadLength = payloadLength;

            // Step 3: Validate binary header fields BEFORE allocating payload memory
            if (magic != PvspConstants.MagicBytes)
            {
                result.FramingErrorCode = PvspErrorCodes.BadMagic;
                result.FramingErrorMessage = $"Invalid Magic Bytes: expected 0x5053, got 0x{magic:X4}.";
                return result;
            }

            if (version != PvspConstants.ProtocolVersion)
            {
                result.FramingErrorCode = PvspErrorCodes.UnsupportedVersion;
                result.FramingErrorMessage = $"Unsupported protocol version: 0x{version:X2}.";
                return result;
            }

            if (!Enum.IsDefined(typeof(PvspMessageType), rawType))
            {
                result.FramingErrorCode = PvspErrorCodes.UnknownMsgType;
                result.FramingErrorMessage = $"Unknown Message Type: 0x{rawType:X2}.";
                return result;
            }

            result.Frame.MessageType = (PvspMessageType)rawType;

            if (payloadLength > PvspConstants.MaxPayloadSize)
            {
                result.FramingErrorCode = PvspErrorCodes.PayloadTooLarge;
                result.FramingErrorMessage = $"Payload length ({payloadLength} B) exceeds maximum limit of {PvspConstants.MaxPayloadSize} B.";
                return result;
            }

            // Step 4: Allocate buffer and read exactly PayloadLength bytes
            if (payloadLength > 0)
            {
                byte[] payloadBuffer = new byte[payloadLength];
                int payloadBytesRead = await ReadExactlyLoopAsync(stream, payloadBuffer, (int)payloadLength, cancellationToken);

                // If client disconnected in the middle of the payload, treat as incomplete stream close
                if (payloadBytesRead < payloadLength)
                {
                    result.HeaderReadComplete = false;
                    return result;
                }

                result.Frame.PayloadBytes = payloadBuffer;
            }

            return result;
        }

        /// <summary>
        /// Explicit ReadExactly loop that keeps reading from the TCP/TLS stream until the requested byte count is met
        /// or the stream reaches EOF. Solves TCP packet fragmentation / partial reads.
        /// </summary>
        public static async Task<int> ReadExactlyLoopAsync(
            Stream stream,
            byte[] buffer,
            int count,
            CancellationToken cancellationToken)
        {
            int totalRead = 0;
            while (totalRead < count)
            {
                int bytesRead = await stream.ReadAsync(
                    buffer.AsMemory(totalRead, count - totalRead),
                    cancellationToken);

                // ReadAsync returns 0 when the remote socket has closed the connection (FIN)
                if (bytesRead == 0)
                {
                    break;
                }

                totalRead += bytesRead;
            }

            return totalRead;
        }
    }
}