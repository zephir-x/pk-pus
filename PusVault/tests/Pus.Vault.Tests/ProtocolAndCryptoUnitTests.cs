using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Pus.Vault.Common;
using Xunit;

namespace Pus.Vault.Tests
{
    public class ProtocolAndCryptoUnitTests
    {
        [Fact]
        public void CanonicalHmac_ShouldMatchSpecificationTestVector()
        {
            // Exact test vector from Specification
            string hmacSecret = "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=";

            var setPayload = new DataReqPayload
            {
                SessionToken = "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                Action = "SET",
                Key = "STRIPE_API_KEY",
                Value = "demo-secret-value",
                Timestamp = 1762872005
            };

            string computedSetHmac = PvspCryptoHelper.ComputeDataReqHmacHex(hmacSecret, 3, setPayload);
            Assert.Equal("fda9738508eec82c74f473d54be7981b103f10826c1234b91df59be4ba285e5f", computedSetHmac);

            setPayload.Hmac = computedSetHmac;
            byte[] setJsonBytes = PvspJsonSerializer.SerializeToUtf8Bytes(setPayload);
            Assert.Equal(218, setJsonBytes.Length);
            Assert.True(PvspCryptoHelper.VerifyDataReqHmac(hmacSecret, 3, setPayload));
        }

        [Fact]
        public async Task FrameCodec_ShouldHandleFragmentedTcpStream_PartialReads()
        {
            // Test T-07: Send a 56-byte HELLO frame in tiny 3-byte chunks and verify ReadExactly reassembles it
            var hello = new HelloPayload { ClientName = "PusVault-CLI/1.0", Timestamp = 1762872000 };
            byte[] payloadBytes = PvspJsonSerializer.SerializeToUtf8Bytes(hello);
            Assert.Equal(56, payloadBytes.Length);

            byte[] rawFrame = PvspFrameCodec.EncodeFrame(PvspMessageType.Hello, 1, payloadBytes);

            using var fragmentedStream = new FragmentedMemoryStream(rawFrame, maxBytesPerRead: 3);
            FrameReadResult readResult = await PvspFrameCodec.ReadFrameAsync(fragmentedStream, CancellationToken.None);

            Assert.False(readResult.IsEof);
            Assert.True(readResult.HeaderReadComplete);
            Assert.Equal(0, readResult.FramingErrorCode);
            Assert.Equal(PvspMessageType.Hello, readResult.Frame.MessageType);
            Assert.Equal(1u, readResult.Frame.MessageId);
            Assert.Equal(56u, readResult.Frame.PayloadLength);
        }

        // Helper stream that simulates TCP fragmentation by returning at most N bytes per ReadAsync call
        private class FragmentedMemoryStream : MemoryStream
        {
            private readonly int _maxBytesPerRead;
            public FragmentedMemoryStream(byte[] buffer, int maxBytesPerRead) : base(buffer) => _maxBytesPerRead = maxBytesPerRead;

            public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                var slice = buffer.Length > _maxBytesPerRead ? buffer[.._maxBytesPerRead] : buffer;
                return base.ReadAsync(slice, cancellationToken);
            }
        }
    }
}