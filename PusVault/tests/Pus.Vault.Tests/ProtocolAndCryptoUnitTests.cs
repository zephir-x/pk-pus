using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Pus.Vault.Common;
using Xunit;

namespace Pus.Vault.Tests
{
    public class ProtocolAndCryptoUnitTests
    {
        [Fact]
        public void CanonicalHmac_ShouldMatchSpecificationTestVectors_ForSetAndGet()
        {
            // Exact test vectors from Specification
            string hmacSecret = "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=";

            // 1. SET vector (Message ID = 3, 218 bytes)
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

            // 2. GET vector (Message ID = 4, 190 bytes)
            var getPayload = new DataReqPayload
            {
                SessionToken = "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                Action = "GET",
                Key = "STRIPE_API_KEY",
                Timestamp = 1762872008
            };

            string computedGetHmac = PvspCryptoHelper.ComputeDataReqHmacHex(hmacSecret, 4, getPayload);
            Assert.Equal("fca8790166d7423982168cf528aa3f5fe53de6fad1e941ef3c952e4bf50da754", computedGetHmac);

            getPayload.Hmac = computedGetHmac;
            byte[] getJsonBytes = PvspJsonSerializer.SerializeToUtf8Bytes(getPayload);
            Assert.Equal(190, getJsonBytes.Length);
            Assert.True(PvspCryptoHelper.VerifyDataReqHmac(hmacSecret, 4, getPayload));
        }

        [Fact]
        public async Task T07_FrameCodec_ShouldHandleFragmentedTcpStream_PartialReads()
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

        [Fact]
        public async Task T08_FrameCodec_ShouldRejectBadMagic_UnsupportedVersion_UnknownType_AndOversizedPayload()
        {
            // 1. Bad Magic Bytes (0x0000 instead of 0x5053) -> 100 ERR_BAD_MAGIC
            byte[] badMagicFrame = PvspFrameCodec.EncodeFrame(PvspMessageType.Ping, 1);
            badMagicFrame[0] = 0x00;
            badMagicFrame[1] = 0x00;
            using (var ms = new MemoryStream(badMagicFrame))
            {
                FrameReadResult res = await PvspFrameCodec.ReadFrameAsync(ms, CancellationToken.None);
                Assert.True(res.HeaderReadComplete);
                Assert.Equal(PvspErrorCodes.BadMagic, res.FramingErrorCode);
            }

            // 2. Unsupported Version (0x02 instead of 0x01) -> 101 ERR_UNSUPPORTED_VERSION
            byte[] badVerFrame = PvspFrameCodec.EncodeFrame(PvspMessageType.Ping, 1);
            badVerFrame[2] = 0x02;
            using (var ms = new MemoryStream(badVerFrame))
            {
                FrameReadResult res = await PvspFrameCodec.ReadFrameAsync(ms, CancellationToken.None);
                Assert.Equal(PvspErrorCodes.UnsupportedVersion, res.FramingErrorCode);
            }

            // 3. Unknown Message Type (0x99) -> 102 ERR_UNKNOWN_MSG_TYPE
            byte[] badTypeFrame = PvspFrameCodec.EncodeFrame(PvspMessageType.Ping, 1);
            badTypeFrame[3] = 0x99;
            using (var ms = new MemoryStream(badTypeFrame))
            {
                FrameReadResult res = await PvspFrameCodec.ReadFrameAsync(ms, CancellationToken.None);
                Assert.Equal(PvspErrorCodes.UnknownMsgType, res.FramingErrorCode);
            }

            // 4. Payload Length > 64 KiB (e.g., 70,000 bytes in header, 0 bytes following)
            // Must reject immediately with 103 ERR_PAYLOAD_TOO_LARGE without allocating or reading payload
            byte[] oversizedHeader = PvspFrameCodec.EncodeFrame(PvspMessageType.DataReq, 1);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(oversizedHeader.AsSpan(8, 4), 70000u);
            using (var ms = new MemoryStream(oversizedHeader))
            {
                FrameReadResult res = await PvspFrameCodec.ReadFrameAsync(ms, CancellationToken.None);
                Assert.True(res.HeaderReadComplete);
                Assert.Equal(PvspErrorCodes.PayloadTooLarge, res.FramingErrorCode);
                Assert.Empty(res.Frame.PayloadBytes);
            }
        }

        [Fact]
        public void T11_StrictJsonValidator_ShouldRejectInvalidUtf8_MalformedJson_UnknownOrDuplicateFields()
        {
            var allowed = new HashSet<string> { "clientName", "timestamp" };
            var required = new HashSet<string> { "clientName", "timestamp" };

            // 1. Invalid UTF-8 byte sequence (0xFF 0xFE) -> 104 ERR_INVALID_JSON
            byte[] invalidUtf8 = { 0xFF, 0xFE, 0xFD };
            Assert.False(PvspJsonSerializer.TryParseStrictJsonObject(invalidUtf8, allowed, required, out _, out int errCode1, out _));
            Assert.Equal(PvspErrorCodes.InvalidJson, errCode1);

            // 2. Broken JSON syntax -> 104 ERR_INVALID_JSON
            byte[] brokenJson = Encoding.UTF8.GetBytes("{\"clientName\":\"Pus\"");
            Assert.False(PvspJsonSerializer.TryParseStrictJsonObject(brokenJson, allowed, required, out _, out int errCode2, out _));
            Assert.Equal(PvspErrorCodes.InvalidJson, errCode2);

            // 3. Unknown field in JSON -> 106 ERR_INVALID_PAYLOAD
            byte[] unknownFieldJson = Encoding.UTF8.GetBytes("{\"clientName\":\"Pus\",\"timestamp\":123,\"extraField\":1}");
            Assert.False(PvspJsonSerializer.TryParseStrictJsonObject(unknownFieldJson, allowed, required, out _, out int errCode3, out _));
            Assert.Equal(PvspErrorCodes.InvalidPayload, errCode3);

            // 4. Duplicate key in JSON object -> 106 ERR_INVALID_PAYLOAD
            byte[] duplicateKeyJson = Encoding.UTF8.GetBytes("{\"clientName\":\"Pus\",\"clientName\":\"Evil\",\"timestamp\":123}");
            Assert.False(PvspJsonSerializer.TryParseStrictJsonObject(duplicateKeyJson, allowed, required, out _, out int errCode4, out _));
            Assert.Equal(PvspErrorCodes.InvalidPayload, errCode4);

            // 5. Missing required field -> 106 ERR_INVALID_PAYLOAD
            byte[] missingFieldJson = Encoding.UTF8.GetBytes("{\"clientName\":\"Pus\"}");
            Assert.False(PvspJsonSerializer.TryParseStrictJsonObject(missingFieldJson, allowed, required, out _, out int errCode5, out _));
            Assert.Equal(PvspErrorCodes.InvalidPayload, errCode5);

            // 6. Null field value -> 106 ERR_INVALID_PAYLOAD
            byte[] nullFieldJson = Encoding.UTF8.GetBytes("{\"clientName\":null,\"timestamp\":123}");
            Assert.False(PvspJsonSerializer.TryParseStrictJsonObject(nullFieldJson, allowed, required, out _, out int errCode6, out _));
            Assert.Equal(PvspErrorCodes.InvalidPayload, errCode6);
        }

        [Fact]
        public void T03_CustomCaValidator_ShouldRejectUntrustedCa_WrongSan_AndMissingServerAuthEku()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), "pus_cert_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);

            try
            {
                // Generate an untrusted rogue Root CA in memory
                using RSA rogueCaKey = RSA.Create(2048);
                var rogueCaReq = new CertificateRequest("CN=Rogue_CA", rogueCaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                rogueCaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                using X509Certificate2 rogueCaCert = rogueCaReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

                string rogueCaPath = Path.Combine(tempDir, "rogue_ca.crt");
                File.WriteAllText(rogueCaPath, rogueCaCert.ExportCertificatePem());

                // Generate a server certificate WITHOUT serverAuth EKU (only clientAuth 1.3.6.1.5.5.7.3.2)
                using RSA serverKey = RSA.Create(2048);
                var serverReq = new CertificateRequest("CN=localhost", serverKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                var ekuOids = new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }; // clientAuth only!
                serverReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(ekuOids, false));
                using X509Certificate2 certWithoutServerAuth = serverReq.Create(
                    rogueCaCert,
                    DateTimeOffset.UtcNow.AddDays(-1),
                    DateTimeOffset.UtcNow.AddDays(10),
                    Guid.NewGuid().ToByteArray());

                using var chain = new X509Chain();

                // 1. Reject when RemoteCertificateNameMismatch is flagged (SAN / hostname mismatch)
                Assert.False(PvspCryptoHelper.ValidateServerCertificateCustomCa(
                    certWithoutServerAuth, chain, SslPolicyErrors.RemoteCertificateNameMismatch, rogueCaPath));

                // 2. Reject when certificate lacks EKU serverAuth (1.3.6.1.5.5.7.3.1)
                Assert.False(PvspCryptoHelper.ValidateServerCertificateCustomCa(
                    certWithoutServerAuth, chain, SslPolicyErrors.None, rogueCaPath));
            }
            finally
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }

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