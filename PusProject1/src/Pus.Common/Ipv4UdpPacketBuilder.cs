using System;
using System.Net;
using System.Text;

namespace Pus.Common
{
    public static class Ipv4UdpPacketBuilder
    {
        /// <summary>
        /// Manually constructs an IPv4 packet containing a UDP datagram.
        /// Demonstrates Raw Sockets usage (Level 3 OSI) by filling IP and UDP headers byte-by-byte.
        /// </summary>
        public static byte[] BuildPacket(IPAddress sourceIp, IPAddress destIp, ushort sourcePort, ushort destPort, string payloadString)
        {
            byte[] payload = Encoding.UTF8.GetBytes(payloadString);
            
            // Standard IPv4 Header size is 20 bytes (without options). UDP Header is 8 bytes
            int ipv4HeaderLen = 20;
            int udpHeaderLen = 8;
            int totalLen = ipv4HeaderLen + udpHeaderLen + payload.Length;

            byte[] packet = new byte[totalLen];

            // --------------------- IPv4 HEADER (Bytes 0 to 19) ---------------------
            
            // Byte 0: Version (4) in the high nibble (0100) and IHL (5 words = 20 bytes) in the low nibble (0101)
            packet[0] = 0x45; 
            
            // Byte 1: Type of Service (TOS) / Differentiated Services
            packet[1] = 0x00; 
            
            // Bytes 2-3: Total Length of the IP packet (Header + Payload) in Network Byte Order
            packet[2] = (byte)(totalLen >> 8);
            packet[3] = (byte)(totalLen & 0xFF);
            
            // Bytes 4-5: Identification (Random value, here we use fixed 0x1234 for simplicity)
            packet[4] = 0x12;
            packet[5] = 0x34;
            
            // Bytes 6-7: Flags and Fragment Offset (0 = no fragmentation)
            packet[6] = 0x00;
            packet[7] = 0x00;
            
            // Byte 8: Time To Live (TTL) - Max hops
            packet[8] = 64;
            
            // Byte 9: Protocol - 17 stands for UDP (IPPROTO_UDP)
            packet[9] = 17;
            
            // Bytes 10-11: IP Header Checksum (Initially 0, calculated later)
            packet[10] = 0x00;
            packet[11] = 0x00;
            
            // Bytes 12-15: Source IP Address
            byte[] srcBytes = sourceIp.GetAddressBytes();
            Array.Copy(srcBytes, 0, packet, 12, 4);
            
            // Bytes 16-19: Destination IP Address
            byte[] destBytes = destIp.GetAddressBytes();
            Array.Copy(destBytes, 0, packet, 16, 4);

            // Calculate the IP Header Checksum
            byte[] ipHeaderCopy = new byte[ipv4HeaderLen];
            Array.Copy(packet, 0, ipHeaderCopy, 0, ipv4HeaderLen);
            ushort ipChecksum = Checksum.Calculate(ipHeaderCopy);
            
            // Insert the calculated checksum in Network Byte Order
            packet[10] = (byte)(ipChecksum >> 8);
            packet[11] = (byte)(ipChecksum & 0xFF);


            // --------------------- UDP HEADER (Bytes 20 to 27) ---------------------
            
            int udpOffset = ipv4HeaderLen;
            int udpPacketLen = udpHeaderLen + payload.Length;

            // Bytes 20-21: Source Port
            packet[udpOffset] = (byte)(sourcePort >> 8);
            packet[udpOffset + 1] = (byte)(sourcePort & 0xFF);
            
            // Bytes 22-23: Destination Port
            packet[udpOffset + 2] = (byte)(destPort >> 8);
            packet[udpOffset + 3] = (byte)(destPort & 0xFF);
            
            // Bytes 24-25: UDP Length (Header + Data)
            packet[udpOffset + 4] = (byte)(udpPacketLen >> 8);
            packet[udpOffset + 5] = (byte)(udpPacketLen & 0xFF);
            
            // Bytes 26-27: UDP Checksum (Optional in IPv4, set to 0 to instruct OS/router not to verify it)
            packet[udpOffset + 6] = 0x00;
            packet[udpOffset + 7] = 0x00;

            
            // --------------------- PAYLOAD (Bytes 28 onwards) ---------------------
            Array.Copy(payload, 0, packet, udpOffset + 8, payload.Length);

            return packet;
        }
    }
}