using System;

namespace Pus.Common
{
    public static class Checksum
    {
        /// <summary>
        /// Calculates the standard Internet Checksum based on RFC 1071.
        /// It sums up 16-bit words of the buffer and adds any carry bits.
        /// </summary>
        /// <param name="buffer">The byte array to calculate the checksum for.</param>
        /// <returns>A 16-bit unsigned integer representing the checksum.</returns>
        public static ushort Calculate(byte[] buffer)
        {
            int length = buffer.Length;
            int i = 0;
            uint sum = 0;

            // Sum all 16-bit words in the buffer
            while (length > 1)
            {
                // Combine two adjacent bytes into a 16-bit word (Big-Endian interpretation)
                // Bitwise left shift the first byte by 8 and add the second byte
                sum += (uint)((buffer[i] << 8) + buffer[i + 1]);
                i += 2;
                length -= 2;
            }

            // If there's an odd byte left at the end, pad it with zero and add
            if (length > 0)
            {
                sum += (uint)(buffer[i] << 8);
            }

            // Fold 32-bit sum to 16 bits by adding the carry (top 16 bits) to the bottom 16 bits
            while ((sum >> 16) != 0)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            // Return the one's complement of the final sum
            return (ushort)~sum;
        }
    }
}