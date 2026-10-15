using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Pus.Client
{
    /// <summary>
    /// The main client application capable of testing Stream, Datagram, and Raw sockets.
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            bool isTcp = args.Contains("--tcp");
            bool isRaw = args.Contains("--raw");
            bool useIpv6 = args.Contains("--ipv6");
            
            // Loopback addresses: ::1 for IPv6, 127.0.0.1 for IPv4
            string serverIp = useIpv6 ? "::1" : "127.0.0.1";
            int port = 8080;
            string message = "Hello!";

            if (isRaw) RunRawClient(serverIp, port, message);
            else if (isTcp) RunTcpClient(serverIp, port, message, useIpv6);
            else RunUdpClient(serverIp, port, message, useIpv6);
        }

        static void RunRawClient(string ip, int port, string message)
        {
            // Create a Raw socket
            // We use ProtocolType.Udp to match what the server is filtering for
            Socket clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Udp);
            
            try
            {
                // We must set the IP_HDRINCL (Header Included) option
                // This tells the Linux kernel: "Do NOT generate your own IPv4 header - 
                // I have already built it manually at the very beginning of my byte array"
                clientSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

                IPAddress destIp = IPAddress.Parse(ip);
                IPAddress sourceIp = IPAddress.Parse("127.0.0.1");
                ushort sourcePort = 55555; // just a random fake port we chose
                ushort destPort = (ushort)port;

                // Call our helper from Pus.Common to construct the packet byte-by-byte
                // It builds the 20-byte IPv4 header, the 8-byte UDP header, and appends the string message
                byte[] packet = Pus.Common.Ipv4UdpPacketBuilder.BuildPacket(sourceIp, destIp, sourcePort, destPort, message);

                // Print the entire packet in HEX format
                Console.WriteLine("[RAW] Packet bytes to send (HEX):");
                for (int i = 0; i < packet.Length; i++)
                {
                    Console.Write($"{packet[i]:X2} ");
                    if ((i + 1) % 16 == 0) Console.WriteLine(); // new line every 16 bytes for readability
                }
                Console.WriteLine("\n");

                // Send the manually crafted packet over the network
                clientSocket.SendTo(packet, new IPEndPoint(destIp, port));
                Console.WriteLine($"[RAW] Sent manually crafted IP packet to {destIp}:{port}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[RAW Error]: {ex.Message}");
            }
            finally
            {
                clientSocket.Close();
            }
        }

        static void RunTcpClient(string ip, int port, string message, bool useIpv6)
        {
            AddressFamily family = useIpv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
            Socket clientSocket = new Socket(family, SocketType.Stream, ProtocolType.Tcp);
            
            try
            {
                // Connect() initiates the famous "Three-way handshake" (SYN -> SYN-ACK -> ACK)
                // It blocks until the connection is fully established
                clientSocket.Connect(new IPEndPoint(IPAddress.Parse(ip), port));
                Console.WriteLine($"[TCP] Connected to server {ip}:{port}");

                // Convert our readable string into raw bytes and send it through the TCP stream
                byte[] data = Encoding.UTF8.GetBytes(message);
                clientSocket.Send(data);
                Console.WriteLine($"[TCP] Sent: {message}");

                // Wait for the server to reply
                byte[] buffer = new byte[1024];
                int receivedBytes = clientSocket.Receive(buffer);
                Console.WriteLine($"[TCP] Server response: {Encoding.UTF8.GetString(buffer, 0, receivedBytes)}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[TCP Error]: {ex.Message}");
            }
            finally
            {
                // Closing a TCP socket gracefully sends a 'FIN' packet to the server
                clientSocket.Close();
            }
        }

        static void RunUdpClient(string ip, int port, string message, bool useIpv6)
        {
            AddressFamily family = useIpv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
            Socket clientSocket = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
            IPEndPoint serverEndPoint = new IPEndPoint(IPAddress.Parse(ip), port);

            // UDP is "fire and forget" - there is no handshake - we just pack the data and throw it at the IP address
            byte[] data = Encoding.UTF8.GetBytes(message);
            clientSocket.SendTo(data, serverEndPoint);
            Console.WriteLine($"[UDP] Sent datagram: {message}");

            byte[] buffer = new byte[1024];
            EndPoint senderEndPoint = new IPEndPoint(useIpv6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
            
            try
            {
                // Because UDP has no connection state, if the packet gets lost, we would wait here forever
                // Setting ReceiveTimeout ensures we give up after 3 seconds
                clientSocket.ReceiveTimeout = 3000; 
                
                // Wait for the server's reply
                int receivedBytes = clientSocket.ReceiveFrom(buffer, ref senderEndPoint);
                Console.WriteLine($"[UDP] Server response: {Encoding.UTF8.GetString(buffer, 0, receivedBytes)}");
            }
            catch (SocketException)
            {
                Console.WriteLine("[UDP] No response (Timeout). The server might be offline.");
            }
            finally
            {
                clientSocket.Close();
            }
        }
    }
}