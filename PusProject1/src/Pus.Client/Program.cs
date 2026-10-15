using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Pus.Client
{
    class Program
    {
        static void Main(string[] args)
        {
            bool isTcp = args.Contains("--tcp");
            bool useIpv6 = args.Contains("--ipv6");
            
            // IPv6 uses ::1 for loopback, while IPv4 uses 127.0.0.1
            string serverIp = useIpv6 ? "::1" : "127.0.0.1";
            int port = 8080;
            string message = "Hello from PUS Lab!";

            if (isTcp) RunTcpClient(serverIp, port, message, useIpv6);
            else RunUdpClient(serverIp, port, message, useIpv6);
        }

        static void RunTcpClient(string ip, int port, string message, bool useIpv6)
        {
            AddressFamily family = useIpv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
            Socket clientSocket = new Socket(family, SocketType.Stream, ProtocolType.Tcp);
            
            try
            {
                // 1. Initiate a TCP connection (triggers the 3-way handshake: SYN -> SYN-ACK -> ACK)
                clientSocket.Connect(new IPEndPoint(IPAddress.Parse(ip), port));
                Console.WriteLine($"[TCP] Connected to server {ip}:{port}");

                // 2. Convert the string message to a byte array and send it over the stream
                byte[] data = Encoding.UTF8.GetBytes(message);
                clientSocket.Send(data);
                Console.WriteLine($"[TCP] Sent: {message}");

                // 3. Wait for and receive the server's response
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
                // 4. Close the socket (sends a FIN packet to terminate the connection gracefully)
                clientSocket.Close();
            }
        }

        static void RunUdpClient(string ip, int port, string message, bool useIpv6)
        {
            AddressFamily family = useIpv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
            Socket clientSocket = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
            IPEndPoint serverEndPoint = new IPEndPoint(IPAddress.Parse(ip), port);

            // 1. Send the datagram. Unlike TCP, UDP does not establish a connection first
            byte[] data = Encoding.UTF8.GetBytes(message);
            clientSocket.SendTo(data, serverEndPoint);
            Console.WriteLine($"[UDP] Sent datagram: {message}");

            byte[] buffer = new byte[1024];
            EndPoint senderEndPoint = new IPEndPoint(useIpv6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
            
            try
            {
                // Set a timeout. Since UDP is connectionless, if the packet is lost, 
                // the client would otherwise block forever in ReceiveFrom
                clientSocket.ReceiveTimeout = 3000; 
                
                // 2. Wait for the server's response datagram
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