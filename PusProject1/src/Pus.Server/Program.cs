using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Pus.Server
{
    class Program
    {
        static void Main(string[] args)
        {
            // Parse command-line arguments to determine protocol and IP version
            bool isTcp = args.Contains("--tcp");
            bool useIpv6 = args.Contains("--ipv6");
            int port = 8080;

            if (isTcp) RunTcpServer(port, useIpv6);
            else RunUdpServer(port, useIpv6);
        }

        static void RunTcpServer(int port, bool useIpv6)
        {
            // 1. Create a stream-oriented socket for TCP communication
            // AddressFamily specifies the network layer (IPv4 or IPv6)
            // SocketType.Stream and ProtocolType.Tcp ensure reliable, connection-oriented data transfer
            AddressFamily family = useIpv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
            Socket serverSocket = new Socket(family, SocketType.Stream, ProtocolType.Tcp);

            if (useIpv6)
            {
                // Enable Dual-Stack mode. At the OS level, this disables the IPV6_V6ONLY socket option
                // It allows a single IPv6 socket to accept both IPv6 and IPv4 connections (mapped as ::ffff:x.x.x.x)
                serverSocket.DualMode = true;
            }
            
            // 2. Bind the socket to a local address and port
            // IPv6Any (::) or Any (0.0.0.0) means the server listens on all available network interfaces
            IPAddress bindAddress = useIpv6 ? IPAddress.IPv6Any : IPAddress.Any;
            serverSocket.Bind(new IPEndPoint(bindAddress, port));
            
            // 3. Put the socket into a listening state (TCP only)
            // The backlog parameter (10) specifies the maximum length of the pending connections queue
            serverSocket.Listen(10);
            Console.WriteLine($"[TCP] Server is listening on port {port} (IPv6/DualStack: {useIpv6})...");

            // Iterative server model: handles one client at a time in an infinite loop
            while (true)
            {
                // 4. Accept blocks until a connection arrives, then returns a NEW socket for this specific client
                Socket clientSocket = serverSocket.Accept();
                IPEndPoint remoteEndpoint = (IPEndPoint)clientSocket.RemoteEndPoint!;
                
                // Check if the connection came from an IPv4 client mapped to the IPv6 space
                if (useIpv6 && remoteEndpoint.Address.IsIPv4MappedToIPv6)
                {
                    Console.WriteLine($"[TCP] Accepted connection from IPv4 client mapped to IPv6: {remoteEndpoint}");
                }
                else
                {
                    Console.WriteLine($"[TCP] Accepted connection from native {(useIpv6 ? "IPv6" : "IPv4")} client: {remoteEndpoint}");
                }

                // 5. Receive data from the client
                byte[] buffer = new byte[1024];
                int receivedBytes = clientSocket.Receive(buffer);
                string message = Encoding.UTF8.GetString(buffer, 0, receivedBytes);
                Console.WriteLine($"[TCP] Received: {message}");

                // 6. Send an acknowledgment back to the client
                string response = $"TCP Server acknowledges receipt of: {message}";
                clientSocket.Send(Encoding.UTF8.GetBytes(response));

                // 7. Close the connected socket. The listening socket remains open
                clientSocket.Close();
                Console.WriteLine("[TCP] Connection with client closed.\n");
            }
        }

        static void RunUdpServer(int port, bool useIpv6)
        {
            // 1. Create a datagram-oriented socket for UDP communication
            AddressFamily family = useIpv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
            Socket serverSocket = new Socket(family, SocketType.Dgram, ProtocolType.Udp);

            if (useIpv6) serverSocket.DualMode = true;

            // 2. Bind the socket. UDP does not use Listen() or Accept() because it is connectionless
            IPAddress bindAddress = useIpv6 ? IPAddress.IPv6Any : IPAddress.Any;
            serverSocket.Bind(new IPEndPoint(bindAddress, port));
            
            Console.WriteLine($"[UDP] Server is waiting for datagrams on port {port} (IPv6/DualStack: {useIpv6})...");

            byte[] buffer = new byte[1024];
            EndPoint remoteEndPoint = new IPEndPoint(useIpv6 ? IPAddress.IPv6Any : IPAddress.Any, 0);

            while (true)
            {
                // 3. ReceiveFrom blocks until a datagram arrives and populates remoteEndPoint with the sender's info
                int receivedBytes = serverSocket.ReceiveFrom(buffer, ref remoteEndPoint);
                IPEndPoint ipRemote = (IPEndPoint)remoteEndPoint;

                if (useIpv6 && ipRemote.Address.IsIPv4MappedToIPv6)
                    Console.WriteLine($"[UDP] Received datagram from IPv4-mapped IPv6 client {ipRemote}");
                else
                    Console.WriteLine($"[UDP] Received datagram from {ipRemote}");

                string message = Encoding.UTF8.GetString(buffer, 0, receivedBytes);
                Console.WriteLine($"Message: {message}");

                // 4. SendTo replies directly to the address extracted from the received datagram
                string response = $"UDP Server acknowledges receipt of: {message}";
                serverSocket.SendTo(Encoding.UTF8.GetBytes(response), remoteEndPoint);
            }
        }
    }
}