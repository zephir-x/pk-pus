using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Pus.Server
{
    /// <summary>
    /// The main server application demonstrating various socket types (Stream, Datagram, Raw).
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            // Simple command line parsing to decide how the server should run
            bool isTcp = args.Contains("--tcp");
            bool isRaw = args.Contains("--raw");
            bool useIpv6 = args.Contains("--ipv6");
            int port = 8080;

            // Route to the correct server logic based on arguments
            if (isRaw) RunRawServer(port);
            else if (isTcp) RunTcpServer(port, useIpv6);
            else RunUdpServer(port, useIpv6);
        }

        static void RunRawServer(int port)
        {
            // Create a RAW socket
            // Why ProtocolType.Udp - because we want the OS to hand over raw UDP packets to us
            // We bypass the normal transport layer processing
            Socket serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Udp);

            // Bind it to listen on all available IPv4 interfaces (0.0.0.0) on our chosen port
            serverSocket.Bind(new IPEndPoint(IPAddress.Any, port));
            Console.WriteLine($"[RAW] Server is listening for raw IP/UDP packets on port {port}...");

            // In RAW sockets, we receive the ENTIRE IP packet, not just the message
            // So we need a big buffer (65536 is the max possible size of an IP packet)
            byte[] buffer = new byte[65536];
            EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);

            while (true)
            {
                // Wait until a raw packet arrives on our network card
                int receivedBytes = serverSocket.ReceiveFrom(buffer, ref remoteEndPoint);

                // --- DECODING THE IPv4 HEADER ---
                // The very first byte of the IP packet (buffer[0]) contains two pieces of info:
                // Version (IPv4) and Internet Header Length (IHL)
                // We use bitwise AND (& 0x0F) to grab only the last 4 bits (the IHL)
                int ihl = buffer[0] & 0x0F;
                
                // IHL tells us the length in 32-bit words - multiply by 4 to get the length in bytes
                // Usually, it's 5 words * 4 = 20 bytes
                int ipHeaderLen = ihl * 4;

                // Make sure the packet is big enough to even have an IP and UDP header (20 + 8 = 28 bytes)
                if (receivedBytes < ipHeaderLen + 8) continue;

                // --- DECODING THE UDP HEADER ---
                // The UDP header starts exactly where the IP header ends
                // The Destination Port is stored in the 3rd and 4th bytes of the UDP header
                // We shift the first byte left by 8 bits and combine it with the second byte to get the 16-bit port number
                ushort destPort = (ushort)((buffer[ipHeaderLen + 2] << 8) | buffer[ipHeaderLen + 3]);

                // Raw sockets receive ALL UDP traffic on the machine
                // We must manually throw away packets that are not meant for our specific port
                if (destPort != port) continue;

                // Extract the Source Port (1st and 2nd bytes of UDP header)
                ushort srcPort = (ushort)((buffer[ipHeaderLen] << 8) | buffer[ipHeaderLen + 1]);
                
                // Time To Live (TTL) is always the 9th byte in a standard IPv4 header (index 8)
                int ttl = buffer[8];
                
                // Extract the Source IP address (Bytes 12 to 15 in the IP header)
                string srcIp = $"{buffer[12]}.{buffer[13]}.{buffer[14]}.{buffer[15]}";

                // --- EXTRACTING THE ACTUAL MESSAGE ---
                int udpHeaderLen = 8;
                // Total received bytes minus the size of IP and UDP headers gives us the size of our text payload
                int payloadLen = receivedBytes - ipHeaderLen - udpHeaderLen;
                
                // Read the text exactly from where the UDP header ends
                string message = Encoding.UTF8.GetString(buffer, ipHeaderLen + udpHeaderLen, payloadLen);

                Console.WriteLine($"[RAW] Received packet from {srcIp}:{srcPort} (TTL: {ttl})");
                Console.WriteLine($"      Message: {message}\n");
            }
        }

        static void RunTcpServer(int port, bool useIpv6)
        {
            // Pick IPv4 or IPv6 based on the command line flag
            AddressFamily family = useIpv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
            
            // Create a reliable, connection-oriented stream socket (TCP)
            Socket serverSocket = new Socket(family, SocketType.Stream, ProtocolType.Tcp);

            if (useIpv6)
            {
                // This tells the Linux kernel "Hey, let IPv4 clients connect to this IPv6 socket too"
                // It maps their old IPv4 addresses to a fake IPv6 format (::ffff:x.x.x.x)
                serverSocket.DualMode = true;
            }
            
            // Bind the socket to the port so the OS knows to send traffic here
            IPAddress bindAddress = useIpv6 ? IPAddress.IPv6Any : IPAddress.Any;
            serverSocket.Bind(new IPEndPoint(bindAddress, port));
            
            // Listen() is only for TCP - it tells the OS to start queuing up people who want to connect
            serverSocket.Listen(10);
            Console.WriteLine($"[TCP] Server is listening on port {port} (IPv6/DualStack: {useIpv6})...");

            while (true)
            {
                // Accept() blocks the loop and waits for a client
                // When they connect, it gives us a brand NEW socket just for talking to them
                Socket clientSocket = serverSocket.Accept();
                IPEndPoint remoteEndpoint = (IPEndPoint)clientSocket.RemoteEndPoint!;
                
                // Check if the client is using the Dual-Stack mapped address feature
                if (useIpv6 && remoteEndpoint.Address.IsIPv4MappedToIPv6)
                {
                    Console.WriteLine($"[TCP] Accepted connection from IPv4 client mapped to IPv6: {remoteEndpoint}");
                }
                else
                {
                    Console.WriteLine($"[TCP] Accepted connection from native {(useIpv6 ? "IPv6" : "IPv4")} client: {remoteEndpoint}");
                }

                // Read whatever the client sent us
                byte[] buffer = new byte[1024];
                int receivedBytes = clientSocket.Receive(buffer);
                string message = Encoding.UTF8.GetString(buffer, 0, receivedBytes);
                Console.WriteLine($"[TCP] Received: {message}");

                // Send a nice reply back
                string response = $"TCP Server acknowledges receipt of: {message}";
                clientSocket.Send(Encoding.UTF8.GetBytes(response));

                // Always close the client's socket when done to free up resources (sends a FIN packet)
                clientSocket.Close();
                Console.WriteLine("[TCP] Connection with client closed.\n");
            }
        }

        static void RunUdpServer(int port, bool useIpv6)
        {
            // UDP is connectionless - we just need a Datagram socket
            AddressFamily family = useIpv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
            Socket serverSocket = new Socket(family, SocketType.Dgram, ProtocolType.Udp);

            if (useIpv6) serverSocket.DualMode = true;

            // Bind to the port - notice there is NO Listen() and NO Accept() here
            IPAddress bindAddress = useIpv6 ? IPAddress.IPv6Any : IPAddress.Any;
            serverSocket.Bind(new IPEndPoint(bindAddress, port));
            
            Console.WriteLine($"[UDP] Server is waiting for datagrams on port {port} (IPv6/DualStack: {useIpv6})...");

            byte[] buffer = new byte[1024];
            EndPoint remoteEndPoint = new IPEndPoint(useIpv6 ? IPAddress.IPv6Any : IPAddress.Any, 0);

            while (true)
            {
                // ReceiveFrom blocks until a UDP datagram flies in
                // It automatically fills 'remoteEndPoint' with the sender's IP and port
                int receivedBytes = serverSocket.ReceiveFrom(buffer, ref remoteEndPoint);
                IPEndPoint ipRemote = (IPEndPoint)remoteEndPoint;

                if (useIpv6 && ipRemote.Address.IsIPv4MappedToIPv6)
                    Console.WriteLine($"[UDP] Received datagram from IPv4-mapped IPv6 client {ipRemote}");
                else
                    Console.WriteLine($"[UDP] Received datagram from {ipRemote}");

                string message = Encoding.UTF8.GetString(buffer, 0, receivedBytes);
                Console.WriteLine($"      Message: {message}");

                // We use SendTo to shoot the reply directly back to where it came from
                string response = $"UDP Server acknowledges receipt of: {message}";
                serverSocket.SendTo(Encoding.UTF8.GetBytes(response), remoteEndPoint);
            }
        }
    }
}