using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Pus.Server
{
    class Program
    {
        static void Main(string[] args)
        {
            bool isTcp = args.Length > 0 && args[0] == "--tcp";
            int port = 8080;

            if (isTcp)
            {
                RunTcpServer(port);
            }
            else
            {
                RunUdpServer(port);
            }
        }

        static void RunTcpServer(int port)
        {
            // 1. Create an IPv4 stream socket for TCP
            Socket serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            
            // 2. Bind the socket to the local IP address (INADDR_ANY) and port
            serverSocket.Bind(new IPEndPoint(IPAddress.Any, port));
            
            // 3. Enter the listening state - applies only to TCP
            serverSocket.Listen(10);
            Console.WriteLine($"[TCP] Server is listening on port {port}...");

            while (true)
            {
                // 4. Accept an incoming TCP connection - returns a new connected socket
                Socket clientSocket = serverSocket.Accept();
                Console.WriteLine($"[TCP] Accepted connection from: {clientSocket.RemoteEndPoint}");

                byte[] buffer = new byte[1024];
                // 5. Receive data (Recv)
                int receivedBytes = clientSocket.Receive(buffer);
                string message = Encoding.UTF8.GetString(buffer, 0, receivedBytes);
                Console.WriteLine($"[TCP] Received: {message}");

                // 6. Send response (Send)
                string response = $"TCP Server acknowledges receipt of: {message}";
                clientSocket.Send(Encoding.UTF8.GetBytes(response));

                // 7. Close the connection (Close)
                clientSocket.Close();
                Console.WriteLine("[TCP] Connection with client closed.\n");
            }
        }

        static void RunUdpServer(int port)
        {
            // 1. Create an IPv4 datagram socket for UDP
            Socket serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            
            // 2. Bind the socket to the address and port (no Listen or Accept in UDP)
            serverSocket.Bind(new IPEndPoint(IPAddress.Any, port));
            Console.WriteLine($"[UDP] Server is waiting for datagrams on port {port}...");

            byte[] buffer = new byte[1024];
            EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);

            while (true)
            {
                // 3. Receive datagram along with sender's address (Recvfrom)
                int receivedBytes = serverSocket.ReceiveFrom(buffer, ref remoteEndPoint);
                string message = Encoding.UTF8.GetString(buffer, 0, receivedBytes);
                Console.WriteLine($"[UDP] Received datagram from {remoteEndPoint}: {message}");

                // 4. Send response back to the sender (Sendto)
                string response = $"UDP Server acknowledges receipt of: {message}";
                serverSocket.SendTo(Encoding.UTF8.GetBytes(response), remoteEndPoint);
            }
        }
    }
}