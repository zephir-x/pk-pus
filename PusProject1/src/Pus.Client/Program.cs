using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Pus.Client
{
    class Program
    {
        static void Main(string[] args)
        {
            bool isTcp = args.Length > 0 && args[0] == "--tcp";
            string serverIp = "127.0.0.1";
            int port = 8080;
            string message = "Hello!";

            if (isTcp)
            {
                RunTcpClient(serverIp, port, message);
            }
            else
            {
                RunUdpClient(serverIp, port, message);
            }
        }

        static void RunTcpClient(string ip, int port, string message)
        {
            Socket clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            
            try
            {
                // Initiate TCP connection (Three-way handshake)
                clientSocket.Connect(new IPEndPoint(IPAddress.Parse(ip), port));
                Console.WriteLine($"[TCP] Connected to server {ip}:{port}");

                byte[] data = Encoding.UTF8.GetBytes(message);
                clientSocket.Send(data);
                Console.WriteLine($"[TCP] Sent: {message}");

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
                clientSocket.Close();
            }
        }

        static void RunUdpClient(string ip, int port, string message)
        {
            Socket clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            IPEndPoint serverEndPoint = new IPEndPoint(IPAddress.Parse(ip), port);

            byte[] data = Encoding.UTF8.GetBytes(message);
            
            // Send datagram to the specified address
            clientSocket.SendTo(data, serverEndPoint);
            Console.WriteLine($"[UDP] Sent datagram: {message}");

            // Receive response
            byte[] buffer = new byte[1024];
            EndPoint senderEndPoint = new IPEndPoint(IPAddress.Any, 0);
            
            try
            {
                clientSocket.ReceiveTimeout = 3000; // 3 seconds timeout
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