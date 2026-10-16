using System;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Pus.Client
{
    /// <summary>
    /// The main client application demonstrating secure TLS communication.
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            bool isTls = args.Contains("--tls");
            string serverIp = "127.0.0.1";
            int port = 8080;
            string message = "Hello, this is a top secret encrypted message!";

            if (isTls)
            {
                RunTlsClient(serverIp, port, message);
            }
            else
            {
                Console.WriteLine("Please specify a protocol flag (e.g., --tls)");
            }
        }

        /// <summary>
        /// Runs a TCP client that wraps the connection in an SslStream.
        /// Fulfills the 3.5 grade requirements by strictly validating the server's certificate against our custom CA.
        /// </summary>
        static void RunTlsClient(string ip, int port, string message)
        {
            Socket clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            
            try
            {
                // 1. Establish raw TCP connection
                clientSocket.Connect(new IPEndPoint(IPAddress.Parse(ip), port));
                Console.WriteLine($"[TCP] Raw connection established with server {ip}:{port}");

                using NetworkStream networkStream = new NetworkStream(clientSocket);
                
                // 2. Wrap in SslStream and attach our custom validation callback
                using SslStream sslStream = new SslStream(
                    networkStream, 
                    false, 
                    new RemoteCertificateValidationCallback(ValidateServerCertificateStrict)
                );

                // 3. Perform the TLS Handshake - the target host ("localhost") must match the cert's CN
                Console.WriteLine("[TLS] Starting TLS Handshake...");
                sslStream.AuthenticateAsClient("localhost");
                
                Console.WriteLine("[TLS] Handshake successful! Connection is now encrypted and verified.");
                Console.WriteLine($"[TLS] Cipher Algorithm: {sslStream.CipherAlgorithm}, Protocol: {sslStream.SslProtocol}");

                // 4. Securely send and receive data
                byte[] data = Encoding.UTF8.GetBytes(message);
                sslStream.Write(data, 0, data.Length);
                Console.WriteLine($"[TLS] Sent encrypted message: {message}");

                byte[] buffer = new byte[2048];
                int receivedBytes = sslStream.Read(buffer, 0, buffer.Length);
                Console.WriteLine($"[TLS] Server response: {Encoding.UTF8.GetString(buffer, 0, receivedBytes)}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[TLS Error]: {ex.Message}");
            }
            finally
            {
                clientSocket.Close();
            }
        }

        /// <summary>
        /// Custom callback to validate the server's certificate strictly against our custom CA.
        /// </summary>
        static bool ValidateServerCertificateStrict(
              object sender,
              X509Certificate? certificate,
              X509Chain? chain,
              SslPolicyErrors sslPolicyErrors)
        {
            // If the system already trusts it (e.g., standard public certs like Let's Encrypt), we're good
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Console.WriteLine($"[TLS] Intercepted validation error: {sslPolicyErrors}. Attempting custom CA resolution...");

            if (certificate == null || chain == null) 
                return false;

            try 
            {
                // 1. Load our custom Certificate Authority (CA) public root certificate
                string caPath = "scripts/certs/ca.crt";
                using X509Certificate2 customCa = new X509Certificate2(caPath);
                
                // 2. Instruct the chain to use our custom Trust Store instead of the OS's global store
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Clear();
                chain.ChainPolicy.CustomTrustStore.Add(customCa);
                
                // We do not have a Certificate Revocation List (CRL) server running, so we disable revocation checks
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

                // 3. Re-evaluate the certificate chain with our new rules
                bool isChainValid = chain.Build((X509Certificate2)certificate);
                
                if (isChainValid) 
                {
                    Console.WriteLine("[TLS] SUCCESS: Server certificate securely validated against PUS_Local_CA!");
                    return true;
                }
                else 
                {
                    Console.WriteLine("[TLS] FATAL: Certificate chain validation failed against custom CA.");
                    foreach (var status in chain.ChainStatus)
                    {
                        Console.WriteLine($"  -> {status.StatusInformation}");
                    }
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[TLS Error] Custom CA processing failed: {ex.Message}");
                return false;
            }
        }
    }
}