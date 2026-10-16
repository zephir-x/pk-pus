// Disable preview feature warnings for System.Net.Quic
#pragma warning disable CA2252
// Disable platform compatibility warnings (QUIC is only supported on specific OSes)
#pragma warning disable CA1416

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Pus.Client
{
    /// <summary>
    /// The main client application demonstrating secure TLS and QUIC communication.
    /// </summary>
    class Program
    {
        // Changed to async Task to support QUIC natively
        static async Task Main(string[] args)
        {
            // Parse arguments
            bool isTls = args.Contains("--tls");
            bool isQuic = args.Contains("--quic");
            string serverIp = "127.0.0.1";
            int port = 8080;
            string message = "Hello, this is a secret message sent over ";

            if (isQuic)
            {
                // Run QUIC Client
                await RunQuicClient(serverIp, port, message + "QUIC/UDP!");
            }
            else if (isTls)
            {
                // Run TLS Client
                RunTlsClient(serverIp, port, message + "TCP/mTLS!");
            }
            else
            {
                Console.WriteLine("Please specify a protocol flag (--tls or --quic)");
            }
        }

        /// <summary>
        /// Runs a QUIC client that connects over UDP with embedded TLS 1.3.
        /// </summary>
        static async Task RunQuicClient(string ip, int port, string message)
        {
            // 1. Define the exact same ALPN protocol as the server to negotiate successfully
            var alpnProtocol = new SslApplicationProtocol("pus-quic");

            // 2. Setup the client connection options
            var clientOptions = new QuicClientConnectionOptions
            {
                RemoteEndPoint = new IPEndPoint(IPAddress.Parse(ip), port),
                DefaultStreamErrorCode = 0x01,
                DefaultCloseErrorCode = 0x02,
                ClientAuthenticationOptions = new SslClientAuthenticationOptions
                {
                    ApplicationProtocols = new List<SslApplicationProtocol> { alpnProtocol },
                    // Tell the QUIC TLS layer to validate the server's certificate against our custom CA
                    RemoteCertificateValidationCallback = ValidateServerCertificateStrict
                }
            };

            try
            {
                Console.WriteLine($"[QUIC] Connecting to {ip}:{port} over UDP...");
                
                // 3. Initiate the QUIC Connection
                // This performs a highly optimized 1-RTT handshake combining transport and cryptographic setup
                await using var connection = await QuicConnection.ConnectAsync(clientOptions);
                Console.WriteLine("[QUIC] Connected and secured successfully!");

                // 4. Unlike TCP which is a single pipe, QUIC uses multiplexed streams
                // We open a Bidirectional stream to write data and read the response
                await using var stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
                Console.WriteLine($"[QUIC] Opened stream {stream.Id}. Sending data...");

                // 5. Send encrypted data over the UDP-backed stream
                byte[] data = Encoding.UTF8.GetBytes(message);
                await stream.WriteAsync(data);
                
                // Signal that we are done writing to this stream (equivalent to a TCP half-close)
                stream.CompleteWrites();
                Console.WriteLine($"[QUIC] Sent encrypted message: {message}");

                // 6. Await the server's encrypted response on the same stream
                byte[] buffer = new byte[2048];
                int receivedBytes = await stream.ReadAsync(buffer);
                Console.WriteLine($"[QUIC] Server response: {Encoding.UTF8.GetString(buffer, 0, receivedBytes)}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[QUIC Error]: {ex.Message}");
            }
        }
        
        // === TLS TCP CLIENT ===
        
        /// <summary>
        /// Runs a TCP client that wraps the connection in an SslStream.
        /// Provides a client certificate for Mutual TLS (mTLS).
        /// </summary>
        static void RunTlsClient(string ip, int port, string message)
        {
            // 1. Load the Client's certificate and private key
            // This is strictly required for Mutual TLS - the server will ask us to prove our identity
            string clientCertPath = "scripts/certs/client.crt";
            string clientKeyPath = "scripts/certs/client.key";
            using X509Certificate2 clientCertificate = X509Certificate2.CreateFromPemFile(clientCertPath, clientKeyPath);
            
            // 2. Add our certificate to a collection so SslStream can present it during the handshake
            X509CertificateCollection clientCerts = new X509CertificateCollection();
            clientCerts.Add(clientCertificate);
            Console.WriteLine($"[TLS] Loaded Client Certificate: {clientCertificate.Subject}");

            // 3. Create a standard TCP socket
            Socket clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            
            try
            {
                // 4. Initiate the raw TCP connection (Three-way handshake)
                clientSocket.Connect(new IPEndPoint(IPAddress.Parse(ip), port));
                Console.WriteLine($"[TCP] Raw connection established with server {ip}:{port}");

                // 5. Wrap the socket into a NetworkStream
                using NetworkStream networkStream = new NetworkStream(clientSocket);
                
                // 6. Wrap the NetworkStream in an SslStream
                // We attach 'ValidateServerCertificateStrict' to ensure the server isn't an impostor
                using SslStream sslStream = new SslStream(
                    networkStream, 
                    false, 
                    new RemoteCertificateValidationCallback(ValidateServerCertificateStrict)
                );

                Console.WriteLine("[TLS] Starting mTLS Handshake (presenting client certificate)...");
                
                // 7. Perform the TLS Handshake as a client
                // We pass 'clientCerts' here so the SslStream sends our certificate to the server when requested
                sslStream.AuthenticateAsClient("localhost", clientCerts, System.Security.Authentication.SslProtocols.None, false);
                
                Console.WriteLine("[TLS] Handshake successful! mTLS Connection is now encrypted and mutually verified.");
                Console.WriteLine($"[TLS] Cipher Algorithm: {sslStream.CipherAlgorithm}, Protocol: {sslStream.SslProtocol}");

                // 8. Convert the message to bytes and send it through the encrypted stream
                byte[] data = Encoding.UTF8.GetBytes(message);
                sslStream.Write(data, 0, data.Length);
                Console.WriteLine($"[TLS] Sent encrypted message: {message}");

                // 9. Wait for the server to reply and print the decrypted response
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
                // Always gracefully close the socket (sends a FIN packet)
                clientSocket.Close();
            }
        }

        /// <summary>
        /// Custom callback to validate the server's certificate strictly against our custom Certificate Authority.
        /// </summary>
        static bool ValidateServerCertificateStrict(
              object sender,
              X509Certificate? certificate,
              X509Chain? chain,
              SslPolicyErrors sslPolicyErrors)
        {
            // If the OS already trusts it, pass validation immediately
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Console.WriteLine($"[TLS/QUIC] Intercepted server validation error: {sslPolicyErrors}. Attempting custom CA resolution...");

            if (certificate == null || chain == null) 
                return false;

            try 
            {
                // 1. Load our custom Certificate Authority (CA) root certificate
                string caPath = "scripts/certs/ca.crt";
                using X509Certificate2 customCa = new X509Certificate2(caPath);
                
                // 2. Instruct the chain to use our custom Trust Store, bypassing the OS global store
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Clear();
                chain.ChainPolicy.CustomTrustStore.Add(customCa);
                
                // 3. Disable revocation checks (no CRL server exists for our local CA)
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

                // 4. Re-evaluate the certificate chain using our locally loaded CA
                bool isChainValid = chain.Build((X509Certificate2)certificate);
                
                if (isChainValid) 
                {
                    Console.WriteLine("[TLS/QUIC] SUCCESS: Server certificate securely validated against PUS_Local_CA!");
                    return true;
                }
                else 
                {
                    Console.WriteLine("[TLS/QUIC] FATAL: Server certificate chain validation failed.");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[TLS/QUIC Error] Custom CA processing failed: {ex.Message}");
                return false;
            }
        }
    }
}