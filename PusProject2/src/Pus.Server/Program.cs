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

namespace Pus.Server
{
    /// <summary>
    /// The main server application demonstrating secure TLS and QUIC communication.
    /// </summary>
    class Program
    {
        // Changed to async Task to support asynchronous QUIC operations natively
        static async Task Main(string[] args)
        {
            // Simple command line parsing to decide how the server should run
            bool isTls = args.Contains("--tls");
            bool isQuic = args.Contains("--quic");
            int port = 8080;

            if (isQuic)
            {
                // Run QUIC Server over UDP
                await RunQuicServer(port);
            }
            else if (isTls)
            {
                // Run TLS Server over TCP
                RunTlsServer(port);
            }
            else
            {
                Console.WriteLine("Please specify a protocol flag (--tls or --quic)");
            }
        }

        /// <summary>
        /// Runs a QUIC server over UDP.
        /// </summary>
        static async Task RunQuicServer(int port)
        {
            // 1. Load the server's certificate and private key
            // QUIC intrinsically requires TLS 1.3, so a certificate is strictly mandatory
            string certPath = "scripts/certs/server.crt";
            string keyPath = "scripts/certs/server.key";
            using X509Certificate2 serverCertificate = X509Certificate2.CreateFromPemFile(certPath, keyPath);
            Console.WriteLine($"[QUIC] Loaded Server Certificate: {serverCertificate.Subject}");

            // 2. Define the ALPN (Application-Layer Protocol Negotiation)
            // QUIC multiplexes multiple protocols over a single connection - we define a custom application protocol: "pus-quic"
            var alpnProtocol = new SslApplicationProtocol("pus-quic");

            // 3. Configure the QUIC listener options
            var listenerOptions = new QuicListenerOptions
            {
                // Bind to any available IPv4/IPv6 interface on the specified UDP port
                ListenEndPoint = new IPEndPoint(IPAddress.Any, port),
                // Specify which application protocols this server supports
                ApplicationProtocols = new List<SslApplicationProtocol> { alpnProtocol },
                // Provide a callback that configures the connection parameters once a client attempts to connect
                ConnectionOptionsCallback = (connection, sslInfo, cancellationToken) =>
                {
                    return ValueTask.FromResult(new QuicServerConnectionOptions
                    {
                        DefaultStreamErrorCode = 0x01,
                        DefaultCloseErrorCode = 0x02,
                        ServerAuthenticationOptions = new SslServerAuthenticationOptions
                        {
                            ApplicationProtocols = new List<SslApplicationProtocol> { alpnProtocol },
                            ServerCertificate = serverCertificate,
                            // To enforce Mutual TLS (mTLS) in QUIC, set this to true - for simplicity here, it's false
                            ClientCertificateRequired = false 
                        }
                    });
                }
            };

            try
            {
                // 4. Start listening for incoming QUIC connections (which arrive as UDP datagrams under the hood)
                await using var listener = await QuicListener.ListenAsync(listenerOptions);
                Console.WriteLine($"[QUIC] Server is listening on UDP port {port} (ALPN: {alpnProtocol})...");

                while (true)
                {
                    // 5. Accept an incoming QUIC connection
                    // Notice there is no 3-way TCP handshake - the QUIC handshake establishes encryption immediately
                    var connection = await listener.AcceptConnectionAsync();
                    Console.WriteLine($"[QUIC] Connection accepted from: {connection.RemoteEndPoint}");
                    
                    // Fire and forget a task to handle this specific client, allowing concurrent client handling
                    _ = HandleQuicClientAsync(connection);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[QUIC Error]: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles an individual QUIC connection by accepting its data streams.
        /// </summary>
        static async Task HandleQuicClientAsync(QuicConnection connection)
        {
            try
            {
                // QUIC multiplexes data into "Streams" - a client can open multiple streams within one single connection
                // Here we wait for the client to open an inbound stream
                await using var stream = await connection.AcceptInboundStreamAsync();
                Console.WriteLine($"[QUIC] Stream {stream.Id} accepted. Type: {stream.Type}");

                // Read data from the QUIC stream - it is automatically decrypted
                byte[] buffer = new byte[2048];
                int receivedBytes = await stream.ReadAsync(buffer);
                string message = Encoding.UTF8.GetString(buffer, 0, receivedBytes);
                Console.WriteLine($"[QUIC] Decrypted message received: {message}");

                // Send a response back through the exact same QUIC stream
                string response = $"QUIC Server securely acknowledges receipt of: {message}";
                byte[] responseData = Encoding.UTF8.GetBytes(response);
                await stream.WriteAsync(responseData);
                Console.WriteLine("[QUIC] Encrypted response sent to client.\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[QUIC Stream Error]: {ex.Message}");
            }
            finally
            {
                // Clean up the connection once the stream operations are complete
                await connection.DisposeAsync();
            }
        }
        
        // === TLS TCP SERVER ===
        
        /// <summary>
        /// Runs a TCP server that wraps the connection in an SslStream to provide TLS encryption.
        /// Enforces Mutual TLS (mTLS).
        /// </summary>
        static void RunTlsServer(int port)
        {
            // 1. Define paths to our custom server certificate and private key generated by OpenSSL
            string certPath = "scripts/certs/server.crt";
            string keyPath = "scripts/certs/server.key";
            
            // 2. Load the certificate and private key natively from PEM files (supported in modern .NET)
            using X509Certificate2 serverCertificate = X509Certificate2.CreateFromPemFile(certPath, keyPath);
            Console.WriteLine($"[TLS] Loaded Server Certificate: {serverCertificate.Subject}");

            // 3. Create a standard raw TCP socket (Layer 4)
            Socket serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            
            // 4. Bind the socket to all available network interfaces on our chosen port
            serverSocket.Bind(new IPEndPoint(IPAddress.Any, port));
            
            // 5. Start listening for incoming connections
            serverSocket.Listen(10);
            Console.WriteLine($"[TLS] Server is listening on port {port} (mTLS Enforced)...");

            while (true)
            {
                // 6. Accept() blocks until a client connects - it returns a NEW socket dedicated to this client
                Socket clientSocket = serverSocket.Accept();
                Console.WriteLine($"[TLS] TCP connection accepted from: {clientSocket.RemoteEndPoint}");

                try
                {
                    // 7. Wrap the raw Socket in a NetworkStream, as SslStream requires a Stream object to operate
                    using NetworkStream networkStream = new NetworkStream(clientSocket);
                    
                    // 8. Wrap the NetworkStream in an SslStream (Layer 7 / TLS)
                    // We attach 'ValidateClientCertificateStrict' to intercept and rigorously verify the client's certificate
                    using SslStream sslStream = new SslStream(
                        networkStream, 
                        false, 
                        new RemoteCertificateValidationCallback(ValidateClientCertificateStrict)
                    );

                    // 9. Perform the TLS Handshake
                    // 'clientCertificateRequired: true' forces the client to present their certificate, enabling Mutual TLS
                    sslStream.AuthenticateAsServer(serverCertificate, clientCertificateRequired: true, checkCertificateRevocation: false);
                    
                    Console.WriteLine("[TLS] Handshake successful! mTLS Connection is now encrypted and mutually verified.");
                    Console.WriteLine($"[TLS] Cipher Algorithm: {sslStream.CipherAlgorithm}, Protocol: {sslStream.SslProtocol}");

                    // 10. Read encrypted data from the client - SslStream automatically decrypts it for us
                    byte[] buffer = new byte[2048];
                    int receivedBytes = sslStream.Read(buffer, 0, buffer.Length);
                    string message = Encoding.UTF8.GetString(buffer, 0, receivedBytes);
                    Console.WriteLine($"[TLS] Decrypted message received: {message}");

                    // 11. Send an encrypted response back to the client
                    string response = $"TLS Server securely acknowledges receipt of: {message}";
                    byte[] responseData = Encoding.UTF8.GetBytes(response);
                    sslStream.Write(responseData, 0, responseData.Length);
                    
                    Console.WriteLine("[TLS] Encrypted response sent to client.\n");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[TLS Error]: {ex.Message}\n");
                }
                finally
                {
                    // Always close the client's socket when done to free up OS resources
                    clientSocket.Close();
                }
            }
        }

        /// <summary>
        /// Custom callback to validate the client's certificate strictly against our custom Certificate Authority (CA).
        /// </summary>
        static bool ValidateClientCertificateStrict(
              object sender,
              X509Certificate? certificate,
              X509Chain? chain,
              SslPolicyErrors sslPolicyErrors)
        {
            // If the OS natively trusts this certificate, validation passes immediately
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Console.WriteLine($"[TLS] Intercepted client validation error: {sslPolicyErrors}. Attempting custom CA resolution...");

            // If the client failed to provide a certificate during mTLS, reject the connection
            if (certificate == null || chain == null) 
            {
                Console.WriteLine("[TLS] FATAL: Client did not provide a certificate.");
                return false;
            }

            try 
            {
                // 1. Load our custom CA public root certificate from disk - this is our "root of trust"
                string caPath = "scripts/certs/ca.crt";
                using X509Certificate2 customCa = new X509Certificate2(caPath);
                
                // 2. Instruct the certificate validation chain to use OUR custom trust store instead of the global OS store
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Clear();
                chain.ChainPolicy.CustomTrustStore.Add(customCa);
                
                // 3. Disable revocation checks because we do not operate a Certificate Revocation List (CRL) server
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

                // 4. Build the chain - this mathematically verifies the client's signature against our CA
                bool isChainValid = chain.Build((X509Certificate2)certificate);
                
                if (isChainValid) 
                {
                    Console.WriteLine($"[TLS] SUCCESS: Client certificate ({certificate.Subject}) securely validated against PUS_Local_CA!");
                    return true;
                }
                else 
                {
                    Console.WriteLine("[TLS] FATAL: Client certificate chain validation failed.");
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