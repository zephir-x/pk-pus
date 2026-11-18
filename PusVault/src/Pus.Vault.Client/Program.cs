using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Pus.Vault.Client
{
    /// <summary>
    /// Entry point for the PUS-Vault CLI Client application.
    /// </summary>
    public static class Program
    {
        public static async Task<int> Main(string[] args)
        {
            string host = "localhost";
            int port = 8443;
            bool diagnosticsEnabled = args.Contains("--diagnostics");

            string baseDir = ResolveProjectBaseDirectory();
            string caCertPath = Path.Combine(baseDir, "certs", "ca.crt");

            for (int i = 0; i < args.Length - 1; i++)
            {
                if (args[i] == "--host")
                {
                    host = args[i + 1];
                }
                else if (args[i] == "--port" && int.TryParse(args[i + 1], out int parsedPort))
                {
                    port = parsedPort;
                }
                else if (args[i] == "--ca")
                {
                    caCertPath = args[i + 1];
                }
            }

            if (!File.Exists(caCertPath))
            {
                Console.Error.WriteLine($"[STARTUP ERROR] Custom Root CA certificate not found at '{caCertPath}'. Run './scripts/generate_certs.sh' first.");
                return 1;
            }

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
            };

            using var clientEngine = new PvspClientEngine(host, port, caCertPath);
            using var keepAliveWorker = new KeepAliveWorker(clientEngine);

            var cliLoop = new CliCommandLoop(clientEngine, keepAliveWorker, diagnosticsEnabled);
            await cliLoop.RunAsync(cts.Token);

            return 0;
        }

        private static string ResolveProjectBaseDirectory()
        {
            string current = Directory.GetCurrentDirectory();
            if (Directory.Exists(Path.Combine(current, "certs")) || Directory.Exists(Path.Combine(current, "src")))
            {
                return current;
            }

            string? parent = Directory.GetParent(AppContext.BaseDirectory)?.Parent?.Parent?.Parent?.Parent?.FullName;
            return parent ?? current;
        }
    }
}