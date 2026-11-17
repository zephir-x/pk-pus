using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Pus.Vault.Server
{
    /// <summary>
    /// Entry point for the PUS-Vault Server application.
    /// </summary>
    public static class Program
    {
        public static async Task<int> Main(string[] args)
        {
            int port = 8443;
            for (int i = 0; i < args.Length - 1; i++)
            {
                if (args[i] == "--port" && int.TryParse(args[i + 1], out int parsedPort))
                {
                    port = parsedPort;
                }
            }

            string baseDir = ResolveProjectBaseDirectory();
            string certsDir = Path.Combine(baseDir, "certs");
            string serverCertPath = Path.Combine(certsDir, "server.crt");
            string serverKeyPath = Path.Combine(certsDir, "server.key");
            string usersFilePath = Path.Combine(baseDir, "config", "users.json");
            string storeFilePath = Path.Combine(baseDir, "data", "vault_store.json");
            string logsDir = Path.Combine(baseDir, "logs");

            var logger = new SecurityAuditLogger(logsDir);

            if (!File.Exists(serverCertPath) || !File.Exists(serverKeyPath))
            {
                logger.LogError("STARTUP", $"Server TLS certificate or key not found in '{certsDir}'. Run './scripts/generate_certs.sh' first.");
                return 1;
            }

            try
            {
                // Provision config/users.json on first run if it does not exist yet
                if (!File.Exists(usersFilePath))
                {
                    ProvisionInitialUsersInteractiveOrEnv(usersFilePath, logger);
                }

                var authModule = new AuthAndRbacModule(usersFilePath);
                var storageEngine = new VaultStorageEngine(storeFilePath);

                using var cts = new CancellationTokenSource();
                Console.CancelKeyPress += (_, e) =>
                {
                    e.Cancel = true;
                    logger.LogInfo("SERVER", "SIGINT received. Shutting down PUS-Vault Server gracefully...");
                    cts.Cancel();
                };

                using var listener = new SocketConnectionListener(
                    port,
                    serverCertPath,
                    serverKeyPath,
                    authModule,
                    storageEngine,
                    logger);

                listener.StartListening();
                await listener.AcceptLoopAsync(cts.Token);
                return 0;
            }
            catch (Exception ex)
            {
                logger.LogError("STARTUP", $"Fatal server startup error: {ex.Message}");
                return 1;
            }
        }

        private static void ProvisionInitialUsersInteractiveOrEnv(string usersFilePath, SecurityAuditLogger logger)
        {
            string? adminPass = Environment.GetEnvironmentVariable("PUS_ADMIN_PASS");
            string? readerPass = Environment.GetEnvironmentVariable("PUS_READER_PASS");

            if (string.IsNullOrEmpty(adminPass) || string.IsNullOrEmpty(readerPass))
            {
                Console.WriteLine("=== First-Time PUS-Vault User Provisioning (PBKDF2-HMAC-SHA256) ===");
                adminPass = PromptHiddenPassword("Enter initial password for 'admin' (READ_WRITE): ");
                readerPass = PromptHiddenPassword("Enter initial password for 'reader' (READ_ONLY): ");
            }

            AuthAndRbacModule.ProvisionUsersFile(usersFilePath, adminPass, readerPass);
            logger.LogInfo("STARTUP", $"Provisioned user accounts ('admin', 'reader') in '{usersFilePath}'.");
        }

        private static string PromptHiddenPassword(string prompt)
        {
            while (true)
            {
                Console.Write(prompt);
                var sb = new StringBuilder();
                while (true)
                {
                    ConsoleKeyInfo key = Console.ReadKey(intercept: true);
                    if (key.Key == ConsoleKey.Enter)
                    {
                        Console.WriteLine();
                        break;
                    }
                    if (key.Key == ConsoleKey.Backspace && sb.Length > 0)
                    {
                        sb.Length--;
                    }
                    else if (!char.IsControl(key.KeyChar))
                    {
                        sb.Append(key.KeyChar);
                    }
                }

                if (sb.Length > 0)
                {
                    return sb.ToString();
                }

                Console.WriteLine("Password cannot be empty. Please try again.");
            }
        }

        private static string ResolveProjectBaseDirectory()
        {
            string current = Directory.GetCurrentDirectory();
            if (Directory.Exists(Path.Combine(current, "certs")) || Directory.Exists(Path.Combine(current, "src")))
            {
                return current;
            }

            // Fallback when running from bin/Debug/net8.0
            string? parent = Directory.GetParent(AppContext.BaseDirectory)?.Parent?.Parent?.Parent?.Parent?.FullName;
            return parent ?? current;
        }
    }
}