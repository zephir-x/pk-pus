using System;
using System.IO;
using System.Runtime.InteropServices;
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
            int maxSessions = ParsePositiveIntEnv("PUS_MAX_SESSIONS", defaultValue: 64);
            int maxHandshakes = ParsePositiveIntEnv("PUS_MAX_HANDSHAKES", defaultValue: 32);

            for (int i = 0; i < args.Length - 1; i++)
            {
                if (args[i] == "--port" && int.TryParse(args[i + 1], out int parsedPort) && parsedPort is >= 0 and <= 65535)
                {
                    port = parsedPort;
                }
                else if (args[i] == "--max-sessions" && int.TryParse(args[i + 1], out int parsedSessions) && parsedSessions >= 1)
                {
                    maxSessions = parsedSessions;
                }
                else if (args[i] == "--max-handshakes" && int.TryParse(args[i + 1], out int parsedHandshakes) && parsedHandshakes >= 1)
                {
                    maxHandshakes = parsedHandshakes;
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
                IVaultStorage storageEngine = new VaultStorageEngine(storeFilePath);

                using var cts = new CancellationTokenSource();
                int shutdownSignaled = 0;

                void RequestGracefulShutdown(string signalName)
                {
                    if (Interlocked.Exchange(ref shutdownSignaled, 1) == 0)
                    {
                        logger.LogInfo("SERVER", $"{signalName} received. Shutting down PUS-Vault Server gracefully...");
                        try
                        {
                            cts.Cancel();
                        }
                        catch (ObjectDisposedException)
                        {
                            // Already exiting
                        }
                    }
                }

                ConsoleCancelEventHandler cancelHandler = (_, e) =>
                {
                    e.Cancel = true;
                    RequestGracefulShutdown("SIGINT");
                };
                Console.CancelKeyPress += cancelHandler;

                using PosixSignalRegistration? sigTermRegistration = OperatingSystem.IsWindows()
                    ? null
                    : PosixSignalRegistration.Create(PosixSignal.SIGTERM, ctx =>
                    {
                        ctx.Cancel = true;
                        RequestGracefulShutdown("SIGTERM");
                    });

                EventHandler processExitHandler = (_, _) => RequestGracefulShutdown("ProcessExit");
                AppDomain.CurrentDomain.ProcessExit += processExitHandler;

                try
                {
                    using var listener = new SocketConnectionListener(
                        port,
                        serverCertPath,
                        serverKeyPath,
                        authModule,
                        storageEngine,
                        logger,
                        maxConcurrentSessions: maxSessions,
                        maxConcurrentHandshakes: maxHandshakes);

                    logger.LogInfo("STARTUP", $"Server limits configured: maxConcurrentSessions={maxSessions}, maxConcurrentHandshakes={maxHandshakes}.");
                    listener.StartListening();
                    await listener.AcceptLoopAsync(cts.Token);
                    return 0;
                }
                finally
                {
                    Console.CancelKeyPress -= cancelHandler;
                    AppDomain.CurrentDomain.ProcessExit -= processExitHandler;
                }
            }
            catch (Exception ex)
            {
                logger.LogError("STARTUP", $"Fatal server startup error: {ex.Message}");
                return 1;
            }
        }

        private static int ParsePositiveIntEnv(string variableName, int defaultValue)
        {
            string? raw = Environment.GetEnvironmentVariable(variableName);
            return int.TryParse(raw, out int parsed) && parsed >= 1 ? parsed : defaultValue;
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