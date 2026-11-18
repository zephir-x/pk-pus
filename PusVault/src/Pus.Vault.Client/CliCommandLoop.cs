using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Pus.Vault.Common;

namespace Pus.Vault.Client
{
    /// <summary>
    /// Interactive command-line interface (REPL) for the PUS-Vault Client.
    /// Reads sensitive inputs (passwords and secret values) using a non-echoing hidden prompt.
    /// </summary>
    public class CliCommandLoop
    {
        private readonly PvspClientEngine _clientEngine;
        private readonly KeepAliveWorker _keepAliveWorker;
        private readonly bool _diagnosticsEnabled;

        public CliCommandLoop(PvspClientEngine clientEngine, KeepAliveWorker keepAliveWorker, bool diagnosticsEnabled)
        {
            _clientEngine = clientEngine;
            _keepAliveWorker = keepAliveWorker;
            _diagnosticsEnabled = diagnosticsEnabled;

            _clientEngine.OnDiagnosticLog = msg => Console.WriteLine($"[CLIENT-NET] {msg}");
        }

        /// <summary>
        /// Runs the interactive command loop until the user types 'exit' or CancellationToken is triggered.
        /// </summary>
        public async Task RunAsync(CancellationToken ct)
        {
            PrintBanner();
            _keepAliveWorker.Start();

            try
            {
                while (!ct.IsCancellationRequested)
                {
                    string statusTag = _clientEngine.IsAuthenticated
                        ? $"AUTH:{_clientEngine.AssignedRole}"
                        : "DISCONNECTED";

                    Console.Write($"\npus-vault [{statusTag}]> ");
                    string? line = Console.ReadLine();

                    // Handle EOF (Ctrl+D)
                    if (line == null)
                    {
                        Console.WriteLine("\nEOF received. Closing session...");
                        await _clientEngine.DisconnectAsync(clearCachedCredentials: true, ct);
                        break;
                    }

                    line = line.Trim();
                    if (line.Length == 0)
                        continue;

                    string[] parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    string command = parts[0].ToLowerInvariant();

                    bool shouldExit = await DispatchCommandAsync(command, parts, ct);
                    if (shouldExit)
                        break;
                }
            }
            finally
            {
                await _keepAliveWorker.StopAsync();
                await _clientEngine.DisconnectAsync(clearCachedCredentials: true, CancellationToken.None);
            }
        }

        private async Task<bool> DispatchCommandAsync(string command, string[] args, CancellationToken ct)
        {
            switch (command)
            {
                case "help":
                    PrintHelp();
                    return false;

                case "login":
                    await HandleLoginCommandAsync(args, ct);
                    return false;

                case "set":
                    await HandleSetCommandAsync(args, ct);
                    return false;

                case "get":
                    await HandleGetCommandAsync(args, ct);
                    return false;

                case "list":
                    await HandleListCommandAsync(args, ct);
                    return false;

                case "delete":
                    await HandleDeleteCommandAsync(args, ct);
                    return false;

                case "ping":
                    await HandlePingCommandAsync(ct);
                    return false;

                case "diag-hmac" when _diagnosticsEnabled:
                    PrintOperationResult(await _clientEngine.SendDiagnosticCorruptedHmacAsync(ct));
                    return false;

                case "diag-replay" when _diagnosticsEnabled:
                    PrintOperationResult(await _clientEngine.SendDiagnosticReplayTimestampAsync(ct));
                    return false;

                case "diag-magic" when _diagnosticsEnabled:
                    PrintOperationResult(await _clientEngine.SendDiagnosticBadMagicAsync(ct));
                    return false;

                case "exit":
                case "quit":
                    await _clientEngine.DisconnectAsync(clearCachedCredentials: true, ct);
                    Console.WriteLine("[OK] Sent BYE (0x09) and closed TLS/TCP connection.");
                    return true;

                default:
                    Console.WriteLine($"Unknown command '{command}'. Type 'help' to see available commands.");
                    return false;
            }
        }

        private async Task HandleLoginCommandAsync(string[] args, CancellationToken ct)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("Usage: login <username>");
                return;
            }

            string username = args[1];
            string password = ReadHiddenInput($"Enter password for '{username}': ");
            if (string.IsNullOrEmpty(password))
            {
                Console.WriteLine("[ERROR] Password cannot be empty.");
                return;
            }

            try
            {
                var (success, message, errorCode) = await _clientEngine.ConnectAndLoginAsync(username, password, ct);
                if (success)
                {
                    Console.WriteLine($"[OK] {message}");
                }
                else
                {
                    Console.WriteLine($"[AUTH ERROR] (Code={errorCode}) {message}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[TLS/SECURITY ERROR] {ex.Message}");
            }
        }

        private async Task HandleSetCommandAsync(string[] args, CancellationToken ct)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("Usage: set <key> (secret value will be prompted securely without echo)");
                return;
            }

            string key = args[1];
            if (!PvspJsonSerializer.IsValidSecretKeyFormat(key))
            {
                Console.WriteLine("[VALIDATION ERROR] Invalid key format. Allowed: 1..128 ASCII chars (alphanumeric, '_', '-', '.').");
                return;
            }

            string secretValue = ReadHiddenInput($"Enter secret value for '{key}': ");
            if (Encoding.UTF8.GetByteCount(secretValue) > PvspConstants.MaxValueBytes)
            {
                Console.WriteLine($"[VALIDATION ERROR] Secret value exceeds {PvspConstants.MaxValueBytes} UTF-8 bytes limit.");
                return;
            }

            ClientOperationResult res = await _clientEngine.ExecuteDataRequestAsync("SET", key, secretValue, ct);
            PrintOperationResult(res);
        }

        private async Task HandleGetCommandAsync(string[] args, CancellationToken ct)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("Usage: get <key>");
                return;
            }

            string key = args[1];
            if (!PvspJsonSerializer.IsValidSecretKeyFormat(key))
            {
                Console.WriteLine("[VALIDATION ERROR] Invalid key format.");
                return;
            }

            ClientOperationResult res = await _clientEngine.ExecuteDataRequestAsync("GET", key, null, ct);
            if (res.IsSuccess)
            {
                Console.WriteLine($"[OK] {key} = {res.Value}");
            }
            else
            {
                PrintOperationResult(res);
            }
        }

        private async Task HandleListCommandAsync(string[] args, CancellationToken ct)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("Usage: list");
                return;
            }

            ClientOperationResult res = await _clientEngine.ExecuteDataRequestAsync("LIST", null, null, ct);
            if (res.IsSuccess)
            {
                var keys = res.Keys;
                if (keys == null || keys.Count == 0)
                {
                    Console.WriteLine("[OK] Vault is currently empty (0 keys).");
                }
                else
                {
                    Console.WriteLine($"[OK] Stored secret keys ({keys.Count}):");
                    foreach (string k in keys)
                    {
                        Console.WriteLine($"  - {k}");
                    }
                }
            }
            else
            {
                PrintOperationResult(res);
            }
        }

        private async Task HandleDeleteCommandAsync(string[] args, CancellationToken ct)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("Usage: delete <key>");
                return;
            }

            string key = args[1];
            if (!PvspJsonSerializer.IsValidSecretKeyFormat(key))
            {
                Console.WriteLine("[VALIDATION ERROR] Invalid key format.");
                return;
            }

            ClientOperationResult res = await _clientEngine.ExecuteDataRequestAsync("DELETE", key, null, ct);
            PrintOperationResult(res);
        }

        private async Task HandlePingCommandAsync(CancellationToken ct)
        {
            bool ok = await _clientEngine.SendPingAsync(ct);
            if (ok)
            {
                Console.WriteLine("[OK] Received PONG (0x08) from server.");
            }
            else
            {
                Console.WriteLine("[ERROR] PING failed or session is not authenticated.");
            }
        }

        private static void PrintOperationResult(ClientOperationResult res)
        {
            if (res.IsSuccess)
            {
                Console.WriteLine($"[OK] {res.Message}");
            }
            else if (res.IsUnknownMutationOutcome)
            {
                Console.WriteLine($"[WARNING - UNKNOWN OUTCOME] {res.Message}");
            }
            else if (res.ErrorCode != 0)
            {
                Console.WriteLine($"[SERVER ERROR {res.ErrorCode} {res.ErrorName}] {res.Message}");
            }
            else
            {
                Console.WriteLine($"[ERROR] {res.Message}");
            }
        }

        /// <summary>
        /// Reads sensitive text from the terminal without echoing characters to the screen.
        /// Falls back to Console.ReadLine() if standard input is redirected.
        /// </summary>
        private static string ReadHiddenInput(string prompt)
        {
            Console.Write(prompt);
            if (Console.IsInputRedirected)
            {
                string? line = Console.ReadLine();
                Console.WriteLine();
                return line ?? string.Empty;
            }

            var sb = new StringBuilder();
            while (true)
            {
                ConsoleKeyInfo key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    break;
                }

                if (key.Key == ConsoleKey.Backspace)
                {
                    if (sb.Length > 0)
                    {
                        sb.Length--;
                    }
                }
                else if (!char.IsControl(key.KeyChar))
                {
                    sb.Append(key.KeyChar);
                }
            }

            return sb.ToString();
        }

        private void PrintBanner()
        {
            Console.WriteLine("==================================================================");
            Console.WriteLine("  PUS-Vault CLI Client (PVSP v1.0 over TCP + TLS 1.3 Custom CA)   ");
            Console.WriteLine("==================================================================");
            if (_diagnosticsEnabled)
            {
                Console.WriteLine("  [*] DIAGNOSTICS MODE ENABLED (--diagnostics)");
            }
            PrintHelp();
        }

        private void PrintHelp()
        {
            Console.WriteLine("\nAvailable Commands:");
            Console.WriteLine("  login <user>   - Connect via TLS 1.3 and authenticate (prompts for password)");
            Console.WriteLine("  set <key>      - Store or update a secret (prompts for value without echo)");
            Console.WriteLine("  get <key>      - Retrieve a secret value by key");
            Console.WriteLine("  list           - List all secret keys stored in the vault");
            Console.WriteLine("  delete <key>   - Delete a secret key from the vault");
            Console.WriteLine("  ping           - Send an explicit keep-alive PING (0x07) frame");
            Console.WriteLine("  help           - Show this command list");
            Console.WriteLine("  exit           - Send BYE (0x09) and close the application");

            if (_diagnosticsEnabled)
            {
                Console.WriteLine("\nDiagnostic Test Commands (--diagnostics):");
                Console.WriteLine("  diag-hmac      - Send DATA_REQ with corrupted HMAC (triggers 204 ERR_INVALID_HMAC)");
                Console.WriteLine("  diag-replay    - Send DATA_REQ with expired timestamp (triggers 301 ERR_REPLAY_DETECTED)");
                Console.WriteLine("  diag-magic     - Send frame with invalid Magic Bytes 0x0000 (triggers 100 ERR_BAD_MAGIC)");
            }
        }
    }
}