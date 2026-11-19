using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Pus.Vault.Server
{
    /// <summary>
    /// Thread-safe audit and diagnostic logger that writes structured UTC logs to the console and a local file.
    /// Sanitizes user-supplied strings to prevent log injection and ANSI escape attacks, and never logs secrets or passwords.
    /// </summary>
    public class SecurityAuditLogger
    {
        private readonly string _logFilePath;
        private readonly long _maxFileBytes;
        private readonly object _writeLock = new();

        public SecurityAuditLogger(string logDirectory, string logFileName = "server_audit.log", long maxFileBytes = 5 * 1024 * 1024)
        {
            _maxFileBytes = maxFileBytes;

            // Ensure the log directory exists before writing any entries
            Directory.CreateDirectory(logDirectory);
            SetUnixOwnerPermissions(logDirectory, isDirectory: true);

            _logFilePath = Path.Combine(logDirectory, logFileName);
            EnsureLogFilePermissions();
        }

        public void LogInfo(string sessionEndpoint, string message) =>
            WriteEntry("INFO", sessionEndpoint, message);

        public void LogWarn(string sessionEndpoint, string message) =>
            WriteEntry("WARN", sessionEndpoint, message);

        public void LogSecurity(string sessionEndpoint, string message) =>
            WriteEntry("SECURITY", sessionEndpoint, message);

        public void LogError(string sessionEndpoint, string message) =>
            WriteEntry("ERROR", sessionEndpoint, message);

        /// <summary>
        /// Escapes newlines, tabs, and all Unicode/ASCII control characters (including ANSI ESC sequences)
        /// from untrusted input so an attacker cannot forge log lines or corrupt operator terminals.
        /// </summary>
        public static string Sanitize(string? input)
        {
            if (string.IsNullOrEmpty(input))
                return "<empty>";

            var sb = new StringBuilder(input.Length);
            foreach (char c in input)
            {
                switch (c)
                {
                    case '\r':
                        sb.Append("\\r");
                        break;
                    case '\n':
                        sb.Append("\\n");
                        break;
                    case '\t':
                        sb.Append("\\t");
                        break;
                    default:
                        if (char.IsControl(c))
                        {
                            sb.Append($"\\u{(int)c:x4}");
                        }
                        else
                        {
                            sb.Append(c);
                        }
                        break;
                }
            }

            return sb.ToString();
        }

        private void WriteEntry(string level, string sessionEndpoint, string message)
        {
            string timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss 'UTC'");
            string safeEndpoint = Sanitize(sessionEndpoint);
            string safeMessage = Sanitize(message);

            string formattedLine = $"[{timestamp}] [{level}] [Session:{safeEndpoint}] {safeMessage}";

            // Synchronize console and file writes across all concurrent client threads
            lock (_writeLock)
            {
                Console.WriteLine(formattedLine);

                try
                {
                    RotateIfNecessary();
                    File.AppendAllText(_logFilePath, formattedLine + Environment.NewLine);
                }
                catch (IOException ex)
                {
                    Console.Error.WriteLine($"[LOGGER ERROR] Failed to write audit log: {ex.Message}");
                }
            }
        }

        private void RotateIfNecessary()
        {
            var fileInfo = new FileInfo(_logFilePath);
            if (fileInfo.Exists && fileInfo.Length >= _maxFileBytes)
            {
                string archivePath = _logFilePath + ".1";
                File.Move(_logFilePath, archivePath, overwrite: true);
                EnsureLogFilePermissions();
            }
        }

        private void EnsureLogFilePermissions()
        {
            if (!File.Exists(_logFilePath))
            {
                File.WriteAllText(_logFilePath, string.Empty);
            }

            SetUnixOwnerPermissions(_logFilePath, isDirectory: false);
        }

        private static void SetUnixOwnerPermissions(string path, bool isDirectory)
        {
            // Enforce strict owner-only permissions on Linux (0700 for directory, 0600 for file)
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                UnixFileMode mode = isDirectory
                    ? UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                    : UnixFileMode.UserRead | UnixFileMode.UserWrite;

                File.SetUnixFileMode(path, mode);
            }
        }
    }
}