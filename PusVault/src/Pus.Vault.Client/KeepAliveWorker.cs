using System;
using System.Threading;
using System.Threading.Tasks;

namespace Pus.Vault.Client
{
    /// <summary>
    /// Background worker that periodically sends a PING (0x07) frame after 20 seconds of client inactivity,
    /// using the shared PvspClientEngine writer queue when no business request is in flight.
    /// </summary>
    public class KeepAliveWorker : IDisposable
    {
        private readonly PvspClientEngine _clientEngine;
        private readonly TimeSpan _keepAliveInterval;
        private readonly TimeSpan _pollInterval;
        private CancellationTokenSource? _workerCts;
        private Task? _workerTask;

        public KeepAliveWorker(
            PvspClientEngine clientEngine,
            TimeSpan? keepAliveInterval = null,
            TimeSpan? pollInterval = null)
        {
            _clientEngine = clientEngine;
            _keepAliveInterval = keepAliveInterval ?? TimeSpan.FromSeconds(20);
            _pollInterval = pollInterval ?? TimeSpan.FromSeconds(1);
        }

        /// <summary>
        /// Starts the background keep-alive loop.
        /// </summary>
        public void Start()
        {
            if (_workerTask != null)
                return;

            _workerCts = new CancellationTokenSource();
            _workerTask = Task.Run(() => RunLoopAsync(_workerCts.Token));
        }

        /// <summary>
        /// Stops the background keep-alive loop gracefully.
        /// </summary>
        public async Task StopAsync()
        {
            if (_workerCts == null || _workerTask == null)
                return;

            _workerCts.Cancel();
            try
            {
                await _workerTask;
            }
            catch (OperationCanceledException)
            {
                // Expected on shutdown
            }
            finally
            {
                _workerCts.Dispose();
                _workerCts = null;
                _workerTask = null;
            }
        }

        private async Task RunLoopAsync(CancellationToken ct)
        {
            using var timer = new PeriodicTimer(_pollInterval);
            while (await timer.WaitForNextTickAsync(ct))
            {
                if (!_clientEngine.IsAuthenticated || _clientEngine.IsRequestInFlight)
                    continue;

                TimeSpan idleDuration = DateTime.UtcNow - _clientEngine.LastActivityUtc;
                if (idleDuration >= _keepAliveInterval)
                {
                    await _clientEngine.SendPingAsync(ct);
                }
            }
        }

        public void Dispose()
        {
            _workerCts?.Cancel();
            _workerCts?.Dispose();
        }
    }
}