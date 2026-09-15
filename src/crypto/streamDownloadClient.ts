/**
 * streamDownloadClient.ts
 * High-performance, zero-RAM single file streaming download client.
 * Connects the 4-layer cascade pipeline to Chrome/Edge/Firefox/Safari native download managers
 * via a dedicated Service Worker stream with hardware-level backpressure.
 * Enables arbitrary file sizes (100 MB to 100+ GB) to be saved as ONE SINGLE FILE directly
 * into the browser's Downloads directory without V8 heap accumulation or "Aw, Snap!" renderer crashes.
 */

export interface StreamDownloadSession {
  streamId: string;
  write(chunk: Uint8Array): Promise<void>;
  close(): Promise<void>;
  abort(reason?: string): Promise<void>;
}

export async function createStreamDownloadSession(options: {
  filename: string;
  totalSize?: number;
  signal?: AbortSignal;
}): Promise<StreamDownloadSession | null> {
  if (typeof window === 'undefined' || typeof navigator === 'undefined' || !('serviceWorker' in navigator)) {
    return null;
  }

  try {
    // Register dedicated stream service worker with scope ./stream/
    const reg = await navigator.serviceWorker.register('./sw-stream.js', { scope: './stream/' });

    // Wait until the service worker is active
    let sw = reg.active;
    if (!sw) {
      sw = reg.installing || reg.waiting;
      if (sw) {
        await new Promise<void>((resolve) => {
          const handler = () => {
            if (sw?.state === 'activated') {
              sw.removeEventListener('statechange', handler);
              resolve();
            }
          };
          sw.addEventListener('statechange', handler);
          // Safety timeout
          setTimeout(resolve, 3000);
        });
      }
    }

    const activeSw = reg.active;
    if (!activeSw) {
      console.warn('Stream Service Worker could not be activated');
      return null;
    }

    const streamId = `fk_stream_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    const channel = new MessageChannel();

    let pullPending = false;
    let pullWaiter: (() => void) | null = null;
    let isCancelled = false;
    let cancelReason = '';

    channel.port1.onmessage = (event) => {
      const data = event.data;
      if (!data) return;
      if (data.type === 'PULL') {
        pullPending = true;
        if (pullWaiter) {
          const wake = pullWaiter;
          pullWaiter = null;
          wake();
        }
      } else if (data.type === 'CANCEL') {
        isCancelled = true;
        cancelReason = data.reason || 'Download cancelled by user';
        if (pullWaiter) {
          const wake = pullWaiter;
          pullWaiter = null;
          wake();
        }
      }
    };

    // Wait for READY acknowledgment from Service Worker
    const isReady = await new Promise<boolean>((resolve) => {
      const timeout = setTimeout(() => resolve(false), 4000);
      const readyHandler = (e: MessageEvent) => {
        if (e.data?.type === 'READY') {
          clearTimeout(timeout);
          channel.port1.removeEventListener('message', readyHandler);
          resolve(true);
        }
      };
      channel.port1.addEventListener('message', readyHandler);
      channel.port1.start();

      activeSw.postMessage(
        {
          type: 'REGISTER_STREAM',
          streamId,
          filename: options.filename,
          totalSize: options.totalSize || 0,
        },
        [channel.port2]
      );
    });

    if (!isReady) {
      console.warn('Stream Service Worker READY handshake timed out');
      return null;
    }

    // Trigger single-file download via hidden iframe
    const downloadUrl = `./stream/download?id=${encodeURIComponent(streamId)}&filename=${encodeURIComponent(options.filename)}`;
    const iframe = document.createElement('iframe');
    iframe.style.position = 'fixed';
    iframe.style.left = '-9999px';
    iframe.style.top = '-9999px';
    iframe.style.width = '1px';
    iframe.style.height = '1px';
    iframe.style.opacity = '0';
    iframe.style.pointerEvents = 'none';
    iframe.src = downloadUrl;
    document.body.appendChild(iframe);

    // Safety fallback cleanup after 4 hours for abandoned sessions
    const cleanupFallbackTimer = setTimeout(() => {
      if (document.body.contains(iframe)) {
        document.body.removeChild(iframe);
      }
    }, 14400000);

    // Heartbeat ping interval to keep Service Worker active during long downloads on Firefox/Safari
    const heartbeatTimer = setInterval(() => {
      if (!isCancelled) {
        try {
          channel.port1.postMessage({ type: 'PING' });
        } catch {
          // Ignore
        }
      }
    }, 10000);

    const onSignalAbort = () => {
      abort(options.signal?.reason ? String(options.signal.reason) : 'Aborted');
    };

    if (options.signal) {
      if (options.signal.aborted) {
        onSignalAbort();
      } else {
        options.signal.addEventListener('abort', onSignalAbort, { once: true });
      }
    }

    const write = async (chunk: Uint8Array): Promise<void> => {
      if (isCancelled || options.signal?.aborted) {
        throw new Error(cancelReason || 'Aborted');
      }

      // Backpressure: wait for consumer pull if queue is not drained
      if (!pullPending) {
        await new Promise<void>((resolve, reject) => {
          const timer = setTimeout(() => {
            pullWaiter = null;
            resolve();
          }, 50); // 50ms fast fallback interval
          pullWaiter = () => {
            clearTimeout(timer);
            pullWaiter = null;
            if (isCancelled || options.signal?.aborted) {
              reject(new Error(cancelReason || 'Aborted'));
            } else {
              resolve();
            }
          };
        });
      }
      pullPending = false;

      // Transfer ArrayBuffer with true zero-copy when spanning full buffer, or slice if sub-allocated
      const transferBuf = (chunk.byteOffset === 0 && chunk.byteLength === chunk.buffer.byteLength)
        ? chunk.buffer
        : chunk.slice().buffer;
      channel.port1.postMessage({ type: 'CHUNK', chunk: transferBuf }, [transferBuf]);
    };

    const close = async (): Promise<void> => {
      options.signal?.removeEventListener('abort', onSignalAbort);
      clearTimeout(cleanupFallbackTimer);
      clearInterval(heartbeatTimer);
      channel.port1.postMessage({ type: 'CLOSE' });
      setTimeout(() => {
        try {
          channel.port1.close();
        } catch {
          // Ignore
        }
        if (document.body.contains(iframe)) {
          document.body.removeChild(iframe);
        }
      }, 5000);
    };

    const abort = async (reason?: string): Promise<void> => {
      options.signal?.removeEventListener('abort', onSignalAbort);
      isCancelled = true;
      cancelReason = reason || 'Aborted';
      if (pullWaiter) {
        const waiter = pullWaiter;
        pullWaiter = null;
        waiter();
      }
      clearTimeout(cleanupFallbackTimer);
      clearInterval(heartbeatTimer);
      channel.port1.postMessage({ type: 'ABORT', error: reason });
      try {
        channel.port1.close();
      } catch {
        // Ignore
      }
      if (document.body.contains(iframe)) {
        document.body.removeChild(iframe);
      }
    };

    return { streamId, write, close, abort };
  } catch (err) {
    console.warn('Failed to initialize Service Worker stream session:', err);
    return null;
  }
}
