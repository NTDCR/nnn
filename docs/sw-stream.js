/* sw-stream.js - Fort-Knox Cascade Stream Downloader Service Worker */
'use strict';

const streamRegistry = new Map();

self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('message', (event) => {
  const data = event.data;
  if (!data) return;

  if (data.type === 'REGISTER_STREAM') {
    const { streamId, filename, totalSize } = data;
    const port = event.ports[0];
    if (!port) return;

    let controllerRef = null;
    let isClosed = false;

    const stream = new ReadableStream(
      {
        start(controller) {
          controllerRef = controller;
          port.postMessage({ type: 'READY' });
        },
        pull() {
          if (!isClosed) {
            port.postMessage({ type: 'PULL' });
          }
        },
        cancel(reason) {
          isClosed = true;
          port.postMessage({ type: 'CANCEL', reason: String(reason) });
          streamRegistry.delete(streamId);
        },
      },
      {
        highWaterMark: 4,
      }
    );

    port.onmessage = (e) => {
      const msg = e.data;
      if (!msg) return;

      if (msg.type === 'CHUNK' && controllerRef && !isClosed) {
        try {
          controllerRef.enqueue(new Uint8Array(msg.chunk));
        } catch (err) {
          isClosed = true;
          port.postMessage({ type: 'ERROR', error: String(err) });
        }
      } else if (msg.type === 'CLOSE' && controllerRef && !isClosed) {
        isClosed = true;
        try {
          controllerRef.close();
        } catch {
          // Ignore close error
        }
        streamRegistry.delete(streamId);
      } else if (msg.type === 'ABORT' && controllerRef) {
        isClosed = true;
        try {
          controllerRef.error(new Error(msg.error || 'Aborted'));
        } catch {
          // Ignore abort error
        }
        streamRegistry.delete(streamId);
      }
    };

    streamRegistry.set(streamId, {
      stream,
      filename: filename || 'download.bin',
      totalSize: totalSize || 0,
      createdAt: Date.now(),
    });

    // Cleanup unconsumed streams after 5 minutes
    setTimeout(() => {
      if (streamRegistry.has(streamId)) {
        streamRegistry.delete(streamId);
      }
    }, 300000);
  }
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.pathname.includes('/stream/download')) {
    const streamId = url.searchParams.get('id');
    const entry = streamRegistry.get(streamId);

    if (!entry) {
      event.respondWith(
        new Response('Stream download not found or already consumed.', {
          status: 404,
          headers: { 'Content-Type': 'text/plain' },
        })
      );
      return;
    }

    // Single use
    streamRegistry.delete(streamId);

    const safeFilename = entry.filename.replace(/["\r\n]/g, '_');
    const encodedFilename = encodeURIComponent(safeFilename);

    const headers = new Headers({
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${safeFilename}"; filename*=UTF-8''${encodedFilename}`,
      'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
      'Pragma': 'no-cache',
      'Expires': '0',
    });

    if (entry.totalSize && entry.totalSize > 0) {
      headers.set('Content-Length', String(entry.totalSize));
    }

    event.respondWith(new Response(entry.stream, { headers }));
  }
});
