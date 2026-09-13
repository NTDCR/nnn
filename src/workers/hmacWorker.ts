/**
 * Fort-Knox Cascade Dedicated HMAC-SHA256 Worker
 * Offloads continuous plaintext integrity hashing from the main thread event loop.
 * Runs completely concurrently with ALU encryption/decryption workers.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';

let hmacHasher: ReturnType<typeof hmac.create> | null = null;
let nextExpectedChunk = 0;
const pendingChunks = new Map<number, Uint8Array>();
let isFinalizing = false;
let totalExpectedChunks = 0;

function drainPendingChunks() {
  if (!hmacHasher) return;
  while (pendingChunks.has(nextExpectedChunk)) {
    const chunk = pendingChunks.get(nextExpectedChunk)!;
    pendingChunks.delete(nextExpectedChunk);
    hmacHasher.update(chunk);
    chunk.fill(0); // Immediate zeroization of digested plaintext!
    nextExpectedChunk++;
  }

  if (isFinalizing && nextExpectedChunk === totalExpectedChunks) {
    const digest = hmacHasher.digest();
    hmacHasher = null;
    (self as unknown as { postMessage: (msg: unknown, transfer?: Transferable[]) => void }).postMessage(
      {
        type: 'DIGEST_DONE',
        digest: digest.buffer,
      },
      [digest.buffer]
    );
  }
}

self.onmessage = (e: MessageEvent) => {
  const data = e.data;
  const action = data.action;

  if (action === 'INIT_HMAC') {
    const key = new Uint8Array(data.key);
    try {
      hmacHasher = hmac.create(sha256, key);
      nextExpectedChunk = 0;
      pendingChunks.clear();
      isFinalizing = false;
      totalExpectedChunks = 0;
      self.postMessage({ type: 'HMAC_READY' });
    } finally {
      key.fill(0);
    }
    return;
  }

  if (action === 'UPDATE_CHUNK') {
    const { chunkIndex, chunkData } = data;
    const bytes = new Uint8Array(chunkData);
    pendingChunks.set(chunkIndex, bytes);
    drainPendingChunks();
    return;
  }

  if (action === 'FINALIZE') {
    totalExpectedChunks = data.totalChunks;
    isFinalizing = true;
    drainPendingChunks();
    return;
  }

  if (action === 'DESTROY') {
    for (const b of pendingChunks.values()) {
      b.fill(0);
    }
    pendingChunks.clear();
    hmacHasher = null;
    self.close();
    return;
  }
};
