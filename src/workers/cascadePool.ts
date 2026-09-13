/**
 * Fort-Knox Cascade Multi-Worker Pool Coordinator
 * Accelerates container encryption and decryption by utilizing multi-core CPU parallelism
 * with strictly ordered sequential streaming and zero-RAM footprint via Transferable ArrayBuffers.
 */

import { CascadeKeys, WorkerProgressMessage, WorkerSuccessMessage } from '../types/crypto.ts';
import { hexToBytes, fillRandomBytes, GENERIC_DECRYPT_ERROR } from '../crypto/cascade.ts';
import {
  METADATA_SIZE,
  POINTER_BLOCK_SIZE,
  CASCADE_ORDER_TAG_STRING,
  constantTimeCompare,
  encodeMetadataBlob,
  decodeMetadataBlob,
  maskMetadataBlob,
  encryptTailPointer,
  decryptTailPointer,
  deriveHmacKey,
} from '../crypto/format.ts';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

const CHUNK_SIZE = 1048576; // 1 MB
const ENCRYPTED_CHUNK_SIZE = CHUNK_SIZE + 32;

export interface ProcessFileOptions {
  action: 'ENCRYPT' | 'DECRYPT';
  file: File;
  keys: CascadeKeys;
  onStart?: (totalChunks: number, totalBytes: number) => void;
  onProgress?: (progress: WorkerProgressMessage) => void;
  onChunkOutput: (chunkBytes: Uint8Array) => Promise<void> | void;
  signal?: AbortSignal;
}

export async function processFileWithPool(options: ProcessFileOptions): Promise<WorkerSuccessMessage> {
  const { action, file, keys, onStart, onProgress, onChunkOutput, signal } = options;

  let k1: Uint8Array | null = null;
  let k2: Uint8Array | null = null;
  let k3: Uint8Array | null = null;
  let k4: Uint8Array | null = null;

  const workers: Worker[] = [];

  try {
    k1 = hexToBytes(keys.layer1ThreefishHex, 128);
    k2 = hexToBytes(keys.layer2SerpentHex, 32);
    k3 = hexToBytes(keys.layer3ChaChaHex, 32);
    k4 = hexToBytes(keys.layer4AesHex, 32);

    // Adaptive mobile-aware pool sizing:
    // Mobile CPUs have heterogenous big.LITTLE architectures (typically 2 Big/Performance cores + 4-6 Little cores).
    // Using >2 workers on mobile spills onto slow Little cores causing severe Head-of-Line blocking and thermal throttling.
    // Desktop systems have 4-16 uniform high-performance cores, scaling cleanly to 4 workers.
    const isMultiChunk = file.size > CHUNK_SIZE;
    const isMobile = typeof navigator !== 'undefined' && /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent);
    const maxWorkers = isMobile ? 2 : Math.min(4, Math.max(2, (navigator?.hardwareConcurrency || 4) >> 1));
    const poolSize = isMultiChunk ? maxWorkers : 1;

    // Instantiate and initialize worker pool
    for (let i = 0; i < poolSize; i++) {
      const w = new Worker(new URL('./cascadeWorker.ts', import.meta.url), { type: 'module' });
      workers.push(w);
    }

    if (signal?.aborted) throw new Error('Aborted');

    // Initialize each worker with keys
    const initPromises = workers.map(
      (w) =>
        new Promise<void>((resolve, reject) => {
          const handler = (e: MessageEvent) => {
            if (e.data.type === 'POOL_READY') {
              w.removeEventListener('message', handler);
              resolve();
            } else if (e.data.type === 'ERROR') {
              w.removeEventListener('message', handler);
              reject(new Error(e.data.error || 'Worker init failed'));
            }
          };
          w.addEventListener('message', handler);
          w.postMessage({ action: 'INIT_POOL', keys });
        })
    );
    await Promise.all(initPromises);

    if (signal?.aborted) throw new Error('Aborted');

    if (action === 'ENCRYPT') {
      return await executePoolEncryption({
        file,
        workers,
        k1,
        k2,
        k4,
        onStart,
        onProgress,
        onChunkOutput,
        signal,
      });
    } else {
      return await executePoolDecryption({
        file,
        workers,
        k1,
        k2,
        k4,
        onStart,
        onProgress,
        onChunkOutput,
        signal,
      });
    }
  } finally {
    // Ephemeral key hygiene and worker termination
    workers.forEach((w) => w.terminate());
    if (k1) k1.fill(0);
    if (k2) k2.fill(0);
    if (k3) k3.fill(0);
    if (k4) k4.fill(0);
  }
}

async function executePoolEncryption(params: {
  file: File;
  workers: Worker[];
  k1: Uint8Array;
  k2: Uint8Array;
  k4: Uint8Array;
  onStart?: (totalChunks: number, totalBytes: number) => void;
  onProgress?: (progress: WorkerProgressMessage) => void;
  onChunkOutput: (chunkBytes: Uint8Array) => Promise<void> | void;
  signal?: AbortSignal;
}): Promise<WorkerSuccessMessage> {
  const { file, workers, k1, k2, k4, onStart, onProgress, onChunkOutput, signal } = params;
  const originalSize = file.size;
  const chunkCount = Math.max(1, Math.ceil(originalSize / CHUNK_SIZE));

  const hmacKey = deriveHmacKey(k1, k2);
  const hmacHasher = hmac.create(sha256, hmacKey);

  const nonceThreefish = new Uint8Array(16);
  const nonceSerpent = new Uint8Array(16);
  const nonceChaCha = new Uint8Array(12);
  const nonceAes = new Uint8Array(12);

  crypto.getRandomValues(nonceThreefish);
  crypto.getRandomValues(nonceSerpent);
  crypto.getRandomValues(nonceChaCha);
  crypto.getRandomValues(nonceAes);

  const totalBytes = chunkCount * ENCRYPTED_CHUNK_SIZE + METADATA_SIZE + POINTER_BLOCK_SIZE;
  onStart?.(chunkCount, totalBytes);

  const startTime = performance.now();
  let processedBytes = 0;

  // Strict sequential reassembly sequencer
  let nextEmitChunk = 0;
  const completedChunks = new Map<number, Uint8Array>();

  // Strict sequential HMAC digest calculation
  let nextHmacChunk = 0;
  const rawChunkMap = new Map<number, Uint8Array>();
  const updateSequentialHmac = (chunkIdx: number, bytes: Uint8Array) => {
    rawChunkMap.set(chunkIdx, bytes);
    while (rawChunkMap.has(nextHmacChunk)) {
      const b = rawChunkMap.get(nextHmacChunk)!;
      rawChunkMap.delete(nextHmacChunk);
      hmacHasher.update(b);
      nextHmacChunk++;
    }
  };

  // Background pipelined chunk prefetcher (eliminates storage read latency)
  const slicePrefetchMap = new Map<number, Promise<ArrayBuffer>>();
  const getChunkSlice = (chunkIdx: number): Promise<ArrayBuffer> => {
    if (!slicePrefetchMap.has(chunkIdx)) {
      const start = chunkIdx * CHUNK_SIZE;
      const end = Math.min(originalSize, start + CHUNK_SIZE);
      slicePrefetchMap.set(chunkIdx, file.slice(start, end).arrayBuffer());
    }
    return slicePrefetchMap.get(chunkIdx)!;
  };

  const emitReadyChunks = async () => {
    while (completedChunks.has(nextEmitChunk)) {
      const chunk = completedChunks.get(nextEmitChunk)!;
      completedChunks.delete(nextEmitChunk);
      await onChunkOutput(chunk);
      nextEmitChunk++;
    }
  };

  // Dispatch chunks across workers
  let nextDispatchChunk = 0;

  const dispatchToWorker = async (worker: Worker) => {
    while (nextDispatchChunk < chunkCount) {
      if (signal?.aborted) throw new Error('Aborted');
      const idx = nextDispatchChunk++;

      // Trigger background read-ahead prefetching for upcoming chunks
      if (idx + 1 < chunkCount) getChunkSlice(idx + 1);
      if (idx + 2 < chunkCount) getChunkSlice(idx + 2);

      const rawBuffer = await getChunkSlice(idx);
      slicePrefetchMap.delete(idx);
      const rawBytes = new Uint8Array(rawBuffer);

      // Feed to strictly sequenced HMAC
      updateSequentialHmac(idx, rawBytes);

      const chunkWithTags = new Uint8Array(ENCRYPTED_CHUNK_SIZE);
      chunkWithTags.set(rawBytes, 0);
      if (rawBytes.length < CHUNK_SIZE) {
        fillRandomBytes(chunkWithTags.subarray(rawBytes.length, CHUNK_SIZE));
      }

      // Delegate chunk encryption to worker thread
      const encryptedBuffer = await new Promise<ArrayBuffer>((resolve, reject) => {
        const handler = (e: MessageEvent) => {
          if (e.data.type === 'CHUNK_DONE' && e.data.chunkIndex === idx) {
            worker.removeEventListener('message', handler);
            resolve(e.data.data);
          } else if (e.data.type === 'ERROR') {
            worker.removeEventListener('message', handler);
            reject(new Error(e.data.error || 'Chunk encryption failed'));
          }
        };
        worker.addEventListener('message', handler);
        worker.postMessage(
          {
            action: 'ENCRYPT_CHUNK',
            chunkIndex: idx,
            chunkData: chunkWithTags.buffer,
            nonceThreefish,
            nonceSerpent,
            nonceChaCha,
            nonceAes,
          },
          [chunkWithTags.buffer]
        );
      });

      completedChunks.set(idx, new Uint8Array(encryptedBuffer));
      await emitReadyChunks();

      processedBytes += rawBytes.length;
      const elapsedSec = (performance.now() - startTime) / 1000;
      const speedMBs = processedBytes / (1024 * 1024) / Math.max(0.01, elapsedSec);
      const remainingChunks = chunkCount - (idx + 1);
      const etaSeconds = speedMBs > 0 ? (remainingChunks * (CHUNK_SIZE / (1024 * 1024))) / speedMBs : 0;

      onProgress?.({
        type: 'PROGRESS',
        phase: 'ENCRYPTING',
        currentChunk: Math.min(chunkCount, nextEmitChunk),
        totalChunks: chunkCount,
        currentLayer: 4,
        processedBytes,
        totalBytes: originalSize,
        speedMBs: Number(speedMBs.toFixed(1)),
        etaSeconds: Math.max(0, Math.round(etaSeconds)),
      });
    }
  };

  await Promise.all(workers.map((w) => dispatchToWorker(w)));
  await emitReadyChunks();

  // Finalize container metadata & tail pointer
  const hmacIntegrity = hmacHasher.digest();
  const orderHash = sha256(new TextEncoder().encode(CASCADE_ORDER_TAG_STRING));

  const metadata = encodeMetadataBlob({
    magic: 0x464B4E31,
    version: 1,
    originalSize,
    chunkCount,
    chunkSize: CHUNK_SIZE,
    nonceThreefish,
    nonceSerpent,
    nonceChaCha20: nonceChaCha,
    nonceAes256: nonceAes,
    hmacIntegrity,
    orderConfirm: orderHash,
  });

  const maskedMeta = await maskMetadataBlob(metadata, k4);
  const salt16 = new Uint8Array(maskedMeta.subarray(maskedMeta.length - 16));
  const metadataOffset = chunkCount * ENCRYPTED_CHUNK_SIZE;
  const tailPointer = await encryptTailPointer(metadataOffset, METADATA_SIZE, k4, salt16);

  await onChunkOutput(maskedMeta);
  await onChunkOutput(tailPointer);

  const totalTimeMs = performance.now() - startTime;
  const avgSpeed = (originalSize / (1024 * 1024)) / Math.max(0.01, totalTimeMs / 1000);

  return {
    type: 'SUCCESS',
    mode: 'ENCRYPT',
    fileName: file.name,
    originalSize,
    finalSize: totalBytes,
    totalTimeMs: Math.round(totalTimeMs),
    averageSpeedMBs: Number(avgSpeed.toFixed(1)),
  };
}

async function executePoolDecryption(params: {
  file: File;
  workers: Worker[];
  k1: Uint8Array;
  k2: Uint8Array;
  k4: Uint8Array;
  onStart?: (totalChunks: number, totalBytes: number) => void;
  onProgress?: (progress: WorkerProgressMessage) => void;
  onChunkOutput: (chunkBytes: Uint8Array) => Promise<void> | void;
  signal?: AbortSignal;
}): Promise<WorkerSuccessMessage> {
  const { file, workers, k1, k2, k4, onStart, onProgress, onChunkOutput, signal } = params;
  const containerSize = file.size;

  if (containerSize < METADATA_SIZE + POINTER_BLOCK_SIZE) {
    throw new Error(GENERIC_DECRYPT_ERROR);
  }

  // 1. Decrypt tail pointer
  const tailSlice = file.slice(containerSize - POINTER_BLOCK_SIZE, containerSize);
  const tailBuffer = await tailSlice.arrayBuffer();
  const tailBytes = new Uint8Array(tailBuffer);

  const saltSlice = file.slice(containerSize - POINTER_BLOCK_SIZE - 16, containerSize - POINTER_BLOCK_SIZE);
  const saltBuffer = await saltSlice.arrayBuffer();
  const salt16 = new Uint8Array(saltBuffer);

  const { offset, length } = await decryptTailPointer(tailBytes, k4, salt16);
  if (offset < 0 || length !== METADATA_SIZE || offset + length + POINTER_BLOCK_SIZE !== containerSize) {
    throw new Error(GENERIC_DECRYPT_ERROR);
  }

  // 2. Decode & unmask metadata
  const metaSlice = file.slice(offset, offset + length);
  const metaBuffer = await metaSlice.arrayBuffer();
  const rawMetaBytes = new Uint8Array(metaBuffer);

  const unmasked = await maskMetadataBlob(rawMetaBytes, k4);
  const metadata = decodeMetadataBlob(unmasked);

  // Adversarial integrity check
  const expectedOrderHash = sha256(new TextEncoder().encode(CASCADE_ORDER_TAG_STRING));
  if (!constantTimeCompare(metadata.orderConfirm, expectedOrderHash)) {
    throw new Error(GENERIC_DECRYPT_ERROR);
  }

  const { originalSize, chunkCount, nonceThreefish, nonceSerpent, nonceChaCha20, nonceAes256 } = metadata;

  if (chunkCount * ENCRYPTED_CHUNK_SIZE !== offset) {
    throw new Error(GENERIC_DECRYPT_ERROR);
  }
  if (originalSize < 0 || originalSize > chunkCount * CHUNK_SIZE || (chunkCount > 1 && originalSize <= (chunkCount - 1) * CHUNK_SIZE)) {
    throw new Error(GENERIC_DECRYPT_ERROR);
  }

  const hmacKey = deriveHmacKey(k1, k2);
  const hmacHasher = hmac.create(sha256, hmacKey);

  onStart?.(chunkCount, originalSize);

  const startTime = performance.now();
  let processedBytes = 0;

  // Strict sequential reassembly sequencer
  let nextEmitChunk = 0;
  const completedChunks = new Map<number, Uint8Array>();

  const emitReadyChunks = async () => {
    while (completedChunks.has(nextEmitChunk)) {
      const plainChunk = completedChunks.get(nextEmitChunk)!;
      completedChunks.delete(nextEmitChunk);

      const isLast = nextEmitChunk === chunkCount - 1;
      const validLen = isLast ? originalSize - (chunkCount - 1) * CHUNK_SIZE : CHUNK_SIZE;
      const finalBytes = plainChunk.subarray(0, validLen);

      hmacHasher.update(finalBytes);
      await onChunkOutput(finalBytes);

      processedBytes += finalBytes.length;
      nextEmitChunk++;
    }
  };

  // Background pipelined chunk prefetcher for encrypted chunks
  const slicePrefetchMap = new Map<number, Promise<ArrayBuffer>>();
  const getEncChunkSlice = (chunkIdx: number): Promise<ArrayBuffer> => {
    if (!slicePrefetchMap.has(chunkIdx)) {
      const start = chunkIdx * ENCRYPTED_CHUNK_SIZE;
      const end = start + ENCRYPTED_CHUNK_SIZE;
      slicePrefetchMap.set(chunkIdx, file.slice(start, end).arrayBuffer());
    }
    return slicePrefetchMap.get(chunkIdx)!;
  };

  let nextDispatchChunk = 0;

  const dispatchToWorker = async (worker: Worker) => {
    while (nextDispatchChunk < chunkCount) {
      if (signal?.aborted) throw new Error('Aborted');
      const idx = nextDispatchChunk++;

      // Trigger background read-ahead prefetching for upcoming chunks
      if (idx + 1 < chunkCount) getEncChunkSlice(idx + 1);
      if (idx + 2 < chunkCount) getEncChunkSlice(idx + 2);

      const encBuffer = await getEncChunkSlice(idx);
      slicePrefetchMap.delete(idx);
      if (encBuffer.byteLength < ENCRYPTED_CHUNK_SIZE) {
        throw new Error(GENERIC_DECRYPT_ERROR);
      }

      const plainBuffer = await new Promise<ArrayBuffer>((resolve, reject) => {
        const handler = (e: MessageEvent) => {
          if (e.data.type === 'CHUNK_DONE' && e.data.chunkIndex === idx) {
            worker.removeEventListener('message', handler);
            resolve(e.data.data);
          } else if (e.data.type === 'ERROR') {
            worker.removeEventListener('message', handler);
            reject(new Error(GENERIC_DECRYPT_ERROR));
          }
        };
        worker.addEventListener('message', handler);
        worker.postMessage(
          {
            action: 'DECRYPT_CHUNK',
            chunkIndex: idx,
            chunkData: encBuffer,
            nonceThreefish,
            nonceSerpent,
            nonceChaCha: nonceChaCha20,
            nonceAes: nonceAes256,
          },
          [encBuffer]
        );
      });

      completedChunks.set(idx, new Uint8Array(plainBuffer));
      await emitReadyChunks();

      const elapsedSec = (performance.now() - startTime) / 1000;
      const speedMBs = processedBytes / (1024 * 1024) / Math.max(0.01, elapsedSec);
      const remainingChunks = chunkCount - (idx + 1);
      const etaSeconds = speedMBs > 0 ? (remainingChunks * (CHUNK_SIZE / (1024 * 1024))) / speedMBs : 0;

      onProgress?.({
        type: 'PROGRESS',
        phase: 'DECRYPTING',
        currentChunk: Math.min(chunkCount, nextEmitChunk),
        totalChunks: chunkCount,
        currentLayer: 1,
        processedBytes,
        totalBytes: originalSize,
        speedMBs: Number(speedMBs.toFixed(1)),
        etaSeconds: Math.max(0, Math.round(etaSeconds)),
      });
    }
  };

  await Promise.all(workers.map((w) => dispatchToWorker(w)));
  await emitReadyChunks();

  // Adversarial check: Verify HMAC integrity of entire recovered plaintext
  const computedHmac = hmacHasher.digest();
  if (!constantTimeCompare(computedHmac, metadata.hmacIntegrity)) {
    throw new Error(GENERIC_DECRYPT_ERROR);
  }

  const totalTimeMs = performance.now() - startTime;
  const avgSpeed = (originalSize / (1024 * 1024)) / Math.max(0.01, totalTimeMs / 1000);

  const strippedName = file.name.replace(/\.fortknox$/i, '');
  const restoredName = strippedName.length > 0 ? strippedName : 'decrypted_file';

  return {
    type: 'SUCCESS',
    mode: 'DECRYPT',
    fileName: restoredName,
    originalSize: containerSize,
    finalSize: originalSize,
    totalTimeMs: Math.round(totalTimeMs),
    averageSpeedMBs: Number(avgSpeed.toFixed(1)),
  };
}
