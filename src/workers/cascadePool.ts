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
  coreConcurrency?: 'auto' | 'webgpu' | 2 | 4 | 6 | 8;
  onStart?: (totalChunks: number, totalBytes: number) => void;
  onProgress?: (progress: WorkerProgressMessage) => void;
  onChunkOutput: (chunkBytes: Uint8Array) => Promise<void> | void;
  signal?: AbortSignal;
}

interface WorkerProbeResult {
  worker: Worker;
  elapsedMs: number;
}

// Cached core profile so calibration probe runs strictly ONCE per application session (~3ms overhead)
let cachedCalibratedWorkers: number | null = null;

/**
 * Calibrates the worker pool and strictly filters out Efficiency (E) cores on hybrid CPU architectures.
 * Only executes when > 4 logical threads are available and mode is 'auto'.
 * Standard 2-core / 4-thread CPUs (all P-cores) bypass filtering completely.
 * On hybrid systems, true E-cores (>2.2x slower than fastest P-core) are pruned.
 */
async function calibrateAndFilterPCores(candidateWorkers: Worker[]): Promise<Worker[]> {
  // Systems with 4 or fewer threads are entirely Performance cores (no E-cores)
  if (candidateWorkers.length <= 4) {
    return candidateWorkers;
  }

  try {
    const probePromises = candidateWorkers.map(
      (w) =>
        new Promise<WorkerProbeResult>((resolve) => {
          const cleanup = () => {
            w.removeEventListener('message', handler);
            w.removeEventListener('error', errHandler);
          };
          const handler = (e: MessageEvent) => {
            if (e.data?.type === 'PROBE_DONE') {
              cleanup();
              resolve({
                worker: w,
                elapsedMs: typeof e.data.elapsedMs === 'number' ? e.data.elapsedMs : 9999,
              });
            }
          };
          const errHandler = () => {
            cleanup();
            resolve({
              worker: w,
              elapsedMs: 9999,
            });
          };
          w.addEventListener('message', handler);
          w.addEventListener('error', errHandler, { once: true });
          w.postMessage({ action: 'PROBE_CORE' });
        })
    );

    // Timeout safety fallback of 1500ms
    const fallback = candidateWorkers.map((w) => ({ worker: w, elapsedMs: 50 }));
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<WorkerProbeResult[]>((resolve) => {
      timer = setTimeout(() => resolve(fallback), 1500);
    });

    const results = await Promise.race([Promise.all(probePromises), timeout]);
    if (timer) clearTimeout(timer);
    // Sort ascending by execution time (fastest first)
    const sorted = [...results].sort((a, b) => a.elapsedMs - b.elapsedMs);
    const fastest = Math.max(1.0, sorted[0].elapsedMs);

    // Strict P-Core threshold: True Efficiency cores are 2.2x to 3.5x slower.
    // Preserves all Performance cores without false-positive pruning from scheduler jitter.
    const pCoreWorkers: Worker[] = [];
    const eCoreWorkers: Worker[] = [];

    for (const res of sorted) {
      if (res.elapsedMs <= fastest * 2.2) {
        pCoreWorkers.push(res.worker);
      } else {
        eCoreWorkers.push(res.worker);
      }
    }

    // Safety: ensure at least 2 workers (or candidate count) are retained (supports dual P-core mobile Big.LITTLE)
    const minRetained = Math.min(candidateWorkers.length, 2);
    while (pCoreWorkers.length < minRetained && eCoreWorkers.length > 0) {
      pCoreWorkers.push(eCoreWorkers.pop()!);
    }

    // Cleanly destroy and terminate verified E-core workers
    for (const eWorker of eCoreWorkers) {
      try {
        eWorker.postMessage({ action: 'DESTROY_POOL' });
      } catch {
        // Ignore if already terminated
      }
      eWorker.terminate();
    }

    cachedCalibratedWorkers = pCoreWorkers.length;
    return pCoreWorkers;
  } catch {
    cachedCalibratedWorkers = Math.min(candidateWorkers.length, 2);
    return candidateWorkers;
  }
}

export async function processFileWithPool(options: ProcessFileOptions): Promise<WorkerSuccessMessage> {
  const { action, file, keys, coreConcurrency, onStart, onProgress, onChunkOutput, signal } = options;

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

    const isMultiChunk = file.size > CHUNK_SIZE;
    const hardwareConcurrency = typeof navigator !== 'undefined' ? navigator.hardwareConcurrency || 4 : 4;
    const ua = typeof navigator !== 'undefined' ? navigator.userAgent : '';
    const isDesktopOS = /Windows NT|Win64|x86_64|X11.*Linux|Macintosh|Mac OS X/i.test(ua);
    const isExplicitMobile = /Android|iPhone|iPod|BlackBerry|IEMobile|Opera Mini/i.test(ua) ||
      Boolean((navigator as unknown as { userAgentData?: { mobile?: boolean } }).userAgentData?.mobile);
    const isMobileDevice = !isDesktopOS && isExplicitMobile;

    let targetWorkerCount: number;
    if (!isMultiChunk) {
      targetWorkerCount = 1;
    } else if (coreConcurrency === 'webgpu') {
      targetWorkerCount = isMobileDevice ? 2 : Math.min(hardwareConcurrency, 8);
    } else if (coreConcurrency === 2 || coreConcurrency === 4 || coreConcurrency === 6 || coreConcurrency === 8) {
      targetWorkerCount = coreConcurrency;
    } else {
      // 'auto' mode:
      if (isMobileDevice) {
        // Mobile heterogeneous SoCs (e.g. Samsung Exynos 1280 on Galaxy M34 5G) feature 2x Cortex-A78 P-cores + 6x Cortex-A55 E-cores.
        // Assigning exactly 2 workers allows Android EAS to pin them strictly to the 2 Performance cores,
        // completely eliminating E-core head-of-line stalls and thermal throttling.
        targetWorkerCount = 2;
      } else if (hardwareConcurrency <= 4) {
        targetWorkerCount = Math.max(2, hardwareConcurrency);
      } else if (cachedCalibratedWorkers !== null) {
        targetWorkerCount = cachedCalibratedWorkers;
      } else {
        // Probe candidate workers up to hardware capacity (capped at 8)
        const candidates = hardwareConcurrency >= 8 ? 8 : (hardwareConcurrency >= 6 ? 6 : 4);
        targetWorkerCount = candidates;
      }
    }

    // Instantiate worker pool
    for (let i = 0; i < targetWorkerCount; i++) {
      const w = new Worker(new URL('./cascadeWorker.ts', import.meta.url), { type: 'module' });
      workers.push(w);
    }

    if (signal?.aborted) throw new Error('Aborted');

    // Initialize each worker with keys and safe crash handling
    const initPromises = workers.map(
      (w) =>
        new Promise<void>((resolve, reject) => {
          const cleanup = () => {
            w.removeEventListener('message', msgHandler);
            w.removeEventListener('error', errHandler);
          };
          const msgHandler = (e: MessageEvent) => {
            if (e.data.type === 'POOL_READY') {
              cleanup();
              resolve();
            } else if (e.data.type === 'ERROR') {
              cleanup();
              reject(new Error(e.data.error || 'Worker init failed'));
            }
          };
          const errHandler = (e: ErrorEvent) => {
            cleanup();
            reject(new Error(e?.message || 'Worker initialization crashed'));
          };
          w.addEventListener('message', msgHandler);
          w.addEventListener('error', errHandler);
          w.postMessage({ action: 'INIT_POOL', keys });
        })
    );
    const abortPromise = new Promise<never>((_, reject) => {
      if (signal?.aborted) {
        reject(new Error('Aborted'));
        return;
      }
      signal?.addEventListener('abort', () => reject(new Error('Aborted')), { once: true });
    });
    let initTimeoutTimer: ReturnType<typeof setTimeout> | undefined;
    const timeoutPromise = new Promise<never>((_, reject) => {
      initTimeoutTimer = setTimeout(() => reject(new Error('Worker pool initialization timed out')), 10000);
    });

    try {
      await Promise.race([Promise.all(initPromises), abortPromise, timeoutPromise]);
    } finally {
      if (initTimeoutTimer) clearTimeout(initTimeoutTimer);
    }

    if (signal?.aborted) throw new Error('Aborted');

    // Strict P-Core Enforcement: Calibrate strictly once when in 'auto' or 'webgpu' mode and system has > 4 threads on desktop
    let activeWorkers = workers;
    if (isMultiChunk && workers.length > 4 && (coreConcurrency === 'auto' || coreConcurrency === 'webgpu') && !isMobileDevice && cachedCalibratedWorkers === null) {
      activeWorkers = await calibrateAndFilterPCores(workers);
    }

    if (signal?.aborted) throw new Error('Aborted');

    if (action === 'ENCRYPT') {
      return await executePoolEncryption({
        file,
        workers: activeWorkers,
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
        workers: activeWorkers,
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
    // Ephemeral key hygiene and worker memory zeroization
    workers.forEach((w) => {
      try {
        w.postMessage({ action: 'DESTROY_POOL' });
      } catch {
        // Ignore if already terminated
      }
      w.terminate();
    });
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

  let hmacKey: Uint8Array | null = deriveHmacKey(k1, k2);
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

  // Asynchronous background writer to decouple storage/disk I/O from worker ALU computation
  let writerPromise: Promise<void> = Promise.resolve();
  let writerError: Error | null = null;
  let workerError: Error | null = null;
  const backpressureWaiters: (() => void)[] = [];

  const notifyDrain = () => {
    while (backpressureWaiters.length > 0) {
      const wake = backpressureWaiters.shift();
      wake?.();
    }
  };

  const drainReadyChunks = () => {
    writerPromise = writerPromise.then(async () => {
      while (completedChunks.has(nextEmitChunk)) {
        if (signal?.aborted) throw new Error('Aborted');
        if (workerError) throw workerError;
        const chunk = completedChunks.get(nextEmitChunk)!;
        completedChunks.delete(nextEmitChunk);
        await onChunkOutput(chunk);
        nextEmitChunk++;
        notifyDrain();
      }
    }).catch((err) => {
      writerError = err instanceof Error ? err : new Error(String(err));
      notifyDrain();
    });
  };

  // Real-time sliding window speed calculation (2.0s window) with weighted blend
  interface SpeedSample {
    time: number;
    bytes: number;
  }
  const speedSamples: SpeedSample[] = [];
  const WINDOW_MS = 2000;

  const calculateLiveSpeed = (chunkBytes: number): number => {
    const now = performance.now();
    speedSamples.push({ time: now, bytes: chunkBytes });
    while (speedSamples.length > 1 && now - speedSamples[0].time > WINDOW_MS) {
      speedSamples.shift();
    }
    const elapsedTotalSec = Math.max(0.05, (now - startTime) / 1000);
    const overallSpeed = processedBytes / (1024 * 1024) / elapsedTotalSec;

    if (speedSamples.length < 2) {
      return overallSpeed;
    }
    const windowSec = (now - speedSamples[0].time) / 1000;
    if (windowSec < 0.1) {
      return overallSpeed;
    }
    let windowBytes = 0;
    for (let i = 0; i < speedSamples.length; i++) {
      windowBytes += speedSamples[i].bytes;
    }
    const windowSpeed = windowBytes / (1024 * 1024) / windowSec;
    return windowSpeed * 0.7 + overallSpeed * 0.3;
  };

  // Setup permanent message dispatch router for each worker (eliminates per-chunk addEventListener/removeEventListener churn)
  const pendingEncMap = new Map<number, { resolve: (data: ArrayBuffer) => void; reject: (err: Error) => void }>();

  // Instant abort listener to immediately reject pending chunks and wake backpressure
  const onAbort = () => {
    const abortErr = new Error('Aborted');
    for (const p of pendingEncMap.values()) {
      p.reject(abortErr);
    }
    pendingEncMap.clear();
    notifyDrain();
  };
  if (signal) {
    if (signal.aborted) onAbort();
    else signal.addEventListener('abort', onAbort, { once: true });
  }

  try {
    workers.forEach((w) => {
      w.onmessage = (e: MessageEvent) => {
        if (e.data.type === 'CHUNK_DONE') {
          const p = pendingEncMap.get(e.data.chunkIndex);
          if (p) {
            pendingEncMap.delete(e.data.chunkIndex);
            p.resolve(e.data.data);
          }
        } else if (e.data.type === 'ERROR') {
          const err = new Error(e.data.error || 'Chunk encryption failed');
          workerError = err;
          for (const p of pendingEncMap.values()) {
            p.reject(err);
          }
          pendingEncMap.clear();
          notifyDrain();
        }
      };
      w.onerror = (e: ErrorEvent) => {
        const err = new Error(e?.message || 'Worker thread crashed');
        workerError = err;
        for (const p of pendingEncMap.values()) {
          p.reject(err);
        }
        pendingEncMap.clear();
        notifyDrain();
      };
    });

  // Dispatch chunks across workers
  let nextDispatchChunk = 0;
  let completedChunksCount = 0;

  const dispatchToWorker = async (worker: Worker) => {
    while (nextDispatchChunk < chunkCount) {
      if (signal?.aborted) throw new Error('Aborted');
      if (writerError) throw writerError;
      if (workerError) throw workerError;
      const idx = nextDispatchChunk++;

      // Trigger background read-ahead prefetching for upcoming chunks
      for (let p = 1; p <= 4; p++) {
        if (idx + p < chunkCount) getChunkSlice(idx + p);
      }

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
        pendingEncMap.set(idx, { resolve, reject });
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
      drainReadyChunks();
      completedChunksCount++;

      // Event-driven backpressure: wake instantly via microtask when output writes advance
      const maxBuffered = Math.max(16, workers.length * 4);
      while (completedChunks.size >= maxBuffered && !writerError && !workerError) {
        if (signal?.aborted) throw new Error('Aborted');
        await new Promise<void>((resolve) => {
          const timer = setTimeout(resolve, 2);
          backpressureWaiters.push(() => {
            clearTimeout(timer);
            resolve();
          });
        });
      }
      if (writerError) throw writerError;
      if (workerError) throw workerError;

      processedBytes += rawBytes.length;
      const speedMBs = calculateLiveSpeed(rawBytes.length);
      const remainingChunks = chunkCount - completedChunksCount;
      const etaSeconds = speedMBs > 0 ? (remainingChunks * (CHUNK_SIZE / (1024 * 1024))) / speedMBs : 0;

      onProgress?.({
        type: 'PROGRESS',
        phase: 'ENCRYPTING',
        currentChunk: Math.min(chunkCount, completedChunksCount + (completedChunksCount < chunkCount ? 1 : 0)),
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
  drainReadyChunks();
  await writerPromise;
  if (writerError) throw writerError;

  // Emit guaranteed 100% final progress so UI smoothly transitions to success
  onProgress?.({
    type: 'PROGRESS',
    phase: 'ENCRYPTING',
    currentChunk: chunkCount,
    totalChunks: chunkCount,
    currentLayer: 4,
    processedBytes: originalSize,
    totalBytes: originalSize,
    speedMBs: Number(calculateLiveSpeed(0).toFixed(1)),
    etaSeconds: 0,
  });

  // Finalize container metadata & tail pointer
  if (nextHmacChunk < chunkCount) {
    throw new Error('Incomplete encryption stream');
  }
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
    fileName: `${file.name}.fortknox`,
    originalSize,
    finalSize: totalBytes,
    totalTimeMs: Math.round(totalTimeMs),
    averageSpeedMBs: Number(avgSpeed.toFixed(1)),
  };
  } finally {
    if (hmacKey) {
      hmacKey.fill(0);
      hmacKey = null;
    }
    for (const b of completedChunks.values()) {
      b.fill(0);
    }
    completedChunks.clear();
    for (const b of rawChunkMap.values()) {
      b.fill(0);
    }
    rawChunkMap.clear();

    signal?.removeEventListener('abort', onAbort);
    const cancelErr = new Error(signal?.aborted ? 'Aborted' : 'Encryption stream interrupted');
    for (const p of pendingEncMap.values()) {
      p.reject(cancelErr);
    }
    pendingEncMap.clear();
    notifyDrain();
  }
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
  let metadata: ReturnType<typeof decodeMetadataBlob>;
  try {
    metadata = decodeMetadataBlob(unmasked);
  } finally {
    unmasked.fill(0);
  }

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

  let hmacKey: Uint8Array | null = deriveHmacKey(k1, k2);
  const hmacHasher = hmac.create(sha256, hmacKey);

  onStart?.(chunkCount, originalSize);

  const startTime = performance.now();
  let processedBytes = 0;

  // Strict sequential reassembly sequencer
  let nextEmitChunk = 0;
  const completedChunks = new Map<number, Uint8Array>();

  // Strict sequential HMAC digest calculation (runs concurrently with output writes)
  let nextHmacChunk = 0;
  const rawHmacMap = new Map<number, Uint8Array>();
  const updateSequentialHmac = (chunkIdx: number, bytes: Uint8Array) => {
    rawHmacMap.set(chunkIdx, bytes);
    while (rawHmacMap.has(nextHmacChunk)) {
      const b = rawHmacMap.get(nextHmacChunk)!;
      rawHmacMap.delete(nextHmacChunk);
      hmacHasher.update(b);
      nextHmacChunk++;
    }
  };

  // Asynchronous background writer to decouple storage/disk I/O from worker ALU computation
  let writerPromise: Promise<void> = Promise.resolve();
  let writerError: Error | null = null;
  let workerError: Error | null = null;
  const backpressureWaiters: (() => void)[] = [];

  const notifyDrain = () => {
    while (backpressureWaiters.length > 0) {
      const wake = backpressureWaiters.shift();
      wake?.();
    }
  };

  const drainReadyChunks = () => {
    writerPromise = writerPromise.then(async () => {
      while (completedChunks.has(nextEmitChunk)) {
        if (signal?.aborted) throw new Error('Aborted');
        if (workerError) throw workerError;
        const finalBytes = completedChunks.get(nextEmitChunk)!;
        completedChunks.delete(nextEmitChunk);

        await onChunkOutput(finalBytes);

        nextEmitChunk++;
        notifyDrain();
      }
    }).catch((err) => {
      writerError = err instanceof Error ? err : new Error(String(err));
      notifyDrain();
    });
  };

  // Real-time sliding window speed calculation (2.0s window) with weighted blend
  interface SpeedSample {
    time: number;
    bytes: number;
  }
  const speedSamples: SpeedSample[] = [];
  const WINDOW_MS = 2000;

  const calculateLiveSpeed = (chunkBytes: number): number => {
    const now = performance.now();
    speedSamples.push({ time: now, bytes: chunkBytes });
    while (speedSamples.length > 1 && now - speedSamples[0].time > WINDOW_MS) {
      speedSamples.shift();
    }
    const elapsedTotalSec = Math.max(0.05, (now - startTime) / 1000);
    const overallSpeed = processedBytes / (1024 * 1024) / elapsedTotalSec;

    if (speedSamples.length < 2) {
      return overallSpeed;
    }
    const windowSec = (now - speedSamples[0].time) / 1000;
    if (windowSec < 0.1) {
      return overallSpeed;
    }
    let windowBytes = 0;
    for (let i = 0; i < speedSamples.length; i++) {
      windowBytes += speedSamples[i].bytes;
    }
    const windowSpeed = windowBytes / (1024 * 1024) / windowSec;
    return windowSpeed * 0.7 + overallSpeed * 0.3;
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

  // Setup permanent message dispatch router for each worker (eliminates per-chunk addEventListener/removeEventListener churn)
  const pendingDecMap = new Map<number, { resolve: (data: ArrayBuffer) => void; reject: (err: Error) => void }>();

  // Instant abort listener to immediately reject pending chunks and wake backpressure
  const onAbort = () => {
    const abortErr = new Error('Aborted');
    for (const p of pendingDecMap.values()) {
      p.reject(abortErr);
    }
    pendingDecMap.clear();
    notifyDrain();
  };
  if (signal) {
    if (signal.aborted) onAbort();
    else signal.addEventListener('abort', onAbort, { once: true });
  }

  try {
    workers.forEach((w) => {
      w.onmessage = (e: MessageEvent) => {
        if (e.data.type === 'CHUNK_DONE') {
          const p = pendingDecMap.get(e.data.chunkIndex);
          if (p) {
            pendingDecMap.delete(e.data.chunkIndex);
            p.resolve(e.data.data);
          }
        } else if (e.data.type === 'ERROR') {
          const err = new Error(GENERIC_DECRYPT_ERROR);
          workerError = err;
          for (const p of pendingDecMap.values()) {
            p.reject(err);
          }
          pendingDecMap.clear();
          notifyDrain();
        }
      };
      w.onerror = () => {
        const err = new Error(GENERIC_DECRYPT_ERROR);
        workerError = err;
        for (const p of pendingDecMap.values()) {
          p.reject(err);
        }
        pendingDecMap.clear();
        notifyDrain();
      };
    });

  let nextDispatchChunk = 0;
  let completedChunksCount = 0;

  const dispatchToWorker = async (worker: Worker) => {
    while (nextDispatchChunk < chunkCount) {
      if (signal?.aborted) throw new Error('Aborted');
      if (writerError) throw writerError;
      if (workerError) throw workerError;
      const idx = nextDispatchChunk++;

      // Trigger background read-ahead prefetching for upcoming chunks
      for (let p = 1; p <= 4; p++) {
        if (idx + p < chunkCount) getEncChunkSlice(idx + p);
      }

      const encBuffer = await getEncChunkSlice(idx);
      slicePrefetchMap.delete(idx);
      if (encBuffer.byteLength < ENCRYPTED_CHUNK_SIZE) {
        throw new Error(GENERIC_DECRYPT_ERROR);
      }

      const plainBuffer = await new Promise<ArrayBuffer>((resolve, reject) => {
        pendingDecMap.set(idx, { resolve, reject });
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

      const isLast = idx === chunkCount - 1;
      const validLen = isLast ? originalSize - (chunkCount - 1) * CHUNK_SIZE : CHUNK_SIZE;
      const plainBytes = new Uint8Array(plainBuffer);
      const finalBytes = plainBytes.subarray(0, validLen);

      // Decoupled concurrent HMAC computation (runs immediately without blocking writer)
      updateSequentialHmac(idx, finalBytes);

      completedChunks.set(idx, finalBytes);
      drainReadyChunks();
      completedChunksCount++;

      // Event-driven backpressure: wake instantly via microtask when output writes advance
      const maxBuffered = Math.max(16, workers.length * 4);
      while (completedChunks.size >= maxBuffered && !writerError && !workerError) {
        if (signal?.aborted) throw new Error('Aborted');
        await new Promise<void>((resolve) => {
          const timer = setTimeout(resolve, 2);
          backpressureWaiters.push(() => {
            clearTimeout(timer);
            resolve();
          });
        });
      }
      if (writerError) throw writerError;
      if (workerError) throw workerError;

      processedBytes += validLen;
      const speedMBs = calculateLiveSpeed(validLen);
      const remainingChunks = chunkCount - completedChunksCount;
      const etaSeconds = speedMBs > 0 ? (remainingChunks * (CHUNK_SIZE / (1024 * 1024))) / speedMBs : 0;

      onProgress?.({
        type: 'PROGRESS',
        phase: 'DECRYPTING',
        currentChunk: Math.min(chunkCount, completedChunksCount + (completedChunksCount < chunkCount ? 1 : 0)),
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
  drainReadyChunks();
  await writerPromise;
  if (writerError) throw writerError;

  // Emit guaranteed 100% final progress so UI smoothly transitions to success
  onProgress?.({
    type: 'PROGRESS',
    phase: 'DECRYPTING',
    currentChunk: chunkCount,
    totalChunks: chunkCount,
    currentLayer: 1,
    processedBytes: originalSize,
    totalBytes: originalSize,
    speedMBs: Number(calculateLiveSpeed(0).toFixed(1)),
    etaSeconds: 0,
  });

  // Ensure all HMAC chunks have been processed
  if (nextHmacChunk < chunkCount) {
    throw new Error(GENERIC_DECRYPT_ERROR);
  }

  // Adversarial check: Verify HMAC integrity of entire recovered plaintext
  const computedHmac = hmacHasher.digest();
  if (!constantTimeCompare(computedHmac, metadata.hmacIntegrity)) {
    throw new Error(GENERIC_DECRYPT_ERROR);
  }

  const totalTimeMs = performance.now() - startTime;
  const avgSpeed = (originalSize / (1024 * 1024)) / Math.max(0.01, totalTimeMs / 1000);

  const strippedName = file.name.replace(/\.fortknox$/i, '');
  const restoredName = strippedName !== file.name && strippedName.length > 0
    ? strippedName
    : `decrypted_${file.name.length > 0 ? file.name : 'file'}`;

  return {
    type: 'SUCCESS',
    mode: 'DECRYPT',
    fileName: restoredName,
    originalSize: containerSize,
    finalSize: originalSize,
    totalTimeMs: Math.round(totalTimeMs),
    averageSpeedMBs: Number(avgSpeed.toFixed(1)),
  };
  } finally {
    if (hmacKey) {
      hmacKey.fill(0);
      hmacKey = null;
    }
    for (const b of completedChunks.values()) {
      b.fill(0);
    }
    completedChunks.clear();
    for (const b of rawHmacMap.values()) {
      b.fill(0);
    }
    rawHmacMap.clear();

    signal?.removeEventListener('abort', onAbort);
    const cancelErr = new Error(signal?.aborted ? 'Aborted' : GENERIC_DECRYPT_ERROR);
    for (const p of pendingDecMap.values()) {
      p.reject(cancelErr);
    }
    pendingDecMap.clear();
    notifyDrain();
  }
}
