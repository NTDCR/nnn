/**
 * Fort-Knox Cascade Cryptographic Streaming Web Worker
 * Performs chunk-by-chunk zero-RAM cascade encryption and decryption for the multi-worker pool.
 * Dedicated to pure cryptographic ALU execution with zero storage/main-thread lockup.
 */

import { hexToBytes, GENERIC_DECRYPT_ERROR } from '../crypto/cascade.ts';
import { createCascadeEngine, WasmCascadeInstance } from '../crypto/wasmBridge.ts';
import { shapeChunkFixed, unshapeChunkFixed } from '../crypto/distributionMatcher.ts';

const CHUNK_SIZE = 1048576; // 1 MB
const ENCRYPTED_CHUNK_SIZE = CHUNK_SIZE + 32;

const postWorkerMessage = (message: unknown, transfer?: Transferable[]) => {
  (self as unknown as { postMessage: (msg: unknown, transfer?: Transferable[]) => void }).postMessage(
    message,
    transfer
  );
};

let pooledEngine: WasmCascadeInstance | null = null;

self.onmessage = async (e: MessageEvent) => {
  const data = e.data;
  const action = data.action;

  if (action === 'INIT_POOL') {
    let k1: Uint8Array | null = null;
    let k2: Uint8Array | null = null;
    let k3: Uint8Array | null = null;
    let k4: Uint8Array | null = null;
    try {
      const keys = data.keys;
      k1 = hexToBytes(keys.layer1ThreefishHex, 128);
      k2 = hexToBytes(keys.layer2SerpentHex, 32);
      k3 = hexToBytes(keys.layer3ChaChaHex, 32);
      k4 = hexToBytes(keys.layer4AesHex, 32);
      pooledEngine = await createCascadeEngine(k1, k2, k3, k4);

      // Micro-warmup pass to tier up V8 TurboFan / WebAssembly for immediate peak bidirectional speed
      const warmBuf = new Uint8Array(65536);
      const warmNonce = new Uint8Array(16);
      try {
        const warmEnc = await pooledEngine.encryptChunk(
          warmBuf,
          0,
          warmNonce,
          warmNonce,
          warmNonce.subarray(0, 12),
          warmNonce.subarray(0, 12)
        );
        const warmDec = await pooledEngine.decryptChunk(
          warmEnc.ciphertext,
          0,
          warmNonce,
          warmNonce,
          warmNonce.subarray(0, 12),
          warmNonce.subarray(0, 12),
          warmEnc.tagChaCha,
          warmEnc.tagAes
        );
        warmDec.fill(0);
        warmEnc.ciphertext.fill(0);
      } finally {
        warmBuf.fill(0);
        warmNonce.fill(0);
      }

      self.postMessage({ type: 'POOL_READY' });
    } catch (err: unknown) {
      self.postMessage({ type: 'ERROR', error: err instanceof Error ? err.message : 'Pool init failed' });
    } finally {
      k1?.fill(0);
      k2?.fill(0);
      k3?.fill(0);
      k4?.fill(0);
    }
    return;
  }

  if (action === 'PROBE_CORE') {
    try {
      if (!pooledEngine) throw new Error('Engine not initialized');
      const probeBuf = new Uint8Array(131072);
      const probeNonce = new Uint8Array(16);
      try {
        // Warmup pass to trigger V8 TurboFan / WebKit FTL tier-up compilation for BOTH Encrypt & Decrypt
        const enc = await pooledEngine.encryptChunk(
          probeBuf,
          0,
          probeNonce,
          probeNonce,
          probeNonce.subarray(0, 12),
          probeNonce.subarray(0, 12)
        );
        const dec = await pooledEngine.decryptChunk(
          enc.ciphertext,
          0,
          probeNonce,
          probeNonce,
          probeNonce.subarray(0, 12),
          probeNonce.subarray(0, 12),
          enc.tagChaCha,
          enc.tagAes
        );
        dec.fill(0);
        enc.ciphertext.fill(0);

        // Measured benchmark pass
        const start = performance.now();
        const encBench = await pooledEngine.encryptChunk(
          probeBuf,
          0,
          probeNonce,
          probeNonce,
          probeNonce.subarray(0, 12),
          probeNonce.subarray(0, 12)
        );
        const elapsedMs = performance.now() - start;
        encBench.ciphertext.fill(0);
        self.postMessage({ type: 'PROBE_DONE', elapsedMs });
      } finally {
        probeBuf.fill(0);
        probeNonce.fill(0);
      }
    } catch {
      self.postMessage({ type: 'PROBE_DONE', elapsedMs: 9999 });
    }
    return;
  }

  if (action === 'ENCRYPT_CHUNK') {
    let chunkWithTags: Uint8Array | null = null;
    try {
      if (!pooledEngine) throw new Error('Engine not initialized');
      const { chunkIndex, chunkData, nonceThreefish, nonceSerpent, nonceChaCha, nonceAes, entropyShaped } = data;
      chunkWithTags = new Uint8Array(chunkData);
      if (chunkWithTags.length < ENCRYPTED_CHUNK_SIZE) {
        throw new Error('Invalid chunk buffer size');
      }
      const chunkSlice = chunkWithTags.subarray(0, CHUNK_SIZE);
      const { ciphertext, tagChaCha, tagAes } = await pooledEngine.encryptChunk(
        chunkSlice,
        chunkIndex,
        new Uint8Array(nonceThreefish),
        new Uint8Array(nonceSerpent),
        new Uint8Array(nonceChaCha),
        new Uint8Array(nonceAes)
      );
      if (ciphertext !== chunkSlice) {
        chunkWithTags.set(ciphertext, 0);
      }
      chunkWithTags.set(tagChaCha, CHUNK_SIZE);
      chunkWithTags.set(tagAes, CHUNK_SIZE + 16);

      let finalBuffer: ArrayBuffer;
      if (entropyShaped) {
        const shaped = shapeChunkFixed(chunkWithTags);
        chunkWithTags.fill(0);
        finalBuffer = shaped.buffer as ArrayBuffer;
      } else {
        finalBuffer = chunkWithTags.buffer as ArrayBuffer;
      }

      postWorkerMessage(
        {
          type: 'CHUNK_DONE',
          chunkIndex,
          data: finalBuffer,
        },
        [finalBuffer]
      );
    } catch (err: unknown) {
      if (chunkWithTags && chunkWithTags.byteLength > 0 && !chunkWithTags.buffer.detached) {
        chunkWithTags.fill(0);
      }
      self.postMessage({ type: 'ERROR', error: err instanceof Error ? err.message : 'Chunk encryption failed' });
    }
    return;
  }

  if (action === 'DECRYPT_CHUNK') {
    let chunkWithTags: Uint8Array | null = null;
    try {
      if (!pooledEngine) throw new Error('Engine not initialized');
      const { chunkIndex, chunkData, nonceThreefish, nonceSerpent, nonceChaCha, nonceAes, entropyShaped } = data;
      if (entropyShaped) {
        const shapedSlot = new Uint8Array(chunkData);
        chunkWithTags = unshapeChunkFixed(shapedSlot, ENCRYPTED_CHUNK_SIZE);
        shapedSlot.fill(0);
      } else {
        chunkWithTags = new Uint8Array(chunkData);
      }
      if (chunkWithTags.length !== ENCRYPTED_CHUNK_SIZE) {
        throw new Error(GENERIC_DECRYPT_ERROR);
      }
      let plain: Uint8Array;
      if (typeof pooledEngine.decryptChunkContiguous === 'function') {
        // Zero-copy in-place contiguous tag arrangement:
        // 1. Save 16-byte tagChaCha to stack array (only 16 bytes copied)
        const tagChaCha = new Uint8Array(16);
        tagChaCha.set(chunkWithTags.subarray(CHUNK_SIZE, CHUNK_SIZE + 16));

        // 2. Move 16-byte tagAes directly contiguous with ciphertext in-place (16 bytes copy)
        chunkWithTags.copyWithin(CHUNK_SIZE, CHUNK_SIZE + 16, CHUNK_SIZE + 32);

        // 3. Contiguous slice (1048576 + 16 bytes) with ZERO 1MB memory staging copy
        const contiguousCipherAndTag = chunkWithTags.subarray(0, CHUNK_SIZE + 16);

        plain = await pooledEngine.decryptChunkContiguous(
          contiguousCipherAndTag,
          chunkIndex,
          new Uint8Array(nonceThreefish),
          new Uint8Array(nonceSerpent),
          new Uint8Array(nonceChaCha),
          new Uint8Array(nonceAes),
          tagChaCha
        );
      } else {
        const ciphertext = chunkWithTags.subarray(0, CHUNK_SIZE);
        const tagChaCha = chunkWithTags.subarray(CHUNK_SIZE, CHUNK_SIZE + 16);
        const tagAes = chunkWithTags.subarray(CHUNK_SIZE + 16, CHUNK_SIZE + 32);
        plain = await pooledEngine.decryptChunk(
          ciphertext,
          chunkIndex,
          new Uint8Array(nonceThreefish),
          new Uint8Array(nonceSerpent),
          new Uint8Array(nonceChaCha),
          new Uint8Array(nonceAes),
          tagChaCha,
          tagAes
        );
      }
      const isOriginalBuffer = plain.byteLength === plain.buffer.byteLength && plain.byteOffset === 0 && plain.buffer === chunkWithTags.buffer;
      const outBuffer = (plain.byteLength === plain.buffer.byteLength && plain.byteOffset === 0)
        ? plain.buffer
        : plain.slice().buffer;
      if (!isOriginalBuffer) {
        chunkWithTags.fill(0);
      }
      postWorkerMessage(
        {
          type: 'CHUNK_DONE',
          chunkIndex,
          data: outBuffer,
        },
        [outBuffer]
      );
    } catch {
      if (chunkWithTags && chunkWithTags.byteLength > 0 && !chunkWithTags.buffer.detached) {
        chunkWithTags.fill(0);
      }
      self.postMessage({ type: 'ERROR', error: GENERIC_DECRYPT_ERROR });
    }
    return;
  }

  if (action === 'DESTROY_POOL') {
    if (pooledEngine && typeof pooledEngine.destroy === 'function') {
      try {
        pooledEngine.destroy();
      } catch {
        // Ignore cleanup error
      }
    }
    pooledEngine = null;
    self.postMessage({ type: 'POOL_DESTROYED' });
    return;
  }
};
