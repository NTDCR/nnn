/**
 * Fort-Knox Cascade Cryptographic Streaming Web Worker
 * Performs chunk-by-chunk zero-RAM cascade encryption and decryption for the multi-worker pool.
 * Dedicated to pure cryptographic ALU execution with zero storage/main-thread lockup.
 */

import { hexToBytes, GENERIC_DECRYPT_ERROR } from '../crypto/cascade.ts';
import { createCascadeEngine, WasmCascadeInstance } from '../crypto/wasmBridge.ts';

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
    try {
      const keys = data.keys;
      const k1 = hexToBytes(keys.layer1ThreefishHex, 128);
      const k2 = hexToBytes(keys.layer2SerpentHex, 32);
      const k3 = hexToBytes(keys.layer3ChaChaHex, 32);
      const k4 = hexToBytes(keys.layer4AesHex, 32);
      pooledEngine = await createCascadeEngine(k1, k2, k3, k4);
      self.postMessage({ type: 'POOL_READY' });
    } catch (err: unknown) {
      self.postMessage({ type: 'ERROR', error: err instanceof Error ? err.message : 'Pool init failed' });
    }
    return;
  }

  if (action === 'PROBE_CORE') {
    try {
      if (!pooledEngine) throw new Error('Engine not initialized');
      const probeBuf = new Uint8Array(131072);
      const probeNonce = new Uint8Array(16);

      // Warmup pass to trigger V8 TurboFan / WebKit FTL tier-up compilation
      await pooledEngine.encryptChunk(
        probeBuf,
        0,
        probeNonce,
        probeNonce,
        probeNonce.subarray(0, 12),
        probeNonce.subarray(0, 12)
      );

      // Measured benchmark pass
      const start = performance.now();
      await pooledEngine.encryptChunk(
        probeBuf,
        0,
        probeNonce,
        probeNonce,
        probeNonce.subarray(0, 12),
        probeNonce.subarray(0, 12)
      );
      const elapsedMs = performance.now() - start;
      self.postMessage({ type: 'PROBE_DONE', elapsedMs });
    } catch {
      self.postMessage({ type: 'PROBE_DONE', elapsedMs: 9999 });
    }
    return;
  }

  if (action === 'ENCRYPT_CHUNK') {
    try {
      if (!pooledEngine) throw new Error('Engine not initialized');
      const { chunkIndex, chunkData, nonceThreefish, nonceSerpent, nonceChaCha, nonceAes } = data;
      const chunkWithTags = new Uint8Array(chunkData);
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
      postWorkerMessage(
        {
          type: 'CHUNK_DONE',
          chunkIndex,
          data: chunkWithTags.buffer,
        },
        [chunkWithTags.buffer]
      );
    } catch (err: unknown) {
      self.postMessage({ type: 'ERROR', error: err instanceof Error ? err.message : 'Chunk encryption failed' });
    }
    return;
  }

  if (action === 'DECRYPT_CHUNK') {
    try {
      if (!pooledEngine) throw new Error('Engine not initialized');
      const { chunkIndex, chunkData, nonceThreefish, nonceSerpent, nonceChaCha, nonceAes } = data;
      const chunkWithTags = new Uint8Array(chunkData);
      if (chunkWithTags.length < ENCRYPTED_CHUNK_SIZE) {
        throw new Error(GENERIC_DECRYPT_ERROR);
      }
      const ciphertext = chunkWithTags.subarray(0, CHUNK_SIZE);
      const tagChaCha = chunkWithTags.subarray(CHUNK_SIZE, CHUNK_SIZE + 16);
      const tagAes = chunkWithTags.subarray(CHUNK_SIZE + 16, CHUNK_SIZE + 32);
      const plain = await pooledEngine.decryptChunk(
        ciphertext,
        chunkIndex,
        new Uint8Array(nonceThreefish),
        new Uint8Array(nonceSerpent),
        new Uint8Array(nonceChaCha),
        new Uint8Array(nonceAes),
        tagChaCha,
        tagAes
      );
      const outBuffer = (plain.byteLength === plain.buffer.byteLength && plain.byteOffset === 0)
        ? plain.buffer
        : plain.slice().buffer;
      postWorkerMessage(
        {
          type: 'CHUNK_DONE',
          chunkIndex,
          data: outBuffer,
        },
        [outBuffer]
      );
    } catch {
      self.postMessage({ type: 'ERROR', error: GENERIC_DECRYPT_ERROR });
    }
    return;
  }

  if (action === 'DESTROY_POOL') {
    pooledEngine = null;
    self.postMessage({ type: 'POOL_DESTROYED' });
    return;
  }
};
