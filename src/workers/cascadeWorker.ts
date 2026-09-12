/**
 * Fort-Knox Cascade Cryptographic Streaming Web Worker
 * Performs chunk-by-chunk zero-RAM cascade encryption and decryption.
 * RAM footprint capped at 2 - 3 MB via Transferable ArrayBuffers.
 */

import { hexToBytes, fillRandomBytes, GENERIC_DECRYPT_ERROR } from '../crypto/cascade.ts';
import { createCascadeEngine, WasmCascadeInstance } from '../crypto/wasmBridge.ts';
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

const postWorkerMessage = (message: unknown, transfer?: Transferable[]) => {
  (self as unknown as { postMessage: (msg: unknown, transfer?: Transferable[]) => void }).postMessage(
    message,
    transfer
  );
};

self.onmessage = async (e: MessageEvent) => {
  const { action, file, keys } = e.data;
  let k1: Uint8Array | null = null;
  let k2: Uint8Array | null = null;
  let k3: Uint8Array | null = null;
  let k4: Uint8Array | null = null;

  try {
    k1 = hexToBytes(keys.layer1ThreefishHex);
    k2 = hexToBytes(keys.layer2SerpentHex, 32);
    k3 = hexToBytes(keys.layer3ChaChaHex, 32);
    k4 = hexToBytes(keys.layer4AesHex, 32);

    const engine = await createCascadeEngine(
      k1,
      k2,
      k3,
      k4
    );

    if (action === 'ENCRYPT') {
      await processEncryption(file, engine, k1, k2, k4);
    } else if (action === 'DECRYPT') {
      await processDecryption(file, engine, k1, k2, k4);
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : GENERIC_DECRYPT_ERROR;
    self.postMessage({
      type: 'ERROR',
      error: message.includes('key') || message.includes('Decryption')
        ? GENERIC_DECRYPT_ERROR
        : message,
    });
  } finally {
    // Comprehensive ephemeral key hygiene
    if (k1) k1.fill(0);
    if (k2) k2.fill(0);
    if (k3) k3.fill(0);
    if (k4) k4.fill(0);
  }
};

async function processEncryption(
  file: File,
  pipeline: WasmCascadeInstance,
  k1: Uint8Array,
  k2: Uint8Array,
  k4: Uint8Array
) {
  const originalSize = file.size;
  const chunkCount = Math.max(1, Math.ceil(originalSize / CHUNK_SIZE));

  // Initialize genuine HMAC-SHA256 calculation for plaintext integrity
  const hmacKey = deriveHmacKey(k1, k2);
  const hmacHasher = hmac.create(sha256, hmacKey);

  // Generate independent random nonces for each layer
  const nonceThreefish = new Uint8Array(16);
  const nonceSerpent = new Uint8Array(16);
  const nonceChaCha = new Uint8Array(12);
  const nonceAes = new Uint8Array(12);

  crypto.getRandomValues(nonceThreefish);
  crypto.getRandomValues(nonceSerpent);
  crypto.getRandomValues(nonceChaCha);
  crypto.getRandomValues(nonceAes);

  const startTime = performance.now();
  let processedBytes = 0;

  // Start notification
  self.postMessage({
    type: 'START',
    totalChunks: chunkCount,
    totalBytes: chunkCount * CHUNK_SIZE + METADATA_SIZE + POINTER_BLOCK_SIZE,
  });

  // Stream each 1 MB chunk
  for (let i = 0; i < chunkCount; i++) {
    const startByte = i * CHUNK_SIZE;
    const endByte = Math.min(originalSize, startByte + CHUNK_SIZE);
    const blobSlice = file.slice(startByte, endByte);
    const arrayBuffer = await blobSlice.arrayBuffer();

    // Plaintext integrity update (accumulates unpadded bytes)
    hmacHasher.update(new Uint8Array(arrayBuffer));

    let chunk = new Uint8Array(CHUNK_SIZE);
    chunk.set(new Uint8Array(arrayBuffer), 0);

    // If final chunk is smaller than 1 MB, pad with cryptographic random bytes
    if (arrayBuffer.byteLength < CHUNK_SIZE) {
      const padLen = CHUNK_SIZE - arrayBuffer.byteLength;
      const pad = new Uint8Array(padLen);
      fillRandomBytes(pad);
      chunk.set(pad, arrayBuffer.byteLength);
    }

    // Cascade encrypt
    const { ciphertext, tagChaCha, tagAes } = await pipeline.encryptChunk(
      chunk,
      i,
      nonceThreefish,
      nonceSerpent,
      nonceChaCha,
      nonceAes
    );

    // Store ciphertext along with its authentication tags (1 MB + 16B + 16B = 1,048,608 bytes)
    const ENCRYPTED_CHUNK_SIZE = CHUNK_SIZE + 32;
    const chunkWithTags = new Uint8Array(ENCRYPTED_CHUNK_SIZE);
    chunkWithTags.set(ciphertext, 0);
    chunkWithTags.set(tagChaCha, CHUNK_SIZE);
    chunkWithTags.set(tagAes, CHUNK_SIZE + 16);

    processedBytes += CHUNK_SIZE;
    const elapsedSec = (performance.now() - startTime) / 1000;
    const speedMBs = processedBytes / (1024 * 1024) / Math.max(0.01, elapsedSec);
    const remainingChunks = chunkCount - i - 1;
    const etaSeconds = speedMBs > 0 ? (remainingChunks * (CHUNK_SIZE / (1024 * 1024))) / speedMBs : 0;

    // Send encrypted chunk to consumer with Transferable ArrayBuffer (Zero Copy)
    postWorkerMessage(
      {
        type: 'CHUNK_OUTPUT',
        chunkIndex: i,
        data: chunkWithTags.buffer,
      },
      [chunkWithTags.buffer]
    );

    self.postMessage({
      type: 'PROGRESS',
      phase: 'ENCRYPTING',
      currentChunk: i + 1,
      totalChunks: chunkCount,
      currentLayer: 4,
      processedBytes,
      totalBytes: chunkCount * CHUNK_SIZE,
      speedMBs: Number(speedMBs.toFixed(1)),
      etaSeconds: Math.ceil(etaSeconds),
    });
  }

  // Generate authentic plaintext integrity tag
  const hmacIntegrity = hmacHasher.digest();

  const orderConfirm = new Uint8Array(32);
  // Layer order hash
  const orderEncoder = new TextEncoder().encode(CASCADE_ORDER_TAG_STRING);
  const orderHash = await crypto.subtle.digest('SHA-256', orderEncoder);
  orderConfirm.set(new Uint8Array(orderHash));

  // Build 512-byte metadata blob
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
    orderConfirm,
  });

  // Mask metadata using Key 4
  const maskedMetadata = await maskMetadataBlob(metadata, k4);

  // Salt derived from trailing 16 random padding bytes of masked metadata
  const salt16 = new Uint8Array(maskedMetadata.subarray(maskedMetadata.length - 16));

  // Metadata placement offset (immediately after all chunks)
  const ENCRYPTED_CHUNK_SIZE = CHUNK_SIZE + 32;
  const metadataOffset = chunkCount * ENCRYPTED_CHUNK_SIZE;

  // Emit masked metadata blob
  postWorkerMessage(
    {
      type: 'CHUNK_OUTPUT',
      chunkIndex: chunkCount,
      data: maskedMetadata.buffer,
    },
    [maskedMetadata.buffer]
  );

  // Encrypt 32-byte tail pointer with container-specific salt
  const tailPointer = await encryptTailPointer(metadataOffset, METADATA_SIZE, k4, salt16);

  // Emit 32-byte tail pointer
  postWorkerMessage(
    {
      type: 'CHUNK_OUTPUT',
      chunkIndex: chunkCount + 1,
      data: tailPointer.buffer,
    },
    [tailPointer.buffer]
  );

  const totalTimeMs = performance.now() - startTime;
  const avgSpeed = (originalSize / (1024 * 1024)) / Math.max(0.01, totalTimeMs / 1000);

  self.postMessage({
    type: 'SUCCESS',
    mode: 'ENCRYPT',
    fileName: `${file.name}.fortknox`,
    originalSize,
    finalSize: chunkCount * ENCRYPTED_CHUNK_SIZE + METADATA_SIZE + POINTER_BLOCK_SIZE,
    totalTimeMs: Math.round(totalTimeMs),
    averageSpeedMBs: Number(avgSpeed.toFixed(1)),
  });
}

async function processDecryption(
  file: File,
  pipeline: WasmCascadeInstance,
  k1: Uint8Array,
  k2: Uint8Array,
  k4: Uint8Array
) {
  const containerSize = file.size;
  if (containerSize < METADATA_SIZE + POINTER_BLOCK_SIZE) {
    throw new Error(GENERIC_DECRYPT_ERROR);
  }

  // 1. Read last 32 bytes (tail pointer) and the preceding 16 bytes (salt)
  const tailSlice = file.slice(containerSize - POINTER_BLOCK_SIZE, containerSize);
  const tailBuffer = await tailSlice.arrayBuffer();
  const tailBytes = new Uint8Array(tailBuffer);

  const saltSlice = file.slice(
    containerSize - POINTER_BLOCK_SIZE - 16,
    containerSize - POINTER_BLOCK_SIZE
  );
  const saltBuffer = await saltSlice.arrayBuffer();
  const salt16 = new Uint8Array(saltBuffer);

  // 2. Decrypt tail pointer with Key 4 (salted or legacy fallback)
  const { offset, length } = await decryptTailPointer(tailBytes, k4, salt16);
  if (
    offset < 0 ||
    length !== METADATA_SIZE ||
    offset + length + POINTER_BLOCK_SIZE !== containerSize
  ) {
    throw new Error(GENERIC_DECRYPT_ERROR);
  }

  // 3. Read 512-byte metadata blob
  const metaSlice = file.slice(offset, offset + length);
  const metaBuffer = await metaSlice.arrayBuffer();
  const rawMetaBytes = new Uint8Array(metaBuffer);

  // 4. Unmask metadata using Key 4
  const unmasked = await maskMetadataBlob(rawMetaBytes, k4);
  const metadata = decodeMetadataBlob(unmasked);

  // Adversarial integrity check: verify cascade order confirmation tag with constantTimeCompare
  const expectedOrderHash = new Uint8Array(await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(CASCADE_ORDER_TAG_STRING)
  ));
  if (!constantTimeCompare(metadata.orderConfirm, expectedOrderHash)) {
    throw new Error(GENERIC_DECRYPT_ERROR);
  }

  const { originalSize, chunkCount, nonceThreefish, nonceSerpent, nonceChaCha20, nonceAes256 } = metadata;
  const ENCRYPTED_CHUNK_SIZE = CHUNK_SIZE + 32;

  // Strict container structural invariants
  if (chunkCount * ENCRYPTED_CHUNK_SIZE !== offset) {
    throw new Error(GENERIC_DECRYPT_ERROR);
  }

  if (
    originalSize < 0 ||
    originalSize > chunkCount * CHUNK_SIZE ||
    (chunkCount > 1 && originalSize <= (chunkCount - 1) * CHUNK_SIZE)
  ) {
    throw new Error(GENERIC_DECRYPT_ERROR);
  }

  // Initialize HMAC-SHA256 for plaintext verification
  const hmacKey = deriveHmacKey(k1, k2);
  const hmacHasher = hmac.create(sha256, hmacKey);

  const startTime = performance.now();
  let processedBytes = 0;

  self.postMessage({
    type: 'START',
    totalChunks: chunkCount,
    totalBytes: originalSize,
  });

  // Stream each chunk and decrypt
  for (let i = 0; i < chunkCount; i++) {
    const startByte = i * ENCRYPTED_CHUNK_SIZE;
    const endByte = startByte + ENCRYPTED_CHUNK_SIZE;
    const blobSlice = file.slice(startByte, endByte);
    const arrayBuffer = await blobSlice.arrayBuffer();
    const chunkWithTags = new Uint8Array(arrayBuffer);

    if (chunkWithTags.length < ENCRYPTED_CHUNK_SIZE) {
      throw new Error(GENERIC_DECRYPT_ERROR);
    }

    const ciphertext = chunkWithTags.subarray(0, CHUNK_SIZE);
    const tagChaCha = chunkWithTags.subarray(CHUNK_SIZE, CHUNK_SIZE + 16);
    const tagAes = chunkWithTags.subarray(CHUNK_SIZE + 16, CHUNK_SIZE + 32);

    // Decrypt chunk through pipeline
    const plaintextChunk = await pipeline.decryptChunk(
      ciphertext,
      i,
      nonceThreefish,
      nonceSerpent,
      nonceChaCha20,
      nonceAes256,
      tagChaCha,
      tagAes
    ).catch(() => {
      // If AEAD mismatch or decryption failure, throw generic constant-time error
      throw new Error(GENERIC_DECRYPT_ERROR);
    });

    // Determine slice length for final chunk
    let outputBytes = plaintextChunk;
    if (i === chunkCount - 1) {
      const remainingBytes = originalSize - (chunkCount - 1) * CHUNK_SIZE;
      outputBytes = plaintextChunk.subarray(0, remainingBytes);
    }

    // Accumulate unpadded plaintext into HMAC
    hmacHasher.update(outputBytes);

    processedBytes += outputBytes.length;
    const elapsedSec = (performance.now() - startTime) / 1000;
    const speedMBs = processedBytes / (1024 * 1024) / Math.max(0.01, elapsedSec);

    const outBuffer = (outputBytes.byteLength === outputBytes.buffer.byteLength && outputBytes.byteOffset === 0)
      ? outputBytes.buffer
      : outputBytes.slice().buffer;

    postWorkerMessage(
      {
        type: 'CHUNK_OUTPUT',
        chunkIndex: i,
        data: outBuffer,
      },
      [outBuffer]
    );

    self.postMessage({
      type: 'PROGRESS',
      phase: 'DECRYPTING',
      currentChunk: i + 1,
      totalChunks: chunkCount,
      currentLayer: 1,
      processedBytes,
      totalBytes: originalSize,
      speedMBs: Number(speedMBs.toFixed(1)),
      etaSeconds: Math.ceil(((chunkCount - i - 1) * (CHUNK_SIZE / (1024 * 1024))) / Math.max(0.01, speedMBs)),
    });
  }

  // Strict constant-time HMAC plaintext integrity verification
  const computedHmac = hmacHasher.digest();
  if (!constantTimeCompare(computedHmac, metadata.hmacIntegrity)) {
    throw new Error(GENERIC_DECRYPT_ERROR);
  }

  const totalTimeMs = performance.now() - startTime;
  const avgSpeed = (originalSize / (1024 * 1024)) / Math.max(0.01, totalTimeMs / 1000);

  // Restore original filename by stripping .fortknox (case-insensitive)
  const strippedName = file.name.replace(/\.fortknox$/i, '');
  const restoredName = strippedName.length > 0 ? strippedName : 'decrypted_file';

  self.postMessage({
    type: 'SUCCESS',
    mode: 'DECRYPT',
    fileName: restoredName,
    originalSize: containerSize,
    finalSize: originalSize,
    totalTimeMs: Math.round(totalTimeMs),
    averageSpeedMBs: Number(avgSpeed.toFixed(1)),
  });
}
