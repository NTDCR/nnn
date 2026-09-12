/**
 * Antiforensic Container Format Encoders & Decoders
 * Complies with /docs/FILE_FORMAT_SPEC.md
 * - Zero Magic Bytes in Container Header
 * - Hidden Metadata Blob at Pseudo-Random Offset
 * - Encrypted 32-Byte Tail Pointer
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { chacha20 } from '@noble/ciphers/chacha.js';
import { ContainerMetadata } from '../types/crypto.ts';
import { fillRandomBytes } from './cascade.ts';

const METADATA_MAGIC = 0x464B4E31; // "FKN1"
const CONTAINER_VERSION = 1;
export const METADATA_SIZE = 512; // Exactly 512 bytes
export const POINTER_BLOCK_SIZE = 32; // Last 32 bytes of file

/**
 * Constant time byte comparison
 */
export function constantTimeCompare(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Derives a 32-byte subkey for metadata masking using SHA-256 (via @noble/hashes)
 */
async function deriveMetadataKey(key4: Uint8Array): Promise<Uint8Array> {
  const combined = new Uint8Array(key4.length + 20);
  combined.set(key4, 0);
  combined.set(new TextEncoder().encode('FORTKNOX_METADATA_V1'), key4.length);
  return sha256(combined);
}

/**
 * Derives a deterministic 12-byte nonce from Key 4 for the tail pointer (via @noble/hashes)
 */
async function derivePointerNonce(key4: Uint8Array): Promise<Uint8Array> {
  const combined = new Uint8Array(key4.length + 25);
  combined.set(key4, 0);
  combined.set(new TextEncoder().encode('FORTKNOX_POINTER_NONCE_V1'), key4.length);
  return sha256(combined).subarray(0, 12);
}

/**
 * Derives a deterministic 12-byte nonce from Key 4 for metadata masking (via @noble/hashes)
 */
async function deriveMetadataNonce(key4: Uint8Array): Promise<Uint8Array> {
  const combined = new Uint8Array(key4.length + 26);
  combined.set(key4, 0);
  combined.set(new TextEncoder().encode('FORTKNOX_METADATA_NONCE_V1'), key4.length);
  return sha256(combined).subarray(0, 12);
}

export const CASCADE_ORDER_TAG_STRING = 'FORTKNOX_CASCADE_ORDER_L1_L2_L3_L4_VERIFIED';

/**
 * Encodes the 512-byte metadata blob
 */
export function encodeMetadataBlob(meta: Partial<ContainerMetadata> & {
  originalSize: number;
  chunkCount: number;
  chunkSize: number;
  nonceThreefish: Uint8Array;
  nonceSerpent: Uint8Array;
  nonceChaCha20: Uint8Array;
  nonceAes256: Uint8Array;
  orderConfirm: Uint8Array;
  hmacIntegrity?: Uint8Array;
}): Uint8Array {
  const buf = new Uint8Array(METADATA_SIZE);
  // Fill entire buffer with cryptographic random noise first
  fillRandomBytes(buf);

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  view.setUint32(0, meta.magic ?? METADATA_MAGIC, true);
  view.setUint32(4, meta.version ?? CONTAINER_VERSION, true);
  view.setBigUint64(8, BigInt(meta.originalSize), true);
  view.setUint32(16, meta.chunkCount, true);
  view.setUint32(20, meta.chunkSize, true);

  buf.set(meta.nonceThreefish.subarray(0, 16), 24);
  buf.set(meta.nonceSerpent.subarray(0, 16), 40);
  buf.set(meta.nonceChaCha20.subarray(0, 12), 56);
  buf.set(meta.nonceAes256.subarray(0, 12), 68);
  if (meta.hmacIntegrity) {
    buf.set(meta.hmacIntegrity.subarray(0, 32), 80);
  }
  buf.set(meta.orderConfirm.subarray(0, 32), 112);

  return buf;
}

/**
 * Decodes the 512-byte metadata blob
 */
export function decodeMetadataBlob(buf: Uint8Array): ContainerMetadata {
  if (buf.length !== METADATA_SIZE) {
    throw new Error('Decryption failed. Check all keys.');
  }

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const magic = view.getUint32(0, true);
  const version = view.getUint32(4, true);

  if (magic !== METADATA_MAGIC || version !== CONTAINER_VERSION) {
    throw new Error('Decryption failed. Check all keys.');
  }

  const originalSize = Number(view.getBigUint64(8, true));
  const chunkCount = view.getUint32(16, true);
  const chunkSize = view.getUint32(20, true);

  if (originalSize < 0 || chunkCount <= 0 || chunkSize !== 1048576) {
    throw new Error('Decryption failed. Check all keys.');
  }

  const nonceThreefish = new Uint8Array(buf.subarray(24, 40));
  const nonceSerpent = new Uint8Array(buf.subarray(40, 56));
  const nonceChaCha20 = new Uint8Array(buf.subarray(56, 68));
  const nonceAes256 = new Uint8Array(buf.subarray(68, 80));
  const hmacIntegrity = new Uint8Array(buf.subarray(80, 112));
  const orderConfirm = new Uint8Array(buf.subarray(112, 144));

  return {
    magic,
    version,
    originalSize,
    chunkCount,
    chunkSize,
    nonceThreefish,
    nonceSerpent,
    nonceChaCha20,
    nonceAes256,
    hmacIntegrity,
    orderConfirm,
  };
}

/**
 * Applies XOR mask to metadata blob using ChaCha20 keystream
 */
export async function maskMetadataBlob(
  metaBlob: Uint8Array,
  key4: Uint8Array,
  explicitNonce?: Uint8Array
): Promise<Uint8Array> {
  const metaKey = await deriveMetadataKey(key4);
  const nonce12 = explicitNonce || (await deriveMetadataNonce(key4));
  return chacha20(metaKey, nonce12, metaBlob, undefined, 1);
}

/**
 * Encrypts the 32-byte tail pointer
 * [Offset (8B)] [Length (4B)] [Padding (4B)] [Tag (16B)]
 */
export async function encryptTailPointer(
  offset: number,
  length: number,
  key4: Uint8Array
): Promise<Uint8Array> {
  const pointerData = new Uint8Array(16);
  const view = new DataView(pointerData.buffer, pointerData.byteOffset, pointerData.byteLength);
  view.setBigUint64(0, BigInt(offset), true);
  view.setUint32(8, length, true);
  // Padding with random bytes
  crypto.getRandomValues(pointerData.subarray(12, 16));

  const pointerNonce = await derivePointerNonce(key4);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key4,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const cipher = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: pointerNonce, tagLength: 128 },
    cryptoKey,
    pointerData
  );

  return new Uint8Array(cipher); // Exactly 32 bytes (16B cipher + 16B tag)
}

/**
 * Decrypts the 32-byte tail pointer
 */
export async function decryptTailPointer(
  tail32: Uint8Array,
  key4: Uint8Array
): Promise<{ offset: number; length: number }> {
  if (tail32.length !== 32) {
    throw new Error('Decryption failed. Check all keys.');
  }

  const pointerNonce = await derivePointerNonce(key4);

  try {
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key4,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: pointerNonce, tagLength: 128 },
      cryptoKey,
      tail32
    );

    const view = new DataView(decrypted);
    const offset = Number(view.getBigUint64(0, true));
    const length = view.getUint32(8, true);

    if (length !== METADATA_SIZE || offset < 0) {
      throw new Error('Decryption failed. Check all keys.');
    }

    return { offset, length };
  } catch {
    throw new Error('Decryption failed. Check all keys.');
  }
}
