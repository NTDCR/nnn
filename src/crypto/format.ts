/**
 * Antiforensic Container Format Encoders & Decoders
 * Complies with /docs/FILE_FORMAT_SPEC.md
 * - Zero Magic Bytes in Container Header
 * - Hidden Metadata Blob at Pseudo-Random Offset
 * - Encrypted 32-Byte Tail Pointer
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { chacha20 } from '@noble/ciphers/chacha.js';
import { gcm } from '@noble/ciphers/aes.js';
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
 * Authoritatively derives a 32-byte key for HMAC-SHA256 plaintext integrity from Layer 1 & 2 keys.
 * Strictly enforces 128-byte (1024-bit) Layer 1 key and 32-byte (256-bit) Layer 2 key.
 */
export function deriveHmacKey(k1: Uint8Array, k2: Uint8Array): Uint8Array {
  if (k1.length !== 128 || k2.length !== 32) {
    throw new Error('HMAC key derivation requires strictly a 128-byte Layer 1 key and a 32-byte Layer 2 key.');
  }
  const label = new TextEncoder().encode('FORTKNOX_HMAC_KEY_V1');
  const combined = new Uint8Array(k1.length + k2.length + label.length);
  combined.set(k1, 0);
  combined.set(k2, k1.length);
  combined.set(label, k1.length + k2.length);
  return sha256(combined);
}

/**
 * Derives a 32-byte subkey for metadata masking using SHA-256 (via @noble/hashes)
 */
async function deriveMetadataKey(key4: Uint8Array): Promise<Uint8Array> {
  const label = new TextEncoder().encode('FORTKNOX_METADATA_V1');
  const combined = new Uint8Array(key4.length + label.length);
  combined.set(key4, 0);
  combined.set(label, key4.length);
  return sha256(combined);
}

/**
 * Derives a 12-byte nonce from Key 4 with optional container salt for the tail pointer
 */
export async function derivePointerNonce(key4: Uint8Array, salt?: Uint8Array): Promise<Uint8Array> {
  const label = new TextEncoder().encode('FORTKNOX_POINTER_NONCE_V1');
  const saltLen = salt ? salt.length : 0;
  const combined = new Uint8Array(key4.length + label.length + saltLen);
  combined.set(key4, 0);
  combined.set(label, key4.length);
  if (salt) {
    combined.set(salt, key4.length + label.length);
  }
  return sha256(combined).subarray(0, 12);
}

/**
 * Derives a 12-byte nonce from Key 4 with optional container salt for metadata masking
 */
export async function deriveMetadataNonce(key4: Uint8Array, salt?: Uint8Array): Promise<Uint8Array> {
  const label = new TextEncoder().encode('FORTKNOX_METADATA_NONCE_V1');
  const saltLen = salt ? salt.length : 0;
  const combined = new Uint8Array(key4.length + label.length + saltLen);
  combined.set(key4, 0);
  combined.set(label, key4.length);
  if (salt) {
    combined.set(salt, key4.length + label.length);
  }
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
  explicitNonceOrSalt?: Uint8Array
): Promise<Uint8Array> {
  const metaKey = await deriveMetadataKey(key4);
  let nonce12: Uint8Array;
  if (explicitNonceOrSalt && explicitNonceOrSalt.length === 12) {
    nonce12 = explicitNonceOrSalt;
  } else if (explicitNonceOrSalt) {
    nonce12 = await deriveMetadataNonce(key4, explicitNonceOrSalt);
  } else {
    nonce12 = await deriveMetadataNonce(key4);
  }
  return chacha20(metaKey, nonce12, metaBlob, undefined, 1);
}

/**
 * Encrypts the 32-byte tail pointer
 * [Offset (8B)] [Length (4B)] [Padding (4B)] [Tag (16B)]
 */
export async function encryptTailPointer(
  offset: number,
  length: number,
  key4: Uint8Array,
  salt?: Uint8Array
): Promise<Uint8Array> {
  const pointerData = new Uint8Array(16);
  const view = new DataView(pointerData.buffer, pointerData.byteOffset, pointerData.byteLength);
  view.setBigUint64(0, BigInt(offset), true);
  view.setUint32(8, length, true);
  // Padding with random bytes
  fillRandomBytes(pointerData.subarray(12, 16));

  const pointerNonce = await derivePointerNonce(key4, salt);

  if (typeof crypto !== 'undefined' && crypto?.subtle && typeof crypto.subtle.importKey === 'function') {
    try {
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
    } catch {
      // Fall through to Noble Ciphers fallback
    }
  }

  // Pure software AES-GCM fallback (Noble Ciphers)
  const cipher = gcm(key4, pointerNonce);
  return cipher.encrypt(pointerData);
}

/**
 * Decrypts the 32-byte tail pointer with constant-time error masking
 */
export async function decryptTailPointer(
  tail32: Uint8Array,
  key4: Uint8Array,
  salt: Uint8Array
): Promise<{ offset: number; length: number }> {
  if (tail32.length !== 32 || !salt || salt.length !== 16) {
    throw new Error('Decryption failed. Check all keys.');
  }

  const pointerNonce = await derivePointerNonce(key4, salt);

  if (typeof crypto !== 'undefined' && crypto?.subtle && typeof crypto.subtle.importKey === 'function') {
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

      if (length === METADATA_SIZE && offset >= 0) {
        return { offset, length };
      }
    } catch {
      // Fall through to Noble Ciphers fallback
    }
  }

  // Pure software AES-GCM fallback (Noble Ciphers)
  try {
    const cipher = gcm(key4, pointerNonce);
    const decrypted = cipher.decrypt(tail32);
    const view = new DataView(decrypted.buffer, decrypted.byteOffset, decrypted.byteLength);
    const offset = Number(view.getBigUint64(0, true));
    const length = view.getUint32(8, true);

    if (length === METADATA_SIZE && offset >= 0) {
      return { offset, length };
    }
  } catch {
    // Constant-time generic error
  }

  throw new Error('Decryption failed. Check all keys.');
}
