/**
 * Antiforensic Container Format Encoders & Decoders
 * Complies with /docs/FILE_FORMAT_SPEC.md
 * - Zero Magic Bytes in Container Header
 * - Hidden Metadata Blob at Pseudo-Random Offset
 * - Encrypted 32-Byte Tail Pointer
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
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
  try {
    combined.set(k1, 0);
    combined.set(k2, k1.length);
    combined.set(label, k1.length + k2.length);
    return sha256(combined);
  } finally {
    combined.fill(0);
  }
}

/**
 * Derives a 32-byte subkey for metadata masking using SHA-256 (via @noble/hashes)
 */
export async function deriveMetadataKey(key4: Uint8Array): Promise<Uint8Array> {
  if (key4.length !== 32) {
    throw new Error('Metadata key derivation requires strictly a 32-byte key.');
  }
  const label = new TextEncoder().encode('FORTKNOX_METADATA_V1');
  const combined = new Uint8Array(key4.length + label.length);
  try {
    combined.set(key4, 0);
    combined.set(label, key4.length);
    return sha256(combined);
  } finally {
    combined.fill(0);
  }
}

/**
 * Derives a 12-byte nonce from Key 4 with optional container salt for the tail pointer
 */
export async function derivePointerNonce(key4: Uint8Array, salt?: Uint8Array): Promise<Uint8Array> {
  if (key4.length !== 32) {
    throw new Error('Pointer nonce derivation requires strictly a 32-byte key.');
  }
  const label = new TextEncoder().encode('FORTKNOX_POINTER_NONCE_V1');
  const saltLen = salt ? salt.length : 0;
  const combined = new Uint8Array(key4.length + label.length + saltLen);
  try {
    combined.set(key4, 0);
    combined.set(label, key4.length);
    if (salt) {
      combined.set(salt, key4.length + label.length);
    }
    return sha256(combined).subarray(0, 12);
  } finally {
    combined.fill(0);
  }
}

/**
 * Derives a 12-byte nonce from Key 4 with optional container salt for metadata masking
 */
export async function deriveMetadataNonce(key4: Uint8Array, salt?: Uint8Array): Promise<Uint8Array> {
  if (key4.length !== 32) {
    throw new Error('Metadata nonce derivation requires strictly a 32-byte key.');
  }
  const label = new TextEncoder().encode('FORTKNOX_METADATA_NONCE_V1');
  const saltLen = salt ? salt.length : 0;
  const combined = new Uint8Array(key4.length + label.length + saltLen);
  try {
    combined.set(key4, 0);
    combined.set(label, key4.length);
    if (salt) {
      combined.set(salt, key4.length + label.length);
    }
    return sha256(combined).subarray(0, 12);
  } finally {
    combined.fill(0);
  }
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
  if (meta.originalSize < 0 || !Number.isSafeInteger(meta.originalSize)) {
    throw new Error('Invalid original file size');
  }
  if (meta.chunkCount <= 0 || !Number.isSafeInteger(meta.chunkCount)) {
    throw new Error('Invalid chunk count');
  }
  if (meta.chunkSize !== 1048576) {
    throw new Error('Invalid chunk size');
  }
  if (
    meta.originalSize > meta.chunkCount * meta.chunkSize ||
    (meta.chunkCount > 1 && meta.originalSize <= (meta.chunkCount - 1) * meta.chunkSize)
  ) {
    throw new Error('Invalid chunk count or original file size relationship in metadata encoding');
  }
  if (
    meta.nonceThreefish.length !== 16 ||
    meta.nonceSerpent.length !== 16 ||
    meta.nonceChaCha20.length !== 12 ||
    meta.nonceAes256.length !== 12 ||
    meta.orderConfirm.length !== 32 ||
    (meta.hmacIntegrity && meta.hmacIntegrity.length !== 32)
  ) {
    throw new Error('Invalid cryptographic component lengths in metadata encoding');
  }
  const buf = new Uint8Array(METADATA_SIZE);
  // Fill entire buffer with cryptographic random noise first
  fillRandomBytes(buf);

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  view.setUint32(0, meta.magic ?? METADATA_MAGIC, true);
  view.setUint32(4, meta.version ?? CONTAINER_VERSION, true);
  view.setBigUint64(8, BigInt(meta.originalSize), true);
  view.setUint32(16, meta.chunkCount, true);
  view.setUint32(20, meta.chunkSize, true);

  buf.set(meta.nonceThreefish, 24);
  buf.set(meta.nonceSerpent, 40);
  buf.set(meta.nonceChaCha20, 56);
  buf.set(meta.nonceAes256, 68);
  if (meta.hmacIntegrity) {
    buf.set(meta.hmacIntegrity, 80);
  }
  buf.set(meta.orderConfirm, 112);

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

  const rawSizeBig = view.getBigUint64(8, true);
  const chunkCount = view.getUint32(16, true);
  const chunkSize = view.getUint32(20, true);

  if (
    rawSizeBig > BigInt(Number.MAX_SAFE_INTEGER) ||
    chunkCount <= 0 ||
    chunkSize !== 1048576
  ) {
    throw new Error('Decryption failed. Check all keys.');
  }

  const originalSize = Number(rawSizeBig);

  if (
    originalSize < 0 ||
    !Number.isSafeInteger(originalSize) ||
    originalSize > chunkCount * chunkSize ||
    (chunkCount > 1 && originalSize <= (chunkCount - 1) * chunkSize)
  ) {
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
  if (metaBlob.length !== METADATA_SIZE || key4.length !== 32) {
    throw new Error('Metadata masking requires strictly 512-byte metadata blob and 32-byte key.');
  }
  const metaKey = await deriveMetadataKey(key4);
  let nonce12: Uint8Array;
  let isOwnedNonce = false;
  if (explicitNonceOrSalt && explicitNonceOrSalt.length === 12) {
    nonce12 = explicitNonceOrSalt;
  } else if (explicitNonceOrSalt) {
    nonce12 = await deriveMetadataNonce(key4, explicitNonceOrSalt);
    isOwnedNonce = true;
  } else {
    nonce12 = await deriveMetadataNonce(key4);
    isOwnedNonce = true;
  }
  try {
    return chacha20(metaKey, nonce12, metaBlob, undefined, 1);
  } finally {
    metaKey.fill(0);
    if (isOwnedNonce) {
      nonce12.fill(0);
    }
  }
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
  if (offset < 0 || !Number.isSafeInteger(offset) || length !== METADATA_SIZE || key4.length !== 32) {
    throw new Error('Invalid tail pointer parameters.');
  }
  const pointerData = new Uint8Array(16);
  const view = new DataView(pointerData.buffer, pointerData.byteOffset, pointerData.byteLength);
  view.setBigUint64(0, BigInt(offset), true);
  view.setUint32(8, length, true);
  // Padding with random bytes
  fillRandomBytes(pointerData.subarray(12, 16));

  const pointerNonce = await derivePointerNonce(key4, salt);

  try {
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
  } finally {
    pointerNonce.fill(0);
    pointerData.fill(0);
  }
}

/**
 * Decrypts the 32-byte tail pointer with constant-time error masking
 */
export async function decryptTailPointer(
  tail32: Uint8Array,
  key4: Uint8Array,
  salt: Uint8Array
): Promise<{ offset: number; length: number }> {
  if (key4.length !== 32 || tail32.length !== 32 || !salt || salt.length !== 16) {
    throw new Error('Decryption failed. Check all keys.');
  }

  const pointerNonce = await derivePointerNonce(key4, salt);

  try {
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
        const offsetBig = view.getBigUint64(0, true);
        const length = view.getUint32(8, true);
        new Uint8Array(decrypted).fill(0);

        if (length === METADATA_SIZE && offsetBig <= BigInt(Number.MAX_SAFE_INTEGER)) {
          const offset = Number(offsetBig);
          if (offset >= 0) {
            return { offset, length };
          }
        }
        throw new Error('Decryption failed. Check all keys.');
      } catch (e: unknown) {
        if (e instanceof Error && e.message === 'Decryption failed. Check all keys.') {
          throw e;
        }
        // Fall through to Noble Ciphers fallback
      }
    }

    // Pure software AES-GCM fallback (Noble Ciphers)
    try {
      const cipher = gcm(key4, pointerNonce);
      const decrypted = cipher.decrypt(tail32);
      const view = new DataView(decrypted.buffer, decrypted.byteOffset, decrypted.byteLength);
      const offsetBig = view.getBigUint64(0, true);
      const length = view.getUint32(8, true);
      decrypted.fill(0);

      if (length === METADATA_SIZE && offsetBig <= BigInt(Number.MAX_SAFE_INTEGER)) {
        const offset = Number(offsetBig);
        if (offset >= 0) {
          return { offset, length };
        }
      }
    } catch {
      // Constant-time generic error
    }

    throw new Error('Decryption failed. Check all keys.');
  } finally {
    pointerNonce.fill(0);
  }
}

export const BLIND_MAX_DELTA = 16384; // 16 KB maximum blind pointer offset window

/**
 * Derives a blind pointer offset delta from Key 4 using HMAC-SHA256.
 * The pointer is placed at `containerEnd - 32 - delta`, surrounded by CSPRNG jitter noise,
 * completely eliminating any fixed pointer location at EOF - 32.
 */
export function deriveBlindPointerDelta(key4: Uint8Array, maxDelta: number = BLIND_MAX_DELTA): number {
  if (key4.length !== 32) {
    throw new Error('Blind pointer derivation requires strictly a 32-byte Key 4.');
  }
  if (maxDelta <= 0) return 0;
  const label = new TextEncoder().encode('FORTKNOX_BLIND_POINTER_DELTA_V2');
  const h = hmac(sha256, key4, label);
  const view = new DataView(h.buffer, h.byteOffset, h.byteLength);
  const rawNum = view.getUint32(0, true);
  return rawNum % (maxDelta + 1);
}

/**
 * Generates a valid RIFF WAVE (.wav) carrier header containing 1 second of silent PCM audio (44.1 kHz, 16-bit mono)
 * followed by a standard RIFF "JUNK" chunk header to encapsulate the encrypted container payload.
 * When opened in VLC, Windows Media Player, QuickTime, or Audacity, it plays valid audio.
 * Forensic tools (file, mediainfo, exiftool) identify it as compliant WAVE audio.
 */
export function createWavCarrierHeader(payloadLength: number): Uint8Array {
  const pcmAudioBytes = 44100 * 2; // 1 second of 16-bit mono silence (88,200 bytes)
  const junkChunkHeaderBytes = 8; // "JUNK" (4B) + uint32 length (4B)
  const totalRiffSize = 4 + (8 + 16) + (8 + pcmAudioBytes) + (junkChunkHeaderBytes + payloadLength);

  const header = new Uint8Array(44 + pcmAudioBytes + junkChunkHeaderBytes);
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);

  // 1. "RIFF" chunk descriptor
  header.set([0x52, 0x49, 0x46, 0x46], 0); // "RIFF"
  view.setUint32(4, totalRiffSize, true);
  header.set([0x57, 0x41, 0x56, 0x45], 8); // "WAVE"

  // 2. "fmt " sub-chunk
  header.set([0x66, 0x6d, 0x74, 0x20], 12); // "fmt "
  view.setUint32(16, 16, true); // Subchunk1Size (16 for PCM)
  view.setUint16(20, 1, true);  // AudioFormat (1 = PCM)
  view.setUint16(22, 1, true);  // NumChannels (1 = Mono)
  view.setUint32(24, 44100, true); // SampleRate (44.1 kHz)
  view.setUint32(28, 88200, true); // ByteRate (44100 * 1 * 2)
  view.setUint16(32, 2, true);  // BlockAlign (1 * 16/8)
  view.setUint16(34, 16, true); // BitsPerSample (16 bits)

  // 3. "data" sub-chunk (88,200 bytes of silence)
  header.set([0x64, 0x61, 0x74, 0x61], 36); // "data"
  view.setUint32(40, pcmAudioBytes, true);

  // 4. "JUNK" sub-chunk header wrapping the cascade container
  const junkOffset = 44 + pcmAudioBytes;
  header.set([0x4a, 0x55, 0x4e, 0x4b], junkOffset); // "JUNK"
  view.setUint32(junkOffset + 4, payloadLength, true);

  return header;
}

/**
 * Detects whether an input file is a RIFF WAVE polyglot carrier,
 * and if so, returns the exact byte offset where the encrypted container payload begins.
 */
export function detectCarrierPayloadOffset(fileStartBytes: Uint8Array): { isCarrier: boolean; payloadOffset: number } {
  if (fileStartBytes.length < 44) return { isCarrier: false, payloadOffset: 0 };

  const isRiff = fileStartBytes[0] === 0x52 && fileStartBytes[1] === 0x49 && fileStartBytes[2] === 0x46 && fileStartBytes[3] === 0x46;
  const isWave = fileStartBytes[8] === 0x57 && fileStartBytes[9] === 0x41 && fileStartBytes[10] === 0x56 && fileStartBytes[11] === 0x45;
  if (!isRiff || !isWave) return { isCarrier: false, payloadOffset: 0 };

  // Parse RIFF chunks sequentially from header DataView
  let pos = 12;
  const view = new DataView(fileStartBytes.buffer, fileStartBytes.byteOffset, fileStartBytes.byteLength);
  while (pos + 8 <= fileStartBytes.length) {
    const chunkId = String.fromCharCode(fileStartBytes[pos], fileStartBytes[pos+1], fileStartBytes[pos+2], fileStartBytes[pos+3]);
    const chunkSize = view.getUint32(pos + 4, true);
    if (chunkId === 'JUNK' || chunkId === 'PAD ') {
      return { isCarrier: true, payloadOffset: pos + 8 };
    }
    if (chunkId === 'data') {
      // JUNK chunk encapsulates cascade container immediately succeeding the PCM audio stream
      const junkPos = pos + 8 + chunkSize;
      return { isCarrier: true, payloadOffset: junkPos + 8 };
    }
    pos += 8 + chunkSize;
  }
  return { isCarrier: false, payloadOffset: 0 };
}
