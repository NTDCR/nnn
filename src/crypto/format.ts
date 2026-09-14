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

export const BLIND_MAX_DELTA = 65536; // 64 KB maximum blind pointer offset window

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
 * Generates a valid RIFF WAVE (.wav) carrier header containing 1 second of acoustic dithered PCM audio (44.1 kHz, 16-bit mono)
 * followed by a standard RIFF "JUNK" chunk header to encapsulate the encrypted container payload.
 * When opened in VLC, Windows Media Player, QuickTime, or Audacity, it plays valid audio without clipping.
 * Synthetic low-level acoustic dithering eliminates the 0.0 entropy step-function in binwalk/cutter visualizers.
 */
export function createWavCarrierHeader(payloadLength: number): Uint8Array {
  const pcmAudioBytes = 44100 * 2; // 1 second of 16-bit mono audio (88,200 bytes)
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

  // 3. "data" sub-chunk (88,200 bytes of authentic low-level TPDF acoustic dithering)
  header.set([0x64, 0x61, 0x74, 0x61], 36); // "data"
  view.setUint32(40, pcmAudioBytes, true);

  // Fill PCM data with professional acoustic TPDF dither (+-1 to +-8 LSB at -72 dBFS)
  // Completely inaudible studio room air when played, but exhibits realistic ~3.5-4.8 bits/byte entropy
  // Eliminates the sharp 0.0 -> 8.0 entropy step-function alert in binwalk / cutter visualizers
  const ditherRand = new Uint8Array(44100);
  fillRandomBytes(ditherRand);
  const pcmOffset = 44;
  let walk = 0;
  for (let i = 0; i < 44100; i++) {
    const step = (ditherRand[i] & 0x07) - 3;
    walk = Math.max(-12, Math.min(12, walk + step));
    view.setInt16(pcmOffset + i * 2, walk, true);
  }
  ditherRand.fill(0);

  // 4. "JUNK" sub-chunk header wrapping the cascade container
  const junkOffset = 44 + pcmAudioBytes;
  header.set([0x4a, 0x55, 0x4e, 0x4b], junkOffset); // "JUNK"
  view.setUint32(junkOffset + 4, payloadLength, true);

  return header;
}

// --- PNG / JPEG Polyglot Carrier Engine ---

const CRC_TABLE = new Uint32Array(256);
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
  CRC_TABLE[n] = c >>> 0;
}

export function calculateCrc32(buf: Uint8Array): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

export function calculateAdler32(buf: Uint8Array): number {
  let a = 1, b = 0;
  for (let i = 0; i < buf.length; i++) {
    a = (a + buf[i]) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

/**
 * Generates a valid PNG carrier header (264 bytes)
 * Contains authentic IHDR, IDAT (8x8 RGB pixel gradient), and starts an ancillary private 'foRt' chunk.
 * Displays as an authentic PNG image in Chrome, Safari, Photos, and Preview.
 */
export function createPngCarrierHeader(payloadLength: number): Uint8Array {
  const width = 8, height = 8;
  const rawScanlines = new Uint8Array(height * (1 + width * 3));
  for (let y = 0; y < height; y++) {
    const rowStart = y * (1 + width * 3);
    rawScanlines[rowStart] = 0;
    for (let x = 0; x < width; x++) {
      const px = rowStart + 1 + x * 3;
      rawScanlines[px] = 0x1E;     // R
      rawScanlines[px + 1] = 0x1E; // G
      rawScanlines[px + 2] = 0x2E; // B
    }
  }
  const adler = calculateAdler32(rawScanlines);
  const rawLen = rawScanlines.length;
  const zlibStream = new Uint8Array(2 + 5 + rawLen + 4);
  zlibStream[0] = 0x78; zlibStream[1] = 0x01;
  zlibStream[2] = 0x01;
  zlibStream[3] = rawLen & 0xff; zlibStream[4] = (rawLen >> 8) & 0xff;
  const nlen = (~rawLen) & 0xffff;
  zlibStream[5] = nlen & 0xff; zlibStream[6] = (nlen >> 8) & 0xff;
  zlibStream.set(rawScanlines, 7);
  const adlerOffset = 7 + rawLen;
  zlibStream[adlerOffset] = (adler >> 24) & 0xff;
  zlibStream[adlerOffset + 1] = (adler >> 16) & 0xff;
  zlibStream[adlerOffset + 2] = (adler >> 8) & 0xff;
  zlibStream[adlerOffset + 3] = adler & 0xff;

  const header = new Uint8Array(8 + 25 + (12 + zlibStream.length) + 8);
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);

  // 1. Signature
  header.set([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], 0);

  // 2. IHDR
  view.setUint32(8, 13, false);
  header.set([0x49, 0x48, 0x44, 0x52], 12); // IHDR
  view.setUint32(16, width, false);
  view.setUint32(20, height, false);
  header[24] = 8; // 8-bit
  header[25] = 2; // RGB
  header[26] = 0; header[27] = 0; header[28] = 0;
  const ihdrCrc = calculateCrc32(header.subarray(12, 29));
  view.setUint32(29, ihdrCrc, false);

  // 3. IDAT
  const idatOffset = 33;
  view.setUint32(idatOffset, zlibStream.length, false);
  header.set([0x49, 0x44, 0x41, 0x54], idatOffset + 4); // IDAT
  header.set(zlibStream, idatOffset + 8);
  const idatCrc = calculateCrc32(header.subarray(idatOffset + 4, idatOffset + 8 + zlibStream.length));
  view.setUint32(idatOffset + 8 + zlibStream.length, idatCrc, false);

  // 4. foRt ancillary private chunk header (length = payloadLength)
  const fortOffset = idatOffset + 12 + zlibStream.length;
  view.setUint32(fortOffset, payloadLength, false);
  header.set([0x66, 0x6F, 0x52, 0x74], fortOffset + 4); // "foRt"

  return header;
}

/**
 * Generates a valid minimal JFIF JPEG image carrier header (332 bytes)
 * Ends with 0xFF 0xD9 (EOI). The cascade container is stored in trailing slack space.
 * Displays as an authentic image in photo viewers; forensic tools classify it as valid JPEG.
 */
export function createJpgCarrierHeader(): Uint8Array {
  return new Uint8Array([
    0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x48,
    0x00, 0x48, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43, 0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08,
    0x07, 0x07, 0x07, 0x09, 0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
    0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20, 0x24, 0x2E, 0x27, 0x20,
    0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29, 0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27,
    0x39, 0x3D, 0x38, 0x32, 0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x08,
    0x00, 0x08, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x05, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0xFF, 0xC4, 0x00, 0xB5, 0x10, 0x00, 0x02, 0x01, 0x03,
    0x03, 0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04, 0x00, 0x00, 0x01, 0x7D, 0x01, 0x02, 0x03, 0x00,
    0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32,
    0x81, 0x91, 0xA1, 0x08, 0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0, 0x24, 0x33, 0x62, 0x72,
    0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x34, 0x35,
    0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55,
    0x56, 0x57, 0x58, 0x59, 0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x73, 0x74, 0x75,
    0x76, 0x77, 0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x92, 0x93, 0x94,
    0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2,
    0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9,
    0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6,
    0xE7, 0xE8, 0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFF, 0xDA,
    0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0x7F, 0x00, 0xFF, 0xD9
  ]);
}

/**
 * Detects whether an input file is a polyglot carrier (WAVE, PNG, or JPEG),
 * and if so, returns the exact byte offset where the encrypted container payload begins.
 */
export function detectCarrierPayloadOffset(fileStartBytes: Uint8Array): {
  isCarrier: boolean;
  payloadOffset: number;
  carrierType?: 'wav' | 'png' | 'jpg';
} {
  if (fileStartBytes.length < 16) return { isCarrier: false, payloadOffset: 0 };

  // 1. RIFF WAVE Carrier
  if (
    fileStartBytes[0] === 0x52 && fileStartBytes[1] === 0x49 && fileStartBytes[2] === 0x46 && fileStartBytes[3] === 0x46 &&
    fileStartBytes[8] === 0x57 && fileStartBytes[9] === 0x41 && fileStartBytes[10] === 0x56 && fileStartBytes[11] === 0x45
  ) {
    let pos = 12;
    const view = new DataView(fileStartBytes.buffer, fileStartBytes.byteOffset, fileStartBytes.byteLength);
    while (pos + 8 <= fileStartBytes.length) {
      const chunkId = String.fromCharCode(fileStartBytes[pos], fileStartBytes[pos+1], fileStartBytes[pos+2], fileStartBytes[pos+3]);
      const chunkSize = view.getUint32(pos + 4, true);
      if (chunkId === 'JUNK' || chunkId === 'PAD ') {
        return { isCarrier: true, payloadOffset: pos + 8, carrierType: 'wav' };
      }
      if (chunkId === 'data') {
        const junkPos = pos + 8 + chunkSize;
        return { isCarrier: true, payloadOffset: junkPos + 8, carrierType: 'wav' };
      }
      pos += 8 + chunkSize;
    }
    return { isCarrier: false, payloadOffset: 0 };
  }

  // 2. PNG Carrier
  if (
    fileStartBytes[0] === 0x89 && fileStartBytes[1] === 0x50 && fileStartBytes[2] === 0x4E && fileStartBytes[3] === 0x47 &&
    fileStartBytes[4] === 0x0D && fileStartBytes[5] === 0x0A && fileStartBytes[6] === 0x1A && fileStartBytes[7] === 0x0A
  ) {
    let pos = 8;
    const view = new DataView(fileStartBytes.buffer, fileStartBytes.byteOffset, fileStartBytes.byteLength);
    while (pos + 8 <= fileStartBytes.length) {
      const chunkLen = view.getUint32(pos, false);
      const chunkType = String.fromCharCode(fileStartBytes[pos+4], fileStartBytes[pos+5], fileStartBytes[pos+6], fileStartBytes[pos+7]);
      if (chunkType === 'foRt' || chunkType === 'ftKX' || chunkType === 'caSC') {
        return { isCarrier: true, payloadOffset: pos + 8, carrierType: 'png' };
      }
      pos += 8 + chunkLen + 4;
    }
    return { isCarrier: false, payloadOffset: 0 };
  }

  // 3. JPEG Carrier
  if (
    fileStartBytes[0] === 0xFF && fileStartBytes[1] === 0xD8 && fileStartBytes[2] === 0xFF
  ) {
    // Scan for FF D9 (EOI) within first 2048 bytes
    const limit = Math.min(fileStartBytes.length - 1, 2048);
    for (let i = 2; i < limit; i++) {
      if (fileStartBytes[i] === 0xFF && fileStartBytes[i+1] === 0xD9) {
        return { isCarrier: true, payloadOffset: i + 2, carrierType: 'jpg' };
      }
    }
  }

  return { isCarrier: false, payloadOffset: 0 };
}
