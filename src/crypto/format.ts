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
  lastModified?: number;
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

  if (meta.lastModified && Number.isSafeInteger(meta.lastModified) && meta.lastModified > 0) {
    view.setBigUint64(144, BigInt(meta.lastModified), true);
  }

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

  const rawLastModifiedBig = view.getBigUint64(144, true);
  let lastModified: number | undefined;
  // If timestamp falls in valid realistic Unix timestamp range (year 1990 to 2100 in ms)
  if (rawLastModifiedBig > 631152000000n && rawLastModifiedBig < 4102444800000n) {
    lastModified = Number(rawLastModifiedBig);
  }

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
    lastModified,
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
export interface WavCarrierOptions {
  audibleTone?: boolean;
  legacyFixed?: boolean;
}

export function createWavCarrierHeader(payloadLength: number, options?: WavCarrierOptions): Uint8Array {
  const pcmAudioBytes = 44100 * 2; // 1 second of 16-bit mono audio (88,200 bytes)
  const junkChunkHeaderBytes = 8; // "JUNK" (4B) + uint32 length (4B)
  const totalRiffSize = 4 + (8 + 16) + (8 + pcmAudioBytes) + (junkChunkHeaderBytes + payloadLength);

  const header = new Uint8Array(44 + pcmAudioBytes + junkChunkHeaderBytes);
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);

  // 1. "RIFF" chunk descriptor (clamped to 0xFFFFFFFF - 8 to prevent 32-bit overflow on > 4 GB files)
  header.set([0x52, 0x49, 0x46, 0x46], 0); // "RIFF"
  view.setUint32(4, Math.min(0xFFFFFFFF - 8, totalRiffSize), true);
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

  // 3. "data" sub-chunk (dynamic proportional duration matching file size)
  header.set([0x64, 0x61, 0x74, 0x61], 36); // "data"
  const totalDataBytes = options?.legacyFixed
    ? pcmAudioBytes
    : Math.min(0xFFFFFFFF - 44, pcmAudioBytes + junkChunkHeaderBytes + payloadLength);
  view.setUint32(40, totalDataBytes, true);

  const ditherRand = new Uint8Array(44100);
  fillRandomBytes(ditherRand);
  const pcmOffset = 44;

  if (options?.audibleTone) {
    const TWO_PI = 2 * Math.PI;
    for (let i = 0; i < 44100; i++) {
      const t = i / 44100;
      const env = Math.sin(Math.PI * t);
      const tone = 0.7 * Math.sin(TWO_PI * 440 * t) + 0.3 * Math.sin(TWO_PI * 880 * t);
      const signal = Math.round(env * env * 2200 * tone);
      const dither = (ditherRand[i] & 0x07) - 3;
      view.setInt16(pcmOffset + i * 2, Math.max(-32767, Math.min(32767, signal + dither)), true);
    }
  } else {
    // Fill PCM data with professional acoustic TPDF dither (+-1 to +-8 LSB at -72 dBFS)
    // Inaudible studio room air when played, but exhibits realistic ~3.5-4.8 bits/byte entropy
    let walk = 0;
    for (let i = 0; i < 44100; i++) {
      const step = (ditherRand[i] & 0x07) - 3;
      walk = Math.max(-12, Math.min(12, walk + step));
      view.setInt16(pcmOffset + i * 2, walk, true);
    }
  }
  ditherRand.fill(0);

  // 4. "JUNK" sub-chunk header wrapping the cascade container
  const junkOffset = 44 + pcmAudioBytes;
  header.set([0x4a, 0x55, 0x4e, 0x4b], junkOffset); // "JUNK"
  view.setUint32(junkOffset + 4, Math.min(0xFFFFFFFF, payloadLength), true);

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

export interface PngCarrierOptions {
  width?: number;
  height?: number;
  includeAncillaryMetadata?: boolean;
}

export interface JpgCarrierOptions {
  includeExif?: boolean;
}

/**
 * Generates a valid PNG carrier header
 * When includeAncillaryMetadata is enabled, synthesizes standard W3C ancillary chunks (sRGB, pHYs, tEXt)
 * and an adaptive gradient canvas. Default mode produces the verified 264-byte baseline header.
 */
export function createPngCarrierHeader(payloadLength: number, options?: PngCarrierOptions): Uint8Array {
  const includeMeta = options?.includeAncillaryMetadata ?? false;
  const width = options?.width ?? 8;
  const height = options?.height ?? 8;

  const rawScanlines = new Uint8Array(height * (1 + width * 3));
  for (let y = 0; y < height; y++) {
    const rowStart = y * (1 + width * 3);
    rawScanlines[rowStart] = 0;
    for (let x = 0; x < width; x++) {
      const px = rowStart + 1 + x * 3;
      if (includeMeta) {
        rawScanlines[px] = Math.min(255, 30 + Math.floor((x / width) * 40));
        rawScanlines[px + 1] = Math.min(255, 30 + Math.floor((y / height) * 40));
        rawScanlines[px + 2] = Math.min(255, 60 + Math.floor(((x + y) / (width + height)) * 80));
      } else {
        rawScanlines[px] = 0x1E;     // R
        rawScanlines[px + 1] = 0x1E; // G
        rawScanlines[px + 2] = 0x2E; // B
      }
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

  if (!includeMeta) {
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

  // Enhanced PNG header with sRGB, pHYs, and tEXt chunks
  const srgbData = new Uint8Array([0x73, 0x52, 0x47, 0x42, 0x00]); // sRGB\0
  const srgbCrc = calculateCrc32(srgbData);

  const physData = new Uint8Array([
    0x70, 0x48, 0x59, 0x73,
    0x00, 0x00, 0x0E, 0xC4, // 3780 dpm X (96 DPI)
    0x00, 0x00, 0x0E, 0xC4, // 3780 dpm Y
    0x01                    // unit: meter
  ]);
  const physCrc = calculateCrc32(physData);

  const textKeyword = new TextEncoder().encode('Software\0FortKnox Photo Engine');
  const textData = new Uint8Array(4 + textKeyword.length);
  textData.set([0x74, 0x45, 0x58, 0x74], 0); // "tEXt"
  textData.set(textKeyword, 4);
  const textCrc = calculateCrc32(textData);

  const totalLen = 8 + 25 + 13 + 21 + (12 + textKeyword.length) + (12 + zlibStream.length) + 8;
  const header = new Uint8Array(totalLen);
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);

  let p = 0;
  // 1. Signature
  header.set([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], p); p += 8;

  // 2. IHDR
  view.setUint32(p, 13, false); p += 4;
  header.set([0x49, 0x48, 0x44, 0x52], p);
  view.setUint32(p + 4, width, false);
  view.setUint32(p + 8, height, false);
  header[p + 12] = 8;
  header[p + 13] = 2;
  header[p + 14] = 0; header[p + 15] = 0; header[p + 16] = 0;
  const ihdrCrc = calculateCrc32(header.subarray(p, p + 17));
  p += 17;
  view.setUint32(p, ihdrCrc, false); p += 4;

  // 3. sRGB
  view.setUint32(p, 1, false); p += 4;
  header.set(srgbData, p); p += srgbData.length;
  view.setUint32(p, srgbCrc, false); p += 4;

  // 4. pHYs
  view.setUint32(p, 9, false); p += 4;
  header.set(physData, p); p += physData.length;
  view.setUint32(p, physCrc, false); p += 4;

  // 5. tEXt
  view.setUint32(p, textKeyword.length, false); p += 4;
  header.set(textData, p); p += textData.length;
  view.setUint32(p, textCrc, false); p += 4;

  // 6. IDAT
  view.setUint32(p, zlibStream.length, false); p += 4;
  header.set([0x49, 0x44, 0x41, 0x54], p);
  header.set(zlibStream, p + 4);
  const idatCrc = calculateCrc32(header.subarray(p, p + 4 + zlibStream.length));
  p += 4 + zlibStream.length;
  view.setUint32(p, idatCrc, false); p += 4;

  // 7. foRt ancillary private chunk header (length = payloadLength)
  view.setUint32(p, payloadLength, false); p += 4;
  header.set([0x66, 0x6F, 0x52, 0x74], p); p += 4;

  return header;
}

/**
 * Generates a valid minimal JFIF JPEG image carrier header
 * When options.includeExif is true, inserts an authentic standard APP1 EXIF metadata block.
 * Ends with 0xFF 0xD9 (EOI). The cascade container is stored in trailing slack space.
 */
export function createJpgCarrierHeader(options?: JpgCarrierOptions): Uint8Array {
  const baseJpg = [
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
  ];

  if (!options?.includeExif) {
    return new Uint8Array(baseJpg);
  }

  // Insert standard APP1 EXIF segment immediately after APP0 (at index 20)
  const exifSegment = [
    0xFF, 0xE1, // APP1 marker
    0x00, 0x41, // length = 65 bytes
    0x45, 0x78, 0x69, 0x66, 0x00, 0x00, // "Exif\0\0"
    0x49, 0x49, 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00, // TIFF header (little endian "II", 42, IFD0 offset 8)
    0x02, 0x00, // 2 directory entries
    0x31, 0x01, 0x02, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x26, 0x00, 0x00, 0x00, // Tag 0x0131 (Software)
    0x0F, 0x01, 0x02, 0x00, 0x07, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00, // Tag 0x010F (Make)
    0x00, 0x00, 0x00, 0x00, // Next IFD offset
    0x46, 0x6F, 0x72, 0x74, 0x4B, 0x6E, 0x6F, 0x78, 0x20, 0x32, 0x00, 0x00, // "FortKnox 2\0\0" (12 bytes)
    0x43, 0x61, 0x6D, 0x65, 0x72, 0x61, 0x00 // "Camera\0" (7 bytes)
  ];

  const fullJpg = new Uint8Array(baseJpg.length + exifSegment.length);
  fullJpg.set(baseJpg.slice(0, 20), 0); // SOI + APP0
  fullJpg.set(exifSegment, 20);         // APP1 EXIF
  fullJpg.set(baseJpg.slice(20), 20 + exifSegment.length); // Remainder through FF D9
  return fullJpg;
}

function writeBothEndianU32(view: DataView, offset: number, val: number): void {
  view.setUint32(offset, val, true);
  view.setUint32(offset + 4, val, false);
}

function writeBothEndianU16(view: DataView, offset: number, val: number): void {
  view.setUint16(offset, val, true);
  view.setUint16(offset + 2, val, false);
}

/**
 * Generates an authentic ISO-9660 (.iso) optical disc image carrier header (43,008 bytes = 21 sectors of 2048B).
 * - Sectors 0..15: System area (zeroed)
 * - Sector 16: Primary Volume Descriptor (PVD) with 'CD001' signature, volume label 'SECURE_ARCHIVE'
 * - Sector 17: Volume Descriptor Set Terminator ('CD001')
 * - Sector 18: Type L Path Table
 * - Sector 19: Type M Path Table
 * - Sector 20: Root Directory record pointing to DATA.BIN;1 (Sector 21)
 * - Sector 21 (offset 43,008): The encrypted cascade container begins.
 * Natively mounts in Windows Explorer, macOS, Linux, and 7-Zip as a virtual disc containing DATA.BIN.
 * Provides authentic masquerade for multi-gigabyte (1 GB - 50 GB) archives.
 */
export function createIsoCarrierHeader(payloadLength: number): Uint8Array {
  const SECTOR_SIZE = 2048;
  const HEADER_SECTORS = 21;
  const payloadSectors = Math.ceil(payloadLength / SECTOR_SIZE);
  const totalSectors = HEADER_SECTORS + payloadSectors;

  const header = new Uint8Array(HEADER_SECTORS * SECTOR_SIZE);
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);

  // Sector 16: Primary Volume Descriptor (PVD)
  const pvdOffset = 16 * SECTOR_SIZE;
  header[pvdOffset] = 1; // Primary Volume Descriptor
  header.set([0x43, 0x44, 0x30, 0x30, 0x31], pvdOffset + 1); // "CD001"
  header[pvdOffset + 6] = 1; // Version 1

  // System Identifier (8..39) & Volume Identifier (40..71)
  const sysIdent = new TextEncoder().encode('FORTKNOX_OS'.padEnd(32, ' '));
  const volIdent = new TextEncoder().encode('SECURE_ARCHIVE'.padEnd(32, ' '));
  header.set(sysIdent, pvdOffset + 8);
  header.set(volIdent, pvdOffset + 40);

  // Volume Space Size (80..87)
  writeBothEndianU32(view, pvdOffset + 80, totalSectors);

  // Volume Set Size & Sequence Number (120..127)
  writeBothEndianU16(view, pvdOffset + 120, 1);
  writeBothEndianU16(view, pvdOffset + 124, 1);
  writeBothEndianU16(view, pvdOffset + 128, SECTOR_SIZE);

  // Path Table Size (132..139) = 10 bytes
  writeBothEndianU32(view, pvdOffset + 132, 10);
  view.setUint32(pvdOffset + 140, 18, true);  // Type L at Sector 18
  view.setUint32(pvdOffset + 148, 19, false); // Type M at Sector 19

  // Root Directory Record in PVD (156..189, 34 bytes)
  view.setUint8(pvdOffset + 156, 34);
  writeBothEndianU32(view, pvdOffset + 158, 20); // Sector 20
  writeBothEndianU32(view, pvdOffset + 166, SECTOR_SIZE);
  header.set([124, 9, 14, 12, 0, 0, 0], pvdOffset + 174); // 2024-09-14
  header[pvdOffset + 181] = 0x02; // Directory flag
  writeBothEndianU16(view, pvdOffset + 184, 1);
  header[pvdOffset + 188] = 1;
  header[pvdOffset + 189] = 0; // root \0

  // Padding & Date fields (190..812)
  header.fill(0x20, pvdOffset + 190, pvdOffset + 813);
  const nowAscii = new TextEncoder().encode('2026091412000000\0');
  const zeroAscii = new TextEncoder().encode('0000000000000000\0');
  header.set(nowAscii, pvdOffset + 813);
  header.set(nowAscii, pvdOffset + 830);
  header.set(zeroAscii, pvdOffset + 847);
  header.set(nowAscii, pvdOffset + 864);
  header[pvdOffset + 881] = 1; // File structure version 1

  // Sector 17: Volume Descriptor Set Terminator
  const termOffset = 17 * SECTOR_SIZE;
  header[termOffset] = 255;
  header.set([0x43, 0x44, 0x30, 0x30, 0x31], termOffset + 1);
  header[termOffset + 6] = 1;

  // Sector 18: Type L Path Table (little-endian)
  const pathLOffset = 18 * SECTOR_SIZE;
  header[pathLOffset] = 1;
  view.setUint32(pathLOffset + 2, 20, true);
  view.setUint16(pathLOffset + 6, 1, true);
  header[pathLOffset + 8] = 0;

  // Sector 19: Type M Path Table (big-endian)
  const pathMOffset = 19 * SECTOR_SIZE;
  header[pathMOffset] = 1;
  view.setUint32(pathMOffset + 2, 20, false);
  view.setUint16(pathMOffset + 6, 1, false);
  header[pathMOffset + 8] = 0;

  // Sector 20: Root Directory Sector
  const rootOffset = 20 * SECTOR_SIZE;
  // '.' Entry
  view.setUint8(rootOffset, 34);
  writeBothEndianU32(view, rootOffset + 2, 20);
  writeBothEndianU32(view, rootOffset + 10, SECTOR_SIZE);
  header[rootOffset + 25] = 0x02;
  writeBothEndianU16(view, rootOffset + 28, 1);
  header[rootOffset + 32] = 1;
  header[rootOffset + 33] = 0;

  // '..' Entry
  view.setUint8(rootOffset + 34, 34);
  writeBothEndianU32(view, rootOffset + 36, 20);
  writeBothEndianU32(view, rootOffset + 44, SECTOR_SIZE);
  header[rootOffset + 59] = 0x02;
  writeBothEndianU16(view, rootOffset + 62, 1);
  header[rootOffset + 66] = 1;
  header[rootOffset + 67] = 1;

  // 'DATA.BIN;1' File Entry (Sector 21, offset 43008)
  const fileEntryOffset = rootOffset + 68;
  const nameBytes = new TextEncoder().encode('DATA.BIN;1');
  const recLen = 33 + nameBytes.length + 1; // 44 bytes
  view.setUint8(fileEntryOffset, recLen);
  writeBothEndianU32(view, fileEntryOffset + 2, 21); // Sector 21
  writeBothEndianU32(view, fileEntryOffset + 10, payloadLength);
  header[fileEntryOffset + 25] = 0; // File flag
  writeBothEndianU16(view, fileEntryOffset + 28, 1);
  header[fileEntryOffset + 32] = nameBytes.length;
  header.set(nameBytes, fileEntryOffset + 33);

  return header;
}

const MP4_PREVIEW_BASE_B64 =
  'AAAAHGZ0eXBpc29tAAACAGlzb21pc28ybXA0MQAAAAhmcmVlAAAC721kYXQhEAUgpBv/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA3pwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcCEQBSCkG//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADengAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcAAAAsJtb292AAAAbG12aGQAAAAAAAAAAAAAAAAAAAPoAAAALwABAAABAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAAB7HRyYWsAAABcdGtoZAAAAAMAAAAAAAAAAAAAAAIAAAAAAAAALwAAAAAAAAAAAAAAAQEAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAACRlZHRzAAAAHGVsc3QAAAAAAAAAAQAAAC8AAAAAAAEAAAAAAWRtZGlhAAAAIG1kaGQAAAAAAAAAAAAAAAAAAKxEAAAIAFXEAAAAAAAtaGRscgAAAAAAAAAAc291bgAAAAAAAAAAAAAAAFNvdW5kSGFuZGxlcgAAAAEPbWluZgAAABBzbWhkAAAAAAAAAAAAAAAkZGluZgAAABxkcmVmAAAAAAAAAAEAAAAMdXJsIAAAAAEAAADTc3RibAAAAGdzdHNkAAAAAAAAAAEAAABXbXA0YQAAAAAAAAABAAAAAAAAAAAAAgAQAAAAAKxEAAAAAAAzZXNkcwAAAAADgICAIgACAASAgIAUQBUAAAAAAfQAAAHz+QWAgIACEhAGgICAAQIAAAAYc3R0cwAAAAAAAAABAAAAAgAABAAAAAAcc3RzYwAAAAAAAAABAAAAAQAAAAIAAAABAAAAHHN0c3oAAAAAAAAAAAAAAAIAAAFzAAABdAAAABRzdGNvAAAAAAAAAAEAAAAsAAAAYnVkdGEAAABabWV0YQAAAAAAAAAhaGRscgAAAAAAAAAAbWRpcmFwcGwAAAAAAAAAAAAAAAAtaWxzdAAAACWpdG9vAAAAHWRhdGEAAAABAAAAAExhdmY1Ni40MC4xMDE=';

function decodeBase64(b64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    return Uint8Array.from(Buffer.from(b64, 'base64'));
  }
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const MP4_PREVIEW_BASE: Uint8Array = decodeBase64(MP4_PREVIEW_BASE_B64);

export interface Mp4CarrierOptions {
  legacySynthetic?: boolean;
  fixedDuration?: boolean;
}

/**
 * Generates an authentic ISO Base Media File Format (ISO/IEC 14496-12 / MP4) video carrier header.
 * - Playable Polyglot mode (Default): Embeds an authentic 1,493-byte ISO-BMFF media clip containing
 *   real media frames and track metadata in mdat #1 indexed by moov, followed by mdat #2 box header
 *   wrapping the cascade container. Duration in mvhd, tkhd, elst, and mdhd dynamically scales
 *   with payloadLength at nominal 2 Mbps, mathematically matching the physical file size and seek bar.
 *   Plays natively in VLC, Windows Media Player, Movies & TV, Chrome, QuickTime.
 * - Legacy Synthetic mode (legacySynthetic: true): Generates the 579-byte synthetic ISO-BMFF header for backward compatibility.
 */
export function createMp4CarrierHeader(payloadLength: number, options?: Mp4CarrierOptions): Uint8Array {
  if (options?.legacySynthetic) {
    function makeBox(type: string, payload: Uint8Array): Uint8Array {
      const box = new Uint8Array(8 + payload.length);
      const view = new DataView(box.buffer);
      view.setUint32(0, box.length, false);
      box[4] = type.charCodeAt(0);
      box[5] = type.charCodeAt(1);
      box[6] = type.charCodeAt(2);
      box[7] = type.charCodeAt(3);
      box.set(payload, 8);
      return box;
    }

    function concat(...arrays: Uint8Array[]): Uint8Array {
      const total = arrays.reduce((acc, a) => acc + a.length, 0);
      const res = new Uint8Array(total);
      let off = 0;
      for (const a of arrays) {
        res.set(a, off);
        off += a.length;
      }
      return res;
    }

    const ftypPayload = new Uint8Array(16);
    const ftypView = new DataView(ftypPayload.buffer);
    ftypPayload.set(new TextEncoder().encode('isom'), 0);
    ftypView.setUint32(4, 512, false);
    ftypPayload.set(new TextEncoder().encode('isomiso2'), 8);
    const ftypBox = makeBox('ftyp', ftypPayload);

    const mvhdPayload = new Uint8Array(100);
    const mvhdView = new DataView(mvhdPayload.buffer);
    mvhdView.setUint32(12, 1000, false);
    mvhdView.setUint32(16, 1000, false);
    mvhdView.setUint32(20, 0x00010000, false);
    mvhdView.setUint16(24, 0x0100, false);
    mvhdView.setUint32(36, 0x00010000, false);
    mvhdView.setUint32(52, 0x00010000, false);
    mvhdView.setUint32(80, 0x40000000, false);
    mvhdView.setUint32(96, 2, false);
    const mvhdBox = makeBox('mvhd', mvhdPayload);

    const tkhdPayload = new Uint8Array(84);
    const tkhdView = new DataView(tkhdPayload.buffer);
    tkhdView.setUint32(0, 0x00000003, false);
    tkhdView.setUint32(12, 1, false);
    tkhdView.setUint32(20, 1000, false);
    tkhdView.setUint32(36, 0x00010000, false);
    tkhdView.setUint32(52, 0x00010000, false);
    tkhdView.setUint32(80, 0x40000000, false);
    tkhdView.setUint32(76, 64 << 16, false);
    tkhdView.setUint32(80, 64 << 16, false);
    const tkhdBox = makeBox('tkhd', tkhdPayload);

    const mdhdPayload = new Uint8Array(24);
    const mdhdView = new DataView(mdhdPayload.buffer);
    mdhdView.setUint32(12, 1000, false);
    mdhdView.setUint32(16, 1000, false);
    mdhdView.setUint16(20, 0x55c4, false);
    const mdhdBox = makeBox('mdhd', mdhdPayload);

    const hdlrPayload = new Uint8Array(25);
    hdlrPayload.set(new TextEncoder().encode('vide'), 8);
    hdlrPayload.set(new TextEncoder().encode('VideoHandler\0'), 12);
    const hdlrBox = makeBox('hdlr', hdlrPayload);

    const vmhdPayload = new Uint8Array(12);
    new DataView(vmhdPayload.buffer).setUint32(0, 1, false);
    const vmhdBox = makeBox('vmhd', vmhdPayload);

    const urlBox = makeBox('url ', new Uint8Array([0, 0, 0, 1]));
    const drefPayload = new Uint8Array(8 + urlBox.length);
    new DataView(drefPayload.buffer).setUint32(4, 1, false);
    drefPayload.set(urlBox, 8);
    const drefBox = makeBox('dref', drefPayload);
    const dinfBox = makeBox('dinf', drefBox);

    const visualEntry = new Uint8Array(78);
    const vView = new DataView(visualEntry.buffer);
    visualEntry.set(new TextEncoder().encode('mp4v'), 4);
    vView.setUint16(14, 1, false);
    vView.setUint16(24, 64, false);
    vView.setUint16(26, 64, false);
    vView.setUint32(28, 0x00480000, false);
    vView.setUint32(32, 0x00480000, false);
    vView.setUint16(40, 1, false);
    visualEntry[42] = 12;
    visualEntry.set(new TextEncoder().encode('FortKnox MP4'), 43);
    vView.setUint16(74, 24, false);
    vView.setInt16(76, -1, false);
    vView.setUint32(0, visualEntry.length, false);

    const stsdPayload = new Uint8Array(8 + visualEntry.length);
    new DataView(stsdPayload.buffer).setUint32(4, 1, false);
    stsdPayload.set(visualEntry, 8);
    const stsdBox = makeBox('stsd', stsdPayload);

    const sttsPayload = new Uint8Array(16);
    const sttsView = new DataView(sttsPayload.buffer);
    sttsView.setUint32(4, 1, false);
    sttsView.setUint32(8, 1, false);
    sttsView.setUint32(12, 1000, false);
    const sttsBox = makeBox('stts', sttsPayload);

    const stscPayload = new Uint8Array(20);
    const stscView = new DataView(stscPayload.buffer);
    stscView.setUint32(4, 1, false);
    stscView.setUint32(8, 1, false);
    stscView.setUint32(12, 1, false);
    stscView.setUint32(16, 1, false);
    const stscBox = makeBox('stsc', stscPayload);

    const stszPayload = new Uint8Array(12);
    const stszBox = makeBox('stsz', stszPayload);

    const stcoPayload = new Uint8Array(12);
    const stcoBox = makeBox('stco', stcoPayload);

    const stblBox = makeBox('stbl', concat(stsdBox, sttsBox, stscBox, stszBox, stcoBox));
    const minfBox = makeBox('minf', concat(vmhdBox, dinfBox, stblBox));
    const mdiaBox = makeBox('mdia', concat(mdhdBox, hdlrBox, minfBox));
    const trakBox = makeBox('trak', concat(tkhdBox, mdiaBox));
    const moovBox = makeBox('moov', concat(mvhdBox, trakBox));

    const isLarge = payloadLength + 8 > 0xFFFFFFFF;
    let mdatHeader: Uint8Array;
    if (!isLarge) {
      mdatHeader = new Uint8Array(8);
      const mView = new DataView(mdatHeader.buffer);
      mView.setUint32(0, payloadLength + 8, false);
      mdatHeader[4] = 0x6D;
      mdatHeader[5] = 0x64;
      mdatHeader[6] = 0x61;
      mdatHeader[7] = 0x74;
    } else {
      mdatHeader = new Uint8Array(16);
      const mView = new DataView(mdatHeader.buffer);
      mView.setUint32(0, 1, false);
      mdatHeader[4] = 0x6D;
      mdatHeader[5] = 0x64;
      mdatHeader[6] = 0x61;
      mdatHeader[7] = 0x74;
      mView.setBigUint64(8, BigInt(payloadLength + 16), false);
    }

    return concat(ftypBox, moovBox, mdatHeader);
  }

  // Playable Polyglot Mode (Default): Authentic 1,493-byte base MP4 + mdat #2 box header
  const isLarge = payloadLength + 8 > 0xFFFFFFFF;
  let mdatHeader: Uint8Array;
  if (!isLarge) {
    mdatHeader = new Uint8Array(8);
    const mView = new DataView(mdatHeader.buffer);
    mView.setUint32(0, payloadLength + 8, false);
    mdatHeader[4] = 0x6d; // 'm'
    mdatHeader[5] = 0x64; // 'd'
    mdatHeader[6] = 0x61; // 'a'
    mdatHeader[7] = 0x74; // 't'
  } else {
    mdatHeader = new Uint8Array(16);
    const mView = new DataView(mdatHeader.buffer);
    mView.setUint32(0, 1, false);
    mdatHeader[4] = 0x6d;
    mdatHeader[5] = 0x64;
    mdatHeader[6] = 0x61;
    mdatHeader[7] = 0x74;
    mView.setBigUint64(8, BigInt(payloadLength + 16), false);
  }

  // Clone base template and patch duration to dynamically match payload file size
  const base = MP4_PREVIEW_BASE.slice();
  if (!options?.fixedDuration) {
    // Nominal HD video bitrate: 2,000,000 bits per sec (250 KB/sec)
    // Duration T in seconds (clamped to range 3s .. 86,400s [24 hours])
    const T = Math.max(3, Math.min(86400, Math.round((payloadLength * 8) / 2000000)));
    const baseView = new DataView(base.buffer, base.byteOffset, base.byteLength);
    // mvhd duration (offset 819, timescale 1000)
    baseView.setUint32(819, T * 1000, false);
    // tkhd duration (offset 939, timescale 1000)
    baseView.setUint32(939, T * 1000, false);
    // elst duration (offset 1027, timescale 1000)
    baseView.setUint32(1027, T * 1000, false);
    // mdhd duration (offset 1071, timescale 44100)
    baseView.setUint32(1071, Math.min(0xFFFFFFFF, T * 44100), false);
  }

  const carrier = new Uint8Array(base.length + mdatHeader.length);
  carrier.set(base, 0);
  carrier.set(mdatHeader, base.length);
  return carrier;
}

/**
 * Detects whether an input file is a polyglot carrier (WAVE, PNG, JPEG, ISO-9660, or MP4),
 * and if so, returns the exact byte offset where the encrypted container payload begins.
 */
export function detectCarrierPayloadOffset(fileStartBytes: Uint8Array): {
  isCarrier: boolean;
  payloadOffset: number;
  carrierType?: 'wav' | 'png' | 'jpg' | 'iso' | 'mp4';
} {
  if (fileStartBytes.length < 16) return { isCarrier: false, payloadOffset: 0 };

  // 1. RIFF WAVE Carrier
  if (
    fileStartBytes[0] === 0x52 && fileStartBytes[1] === 0x49 && fileStartBytes[2] === 0x46 && fileStartBytes[3] === 0x46 &&
    fileStartBytes[8] === 0x57 && fileStartBytes[9] === 0x41 && fileStartBytes[10] === 0x56 && fileStartBytes[11] === 0x45
  ) {
    // Fast O(1) detection for FortKnox standard audible WAV carrier (JUNK chunk at offset 88244)
    if (
      fileStartBytes.length >= 88252 &&
      fileStartBytes[88244] === 0x4a && // 'J'
      fileStartBytes[88245] === 0x55 && // 'U'
      fileStartBytes[88246] === 0x4e && // 'N'
      fileStartBytes[88247] === 0x4b    // 'K'
    ) {
      return { isCarrier: true, payloadOffset: 88252, carrierType: 'wav' };
    }

    let pos = 12;
    const view = new DataView(fileStartBytes.buffer, fileStartBytes.byteOffset, fileStartBytes.byteLength);
    while (pos + 8 <= fileStartBytes.length) {
      const chunkId = String.fromCharCode(fileStartBytes[pos], fileStartBytes[pos+1], fileStartBytes[pos+2], fileStartBytes[pos+3]);
      const chunkSize = view.getUint32(pos + 4, true);
      if (chunkId === 'JUNK' || chunkId === 'PAD ') {
        return { isCarrier: true, payloadOffset: pos + 8, carrierType: 'wav' };
      }
      if (chunkId === 'data') {
        // If data chunk size is 88,200 (1 second PCM) or if only a short probe buffer was provided (< 88,252 bytes),
        // the FortKnox container payload begins after the 88,200 PCM bytes + 8-byte JUNK header = offset 88,252
        if (chunkSize === 88200 || fileStartBytes.length < 88252) {
          return { isCarrier: true, payloadOffset: 88252, carrierType: 'wav' };
        }
        const junkPos = pos + 8 + chunkSize;
        if (junkPos + 8 <= fileStartBytes.length) {
          return { isCarrier: true, payloadOffset: junkPos + 8, carrierType: 'wav' };
        }
      }
      pos += 8 + chunkSize;
      if (chunkSize % 2 !== 0) pos++;
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
      if (chunkType === 'IEND') {
        const nextPos = pos + 12;
        if (nextPos + 8 <= fileStartBytes.length) {
          const nextType = String.fromCharCode(fileStartBytes[nextPos+4], fileStartBytes[nextPos+5], fileStartBytes[nextPos+6], fileStartBytes[nextPos+7]);
          if (nextType === 'foRt' || nextType === 'ftKX' || nextType === 'caSC') {
            return { isCarrier: true, payloadOffset: nextPos + 8, carrierType: 'png' };
          }
        }
        return { isCarrier: true, payloadOffset: nextPos, carrierType: 'png' };
      }
      pos += 8 + chunkLen + 4;
    }
    return { isCarrier: false, payloadOffset: 0 };
  }

  // 3. JPEG Carrier
  if (
    fileStartBytes[0] === 0xFF && fileStartBytes[1] === 0xD8 && fileStartBytes[2] === 0xFF
  ) {
    // Scan for FF D9 (EOI) within first 4096 bytes
    const limit = Math.min(fileStartBytes.length - 1, 4096);
    for (let i = 2; i < limit; i++) {
      if (fileStartBytes[i] === 0xFF && fileStartBytes[i+1] === 0xD9) {
        return { isCarrier: true, payloadOffset: i + 2, carrierType: 'jpg' };
      }
    }
  }

  // 4. ISO-9660 Carrier (Sector 16 Primary Volume Descriptor with 'CD001' marker)
  if (fileStartBytes.length >= 32774) {
    const pvdOffset = 16 * 2048; // 32,768 (Sector 16)
    if (
      fileStartBytes[pvdOffset] === 1 &&
      fileStartBytes[pvdOffset + 1] === 0x43 && // 'C'
      fileStartBytes[pvdOffset + 2] === 0x44 && // 'D'
      fileStartBytes[pvdOffset + 3] === 0x30 && // '0'
      fileStartBytes[pvdOffset + 4] === 0x30 && // '0'
      fileStartBytes[pvdOffset + 5] === 0x31    // '1'
    ) {
      return { isCarrier: true, payloadOffset: 43008, carrierType: 'iso' };
    }
  }

  // 5. MP4 / ISO Base Media File Format (ISO-BMFF) Carrier
  if (
    fileStartBytes.length >= 16 &&
    fileStartBytes[4] === 0x66 && // 'f'
    fileStartBytes[5] === 0x74 && // 't'
    fileStartBytes[6] === 0x79 && // 'y'
    fileStartBytes[7] === 0x70    // 'p'
  ) {
    let pos = 0;
    const view = new DataView(fileStartBytes.buffer, fileStartBytes.byteOffset, fileStartBytes.byteLength);
    let lastMdatOffset = -1;
    let lastMdatHeaderLen = 8;
    let seenMoov = false;

    while (pos + 8 <= fileStartBytes.length) {
      const boxSize = view.getUint32(pos, false);
      const boxType = String.fromCharCode(
        fileStartBytes[pos + 4],
        fileStartBytes[pos + 5],
        fileStartBytes[pos + 6],
        fileStartBytes[pos + 7]
      );
      if (boxType === 'moov') {
        seenMoov = true;
      } else if (boxType === 'mdat') {
        const headerLen = boxSize === 1 ? 16 : 8;
        lastMdatOffset = pos;
        lastMdatHeaderLen = headerLen;
        // In dual-box playable MP4 architecture, payload container mdat appears after moov
        if (seenMoov) {
          return {
            isCarrier: true,
            payloadOffset: pos + headerLen,
            carrierType: 'mp4',
          };
        }
      }
      if (boxSize <= 0) break;
      if (boxSize === 1) {
        if (pos + 16 > fileStartBytes.length) break;
        const largeSize = Number(view.getBigUint64(pos + 8, false));
        if (largeSize <= 0) break;
        pos += largeSize;
      } else {
        pos += boxSize;
      }
    }
    // Fallback if moov was not after mdat (e.g. legacy container where mdat is first)
    if (lastMdatOffset !== -1) {
      return {
        isCarrier: true,
        payloadOffset: lastMdatOffset + lastMdatHeaderLen,
        carrierType: 'mp4',
      };
    }
  }

  return { isCarrier: false, payloadOffset: 0 };
}
