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
import {
  protectMetadataBlob,
  healMetadataBlob,
  rsEncode,
  rsDecode,
  encodeInterleaved,
  decodeInterleaved,
  DEFAULT_RS_PARITY_BYTES,
  DEFAULT_INTERLEAVE_DEPTH,
} from './reedsolomon.ts';

import {
  TARGET_SHAPED_ENTROPY,
  THEORETICAL_EXPANSION_RATIO,
  shapeCiphertext,
  unshapeCiphertext,
  calculateShannonMetrics,
  verifyKraftMcMillan,
  FIXED_SHAPED_CHUNK_SIZE,
  shapeChunkFixed,
  unshapeChunkFixed,
} from './distributionMatcher.ts';

export {
  protectMetadataBlob,
  healMetadataBlob,
  rsEncode,
  rsDecode,
  encodeInterleaved,
  decodeInterleaved,
  DEFAULT_RS_PARITY_BYTES,
  DEFAULT_INTERLEAVE_DEPTH,
  TARGET_SHAPED_ENTROPY,
  THEORETICAL_EXPANSION_RATIO,
  shapeCiphertext,
  unshapeCiphertext,
  calculateShannonMetrics,
  verifyKraftMcMillan,
  FIXED_SHAPED_CHUNK_SIZE,
  shapeChunkFixed,
  unshapeChunkFixed,
};

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

  if (meta.entropyShaped) {
    view.setUint32(152, 0x53485031, true); // "SHP1" marker
  } else {
    view.setUint32(152, 0, true);
  }

  // Industrial Reed-Solomon Forward Error Correction (Critical Metadata Protection)
  // Embeds 64-byte systematic RS parity into bytes 160-223 to protect headers from silent corruption
  protectMetadataBlob(buf);

  return buf;
}

/**
 * Decodes the 512-byte metadata blob with automatic Reed-Solomon self-healing
 */
export function decodeMetadataBlob(buf: Uint8Array): ContainerMetadata {
  if (buf.length !== METADATA_SIZE) {
    throw new Error('Decryption failed. Check all keys.');
  }

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);

  // Proactive Reed-Solomon Forward Error Correction
  // Checks syndromes and heals up to 32 byte errors anywhere in critical headers (bytes 0..159)
  healMetadataBlob(buf);

  const magic = view.getUint32(0, true);
  const version = view.getUint32(4, true);

  if (magic !== METADATA_MAGIC || version !== CONTAINER_VERSION) {
    throw new Error('Decryption failed. Check all keys.');
  }
  const rawSizeBig = view.getBigUint64(8, true);
  const chunkCount = view.getUint32(16, true);
  const chunkSize = view.getUint32(20, true);
  const originalSize = Number(rawSizeBig);

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

  const entropyMarker = view.getUint32(152, true);
  const entropyShaped = entropyMarker === 0x53485031;

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
    entropyShaped,
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
  legacyFixed?: boolean;
  proportionalDuration?: boolean;
  durationSec?: number;
  maxDurationSec?: number;
}

/**
 * Generates an authentic ISO Base Media File Format (ISO/IEC 14496-12 / MP4) video carrier header.
 * - Dynamic Stream-Synchronized Mode (Default): Dynamically scales video duration to match payload size
 *   and synthesizes an authentic ISO-BMFF sample table (stts, stsc, stsz, stco) referencing real AAC
 *   media frames in mdat #1. Media players (VLC, Windows Media Player, QuickTime, Movies & TV, Chrome)
 *   play continuously across the entire duration with 0 jump, 0 freeze, and flawless seeking.
 * - Legacy Fixed Mode (legacyFixed: true): Emits the static 1,493-byte base MP4 clip (47ms duration).
 * - Legacy Synthetic Mode (legacySynthetic: true): Generates the 579-byte synthetic ISO-BMFF header.
 */
export function createMp4CarrierHeader(payloadLength: number, options?: Mp4CarrierOptions): Uint8Array {
  function makeBox(type: string, payload: Uint8Array): Uint8Array {
    const box = new Uint8Array(8 + payload.length);
    const view = new DataView(box.buffer, box.byteOffset, box.byteLength);
    view.setUint32(0, box.length, false);
    box[4] = type.charCodeAt(0);
    box[5] = type.charCodeAt(1);
    box[6] = type.charCodeAt(2);
    box[7] = type.charCodeAt(3);
    box.set(payload, 8);
    return box;
  }

  function concat(...arrays: Uint8Array[]): Uint8Array {
    let total = 0;
    for (let i = 0; i < arrays.length; i++) total += arrays[i].length;
    const res = new Uint8Array(total);
    let off = 0;
    for (let i = 0; i < arrays.length; i++) {
      res.set(arrays[i], off);
      off += arrays[i].length;
    }
    return res;
  }

  if (options?.legacySynthetic) {
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

  // Payload container box header (mdat #2)
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

  // Dynamic Stream-Synchronized Proportional Duration Mode:
  // Enabled via options?.proportionalDuration or explicit durationSec.
  // Dynamically scales video duration to match payload size and synthesizes an authentic ISO-BMFF
  // sample table (stts, stsc, stsz, stco) referencing real AAC media frames in mdat #1.
  // Media players (VLC, Windows Media Player, QuickTime, Movies & TV, Chrome) play continuously
  // across the full duration with 0 jump, 0 freeze, and flawless seeking.
  if (options?.proportionalDuration || options?.durationSec !== undefined) {
    let durationSec = options?.durationSec;
    if (durationSec === undefined) {
      // Nominal HD video bitrate: 2,000,000 bits per sec (250 KB/sec)
      // Clamped to range 3s .. maxDurationSec (default 86,400s / 24 hours, or clamped to 7,200s in pool)
      const maxDur = options?.maxDurationSec ?? 86400;
      durationSec = Math.max(3, Math.min(maxDur, Math.round((payloadLength * 8) / 2000000)));
    }

    const movieDurationMs = durationSec * 1000;
    const mediaDurationTicks = Math.min(0xFFFFFFFF, durationSec * 44100);

    // Audio track calculations: 44.1 kHz timescale, 1024 samples/frame
    const totalTicks = durationSec * 44100;
    const numSamples = Math.ceil(totalTicks / 1024);
    const safeSamples = numSamples % 2 === 0 ? numSamples : numSamples + 1;
    const numChunks = safeSamples / 2;

    // 1. Static pre-moov boxes: ftyp (28) + free (8) + mdat #1 (751) = 787 bytes
    // mdat #1 contains authentic AAC audio frames at file offset 44
    const preMoov = MP4_PREVIEW_BASE.subarray(0, 787);

    // 2. Sample table boxes (stbl)
    // stsd (103 bytes) extracted from base at offset 1192
    const stsdBox = MP4_PREVIEW_BASE.subarray(1192, 1192 + 103);

    // stts (24 bytes)
    const sttsBox = new Uint8Array(24);
    const sttsView = new DataView(sttsBox.buffer);
    sttsView.setUint32(0, 24, false);
    sttsBox.set([0x73, 0x74, 0x74, 0x73], 4); // 'stts'
    sttsView.setUint32(8, 0, false);           // version & flags
    sttsView.setUint32(12, 1, false);          // entry_count
    sttsView.setUint32(16, safeSamples, false);// sample_count
    sttsView.setUint32(20, 1024, false);       // sample_delta

    // stsc (28 bytes)
    const stscBox = new Uint8Array(28);
    const stscView = new DataView(stscBox.buffer);
    stscView.setUint32(0, 28, false);
    stscBox.set([0x73, 0x74, 0x73, 0x63], 4); // 'stsc'
    stscView.setUint32(8, 0, false);           // version & flags
    stscView.setUint32(12, 1, false);          // entry_count
    stscView.setUint32(16, 1, false);          // first_chunk
    stscView.setUint32(20, 2, false);          // samples_per_chunk
    stscView.setUint32(24, 1, false);          // sample_description_index

    // stsz (20 + safeSamples * 4 bytes)
    const stszTotal = 20 + safeSamples * 4;
    const stszBox = new Uint8Array(stszTotal);
    const stszView = new DataView(stszBox.buffer);
    stszView.setUint32(0, stszTotal, false);
    stszBox.set([0x73, 0x74, 0x73, 0x7a], 4); // 'stsz'
    stszView.setUint32(8, 0, false);           // version & flags
    stszView.setUint32(12, 0, false);          // sample_size = 0 (variable)
    stszView.setUint32(16, safeSamples, false);// sample_count
    for (let i = 0; i < safeSamples; i++) {
      stszView.setUint32(20 + i * 4, i % 2 === 0 ? 371 : 372, false);
    }

    // stco (16 + numChunks * 4 bytes)
    const stcoTotal = 16 + numChunks * 4;
    const stcoBox = new Uint8Array(stcoTotal);
    const stcoView = new DataView(stcoBox.buffer);
    stcoView.setUint32(0, stcoTotal, false);
    stcoBox.set([0x73, 0x74, 0x63, 0x6f], 4); // 'stco'
    stcoView.setUint32(8, 0, false);           // version & flags
    stcoView.setUint32(12, numChunks, false);  // entry_count
    for (let i = 0; i < numChunks; i++) {
      stcoView.setUint32(16 + i * 4, 44, false); // chunk offset 44 (mdat #1 audio buffer)
    }

    // stbl container
    const stblChildren = concat(stsdBox, sttsBox, stscBox, stszBox, stcoBox);
    const stblBox = makeBox('stbl', stblChildren);

    // smhd (16 bytes) and dinf (36 bytes) from base
    const smhdBox = MP4_PREVIEW_BASE.subarray(1132, 1132 + 16);
    const dinfBox = MP4_PREVIEW_BASE.subarray(1148, 1148 + 36);

    // minf container
    const minfChildren = concat(smhdBox, dinfBox, stblBox);
    const minfBox = makeBox('minf', minfChildren);

    // mdhd (32 bytes)
    const mdhdBox = new Uint8Array(32);
    const mdhdView = new DataView(mdhdBox.buffer);
    mdhdView.setUint32(0, 32, false);
    mdhdBox.set([0x6d, 0x64, 0x68, 0x64], 4); // 'mdhd'
    mdhdView.setUint32(8, 0, false);           // version & flags
    mdhdView.setUint32(12, 0, false);          // creation_time
    mdhdView.setUint32(16, 0, false);          // modification_time
    mdhdView.setUint32(20, 44100, false);      // timescale
    mdhdView.setUint32(24, mediaDurationTicks, false); // duration
    mdhdView.setUint16(28, 0x55c4, false);     // language (und)
    mdhdView.setUint16(30, 0, false);

    // hdlr (45 bytes) from base
    const hdlrBox = MP4_PREVIEW_BASE.subarray(1079, 1079 + 45);

    // mdia container
    const mdiaChildren = concat(mdhdBox, hdlrBox, minfBox);
    const mdiaBox = makeBox('mdia', mdiaChildren);

    // tkhd (92 bytes) from base with updated duration
    const tkhdBox = MP4_PREVIEW_BASE.subarray(911, 911 + 92).slice();
    new DataView(tkhdBox.buffer).setUint32(28, movieDurationMs, false);

    // edts (36 bytes) containing elst (28 bytes)
    const elstBox = new Uint8Array(28);
    const elstView = new DataView(elstBox.buffer);
    elstView.setUint32(0, 28, false);
    elstBox.set([0x65, 0x6c, 0x73, 0x74], 4); // 'elst'
    elstView.setUint32(8, 0, false);           // version & flags
    elstView.setUint32(12, 1, false);          // entry_count
    elstView.setUint32(16, movieDurationMs, false); // track_duration
    elstView.setInt32(20, 0, false);           // media_time
    elstView.setInt16(24, 1, false);           // media_rate_integer
    elstView.setInt16(26, 0, false);           // media_rate_fraction
    const edtsBox = makeBox('edts', elstBox);

    // trak container
    const trakChildren = concat(tkhdBox, edtsBox, mdiaBox);
    const trakBox = makeBox('trak', trakChildren);

    // mvhd (108 bytes) from base with updated timescale and duration
    const mvhdBox = MP4_PREVIEW_BASE.subarray(795, 795 + 108).slice();
    const mvhdView = new DataView(mvhdBox.buffer);
    mvhdView.setUint32(20, 1000, false);       // timescale
    mvhdView.setUint32(24, movieDurationMs, false); // duration

    // udta (98 bytes) from base
    const udtaBox = MP4_PREVIEW_BASE.subarray(1395, 1395 + 98);

    // moov container
    const moovChildren = concat(mvhdBox, trakBox, udtaBox);
    const moovBox = makeBox('moov', moovChildren);

    return concat(preMoov, moovBox, mdatHeader);
  }

  // Fixed Mode (Default without proportionalDuration):
  // Authentic 1,493-byte base MP4 + mdat #2 box header (stream-synchronized 47ms media clip)
  const base = MP4_PREVIEW_BASE.slice();
  const carrier = new Uint8Array(base.length + mdatHeader.length);
  carrier.set(base, 0);
  carrier.set(mdatHeader, base.length);
  return carrier;
}

/**
 * Detects whether an input file is a polyglot carrier (WAVE, ISO-9660, or MP4),
 * and if so, returns the exact byte offset where the encrypted container payload begins.
 */
export interface CarrierPayloadOffsetResult {
  isCarrier: boolean;
  payloadOffset: number;
  carrierType?: 'wav' | 'iso' | 'mp4';
  pendingProbeOffset?: number;
}

export function detectCarrierPayloadOffset(fileStartBytes: Uint8Array): CarrierPayloadOffsetResult {
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

  // 2. ISO-9660 Carrier (Sector 16 Primary Volume Descriptor with 'CD001' marker)
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

  // 3. MP4 / ISO Base Media File Format (ISO-BMFF) Carrier
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
        const moovBoxSize = boxSize === 1
          ? (pos + 16 <= fileStartBytes.length ? Number(view.getBigUint64(pos + 8, false)) : 0)
          : boxSize;
        if (moovBoxSize > 0 && pos + moovBoxSize > fileStartBytes.length) {
          return {
            isCarrier: true,
            payloadOffset: 0,
            carrierType: 'mp4',
            pendingProbeOffset: pos + moovBoxSize,
          };
        }
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
