/**
 * 4-Layer Cryptographic Cascade Orchestrator
 * Sequence:
 *   Encryption: Plaintext -> Threefish-1024 -> Serpent-256 -> ChaCha20-Poly1305 -> AES-256-GCM -> Output
 *   Decryption: Ciphertext -> AES-256-GCM -> ChaCha20-Poly1305 -> Serpent-256 -> Threefish-1024 -> Plaintext
 */

import { Threefish1024 } from './threefish1024.ts';
import { Serpent256 } from './serpent256.ts';
import { ChaCha20Poly1305 } from './chacha20poly1305.ts';
import { Aes256Gcm } from './aes256gcm.ts';

export const GENERIC_DECRYPT_ERROR = 'Decryption failed. Check all keys.';

export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string') {
    throw new Error('Key must be a string.');
  }
  const cleanHex = hex.trim().replace(/^0x/i, '').replace(/[\s\-_:]/g, '');
  if (!/^[0-9a-fA-F]{64}$/.test(cleanHex)) {
    throw new Error('Key must be exactly 64 hexadecimal characters (256 bits).');
  }
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Safely fills any size Uint8Array with cryptographically secure random values,
 * chunking into 65,536-byte segments to respect Web Crypto API quota limits.
 */
export function fillRandomBytes(buffer: Uint8Array): void {
  const MAX_CHUNK = 65536;
  for (let offset = 0; offset < buffer.length; offset += MAX_CHUNK) {
    const chunk = buffer.subarray(offset, Math.min(offset + MAX_CHUNK, buffer.length));
    crypto.getRandomValues(chunk);
  }
}

export function generateRandomKey(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

export function calculateEntropyScore(hex: string): { bits: number; label: string; color: string } {
  if (!hex) return { bits: 0, label: 'Missing', color: 'text-rose-400' };
  const clean = hex.trim().replace(/^0x/i, '').replace(/[\s\-_:]/g, '');
  if (!/^[0-9a-fA-F]*$/.test(clean)) {
    return { bits: 0, label: 'Invalid hex character', color: 'text-rose-400' };
  }
  if (clean.length < 64) {
    const bits = Math.floor((clean.length / 64) * 256);
    return { bits, label: `Incomplete (${clean.length}/64 hex)`, color: 'text-amber-400' };
  }
  if (clean.length > 64) {
    return { bits: 256, label: `Too long (${clean.length}/64 hex)`, color: 'text-rose-400' };
  }

  // Calculate Shannon entropy over nibbles
  const counts: { [char: string]: number } = {};
  for (const c of clean.toLowerCase()) {
    counts[c] = (counts[c] || 0) + 1;
  }
  let entropy = 0;
  for (const c in counts) {
    const p = counts[c] / clean.length;
    entropy -= p * Math.log2(p);
  }

  // Max entropy for 16 hex chars is 4.0
  const normalizedBits = Math.round((entropy / 4.0) * 256);
  if (normalizedBits >= 240) {
    return { bits: 256, label: 'Fort-Knox (Full 256-bit CSPRNG)', color: 'text-emerald-400' };
  } else if (normalizedBits >= 192) {
    return { bits: normalizedBits, label: 'High Entropy', color: 'text-blue-400' };
  } else {
    return { bits: normalizedBits, label: 'Low Entropy (Pattern detected)', color: 'text-amber-400' };
  }
}

export class CascadePipeline {
  private threefish: Threefish1024;
  private serpent: Serpent256;
  private chacha: ChaCha20Poly1305;
  private aes: Aes256Gcm;

  constructor(
    key1: Uint8Array | string,
    key2: Uint8Array | string,
    key3: Uint8Array | string,
    key4: Uint8Array | string
  ) {
    const k1 = typeof key1 === 'string' ? hexToBytes(key1) : key1;
    const k2 = typeof key2 === 'string' ? hexToBytes(key2) : key2;
    const k3 = typeof key3 === 'string' ? hexToBytes(key3) : key3;
    const k4 = typeof key4 === 'string' ? hexToBytes(key4) : key4;

    const tweak = new Uint8Array([
      0x54, 0x68, 0x72, 0x65, 0x65, 0x66, 0x69, 0x73,
      0x68, 0x54, 0x77, 0x65, 0x61, 0x6b, 0x31, 0x36
    ]);

    this.threefish = new Threefish1024(k1, tweak);
    this.serpent = new Serpent256(k2);
    this.chacha = new ChaCha20Poly1305(k3);
    this.aes = new Aes256Gcm(k4);
  }

  /**
   * Encrypt 1 MB chunk across all 4 layers
   * Returns: { ciphertext, tags: 32 bytes (16B ChaCha + 16B AES) }
   */
  public async encryptChunk(
    chunkData: Uint8Array,
    chunkIndex: number,
    nonceThreefish: Uint8Array,
    nonceSerpent: Uint8Array,
    nonceChaCha: Uint8Array,
    nonceAes: Uint8Array
  ): Promise<{ ciphertext: Uint8Array; tagChaCha: Uint8Array; tagAes: Uint8Array }> {
    const work = new Uint8Array(chunkData);

    // Layer 1: Threefish-1024 CTR
    this.threefish.processCtr(work, nonceThreefish, chunkIndex);

    // Layer 2: Serpent-256 CTR
    this.serpent.processCtr(work, nonceSerpent, chunkIndex);

    // Layer 3: ChaCha20-Poly1305 AEAD
    const chunkNonceChaCha = this.chacha.deriveChunkNonce(nonceChaCha, chunkIndex);
    const aad = new Uint8Array(8);
    new DataView(aad.buffer, aad.byteOffset, 8).setBigUint64(0, BigInt(chunkIndex), true);
    const tagChaCha = this.chacha.encryptInPlace(work, chunkNonceChaCha, aad);

    // Layer 4: AES-256-GCM AEAD
    const chunkNonceAes = this.aes.deriveChunkNonce(nonceAes, chunkIndex);
    const aesResult = await this.aes.encrypt(work, chunkNonceAes, aad);

    return {
      ciphertext: aesResult.ciphertext,
      tagChaCha,
      tagAes: aesResult.tag,
    };
  }

  /**
   * Decrypt 1 MB chunk across all 4 layers in reverse order
   */
  public async decryptChunk(
    ciphertext: Uint8Array,
    chunkIndex: number,
    nonceThreefish: Uint8Array,
    nonceSerpent: Uint8Array,
    nonceChaCha: Uint8Array,
    nonceAes: Uint8Array,
    tagChaCha: Uint8Array,
    tagAes: Uint8Array
  ): Promise<Uint8Array> {
    try {
      const aad = new Uint8Array(8);
      new DataView(aad.buffer, aad.byteOffset, 8).setBigUint64(0, BigInt(chunkIndex), true);

      // Layer 4: AES-256-GCM AEAD (reverse 1)
      const chunkNonceAes = this.aes.deriveChunkNonce(nonceAes, chunkIndex);
      const afterAes = await this.aes.decrypt(ciphertext, chunkNonceAes, tagAes, aad);

      // Layer 3: ChaCha20-Poly1305 AEAD (reverse 2)
      const work = new Uint8Array(afterAes);
      const chunkNonceChaCha = this.chacha.deriveChunkNonce(nonceChaCha, chunkIndex);
      this.chacha.decryptInPlace(work, chunkNonceChaCha, tagChaCha, aad);

      // Layer 2: Serpent-256 CTR (reverse 3)
      this.serpent.processCtr(work, nonceSerpent, chunkIndex);

      // Layer 1: Threefish-1024 CTR (reverse 4)
      this.threefish.processCtr(work, nonceThreefish, chunkIndex);

      return work;
    } catch {
      throw new Error(GENERIC_DECRYPT_ERROR);
    }
  }
}
