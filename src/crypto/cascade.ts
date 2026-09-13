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

export function hexToBytes(hex: string, expectedBytes?: number): Uint8Array {
  if (typeof hex !== 'string') {
    throw new Error('Key must be a string.');
  }
  const cleanHex = hex.trim().replace(/^0x/i, '').replace(/[\s\-_:"']/g, '');
  if (!/^[0-9a-fA-F]*$/.test(cleanHex)) {
    throw new Error('Key must contain valid hexadecimal characters.');
  }

  if (expectedBytes !== undefined) {
    if (cleanHex.length !== expectedBytes * 2) {
      throw new Error(`Key must be exactly ${expectedBytes * 2} hexadecimal characters (${expectedBytes * 8} bits).`);
    }
  } else {
    // Strictly require either 256 bits (64 hex) or 1024 bits (256 hex)
    if (cleanHex.length !== 64 && cleanHex.length !== 256) {
      throw new Error('Key must be either 64 hex characters (256 bits) or 256 hex characters (1024 bits).');
    }
  }

  const byteLength = cleanHex.length / 2;
  const bytes = new Uint8Array(byteLength);
  for (let i = 0; i < byteLength; i++) {
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

export function generateRandomKey(byteLength: number = 32): string {
  const bytes = new Uint8Array(byteLength);
  fillRandomBytes(bytes);
  return bytesToHex(bytes);
}

export function calculateEntropyScore(hex: string, expectedBits: number = 256): { bits: number; label: string; color: string } {
  if (!hex) return { bits: 0, label: 'Missing', color: 'text-rose-400' };
  const clean = hex.trim().replace(/^0x/i, '').replace(/[\s\-_:"']/g, '');
  if (!/^[0-9a-fA-F]*$/.test(clean)) {
    return { bits: 0, label: 'Invalid hex character', color: 'text-rose-400' };
  }
  // If 1024-bit expected, strictly require full 1024-bit (256 hex)
  if (expectedBits === 1024) {
    if (clean.length < 256) {
      const bits = Math.floor((clean.length / 256) * 1024);
      return { bits, label: `Incomplete (${clean.length}/256 hex)`, color: 'text-amber-400' };
    }
    if (clean.length > 256) {
      return { bits: 1024, label: `Too long (${clean.length}/256 hex)`, color: 'text-rose-400' };
    }
  } else {
    if (clean.length < 64) {
      const bits = Math.floor((clean.length / 64) * 256);
      return { bits, label: `Incomplete (${clean.length}/64 hex)`, color: 'text-amber-400' };
    }
    if (clean.length > 64) {
      return { bits: 256, label: `Too long (${clean.length}/64 hex)`, color: 'text-rose-400' };
    }
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
  const normalizedBits = Math.round((entropy / 4.0) * expectedBits);
  const fullThreshold = expectedBits === 1024 ? 960 : 240;
  const highThreshold = expectedBits === 1024 ? 768 : 192;

  if (normalizedBits >= fullThreshold) {
    return {
      bits: expectedBits,
      label: expectedBits === 1024 ? 'Fort-Knox (Full 1024-bit CSPRNG)' : 'Fort-Knox (Full 256-bit CSPRNG)',
      color: 'text-emerald-400',
    };
  } else if (normalizedBits >= highThreshold) {
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
  private aadBuf: Uint8Array = new Uint8Array(8);
  private aadView: DataView;

  constructor(
    key1: Uint8Array | string,
    key2: Uint8Array | string,
    key3: Uint8Array | string,
    key4: Uint8Array | string
  ) {
    this.aadView = new DataView(this.aadBuf.buffer);
    const k1 = typeof key1 === 'string' ? hexToBytes(key1, 128) : key1;
    const k2 = typeof key2 === 'string' ? hexToBytes(key2, 32) : key2;
    const k3 = typeof key3 === 'string' ? hexToBytes(key3, 32) : key3;
    const k4 = typeof key4 === 'string' ? hexToBytes(key4, 32) : key4;

    if (k1.length !== 128) {
      throw new Error('Layer 1 (Threefish-1024) requires strictly a 128-byte (1024-bit) key.');
    }
    if (k2.length !== 32 || k3.length !== 32 || k4.length !== 32) {
      throw new Error('Layers 2, 3, and 4 require strictly 32-byte (256-bit) keys.');
    }

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
    nonceAes: Uint8Array,
    inPlace: boolean = true
  ): Promise<{ ciphertext: Uint8Array; tagChaCha: Uint8Array; tagAes: Uint8Array }> {
    const work = inPlace ? chunkData : new Uint8Array(chunkData);

    // Layer 1: Threefish-1024 CTR
    this.threefish.processCtr(work, nonceThreefish, chunkIndex);

    // Layer 2: Serpent-256 CTR
    this.serpent.processCtr(work, nonceSerpent, chunkIndex);

    // Layer 3: ChaCha20-Poly1305 AEAD
    const chunkNonceChaCha = this.chacha.deriveChunkNonce(nonceChaCha, chunkIndex);
    this.aadView.setBigUint64(0, BigInt(chunkIndex), true);
    const tagChaCha = this.chacha.encryptInPlace(work, chunkNonceChaCha, this.aadBuf);

    // Layer 4: AES-256-GCM AEAD
    const chunkNonceAes = this.aes.deriveChunkNonce(nonceAes, chunkIndex);
    const aesResult = await this.aes.encrypt(work, chunkNonceAes, this.aadBuf);

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
      this.aadView.setBigUint64(0, BigInt(chunkIndex), true);

      // Layer 4: AES-256-GCM AEAD (reverse 1)
      const chunkNonceAes = this.aes.deriveChunkNonce(nonceAes, chunkIndex);
      const afterAes = await this.aes.decrypt(ciphertext, chunkNonceAes, tagAes, this.aadBuf);

      // Layer 3: ChaCha20-Poly1305 AEAD (reverse 2) - decrypt in place directly in afterAes buffer
      const chunkNonceChaCha = this.chacha.deriveChunkNonce(nonceChaCha, chunkIndex);
      this.chacha.decryptInPlace(afterAes, chunkNonceChaCha, tagChaCha, this.aadBuf);

      // Layer 2: Serpent-256 CTR (reverse 3)
      this.serpent.processCtr(afterAes, nonceSerpent, chunkIndex);

      // Layer 1: Threefish-1024 CTR (reverse 4)
      this.threefish.processCtr(afterAes, nonceThreefish, chunkIndex);

      return afterAes;
    } catch {
      throw new Error(GENERIC_DECRYPT_ERROR);
    }
  }

  public destroy(): void {
    this.threefish.destroy();
    this.serpent.destroy();
    this.chacha.destroy();
    this.aes.destroy();
    this.aadBuf.fill(0);
  }
}
