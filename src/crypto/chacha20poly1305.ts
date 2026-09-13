/**
 * ChaCha20-Poly1305 AEAD (RFC 8439)
 * Powered by @noble/ciphers (Audited by Cure53, 0-dependency)
 * Constant-time tag verification
 */

import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { ChaChaSimdEngine } from './chachaSimdEngine.ts';

export class ChaCha20Poly1305 {
  private rawKey: Uint8Array;
  private simdEngine: ChaChaSimdEngine | null = null;
  private isDestroyed = false;

  constructor(keyBytes: Uint8Array) {
    if (keyBytes.length !== 32) {
      throw new Error('ChaCha20-Poly1305 key must be 32 bytes');
    }
    this.rawKey = new Uint8Array(keyBytes);
    this.simdEngine = ChaChaSimdEngine.create(keyBytes);
  }

  public deriveChunkNonce(baseNonce: Uint8Array, chunkIndex: number): Uint8Array {
    if (baseNonce.length < 12) {
      throw new Error('ChaCha20-Poly1305 base nonce must be at least 12 bytes');
    }
    if (chunkIndex < 0 || !Number.isSafeInteger(chunkIndex)) {
      throw new Error('Invalid chunk index');
    }
    const nonce = new Uint8Array(baseNonce.subarray(0, 12));
    const low = chunkIndex >>> 0;
    const high = Math.floor(chunkIndex / 0x100000000) >>> 0;
    nonce[4] ^= low & 0xff;
    nonce[5] ^= (low >>> 8) & 0xff;
    nonce[6] ^= (low >>> 16) & 0xff;
    nonce[7] ^= (low >>> 24) & 0xff;
    nonce[8] ^= high & 0xff;
    nonce[9] ^= (high >>> 8) & 0xff;
    nonce[10] ^= (high >>> 16) & 0xff;
    nonce[11] ^= (high >>> 24) & 0xff;
    return nonce;
  }

  public destroy(): void {
    this.isDestroyed = true;
    if (this.simdEngine) {
      this.simdEngine.destroy();
      this.simdEngine = null;
    }
    this.rawKey.fill(0);
  }

  /**
   * Encrypt in-place using SIMD128-accelerated or audited @noble/ciphers chacha20poly1305
   * Returns 16-byte Poly1305 authentication tag
   */
  public encryptInPlace(data: Uint8Array, nonce12: Uint8Array, aad: Uint8Array = new Uint8Array()): Uint8Array {
    if (this.isDestroyed) {
      throw new Error('ChaCha20Poly1305 has been destroyed');
    }
    if (nonce12.length !== 12) {
      throw new Error('ChaCha20-Poly1305 requires strictly a 12-byte nonce.');
    }
    if (this.simdEngine) {
      return this.simdEngine.encryptInPlace(data, nonce12, aad);
    }
    const cipher = chacha20poly1305(this.rawKey, nonce12, aad);
    const requiredLen = data.length + 16;
    const outBuf = new Uint8Array(requiredLen);
    cipher.encrypt(data, outBuf);
    const splitPoint = data.length;
    data.set(outBuf.subarray(0, splitPoint));
    return new Uint8Array(outBuf.subarray(splitPoint, splitPoint + 16));
  }

  /**
   * Decrypt in-place using SIMD128-accelerated or audited @noble/ciphers chacha20poly1305
   * Throws constant-time error if tag verification fails
   */
  public decryptInPlace(data: Uint8Array, nonce12: Uint8Array, tag16: Uint8Array, aad: Uint8Array = new Uint8Array()): void {
    if (this.isDestroyed) {
      data.fill(0);
      throw new Error('ChaCha20Poly1305 has been destroyed');
    }
    if (nonce12.length !== 12 || tag16.length !== 16) {
      data.fill(0);
      throw new Error('Decryption failed. Check all keys.');
    }
    if (this.simdEngine) {
      this.simdEngine.decryptInPlace(data, nonce12, tag16, aad);
      return;
    }
    const cipher = chacha20poly1305(this.rawKey, nonce12, aad);
    const requiredLen = data.length + 16;
    const fullCiphertext = new Uint8Array(requiredLen);
    fullCiphertext.set(data, 0);
    fullCiphertext.set(tag16, data.length);
    try {
      const plain = cipher.decrypt(fullCiphertext);
      data.set(plain);
    } catch {
      data.fill(0);
      throw new Error('Decryption failed. Check all keys.');
    }
  }
}
