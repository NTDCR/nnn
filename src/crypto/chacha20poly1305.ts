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
    const nonce = new Uint8Array(baseNonce.subarray(0, 12));
    const idxView = new DataView(new ArrayBuffer(8));
    idxView.setBigUint64(0, BigInt(chunkIndex), true);
    for (let i = 0; i < 8; i++) {
      nonce[4 + i] ^= idxView.getUint8(i);
    }
    return nonce;
  }

  private decryptBuffer: Uint8Array = new Uint8Array(1048576 + 16);
  private encryptBuffer: Uint8Array = new Uint8Array(1048576 + 16);

  public destroy(): void {
    if (this.simdEngine) {
      this.simdEngine.destroy();
      this.simdEngine = null;
    }
    this.rawKey.fill(0);
    this.decryptBuffer.fill(0);
    this.encryptBuffer.fill(0);
  }

  /**
   * Encrypt in-place using SIMD128-accelerated or audited @noble/ciphers chacha20poly1305
   * Returns 16-byte Poly1305 authentication tag
   */
  public encryptInPlace(data: Uint8Array, nonce12: Uint8Array, aad: Uint8Array = new Uint8Array()): Uint8Array {
    const cipher = this.simdEngine
      ? this.simdEngine.getCipher(nonce12, aad)
      : chacha20poly1305(this.rawKey, nonce12, aad);
    const requiredLen = data.length + 16;
    const outBuf = this.encryptBuffer.length >= requiredLen
      ? this.encryptBuffer.subarray(0, requiredLen)
      : new Uint8Array(requiredLen);
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
    const cipher = this.simdEngine
      ? this.simdEngine.getCipher(nonce12, aad)
      : chacha20poly1305(this.rawKey, nonce12, aad);
    const requiredLen = data.length + 16;
    const fullCiphertext = this.decryptBuffer.length >= requiredLen
      ? this.decryptBuffer.subarray(0, requiredLen)
      : new Uint8Array(requiredLen);
    fullCiphertext.set(data, 0);
    fullCiphertext.set(tag16, data.length);
    try {
      const plain = cipher.decrypt(fullCiphertext);
      data.set(plain);
    } catch {
      throw new Error('Decryption failed. Check all keys.');
    }
  }
}
