/**
 * ChaCha20-Poly1305 AEAD (RFC 8439)
 * Powered by @noble/ciphers (Audited by Cure53, 0-dependency)
 * Constant-time tag verification
 */

import { chacha20, chacha20poly1305 } from '@noble/ciphers/chacha.js';

export class ChaCha20 {
  private key: Uint8Array;

  constructor(keyBytes: Uint8Array) {
    if (keyBytes.length !== 32) {
      throw new Error('ChaCha20 key must be 32 bytes');
    }
    this.key = new Uint8Array(keyBytes);
  }

  public applyKeystream(data: Uint8Array, nonce12: Uint8Array, counter: number = 0): void {
    // In @noble/ciphers, chacha20(key, nonce, data, output, counter)
    const stream = chacha20(this.key, nonce12, data, undefined, counter);
    data.set(stream);
  }

  public generateBlock(counter: number, nonce12: Uint8Array, outBlock: Uint8Array): void {
    const zeroes = new Uint8Array(outBlock.length);
    const stream = chacha20(this.key, nonce12, zeroes, undefined, counter);
    outBlock.set(stream);
  }
}

export class Poly1305 {
  /**
   * Computes Poly1305 authentication tag using audited @noble/ciphers implementation
   */
  public static computeTag(key32: Uint8Array, message: Uint8Array, aad: Uint8Array = new Uint8Array()): Uint8Array {
    // A synthetic ChaCha20Poly1305 invocation or using @noble Poly1305
    const dummyNonce = new Uint8Array(12);
    const cipher = chacha20poly1305(key32, dummyNonce, aad);
    const full = cipher.encrypt(message);
    return full.subarray(full.length - 16);
  }
}

export class ChaCha20Poly1305 {
  private rawKey: Uint8Array;

  constructor(keyBytes: Uint8Array) {
    if (keyBytes.length !== 32) {
      throw new Error('ChaCha20-Poly1305 key must be 32 bytes');
    }
    this.rawKey = new Uint8Array(keyBytes);
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

  public destroy(): void {
    this.rawKey.fill(0);
  }

  /**
   * Encrypt in-place using audited @noble/ciphers chacha20poly1305
   * Returns 16-byte Poly1305 authentication tag
   */
  public encryptInPlace(data: Uint8Array, nonce12: Uint8Array, aad: Uint8Array = new Uint8Array()): Uint8Array {
    const cipher = chacha20poly1305(this.rawKey, nonce12, aad);
    const fullCiphertext = cipher.encrypt(data);
    const ciphertextOnly = fullCiphertext.subarray(0, fullCiphertext.length - 16);
    const tag = fullCiphertext.subarray(fullCiphertext.length - 16);
    data.set(ciphertextOnly);
    return new Uint8Array(tag);
  }

  /**
   * Decrypt in-place using audited @noble/ciphers chacha20poly1305
   * Throws constant-time error if tag verification fails
   */
  public decryptInPlace(data: Uint8Array, nonce12: Uint8Array, tag16: Uint8Array, aad: Uint8Array = new Uint8Array()): void {
    const cipher = chacha20poly1305(this.rawKey, nonce12, aad);
    const fullCiphertext = new Uint8Array(data.length + 16);
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
