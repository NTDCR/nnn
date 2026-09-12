/**
 * AES-256-GCM AEAD (NIST SP 800-38D)
 * Hardware-accelerated (AES-NI / ARMv8 Crypto) via Web Crypto Subtle API
 * Provides Galois/Counter Mode authentication tag
 */

import { gcm } from '@noble/ciphers/aes.js';

export class Aes256Gcm {
  private cryptoKeyPromise: Promise<CryptoKey> | null = null;
  private rawKey: Uint8Array;

  constructor(keyBytes: Uint8Array) {
    if (keyBytes.length !== 32) {
      throw new Error('AES-256-GCM key must be 32 bytes');
    }
    this.rawKey = new Uint8Array(keyBytes);
    if (typeof crypto !== 'undefined' && crypto?.subtle && typeof crypto.subtle.importKey === 'function') {
      this.cryptoKeyPromise = crypto.subtle.importKey(
        'raw',
        this.rawKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      ).catch(() => null);
    }
  }

  public deriveChunkNonce(baseNonce: Uint8Array, chunkIndex: number): Uint8Array {
    if (baseNonce.length < 12) {
      throw new Error('AES-256-GCM base nonce must be at least 12 bytes');
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
    this.cryptoKeyPromise = null;
  }

  /**
   * Encrypt data using Web Crypto AES-GCM or Noble fallback
   * Returns ciphertext and 16-byte tag
   */
  public async encrypt(
    data: Uint8Array,
    nonce12: Uint8Array,
    aad: Uint8Array = new Uint8Array()
  ): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
    if (this.cryptoKeyPromise) {
      try {
        const key = await this.cryptoKeyPromise;
        if (key && typeof crypto !== 'undefined' && crypto?.subtle) {
          const cipherBuffer = await crypto.subtle.encrypt(
            {
              name: 'AES-GCM',
              iv: nonce12,
              additionalData: aad,
              tagLength: 128,
            },
            key,
            data
          );
          const result = new Uint8Array(cipherBuffer);
          const splitPoint = result.length - 16;
          return {
            ciphertext: new Uint8Array(result.subarray(0, splitPoint)),
            tag: new Uint8Array(result.subarray(splitPoint)),
          };
        }
      } catch {
        // Fall through to Noble Ciphers fallback
      }
    }

    // Pure software AES-GCM fallback (Noble Ciphers)
    const cipher = gcm(this.rawKey, nonce12, aad);
    const ctWithTag = cipher.encrypt(data);
    const splitPoint = ctWithTag.length - 16;
    return {
      ciphertext: new Uint8Array(ctWithTag.subarray(0, splitPoint)),
      tag: new Uint8Array(ctWithTag.subarray(splitPoint)),
    };
  }

  /**
   * Decrypt data using Web Crypto AES-GCM or Noble fallback
   * Verifies tag in constant time
   */
  public async decrypt(
    ciphertext: Uint8Array,
    nonce12: Uint8Array,
    tag16: Uint8Array,
    aad: Uint8Array = new Uint8Array()
  ): Promise<Uint8Array> {
    const fullCipher = new Uint8Array(ciphertext.length + 16);
    fullCipher.set(ciphertext, 0);
    fullCipher.set(tag16, ciphertext.length);

    if (this.cryptoKeyPromise) {
      try {
        const key = await this.cryptoKeyPromise;
        if (key && typeof crypto !== 'undefined' && crypto?.subtle) {
          const plainBuffer = await crypto.subtle.decrypt(
            {
              name: 'AES-GCM',
              iv: nonce12,
              additionalData: aad,
              tagLength: 128,
            },
            key,
            fullCipher
          );
          return new Uint8Array(plainBuffer);
        }
      } catch {
        // Fall through to Noble Ciphers fallback
      }
    }

    // Pure software AES-GCM fallback (Noble Ciphers)
    try {
      const cipher = gcm(this.rawKey, nonce12, aad);
      return cipher.decrypt(fullCipher);
    } catch {
      throw new Error('Decryption failed. Check all keys.');
    }
  }
}
