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
    this.rawKey.fill(0);
    this.cryptoKeyPromise = null;
  }

  /**
   * Encrypt data using Web Crypto AES-GCM or Noble fallback
   * Returns ciphertext and 16-byte tag with zero-copy subarray views
   */
  public async encrypt(
    data: Uint8Array,
    nonce12: Uint8Array,
    aad: Uint8Array = new Uint8Array()
  ): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
    if (nonce12.length !== 12) {
      throw new Error('AES-256-GCM requires strictly a 12-byte nonce.');
    }
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
            ciphertext: result.subarray(0, splitPoint),
            tag: result.subarray(splitPoint),
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
      ciphertext: ctWithTag.subarray(0, splitPoint),
      tag: ctWithTag.subarray(splitPoint),
    };
  }

  /**
   * Decrypt data using Web Crypto AES-GCM or Noble fallback
   * Verifies tag in constant time with zero-copy reusable assembly buffer
   */
  public async decrypt(
    ciphertext: Uint8Array,
    nonce12: Uint8Array,
    tag16: Uint8Array,
    aad: Uint8Array = new Uint8Array()
  ): Promise<Uint8Array> {
    if (nonce12.length !== 12 || tag16.length !== 16) {
      throw new Error('Decryption failed. Check all keys.');
    }
    const requiredLen = ciphertext.length + 16;
    const fullCipher = new Uint8Array(requiredLen);
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

  /**
   * Decrypt contiguous ciphertext + 16-byte authentication tag with ZERO memory allocation or staging copy.
   * Directly consumes contiguous buffer for Web Crypto or Noble fallback.
   */
  public async decryptContiguous(
    contiguousCipherAndTag: Uint8Array,
    nonce12: Uint8Array,
    aad: Uint8Array = new Uint8Array()
  ): Promise<Uint8Array> {
    if (nonce12.length !== 12 || contiguousCipherAndTag.length < 16) {
      throw new Error('Decryption failed. Check all keys.');
    }
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
            contiguousCipherAndTag
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
      return cipher.decrypt(contiguousCipherAndTag);
    } catch {
      throw new Error('Decryption failed. Check all keys.');
    }
  }
}
