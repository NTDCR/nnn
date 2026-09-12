/**
 * AES-256-GCM AEAD (NIST SP 800-38D)
 * Hardware-accelerated (AES-NI / ARMv8 Crypto) via Web Crypto Subtle API
 * Provides Galois/Counter Mode authentication tag
 */

export class Aes256Gcm {
  private cryptoKeyPromise: Promise<CryptoKey>;
  private rawKey: Uint8Array;

  constructor(keyBytes: Uint8Array) {
    if (keyBytes.length !== 32) {
      throw new Error('AES-256-GCM key must be 32 bytes');
    }
    this.rawKey = new Uint8Array(keyBytes);
    this.cryptoKeyPromise = crypto.subtle.importKey(
      'raw',
      this.rawKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
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
  }

  /**
   * Encrypt data using Web Crypto AES-GCM
   * Returns ciphertext and 16-byte tag
   */
  public async encrypt(
    data: Uint8Array,
    nonce12: Uint8Array,
    aad: Uint8Array = new Uint8Array()
  ): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
    const key = await this.cryptoKeyPromise;
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
    const ciphertext = result.subarray(0, splitPoint);
    const tag = result.subarray(splitPoint);

    return { ciphertext: new Uint8Array(ciphertext), tag: new Uint8Array(tag) };
  }

  /**
   * Decrypt data using Web Crypto AES-GCM
   * Verifies tag in constant time
   */
  public async decrypt(
    ciphertext: Uint8Array,
    nonce12: Uint8Array,
    tag16: Uint8Array,
    aad: Uint8Array = new Uint8Array()
  ): Promise<Uint8Array> {
    const key = await this.cryptoKeyPromise;

    // Concatenate ciphertext and tag for WebCrypto decrypt
    const fullCipher = new Uint8Array(ciphertext.length + 16);
    fullCipher.set(ciphertext, 0);
    fullCipher.set(tag16, ciphertext.length);

    try {
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
    } catch {
      throw new Error('Decryption failed. Check all keys.');
    }
  }
}
