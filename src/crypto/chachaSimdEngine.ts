/**
 * WebAssembly SIMD128 ChaCha20-Poly1305 AEAD Engine (RFC 8439)
 * Executes ChaCha20 256-bit stream cipher with 128-bit SIMD vectorization (v128 / i32x4)
 * and fused 64-bit Donna Poly1305 with constant-time MAC verification.
 * Zero-copy in-place execution for high-throughput single-core performance.
 */

import { CHACHA_SIMD_BASE64 } from './chachaSimdBinary.ts';

function base64ToUint8Array(base64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    const buf = Buffer.from(base64, 'base64');
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

let cachedModule: WebAssembly.Module | null = null;
let isSimdSupported: boolean | null = null;

function getWasmModule(): WebAssembly.Module | null {
  if (isSimdSupported === false) return null;
  if (cachedModule) return cachedModule;

  try {
    if (typeof WebAssembly === 'undefined' || !WebAssembly.validate) {
      isSimdSupported = false;
      return null;
    }
    const bytes = base64ToUint8Array(CHACHA_SIMD_BASE64);
    if (!WebAssembly.validate(bytes)) {
      isSimdSupported = false;
      return null;
    }
    cachedModule = new WebAssembly.Module(bytes);
    isSimdSupported = true;
    return cachedModule;
  } catch {
    isSimdSupported = false;
    return null;
  }
}

const BASE_OFFSET = 65536; // 64 KB offset (avoids runtime/static globals in first page)
const KEY_OFFSET = BASE_OFFSET; // 32 bytes
const NONCE_OFFSET = BASE_OFFSET + 32; // 12 bytes
const TAG_OFFSET = BASE_OFFSET + 48; // 16 bytes
const OTK_OFFSET = BASE_OFFSET + 64; // 32 bytes
const COMP_TAG_OFFSET = BASE_OFFSET + 96; // 16 bytes
const AAD_OFFSET = BASE_OFFSET + 128;

interface ChaChaPolyExports {
  initChaCha: (keyPtr: number, noncePtr: number) => void;
  processChaChaCtr: (dataPtr: number, dataLen: number, startCounter: number) => void;
  poly1305_init: (keyPtr: number) => void;
  poly1305_process_16: (w0: number, w1: number, w2: number, w3: number) => void;
  poly1305_update_blocks: (msgPtr: number, fullBlocksLen: number) => void;
  poly1305_process_partial_padded: (ptr: number, len: number) => void;
  poly1305_finish: (tagPtr: number, keyPtr: number) => void;
  encrypt_aead: (
    dataPtr: number,
    dataLen: number,
    aadPtr: number,
    aadLen: number,
    keyPtr: number,
    noncePtr: number,
    tagPtr: number,
    otkPtr: number
  ) => void;
  decrypt_aead: (
    dataPtr: number,
    dataLen: number,
    aadPtr: number,
    aadLen: number,
    keyPtr: number,
    noncePtr: number,
    tagPtr: number,
    otkPtr: number,
    compTagPtr: number
  ) => number;
  memory: WebAssembly.Memory;
}

export class ChaChaSimdEngine {
  private memory: WebAssembly.Memory;
  private exports: ChaChaPolyExports;
  private rawKey: Uint8Array;
  private isDestroyed = false;

  private constructor(wasmInstance: WebAssembly.Instance, rawKey: Uint8Array) {
    this.exports = wasmInstance.exports as unknown as ChaChaPolyExports;
    this.memory = this.exports.memory;
    this.rawKey = new Uint8Array(rawKey);

    // Pre-grow memory to 34 pages (~2.2 MB) to eliminate growth pauses on 1 MB chunks
    const curPages = this.memory.buffer.byteLength >>> 16;
    if (curPages < 34) {
      this.memory.grow(34 - curPages);
    }
  }

  public static create(keyBytes: Uint8Array): ChaChaSimdEngine | null {
    if (keyBytes.length !== 32) {
      return null;
    }
    try {
      const wasmModule = getWasmModule();
      if (!wasmModule) return null;

      const instance = new WebAssembly.Instance(wasmModule, {
        env: {
          abort: () => {
            throw new Error('WASM ChaCha SIMD aborted');
          },
        },
      });

      return new ChaChaSimdEngine(instance, keyBytes);
    } catch {
      return null;
    }
  }

  private ensureCapacity(requiredBytes: number): void {
    const currentBytes = this.memory.buffer.byteLength;
    if (currentBytes < requiredBytes) {
      const additionalPages = Math.ceil((requiredBytes - currentBytes) / 65536) + 4;
      this.memory.grow(additionalPages);
    }
  }

  /**
   * Encrypt data in-place using fused SIMD128 ChaCha20 and Poly1305
   * Mutates `data` directly and returns 16-byte Poly1305 authentication tag
   */
  public encryptInPlace(data: Uint8Array, nonce12: Uint8Array, aad: Uint8Array = new Uint8Array(0)): Uint8Array {
    if (this.isDestroyed) {
      throw new Error('ChaChaSimdEngine has been destroyed');
    }
    if (nonce12.length !== 12) {
      throw new Error('ChaCha20-Poly1305 nonce must be strictly 12 bytes');
    }
    const aadLen = aad.length;
    if (aadLen < 0 || !Number.isSafeInteger(aadLen) || aadLen > 65536) {
      throw new Error('Invalid AAD length');
    }
    const dataLen = data.length;
    const dataOffset = AAD_OFFSET + ((aadLen + 15) & ~15) + 64;
    const totalRequired = dataOffset + dataLen + 64;

    this.ensureCapacity(totalRequired);

    let memU8 = new Uint8Array(this.memory.buffer);
    memU8.set(this.rawKey, KEY_OFFSET);
    memU8.set(nonce12, NONCE_OFFSET);
    if (aadLen > 0) {
      memU8.set(aad, AAD_OFFSET);
    }
    memU8.set(data, dataOffset);

    try {
      this.exports.encrypt_aead(
        dataOffset,
        dataLen,
        AAD_OFFSET,
        aadLen,
        KEY_OFFSET,
        NONCE_OFFSET,
        TAG_OFFSET,
        OTK_OFFSET
      );

      memU8 = new Uint8Array(this.memory.buffer);
      data.set(memU8.subarray(dataOffset, dataOffset + dataLen));
      return new Uint8Array(memU8.subarray(TAG_OFFSET, TAG_OFFSET + 16));
    } finally {
      const scrub = new Uint8Array(this.memory.buffer);
      scrub.subarray(dataOffset, dataOffset + dataLen).fill(0);
      scrub.subarray(KEY_OFFSET, KEY_OFFSET + 32).fill(0);
      scrub.subarray(NONCE_OFFSET, NONCE_OFFSET + 12).fill(0);
      scrub.subarray(TAG_OFFSET, TAG_OFFSET + 16).fill(0);
      scrub.subarray(OTK_OFFSET, OTK_OFFSET + 32).fill(0);
      if (aadLen > 0) {
        scrub.subarray(AAD_OFFSET, AAD_OFFSET + aadLen).fill(0);
      }
    }
  }

  /**
   * Decrypt data in-place using fused SIMD128 ChaCha20 and constant-time Poly1305 verification
   * Mutates `data` directly to plaintext if and only if tag is 100% valid
   */
  public decryptInPlace(data: Uint8Array, nonce12: Uint8Array, tag16: Uint8Array, aad: Uint8Array = new Uint8Array(0)): void {
    if (this.isDestroyed) {
      throw new Error('ChaChaSimdEngine has been destroyed');
    }
    if (tag16.length !== 16 || nonce12.length !== 12) {
      throw new Error('Decryption failed. Check all keys.');
    }

    const aadLen = aad.length;
    if (aadLen < 0 || !Number.isSafeInteger(aadLen) || aadLen > 65536) {
      throw new Error('Invalid AAD length');
    }
    const dataLen = data.length;
    const dataOffset = AAD_OFFSET + ((aadLen + 15) & ~15) + 64;
    const totalRequired = dataOffset + dataLen + 64;

    this.ensureCapacity(totalRequired);

    let memU8 = new Uint8Array(this.memory.buffer);
    memU8.set(this.rawKey, KEY_OFFSET);
    memU8.set(nonce12, NONCE_OFFSET);
    memU8.set(tag16, TAG_OFFSET);
    if (aadLen > 0) {
      memU8.set(aad, AAD_OFFSET);
    }
    memU8.set(data, dataOffset);

    try {
      const res = this.exports.decrypt_aead(
        dataOffset,
        dataLen,
        AAD_OFFSET,
        aadLen,
        KEY_OFFSET,
        NONCE_OFFSET,
        TAG_OFFSET,
        OTK_OFFSET,
        COMP_TAG_OFFSET
      );

      if (res !== 0) {
        throw new Error('Decryption failed. Check all keys.');
      }

      memU8 = new Uint8Array(this.memory.buffer);
      data.set(memU8.subarray(dataOffset, dataOffset + dataLen));
    } finally {
      const scrub = new Uint8Array(this.memory.buffer);
      scrub.subarray(dataOffset, dataOffset + dataLen).fill(0);
      scrub.subarray(KEY_OFFSET, KEY_OFFSET + 32).fill(0);
      scrub.subarray(NONCE_OFFSET, NONCE_OFFSET + 12).fill(0);
      scrub.subarray(TAG_OFFSET, TAG_OFFSET + 16).fill(0);
      scrub.subarray(OTK_OFFSET, OTK_OFFSET + 32).fill(0);
      scrub.subarray(COMP_TAG_OFFSET, COMP_TAG_OFFSET + 16).fill(0);
      if (aadLen > 0) {
        scrub.subarray(AAD_OFFSET, AAD_OFFSET + aadLen).fill(0);
      }
    }
  }

  /**
   * Standard AEAD cipher interface compatible with @noble/ciphers
   */
  public getCipher(nonce: Uint8Array, aad?: Uint8Array) {
    const aadBytes = aad || new Uint8Array(0);

    return {
      encrypt: (plaintext: Uint8Array, output?: Uint8Array): Uint8Array => {
        const outLen = plaintext.length + 16;
        const outBuf = output && output.length >= outLen ? output.subarray(0, outLen) : new Uint8Array(outLen);
        outBuf.set(plaintext, 0);

        const workSub = outBuf.subarray(0, plaintext.length);
        const tag = this.encryptInPlace(workSub, nonce, aadBytes);
        outBuf.set(tag, plaintext.length);
        return outBuf;
      },

      decrypt: (ciphertextWithTag: Uint8Array, output?: Uint8Array): Uint8Array => {
        if (ciphertextWithTag.length < 16) {
          throw new Error('Decryption failed. Check all keys.');
        }
        const plainLen = ciphertextWithTag.length - 16;
        const outBuf = output && output.length >= plainLen ? output.subarray(0, plainLen) : new Uint8Array(plainLen);
        outBuf.set(ciphertextWithTag.subarray(0, plainLen));

        const tag16 = ciphertextWithTag.subarray(plainLen);
        this.decryptInPlace(outBuf, nonce, tag16, aadBytes);
        return outBuf;
      },
    };
  }

  public destroy(): void {
    this.isDestroyed = true;
    try {
      const memU8 = new Uint8Array(this.memory.buffer);
      memU8.fill(0);
      this.rawKey.fill(0);
    } catch {
      // Ignore cleanup error
    }
  }
}
