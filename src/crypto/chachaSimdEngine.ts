/**
 * WebAssembly SIMD128 ChaCha20-Poly1305 Engine
 * Executes ChaCha20 256-bit stream cipher with 128-bit SIMD vectorization (v128 / i32x4)
 * RFC 8439 compliant with audited Poly1305 constant-time AEAD verification.
 */

import { CHACHA_SIMD_BASE64 } from './chachaSimdBinary.ts';
import { _poly1305_aead } from '@noble/ciphers/chacha.js';

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

const BASE_OFFSET = 65536;
const KEY_OFFSET = BASE_OFFSET;
const NONCE_OFFSET = BASE_OFFSET + 32;
const DATA_OFFSET = BASE_OFFSET + 1024;

export class ChaChaSimdEngine {
  private memory: WebAssembly.Memory;
  private exports: {
    initChaCha: (keyPtr: number, noncePtr: number) => void;
    processChaChaCtr: (dataPtr: number, dataLen: number, startCounter: number) => void;
    memory: WebAssembly.Memory;
  };
  private aeadFactory: ReturnType<typeof _poly1305_aead>;
  private rawKey: Uint8Array;

  private constructor(wasmInstance: WebAssembly.Instance, rawKey: Uint8Array) {
    this.exports = wasmInstance.exports as unknown as ChaChaSimdEngine['exports'];
    this.memory = this.exports.memory;
    this.rawKey = new Uint8Array(rawKey);

    const xorStream = (key: Uint8Array, nonce: Uint8Array, data: Uint8Array, output?: Uint8Array, counter: number = 0) => {
      const len = data.length;
      const requiredBytes = DATA_OFFSET + len + 128;
      this.ensureCapacity(requiredBytes);

      const memU8 = new Uint8Array(this.memory.buffer);
      memU8.set(key, KEY_OFFSET);
      memU8.set(nonce, NONCE_OFFSET);
      this.exports.initChaCha(KEY_OFFSET, NONCE_OFFSET);

      memU8.set(data, DATA_OFFSET);
      this.exports.processChaChaCtr(DATA_OFFSET, len, counter >>> 0);

      const result = memU8.subarray(DATA_OFFSET, DATA_OFFSET + len);
      if (output) {
        output.set(result);
        return output;
      }
      return new Uint8Array(result);
    };

    this.aeadFactory = _poly1305_aead(xorStream as any);
  }

  public static create(keyBytes: Uint8Array): ChaChaSimdEngine | null {
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
      const additionalPages = Math.ceil((requiredBytes - currentBytes) / 65536) + 2;
      this.memory.grow(additionalPages);
    }
  }

  public getCipher(nonce: Uint8Array, aad?: Uint8Array) {
    return this.aeadFactory(this.rawKey, nonce, aad);
  }

  public destroy(): void {
    try {
      const memU8 = new Uint8Array(this.memory.buffer);
      memU8.fill(0, BASE_OFFSET, DATA_OFFSET + 1024);
      this.rawKey.fill(0);
    } catch {
      // Ignore cleanup error
    }
  }
}
