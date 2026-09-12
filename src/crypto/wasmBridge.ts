/**
 * WebAssembly Bridge for Fort-Knox Cascade
 * Executes 4-layer cryptographic cascade in high-performance WebAssembly
 * powered by audited RustCrypto crates:
 * - Threefish-1024 (threefish 0.6.0)
 * - Serpent-256 (serpent 0.4.0)
 * - ChaCha20-Poly1305 (chacha20poly1305 0.10.1 - NCC Group audited)
 * - AES-256-GCM (aes-gcm 0.10.3 - NCC Group audited)
 */

import initWasm, {
  CascadeEngine as WasmCascadeEngine,
  encrypt_layer as wasmEncryptLayer,
  decrypt_layer as wasmDecryptLayer
} from '../wasm_pkg/fortknox_cascade_crypto.js';
import { CascadePipeline, hexToBytes, GENERIC_DECRYPT_ERROR } from './cascade.ts';

const WASM_PUBLIC_URL = new URL('../wasm_pkg/fortknox_cascade_crypto_bg.wasm', import.meta.url).href;

export interface WasmCascadeInstance {
  isWasmAccelerated: boolean;
  engineType: 'WASM (RustCrypto)' | 'TypeScript Fallback';
  encryptChunk(
    chunk: Uint8Array,
    index: number,
    n1: Uint8Array,
    n2: Uint8Array,
    n3: Uint8Array,
    n4: Uint8Array
  ): Promise<{ ciphertext: Uint8Array; tagChaCha: Uint8Array; tagAes: Uint8Array }>;
  decryptChunk(
    chunk: Uint8Array,
    index: number,
    n1: Uint8Array,
    n2: Uint8Array,
    n3: Uint8Array,
    n4: Uint8Array,
    tagChaCha: Uint8Array,
    tagAes: Uint8Array
  ): Promise<Uint8Array>;
}

let wasmInitPromise: Promise<boolean> | null = null;
let isWasmLoaded = false;

/**
 * Initialize WebAssembly module (singleton)
 */
async function ensureWasmLoaded(): Promise<boolean> {
  if (isWasmLoaded) return true;
  if (wasmInitPromise) return wasmInitPromise;

  wasmInitPromise = (async () => {
    try {
      // Node.js environment support for CLI and unit tests
      if (typeof window === 'undefined' && typeof process !== 'undefined') {
        try {
          const dynamicImport = new Function('specifier', 'return import(specifier)');
          const fs = await dynamicImport('fs');
          const path = await dynamicImport('path');
          const wasmPath = path.resolve(process.cwd(), 'src/wasm_pkg/fortknox_cascade_crypto_bg.wasm');
          if (fs.existsSync(wasmPath)) {
            const buffer = fs.readFileSync(wasmPath);
            await initWasm({ module_or_path: buffer });
            isWasmLoaded = true;
            return true;
          }
        } catch {
          // Ignore in non-Node environments
        }
      }

      // Browser environment: fetch WASM binary from public directory
      await initWasm({ module_or_path: WASM_PUBLIC_URL });
      isWasmLoaded = true;
      return true;
    } catch (err) {
      console.warn('WASM initialization fallback to pure TypeScript:', err);
      isWasmLoaded = false;
      return false;
    }
  })();

  return wasmInitPromise;
}

/**
 * Creates an instance of the 4-layer cascade engine.
 * Prefers native WebAssembly (RustCrypto audited libraries) with graceful TS fallback.
 */
export async function createCascadeEngine(
  k1Input: string | Uint8Array,
  k2Input: string | Uint8Array,
  k3Input: string | Uint8Array,
  k4Input: string | Uint8Array
): Promise<WasmCascadeInstance> {
  const k1 = typeof k1Input === 'string' ? hexToBytes(k1Input) : k1Input;
  const k2 = typeof k2Input === 'string' ? hexToBytes(k2Input) : k2Input;
  const k3 = typeof k3Input === 'string' ? hexToBytes(k3Input) : k3Input;
  const k4 = typeof k4Input === 'string' ? hexToBytes(k4Input) : k4Input;

  const wasmReady = await ensureWasmLoaded();

  if (wasmReady) {
    try {
      const wasmEngine = new WasmCascadeEngine(k1, k2, k3, k4);

      return {
        isWasmAccelerated: true,
        engineType: 'WASM (RustCrypto)',
        async encryptChunk(chunk, index, n1, n2, n3, n4) {
          // Copy input to mutate in-place in WASM linear memory
          const work = new Uint8Array(chunk);
          const tags = wasmEngine.encrypt_chunk(
            work,
            BigInt(index),
            n1,
            n2,
            n3,
            n4
          );
          return {
            ciphertext: work,
            tagChaCha: tags.slice(0, 16),
            tagAes: tags.slice(16, 32),
          };
        },
        async decryptChunk(chunk, index, n1, n2, n3, n4, tChaCha, tAes) {
          try {
            const work = new Uint8Array(chunk);
            wasmEngine.decrypt_chunk(
              work,
              BigInt(index),
              n1,
              n2,
              n3,
              n4,
              tChaCha,
              tAes
            );
            return work;
          } catch {
            throw new Error(GENERIC_DECRYPT_ERROR);
          }
        },
      };
    } catch (e) {
      console.warn('WasmCascadeEngine init failed, falling back:', e);
    }
  }

  // Fallback to pure TypeScript pipeline
  const pipeline = new CascadePipeline(k1, k2, k3, k4);

  return {
    isWasmAccelerated: false,
    engineType: 'TypeScript Fallback',
    async encryptChunk(chunk, index, n1, n2, n3, n4) {
      return pipeline.encryptChunk(chunk, index, n1, n2, n3, n4);
    },
    async decryptChunk(chunk, index, n1, n2, n3, n4, tChaCha, tAes) {
      return pipeline.decryptChunk(chunk, index, n1, n2, n3, n4, tChaCha, tAes);
    },
  };
}

/**
 * Execute standalone Threefish-1024 or Serpent-256 layer in WASM
 */
export async function executeWasmLayer(
  layerIdx: 1 | 2 | 3 | 4,
  mode: 'encrypt' | 'decrypt',
  data: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array
): Promise<Uint8Array> {
  await ensureWasmLoaded();
  if (mode === 'encrypt') {
    return wasmEncryptLayer(layerIdx, data, key, nonce);
  } else {
    return wasmDecryptLayer(layerIdx, data, key, nonce);
  }
}

