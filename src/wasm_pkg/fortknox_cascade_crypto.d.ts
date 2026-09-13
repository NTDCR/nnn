/* tslint:disable */
/* eslint-disable */

export class CascadeEngine {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Cascade Decrypt Chunk:
     * Encrypted Chunk -> AES-256-GCM -> ChaCha20-Poly1305 -> Serpent-256-CTR -> Threefish-1024-CTR
     */
    decrypt_chunk(chunk_data: Uint8Array, chunk_index: bigint, nonce_tf: Uint8Array, nonce_sp: Uint8Array, nonce_cc: Uint8Array, nonce_ae: Uint8Array, tag_cc: Uint8Array, tag_ae: Uint8Array): void;
    /**
     * Cascade Encrypt Chunk (In-Place / zero RAM copy):
     * Chunk -> Threefish-1024-CTR -> Serpent-256-CTR -> ChaCha20-Poly1305 -> AES-256-GCM
     * Returns 32 bytes of concatenated authentication tags [tag_chacha (16B), tag_aes (16B)]
     */
    encrypt_chunk(chunk_data: Uint8Array, chunk_index: bigint, nonce_tf: Uint8Array, nonce_sp: Uint8Array, nonce_cc: Uint8Array, nonce_ae: Uint8Array): Uint8Array;
    /**
     * Initialize all 4 cipher layers from 4 independent 32-byte keys
     */
    constructor(key1: Uint8Array, key2: Uint8Array, key3: Uint8Array, key4: Uint8Array);
}

/**
 * Standalone Layer Decrypt
 */
export function decrypt_layer(layer_idx: number, chunk: Uint8Array, key: Uint8Array, nonce: Uint8Array): Uint8Array;

/**
 * Standalone Layer Encrypt (for individual testing or benchmarking)
 */
export function encrypt_layer(layer_idx: number, chunk: Uint8Array, key: Uint8Array, nonce: Uint8Array): Uint8Array;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_cascadeengine_free: (a: number, b: number) => void;
    readonly cascadeengine_decrypt_chunk: (a: number, b: number, c: number, d: any, e: bigint, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number) => [number, number];
    readonly cascadeengine_encrypt_chunk: (a: number, b: number, c: number, d: any, e: bigint, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number) => [number, number, number, number];
    readonly cascadeengine_new: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly decrypt_layer: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly encrypt_layer: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
