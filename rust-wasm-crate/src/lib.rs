//! Fort-Knox Cascade Cryptography Core - WebAssembly Bindings
//!
//! Exposes 4-layer cryptographic cascade:
//! Layer 1 (innermost): Threefish-1024-CTR
//! Layer 2: Serpent-256-CTR
//! Layer 3: ChaCha20-Poly1305 AEAD
//! Layer 4 (outermost): AES-256-GCM AEAD
//!
//! Designed for zero-RAM chunk streaming (1 MB chunks).

pub mod aes;
pub mod chacha;
pub mod serpent;
pub mod threefish;

use aes::Aes256GcmAead;
use chacha::ChaCha20Aead;
use serpent::Serpent256Ctr;
use threefish::Threefish1024;

use wasm_bindgen::prelude::*;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const GENERIC_ERROR: &str = "Decryption failed. Check all keys.";

#[wasm_bindgen]
pub struct CascadeEngine {
    threefish: Threefish1024,
    serpent: Serpent256Ctr,
    chacha: ChaCha20Aead,
    aes: Aes256GcmAead,
}

#[wasm_bindgen]
impl CascadeEngine {
    /// Initialize all 4 cipher layers from 4 independent 32-byte keys
    #[wasm_bindgen(constructor)]
    pub fn new(key1: &[u8], key2: &[u8], key3: &[u8], key4: &[u8]) -> Result<CascadeEngine, JsValue> {
        if (key1.len() != 128 && key1.len() != 32) || key2.len() != 32 || key3.len() != 32 || key4.len() != 32 {
            return Err(JsValue::from_str("Layer 1 key must be 128 bytes (1024 bits) or 32 bytes; Layers 2-4 must be 32 bytes"));
        }

        let k2: &[u8; 32] = key2.try_into().unwrap();
        let k3: &[u8; 32] = key3.try_into().unwrap();
        let k4: &[u8; 32] = key4.try_into().unwrap();

        let tweak = [0x54, 0x68, 0x72, 0x65, 0x65, 0x66, 0x69, 0x73, 0x68, 0x54, 0x77, 0x65, 0x61, 0x6b, 0x31, 0x36];

        let threefish = if key1.len() == 128 {
            let k1_128: &[u8; 128] = key1.try_into().unwrap();
            Threefish1024::from_1024_bit_key(k1_128, &tweak)
        } else {
            let k1_32: &[u8; 32] = key1.try_into().unwrap();
            Threefish1024::new(k1_32, &tweak)
        };

        Ok(CascadeEngine {
            threefish,
            serpent: Serpent256Ctr::new(k2),
            chacha: ChaCha20Aead::new(k3),
            aes: Aes256GcmAead::new(k4),
        })
    }

    /// Cascade Encrypt Chunk (In-Place / zero RAM copy):
    /// Chunk -> Threefish-1024-CTR -> Serpent-256-CTR -> ChaCha20-Poly1305 -> AES-256-GCM
    /// Returns 32 bytes of concatenated authentication tags [tag_chacha (16B), tag_aes (16B)]
    pub fn encrypt_chunk(
        &self,
        chunk_data: &mut [u8],
        chunk_index: u64,
        nonce_tf: &[u8], // 16 bytes
        nonce_sp: &[u8], // 16 bytes
        nonce_cc: &[u8], // 12 bytes
        nonce_ae: &[u8], // 12 bytes
    ) -> Result<Vec<u8>, JsValue> {
        let n_tf: &[u8; 16] = nonce_tf.try_into().map_err(|_| "Invalid Threefish nonce")?;
        let n_sp: &[u8; 16] = nonce_sp.try_into().map_err(|_| "Invalid Serpent nonce")?;
        let n_cc: &[u8; 12] = nonce_cc.try_into().map_err(|_| "Invalid ChaCha nonce")?;
        let n_ae: &[u8; 12] = nonce_ae.try_into().map_err(|_| "Invalid AES nonce")?;

        // 1. Threefish-1024-CTR (innermost)
        self.threefish.apply_ctr(n_tf, chunk_index, chunk_data);

        // 2. Serpent-256-CTR
        self.serpent.apply_ctr(n_sp, chunk_index, chunk_data);

        // 3. ChaCha20-Poly1305 AEAD
        let cc_chunk_nonce = ChaCha20Aead::derive_chunk_nonce(n_cc, chunk_index);
        let aad = chunk_index.to_le_bytes();
        let tag_cc = self.chacha.encrypt_in_place(&cc_chunk_nonce, chunk_data, &aad)
            .map_err(|e| JsValue::from_str(&e))?;

        // 4. AES-256-GCM AEAD (outermost)
        let ae_chunk_nonce = Aes256GcmAead::derive_chunk_nonce(n_ae, chunk_index);
        let tag_ae = self.aes.encrypt_in_place(&ae_chunk_nonce, chunk_data, &aad)
            .map_err(|e| JsValue::from_str(&e))?;

        // Concatenate chunk tags: 16 bytes ChaCha + 16 bytes AES = 32 bytes
        let mut tags = Vec::with_capacity(32);
        tags.extend_from_slice(&tag_cc);
        tags.extend_from_slice(&tag_ae);
        Ok(tags)
    }

    /// Cascade Decrypt Chunk:
    /// Encrypted Chunk -> AES-256-GCM -> ChaCha20-Poly1305 -> Serpent-256-CTR -> Threefish-1024-CTR
    pub fn decrypt_chunk(
        &self,
        chunk_data: &mut [u8],
        chunk_index: u64,
        nonce_tf: &[u8],
        nonce_sp: &[u8],
        nonce_cc: &[u8],
        nonce_ae: &[u8],
        tag_cc: &[u8], // 16 bytes
        tag_ae: &[u8], // 16 bytes
    ) -> Result<(), JsValue> {
        let n_tf: &[u8; 16] = nonce_tf.try_into().map_err(|_| GENERIC_ERROR)?;
        let n_sp: &[u8; 16] = nonce_sp.try_into().map_err(|_| GENERIC_ERROR)?;
        let n_cc: &[u8; 12] = nonce_cc.try_into().map_err(|_| GENERIC_ERROR)?;
        let n_ae: &[u8; 12] = nonce_ae.try_into().map_err(|_| GENERIC_ERROR)?;
        let t_cc: &[u8; 16] = tag_cc.try_into().map_err(|_| GENERIC_ERROR)?;
        let t_ae: &[u8; 16] = tag_ae.try_into().map_err(|_| GENERIC_ERROR)?;

        let aad = chunk_index.to_le_bytes();

        // 1. AES-256-GCM (outermost decryption)
        let ae_chunk_nonce = Aes256GcmAead::derive_chunk_nonce(n_ae, chunk_index);
        self.aes.decrypt_in_place(&ae_chunk_nonce, chunk_data, t_ae, &aad)
            .map_err(|_| JsValue::from_str(GENERIC_ERROR))?;

        // 2. ChaCha20-Poly1305 AEAD
        let cc_chunk_nonce = ChaCha20Aead::derive_chunk_nonce(n_cc, chunk_index);
        self.chacha.decrypt_in_place(&cc_chunk_nonce, chunk_data, t_cc, &aad)
            .map_err(|_| JsValue::from_str(GENERIC_ERROR))?;

        // 3. Serpent-256-CTR
        self.serpent.apply_ctr(n_sp, chunk_index, chunk_data);

        // 4. Threefish-1024-CTR (innermost decryption)
        self.threefish.apply_ctr(n_tf, chunk_index, chunk_data);

        Ok(())
    }
}

/// Standalone Layer Encrypt (for individual testing or benchmarking)
#[wasm_bindgen]
pub fn encrypt_layer(layer_idx: u8, mut chunk: Vec<u8>, key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, JsValue> {
    match layer_idx {
        1 => {
            let tweak = [0x54, 0x68, 0x72, 0x65, 0x65, 0x66, 0x69, 0x73, 0x68, 0x54, 0x77, 0x65, 0x61, 0x6b, 0x31, 0x36];
            let tf = if key.len() == 128 {
                let k128: &[u8; 128] = key.try_into().unwrap();
                Threefish1024::from_1024_bit_key(k128, &tweak)
            } else if key.len() == 32 {
                let k32: &[u8; 32] = key.try_into().unwrap();
                Threefish1024::new(k32, &tweak)
            } else {
                return Err(JsValue::from_str("Threefish key must be 128 bytes or 32 bytes"));
            };
            let n: &[u8; 16] = nonce.try_into().map_err(|_| "Nonce must be 16 bytes for Threefish")?;
            tf.apply_ctr(n, 0, &mut chunk);
            Ok(chunk)
        }
        2 => {
            if key.len() != 32 { return Err(JsValue::from_str("Key must be 32 bytes")); }
            let k: &[u8; 32] = key.try_into().unwrap();
            let sp = Serpent256Ctr::new(k);
            let n: &[u8; 16] = nonce.try_into().map_err(|_| "Nonce must be 16 bytes for Serpent")?;
            sp.apply_ctr(n, 0, &mut chunk);
            Ok(chunk)
        }
        3 => {
            if key.len() != 32 { return Err(JsValue::from_str("Key must be 32 bytes")); }
            let k: &[u8; 32] = key.try_into().unwrap();
            let cc = ChaCha20Aead::new(k);
            let n: &[u8; 12] = nonce.try_into().map_err(|_| "Nonce must be 12 bytes for ChaCha20")?;
            let tag = cc.encrypt_in_place(n, &mut chunk, b"")
                .map_err(|e| JsValue::from_str(&e))?;
            chunk.extend_from_slice(&tag);
            Ok(chunk)
        }
        4 => {
            if key.len() != 32 { return Err(JsValue::from_str("Key must be 32 bytes")); }
            let k: &[u8; 32] = key.try_into().unwrap();
            let ae = Aes256GcmAead::new(k);
            let n: &[u8; 12] = nonce.try_into().map_err(|_| "Nonce must be 12 bytes for AES-GCM")?;
            let tag = ae.encrypt_in_place(n, &mut chunk, b"")
                .map_err(|e| JsValue::from_str(&e))?;
            chunk.extend_from_slice(&tag);
            Ok(chunk)
        }
        _ => Err(JsValue::from_str("Invalid layer index (1..4)")),
    }
}

/// Standalone Layer Decrypt
#[wasm_bindgen]
pub fn decrypt_layer(layer_idx: u8, mut chunk: Vec<u8>, key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, JsValue> {
    match layer_idx {
        1 => {
            let tweak = [0x54, 0x68, 0x72, 0x65, 0x65, 0x66, 0x69, 0x73, 0x68, 0x54, 0x77, 0x65, 0x61, 0x6b, 0x31, 0x36];
            let tf = if key.len() == 128 {
                let k128: &[u8; 128] = key.try_into().unwrap();
                Threefish1024::from_1024_bit_key(k128, &tweak)
            } else if key.len() == 32 {
                let k32: &[u8; 32] = key.try_into().unwrap();
                Threefish1024::new(k32, &tweak)
            } else {
                return Err(JsValue::from_str(GENERIC_ERROR));
            };
            let n: &[u8; 16] = nonce.try_into().map_err(|_| GENERIC_ERROR)?;
            tf.apply_ctr(n, 0, &mut chunk);
            Ok(chunk)
        }
        2 => {
            if key.len() != 32 { return Err(JsValue::from_str(GENERIC_ERROR)); }
            let k: &[u8; 32] = key.try_into().unwrap();
            let sp = Serpent256Ctr::new(k);
            let n: &[u8; 16] = nonce.try_into().map_err(|_| GENERIC_ERROR)?;
            sp.apply_ctr(n, 0, &mut chunk);
            Ok(chunk)
        }
        3 => {
            if chunk.len() < 16 {
                return Err(JsValue::from_str(GENERIC_ERROR));
            }
            let data_len = chunk.len() - 16;
            let tag: [u8; 16] = chunk[data_len..].try_into().unwrap();
            chunk.truncate(data_len);

            let cc = ChaCha20Aead::new(k);
            let n: &[u8; 12] = nonce.try_into().map_err(|_| GENERIC_ERROR)?;
            cc.decrypt_in_place(n, &mut chunk, &tag, b"")
                .map_err(|_| JsValue::from_str(GENERIC_ERROR))?;
            Ok(chunk)
        }
        4 => {
            if chunk.len() < 16 {
                return Err(JsValue::from_str(GENERIC_ERROR));
            }
            let data_len = chunk.len() - 16;
            let tag: [u8; 16] = chunk[data_len..].try_into().unwrap();
            chunk.truncate(data_len);

            let ae = Aes256GcmAead::new(k);
            let n: &[u8; 12] = nonce.try_into().map_err(|_| GENERIC_ERROR)?;
            ae.decrypt_in_place(n, &mut chunk, &tag, b"")
                .map_err(|_| JsValue::from_str(GENERIC_ERROR))?;
            Ok(chunk)
        }
        _ => Err(JsValue::from_str(GENERIC_ERROR)),
    }
}
