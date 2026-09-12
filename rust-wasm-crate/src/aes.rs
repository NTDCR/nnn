//! AES-256-GCM AEAD (NIST SP 800-38D)
//! Outermost encryption envelope with 128-bit GHASH authentication tag.

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Key, Nonce, Tag,
};
use subtle::ConstantTimeEq;

pub struct Aes256GcmAead {
    cipher: Aes256Gcm,
}

impl Aes256GcmAead {
    pub fn new(key: &[u8; 32]) -> Self {
        let k = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(k);
        Aes256GcmAead { cipher }
    }

    /// Derive per-chunk 12-byte nonce: base_nonce XOR chunk_index
    pub fn derive_chunk_nonce(base_nonce: &[u8; 12], chunk_index: u64) -> [u8; 12] {
        let mut nonce = *base_nonce;
        let index_bytes = chunk_index.to_le_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= index_bytes[i];
        }
        nonce
    }

    /// Encrypt data in-place and return 16-byte GCM authentication tag
    pub fn encrypt_in_place(&self, nonce12: &[u8; 12], data: &mut [u8], aad: &[u8]) -> Result<[u8; 16], String> {
        let n = Nonce::from_slice(nonce12);
        let tag = self.cipher.encrypt_in_place_detached(n, aad, data)
            .map_err(|_| "AES-256-GCM encryption failed".to_string())?;
        
        let mut tag_bytes = [0u8; 16];
        tag_bytes.copy_from_slice(tag.as_slice());
        Ok(tag_bytes)
    }

    /// Decrypt data in-place and verify 16-byte GCM tag in constant time
    pub fn decrypt_in_place(&self, nonce12: &[u8; 12], data: &mut [u8], tag16: &[u8; 16], aad: &[u8]) -> Result<(), String> {
        let n = Nonce::from_slice(nonce12);
        let t = Tag::from_slice(tag16);
        self.cipher.decrypt_in_place_detached(n, aad, data, t)
            .map_err(|_| "Decryption failed. Check all keys.".to_string())
    }
}
