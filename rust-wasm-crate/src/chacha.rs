//! ChaCha20-Poly1305 AEAD (RFC 8439)
//! High-performance, constant-time authenticated encryption using RustCrypto.

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce, Tag,
};
use subtle::ConstantTimeEq;

pub struct ChaCha20Aead {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Aead {
    pub fn new(key: &[u8; 32]) -> Self {
        let k = Key::from_slice(key);
        let cipher = ChaCha20Poly1305::new(k);
        ChaCha20Aead { cipher }
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

    /// Encrypt data in-place and return 16-byte Poly1305 authentication tag
    pub fn encrypt_in_place(&self, nonce12: &[u8; 12], data: &mut [u8], aad: &[u8]) -> Result<[u8; 16], String> {
        let n = Nonce::from_slice(nonce12);
        let tag = self.cipher.encrypt_in_place_detached(n, aad, data)
            .map_err(|_| "ChaCha20-Poly1305 encryption failed".to_string())?;
        
        let mut tag_bytes = [0u8; 16];
        tag_bytes.copy_from_slice(tag.as_slice());
        Ok(tag_bytes)
    }

    /// Decrypt data in-place and verify 16-byte Poly1305 tag in constant time
    pub fn decrypt_in_place(&self, nonce12: &[u8; 12], data: &mut [u8], tag16: &[u8; 16], aad: &[u8]) -> Result<(), String> {
        let n = Nonce::from_slice(nonce12);
        let t = Tag::from_slice(tag16);
        self.cipher.decrypt_in_place_detached(n, aad, data, t)
            .map_err(|_| "Decryption failed. Check all keys.".to_string())
    }
}
