//! Serpent-256 Block Cipher Implementation in CTR Mode
//! 128-bit block size (16 bytes), 256-bit key size (32 bytes), 32 rounds
//! Complies with the NESSIE / AES finalist specification.

use serpent::cipher::{BlockEncrypt, NewBlockCipher};
use serpent::cipher::generic_array::GenericArray;
use serpent::Serpent;
use zeroize::Zeroize;

pub const BLOCK_SIZE: usize = 16; // 128 bits = 16 bytes

pub struct Serpent256Ctr {
    cipher: Serpent,
}

impl Serpent256Ctr {
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = Serpent::new_from_slice(key).expect("Valid 32-byte key");
        Serpent256Ctr { cipher }
    }

    /// Process chunk in CTR mode (constant memory, in-place XOR)
    pub fn apply_ctr(&self, base_nonce: &[u8; 16], chunk_index: u64, data: &mut [u8]) {
        let mut counter = (chunk_index as u128) * ((data.len() + BLOCK_SIZE - 1) / BLOCK_SIZE) as u128;
        let mut keystream_block = GenericArray::default();

        let mut offset = 0;
        while offset < data.len() {
            // Build CTR block: 8 bytes base_nonce + 8 bytes counter XOR chunk
            let mut ctr_bytes = [0u8; 16];
            ctr_bytes[0..8].copy_from_slice(&base_nonce[0..8]);
            let mixed_counter = counter ^ ((chunk_index as u128) << 64);
            ctr_bytes[8..16].copy_from_slice(&mixed_counter.to_le_bytes()[0..8]);

            keystream_block.copy_from_slice(&ctr_bytes);
            self.cipher.encrypt_block(&mut keystream_block);

            let to_xor = std::cmp::min(BLOCK_SIZE, data.len() - offset);
            for i in 0..to_xor {
                data[offset + i] ^= keystream_block[i];
            }

            offset += to_xor;
            counter += 1;
        }

        keystream_block.as_mut_slice().zeroize();
    }
}
