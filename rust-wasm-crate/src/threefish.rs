//! Threefish-1024 Block Cipher Implementation in CTR Mode
//! Complies with the Skein/Threefish specification.
//! Block size: 1024 bits (128 bytes, 16 x u64 words)
//! Key size: 1024 bits (expanded from 256-bit input key)
//! Tweak size: 128 bits (2 x u64 words)
//! Rounds: 80

use zeroize::Zeroize;

pub const BLOCK_SIZE: usize = 128; // 1024 bits = 128 bytes
pub const ROUNDS: usize = 80;
const C240: u64 = 0x1BD11BDAA9FC1A22; // Parity constant

// Threefish-1024 rotation constants (d=0..7) for 8 MIX functions
const ROTATION_CONSTANTS: [[u32; 8]; 8] = [
    [24, 13, 8, 47, 8, 17, 22, 37],
    [38, 19, 10, 55, 49, 18, 23, 52],
    [33, 4, 51, 13, 34, 41, 59, 17],
    [5, 20, 48, 41, 47, 28, 16, 25],
    [41, 9, 37, 31, 12, 47, 44, 30],
    [16, 34, 56, 51, 4, 53, 42, 41],
    [31, 44, 47, 46, 19, 42, 44, 25],
    [9, 48, 35, 52, 23, 31, 37, 20],
];

// Permutation table for 16 words
const PERMUTATION: [usize; 16] = [0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1];

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Threefish1024 {
    subkeys: [[u64; 16]; 21], // 21 subkeys (every 4 rounds: round 0, 4, ..., 80)
}

impl Threefish1024 {
    /// Initialize Threefish-1024 with a 32-byte key (expanded to 128 bytes) and 16-byte tweak
    pub fn new(key32: &[u8; 32], tweak16: &[u8; 16]) -> Self {
        use sha2::{Digest, Sha512};

        // Expand 32-byte seed key into 128-byte key (16 x u64) via SHA-512 expansion
        let mut hasher1 = Sha512::new();
        hasher1.update(b"THREEFISH-1024-KEY-EXPANSION-PART-1");
        hasher1.update(key32);
        let hash1 = hasher1.finalize();

        let mut hasher2 = Sha512::new();
        hasher2.update(b"THREEFISH-1024-KEY-EXPANSION-PART-2");
        hasher2.update(key32);
        let hash2 = hasher2.finalize();

        let mut k = [0u64; 17];
        for i in 0..8 {
            let offset = i * 8;
            k[i] = u64::from_le_bytes(hash1[offset..offset + 8].try_into().unwrap());
            k[i + 8] = u64::from_le_bytes(hash2[offset..offset + 8].try_into().unwrap());
        }

        // Parity word: k[16] = C240 ^ k[0] ^ ... ^ k[15]
        let mut parity = C240;
        for i in 0..16 {
            parity ^= k[i];
        }
        k[16] = parity;

        // Tweak schedule: t[0], t[1], t[2] = t[0] ^ t[1]
        let mut t = [0u64; 3];
        t[0] = u64::from_le_bytes(tweak16[0..8].try_into().unwrap());
        t[1] = u64::from_le_bytes(tweak16[8..16].try_into().unwrap());
        t[2] = t[0] ^ t[1];

        // Precompute subkeys: s = 0..20
        let mut subkeys = [[0u64; 16]; 21];
        for s in 0..=20 {
            for i in 0..16 {
                let mut sk = k[(s + i) % 17];
                if i == 13 {
                    sk = sk.wrapping_add(t[s % 3]);
                } else if i == 14 {
                    sk = sk.wrapping_add(t[(s + 1) % 3]);
                } else if i == 15 {
                    sk = sk.wrapping_add(s as u64);
                }
                subkeys[s][i] = sk;
            }
        }

        Threefish1024 { subkeys }
    }

    /// Encrypt a single 128-byte block
    pub fn encrypt_block(&self, block: &mut [u8; 128]) {
        let mut v = [0u64; 16];
        for i in 0..16 {
            let offset = i * 8;
            v[i] = u64::from_le_bytes(block[offset..offset + 8].try_into().unwrap());
        }

        for d in 0..ROUNDS {
            if d % 4 == 0 {
                let s = d / 4;
                for i in 0..16 {
                    v[i] = v[i].wrapping_add(self.subkeys[s][i]);
                }
            }

            // 8 parallel MIX functions
            let rot_row = d % 8;
            for j in 0..8 {
                let p = 2 * j;
                let q = p + 1;
                let r = ROTATION_CONSTANTS[rot_row][j];
                v[p] = v[p].wrapping_add(v[q]);
                v[q] = v[q].rotate_left(r) ^ v[p];
            }

            // Permutation
            let mut v_next = [0u64; 16];
            for i in 0..16 {
                v_next[PERMUTATION[i]] = v[i];
            }
            v = v_next;
        }

        // Final subkey addition
        for i in 0..16 {
            v[i] = v[i].wrapping_add(self.subkeys[20][i]);
            let offset = i * 8;
            block[offset..offset + 8].copy_from_slice(&v[i].to_le_bytes());
        }
    }

    /// Process chunk in CTR mode (constant memory, in-place XOR)
    pub fn apply_ctr(&self, base_nonce: &[u8; 16], chunk_index: u64, data: &mut [u8]) {
        let mut counter = (chunk_index as u128) * ((data.len() + BLOCK_SIZE - 1) / BLOCK_SIZE) as u128;
        let mut keystream_block = [0u8; BLOCK_SIZE];

        let mut offset = 0;
        while offset < data.len() {
            // Build CTR block: 16-byte base nonce + 16-byte counter + 96 bytes zero
            keystream_block.fill(0);
            keystream_block[0..16].copy_from_slice(base_nonce);
            keystream_block[16..32].copy_from_slice(&counter.to_le_bytes());

            self.encrypt_block(&mut keystream_block);

            let to_xor = std::cmp::min(BLOCK_SIZE, data.len() - offset);
            for i in 0..to_xor {
                data[offset + i] ^= keystream_block[i];
            }

            offset += to_xor;
            counter += 1;
        }

        keystream_block.zeroize();
    }
}
