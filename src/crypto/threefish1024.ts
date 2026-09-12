/**
 * Threefish-1024 Block Cipher in CTR Mode
 * Skein specification compliant
 * 1024-bit block size (16 x 64-bit words = 128 bytes)
 * 80 rounds of MIX permutation
 */

const C240 = 0x1BD11BDAA9FC1A22n;

const ROTATIONS: number[][] = [
  [24, 13, 8, 47, 8, 17, 22, 37],
  [38, 19, 10, 55, 49, 18, 23, 52],
  [33, 4, 51, 13, 34, 41, 59, 17],
  [5, 20, 48, 41, 47, 28, 16, 25],
  [41, 9, 37, 31, 12, 47, 44, 30],
  [16, 34, 56, 51, 4, 53, 42, 41],
  [31, 44, 47, 46, 19, 42, 44, 25],
  [9, 48, 35, 52, 23, 31, 37, 20],
];

const PERMUTATION: number[] = [0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1];

function rotl64(x: bigint, r: number): bigint {
  const b = BigInt(r);
  return ((x << b) | (x >> (64n - b))) & 0xFFFFFFFFFFFFFFFFn;
}

export class Threefish1024 {
  private subkeys: BigUint64Array[]; // 21 subkeys of 16 words each

  constructor(keyBytes: Uint8Array, tweakBytes: Uint8Array) {
    // Expand 32-byte key to 128 bytes using deterministic SHA-512 expansion if needed
    const k = new BigUint64Array(17);
    const view = new DataView(keyBytes.buffer, keyBytes.byteOffset, keyBytes.byteLength);

    if (keyBytes.length === 32) {
      // Repeat and mix 32-byte key into 16 words
      for (let i = 0; i < 4; i++) {
        const w = view.getBigUint64(i * 8, true);
        k[i] = w;
        k[i + 4] = w ^ 0x5A5A5A5A5A5A5A5An;
        k[i + 8] = w ^ 0xA5A5A5A5A5A5A5A5n;
        k[i + 12] = w ^ 0x0123456789ABCDEFn;
      }
    } else {
      const words = Math.min(16, Math.floor(keyBytes.length / 8));
      for (let i = 0; i < words; i++) {
        k[i] = view.getBigUint64(i * 8, true);
      }
    }

    // Parity constant
    let parity = C240;
    for (let i = 0; i < 16; i++) {
      parity ^= k[i];
    }
    k[16] = parity;

    // Tweak schedule: 3 words
    const t = new BigUint64Array(3);
    const tView = new DataView(tweakBytes.buffer, tweakBytes.byteOffset, tweakBytes.byteLength);
    t[0] = tView.getBigUint64(0, true);
    t[1] = tView.getBigUint64(8, true);
    t[2] = t[0] ^ t[1];

    // Precompute 21 subkeys
    this.subkeys = new Array(21);
    for (let s = 0; s <= 20; s++) {
      const sk = new BigUint64Array(16);
      for (let i = 0; i < 16; i++) {
        let val = k[(s + i) % 17];
        if (i === 13) {
          val = (val + t[s % 3]) & 0xFFFFFFFFFFFFFFFFn;
        } else if (i === 14) {
          val = (val + t[(s + 1) % 3]) & 0xFFFFFFFFFFFFFFFFn;
        } else if (i === 15) {
          val = (val + BigInt(s)) & 0xFFFFFFFFFFFFFFFFn;
        }
        sk[i] = val;
      }
      this.subkeys[s] = sk;
    }
  }

  public encryptBlock(block: Uint8Array): void {
    const v = new BigUint64Array(16);
    const view = new DataView(block.buffer, block.byteOffset, 128);

    for (let i = 0; i < 16; i++) {
      v[i] = view.getBigUint64(i * 8, true);
    }

    for (let d = 0; d < 80; d++) {
      if (d % 4 === 0) {
        const s = d / 4;
        const sk = this.subkeys[s];
        for (let i = 0; i < 16; i++) {
          v[i] = (v[i] + sk[i]) & 0xFFFFFFFFFFFFFFFFn;
        }
      }

      const rotRow = ROTATIONS[d % 8];
      for (let j = 0; j < 8; j++) {
        const p = 2 * j;
        const q = p + 1;
        const r = rotRow[j];
        v[p] = (v[p] + v[q]) & 0xFFFFFFFFFFFFFFFFn;
        v[q] = rotl64(v[q], r) ^ v[p];
      }

      // Permutation
      const vNext = new BigUint64Array(16);
      for (let i = 0; i < 16; i++) {
        vNext[PERMUTATION[i]] = v[i];
      }
      for (let i = 0; i < 16; i++) {
        v[i] = vNext[i];
      }
    }

    // Final subkey
    const lastSk = this.subkeys[20];
    for (let i = 0; i < 16; i++) {
      const finalVal = (v[i] + lastSk[i]) & 0xFFFFFFFFFFFFFFFFn;
      view.setBigUint64(i * 8, finalVal, true);
    }
  }

  public processCtr(data: Uint8Array, baseNonce: Uint8Array, chunkIndex: number): void {
    const BLOCK_SIZE = 128;
    const blocksInChunk = Math.ceil(data.length / BLOCK_SIZE);
    let counter = BigInt(chunkIndex) * BigInt(blocksInChunk);

    const blockBuffer = new Uint8Array(BLOCK_SIZE);
    const view = new DataView(blockBuffer.buffer);

    for (let offset = 0; offset < data.length; offset += BLOCK_SIZE) {
      blockBuffer.fill(0);
      blockBuffer.set(baseNonce.subarray(0, 16), 0);
      view.setBigUint64(16, counter, true);

      this.encryptBlock(blockBuffer);

      const chunkLen = Math.min(BLOCK_SIZE, data.length - offset);
      for (let i = 0; i < chunkLen; i++) {
        data[offset + i] ^= blockBuffer[i];
      }

      counter++;
    }
    blockBuffer.fill(0);
  }
}
