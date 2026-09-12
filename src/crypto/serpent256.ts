/**
 * Serpent-256 Block Cipher in CTR Mode
 * 128-bit block (16 bytes), 256-bit key (32 bytes), 32 rounds
 * NIST AES Finalist Specification
 */

// 8 S-Boxes for Serpent (4-bit nibbles)
const SBOX: number[][] = [
  [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],
  [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],
  [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],
  [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],
  [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],
  [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],
  [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],
  [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6],
];

const PHI = 0x9E3779B9; // Golden ratio constant for key schedule

function rotl32(x: number, r: number): number {
  return ((x << r) | (x >>> (32 - r))) >>> 0;
}

function applySboxBitslice(s: number[], r0: number, r1: number, r2: number, r3: number): [number, number, number, number] {
  let o0 = 0, o1 = 0, o2 = 0, o3 = 0;
  for (let bit = 0; bit < 32; bit++) {
    const inVal = ((r0 >>> bit) & 1) |
                  (((r1 >>> bit) & 1) << 1) |
                  (((r2 >>> bit) & 1) << 2) |
                  (((r3 >>> bit) & 1) << 3);
    const outVal = s[inVal];
    o0 |= (outVal & 1) << bit;
    o1 |= ((outVal >>> 1) & 1) << bit;
    o2 |= ((outVal >>> 2) & 1) << bit;
    o3 |= ((outVal >>> 3) & 1) << bit;
  }
  return [o0 >>> 0, o1 >>> 0, o2 >>> 0, o3 >>> 0];
}

export class Serpent256 {
  private subkeys: Uint32Array; // 33 subkeys of 4 words = 132 words

  constructor(keyBytes: Uint8Array) {
    if (keyBytes.length !== 32) {
      throw new Error('Serpent-256 requires exactly 32 bytes key');
    }

    const w = new Uint32Array(140);
    const keyView = new DataView(keyBytes.buffer, keyBytes.byteOffset, keyBytes.byteLength);

    // Load 8 32-bit words
    for (let i = 0; i < 8; i++) {
      w[i] = keyView.getUint32(i * 4, true);
    }

    // Key expansion
    for (let i = 8; i < 140; i++) {
      const temp = w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ (i - 8);
      w[i] = rotl32(temp, 11);
    }

    // Apply S-boxes in bit-slice format to generate 33 subkeys (132 words)
    this.subkeys = new Uint32Array(132);
    for (let i = 0; i < 33; i++) {
      const boxIdx = (32 + 3 - i) % 8;
      const baseIdx = 8 + i * 4;
      const [sk0, sk1, sk2, sk3] = applySboxBitslice(
        SBOX[boxIdx],
        w[baseIdx],
        w[baseIdx + 1],
        w[baseIdx + 2],
        w[baseIdx + 3]
      );
      this.subkeys[i * 4] = sk0;
      this.subkeys[i * 4 + 1] = sk1;
      this.subkeys[i * 4 + 2] = sk2;
      this.subkeys[i * 4 + 3] = sk3;
    }
  }

  public encryptBlock(block: Uint8Array): void {
    const view = new DataView(block.buffer, block.byteOffset, 16);
    let x0 = view.getUint32(0, true);
    let x1 = view.getUint32(4, true);
    let x2 = view.getUint32(8, true);
    let x3 = view.getUint32(12, true);

    for (let r = 0; r < 32; r++) {
      // Key mixing
      x0 ^= this.subkeys[r * 4];
      x1 ^= this.subkeys[r * 4 + 1];
      x2 ^= this.subkeys[r * 4 + 2];
      x3 ^= this.subkeys[r * 4 + 3];

      // S-Box application in bit-slice form
      const s = SBOX[r % 8];
      [x0, x1, x2, x3] = applySboxBitslice(s, x0, x1, x2, x3);

      // Linear transformation (except round 31)
      if (r < 31) {
        x0 = rotl32(x0, 13);
        x2 = rotl32(x2, 3);
        x1 = (x1 ^ x0 ^ x2) >>> 0;
        x3 = (x3 ^ x2 ^ ((x0 << 3) >>> 0)) >>> 0;
        x1 = rotl32(x1, 1);
        x3 = rotl32(x3, 7);
        x0 = (x0 ^ x1 ^ x3) >>> 0;
        x2 = (x2 ^ x3 ^ ((x1 << 7) >>> 0)) >>> 0;
        x0 = rotl32(x0, 5);
        x2 = rotl32(x2, 22);
      }
    }

    // Final key mixing (subkey 32)
    x0 ^= this.subkeys[32 * 4];
    x1 ^= this.subkeys[32 * 4 + 1];
    x2 ^= this.subkeys[32 * 4 + 2];
    x3 ^= this.subkeys[32 * 4 + 3];

    view.setUint32(0, x0 >>> 0, true);
    view.setUint32(4, x1 >>> 0, true);
    view.setUint32(8, x2 >>> 0, true);
    view.setUint32(12, x3 >>> 0, true);
  }

  public processCtr(data: Uint8Array, baseNonce: Uint8Array, chunkIndex: number): void {
    const BLOCK_SIZE = 16;
    const blocksInChunk = Math.ceil(data.length / BLOCK_SIZE);
    let counter = BigInt(chunkIndex) * BigInt(blocksInChunk);

    const blockBuffer = new Uint8Array(BLOCK_SIZE);
    const view = new DataView(blockBuffer.buffer);

    for (let offset = 0; offset < data.length; offset += BLOCK_SIZE) {
      blockBuffer.set(baseNonce.subarray(0, 8), 0);
      view.setBigUint64(8, counter, true);

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
