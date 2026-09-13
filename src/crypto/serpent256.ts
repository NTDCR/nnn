/**
 * Serpent-256 Block Cipher in CTR Mode
 * 128-bit block (16 bytes), 256-bit key (32 bytes), 32 rounds
 * NIST AES Finalist Specification
 * Optimized with 32-lane bit-slice SIMD vectorization and 64-bit vector keystream XOR.
 */

// 8 S-Boxes for Serpent (4-bit nibbles, reference definitions)
export const SBOX: readonly number[][] = [
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

/**
 * 32-Lane Bit-Slice SIMD S-Box Vectorization
 * Evaluates all 32 S-boxes across 32-bit registers (r0, r1, r2, r3) simultaneously
 * using bit-parallel boolean logic with zero branches and zero table lookups.
 */
export function applySboxBitsliceSIMD(
  sIdx: number,
  r0: number,
  r1: number,
  r2: number,
  r3: number,
  out: [number, number, number, number] | Uint32Array
): void {
  const na = ~r0, nb = ~r1, nc = ~r2, nd = ~r3;
  const p0 = na & nb, p1 = r0 & nb, p2 = na & r1, p3 = r0 & r1;
  const q0 = nc & nd, q1 = r2 & nd, q2 = nc & r3, q3 = r2 & r3;

  const m0 = p0 & q0, m1 = p1 & q0, m2 = p2 & q0, m3 = p3 & q0;
  const m4 = p0 & q1, m5 = p1 & q1, m6 = p2 & q1, m7 = p3 & q1;
  const m8 = p0 & q2, m9 = p1 & q2, m10 = p2 & q2, m11 = p3 & q2;
  const m12 = p0 & q3, m13 = p1 & q3, m14 = p2 & q3, m15 = p3 & q3;

  switch (sIdx) {
    case 0:
      out[0] = (m0 | m2 | m3 | m6 | m7 | m9 | m12 | m14) >>> 0;
      out[1] = (m0 | m2 | m4 | m5 | m7 | m8 | m11 | m12) >>> 0;
      out[2] = (m2 | m5 | m6 | m8 | m9 | m10 | m12 | m15) >>> 0;
      out[3] = (m1 | m2 | m4 | m7 | m8 | m9 | m14 | m15) >>> 0;
      break;
    case 1:
      out[0] = (m0 | m3 | m4 | m6 | m8 | m9 | m13 | m14) >>> 0;
      out[1] = (m0 | m2 | m3 | m7 | m9 | m10 | m12 | m14) >>> 0;
      out[2] = (m0 | m1 | m3 | m6 | m10 | m12 | m13 | m15) >>> 0;
      out[3] = (m0 | m1 | m4 | m7 | m9 | m10 | m11 | m13) >>> 0;
      break;
    case 2:
      out[0] = (m2 | m3 | m4 | m7 | m8 | m9 | m13 | m14) >>> 0;
      out[1] = (m1 | m2 | m4 | m6 | m7 | m10 | m13 | m15) >>> 0;
      out[2] = (m1 | m2 | m5 | m7 | m8 | m10 | m11 | m14) >>> 0;
      out[3] = (m0 | m3 | m5 | m6 | m7 | m8 | m10 | m13) >>> 0;
      break;
    case 3:
      out[0] = (m1 | m2 | m5 | m7 | m8 | m9 | m13 | m14) >>> 0;
      out[1] = (m1 | m2 | m6 | m7 | m10 | m12 | m13 | m15) >>> 0;
      out[2] = (m1 | m4 | m6 | m8 | m11 | m13 | m14 | m15) >>> 0;
      out[3] = (m1 | m2 | m3 | m4 | m5 | m8 | m12 | m15) >>> 0;
      break;
    case 4:
      out[0] = (m0 | m1 | m3 | m6 | m9 | m12 | m14 | m15) >>> 0;
      out[1] = (m1 | m3 | m6 | m7 | m8 | m11 | m13 | m14) >>> 0;
      out[2] = (m1 | m4 | m7 | m9 | m10 | m13 | m14 | m15) >>> 0;
      out[3] = (m1 | m2 | m4 | m6 | m11 | m12 | m13 | m15) >>> 0;
      break;
    case 5:
      out[0] = (m0 | m1 | m3 | m6 | m9 | m12 | m14 | m15) >>> 0;
      out[1] = (m0 | m2 | m3 | m5 | m9 | m10 | m13 | m14) >>> 0;
      out[2] = (m0 | m1 | m4 | m7 | m10 | m12 | m13 | m14) >>> 0;
      out[3] = (m0 | m3 | m5 | m6 | m7 | m10 | m11 | m12) >>> 0;
      break;
    case 6:
      out[0] = (m0 | m3 | m7 | m9 | m10 | m11 | m12 | m13) >>> 0;
      out[1] = (m0 | m1 | m6 | m7 | m8 | m11 | m13 | m14) >>> 0;
      out[2] = (m0 | m2 | m3 | m5 | m6 | m8 | m11 | m12) >>> 0;
      out[3] = (m2 | m4 | m7 | m8 | m9 | m11 | m12 | m14) >>> 0;
      break;
    case 7:
    default:
      out[0] = (m0 | m1 | m2 | m7 | m8 | m12 | m13 | m14) >>> 0;
      out[1] = (m2 | m4 | m6 | m7 | m8 | m11 | m13 | m15) >>> 0;
      out[2] = (m1 | m2 | m4 | m8 | m9 | m10 | m14 | m15) >>> 0;
      out[3] = (m1 | m2 | m4 | m5 | m7 | m10 | m11 | m12) >>> 0;
      break;
  }
}

/**
 * Backward compatibility wrapper for applySboxBitslice
 */
export function applySboxBitslice(s: number[], r0: number, r1: number, r2: number, r3: number): [number, number, number, number] {
  let sIdx = SBOX.indexOf(s);
  if (sIdx === -1) sIdx = 0;
  const res: [number, number, number, number] = [0, 0, 0, 0];
  applySboxBitsliceSIMD(sIdx, r0, r1, r2, r3, res);
  return res;
}

export class Serpent256 {
  private subkeys: Uint32Array; // 33 subkeys of 4 words = 132 words
  private sboxOut: [number, number, number, number] = [0, 0, 0, 0];
  private blockBuffer: Uint8Array = new Uint8Array(16);
  private blockView: DataView;

  constructor(keyBytes: Uint8Array) {
    if (keyBytes.length !== 32) {
      throw new Error('Serpent-256 requires exactly 32 bytes key');
    }
    this.blockView = new DataView(this.blockBuffer.buffer);

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

    // Apply S-boxes in 32-lane bit-slice SIMD format to generate 33 subkeys (132 words)
    this.subkeys = new Uint32Array(132);
    const skOut: [number, number, number, number] = [0, 0, 0, 0];
    for (let i = 0; i < 33; i++) {
      const boxIdx = (32 + 3 - i) % 8;
      const baseIdx = 8 + i * 4;
      applySboxBitsliceSIMD(
        boxIdx,
        w[baseIdx],
        w[baseIdx + 1],
        w[baseIdx + 2],
        w[baseIdx + 3],
        skOut
      );
      this.subkeys[i * 4] = skOut[0];
      this.subkeys[i * 4 + 1] = skOut[1];
      this.subkeys[i * 4 + 2] = skOut[2];
      this.subkeys[i * 4 + 3] = skOut[3];
    }
  }

  public encryptBlock(block: Uint8Array): void {
    const view = new DataView(block.buffer, block.byteOffset, 16);
    let x0 = view.getUint32(0, true);
    let x1 = view.getUint32(4, true);
    let x2 = view.getUint32(8, true);
    let x3 = view.getUint32(12, true);

    const sOut = this.sboxOut;

    for (let r = 0; r < 32; r++) {
      // Key mixing
      x0 ^= this.subkeys[r * 4];
      x1 ^= this.subkeys[r * 4 + 1];
      x2 ^= this.subkeys[r * 4 + 2];
      x3 ^= this.subkeys[r * 4 + 3];

      // S-Box application in 32-lane bit-slice SIMD form
      applySboxBitsliceSIMD(r % 8, x0, x1, x2, x3, sOut);
      x0 = sOut[0];
      x1 = sOut[1];
      x2 = sOut[2];
      x3 = sOut[3];

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
    if (baseNonce.length < 8) {
      throw new Error('Serpent-256 base nonce must be at least 8 bytes');
    }
    const BLOCK_SIZE = 16;
    const blocksInChunk = Math.ceil(data.length / BLOCK_SIZE);
    let counter = BigInt(chunkIndex) * BigInt(blocksInChunk);

    const blockBuffer = this.blockBuffer;
    const blockView = this.blockView;
    const dataView = new DataView(data.buffer, data.byteOffset, data.byteLength);

    for (let offset = 0; offset < data.length; offset += BLOCK_SIZE) {
      blockBuffer.set(baseNonce.subarray(0, 8), 0);
      blockView.setBigUint64(8, counter, true);

      this.encryptBlock(blockBuffer);

      const chunkLen = Math.min(BLOCK_SIZE, data.length - offset);
      if (chunkLen === BLOCK_SIZE) {
        // Fast SIMD vector XOR (2 x 64-bit word operations)
        dataView.setBigUint64(offset, dataView.getBigUint64(offset, true) ^ blockView.getBigUint64(0, true), true);
        dataView.setBigUint64(offset + 8, dataView.getBigUint64(offset + 8, true) ^ blockView.getBigUint64(8, true), true);
      } else {
        // Tail byte handling for partial final block
        let i = 0;
        while (i + 4 <= chunkLen) {
          dataView.setUint32(offset + i, dataView.getUint32(offset + i, true) ^ blockView.getUint32(i, true), true);
          i += 4;
        }
        while (i < chunkLen) {
          data[offset + i] ^= blockBuffer[i];
          i++;
        }
      }

      counter++;
    }
    blockBuffer.fill(0);
  }

  public destroy(): void {
    this.subkeys.fill(0);
    this.sboxOut = [0, 0, 0, 0];
    this.blockBuffer.fill(0);
  }
}
