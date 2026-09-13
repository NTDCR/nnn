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

export class Serpent256 {
  private subkeys: Uint32Array; // 33 subkeys of 4 words = 132 words
  private blockBuffer: Uint8Array = new Uint8Array(16);
  private blockView: DataView;
  private keystream: Uint32Array = new Uint32Array(8);

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

  /**
   * 2-Way Interleaved Inlined 32-round Serpent Block Cipher
   * Eliminates 2.1M function calls & 8.4M array dereferences per MB while saturating ALU pipelines.
   */
  private encryptTwo(
    a0: number, a1: number, a2: number, a3: number,
    b0: number, b1: number, b2: number, b3: number,
    out: Uint32Array, outOffset: number
  ): void {
    const sk = this.subkeys;
    let x0 = a0, x1 = a1, x2 = a2, x3 = a3;
    let y0 = b0, y1 = b1, y2 = b2, y3 = b3;

    for (let r = 0; r < 32; r++) {
      const skOffset = r * 4;
      const sk0 = sk[skOffset], sk1 = sk[skOffset + 1], sk2 = sk[skOffset + 2], sk3 = sk[skOffset + 3];

      // Block A
      const aa = x0 ^ sk0, ab = x1 ^ sk1, ac = x2 ^ sk2, ad = x3 ^ sk3;
      const naA = ~aa, nbA = ~ab, ncA = ~ac, ndA = ~ad;
      const p0A = naA & nbA, p1A = aa & nbA, p2A = naA & ab, p3A = aa & ab;
      const q0A = ncA & ndA, q1A = ac & ndA, q2A = ncA & ad, q3A = ac & ad;
      const m0A = p0A & q0A, m1A = p1A & q0A, m2A = p2A & q0A, m3A = p3A & q0A;
      const m4A = p0A & q1A, m5A = p1A & q1A, m6A = p2A & q1A, m7A = p3A & q1A;
      const m8A = p0A & q2A, m9A = p1A & q2A, m10A = p2A & q2A, m11A = p3A & q2A;
      const m12A = p0A & q3A, m13A = p1A & q3A, m14A = p2A & q3A, m15A = p3A & q3A;

      // Block B
      const ba = y0 ^ sk0, bb = y1 ^ sk1, bc = y2 ^ sk2, bd = y3 ^ sk3;
      const naB = ~ba, nbB = ~bb, ncB = ~bc, ndB = ~bd;
      const p0B = naB & nbB, p1B = ba & nbB, p2B = naB & bb, p3B = ba & bb;
      const q0B = ncB & ndB, q1B = bc & ndB, q2B = ncB & bd, q3B = bc & bd;
      const m0B = p0B & q0B, m1B = p1B & q0B, m2B = p2B & q0B, m3B = p3B & q0B;
      const m4B = p0B & q1B, m5B = p1B & q1B, m6B = p2B & q1B, m7B = p3B & q1B;
      const m8B = p0B & q2B, m9B = p1B & q2B, m10B = p2B & q2B, m11B = p3B & q2B;
      const m12B = p0B & q3B, m13B = p1B & q3B, m14B = p2B & q3B, m15B = p3B & q3B;

      let o0A: number, o1A: number, o2A: number, o3A: number;
      let o0B: number, o1B: number, o2B: number, o3B: number;

      switch (r & 7) {
        case 0:
          o0A = m0A | m2A | m3A | m6A | m7A | m9A | m12A | m14A;
          o1A = m0A | m2A | m4A | m5A | m7A | m8A | m11A | m12A;
          o2A = m2A | m5A | m6A | m8A | m9A | m10A | m12A | m15A;
          o3A = m1A | m2A | m4A | m7A | m8A | m9A | m14A | m15A;
          o0B = m0B | m2B | m3B | m6B | m7B | m9B | m12B | m14B;
          o1B = m0B | m2B | m4B | m5B | m7B | m8B | m11B | m12B;
          o2B = m2B | m5B | m6B | m8B | m9B | m10B | m12B | m15B;
          o3B = m1B | m2B | m4B | m7B | m8B | m9B | m14B | m15B;
          break;
        case 1:
          o0A = m0A | m3A | m4A | m6A | m8A | m9A | m13A | m14A;
          o1A = m0A | m2A | m3A | m7A | m9A | m10A | m12A | m14A;
          o2A = m0A | m1A | m3A | m6A | m10A | m12A | m13A | m15A;
          o3A = m0A | m1A | m4A | m7A | m9A | m10A | m11A | m13A;
          o0B = m0B | m3B | m4B | m6B | m8B | m9B | m13B | m14B;
          o1B = m0B | m2B | m3B | m7B | m9B | m10B | m12B | m14B;
          o2B = m0B | m1B | m3B | m6B | m10B | m12B | m13B | m15B;
          o3B = m0B | m1B | m4B | m7B | m9B | m10B | m11B | m13B;
          break;
        case 2:
          o0A = m2A | m3A | m4A | m7A | m8A | m9A | m13A | m14A;
          o1A = m1A | m2A | m4A | m6A | m7A | m10A | m13A | m15A;
          o2A = m1A | m2A | m5A | m7A | m8A | m10A | m11A | m14A;
          o3A = m0A | m3A | m5A | m6A | m7A | m8A | m10A | m13A;
          o0B = m2B | m3B | m4B | m7B | m8B | m9B | m13B | m14B;
          o1B = m1B | m2B | m4B | m6B | m7B | m10B | m13B | m15B;
          o2B = m1B | m2B | m5B | m7B | m8B | m10B | m11B | m14B;
          o3B = m0B | m3B | m5B | m6B | m7B | m8B | m10B | m13B;
          break;
        case 3:
          o0A = m1A | m2A | m5A | m7A | m8A | m9A | m13A | m14A;
          o1A = m1A | m2A | m6A | m7A | m10A | m12A | m13A | m15A;
          o2A = m1A | m4A | m6A | m8A | m11A | m13A | m14A | m15A;
          o3A = m1A | m2A | m3A | m4A | m5A | m8A | m12A | m15A;
          o0B = m1B | m2B | m5B | m7B | m8B | m9B | m13B | m14B;
          o1B = m1B | m2B | m6B | m7B | m10B | m12B | m13B | m15B;
          o2B = m1B | m4B | m6B | m8B | m11B | m13B | m14B | m15B;
          o3B = m1B | m2B | m3B | m4B | m5B | m8B | m12B | m15B;
          break;
        case 4:
          o0A = m0A | m1A | m3A | m6A | m9A | m12A | m14A | m15A;
          o1A = m1A | m3A | m6A | m7A | m8A | m11A | m13A | m14A;
          o2A = m1A | m4A | m7A | m9A | m10A | m13A | m14A | m15A;
          o3A = m1A | m2A | m4A | m6A | m11A | m12A | m13A | m15A;
          o0B = m0B | m1B | m3B | m6B | m9B | m12B | m14B | m15B;
          o1B = m1B | m3B | m6B | m7B | m8B | m11B | m13B | m14B;
          o2B = m1B | m4B | m7B | m9B | m10B | m13B | m14B | m15B;
          o3B = m1B | m2B | m4B | m6B | m11B | m12B | m13B | m15B;
          break;
        case 5:
          o0A = m0A | m1A | m3A | m6A | m9A | m12A | m14A | m15A;
          o1A = m0A | m2A | m3A | m5A | m9A | m10A | m13A | m14A;
          o2A = m0A | m1A | m4A | m7A | m10A | m12A | m13A | m14A;
          o3A = m0A | m3A | m5A | m6A | m7A | m10A | m11A | m12A;
          o0B = m0B | m1B | m3B | m6B | m9B | m12B | m14B | m15B;
          o1B = m0B | m2B | m3B | m5B | m9B | m10B | m13B | m14B;
          o2B = m0B | m1B | m4B | m7B | m10B | m12B | m13B | m14B;
          o3B = m0B | m3B | m5B | m6B | m7B | m10B | m11B | m12B;
          break;
        case 6:
          o0A = m0A | m3A | m7A | m9A | m10A | m11A | m12A | m13A;
          o1A = m0A | m1A | m6A | m7A | m8A | m11A | m13A | m14A;
          o2A = m0A | m2A | m3A | m5A | m6A | m8A | m11A | m12A;
          o3A = m2A | m4A | m7A | m8A | m9A | m11A | m12A | m14A;
          o0B = m0B | m3B | m7B | m9B | m10B | m11B | m12B | m13B;
          o1B = m0B | m1B | m6B | m7B | m8B | m11B | m13B | m14B;
          o2B = m0B | m2B | m3B | m5B | m6B | m8B | m11B | m12B;
          o3B = m2B | m4B | m7B | m8B | m9B | m11B | m12B | m14B;
          break;
        case 7:
        default:
          o0A = m0A | m1A | m2A | m7A | m8A | m12A | m13A | m14A;
          o1A = m2A | m4A | m6A | m7A | m8A | m11A | m13A | m15A;
          o2A = m1A | m2A | m4A | m8A | m9A | m10A | m14A | m15A;
          o3A = m1A | m2A | m4A | m5A | m7A | m10A | m11A | m12A;
          o0B = m0B | m1B | m2B | m7B | m8B | m12B | m13B | m14B;
          o1B = m2B | m4B | m6B | m7B | m8B | m11B | m13B | m15B;
          o2B = m1B | m2B | m4B | m8B | m9B | m10B | m14B | m15B;
          o3B = m1B | m2B | m4B | m5B | m7B | m10B | m11B | m12B;
          break;
      }

      if (r < 31) {
        o0A = rotl32(o0A, 13);
        o2A = rotl32(o2A, 3);
        o1A = (o1A ^ o0A ^ o2A) >>> 0;
        o3A = (o3A ^ o2A ^ ((o0A << 3) >>> 0)) >>> 0;
        o1A = rotl32(o1A, 1);
        o3A = rotl32(o3A, 7);
        o0A = (o0A ^ o1A ^ o3A) >>> 0;
        o2A = (o2A ^ o3A ^ ((o1A << 7) >>> 0)) >>> 0;
        x0 = rotl32(o0A, 5);
        x1 = o1A;
        x2 = rotl32(o2A, 22);
        x3 = o3A;

        o0B = rotl32(o0B, 13);
        o2B = rotl32(o2B, 3);
        o1B = (o1B ^ o0B ^ o2B) >>> 0;
        o3B = (o3B ^ o2B ^ ((o0B << 3) >>> 0)) >>> 0;
        o1B = rotl32(o1B, 1);
        o3B = rotl32(o3B, 7);
        o0B = (o0B ^ o1B ^ o3B) >>> 0;
        o2B = (o2B ^ o3B ^ ((o1B << 7) >>> 0)) >>> 0;
        y0 = rotl32(o0B, 5);
        y1 = o1B;
        y2 = rotl32(o2B, 22);
        y3 = o3B;
      } else {
        x0 = o0A; x1 = o1A; x2 = o2A; x3 = o3A;
        y0 = o0B; y1 = o1B; y2 = o2B; y3 = o3B;
      }
    }

    out[outOffset] = (x0 ^ sk[128]) >>> 0;
    out[outOffset + 1] = (x1 ^ sk[129]) >>> 0;
    out[outOffset + 2] = (x2 ^ sk[130]) >>> 0;
    out[outOffset + 3] = (x3 ^ sk[131]) >>> 0;

    out[outOffset + 4] = (y0 ^ sk[128]) >>> 0;
    out[outOffset + 5] = (y1 ^ sk[129]) >>> 0;
    out[outOffset + 6] = (y2 ^ sk[130]) >>> 0;
    out[outOffset + 7] = (y3 ^ sk[131]) >>> 0;
  }

  public encryptBlock(block: Uint8Array): void {
    const view = block === this.blockBuffer ? this.blockView : new DataView(block.buffer, block.byteOffset, 16);
    const x0 = view.getUint32(0, true);
    const x1 = view.getUint32(4, true);
    const x2 = view.getUint32(8, true);
    const x3 = view.getUint32(12, true);

    this.encryptTwo(x0, x1, x2, x3, 0, 0, 0, 0, this.keystream, 0);

    view.setUint32(0, this.keystream[0], true);
    view.setUint32(4, this.keystream[1], true);
    view.setUint32(8, this.keystream[2], true);
    view.setUint32(12, this.keystream[3], true);
  }

  public processCtr(data: Uint8Array, baseNonce: Uint8Array, chunkIndex: number): void {
    if (baseNonce.length < 8) {
      throw new Error('Serpent-256 base nonce must be at least 8 bytes');
    }
    const BLOCK_SIZE = 16;
    const TWO_BLOCKS = 32;
    const blocksInChunk = Math.ceil(data.length / BLOCK_SIZE);
    let counter = BigInt(chunkIndex) * BigInt(blocksInChunk);

    const nonceView = new DataView(baseNonce.buffer, baseNonce.byteOffset, 8);
    const n0 = nonceView.getUint32(0, true);
    const n1 = nonceView.getUint32(4, true);

    const canUseU32 = (data.byteOffset % 4 === 0) && (data.length % 4 === 0);
    const dataU32 = canUseU32 ? new Uint32Array(data.buffer, data.byteOffset, data.length >>> 2) : null;
    const dataView = new DataView(data.buffer, data.byteOffset, data.length);
    const keystream = this.keystream;

    let offset = 0;
    while (offset + TWO_BLOCKS <= data.length) {
      const c0Low = Number(counter & 0xFFFFFFFFn) >>> 0;
      const c0High = Number((counter >> 32n) & 0xFFFFFFFFn) >>> 0;
      const c1 = counter + 1n;
      const c1Low = Number(c1 & 0xFFFFFFFFn) >>> 0;
      const c1High = Number((c1 >> 32n) & 0xFFFFFFFFn) >>> 0;

      this.encryptTwo(n0, n1, c0Low, c0High, n0, n1, c1Low, c1High, keystream, 0);

      if (dataU32) {
        const w = offset >>> 2;
        dataU32[w] ^= keystream[0];
        dataU32[w + 1] ^= keystream[1];
        dataU32[w + 2] ^= keystream[2];
        dataU32[w + 3] ^= keystream[3];
        dataU32[w + 4] ^= keystream[4];
        dataU32[w + 5] ^= keystream[5];
        dataU32[w + 6] ^= keystream[6];
        dataU32[w + 7] ^= keystream[7];
      } else {
        for (let i = 0; i < 8; i++) {
          const p = offset + (i << 2);
          dataView.setUint32(p, dataView.getUint32(p, true) ^ keystream[i], true);
        }
      }

      counter += 2n;
      offset += TWO_BLOCKS;
    }

    if (offset < data.length) {
      const cLow = Number(counter & 0xFFFFFFFFn) >>> 0;
      const cHigh = Number((counter >> 32n) & 0xFFFFFFFFn) >>> 0;
      this.encryptTwo(n0, n1, cLow, cHigh, 0, 0, 0, 0, keystream, 0);
      const rem = data.length - offset;
      if (rem === BLOCK_SIZE && dataU32) {
        const w = offset >>> 2;
        dataU32[w] ^= keystream[0];
        dataU32[w + 1] ^= keystream[1];
        dataU32[w + 2] ^= keystream[2];
        dataU32[w + 3] ^= keystream[3];
      } else {
        const ksU8 = new Uint8Array(keystream.buffer);
        for (let i = 0; i < rem; i++) {
          data[offset + i] ^= ksU8[i];
        }
      }
    }
    this.blockBuffer.fill(0);
    keystream.fill(0);
  }

  public destroy(): void {
    this.subkeys.fill(0);
    this.keystream.fill(0);
    this.blockBuffer.fill(0);
  }
}
