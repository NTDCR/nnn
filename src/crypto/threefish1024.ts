/**
 * Threefish-1024 Block Cipher in CTR Mode
 * Skein specification compliant
 * 1024-bit block size (16 x 64-bit words = 32 x 32-bit words = 128 bytes)
 * 80 rounds of MIX ARX permutation
 * Optimized with 32-bit Small Integer (SMI) CPU register pairs for zero-allocation
 * ultra-high-throughput execution and constant-time side-channel resistance.
 */

const ROTATIONS: readonly (readonly number[])[] = [
  [24, 13, 8, 47, 8, 17, 22, 37],
  [38, 19, 10, 55, 49, 18, 23, 52],
  [33, 4, 51, 13, 34, 41, 59, 17],
  [5, 20, 48, 41, 47, 28, 16, 25],
  [41, 9, 37, 31, 12, 47, 44, 30],
  [16, 34, 56, 51, 4, 53, 42, 41],
  [31, 44, 47, 46, 19, 42, 44, 25],
  [9, 48, 35, 52, 23, 31, 37, 20],
];

const MIX_DST_P: readonly number[] = [0, 4, 12, 8, 20, 24, 28, 16];
const MIX_DST_Q: readonly number[] = [18, 26, 22, 30, 14, 6, 10, 2];

import { ThreefishSimdEngine } from './threefishSimdEngine.ts';

export class Threefish1024 {
  // 21 subkeys, each containing 32 32-bit words (16 low/high pairs)
  private subkeys: Uint32Array[];
  private simdEngine: ThreefishSimdEngine | null = null;
  private vBuf: Uint32Array = new Uint32Array(32);
  private vNextBuf: Uint32Array = new Uint32Array(32);
  private v4Buf: Uint32Array = new Uint32Array(128);
  private v4NextBuf: Uint32Array = new Uint32Array(128);
  private blockBuffer: Uint8Array = new Uint8Array(128);
  private blockView: DataView;
  private blockU32: Uint32Array;

  constructor(keyBytes: Uint8Array, tweakBytes: Uint8Array) {
    if (keyBytes.length !== 128) {
      throw new Error('Threefish-1024 requires strictly a 128-byte (1024-bit) key.');
    }
    this.blockView = new DataView(this.blockBuffer.buffer);
    this.blockU32 = new Uint32Array(this.blockBuffer.buffer);

    // 17 64-bit key words represented as low/high 32-bit word arrays
    const kwLow = new Uint32Array(17);
    const kwHigh = new Uint32Array(17);
    const keyView = new DataView(keyBytes.buffer, keyBytes.byteOffset, 128);

    // C240 parity constant (0x1BD11BDA_A9FC1A22)
    let parityLow = 0xA9FC1A22 >>> 0;
    let parityHigh = 0x1BD11BDA >>> 0;

    for (let i = 0; i < 16; i++) {
      const l = keyView.getUint32(i * 8, true);
      const h = keyView.getUint32(i * 8 + 4, true);
      kwLow[i] = l;
      kwHigh[i] = h;
      parityLow = (parityLow ^ l) >>> 0;
      parityHigh = (parityHigh ^ h) >>> 0;
    }
    kwLow[16] = parityLow;
    kwHigh[16] = parityHigh;

    // 3 64-bit tweak words represented as low/high 32-bit word arrays
    const twLow = new Uint32Array(3);
    const twHigh = new Uint32Array(3);
    const tweakView = new DataView(tweakBytes.buffer, tweakBytes.byteOffset, 16);
    twLow[0] = tweakView.getUint32(0, true);
    twHigh[0] = tweakView.getUint32(4, true);
    twLow[1] = tweakView.getUint32(8, true);
    twHigh[1] = tweakView.getUint32(12, true);
    twLow[2] = (twLow[0] ^ twLow[1]) >>> 0;
    twHigh[2] = (twHigh[0] ^ twHigh[1]) >>> 0;

    // Precompute 21 subkeys (32 words each)
    this.subkeys = new Array(21);
    for (let s = 0; s <= 20; s++) {
      const sk = new Uint32Array(32);
      for (let i = 0; i < 16; i++) {
        const idx = (s + i) % 17;
        let l = kwLow[idx];
        let h = kwHigh[idx];

        if (i === 13) {
          const tIdx = s % 3;
          const tl = twLow[tIdx];
          const th = twHigh[tIdx];
          const sumL = (l + tl) >>> 0;
          const carry = sumL < l ? 1 : 0;
          l = sumL;
          h = (h + th + carry) >>> 0;
        } else if (i === 14) {
          const tIdx = (s + 1) % 3;
          const tl = twLow[tIdx];
          const th = twHigh[tIdx];
          const sumL = (l + tl) >>> 0;
          const carry = sumL < l ? 1 : 0;
          l = sumL;
          h = (h + th + carry) >>> 0;
        } else if (i === 15) {
          const sumL = (l + s) >>> 0;
          const carry = sumL < l ? 1 : 0;
          l = sumL;
          h = (h + carry) >>> 0;
        }

        sk[2 * i] = l;
        sk[2 * i + 1] = h;
      }
      this.subkeys[s] = sk;
    }

    this.simdEngine = ThreefishSimdEngine.create(keyBytes, tweakBytes);
  }

  /**
   * Encrypt a single 128-byte block using pure 32-bit CPU register operations.
   * Eliminates 5.24 million BigInt heap allocations per MB.
   */
  public encryptBlock(block: Uint8Array): void {
    const isInternal = block === this.blockBuffer;
    const view = isInternal ? this.blockView : new DataView(block.buffer, block.byteOffset, 128);

    const cur = this.vBuf;
    const nxt = this.vNextBuf;

    if (isInternal) {
      const bU32 = this.blockU32;
      for (let i = 0; i < 32; i++) {
        cur[i] = bU32[i];
      }
    } else {
      for (let i = 0; i < 32; i++) {
        cur[i] = view.getUint32(i * 4, true);
      }
    }

    let pCur = cur;
    let pNxt = nxt;

    for (let d = 0; d < 80; d++) {
      // Subkey injection every 4 rounds
      if ((d & 3) === 0) {
        const s = d >>> 2;
        const sk = this.subkeys[s];
        for (let i = 0; i < 16; i++) {
          const p = i << 1;
          const al = pCur[p];
          const bl = sk[p];
          const sumL = (al + bl) >>> 0;
          const carry = sumL < al ? 1 : 0;
          pCur[p] = sumL;
          pCur[p + 1] = (pCur[p + 1] + sk[p + 1] + carry) >>> 0;
        }
      }

      // 8 MIX operations in parallel ARX lanes
      const rotRow = ROTATIONS[d & 7];
      for (let j = 0; j < 8; j++) {
        const p = j << 2; // 4 * j
        const q = p + 2;

        const al = pCur[p];
        const ah = pCur[p + 1];
        const bl = pCur[q];
        const bh = pCur[q + 1];

        // 64-bit addition: Wp + Wq
        const sumL = (al + bl) >>> 0;
        const carry = sumL < al ? 1 : 0;
        const sumH = (ah + bh + carry) >>> 0;
        pCur[p] = sumL;
        pCur[p + 1] = sumH;

        // 64-bit rotation: Wq <<< R
        const r = rotRow[j];
        let rotL: number, rotH: number;
        if (r < 32) {
          rotL = ((bl << r) | (bh >>> (32 - r))) >>> 0;
          rotH = ((bh << r) | (bl >>> (32 - r))) >>> 0;
        } else if (r === 32) {
          rotL = bh;
          rotH = bl;
        } else {
          const r2 = r - 32;
          rotL = ((bh << r2) | (bl >>> (32 - r2))) >>> 0;
          rotH = ((bl << r2) | (bh >>> (32 - r2))) >>> 0;
        }

        // Fused MIX + Permutation: write directly into pNxt at target word positions
        const dstP = MIX_DST_P[j];
        const dstQ = MIX_DST_Q[j];
        pNxt[dstP] = sumL;
        pNxt[dstP + 1] = sumH;
        pNxt[dstQ] = (rotL ^ sumL) >>> 0;
        pNxt[dstQ + 1] = (rotH ^ sumH) >>> 0;
      }

      // Swap ping-pong buffers (permutation loop is 100% eliminated)
      const tmp = pCur;
      pCur = pNxt;
      pNxt = tmp;
    }

    // Final subkey 20 injection (since 80 rounds is even, pCur is guaranteed to be cur / this.vBuf)
    const lastSk = this.subkeys[20];
    if (isInternal) {
      const bU32 = this.blockU32;
      for (let i = 0; i < 16; i++) {
        const p = i << 1;
        const al = pCur[p];
        const bl = lastSk[p];
        const sumL = (al + bl) >>> 0;
        const carry = sumL < al ? 1 : 0;
        bU32[p] = sumL;
        bU32[p + 1] = (pCur[p + 1] + lastSk[p + 1] + carry) >>> 0;
      }
    } else {
      for (let i = 0; i < 16; i++) {
        const p = i << 1;
        const al = pCur[p];
        const bl = lastSk[p];
        const sumL = (al + bl) >>> 0;
        const carry = sumL < al ? 1 : 0;
        view.setUint32(p * 4, sumL, true);
        view.setUint32((p + 1) * 4, (pCur[p + 1] + lastSk[p + 1] + carry) >>> 0, true);
      }
    }
  }

  /**
   * 4-Way Interleaved 80-round MIX ARX permutation across 4 independent blocks (512 bytes).
   * Eliminates CPU pipeline latency bubbles by saturating multiple execution units simultaneously.
   */
  private encryptFourBlocks(): void {
    let pCur = this.v4Buf;
    let pNxt = this.v4NextBuf;

    for (let d = 0; d < 80; d++) {
      if ((d & 3) === 0) {
        const s = d >>> 2;
        const sk = this.subkeys[s];
        for (let i = 0; i < 16; i++) {
          const p = i << 1;
          const skl = sk[p];
          const skh = sk[p + 1];

          // Block 0
          const al0 = pCur[p];
          const sumL0 = (al0 + skl) >>> 0;
          pCur[p] = sumL0;
          pCur[p + 1] = (pCur[p + 1] + skh + (sumL0 < al0 ? 1 : 0)) >>> 0;

          // Block 1
          const al1 = pCur[32 + p];
          const sumL1 = (al1 + skl) >>> 0;
          pCur[32 + p] = sumL1;
          pCur[32 + p + 1] = (pCur[32 + p + 1] + skh + (sumL1 < al1 ? 1 : 0)) >>> 0;

          // Block 2
          const al2 = pCur[64 + p];
          const sumL2 = (al2 + skl) >>> 0;
          pCur[64 + p] = sumL2;
          pCur[64 + p + 1] = (pCur[64 + p + 1] + skh + (sumL2 < al2 ? 1 : 0)) >>> 0;

          // Block 3
          const al3 = pCur[96 + p];
          const sumL3 = (al3 + skl) >>> 0;
          pCur[96 + p] = sumL3;
          pCur[96 + p + 1] = (pCur[96 + p + 1] + skh + (sumL3 < al3 ? 1 : 0)) >>> 0;
        }
      }

      const rotRow = ROTATIONS[d & 7];
      for (let j = 0; j < 8; j++) {
        const p = j << 2;
        const q = p + 2;

        const al0 = pCur[p]; const ah0 = pCur[p + 1];
        const bl0 = pCur[q]; const bh0 = pCur[q + 1];

        const al1 = pCur[32 + p]; const ah1 = pCur[32 + p + 1];
        const bl1 = pCur[32 + q]; const bh1 = pCur[32 + q + 1];

        const al2 = pCur[64 + p]; const ah2 = pCur[64 + p + 1];
        const bl2 = pCur[64 + q]; const bh2 = pCur[64 + q + 1];

        const al3 = pCur[96 + p]; const ah3 = pCur[96 + p + 1];
        const bl3 = pCur[96 + q]; const bh3 = pCur[96 + q + 1];

        // Sums
        const sumL0 = (al0 + bl0) >>> 0;
        const sumH0 = (ah0 + bh0 + (sumL0 < al0 ? 1 : 0)) >>> 0;
        pCur[p] = sumL0; pCur[p + 1] = sumH0;

        const sumL1 = (al1 + bl1) >>> 0;
        const sumH1 = (ah1 + bh1 + (sumL1 < al1 ? 1 : 0)) >>> 0;
        pCur[32 + p] = sumL1; pCur[32 + p + 1] = sumH1;

        const sumL2 = (al2 + bl2) >>> 0;
        const sumH2 = (ah2 + bh2 + (sumL2 < al2 ? 1 : 0)) >>> 0;
        pCur[64 + p] = sumL2; pCur[64 + p + 1] = sumH2;

        const sumL3 = (al3 + bl3) >>> 0;
        const sumH3 = (ah3 + bh3 + (sumL3 < al3 ? 1 : 0)) >>> 0;
        pCur[96 + p] = sumL3; pCur[96 + p + 1] = sumH3;

        // Rotations
        const r = rotRow[j];
        let rotL0: number, rotH0: number;
        let rotL1: number, rotH1: number;
        let rotL2: number, rotH2: number;
        let rotL3: number, rotH3: number;

        if (r < 32) {
          const inv = 32 - r;
          rotL0 = ((bl0 << r) | (bh0 >>> inv)) >>> 0;
          rotH0 = ((bh0 << r) | (bl0 >>> inv)) >>> 0;
          rotL1 = ((bl1 << r) | (bh1 >>> inv)) >>> 0;
          rotH1 = ((bh1 << r) | (bl1 >>> inv)) >>> 0;
          rotL2 = ((bl2 << r) | (bh2 >>> inv)) >>> 0;
          rotH2 = ((bh2 << r) | (bl2 >>> inv)) >>> 0;
          rotL3 = ((bl3 << r) | (bh3 >>> inv)) >>> 0;
          rotH3 = ((bh3 << r) | (bl3 >>> inv)) >>> 0;
        } else if (r === 32) {
          rotL0 = bh0; rotH0 = bl0;
          rotL1 = bh1; rotH1 = bl1;
          rotL2 = bh2; rotH2 = bl2;
          rotL3 = bh3; rotH3 = bl3;
        } else {
          const r2 = r - 32;
          const inv = 32 - r2;
          rotL0 = ((bh0 << r2) | (bl0 >>> inv)) >>> 0;
          rotH0 = ((bl0 << r2) | (bh0 >>> inv)) >>> 0;
          rotL1 = ((bh1 << r2) | (bl1 >>> inv)) >>> 0;
          rotH1 = ((bl1 << r2) | (bh1 >>> inv)) >>> 0;
          rotL2 = ((bh2 << r2) | (bl2 >>> inv)) >>> 0;
          rotH2 = ((bl2 << r2) | (bh2 >>> inv)) >>> 0;
          rotL3 = ((bh3 << r2) | (bl3 >>> inv)) >>> 0;
          rotH3 = ((bl3 << r2) | (bh3 >>> inv)) >>> 0;
        }

        const dstP = MIX_DST_P[j];
        const dstQ = MIX_DST_Q[j];

        pNxt[dstP] = sumL0;
        pNxt[dstP + 1] = sumH0;
        pNxt[dstQ] = (rotL0 ^ sumL0) >>> 0;
        pNxt[dstQ + 1] = (rotH0 ^ sumH0) >>> 0;

        pNxt[32 + dstP] = sumL1;
        pNxt[32 + dstP + 1] = sumH1;
        pNxt[32 + dstQ] = (rotL1 ^ sumL1) >>> 0;
        pNxt[32 + dstQ + 1] = (rotH1 ^ sumH1) >>> 0;

        pNxt[64 + dstP] = sumL2;
        pNxt[64 + dstP + 1] = sumH2;
        pNxt[64 + dstQ] = (rotL2 ^ sumL2) >>> 0;
        pNxt[64 + dstQ + 1] = (rotH2 ^ sumH2) >>> 0;

        pNxt[96 + dstP] = sumL3;
        pNxt[96 + dstP + 1] = sumH3;
        pNxt[96 + dstQ] = (rotL3 ^ sumL3) >>> 0;
        pNxt[96 + dstQ + 1] = (rotH3 ^ sumH3) >>> 0;
      }

      const tmp = pCur; pCur = pNxt; pNxt = tmp;
    }

    const lastSk = this.subkeys[20];
    for (let i = 0; i < 16; i++) {
      const p = i << 1;
      const skl = lastSk[p];
      const skh = lastSk[p + 1];

      for (let b = 0; b < 4; b++) {
        const base = (b << 5) + p;
        const al = pCur[base];
        const sumL = (al + skl) >>> 0;
        pCur[base] = sumL;
        pCur[base + 1] = (pCur[base + 1] + skh + (sumL < al ? 1 : 0)) >>> 0;
      }
    }
  }

  /**
   * High-throughput CTR mode stream cipher processing.
   * Operates on native 32-bit CPU register words with 4-way superscalar interleaving.
   */
  public processCtr(data: Uint8Array, baseNonce: Uint8Array, chunkIndex: number): void {
    if (baseNonce.length < 16) {
      throw new Error('Threefish-1024 base nonce must be at least 16 bytes');
    }

    if (this.simdEngine) {
      this.simdEngine.processCtr(data, baseNonce, chunkIndex);
      return;
    }

    const BLOCK_SIZE = 128;
    const FOUR_BLOCKS = 512;
    const blocksInChunk = Math.ceil(data.length / BLOCK_SIZE);
    let counter = BigInt(chunkIndex) * BigInt(blocksInChunk);

    const nonceView = new DataView(baseNonce.buffer, baseNonce.byteOffset, 16);
    const n0 = nonceView.getUint32(0, true);
    const n1 = nonceView.getUint32(4, true);
    const n2 = nonceView.getUint32(8, true);
    const n3 = nonceView.getUint32(12, true);

    const nonce16 = baseNonce.subarray(0, 16);
    const blockBuffer = this.blockBuffer;
    const blockView = this.blockView;
    const blockU32 = this.blockU32;

    const canUseU32 = (data.byteOffset % 4 === 0) && (data.length % 4 === 0);
    const dataU32 = canUseU32 ? new Uint32Array(data.buffer, data.byteOffset, data.length >>> 2) : null;
    const dataView = new DataView(data.buffer, data.byteOffset, data.length);

    let offset = 0;

    // Process sets of 4 128-byte blocks (512 bytes) via 4-way interleaved execution
    while (offset + FOUR_BLOCKS <= data.length) {
      this.v4Buf.fill(0);
      for (let b = 0; b < 4; b++) {
        const c = counter + BigInt(b);
        const base = b << 5;
        this.v4Buf[base] = n0;
        this.v4Buf[base + 1] = n1;
        this.v4Buf[base + 2] = n2;
        this.v4Buf[base + 3] = n3;
        this.v4Buf[base + 4] = Number(c & 0xFFFFFFFFn) >>> 0;
        this.v4Buf[base + 5] = Number((c >> 32n) & 0xFFFFFFFFn) >>> 0;
        this.v4Buf[base + 6] = Number((c >> 64n) & 0xFFFFFFFFn) >>> 0;
        this.v4Buf[base + 7] = Number((c >> 96n) & 0xFFFFFFFFn) >>> 0;
      }

      this.encryptFourBlocks();

      if (dataU32) {
        const wBase = offset >>> 2;
        for (let i = 0; i < 128; i++) {
          dataU32[wBase + i] ^= this.v4Buf[i];
        }
      } else {
        for (let i = 0; i < 128; i++) {
          const bytePos = offset + (i << 2);
          dataView.setUint32(bytePos, dataView.getUint32(bytePos, true) ^ this.v4Buf[i], true);
        }
      }

      counter += 4n;
      offset += FOUR_BLOCKS;
    }

    // Trailing blocks if data.length is not an exact multiple of 512
    while (offset < data.length) {
      blockBuffer.fill(0);
      blockBuffer.set(nonce16, 0);
      blockView.setBigUint64(16, counter & 0xFFFFFFFFFFFFFFFFn, true);
      blockView.setBigUint64(24, (counter >> 64n) & 0xFFFFFFFFFFFFFFFFn, true);

      this.encryptBlock(blockBuffer);

      const chunkLen = Math.min(BLOCK_SIZE, data.length - offset);
      if (chunkLen === BLOCK_SIZE && dataU32) {
        const wordBase = offset >>> 2;
        for (let i = 0; i < 32; i++) {
          dataU32[wordBase + i] ^= blockU32[i];
        }
      } else if (chunkLen === BLOCK_SIZE) {
        // Fast 32-bit vector word XORing (32 x 32-bit operations)
        for (let i = 0; i < 32; i++) {
          const bytePos = offset + (i << 2);
          dataView.setUint32(bytePos, dataView.getUint32(bytePos, true) ^ blockView.getUint32(i << 2, true), true);
        }
      } else {
        // Tail byte handling for partial final block
        let i = 0;
        while (i + 4 <= chunkLen) {
          if (dataU32) {
            dataU32[(offset >>> 2) + (i >>> 2)] ^= blockU32[i >>> 2];
          } else {
            dataView.setUint32(offset + i, dataView.getUint32(offset + i, true) ^ blockView.getUint32(i, true), true);
          }
          i += 4;
        }
        while (i < chunkLen) {
          data[offset + i] ^= blockBuffer[i];
          i++;
        }
      }

      counter++;
      offset += BLOCK_SIZE;
    }
    blockBuffer.fill(0);
    this.v4Buf.fill(0);
  }

  public destroy(): void {
    if (this.simdEngine) {
      this.simdEngine.destroy();
      this.simdEngine = null;
    }
    for (let s = 0; s < this.subkeys.length; s++) {
      this.subkeys[s].fill(0);
    }
    this.vBuf.fill(0);
    this.vNextBuf.fill(0);
    this.v4Buf.fill(0);
    this.v4NextBuf.fill(0);
    this.blockBuffer.fill(0);
  }
}
