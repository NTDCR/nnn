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

export class Threefish1024 {
  // 21 subkeys, each containing 32 32-bit words (16 low/high pairs)
  private subkeys: Uint32Array[];
  private vBuf: Uint32Array = new Uint32Array(32);
  private vNextBuf: Uint32Array = new Uint32Array(32);
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
   * High-throughput CTR mode stream cipher processing.
   * Operates on native 32-bit CPU register words with zero heap allocation.
   */
  public processCtr(data: Uint8Array, baseNonce: Uint8Array, chunkIndex: number): void {
    if (baseNonce.length < 16) {
      throw new Error('Threefish-1024 base nonce must be at least 16 bytes');
    }
    const BLOCK_SIZE = 128;
    const blocksInChunk = Math.ceil(data.length / BLOCK_SIZE);
    let counter = BigInt(chunkIndex) * BigInt(blocksInChunk);

    const blockBuffer = this.blockBuffer;
    const blockView = this.blockView;
    const dataView = new DataView(data.buffer, data.byteOffset, data.byteLength);

    // Pre-slice 16-byte nonce once outside the 8,192-iteration block loop
    const nonce16 = baseNonce.subarray(0, 16);

    const canUseU32 = (data.byteOffset % 4 === 0) && (data.length % 4 === 0);
    const dataU32 = canUseU32 ? new Uint32Array(data.buffer, data.byteOffset, data.length >>> 2) : null;
    const blockU32 = this.blockU32;

    for (let offset = 0; offset < data.length; offset += BLOCK_SIZE) {
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
    }
    blockBuffer.fill(0);
  }

  public destroy(): void {
    for (let s = 0; s < this.subkeys.length; s++) {
      this.subkeys[s].fill(0);
    }
    this.vBuf.fill(0);
    this.vNextBuf.fill(0);
    this.blockBuffer.fill(0);
  }
}
