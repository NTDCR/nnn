/**
 * Industrial-Grade Reed-Solomon Forward Error Correction (FEC) Codec
 * Specification:
 * - Galois Field: GF(2^8) with primitive polynomial p(x) = x^8 + x^4 + x^3 + x^2 + 1 (0x11d = 285)
 * - Generator root: alpha = 0x02 (CCSDS / NASA 101.0-B-6, ISO/IEC 18004, RAID-6 standard)
 * - Decoding: Syndrome evaluation -> Berlekamp-Massey -> Chien search -> Forney algorithm
 * - Interleaved burst-error and bad sector recovery
 * - Critical metadata blob self-healing
 */

// Precomputed GF(2^8) exponential and logarithm lookup tables
const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);

let gfInitialized = false;

export function initGaloisField(): void {
  if (gfInitialized) return;
  let val = 1;
  GF_EXP[0] = 1;
  GF_LOG[0] = 0; // Mathematically undefined, safe sentinel
  for (let i = 1; i < 255; i++) {
    val <<= 1;
    if (val & 0x100) {
      val ^= 0x11d; // Primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1
    }
    GF_EXP[i] = val;
    GF_LOG[val] = i;
  }
  for (let i = 255; i < 512; i++) {
    GF_EXP[i] = GF_EXP[i - 255];
  }
  gfInitialized = true;
}

// Guarantee immediate table initialization upon module import
initGaloisField();

/**
 * Multiplication in GF(2^8) in O(1) time
 */
export function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

/**
 * Division in GF(2^8) in O(1) time
 */
export function gfDiv(a: number, b: number): number {
  if (a === 0) return 0;
  if (b === 0) throw new Error('Division by zero in GF(2^8)');
  return GF_EXP[(GF_LOG[a] - GF_LOG[b] + 255) % 255];
}

/**
 * Multiplicative inversion in GF(2^8)
 */
export function gfInv(a: number): number {
  if (a === 0) throw new Error('Zero cannot be inverted in GF(2^8)');
  return GF_EXP[255 - GF_LOG[a]];
}

/**
 * Exponentiation in GF(2^8)
 */
export function gfPow(a: number, p: number): number {
  if (a === 0) return 0;
  if (p === 0) return 1;
  return GF_EXP[(GF_LOG[a] * p) % 255];
}

/**
 * Multiplies two polynomials over GF(2^8)
 * Representation: descending order, index 0 is highest degree coefficient.
 */
export function polyMul(p1: Uint8Array, p2: Uint8Array): Uint8Array {
  const result = new Uint8Array(p1.length + p2.length - 1);
  for (let i = 0; i < p1.length; i++) {
    if (p1[i] === 0) continue;
    for (let j = 0; j < p2.length; j++) {
      if (p2[j] === 0) continue;
      result[i + j] ^= gfMul(p1[i], p2[j]);
    }
  }
  return result;
}

/**
 * Evaluates polynomial at x using Horner's method
 */
export function polyEval(poly: Uint8Array, x: number): number {
  let y = poly[0];
  for (let i = 1; i < poly.length; i++) {
    y = gfMul(y, x) ^ poly[i];
  }
  return y;
}

// Cache of generator polynomials for common parity lengths
const GENERATOR_CACHE = new Map<number, Uint8Array>();

/**
 * Creates or retrieves generator polynomial g(x) = prod_{i=0}^{nParity-1} (x - alpha^i)
 */
export function createGeneratorPoly(nParity: number): Uint8Array {
  if (nParity <= 0 || nParity > 128) {
    throw new Error(`Invalid parity count ${nParity}. Must be between 1 and 128.`);
  }
  const cached = GENERATOR_CACHE.get(nParity);
  if (cached) return cached;

  let g: Uint8Array = new Uint8Array([1]);
  for (let i = 0; i < nParity; i++) {
    g = polyMul(g, new Uint8Array([1, GF_EXP[i]]));
  }

  GENERATOR_CACHE.set(nParity, g);
  return g;
}

/**
 * Systematic Reed-Solomon Encoder
 * The input data is unaltered in the first data.length bytes, followed by nParity parity symbols.
 * Fast LFSR synthetic division in O(K * 2t) time.
 */
export function rsEncode(data: Uint8Array, nParity: number): Uint8Array {
  const gen = createGeneratorPoly(nParity);
  const codeword = new Uint8Array(data.length + nParity);
  codeword.set(data, 0);

  const remainder = new Uint8Array(nParity);
  for (let i = 0; i < data.length; i++) {
    const coef = data[i] ^ remainder[0];
    for (let j = 0; j < nParity - 1; j++) {
      remainder[j] = remainder[j + 1] ^ gfMul(coef, gen[j + 1]);
    }
    remainder[nParity - 1] = gfMul(coef, gen[nParity]);
  }
  codeword.set(remainder, data.length);
  return codeword;
}

/**
 * Computes syndrome vector S_0 ... S_{nParity-1}
 * If all syndromes are zero, returns empty array (fast-path zero-error detection).
 */
export function calcSyndromes(codeword: Uint8Array, nParity: number): Uint8Array {
  const syn = new Uint8Array(nParity);
  let hasError = false;
  for (let i = 0; i < nParity; i++) {
    const val = polyEval(codeword, GF_EXP[i]);
    syn[i] = val;
    if (val !== 0) hasError = true;
  }
  return hasError ? syn : new Uint8Array(0);
}

/**
 * Berlekamp-Massey Algorithm
 * Finds the minimal error locator polynomial Lambda(x) = 1 + Lambda_1*x + ... + Lambda_v*x^v.
 * Returns Lambda in ascending degree order: index i is coefficient of x^i.
 * Returns null if the number of errors exceeds the error correction capacity t = floor(nParity / 2).
 */
export function berlekampMassey(syndromes: Uint8Array, nParity: number): Uint8Array | null {
  let lambda: number[] = [1];
  let b: number[] = [1];
  let l = 0;
  let m = 1;
  let bDiscrepancy = 1;

  for (let r = 0; r < nParity; r++) {
    let disc = syndromes[r];
    for (let i = 1; i <= l; i++) {
      disc ^= gfMul(lambda[i], syndromes[r - i]);
    }

    if (disc === 0) {
      m++;
    } else {
      const temp = [...lambda];
      const scale = gfDiv(disc, bDiscrepancy);
      const bShifted = new Array(m).fill(0).concat(b);
      while (lambda.length < bShifted.length) lambda.push(0);

      for (let i = 0; i < bShifted.length; i++) {
        lambda[i] ^= gfMul(scale, bShifted[i]);
      }

      if (2 * l <= r) {
        l = r + 1 - l;
        b = temp;
        bDiscrepancy = disc;
        m = 1;
      } else {
        m++;
      }
    }
  }

  // Trim trailing zeros
  while (lambda.length > 1 && lambda[lambda.length - 1] === 0) {
    lambda.pop();
  }

  const maxT = Math.floor(nParity / 2);
  if (lambda.length - 1 > maxT) {
    return null; // Error count exceeds maximum capacity
  }

  return new Uint8Array(lambda);
}

/**
 * Chien Search
 * Evaluates Lambda(alpha^-i) for all positions to find roots.
 * Returns array of codeword byte indices where corruption occurred.
 * Returns null if the number of roots found does not equal the degree of Lambda(x) (uncorrectable).
 */
export function chienSearch(lambda: Uint8Array, totalLen: number): number[] | null {
  const numErrors = lambda.length - 1;
  if (numErrors === 0) return [];
  const positions: number[] = [];

  for (let i = 0; i < totalLen; i++) {
    const invAlpha = GF_EXP[(255 - (i % 255)) % 255];
    let sum = 0;
    for (let j = 0; j < lambda.length; j++) {
      sum ^= gfMul(lambda[j], gfPow(invAlpha, j));
    }
    if (sum === 0) {
      positions.push(totalLen - 1 - i);
    }
  }

  if (positions.length !== numErrors) {
    return null; // Mismatch between polynomial degree and root count
  }

  return positions;
}

/**
 * Forney Algorithm
 * Computes exact byte error values (magnitudes) for each identified error position.
 * Magnitude Y_k = X_k * Omega(X_k^-1) / Lambda'(X_k^-1)
 */
export function forney(
  syndromes: Uint8Array,
  lambda: Uint8Array,
  errorPositions: number[],
  totalLen: number
): number[] {
  const nParity = syndromes.length;
  // Omega(x) = (S(x) * Lambda(x)) mod x^nParity
  const omega = new Uint8Array(nParity);
  for (let i = 0; i < nParity; i++) {
    for (let j = 0; j < lambda.length && j <= i; j++) {
      omega[i] ^= gfMul(syndromes[i - j], lambda[j]);
    }
  }

  // Lambda'(x): formal derivative of Lambda
  const lambdaPrime = new Uint8Array(lambda.length);
  for (let i = 1; i < lambda.length; i += 2) {
    lambdaPrime[i] = lambda[i];
  }

  const magnitudes: number[] = [];
  for (const pos of errorPositions) {
    const i = totalLen - 1 - pos;
    const xInv = GF_EXP[(255 - (i % 255)) % 255];
    const x = GF_EXP[i % 255];

    let num = 0;
    for (let j = 0; j < omega.length; j++) {
      num ^= gfMul(omega[j], gfPow(xInv, j));
    }

    let den = 0;
    for (let j = 1; j < lambdaPrime.length; j += 2) {
      den ^= gfMul(lambdaPrime[j], gfPow(xInv, j - 1));
    }

    if (den === 0) {
      throw new Error('Forney denominator evaluated to zero');
    }

    let mag = gfDiv(num, den);
    mag = gfMul(mag, x);
    magnitudes.push(mag);
  }

  return magnitudes;
}

/**
 * Decodes and heals a single Reed-Solomon codeword in-place or returning healed buffer
 */
export function rsDecode(
  codeword: Uint8Array,
  nParity: number
): { data: Uint8Array; correctedCount: number; success: boolean } {
  const totalLen = codeword.length;
  const dataLen = totalLen - nParity;
  const work = new Uint8Array(codeword);

  // 1. Check Syndromes (fast-path for uncorrupted data)
  const syn = calcSyndromes(work, nParity);
  if (syn.length === 0) {
    return { data: work.subarray(0, dataLen), correctedCount: 0, success: true };
  }

  // 2. Berlekamp-Massey
  const lambda = berlekampMassey(syn, nParity);
  if (!lambda) {
    return { data: work.subarray(0, dataLen), correctedCount: 0, success: false };
  }

  // 3. Chien Search
  const positions = chienSearch(lambda, totalLen);
  if (!positions) {
    return { data: work.subarray(0, dataLen), correctedCount: 0, success: false };
  }

  // 4. Forney Evaluation
  let magnitudes: number[];
  try {
    magnitudes = forney(syn, lambda, positions, totalLen);
  } catch {
    return { data: work.subarray(0, dataLen), correctedCount: 0, success: false };
  }

  // 5. In-Place Error Healing
  for (let k = 0; k < positions.length; k++) {
    work[positions[k]] ^= magnitudes[k];
  }

  // 6. Post-Repair Syndrome Verification
  const verifySyn = calcSyndromes(work, nParity);
  if (verifySyn.length !== 0) {
    return { data: work.subarray(0, dataLen), correctedCount: 0, success: false };
  }

  return {
    data: work.subarray(0, dataLen),
    correctedCount: positions.length,
    success: true,
  };
}

// =========================================================================
// Interleaved Forward Error Correction (Burst Error & Bad Sector Resilience)
// =========================================================================

export const DEFAULT_RS_PARITY_BYTES = 16; // 16 parity bytes per codeword (t = 8 symbol errors correctable)
export const DEFAULT_INTERLEAVE_DEPTH = 64; // Interleaving depth across codewords

/**
 * Calculates max data symbols per codeword respecting GF(2^8) N <= 255 constraint
 */
export function getMaxDataSymbolsPerCodeword(nParity: number): number {
  return 255 - nParity;
}

/**
 * Encodes arbitrary length data using block-interleaved Reed-Solomon codewords.
 * Divides data into blocks of (depth * K) bytes.
 * In each block, 'depth' codewords are interleaved so consecutive byte bursts
 * are distributed across different codewords.
 */
export function encodeInterleaved(
  data: Uint8Array,
  nParity: number = DEFAULT_RS_PARITY_BYTES,
  depth: number = DEFAULT_INTERLEAVE_DEPTH
): Uint8Array {
  const dataLen = data.length;
  const K = getMaxDataSymbolsPerCodeword(nParity);
  const blockDataCap = depth * K;
  const numBlocks = Math.max(1, Math.ceil(dataLen / blockDataCap));
  const parityTotal = numBlocks * depth * nParity;
  const parity = new Uint8Array(parityTotal);

  let parityOffset = 0;

  for (let b = 0; b < numBlocks; b++) {
    const blockStart = b * blockDataCap;
    const blockEnd = Math.min(dataLen, blockStart + blockDataCap);
    const blockBytes = data.subarray(blockStart, blockEnd);
    const blockLen = blockBytes.length;

    for (let d = 0; d < depth; d++) {
      const symbolsCount = Math.ceil((blockLen - d) / depth);
      if (symbolsCount <= 0) {
        // Zero-fill unused parity slot for this block
        parityOffset += nParity;
        continue;
      }

      const stream = new Uint8Array(symbolsCount);
      for (let i = 0; i < symbolsCount; i++) {
        stream[i] = blockBytes[d + i * depth];
      }

      const encoded = rsEncode(stream, nParity);
      const pSlice = encoded.subarray(symbolsCount, symbolsCount + nParity);
      parity.set(pSlice, parityOffset);
      parityOffset += nParity;
    }
  }

  return parity;
}

/**
 * Decodes and heals block-interleaved data in-place using stored parity symbols.
 * Seamlessly corrects both random bit flips and consecutive burst corruptions (e.g. bad sectors).
 */
export function decodeInterleaved(
  data: Uint8Array,
  parity: Uint8Array,
  nParity: number = DEFAULT_RS_PARITY_BYTES,
  depth: number = DEFAULT_INTERLEAVE_DEPTH
): { healedBytes: number; success: boolean } {
  const dataLen = data.length;
  const K = getMaxDataSymbolsPerCodeword(nParity);
  const blockDataCap = depth * K;
  const numBlocks = Math.max(1, Math.ceil(dataLen / blockDataCap));
  const expectedParityLen = numBlocks * depth * nParity;

  if (parity.length < expectedParityLen) {
    return { healedBytes: 0, success: false };
  }

  let totalHealed = 0;
  let parityOffset = 0;

  for (let b = 0; b < numBlocks; b++) {
    const blockStart = b * blockDataCap;
    const blockEnd = Math.min(dataLen, blockStart + blockDataCap);
    const blockBytes = data.subarray(blockStart, blockEnd);
    const blockLen = blockBytes.length;

    for (let d = 0; d < depth; d++) {
      const symbolsCount = Math.ceil((blockLen - d) / depth);
      if (symbolsCount <= 0) {
        parityOffset += nParity;
        continue;
      }

      // Assemble interleaved codeword
      const codeword = new Uint8Array(symbolsCount + nParity);
      for (let i = 0; i < symbolsCount; i++) {
        codeword[i] = blockBytes[d + i * depth];
      }
      codeword.set(parity.subarray(parityOffset, parityOffset + nParity), symbolsCount);
      parityOffset += nParity;

      const res = rsDecode(codeword, nParity);
      if (!res.success) {
        return { healedBytes: totalHealed, success: false };
      }

      if (res.correctedCount > 0) {
        for (let i = 0; i < symbolsCount; i++) {
          if (blockBytes[d + i * depth] !== res.data[i]) {
            blockBytes[d + i * depth] = res.data[i];
            totalHealed++;
          }
        }
      }
    }
  }

  return { healedBytes: totalHealed, success: true };
}


// =========================================================================
// Critical Metadata Blob Self-Healing
// =========================================================================

export const METADATA_CRITICAL_LEN = 160; // First 160 bytes: Magic, Version, Sizes, Nonces, HMAC, OrderConfirm, Timestamp
export const METADATA_ECC_PARITY_LEN = 64; // 64 parity symbols -> Corrects up to 32 byte errors (20% corruption!)
export const METADATA_ECC_OFFSET = 160; // Located in the 352-byte random padding area (bytes 160 to 223)

/**
 * Protects a 512-byte metadata blob by embedding 64 bytes of systematic Reed-Solomon parity
 * into bytes 160-223.
 */
export function protectMetadataBlob(blob512: Uint8Array): void {
  if (blob512.length !== 512) {
    throw new Error('Metadata blob must be exactly 512 bytes.');
  }
  const critical = blob512.subarray(0, METADATA_CRITICAL_LEN);
  const encoded = rsEncode(critical, METADATA_ECC_PARITY_LEN);
  const parity = encoded.subarray(METADATA_CRITICAL_LEN, METADATA_CRITICAL_LEN + METADATA_ECC_PARITY_LEN);
  blob512.set(parity, METADATA_ECC_OFFSET);
}

/**
 * Checks and heals a 512-byte metadata blob if silent corruption occurred.
 * Restores magic, nonces, chunk counts, and cryptographic headers to authentic state.
 */
export function healMetadataBlob(blob512: Uint8Array): { healed: boolean; correctedCount: number } {
  if (blob512.length !== 512) {
    return { healed: false, correctedCount: 0 };
  }

  // Construct codeword from critical headers and stored parity
  const codeword = new Uint8Array(METADATA_CRITICAL_LEN + METADATA_ECC_PARITY_LEN);
  codeword.set(blob512.subarray(0, METADATA_CRITICAL_LEN), 0);
  codeword.set(blob512.subarray(METADATA_ECC_OFFSET, METADATA_ECC_OFFSET + METADATA_ECC_PARITY_LEN), METADATA_CRITICAL_LEN);

  try {
    const res = rsDecode(codeword, METADATA_ECC_PARITY_LEN);
    if (!res.success) {
      return { healed: false, correctedCount: 0 };
    }

    if (res.correctedCount > 0) {
      // Write back healed critical header bytes
      blob512.set(res.data, 0);
      return { healed: true, correctedCount: res.correctedCount };
    }

    return { healed: false, correctedCount: 0 };
  } finally {
    codeword.fill(0);
  }
}
