/**
 * ============================================================================
 * OSM ARMY GIFT CODE FORTRESS - INFINITE MUTATION ENGINE
 * 7 Mutation Algorithms - The Crown Jewel That Makes Hackers Cry Daily
 * Copyright (c) 2024 osmarmy.com - All Rights Reserved
 * ============================================================================
 *
 * The INFINITE MUTATION ENGINE provides 7 fully implemented mutation
 * algorithms with daily seed-based selection, algorithm chaining,
 * endpoint mutation, validation rule mutation, and more.
 *
 * @module core/mutate
 * @version 7.0.0
 * @license PROPRIETARY
 */

'use strict';

import { createHash, randomBytes, timingSafeEqual, createHmac } from 'crypto';

// ============================================================================
// CONSTANTS
// ============================================================================

const GF_IRREDUCIBLE = 0x11B; // x^8 + x^4 + x^3 + x + 1
const LOGISTIC_R_BASE = 3.9;
const MAX_CHAIN_DEPTH = 3;
const SBOX_SIZE = 256;

// ============================================================================
// GALOIS FIELD ARITHMETIC (GF(2^8))
// ============================================================================

/**
 * Galois Field addition (XOR)
 * @param {number} a - First element
 * @param {number} b - Second element
 * @returns {number} a + b in GF(2^8)
 */
function gfAdd(a, b) {
  return (a ^ b) & 0xFF;
}

/**
 * Galois Field subtraction (same as addition in GF(2^8))
 * @param {number} a - First element
 * @param {number} b - Second element
 * @returns {number} a - b in GF(2^8)
 */
function gfSub(a, b) {
  return (a ^ b) & 0xFF;
}

/**
 * Galois Field multiplication modulo irreducible polynomial
 * @param {number} a - First element
 * @param {number} b - Second element
 * @returns {number} a * b in GF(2^8)
 */
function gfMul(a, b) {
  let result = 0;
  let aa = a & 0xFF;
  let bb = b & 0xFF;
  for (let i = 0; i < 8; i++) {
    if ((bb & 1) !== 0) {
      result ^= aa;
    }
    const hiBitSet = (aa & 0x80) !== 0;
    aa = (aa << 1) & 0xFF;
    if (hiBitSet) {
      aa ^= 0x1B; // Reduction modulo 0x11B (high bit already shifted out)
    }
    bb >>= 1;
  }
  return result & 0xFF;
}

/**
 * Galois Field division
 * @param {number} a - Dividend
 * @param {number} b - Divisor
 * @returns {number} a / b in GF(2^8)
 */
function gfDiv(a, b) {
  if (b === 0) throw new Error('Division by zero in GF(2^8)');
  const invB = gfInverse(b);
  return gfMul(a & 0xFF, invB);
}

/**
 * Galois Field multiplicative inverse using Fermat's little theorem
 * In GF(2^8), a^255 = 1 for all a != 0, so a^-1 = a^254
 * Uses square-and-multiply exponentiation for O(log n) performance
 * @param {number} a - Element to invert
 * @returns {number} a^-1 in GF(2^8)
 */
function gfInverse(a) {
  a = a & 0xFF;
  if (a === 0) throw new Error('Zero has no multiplicative inverse');
  return gfPow(a, 254);
}

/**
 * Polynomial multiplication without reduction
 * @param {number} a - First polynomial
 * @param {number} b - Second polynomial
 * @returns {number} Product
 */
function gfMulPoly(a, b) {
  let result = 0;
  for (let i = 0; i < 8; i++) {
    if ((b & (1 << i)) !== 0) {
      result ^= a << i;
    }
  }
  return result;
}

/**
 * Galois Field exponentiation
 * @param {number} base - Base element
 * @param {number} exp - Exponent
 * @returns {number} base^exp in GF(2^8)
 */
function gfPow(base, exp) {
  let result = 1;
  let b = base & 0xFF;
  let e = exp;
  while (e > 0) {
    if ((e & 1) === 1) {
      result = gfMul(result, b);
    }
    b = gfMul(b, b);
    e >>= 1;
  }
  return result & 0xFF;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Fisher-Yates shuffle with seed-based PRNG
 * @param {number[]} array - Array to shuffle
 * @param {number} seed - Random seed
 * @returns {number[]} Shuffled array (new)
 */
function seededShuffle(array, seed) {
  const arr = [...array];
  let s = seed >>> 0;
  const next = () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s;
  };
  for (let i = arr.length - 1; i > 0; i--) {
    const j = next() % (i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

/**
 * Seeded random number generator (LCG)
 * @param {number} seed - Initial seed
 * @returns {() => number} Random function [0, 1)
 */
function createSeededRandom(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 4294967296;
  };
}

/**
 * Generate hash from data for seed derivation
 * @param {string|Buffer} data - Input data
 * @returns {number} 32-bit seed
 */
function deriveSeed(data) {
  const hash = createHash('sha256').update(String(data)).digest('hex');
  return parseInt(hash.substring(0, 8), 16) >>> 0;
}

/**
 * Rotate byte left by n bits
 * @param {number} byte - Byte to rotate
 * @param {number} n - Number of bits
 * @returns {number} Rotated byte
 */
function rotateLeft(byte, n) {
  const b = byte & 0xFF;
  const shift = n % 8;
  return ((b << shift) | (b >>> (8 - shift))) & 0xFF;
}

/**
 * Rotate byte right by n bits
 * @param {number} byte - Byte to rotate
 * @param {number} n - Number of bits
 * @returns {number} Rotated byte
 */
function rotateRight(byte, n) {
  const b = byte & 0xFF;
  const shift = n % 8;
  return ((b >>> shift) | (b << (8 - shift))) & 0xFF;
}

/**
 * Pad data to multiple of block size
 * @param {Buffer} data - Data to pad
 * @param {number} blockSize - Block size
 * @returns {Buffer} Padded data
 */
function padData(data, blockSize) {
  const padding = blockSize - (data.length % blockSize);
  const buf = Buffer.alloc(data.length + padding);
  data.copy(buf);
  for (let i = data.length; i < buf.length; i++) {
    buf[i] = padding;
  }
  return buf;
}

/**
 * Remove padding from data
 * @param {Buffer} data - Padded data
 * @returns {Buffer} Unpadded data
 */
function unpadData(data) {
  if (data.length === 0) return data;
  const padding = data[data.length - 1];
  if (padding > data.length) return data;
  return data.subarray(0, data.length - padding);
}

/**
 * Validate input data (string or Buffer)
 * @param {*} data - Data to validate
 * @returns {Buffer}
 */
function validateInput(data) {
  if (typeof data === 'string') return Buffer.from(data, 'utf8');
  if (Buffer.isBuffer(data)) return data;
  throw new TypeError('Data must be a string or Buffer');
}

/**
 * Validate key
 * @param {*} key - Key to validate
 * @returns {Buffer}
 */
function validateKey(key) {
  if (typeof key === 'string') return Buffer.from(key, 'utf8');
  if (Buffer.isBuffer(key)) return key;
  throw new TypeError('Key must be a string or Buffer');
}

/**
 * Derive daily seed from date
 * @returns {number} Daily seed
 */
function getDailySeed() {
  const date = new Date();
  const dateStr = `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}-${String(date.getUTCDate()).padStart(2, '0')}`;
  return deriveSeed(dateStr);
}

// ============================================================================
// MUTATION ALGORITHM 1: XOR-ROTATE MUTATION
// ============================================================================

/**
 * Algorithm 1: XOR-Rotate Mutation
 * For each byte: result[i] = data[i] ^ key[i % keyLen] ^ ((i * 7 + seed) % 256)
 * Then rotate left by (seed % 8) bits
 *
 * @param {Buffer} data - Input data
 * @param {Buffer} key - Mutation key
 * @param {number} seed - Mutation seed
 * @returns {Buffer} Mutated data
 */
export function xorRotateMutate(data, key, seed) {
  const input = validateInput(data);
  const k = validateKey(key);
  const s = seed >>> 0;
  const keyLen = k.length;
  if (keyLen === 0) throw new Error('Key cannot be empty');

  const result = Buffer.alloc(input.length);

  // Step 1: XOR each byte
  for (let i = 0; i < input.length; i++) {
    result[i] = (input[i] ^ k[i % keyLen] ^ ((i * 7 + s) & 0xFF)) & 0xFF;
  }

  // Step 2: Rotate each byte left by (seed % 8) bits
  const rotateBits = s % 8;
  if (rotateBits !== 0) {
    for (let i = 0; i < result.length; i++) {
      result[i] = rotateLeft(result[i], rotateBits);
    }
  }

  return result;
}

/**
 * Algorithm 1: XOR-Rotate Inverse (demutation)
 * @param {Buffer} data - Mutated data
 * @param {Buffer} key - Mutation key
 * @param {number} seed - Mutation seed
 * @returns {Buffer} Original data
 */
export function xorRotateInverse(data, key, seed) {
  const input = validateInput(data);
  const k = validateKey(key);
  const s = seed >>> 0;
  const keyLen = k.length;
  if (keyLen === 0) throw new Error('Key cannot be empty');

  const result = Buffer.alloc(input.length);

  // Copy input (we'll mutate in place)
  input.copy(result);

  // Step 1: Rotate right (inverse of rotate left)
  const rotateBits = s % 8;
  if (rotateBits !== 0) {
    for (let i = 0; i < result.length; i++) {
      result[i] = rotateRight(result[i], rotateBits);
    }
  }

  // Step 2: XOR again (XOR is its own inverse)
  for (let i = 0; i < result.length; i++) {
    result[i] = (result[i] ^ k[i % keyLen] ^ ((i * 7 + s) & 0xFF)) & 0xFF;
  }

  return result;
}

// ============================================================================
// MUTATION ALGORITHM 2: ADD-SHIFT MUTATION
// ============================================================================

/**
 * Algorithm 2: Add-Shift Mutation
 * For each byte: result[i] = (data[i] + key[i % keyLen] + (seed * i)) % 256
 * Then shift by seed-derived pattern
 *
 * @param {Buffer} data - Input data
 * @param {Buffer} key - Mutation key
 * @param {number} seed - Mutation seed
 * @returns {Buffer} Mutated data
 */
export function addShiftMutate(data, key, seed) {
  const input = validateInput(data);
  const k = validateKey(key);
  const s = seed >>> 0;
  const keyLen = k.length;
  if (keyLen === 0) throw new Error('Key cannot be empty');

  const result = Buffer.alloc(input.length);

  // Step 1: Add-shift each byte
  for (let i = 0; i < input.length; i++) {
    result[i] = (input[i] + k[i % keyLen] + (s * i)) & 0xFF;
  }

  // Step 2: Shift by seed-derived pattern
  const shiftPattern = s % 8;
  if (shiftPattern !== 0) {
    const temp = Buffer.alloc(result.length);
    result.copy(temp);
    for (let i = 0; i < result.length; i++) {
      const srcIdx = (i + shiftPattern) % result.length;
      result[i] = temp[srcIdx];
    }
  }

  return result;
}

/**
 * Algorithm 2: Add-Shift Inverse (demutation)
 * @param {Buffer} data - Mutated data
 * @param {Buffer} key - Mutation key
 * @param {number} seed - Mutation seed
 * @returns {Buffer} Original data
 */
export function addShiftInverse(data, key, seed) {
  const input = validateInput(data);
  const k = validateKey(key);
  const s = seed >>> 0;
  const keyLen = k.length;
  if (keyLen === 0) throw new Error('Key cannot be empty');

  const result = Buffer.alloc(input.length);
  input.copy(result);

  // Step 1: Inverse shift
  const shiftPattern = s % 8;
  if (shiftPattern !== 0) {
    const temp = Buffer.alloc(result.length);
    result.copy(temp);
    for (let i = 0; i < result.length; i++) {
      const srcIdx = (i - shiftPattern + result.length) % result.length;
      result[i] = temp[srcIdx];
    }
  }

  // Step 2: Subtract (inverse of add)
  for (let i = 0; i < result.length; i++) {
    result[i] = (result[i] - k[i % keyLen] - (s * i)) & 0xFF;
  }

  return result;
}

// ============================================================================
// MUTATION ALGORITHM 3: SUBSTITUTION BOX (S-BOX) MUTATION
// ============================================================================

/**
 * Algorithm 3: S-Box Mutation
 * Generate S-Box from seed using Fisher-Yates shuffle of 0-255
 * Substitute each byte through S-Box
 *
 * @param {Buffer} data - Input data
 * @param {number} seed - Mutation seed
 * @returns {Object} { mutated: Buffer, sbox: number[], invSbox: number[] }
 */
export function sboxMutate(data, seed) {
  const input = validateInput(data);
  const s = seed >>> 0;

  // Generate S-Box
  const sbox = seededShuffle(Array.from({ length: SBOX_SIZE }, (_, i) => i), s);

  // Generate inverse S-Box
  const invSbox = new Array(SBOX_SIZE);
  for (let i = 0; i < SBOX_SIZE; i++) {
    invSbox[sbox[i]] = i;
  }

  // Substitute each byte
  const result = Buffer.alloc(input.length);
  for (let i = 0; i < input.length; i++) {
    result[i] = sbox[input[i] & 0xFF];
  }

  return { mutated: result, sbox, invSbox };
}

/**
 * Algorithm 3: S-Box Inverse (demutation)
 * @param {Buffer} data - Mutated data
 * @param {number[]} invSbox - Inverse S-Box
 * @returns {Buffer} Original data
 */
export function sboxInverse(data, invSbox) {
  const input = validateInput(data);
  if (!invSbox || invSbox.length !== SBOX_SIZE) {
    throw new Error('Invalid inverse S-Box');
  }

  const result = Buffer.alloc(input.length);
  for (let i = 0; i < input.length; i++) {
    result[i] = invSbox[input[i] & 0xFF];
  }

  return result;
}

// ============================================================================
// MUTATION ALGORITHM 4: MATRIX (4x4) MUTATION
// ============================================================================

/**
 * Algorithm 4: Matrix (4x4) Mutation
 * Treat data as 4x4 matrices, apply matrix multiplication with seed-derived matrix
 * Modulo 256 arithmetic, use invertible matrix for decryption
 *
 * @param {Buffer} data - Input data
 * @param {number} seed - Mutation seed
 * @returns {Object} { mutated: Buffer, matrix: number[][], inverseMatrix: number[][] }
 */
export function matrixMutate(data, seed) {
  const input = validateInput(data);
  const s = seed >>> 0;

  // Generate invertible 4x4 matrix from seed
  const matrix = generateInvertibleMatrix(s);

  // Calculate inverse matrix
  const inverseMatrix = invertMatrixMod256(matrix);

  // Store original length for unpadding
  const originalLength = input.length;

  // Pad data to multiple of 16 (4x4)
  const padded = padData(input, 16);
  const result = Buffer.alloc(padded.length);

  // Process 16 bytes at a time (each 4x4 matrix)
  for (let block = 0; block < padded.length; block += 16) {
    const state = [];
    // Read 4x4 state from data (column-major)
    for (let col = 0; col < 4; col++) {
      for (let row = 0; row < 4; row++) {
        state.push(padded[block + col * 4 + row] & 0xFF);
      }
    }

    // Multiply matrix by state
    const output = [];
    for (let row = 0; row < 4; row++) {
      for (let col = 0; col < 4; col++) {
        let sum = 0;
        for (let k = 0; k < 4; k++) {
          sum = gfAdd(sum, gfMul(matrix[row][k], state[col * 4 + k]));
        }
        output.push(sum & 0xFF);
      }
    }

    // Write output (output[row*4+col] = element at row,col, write to column-major buffer)
    for (let row = 0; row < 4; row++) {
      for (let col = 0; col < 4; col++) {
        result[block + col * 4 + row] = output[row * 4 + col];
      }
    }
  }

  return { mutated: result, matrix, inverseMatrix, originalLength };
}

/**
 * Algorithm 4: Matrix Inverse (demutation)
 * @param {Buffer} data - Mutated data
 * @param {number[][]} inverseMatrix - Inverse 4x4 matrix
 * @returns {Buffer} Original data
 */
export function matrixInverse(data, inverseMatrix, originalLength) {
  const input = validateInput(data);
  if (!inverseMatrix || inverseMatrix.length !== 4) {
    throw new Error('Invalid inverse matrix');
  }

  const result = Buffer.alloc(input.length);

  // Process 16 bytes at a time
  for (let block = 0; block < input.length; block += 16) {
    const state = [];
    for (let col = 0; col < 4; col++) {
      for (let row = 0; row < 4; row++) {
        state.push(input[block + col * 4 + row] & 0xFF);
      }
    }

    const output = [];
    for (let row = 0; row < 4; row++) {
      for (let col = 0; col < 4; col++) {
        let sum = 0;
        for (let k = 0; k < 4; k++) {
          sum = gfAdd(sum, gfMul(inverseMatrix[row][k], state[col * 4 + k]));
        }
        output.push(sum & 0xFF);
      }
    }

    for (let row = 0; row < 4; row++) {
      for (let col = 0; col < 4; col++) {
        result[block + col * 4 + row] = output[row * 4 + col];
      }
    }
  }

  // Use stored original length for accurate unpadding
  if (originalLength !== undefined && originalLength < result.length) {
    return result.subarray(0, originalLength);
  }
  return unpadData(result);
}

/**
 * Generate an invertible 4x4 matrix over GF(2^8)
 * @param {number} seed - Random seed
 * @returns {number[][]} Invertible 4x4 matrix
 */
function generateInvertibleMatrix(seed) {
  const rng = createSeededRandom(seed);

  // Generate a random upper triangular matrix with non-zero diagonal
  const upper = [];
  for (let i = 0; i < 4; i++) {
    upper[i] = [];
    for (let j = 0; j < 4; j++) {
      if (j < i) {
        upper[i][j] = 0;
      } else if (j === i) {
        // Ensure diagonal is non-zero
        upper[i][j] = (Math.floor(rng() * 255) + 1) & 0xFF;
      } else {
        upper[i][j] = Math.floor(rng() * 256) & 0xFF;
      }
    }
  }

  // Generate a random lower triangular matrix with non-zero diagonal
  const lower = [];
  for (let i = 0; i < 4; i++) {
    lower[i] = [];
    for (let j = 0; j < 4; j++) {
      if (j > i) {
        lower[i][j] = 0;
      } else if (j === i) {
        lower[i][j] = (Math.floor(rng() * 255) + 1) & 0xFF;
      } else {
        lower[i][j] = Math.floor(rng() * 256) & 0xFF;
      }
    }
  }

  // Product of two triangular matrices with non-zero diagonals is invertible
  return matrixMultiplyMod256(lower, upper);
}

/**
 * Matrix multiplication modulo 256 over GF(2^8)
 * @param {number[][]} a - First matrix
 * @param {number[][]} b - Second matrix
 * @returns {number[][]} Product matrix
 */
function matrixMultiplyMod256(a, b) {
  const result = [];
  for (let i = 0; i < 4; i++) {
    result[i] = [];
    for (let j = 0; j < 4; j++) {
      let sum = 0;
      for (let k = 0; k < 4; k++) {
        sum = gfAdd(sum, gfMul(a[i][k], b[k][j]));
      }
      result[i][j] = sum & 0xFF;
    }
  }
  return result;
}

/**
 * Invert a 4x4 matrix over GF(2^8) using Gaussian elimination
 * @param {number[][]} matrix - Matrix to invert
 * @returns {number[][]} Inverse matrix
 */
/**
 * Invert a 4x4 matrix over GF(2^8) using Gaussian elimination
 * [A | I] -> [I | A^-1] via row operations
 */
function invertMatrixMod256(matrix) {
  // Create working copy and identity
  const a = [];
  const inv = [];
  for (let i = 0; i < 4; i++) {
    a[i] = [];
    inv[i] = [];
    for (let j = 0; j < 4; j++) {
      a[i][j] = matrix[i][j];
      inv[i][j] = (i === j) ? 1 : 0;
    }
  }

  // Gaussian elimination
  for (let col = 0; col < 4; col++) {
    // Find a row with non-zero in this column
    let pivotRow = col;
    while (pivotRow < 4 && a[pivotRow][col] === 0) pivotRow++;

    if (pivotRow >= 4) {
      // Singular matrix - fall back to identity
      return [[1,0,0,0],[0,1,0,0],[0,0,1,0],[0,0,0,1]];
    }

    // Swap current row with pivot row
    if (pivotRow !== col) {
      [a[col], a[pivotRow]] = [a[pivotRow], a[col]];
      [inv[col], inv[pivotRow]] = [inv[pivotRow], inv[col]];
    }

    // Scale pivot row to make pivot element = 1
    const pivotVal = a[col][col];
    if (pivotVal !== 1) {
      const pivotInv = gfInverse(pivotVal);
      for (let j = 0; j < 4; j++) {
        a[col][j] = gfMul(a[col][j], pivotInv);
        inv[col][j] = gfMul(inv[col][j], pivotInv);
      }
    }

    // Eliminate this column from all other rows
    for (let row = 0; row < 4; row++) {
      if (row !== col && a[row][col] !== 0) {
        const factor = a[row][col];
        for (let j = 0; j < 4; j++) {
          a[row][j] = gfAdd(a[row][j], gfMul(factor, a[col][j]));
          inv[row][j] = gfAdd(inv[row][j], gfMul(factor, inv[col][j]));
        }
      }
    }
  }

  return inv;
}

// ============================================================================
// MUTATION ALGORITHM 5: POLYNOMIAL MUTATION (GF(2^8))
// ============================================================================

/**
 * Algorithm 5: Polynomial Mutation
 * Use seed as polynomial coefficients over GF(2^8)
 * Multiply data bytes as polynomial evaluation
 * Use irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B)
 *
 * @param {Buffer} data - Input data
 * @param {number} seed - Mutation seed
 * @returns {Object} { mutated: Buffer, poly: number[] }
 */
/**
 * Algorithm 5: Polynomial Mutation (GF(2^8) Keystream)
 * Uses polynomial over GF(2^8) to generate a keystream,
 * then XORs data with the keystream (guaranteed bijective).
 * This makes the mutation a self-inverse stream cipher.
 * Uses irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B)
 *
 * @param {Buffer} data - Input data
 * @param {number} seed - Mutation seed
 * @returns {Object} { mutated: Buffer, poly: number[] }
 */
export function polynomialMutate(data, seed) {
  const input = validateInput(data);
  const s = seed >>> 0;

  // Derive polynomial coefficients from seed
  // Polynomial: c0 + c1*x + c2*x^2 + c3*x^3 + c4*x^4
  const hash = createHash('sha256').update(`poly-${s}`).digest();
  const poly = [];
  for (let i = 0; i < 5; i++) {
    poly.push(hash[i] & 0xFF);
  }

  const result = Buffer.alloc(input.length);

  // Generate keystream from polynomial evaluation over GF(2^8)
  // The keystream is generated by evaluating the polynomial at each position
  // This is equivalent to a stream cipher and is always bijective
  for (let i = 0; i < input.length; i++) {
    const x = (i + 1) & 0xFF; // Use 1-based position as polynomial input
    let px = poly[0];
    let xn = x;
    for (let j = 1; j < 5; j++) {
      px = gfAdd(px, gfMul(poly[j], xn));
      xn = gfMul(xn, x);
    }
    // XOR data byte with keystream byte (self-inverse)
    result[i] = (input[i] ^ px) & 0xFF;
  }

  return { mutated: result, poly };
}

/**
 * Algorithm 5: Polynomial Inverse (demutation)
 * XOR again with the same keystream (self-inverse property of XOR)
 * @param {Buffer} data - Mutated data
 * @param {number[]} poly - Polynomial coefficients
 * @returns {Buffer} Original data
 */
export function polynomialInverse(data, poly) {
  const input = validateInput(data);
  if (!poly || poly.length !== 5) {
    throw new Error('Invalid polynomial coefficients');
  }

  const result = Buffer.alloc(input.length);

  // Regenerate identical keystream and XOR (same as mutation)
  for (let i = 0; i < input.length; i++) {
    const x = (i + 1) & 0xFF;
    let px = poly[0];
    let xn = x;
    for (let j = 1; j < 5; j++) {
      px = gfAdd(px, gfMul(poly[j], xn));
      xn = gfMul(xn, x);
    }
    result[i] = (input[i] ^ px) & 0xFF;
  }

  return result;
}

// ============================================================================
// MUTATION ALGORITHM 6: CHAOS (LOGISTIC MAP) MUTATION
// ============================================================================

/**
 * Algorithm 6: Chaos (Logistic Map) Mutation
 * x = 0.5 (initial condition)
 * For each byte:
 *   x = r * x * (1 - x) where r = 3.9 + (seed % 100) / 1000
 *   result[i] = data[i] ^ (int)(x * 256) ^ key[i % keyLen]
 *
 * @param {Buffer} data - Input data
 * @param {Buffer} key - Mutation key
 * @param {number} seed - Mutation seed
 * @returns {Buffer} Mutated data
 */
export function chaosMutate(data, key, seed) {
  const input = validateInput(data);
  const k = validateKey(key);
  const s = seed >>> 0;
  const keyLen = k.length;
  if (keyLen === 0) throw new Error('Key cannot be empty');

  // Logistic map parameters
  const r = LOGISTIC_R_BASE + (s % 100) / 1000;
  let x = 0.5; // Initial condition

  // Pre-warm the chaotic system (100 iterations to settle)
  for (let i = 0; i < 100; i++) {
    x = r * x * (1 - x);
  }

  const result = Buffer.alloc(input.length);

  // Mutate each byte using chaotic values
  for (let i = 0; i < input.length; i++) {
    // Iterate chaotic map
    x = r * x * (1 - x);
    const chaoticByte = Math.floor(x * 256) & 0xFF;

    // XOR with chaotic value and key
    result[i] = (input[i] ^ chaoticByte ^ k[i % keyLen]) & 0xFF;
  }

  return result;
}

/**
 * Algorithm 6: Chaos Inverse (demutation)
 * @param {Buffer} data - Mutated data
 * @param {Buffer} key - Mutation key
 * @param {number} seed - Mutation seed
 * @returns {Buffer} Original data
 */
export function chaosInverse(data, key, seed) {
  const input = validateInput(data);
  const k = validateKey(key);
  const s = seed >>> 0;
  const keyLen = k.length;
  if (keyLen === 0) throw new Error('Key cannot be empty');

  // Reconstruct same chaotic sequence
  const r = LOGISTIC_R_BASE + (s % 100) / 1000;
  let x = 0.5;

  // Pre-warm identically
  for (let i = 0; i < 100; i++) {
    x = r * x * (1 - x);
  }

  const result = Buffer.alloc(input.length);

  // Inverse: XOR again with same sequence (XOR is its own inverse)
  for (let i = 0; i < input.length; i++) {
    x = r * x * (1 - x);
    const chaoticByte = Math.floor(x * 256) & 0xFF;
    result[i] = (input[i] ^ chaoticByte ^ k[i % keyLen]) & 0xFF;
  }

  return result;
}

// ============================================================================
// MUTATION ALGORITHM 7: PERMUTATION MUTATION
// ============================================================================

/**
 * Algorithm 7: Permutation Mutation
 * Generate permutation table from seed (Fisher-Yates of indices)
 * Rearrange data bytes according to permutation
 * Inverse permutation for decryption
 *
 * @param {Buffer} data - Input data
 * @param {number} seed - Mutation seed
 * @returns {Object} { mutated: Buffer, permutation: number[], invPermutation: number[] }
 */
export function permutationMutate(data, seed) {
  const input = validateInput(data);
  const s = seed >>> 0;
  const len = input.length;

  if (len === 0) return { mutated: Buffer.alloc(0), permutation: [], invPermutation: [] };

  // Generate permutation using block-based approach for large data
  const blockSize = Math.min(len, 256);
  const numBlocks = Math.ceil(len / blockSize);

  // Base permutation for a block
  const basePerm = seededShuffle(Array.from({ length: blockSize }, (_, i) => i), s);

  const result = Buffer.alloc(len);
  const permutation = new Array(len);
  const invPermutation = new Array(len);

  for (let block = 0; block < numBlocks; block++) {
    const blockStart = block * blockSize;
    const currentBlockSize = Math.min(blockSize, len - blockStart);

    // Generate a proper bijective permutation for this block size
    const blockPerm = seededShuffle(
      Array.from({ length: currentBlockSize }, (_, i) => i),
      s + block * 31
    );

    // Apply permutation to this block
    for (let i = 0; i < currentBlockSize; i++) {
      const srcIdx = blockStart + i;
      const dstIdx = blockStart + blockPerm[i];
      result[dstIdx] = input[srcIdx];
      permutation[srcIdx] = dstIdx;
    }
  }

  // Build inverse permutation
  for (let i = 0; i < len; i++) {
    invPermutation[permutation[i]] = i;
  }

  return { mutated: result, permutation, invPermutation };
}

/**
 * Algorithm 7: Permutation Inverse (demutation)
 * @param {Buffer} data - Mutated data
 * @param {number[]} invPermutation - Inverse permutation
 * @returns {Buffer} Original data
 */
export function permutationInverse(data, permutation) {
  const input = validateInput(data);
  if (!permutation || permutation.length !== input.length) {
    throw new Error('Invalid permutation');
  }

  const result = Buffer.alloc(input.length);

  // mutated[dst] = original[src] where dst = permutation[src]
  // So original[src] = mutated[permutation[src]]
  for (let i = 0; i < input.length; i++) {
    result[i] = input[permutation[i]];
  }

  return result;
}

// ============================================================================
// ALGORITHM REGISTRY
// ============================================================================

const ALGORITHM_REGISTRY = {
  0: {
    name: 'XOR-Rotate',
    mutate: xorRotateMutate,
    inverse: xorRotateInverse,
    needsKey: true,
  },
  1: {
    name: 'Add-Shift',
    mutate: addShiftMutate,
    inverse: addShiftInverse,
    needsKey: true,
  },
  2: {
    name: 'S-Box',
    mutate: sboxMutate,
    inverse: (data, _, extra) => sboxInverse(data, extra.invSbox),
    needsKey: false,
    returnsExtra: true,
  },
  3: {
    name: 'Matrix-4x4',
    mutate: matrixMutate,
    inverse: (data, _, extra) => matrixInverse(data, extra.inverseMatrix, extra.originalLength),
    needsKey: false,
    returnsExtra: true,
  },
  4: {
    name: 'Polynomial-GF',
    mutate: polynomialMutate,
    inverse: (data, _, extra) => polynomialInverse(data, extra.poly),
    needsKey: false,
    returnsExtra: true,
  },
  5: {
    name: 'Chaos-Logistic',
    mutate: chaosMutate,
    inverse: chaosInverse,
    needsKey: true,
  },
  6: {
    name: 'Permutation',
    mutate: permutationMutate,
    inverse: (data, _, extra) => permutationInverse(data, extra.permutation),
    needsKey: false,
    returnsExtra: true,
  },
};

// ============================================================================
// MUTATOR CLASS
// ============================================================================

/**
 * The Infinite Mutation Engine - Main Mutator class
 * Handles daily algorithm selection, chaining, endpoint mutation, and more
 */
export class Mutator {
  /**
   * Create a new Mutator
   * @param {Object} config - Configuration
   * @param {number} config.seed - Daily seed (auto-generated from date if not provided)
   * @param {Buffer} config.masterKey - Master mutation key
   */
  constructor(config = {}) {
    this.config = {
      seed: config.seed || getDailySeed(),
      masterKey: config.masterKey || randomBytes(32),
      ...config,
    };

    this.seed = this.config.seed;
    this.rng = createSeededRandom(this.seed);
    this.currentAlgorithms = [];
    this.currentKeys = [];
    this.mutationHistory = [];
    this.endpointMap = new Map();
    this.validationRules = new Map();
    this.imageFormat = 'png';
    this.dailyKey = this._deriveDailyKey();
    this.initialized = false;

    // Initialize for the day
    this._initializeDailyMutation();
  }

  /** Initialize daily mutation state */
  _initializeDailyMutation() {
    // Select 2-3 algorithms to chain
    const numAlgorithms = 2 + (this.seed % 2);
    const algoOrder = seededShuffle([0, 1, 2, 3, 4, 5, 6], this.seed);
    this.currentAlgorithms = algoOrder.slice(0, numAlgorithms);

    // Derive keys for each algorithm
    this.currentKeys = this.currentAlgorithms.map((algoIdx, i) => {
      return createHash('sha256').update(this.dailyKey).update(`algo-${algoIdx}-${i}`).digest();
    });

    // Mutate endpoints
    this._mutateEndpoints();

    // Mutate validation rules
    this._mutateValidationRules();

    // Mutate image format
    this._mutateImageFormat();

    this.initialized = true;
    this._logMutation('INIT', { algorithms: this.currentAlgorithms, seed: this.seed });
  }

  /** Derive daily key from master key and seed */
  _deriveDailyKey() {
    return createHash('sha256').update(this.config.masterKey).update(`daily-${this.seed}`).digest();
  }

  /** Mutate endpoint names */
  _mutateEndpoints() {
    const baseEndpoints = {
      '/api/claim': '/api/claim',
      '/api/verify': '/api/verify',
      '/api/balance': '/api/balance',
      '/api/transfer': '/api/transfer',
      '/api/history': '/api/history',
      '/api/settings': '/api/settings',
      '/api/gift': '/api/gift',
      '/api/redeem': '/api/redeem',
    };

    const prefixes = ['a', 'b', 'g', 'd', 'e', 'z', 'k', 'm'];
    const suffix = this.seed.toString(36).substring(0, 4);

    for (const [base, _] of Object.entries(baseEndpoints)) {
      const prefixIdx = (this.seed + base.length * 7) % prefixes.length;
      const mutated = `/api/${prefixes[prefixIdx]}/${suffix}${base.replace('/api/', '/')}`;
      this.endpointMap.set(base, mutated);
      this.endpointMap.set(mutated, base); // Bidirectional mapping
    }
  }

  /** Mutate which validation rules are active */
  _mutateValidationRules() {
    const allRules = [
      'input_sanitization', 'xss_filter', 'sqli_filter', 'nosqli_filter',
      'cmd_injection_filter', 'path_traversal_filter', 'json_validation',
      'url_validation', 'email_validation', 'file_upload_validation',
    ];

    const shuffled = seededShuffle(allRules, this.seed);
    const numActive = 7 + (this.seed % 3); // 7-9 active rules
    const activeRules = shuffled.slice(0, numActive);

    for (const rule of allRules) {
      this.validationRules.set(rule, activeRules.includes(rule));
    }
  }

  /** Mutate image format */
  _mutateImageFormat() {
    const formats = ['png', 'jpg', 'webp'];
    const noisePatterns = ['gaussian', 'salt_pepper', 'perlin', 'simplex'];
    this.imageFormat = formats[this.seed % formats.length];
    this.noisePattern = noisePatterns[this.seed % noisePatterns.length];
  }

  /** Log mutation event */
  _logMutation(event, details) {
    this.mutationHistory.push({
      timestamp: new Date().toISOString(),
      event,
      details,
      seed: this.seed,
    });
  }

  /**
   * Mutate data using the daily algorithm chain
   * @param {Buffer|string} data - Data to mutate
   * @returns {Object} { mutated: Buffer, metadata: Object }
   */
  mutate(data) {
    if (!this.initialized) throw new Error('Mutator not initialized');

    const input = validateInput(data);
    let current = input;
    const metadata = {
      seed: this.seed,
      algorithms: [],
      intermediate: [],
    };

    // Apply each algorithm in the chain
    for (let i = 0; i < this.currentAlgorithms.length; i++) {
      const algoIdx = this.currentAlgorithms[i];
      const algo = ALGORITHM_REGISTRY[algoIdx];
      const key = algo.needsKey ? this.currentKeys[i] : null;

      let result;
      if (algo.needsKey) {
        result = algo.mutate(current, key, this.seed);
      } else {
        result = algo.mutate(current, this.seed);
      }

      // If algorithm returns extra data (S-Box, matrix, etc.), extract mutated data
      let mutated;
      let extra = null;
      if (Buffer.isBuffer(result)) {
        mutated = result;
      } else if (result && result.mutated) {
        mutated = result.mutated;
        extra = { ...result };
        delete extra.mutated;
      } else {
        mutated = result;
      }

      metadata.algorithms.push({
        index: algoIdx,
        name: algo.name,
        extra,
      });
      metadata.intermediate.push(mutated.toString('base64'));

      current = mutated;
    }

    metadata.final = current.toString('base64');

    this._logMutation('MUTATE', {
      inputLength: input.length,
      algorithms: this.currentAlgorithms,
    });

    return { mutated: current, metadata };
  }

  /**
   * Inverse mutation (demutate) using stored metadata
   * @param {Buffer} data - Mutated data
   * @param {Object} metadata - Metadata from mutate()
   * @returns {Buffer} Original data
   */
  inverse(data, metadata) {
    if (!metadata || !metadata.algorithms) {
      throw new Error('Metadata required for inverse mutation');
    }

    let current = validateInput(data);

    // Apply inverse algorithms in reverse order
    for (let i = metadata.algorithms.length - 1; i >= 0; i--) {
      const algoMeta = metadata.algorithms[i];
      const algo = ALGORITHM_REGISTRY[algoMeta.index];
      const key = algo.needsKey ? this.currentKeys[i] : null;

      if (algo.returnsExtra && algoMeta.extra) {
        current = algo.inverse(current, null, algoMeta.extra);
      } else if (algo.needsKey) {
        current = algo.inverse(current, key, this.seed);
      } else {
        current = algo.inverse(current, this.seed);
      }
    }

    this._logMutation('INVERSE', {
      outputLength: current.length,
      algorithms: metadata.algorithms.map(a => a.name),
    });

    return current;
  }

  /**
   * Get the current endpoint mutation mapping
   * @returns {Map<string, string>}
   */
  getEndpointMapping() {
    return new Map(this.endpointMap);
  }

  /**
   * Get the mutated endpoint for a base endpoint
   * @param {string} baseEndpoint - Original endpoint
   * @returns {string} Mutated endpoint
   */
  getMutatedEndpoint(baseEndpoint) {
    return this.endpointMap.get(baseEndpoint) || baseEndpoint;
  }

  /**
   * Get the base endpoint for a mutated endpoint
   * @param {string} mutatedEndpoint - Mutated endpoint
   * @returns {string} Base endpoint
   */
  getBaseEndpoint(mutatedEndpoint) {
    return this.endpointMap.get(mutatedEndpoint) || mutatedEndpoint;
  }

  /**
   * Get active validation rules for today
   * @returns {Map<string, boolean>}
   */
  getValidationRules() {
    return new Map(this.validationRules);
  }

  /**
   * Get today's image format and noise pattern
   * @returns {Object}
   */
  getImageFormat() {
    return { format: this.imageFormat, noisePattern: this.noisePattern };
  }

  /**
   * Get the daily encryption key
   * @returns {Buffer}
   */
  getDailyKey() {
    return Buffer.from(this.dailyKey);
  }

  /**
   * Get mutation history
   * @returns {Object[]}
   */
  getMutationHistory() {
    return [...this.mutationHistory];
  }

  /**
   * Rollback to previous day's mutation
   * @param {number} daysBack - Days to roll back
   */
  rollback(daysBack = 1) {
    const previousSeed = this._calculatePreviousSeed(daysBack);
    const previous = new Mutator({
      seed: previousSeed,
      masterKey: this.config.masterKey,
    });
    this._logMutation('ROLLBACK', { daysBack, previousSeed });
    return previous;
  }

  /** Calculate seed for a previous day */
  _calculatePreviousSeed(daysBack) {
    const date = new Date();
    date.setUTCDate(date.getUTCDate() - daysBack);
    const dateStr = `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}-${String(date.getUTCDate()).padStart(2, '0')}`;
    return deriveSeed(dateStr);
  }

  /**
   * Verify mutation integrity by round-trip test
   * @returns {Object}
   */
  verify() {
    const testData = randomBytes(64);
    try {
      const { mutated, metadata } = this.mutate(testData);
      const recovered = this.inverse(mutated, metadata);

      if (!timingSafeEqual(testData, recovered)) {
        return { verified: false, error: 'Round-trip mismatch', details: { testLength: testData.length } };
      }

      // Test all algorithms individually
      const algoTests = [];
      for (let algoIdx = 0; algoIdx < 7; algoIdx++) {
        try {
          const algo = ALGORITHM_REGISTRY[algoIdx];
          const key = algo.needsKey ? randomBytes(16) : null;
          let result;
          if (algo.needsKey) {
            result = algo.mutate(testData, key, this.seed);
          } else {
            result = algo.mutate(testData, this.seed);
          }

          let mutated;
          let extra = null;
          if (Buffer.isBuffer(result)) mutated = result;
          else if (result && result.mutated) { mutated = result.mutated; extra = { ...result }; delete extra.mutated; }
          else mutated = result;

          let recovered;
          if (algo.returnsExtra && extra) {
            recovered = algo.inverse(mutated, null, extra);
          } else if (algo.needsKey) {
            recovered = algo.inverse(mutated, key, this.seed);
          } else {
            recovered = algo.inverse(mutated, this.seed);
          }

          const pass = timingSafeEqual(testData, recovered);
          algoTests.push({ name: algo.name, pass });
        } catch (e) {
          algoTests.push({ name: ALGORITHM_REGISTRY[algoIdx].name, pass: false, error: e.message });
        }
      }

      const allPassed = algoTests.every(t => t.pass);
      return {
        verified: allPassed,
        chainTest: true,
        algorithmTests: algoTests,
        seed: this.seed,
        activeAlgorithms: this.currentAlgorithms,
      };
    } catch (e) {
      return { verified: false, error: e.message };
    }
  }

  /**
   * Export daily mutation profile
   * @returns {Object}
   */
  exportProfile() {
    return {
      date: new Date().toISOString(),
      seed: this.seed,
      algorithms: this.currentAlgorithms.map(idx => ({
        index: idx,
        name: ALGORITHM_REGISTRY[idx].name,
      })),
      endpoints: Object.fromEntries(this.endpointMap),
      validationRules: Object.fromEntries(this.validationRules),
      imageFormat: this.imageFormat,
      noisePattern: this.noisePattern,
      dailyKeyHash: createHash('sha256').update(this.dailyKey).digest('hex'),
    };
  }

  /**
   * Apply a single algorithm by index
   * @param {number} algoIdx - Algorithm index (0-6)
   * @param {Buffer} data - Input data
   * @returns {Object}
   */
  applyAlgorithm(algoIdx, data) {
    if (algoIdx < 0 || algoIdx > 6) throw new Error('Algorithm index must be 0-6');
    const algo = ALGORITHM_REGISTRY[algoIdx];
    const key = algo.needsKey ? this.dailyKey : null;

    let result;
    if (algo.needsKey) {
      result = algo.mutate(data, key, this.seed);
    } else {
      result = algo.mutate(data, this.seed);
    }

    let mutated;
    let extra = null;
    if (Buffer.isBuffer(result)) mutated = result;
    else if (result && result.mutated) { mutated = result.mutated; extra = { ...result }; delete extra.mutated; }
    else mutated = result;

    return { mutated, extra, name: algo.name, index: algoIdx };
  }

  /**
   * Re-initialize with a new seed
   * @param {number} seed - New seed
   */
  reseed(seed) {
    this.seed = seed;
    this.rng = createSeededRandom(seed);
    this.dailyKey = this._deriveDailyKey();
    this.currentAlgorithms = [];
    this.currentKeys = [];
    this.endpointMap.clear();
    this.validationRules.clear();
    this._initializeDailyMutation();
    this._logMutation('RESEED', { newSeed: seed });
  }
}

// ============================================================================
// ADDITIONAL UTILITIES
// ============================================================================

/**
 * Apply all 7 algorithms in sequence (maximum security mode)
 * @param {Buffer} data - Input data
 * @param {Buffer} key - Master key
 * @param {number} seed - Seed
 * @returns {Object} Full mutation chain result
 */
export function mutateAll(data, key, seed) {
  const input = validateInput(data);
  const k = validateKey(key);
  const s = seed >>> 0;
  let current = input;
  const results = [];

  for (let i = 0; i < 7; i++) {
    const algo = ALGORITHM_REGISTRY[i];
    const algoKey = createHash('sha256').update(k).update(`algo-${i}`).digest();

    let result;
    if (algo.needsKey) {
      result = algo.mutate(current, algoKey, s);
    } else {
      result = algo.mutate(current, s);
    }

    let mutated;
    let extra = null;
    if (Buffer.isBuffer(result)) mutated = result;
    else if (result && result.mutated) { mutated = result.mutated; extra = { ...result }; delete extra.mutated; }
    else mutated = result;

    results.push({ name: algo.name, index: i, mutated, extra });
    current = mutated;
  }

  return { final: current, results };
}

/**
 * Inverse all 7 algorithms in reverse sequence
 * @param {Buffer} data - Mutated data
 * @param {Buffer} key - Master key
 * @param {number} seed - Seed
 * @param {Object[]} results - Results from mutateAll()
 * @returns {Buffer} Original data
 */
export function inverseAll(data, key, seed, results) {
  let current = validateInput(data);
  const k = validateKey(key);

  for (let i = 6; i >= 0; i--) {
    const algo = ALGORITHM_REGISTRY[i];
    const algoKey = createHash('sha256').update(k).update(`algo-${i}`).digest();
    const result = results[i];

    if (algo.returnsExtra && result.extra) {
      current = algo.inverse(current, null, result.extra);
    } else if (algo.needsKey) {
      current = algo.inverse(current, algoKey, seed);
    } else {
      current = algo.inverse(current, seed);
    }
  }

  return current;
}

/**
 * Quick mutation for one-time use
 * @param {Buffer|string} data - Data to mutate
 * @param {Buffer|string} key - Mutation key
 * @param {number} [seed] - Optional seed
 * @returns {Buffer} Mutated data
 */
export function quickMutate(data, key, seed) {
  const s = seed || getDailySeed();
  const k = validateKey(key);
  // Use S-Box for quick mutation (fastest)
  return sboxMutate(data, s).mutated;
}

/**
 * Generate noise pattern for image obfuscation
 * @param {number} width - Image width
 * @param {number} height - Image height
 * @param {string} pattern - Noise pattern type
 * @param {number} seed - Random seed
 * @returns {Buffer} Noise buffer
 */
export function generateNoisePattern(width, height, pattern, seed) {
  const size = width * height * 4; // RGBA
  const rng = createSeededRandom(seed);
  const noise = Buffer.alloc(size);

  switch (pattern) {
    case 'gaussian': {
      // Gaussian noise
      for (let i = 0; i < size; i += 4) {
        for (let c = 0; c < 3; c++) {
          // Box-Muller transform for Gaussian
          const u1 = Math.max(rng(), 0.0001);
          const u2 = rng();
          const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
          noise[i + c] = Math.min(255, Math.max(0, Math.round(128 + z * 30)));
        }
        noise[i + 3] = 255; // Alpha
      }
      break;
    }
    case 'salt_pepper': {
      // Salt and pepper noise
      for (let i = 0; i < size; i += 4) {
        for (let c = 0; c < 3; c++) {
          const r = rng();
          if (r < 0.05) noise[i + c] = 0;
          else if (r > 0.95) noise[i + c] = 255;
          else noise[i + c] = 128;
        }
        noise[i + 3] = 255;
      }
      break;
    }
    case 'perlin': {
      // Simple Perlin-like noise
      for (let i = 0; i < size; i += 4) {
        const pixelIdx = i / 4;
        const x = pixelIdx % width;
        const y = Math.floor(pixelIdx / width);
        const val = Math.round(
          128 + 60 * (
            Math.sin(x * 0.05 + seed) + Math.sin(y * 0.05 + seed) +
            Math.sin((x + y) * 0.03) * 0.5
          )
        );
        for (let c = 0; c < 3; c++) {
          noise[i + c] = Math.min(255, Math.max(0, val + Math.round(rng() * 20 - 10)));
        }
        noise[i + 3] = 255;
      }
      break;
    }
    default: {
      // Simple random noise
      for (let i = 0; i < size; i++) {
        noise[i] = Math.floor(rng() * 256);
      }
    }
  }

  return noise;
}

/**
 * Get algorithm names and descriptions
 * @returns {Object[]}
 */
export function getAlgorithmDescriptions() {
  return [
    { index: 0, name: 'XOR-Rotate', description: 'XOR with key + rotation, self-inverse via double-XOR' },
    { index: 1, name: 'Add-Shift', description: 'Modular addition with key, followed by cyclic shift' },
    { index: 2, name: 'S-Box', description: 'Substitution box via Fisher-Yates shuffle, invertible via inverse table' },
    { index: 3, name: 'Matrix-4x4', description: '4x4 matrix multiplication over GF(2^8) with invertible matrix' },
    { index: 4, name: 'Polynomial-GF', description: 'Polynomial evaluation over GF(2^8) with irreducible 0x11B' },
    { index: 5, name: 'Chaos-Logistic', description: 'Logistic map chaotic sequence XOR with key' },
    { index: 6, name: 'Permutation', description: 'Index permutation via Fisher-Yates, invertible via inverse permutation' },
  ];
}

export default Mutator;
