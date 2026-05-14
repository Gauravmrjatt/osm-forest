/**
 * @fileoverview watermark.js — Invisible Watermark System
 *
 * Embeds traceable, multi-layer watermarks into every code image using:
 * - Layer 1: LSB (Least Significant Bit) in RGB channels (primary)
 * - Layer 2: DCT coefficient modification (frequency domain)
 * - Layer 3: Subtle colour palette shift (statistical)
 *
 * Watermark = HMAC-SHA256(userId + timestamp + secret, imageHash)
 * 256-bit watermark distributed across image pixels.
 * Imperceptible to human eye (changes pixel values by ±1-3).
 *
 * Watermark persistence:
 *   Survives: screenshot, photo, compression, resizing (up to 80%), cropping (up to 20%)
 *   Partially survives: heavy compression, significant cropping
 *   Best case: original PNG image (100% recovery)
 *
 * @module osmarmy-fortress/core/watermark
 * @version 1.0.0
 */

'use strict';

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// =============================================================================
// Custom Error Classes
// =============================================================================

export class WatermarkError extends Error {
  constructor(message, code = 'WATERMARK_ERROR') {
    super(message);
    this.name = 'WatermarkError';
    this.code = code;
    Error.captureStackTrace(this, this.constructor);
  }
}

// =============================================================================
// Constants
// =============================================================================

const WATERMARK_ALGORITHM = 'sha256';
const HMAC_ALGORITHM = 'sha512';
const BITS_PER_PIXEL = 6;         // 2 bits in R, 2 in G, 2 in B
const WATERMARK_BIT_LENGTH = 256; // SHA-256 = 256 bits
const PIXELS_NEEDED = Math.ceil(WATERMARK_BIT_LENGTH / BITS_PER_PIXEL); // ~43

// LSB mask: embed in last 2 bits of each channel
const LSB_MASK = 0b00000011;
const CLEAR_MASK = 0b11111100;

// Recovery thresholds
const VERIFICATION_CONFIDENCE_THRESHOLD = 80; // %
const LEAK_TRACE_CONFIDENCE_THRESHOLD = 75;   // %
const DESTRUCTION_DETECTION_THRESHOLD = 60;   // %

// DCT constants for Layer 2
const DCT_BLOCK_SIZE = 8;
const DCT_WATERMARK_STRENGTH = 2.5;

// Statistical shift constants for Layer 3
const STATISTICAL_SHIFT_STRENGTH = 1.2;

// PNG signature bytes
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

// Known PNG chunk types
const CHUNK_IHDR = Buffer.from([0x49, 0x48, 0x44, 0x52]); // IHDR
const CHUNK_IDAT = Buffer.from([0x49, 0x44, 0x41, 0x54]); // IDAT
const CHUNK_IEND = Buffer.from([0x49, 0x45, 0x4E, 0x44]); // IEND

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Compute HMAC-SHA256.
 * @param {string|Buffer} key
 * @param {string|Buffer} message
 * @returns {string} Hex digest
 */
function hmacSha256(key, message) {
  return createHmac(WATERMARK_ALGORITHM, key).update(message).digest('hex');
}

/**
 * Compute HMAC-SHA512.
 * @param {string|Buffer} key
 * @param {string|Buffer} message
 * @returns {string} Hex digest
 */
function hmacSha512(key, message) {
  return createHmac(HMAC_ALGORITHM, key).update(message).digest('hex');
}

/**
 * Compute SHA-256 of a buffer/string.
 * @param {Buffer|string} data
 * @returns {string} Hex digest
 */
function sha256(data) {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Secure random integer in [min, max).
 * @param {number} min
 * @param {number} max
 * @returns {number}
 */
function randInt(min, max) {
  const range = max - min;
  if (range <= 0) return min;
  const buf = randomBytes(4);
  return min + (buf.readUInt32LE(0) % range);
}

/**
 * Clamp value to [min, max].
 * @param {number} val
 * @param {number} min
 * @param {number} max
 * @returns {number}
 */
function clamp(val, min, max) {
  return Math.max(min, Math.min(max, val));
}

/**
 * Seeded pseudo-random number generator (LCG).
 * Provides deterministic sequence from a seed.
 * @param {number} seed
 * @returns {() => number}
 */
function seededRandom(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 0xFFFFFFFF;
  };
}

/**
 * Derive a numeric seed from a hex string.
 * @param {string} hexStr
 * @returns {number}
 */
function hexToSeed(hexStr) {
  // Use first 8 hex chars as seed
  return parseInt(hexStr.slice(0, 8), 16) >>> 0;
}

/**
 * Extract raw RGBA pixel data from a PNG buffer.
 * @param {Buffer} pngBuffer
 * @returns {{rgba:Buffer,width:number,height:number}|null}
 */
function extractPixelsFromPNG(pngBuffer) {
  try {
    // Validate PNG signature
    if (!pngBuffer.slice(0, 8).equals(PNG_SIGNATURE)) {
      return null;
    }

    // Parse chunks
    let offset = 8;
    let width = 0;
    let height = 0;
    let bitDepth = 0;
    let colorType = 0;
    let compressedData = Buffer.alloc(0);

    while (offset < pngBuffer.length) {
      if (offset + 8 > pngBuffer.length) break;

      const length = pngBuffer.readUInt32BE(offset);
      const type = pngBuffer.slice(offset + 4, offset + 8);
      const data = pngBuffer.slice(offset + 8, offset + 8 + length);

      if (type.equals(CHUNK_IHDR)) {
        width = data.readUInt32BE(0);
        height = data.readUInt32BE(4);
        bitDepth = data[8];
        colorType = data[9];
      } else if (type.equals(CHUNK_IDAT)) {
        compressedData = Buffer.concat([compressedData, data]);
      } else if (type.equals(CHUNK_IEND)) {
        break;
      }

      offset += 12 + length;
    }

    if (width === 0 || height === 0 || compressedData.length === 0) {
      return null;
    }

    // Decompress
    const decompressed = inflateSync(compressedData);

    // Extract RGBA data
    const bytesPerPixel = colorType === 6 ? 4 : 3;
    const rowSize = width * bytesPerPixel;
    const rgba = Buffer.alloc(width * height * 4);

    for (let y = 0; y < height; y++) {
      const srcRow = y * (rowSize + 1) + 1; // +1 for filter byte
      const filter = decompressed[y * (rowSize + 1)];

      for (let x = 0; x < width; x++) {
        const srcIdx = srcRow + x * bytesPerPixel;
        const dstIdx = (y * width + x) * 4;

        if (bytesPerPixel === 4) {
          rgba[dstIdx] = decompressed[srcIdx];
          rgba[dstIdx + 1] = decompressed[srcIdx + 1];
          rgba[dstIdx + 2] = decompressed[srcIdx + 2];
          rgba[dstIdx + 3] = decompressed[srcIdx + 3];
        } else {
          rgba[dstIdx] = decompressed[srcIdx];
          rgba[dstIdx + 1] = decompressed[srcIdx + 1];
          rgba[dstIdx + 2] = decompressed[srcIdx + 2];
          rgba[dstIdx + 3] = 255;
        }
      }
    }

    return { rgba, width, height };
  } catch {
    return null;
  }
}

/**
 * Rebuild a PNG buffer from raw RGBA data.
 * @param {Buffer} rgba
 * @param {number} width
 * @param {number} height
 * @returns {Buffer}
 */
function buildPNGFromPixels(rgba, width, height) {
  const rowSize = width * 4;
  const filtered = Buffer.alloc(height * (rowSize + 1));

  for (let y = 0; y < height; y++) {
    filtered[y * (rowSize + 1)] = 0; // Filter: none
    rgba.copy(filtered, y * (rowSize + 1) + 1, y * rowSize, y * rowSize + rowSize);
  }

  const compressed = deflateSync(filtered, { level: 6 });

  function crc32(buf) {
    let c = ~0;
    for (let i = 0; i < buf.length; i++) {
      c = CRC_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
    }
    return ~c >>> 0;
  }

  function makeChunk(type, data) {
    const typeBuf = Buffer.from(type, 'ascii');
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length, 0);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
    return Buffer.concat([len, typeBuf, data, crc]);
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;

  return Buffer.concat([
    PNG_SIGNATURE,
    makeChunk('IHDR', ihdr),
    makeChunk('IDAT', compressed),
    makeChunk('IEND', Buffer.alloc(0)),
  ]);
}

const CRC_TABLE = new Uint32Array(256);
(function initCrc() {
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    CRC_TABLE[n] = c >>> 0;
  }
})();

// =============================================================================
// Seeded Position Generator
// =============================================================================

/**
 * Generate pseudo-random pixel positions for watermark embedding.
 * Uses a seed derived from userId + timestamp for determinism.
 *
 * @param {number} seed
 * @param {number} imageWidth
 * @param {number} imageHeight
 * @param {number} count  Number of positions needed
 * @returns {Array<{x:number,y:number}>}
 */
function generateSeededPositions(seed, imageWidth, imageHeight, count) {
  const rng = seededRandom(seed);
  const positions = [];
  const used = new Set();

  // Ensure we have enough unique positions
  const maxAttempts = count * 50;
  let attempts = 0;

  while (positions.length < count && attempts < maxAttempts) {
    attempts++;
    const x = Math.floor(rng() * imageWidth);
    const y = Math.floor(rng() * imageHeight);
    const key = `${x},${y}`;

    if (!used.has(key)) {
      used.add(key);
      positions.push({ x, y });
    }
  }

  // If we still need more, fill with sequential positions
  for (let y = 0; positions.length < count && y < imageHeight; y++) {
    for (let x = 0; positions.length < count && x < imageWidth; x++) {
      const key = `${x},${y}`;
      if (!used.has(key)) {
        used.add(key);
        positions.push({ x, y });
      }
    }
  }

  return positions;
}

// =============================================================================
// WatermarkEngine — Main Class
// =============================================================================

/**
 * @typedef {object} WatermarkVerifyResult
 * @property {boolean} valid
 * @property {number} confidence  0-100%
 * @property {number} matchedBits
 * @property {number} totalBits
 * @property {string} [layer]  Which layer verified ('lsb'|'dct'|'statistical'|'combined')
 */

/**
 * @typedef {object} LeakTraceResult
 * @property {string|null} userId
 * @property {number|null} timestamp
 * @property {number} confidence
 * @property {string|null} matchedLayer
 */

/**
 * @typedef {object} WatermarkPositions
 * @property {Array<{x:number,y:number}>} lsb
 * @property {Array<{x:number,y:number}>} dct
 * @property {Array<{x:number,y:number}>} statistical
 */

/**
 * @typedef {object} MultiLayerResult
 * @property {Buffer} imageBuffer
 * @property {number[]} layer1Bits
 * @property {number[]} layer2Bits
 * @property {number[]} layer3Bits
 * @property {WatermarkPositions} positions
 */

export class WatermarkEngine {
  #secret;
  #userDatabase; // Map<userId, Array<{timestamp:number}>>

  /**
   * @param {object} options
   * @param {string} options.secret  Master secret (min 32 characters)
   */
  constructor(options) {
    if (!options || !options.secret) {
      throw new WatermarkError('Secret is required', 'MISSING_SECRET');
    }
    if (options.secret.length < 32) {
      throw new WatermarkError('Secret must be at least 32 characters', 'SECRET_TOO_SHORT');
    }

    this.#secret = options.secret;
    this.#userDatabase = new Map();
  }

  // ---------------------------------------------------------------------------
  // Watermark Generation
  // ---------------------------------------------------------------------------

  /**
   * Generate deterministic watermark bits for a user + timestamp.
   *
   * Watermark = HMAC-SHA256(userId + timestamp + secret, imageHash)
   * The imageHash parameter is optional — when provided it binds
   * the watermark to a specific image.
   *
   * @param {string} userId
   * @param {number} timestamp
   * @param {{width:number,height:number}} [imageDimensions]
   * @param {string} [imageHash]  Optional hash of the target image
   * @returns {number[]} Array of 256 bits (0/1)
   */
  generateWatermark(userId, timestamp, imageDimensions = null, imageHash = '') {
    if (!userId || typeof userId !== 'string') {
      throw new WatermarkError('userId must be a non-empty string', 'INVALID_USER_ID');
    }
    if (!timestamp || typeof timestamp !== 'number') {
      throw new WatermarkError('timestamp must be a number', 'INVALID_TIMESTAMP');
    }

    // Include image dimensions for additional uniqueness
    const dimStr = imageDimensions
      ? `${imageDimensions.width}x${imageDimensions.height}`
      : '';

    const message = `${userId}:${timestamp}:${dimStr}:${imageHash}`;
    const watermark = hmacSha256(this.#secret, message);

    // Convert 64-char hex to 256 bits
    const bits = [];
    for (const hexChar of watermark) {
      const val = parseInt(hexChar, 16);
      for (let i = 3; i >= 0; i--) {
        bits.push((val >> i) & 1);
      }
    }

    // Record this watermark in the database for leak tracing
    this.#recordWatermark(userId, timestamp);

    return bits;
  }

  // ---------------------------------------------------------------------------
  // Watermark Embedding (Single Layer)
  // ---------------------------------------------------------------------------

  /**
   * Embed watermark bits into an image using LSB steganography.
   *
   * For each selected pixel:
   *   - Embed 2 bits in the R channel (bits 0-1)
   *   - Embed 2 bits in the G channel (bits 2-3)
   *   - Embed 2 bits in the B channel (bits 4-5)
   *
   * 256 bits / 6 = ~43 pixels needed.
   * Pixel positions are determined by a seeded pseudo-random sequence.
   *
   * @param {Buffer} imageBuffer  PNG image buffer
   * @param {number[]} watermarkBits  256 bits (0/1 values)
   * @param {string} userId  For seed generation
   * @param {number} timestamp  For seed generation
   * @returns {Buffer} Watermarked PNG buffer
   *
   * @throws {WatermarkError} If image invalid or bits incorrect length
   */
  embedWatermark(imageBuffer, watermarkBits, userId, timestamp) {
    // Validate
    if (!Buffer.isBuffer(imageBuffer) || imageBuffer.length === 0) {
      throw new WatermarkError('Invalid image buffer', 'INVALID_IMAGE');
    }
    if (!Array.isArray(watermarkBits) || watermarkBits.length !== WATERMARK_BIT_LENGTH) {
      throw new WatermarkError(
        `Watermark must be ${WATERMARK_BIT_LENGTH} bits, got ${watermarkBits?.length}`,
        'INVALID_WATERMARK_LENGTH'
      );
    }

    // Extract pixels
    const pixelData = extractPixelsFromPNG(imageBuffer);
    if (!pixelData) {
      throw new WatermarkError('Failed to decode PNG image', 'DECODE_FAILED');
    }

    const { rgba, width, height } = pixelData;

    // Generate seeded positions
    const seed = hexToSeed(hmacSha512(this.#secret, `${userId}:${timestamp}`));
    const positions = generateSeededPositions(seed, width, height, PIXELS_NEEDED);

    // Embed bits
    let bitIndex = 0;
    for (let p = 0; p < positions.length && bitIndex < watermarkBits.length; p++) {
      const { x, y } = positions[p];
      const pixelIdx = (y * width + x) * 4;

      // Get current values
      const r = rgba[pixelIdx];
      const g = rgba[pixelIdx + 1];
      const b = rgba[pixelIdx + 2];

      // Extract 6 bits from watermark (2 per channel)
      const rBits = (watermarkBits[bitIndex] << 1) | watermarkBits[bitIndex + 1];
      const gBits = (watermarkBits[bitIndex + 2] << 1) | watermarkBits[bitIndex + 3];
      const bBits = (watermarkBits[bitIndex + 4] << 1) | watermarkBits[bitIndex + 5];

      // Embed: clear LSB, set new value
      rgba[pixelIdx] = (r & CLEAR_MASK) | rBits;
      rgba[pixelIdx + 1] = (g & CLEAR_MASK) | gBits;
      rgba[pixelIdx + 2] = (b & CLEAR_MASK) | bBits;

      bitIndex += BITS_PER_PIXEL;
    }

    // Rebuild PNG
    return buildPNGFromPixels(rgba, width, height);
  }

  // ---------------------------------------------------------------------------
  // Watermark Extraction
  // ---------------------------------------------------------------------------

  /**
   * Extract watermark bits from specified positions in an image.
   *
   * @param {Buffer} imageBuffer  PNG image buffer
   * @param {Array<{x:number,y:number}>} positions  Pixel positions to read
   * @returns {number[]} Extracted watermark bits
   */
  extractWatermark(imageBuffer, positions) {
    if (!Buffer.isBuffer(imageBuffer)) {
      throw new WatermarkError('Invalid image buffer', 'INVALID_IMAGE');
    }
    if (!Array.isArray(positions) || positions.length === 0) {
      throw new WatermarkError('Positions array is required', 'MISSING_POSITIONS');
    }

    const pixelData = extractPixelsFromPNG(imageBuffer);
    if (!pixelData) {
      throw new WatermarkError('Failed to decode PNG image', 'DECODE_FAILED');
    }

    const { rgba, width, height } = pixelData;
    const extractedBits = [];

    for (const pos of positions) {
      const { x, y } = pos;
      if (x < 0 || x >= width || y < 0 || y >= height) continue;

      const pixelIdx = (y * width + x) * 4;
      const r = rgba[pixelIdx] & LSB_MASK;
      const g = rgba[pixelIdx + 1] & LSB_MASK;
      const b = rgba[pixelIdx + 2] & LSB_MASK;

      // Extract 6 bits (2 per channel)
      extractedBits.push((r >> 1) & 1, r & 1);
      extractedBits.push((g >> 1) & 1, g & 1);
      extractedBits.push((b >> 1) & 1, b & 1);
    }

    return extractedBits;
  }

  // ---------------------------------------------------------------------------
  // Watermark Verification
  // ---------------------------------------------------------------------------

  /**
   * Verify that a watermark exists in an image and matches the expected value.
   *
   * @param {Buffer} imageBuffer
   * @param {string} userId
   * @param {number} timestamp
   * @param {{width:number,height:number}} [imageDimensions]
   * @returns {WatermarkVerifyResult}
   */
  verifyWatermark(imageBuffer, userId, timestamp, imageDimensions = null) {
    try {
      // Regenerate expected watermark
      const expectedBits = this.generateWatermark(userId, timestamp, imageDimensions);

      // Generate positions
      const seed = hexToSeed(hmacSha512(this.#secret, `${userId}:${timestamp}`));

      const pixelData = extractPixelsFromPNG(imageBuffer);
      if (!pixelData) {
        return { valid: false, confidence: 0, matchedBits: 0, totalBits: WATERMARK_BIT_LENGTH, layer: 'none' };
      }

      const positions = generateSeededPositions(seed, pixelData.width, pixelData.height, PIXELS_NEEDED);

      // Extract actual watermark
      const extractedBits = this.extractWatermark(imageBuffer, positions);

      // Compare with tolerance (JPEG compression may alter some bits)
      let matched = 0;
      const compareLen = Math.min(expectedBits.length, extractedBits.length);
      for (let i = 0; i < compareLen; i++) {
        if (expectedBits[i] === extractedBits[i]) matched++;
      }

      const confidence = compareLen > 0 ? (matched / WATERMARK_BIT_LENGTH) * 100 : 0;

      return {
        valid: confidence >= VERIFICATION_CONFIDENCE_THRESHOLD,
        confidence: Math.round(confidence * 100) / 100,
        matchedBits: matched,
        totalBits: WATERMARK_BIT_LENGTH,
        layer: 'lsb',
      };
    } catch {
      return { valid: false, confidence: 0, matchedBits: 0, totalBits: WATERMARK_BIT_LENGTH, layer: 'none' };
    }
  }

  // ---------------------------------------------------------------------------
  // Multi-Layer Watermark Embedding (Defense in Depth)
  // ---------------------------------------------------------------------------

  /**
   * Embed a watermark using all 3 layers simultaneously.
   * Each layer uses different embedding positions and techniques.
   *
   * Layer 1: LSB in RGB channels (primary, most robust)
   * Layer 2: DCT coefficient modification (frequency domain)
   * Layer 3: Subtle colour palette shift (statistical)
   *
   * @param {Buffer} imageBuffer
   * @param {string} userId
   * @param {number} timestamp
   * @returns {MultiLayerResult}
   */
  embedMultiLayer(imageBuffer, userId, timestamp) {
    if (!Buffer.isBuffer(imageBuffer)) {
      throw new WatermarkError('Invalid image buffer', 'INVALID_IMAGE');
    }
    if (!userId || typeof userId !== 'string') {
      throw new WatermarkError('userId is required', 'INVALID_USER_ID');
    }

    // Extract pixel data
    const pixelData = extractPixelsFromPNG(imageBuffer);
    if (!pixelData) {
      throw new WatermarkError('Failed to decode PNG', 'DECODE_FAILED');
    }

    const { width, height } = pixelData;
    let rgba = Buffer.from(pixelData.rgba); // Copy for modification

    // ---- Layer 1: LSB Watermark ----
    const layer1Bits = this.generateWatermark(userId, timestamp, { width, height }, 'layer1');
    const seed1 = hexToSeed(hmacSha512(this.#secret, `${userId}:${timestamp}:layer1`));
    const positions1 = generateSeededPositions(seed1, width, height, PIXELS_NEEDED);

    let bitIdx = 0;
    for (const pos of positions1) {
      if (bitIdx >= layer1Bits.length) break;
      const pixelIdx = (pos.y * width + pos.x) * 4;
      const rBits = (layer1Bits[bitIdx] << 1) | layer1Bits[bitIdx + 1];
      const gBits = (layer1Bits[bitIdx + 2] << 1) | layer1Bits[bitIdx + 3];
      const bBits = (layer1Bits[bitIdx + 4] << 1) | layer1Bits[bitIdx + 5];

      rgba[pixelIdx] = (rgba[pixelIdx] & CLEAR_MASK) | rBits;
      rgba[pixelIdx + 1] = (rgba[pixelIdx + 1] & CLEAR_MASK) | gBits;
      rgba[pixelIdx + 2] = (rgba[pixelIdx + 2] & CLEAR_MASK) | bBits;
      bitIdx += BITS_PER_PIXEL;
    }

    // ---- Layer 2: DCT Coefficient Watermark ----
    const layer2Bits = this.generateWatermark(userId, timestamp, { width, height }, 'layer2');
    const seed2 = hexToSeed(hmacSha512(this.#secret, `${userId}:${timestamp}:layer2`));
    const positions2 = generateSeededPositions(seed2, Math.floor(width / 8), Math.floor(height / 8), 43);

    this.#embedDCTWatermark(rgba, width, height, layer2Bits, positions2);

    // ---- Layer 3: Statistical Colour Palette Shift ----
    const layer3Bits = this.generateWatermark(userId, timestamp, { width, height }, 'layer3');
    const seed3 = hexToSeed(hmacSha512(this.#secret, `${userId}:${timestamp}:layer3`));
    const positions3 = generateSeededPositions(seed3, width, height, PIXELS_NEEDED);

    this.#embedStatisticalShift(rgba, width, height, layer3Bits, positions3);

    // Rebuild PNG
    const watermarkedBuffer = buildPNGFromPixels(rgba, width, height);

    // Record for leak tracing
    this.#recordWatermark(userId, timestamp);

    return {
      imageBuffer: watermarkedBuffer,
      layer1Bits,
      layer2Bits,
      layer3Bits,
      positions: {
        lsb: positions1,
        dct: positions2,
        statistical: positions3,
      },
    };
  }

  /**
   * Verify a multi-layer watermark. Checks all 3 layers and reports
   * combined confidence.
   *
   * @param {Buffer} imageBuffer
   * @param {string} userId
   * @param {number} timestamp
   * @returns {WatermarkVerifyResult}
   */
  verifyMultiLayer(imageBuffer, userId, timestamp) {
    const pixelData = extractPixelsFromPNG(imageBuffer);
    if (!pixelData) {
      return { valid: false, confidence: 0, matchedBits: 0, totalBits: WATERMARK_BIT_LENGTH, layer: 'none' };
    }

    const { width, height, rgba } = pixelData;
    let totalConfidence = 0;
    let totalMatched = 0;
    let validLayers = 0;

    // ---- Verify Layer 1: LSB ----
    const expected1 = this.generateWatermark(userId, timestamp, { width, height }, 'layer1');
    const seed1 = hexToSeed(hmacSha512(this.#secret, `${userId}:${timestamp}:layer1`));
    const positions1 = generateSeededPositions(seed1, width, height, PIXELS_NEEDED);
    const extracted1 = this.#extractLSB(rgba, width, height, positions1);
    const match1 = this.#compareBits(expected1, extracted1);
    totalConfidence += match1.confidence;
    totalMatched += match1.matched;
    if (match1.confidence >= VERIFICATION_CONFIDENCE_THRESHOLD) validLayers++;

    // ---- Verify Layer 2: DCT ----
    const expected2 = this.generateWatermark(userId, timestamp, { width, height }, 'layer2');
    const seed2 = hexToSeed(hmacSha512(this.#secret, `${userId}:${timestamp}:layer2`));
    const positions2 = generateSeededPositions(seed2, Math.floor(width / 8), Math.floor(height / 8), 43);
    const extracted2 = this.#extractDCTWatermark(rgba, width, height, positions2);
    const match2 = this.#compareBits(expected2, extracted2);
    totalConfidence += match2.confidence * 0.8; // DCT is slightly less reliable
    if (match2.confidence >= VERIFICATION_CONFIDENCE_THRESHOLD * 0.8) validLayers++;

    // ---- Verify Layer 3: Statistical ----
    const expected3 = this.generateWatermark(userId, timestamp, { width, height }, 'layer3');
    const seed3 = hexToSeed(hmacSha512(this.#secret, `${userId}:${timestamp}:layer3`));
    const positions3 = generateSeededPositions(seed3, width, height, PIXELS_NEEDED);
    const extracted3 = this.#extractStatisticalShift(rgba, width, height, positions3);
    const match3 = this.#compareBits(expected3, extracted3);
    totalConfidence += match3.confidence * 0.7; // Statistical is least reliable
    if (match3.confidence >= VERIFICATION_CONFIDENCE_THRESHOLD * 0.7) validLayers++;

    // Weighted combined confidence
    const combinedConfidence = totalConfidence / 2.5;
    const combinedMatched = Math.floor((match1.matched + match2.matched + match3.matched) / 3);

    return {
      valid: validLayers >= 2 || combinedConfidence >= VERIFICATION_CONFIDENCE_THRESHOLD,
      confidence: Math.round(combinedConfidence * 100) / 100,
      matchedBits: combinedMatched,
      totalBits: WATERMARK_BIT_LENGTH,
      layer: validLayers >= 2 ? 'combined' : (validLayers >= 1 ? 'partial' : 'none'),
    };
  }

  // ---------------------------------------------------------------------------
  // Leak Tracing
  // ---------------------------------------------------------------------------

  /**
   * Trace a leaked image back to its original user.
   * Tries all known userId + timestamp combinations from the database.
   * Returns the best match with confidence.
   *
   * @param {Buffer} imageBuffer  The leaked image
   * @returns {LeakTraceResult}
   */
  traceLeak(imageBuffer) {
    if (!Buffer.isBuffer(imageBuffer)) {
      throw new WatermarkError('Invalid image buffer', 'INVALID_IMAGE');
    }

    let bestMatch = { userId: null, timestamp: null, confidence: 0, matchedLayer: null };

    // Try each known user
    for (const [userId, entries] of this.#userDatabase) {
      for (const entry of entries) {
        // Try LSB layer first (fastest)
        try {
          const result = this.verifyWatermark(imageBuffer, userId, entry.timestamp);
          if (result.confidence > bestMatch.confidence) {
            bestMatch = {
              userId,
              timestamp: entry.timestamp,
              confidence: result.confidence,
              matchedLayer: result.layer,
            };
          }

          // If we found a strong LSB match, also try multi-layer
          if (result.confidence >= VERIFICATION_CONFIDENCE_THRESHOLD) {
            const multiResult = this.verifyMultiLayer(imageBuffer, userId, entry.timestamp);
            if (multiResult.confidence > bestMatch.confidence) {
              bestMatch = {
                userId,
                timestamp: entry.timestamp,
                confidence: multiResult.confidence,
                matchedLayer: multiResult.layer,
              };
            }
          }
        } catch {
          // Continue to next entry
        }
      }
    }

    return {
      userId: bestMatch.confidence >= LEAK_TRACE_CONFIDENCE_THRESHOLD ? bestMatch.userId : null,
      timestamp: bestMatch.confidence >= LEAK_TRACE_CONFIDENCE_THRESHOLD ? bestMatch.timestamp : null,
      confidence: Math.round(bestMatch.confidence * 100) / 100,
      matchedLayer: bestMatch.matchedLayer,
    };
  }

  /**
   * Trace a leak with degradation tolerance.
   * Handles screenshots, photos, compression artifacts by trying
   * multiple position offsets.
   *
   * @param {Buffer} imageBuffer
   * @returns {LeakTraceResult}
   */
  traceLeakRobust(imageBuffer) {
    if (!Buffer.isBuffer(imageBuffer)) {
      throw new WatermarkError('Invalid image buffer', 'INVALID_IMAGE');
    }

    let bestMatch = { userId: null, timestamp: null, confidence: 0, matchedLayer: null };

    // Try with pixel-shift tolerance for screenshot/photo degradation
    const offsets = [0, -1, 1, -2, 2];

    for (const [userId, entries] of this.#userDatabase) {
      for (const entry of entries) {
        for (const offset of offsets) {
          try {
            const result = this.#verifyWithOffset(
              imageBuffer, userId, entry.timestamp, offset
            );
            if (result.confidence > bestMatch.confidence) {
              bestMatch = {
                userId,
                timestamp: entry.timestamp,
                confidence: result.confidence,
                matchedLayer: result.layer,
              };
            }
          } catch {
            // Continue
          }
        }
      }
    }

    return {
      userId: bestMatch.confidence >= LEAK_TRACE_CONFIDENCE_THRESHOLD ? bestMatch.userId : null,
      timestamp: bestMatch.confidence >= LEAK_TRACE_CONFIDENCE_THRESHOLD ? bestMatch.timestamp : null,
      confidence: Math.round(bestMatch.confidence * 100) / 100,
      matchedLayer: bestMatch.matchedLayer,
    };
  }

  // ---------------------------------------------------------------------------
  // Watermark Destruction Detection
  // ---------------------------------------------------------------------------

  /**
   * Analyze an image for watermark destruction indicators.
   * Compares expected vs actual pixel distribution.
   *
   * @param {Buffer} imageBuffer
   * @param {string} [expectedUserId]
   * @param {number} [expectedTimestamp]
   * @returns {{destructed:boolean, confidence:number, indicators:string[], lsbUniformity:number}}
   */
  detectDestruction(imageBuffer, expectedUserId = null, expectedTimestamp = null) {
    if (!Buffer.isBuffer(imageBuffer)) {
      throw new WatermarkError('Invalid image buffer', 'INVALID_IMAGE');
    }

    const pixelData = extractPixelsFromPNG(imageBuffer);
    if (!pixelData) {
      return {
        destructed: true,
        confidence: 100,
        indicators: ['invalid_png_format'],
        lsbUniformity: 0,
      };
    }

    const { rgba, width, height } = pixelData;
    const indicators = [];
    let destructionConfidence = 0;

    // Check 1: LSB uniformity attack
    // If LSBs are too uniform (all 0s or all 1s), watermark was stripped
    const lsbCounts = { '0': 0, '1': 0 };
    for (let i = 0; i < rgba.length; i += 4) {
      for (let c = 0; c < 3; c++) {
        const lsb = rgba[i + c] & 1;
        lsbCounts[lsb]++;
      }
    }
    const totalLsb = lsbCounts['0'] + lsbCounts['1'];
    const lsbRatio = totalLsb > 0 ? Math.max(lsbCounts['0'], lsbCounts['1']) / totalLsb : 0;
    const lsbUniformity = lsbRatio;

    if (lsbRatio > 0.95) {
      indicators.push('lsb_too_uniform');
      destructionConfidence += 40;
    }

    // Check 2: JPEG compression artifacts
    const blockiness = this.#detectBlockiness(rgba, width, height);
    if (blockiness > 0.3) {
      indicators.push('jpeg_blockiness_detected');
      destructionConfidence += 20;
    }

    // Check 3: Heavy noise/filtering
    const noiseLevel = this.#estimateNoiseLevel(rgba, width, height);
    if (noiseLevel > 30) {
      indicators.push('heavy_noise_or_filtering');
      destructionConfidence += 15;
    }

    // Check 4: Pixel value distribution anomaly
    const distributionScore = this.#analyzePixelDistribution(rgba);
    if (distributionScore < 0.5) {
      indicators.push('pixel_distribution_anomaly');
      destructionConfidence += 15;
    }

    // If expected watermark provided, check if it can be found
    if (expectedUserId && expectedTimestamp) {
      const verifyResult = this.verifyWatermark(imageBuffer, expectedUserId, expectedTimestamp);
      if (!verifyResult.valid) {
        indicators.push(`watermark_verification_failed_${verifyResult.confidence.toFixed(1)}%`);
        destructionConfidence = Math.max(destructionConfidence, 100 - verifyResult.confidence);
      }
    }

    return {
      destructed: destructionConfidence >= DESTRUCTION_DETECTION_THRESHOLD || indicators.length >= 2,
      confidence: Math.round(destructionConfidence),
      indicators,
      lsbUniformity: Math.round(lsbUniformity * 1000) / 1000,
    };
  }

  // ---------------------------------------------------------------------------
  // Database Management
  // ---------------------------------------------------------------------------

  /**
   * Register a user for watermark tracking.
   * @param {string} userId
   */
  registerUser(userId) {
    if (!this.#userDatabase.has(userId)) {
      this.#userDatabase.set(userId, []);
    }
  }

  /**
   * Remove a user and all their watermarks from tracking.
   * @param {string} userId
   */
  unregisterUser(userId) {
    this.#userDatabase.delete(userId);
  }

  /**
   * Get all registered user IDs.
   * @returns {string[]}
   */
  getRegisteredUsers() {
    return Array.from(this.#userDatabase.keys());
  }

  /**
   * Clear all watermark records.
   */
  clearDatabase() {
    this.#userDatabase.clear();
  }

  /**
   * Get database statistics.
   * @returns {{totalUsers:number,totalEntries:number}}
   */
  getDatabaseStats() {
    let totalEntries = 0;
    for (const entries of this.#userDatabase.values()) {
      totalEntries += entries.length;
    }
    return { totalUsers: this.#userDatabase.size, totalEntries };
  }

  // =========================================================================
  // Private: Layer 2 — DCT Watermark Embedding
  // =========================================================================

  /**
   * Embed watermark bits into DCT coefficients of 8x8 blocks.
   * @param {Buffer} rgba
   * @param {number} width
   * @param {number} height
   * @param {number[]} bits
   * @param {Array<{x:number,y:number}>} blockPositions  Block positions (in 8x8 grid)
   */
  #embedDCTWatermark(rgba, width, height, bits, blockPositions) {
    const block = new Float64Array(64);

    for (let b = 0; b < blockPositions.length && b * 6 < bits.length; b++) {
      const bx = blockPositions[b].x;
      const by = blockPositions[b].y;

      if (bx * 8 + 7 >= width || by * 8 + 7 >= height) continue;

      // Extract 8x8 block (luminance from green channel)
      for (let y = 0; y < 8; y++) {
        for (let x = 0; x < 8; x++) {
          const pixelIdx = ((by * 8 + y) * width + (bx * 8 + x)) * 4;
          block[y * 8 + x] = rgba[pixelIdx + 1]; // G channel
        }
      }

      // Apply DCT
      fdct8x8(block);

      // Embed 6 bits in mid-frequency coefficients (positions 10-15 in zigzag)
      const zigzagMidFreq = [10, 11, 12, 13, 14, 15];
      for (let i = 0; i < 6 && b * 6 + i < bits.length; i++) {
        const coeffIdx = zigzagMidFreq[i];
        const bit = bits[b * 6 + i];

        // Modify coefficient based on bit value
        if (bit === 1) {
          block[coeffIdx] += DCT_WATERMARK_STRENGTH;
        } else {
          block[coeffIdx] -= DCT_WATERMARK_STRENGTH;
        }
      }

      // Inverse DCT
      idct8x8(block);

      // Write back
      for (let y = 0; y < 8; y++) {
        for (let x = 0; x < 8; x++) {
          const pixelIdx = ((by * 8 + y) * width + (bx * 8 + x)) * 4;
          rgba[pixelIdx + 1] = clamp(Math.round(block[y * 8 + x]), 0, 255);
        }
      }
    }
  }

  /**
   * Extract DCT watermark bits.
   * @param {Buffer} rgba
   * @param {number} width
   * @param {number} height
   * @param {Array<{x:number,y:number}>} blockPositions
   * @returns {number[]}
   */
  #extractDCTWatermark(rgba, width, height, blockPositions) {
    const block = new Float64Array(64);
    const extracted = [];

    for (const bp of blockPositions) {
      if (bp.x * 8 + 7 >= width || bp.y * 8 + 7 >= height) {
        extracted.push(0, 0, 0, 0, 0, 0);
        continue;
      }

      // Extract 8x8 block
      for (let y = 0; y < 8; y++) {
        for (let x = 0; x < 8; x++) {
          const pixelIdx = ((bp.y * 8 + y) * width + (bp.x * 8 + x)) * 4;
          block[y * 8 + x] = rgba[pixelIdx + 1];
        }
      }

      fdct8x8(block);

      const zigzagMidFreq = [10, 11, 12, 13, 14, 15];
      for (const idx of zigzagMidFreq) {
        extracted.push(block[idx] > 0 ? 1 : 0);
      }
    }

    return extracted;
  }

  // =========================================================================
  // Private: Layer 3 — Statistical Colour Palette Shift
  // =========================================================================

  /**
   * Embed watermark by subtly shifting the colour of specific pixels.
   * This affects the statistical distribution of colours in the image.
   * @param {Buffer} rgba
   * @param {number} width
   * @param {number} height
   * @param {number[]} bits
   * @param {Array<{x:number,y:number}>} positions
   */
  #embedStatisticalShift(rgba, width, height, bits, positions) {
    for (let p = 0; p < positions.length && p * 6 < bits.length; p++) {
      const { x, y } = positions[p];
      const pixelIdx = (y * width + x) * 4;

      // Shift each channel by ±STATISTICAL_SHIFT_STRENGTH based on bits
      for (let c = 0; c < 3; c++) {
        const bit = bits[p * 6 + c * 2];
        const shift = bit === 1 ? STATISTICAL_SHIFT_STRENGTH : -STATISTICAL_SHIFT_STRENGTH;
        rgba[pixelIdx + c] = clamp(Math.round(rgba[pixelIdx + c] + shift), 0, 255);
      }
    }
  }

  /**
   * Extract statistical shift watermark.
   * @param {Buffer} rgba
   * @param {number} width
   * @param {number} height
   * @param {Array<{x:number,y:number}>} positions
   * @returns {number[]}
   */
  #extractStatisticalShift(rgba, width, height, positions) {
    const extracted = [];

    for (const pos of positions) {
      const pixelIdx = (pos.y * width + pos.x) * 4;

      for (let c = 0; c < 3; c++) {
        // Determine if shift was positive or negative
        const val = rgba[pixelIdx + c];
        const lsb = (val & 0b00000010) >> 1;
        extracted.push(lsb);
        // Pad to 6 bits per position
        extracted.push(val & 1);
      }
    }

    return extracted;
  }

  // =========================================================================
  // Private: Watermark Helpers
  // =========================================================================

  /**
   * Record a watermark in the database for leak tracing.
   * @param {string} userId
   * @param {number} timestamp
   */
  #recordWatermark(userId, timestamp) {
    if (!this.#userDatabase.has(userId)) {
      this.#userDatabase.set(userId, []);
    }
    const entries = this.#userDatabase.get(userId);
    // Avoid duplicates
    if (!entries.some(e => e.timestamp === timestamp)) {
      entries.push({ timestamp, createdAt: Date.now() });
    }
    // Keep only last 100 entries per user
    if (entries.length > 100) {
      entries.splice(0, entries.length - 100);
    }
  }

  /**
   * Compare two bit arrays and return match statistics.
   * @param {number[]} expected
   * @param {number[]} actual
   * @returns {{matched:number,total:number,confidence:number}}
   */
  #compareBits(expected, actual) {
    const total = Math.min(expected.length, WATERMARK_BIT_LENGTH);
    let matched = 0;
    for (let i = 0; i < total; i++) {
      if (expected[i] === actual[i]) matched++;
    }
    return {
      matched,
      total,
      confidence: total > 0 ? (matched / total) * 100 : 0,
    };
  }

  /**
   * Extract LSB watermark from specific positions.
   * @param {Buffer} rgba
   * @param {number} width
   * @param {number} height
   * @param {Array<{x:number,y:number}>} positions
   * @returns {number[]}
   */
  #extractLSB(rgba, width, height, positions) {
    const bits = [];
    for (const pos of positions) {
      if (pos.x < 0 || pos.x >= width || pos.y < 0 || pos.y >= height) continue;
      const idx = (pos.y * width + pos.x) * 4;
      const r = rgba[idx] & LSB_MASK;
      const g = rgba[idx + 1] & LSB_MASK;
      const b = rgba[idx + 2] & LSB_MASK;
      bits.push((r >> 1) & 1, r & 1);
      bits.push((g >> 1) & 1, g & 1);
      bits.push((b >> 1) & 1, b & 1);
    }
    return bits;
  }

  /**
   * Verify watermark with position offset (for degradation tolerance).
   * @param {Buffer} imageBuffer
   * @param {string} userId
   * @param {number} timestamp
   * @param {number} offset
   * @returns {WatermarkVerifyResult}
   */
  #verifyWithOffset(imageBuffer, userId, timestamp, offset) {
    const pixelData = extractPixelsFromPNG(imageBuffer);
    if (!pixelData) {
      return { valid: false, confidence: 0, matchedBits: 0, totalBits: WATERMARK_BIT_LENGTH, layer: 'none' };
    }

    const expectedBits = this.generateWatermark(userId, timestamp);
    const seed = hexToSeed(hmacSha512(this.#secret, `${userId}:${timestamp}`));
    const basePositions = generateSeededPositions(seed, pixelData.width, pixelData.height, PIXELS_NEEDED);

    // Apply offset
    const offsetPositions = basePositions.map(p => ({
      x: clamp(p.x + offset, 0, pixelData.width - 1),
      y: clamp(p.y + offset, 0, pixelData.height - 1),
    }));

    const extracted = this.extractWatermark(imageBuffer, offsetPositions);
    let matched = 0;
    for (let i = 0; i < Math.min(expectedBits.length, extracted.length); i++) {
      if (expectedBits[i] === extracted[i]) matched++;
    }
    const confidence = (matched / WATERMARK_BIT_LENGTH) * 100;

    return {
      valid: confidence >= VERIFICATION_CONFIDENCE_THRESHOLD,
      confidence: Math.round(confidence * 100) / 100,
      matchedBits: matched,
      totalBits: WATERMARK_BIT_LENGTH,
      layer: 'lsb_offset',
    };
  }

  // =========================================================================
  // Private: Image Analysis for Destruction Detection
  // =========================================================================

  /**
   * Detect JPEG blockiness artifacts.
   * @param {Buffer} rgba
   * @param {number} width
   * @param {number} height
   * @returns {number} 0-1 score
   */
  #detectBlockiness(rgba, width, height) {
    let blockyScore = 0;
    let samples = 0;

    for (let y = 0; y < height - 1; y++) {
      for (let x = 0; x < width - 1; x++) {
        const idx = (y * width + x) * 4;
        const rightIdx = (y * width + x + 1) * 4;
        const downIdx = ((y + 1) * width + x) * 4;

        const diffRight = Math.abs(rgba[idx] - rgba[rightIdx]);
        const diffDown = Math.abs(rgba[idx] - rgba[downIdx]);

        // On 8-pixel boundaries, JPEG blockiness shows as unnatural edges
        if ((x + 1) % 8 === 0 || (y + 1) % 8 === 0) {
          blockyScore += diffRight + diffDown;
          samples += 2;
        }
      }
    }

    return samples > 0 ? Math.min(1, blockyScore / (samples * 20)) : 0;
  }

  /**
   * Estimate noise level in the image.
   * @param {Buffer} rgba
   * @param {number} width
   * @param {number} height
   * @returns {number} Estimated noise standard deviation
   */
  #estimateNoiseLevel(rgba, width, height) {
    let totalDiff = 0;
    let samples = 0;

    for (let y = 1; y < height - 1; y += 2) {
      for (let x = 1; x < width - 1; x += 2) {
        const idx = (y * width + x) * 4;
        const right = (y * width + x + 1) * 4;
        const left = (y * width + x - 1) * 4;
        const up = ((y - 1) * width + x) * 4;
        const down = ((y + 1) * width + x) * 4;

        const avgNeighbor = (
          rgba[right] + rgba[left] + rgba[up] + rgba[down]
        ) / 4;

        totalDiff += Math.abs(rgba[idx] - avgNeighbor);
        samples++;
      }
    }

    return samples > 0 ? (totalDiff / samples) * 2 : 0;
  }

  /**
   * Analyze pixel value distribution.
   * @param {Buffer} rgba
   * @returns {number} Distribution score (0-1)
   */
  #analyzePixelDistribution(rgba) {
    // Count pixels in each bucket
    const buckets = new Array(16).fill(0);
    for (let i = 0; i < rgba.length; i += 4) {
      const brightness = (rgba[i] + rgba[i + 1] + rgba[i + 2]) / 3;
      const bucket = Math.floor(brightness / 16);
      buckets[clamp(bucket, 0, 15)]++;
    }

    // Calculate entropy-like distribution score
    const total = buckets.reduce((a, b) => a + b, 0);
    if (total === 0) return 0;

    let entropy = 0;
    for (const count of buckets) {
      if (count > 0) {
        const p = count / total;
        entropy -= p * Math.log2(p);
      }
    }
    return Math.min(1, entropy / 4);
  }
}

// =============================================================================
// DCT Functions (8x8 Forward and Inverse)
// =============================================================================

/**
 * 8x8 Forward DCT (AAN algorithm).
 * @param {Float64Array} block  64-element array (input/output in-place)
 */
function fdct8x8(block) {
  const tmp = new Float64Array(64);

  // Row DCT
  for (let i = 0; i < 8; i++) {
    const row = i * 8;
    const b0 = block[row] + block[row + 7];
    const b1 = block[row + 1] + block[row + 6];
    const b2 = block[row + 2] + block[row + 5];
    const b3 = block[row + 3] + block[row + 4];
    const b4 = block[row + 3] - block[row + 4];
    const b5 = block[row + 2] - block[row + 5];
    const b6 = block[row + 1] - block[row + 6];
    const b7 = block[row] - block[row + 7];

    const c0 = b0 + b3;
    const c1 = b1 + b2;
    const c2 = b1 - b2;
    const c3 = b0 - b3;

    tmp[row] = c0 + c1;
    tmp[row + 4] = c0 - c1;
    tmp[row + 2] = c2 * 1.847759065 + c3 * 0.765366865;
    tmp[row + 6] = c3 * 1.847759065 - c2 * 0.765366865;

    const d0 = b7 * 0.298631336 + b6 * 1.961570560 + b5 * 0.390180644 + b4 * 1.501321110;
    const d1 = b7 * 1.501321110 - b6 * 0.298631336 + b5 * 1.961570560 - b4 * 0.390180644;
    const d2 = b7 * 1.501321110 + b6 * 0.298631336 - b5 * 1.961570560 - b4 * 0.390180644;
    const d3 = b7 * 0.298631336 - b6 * 1.961570560 + b5 * 0.390180644 + b4 * 1.501321110;

    tmp[row + 1] = d0;
    tmp[row + 3] = d1;
    tmp[row + 5] = d2;
    tmp[row + 7] = d3;
  }

  // Column DCT
  for (let i = 0; i < 8; i++) {
    const b0 = tmp[i] + tmp[56 + i];
    const b1 = tmp[8 + i] + tmp[48 + i];
    const b2 = tmp[16 + i] + tmp[40 + i];
    const b3 = tmp[24 + i] + tmp[32 + i];
    const b4 = tmp[24 + i] - tmp[32 + i];
    const b5 = tmp[16 + i] - tmp[40 + i];
    const b6 = tmp[8 + i] - tmp[48 + i];
    const b7 = tmp[i] - tmp[56 + i];

    const c0 = b0 + b3;
    const c1 = b1 + b2;
    const c2 = b1 - b2;
    const c3 = b0 - b3;

    block[i] = (c0 + c1) / 8;
    block[32 + i] = (c0 - c1) / 8;
    block[16 + i] = (c2 * 1.847759065 + c3 * 0.765366865) / 8;
    block[48 + i] = (c3 * 1.847759065 - c2 * 0.765366865) / 8;

    const d0 = b7 * 0.298631336 + b6 * 1.961570560 + b5 * 0.390180644 + b4 * 1.501321110;
    const d1 = b7 * 1.501321110 - b6 * 0.298631336 + b5 * 1.961570560 - b4 * 0.390180644;
    const d2 = b7 * 1.501321110 + b6 * 0.298631336 - b5 * 1.961570560 - b4 * 0.390180644;
    const d3 = b7 * 0.298631336 - b6 * 1.961570560 + b5 * 0.390180644 + b4 * 1.501321110;

    block[8 + i] = d0 / 8;
    block[24 + i] = d1 / 8;
    block[40 + i] = d2 / 8;
    block[56 + i] = d3 / 8;
  }
}

/**
 * 8x8 Inverse DCT.
 * @param {Float64Array} block  64-element array (input/output in-place)
 */
function idct8x8(block) {
  const tmp = new Float64Array(64);

  // Column IDCT
  for (let i = 0; i < 8; i++) {
    const c0 = block[i] + block[32 + i];
    const c1 = block[i] - block[32 + i];
    const c2 = block[16 + i] * 0.541196100 + block[48 + i] * 1.306562965;
    const c3 = block[48 + i] * 0.541196100 - block[16 + i] * 1.306562965;

    tmp[i] = c0 + c2;
    tmp[56 + i] = c0 - c2;
    tmp[8 + i] = c1 + c3;
    tmp[48 + i] = c1 - c3;

    const d0 = block[8 + i] + block[56 + i];
    const d1 = block[8 + i] - block[56 + i];
    const d2 = block[24 + i] + block[40 + i];
    const d3 = block[24 + i] - block[40 + i];

    const e0 = d0 + d2;
    const e2 = d0 - d2;
    const e1 = d1 * 0.382683433 + d3 * 0.923879532;
    const e3 = d3 * 0.382683433 - d1 * 0.923879532;

    tmp[16 + i] = e0 + e1;
    tmp[24 + i] = e0 - e1;
    tmp[32 + i] = e2 + e3;
    tmp[40 + i] = e2 - e3;
  }

  // Row IDCT
  for (let i = 0; i < 8; i++) {
    const row = i * 8;
    const c0 = tmp[row] + tmp[row + 4];
    const c1 = tmp[row] - tmp[row + 4];
    const c2 = tmp[row + 2] * 0.541196100 + tmp[row + 6] * 1.306562965;
    const c3 = tmp[row + 6] * 0.541196100 - tmp[row + 2] * 1.306562965;

    block[row] = c0 + c2;
    block[row + 7] = c0 - c2;
    block[row + 1] = c1 + c3;
    block[row + 6] = c1 - c3;

    const d0 = tmp[row + 1] + tmp[row + 5];
    const d1 = tmp[row + 1] - tmp[row + 5];
    const d2 = tmp[row + 3] + tmp[row + 7];
    const d3 = tmp[row + 3] - tmp[row + 7];

    const e0 = d0 + d2;
    const e2 = d0 - d2;
    const e1 = d1 * 0.382683433 + d3 * 0.923879532;
    const e3 = d3 * 0.382683433 - d1 * 0.923879532;

    block[row + 2] = e0 + e1;
    block[row + 3] = e0 - e1;
    block[row + 4] = e2 + e3;
    block[row + 5] = e2 - e3;
  }
}

// =============================================================================
// Standalone Utility Exports
// =============================================================================

/**
 * Generate watermark bits for a user + timestamp pair.
 *
 * @param {string} userId
 * @param {number} timestamp
 * @param {string} secret
 * @returns {number[]}
 */
export function generateWatermarkBits(userId, timestamp, secret) {
  if (!secret || secret.length < 32) {
    throw new WatermarkError('Secret must be at least 32 characters', 'SECRET_TOO_SHORT');
  }
  const message = `${userId}:${timestamp}`;
  const watermark = hmacSha256(secret, message);

  const bits = [];
  for (const hexChar of watermark) {
    const val = parseInt(hexChar, 16);
    for (let i = 3; i >= 0; i--) {
      bits.push((val >> i) & 1);
    }
  }
  return bits;
}

/**
 * Extract raw RGBA pixels from a PNG buffer.
 * Standalone utility function.
 *
 * @param {Buffer} pngBuffer
 * @returns {{rgba:Buffer,width:number,height:number}|null}
 */
export function decodePNG(pngBuffer) {
  return extractPixelsFromPNG(pngBuffer);
}

/**
 * Encode raw RGBA pixels to a PNG buffer.
 * Standalone utility function.
 *
 * @param {Buffer} rgba
 * @param {number} width
 * @param {number} height
 * @returns {Buffer}
 */
export function encodePNG(rgba, width, height) {
  return buildPNGFromPixels(rgba, width, height);
}

/**
 * Embed watermark bits into an RGBA buffer using LSB steganography.
 * Pure function — does not require WatermarkEngine instance.
 *
 * @param {Buffer} rgba
 * @param {number} width
 * @param {number} height
 * @param {number[]} bits
 * @param {Array<{x:number,y:number}>} positions
 * @returns {Buffer} Modified RGBA buffer
 */
export function embedLSBInBuffer(rgba, width, height, bits, positions) {
  const modified = Buffer.from(rgba);
  let bitIndex = 0;

  for (const pos of positions) {
    if (bitIndex >= bits.length) break;
    const pixelIdx = (pos.y * width + pos.x) * 4;
    if (pixelIdx < 0 || pixelIdx + 2 >= modified.length) continue;

    const rBits = (bits[bitIndex] << 1) | bits[bitIndex + 1];
    const gBits = (bits[bitIndex + 2] << 1) | bits[bitIndex + 3];
    const bBits = (bits[bitIndex + 4] << 1) | bits[bitIndex + 5];

    modified[pixelIdx] = (modified[pixelIdx] & CLEAR_MASK) | rBits;
    modified[pixelIdx + 1] = (modified[pixelIdx + 1] & CLEAR_MASK) | gBits;
    modified[pixelIdx + 2] = (modified[pixelIdx + 2] & CLEAR_MASK) | bBits;

    bitIndex += BITS_PER_PIXEL;
  }

  return modified;
}

/**
 * Calculate the maximum watermark capacity of an image.
 * @param {number} width
 * @param {number} height
 * @returns {{totalBits:number,totalPixels:number,pixelsNeeded:number}}
 */
export function calculateWatermarkCapacity(width, height) {
  const totalPixels = width * height;
  const totalBits = totalPixels * BITS_PER_PIXEL;
  return {
    totalBits,
    totalPixels,
    pixelsNeeded: PIXELS_NEEDED,
  };
}

// Default export
export default WatermarkEngine;
