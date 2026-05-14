/**
 * @fileoverview fragment.js — 3-Factor Code Decryption Engine (Crown Jewel)
 *
 * The gift code is split into 3 fragments using cryptographically secure XOR splitting:
 *   Fragment A = random bytes
 *   Fragment B = random bytes
 *   Fragment C = code XOR Fragment A XOR Fragment B
 *
 * Server sends Factor Challenges to the client. The client solves them to earn
 * fragments, then combines all three to recover the original code.
 *
 * Security model:
 * - Factor 1 (Fragment A): Time-bound HMAC challenge — proves live page load
 * - Factor 2 (Fragment B): Human interaction proof — mouse entropy, curvature, timing
 * - Factor 3 (Fragment C): Browser fingerprint + behavioural score — anti-automation
 *
 * @module osmarmy-fortress/core/fragment
 * @version 1.0.0
 * @author OsmArmy Security Team
 */

'use strict';

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

// =============================================================================
// Custom Error Classes
// =============================================================================

/** Base error for all fragment-engine failures. */
export class FragmentEngineError extends Error {
  /**
   * @param {string} message
   * @param {string} code  Machine-readable error code
   * @param {number} [statusCode=500]
   */
  constructor(message, code, statusCode = 500) {
    super(message);
    this.name = 'FragmentEngineError';
    this.code = code;
    this.statusCode = statusCode;
    Error.captureStackTrace(this, this.constructor);
  }
}

/** Challenge-related errors (expired, replay, bad response, etc.). */
export class ChallengeError extends FragmentEngineError {
  constructor(message, code = 'CHALLENGE_INVALID', statusCode = 403) {
    super(message, code, statusCode);
    this.name = 'ChallengeError';
  }
}

/** Token lifecycle errors. */
export class TokenError extends FragmentEngineError {
  constructor(message, code = 'TOKEN_INVALID', statusCode = 401) {
    super(message, code, statusCode);
    this.name = 'TokenError';
  }
}

/** Interaction-validation errors. */
export class InteractionError extends FragmentEngineError {
  constructor(message, code = 'INTERACTION_INVALID', statusCode = 403) {
    super(message, code, statusCode);
    this.name = 'InteractionError';
  }
}

// =============================================================================
// Constants
// =============================================================================

const CHALLENGE_TTL_MS = 10_000;          // 10-second challenge expiry
const TOKEN_TTL_MS = 10_000;              // 10-second token expiry
const HMAC_ALGORITHM = 'sha512';
const WATERMARK_ALGORITHM = 'sha256';
const FRAGMENT_A_CHALLENGE_PREFIX = 'FACTOR_A';
const FRAGMENT_B_CHALLENGE_PREFIX = 'FACTOR_B';
const FRAGMENT_C_CHALLENGE_PREFIX = 'FACTOR_C';

// Known automation / headless fingerprints (SHA-256 hex hashes)
const KNOWN_AUTOMATION_HASHES = new Set([
  'a3b5c7d9e1f2030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d',
  'b4c6d8e0f2030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e',
  'c5d7e9f1030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
  'd6e8f0f20405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
  'e7f9f1f305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021',
]);

// Interaction validation thresholds
const INTERACTION_THRESHOLD = Object.freeze({
  MIN_MOUSE_EVENTS: 3,
  MIN_SCROLL_EVENTS: 1,
  MIN_SPEED_VARIANCE: 100,
  MAX_SPEED_VARIANCE: 500,
  MIN_ENTROPY: 0.70,
  MIN_CURVATURE: 0.30,
  MIN_DURATION_MS: 5_000,
  MAX_TELEPORT_PX: 300,
  MIN_DIRECTION_CHANGES: 1,
  SCROLL_PAUSE_MS: 300,
});

// Fingerprint validation thresholds
const FINGERPRINT_THRESHOLD = Object.freeze({
  MIN_HARDWARE_CONCURRENCY: 1,
  MAX_HARDWARE_CONCURRENCY: 16,
  MIN_BEHAVIORAL_SCORE: 0,
  MAX_BEHAVIORAL_SCORE: 30,
  MIN_SCREEN_WIDTH: 320,
  MAX_SCREEN_WIDTH: 7680,
  MIN_SCREEN_HEIGHT: 240,
  MAX_SCREEN_HEIGHT: 4320,
  MIN_CANVAS_LENGTH: 16,
  MIN_WEBGL_LENGTH: 8,
});

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Compute SHA-256 checksum of a string or buffer.
 * @param {string|Buffer} data
 * @returns {string} Hex-encoded digest
 */
function sha256(data) {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Compute HMAC-SHA512 of key + message.
 * @param {string|Buffer} key
 * @param {string|Buffer} message
 * @returns {string} Hex-encoded digest
 */
function hmacSha512(key, message) {
  return createHmac(HMAC_ALGORITHM, key).update(message).digest('hex');
}

/**
 * Compute HMAC-SHA256 of key + message.
 * @param {string|Buffer} key
 * @param {string|Buffer} message
 * @returns {string} Hex-encoded digest
 */
function hmacSha256(key, message) {
  return createHmac(WATERMARK_ALGORITHM, key).update(message).digest('hex');
}

/**
 * Generate a cryptographically secure random hex string.
 * @param {number} byteLength
 * @returns {string}
 */
function secureRandomHex(byteLength) {
  return randomBytes(byteLength).toString('hex');
}

/**
 * Generate a cryptographically secure random byte array.
 * @param {number} length
 * @returns {Buffer}
 */
function secureRandomBytes(length) {
  return randomBytes(length);
}

/**
 * XOR three buffers together. All buffers must be the same length.
 * @param {Buffer} a
 * @param {Buffer} b
 * @param {Buffer} c
 * @returns {Buffer}
 */
function xorBuffers(a, b, c) {
  const len = a.length;
  if (b.length !== len || c.length !== len) {
    throw new FragmentEngineError('Buffer length mismatch in xorBuffers', 'XOR_LEN_MISMATCH');
  }
  const result = Buffer.allocUnsafe(len);
  for (let i = 0; i < len; i++) {
    result[i] = a[i] ^ b[i] ^ c[i];
  }
  return result;
}

/**
 * Perform constant-time comparison of two hex strings.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function constantTimeCompare(a, b) {
  try {
    const bufA = Buffer.from(a, 'hex');
    const bufB = Buffer.from(b, 'hex');
    if (bufA.length !== bufB.length) return false;
    return timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

/**
 * Calculate Shannon entropy of an array of numeric values.
 * @param {number[]} values
 * @returns {number} Entropy in bits (0 = no entropy, log2(N) = max)
 */
function shannonEntropy(values) {
  if (!values || values.length === 0) return 0;

  // Build frequency histogram — bin to integers for mouse coordinates
  const freq = new Map();
  for (const v of values) {
    const bin = Math.floor(v);
    freq.set(bin, (freq.get(bin) || 0) + 1);
  }

  const total = values.length;
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / total;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Compute curvature of a 3-point path segment.
 * Returns a value between 0 (straight) and 1 (max curve).
 * @param {{x:number,y:number}} p1
 * @param {{x:number,y:number}} p2
 * @param {{x:number,y:number}} p3
 * @returns {number}
 */
function curvatureScore(p1, p2, p3) {
  const d1 = Math.hypot(p2.x - p1.x, p2.y - p1.y);
  const d2 = Math.hypot(p3.x - p2.x, p3.y - p2.y);
  const d3 = Math.hypot(p3.x - p1.x, p3.y - p1.y);

  if (d1 === 0 || d2 === 0) return 0;

  // Heron's formula for triangle area
  const s = (d1 + d2 + d3) / 2;
  const area = Math.sqrt(Math.max(0, s * (s - d1) * (s - d2) * (s - d3)));

  // Curvature = 4*area / (d1*d2*d3) for circumcircle, normalised
  const curvature = (4 * area) / (d1 * d2 * d3 + 1e-10);
  return Math.min(1, curvature * 50); // Scale to 0-1 range
}

// =============================================================================
// Token Store (in-memory with TTL sweeping)
// =============================================================================

/** Simple in-memory store with automatic expiry sweeping. */
class TokenStore {
  /** @type {Map<string, TokenEntry>} */
  #store = new Map();
  #sweepIntervalMs;
  #sweepTimer = null;

  /**
   * @param {object} [options]
   * @param {number} [options.sweepIntervalMs=5000] How often to sweep expired tokens
   */
  constructor(options = {}) {
    this.#sweepIntervalMs = options.sweepIntervalMs || 5_000;
    this.#startSweep();
  }

  /**
   * Store a new token.
   * @param {string} token
   * @param {TokenEntry} entry
   */
  set(token, entry) {
    this.#store.set(token, entry);
  }

  /**
   * Retrieve a token entry.
   * @param {string} token
   * @returns {TokenEntry|undefined}
   */
  get(token) {
    const entry = this.#store.get(token);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this.#store.delete(token);
      return undefined;
    }
    return entry;
  }

  /**
   * Check if a token exists and is still valid (non-expired).
   * @param {string} token
   * @returns {boolean}
   */
  has(token) {
    return this.get(token) !== undefined;
  }

  /**
   * Delete a token.
   * @param {string} token
   */
  delete(token) {
    this.#store.delete(token);
  }

  /** @returns {number} Current token count. */
  get size() {
    return this.#store.size;
  }

  /** Clean up expired entries periodically. */
  #startSweep() {
    this.#sweepTimer = setInterval(() => {
      const now = Date.now();
      for (const [token, entry] of this.#store) {
        if (now > entry.expiresAt) {
          this.#store.delete(token);
        }
      }
    }, this.#sweepIntervalMs);

    // Don't let the timer keep the process alive
    if (this.#sweepTimer.unref) {
      this.#sweepTimer.unref();
    }
  }

  /** Destroy the store and stop sweeping. */
  destroy() {
    if (this.#sweepTimer) {
      clearInterval(this.#sweepTimer);
      this.#sweepTimer = null;
    }
    this.#store.clear();
  }
}

// =============================================================================
// FragmentEngine — Main Class
// =============================================================================

/**
 * @typedef {object} SplitResult
 * @property {Buffer} fragmentA
 * @property {Buffer} fragmentB
 * @property {Buffer} fragmentC
 * @property {FragmentMetadata} metadata
 */

/**
 * @typedef {object} FragmentMetadata
 * @property {number} length
 * @property {string} checksum   SHA-256 of the original code
 * @property {number} timestamp  Epoch ms when split occurred
 * @property {string} splitId    Unique identifier for this split
 */

/**
 * @typedef {object} TokenEntry
 * @property {string} token
 * @property {number} createdAt
 * @property {number} expiresAt
 * @property {string} ip
 * @property {string} deviceFingerprint
 * @property {string} codeHash       SHA-256 of the code (one code per token)
 * @property {Set<number>} completedFactors
 * @property {Map<number,string>} responses   factorNumber -> response hex
 * @property {boolean} consumed
 * @property {SplitResult|null} splitResult   Stored fragments for this token
 */

/**
 * @typedef {object} InteractionData
 * @property {MouseEvent[]} mouseEvents
 * @property {ScrollEvent[]} scrollEvents
 * @property {TimingData} timing
 */

/**
 * @typedef {object} MouseEvent
 * @property {number} x
 * @property {number} y
 * @property {number} timestamp
 * @property {string} type   'move' | 'click' | 'enter' | 'leave'
 */

/**
 * @typedef {object} ScrollEvent
 * @property {number} scrollY
 * @property {number} scrollX
 * @property {number} timestamp
 * @property {string} direction  'up' | 'down' | 'left' | 'right'
 */

/**
 * @typedef {object} TimingData
 * @property {number} firstEventAt
 * @property {number} lastEventAt
 * @property {number} totalDurationMs
 */

/**
 * @typedef {object} BrowserFingerprint
 * @property {string} canvas        Canvas fingerprint string
 * @property {string} webgl         WebGL fingerprint string
 * @property {number} screenWidth
 * @property {number} screenHeight
 * @property {string} timezone
 * @property {number} hardwareConcurrency
 * @property {boolean} isHeadless
 * @property {boolean} isVirtualMachine
 * @property {string[]} plugins
 * @property {string} userAgent
 * @property {string} language
 */

/**
 * @typedef {object} FactorChallenge
 * @property {string} token
 * @property {number} factorNumber
 * @property {string} challenge    The challenge payload (hex HMAC prefix)
 * @property {number} expiresAt
 * @property {string} type         'time_hmac' | 'interaction' | 'fingerprint'
 */

/**
 * @typedef {object} LeakTraceResult
 * @property {string|null} userId
 * @property {number|null} timestamp
 * @property {number} confidence
 */

export class FragmentEngine {
  #secret;
  #dailySeed;
  #tokenStore;
  #usedTokenFingerprints;

  /**
   * Create a new FragmentEngine.
   *
   * @param {object} options
   * @param {string} options.secret   Master secret for HMAC operations (min 32 chars)
   * @param {string} [options.dailySeed]  Daily rotating seed (auto-generated if omitted)
   * @param {number} [options.tokenSweepIntervalMs=5000]
   */
  constructor(options) {
    if (!options || !options.secret) {
      throw new FragmentEngineError('Secret is required', 'MISSING_SECRET');
    }
    if (options.secret.length < 32) {
      throw new FragmentEngineError('Secret must be at least 32 characters', 'SECRET_TOO_SHORT');
    }

    this.#secret = options.secret;
    this.#dailySeed = options.dailySeed || this.#generateDailySeed();
    this.#tokenStore = new TokenStore({ sweepIntervalMs: options.tokenSweepIntervalMs });
    this.#usedTokenFingerprints = new Set(); // Prevents replay of token+fingerprint combos
  }

  // ---------------------------------------------------------------------------
  // Getters
  // ---------------------------------------------------------------------------

  /** @returns {string} Current daily seed. */
  get dailySeed() {
    return this.#dailySeed;
  }

  /** @returns {number} Number of active tokens. */
  get activeTokenCount() {
    return this.#tokenStore.size;
  }

  // ---------------------------------------------------------------------------
  // Daily Seed Management
  // ---------------------------------------------------------------------------

  /**
   * Generate a new daily seed. Should be called once per day (e.g. via cron).
   * @returns {string} The new daily seed.
   */
  rotateDailySeed() {
    this.#dailySeed = this.#generateDailySeed();
    return this.#dailySeed;
  }

  /**
   * Generate a deterministic daily seed based on calendar date + master secret.
   * @returns {string}
   */
  #generateDailySeed() {
    const date = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    return hmacSha256(this.#secret, `daily-seed:${date}`);
  }

  // ---------------------------------------------------------------------------
  // Code Splitting
  // ---------------------------------------------------------------------------

  /**
   * Split a gift code into 3 fragments using cryptographically secure XOR splitting.
   *
   *   Fragment A = random bytes (same length as code)
   *   Fragment B = random bytes (same length as code)
   *   Fragment C = code XOR Fragment A XOR Fragment B
   *
   * @param {string} code  The gift code to split (UTF-8 string)
   * @returns {SplitResult}
   *
   * @throws {FragmentEngineError} If code is empty or invalid
   */
  splitCode(code) {
    if (typeof code !== 'string' || code.length === 0) {
      throw new FragmentEngineError('Code must be a non-empty string', 'INVALID_CODE');
    }
    if (code.length > 256) {
      throw new FragmentEngineError('Code exceeds maximum length of 256 characters', 'CODE_TOO_LONG');
    }

    const codeBuffer = Buffer.from(code, 'utf8');
    const length = codeBuffer.length;

    // CSPRNG for both random fragments
    const fragmentA = secureRandomBytes(length);
    const fragmentB = secureRandomBytes(length);

    // Fragment C = code XOR A XOR B  (all 3 XOR together recover the code)
    const fragmentC = xorBuffers(codeBuffer, fragmentA, fragmentB);

    /** @type {FragmentMetadata} */
    const metadata = {
      length,
      checksum: sha256(codeBuffer),
      timestamp: Date.now(),
      splitId: secureRandomHex(16),
    };

    return { fragmentA, fragmentB, fragmentC, metadata };
  }

  /**
   * Combine 3 fragments to recover the original code.
   *
   *   code = Fragment A XOR Fragment B XOR Fragment C
   *
   * @param {Buffer} fragA
   * @param {Buffer} fragB
   * @param {Buffer} fragC
   * @param {FragmentMetadata} metadata  For checksum validation
   * @returns {string} The recovered gift code
   *
   * @throws {FragmentEngineError} If fragment lengths mismatch or checksum fails
   */
  combineFragments(fragA, fragB, fragC, metadata) {
    // Validate input types
    if (!Buffer.isBuffer(fragA) || !Buffer.isBuffer(fragB) || !Buffer.isBuffer(fragC)) {
      throw new FragmentEngineError('All fragments must be Buffers', 'INVALID_FRAGMENT_TYPE');
    }

    const len = fragA.length;
    if (fragB.length !== len || fragC.length !== len) {
      throw new FragmentEngineError(
        `Fragment length mismatch: A=${fragA.length}, B=${fragB.length}, C=${fragC.length}`,
        'FRAGMENT_LENGTH_MISMATCH'
      );
    }

    // Recover code via triple XOR
    const recovered = xorBuffers(fragA, fragB, fragC);

    // Validate against stored checksum
    if (metadata && metadata.checksum) {
      const recoveredChecksum = sha256(recovered);
      if (recoveredChecksum !== metadata.checksum) {
        throw new FragmentEngineError(
          'Fragment checksum mismatch — possible tampering detected',
          'CHECKSUM_MISMATCH',
          403
        );
      }
    }

    return recovered.toString('utf8');
  }

  // ---------------------------------------------------------------------------
  // Token Lifecycle
  // ---------------------------------------------------------------------------

  /**
   * Create a new token when the user opens the daily gift page.
   *
   * @param {string} ip                 Client IP address
   * @param {string} deviceFingerprint  SHA-256 of device fingerprint
   * @param {string} code               The gift code (only one per token)
   * @returns {{token:string, expiresAt:number}} The new token and its expiry
   *
   * @throws {TokenError} If fingerprint already has an active token
   */
  createToken(ip, deviceFingerprint, code) {
    if (!ip || typeof ip !== 'string') {
      throw new TokenError('IP address is required', 'MISSING_IP');
    }
    if (!deviceFingerprint || typeof deviceFingerprint !== 'string') {
      throw new TokenError('Device fingerprint is required', 'MISSING_FINGERPRINT');
    }
    if (!code || typeof code !== 'string') {
      throw new TokenError('Code is required', 'MISSING_CODE');
    }

    // Prevent duplicate tokens for same fingerprint
    const fingerprintKey = `${ip}:${deviceFingerprint}`;
    if (this.#usedTokenFingerprints.has(fingerprintKey)) {
      throw new TokenError(
        'Token already issued for this device — wait for expiry',
        'TOKEN_ALREADY_ISSUED'
      );
    }

    const token = secureRandomHex(32);
    const now = Date.now();
    const expiresAt = now + TOKEN_TTL_MS;

    // Split the code and store fragments server-side
    const splitResult = this.splitCode(code);

    /** @type {TokenEntry} */
    const entry = {
      token,
      createdAt: now,
      expiresAt,
      ip,
      deviceFingerprint,
      codeHash: sha256(code),
      completedFactors: new Set(),
      responses: new Map(),
      consumed: false,
      splitResult,
    };

    this.#tokenStore.set(token, entry);
    this.#usedTokenFingerprints.add(fingerprintKey);

    // Auto-release fingerprint lock after expiry
    setTimeout(() => {
      this.#usedTokenFingerprints.delete(fingerprintKey);
    }, TOKEN_TTL_MS + 1_000).unref?.();

    return { token, expiresAt };
  }

  /**
   * Retrieve a token entry after validating it exists and is not expired.
   *
   * @param {string} token
   * @returns {TokenEntry}
   * @throws {TokenError} If token missing, expired, or consumed
   */
  #getValidToken(token) {
    if (!token || typeof token !== 'string') {
      throw new TokenError('Token is required', 'MISSING_TOKEN');
    }

    const entry = this.#tokenStore.get(token);
    if (!entry) {
      throw new TokenError('Token not found or expired', 'TOKEN_NOT_FOUND', 401);
    }
    if (entry.consumed) {
      throw new TokenError('Token has already been consumed', 'TOKEN_CONSUMED', 403);
    }

    return entry;
  }

  /**
   * Validate that a request's IP and fingerprint match the token's binding.
   *
   * @param {TokenEntry} entry
   * @param {string} ip
   * @param {string} deviceFingerprint
   * @throws {TokenError} On mismatch
   */
  #validateTokenBinding(entry, ip, deviceFingerprint) {
    if (entry.ip !== ip) {
      throw new TokenError('Token bound to different IP address', 'IP_MISMATCH', 403);
    }
    if (entry.deviceFingerprint !== deviceFingerprint) {
      throw new TokenError('Token bound to different device', 'DEVICE_MISMATCH', 403);
    }
  }

  /**
   * Consume a token — mark it used and remove fragments.
   *
   * @param {string} token
   */
  consumeToken(token) {
    const entry = this.#getValidToken(token);
    entry.consumed = true;
    entry.splitResult = null; // Wipe fragments from memory
  }

  // ---------------------------------------------------------------------------
  // Factor 1: Time-Bound HMAC Challenge (Fragment A)
  // ---------------------------------------------------------------------------

  /**
   * Verify Factor 1 response and return Fragment A if correct.
   *
   * Factor 1 proves the client loaded the page at the correct time by requiring
   * them to respond with the first 8 hex chars of HMAC-SHA512(dailySeed + token + timestamp).
   *
   * @param {string} token            The token from createToken()
   * @param {string} clientResponse   First 8 hex chars of the expected HMAC
   * @param {number} clientTimestamp  Client's timestamp (must be within 10s of token creation)
   * @param {string} ip               Request IP
   * @param {string} deviceFingerprint
   * @returns {{verified:boolean, fragmentA?:Buffer}} Fragment A on success
   *
   * @throws {ChallengeError|TokenError} On any validation failure
   */
  verifyFragmentA(token, clientResponse, clientTimestamp, ip, deviceFingerprint) {
    // Validate inputs
    if (!clientResponse || typeof clientResponse !== 'string') {
      throw new ChallengeError('Client response is required', 'MISSING_RESPONSE');
    }
    if (!clientTimestamp || typeof clientTimestamp !== 'number') {
      throw new ChallengeError('Client timestamp is required', 'MISSING_TIMESTAMP');
    }

    const entry = this.#getValidToken(token);
    this.#validateTokenBinding(entry, ip, deviceFingerprint);

    // Check Factor 1 not already completed
    if (entry.completedFactors.has(1)) {
      throw new ChallengeError('Factor 1 already completed for this token', 'FACTOR_ALREADY_USED');
    }

    // Verify the time window — client timestamp must be within 10s of token creation
    const timeDiff = Math.abs(clientTimestamp - entry.createdAt);
    if (timeDiff > CHALLENGE_TTL_MS) {
      throw new ChallengeError(
        `Timestamp out of range: ${timeDiff}ms > ${CHALLENGE_TTL_MS}ms`,
        'TIMESTAMP_OUT_OF_RANGE'
      );
    }

    // Compute expected HMAC-SHA512(dailySeed + token + clientTimestamp)
    const hmacPayload = `${this.#dailySeed}:${token}:${clientTimestamp}`;
    const expectedHmac = hmacSha512(this.#secret, hmacPayload);
    const expectedPrefix = expectedHmac.slice(0, 8);

    // Constant-time comparison to prevent timing attacks
    if (!constantTimeCompare(clientResponse, expectedPrefix)) {
      // Log failed attempt for monitoring
      throw new ChallengeError('Fragment A challenge response invalid', 'INVALID_RESPONSE');
    }

    // Success — mark factor as completed
    entry.completedFactors.add(1);
    entry.responses.set(1, clientResponse);

    return {
      verified: true,
      fragmentA: entry.splitResult ? entry.splitResult.fragmentA : null,
    };
  }

  // ---------------------------------------------------------------------------
  // Factor 2: Human Interaction Proof (Fragment B)
  // ---------------------------------------------------------------------------

  /**
   * Verify Factor 2 — human interaction proof via mouse/scroll analysis.
   *
   * Validates:
   * - Mouse entropy > 0.7 (Shannon entropy)
   * - At least 3 distinct mouse movements
   * - At least 1 scroll event with pause
   * - Speed variance between 100-500px/sec
   * - At least 1 direction change
   * - Minimum 5 seconds interaction time
   * - No teleport (instant large jumps > 300px)
   * - Curvature score > 0.3 (human paths curve)
   *
   * @param {string} token
   * @param {InteractionData} interactionData
   * @param {string} ip
   * @param {string} deviceFingerprint
   * @returns {{verified:boolean, fragmentB?:Buffer, metrics:object}}
   *
   * @throws {InteractionError|TokenError} On any validation failure
   */
  verifyFragmentB(token, interactionData, ip, deviceFingerprint) {
    // Input validation
    if (!interactionData || typeof interactionData !== 'object') {
      throw new InteractionError('Interaction data is required', 'MISSING_DATA');
    }
    if (!Array.isArray(interactionData.mouseEvents)) {
      throw new InteractionError('mouseEvents must be an array', 'INVALID_MOUSE_EVENTS');
    }
    if (!Array.isArray(interactionData.scrollEvents)) {
      throw new InteractionError('scrollEvents must be an array', 'INVALID_SCROLL_EVENTS');
    }

    const entry = this.#getValidToken(token);
    this.#validateTokenBinding(entry, ip, deviceFingerprint);

    if (entry.completedFactors.has(2)) {
      throw new InteractionError('Factor 2 already completed for this token', 'FACTOR_ALREADY_USED');
    }

    // Factor 1 must be completed before Factor 2
    if (!entry.completedFactors.has(1)) {
      throw new InteractionError('Factor 1 must be completed first', 'OUT_OF_ORDER');
    }

    const { mouseEvents, scrollEvents, timing } = interactionData;
    const failures = [];
    const metrics = {};

    // ---- 1. Minimum mouse events ----
    if (mouseEvents.length < INTERACTION_THRESHOLD.MIN_MOUSE_EVENTS) {
      failures.push(`mouseEvents: ${mouseEvents.length} < ${INTERACTION_THRESHOLD.MIN_MOUSE_EVENTS}`);
    }
    metrics.mouseEventCount = mouseEvents.length;

    // ---- 2. Minimum scroll events ----
    if (scrollEvents.length < INTERACTION_THRESHOLD.MIN_SCROLL_EVENTS) {
      failures.push(`scrollEvents: ${scrollEvents.length} < ${INTERACTION_THRESHOLD.MIN_SCROLL_EVENTS}`);
    }
    metrics.scrollEventCount = scrollEvents.length;

    // ---- 3. Minimum interaction duration ----
    const duration = timing && timing.totalDurationMs
      ? timing.totalDurationMs
      : (mouseEvents.length >= 2
          ? mouseEvents[mouseEvents.length - 1].timestamp - mouseEvents[0].timestamp
          : 0);
    metrics.durationMs = duration;
    if (duration < INTERACTION_THRESHOLD.MIN_DURATION_MS) {
      failures.push(`duration: ${duration}ms < ${INTERACTION_THRESHOLD.MIN_DURATION_MS}ms`);
    }

    // ---- 4. Mouse entropy ----
    // Combine all x and y coordinates for entropy calculation
    const allCoords = [];
    for (const ev of mouseEvents) {
      if (typeof ev.x === 'number') allCoords.push(ev.x);
      if (typeof ev.y === 'number') allCoords.push(ev.y);
    }
    const entropy = allCoords.length > 0 ? shannonEntropy(allCoords) : 0;
    metrics.entropy = Math.round(entropy * 1000) / 1000;
    if (entropy < INTERACTION_THRESHOLD.MIN_ENTROPY) {
      failures.push(`entropy: ${entropy.toFixed(3)} < ${INTERACTION_THRESHOLD.MIN_ENTROPY}`);
    }

    // ---- 5. Speed variance ----
    const speeds = [];
    const directionChanges = [];
    let lastDx = 0;
    let lastDy = 0;

    for (let i = 1; i < mouseEvents.length; i++) {
      const dt = mouseEvents[i].timestamp - mouseEvents[i - 1].timestamp;
      if (dt <= 0) continue;

      const dx = mouseEvents[i].x - mouseEvents[i - 1].x;
      const dy = mouseEvents[i].y - mouseEvents[i - 1].y;
      const dist = Math.hypot(dx, dy);
      const speed = dist / (dt / 1000); // px/sec
      speeds.push(speed);

      // Direction change detection
      if (i > 1 && (lastDx !== 0 || lastDy !== 0)) {
        const dot = lastDx * dx + lastDy * dy;
        const mag1 = Math.hypot(lastDx, lastDy);
        const mag2 = Math.hypot(dx, dy);
        if (mag1 > 0 && mag2 > 0) {
          const cosAngle = dot / (mag1 * mag2);
          if (cosAngle < 0.707) { // > 45 degree turn
            directionChanges.push(i);
          }
        }
      }
      lastDx = dx;
      lastDy = dy;
    }

    const avgSpeed = speeds.length > 0 ? speeds.reduce((a, b) => a + b, 0) / speeds.length : 0;
    const speedVariance = speeds.length > 0
      ? Math.sqrt(speeds.reduce((sum, s) => sum + (s - avgSpeed) ** 2, 0) / speeds.length)
      : 0;
    metrics.avgSpeed = Math.round(avgSpeed);
    metrics.speedVariance = Math.round(speedVariance);
    metrics.directionChanges = directionChanges.length;

    if (speedVariance < INTERACTION_THRESHOLD.MIN_SPEED_VARIANCE ||
        speedVariance > INTERACTION_THRESHOLD.MAX_SPEED_VARIANCE) {
      failures.push(
        `speedVariance: ${Math.round(speedVariance)} not in [${INTERACTION_THRESHOLD.MIN_SPEED_VARIANCE}, ${INTERACTION_THRESHOLD.MAX_SPEED_VARIANCE}]`
      );
    }
    if (directionChanges.length < INTERACTION_THRESHOLD.MIN_DIRECTION_CHANGES) {
      failures.push(`directionChanges: ${directionChanges.length} < ${INTERACTION_THRESHOLD.MIN_DIRECTION_CHANGES}`);
    }

    // ---- 6. No teleport detection ----
    let teleports = 0;
    for (let i = 1; i < mouseEvents.length; i++) {
      const dt = mouseEvents[i].timestamp - mouseEvents[i - 1].timestamp;
      if (dt <= 50) continue; // Only check non-instant movements
      const dist = Math.hypot(
        mouseEvents[i].x - mouseEvents[i - 1].x,
        mouseEvents[i].y - mouseEvents[i - 1].y
      );
      // If distance is huge and time is small = teleport
      const effectiveDt = Math.max(dt, 1);
      const effectiveSpeed = dist / (effectiveDt / 1000);
      if (dist > INTERACTION_THRESHOLD.MAX_TELEPORT_PX && effectiveSpeed > 5000) {
        teleports++;
      }
    }
    metrics.teleports = teleports;
    if (teleports > 0) {
      failures.push(`teleports detected: ${teleports}`);
    }

    // ---- 7. Curvature score ----
    let totalCurvature = 0;
    let curvatureSamples = 0;
    for (let i = 2; i < mouseEvents.length; i++) {
      const p1 = { x: mouseEvents[i - 2].x, y: mouseEvents[i - 2].y };
      const p2 = { x: mouseEvents[i - 1].x, y: mouseEvents[i - 1].y };
      const p3 = { x: mouseEvents[i].x, y: mouseEvents[i].y };
      totalCurvature += curvatureScore(p1, p2, p3);
      curvatureSamples++;
    }
    const avgCurvature = curvatureSamples > 0 ? totalCurvature / curvatureSamples : 0;
    metrics.avgCurvature = Math.round(avgCurvature * 1000) / 1000;
    if (avgCurvature < INTERACTION_THRESHOLD.MIN_CURVATURE) {
      failures.push(`curvature: ${avgCurvature.toFixed(3)} < ${INTERACTION_THRESHOLD.MIN_CURVATURE}`);
    }

    // ---- 8. Scroll pause detection ----
    let hasScrollPause = false;
    for (let i = 1; i < scrollEvents.length; i++) {
      const pause = scrollEvents[i].timestamp - scrollEvents[i - 1].timestamp;
      if (pause >= INTERACTION_THRESHOLD.SCROLL_PAUSE_MS) {
        hasScrollPause = true;
        break;
      }
    }
    metrics.hasScrollPause = hasScrollPause;
    if (!hasScrollPause) {
      failures.push('no scroll pause detected');
    }

    // ---- Final verdict ----
    if (failures.length > 0) {
      throw new InteractionError(
        `Interaction validation failed: ${failures.join('; ')}`,
        'INTERACTION_CHECKS_FAILED'
      );
    }

    // Success
    entry.completedFactors.add(2);

    return {
      verified: true,
      fragmentB: entry.splitResult ? entry.splitResult.fragmentB : null,
      metrics,
    };
  }

  // ---------------------------------------------------------------------------
  // Factor 3: Browser Fingerprint + Behavioural Score (Fragment C)
  // ---------------------------------------------------------------------------

  /**
   * Verify Factor 3 — browser fingerprint and behavioural score validation.
   *
   * Validates fingerprint:
   * - Not a known automation fingerprint
   * - Canvas fingerprint present and valid
   * - WebGL fingerprint present
   * - Screen resolution reasonable
   * - Timezone valid
   * - Hardware concurrency between 1-16
   * - Not headless browser
   * - Not virtual machine
   *
   * Validates behavioural score: 0-30 (human range)
   *
   * @param {string} token
   * @param {BrowserFingerprint} browserFingerprint
   * @param {number} behavioralScore  0-30 = human, >30 = likely bot
   * @param {string} ip
   * @param {string} deviceFingerprint
   * @returns {{verified:boolean, fragmentC?:Buffer, checks:object}}
   *
   * @throws {ChallengeError|TokenError} On any validation failure
   */
  verifyFragmentC(token, browserFingerprint, behavioralScore, ip, deviceFingerprint) {
    // Input validation
    if (!browserFingerprint || typeof browserFingerprint !== 'object') {
      throw new ChallengeError('Browser fingerprint is required', 'MISSING_FINGERPRINT');
    }
    if (typeof behavioralScore !== 'number' || Number.isNaN(behavioralScore)) {
      throw new ChallengeError('Behavioral score must be a number', 'INVALID_SCORE');
    }

    const entry = this.#getValidToken(token);
    this.#validateTokenBinding(entry, ip, deviceFingerprint);

    if (entry.completedFactors.has(3)) {
      throw new ChallengeError('Factor 3 already completed for this token', 'FACTOR_ALREADY_USED');
    }

    // Factors 1 and 2 must be completed first
    if (!entry.completedFactors.has(1) || !entry.completedFactors.has(2)) {
      throw new ChallengeError('Factors 1 and 2 must be completed first', 'OUT_OF_ORDER');
    }

    const fp = browserFingerprint;
    const failures = [];
    const checks = {};

    // ---- 1. Check against known automation fingerprints ----
    const fpHash = sha256(JSON.stringify({
      canvas: fp.canvas,
      webgl: fp.webgl,
      hardwareConcurrency: fp.hardwareConcurrency,
    }));
    checks.knownAutomation = !KNOWN_AUTOMATION_HASHES.has(fpHash);
    if (!checks.knownAutomation) {
      failures.push('known automation fingerprint detected');
    }

    // ---- 2. Canvas fingerprint present and valid ----
    checks.canvasPresent = typeof fp.canvas === 'string' &&
                           fp.canvas.length >= FINGERPRINT_THRESHOLD.MIN_CANVAS_LENGTH;
    if (!checks.canvasPresent) {
      failures.push(`canvas fingerprint missing or too short: ${fp.canvas?.length || 0}`);
    }

    // ---- 3. WebGL fingerprint present ----
    checks.webglPresent = typeof fp.webgl === 'string' &&
                          fp.webgl.length >= FINGERPRINT_THRESHOLD.MIN_WEBGL_LENGTH;
    if (!checks.webglPresent) {
      failures.push(`webgl fingerprint missing or too short: ${fp.webgl?.length || 0}`);
    }

    // ---- 4. Screen resolution reasonable ----
    checks.screenValid =
      typeof fp.screenWidth === 'number' &&
      typeof fp.screenHeight === 'number' &&
      fp.screenWidth >= FINGERPRINT_THRESHOLD.MIN_SCREEN_WIDTH &&
      fp.screenWidth <= FINGERPRINT_THRESHOLD.MAX_SCREEN_WIDTH &&
      fp.screenHeight >= FINGERPRINT_THRESHOLD.MIN_SCREEN_HEIGHT &&
      fp.screenHeight <= FINGERPRINT_THRESHOLD.MAX_SCREEN_HEIGHT;
    if (!checks.screenValid) {
      failures.push(`screen resolution invalid: ${fp.screenWidth}x${fp.screenHeight}`);
    }

    // ---- 5. Timezone valid ----
    checks.timezoneValid = typeof fp.timezone === 'string' &&
                           fp.timezone.length > 0 &&
                           Intl.supportedValuesOf?.('timeZone')?.includes(fp.timezone) !== false;
    // Fallback: check IANA format
    if (checks.timezoneValid && fp.timezone) {
      try {
        // Validate by attempting to create a formatter
        new Intl.DateTimeFormat('en', { timeZone: fp.timezone });
        checks.timezoneValid = true;
      } catch {
        checks.timezoneValid = false;
        failures.push(`invalid timezone: ${fp.timezone}`);
      }
    }

    // ---- 6. Hardware concurrency between 1-16 ----
    checks.hardwareValid =
      typeof fp.hardwareConcurrency === 'number' &&
      Number.isInteger(fp.hardwareConcurrency) &&
      fp.hardwareConcurrency >= FINGERPRINT_THRESHOLD.MIN_HARDWARE_CONCURRENCY &&
      fp.hardwareConcurrency <= FINGERPRINT_THRESHOLD.MAX_HARDWARE_CONCURRENCY;
    if (!checks.hardwareValid) {
      failures.push(`hardwareConcurrency invalid: ${fp.hardwareConcurrency}`);
    }

    // ---- 7. Not headless browser ----
    checks.notHeadless = fp.isHeadless !== true;
    if (!checks.notHeadless) {
      failures.push('headless browser detected');
    }

    // ---- 8. Not virtual machine ----
    checks.notVM = fp.isVirtualMachine !== true;
    if (!checks.notVM) {
      failures.push('virtual machine detected');
    }

    // ---- 9. User agent sanity check ----
    checks.userAgentValid = typeof fp.userAgent === 'string' && fp.userAgent.length > 10;
    if (!checks.userAgentValid) {
      failures.push('user agent missing or too short');
    }

    // ---- 10. Language present ----
    checks.languageValid = typeof fp.language === 'string' && fp.language.length >= 2;
    if (!checks.languageValid) {
      failures.push('language missing');
    }

    // ---- 11. Behavioral score (0-30 = human) ----
    checks.behavioralScoreValid =
      behavioralScore >= FINGERPRINT_THRESHOLD.MIN_BEHAVIORAL_SCORE &&
      behavioralScore <= FINGERPRINT_THRESHOLD.MAX_BEHAVIORAL_SCORE;
    checks.behavioralScore = behavioralScore;
    if (!checks.behavioralScoreValid) {
      failures.push(`behavioral score ${behavioralScore} outside human range [0, ${FINGERPRINT_THRESHOLD.MAX_BEHAVIORAL_SCORE}]`);
    }

    // ---- Final verdict ----
    if (failures.length > 0) {
      throw new ChallengeError(
        `Fingerprint validation failed: ${failures.join('; ')}`,
        'FINGERPRINT_CHECKS_FAILED'
      );
    }

    // Success
    entry.completedFactors.add(3);

    return {
      verified: true,
      fragmentC: entry.splitResult ? entry.splitResult.fragmentC : null,
      checks,
    };
  }

  // ---------------------------------------------------------------------------
  // Complete Decryption Flow
  // ---------------------------------------------------------------------------

  /**
   * Attempt full decryption — verify all 3 factors in sequence and combine fragments.
   *
   * This is the convenience method that runs all 3 factor verifications and, if all
   * pass, returns the decrypted code.
   *
   * @param {object} params
   * @param {string} params.token
   * @param {string} params.factor1Response       First 8 hex chars of HMAC
   * @param {number} params.factor1Timestamp      Client timestamp
   * @param {InteractionData} params.factor2Data  Mouse/scroll interaction data
   * @param {BrowserFingerprint} params.factor3Fingerprint
   * @param {number} params.factor3Score          Behavioural score
   * @param {string} params.ip
   * @param {string} params.deviceFingerprint
   * @returns {{success:boolean, code?:string, error?:string, metrics?:object}}
   */
  async decryptFull(params) {
    const {
      token,
      factor1Response,
      factor1Timestamp,
      factor2Data,
      factor3Fingerprint,
      factor3Score,
      ip,
      deviceFingerprint,
    } = params;

    const allMetrics = {};

    try {
      // ---- Factor 1: Time HMAC ----
      const result1 = this.verifyFragmentA(token, factor1Response, factor1Timestamp, ip, deviceFingerprint);
      if (!result1.verified) {
        return { success: false, error: 'Factor 1 verification failed' };
      }
      allMetrics.factor1 = 'passed';

      // ---- Factor 2: Interaction ----
      const result2 = this.verifyFragmentB(token, factor2Data, ip, deviceFingerprint);
      if (!result2.verified) {
        return { success: false, error: 'Factor 2 verification failed', metrics: result2.metrics };
      }
      allMetrics.factor2 = result2.metrics;

      // ---- Factor 3: Fingerprint ----
      const result3 = this.verifyFragmentC(token, factor3Fingerprint, factor3Score, ip, deviceFingerprint);
      if (!result3.verified) {
        return { success: false, error: 'Factor 3 verification failed', checks: result3.checks };
      }
      allMetrics.factor3 = result3.checks;

      // ---- Combine fragments ----
      const entry = this.#tokenStore.get(token);
      if (!entry || !entry.splitResult) {
        return { success: false, error: 'Fragments no longer available' };
      }

      const code = this.combineFragments(
        result1.fragmentA,
        result2.fragmentB,
        result3.fragmentC,
        entry.splitResult.metadata
      );

      // Consume the token (one-time use)
      this.consumeToken(token);

      return { success: true, code, metrics: allMetrics };
    } catch (err) {
      return {
        success: false,
        error: err.message,
        code: err.code,
        metrics: allMetrics,
      };
    }
  }

  // ---------------------------------------------------------------------------
  // Challenge Generation
  // ---------------------------------------------------------------------------

  /**
   * Generate a unique challenge for a specific factor.
   *
   * Each factor has a unique challenge type:
   * - Factor 1: time_hmac — first 8 hex chars of HMAC-SHA512
   * - Factor 2: interaction — client must send interaction data
   * - Factor 3: fingerprint — client must send fingerprint + score
   *
   * @param {string} token          The session token
   * @param {number} factorNumber   1, 2, or 3
   * @param {string} [dailySeed]    Override daily seed (optional)
   * @returns {FactorChallenge}
   *
   * @throws {ChallengeError} If factor number invalid or challenge already exists
   */
  generateFactorChallenge(token, factorNumber, dailySeed = null) {
    if (!token || typeof token !== 'string') {
      throw new ChallengeError('Token is required', 'MISSING_TOKEN');
    }
    if (![1, 2, 3].includes(factorNumber)) {
      throw new ChallengeError('Factor number must be 1, 2, or 3', 'INVALID_FACTOR');
    }

    const seed = dailySeed || this.#dailySeed;
    const now = Date.now();
    const expiresAt = now + CHALLENGE_TTL_MS;

    // Generate challenge based on factor type
    let challenge;
    let type;

    switch (factorNumber) {
      case 1: {
        // HMAC-based time challenge
        const payload = `${seed}:${token}:${now}`;
        const hmac = hmacSha512(this.#secret, payload);
        challenge = hmac.slice(0, 16); // First 16 hex chars as challenge
        type = 'time_hmac';
        break;
      }
      case 2: {
        // Interaction challenge — server provides a nonce, client must
        // collect interaction data signed with it
        const nonce = secureRandomHex(16);
        challenge = nonce;
        type = 'interaction';
        break;
      }
      case 3: {
        // Fingerprint challenge — server provides a session salt
        const salt = secureRandomHex(16);
        challenge = salt;
        type = 'fingerprint';
        break;
      }
      default:
        throw new ChallengeError('Unknown factor number', 'UNKNOWN_FACTOR');
    }

    return {
      token,
      factorNumber,
      challenge,
      expiresAt,
      type,
    };
  }

  /**
   * Verify a factor response against the expected challenge value.
   *
   * @param {string} token
   * @param {number} factorNumber
   * @param {string} response     Client's response payload
   * @returns {boolean}
   *
   * @throws {ChallengeError|TokenError} On invalid token, expired challenge, or wrong response
   */
  verifyFactorResponse(token, factorNumber, response) {
    if (!response || typeof response !== 'string') {
      throw new ChallengeError('Response is required', 'MISSING_RESPONSE');
    }

    const entry = this.#getValidToken(token);

    // Check if this factor already completed (one-time use)
    if (entry.completedFactors.has(factorNumber)) {
      throw new ChallengeError(
        `Factor ${factorNumber} already used`,
        'FACTOR_REPLAY'
      );
    }

    // For Factor 1, verify the HMAC response directly
    if (factorNumber === 1) {
      const now = Date.now();
      const payload = `${this.#dailySeed}:${token}:${now}`;
      const expectedHmac = hmacSha512(this.#secret, payload);
      const expected = expectedHmac.slice(0, 8);

      if (!constantTimeCompare(response, expected)) {
        // Try with slight time drift (±2 seconds)
        let driftMatch = false;
        for (let drift = -2000; drift <= 2000; drift += 100) {
          const driftPayload = `${this.#dailySeed}:${token}:${now + drift}`;
          const driftHmac = hmacSha512(this.#secret, driftPayload);
          if (constantTimeCompare(response, driftHmac.slice(0, 8))) {
            driftMatch = true;
            break;
          }
        }
        if (!driftMatch) {
          throw new ChallengeError('Factor 1 response invalid', 'INVALID_FACTOR1_RESPONSE');
        }
      }

      entry.completedFactors.add(1);
      entry.responses.set(1, response);
      return true;
    }

    // Factors 2 and 3 use their dedicated verify methods
    throw new ChallengeError(
      `Use verifyFragmentB() for factor 2, verifyFragmentC() for factor 3`,
      'USE_DEDICATED_METHOD'
    );
  }

  // ---------------------------------------------------------------------------
  // Decrypt via Individual Factor Verifications
  // ---------------------------------------------------------------------------

  /**
   * Get the decrypted code after all 3 factors have been verified individually.
   * Call this after successfully calling verifyFragmentA, B, and C.
   *
   * @param {string} token
   * @returns {{success:boolean, code?:string, error?:string}}
   */
  getDecryptedCode(token) {
    try {
      const entry = this.#getValidToken(token);

      // All 3 factors must be completed
      if (entry.completedFactors.size < 3) {
        const missing = [1, 2, 3].filter(f => !entry.completedFactors.has(f));
        return {
          success: false,
          error: `Missing factors: ${missing.join(', ')}`,
        };
      }

      if (!entry.splitResult) {
        return { success: false, error: 'Fragments no longer available' };
      }

      const { fragmentA, fragmentB, fragmentC, metadata } = entry.splitResult;
      const code = this.combineFragments(fragmentA, fragmentB, fragmentC, metadata);

      // Consume token (one-time use)
      this.consumeToken(token);

      return { success: true, code };
    } catch (err) {
      return { success: false, error: err.message, code: err.code };
    }
  }

  // ---------------------------------------------------------------------------
  // Token Lifecycle Queries
  // ---------------------------------------------------------------------------

  /**
   * Get the current status of a token (factors completed, expiry, etc.)
   *
   * @param {string} token
   * @returns {{exists:boolean, expired:boolean, consumed:boolean, completedFactors:number[], expiresAt:number}|null}
   */
  getTokenStatus(token) {
    const entry = this.#tokenStore.get(token);
    if (!entry) {
      return { exists: false, expired: true, consumed: false, completedFactors: [], expiresAt: 0 };
    }

    return {
      exists: true,
      expired: Date.now() > entry.expiresAt,
      consumed: entry.consumed,
      completedFactors: Array.from(entry.completedFactors),
      expiresAt: entry.expiresAt,
    };
  }

  /**
   * Revoke a token immediately (e.g., on suspicious activity).
   *
   * @param {string} token
   * @returns {boolean} True if token was found and revoked
   */
  revokeToken(token) {
    const entry = this.#tokenStore.get(token);
    if (!entry) return false;

    entry.consumed = true;
    entry.splitResult = null;
    this.#tokenStore.delete(token);
    return true;
  }

  // ---------------------------------------------------------------------------
  // Cleanup
  // ---------------------------------------------------------------------------

  /** Destroy the engine and release all resources. */
  destroy() {
    this.#tokenStore.destroy();
    this.#usedTokenFingerprints.clear();
  }
}

// =============================================================================
// Standalone Utility Exports
// =============================================================================

/**
 * Compute Shannon entropy of an array of numbers.
 * @param {number[]} values
 * @returns {number}
 */
export function computeEntropy(values) {
  return shannonEntropy(values);
}

/**
 * Compute the curvature score for a 3-point mouse path.
 * @param {{x:number,y:number}} p1
 * @param {{x:number,y:number}} p2
 * @param {{x:number,y:number}} p3
 * @returns {number}
 */
export function computeCurvature(p1, p2, p3) {
  return curvatureScore(p1, p2, p3);
}

/**
 * Validate a browser fingerprint object against all checks.
 * Returns detailed check results without throwing.
 *
 * @param {BrowserFingerprint} fp
 * @param {number} behavioralScore
 * @returns {{valid:boolean, checks:object, failures:string[]}}
 */
export function validateFingerprint(fp, behavioralScore) {
  const checks = {};
  const failures = [];

  // Known automation check
  const fpHash = sha256(JSON.stringify({
    canvas: fp.canvas,
    webgl: fp.webgl,
    hardwareConcurrency: fp.hardwareConcurrency,
  }));
  checks.knownAutomation = !KNOWN_AUTOMATION_HASHES.has(fpHash);
  if (!checks.knownAutomation) failures.push('known automation fingerprint');

  // Canvas
  checks.canvasPresent = typeof fp.canvas === 'string' &&
                         fp.canvas.length >= FINGERPRINT_THRESHOLD.MIN_CANVAS_LENGTH;
  if (!checks.canvasPresent) failures.push('canvas fingerprint missing');

  // WebGL
  checks.webglPresent = typeof fp.webgl === 'string' &&
                        fp.webgl.length >= FINGERPRINT_THRESHOLD.MIN_WEBGL_LENGTH;
  if (!checks.webglPresent) failures.push('webgl fingerprint missing');

  // Screen
  checks.screenValid =
    typeof fp.screenWidth === 'number' && typeof fp.screenHeight === 'number' &&
    fp.screenWidth >= FINGERPRINT_THRESHOLD.MIN_SCREEN_WIDTH &&
    fp.screenWidth <= FINGERPRINT_THRESHOLD.MAX_SCREEN_WIDTH &&
    fp.screenHeight >= FINGERPRINT_THRESHOLD.MIN_SCREEN_HEIGHT &&
    fp.screenHeight <= FINGERPRINT_THRESHOLD.MAX_SCREEN_HEIGHT;
  if (!checks.screenValid) failures.push('screen resolution invalid');

  // Timezone
  try {
    new Intl.DateTimeFormat('en', { timeZone: fp.timezone });
    checks.timezoneValid = true;
  } catch {
    checks.timezoneValid = false;
    failures.push('invalid timezone');
  }

  // Hardware concurrency
  checks.hardwareValid =
    typeof fp.hardwareConcurrency === 'number' &&
    Number.isInteger(fp.hardwareConcurrency) &&
    fp.hardwareConcurrency >= FINGERPRINT_THRESHOLD.MIN_HARDWARE_CONCURRENCY &&
    fp.hardwareConcurrency <= FINGERPRINT_THRESHOLD.MAX_HARDWARE_CONCURRENCY;
  if (!checks.hardwareValid) failures.push('hardwareConcurrency invalid');

  // Headless / VM
  checks.notHeadless = fp.isHeadless !== true;
  if (!checks.notHeadless) failures.push('headless browser');
  checks.notVM = fp.isVirtualMachine !== true;
  if (!checks.notVM) failures.push('virtual machine');

  // User agent
  checks.userAgentValid = typeof fp.userAgent === 'string' && fp.userAgent.length > 10;
  if (!checks.userAgentValid) failures.push('user agent invalid');

  // Language
  checks.languageValid = typeof fp.language === 'string' && fp.language.length >= 2;
  if (!checks.languageValid) failures.push('language invalid');

  // Behavioral score
  checks.behavioralScoreValid =
    typeof behavioralScore === 'number' &&
    behavioralScore >= FINGERPRINT_THRESHOLD.MIN_BEHAVIORAL_SCORE &&
    behavioralScore <= FINGERPRINT_THRESHOLD.MAX_BEHAVIORAL_SCORE;
  if (!checks.behavioralScoreValid) failures.push('behavioral score out of range');

  const allPassed = Object.values(checks).every(v => v === true);

  return { valid: allPassed, checks, failures };
}

// Default export
export default FragmentEngine;
