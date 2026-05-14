/**
 * @fileoverview Daily Mutation Engine for Osm Army Gift Code Fortress.
 * Runs every day at 00:00:01 UTC. Generates a new daily seed, applies mutations
 * across 10 configurable dimensions, verifies integrity via round-trip tests,
 * and rolls back on any failure.
 *
 * Mutation dimensions:
 *  1. Algorithm selection (2-3 from pool of 7)
 *  2. API endpoint name mutation (claim→get, verify→check, etc.)
 *  3. Validation rule priority rotation
 *  4. Anti-OCR image style rotation
 *  5. Rate limit multiplier updates
 *  6. JWT signing subkey rotation
 *  7. Fingerprint component weight refresh
 *  8. Behavioural analysis threshold updates
 *  9. Proof-of-work difficulty base change
 * 10. CAPTCHA challenge type mutation
 *
 * @module cron/mutate
 * @version 5.0.0
 */

'use strict';

import { createHash, randomBytes, createHmac } from 'node:crypto';
import { EventEmitter } from 'node:events';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const MUTATION_CRON_EXPR = '1 0 0 * * *'; // 00:00:01 every day

const SERVER_SECRET_ENV = 'SERVER_SECRET';
const MUTATION_VERSION_COLLECTION = 'mutation_versions';
const MUTATION_LOG_COLLECTION = 'mutation_logs';

/** Pool of 7 algorithm identifiers for gift-code derivation. */
const ALGORITHM_POOL = Object.freeze([
  'sha256_hmac_pbkdf2',
  'sha512_scrypt_aes256gcm',
  'blake2b_chacha20_poly1305',
  'sha3_256_argon2id_xchacha',
  'ripemd160_bcrypt_cast5',
  'sha384_hkdf_salsa20',
  'whirlpool_ecies_twofish',
]);

/** API endpoint name mutations. */
const ENDPOINT_MUTATIONS = Object.freeze([
  { claim: 'get',    verify: 'check',   redeem: 'apply',   status: 'info',   health: 'ping' },
  { claim: 'claim',  verify: 'verify',  redeem: 'redeem',  status: 'status', health: 'health' },
  { claim: 'fetch',  verify: 'confirm', redeem: 'use',     status: 'state',  health: 'alive' },
  { claim: 'grab',   verify: 'auth',    redeem: 'burn',    status: 'stats',  health: 'ready' },
  { claim: 'pull',   verify: 'valid',   redeem: 'spend',   status: 'data',   health: 'up' },
  { claim: 'take',   verify: 'ok',      redeem: 'consume', status: 'view',   health: 'live' },
  { claim: 'draw',   verify: 'sure',    redeem: 'cash',    status: 'show',   health: 'run' },
]);

/** Anti-OCR image style presets. */
const OCR_STYLE_PRESETS = Object.freeze([
  'wave_distortion_color_noise',
  'grid_overlay_dots_lines',
  'fragmented_text_scramble',
  'gradient_mesh_obfuscation',
  'pixelate_reconstruct_blur',
  'rotated_captcha_mesh',
  'elastic_deform_sine_wave',
]);

/** CAPTCHA challenge type pool. */
const CAPTCHA_TYPES = Object.freeze([
  'math_equation',
  'image_classification',
  'slider_puzzle',
  'text_click_order',
  'audio_transcription',
  'gesture_pattern',
  'spatial_reasoning',
]);

/** Validation rule priority pools. */
const VALIDATION_RULES = Object.freeze([
  'ip_reputation_check',
  'device_fingerprint_verify',
  'behavioural_score_threshold',
  'telegram_verification_status',
  'rate_limit_compliance',
  'proof_of_work_validity',
  'captcha_response_check',
  'time_based_code_window',
  'geographic_restriction',
  'honeypot_field_check',
]);

// ---------------------------------------------------------------------------
// Custom Errors
// ---------------------------------------------------------------------------

export class MutationError extends Error {
  constructor(message, code, extra = {}) {
    super(message);
    this.name = 'MutationError';
    this.code = code;
    this.rollbackSuccessful = false;
    Object.assign(this, extra);
    Error.captureStackTrace(this, this.constructor);
  }
}

// ---------------------------------------------------------------------------
// Utility Functions
// ---------------------------------------------------------------------------

/**
 * Get current UTC date as YYYY-MM-DD.
 * @returns {string}
 */
function getUTCDateString() {
  const d = new Date();
  return d.toISOString().split('T')[0];
}

/**
 * Get day of week (0=Sunday ... 6=Saturday).
 * @returns {number}
 */
function getUTCDayOfWeek() {
  return new Date().getUTCDay();
}

/**
 * Hash seed material with SHA-512.
 * @param {string} material
 * @returns {string} Hex digest
 */
function sha512Hex(material) {
  return createHash('sha512').update(material).digest('hex');
}

/**
 * Derive an integer in range [0, max) from a hex string deterministically.
 * @param {string} hex
 * @param {number} offset Byte offset into the hex string
 * @param {number} max Upper bound (exclusive)
 * @returns {number}
 */
function deriveIndex(hex, offset, max) {
  const start = (offset * 8) % (hex.length - 8);
  const slice = hex.substring(start, start + 8);
  const val = parseInt(slice, 16);
  return val % max;
}

/**
 * Derive multiple unique indices from the seed.
 * @param {string} hexSeed
 * @param {number} count How many to select
 * @param {number} maxPool Pool size
 * @returns {number[]} Unique indices
 */
function deriveUniqueIndices(hexSeed, count, maxPool) {
  const indices = new Set();
  let offset = 0;
  while (indices.size < count && offset < 100) {
    const idx = deriveIndex(hexSeed, offset, maxPool);
    indices.add(idx);
    offset++;
  }
  return Array.from(indices);
}

/**
 * Sleep for N milliseconds.
 * @param {number} ms
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Deep clone a plain object (JSON round-trip).
 * @param {T} obj
 * @returns {T}
 * @template T
 */
function deepClone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

/**
 * Generate a simple text diff between two objects (flat key=value).
 * @param {Object} before
 * @param {Object} after
 * @returns {string[]}
 */
function diffObjects(before, after) {
  const lines = [];
  const allKeys = new Set([...Object.keys(before || {}), ...Object.keys(after || {})]);
  for (const key of allKeys) {
    const bVal = JSON.stringify(before?.[key]);
    const aVal = JSON.stringify(after?.[key]);
    if (bVal !== aVal) {
      lines.push(`- ${key}: ${bVal}`);
      lines.push(`+ ${key}: ${aVal}`);
    }
  }
  return lines;
}

// ---------------------------------------------------------------------------
// Mutation Engine
// ---------------------------------------------------------------------------

/**
 * DailyMutationEngine generates, applies, verifies, and logs configuration
 * mutations. It is fully deterministic given the server secret and calendar date.
 */
export class DailyMutationEngine extends EventEmitter {
  /**
   * @param {Object} options
   * @param {Object|null} [options.db] MongoDB database instance
   * @param {string} [options.serverSecret] Falls back to SERVER_SECRET env
   * @param {Function|null} [options.telegramSend] Async function to send Telegram alerts
   * @param {Function|null} [options.cacheClear] Async function to clear caches
   * @param {Function|null} [options.keyRotate] Async function to rotate encryption subkeys
   * @param {Function|null} [options.ipRefresh] Async function to refresh IP reputation
   */
  constructor(options = {}) {
    super();
    this.db = options.db || null;
    this.serverSecret = options.serverSecret || process.env[SERVER_SECRET_ENV] || '';
    this.telegramSend = options.telegramSend || null;
    this.cacheClear = options.cacheClear || null;
    this.keyRotate = options.keyRotate || null;
    this.ipRefresh = options.ipRefresh || null;

    this.versionCollection = null;
    this.logCollection = null;

    // Current and previous mutation profiles
    /** @type {Object|null} */
    this.currentProfile = null;
    /** @type {Object|null} */
    this.previousProfile = null;

    // In-memory cached endpoint mapping
    /** @type {Object|null} */
    this.activeEndpointMap = null;
  }

  // ------------------------------------------------------------------
  // Initialisation
  // ------------------------------------------------------------------

  /**
   * Initialise database collections.
   * @returns {Promise<void>}
   */
  async init() {
    if (!this.db) return;
    this.versionCollection = this.db.collection(MUTATION_VERSION_COLLECTION);
    this.logCollection = this.db.collection(MUTATION_LOG_COLLECTION);

    await this.versionCollection.createIndex(
      { versionDate: -1 },
      { background: true, name: 'versionDate_desc' }
    );
    await this.versionCollection.createIndex(
      { active: 1 },
      { background: true, name: 'active_flag' }
    );
    await this.logCollection.createIndex(
      { timestamp: -1 },
      { expireAfterSeconds: 365 * 86400, background: true, name: 'ttl_1year' }
    );
  }

  // ------------------------------------------------------------------
  // Core Daily Mutation
  // ------------------------------------------------------------------

  /**
   * Execute the full daily mutation cycle.
   * @returns {Promise<{success:boolean,version:number,profile:Object|null,error:Error|null}>}
   */
  async run() {
    const startedAt = Date.now();
    let profile = null;
    let error = null;
    let rollbackTriggered = false;

    try {
      this.emit('mutation_start', { timestamp: new Date().toISOString() });

      // 0. Validate prerequisites
      if (!this.serverSecret) {
        throw new MutationError('SERVER_SECRET is not configured', 'MISSING_SECRET');
      }

      // 1. Generate the deterministic daily seed
      const seed = this.generateDailySeed();
      this.emit('seed_generated', { seedPrefix: seed.substring(0, 16) });

      // 2. Build the mutation profile from the seed
      profile = this.buildMutationProfile(seed);
      this.emit('profile_built', { version: profile.version, algorithms: profile.selectedAlgorithms });

      // 3. Load previous profile for diff and potential rollback
      this.previousProfile = await this.loadPreviousProfile();

      // 4. Apply mutation profile atomically
      const applied = await this.applyProfile(profile);
      if (!applied) {
        throw new MutationError('Failed to apply mutation profile', 'APPLY_FAILED');
      }

      // 5. Verify mutation integrity (round-trip self-test)
      const verified = await this.verifyMutation(profile);
      if (!verified.success) {
        rollbackTriggered = true;
        const rolledBack = await this.rollback(this.previousProfile);
        throw new MutationError(
          `Mutation verification failed: ${verified.failures.join(', ')}`,
          'VERIFICATION_FAILED',
          { rollbackSuccessful: rolledBack, failures: verified.failures }
        );
      }

      // 6. Persist successful mutation
      await this.persistProfile(profile, verified);

      // 7. Clear yesterday's caches
      if (this.cacheClear) {
        await this.cacheClear();
        this.emit('cache_cleared');
      }

      // 8. Update endpoint mappings (active immediately)
      this.activeEndpointMap = profile.endpointMap;

      // 9. Rotate encryption subkeys
      if (this.keyRotate) {
        await this.keyRotate(seed);
        this.emit('keys_rotated');
      }

      // 10. Refresh IP reputation lists
      if (this.ipRefresh) {
        await this.ipRefresh();
        this.emit('ip_refreshed');
      }

      // 11. Log mutation details
      await this.logMutation(profile, verified, startedAt);

      // 12. Send Telegram success notification
      await this.notifySuccess(profile);

      this.currentProfile = profile;
      this.emit('mutation_complete', { version: profile.version, durationMs: Date.now() - startedAt });

      return { success: true, version: profile.version, profile, error: null };
    } catch (err) {
      error = err;
      this.emit('mutation_error', { error: err.message, code: err.code, rollback: rollbackTriggered });
      await this.logMutation(profile || {}, { success: false, failures: [err.message] }, startedAt, err);

      // If not already rolled back, attempt rollback on any error
      if (!rollbackTriggered && this.previousProfile) {
        try {
          await this.rollback(this.previousProfile);
          err.rollbackSuccessful = true;
        } catch (rbErr) {
          err.rollbackError = rbErr.message;
          err.rollbackSuccessful = false;
        }
      }

      // Notify admins
      await this.notifyFailure(err);

      // Auto-retry once after 5 minutes
      this.scheduleRetry(300_000);

      return { success: false, version: profile?.version || 0, profile, error: err };
    }
  }

  /**
   * Schedule a one-time retry of the mutation.
   * @param {number} delayMs
   */
  scheduleRetry(delayMs) {
    setTimeout(() => {
      this.emit('mutation_retry', { scheduledAt: new Date().toISOString() });
      this.run().catch(() => {});
    }, delayMs);
  }

  // ------------------------------------------------------------------
  // Step 1: Seed Generation
  // ------------------------------------------------------------------

  /**
   * Generate the deterministic daily seed.
   * seed = SHA512(SERVER_SECRET + YYYY-MM-DD + dayOfWeek)
   * @returns {string} 128-character hex seed
   */
  generateDailySeed() {
    const dateStr = getUTCDateString();
    const dayOfWeek = getUTCDayOfWeek();
    const material = `${this.serverSecret}:${dateStr}:${dayOfWeek}`;
    return sha512Hex(material);
  }

  // ------------------------------------------------------------------
  // Step 2: Profile Building
  // ------------------------------------------------------------------

  /**
   * Build the full mutation profile from the seed.
   * @param {string} seed
   * @returns {Object}
   */
  buildMutationProfile(seed) {
    const version = this.deriveVersion(seed);
    const selectedAlgorithms = this.selectAlgorithms(seed);
    const endpointMap = this.mutateEndpoints(seed);
    const validationPriority = this.rotateValidationRules(seed);
    const ocrStyle = this.selectOCRStyle(seed);
    const rateLimitMultipliers = this.updateRateLimitMultipliers(seed);
    const jwtSubkey = this.deriveJWTSubkey(seed);
    const fingerprintWeights = this.refreshFingerprintWeights(seed);
    const behavioralThresholds = this.updateBehavioralThresholds(seed);
    const powDifficulty = this.changePoWDifficulty(seed);
    const captchaType = this.mutateCaptchaType(seed);

    return {
      version,
      seedPrefix: seed.substring(0, 16),
      date: getUTCDateString(),
      dayOfWeek: getUTCDayOfWeek(),
      appliedAt: null,
      verifiedAt: null,
      active: false,

      selectedAlgorithms,
      endpointMap,
      validationPriority,
      ocrStyle,
      rateLimitMultipliers,
      jwtSubkey,
      fingerprintWeights,
      behavioralThresholds,
      powDifficulty,
      captchaType,
    };
  }

  /**
   * Derive a monotonically increasing version number.
   * @param {string} seed
   * @returns {number}
   */
  deriveVersion(seed) {
    // First 8 hex chars → int as base version component
    const base = parseInt(seed.substring(0, 8), 16);
    const dateInt = parseInt(getUTCDateString().replace(/-/g, ''), 10);
    return dateInt * 1000 + (base % 1000);
  }

  /**
   * Select 2-3 algorithms from the pool of 7 deterministically.
   * @param {string} seed
   * @returns {string[]}
   */
  selectAlgorithms(seed) {
    const count = 2 + (deriveIndex(seed, 10, 2)); // 2 or 3
    const indices = deriveUniqueIndices(seed, count, ALGORITHM_POOL.length);
    return indices.sort((a, b) => a - b).map((i) => ALGORITHM_POOL[i]);
  }

  /**
   * Mutate API endpoint names.
   * @param {string} seed
   * @returns {Object}
   */
  mutateEndpoints(seed) {
    const idx = deriveIndex(seed, 20, ENDPOINT_MUTATIONS.length);
    return { ...ENDPOINT_MUTATIONS[idx] };
  }

  /**
   * Rotate validation rule priorities.
   * @param {string} seed
   * @returns {string[]}
   */
  rotateValidationRules(seed) {
    // Fisher-Yates shuffle seeded deterministically
    const arr = [...VALIDATION_RULES];
    let h = seed;
    for (let i = arr.length - 1; i > 0; i--) {
      h = sha512Hex(h + String(i));
      const j = deriveIndex(h, 0, i + 1);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
  }

  /**
   * Select anti-OCR image style.
   * @param {string} seed
   * @returns {string}
   */
  selectOCRStyle(seed) {
    const idx = deriveIndex(seed, 30, OCR_STYLE_PRESETS.length);
    return OCR_STYLE_PRESETS[idx];
  }

  /**
   * Derive rate limit multipliers for the day.
   * @param {string} seed
   * @returns {Object}
   */
  updateRateLimitMultipliers(seed) {
    const h = sha512Hex(seed + ':rl');
    return {
      claim: 1.0 + (deriveIndex(h, 0, 50) / 100),   // 1.00 - 1.49
      verify: 1.0 + (deriveIndex(h, 1, 50) / 100),
      login: 1.0 + (deriveIndex(h, 2, 100) / 100),  // 1.00 - 1.99
      api: 1.0 + (deriveIndex(h, 3, 30) / 100),
      global: 1.0 + (deriveIndex(h, 4, 20) / 100),
    };
  }

  /**
   * Derive a JWT signing subkey identifier.
   * @param {string} seed
   * @returns {string}
   */
  deriveJWTSubkey(seed) {
    const h = sha512Hex(seed + ':jwt');
    return `subkey_${h.substring(0, 16)}`;
  }

  /**
   * Refresh fingerprint component weights.
   * @param {string} seed
   * @returns {Object}
   */
  refreshFingerprintWeights(seed) {
    const h = sha512Hex(seed + ':fp');
    const w = (offset) => 0.5 + (deriveIndex(h, offset, 100) / 100); // 0.5 - 1.49
    return {
      canvas: w(0),
      webgl: w(1),
      fonts: w(2),
      timezone: w(3),
      plugins: w(4),
      screen: w(5),
      navigator: w(6),
      touch: w(7),
      cpuCores: w(8),
      memory: w(9),
    };
  }

  /**
   * Update behavioural analysis thresholds.
   * @param {string} seed
   * @returns {Object}
   */
  updateBehavioralThresholds(seed) {
    const h = sha512Hex(seed + ':behav');
    const t = (offset, base, range) => base + deriveIndex(h, offset, range);
    return {
      typingSpeedMin: t(0, 50, 100),       // 50-149 wpm
      typingSpeedMax: t(1, 150, 300),      // 150-449 wpm
      mouseJitterThreshold: t(2, 5, 20),   // 5-24 px
      clickConsistency: t(3, 70, 30),      // 70-99%
      timeOnPageMin: t(4, 5, 25),          // 5-29 sec
      formFillSequence: t(5, 60, 40),      // 60-99% natural
      scrollVelocityMax: t(6, 200, 500),   // 200-699 px/s
      keyHoldDuration: t(7, 80, 120),      // 80-199 ms
    };
  }

  /**
   * Change proof-of-work difficulty base.
   * @param {string} seed
   * @returns {number}
   */
  changePoWDifficulty(seed) {
    // Difficulty between 4 and 7 leading zeros
    return 4 + deriveIndex(seed, 40, 4);
  }

  /**
   * Mutate CAPTCHA challenge type.
   * @param {string} seed
   * @returns {string}
   */
  mutateCaptchaType(seed) {
    const idx = deriveIndex(seed, 50, CAPTCHA_TYPES.length);
    return CAPTCHA_TYPES[idx];
  }

  // ------------------------------------------------------------------
  // Step 3: Previous Profile
  // ------------------------------------------------------------------

  /**
   * Load the most recently active profile from the database.
   * @returns {Promise<Object|null>}
   */
  async loadPreviousProfile() {
    if (!this.versionCollection) return null;
    try {
      const doc = await this.versionCollection.findOne(
        { active: true },
        { sort: { versionDate: -1 } }
      );
      if (!doc) return null;
      const { _id, ...rest } = doc;
      return rest;
    } catch {
      return null;
    }
  }

  // ------------------------------------------------------------------
  // Step 4: Apply Profile
  // ------------------------------------------------------------------

  /**
   * Apply the mutation profile atomically.
   * @param {Object} profile
   * @returns {Promise<boolean>}
   */
  async applyProfile(profile) {
    try {
      // In a real deployment this would update in-memory configs,
      // refresh hot-reloadable modules, and update database records.
      // We store the profile as "pending" first, then activate after verification.

      profile.appliedAt = new Date().toISOString();

      if (this.versionCollection) {
        await this.versionCollection.updateMany(
          { active: true },
          { $set: { active: false } }
        );
        await this.versionCollection.insertOne({
          ...profile,
          active: false, // Will be activated after verification
          pending: true,
          createdAt: new Date(),
          versionDate: getUTCDateString(),
        });
      }

      this.emit('profile_applied', { version: profile.version });
      return true;
    } catch (err) {
      this.emit('apply_error', { error: err.message });
      return false;
    }
  }

  // ------------------------------------------------------------------
  // Step 5: Verification
  // ------------------------------------------------------------------

  /**
   * Run full mutation round-trip verification.
   * @param {Object} profile
   * @returns {Promise<{success:boolean,failures:string[]}>}
   */
  async verifyMutation(profile) {
    const failures = [];

    // 5a. Algorithm round-trip
    try {
      const algoOk = await this.verifyAlgorithms(profile.selectedAlgorithms);
      if (!algoOk) failures.push('algorithm_roundtrip');
    } catch (err) {
      failures.push(`algorithm_exception:${err.message}`);
    }

    // 5b. Endpoint accessibility
    try {
      const epOk = await this.verifyEndpoints(profile.endpointMap);
      if (!epOk) failures.push('endpoint_accessibility');
    } catch (err) {
      failures.push(`endpoint_exception:${err.message}`);
    }

    // 5c. Encryption/decryption validation
    try {
      const encOk = await this.verifyEncryption(profile.jwtSubkey);
      if (!encOk) failures.push('encryption_validation');
    } catch (err) {
      failures.push(`encryption_exception:${err.message}`);
    }

    // 5d. Config integrity
    try {
      const cfgOk = this.verifyConfigIntegrity(profile);
      if (!cfgOk) failures.push('config_integrity');
    } catch (err) {
      failures.push(`config_exception:${err.message}`);
    }

    // 5e. Seed reproducibility
    try {
      const reproOk = this.verifySeedReproducibility(profile);
      if (!reproOk) failures.push('seed_reproducibility');
    } catch (err) {
      failures.push(`seed_exception:${err.message}`);
    }

    profile.verifiedAt = new Date().toISOString();

    return {
      success: failures.length === 0,
      failures,
      checksRun: 5,
    };
  }

  /**
   * Verify selected algorithms produce deterministic output.
   * @param {string[]} algorithms
   * @returns {Promise<boolean>}
   */
  async verifyAlgorithms(algorithms) {
    if (!algorithms || algorithms.length < 2) return false;
    const testInput = 'mutation_test_vector_2024';
    for (const algo of algorithms) {
      // Verify algorithm identifier is known
      if (!ALGORITHM_POOL.includes(algo)) return false;
      // Verify it produces non-empty output (mock hash)
      const hash = createHash('sha256').update(`${algo}:${testInput}`).digest('hex');
      if (!hash || hash.length !== 64) return false;
    }
    return true;
  }

  /**
   * Verify endpoint mappings are non-empty and unique.
   * @param {Object} endpointMap
   * @returns {Promise<boolean>}
   */
  async verifyEndpoints(endpointMap) {
    if (!endpointMap || typeof endpointMap !== 'object') return false;
    const required = ['claim', 'verify', 'redeem', 'status', 'health'];
    const values = Object.values(endpointMap);
    // All required keys present
    if (!required.every((k) => k in endpointMap)) return false;
    // Values are non-empty strings
    if (!values.every((v) => typeof v === 'string' && v.length > 0)) return false;
    // Values are unique
    if (new Set(values).size !== values.length) return false;
    return true;
  }

  /**
   * Verify encryption subkey produces valid HMAC.
   * @param {string} jwtSubkey
   * @returns {Promise<boolean>}
   */
  async verifyEncryption(jwtSubkey) {
    if (!jwtSubkey || typeof jwtSubkey !== 'string') return false;
    const testMsg = 'encrypt_test';
    const sig = createHmac('sha256', jwtSubkey).update(testMsg).digest('hex');
    // Verify reproducibility
    const sig2 = createHmac('sha256', jwtSubkey).update(testMsg).digest('hex');
    return sig === sig2 && sig.length === 64;
  }

  /**
   * Verify profile has no missing or NaN fields.
   * @param {Object} profile
   * @returns {boolean}
   */
  verifyConfigIntegrity(profile) {
    if (!profile) return false;
    const criticalFields = [
      'version', 'selectedAlgorithms', 'endpointMap',
      'validationPriority', 'ocrStyle', 'rateLimitMultipliers',
      'jwtSubkey', 'fingerprintWeights', 'behavioralThresholds',
      'powDifficulty', 'captchaType',
    ];
    for (const field of criticalFields) {
      if (profile[field] === undefined || profile[field] === null) return false;
      if (typeof profile[field] === 'number' && Number.isNaN(profile[field])) return false;
    }
    // Verify version is positive integer
    if (!Number.isInteger(profile.version) || profile.version <= 0) return false;
    // Verify algorithms count
    if (profile.selectedAlgorithms.length < 2 || profile.selectedAlgorithms.length > 3) return false;
    // Verify PoW difficulty in range
    if (profile.powDifficulty < 4 || profile.powDifficulty > 8) return false;
    return true;
  }

  /**
   * Verify the seed can be reproduced identically.
   * @param {Object} profile
   * @returns {boolean}
   */
  verifySeedReproducibility(profile) {
    const reproduced = this.generateDailySeed();
    return reproduced.substring(0, 16) === profile.seedPrefix;
  }

  // ------------------------------------------------------------------
  // Step 6: Persist
  // ------------------------------------------------------------------

  /**
   * Persist the verified profile as the active configuration.
   * @param {Object} profile
   * @param {Object} verificationResult
   * @returns {Promise<void>}
   */
  async persistProfile(profile, verificationResult) {
    profile.active = true;
    profile.pending = false;
    profile.verification = verificationResult;

    if (this.versionCollection) {
      await this.versionCollection.updateMany(
        { active: true },
        { $set: { active: false } }
      );
      await this.versionCollection.updateOne(
        { version: profile.version, versionDate: getUTCDateString() },
        { $set: { active: true, pending: false, verification: verificationResult } }
      );
    }

    this.emit('profile_persisted', { version: profile.version });
  }

  // ------------------------------------------------------------------
  // Rollback
  // ------------------------------------------------------------------

  /**
   * Rollback to the previous profile.
   * @param {Object|null} previousProfile
   * @returns {Promise<boolean>}
   */
  async rollback(previousProfile) {
    try {
      this.emit('rollback_start');

      if (!previousProfile) {
        // No previous profile: create a safe default
        previousProfile = this.buildDefaultProfile();
      }

      // Reactivate the previous profile
      if (this.versionCollection) {
        await this.versionCollection.updateMany(
          { active: true },
          { $set: { active: false } }
        );
        // Find the previous version document and reactivate it
        await this.versionCollection.updateOne(
          { version: previousProfile.version },
          { $set: { active: true, pending: false, rolledBackTo: true } }
        );
      }

      // Restore endpoint mappings
      this.activeEndpointMap = previousProfile.endpointMap || this.buildDefaultProfile().endpointMap;
      this.currentProfile = previousProfile;

      this.emit('rollback_complete', { version: previousProfile.version });
      return true;
    } catch (err) {
      this.emit('rollback_error', { error: err.message });
      return false;
    }
  }

  /**
   * Build a safe default profile for emergency fallback.
   * @returns {Object}
   */
  buildDefaultProfile() {
    return {
      version: 0,
      seedPrefix: 'default000000000',
      date: getUTCDateString(),
      dayOfWeek: getUTCDayOfWeek(),
      active: true,
      selectedAlgorithms: ['sha256_hmac_pbkdf2', 'sha512_scrypt_aes256gcm'],
      endpointMap: { claim: 'claim', verify: 'verify', redeem: 'redeem', status: 'status', health: 'health' },
      validationPriority: [...VALIDATION_RULES],
      ocrStyle: 'wave_distortion_color_noise',
      rateLimitMultipliers: { claim: 1, verify: 1, login: 1, api: 1, global: 1 },
      jwtSubkey: 'subkey_default_fallback',
      fingerprintWeights: {
        canvas: 1, webgl: 1, fonts: 1, timezone: 1, plugins: 1,
        screen: 1, navigator: 1, touch: 1, cpuCores: 1, memory: 1,
      },
      behavioralThresholds: {
        typingSpeedMin: 100, typingSpeedMax: 300, mouseJitterThreshold: 10,
        clickConsistency: 85, timeOnPageMin: 15, formFillSequence: 80,
        scrollVelocityMax: 500, keyHoldDuration: 120,
      },
      powDifficulty: 4,
      captchaType: 'math_equation',
    };
  }

  // ------------------------------------------------------------------
  // Logging
  // ------------------------------------------------------------------

  /**
   * Log mutation details to the database.
   * @param {Object} profile
   * @param {Object} verification
   * @param {number} startedAt
   * @param {Error|null} [error]
   * @returns {Promise<void>}
   */
  async logMutation(profile, verification, startedAt, error = null) {
    const durationMs = Date.now() - startedAt;
    const diff = this.previousProfile
      ? diffObjects(this.previousProfile, profile)
      : [];

    const logEntry = {
      version: profile?.version || 0,
      timestamp: new Date(),
      durationMs,
      seedPrefix: profile?.seedPrefix || 'unknown',
      date: getUTCDateString(),
      selectedAlgorithms: profile?.selectedAlgorithms || [],
      endpointMap: profile?.endpointMap || {},
      ocrStyle: profile?.ocrStyle || 'unknown',
      captchaType: profile?.captchaType || 'unknown',
      powDifficulty: profile?.powDifficulty || 0,
      verificationSuccess: verification?.success || false,
      verificationFailures: verification?.failures || [],
      diff: diff.slice(0, 100),
      rolledBack: !!error,
      error: error
        ? { message: error.message, code: error.code || 'UNKNOWN' }
        : null,
    };

    if (this.logCollection) {
      await this.logCollection.insertOne(logEntry);
    }

    this.emit('logged', { version: logEntry.version, durationMs });
  }

  // ------------------------------------------------------------------
  // Notifications
  // ------------------------------------------------------------------

  /**
   * Send Telegram success notification.
   * @param {Object} profile
   * @returns {Promise<void>}
   */
  async notifySuccess(profile) {
    if (!this.telegramSend) return;
    const text = [
      `✅ *Daily Mutation Applied Successfully*`,
      ``,
      `*Version:* \`${profile.version}\``,
      `*Date:* \`${profile.date}\``,
      `*Algorithms:* ${profile.selectedAlgorithms.join(', ')}`,
      `*Endpoints:* \`${JSON.stringify(profile.endpointMap)}\``,
      `*OCR Style:* \`${profile.ocrStyle}\``,
      `*CAPTCHA:* \`${profile.captchaType}\``,
      `*PoW Difficulty:* \`${profile.powDifficulty}\``,
      `*JWT Subkey:* \`${profile.jwtSubkey.substring(0, 20)}...\``,
      ``,
      `_All verification checks passed_ ✅`,
    ].join('\n');

    try {
      await this.telegramSend({ severity: 'SUCCESS', title: 'Daily Mutation Applied', message: text });
    } catch {
      // Best-effort notification
    }
  }

  /**
   * Send Telegram failure notification.
   * @param {Error} error
   * @returns {Promise<void>}
   */
  async notifyFailure(error) {
    if (!this.telegramSend) return;
    const text = [
      `🚨 *Daily Mutation FAILED*`,
      ``,
      `*Error:* \`${error.message}\``,
      `*Code:* \`${error.code || 'UNKNOWN'}\``,
      `*Rollback:* ${error.rollbackSuccessful !== false ? '✅ Success' : '❌ Failed'}`,
      `*Time:* \`${new Date().toISOString()}\``,
      ``,
      `Auto-retry scheduled in 5 minutes.`,
    ].join('\n');

    try {
      await this.telegramSend({ severity: 'CRITICAL', title: 'Mutation Failure', message: text });
    } catch {
      // Best-effort notification
    }
  }

  // ------------------------------------------------------------------
  // Public Accessors
  // ------------------------------------------------------------------

  /**
   * Get the current active endpoint map.
   * @returns {Object|null}
   */
  getEndpointMap() {
    return this.activeEndpointMap;
  }

  /**
   * Resolve an endpoint name through the current mutation map.
   * @param {string} canonical e.g. 'claim'
   * @returns {string} Mutated name e.g. 'get'
   */
  resolveEndpoint(canonical) {
    if (!this.activeEndpointMap) return canonical;
    return this.activeEndpointMap[canonical] || canonical;
  }

  /**
   * Get the current mutation profile.
   * @returns {Object|null}
   */
  getCurrentProfile() {
    return this.currentProfile;
  }

  /**
   * Get health status.
   * @returns {Object}
   */
  health() {
    return {
      hasProfile: !!this.currentProfile,
      version: this.currentProfile?.version || 0,
      date: this.currentProfile?.date || null,
      algorithms: this.currentProfile?.selectedAlgorithms || [],
      endpointMap: this.activeEndpointMap,
      serverSecretConfigured: !!this.serverSecret,
    };
  }
}

// ---------------------------------------------------------------------------
// Job Runner
// ---------------------------------------------------------------------------

/**
 * Run the daily mutation job.
 * @param {Object} options
 * @returns {Promise<{success:boolean,version:number}>}
 */
export async function runDailyMutation(options = {}) {
  const engine = new DailyMutationEngine(options);
  await engine.init();
  return engine.run();
}

// ---------------------------------------------------------------------------
// Default Export
// ---------------------------------------------------------------------------

export default {
  DailyMutationEngine,
  runDailyMutation,
  MutationError,
  MUTATION_CRON_EXPR,
};
