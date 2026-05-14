/**
 * @fileoverview SuspiciousGuard — Progressive Security for Gift Code Delivery
 *
 * CRITICAL SECURITY RULES (enforced by design):
 *   1. Code / plaintext → NEVER accepted as parameters; NEVER returned.
 *   2. claimId / nonce / tokens → NEVER contain code values.
 *   3. decryptString() lives ONLY in codeReveal.js — this module never decrypts.
 *   4. All DB writes use MongoDB atomic operations ($setOnInsert, findOneAndUpdate).
 *   5. Cache headers: no-cache, no-store, must-revalidate, proxy-revalidate.
 *
 * Features:
 *   - Risk scoring (0-100) from multiple signals
 *   - Progressive challenges: none → PoW → Turnstile → block
 *   - Automatic block escalation (failCount × 5 min)
 *   - In-memory hot-path cache + persistent MongoDB storage
 */

import { createHash } from 'crypto';

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/** MongoDB collection names */
const COLL_RISK_SCORES        = 'risk_scores';
const COLL_IP_REPUTATION      = 'ip_reputation';
const COLL_REQUEST_LOG        = 'request_log';
const COLL_IP_DEVICE_MAPPINGS = 'ip_device_mappings';
const COLL_API_PROBE_LOG      = 'api_probe_log';
const COLL_TIMELOCK_HITS      = 'timelock_hits';
const COLL_DEVICE_BINDINGS    = 'device_bindings';

/** Challenge types returned by getRequiredChallenge() */
export const ChallengeType = Object.freeze({
  NONE:      'none',      // riskScore < 30  — normal flow
  POW:       'pow',       // riskScore 30-60 — progressive Proof-of-Work
  TURNSTILE: 'turnstile', // riskScore 60-85 — Cloudflare Turnstile
  BLOCK:     'block',     // riskScore > 85  — temporary block
});

/** Progressive punishment: base block duration per failure (ms) */
const BASE_BLOCK_MS          = 5 * 60 * 1000;   // 5 minutes
const MAX_BLOCK_MS           = 24 * 60 * 60 * 1000; // 24 hours hard cap
const HARD_BLOCK_DURATION_MS = 60 * 60 * 1000;  // 1 hour for score > 85

/** Risk scoring weights (must sum to <= 100) */
const WEIGHT_FAIL_COUNT = 35;  // failed attempts history
const WEIGHT_VELOCITY   = 25;  // request speed pattern
const WEIGHT_IP_REP     = 20;  // IP reputation score
const WEIGHT_BEHAVIOR   = 15;  // behavioral anomaly score
const WEIGHT_DEVICE_REP = 5;   // device reputation

/** Velocity thresholds (requests per sliding window) */
const VELOCITY_WINDOW_MS = 60 * 1000; // 1 minute
const VELOCITY_WARN_RPM  = 10;        // requests per minute → warn
const VELOCITY_BLOCK_RPM = 30;        // requests per minute → critical

/** PoW difficulty tiers */
const POW_DIFFICULTY = Object.freeze({
  LOW:    4, // 4 leading zero bits
  MEDIUM: 6,
  HIGH:   8,
});

/** In-memory hot-path cache (avoids DB round-trip for isBlocked) */
const blockCache   = new Map(); // key → { blockedUntil, failCount }
const CACHE_TTL_MS = 30_000;    // 30s cache freshness

// ─────────────────────────────────────────────────────────────────────────────
// MongoDB handle — injected at module init (see initSuspiciousGuard)
// ─────────────────────────────────────────────────────────────────────────────

let _db = null;

/** @param {Db} db — connected MongoDB Db instance */
export function initSuspiciousGuard(db) {
  _db = db;
  // Ensure indexes exist (idempotent)
  _db.collection(COLL_RISK_SCORES).createIndex(
    { telegramId: 1 }, { unique: true, sparse: true }
  );
  _db.collection(COLL_RISK_SCORES).createIndex(
    { deviceId: 1 }, { unique: true, sparse: true }
  );
  _db.collection(COLL_RISK_SCORES).createIndex({ blockedUntil: 1 }, { expireAfterSeconds: 0 });
  _db.collection(COLL_IP_REPUTATION).createIndex({ ipHash: 1 }, { unique: true });
  _db.collection(COLL_REQUEST_LOG).createIndex({ createdAt: 1 }, { expireAfterSeconds: 86400 });

  // ── Category 5: Multi-Telegram detection ──
  _db.collection(COLL_IP_DEVICE_MAPPINGS).createIndex(
    { ipHash: 1, deviceId: 1 }, { unique: true }
  );
  _db.collection(COLL_IP_DEVICE_MAPPINGS).createIndex(
    { ipHash: 1 }, { sparse: true }
  );
  _db.collection(COLL_IP_DEVICE_MAPPINGS).createIndex(
    { deviceId: 1 }, { sparse: true }
  );
  _db.collection(COLL_IP_DEVICE_MAPPINGS).createIndex(
    { createdAt: 1 }, { expireAfterSeconds: 86400 * 30 } // 30 day TTL
  );

  // ── Category 5: API probe tracking ──
  _db.collection(COLL_API_PROBE_LOG).createIndex(
    { ipHash: 1, createdAt: 1 }
  );
  _db.collection(COLL_API_PROBE_LOG).createIndex(
    { createdAt: 1 }, { expireAfterSeconds: 86400 * 7 } // 7 day TTL
  );

  // ── Category 5: Timelock hit tracking ──
  _db.collection(COLL_TIMELOCK_HITS).createIndex(
    { telegramId: 1, createdAt: 1 }
  );
  _db.collection(COLL_TIMELOCK_HITS).createIndex(
    { createdAt: 1 }, { expireAfterSeconds: 86400 } // 1 day TTL
  );

  // ── Category 5: Device bindings ──
  _db.collection(COLL_DEVICE_BINDINGS).createIndex(
    { telegramId: 1 }, { unique: true }
  );
  _db.collection(COLL_DEVICE_BINDINGS).createIndex(
    { deviceFingerprint: 1 }, { sparse: true }
  );
}

function getColl(name) {
  if (!_db) throw new Error('SuspiciousGuard not initialized — call initSuspiciousGuard(db) first');
  return _db.collection(name);
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/** Deterministic hash for IDs — used for cache keys and IP hashing. */
function quickHash(val) {
  if (!val) return 'null';
  return createHash('sha256').update(String(val)).digest('hex').slice(0, 16);
}

/** Build a composite cache key from telegramId + deviceId. */
function cacheKey(telegramId, deviceId) {
  return `${quickHash(telegramId || '0')}:${quickHash(deviceId || '0')}`;
}

/** Clamp a number between min and max. */
function clamp(num, min, max) {
  return Math.min(max, Math.max(min, num));
}

/**
 * Calculate velocity score from recent request log.
 * Returns 0-100 based on requests-per-minute in the sliding window.
 */
async function calculateVelocityScore(telegramId, deviceId) {
  try {
    const windowStart = new Date(Date.now() - VELOCITY_WINDOW_MS);
    const query = {
      $or: [
        { telegramIdHash: quickHash(telegramId) },
        { deviceIdHash: quickHash(deviceId) },
      ],
      createdAt: { $gte: windowStart },
    };

    const recentCount = await getColl(COLL_REQUEST_LOG).countDocuments(query);

    if (recentCount >= VELOCITY_BLOCK_RPM) return 100;
    if (recentCount >= VELOCITY_WARN_RPM) {
      return clamp(
        ((recentCount - VELOCITY_WARN_RPM) / (VELOCITY_BLOCK_RPM - VELOCITY_WARN_RPM)) * 100,
        0,
        100
      );
    }
    return 0;
  } catch {
    // Fail-open: if DB is down, assume medium risk
    return 50;
  }
}

/**
 * Fetch IP reputation score from DB.
 * Returns 0-100 (0 = clean, 100 = known malicious).
 */
async function getIpReputation(ipHash) {
  try {
    const doc = await getColl(COLL_IP_REPUTATION).findOne(
      { ipHash },
      { projection: { score: 1, _id: 0 } }
    );
    return doc?.score ?? 0;
  } catch {
    return 50; // fail-open medium risk
  }
}

/**
 * Log a request event for velocity tracking.
 * Uses atomic insert — collection has TTL index for auto-cleanup.
 */
async function recordRequestEvent(telegramId, deviceId, ipHash, action) {
  try {
    await getColl(COLL_REQUEST_LOG).insertOne({
      telegramIdHash: quickHash(telegramId),
      deviceIdHash:   quickHash(deviceId),
      ipHash,
      action,         // 'CLAIM_ATTEMPT' | 'CLAIM_SUCCESS' | 'CLAIM_FAILURE'
      createdAt:      new Date(),
    });
  } catch {
    // Non-critical: velocity calculation degrades gracefully
  }
}

/** Update the in-memory block cache after DB mutation. */
function updateBlockCache(telegramId, deviceId, blockedUntil, failCount) {
  const key = cacheKey(telegramId, deviceId);
  blockCache.set(key, { blockedUntil, failCount, cachedAt: Date.now() });
}

/** Read from in-memory block cache if fresh. */
function readBlockCache(telegramId, deviceId) {
  const key = cacheKey(telegramId, deviceId);
  const entry = blockCache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.cachedAt > CACHE_TTL_MS) {
    blockCache.delete(key);
    return null;
  }
  return entry;
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Calculate a composite risk score (0-100) for the identity tuple.
 *
 * Signals:
 *   - Failed attempt count (persistent in DB)
 *   - Request velocity (sliding window)
 *   - IP reputation (cross-user intelligence)
 *   - Behavioral anomalies (timing, sequence)
 *   - Device reputation
 *
 * @param {string} sessionToken   — opaque session token (hashed internally)
 * @param {string} telegramId     — user's Telegram ID
 * @param {string} deviceId       — device fingerprint / ID
 * @param {string} [ipHash]       — pre-hashed IP (optional)
 * @returns {Promise<number>}     — risk score 0-100
 *
 * SECURITY: NO code values are ever accepted or returned.
 */
export async function checkSuspiciousScore(sessionToken, telegramId, deviceId, ipHash = null) {
  const scores = {
    failScore:     0,
    velocityScore: 0,
    ipScore:       0,
    behaviorScore: 0,
    deviceScore:   0,
  };

  // ── 1. Fail count from DB ──
  try {
    const riskDoc = await getColl(COLL_RISK_SCORES).findOne({
      $or: [
        { telegramId: String(telegramId || '') },
        { deviceId: String(deviceId || '') },
      ],
    }, {
      projection: {
        failCount:    1,
        score:        1,
        blockedUntil: 1,
        lastFailAt:   1,
        behaviorScore:1,
        deviceScore:  1,
      },
    });

    if (riskDoc) {
      // Normalize failCount (cap at 20 for scoring)
      scores.failScore = clamp((riskDoc.failCount || 0) / 20 * 100, 0, 100);
      scores.behaviorScore = riskDoc.behaviorScore || 0;
      scores.deviceScore = riskDoc.deviceScore || 0;
    }
  } catch {
    scores.failScore = 50; // fail-open
  }

  // ── 2. Velocity (request rate) ──
  scores.velocityScore = await calculateVelocityScore(telegramId, deviceId);

  // ── 3. IP reputation ──
  if (ipHash) {
    scores.ipScore = await getIpReputation(ipHash);
  }

  // ── 4. Behavioral score from DB (if exists) ──
  // Already loaded above

  // ── Composite weighted score ──
  const composite =
    (scores.failScore   * WEIGHT_FAIL_COUNT / 100) +
    (scores.velocityScore * WEIGHT_VELOCITY / 100) +
    (scores.ipScore     * WEIGHT_IP_REP / 100) +
    (scores.behaviorScore * WEIGHT_BEHAVIOR / 100) +
    (scores.deviceScore * WEIGHT_DEVICE_REP / 100);

  return clamp(Math.round(composite), 0, 100);
}

/**
 * Determine which challenge/gate the user must pass based on risk score.
 *
 * Thresholds:
 *   < 30  → none        (normal operation)
 *   30-60 → pow         (progressive Proof-of-Work difficulty)
 *   60-85 → turnstile   (Cloudflare Turnstile CAPTCHA)
 *   > 85  → block       (temporary hard block, 1 hour)
 *
 * @param {number} riskScore — 0-100 from checkSuspiciousScore()
 * @returns {object}         — { type, difficulty?, durationMs?, reason }
 */
export function getRequiredChallenge(riskScore) {
  if (riskScore < 30) {
    return {
      type:         ChallengeType.NONE,
      difficulty:   null,
      durationMs:   null,
      reason:       'Risk score below threshold — normal flow',
      cacheControl: 'no-cache, no-store, must-revalidate, proxy-revalidate',
    };
  }

  if (riskScore <= 60) {
    // Progressive PoW: higher score = more leading zero bits required
    const diff = riskScore < 40 ? POW_DIFFICULTY.LOW
      : riskScore < 50 ? POW_DIFFICULTY.MEDIUM
      : POW_DIFFICULTY.HIGH;

    return {
      type:         ChallengeType.POW,
      difficulty:   diff,
      durationMs:   null,
      reason:       `PoW required (${diff} leading zero bits)`,
      cacheControl: 'no-cache, no-store, must-revalidate, proxy-revalidate',
    };
  }

  if (riskScore <= 85) {
    return {
      type:         ChallengeType.TURNSTILE,
      difficulty:   null,
      durationMs:   null,
      reason:       'Cloudflare Turnstile challenge required',
      cacheControl: 'no-cache, no-store, must-revalidate, proxy-revalidate',
    };
  }

  // riskScore > 85 → hard block
  return {
    type:         ChallengeType.BLOCK,
    difficulty:   null,
    durationMs:   HARD_BLOCK_DURATION_MS,
    reason:       `Hard block: risk score ${riskScore} exceeds 85 threshold`,
    blockedUntil: new Date(Date.now() + HARD_BLOCK_DURATION_MS).toISOString(),
    cacheControl: 'no-cache, no-store, must-revalidate, proxy-revalidate',
  };
}

/**
 * Record a failed claim/verification attempt.
 * Atomically increments failCount and updates block status.
 *
 * Progressive punishment: block duration = failCount × 5 minutes (capped at 24h).
 *
 * @param {string} telegramId — user's Telegram ID
 * @param {string} deviceId   — device fingerprint / ID
 * @returns {Promise<object>} — { failCount, blockedUntil, isNowBlocked }
 *
 * ATOMIC: Uses findOneAndUpdate with $inc + $set.
 * SECURITY: Does NOT accept or log any code value.
 */
export async function recordFailure(telegramId, deviceId) {
  const now = new Date();
  const telegramIdStr = String(telegramId || '');
  const deviceIdStr   = String(deviceId || '');

  // Build progressive block duration
  const getBlockDuration = (failCount) => {
    const duration = Math.min(failCount * BASE_BLOCK_MS, MAX_BLOCK_MS);
    return duration;
  };

  // Atomic upsert: increment failCount, set timestamps, recalculate block
  const result = await getColl(COLL_RISK_SCORES).findOneAndUpdate(
    {
      $or: [
        { telegramId: telegramIdStr },
        { deviceId: deviceIdStr },
      ],
    },
    {
      $inc:  { failCount: 1 },
      $set:  {
        lastFailAt: now,
        updatedAt:  now,
      },
      $setOnInsert: {
        telegramId:    telegramIdStr,
        deviceId:      deviceIdStr,
        score:         0,
        behaviorScore: 0,
        deviceScore:   0,
        createdAt:     now,
      },
    },
    {
      upsert:         true,
      returnDocument: 'after',
      projection:     { failCount: 1, blockedUntil: 1, score: 1 },
    }
  );

  const doc = result.value || result; // MongoDB driver v4/v5 compatibility
  const failCount = doc.failCount || 1;

  // Calculate progressive block
  const blockMs = getBlockDuration(failCount);
  const blockedUntil = new Date(now.getTime() + blockMs);

  // If failCount exceeds threshold, write the block timestamp (also atomic)
  let finalDoc = doc;
  if (failCount >= 3) { // Start blocking after 3 failures
    const blockResult = await getColl(COLL_RISK_SCORES).findOneAndUpdate(
      {
        $or: [
          { telegramId: telegramIdStr },
          { deviceId: deviceIdStr },
        ],
      },
      {
        $set: {
          blockedUntil,
          score: clamp(failCount * 5, 0, 100), // rough score escalation
        },
      },
      {
        returnDocument: 'after',
        projection:     { failCount: 1, blockedUntil: 1, score: 1 },
      }
    );
    finalDoc = blockResult.value || blockResult;
  }

  // Update cache
  updateBlockCache(telegramId, deviceId, blockedUntil, failCount);

  // Log request event for velocity tracking
  await recordRequestEvent(telegramId, deviceId, null, 'CLAIM_FAILURE');

  return {
    failCount:       finalDoc.failCount || failCount,
    blockedUntil:    finalDoc.blockedUntil || blockedUntil,
    isNowBlocked:    failCount >= 3,
    blockDurationMs: blockMs,
  };
}

/**
 * Record a successful claim/verification.
 * Atomically resets failCount and clears block status.
 *
 * @param {string} telegramId — user's Telegram ID
 * @param {string} deviceId   — device fingerprint / ID
 * @returns {Promise<object>} — { failCountReset, blockCleared, previousFailCount }
 *
 * ATOMIC: Uses findOneAndUpdate with $set.
 */
export async function recordSuccess(telegramId, deviceId) {
  const now = new Date();
  const telegramIdStr = String(telegramId || '');
  const deviceIdStr   = String(deviceId || '');

  const result = await getColl(COLL_RISK_SCORES).findOneAndUpdate(
    {
      $or: [
        { telegramId: telegramIdStr },
        { deviceId: deviceIdStr },
      ],
    },
    {
      $set: {
        failCount:     0,
        score:         0,
        behaviorScore: 0,
        blockedUntil:  null,
        lastSuccessAt: now,
        updatedAt:     now,
      },
    },
    {
      upsert:         false, // Don't create doc on success-only — must have failed first
      returnDocument: 'after',
      projection:     { failCount: 1, blockedUntil: 1 },
    }
  );

  const doc = result.value || result;

  // Clear cache
  blockCache.delete(cacheKey(telegramId, deviceId));

  // Log success for velocity
  await recordRequestEvent(telegramId, deviceId, null, 'CLAIM_SUCCESS');

  return {
    failCountReset:    true,
    blockCleared:      true,
    previousFailCount: doc?.failCount ?? 0,
  };
}

/**
 * Check if the user/device is currently blocked.
 * Checks in-memory cache first, then DB fallback.
 *
 * @param {string} telegramId — user's Telegram ID
 * @param {string} deviceId   — device fingerprint / ID
 * @returns {Promise<object>} — { blocked: boolean, remainingSeconds: number|null, reason: string|null }
 */
export async function isBlocked(telegramId, deviceId) {
  const now = Date.now();

  // ── 1. Hot-path: in-memory cache ──
  const cached = readBlockCache(telegramId, deviceId);
  if (cached) {
    if (cached.blockedUntil && cached.blockedUntil.getTime() > now) {
      const remainingMs = cached.blockedUntil.getTime() - now;
      return {
        blocked:          true,
        remainingSeconds: Math.ceil(remainingMs / 1000),
        reason:           `Progressive block: ${cached.failCount} failures`,
        cacheControl:     'no-cache, no-store, must-revalidate, proxy-revalidate',
      };
    }
    // Cache says not blocked — still verify with DB (stale cache edge case)
  }

  // ── 2. DB fallback ──
  try {
    const doc = await getColl(COLL_RISK_SCORES).findOne({
      $or: [
        { telegramId: String(telegramId || '') },
        { deviceId: String(deviceId || '') },
      ],
    }, {
      projection: { blockedUntil: 1, failCount: 1, score: 1 },
    });

    if (!doc || !doc.blockedUntil) {
      return {
        blocked:          false,
        remainingSeconds: null,
        reason:           null,
        cacheControl:     'no-cache, no-store, must-revalidate, proxy-revalidate',
      };
    }

    const blockedMs = doc.blockedUntil.getTime() - now;
    if (blockedMs > 0) {
      // Update cache for next check
      updateBlockCache(telegramId, deviceId, doc.blockedUntil, doc.failCount || 0);
      return {
        blocked:          true,
        remainingSeconds: Math.ceil(blockedMs / 1000),
        reason:           `Progressive block: ${doc.failCount || 0} failures, riskScore ${doc.score || 0}`,
        cacheControl:     'no-cache, no-store, must-revalidate, proxy-revalidate',
      };
    }
  } catch {
    // DB failure — fail-open (not blocked) to prevent system lockout
    return {
      blocked:          false,
      remainingSeconds: null,
      reason:           'DB unavailable — failing open',
      cacheControl:     'no-cache, no-store, must-revalidate, proxy-revalidate',
    };
  }

  // Block expired
  return {
    blocked:          false,
    remainingSeconds: null,
    reason:           null,
    cacheControl:     'no-cache, no-store, must-revalidate, proxy-revalidate',
  };
}

/**
 * Manually clear a block (admin intervention).
 *
 * @param {string} telegramId — user's Telegram ID
 * @param {string} deviceId   — device fingerprint / ID
 * @param {string} adminId    — admin who cleared the block (for audit)
 * @returns {Promise<object>} — { cleared: boolean, previousBlockUntil }
 */
export async function clearBlock(telegramId, deviceId, adminId) {
  const result = await getColl(COLL_RISK_SCORES).findOneAndUpdate(
    {
      $or: [
        { telegramId: String(telegramId || '') },
        { deviceId: String(deviceId || '') },
      ],
    },
    {
      $set: {
        blockedUntil: null,
        failCount:    0,
        score:        0,
        unblockedAt:  new Date(),
        unblockedBy:  quickHash(adminId), // hashed for audit
      },
    },
    {
      returnDocument: 'after',
      projection:     { blockedUntil: 1, failCount: 1 },
    }
  );

  const doc = result.value || result;

  // Clear cache
  blockCache.delete(cacheKey(telegramId, deviceId));

  return {
    cleared:           doc !== null,
    previousFailCount: doc?.failCount ?? 0,
  };
}

/**
 * Report IP reputation (crowdsourced or external feed).
 * Atomic upsert — used by IP reputation scoring.
 *
 * @param {string} ipHash — SHA-256 hash of IP address (NEVER raw IP)
 * @param {number} score  — 0-100 (0=clean, 100=malicious)
 * @param {string} source — e.g. 'abuseipdb', 'manual', 'honeypot'
 */
export async function reportIpReputation(ipHash, score, source) {
  await getColl(COLL_IP_REPUTATION).updateOne(
    { ipHash },
    {
      $set: {
        score:     clamp(score, 0, 100),
        source,
        updatedAt: new Date(),
      },
      $setOnInsert: {
        ipHash,
        createdAt: new Date(),
      },
    },
    { upsert: true }
  );
}

/**
 * Record behavioral anomaly signal (e.g. timing attack pattern).
 * Adjusts the behaviorScore component of risk.
 *
 * @param {string} telegramId — user's Telegram ID
 * @param {string} deviceId   — device fingerprint / ID
 * @param {number} delta      — amount to adjust behaviorScore (+/-)
 */
export async function adjustBehaviorScore(telegramId, deviceId, delta) {
  const result = await getColl(COLL_RISK_SCORES).findOneAndUpdate(
    {
      $or: [
        { telegramId: String(telegramId || '') },
        { deviceId: String(deviceId || '') },
      ],
    },
    {
      $inc: { behaviorScore: clamp(delta, -100, 100) },
      $set: { updatedAt: new Date() },
      $setOnInsert: {
        telegramId:  String(telegramId || ''),
        deviceId:    String(deviceId || ''),
        failCount:   0,
        score:       0,
        deviceScore: 0,
        createdAt:   new Date(),
      },
    },
    { upsert: true, returnDocument: 'after' }
  );

  const doc = result.value || result;
  return {
    behaviorScore: clamp(doc.behaviorScore || 0, 0, 100),
  };
}

// ═════════════════════════════════════════════════════════════════════════════
// CATEGORY 5 — Suspicious Verified Users
// ═════════════════════════════════════════════════════════════════════════════

/**
 * 5.1 Multi-Telegram Account Detection
 *
 * Tracks {ipHash, deviceId} → telegramId[] mappings.
 * - If same ip+device has > 2 telegramIds  → HIGH RISK
 * - If same ip has > 5 telegramIds         → BLOCK
 * - If same device has > 3 telegramIds     → BLOCK
 *
 * @param {string} ipHash      — hashed IP address
 * @param {string} deviceId    — device fingerprint
 * @param {string} telegramId  — Telegram user ID
 * @returns {Promise<{
 *   riskLevel: 'none'|'high'|'block',
 *   ipTelegramCount: number,
 *   deviceTelegramCount: number,
 *   combinedTelegramCount: number,
 * }>}
 */
export async function checkMultiTelegram(ipHash, deviceId, telegramId) {
  const now = new Date();
  const telegramIdStr = String(telegramId || '');
  const deviceIdStr   = String(deviceId || '');

  if (!ipHash || !telegramIdStr) {
    return { riskLevel: 'none', ipTelegramCount: 0, deviceTelegramCount: 0, combinedTelegramCount: 0 };
  }

  // Atomic upsert: add this telegramId to the mapping
  const result = await getColl(COLL_IP_DEVICE_MAPPINGS).findOneAndUpdate(
    { ipHash, deviceId: deviceIdStr },
    {
      $addToSet: { telegramIds: telegramIdStr },
      $set: { updatedAt: now },
      $setOnInsert: {
        ipHash,
        deviceId: deviceIdStr,
        createdAt: now,
      },
    },
    { upsert: true, returnDocument: 'after' }
  );

  const doc = result.value || result;

  // Also track by IP alone (separate query)
  const ipResult = await getColl(COLL_IP_DEVICE_MAPPINGS).aggregate([
    { $match: { ipHash } },
    { $group: { _id: '$ipHash', allTelegramIds: { $addToSet: '$telegramIds' } } },
    { $project: { count: { $size: { $reduce: { input: '$allTelegramIds', initialValue: [], in: { $setUnion: ['$$value', '$$this'] } } } } } },
  ]).toArray();

  const ipTelegramCount = ipResult.length > 0 ? ipResult[0].count : 1;

  // Track by device alone
  const deviceResult = await getColl(COLL_IP_DEVICE_MAPPINGS).aggregate([
    { $match: { deviceId: deviceIdStr } },
    { $group: { _id: '$deviceId', allTelegramIds: { $addToSet: '$telegramIds' } } },
    { $project: { count: { $size: { $reduce: { input: '$allTelegramIds', initialValue: [], in: { $setUnion: ['$$value', '$$this'] } } } } } },
  ]).toArray();

  const deviceTelegramCount = deviceResult.length > 0 ? deviceResult[0].count : 1;

  const combinedTelegramCount = doc.telegramIds ? doc.telegramIds.length : 1;

  // Risk assessment
  let riskLevel = 'none';
  if (ipTelegramCount > 5) {
    riskLevel = 'block';
  } else if (deviceTelegramCount > 3) {
    riskLevel = 'block';
  } else if (combinedTelegramCount > 2) {
    riskLevel = 'high';
  }

  return {
    riskLevel,
    ipTelegramCount,
    deviceTelegramCount,
    combinedTelegramCount,
  };
}

/**
 * 5.2 Direct API Probing Detection
 *
 * If a user hits /claim or /reveal WITHOUT completing earlier gates,
 * record as "API_PROBE". After 3 probes: temp block 1 hour.
 * Progressive: failCount × 5 min block.
 *
 * @param {string} ipHash     — hashed IP
 * @param {string} deviceId   — device fingerprint
 * @param {string} endpoint   — '/claim' or '/reveal'
 * @param {boolean} gatesCompleted — whether the user completed required gates
 * @returns {Promise<{
 *   isProbe: boolean,
 *   probeCount: number,
 *   shouldBlock: boolean,
 *   blockDurationMs: number,
 * }>}
 */
export async function recordApiProbe(ipHash, deviceId, endpoint, gatesCompleted) {
  const now = new Date();
  const ipHashStr   = String(ipHash || '');
  const deviceIdStr = String(deviceId || '');

  if (gatesCompleted) {
    return { isProbe: false, probeCount: 0, shouldBlock: false, blockDurationMs: 0 };
  }

  // Record the probe attempt
  await getColl(COLL_API_PROBE_LOG).insertOne({
    ipHash: ipHashStr,
    deviceId: deviceIdStr,
    endpoint: endpoint.replace(/^\//, ''), // normalize: 'claim' or 'reveal'
    action: 'API_PROBE',
    createdAt: now,
  });

  // Count probes in the last hour
  const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
  const probeCount = await getColl(COLL_API_PROBE_LOG).countDocuments({
    ipHash: ipHashStr,
    action: 'API_PROBE',
    createdAt: { $gte: oneHourAgo },
  });

  // Progressive: after 3 probes, block duration = probeCount × 5 min
  const shouldBlock = probeCount >= 3;
  const blockDurationMs = shouldBlock
    ? Math.min(probeCount * 5 * 60 * 1000, 24 * 60 * 60 * 1000)
    : 0;

  if (shouldBlock) {
    // Update risk score with block
    await getColl(COLL_RISK_SCORES).findOneAndUpdate(
      { $or: [{ ipHash: ipHashStr }, { deviceId: deviceIdStr }] },
      {
        $set: {
          blockedUntil: new Date(now.getTime() + blockDurationMs),
          score: clamp(probeCount * 10, 0, 100),
          updatedAt: now,
        },
        $setOnInsert: {
          ipHash: ipHashStr,
          deviceId: deviceIdStr,
          failCount: probeCount,
          createdAt: now,
        },
      },
      { upsert: true }
    );
  }

  return {
    isProbe: true,
    probeCount,
    shouldBlock,
    blockDurationMs,
  };
}

/**
 * 5.3 Cooldown for Timelock Violations
 *
 * User repeatedly requests while timer locked:
 * - "TIMELOCK_HIT" count increments
 * - After 5 hits in 2 min → cooldown 5 min
 * - After 10 hits → cooldown 30 min
 * Returns: { error: 'COOLDOWN', retryAfter: 300 }
 *
 * @param {string} telegramId  — Telegram user ID
 * @param {string} deviceId    — device fingerprint
 * @param {string} [action='TIMELOCK_HIT'] — the action to record
 * @returns {Promise<{
 *   onCooldown: boolean,
 *   cooldownSeconds: number,
 *   hitCount: number,
 * }>}
 */
export async function checkTimelockCooldown(telegramId, deviceId, action = 'TIMELOCK_HIT') {
  const now = new Date();
  const telegramIdStr = String(telegramId || '');
  const deviceIdStr   = String(deviceId || '');

  if (!telegramIdStr && !deviceIdStr) {
    return { onCooldown: false, cooldownSeconds: 0, hitCount: 0 };
  }

  // Record the hit
  await getColl(COLL_TIMELOCK_HITS).insertOne({
    telegramId: telegramIdStr,
    deviceId: deviceIdStr,
    action,
    createdAt: now,
  });

  // Count hits in the last 2 minutes
  const twoMinAgo = new Date(now.getTime() - 2 * 60 * 1000);
  const query = telegramIdStr
    ? { telegramId: telegramIdStr, createdAt: { $gte: twoMinAgo } }
    : { deviceId: deviceIdStr, createdAt: { $gte: twoMinAgo } };

  const hitCount = await getColl(COLL_TIMELOCK_HITS).countDocuments(query);

  // Progressive cooldown thresholds
  let cooldownSeconds = 0;
  if (hitCount >= 10) {
    cooldownSeconds = 30 * 60; // 30 minutes
  } else if (hitCount >= 5) {
    cooldownSeconds = 5 * 60;  // 5 minutes
  }

  const onCooldown = cooldownSeconds > 0;

  if (onCooldown) {
    // Apply cooldown block in risk_scores
    await getColl(COLL_RISK_SCORES).findOneAndUpdate(
      { $or: [{ telegramId: telegramIdStr }, { deviceId: deviceIdStr }] },
      {
        $set: {
          blockedUntil: new Date(now.getTime() + cooldownSeconds * 1000),
          score: Math.min(50 + hitCount * 5, 100),
          updatedAt: now,
        },
        $setOnInsert: {
          telegramId: telegramIdStr,
          deviceId: deviceIdStr,
          failCount: hitCount,
          createdAt: now,
        },
      },
      { upsert: true }
    );
  }

  return { onCooldown, cooldownSeconds, hitCount };
}

/**
 * 5.4 Device / User-Agent Change Detection & Re-verification
 *
 * Stores { telegramId, deviceFingerprint, userAgentHash, lastSeen }.
 * If new request has different fingerprint → require re-verification.
 *   - Invalidates old session
 *   - Requires Telegram channel re-join
 *   - New fingerprint + device binding
 *
 * @param {string} telegramId          — Telegram user ID
 * @param {string} deviceFingerprint   — current device fingerprint
 * @param {string} userAgent           — raw user-agent string
 * @returns {Promise<{
 *   changed: boolean,
 *   requiresReverify: boolean,
 *   previousFingerprint: string|null,
 *   previousUserAgentHash: string|null,
 * }>}
 */
export async function checkDeviceChange(telegramId, deviceFingerprint, userAgent) {
  const now = new Date();
  const telegramIdStr = String(telegramId || '');
  const fingerprintStr = String(deviceFingerprint || '');

  if (!telegramIdStr || !fingerprintStr) {
    return { changed: false, requiresReverify: false, previousFingerprint: null, previousUserAgentHash: null };
  }

  const userAgentHash = quickHash(userAgent || '');

  // Look up existing binding
  const existing = await getColl(COLL_DEVICE_BINDINGS).findOne(
    { telegramId: telegramIdStr },
    { projection: { deviceFingerprint: 1, userAgentHash: 1, lastSeen: 1, createdAt: 1 } }
  );

  if (!existing) {
    // First time seeing this telegramId — create binding
    await getColl(COLL_DEVICE_BINDINGS).insertOne({
      telegramId: telegramIdStr,
      deviceFingerprint: fingerprintStr,
      userAgentHash,
      lastSeen: now,
      createdAt: now,
    });
    return { changed: false, requiresReverify: false, previousFingerprint: null, previousUserAgentHash: null };
  }

  // Check if device changed
  const fingerprintChanged = existing.deviceFingerprint !== fingerprintStr;
  const uaChanged = existing.userAgentHash !== userAgentHash;
  const changed = fingerprintChanged || uaChanged;

  if (changed) {
    // Update binding with new device, but mark as requiring re-verification
    await getColl(COLL_DEVICE_BINDINGS).findOneAndUpdate(
      { telegramId: telegramIdStr },
      {
        $set: {
          deviceFingerprint: fingerprintStr,
          userAgentHash,
          lastSeen: now,
          changedAt: now,
          reverifyRequired: true,
        },
      }
    );

    return {
      changed: true,
      requiresReverify: true,
      previousFingerprint: existing.deviceFingerprint || null,
      previousUserAgentHash: existing.userAgentHash || null,
    };
  }

  // No change — just update lastSeen
  await getColl(COLL_DEVICE_BINDINGS).findOneAndUpdate(
    { telegramId: telegramIdStr },
    { $set: { lastSeen: now, reverifyRequired: false } }
);

  return {
    changed: false,
    requiresReverify: false,
    previousFingerprint: existing.deviceFingerprint,
    previousUserAgentHash: existing.userAgentHash,
  };
}

/**
 * Clear the reverify flag after a user successfully re-verifies.
 * @param {string} telegramId
 */
export async function clearReverifyFlag(telegramId) {
  const result = await getColl(COLL_DEVICE_BINDINGS).findOneAndUpdate(
    { telegramId: String(telegramId || '') },
    { $set: { reverifyRequired: false, reverifyClearedAt: new Date() } },
    { returnDocument: 'after' }
  );
  return { cleared: !!(result.value || result) };
}

// ─────────────────────────────────────────────────────────────────────────────
// Default export
// ─────────────────────────────────────────────────────────────────────────────

export default {
  initSuspiciousGuard,
  checkSuspiciousScore,
  getRequiredChallenge,
  recordFailure,
  recordSuccess,
  isBlocked,
  clearBlock,
  reportIpReputation,
  adjustBehaviorScore,
  ChallengeType,
  // Category 5 — Suspicious Verified Users
  checkMultiTelegram,
  recordApiProbe,
  checkTimelockCooldown,
  checkDeviceChange,
  clearReverifyFlag,
};
