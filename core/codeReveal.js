/**
 * @fileoverview codeReveal.js - Hardened Code Delivery Engine
 * @description CRITICAL SECURITY MODULE: Gift code reveal with full hardening.
 *
 * SECURITY RULES (ALL ENFORCED):
 *   1. unlock_at = Final Authority: Code ONLY delivered when Date.now() >= unlock_at
 *   2. claimId + nonce: Stored in Redis with 30s TTL (SET NX EX), fallback to MongoDB
 *   3. Atomic lock: Redis SET NX for claim, findOneAndUpdate MongoDB fallback
 *   4. Cache disabled: Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate
 *   5. Token/nonce NEVER contains code: claimId/nonce are SHA256 hashes and random hex
 *   6. DB code encrypted: decryptString ONLY called at reveal moment (this file only)
 *   7. Logs NEVER contain code: masked as [32-CHAR-CODE] or ***
 *   8. Redis atomic used toggle: SET claim:ticket:{claimId}:used "true" EX 3600 NX
 *   9. Replay protection: nonce:seen:{nonce} tracked for 24h, rejects duplicates
 *  10. Redis unavailable → automatic MongoDB fallback with identical semantics
 *
 * @module core/codeReveal
 * @version 3.0.0-hardened
 */

import { ObjectId } from 'mongodb';
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import { DatabaseManager } from './database.js';
import { decryptString, sha256, generateHexToken } from './encrypt.js';

// ============================================================================
// CONSTANTS
// ============================================================================

/** Claim ticket TTL in seconds (30 seconds) */
const CLAIM_TTL_SECONDS = 30;

/** Claim ticket TTL in milliseconds */
const CLAIM_TTL_MS = CLAIM_TTL_SECONDS * 1000;

/** Used-flag TTL in seconds (1 hour) */
const USED_FLAG_TTL_SECONDS = 3600;

/** Nonce replay tracking TTL in seconds (24 hours) */
const NONCE_REPLAY_TTL_SECONDS = 86400;

/** Rate limit: max successful reveals per telegramId per hour */
const MAX_REVEALS_PER_HOUR = 5;

/** Rate limit: max failed attempts per telegramId per hour */
const MAX_FAILED_ATTEMPTS_PER_HOUR = 3;

/** Rate limit window in milliseconds (1 hour) */
const RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000;

/** Redis key prefixes */
const REDIS_KEY = {
  CLAIM_TICKET: (claimId) => `claim:ticket:${claimId}`,
  CLAIM_USED: (claimId) => `claim:ticket:${claimId}:used`,
  NONCE_SEEN: (nonce) => `nonce:seen:${nonce}`,
};

/** Cache headers for all responses - no caching whatsoever */
const NO_CACHE_HEADERS = {
  'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0',
  'Pragma': 'no-cache',
  'Expires': '-1',
  'Surrogate-Control': 'no-store',
  'Vary': 'Origin, Authorization',
};

/** Collection name for claim tickets */
const CLAIM_TICKETS_COLLECTION = 'claim_tickets';

/** @type {boolean} - Whether claim/nonce indexes have been initialized */
let indexesInitialized = false;

/**
 * Initialize all claim-related collection indexes.
 * Centralizes index creation for claim_tickets, code_claims, and nonce_tracking.
 * Called once at server startup. Idempotent.
 *
 * @param {import('mongodb').Db} db - MongoDB database instance
 * @returns {Promise<void>}
 */
export async function initializeClaimIndexes(db) {
  if (indexesInitialized) return;
  if (!db) return;

  try {
    // claim_tickets: unique on claimId, TTL on expiresAt
    await db.collection(CLAIM_TICKETS_COLLECTION).createIndex(
      { claimId: 1 },
      { unique: true, background: true, name: 'claim_tickets_claimId_unique' }
    );
    await db.collection(CLAIM_TICKETS_COLLECTION).createIndex(
      { expiresAt: 1 },
      { expireAfterSeconds: 0, background: true, name: 'claim_tickets_ttl' }
    );
    await db.collection(CLAIM_TICKETS_COLLECTION).createIndex(
      { telegramId: 1, createdAt: -1 },
      { background: true, name: 'claim_tickets_telegramId_lookup' }
    );

    // code_claims: unique on codeId+userId+claimDate (one claim per user per code per day)
    // claimDate is 'YYYY-MM-DD' string — prevents race condition on exact timestamp
    await db.collection('code_claims').createIndex(
      { telegramId: 1, codeId: 1, claimDate: 1 },
      { unique: true, background: true, name: 'code_claims_telegramId_codeId_claimDate_unique' }
    );

    // nonce_tracking: unique on nonce, TTL on expiresAt
    await db.collection('nonce_tracking').createIndex(
      { nonce: 1 },
      { unique: true, background: true, name: 'nonce_tracking_nonce_unique' }
    );
    await db.collection('nonce_tracking').createIndex(
      { expiresAt: 1 },
      { expireAfterSeconds: 0, background: true, name: 'nonce_tracking_ttl' }
    );

    indexesInitialized = true;
  } catch (err) {
    // Index may already exist - continue
    if (!err.message?.includes('already exists')) {
      throw new RevealError('Failed to initialize claim indexes', 'INDEX_INIT_ERROR', 500);
    }
    indexesInitialized = true;
  }
}

// ============================================================================
// REDIS CLIENT (Lazy-Loaded with Graceful Fallback)
// ============================================================================

/** @type {import('ioredis').Redis|null} */
let redisClient = null;
let redisAvailable = false;
let redisChecked = false;

/**
 * Lazy-load and test Redis connection.
 * If Redis is unavailable, falls back silently to MongoDB-only mode.
 * @returns {Promise<import('ioredis').Redis|null>}
 */
async function getRedisClient() {
  // Return cached result if already checked this process lifetime
  if (redisChecked) {
    return redisAvailable ? redisClient : null;
  }

  // Attempt to load Redis
  try {
    const { Redis } = await import('ioredis');
    const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';

    redisClient = new Redis(redisUrl, {
      retryStrategy: (times) => {
        // Stop retrying after 3 attempts
        if (times > 3) return null;
        return Math.min(times * 100, 500);
      },
      maxRetriesPerRequest: 1,
      connectTimeout: 2000,
      commandTimeout: 2000,
      lazyConnect: true, // Don't connect until first command
    });

    // Test connection
    await redisClient.ping();
    redisAvailable = true;
    redisChecked = true;
    return redisClient;
  } catch {
    // Redis not available — use MongoDB fallback exclusively
    redisAvailable = false;
    redisChecked = true;
    redisClient = null;
    return null;
  }
}

/**
 * Check if Redis is available without triggering a connection attempt.
 * @returns {boolean}
 */
function isRedisReady() {
  return redisAvailable && redisClient !== null;
}

// ============================================================================
// IN-MEMORY RATE LIMITING STORES
// ============================================================================

/** @type {Map<string, number[]>} - telegramId -> array of reveal timestamps */
const revealRateLimitStore = new Map();

/** @type {Map<string, number[]>} - telegramId -> array of failed attempt timestamps */
const failedAttemptStore = new Map();

/**
 * Clean expired rate limit entries periodically.
 */
setInterval(() => {
  const cutoff = Date.now() - RATE_LIMIT_WINDOW_MS;
  for (const [key, timestamps] of revealRateLimitStore) {
    const filtered = timestamps.filter((t) => t > cutoff);
    if (filtered.length === 0) revealRateLimitStore.delete(key);
    else revealRateLimitStore.set(key, filtered);
  }
  for (const [key, timestamps] of failedAttemptStore) {
    const filtered = timestamps.filter((t) => t > cutoff);
    if (filtered.length === 0) failedAttemptStore.delete(key);
    else failedAttemptStore.set(key, filtered);
  }
}, 60_000);

// ============================================================================
// CUSTOM ERROR CLASSES
// ============================================================================

/**
 * Base error for code reveal operations.
 * All error messages are safe to expose to the client (no codes, no tokens).
 */
export class RevealError extends Error {
  /**
   * @param {string} message - Human-readable error message
   * @param {string} code - Machine-readable error code
   * @param {number} statusCode - HTTP status code
   * @param {Object} extra - Extra response fields (e.g., remainingSeconds, retryAfter)
   */
  constructor(message, code, statusCode = 400, extra = {}) {
    super(message);
    this.name = 'RevealError';
    this.code = code;
    this.statusCode = statusCode;
    this.extra = extra;
    Error.captureStackTrace(this, this.constructor);
  }
}

// ============================================================================
// SANITIZATION HELPERS (Rule 7: Logs NEVER contain code)
// ============================================================================

/**
 * Sanitize a claimId for logging - return a short hash prefix only.
 * @param {string} claimId - Raw claimId
 * @returns {string} Sanitized claimId for logs
 */
function sanitizeClaimId(claimId) {
  if (!claimId || typeof claimId !== 'string') return '[MISSING]';
  return claimId.substring(0, 8) + '...' + claimId.substring(claimId.length - 4);
}

/**
 * Sanitize telegramId for logging.
 * @param {string} telegramId - Raw telegramId
 * @returns {string} Sanitized telegramId
 */
function sanitizeTelegramId(telegramId) {
  if (!telegramId || typeof telegramId !== 'string') return '[MISSING]';
  if (telegramId.length <= 8) return '***' + telegramId;
  return telegramId.substring(0, 4) + '...' + telegramId.substring(telegramId.length - 4);
}

/**
 * Sanitize deviceId for logging.
 * @param {string} deviceId - Raw deviceId
 * @returns {string} Sanitized deviceId
 */
function sanitizeDeviceId(deviceId) {
  if (!deviceId || typeof deviceId !== 'string') return '[MISSING]';
  return deviceId.substring(0, 6) + '...';
}

/**
 * Sanitize sessionToken for logging.
 * @param {string} token - Raw session token
 * @returns {string} Sanitized token (first 8 chars only)
 */
function sanitizeToken(token) {
  if (!token || typeof token !== 'string') return '[MISSING]';
  return token.substring(0, 8) + '...';
}

/**
 * Build a sanitized log context object.
 * NEVER includes the actual code, full tokens, or full claimIds.
 * @param {Object} params - Raw parameters
 * @returns {Object} Sanitized context safe for logging
 */
function buildLogContext({ claimId, telegramId, deviceId, sessionToken, codeLength, codeId }) {
  const ctx = {};
  if (claimId) ctx.claimId = sanitizeClaimId(claimId);
  if (telegramId) ctx.telegramId = sanitizeTelegramId(telegramId);
  if (deviceId) ctx.deviceId = sanitizeDeviceId(deviceId);
  if (sessionToken) ctx.sessionToken = sanitizeToken(sessionToken);
  if (codeLength) ctx.codeLength = codeLength;
  if (codeId) ctx.codeId = codeId;
  return ctx;
}

// ============================================================================
// CLAIM TICKET COLLECTION INITIALIZATION
// ============================================================================

/** @type {boolean} */
let claimCollectionInitialized = false;

/**
 * Ensure the claim_tickets collection exists with proper TTL index.
 * Called lazily on first use. Idempotent.
 *
 * @returns {Promise<import('mongodb').Collection>}
 */
async function getClaimTicketsCollection() {
  const dbManager = DatabaseManager.getInstance();
  const nativeDb = dbManager.db;

  if (!nativeDb) {
    throw new RevealError('Database not available', 'DB_UNAVAILABLE', 500);
  }

  const collection = nativeDb.collection(CLAIM_TICKETS_COLLECTION);

  // Create TTL index on first use (idempotent - MongoDB ignores duplicate index creation)
  if (!claimCollectionInitialized) {
    try {
      await collection.createIndex(
        { expiresAt: 1 },
        { expireAfterSeconds: 0, background: true, name: 'claim_tickets_ttl' }
      );
      await collection.createIndex(
        { claimId: 1 },
        { unique: true, background: true, name: 'claim_tickets_claimId_unique' }
      );
      await collection.createIndex(
        { telegramId: 1, createdAt: -1 },
        { background: true, name: 'claim_tickets_telegramId_lookup' }
      );
      claimCollectionInitialized = true;
      // Also mark the new centralized flag to avoid redundant work
      indexesInitialized = true;
    } catch (err) {
      // Index may already exist - continue
      if (!err.message?.includes('already exists')) {
        throw new RevealError('Failed to initialize claim tickets collection', 'DB_INIT_ERROR', 500);
      }
      claimCollectionInitialized = true;
      indexesInitialized = true;
    }
  }

  return collection;
}

// ============================================================================
// AUDIT LOGGING (Rule 7: Never log actual code)
// ============================================================================

/**
 * Log an audit event with fully sanitized data.
 * The code value is NEVER written to logs.
 *
 * @param {string} action - Action name
 * @param {Object} context - Context data (will be sanitized)
 */
async function logAuditEvent(action, context = {}) {
  try {
    const dbManager = DatabaseManager.getInstance();
    const sanitizedContext = buildLogContext(context);

    // If codeLength is present, log it. NEVER log the actual code.
    if (context.codeLength) {
      sanitizedContext.codeLength = context.codeLength;
    }
    if (context.remainingSeconds !== undefined) {
      sanitizedContext.remainingSeconds = context.remainingSeconds;
    }
    if (context.retryAfter !== undefined) {
      sanitizedContext.retryAfter = context.retryAfter;
    }
    if (context.redisAvailable !== undefined) {
      sanitizedContext.redisAvailable = context.redisAvailable;
    }
    if (context.replayNonce) {
      sanitizedContext.replayNonce = context.replayNonce.substring(0, 8) + '...';
    }

    await dbManager.insertOne('audit_logs', {
      action: `CODE_REVEAL_${action}`,
      context: sanitizedContext,
      severity: context.severity || 'info',
      createdAt: new Date(),
      eventHash: generateHexToken(16),
    });
  } catch {
    // Audit logging must never break the request
    // Silently fail - security monitoring may miss this event
  }
}

// ============================================================================
// RATE LIMITING
// ============================================================================

/**
 * Check if a telegramId has exceeded the reveal rate limit.
 * Max 5 successful reveals per hour.
 *
 * @param {string} telegramId - Telegram user ID
 * @returns {{allowed: boolean, retryAfter: number, count: number}}
 */
function checkRevealRateLimit(telegramId) {
  const now = Date.now();
  const cutoff = now - RATE_LIMIT_WINDOW_MS;
  const timestamps = revealRateLimitStore.get(telegramId) || [];
  const recent = timestamps.filter((t) => t > cutoff);

  // Update the store with filtered list
  revealRateLimitStore.set(telegramId, recent);

  if (recent.length >= MAX_REVEALS_PER_HOUR) {
    const oldest = recent[0];
    const retryAfter = Math.ceil((oldest + RATE_LIMIT_WINDOW_MS - now) / 1000);
    return { allowed: false, retryAfter: Math.max(1, retryAfter), count: recent.length };
  }

  return { allowed: true, retryAfter: 0, count: recent.length };
}

/**
 * Record a successful reveal for rate limiting.
 * @param {string} telegramId - Telegram user ID
 */
function recordSuccessfulReveal(telegramId) {
  const timestamps = revealRateLimitStore.get(telegramId) || [];
  timestamps.push(Date.now());
  revealRateLimitStore.set(telegramId, timestamps);
}

/**
 * Check if a telegramId has exceeded the failed attempt rate limit.
 * Max 3 failed attempts per hour.
 *
 * @param {string} telegramId - Telegram user ID
 * @returns {{allowed: boolean, retryAfter: number, count: number}}
 */
function checkFailedAttemptRateLimit(telegramId) {
  const now = Date.now();
  const cutoff = now - RATE_LIMIT_WINDOW_MS;
  const timestamps = failedAttemptStore.get(telegramId) || [];
  const recent = timestamps.filter((t) => t > cutoff);

  failedAttemptStore.set(telegramId, recent);

  if (recent.length >= MAX_FAILED_ATTEMPTS_PER_HOUR) {
    const oldest = recent[0];
    const retryAfter = Math.ceil((oldest + RATE_LIMIT_WINDOW_MS - now) / 1000);
    return { allowed: false, retryAfter: Math.max(1, retryAfter), count: recent.length };
  }

  return { allowed: true, retryAfter: 0, count: recent.length };
}

/**
 * Record a failed attempt for rate limiting.
 * @param {string} telegramId - Telegram user ID
 */
function recordFailedAttempt(telegramId) {
  const timestamps = failedAttemptStore.get(telegramId) || [];
  timestamps.push(Date.now());
  failedAttemptStore.set(telegramId, timestamps);
}

// ============================================================================
// REDIS ATOMIC OPERATIONS (Primary)
// MongoDB Fallback (when Redis unavailable)
// ============================================================================

/**
 * Atomically create a claim ticket.
 *
 * Redis (preferred):
 *   SET claim:ticket:{claimId} JSON.stringify(ticketData) EX 30 NX
 *   Returns true if set, false if claimId already exists.
 *
 * MongoDB (fallback):
 *   insertOne with unique index on claimId
 *   Returns true on success, false on duplicate key error.
 *
 * @param {string} claimId
 * @param {Object} ticketData - {nonce, telegramId, deviceId, sessionToken, used, createdAt, expiresAt}
 * @returns {Promise<boolean>} true if created, false if already exists
 */
async function atomicCreateClaimTicket(claimId, ticketData) {
  const redis = await getRedisClient();

  if (redis) {
    try {
      const key = REDIS_KEY.CLAIM_TICKET(claimId);
      const result = await redis.set(
        key,
        JSON.stringify(ticketData),
        'EX',
        CLAIM_TTL_SECONDS,
        'NX'
      );
      // Redis SET NX returns 'OK' on success, null on key exists
      return result === 'OK';
    } catch {
      // Redis error — fall through to MongoDB
    }
  }

  // ── MongoDB Fallback ──
  try {
    const collection = await getClaimTicketsCollection();
    await collection.insertOne({
      claimId,
      ...ticketData,
    });
    return true;
  } catch (err) {
    // Duplicate key error = claimId already exists
    if (err.code === 11000 || err.message?.includes('duplicate')) {
      return false;
    }
    throw err;
  }
}

/**
 * Atomically mark a claim ticket as used.
 *
 * Redis (preferred):
 *   SET claim:ticket:{claimId}:used "true" EX 3600 NX
 *   Returns {isFirstUse: true} if set (first use)
 *   Returns {isFirstUse: false} if key already exists (replay attack)
 *
 * MongoDB (fallback):
 *   findOneAndUpdate({ claimId, used: false }, { $set: { used: true, usedAt: now } })
 *   Returns {isFirstUse: true} if matched, {isFirstUse: false} if not matched.
 *
 * @param {string} claimId
 * @returns {Promise<{isFirstUse: boolean}>}
 */
async function atomicMarkUsed(claimId) {
  const redis = await getRedisClient();

  if (redis) {
    try {
      const usedKey = REDIS_KEY.CLAIM_USED(claimId);
      const result = await redis.set(usedKey, 'true', 'EX', USED_FLAG_TTL_SECONDS, 'NX');
      // SET NX returns 'OK' on first set, null if key exists
      if (result === 'OK') {
        return { isFirstUse: true };
      }
      return { isFirstUse: false };
    } catch {
      // Redis error — fall through to MongoDB
    }
  }

  // ── MongoDB Fallback ──
  try {
    const collection = await getClaimTicketsCollection();
    const result = await collection.findOneAndUpdate(
      { claimId, used: false },
      { $set: { used: true, usedAt: new Date() } },
      { returnDocument: 'after' }
    );

    // findOneAndUpdate returns the updated document
    // If result is null, no document matched (already used or not found)
    if (result && result.used === true && result.usedAt) {
      // We set used=true — but check if usedAt was already set (race condition)
      // In MongoDB fallback, findOneAndUpdate only returns the doc if it matched
      // So if we get here, we won the race
      return { isFirstUse: true };
    }
    return { isFirstUse: false };
  } catch {
    // On error, assume not first use (fail secure)
    return { isFirstUse: false };
  }
}

/**
 * Check if a claim ticket has already been used.
 *
 * Redis (preferred):
 *   EXISTS claim:ticket:{claimId}:used
 *   Returns 1 if used, 0 if not.
 *
 * MongoDB (fallback):
 *   findOne({ claimId }) and check used field
 *
 * @param {string} claimId
 * @returns {Promise<boolean>} true if already used
 */
async function isClaimUsed(claimId) {
  const redis = await getRedisClient();

  if (redis) {
    try {
      const usedKey = REDIS_KEY.CLAIM_USED(claimId);
      const exists = await redis.exists(usedKey);
      return exists === 1;
    } catch {
      // Fall through to MongoDB
    }
  }

  // ── MongoDB Fallback ──
  try {
    const collection = await getClaimTicketsCollection();
    const doc = await collection.findOne(
      { claimId },
      { projection: { used: 1 } }
    );
    return doc ? doc.used === true : false;
  } catch {
    // On error, assume used (fail secure)
    return true;
  }
}

/**
 * Retrieve a claim ticket by claimId.
 *
 * Redis (preferred):
 *   GET claim:ticket:{claimId} → parse JSON
 *
 * MongoDB (fallback):
 *   findOne({ claimId, used: false })
 *
 * @param {string} claimId
 * @returns {Promise<Object|null>} ticket data or null
 */
async function getClaimTicket(claimId) {
  const redis = await getRedisClient();

  if (redis) {
    try {
      const key = REDIS_KEY.CLAIM_TICKET(claimId);
      const data = await redis.get(key);
      if (data) {
        return JSON.parse(data);
      }
      return null;
    } catch {
      // Fall through to MongoDB
    }
  }

  // ── MongoDB Fallback ──
  try {
    const collection = await getClaimTicketsCollection();
    return await collection.findOne(
      { claimId, used: false },
      { projection: { claimId: 1, nonce: 1, telegramId: 1, deviceId: 1, sessionToken: 1, expiresAt: 1, used: 1 } }
    );
  } catch {
    return null;
  }
}

/**
 * Track a nonce to prevent replay attacks.
 * SET nonce:seen:{nonce} "1" EX 86400 NX
 * Returns true if nonce was new, false if already seen.
 *
 * @param {string} nonce
 * @returns {Promise<boolean>} true if nonce is new, false if replay detected
 */
async function trackNonceForReplayProtection(nonce) {
  const redis = await getRedisClient();

  if (redis) {
    try {
      const key = REDIS_KEY.NONCE_SEEN(nonce);
      const result = await redis.set(key, '1', 'EX', NONCE_REPLAY_TTL_SECONDS, 'NX');
      // SET NX returns 'OK' on first set (new nonce), null if already exists (replay)
      return result === 'OK';
    } catch {
      // Redis error — fall through (allow the request rather than blocking)
    }
  }

  // ── MongoDB Fallback: store seen nonces in a dedicated collection ──
  try {
    const dbManager = DatabaseManager.getInstance();
    await dbManager.insertOne('nonce_tracking', {
      nonce: sha256(nonce), // Hash the nonce before storing
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + NONCE_REPLAY_TTL_SECONDS * 1000),
    });
    return true;
  } catch (err) {
    // Duplicate key error = nonce already seen
    if (err.code === 11000 || err.message?.includes('duplicate')) {
      return false;
    }
    // On other errors, allow the request (fail open for UX, nonce tracking is defense-in-depth)
    return true;
  }
}

// ============================================================================
// CLAIM TICKET GENERATION (Rule 2: claimId + nonce with 30s TTL)
// ============================================================================

/**
 * Generate a cryptographically secure one-time claim ticket.
 * Stored atomically in Redis with 30-second TTL (SET NX EX).
 * Falls back to MongoDB with identical semantics.
 *
 * The claimId is a SHA-256 hash of session data + timestamp + randomness.
 * The nonce is a cryptographically secure random 16-byte hex string.
 * NEITHER contains the actual gift code (Rule 5).
 *
 * @param {string} sessionToken - Session token
 * @param {string} telegramId - Telegram user ID
 * @param {string} deviceId - Device identifier
 * @returns {Promise<{claimId: string, nonce: string, expiresIn: number}>}
 */
export async function generateClaimTicket(sessionToken, telegramId, deviceId) {
  // Input validation
  if (!sessionToken || typeof sessionToken !== 'string') {
    throw new RevealError('Session token is required', 'INVALID_SESSION', 400);
  }
  if (!telegramId || typeof telegramId !== 'string') {
    throw new RevealError('Telegram ID is required', 'INVALID_TELEGRAM_ID', 400);
  }
  if (!deviceId || typeof deviceId !== 'string') {
    throw new RevealError('Device ID is required', 'INVALID_DEVICE_ID', 400);
  }

  const now = Date.now();
  const randomComponent = randomBytes(32).toString('hex');

  // claimId = SHA-256 hash of session + telegram + device + timestamp + randomness
  // This is a ONE-WAY hash. The code can NEVER be derived from claimId (Rule 5).
  const claimIdPayload = `${sessionToken}:${telegramId}:${deviceId}:${now}:${randomComponent}`;
  const claimId = sha256(claimIdPayload);

  // nonce = 16 bytes of CSPRNG data as hex - completely independent of code
  const nonce = randomBytes(16).toString('hex');

  const expiresAt = new Date(now + CLAIM_TTL_MS);

  // Build ticket data for storage
  const ticketData = {
    nonce,
    telegramId,
    deviceId,
    sessionToken,
    used: false,
    createdAt: new Date(now),
    expiresAt,
  };

  // Atomically create the claim ticket (Redis SET NX EX, or MongoDB insertOne)
  const created = await atomicCreateClaimTicket(claimId, ticketData);

  // If claimId collision occurred (extremely unlikely), generate new one
  if (!created) {
    // Recurse with a new random component (extremely unlikely)
    return generateClaimTicket(sessionToken, telegramId, deviceId);
  }

  await logAuditEvent('TICKET_CREATED', {
    claimId,
    telegramId,
    deviceId,
    expiresIn: CLAIM_TTL_SECONDS,
    redisAvailable: isRedisReady(),
    severity: 'info',
  });

  return { claimId, nonce, expiresIn: CLAIM_TTL_SECONDS };
}

// ============================================================================
// CORE CODE REVEAL (All 10 rules enforced)
// ============================================================================

/**
 * MAIN: Reveal a gift code after ALL security checks pass.
 * This is the ONLY function that calls decryptString (Rule 6).
 *
 * Security layers (in order):
 *   1. Input validation
 *   2. Failed attempt rate limiting (max 3/hour)
 *   3. Replay protection: nonce duplicate detection
 *   4. Claim ticket retrieval + binding validation (atomic)
 *   5. Atomic one-time use lock (Redis SET NX / MongoDB findOneAndUpdate)
 *   6. unlock_at time-lock check (BEFORE any code DB read)
 *   7. Reveal rate limiting (max 5/hour)
 *   8. Telegram channel verification (double-check)
 *   9. Code decryption (decryptString ONLY here)
 *  10. Mark code as claimed in DB (atomic)
 *  11. Record successful reveal for rate limiting
 *
 * @param {Object} params - Reveal parameters
 * @param {string} params.sessionToken - Session token
 * @param {string} params.claimId - Claim ticket ID
 * @param {string} params.nonce - Claim ticket nonce
 * @param {string} params.telegramId - Telegram user ID
 * @param {string} params.deviceId - Device identifier
 * @param {string} [params.powSolution] - Optional PoW solution
 * @param {number} [params.behavioralScore] - Optional behavioral score
 * @returns {Promise<Object>} Response object
 */
export async function revealCode({
  sessionToken,
  claimId,
  nonce,
  telegramId,
  deviceId,
  powSolution,
  behavioralScore,
  codeId,  // BUG 5 FIX: session-bound codeId for exact code lookup
}) {
  // ───────────────────────────────────────────────────────────────────────────
  // LAYER 1: Input validation
  // ───────────────────────────────────────────────────────────────────────────
  if (!sessionToken || typeof sessionToken !== 'string') {
    await logAuditEvent('FAIL_INVALID_INPUT', {
      reason: 'missing_sessionToken',
      severity: 'warn',
    });
    throw new RevealError('Session token is required', 'INVALID_REQUEST', 400);
  }
  if (!claimId || typeof claimId !== 'string') {
    await logAuditEvent('FAIL_INVALID_INPUT', {
      reason: 'missing_claimId',
      severity: 'warn',
    });
    throw new RevealError('Claim ID is required', 'INVALID_REQUEST', 400);
  }
  if (!nonce || typeof nonce !== 'string') {
    await logAuditEvent('FAIL_INVALID_INPUT', {
      claimId,
      reason: 'missing_nonce',
      severity: 'warn',
    });
    throw new RevealError('Nonce is required', 'INVALID_REQUEST', 400);
  }
  if (!telegramId || typeof telegramId !== 'string') {
    await logAuditEvent('FAIL_INVALID_INPUT', {
      claimId,
      reason: 'missing_telegramId',
      severity: 'warn',
    });
    throw new RevealError('Telegram ID is required', 'INVALID_REQUEST', 400);
  }
  if (!deviceId || typeof deviceId !== 'string') {
    await logAuditEvent('FAIL_INVALID_INPUT', {
      claimId,
      reason: 'missing_deviceId',
      severity: 'warn',
    });
    throw new RevealError('Device ID is required', 'INVALID_REQUEST', 400);
  }

  // ───────────────────────────────────────────────────────────────────────────
  // LAYER 2: Failed attempt rate limiting (max 3 failed per hour)
  // ───────────────────────────────────────────────────────────────────────────
  const failLimit = checkFailedAttemptRateLimit(telegramId);
  if (!failLimit.allowed) {
    await logAuditEvent('FAIL_RATE_LIMITED_ATTEMPTS', {
      claimId,
      telegramId,
      retryAfter: failLimit.retryAfter,
      count: failLimit.count,
      severity: 'warn',
    });
    throw new RevealError(
      'Too many failed attempts',
      'RATE_LIMITED',
      429,
      { retryAfter: failLimit.retryAfter }
    );
  }

  // ───────────────────────────────────────────────────────────────────────────
  // LAYER 3: Replay Protection — NONCE CHECK (actual tracking moved to Layer 8.5)
  // We validate the nonce format here but DO NOT burn it yet.
  // The nonce is only marked as "seen" AFTER all security checks pass
  // (just before decryption). This prevents nonce burn before timelock.
  // ───────────────────────────────────────────────────────────────────────────
  if (!nonce || typeof nonce !== 'string' || nonce.length < 16) {
    recordFailedAttempt(telegramId);
    await logAuditEvent('FAIL_INVALID_NONCE', {
      claimId,
      telegramId,
      severity: 'warn',
    });
    throw new RevealError('Invalid nonce format', 'INVALID_NONCE', 400);
  }

  // ───────────────────────────────────────────────────────────────────────────
  // LAYER 4: Claim ticket retrieval with binding validation
  // Uses atomic get from Redis or findOne from MongoDB.
  // ───────────────────────────────────────────────────────────────────────────
  const ticket = await getClaimTicket(claimId);

  if (!ticket) {
    recordFailedAttempt(telegramId);
    await logAuditEvent('FAIL_INVALID_CLAIM', {
      claimId,
      telegramId,
      reason: 'ticket_not_found_or_used',
      severity: 'warn',
    });
    throw new RevealError('Invalid or already used claim ticket', 'INVALID_CLAIM', 400);
  }

  // Check TTL expiry
  if (ticket.expiresAt) {
    const expiryTime = typeof ticket.expiresAt === 'string'
      ? new Date(ticket.expiresAt).getTime()
      : ticket.expiresAt.getTime ? ticket.expiresAt.getTime() : ticket.expiresAt;
    if (expiryTime < Date.now()) {
      recordFailedAttempt(telegramId);
      // Clean up expired ticket
      const collection = await getClaimTicketsCollection();
      await collection.deleteOne({ claimId }).catch(() => {});
      await logAuditEvent('FAIL_CLAIM_EXPIRED', {
        claimId,
        telegramId,
        severity: 'info',
      });
      throw new RevealError('Claim ticket expired. Start over.', 'CLAIM_EXPIRED', 400);
    }
  }

  // Validate all bindings (constant-time comparison for tokens)
  if (ticket.telegramId !== telegramId) {
    recordFailedAttempt(telegramId);
    await logAuditEvent('FAIL_TELEGRAM_MISMATCH', {
      claimId,
      telegramId,
      severity: 'high',
    });
    throw new RevealError('Telegram ID mismatch', 'TELEGRAM_MISMATCH', 403);
  }

  if (ticket.deviceId !== deviceId) {
    recordFailedAttempt(telegramId);
    await logAuditEvent('FAIL_DEVICE_MISMATCH', {
      claimId,
      telegramId,
      severity: 'high',
    });
    throw new RevealError('Device binding mismatch', 'DEVICE_MISMATCH', 403);
  }

  if (ticket.sessionToken !== sessionToken) {
    recordFailedAttempt(telegramId);
    await logAuditEvent('FAIL_TOKEN_MISMATCH', {
      claimId,
      telegramId,
      severity: 'high',
    });
    throw new RevealError('Session token mismatch', 'TOKEN_MISMATCH', 403);
  }

  // Constant-time nonce comparison to prevent timing attacks
  const ticketNonceBuf = Buffer.from(ticket.nonce || '', 'utf8');
  const inputNonceBuf = Buffer.from(nonce, 'utf8');
  if (ticketNonceBuf.length !== inputNonceBuf.length) {
    recordFailedAttempt(telegramId);
    await logAuditEvent('FAIL_NONCE_MISMATCH', {
      claimId,
      telegramId,
      severity: 'high',
    });
    throw new RevealError('Nonce verification failed', 'NONCE_MISMATCH', 403);
  }
  try {
    if (!timingSafeEqual(ticketNonceBuf, inputNonceBuf)) {
      recordFailedAttempt(telegramId);
      await logAuditEvent('FAIL_NONCE_MISMATCH', {
        claimId,
        telegramId,
        severity: 'high',
      });
      throw new RevealError('Nonce verification failed', 'NONCE_MISMATCH', 403);
    }
  } catch {
    recordFailedAttempt(telegramId);
    await logAuditEvent('FAIL_NONCE_MISMATCH', {
      claimId,
      telegramId,
      severity: 'high',
    });
    throw new RevealError('Nonce verification failed', 'NONCE_MISMATCH', 403);
  }

  // ───────────────────────────────────────────────────────────────────────────
  // LAYER 5: Atomically lock the claim ticket (prevent race conditions)
  // Redis: SET claim:ticket:{claimId}:used "true" EX 3600 NX
  // If SET NX returns OK → first use, proceed
  // If SET NX returns null → already used, REJECT (replay attack)
  //
  // MongoDB fallback: findOneAndUpdate({ claimId, used: false }, ...)
  // ───────────────────────────────────────────────────────────────────────────
  const lockResult = await atomicMarkUsed(claimId);

  if (!lockResult.isFirstUse) {
    // Another request already claimed this ticket (race condition or replay)
    recordFailedAttempt(telegramId);
    await logAuditEvent('FAIL_RACE_CONDITION', {
      claimId,
      telegramId,
      severity: 'high',
    });
    throw new RevealError(
      'Claim ticket already used',
      'CLAIM_REUSED',
      409,
      { message: 'Claim already consumed' }
    );
  }

  // ───────────────────────────────────────────────────────────────────────────
  // LAYER 6: unlock_at check — THE FINAL AUTHORITY (Rule 1)
  // CRITICAL: We check unlock_at BEFORE reading any code from the database.
  // This ensures the code is NEVER even looked at until the time-lock expires.
  // ───────────────────────────────────────────────────────────────────────────
  const dbManager = DatabaseManager.getInstance();

  // BUG 5 FIX: Look up code by session-bound codeId (exact binding)
  // NO FALLBACK — codeId is MANDATORY, set by /gift when creating session
  let codeMetaDoc = null;
  if (codeId) {
    codeMetaDoc = await dbManager.findOne(
      'gift_codes',
      { _id: new ObjectId(codeId), status: 'active' },
      { projection: { _id: 1, releaseAt: 1, expirySeconds: 1, status: 1 } }
    );
  }
  // If codeId missing or code not found → REJECT (no global fallback)
  if (!codeMetaDoc) {
    recordFailedAttempt(telegramId);
    await logAuditEvent('FAIL_NO_CODE_AVAILABLE', {
      claimId,
      telegramId,
      severity: 'error',
    });
    throw new RevealError('No active code available', 'NO_CODE_AVAILABLE', 404);
  }

  const unlockAt = codeMetaDoc.releaseAt ? codeMetaDoc.releaseAt.getTime() : 0;

  if (unlockAt > Date.now()) {
    // Time-lock still active — do NOT even look at the encrypted code
    const remainingSeconds = Math.ceil((unlockAt - Date.now()) / 1000);

    await logAuditEvent('FAIL_TIMELOCK_ACTIVE', {
      claimId,
      telegramId,
      codeId: codeMetaDoc._id.toString(),
      remainingSeconds,
      severity: 'info',
    });

    // Release the ticket lock so user can retry after timer
    const collection = await getClaimTicketsCollection();
    await collection.updateOne(
      { claimId },
      { $set: { used: false, lockedAt: null } }
    ).catch(() => {});

    // Also release the Redis used flag so retry is possible
    const redis = await getRedisClient();
    if (redis) {
      await redis.del(REDIS_KEY.CLAIM_USED(claimId)).catch(() => {});
    }

    throw new RevealError(
      'Timer still running',
      'TIMELOCK_ACTIVE',
      423,
      { remainingSeconds }
    );
  }

  // ───────────────────────────────────────────────────────────────────────────
  // LAYER 7: Reveal rate limiting (max 5 successful reveals per hour)
  // ───────────────────────────────────────────────────────────────────────────
  const revealLimit = checkRevealRateLimit(telegramId);
  if (!revealLimit.allowed) {
    recordFailedAttempt(telegramId);
    await logAuditEvent('FAIL_RATE_LIMITED_REVEALS', {
      claimId,
      telegramId,
      retryAfter: revealLimit.retryAfter,
      count: revealLimit.count,
      severity: 'warn',
    });

    // Release the ticket lock
    const collection = await getClaimTicketsCollection();
    await collection.updateOne(
      { claimId },
      { $set: { used: false } }
    ).catch(() => {});

    // Release Redis used flag
    const redis = await getRedisClient();
    if (redis) {
      await redis.del(REDIS_KEY.CLAIM_USED(claimId)).catch(() => {});
    }

    throw new RevealError(
      'Too many code reveals. Try again later.',
      'RATE_LIMITED',
      429,
      { retryAfter: revealLimit.retryAfter }
    );
  }

  // ───────────────────────────────────────────────────────────────────────────
  // LAYER 8: Telegram channel verification (double-check)
  // ───────────────────────────────────────────────────────────────────────────
  try {
    const { verifyTelegramMembership } = await import('./telegramVerify.js');
    // D FIX: Use same env names as .env.example: TELEGRAM_CHANNEL_PRIMARY/SECONDARY/ALERTS
    const channels = [
      process.env.TELEGRAM_CHANNEL_PRIMARY || process.env.TG_CHANNEL_1 || '-1002627799078',
      process.env.TELEGRAM_CHANNEL_SECONDARY || process.env.TG_CHANNEL_2 || '-1003910695659',
      process.env.TELEGRAM_CHANNEL_ALERTS || process.env.TG_CHANNEL_3 || '-1003940794962',
    ];
    const memberStatus = await verifyTelegramMembership(telegramId, channels);
    // verifyAllChannels returns { allJoined, channels } — use allJoined directly
    const allJoined = memberStatus.allJoined === true;

    if (!allJoined) {
      recordFailedAttempt(telegramId);
      await logAuditEvent('FAIL_CHANNELS_NOT_JOINED', {
        claimId,
        telegramId,
        severity: 'warn',
      });

      // Release the ticket lock
      const collection = await getClaimTicketsCollection();
      await collection.updateOne(
        { claimId },
        { $set: { used: false } }
      ).catch(() => {});

      // Release Redis used flag
      const redis = await getRedisClient();
      if (redis) {
        await redis.del(REDIS_KEY.CLAIM_USED(claimId)).catch(() => {});
      }

      throw new RevealError('All 3 Telegram channels must be joined', 'CHANNELS_NOT_JOINED', 403);
    }
  } catch (err) {
    // If it's already a RevealError, re-throw
    if (err instanceof RevealError) throw err;

    // BUG 2 FIX: In production, Telegram verification failure = BLOCK
    // Only skip in development/testing
    if (process.env.NODE_ENV === 'production') {
      await logAuditEvent('TELEGRAM_VERIFY_FAILED', {
        claimId,
        telegramId,
        reason: err.message,
        severity: 'critical',
      });
      throw new RevealError('Telegram verification failed', 'CHANNEL_VERIFY_FAILED', 403);
    }

    // Dev only: log but don't block
    await logAuditEvent('TELEGRAM_VERIFY_SKIPPED', {
      claimId,
      telegramId,
      reason: err.message,
      severity: 'info',
    });
  }

  // ───────────────────────────────────────────────────────────────────────────
  // LAYER 8.5: Replay Protection — Mark nonce as seen (AFTER all checks pass)
  // CRITICAL: Nonce is only burned here, AFTER timelock and all other checks.
  // If we burned it earlier and the user hit "reveal" before timer expiry,
  // the nonce would be consumed and they couldn't retry after the timer.
  // ───────────────────────────────────────────────────────────────────────────
  const isNewNonce = await trackNonceForReplayProtection(nonce);
  if (!isNewNonce) {
    recordFailedAttempt(telegramId);
    await logAuditEvent('FAIL_REPLAY_DETECTED', {
      claimId,
      telegramId,
      replayNonce: nonce,
      severity: 'critical',
    });
    // Release the ticket lock so a fresh request can be made
    const collection = await getClaimTicketsCollection();
    await collection.updateOne(
      { claimId },
      { $set: { used: false } }
    ).catch(() => {});
    const redis = await getRedisClient();
    if (redis) {
      await redis.del(REDIS_KEY.CLAIM_USED(claimId)).catch(() => {});
    }
    throw new RevealError(
      'Request already processed',
      'CLAIM_REUSED',
      409,
      { message: 'Claim already consumed' }
    );
  }

  // ───────────────────────────────────────────────────────────────────────────
  // LAYER 9: Retrieve and decrypt code (Rule 6: decryptString ONLY here)
  // At this point ALL checks passed. We now fetch the encrypted code field
  // and decrypt it. This is the ONLY place decryptString is called.
  // ───────────────────────────────────────────────────────────────────────────
  let encryptedCodeBlob = null;
  try {
    // Fetch ONLY the encrypted code blob - we already have metadata
    const codeDoc = await dbManager.findOne(
      'gift_codes',
      { _id: codeMetaDoc._id },
      { projection: { code: 1, _id: 1 } }
    );

    if (!codeDoc || !codeDoc.code) {
      throw new RevealError('Code data corrupted', 'CODE_DATA_ERROR', 500);
    }

    encryptedCodeBlob = codeDoc.code;
  } catch (err) {
    recordFailedAttempt(telegramId);
    await logAuditEvent('FAIL_CODE_FETCH_ERROR', {
      claimId,
      telegramId,
      codeId: codeMetaDoc._id.toString(),
      severity: 'error',
    });
    throw new RevealError('Failed to retrieve code data', 'CODE_FETCH_ERROR', 500);
  }

  // ── decryptString: THE ONLY PLACE THIS IS CALLED (Rule 6) ──
  let plaintextCode = null;
  try {
    plaintextCode = decryptString(encryptedCodeBlob);
  } catch (err) {
    recordFailedAttempt(telegramId);
    await logAuditEvent('FAIL_DECRYPT_ERROR', {
      claimId,
      telegramId,
      codeId: codeMetaDoc._id.toString(),
      severity: 'critical',
    });
    throw new RevealError('Failed to decrypt code', 'DECRYPT_ERROR', 500);
  }

  // Validate decrypted code
  if (!plaintextCode || typeof plaintextCode !== 'string') {
    recordFailedAttempt(telegramId);
    await logAuditEvent('FAIL_INVALID_CODE_DATA', {
      claimId,
      telegramId,
      codeId: codeMetaDoc._id.toString(),
      severity: 'critical',
    });
    throw new RevealError('Invalid code data', 'INVALID_CODE_DATA', 500);
  }

  // ───────────────────────────────────────────────────────────────────────────
  // LAYER 10: Atomically track per-user claim (code remains active for ALL)
  // CRITICAL FIX (Bug 6): Instead of marking the gift_code as "claimed"
  // (which makes it inactive for everyone), we track per-user claims in
  // a separate `code_claims` collection. ONE code for ALL users.
  // ───────────────────────────────────────────────────────────────────────────
  try {
    const now = new Date();
    const claimDate = now.toISOString().split('T')[0]; // "2024-01-15"
    const codeIdStr = codeMetaDoc._id.toString();

    // BUG 7/9 FIX: Atomic insertOne prevents duplicate reveal race
    // Unique index {telegramId, codeId, claimDate} ensures only one claim per user per code per day
    // Two parallel requests: first insertOne succeeds, second gets 11000 duplicate error
    try {
      await dbManager.insertOne('code_claims', {
        telegramId, codeId: codeIdStr, claimDate, claimedAt: now, claimId,
      });
    } catch (err) {
      if (err.code === 11000 || err.message?.includes('duplicate')) {
        throw new RevealError('You already claimed this code today', 'ALREADY_CLAIMED', 429);
      }
      throw err; // Re-throw non-duplicate errors
    }
  } catch (err) {
    if (err instanceof RevealError) throw err;
    if (err.code === 11000 || err.message?.includes('duplicate')) {
      throw new RevealError('You already claimed this code today', 'ALREADY_CLAIMED', 429);
    } else {
      await logAuditEvent('FAIL_CODE_CLAIM_DB_ERROR', {
        claimId,
        telegramId,
        codeId: codeMetaDoc._id.toString(),
        severity: 'error',
      });
      throw new RevealError('Failed to record claim', 'CLAIM_DB_ERROR', 500);
    }
  }

  // ───────────────────────────────────────────────────────────────────────────
  // LAYER 11: Record successful reveal for rate limiting
  // ───────────────────────────────────────────────────────────────────────────
  recordSuccessfulReveal(telegramId);

  const codeLength = plaintextCode.length;
  const expirySeconds = codeMetaDoc.expirySeconds || 15;

  // ───────────────────────────────────────────────────────────────────────────
  // AUDIT: Log successful delivery (NEVER log the actual code - Rule 7)
  // We log codeLength and codeId only.
  // ───────────────────────────────────────────────────────────────────────────
  await logAuditEvent('CODE_DELIVERED', {
    claimId,
    telegramId,
    deviceId,
    codeId: codeMetaDoc._id.toString(),
    codeLength,          // e.g., 32 — NEVER the actual code
    expirySeconds,
    redisAvailable: isRedisReady(),
    severity: 'info',
  });

  // ───────────────────────────────────────────────────────────────────────────
  // RETURN: Code delivered (success response format per spec)
  // ───────────────────────────────────────────────────────────────────────────
  return {
    success: true,
    code: plaintextCode,      // Actual code ONLY returned here, never logged
    codeLength,               // 32 — logged, safe
    expirySeconds,            // e.g., 15
  };
}

// ============================================================================
// RESPONSE HELPERS (Rule 4: Cache disabled on all responses)
// ============================================================================

/**
 * Build a success response object with no-cache headers attached.
 * Enhanced per security spec with Expires: -1 and Vary headers.
 *
 * @param {import('express').Response} res - Express response
 * @param {Object} data - Response data
 * @returns {import('express').Response}
 */
export function sendRevealSuccess(res, data) {
  for (const [header, value] of Object.entries(NO_CACHE_HEADERS)) {
    res.setHeader(header, value);
  }
  return res.status(200).json({
    success: true,
    ...data,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Build an error response object with no-cache headers attached.
 * NEVER includes the actual code.
 *
 * @param {import('express').Response} res - Express response
 * @param {RevealError} error - RevealError instance
 * @returns {import('express').Response}
 */
export function sendRevealError(res, error) {
  for (const [header, value] of Object.entries(NO_CACHE_HEADERS)) {
    res.setHeader(header, value);
  }

  const response = {
    success: false,
    error: error.code || 'UNKNOWN_ERROR',
    message: error.message,
    timestamp: new Date().toISOString(),
  };

  // Add extra fields if present (e.g., remainingSeconds, retryAfter)
  if (error.extra && typeof error.extra === 'object') {
    Object.assign(response, error.extra);
  }

  return res.status(error.statusCode || 400).json(response);
}

// ============================================================================
// EXPRESS ROUTE HANDLER
// ============================================================================

/**
 * Express route handler for POST /api/v1/code/reveal
 * Wraps revealCode() with proper HTTP response formatting.
 *
 * @param {import('express').Request} req - Express request
 * @param {import('express').Response} res - Express response
 */
export async function handleCodeReveal(req, res) {
  try {
    const { sessionToken, claimId, nonce, telegramId, deviceId, powSolution, behavioralScore } = req.body || {};

    const result = await revealCode({
      sessionToken,
      claimId,
      nonce,
      telegramId,
      deviceId,
      powSolution,
      behavioralScore,
    });

    return sendRevealSuccess(res, result);
  } catch (err) {
    // Log the error with sanitized data (Rule 7)
    const sanitized = buildLogContext({
      ...(req.body?.claimId ? { claimId: req.body.claimId } : {}),
      ...(req.body?.telegramId ? { telegramId: req.body.telegramId } : {}),
      ...(req.body?.deviceId ? { deviceId: req.body.deviceId } : {}),
    });

    // Log error code and message, NEVER the code itself
    await logAuditEvent('REQUEST_ERROR', {
      ...sanitized,
      errorCode: err.code || 'UNKNOWN',
      errorMessage: err.message,
      severity: 'error',
    });

    if (err instanceof RevealError) {
      return sendRevealError(res, err);
    }

    // Unknown error - generic response (don't leak internal details)
    return sendRevealError(
      res,
      new RevealError('Code reveal failed', 'REVEAL_FAILED', 500)
    );
  }
}

// ============================================================================
// UTILITY EXPORTS
// ============================================================================

/**
 * Check if a user has already claimed a code today.
 * Used by the claim flow to prevent duplicate claims.
 *
 * @param {string} telegramId - Telegram user ID
 * @returns {Promise<boolean>}
 */
export async function hasClaimedToday(telegramId) {
  if (!telegramId || typeof telegramId !== 'string') {
    return false;
  }

  try {
    const dbManager = DatabaseManager.getInstance();
    const claimDate = new Date().toISOString().split('T')[0]; // "2024-01-15"

    // Check code_claims collection for per-user daily claim tracking
    const claimed = await dbManager.findOne(
      'code_claims',
      {
        telegramId,
        claimDate,
      },
      { projection: { _id: 1 } }
    );

    return !!claimed;
  } catch (err) {
    // BUG 8 FIX: Don't fail open — DB error = claim blocked
    // This prevents bypassing daily claim limit when DB is down
    console.error('[HAS_CLAIMED_TODAY] DB error:', err.message);
    throw new RevealError(
      'Unable to verify claim status. Please try again.',
      'CLAIM_CHECK_ERROR',
      503
    );
  }
}

/**
 * Get current rate limit status for a telegramId.
 * Used by the frontend to show remaining attempts.
 *
 * @param {string} telegramId - Telegram user ID
 * @returns {{reveals: {remaining: number, max: number}, failed: {remaining: number, max: number}}}
 */
export function getRateLimitStatus(telegramId) {
  const revealStatus = checkRevealRateLimit(telegramId);
  const failedStatus = checkFailedAttemptRateLimit(telegramId);

  return {
    reveals: {
      remaining: Math.max(0, MAX_REVEALS_PER_HOUR - revealStatus.count),
      max: MAX_REVEALS_PER_HOUR,
    },
    failed: {
      remaining: Math.max(0, MAX_FAILED_ATTEMPTS_PER_HOUR - failedStatus.count),
      max: MAX_FAILED_ATTEMPTS_PER_HOUR,
    },
  };
}

/**
 * Purge all in-memory rate limit data.
 * Useful for testing or admin operations.
 */
export function purgeRateLimitData() {
  revealRateLimitStore.clear();
  failedAttemptStore.clear();
}

// ============================================================================
// DEFAULT EXPORT
// ============================================================================

export default {
  generateClaimTicket,
  revealCode,
  handleCodeReveal,
  hasClaimedToday,
  getRateLimitStatus,
  purgeRateLimitData,
  sendRevealSuccess,
  sendRevealError,
  initializeClaimIndexes,
};