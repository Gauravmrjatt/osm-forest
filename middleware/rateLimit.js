/**
 * @fileoverview Advanced Rate Limiting Middleware for Osm Army Gift Code Fortress.
 * Implements sliding window, token bucket, fixed window, and distributed (MongoDB-backed)
 * rate limiting algorithms with progressive penalties, per-identifier tracking, and
 * comprehensive header injection.
 *
 * @module middleware/rateLimit
 * @version 5.0.0
 * @license MIT
 */

'use strict';

import { createHash, randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';

// ---------------------------------------------------------------------------
// Custom Error Classes
// ---------------------------------------------------------------------------

/**
 * Base error for rate limiter operations.
 * @extends Error
 */
export class RateLimitError extends Error {
  /**
   * @param {string} message
   * @param {string} code
   * @param {number} statusCode
   * @param {Object} [extra={}]
   */
  constructor(message, code, statusCode, extra = {}) {
    super(message);
    this.name = 'RateLimitError';
    this.code = code;
    this.statusCode = statusCode;
    Object.assign(this, extra);
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Thrown when a request exceeds the rate limit.
 * @extends RateLimitError
 */
export class RateLimitExceededError extends RateLimitError {
  /**
   * @param {string} identifier
   * @param {number} retryAfter
   * @param {Object} [extra={}]
   */
  constructor(identifier, retryAfter, extra = {}) {
    super(
      `Rate limit exceeded for identifier: ${identifier}. Retry after ${retryAfter} seconds.`,
      'RATE_LIMIT_EXCEEDED',
      429,
      { identifier, retryAfter, ...extra }
    );
    this.name = 'RateLimitExceededError';
  }
}

// ---------------------------------------------------------------------------
// Utility Helpers
// ---------------------------------------------------------------------------

/**
 * Hash an identifier to a consistent key string.
 * @param {string} identifier
 * @returns {string} SHA-256 hex digest
 */
function hashIdentifier(identifier) {
  return createHash('sha256').update(String(identifier)).digest('hex');
}

/**
 * Get current Unix timestamp in milliseconds.
 * @returns {number}
 */
function nowMs() {
  return Date.now();
}

/**
 * Sleep for a given number of milliseconds.
 * @param {number} ms
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Default Configuration (mirrors config.js values)
// ---------------------------------------------------------------------------

const DEFAULT_POLICIES = Object.freeze({
  default:        { windowMs: 60_000, maxRequests: 100 },
  strict:         { windowMs: 60_000, maxRequests: 10 },
  api:            { windowMs: 60_000, maxRequests: 30 },
  claim:          { windowMs: 86_400_000, maxRequests: 3 },
  login:          { windowMs: 3_600_000, maxRequests: 5 },
  admin:          { windowMs: 60_000, maxRequests: 60 },

  // ── Category 6: Endpoint-specific policies ──
  timer_status:   { windowMs: 60_000, maxRequests: 30, description: 'GET /api/v1/timer-status' },
  code_claim:     { windowMs: 60_000, maxRequests: 10,  description: 'POST /api/v1/code/claim' },
  code_reveal:    { windowMs: 60_000, maxRequests: 5,   description: 'POST /api/v1/code/reveal (per IP)' },
  code_reveal_hourly: { windowMs: 3_600_000, maxRequests: 5, description: 'POST /api/v1/code/reveal (per telegram, hourly)' },
  pow:            { windowMs: 60_000, maxRequests: 20,  description: 'POST /api/v1/pow/*' },
  behavior:       { windowMs: 60_000, maxRequests: 10,  description: 'POST /api/v1/behavior/*' },
});

/**
 * Resolve a policy name or object to a full configuration.
 * @param {string|Object} policy
 * @returns {Object}
 */
function resolvePolicy(policy) {
  if (typeof policy === 'string') {
    const key = policy.toLowerCase().trim();
    if (!DEFAULT_POLICIES[key]) {
      throw new RateLimitError(
        `Unknown rate limit policy: ${policy}`,
        'UNKNOWN_POLICY',
        500
      );
    }
    return { ...DEFAULT_POLICIES[key], name: key };
  }
  if (typeof policy === 'object' && policy !== null) {
    return {
      windowMs: policy.windowMs || policy.window || 60_000,
      maxRequests: policy.maxRequests || policy.max || 100,
      name: policy.name || 'custom',
      ...policy,
    };
  }
  throw new RateLimitError(
    'Invalid rate limit policy',
    'INVALID_POLICY',
    500
  );
}

// ---------------------------------------------------------------------------
// MongoDB Collection Wrapper (distributed storage)
// ---------------------------------------------------------------------------

/**
 * Thin MongoDB wrapper for distributed rate-limit storage.
 * Expects the native MongoDB driver db instance.
 */
class MongoRateLimitStore {
  /**
   * @param {import('mongodb').Db} db
   * @param {string} [collectionName='rate_limits']
   */
  constructor(db, collectionName = 'rate_limits') {
    this.db = db;
    this.collectionName = collectionName;
    /** @type {import('mongodb').Collection|null} */
    this.collection = null;
    this.initialized = false;
  }

  /**
   * Initialise the collection and TTL index.
   * @returns {Promise<void>}
   */
  async init() {
    if (this.initialized || !this.db) return;
    this.collection = this.db.collection(this.collectionName);
    await this.collection.createIndex(
      { expiresAt: 1 },
      { expireAfterSeconds: 0, background: true, name: 'ttl_expiresAt' }
    );
    await this.collection.createIndex(
      { key: 1, policy: 1 },
      { background: true, name: 'key_policy_lookup' }
    );
    await this.collection.createIndex(
      { identifier: 1, createdAt: -1 },
      { background: true, name: 'identifier_createdAt' }
    );
    this.initialized = true;
  }

  /**
   * Fetch the current hit document for a key.
   * @param {string} key
   * @param {string} policy
   * @returns {Promise<Object|null>}
   */
  async get(key, policy) {
    if (!this.collection) return null;
    const doc = await this.collection.findOne(
      { key, policy },
      { projection: { _id: 0 } }
    );
    if (!doc) return null;
    return {
      ...doc,
      createdAt: doc.createdAt instanceof Date ? doc.createdAt.getTime() : doc.createdAt,
      expiresAt: doc.expiresAt instanceof Date ? doc.expiresAt.getTime() : doc.expiresAt,
    };
  }

  /**
   * Upsert a hit document.
   * @param {string} key
   * @param {string} policy
   * @param {Object} data
   * @returns {Promise<void>}
   */
  async set(key, policy, data) {
    if (!this.collection) return;
    const expiresAt = new Date(data.expiresAt || Date.now() + 86_400_000);
    await this.collection.updateOne(
      { key, policy },
      {
        $set: {
          ...data,
          key,
          policy,
          expiresAt,
          updatedAt: new Date(),
        },
      },
      { upsert: true }
    );
  }

  /**
   * Atomically increment the counter for a key.
   * @param {string} key
   * @param {string} policy
   * @param {number} windowMs
   * @returns {Promise<number>} New count
   */
  async increment(key, policy, windowMs) {
    if (!this.collection) return 1;
    const expiresAt = new Date(Date.now() + windowMs);
    const result = await this.collection.findOneAndUpdate(
      { key, policy },
      {
        $inc: { count: 1 },
        $setOnInsert: {
          key,
          policy,
          createdAt: new Date(),
          expiresAt,
        },
        $set: { updatedAt: new Date() },
      },
      { upsert: true, returnDocument: 'after' }
    );
    return (result && result.count) || 1;
  }

  /**
   * Add a timestamp to the sliding-window hits array.
   * @param {string} key
   * @param {string} policy
   * @param {number} ts
   * @param {number} windowMs
   * @returns {Promise<number>} Count of timestamps in window
   */
  async pushTimestamp(key, policy, ts, windowMs) {
    if (!this.collection) return 1;
    const expiresAt = new Date(ts + windowMs);
    await this.collection.updateOne(
      { key, policy },
      {
        $push: { hits: ts },
        $setOnInsert: {
          key,
          policy,
          createdAt: new Date(),
          expiresAt,
        },
        $set: { updatedAt: new Date() },
      },
      { upsert: true }
    );
    // Pull stale timestamps
    const cutoff = ts - windowMs;
    await this.collection.updateOne(
      { key, policy },
      { $pull: { hits: { $lt: cutoff } } }
    );
    const doc = await this.collection.findOne(
      { key, policy },
      { projection: { hits: 1, _id: 0 } }
    );
    return doc && Array.isArray(doc.hits) ? doc.hits.length : 1;
  }

  /**
   * Remove a document.
   * @param {string} key
   * @param {string} policy
   * @returns {Promise<void>}
   */
  async del(key, policy) {
    if (!this.collection) return;
    await this.collection.deleteOne({ key, policy });
  }

  /**
   * Clear the entire collection (use with caution).
   * @returns {Promise<void>}
   */
  async clear() {
    if (!this.collection) return;
    await this.collection.deleteMany({});
  }
}

// ---------------------------------------------------------------------------
// In-Memory Store (for single-instance or fallback)
// ---------------------------------------------------------------------------

class MemoryRateLimitStore {
  constructor() {
    /** @type {Map<string, Object>} */
    this.data = new Map();
    /** @type {Map<string, number[]>} */
    this.hits = new Map();
    this.lastCleanup = Date.now();
  }

  _key(key, policy) {
    return `${policy}::${key}`;
  }

  _cleanupIfNeeded() {
    const now = Date.now();
    if (now - this.lastCleanup < 60_000) return;
    this.lastCleanup = now;
    for (const [k, v] of this.data) {
      if (v.expiresAt && v.expiresAt < now) {
        this.data.delete(k);
        this.hits.delete(k);
      }
    }
  }

  /**
   * @param {string} key
   * @param {string} policy
   * @returns {Object|null}
   */
  get(key, policy) {
    this._cleanupIfNeeded();
    return this.data.get(this._key(key, policy)) || null;
  }

  /**
   * @param {string} key
   * @param {string} policy
   * @param {Object} data
   */
  set(key, policy, data) {
    this.data.set(this._key(key, policy), { ...data });
  }

  /**
   * @param {string} key
   * @param {string} policy
   * @param {number} windowMs
   * @returns {number}
   */
  increment(key, policy, windowMs) {
    this._cleanupIfNeeded();
    const k = this._key(key, policy);
    const existing = this.data.get(k);
    if (!existing || (existing.expiresAt && existing.expiresAt < Date.now())) {
      const doc = {
        count: 1,
        createdAt: Date.now(),
        expiresAt: Date.now() + windowMs,
      };
      this.data.set(k, doc);
      return 1;
    }
    existing.count = (existing.count || 0) + 1;
    return existing.count;
  }

  /**
   * @param {string} key
   * @param {string} policy
   * @param {number} ts
   * @param {number} windowMs
   * @returns {number}
   */
  pushTimestamp(key, policy, ts, windowMs) {
    this._cleanupIfNeeded();
    const k = this._key(key, policy);
    let arr = this.hits.get(k);
    if (!arr) {
      arr = [];
      this.hits.set(k, arr);
    }
    const cutoff = ts - windowMs;
    // Remove stale entries
    const idx = arr.findIndex((t) => t >= cutoff);
    const cleaned = idx === -1 ? [] : arr.slice(idx);
    cleaned.push(ts);
    this.hits.set(k, cleaned);
    return cleaned.length;
  }

  /**
   * @param {string} key
   * @param {string} policy
   */
  del(key, policy) {
    const k = this._key(key, policy);
    this.data.delete(k);
    this.hits.delete(k);
  }

  clear() {
    this.data.clear();
    this.hits.clear();
  }
}

// ---------------------------------------------------------------------------
// Penalty Tracker
// ---------------------------------------------------------------------------

/**
 * Tracks progressive penalties per identifier.
 */
class PenaltyTracker {
  /**
   * @param {MemoryRateLimitStore|MongoRateLimitStore} store
   */
  constructor(store) {
    this.store = store;
  }

  _penaltyKey(identifier) {
    return `penalty::${hashIdentifier(identifier)}`;
  }

  /**
   * Record a violation and return the current penalty tier.
   * @param {string} identifier
   * @param {number} now
   * @returns {Promise<{tier:number,multiplier:number,durationMs:number,blocked:boolean}>}
   */
  async recordViolation(identifier, now = nowMs()) {
    const key = this._penaltyKey(identifier);
    const existing = await this.store.get(key, '__penalty__');

    let violations = 1;
    let firstAt = now;
    let blockedUntil = 0;
    let tier = 1;

    if (existing) {
      violations = (existing.violations || 0) + 1;
      firstAt = existing.firstAt || now;
    }

    // Determine tier based on consecutive violations
    if (violations === 1) tier = 1;
    else if (violations === 2) tier = 2;
    else if (violations === 3) tier = 3;
    else if (violations === 4) tier = 4;
    else tier = 5;

    const multipliers = { 1: 1, 2: 2, 3: 4, 4: 8, 5: Infinity };
    const durations = {
      1: 0,
      2: 3_600_000,    // 1 hour
      3: 14_400_000,   // 4 hours
      4: 86_400_000,   // 24 hours
      5: Infinity,
    };

    const multiplier = multipliers[tier];
    const durationMs = durations[tier];
    const blocked = tier >= 5 || (durationMs > 0 && now < (existing?.blockedUntil || 0));
    blockedUntil = durationMs === Infinity ? Infinity : now + durationMs;

    await this.store.set(key, '__penalty__', {
      identifier: hashIdentifier(identifier),
      violations,
      firstAt,
      lastAt: now,
      tier,
      blockedUntil,
      expiresAt: now + 86_400_000 * 7, // Keep for 7 days
    });

    return { tier, multiplier, durationMs, blocked, blockedUntil };
  }

  /**
   * Get current penalty info for an identifier.
   * @param {string} identifier
   * @returns {Promise<Object|null>}
   */
  async getPenalty(identifier) {
    const key = this._penaltyKey(identifier);
    const existing = await this.store.get(key, '__penalty__');
    if (!existing) return null;
    return {
      violations: existing.violations || 0,
      tier: existing.tier || 0,
      blockedUntil: existing.blockedUntil || 0,
      lastAt: existing.lastAt || 0,
    };
  }

  /**
   * Check if identifier is currently blocked.
   * @param {string} identifier
   * @param {number} now
   * @returns {Promise<boolean>}
   */
  async isBlocked(identifier, now = nowMs()) {
    const penalty = await this.getPenalty(identifier);
    if (!penalty) return false;
    if (penalty.tier >= 5) return true;
    if (penalty.blockedUntil && now < penalty.blockedUntil) return true;
    return false;
  }

  /**
   * Reset penalties for an identifier (e.g., after admin review).
   * @param {string} identifier
   * @returns {Promise<void>}
   */
  async reset(identifier) {
    const key = this._penaltyKey(identifier);
    await this.store.del(key, '__penalty__');
  }
}

// ---------------------------------------------------------------------------
// Rate Limiter Engine
// ---------------------------------------------------------------------------

/**
 * Core rate limiter that supports multiple algorithms.
 */
export class RateLimiter extends EventEmitter {
  /**
   * @param {Object} [options={}]
   * @param {import('mongodb').Db|null} [options.db] MongoDB database instance
   * @param {boolean} [options.distributed=false] Use MongoDB backend
   * @param {string} [options.algorithm='sliding_window'] sliding_window | token_bucket | fixed_window
   * @param {Object} [options.policy=DEFAULT_POLICIES.default]
   * @param {string[]|null} [options.whitelist=null] Array of whitelisted IPs
   * @param {boolean} [options.headersOnly=false] Track but don't block
   * @param {boolean} [options.skipSuccessfulRequests=false]
   * @param {boolean} [options.skipFailedRequests=false]
   * @param {Function|null} [options.keyGenerator=null] Custom key extractor
   * @param {Function|null} [options.skipFunction=null] Custom skip logic
   * @param {string} [options.collectionName='rate_limits']
   */
  constructor(options = {}) {
    super();
    this.algorithm = (options.algorithm || 'sliding_window').toLowerCase();
    this.policy = resolvePolicy(options.policy || 'default');
    this.whitelist = new Set(options.whitelist || []);
    this.headersOnly = !!options.headersOnly;
    this.skipSuccessfulRequests = !!options.skipSuccessfulRequests;
    this.skipFailedRequests = !!options.skipFailedRequests;
    this.keyGenerator = typeof options.keyGenerator === 'function' ? options.keyGenerator : null;
    this.skipFunction = typeof options.skipFunction === 'function' ? options.skipFunction : null;
    this.distributed = !!options.distributed && !!options.db;

    // Token bucket specific state
    this.tokenBuckets = new Map();

    // Burst bucket: allow N requests in a short window before rate limiting kicks in
    this.burstConfig = options.burst || null; // { windowMs: 10000, maxRequests: 5 }
    this.burstBuckets = new Map();

    // Storage backend
    if (this.distributed && options.db) {
      this.store = new MongoRateLimitStore(options.db, options.collectionName || 'rate_limits');
    } else {
      this.store = new MemoryRateLimitStore();
    }

    this.penaltyTracker = new PenaltyTracker(this.store);
    this.initialized = false;
  }

  /**
   * Initialise the store (required before first use).
   * @returns {Promise<void>}
   */
  async init() {
    if (this.initialized) return;
    if (this.store instanceof MongoRateLimitStore) {
      await this.store.init();
    }
    this.initialized = true;
  }

  /**
   * Alias for init().
   * @param {...*} args
   * @returns {Promise<void>}
   */
  initialize(...args) { return this.init(...args); }

  /**
   * Build a composite key from the request and identifiers.
   * @param {import('express').Request} req
   * @param {Object} identifiers
   * @returns {string}
   */
  buildKey(req, identifiers = {}) {
    if (this.keyGenerator) {
      return this.keyGenerator(req, identifiers);
    }
    const parts = [];
    if (identifiers.ip) parts.push(`ip:${identifiers.ip}`);
    if (identifiers.device) parts.push(`dev:${hashIdentifier(identifiers.device)}`);
    if (identifiers.userId) parts.push(`usr:${identifiers.userId}`);
    if (identifiers.endpoint) parts.push(`ep:${identifiers.endpoint}`);
    if (parts.length === 0) {
      const ip = req.ip || req.connection?.remoteAddress || 'unknown';
      parts.push(`ip:${ip}`);
    }
    return parts.join('|');
  }

  /**
   * Determine if this request should be skipped.
   * @param {import('express').Request} req
   * @returns {Promise<boolean>}
   */
  async shouldSkip(req) {
    // Whitelist check
    const ip = req.ip || req.connection?.remoteAddress || '';
    if (this.whitelist.has(ip)) return true;
    if (this.whitelist.has(req.headers['x-forwarded-for']?.split(',')[0]?.trim())) return true;

    // Custom skip function
    if (this.skipFunction) {
      try {
        const result = await this.skipFunction(req);
        if (result) return true;
      } catch {
        // Ignore skip function errors
      }
    }
    return false;
  }

  /**
   * Sliding Window algorithm: count requests in the current time window.
   * @param {string} key
   * @param {number} windowMs
   * @param {number} maxRequests
   * @param {number} ts
   * @returns {Promise<{allowed:boolean,remaining:number,resetTime:number,currentUsage:number}>}
   */
  async slidingWindow(key, windowMs, maxRequests, ts = nowMs()) {
    const count = await this.store.pushTimestamp(key, this.policy.name, ts, windowMs);
    const allowed = count <= maxRequests;
    const resetTime = ts + windowMs;
    return {
      allowed,
      remaining: Math.max(0, maxRequests - count),
      resetTime,
      currentUsage: count,
    };
  }

  /**
   * Token Bucket algorithm: tokens refill at a constant rate.
   * @param {string} key
   * @param {number} windowMs
   * @param {number} maxRequests
   * @param {number} ts
   * @returns {Promise<{allowed:boolean,remaining:number,resetTime:number,currentUsage:number}>}
   */
  async tokenBucket(key, windowMs, maxRequests, ts = nowMs()) {
    const bucketKey = `tb::${key}::${this.policy.name}`;
    let bucket = this.tokenBuckets.get(bucketKey);
    if (!bucket) {
      bucket = { tokens: maxRequests, lastRefill: ts };
      this.tokenBuckets.set(bucketKey, bucket);
    }

    // Refill tokens based on elapsed time
    const elapsed = ts - bucket.lastRefill;
    const refillRate = maxRequests / windowMs; // tokens per ms
    const tokensToAdd = elapsed * refillRate;
    bucket.tokens = Math.min(maxRequests, bucket.tokens + tokensToAdd);
    bucket.lastRefill = ts;

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      const resetTime = ts + Math.ceil((1 - bucket.tokens) / refillRate);
      return {
        allowed: true,
        remaining: Math.floor(bucket.tokens),
        resetTime,
        currentUsage: maxRequests - Math.floor(bucket.tokens),
      };
    }

    const resetTime = ts + Math.ceil((1 - bucket.tokens) / refillRate);
    return {
      allowed: false,
      remaining: 0,
      resetTime,
      currentUsage: maxRequests,
    };
  }

  /**
   * Fixed Window algorithm: simple counter per time period.
   * @param {string} key
   * @param {number} windowMs
   * @param {number} maxRequests
   * @param {number} ts
   * @returns {Promise<{allowed:boolean,remaining:number,resetTime:number,currentUsage:number}>}
   */
  async fixedWindow(key, windowMs, maxRequests, ts = nowMs()) {
    const windowIndex = Math.floor(ts / windowMs);
    const windowKey = `${key}::${this.policy.name}::${windowIndex}`;
    const count = await this.store.increment(windowKey, 'fixed_window', windowMs);
    const resetTime = (windowIndex + 1) * windowMs;
    return {
      allowed: count <= maxRequests,
      remaining: Math.max(0, maxRequests - count),
      resetTime,
      currentUsage: count,
    };
  }

  /**
   * Burst Bucket: allow a short burst of requests before rate limiting.
   * e.g. { windowMs: 10000, maxRequests: 5 } → allow 5 requests in 10 seconds.
   * Returns { withinBurst: boolean, burstRemaining: number }.
   * @param {string} key
   * @param {number} ts
   * @returns {{withinBurst: boolean, burstRemaining: number}}
   */
  checkBurstBucket(key, ts = nowMs()) {
    if (!this.burstConfig) return { withinBurst: true, burstRemaining: Infinity };

    const bucketKey = `burst::${key}::${this.policy.name}`;
    let bucket = this.burstBuckets.get(bucketKey);

    if (!bucket) {
      bucket = { tokens: this.burstConfig.maxRequests, lastRefill: ts };
      this.burstBuckets.set(bucketKey, bucket);
    }

    // Refill tokens
    const elapsed = ts - bucket.lastRefill;
    const refillRate = this.burstConfig.maxRequests / this.burstConfig.windowMs;
    const tokensToAdd = elapsed * refillRate;
    bucket.tokens = Math.min(this.burstConfig.maxRequests, bucket.tokens + tokensToAdd);
    bucket.lastRefill = ts;

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return { withinBurst: true, burstRemaining: Math.floor(bucket.tokens) };
    }

    return { withinBurst: false, burstRemaining: 0 };
  }

  /**
   * Apply progressive penalty multiplier to limits.
   * @param {string} identifier
   * @returns {Promise<{maxRequests:number,windowMs:number,penaltyInfo:Object|null}>}
   */
  async applyPenalty(identifier) {
    const penalty = await this.penaltyTracker.getPenalty(identifier);
    let maxRequests = this.policy.maxRequests;
    let windowMs = this.policy.windowMs;

    if (penalty && penalty.tier > 1) {
      const multipliers = { 2: 2, 3: 4, 4: 8, 5: Infinity };
      const m = multipliers[penalty.tier] || 1;
      if (m === Infinity) {
        maxRequests = 0;
      } else {
        maxRequests = Math.max(1, Math.floor(maxRequests / m));
        windowMs = windowMs * m;
      }
    }

    return { maxRequests, windowMs, penaltyInfo: penalty };
  }

  /**
   * Check if a request is allowed under the rate limit.
   * @param {import('express').Request} req
   * @param {Object} [identifiers={}]
   * @returns {Promise<{allowed:boolean,limit:number,remaining:number,resetTime:number,retryAfter:number,currentUsage:number,penaltyInfo:Object|null}>}
   */
  async check(req, identifiers = {}) {
    await this.init();

    if (await this.shouldSkip(req)) {
      return {
        allowed: true,
        limit: this.policy.maxRequests,
        remaining: this.policy.maxRequests,
        resetTime: Date.now() + this.policy.windowMs,
        retryAfter: 0,
        currentUsage: 0,
        penaltyInfo: null,
      };
    }

    const key = this.buildKey(req, identifiers);
    const ts = nowMs();

    // Check progressive penalties
    const primaryId = identifiers.ip ||
      req.ip ||
      req.connection?.remoteAddress ||
      'unknown';
    const isBlocked = await this.penaltyTracker.isBlocked(primaryId, ts);
    if (isBlocked) {
      this.emit('blocked', { identifier: primaryId, key, req });
      return {
        allowed: false,
        limit: 0,
        remaining: 0,
        resetTime: ts + 86_400_000,
        retryAfter: 86_400,
        currentUsage: Infinity,
        penaltyInfo: await this.penaltyTracker.getPenalty(primaryId),
      };
    }

    const { maxRequests, windowMs } = await this.applyPenalty(primaryId);

    // ── Burst bucket check ──
    const burstCheck = this.checkBurstBucket(key, ts);
    if (!burstCheck.withinBurst) {
      // Burst exhausted — record violation and reject
      const penalty = await this.penaltyTracker.recordViolation(primaryId, ts);
      this.emit('burst_exceeded', {
        identifier: primaryId,
        key,
        tier: penalty.tier,
        req,
      });
      return {
        allowed: false,
        limit: maxRequests,
        remaining: 0,
        resetTime: ts + windowMs,
        retryAfter: Math.ceil(windowMs / 1000),
        currentUsage: maxRequests,
        penaltyInfo: await this.penaltyTracker.getPenalty(primaryId),
        burstRemaining: 0,
      };
    }

    let result;
    switch (this.algorithm) {
      case 'token_bucket':
        result = await this.tokenBucket(key, windowMs, maxRequests, ts);
        break;
      case 'fixed_window':
        result = await this.fixedWindow(key, windowMs, maxRequests, ts);
        break;
      case 'sliding_window':
      default:
        result = await this.slidingWindow(key, windowMs, maxRequests, ts);
        break;
    }

    const retryAfter = result.allowed
      ? 0
      : Math.ceil((result.resetTime - ts) / 1000);

    if (!result.allowed) {
      // Record violation for progressive penalties
      const penalty = await this.penaltyTracker.recordViolation(primaryId, ts);
      this.emit('violation', {
        identifier: primaryId,
        key,
        tier: penalty.tier,
        req,
      });
    }

    return {
      allowed: result.allowed || this.headersOnly,
      limit: maxRequests,
      remaining: result.remaining,
      resetTime: result.resetTime,
      retryAfter,
      currentUsage: result.currentUsage,
      penaltyInfo: await this.penaltyTracker.getPenalty(primaryId),
    };
  }

  /**
   * Consume a successful request (decrement remaining).
   * @param {string} key
   * @returns {Promise<void>}
   */
  async consume(key) {
    // For sliding window, the hit is already recorded during check
    // For token bucket, token is already consumed during check
    // For fixed window, count is already incremented during check
    this.emit('consume', { key, policy: this.policy.name });
  }

  /**
   * Reset rate limit for a key.
   * @param {string} key
   * @returns {Promise<void>}
   */
  async reset(key) {
    await this.store.del(key, this.policy.name);
    await this.penaltyTracker.reset(key);
    this.emit('reset', { key, policy: this.policy.name });
  }
}

// ---------------------------------------------------------------------------
// Middleware Factory
// ---------------------------------------------------------------------------

/**
 * Singleton map of limiter instances per policy name.
 * @type {Map<string, RateLimiter>}
 */
const limiterInstances = new Map();

/**
 * Global configuration provider (set once at app startup).
 * @returns {Object}
 */
function getConfig() {
  return {
    RATE_LIMIT_DEFAULT:  { window: 60_000, max: 100 },
    RATE_LIMIT_STRICT:   { window: 60_000, max: 10 },
    RATE_LIMIT_API:      { window: 60_000, max: 30 },
    RATE_LIMIT_CLAIM:    { window: 86_400_000, max: 3 },
    RATE_LIMIT_LOGIN:    { window: 3_600_000, max: 5 },
    RATE_LIMIT_ADMIN:    { window: 60_000, max: 60 },
  };
}

/**
 * Resolve configuration object from name.
 * @param {string|Object} policyNameOrConfig
 * @returns {Object}
 */
function resolveConfig(policyNameOrConfig) {
  const cfg = getConfig();
  if (typeof policyNameOrConfig === 'string') {
    const key = policyNameOrConfig.toLowerCase();
    const map = {
      default: cfg.RATE_LIMIT_DEFAULT,
      strict: cfg.RATE_LIMIT_STRICT,
      api: cfg.RATE_LIMIT_API,
      claim: cfg.RATE_LIMIT_CLAIM,
      login: cfg.RATE_LIMIT_LOGIN,
      admin: cfg.RATE_LIMIT_ADMIN,
    };
    // Check hardcoded config first, then fall back to DEFAULT_POLICIES
    const found = map[key] || DEFAULT_POLICIES[key];
    if (!found) {
      throw new RateLimitError(
        `Unknown policy: ${policyNameOrConfig}`,
        'UNKNOWN_POLICY',
        500
      );
    }
    return { ...found, name: key };
  }
  return { ...policyNameOrConfig, name: policyNameOrConfig.name || 'custom' };
}

/**
 * Create or retrieve a cached RateLimiter for the given policy.
 * @param {string|Object} policy
 * @param {Object} [extraOptions={}]
 * @returns {RateLimiter}
 */
function getLimiter(policy, extraOptions = {}) {
  const resolved = resolveConfig(policy);
  const cacheKey = `${resolved.name}::${extraOptions.algorithm || 'sliding_window'}`;
  if (!limiterInstances.has(cacheKey)) {
    limiterInstances.set(
      cacheKey,
      new RateLimiter({
        policy: resolved,
        algorithm: extraOptions.algorithm || 'sliding_window',
        ...extraOptions,
      })
    );
  }
  return limiterInstances.get(cacheKey);
}

/**
 * Extract identifiers from the Express request.
 * @param {import('express').Request} req
 * @param {Object} options
 * @returns {Object}
 */
function extractIdentifiers(req, options = {}) {
  const identifiers = {};
  if (options.perIp !== false) {
    identifiers.ip = req.ip || req.connection?.remoteAddress || '';
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
      identifiers.ip = forwarded.split(',')[0].trim();
    }
  }
  if (options.perDevice && req.headers['x-device-fingerprint']) {
    identifiers.device = req.headers['x-device-fingerprint'];
  }
  if (options.perUser && (req.user?.id || req.headers['x-user-id'])) {
    identifiers.userId = String(req.user?.id || req.headers['x-user-id']);
  }
  if (options.perEndpoint && req.route?.path) {
    identifiers.endpoint = req.route.path;
  } else if (options.perEndpoint) {
    identifiers.endpoint = req.path;
  }
  return identifiers;
}

/**
 * Set rate limit headers on the response.
 * @param {import('express').Response} res
 * @param {Object} info
 * @param {string} policyName
 */
function setHeaders(res, info, policyName) {
  res.setHeader('X-RateLimit-Limit', String(info.limit));
  res.setHeader('X-RateLimit-Remaining', String(Math.max(0, info.remaining)));
  res.setHeader('X-RateLimit-Reset', String(Math.ceil(info.resetTime / 1000)));
  res.setHeader('X-RateLimit-Policy', policyName);
  if (info.penaltyInfo && info.penaltyInfo.tier > 0) {
    res.setHeader('X-RateLimit-Penalty-Tier', String(info.penaltyInfo.tier));
  }
  if (info.burstRemaining !== undefined) {
    res.setHeader('X-RateLimit-Burst-Remaining', String(info.burstRemaining));
  }
  if (info.retryAfter > 0) {
    res.setHeader('Retry-After', String(info.retryAfter));
  }
}

// ---------------------------------------------------------------------------
// Exported Middleware Functions
// ---------------------------------------------------------------------------

/**
 * Factory: create Express rate-limit middleware for a named policy.
 * @param {string|Object} policy - Policy name or configuration object
 * @param {Object} [options={}] - Extra options
 * @returns {Function} Express middleware (req, res, next)
 */
export function rateLimit(policy, options = {}) {
  const limiter = getLimiter(policy, options);

  /**
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @param {import('express').NextFunction} next
   */
  return async function rateLimitMiddleware(req, res, next) {
    try {
      await limiter.init();
      const identifiers = extractIdentifiers(req, {
        perIp: options.perIp !== false,
        perDevice: options.perDevice || false,
        perUser: options.perUser || false,
        perEndpoint: options.perEndpoint || false,
      });

      const info = await limiter.check(req, identifiers);
      const policyName = limiter.policy.name;

      // Attach rate limit info to request for downstream use
      req.rateLimitInfo = info;

      // Always set headers
      setHeaders(res, info, policyName);

      if (!info.allowed) {
        limiter.emit('rejected', { req, identifiers, info });
        return res.status(429).json({
          success: false,
          error: 'Too many requests',
          code: 'RATE_LIMIT_EXCEEDED',
          retryAfter: info.retryAfter,
          limit: info.limit,
          remaining: info.remaining,
          resetTime: info.resetTime,
        });
      }

      // Hook into response finish to optionally skip tracking for success/failure
      const originalEnd = res.end;
      const chunks = [];
      res.end = function (...args) {
        if (args[0]) chunks.push(Buffer.from(args[0]));
        const statusCode = res.statusCode;
        const shouldCountSuccess = !limiter.skipSuccessfulRequests || statusCode >= 400;
        const shouldCountFailure = !limiter.skipFailedRequests || statusCode < 400;
        if (shouldCountSuccess && shouldCountFailure) {
          limiter.consume(limiter.buildKey(req, identifiers)).catch(() => {});
        }
        originalEnd.apply(res, args);
      };

      next();
    } catch (err) {
      // Fail open: if rate limiter breaks, allow the request but log it
      limiter.emit('error', err);
      if (options.failClosed) {
        return next(err);
      }
      next();
    }
  };
}

/**
 * Factory: create a rate-limit middleware with fully custom configuration.
 * @param {Object} config
 * @param {number} [config.windowMs=60000]
 * @param {number} [config.maxRequests=100]
 * @param {string} [config.algorithm='sliding_window']
 * @param {boolean} [config.headersOnly=false]
 * @param {string[]} [config.whitelist=[]]
 * @param {Function} [config.keyGenerator]
 * @param {Function} [config.skipFunction]
 * @param {boolean} [config.perIp=true]
 * @param {boolean} [config.perDevice=false]
 * @param {boolean} [config.perUser=false]
 * @param {boolean} [config.perEndpoint=false]
 * @returns {Function}
 */
rateLimit.custom = function customRateLimit(config = {}) {
  const policy = {
    windowMs: config.windowMs || 60_000,
    maxRequests: config.maxRequests || 100,
    name: 'custom',
  };
  return rateLimit(policy, {
    algorithm: config.algorithm || 'sliding_window',
    headersOnly: config.headersOnly || false,
    whitelist: config.whitelist || [],
    keyGenerator: config.keyGenerator || null,
    skipFunction: config.skipFunction || null,
    perIp: config.perIp !== false,
    perDevice: config.perDevice || false,
    perUser: config.perUser || false,
    perEndpoint: config.perEndpoint || false,
  });
};

/**
 * Factory: create a rate-limit middleware that skips whitelisted IPs.
 * @param {string[]} whitelist - Array of IP addresses or CIDR ranges
 * @param {string|Object} [policy='default']
 * @param {Object} [options={}]
 * @returns {Function}
 */
rateLimit.skip = function skipWhitelist(whitelist, policy = 'default', options = {}) {
  if (!Array.isArray(whitelist)) {
    throw new RateLimitError(
      'Whitelist must be an array of IP addresses',
      'INVALID_WHITELIST',
      500
    );
  }
  return rateLimit(policy, { ...options, whitelist });
};

// ---------------------------------------------------------------------------
// Convenience Shorthand Exports
// ---------------------------------------------------------------------------

/**
 * Strict rate limiting (10 req/min).
 * @param {Object} [options={}]
 * @returns {Function}
 */
export function strictRateLimit(options = {}) {
  return rateLimit('strict', options);
}

/**
 * API rate limiting (30 req/min).
 * @param {Object} [options={}]
 * @returns {Function}
 */
export function apiRateLimit(options = {}) {
  return rateLimit('api', options);
}

/**
 * Claim rate limiting (3 req/day).
 * @param {Object} [options={}]
 * @returns {Function}
 */
export function claimRateLimit(options = {}) {
  return rateLimit('claim', options);
}

/**
 * Login rate limiting (5 req/hour).
 * @param {Object} [options={}]
 * @returns {Function}
 */
export function loginRateLimit(options = {}) {
  return rateLimit('login', options);
}

/**
 * Admin rate limiting (60 req/min).
 * @param {Object} [options={}]
 * @returns {Function}
 */
export function adminRateLimit(options = {}) {
  return rateLimit('admin', options);
}

/**
 * Timer status rate limiting (30 req/min per IP).
 * Burst: 5 requests in 10 seconds.
 * @param {Object} [options={}]
 * @returns {Function}
 */
export function timerStatusRateLimit(options = {}) {
  return rateLimit('timer_status', {
    burst: { windowMs: 10_000, maxRequests: 5 },
    ...options,
  });
}

/**
 * Code claim rate limiting (10 req/min per IP).
 * Burst: 5 requests in 10 seconds.
 * @param {Object} [options={}]
 * @returns {Function}
 */
export function codeClaimRateLimit(options = {}) {
  return rateLimit('code_claim', {
    burst: { windowMs: 10_000, maxRequests: 5 },
    ...options,
  });
}

/**
 * Code reveal rate limiting (5 req/min per IP).
 * Burst: 3 requests in 10 seconds.
 * @param {Object} [options={}]
 * @returns {Function}
 */
export function codeRevealRateLimit(options = {}) {
  return rateLimit('code_reveal', {
    burst: { windowMs: 10_000, maxRequests: 3 },
    ...options,
  });
}

/**
 * Code reveal hourly rate limiting (5 req/hour per telegram).
 * Separate limiter for per-telegram tracking.
 * @param {Object} [options={}]
 * @returns {Function}
 */
export function codeRevealHourlyRateLimit(options = {}) {
  return rateLimit('code_reveal_hourly', {
    perIp: false,
    perUser: true,
    keyGenerator: (req) => {
      // Key by telegramId header/body instead of IP
      const tgId = req.body?.telegramId || req.headers['x-telegram-id'] || req.ip;
      return `tg:${tgId}`;
    },
    ...options,
  });
}

/**
 * PoW endpoint rate limiting (20 req/min per IP).
 * Burst: 5 requests in 10 seconds.
 * @param {Object} [options={}]
 * @returns {Function}
 */
export function powRateLimit(options = {}) {
  return rateLimit('pow', {
    burst: { windowMs: 10_000, maxRequests: 5 },
    ...options,
  });
}

/**
 * Behavior endpoint rate limiting (10 req/min per IP).
 * Burst: 5 requests in 10 seconds.
 * @param {Object} [options={}]
 * @returns {Function}
 */
export function behaviorRateLimit(options = {}) {
  return rateLimit('behavior', {
    burst: { windowMs: 10_000, maxRequests: 5 },
    ...options,
  });
}

// ---------------------------------------------------------------------------
// Combined / Multi-Identifier Middleware
// ---------------------------------------------------------------------------

/**
 * Create a combined rate limiter that checks multiple identifiers.
 * ALL identifiers must pass their respective limits.
 * @param {Object} configMap - Map of identifier type to policy config
 *   e.g. { ip: 'default', userId: 'strict', endpoint: 'api' }
 * @param {Object} [options={}]
 * @returns {Function}
 */
export function combinedRateLimit(configMap, options = {}) {
  const entries = Object.entries(configMap);
  const limiters = entries.map(([type, policy]) => ({
    type,
    limiter: getLimiter(policy, options),
    policy: resolveConfig(policy),
  }));

  return async function combinedMiddleware(req, res, next) {
    try {
      const results = [];
      let mostRestrictive = null;

      for (const entry of limiters) {
        await entry.limiter.init();
        const identifiers = extractIdentifiers(req, {
          perIp: entry.type === 'ip',
          perDevice: entry.type === 'device',
          perUser: entry.type === 'userId',
          perEndpoint: entry.type === 'endpoint',
        });
        const info = await entry.limiter.check(req, identifiers);
        results.push({ type: entry.type, info });
        if (!mostRestrictive || info.remaining < mostRestrictive.info.remaining) {
          mostRestrictive = { type: entry.type, info };
        }
        if (!info.allowed) break;
      }

      // Set headers for the most restrictive limiter
      if (mostRestrictive) {
        setHeaders(res, mostRestrictive.info, `${mostRestrictive.type}:${mostRestrictive.info.penaltyInfo?.tier || 0}`);
      }

      const failed = results.find((r) => !r.info.allowed);
      if (failed) {
        return res.status(429).json({
          success: false,
          error: `Rate limit exceeded for ${failed.type}`,
          code: 'RATE_LIMIT_EXCEEDED',
          retryAfter: failed.info.retryAfter,
          type: failed.type,
        });
      }

      req.rateLimitInfo = mostRestrictive?.info || null;
      next();
    } catch (err) {
      if (options.failClosed) return next(err);
      next();
    }
  };
}

// ---------------------------------------------------------------------------
// Cleanup / Reset Utilities
// ---------------------------------------------------------------------------

/**
 * Clear all in-memory rate limit data (for testing or daily reset).
 * @returns {void}
 */
export function clearAllRateLimits() {
  for (const limiter of limiterInstances.values()) {
    if (limiter.store instanceof MemoryRateLimitStore) {
      limiter.store.clear();
    }
  }
  limiterInstances.clear();
}

/**
 * Reset rate limits for a specific identifier.
 * @param {string} identifier
 * @param {string} [policyName='default']
 * @returns {Promise<void>}
 */
export async function resetRateLimit(identifier, policyName = 'default') {
  const limiter = getLimiter(policyName);
  await limiter.init();
  await limiter.reset(identifier);
}

// ---------------------------------------------------------------------------
// Health Check
// ---------------------------------------------------------------------------

/**
 * Get rate limiter health status.
 * @returns {Object}
 */
export function rateLimitHealth() {
  return {
    instances: limiterInstances.size,
    policies: Array.from(limiterInstances.keys()),
    algorithms: Array.from(limiterInstances.values()).map((l) => l.algorithm),
    uptime: process.uptime(),
  };
}

// ---------------------------------------------------------------------------
// Default Export
// ---------------------------------------------------------------------------

export default {
  rateLimit,
  strictRateLimit,
  apiRateLimit,
  claimRateLimit,
  loginRateLimit,
  adminRateLimit,
  // Category 6 — Endpoint-specific rate limiters
  timerStatusRateLimit,
  codeClaimRateLimit,
  codeRevealRateLimit,
  codeRevealHourlyRateLimit,
  powRateLimit,
  behaviorRateLimit,
  combinedRateLimit,
  RateLimiter,
  RateLimitError,
  RateLimitExceededError,
  clearAllRateLimits,
  resetRateLimit,
  rateLimitHealth,
};
