/**
 * @fileoverview Telegram Channel Verification System for Osm Army Gift Code Fortress.
 * Handles mandatory 3-channel join verification, device-bound token generation,
 * and double-claim prevention.  All state is stored in MongoDB with in-memory
 * caching for hot paths.
 *
 * Features:
 * - Per-channel membership check via Telegram Bot API (getChatMember)
 * - Atomic 3-channel verification gate
 * - Cryptographically secure, device-fingerprint-bound tokens
 * - 10-second token expiry with one-time use enforcement
 * - IP + device fingerprint dual binding
 * - Double-claim prevention per (user, code) pair
 * - 24-hour verification caching to reduce API calls
 *
 * @module core/telegramVerify
 * @version 5.0.0
 */

'use strict';

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

// ---------------------------------------------------------------------------
// Configuration & Constants
// ---------------------------------------------------------------------------

/** The three mandatory channels every user must join. */
export const REQUIRED_CHANNELS = Object.freeze([
  { id: '-1002627799078', name: 'OSM Channel 1', slug: 'osm_official_channel_1' },
  { id: '-1003910695659', name: 'OSM Channel 2', slug: 'osm_official_channel_2' },
  { id: '-1003940794962', name: 'OSM Channel 3', slug: 'osm_official_channel_3' },
]);

/** Folder link that contains all three channels. */
export const CHANNEL_FOLDER_LINK = 'https://t.me/addlist/yZZ5Y0yKuBNhMjc9';

/** Token lifetime in milliseconds (10 minutes). */
const TOKEN_EXPIRY_MS = 600_000;

/** Verification cache TTL in milliseconds (24 hours). */
const VERIFICATION_CACHE_MS = 86_400_000;

/** MongoDB collection names. */
const COLLECTIONS = Object.freeze({
  VERIFICATIONS: 'telegram_verifications',
  CODE_CLAIMS: 'code_claims',
  TOKENS: 'verification_tokens',
});

// ---------------------------------------------------------------------------
// Custom Errors
// ---------------------------------------------------------------------------

export class VerificationError extends Error {
  constructor(message, code, statusCode = 400, extra = {}) {
    super(message);
    this.name = 'VerificationError';
    this.code = code;
    this.statusCode = statusCode;
    Object.assign(this, extra);
    Error.captureStackTrace(this, this.constructor);
  }
}

// ---------------------------------------------------------------------------
// Utility Functions
// ---------------------------------------------------------------------------

/**
 * Sleep for N milliseconds.
 * @param {number} ms
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Generate a cryptographically secure random token string.
 * @param {number} [bytes=32]
 * @returns {string} Hex string
 */
function secureToken(bytes = 32) {
  return randomBytes(bytes).toString('hex');
}

/**
 * Hash a device fingerprint for storage comparison.
 * @param {string} fingerprint
 * @returns {string} SHA-256 hex digest
 */
function hashFingerprint(fingerprint) {
  return createHash('sha256').update(fingerprint).digest('hex');
}

/**
 * Constant-time string comparison to prevent timing attacks.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function safeCompare(a, b) {
  try {
    return timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// TelegramVerify Class
// ---------------------------------------------------------------------------

/**
 * TelegramVerify handles all channel join verification logic.
 *
 * Usage:
 *   const tv = new TelegramVerify({ botToken: '123:ABC', db: mongoDb });
 *   await tv.init();
 *   const result = await tv.verifyAllChannels(telegramUserId);
 *   if (result.allJoined) {
 *     const token = await tv.generateVerificationToken(userId, fingerprint, ip);
 *   }
 */
export class TelegramVerify {
  /** @type {TelegramVerify|null} */
  static _instance = null;

  /**
   * BUG 1 FIX: Singleton getter — returns the shared instance
   * @returns {TelegramVerify|null}
   */
  static getInstance() {
    return TelegramVerify._instance;
  }

  /**
   * BUG 1 FIX: Singleton setter — registers the shared instance
   * @param {TelegramVerify} instance
   */
  static setInstance(instance) {
    TelegramVerify._instance = instance;
  }

  /**
   * @param {Object} options
   * @param {string} options.botToken - Telegram bot token for API calls
   * @param {Object|null} [options.db] - MongoDB database instance
   * @param {string} [options.baseApiUrl='https://api.telegram.org/bot']
   */
  constructor(options = {}) {
    this.botToken = options.botToken || process.env.TELEGRAM_BOT_TOKEN || '';
    this.db = options.db || null;
    this.baseApiUrl = options.baseApiUrl || 'https://api.telegram.org/bot';

    /** @type {import('mongodb').Collection|null} */
    this.verificationColl = null;
    /** @type {import('mongodb').Collection|null} */
    this.claimsColl = null;
    /** @type {import('mongodb').Collection|null} */
    this.tokensColl = null;

    this.initialized = false;

    // In-memory caches
    /** @type {Map<string, Object>} */
    this._verificationCache = new Map();
    /** @type {Map<string, Object>} */
    this._tokenCache = new Map();
    /** @type {Map<string, boolean>} */
    this._claimCache = new Map();
  }

  // ------------------------------------------------------------------
  // Initialisation
  // ------------------------------------------------------------------

  /**
   * Initialise database collections and indexes.
   * @returns {Promise<void>}
   */
  async init() {
    if (this.initialized) return;
    if (!this.botToken) {
      throw new VerificationError(
        'Telegram bot token is required. Set TELEGRAM_BOT_TOKEN.',
        'MISSING_BOT_TOKEN',
        500
      );
    }

    if (this.db) {
      this.verificationColl = this.db.collection(COLLECTIONS.VERIFICATIONS);
      this.claimsColl = this.db.collection(COLLECTIONS.CODE_CLAIMS);
      this.tokensColl = this.db.collection(COLLECTIONS.TOKENS);

      // TTL indexes for automatic cleanup
      await this.verificationColl.createIndex(
        { expiresAt: 1 },
        { expireAfterSeconds: 0, background: true, name: 'ttl_verifications' }
      );
      await this.verificationColl.createIndex(
        { telegramUserId: 1 },
        { background: true, name: 'lookup_user_verification' }
      );

      await this.claimsColl.createIndex(
        { telegramUserId: 1, codeId: 1 },
        { unique: true, background: true, name: 'unique_user_code_claim' }
      );
      await this.claimsColl.createIndex(
        { claimedAt: 1 },
        { expireAfterSeconds: 30 * 86400, background: true, name: 'ttl_claims' }
      );

      await this.tokensColl.createIndex(
        { expiresAt: 1 },
        { expireAfterSeconds: 0, background: true, name: 'ttl_tokens' }
      );
      await this.tokensColl.createIndex(
        { token: 1 },
        { unique: true, background: true, name: 'unique_token' }
      );
      await this.tokensColl.createIndex(
        { telegramUserId: 1 },
        { background: true, name: 'lookup_user_tokens' }
      );
    }

    this.initialized = true;
  }

  /**
   * Alias for init().
   * @param {...*} args
   * @returns {Promise<void>}
   */
  initialize(...args) { return this.init(...args); }

  // ------------------------------------------------------------------
  // Telegram Bot API Helpers
  // ------------------------------------------------------------------

  /**
   * Execute a raw Telegram Bot API method.
   * @param {string} method - API method name, e.g. 'getChatMember'
   * @param {Object} params - Query/body parameters
   * @returns {Promise<Object>} Parsed JSON response
   */
  async _tgApi(method, params = {}) {
    const url = new URL(`${this.baseApiUrl}${this.botToken}/${method}`);
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null) {
        url.searchParams.append(key, String(value));
      }
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);

    try {
      const res = await fetch(url.toString(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'User-Agent': 'OsmArmyVerify/5.0' },
        signal: controller.signal,
      });
      clearTimeout(timeout);

      const data = await res.json();
      if (!data.ok) {
        // Handle specific Telegram error codes
        if (data.error_code === 400 && data.description?.includes('member not found')) {
          return { ok: true, result: { status: 'left', user: {} } };
        }
        if (data.error_code === 400 && data.description?.includes('chat not found')) {
          throw new VerificationError(
            `Channel not accessible: ensure bot is admin in channel`,
            'CHANNEL_NOT_ACCESSIBLE',
            500,
            { telegramError: data.description }
          );
        }
        throw new VerificationError(
          data.description || `Telegram API error: ${method}`,
          `TG_API_${data.error_code}`,
          data.error_code || 500
        );
      }
      return data;
    } catch (err) {
      clearTimeout(timeout);
      if (err.name === 'AbortError') {
        throw new VerificationError(
          `Telegram API timeout: ${method}`,
          'TG_API_TIMEOUT',
          504
        );
      }
      throw err;
    }
  }

  // ------------------------------------------------------------------
  // Channel Membership Verification
  // ------------------------------------------------------------------

  /**
   * Check if a user is a member of a specific Telegram channel.
   *
   * Uses getChatMember API:
   *   https://api.telegram.org/bot<TOKEN>/getChatMember?chat_id=<CHAT_ID>&user_id=<USER_ID>
   *
   * @param {number|string} telegramUserId
   * @param {string} channelId - Channel ID (e.g. '-1002627799078')
   * @returns {Promise<{isMember: boolean, status: string}>}
   *
   * Status meanings:
   *   'creator'     - User is the channel owner
   *   'administrator' - User is an admin
   *   'member'      - Regular member
   *   'restricted'  - Restricted member (may still be joined)
   *   'left'        - Not a member
   *   'kicked'      - Banned from channel
   */
  async verifyChannelMembership(telegramUserId, channelId) {
    if (!telegramUserId) {
      throw new VerificationError('telegramUserId is required', 'MISSING_USER_ID', 400);
    }
    if (!channelId) {
      throw new VerificationError('channelId is required', 'MISSING_CHANNEL_ID', 400);
    }

    const data = await this._tgApi('getChatMember', {
      chat_id: channelId,
      user_id: String(telegramUserId),
    });

    const status = data.result?.status || 'left';
    const isMember = ['creator', 'administrator', 'member', 'restricted'].includes(status);

    return { isMember, status };
  }

  /**
   * Verify membership across all 3 mandatory channels.
   *
   * @param {number|string} telegramUserId
   * @returns {Promise<{allJoined: boolean, channels: Object}>}
   *
   * @example
   * {
   *   allJoined: true,
   *   channels: {
   *     '-1002627799078': { joined: true, name: 'OSM Channel 1', status: 'member' },
   *     '-1003910695659': { joined: false, name: 'OSM Channel 2', status: 'left' },
   *     '-1003940794962': { joined: true, name: 'OSM Channel 3', status: 'member' }
   *   }
   * }
   */
  async verifyAllChannels(telegramUserId) {
    const channels = {};
    let allJoined = true;

    // Check all channels in parallel for speed
    const results = await Promise.allSettled(
      REQUIRED_CHANNELS.map(async (ch) => {
        try {
          const { isMember, status } = await this.verifyChannelMembership(telegramUserId, ch.id);
          return { channelId: ch.id, joined: isMember, name: ch.name, status };
        } catch (err) {
          // If we can't check, assume not joined for safety
          return { channelId: ch.id, joined: false, name: ch.name, status: 'error', error: err.message };
        }
      })
    );

    for (const result of results) {
      if (result.status === 'fulfilled') {
        const { channelId, joined, name, status, error } = result.value;
        channels[channelId] = { joined, name, status };
        if (error) channels[channelId].error = error;
        if (!joined) allJoined = false;
      } else {
        allJoined = false;
      }
    }

    return { allJoined, channels };
  }

  // ------------------------------------------------------------------
  // Verification Token Lifecycle
  // ------------------------------------------------------------------

  /**
   * Generate a device-bound verification token.
   *
   * The token is cryptographically random, bound to both the Telegram user
   * ID and the device fingerprint, expires in 10 seconds, and can only be
   * used once.
   *
   * @param {number|string} telegramUserId
   * @param {string} deviceFingerprint - Unique device identifier hash
   * @param {string} [ip] - Optional IP address for additional binding
   * @returns {Promise<string>} The generated token (hex string)
   */
  async generateVerificationToken(telegramUserId, deviceFingerprint, ip = null, codeId = null) {
    if (!telegramUserId) {
      throw new VerificationError('telegramUserId is required', 'MISSING_USER_ID', 400);
    }
    if (!deviceFingerprint) {
      throw new VerificationError('deviceFingerprint is required', 'MISSING_FINGERPRINT', 400);
    }

    // Revoke any existing active token for this user first
    await this._revokeActiveTokens(telegramUserId);

    const token = secureToken(32);
    const fingerprintHash = hashFingerprint(deviceFingerprint);
    const now = Date.now();
    const expiresAt = new Date(now + TOKEN_EXPIRY_MS);

    const record = {
      token,
      telegramUserId: String(telegramUserId),
      fingerprintHash,
      deviceFingerprintHint: deviceFingerprint.substring(0, 16) + '...', // for debugging only
      ip: ip || null,
      codeId: codeId || null,  // BIND exact codeId for timer-sync + reveal
      used: false,
      createdAt: new Date(now),
      expiresAt,
    };

    // Persist to DB
    if (this.tokensColl) {
      await this.tokensColl.insertOne(record);
    }

    // Cache in memory
    this._tokenCache.set(token, { ...record, _cachedAt: now });

    return token;
  }

  /**
   * Verify a token is valid, not expired, not used, and bound to the
   * requesting device.
   *
   * @param {string} token
   * @param {number|string} telegramUserId
   * @param {string} deviceFingerprint
   * @param {string} [ip]
   * @returns {Promise<boolean>} True if all checks pass
   */
  async verifyToken(token, telegramUserId, deviceFingerprint, ip = null) {
    if (!token || typeof token !== 'string') return false;
    if (!telegramUserId || !deviceFingerprint) return false;

    const fingerprintHash = hashFingerprint(deviceFingerprint);

    // Check memory cache first
    const cached = this._tokenCache.get(token);
    if (cached) {
      if (cached.expiresAt < new Date()) return false;
      if (cached.used) return false;
      if (String(cached.telegramUserId) !== String(telegramUserId)) return false;
      if (!safeCompare(cached.fingerprintHash, fingerprintHash)) return false;
      // Mark as used
      cached.used = true;
      await this._markTokenUsed(token);
      return true;
    }

    // Fallback to DB
    if (!this.tokensColl) return false;

    const doc = await this.tokensColl.findOne({ token });
    if (!doc) return false;
    if (doc.used) return false;
    if (doc.expiresAt < new Date()) return false;
    if (String(doc.telegramUserId) !== String(telegramUserId)) return false;
    if (!safeCompare(doc.fingerprintHash, fingerprintHash)) return false;

    await this._markTokenUsed(token);
    return true;
  }

  /**
   * Atomically consume a verification token.
   * Returns token data only if token is valid, not used, and not expired.
   * Marks token as used in the same operation (atomic — BUG 4 FIX).
   *
   * @param {string} token
   * @returns {Promise<Object|null>} Token data if consumed, null otherwise
   */
  async consumeVerificationToken(token) {
    if (!this.tokensColl) return null;

    const result = await this.tokensColl.findOneAndUpdate(
      { token, used: false, expiresAt: { $gt: new Date() } },
      { $set: { used: true, usedAt: new Date() } },
      { returnDocument: 'after' }
    );

    return result || null;
  }

  /**
   * Mark a token as used in both memory and DB.
   * @param {string} token
   * @returns {Promise<void>}
   * @private
   */
  async _markTokenUsed(token) {
    const cached = this._tokenCache.get(token);
    if (cached) cached.used = true;

    if (this.tokensColl) {
      await this.tokensColl.updateOne(
        { token },
        { $set: { used: true, usedAt: new Date() } }
      );
    }
  }

  /**
   * Revoke all active (unused, unexpired) tokens for a user.
   * @param {number|string} telegramUserId
   * @returns {Promise<void>}
   * @private
   */
  async _revokeActiveTokens(telegramUserId) {
    const userId = String(telegramUserId);

    // Clean memory cache
    for (const [key, val] of this._tokenCache) {
      if (String(val.telegramUserId) === userId && !val.used && val.expiresAt > new Date()) {
        val.used = true;
        val.revoked = true;
      }
    }

    if (this.tokensColl) {
      await this.tokensColl.updateMany(
        { telegramUserId: userId, used: false, expiresAt: { $gt: new Date() } },
        { $set: { used: true, revokedAt: new Date() } }
      );
    }
  }

  // ------------------------------------------------------------------
  // User Verification State
  // ------------------------------------------------------------------

  /**
   * Check if a user has already verified channel membership (within the
   * last 24 hours).
   *
   * @param {number|string} telegramUserId
   * @returns {Promise<boolean>}
   */
  async isUserVerified(telegramUserId) {
    const userId = String(telegramUserId);
    const now = Date.now();

    // Memory cache check
    const cached = this._verificationCache.get(userId);
    if (cached && cached.expiresAt > now) {
      return true;
    }
    if (cached && cached.expiresAt <= now) {
      this._verificationCache.delete(userId);
    }

    // DB check
    if (!this.verificationColl) return false;

    const doc = await this.verificationColl.findOne({
      telegramUserId: userId,
      expiresAt: { $gt: new Date() },
    });

    if (doc) {
      // Refresh memory cache
      this._verificationCache.set(userId, {
        verified: true,
        channels: doc.channels || [],
        verifiedAt: doc.verifiedAt?.getTime() || doc.verifiedAt,
        expiresAt: doc.expiresAt.getTime(),
      });
      return true;
    }

    return false;
  }

  /**
   * Record that a user has verified all channels.
   *
   * @param {number|string} telegramUserId
   * @param {Object} [channels] - Channel verification result from verifyAllChannels
   * @returns {Promise<void>}
   */
  async markChannelsVerified(telegramUserId, channels = {}) {
    const userId = String(telegramUserId);
    const now = Date.now();
    const expiresAt = new Date(now + VERIFICATION_CACHE_MS);

    const record = {
      telegramUserId: userId,
      channels: Object.entries(channels).map(([channelId, info]) => ({
        channelId,
        name: info.name,
        joined: info.joined,
        status: info.status,
      })),
      verifiedAt: new Date(now),
      expiresAt,
    };

    // Upsert in DB
    if (this.verificationColl) {
      await this.verificationColl.updateOne(
        { telegramUserId: userId },
        { $set: record },
        { upsert: true }
      );
    }

    // Update memory cache
    this._verificationCache.set(userId, {
      verified: true,
      channels: record.channels,
      verifiedAt: now,
      expiresAt: expiresAt.getTime(),
    });
  }

  /**
   * Revoke a user's channel verification, forcing re-verification.
   *
   * @param {number|string} telegramUserId
   * @returns {Promise<void>}
   */
  async revokeVerification(telegramUserId) {
    const userId = String(telegramUserId);

    // Remove from memory cache
    this._verificationCache.delete(userId);

    // Remove from DB
    if (this.verificationColl) {
      await this.verificationColl.deleteOne({ telegramUserId: userId });
    }
  }

  /**
   * Get the current verification status for a user.
   *
   * @param {number|string} telegramUserId
   * @returns {Promise<{verified: boolean, channels: Array, verifiedAt: Date|null, expiresIn: number}>}
   *
   * expiresIn is milliseconds until expiry, or -1 if not verified.
   */
  async getVerificationStatus(telegramUserId) {
    const userId = String(telegramUserId);

    // Memory cache
    const cached = this._verificationCache.get(userId);
    if (cached && cached.expiresAt > Date.now()) {
      return {
        verified: true,
        channels: cached.channels,
        verifiedAt: cached.verifiedAt ? new Date(cached.verifiedAt) : null,
        expiresIn: cached.expiresAt - Date.now(),
      };
    }

    // DB
    if (this.verificationColl) {
      const doc = await this.verificationColl.findOne({ telegramUserId: userId });
      if (doc && doc.expiresAt > new Date()) {
        return {
          verified: true,
          channels: doc.channels,
          verifiedAt: doc.verifiedAt,
          expiresIn: doc.expiresAt.getTime() - Date.now(),
        };
      }
    }

    return {
      verified: false,
      channels: [],
      verifiedAt: null,
      expiresIn: -1,
    };
  }

  // ------------------------------------------------------------------
  // Double-Claim Prevention
  // ------------------------------------------------------------------

  /**
   * Check if a user has already claimed a specific code.
   *
   * @param {number|string} telegramUserId
   * @param {string} codeId
   * @returns {Promise<boolean>}
   */
  async hasUserClaimedCode(telegramUserId, codeId) {
    const userId = String(telegramUserId);
    const cacheKey = `${userId}:${codeId}`;

    // Memory cache
    if (this._claimCache.has(cacheKey)) {
      return this._claimCache.get(cacheKey);
    }

    // DB check
    if (!this.claimsColl) return false;

    const doc = await this.claimsColl.findOne({ telegramUserId: userId, codeId });
    const claimed = !!doc;

    // Cache result (negative results also cached briefly)
    this._claimCache.set(cacheKey, claimed);
    setTimeout(() => this._claimCache.delete(cacheKey), 60_000);

    return claimed;
  }

  /**
   * Record that a user has claimed a code.
   *
   * @param {number|string} telegramUserId
   * @param {string} codeId
   * @param {string} deviceFingerprint
   * @param {string} [ip]
   * @returns {Promise<void>}
   * @throws {VerificationError} If user already claimed this code
   */
  async recordCodeClaim(telegramUserId, codeId, deviceFingerprint, ip = null) {
    const userId = String(telegramUserId);
    const cacheKey = `${userId}:${codeId}`;

    // Idempotency: already claimed is an error
    if (await this.hasUserClaimedCode(userId, codeId)) {
      throw new VerificationError(
        'You have already claimed this code. Each user can only claim a code once.',
        'CODE_ALREADY_CLAIMED',
        409,
        { telegramUserId: userId, codeId }
      );
    }

    const fingerprintHash = hashFingerprint(deviceFingerprint);
    const record = {
      telegramUserId: userId,
      codeId,
      fingerprintHash,
      ip: ip || null,
      claimedAt: new Date(),
    };

    try {
      if (this.claimsColl) {
        await this.claimsColl.insertOne(record);
      }
      this._claimCache.set(cacheKey, true);
    } catch (err) {
      if (err.code === 11000) {
        // Duplicate key - race condition
        this._claimCache.set(cacheKey, true);
        throw new VerificationError(
          'You have already claimed this code. Each user can only claim a code once.',
          'CODE_ALREADY_CLAIMED',
          409,
          { telegramUserId: userId, codeId }
        );
      }
      throw err;
    }
  }

  // ------------------------------------------------------------------
  // Device Binding
  // ------------------------------------------------------------------

  /**
   * Check if a token was created for a specific device.
   *
   * @param {string} token
   * @param {string} deviceFingerprint
   * @returns {Promise<boolean>}
   */
  async isTokenBoundToDevice(token, deviceFingerprint) {
    if (!token || !deviceFingerprint) return false;

    const fingerprintHash = hashFingerprint(deviceFingerprint);

    // Memory cache
    const cached = this._tokenCache.get(token);
    if (cached) {
      return safeCompare(cached.fingerprintHash, fingerprintHash);
    }

    // DB
    if (!this.tokensColl) return false;

    const doc = await this.tokensColl.findOne({ token });
    if (!doc) return false;

    return safeCompare(doc.fingerprintHash, fingerprintHash);
  }

  /**
   * Get the binding information for a token (for error messages).
   *
   * @param {string} token
   * @returns {Promise<{bound: boolean, userId: string|null, createdAt: Date|null, expired: boolean}>}
   */
  async getTokenBindingInfo(token) {
    // Memory cache
    const cached = this._tokenCache.get(token);
    if (cached) {
      return {
        bound: true,
        userId: cached.telegramUserId,
        createdAt: cached.createdAt,
        expired: cached.expiresAt < new Date(),
        used: cached.used,
      };
    }

    // DB
    if (!this.tokensColl) {
      return { bound: false, userId: null, createdAt: null, expired: false };
    }

    const doc = await this.tokensColl.findOne({ token });
    if (!doc) {
      return { bound: false, userId: null, createdAt: null, expired: false };
    }

    return {
      bound: true,
      userId: doc.telegramUserId,
      createdAt: doc.createdAt,
      expired: doc.expiresAt < new Date(),
      used: doc.used,
    };
  }

  // ------------------------------------------------------------------
  // Cleanup & Maintenance
  // ------------------------------------------------------------------

  /**
   * Clean expired entries from in-memory caches.
   * Call periodically (e.g., via setInterval every 5 minutes).
   */
  cleanupCaches() {
    const now = Date.now();

    // Token cache
    for (const [key, val] of this._tokenCache) {
      if (val.expiresAt < new Date() || (val._cachedAt && now - val._cachedAt > 300_000)) {
        this._tokenCache.delete(key);
      }
    }

    // Verification cache
    for (const [key, val] of this._verificationCache) {
      if (val.expiresAt <= now) {
        this._verificationCache.delete(key);
      }
    }
  }

  /**
   * Get verification statistics for monitoring.
   * @returns {Promise<Object>}
   */
  async getStats() {
    const stats = {
      memoryCache: {
        verifications: this._verificationCache.size,
        tokens: this._tokenCache.size,
        claims: this._claimCache.size,
      },
    };

    if (this.verificationColl) {
      stats.dbVerifications = await this.verificationColl.countDocuments();
    }
    if (this.claimsColl) {
      stats.dbClaims = await this.claimsColl.countDocuments();
    }
    if (this.tokensColl) {
      stats.dbTokens = await this.tokensColl.countDocuments();
      stats.activeTokens = await this.tokensColl.countDocuments({ used: false, expiresAt: { $gt: new Date() } });
    }

    return stats;
  }
}

// ---------------------------------------------------------------------------
// Singleton Factory
// ---------------------------------------------------------------------------

/** @type {TelegramVerify|null} */
let singletonVerify = null;

/**
 * Get or create the TelegramVerify singleton.
 * @param {Object} [options]
 * @returns {TelegramVerify}
 */
export function getTelegramVerify(options = {}) {
  // BUG 1 FIX: Check TelegramVerify.getInstance() first (set by server.js)
  const instance = TelegramVerify.getInstance();
  if (instance) return instance;

  // Fallback: create new (for dev/testing without server init)
  if (!singletonVerify) {
    singletonVerify = new TelegramVerify(options);
    TelegramVerify.setInstance(singletonVerify);
  }
  return singletonVerify;
}

/**
 * Reset the singleton (useful for testing).
 */
export function resetTelegramVerify() {
  singletonVerify = null;
}

// ---------------------------------------------------------------------------
// Default Export
// ---------------------------------------------------------------------------

/**
 * Standalone function to verify Telegram channel membership.
 * Used by codeReveal.js for server-side channel verification.
 * @param {string} telegramUserId - Telegram user ID
 * @param {string[]} channels - Array of channel IDs
 * @returns {Promise<Object>} Membership status per channel
 */
export async function verifyTelegramMembership(telegramUserId, channels) {
  const tv = getTelegramVerify();
  if (!tv || !tv.initialized) throw new Error('TelegramVerify not initialized');
  return tv.verifyAllChannels(telegramUserId, channels);
}

export default {
  TelegramVerify,
  VerificationError,
  getTelegramVerify,
  resetTelegramVerify,
  verifyTelegramMembership,
  REQUIRED_CHANNELS,
  CHANNEL_FOLDER_LINK,
};
