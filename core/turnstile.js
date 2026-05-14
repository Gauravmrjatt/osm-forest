/**
 * @fileoverview Cloudflare Turnstile Integration — CAPTCHA Alternative
 *
 * CRITICAL SECURITY RULES:
 *   1. NEVER log the full turnstile token — only first 8 chars + "..."
 *   2. CF_SECRET_KEY is ONLY used server-side — never expose to client.
 *   3. Token is single-use; do NOT replay verification results.
 *   4. IP binding: token is bound to the IP it was issued for.
 *
 * Provides:
 *   - verifyTurnstile(token, ip) → { success, error? }
 *   - Turnstile challenge lifecycle management
 *   - Token replay protection
 *
 * @module core/turnstile
 * @version 1.0.0
 */

import { createHash } from 'crypto';

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const REQUEST_TIMEOUT_MS = 10000; // 10s timeout

/** MongoDB collection for replay protection */
const COLL_TURNSTILE_TOKENS = 'turnstile_tokens';

// ─────────────────────────────────────────────────────────────────────────────
// MongoDB handle
// ─────────────────────────────────────────────────────────────────────────────

let _db = null;
let _logFn = null;

/**
 * Initialise the Turnstile module.
 * @param {import('mongodb').Db} db — connected MongoDB Db instance
 * @param {Function} [auditLogFn] — optional audit log function
 */
export function initTurnstile(db, auditLogFn = null) {
  _db = db;
  _logFn = auditLogFn;

  // TTL index: tokens expire after 5 minutes (single-use, short-lived)
  _db.collection(COLL_TURNSTILE_TOKENS).createIndex(
    { createdAt: 1 },
    { expireAfterSeconds: 300 }
  );
  _db.collection(COLL_TURNSTILE_TOKENS).createIndex(
    { tokenHash: 1 },
    { unique: true }
  );
}

function getColl(name) {
  if (!_db) throw new Error('Turnstile not initialized — call initTurnstile(db) first');
  return _db.collection(name);
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

function quickHash(val) {
  if (!val) return 'null';
  return createHash('sha256').update(String(val)).digest('hex').slice(0, 16);
}

function truncate(val, n = 8) {
  if (!val) return '';
  const s = String(val);
  return s.length <= n ? s : `${s.slice(0, n)}...`;
}

/**
 * Check if a token has already been used (replay protection).
 * @param {string} tokenHash
 * @returns {Promise<boolean>}
 */
async function isTokenUsed(tokenHash) {
  try {
    const doc = await getColl(COLL_TURNSTILE_TOKENS).findOne(
      { tokenHash },
      { projection: { _id: 1 } }
    );
    return !!doc;
  } catch {
    return false; // Fail-open: if DB fails, allow verification to proceed
  }
}

/**
 * Mark a token as used (replay protection).
 * @param {string} tokenHash
 * @param {boolean} verified
 * @param {string} ipHash
 */
async function markTokenUsed(tokenHash, verified, ipHash) {
  try {
    await getColl(COLL_TURNSTILE_TOKENS).insertOne({
      tokenHash,
      verified,
      ipHash,
      createdAt: new Date(),
    });
  } catch {
    // Non-critical: replay protection may degrade
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verify a Cloudflare Turnstile token.
 *
 * Flow:
 *   1. Check if token was already used (replay protection)
 *   2. POST to Cloudflare siteverify endpoint
 *   3. Mark token as used
 *   4. Return result
 *
 * @param {string} token — the turnstile response token from the client
 * @param {string} [ip] — the client's IP address (for binding)
 * @returns {Promise<{
 *   success: boolean,
 *   error?: string,
 *   challengeTs?: string,
 *   hostname?: string,
 * }>}
 *
 * SECURITY:
 *   - Token is hashed before storage for replay protection.
 *   - Raw token is NEVER logged in full.
 *   - CF_SECRET_KEY is pulled from environment, never exposed.
 */
export async function verifyTurnstile(token, ip = null) {
  // ── 1. Validate inputs ──
  if (!token || typeof token !== 'string' || token.length < 10) {
    return { success: false, error: 'INVALID_TOKEN' };
  }

  const secretKey = process.env.CF_SECRET_KEY;
  if (!secretKey) {
    // In development without secret, fail-open with warning
    if (process.env.NODE_ENV !== 'production') {
      return { success: true, error: 'DEV_MODE_NO_SECRET' };
    }
    return { success: false, error: 'SERVER_CONFIG_ERROR' };
  }

  const tokenHash = quickHash(token);

  // ── 2. Replay protection ──
  const alreadyUsed = await isTokenUsed(tokenHash);
  if (alreadyUsed) {
    if (_logFn) {
      _logFn('TURNSTILE_REPLAY_ATTEMPT', {
        tokenHash: truncate(tokenHash, 8),
      }, 'WARN');
    }
    return { success: false, error: 'TOKEN_REPLAY' };
  }

  // ── 3. Call Cloudflare siteverify ──
  const ipHash = ip ? quickHash(ip) : null;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    const body = new URLSearchParams();
    body.append('secret', secretKey);
    body.append('response', token);
    if (ip) body.append('remoteip', ip);

    const response = await fetch(TURNSTILE_VERIFY_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body,
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!response.ok) {
      await markTokenUsed(tokenHash, false, ipHash);
      return { success: false, error: 'VERIFICATION_HTTP_ERROR' };
    }

    const data = await response.json();

    // ── 4. Parse result ──
    const success = data.success === true;

    // Error codes from Cloudflare
    const errorCodes = data['error-codes'] || [];
    if (!success && errorCodes.length > 0) {
      const knownErrors = {
        'missing-input-secret':    'SERVER_CONFIG_ERROR',
        'invalid-input-secret':    'SERVER_CONFIG_ERROR',
        'missing-input-response':  'MISSING_TOKEN',
        'invalid-input-response':  'INVALID_TOKEN',
        'bad-request':             'BAD_REQUEST',
        'timeout-or-duplicate':    'TIMEOUT_OR_DUPLICATE',
        'internal-error':          'CF_INTERNAL_ERROR',
      };
      const mappedError = knownErrors[errorCodes[0]] || 'VERIFICATION_FAILED';

      await markTokenUsed(tokenHash, false, ipHash);

      if (_logFn) {
        _logFn('TURNSTILE_VERIFY_FAILED', {
          tokenHash: truncate(tokenHash, 8),
          cfError: errorCodes[0],
          mappedError,
        }, 'WARN');
      }

      return { success: false, error: mappedError };
    }

    // ── 5. Mark as used and return success ──
    await markTokenUsed(tokenHash, true, ipHash);

    if (_logFn && success) {
      _logFn('TURNSTILE_VERIFY_SUCCESS', {
        tokenHash: truncate(tokenHash, 8),
        hostname: data.hostname || 'unknown',
      }, 'INFO');
    }

    return {
      success: true,
      challengeTs: data.challenge_ts || null,
      hostname: data.hostname || null,
    };

  } catch (err) {
    // Network/timeout failure
    await markTokenUsed(tokenHash, false, ipHash);

    if (_logFn) {
      _logFn('TURNSTILE_VERIFY_ERROR', {
        tokenHash: truncate(tokenHash, 8),
        errorType: err.name,
      }, 'ERROR');
    }

    // Fail-closed: if CF is unreachable, require re-attempt
    return { success: false, error: 'VERIFICATION_UNAVAILABLE' };
  }
}

/**
 * Get the site key for the client-side Turnstile widget.
 * @returns {string|null}
 */
export function getTurnstileSiteKey() {
  return process.env.TURNSTILE_SITE_KEY || null;
}

/**
 * Check if Turnstile is properly configured.
 * @returns {{configured: boolean, hasSiteKey: boolean, hasSecret: boolean}}
 */
export function getTurnstileConfigStatus() {
  return {
    configured: !!(process.env.TURNSTILE_SITE_KEY && process.env.CF_SECRET_KEY),
    hasSiteKey: !!process.env.TURNSTILE_SITE_KEY,
    hasSecret: !!process.env.CF_SECRET_KEY,
  };
}

/**
 * Clean up old turnstile tokens (beyond the 5-min window).
 * Called periodically or by a cron job.
 * @returns {Promise<number>} number of documents removed
 */
export async function cleanupTurnstileTokens() {
  try {
    const cutoff = new Date(Date.now() - 10 * 60 * 1000); // 10 min old
    const result = await getColl(COLL_TURNSTILE_TOKENS).deleteMany({
      createdAt: { $lt: cutoff },
    });
    return result.deletedCount || 0;
  } catch {
    return 0;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Default export
// ─────────────────────────────────────────────────────────────────────────────

export default {
  initTurnstile,
  verifyTurnstile,
  getTurnstileSiteKey,
  getTurnstileConfigStatus,
  cleanupTurnstileTokens,
};
