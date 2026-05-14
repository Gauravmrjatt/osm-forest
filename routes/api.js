/**
 * @fileoverview API Routes - The ONLY way clients interact with the system
 * @description All gift code claiming, factor verification, code reveal, and
 * proof-of-work endpoints. NO CODE IS EVER RETURNED AS TEXT IN API RESPONSES!
 * Codes are only delivered as anti-OCR images with embedded watermarks.
 * @module routes/api
 * @version 1.0.0
 */

'use strict';

import { Router } from 'express';
import { ObjectId } from 'mongodb';
import { randomBytes, createHash, timingSafeEqual, createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseManager } from '../core/database.js';
import { createProtector, SecurityViolationError } from '../core/protect.js';
import {
  generateToken,
  generateHexToken,
  generateNonce,
  hmacSHA512,
  verifyHMAC,
  sha256,
  secureCompare,
} from '../core/encrypt.js';
import { ConfigManager } from '../core/config.js';
import { BehaviorAnalyzer } from '../core/behavior.js';
import { FingerprintVerifier } from '../core/fingerprint.js';
import { AlertManager } from '../core/alert.js';
import { SecurityEngine } from '../core/security.js';
import { createHash as createFragmentHash } from '../core/fragment.js';
import { AntiOCRGenerator } from '../core/canvas.js';
import { WatermarkEngine } from '../core/watermark.js';
import { SecureCodeDisplay } from '../core/secureDisplay.js';
import { TelegramVerify } from '../core/telegramVerify.js';
import {
  generateProofOfWorkChallenge,
  verifyProofOfWork,
  generateBehavioralChallenge,
  generateObfuscatedCodeDisplay,
  createValidationChain,
  validateChain,
  generateHoneyPotCodes,
  checkHoneyPot,
} from '../core/antiExtract.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ============================================================================
// ENVIRONMENT VARIABLE HELPER — crash in production if secrets are missing
// ============================================================================

function requireEnv(key) {
  const val = process.env[key];
  if (!val && process.env.NODE_ENV === 'production') {
    throw new Error(`FATAL: ${key} environment variable is required in production`);
  }
  return val;
}

// ============================================================================
// CONFIGURATION
// ============================================================================

const ROUTER_CONFIG = Object.freeze({
  TOKEN_EXPIRY_SECONDS: parseInt(process.env.TOKEN_EXPIRY_SECONDS, 10) || 600,
  CLAIM_RATE_LIMIT_WINDOW_MS: 60_000,
  CLAIM_RATE_LIMIT_MAX: 1,
  POW_MAX_ATTEMPTS: 5,
  POW_BLOCK_DURATION_MS: 24 * 60 * 60_000,
  FACTOR_MAX_ATTEMPTS: 3,
  AUTO_DESTRUCT_MS: 10_000,
  CODE_REVEAL_WINDOW_MS: 10_000,
});

// ============================================================================
// ERROR CLASSES
// ============================================================================

/**
 * API route-specific error.
 */
class ApiRouteError extends Error {
  constructor(message, code = 'API_ERROR', statusCode = 400, details = {}) {
    super(message);
    this.name = 'ApiRouteError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
    this.timestamp = new Date().toISOString();
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Token validation error.
 */
class TokenError extends ApiRouteError {
  constructor(message = 'Invalid token', code = 'TOKEN_INVALID') {
    super(message, code, 401);
    this.name = 'TokenError';
  }
}

/**
 * Rate limit error.
 */
class RateLimitApiError extends ApiRouteError {
  constructor(message = 'Rate limit exceeded', retryAfter = 60) {
    super(message, 'RATE_LIMIT_EXCEEDED', 429);
    this.retryAfter = retryAfter;
  }
}

/**
 * Factor verification error.
 */
class FactorError extends ApiRouteError {
  constructor(message, code = 'FACTOR_FAILED', attemptsLeft = 0) {
    super(message, code, 403);
    this.attemptsLeft = attemptsLeft;
  }
}

// ============================================================================
// IN-MEMORY STORES (with TTL cleanup)
// ============================================================================

/** @type {Map<string, {token: string, ip: string, fingerprint: string, createdAt: number, used: boolean, factorsCompleted: Set<number>, attempts: Map<number, number>}>} */
const tokenStore = new Map();

/** @type {Map<string, {count: number, resetAt: number}>} */
const rateLimitStore = new Map();

/** @type {Map<string, {attempts: number, lastAttempt: number, blocked: boolean, blockedUntil: number}>} */
const powAttempts = new Map();

/** @type {Map<string, {expiresAt: number}>} */
const codeRevealTimers = new Map();

/** @type {Map<string, {token: string, telegramUserId: string, createdAt: number}>} */
const verificationTokenStore = new Map();

/** @type {TelegramVerify|null} */
let telegramVerifier = null;

/**
 * Lazy-load TelegramVerify singleton.
 * @returns {TelegramVerify}
 */
function getTelegramVerifier() {
  if (!telegramVerifier) {
    telegramVerifier = new TelegramVerify();
  }
  return telegramVerifier;
}

// Periodic cleanup of expired tokens
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of tokenStore) {
    if (now > entry.createdAt + ROUTER_CONFIG.TOKEN_EXPIRY_SECONDS * 1000 + 60000) {
      tokenStore.delete(key);
    }
  }
  for (const [key, entry] of rateLimitStore) {
    if (now > entry.resetAt) {
      rateLimitStore.delete(key);
    }
  }
  for (const [key, entry] of powAttempts) {
    if (entry.blocked && now > entry.blockedUntil) {
      powAttempts.delete(key);
    }
  }
  for (const [key, entry] of codeRevealTimers) {
    if (now > entry.expiresAt) {
      codeRevealTimers.delete(key);
    }
  }
  for (const [key, entry] of verificationTokenStore) {
    if (now > entry.createdAt + 24 * 60 * 60 * 1000) {
      verificationTokenStore.delete(key);
    }
  }
}, 30000);

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Get client IP from request.
 * @param {import('express').Request} req - Express request
 * @returns {string} Client IP
 */
function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

/**
 * Send standardized error response.
 * @param {import('express').Response} res - Express response
 * @param {string} message - Error message
 * @param {string} code - Error code
 * @param {number} statusCode - HTTP status
 */
function sendError(res, message, code, statusCode = 400) {
  const response = {
    success: false,
    error: message,
    code,
    timestamp: new Date().toISOString(),
  };
  return res.status(statusCode).json(response);
}

/**
 * Send standardized success response.
 * @param {import('express').Response} res - Express response
 * @param {Object} data - Response data
 * @param {number} statusCode - HTTP status
 */
function sendSuccess(res, data, statusCode = 200) {
  return res.status(statusCode).json({
    success: true,
    data,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Set rate limit headers on response.
 * @param {import('express').Response} res - Express response
 * @param {number} limit - Rate limit
 * @param {number} remaining - Remaining requests
 * @param {number} resetAt - Reset timestamp
 */
function setRateLimitHeaders(res, limit, remaining, resetAt) {
  res.setHeader('X-RateLimit-Limit', String(limit));
  res.setHeader('X-RateLimit-Remaining', String(Math.max(0, remaining)));
  res.setHeader('X-RateLimit-Reset', String(Math.ceil(resetAt / 1000)));
}

/**
 * Check rate limit for an identifier.
 * @param {string} identifier - Rate limit key
 * @param {number} maxRequests - Max requests in window
 * @param {number} windowMs - Window in milliseconds
 * @returns {{allowed: boolean, remaining: number, resetAt: number, retryAfter: number}}
 */
function checkRateLimit(identifier, maxRequests, windowMs) {
  const now = Date.now();
  const entry = rateLimitStore.get(identifier);

  if (!entry || now > entry.resetAt) {
    rateLimitStore.set(identifier, {
      count: 1,
      resetAt: now + windowMs,
    });
    return { allowed: true, remaining: maxRequests - 1, resetAt: now + windowMs, retryAfter: 0 };
  }

  if (entry.count >= maxRequests) {
    const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
    return { allowed: false, remaining: 0, resetAt: entry.resetAt, retryAfter };
  }

  entry.count += 1;
  return { allowed: true, remaining: maxRequests - entry.count, resetAt: entry.resetAt, retryAfter: 0 };
}

/**
 * Validate token and return token data.
 * @param {string} tokenStr - Token string
 * @returns {Object} Token data
 * @throws {TokenError} If invalid
 */
function validateToken(tokenStr) {
  if (!tokenStr || typeof tokenStr !== 'string') {
    throw new TokenError('Token is required');
  }

  const tokenData = tokenStore.get(tokenStr);
  if (!tokenData) {
    throw new TokenError('Token not found');
  }

  const now = Date.now();
  if (now > tokenData.createdAt + ROUTER_CONFIG.TOKEN_EXPIRY_SECONDS * 1000) {
    tokenStore.delete(tokenStr);
    throw new TokenError('Token expired', 'TOKEN_EXPIRED');
  }

  if (tokenData.used) {
    throw new TokenError('Token already used', 'TOKEN_USED');
  }

  return tokenData;
}

/**
 * Log audit event to database.
 * @param {string} action - Action name
 * @param {Object} details - Event details
 */
async function logAudit(action, details) {
  try {
    const db = DatabaseManager.getInstance();
    await db.insertOne('audit_logs', {
      action,
      details: JSON.stringify(details),
      severity: details.severity || 'info',
      ipHash: details.ip ? sha256(details.ip) : null,
      timestamp: new Date(),
      eventHash: generateHexToken(16),
    });
  } catch {
    // Silently fail - audit logging must not break requests
  }
}

/**
 * Get daily mutated endpoint URL.
 * @returns {string} Mutated URL path
 */
function getMutatedEndpoint() {
  const daySeed = new Date().toISOString().slice(0, 10);
  const mutationIndex = parseInt(sha256(daySeed).slice(0, 4), 16) % 1000;
  return `/api/v1/claim?m=${mutationIndex}`;
}

/**
 * Hash IP for storage/comparison.
 * @param {string} ip - IP address
 * @returns {string} Hashed IP
 */
function hashIP(ip) {
  const secret = requireEnv('IP_HASH_SECRET') || (process.env.NODE_ENV !== 'production' ? 'dev-ip-salt' : undefined);
  return sha256(ip + secret);
}

// ============================================================================
// MIDDLEWARE FACTORIES
// ============================================================================

/**
 * Create rate limit middleware.
 * @param {number} maxRequests - Max requests
 * @param {number} windowMs - Window in ms
 * @param {string} [keyPrefix] - Key prefix
 * @returns {Function} Express middleware
 */
function createRateLimitMiddleware(maxRequests, windowMs, keyPrefix = 'rl') {
  return (req, res, next) => {
    const ip = getClientIP(req);
    const key = `${keyPrefix}:${ip}:${req.path}`;
    const result = checkRateLimit(key, maxRequests, windowMs);

    setRateLimitHeaders(res, maxRequests, result.remaining, result.resetAt);

    if (!result.allowed) {
      res.setHeader('Retry-After', String(result.retryAfter));
      return sendError(res, `Rate limit exceeded. Try again in ${result.retryAfter}s.`, 'RATE_LIMIT_EXCEEDED', 429);
    }

    next();
  };
}

/**
 * Fingerprint extraction middleware.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {Function} next
 */
function fingerprintMiddleware(req, res, next) {
  try {
    const fp = {
      ip: getClientIP(req),
      userAgent: req.headers['user-agent'] || '',
      accept: req.headers.accept || '',
      acceptLanguage: req.headers['accept-language'] || '',
      acceptEncoding: req.headers['accept-encoding'] || '',
      secChUa: req.headers['sec-ch-ua'] || '',
      secChUaPlatform: req.headers['sec-ch-ua-platform'] || '',
      secChUaMobile: req.headers['sec-ch-ua-mobile'] || '',
      secFetchSite: req.headers['sec-fetch-site'] || '',
      secFetchMode: req.headers['sec-fetch-mode'] || '',
      secFetchDest: req.headers['sec-fetch-dest'] || '',
      forwardedProto: req.headers['x-forwarded-proto'] || req.protocol,
      dnt: req.headers.dnt,
      viewportWidth: req.headers['viewport-width'],
      deviceMemory: req.headers['device-memory'],
      dpr: req.headers.dpr,
      ect: req.headers.ect,
    };

    req.deviceFingerprint = fp;
    req.fingerprintHash = sha256(JSON.stringify(fp));
    next();
  } catch (err) {
    return sendError(res, 'Fingerprint collection failed', 'FINGERPRINT_ERROR', 500);
  }
}

/**
 * Behavior analysis middleware.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {Function} next
 */
function behaviorMiddleware(req, res, next) {
  try {
    const interactionData = req.body?.interactionData || {};
    const analyzer = new BehaviorAnalyzer();
    const score = analyzer.quickAnalyze({
      mouseEvents: interactionData.mouseEvents || [],
      scrollEvents: interactionData.scrollEvents || [],
      timing: interactionData.timing || {},
      userAgent: req.headers['user-agent'] || '',
    });

    req.behaviorScore = score;
    next();
  } catch (err) {
    req.behaviorScore = 50;
    next();
  }
}

// ============================================================================
// CORS / ORIGIN VALIDATION MIDDLEWARE
// ============================================================================

/**
 * Allowed origins set — loaded from environment or defaults.
 * Rejects: null origin, file://, unknown domains.
 */
const API_ALLOWED_ORIGINS = new Set(
  process.env.ALLOWED_ORIGINS?.split(',') || ['https://osmarmy.com']
);

/**
 * CORS middleware: own-domain-only enforcement.
 *
 * Security rules:
 * - If Origin header is present, it MUST match an allowed origin
 * - If Origin is missing, Referer MUST be present and match an allowed origin
 * - If BOTH are missing → reject (strong bot signal)
 * - null origin, file://, chrome-extension://, and unknown domains are rejected
 * - Only POST and OPTIONS methods are allowed on API paths
 * - Only Content-Type, Authorization, and X-CSRF-Token headers are permitted
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {Function} next
 */
export function corsMiddleware(req, res, next) {
  const origin = req.headers.origin;
  const referer = req.headers.referer;

  // 1. Reject null origin (common for script-initiated / iframe requests)
  if (origin === 'null') {
    return res.status(403).json({
      success: false,
      error: 'FORBIDDEN',
      message: 'Origin validation failed',
    });
  }

  // 2. Check Origin header first (most reliable)
  if (origin) {
    // Reject non-HTTP(S) origins
    if (origin.startsWith('file://') || origin.startsWith('chrome-extension://')) {
      return res.status(403).json({
        success: false,
        error: 'FORBIDDEN',
        message: 'Origin type not allowed',
      });
    }
    if (!API_ALLOWED_ORIGINS.has(origin)) {
      return res.status(403).json({
        success: false,
        error: 'FORBIDDEN',
        message: 'Origin not permitted',
      });
    }
    // Origin is allowed — set CORS headers
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  } else {
    // 3. No Origin header — check Referer as fallback
    if (referer) {
      try {
        const refererOrigin = new URL(referer).origin;
        if (!API_ALLOWED_ORIGINS.has(refererOrigin)) {
          return res.status(403).json({
            success: false,
            error: 'FORBIDDEN',
            message: 'Referer not permitted',
          });
        }
      } catch {
        return res.status(403).json({
          success: false,
          error: 'FORBIDDEN',
          message: 'Invalid referer format',
        });
      }
    } else {
      // 4. Both Origin and Referer are missing — strong bot signal
      // Skip for GET /health, /v1/status, /v1/health (public health checks)
      const publicPaths = ['/v1/health', '/v1/status', '/health'];
      if (!publicPaths.includes(req.path)) {
        return res.status(403).json({
          success: false,
          error: 'FORBIDDEN',
          message: 'Origin validation failed',
        });
      }
    }
  }

  // 5. Handle preflight OPTIONS requests
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, X-CSRF-Token'
    );
    res.setHeader('Access-Control-Max-Age', '86400');
    return res.status(204).end();
  }

  // 6. Set Vary header for proper cache differentiation
  res.setHeader('Vary', 'Origin, Authorization');

  next();
}

/**
 * Standalone function: validate Origin/Referer without middleware.
 * Used by codePage.js and other modules that need origin validation.
 *
 * @param {import('express').Request} req
 * @returns {{valid: boolean, reason: string|null}}
 */
export function validateOriginAndReferer(req) {
  const origin = req.headers.origin;
  const referer = req.headers.referer;

  if (origin === 'null') {
    return { valid: false, reason: 'ORIGIN_NULL' };
  }

  if (origin) {
    if (origin.startsWith('file://') || origin.startsWith('chrome-extension://')) {
      return { valid: false, reason: 'ORIGIN_SCHEME_NOT_ALLOWED' };
    }
    if (API_ALLOWED_ORIGINS.has(origin)) {
      return { valid: true, reason: null };
    }
    return { valid: false, reason: 'ORIGIN_NOT_ALLOWED' };
  }

  if (referer) {
    try {
      const refererOrigin = new URL(referer).origin;
      if (API_ALLOWED_ORIGINS.has(refererOrigin)) {
        return { valid: true, reason: null };
      }
      return { valid: false, reason: 'REFERER_NOT_ALLOWED' };
    } catch {
      return { valid: false, reason: 'REFERER_INVALID' };
    }
  }

  return { valid: false, reason: 'ORIGIN_AND_REFERER_MISSING' };
}

// ============================================================================
// HMAC CHALLENGE FOR FACTOR 1
// ============================================================================

/**
 * Generate server challenge for Factor 1.
 * @param {string} token - Claim token
 * @returns {{challenge: string, expectedResponse: string}} Challenge data
 */
function generateServerChallenge(token) {
  const secret = requireEnv('FACTOR1_SECRET') || (process.env.NODE_ENV !== 'production' ? 'dev-factor1-secret' : undefined);
  const challenge = generateHexToken(16);
  const message = `${token}:${challenge}`;
  const fullHmac = hmacSHA512(message, secret);
  const expectedResponse = fullHmac.substring(0, 8);

  return { challenge, expectedResponse };
}

/**
 * Verify Factor 1 response.
 * @param {string} token - Claim token
 * @param {string} response - Client response (first 8 chars of HMAC)
 * @returns {boolean} Valid or not
 */
function verifyFactor1Response(token, response) {
  const secret = requireEnv('FACTOR1_SECRET') || (process.env.NODE_ENV !== 'production' ? 'dev-factor1-secret' : undefined);
  const message = `${token}:challenge`;
  const fullHmac = hmacSHA512(message, secret);
  const expected = fullHmac.substring(0, 8);

  try {
    const bufA = Buffer.from(response, 'utf8');
    const bufB = Buffer.from(expected, 'utf8');
    if (bufA.length !== bufB.length) return false;
    return timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

// ============================================================================
// ROUTER SETUP
// ============================================================================

const router = Router();
const protector = createProtector({ blockThreshold: 100 });

// ============================================================================
// ROUTE 1: GET /api/v1/verify-token - Check token validity
// ============================================================================

router.get('/v1/verify-token', (req, res) => {
  try {
    const { token } = req.query;

    if (!token || typeof token !== 'string') {
      return sendError(res, 'Token is required', 'TOKEN_REQUIRED', 400);
    }

    const tokenData = tokenStore.get(token);
    if (!tokenData) {
      return sendError(res, 'Token not found or expired', 'TOKEN_NOT_FOUND', 404);
    }

    if (tokenData.used) {
      return sendError(res, 'Token already consumed', 'TOKEN_USED', 410);
    }

    const now = Date.now();
    const expiryTime = tokenData.createdAt + ROUTER_CONFIG.TOKEN_EXPIRY_SECONDS * 1000;
    const expiresIn = Math.max(0, Math.ceil((expiryTime - now) / 1000));

    if (expiresIn <= 0) {
      tokenStore.delete(token);
      return sendError(res, 'Token expired', 'TOKEN_EXPIRED', 410);
    }

    const factorsCompleted = tokenData.factorsCompleted ? Array.from(tokenData.factorsCompleted) : [];

    return sendSuccess(res, {
      valid: true,
      expiresIn,
      factorsRequired: 3,
      factorsCompleted,
    });
  } catch (err) {
    return sendError(res, 'Token verification failed', 'VERIFY_ERROR', 500);
  }
});

// ============================================================================
// ROUTE 2: POST /api/v1/factor/1 - Submit Factor 1 (Server proof)
// ============================================================================

router.post('/v1/factor/1', async (req, res) => {
  try {
    const { token, response } = req.body || {};

    if (!token || typeof token !== 'string') {
      return sendError(res, 'Token is required', 'TOKEN_REQUIRED', 400);
    }

    if (!response || typeof response !== 'string' || response.length !== 8) {
      return sendError(res, 'Response must be exactly 8 characters', 'INVALID_RESPONSE', 400);
    }

    let tokenData;
    try {
      tokenData = validateToken(token);
    } catch (err) {
      return sendError(res, err.message, err.code, 401);
    }

    // Check attempts
    const attempts = tokenData.attempts.get(1) || 0;
    if (attempts >= ROUTER_CONFIG.FACTOR_MAX_ATTEMPTS) {
      tokenStore.delete(token);
      await logAudit('FACTOR1_MAX_ATTEMPTS', {
        tokenHash: sha256(token),
        severity: 'high',
      });
      return sendError(res, 'Maximum attempts exceeded. Token destroyed.', 'MAX_ATTEMPTS_EXCEEDED', 403);
    }

    // Verify HMAC response
    const isValid = verifyFactor1Response(token, response);

    if (!isValid) {
      tokenData.attempts.set(1, attempts + 1);
      const attemptsLeft = ROUTER_CONFIG.FACTOR_MAX_ATTEMPTS - (attempts + 1);

      if (attempts + 1 >= ROUTER_CONFIG.FACTOR_MAX_ATTEMPTS) {
        tokenStore.delete(token);
        await logAudit('FACTOR1_FAILED_DESTROYED', {
          tokenHash: sha256(token),
          severity: 'high',
        });
        return sendError(res, 'Maximum attempts exceeded. Token destroyed.', 'MAX_ATTEMPTS_EXCEEDED', 403);
      }

      return sendSuccess(res, {
        success: false,
        attemptsLeft,
        message: 'Invalid HMAC response',
      }, 403);
    }

    // Success - mark factor 1 as completed
    tokenData.factorsCompleted.add(1);
    tokenData.attempts.set(1, 0);

    await logAudit('FACTOR1_PASSED', {
      tokenHash: sha256(token),
      severity: 'info',
    });

    return sendSuccess(res, {
      success: true,
      factor: 1,
      next: '/api/v1/factor/2',
    });
  } catch (err) {
    return sendError(res, 'Factor 1 verification failed', 'FACTOR1_ERROR', 500);
  }
});

// ============================================================================
// ROUTE 3: POST /api/v1/factor/2 - Submit Factor 2 (Mouse/Scroll proof)
// ============================================================================

router.post('/v1/factor/2', async (req, res) => {
  try {
    const { token, interactionData } = req.body || {};

    if (!token || typeof token !== 'string') {
      return sendError(res, 'Token is required', 'TOKEN_REQUIRED', 400);
    }

    if (!interactionData || typeof interactionData !== 'object') {
      return sendError(res, 'Interaction data is required', 'INTERACTION_REQUIRED', 400);
    }

    let tokenData;
    try {
      tokenData = validateToken(token);
    } catch (err) {
      return sendError(res, err.message, err.code, 401);
    }

    // Verify factor 1 passed first
    if (!tokenData.factorsCompleted.has(1)) {
      return sendError(res, 'Factor 1 must be completed first', 'FACTOR1_REQUIRED', 403);
    }

    // Analyze interaction data via BehaviorAnalyzer
    const analyzer = new BehaviorAnalyzer();
    const mouseEvents = interactionData.mouseEvents || [];
    const scrollEvents = interactionData.scrollEvents || [];
    const timing = interactionData.timing || {};

    // Detailed checks
    const mouseCount = mouseEvents.length;
    const scrollCount = scrollEvents.length;
    const elapsedTime = timing.elapsed || 0;

    // Calculate entropy from mouse movements
    let entropy = 0;
    if (mouseCount >= 2) {
      const movements = mouseEvents.map(e => `${e.x || 0},${e.y || 0}`).join('|');
      const freq = {};
      for (const ch of movements) {
        freq[ch] = (freq[ch] || 0) + 1;
      }
      const len = movements.length;
      for (const count of Object.values(freq)) {
        const p = count / len;
        entropy -= p * Math.log2(p);
      }
    }

    // Calculate average speed
    let avgSpeed = 0;
    if (mouseCount >= 2 && elapsedTime > 0) {
      let totalDist = 0;
      for (let i = 1; i < mouseEvents.length; i++) {
        const dx = (mouseEvents[i].x || 0) - (mouseEvents[i - 1].x || 0);
        const dy = (mouseEvents[i].y || 0) - (mouseEvents[i - 1].y || 0);
        totalDist += Math.sqrt(dx * dx + dy * dy);
      }
      avgSpeed = totalDist / (elapsedTime / 1000);
    }

    // Human checks: entropy > 0.7, 3+ movements, 1+ scroll, 5+ seconds, speed 100-5000px/sec
    const checks = {
      entropySufficient: entropy > 0.7,
      enoughMovements: mouseCount >= 3,
      enoughScroll: scrollCount >= 1,
      enoughTime: elapsedTime >= 5000,
      speedReasonable: avgSpeed >= 100 && avgSpeed <= 5000,
    };

    const score = analyzer.calculateBotScore ? analyzer.calculateBotScore(interactionData) : 0;

    // If any check fails, treat as bot
    const allPassed = Object.values(checks).every(Boolean);

    if (!allPassed) {
      const failedChecks = Object.entries(checks).filter(([, v]) => !v).map(([k]) => k);

      await logAudit('FACTOR2_BOT_DETECTED', {
        tokenHash: sha256(token),
        checks,
        score,
        severity: 'high',
      });

      // Trigger alert
      try {
        const alertManager = new AlertManager();
        await alertManager.send('BOT_BEHAVIOR_DETECTED', {
          tokenHash: sha256(token),
          failedChecks,
          score,
        });
      } catch {
        // Non-blocking
      }

      return sendSuccess(res, {
        success: false,
        score,
        reason: 'bot detected',
        failedChecks,
      }, 403);
    }

    // Success
    tokenData.factorsCompleted.add(2);

    await logAudit('FACTOR2_PASSED', {
      tokenHash: sha256(token),
      severity: 'info',
    });

    return sendSuccess(res, {
      success: true,
      factor: 2,
      next: '/api/v1/factor/3',
    });
  } catch (err) {
    return sendError(res, 'Factor 2 verification failed', 'FACTOR2_ERROR', 500);
  }
});

// ============================================================================
// ROUTE 4: POST /api/v1/factor/3 - Submit Factor 3 (Browser fingerprint)
// ============================================================================

router.post('/v1/factor/3', async (req, res) => {
  try {
    const { token, fingerprint } = req.body || {};

    if (!token || typeof token !== 'string') {
      return sendError(res, 'Token is required', 'TOKEN_REQUIRED', 400);
    }

    if (!fingerprint || typeof fingerprint !== 'object') {
      return sendError(res, 'Fingerprint data is required', 'FINGERPRINT_REQUIRED', 400);
    }

    let tokenData;
    try {
      tokenData = validateToken(token);
    } catch (err) {
      return sendError(res, err.message, err.code, 401);
    }

    // Verify factors 1 and 2 passed first
    if (!tokenData.factorsCompleted.has(1) || !tokenData.factorsCompleted.has(2)) {
      return sendError(res, 'Factors 1 and 2 must be completed first', 'PREVIOUS_FACTORS_REQUIRED', 403);
    }

    // Verify fingerprint via FingerprintVerifier
    const verifier = new FingerprintVerifier();
    const result = verifier.verify(fingerprint);

    // Checks: not automation, not headless, canvas present, valid hardware
    const checks = {
      notAutomation: !fingerprint.webdriver && !fingerprint.automation,
      notHeadless: !verifier.isHeadless(fingerprint),
      canvasPresent: !!(fingerprint.canvas && fingerprint.canvas.length > 10),
      validHardware: (fingerprint.hardwareConcurrency || 0) >= 1 && (fingerprint.hardwareConcurrency || 0) <= 128,
      validWebGL: !(fingerprint.webglVendor || '').toLowerCase().includes('headless'),
      noVM: !(fingerprint.webglRenderer || '').toLowerCase().includes('swiftshader'),
    };

    const allPassed = Object.values(checks).every(Boolean);

    if (!allPassed) {
      const failedChecks = Object.entries(checks).filter(([, v]) => !v).map(([k]) => k);

      await logAudit('FACTOR3_FINGERPRINT_INVALID', {
        tokenHash: sha256(token),
        checks,
        severity: 'high',
      });

      return sendSuccess(res, {
        success: false,
        reason: 'invalid fingerprint',
        failedChecks,
      }, 403);
    }

    // Store fingerprint for later comparison at reveal
    tokenData.browserFingerprint = JSON.stringify(fingerprint);
    tokenData.browserFingerprintHash = sha256(JSON.stringify(fingerprint));
    tokenData.factorsCompleted.add(3);

    await logAudit('FACTOR3_PASSED', {
      tokenHash: sha256(token),
      severity: 'info',
    });

    // Factor 3 passed - now must complete PoW + Behavioral challenge
    return sendSuccess(res, {
      success: true,
      factor: 3,
      redirect: true,
      url: '/api/v1/pow/challenge',
      message: 'Factor 3 passed. Complete proof-of-work challenge next.',
    });
  } catch (err) {
    return sendError(res, 'Factor 3 verification failed', 'FACTOR3_ERROR', 500);
  }
});

// ============================================================================
// ROUTE 5: POST /api/v1/pow/challenge - Get Proof-of-Work Challenge (Ultra Layer)
// ============================================================================

router.post('/v1/pow/challenge', createRateLimitMiddleware(10, 60000, 'pow'), (req, res) => {
  try {
    const { token } = req.body || {};

    if (!token || typeof token !== 'string') {
      return sendError(res, 'Token is required', 'TOKEN_REQUIRED', 400);
    }

    // Validate token
    let tokenData;
    try {
      tokenData = validateToken(token);
    } catch {
      return sendError(res, 'Invalid or expired token', 'TOKEN_INVALID', 403);
    }

    // Must have all 3 factors completed
    if (tokenData.factorsCompleted.size < 3) {
      return sendError(res, 'Complete all 3 factors first', 'FACTORS_INCOMPLETE', 403);
    }

    // Check if PoW already completed
    if (tokenData.powCompleted) {
      return sendSuccess(res, {
        completed: true,
        message: 'Proof-of-work already completed',
      });
    }

    // Generate challenge
    const challenge = generateProofOfWorkChallenge(token, 5); // difficulty 5

    // Store challenge server-side (don't send answer to client!)
    tokenData.powChallenge = challenge;

    // Send challenge WITHOUT the answer
    return sendSuccess(res, {
      challenge: {
        seed: challenge.seed,
        difficulty: challenge.difficulty,
        timestamp: challenge.timestamp,
        maxTime: challenge.maxTime,
        maxAttempts: challenge.maxAttempts,
      },
      message: `Find a nonce such that SHA256(seed + nonce + timestamp) has ${challenge.difficulty} leading zeros`,
    });

  } catch (err) {
    return sendError(res, 'PoW challenge generation failed', 'POW_CHALLENGE_ERROR', 500);
  }
});

// ============================================================================
// ROUTE 6: POST /api/v1/pow/verify - Verify Proof-of-Work Solution (Ultra Layer)
// ============================================================================

router.post('/v1/pow/verify', createRateLimitMiddleware(10, 60000, 'pow'), async (req, res) => {
  try {
    const { token, nonce } = req.body || {};

    if (!token || typeof token !== 'string') {
      return sendError(res, 'Token is required', 'TOKEN_REQUIRED', 400);
    }

    if (typeof nonce !== 'number' || nonce < 0) {
      return sendError(res, 'Valid nonce (number) is required', 'NONCE_REQUIRED', 400);
    }

    // Validate token
    let tokenData;
    try {
      tokenData = validateToken(token);
    } catch {
      return sendError(res, 'Invalid or expired token', 'TOKEN_INVALID', 403);
    }

    // Check if challenge exists
    if (!tokenData.powChallenge) {
      return sendError(res, 'No active challenge. Request one first.', 'NO_CHALLENGE', 400);
    }

    // Verify the solution
    const isValid = verifyProofOfWork(tokenData.powChallenge, nonce);

    if (!isValid) {
      await logAudit('POW_VERIFY_FAILED', {
        tokenHash: sha256(token),
        nonce,
        severity: 'medium',
      });

      return sendSuccess(res, {
        success: false,
        message: 'Invalid nonce. Keep trying or request a new challenge.',
      }, 403);
    }

    // Success!
    tokenData.powCompleted = true;

    await logAudit('POW_VERIFY_PASSED', {
      tokenHash: sha256(token),
      nonce,
      timeMs: Date.now() - tokenData.powChallenge.timestamp,
      severity: 'info',
    });

    return sendSuccess(res, {
      success: true,
      message: 'Proof-of-work verified!',
      next: '/api/v1/behavior/challenge',
    });

  } catch (err) {
    return sendError(res, 'PoW verification failed', 'POW_VERIFY_ERROR', 500);
  }
});

// ============================================================================
// ROUTE 7: POST /api/v1/behavior/challenge - Get Behavioral Challenge (Ultra Layer)
// ============================================================================

router.post('/v1/behavior/challenge', createRateLimitMiddleware(10, 60000, 'beh'), (req, res) => {
  try {
    const { token } = req.body || {};

    if (!token || typeof token !== 'string') {
      return sendError(res, 'Token is required', 'TOKEN_REQUIRED', 400);
    }

    // Validate token
    let tokenData;
    try {
      tokenData = validateToken(token);
    } catch {
      return sendError(res, 'Invalid or expired token', 'TOKEN_INVALID', 403);
    }

    // Must have PoW completed
    if (!tokenData.powCompleted) {
      return sendError(res, 'Complete proof-of-work first', 'POW_INCOMPLETE', 403);
    }

    // Generate behavioral challenges
    const challenges = generateBehavioralChallenge(token);

    // Store validation functions server-side
    tokenData.behaviorChallenges = challenges;

    // Send challenge descriptions to client (not validation logic)
    return sendSuccess(res, {
      challenges: challenges.map(c => ({
        id: c.id,
        type: c.type,
        description: c.description,
      })),
      message: 'Complete both behavioral challenges to continue',
    });

  } catch (err) {
    return sendError(res, 'Behavior challenge generation failed', 'BEH_CHALLENGE_ERROR', 500);
  }
});

// ============================================================================
// ROUTE 8: POST /api/v1/behavior/verify - Verify Behavioral Challenge (Ultra Layer)
// ============================================================================

router.post('/v1/behavior/verify', createRateLimitMiddleware(10, 60000, 'beh'), async (req, res) => {
  try {
    const { token, interactionData } = req.body || {};

    if (!token || typeof token !== 'string') {
      return sendError(res, 'Token is required', 'TOKEN_REQUIRED', 400);
    }

    if (!interactionData || !Array.isArray(interactionData)) {
      return sendError(res, 'Interaction data array is required', 'INTERACTION_DATA_REQUIRED', 400);
    }

    // Validate token
    let tokenData;
    try {
      tokenData = validateToken(token);
    } catch {
      return sendError(res, 'Invalid or expired token', 'TOKEN_INVALID', 403);
    }

    // Check if challenges exist
    if (!tokenData.behaviorChallenges || tokenData.behaviorChallenges.length === 0) {
      return sendError(res, 'No active behavioral challenges', 'NO_BEH_CHALLENGE', 400);
    }

    // Verify each challenge
    const results = [];
    let allPassed = true;

    for (const challenge of tokenData.behaviorChallenges) {
      const passed = challenge.validator(interactionData);
      results.push({
        id: challenge.id,
        type: challenge.type,
        passed,
      });
      if (!passed) allPassed = false;
    }

    if (!allPassed) {
      await logAudit('BEHAVIOR_VERIFY_FAILED', {
        tokenHash: sha256(token),
        results,
        severity: 'medium',
      });

      return sendSuccess(res, {
        success: false,
        results,
        message: 'Not all behavioral challenges passed. Try again.',
      }, 403);
    }

    // All passed!
    tokenData.behaviorCompleted = true;

    await logAudit('BEHAVIOR_VERIFY_PASSED', {
      tokenHash: sha256(token),
      results,
      severity: 'info',
    });

    // ALL 5 GATES PASSED! Return redirect to code page
    return sendSuccess(res, {
      success: true,
      message: 'All security checks passed!',
      redirect: true,
      url: '/code/reveal',
    });

  } catch (err) {
    return sendError(res, 'Behavior verification failed', 'BEH_VERIFY_ERROR', 500);
  }
});

// ============================================================================
// ROUTE 9: GET /api/v1/reveal - REDIRECT ONLY
// Code is NEVER returned by the API. Use POST /code/reveal for server-rendered page.
// ============================================================================

router.get('/v1/reveal', async (_req, res) => {
  // API NEVER returns code. Redirect to secure server-rendered page.
  return sendSuccess(res, {
    redirect: true,
    url: '/code/reveal',
  });
});

// ============================================================================
// ROUTE 6: POST /api/v1/pow - Proof-of-Work challenge
// ============================================================================

router.post('/v1/pow', (req, res) => {
  try {
    const clientIP = getClientIP(req);
    const { difficulty } = req.body || {};

    const requestedDifficulty = typeof difficulty === 'number' && difficulty >= 1 && difficulty <= 8
      ? difficulty
      : 4;

    // Check progressive difficulty
    const powRecord = powAttempts.get(clientIP);
    let actualDifficulty = requestedDifficulty;

    if (powRecord) {
      if (powRecord.blocked) {
        const now = Date.now();
        if (now < powRecord.blockedUntil) {
          const remainingMs = powRecord.blockedUntil - now;
          return sendError(
            res,
            `Blocked for ${Math.ceil(remainingMs / 60000)} minutes due to excessive PoW attempts`,
            'POW_BLOCKED',
            429
          );
        }
        powAttempts.delete(clientIP);
      }

      // Progressive: attempt 1=diff4, attempt 2=diff5, attempt 5+=block24h
      const attemptCount = powRecord.attempts;
      if (attemptCount >= ROUTER_CONFIG.POW_MAX_ATTEMPTS) {
        powRecord.blocked = true;
        powRecord.blockedUntil = Date.now() + ROUTER_CONFIG.POW_BLOCK_DURATION_MS;
        return sendError(
          res,
          'Too many PoW attempts. Blocked for 24 hours.',
          'POW_MAX_ATTEMPTS',
          429
        );
      }

      actualDifficulty = Math.min(requestedDifficulty + attemptCount, 8);
    }

    // Generate challenge
    const challenge = generateHexToken(16);

    // Store challenge with difficulty
    if (!powAttempts.has(clientIP)) {
      powAttempts.set(clientIP, { attempts: 0, lastAttempt: Date.now(), blocked: false, blockedUntil: 0 });
    }

    return sendSuccess(res, {
      challenge,
      difficulty: actualDifficulty,
    });
  } catch (err) {
    return sendError(res, 'PoW challenge generation failed', 'POW_ERROR', 500);
  }
});

// ROUTE 7: /v1/pow/verify — defined above (line 1027) — DUPLICATE REMOVED
// ============================================================================

// BUG 8 FIX: Removed duplicate router.post('/v1/pow/verify') that shadowed real implementation

// ============================================================================
// ROUTE 8: GET /api/v1/status - System status (public, no auth)
// ============================================================================

router.get('/v1/status', (req, res) => {
  const now = new Date();
  const dayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const mutationVersion = `v${Math.floor((now.getTime() - new Date('2024-01-01').getTime()) / 86400000) + 1}`;

  return sendSuccess(res, {
    status: 'operational',
    dailyMutation: 'active',
    version: '1.0.0',
    mutationVersion,
    serverTime: now.toISOString(),
    uptime: process.uptime(),
  });
});

// ============================================================================
// HEALTH CHECK
// ============================================================================

router.get('/v1/health', async (req, res) => {
  try {
    const db = DatabaseManager.getInstance();
    const dbHealthy = db.isConnected ? await Promise.race([
      db.findOne('gift_codes', {}, { projection: { _id: 1 } }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('DB timeout')), 3000)),
    ]).then(() => true).catch(() => false) : false;

    res.status(dbHealthy ? 200 : 503).json({
      success: dbHealthy,
      status: dbHealthy ? 'healthy' : 'degraded',
      database: dbHealthy ? 'connected' : 'disconnected',
      timestamp: new Date().toISOString(),
    });
  } catch {
    res.status(503).json({
      success: false,
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
    });
  }
});

// ============================================================================
// ROUTE 8.5: POST /api/v1/timer/sync - Get synced timer from server
// CRITICAL: Client timer MUST sync with server time-lock
// Returns releaseAt timestamp so client timer matches server exactly
// BUG 5 FIX: Uses tokenData.codeId (bound at /gift) for exact code lookup,
// falling back to global latest only for legacy/edge cases.
// ============================================================================

router.post('/v1/timer/sync', async (req, res) => {
  // BUG 4 FIX: serverTime defined FIRST (used in all return paths)
  const serverNow = Date.now();

  // Prevent CDN/proxy caching of sensitive timer data
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  try {
    const { token } = req.body || {};

    // Validate token exists
    let tokenData = null;
    let tokenValid = false;
    try {
      if (token) {
        tokenData = validateToken(token);
        tokenValid = true;
      }
    } catch {
      tokenValid = false;
    }

    // BUG 8 FIX: Invalid token = 403, not success with tokenValid:false
    if (!tokenValid) {
      return sendError(res, 'Invalid or expired session token', 'INVALID_TOKEN', 403);
    }

    // Get code's release time from DB
    const db = DatabaseManager.getInstance();
    let releaseAt = null;
    let codeExists = false;

    try {
      // codeId is MANDATORY — set by /gift when creating session
      if (!tokenData || !tokenData.codeId) {
        return sendError(res, 'Session not bound to any code', 'CODEID_MISSING', 403);
      }

      const codeDoc = await db.findOne('gift_codes', { _id: new ObjectId(tokenData.codeId) });

      if (!codeDoc) {
        return sendError(res, 'Code not found for this session', 'CODE_NOT_FOUND', 404);
      }

      if (codeDoc && codeDoc.releaseAt) {
        releaseAt = codeDoc.releaseAt.getTime();
        codeExists = true;
      }
    } catch (err) {
      // BUG 6 FIX: Log DB error, don't silently swallow
      console.error('[TIMER_SYNC] DB error:', err.message);
      return sendError(res, 'Database error', 'DB_ERROR', 500);
    }

    // Calculate remaining seconds
    let remainingSeconds = 0;
    let isReleased = false;
    if (releaseAt) {
      remainingSeconds = Math.max(0, Math.ceil((releaseAt - serverNow) / 1000));
      isReleased = serverNow >= releaseAt;
    }

    return sendSuccess(res, {
      serverTime: serverNow,
      releaseAt: releaseAt,
      remainingSeconds: remainingSeconds,
      isReleased: isReleased,
      codeExists: codeExists,
      tokenValid: tokenValid,
      // Source of truth message - client MUST obey this
      _sourceOfTruth: 'SERVER',
    });
  } catch (err) {
    return sendError(res, 'Timer sync failed', 'TIMER_SYNC_ERROR', 500);
  }
});

// ============================================================================
// ROUTE 9: POST /api/v1/secure-display - REDIRECT ONLY
// Code is NEVER returned via API. Server-rendered POST page is the ONLY delivery method.
// ============================================================================

router.post('/v1/secure-display', async (_req, res) => {
  // API NEVER returns code fragments, HTML, CSS, or JS.
  // Redirect to the secure server-rendered page.
  return sendSuccess(res, {
    redirect: true,
    url: '/code/reveal',
  });
});

// ============================================================================
// ROUTE 10: POST /api/v1/verify/channels - Check channel membership
// ============================================================================

router.post('/v1/verify/channels', async (req, res) => {
  try {
    const { telegramUserId } = req.body || {};

    if (!telegramUserId || typeof telegramUserId !== 'string') {
      return sendError(res, 'telegramUserId is required', 'INVALID_TELEGRAM_ID', 400);
    }

    const verifier = getTelegramVerifier();
    const result = await verifier.checkAllChannels(telegramUserId);

    await logAudit('CHANNEL_CHECK', {
      telegramUserId: sha256(telegramUserId),
      allJoined: result.allJoined,
      severity: 'info',
    });

    return sendSuccess(res, {
      allJoined: result.allJoined,
      channels: result.channels,
      message: result.message,
      folderLink: verifier.getFolderLink(),
    });
  } catch (err) {
    return sendError(res, 'Channel verification check failed', 'CHANNEL_CHECK_ERROR', 500);
  }
});

// ============================================================================
// ROUTE 11: POST /api/v1/verify/confirm - Confirm verification after joining
// ============================================================================

router.post('/v1/verify/confirm', async (req, res) => {
  try {
    const { telegramUserId, deviceFingerprint } = req.body || {};
    const clientIP = getClientIP(req);

    if (!telegramUserId || typeof telegramUserId !== 'string') {
      return sendError(res, 'telegramUserId is required', 'INVALID_TELEGRAM_ID', 400);
    }

    if (!deviceFingerprint || typeof deviceFingerprint !== 'string' || deviceFingerprint.length < 10) {
      return sendError(res, 'Invalid device fingerprint', 'INVALID_FINGERPRINT', 400);
    }

    const verifier = getTelegramVerifier();

    // Check 1: All 3 channels joined
    const channelResult = await verifier.checkAllChannels(telegramUserId);
    if (!channelResult.allJoined) {
      return sendSuccess(res, {
        success: false,
        verified: false,
        channels: channelResult.channels,
        message: channelResult.message,
      }, 403);
    }

    // Check 2: User not already verified today
    if (verifier.isVerifiedToday(telegramUserId)) {
      const existing = verifier.getVerification(telegramUserId);
      if (existing && existing.deviceFingerprint === sha256(deviceFingerprint)) {
        // Same device, generate a new token
        const token = generateHexToken(32);
        verificationTokenStore.set(token, {
          token,
          telegramUserId,
          createdAt: Date.now(),
        });
        return sendSuccess(res, {
          success: true,
          verified: true,
          token,
          message: 'Already verified! Redirecting to timer...',
        });
      }
      return sendError(res, 'Already verified on a different device today', 'ALREADY_VERIFIED', 403);
    }

    // Check 3: Device fingerprint valid (basic check)
    if (deviceFingerprint.length < 16) {
      return sendError(res, 'Invalid device fingerprint', 'INVALID_FINGERPRINT', 400);
    }

    // All checks passed - store verification
    verifier.storeVerification(telegramUserId, deviceFingerprint);

    // Generate verification token
    const token = generateHexToken(32);
    verificationTokenStore.set(token, {
      token,
      telegramUserId,
      createdAt: Date.now(),
    });

    await logAudit('VERIFICATION_CONFIRMED', {
      telegramUserId: sha256(telegramUserId),
      ipHash: hashIP(clientIP),
      fingerprintHash: sha256(deviceFingerprint),
      severity: 'info',
    });

    return sendSuccess(res, {
      success: true,
      verified: true,
      token,
      message: 'Verification successful! Redirecting to timer...',
    });
  } catch (err) {
    return sendError(res, 'Verification confirmation failed', 'VERIFY_CONFIRM_ERROR', 500);
  }
});

// ============================================================================
// ROUTE 12: GET /api/v1/token-status - Check token/link status for a user
// ============================================================================

router.get('/v1/token-status', async (req, res) => {
  try {
    const { telegramUserId } = req.query || {};

    if (!telegramUserId || typeof telegramUserId !== 'string') {
      return sendError(res, 'telegramUserId is required', 'INVALID_TELEGRAM_ID', 400);
    }

    const verifier = getTelegramVerifier();
    const status = verifier.getTokenStatus(telegramUserId);

    return sendSuccess(res, {
      hasToken: status.hasToken,
      tokenUsed: status.tokenUsed,
      deviceBound: status.deviceBound,
      canClaim: status.canClaim,
      isVerified: verifier.isVerifiedToday(telegramUserId),
    });
  } catch (err) {
    return sendError(res, 'Token status check failed', 'TOKEN_STATUS_ERROR', 500);
  }
});

// ============================================================================
// ROUTE 13: POST /api/v1/bind-device - Bind token to device
// ============================================================================

router.post('/v1/bind-device', async (req, res) => {
  try {
    const { token, deviceFingerprint, ip } = req.body || {};
    const clientIP = getClientIP(req);

    if (!token || typeof token !== 'string') {
      return sendError(res, 'Token is required', 'TOKEN_REQUIRED', 400);
    }

    if (!deviceFingerprint || typeof deviceFingerprint !== 'string' || deviceFingerprint.length < 10) {
      return sendError(res, 'Invalid device fingerprint', 'INVALID_FINGERPRINT', 400);
    }

    const verifier = getTelegramVerifier();
    const ipToStore = ip || clientIP;

    verifier.bindDevice(token, deviceFingerprint, ipToStore);

    await logAudit('DEVICE_BOUND', {
      tokenHash: sha256(token),
      fingerprintHash: sha256(deviceFingerprint),
      ipHash: hashIP(ipToStore),
      severity: 'info',
    });

    return sendSuccess(res, {
      bound: true,
      message: 'Token bound to this device',
    });
  } catch (err) {
    return sendError(res, 'Device binding failed', 'BIND_ERROR', 500);
  }
});

// ============================================================================
// ROUTE 14: POST /api/v1/check-device - Check if token is valid on this device
// ============================================================================

router.post('/v1/check-device', async (req, res) => {
  try {
    const { token, deviceFingerprint } = req.body || {};

    if (!token || typeof token !== 'string') {
      return sendError(res, 'Token is required', 'TOKEN_REQUIRED', 400);
    }

    if (!deviceFingerprint || typeof deviceFingerprint !== 'string' || deviceFingerprint.length < 10) {
      return sendError(res, 'Invalid device fingerprint', 'INVALID_FINGERPRINT', 400);
    }

    const verifier = getTelegramVerifier();
    const isBound = verifier.isDeviceBound(token, deviceFingerprint);

    if (isBound) {
      return sendSuccess(res, {
        valid: true,
        message: 'Token is valid on this device',
      });
    }

    // Check if the token exists in binding store at all
    const binding = verifier.getBinding(token);
    if (!binding) {
      return sendSuccess(res, {
        valid: false,
        message: 'Token not bound to any device',
      }, 403);
    }

    return sendSuccess(res, {
      valid: false,
      message: 'Token is bound to a different device',
    }, 403);
  } catch (err) {
    return sendError(res, 'Device check failed', 'CHECK_DEVICE_ERROR', 500);
  }
});

// ============================================================================
// ROUTE 1: POST /api/v1/claim - Request a gift code (REQUIRES TELEGRAM) - Now requires Telegram verification
// ============================================================================

router.post('/v1/claim',
  protector.all(),
  createRateLimitMiddleware(ROUTER_CONFIG.CLAIM_RATE_LIMIT_MAX, ROUTER_CONFIG.CLAIM_RATE_LIMIT_WINDOW_MS, 'claim'),
  fingerprintMiddleware,
  behaviorMiddleware,
  async (req, res) => {
    try {
      const clientIP = getClientIP(req);
      const { userId, deviceFingerprint, telegramUserId, verificationToken } = req.body || {};

      // NEW: Validate telegramUserId
      if (!telegramUserId || typeof telegramUserId !== 'string' || telegramUserId.length < 1 || telegramUserId.length > 64) {
        return sendError(res, 'telegramUserId is required. Complete channel verification first.', 'TELEGRAM_ID_REQUIRED', 400);
      }

      // NEW: Validate verificationToken
      if (!verificationToken || typeof verificationToken !== 'string') {
        return sendError(res, 'verificationToken is required. Complete channel verification first.', 'VERIFICATION_TOKEN_REQUIRED', 400);
      }

      // Validate inputs
      if (!userId || typeof userId !== 'string' || userId.length < 1 || userId.length > 64) {
        return sendError(res, 'Invalid userId', 'INVALID_USERID', 400);
      }

      if (!deviceFingerprint || typeof deviceFingerprint !== 'string' || deviceFingerprint.length < 10) {
        return sendError(res, 'Invalid device fingerprint', 'INVALID_FINGERPRINT', 400);
      }

      const verifier = getTelegramVerifier();

      // NEW CHECK 1: verificationToken valid
      const vtEntry = verificationTokenStore.get(verificationToken);
      if (!vtEntry) {
        return sendError(res, 'Invalid or expired verification token', 'INVALID_VERIFICATION_TOKEN', 401);
      }

      // NEW CHECK 2: telegramUserId matches verification token
      if (vtEntry.telegramUserId !== telegramUserId) {
        return sendError(res, 'Telegram ID does not match verification', 'TELEGRAM_ID_MISMATCH', 403);
      }

      // NEW CHECK 3: User is verified (channels joined)
      if (!verifier.isVerifiedToday(telegramUserId)) {
        return sendError(res, 'Not verified. Join all 3 channels first.', 'NOT_VERIFIED', 403);
      }

      // NEW CHECK 4: User not already claimed today
      if (verifier.hasClaimedToday(telegramUserId)) {
        return sendError(res, 'Already claimed today. Come back tomorrow!', 'ALREADY_CLAIMED', 429);
      }

      // NEW CHECK 5: Device fingerprint matches verification
      const verification = verifier.getVerification(telegramUserId);
      if (verification && verification.deviceFingerprint !== sha256(deviceFingerprint)) {
        return sendError(res, 'Device mismatch. Use the same device you verified with.', 'DEVICE_MISMATCH', 403);
      }

      // Check behavior score
      if (req.behaviorScore && req.behaviorScore > 70) {
        await logAudit('CLAIM_BOT_DETECTED', {
          ip: clientIP,
          userId,
          telegramUserId: sha256(telegramUserId),
          score: req.behaviorScore,
          severity: 'high',
        });
        try {
          const alertManager = new AlertManager();
          await alertManager.send('BOT_DETECTED', {
            userId,
            telegramUserId: sha256(telegramUserId),
            ip: clientIP,
            score: req.behaviorScore,
          });
        } catch {
          // Non-blocking
        }
        return sendError(res, 'Bot-like behavior detected', 'BOT_DETECTED', 403);
      }

      // Generate 256-bit random token (32 bytes = 256 bits)
      const token = generateHexToken(32);
      const now = Date.now();

      // Store token with binding
      tokenStore.set(token, {
        token,
        ip: clientIP,
        ipHash: hashIP(clientIP),
        fingerprint: deviceFingerprint,
        fingerprintHash: sha256(deviceFingerprint),
        userId,
        telegramUserId,
        createdAt: now,
        used: false,
        factorsCompleted: new Set(),
        attempts: new Map([[1, 0], [2, 0], [3, 0]]),
      });

      // Record the claim
      verifier.recordClaim(telegramUserId, token, deviceFingerprint);

      // Bind device
      verifier.bindDevice(token, deviceFingerprint, clientIP);

      // Consume verification token
      verificationTokenStore.delete(verificationToken);

      // Set auto-destruct timer
      setTimeout(() => {
        if (tokenStore.has(token) && !tokenStore.get(token).used) {
          tokenStore.delete(token);
        }
      }, ROUTER_CONFIG.TOKEN_EXPIRY_SECONDS * 1000 + 5000);

      // Log attempt
      await logAudit('CLAIM_INITIATED', {
        ip: clientIP,
        userId,
        telegramUserId: sha256(telegramUserId),
        tokenHash: sha256(token),
        severity: 'info',
      });

      const expiresAt = new Date(now + ROUTER_CONFIG.TOKEN_EXPIRY_SECONDS * 1000).toISOString();
      const mutatedUrl = getMutatedEndpoint();

      setRateLimitHeaders(res, ROUTER_CONFIG.CLAIM_RATE_LIMIT_MAX, 0, now + ROUTER_CONFIG.CLAIM_RATE_LIMIT_WINDOW_MS);

      // Set token in httpOnly cookie so API response body never exposes it
      res.cookie('fortress_token', token, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: ROUTER_CONFIG.TOKEN_EXPIRY_SECONDS * 1000 + 5000,
      });

      return sendSuccess(res, {
        redirect: true,
        url: '/redeem',
        message: 'Redirecting...',
      });
    } catch (err) {
      if (err instanceof ApiRouteError) {
        return sendError(res, err.message, err.code, err.statusCode);
      }
      await logAudit('CLAIM_ERROR', {
        error: err.message,
        severity: 'error',
      });
      return sendError(res, 'Claim request failed', 'CLAIM_ERROR', 500);
    }
  }
);

// ============================================================================
// ROUTE 15: POST /api/v1/verify - Check if user is verified (all factors done)
// ============================================================================

router.post('/v1/verify', async (req, res) => {
  try {
    const { token } = req.body || {};

    if (!token || typeof token !== 'string') {
      return sendError(res, 'Token is required', 'TOKEN_REQUIRED', 400);
    }

    let tokenData;
    try {
      tokenData = validateToken(token);
    } catch (err) {
      return sendError(res, err.message, err.code, 401);
    }

    const factorsCompleted = tokenData.factorsCompleted ? Array.from(tokenData.factorsCompleted) : [];
    const allFactorsCompleted = factorsCompleted.length >= 3;

    return sendSuccess(res, {
      verified: allFactorsCompleted,
      factorsCompleted,
      factorsRequired: 3,
      redirect: allFactorsCompleted,
      url: allFactorsCompleted ? '/code/reveal' : undefined,
    });
  } catch (err) {
    return sendError(res, 'Verification check failed', 'VERIFY_ERROR', 500);
  }
});

// ============================================================================
// ROUTE 16: POST /api/v1/code-status - Check if code is ready to be revealed
// ============================================================================

router.post('/v1/code-status', async (req, res) => {
  try {
    const { token } = req.body || {};

    if (!token || typeof token !== 'string') {
      return sendError(res, 'Token is required', 'TOKEN_REQUIRED', 400);
    }

    let tokenData;
    try {
      tokenData = validateToken(token);
    } catch (err) {
      return sendError(res, err.message, err.code, 401);
    }

    const factorsCompleted = tokenData.factorsCompleted ? Array.from(tokenData.factorsCompleted) : [];
    const ready = factorsCompleted.length >= 3;

    return sendSuccess(res, {
      ready,
      factorsCompleted,
      factorsRequired: 3,
      redirect: ready,
      url: ready ? '/code/reveal' : undefined,
    });
  } catch (err) {
    return sendError(res, 'Code status check failed', 'CODE_STATUS_ERROR', 500);
  }
});

// ============================================================================
// D FIX: Public Config — safe values for frontend (NO secrets)
// ============================================================================
router.get('/v1/config/public', (_req, res) => {
  res.json({
    success: true,
    data: {
      botUsername: process.env.TELEGRAM_BOT_USERNAME || 'OSMArmyBot',
      baseUrl: process.env.BASE_URL || 'https://osmarmy.com',
      channels: {
        folderLink: process.env.TELEGRAM_CHANNEL_FOLDER || 'https://t.me/addlist/yZZ5Y0yKuBNhMjc9',
      },
      version: '3.5.14',
    },
  });
});

// ============================================================================
// ERROR HANDLER
// ============================================================================

router.use((err, req, res, _next) => {
  if (err instanceof SecurityViolationError) {
    return res.status(403).json({
      success: false,
      error: 'Security check failed',
      code: 'FORTRESS_BLOCKED',
      timestamp: new Date().toISOString(),
    });
  }

  // Never expose stack traces or internal details
  return res.status(500).json({
    success: false,
    error: 'Internal server error',
    code: 'INTERNAL_ERROR',
    timestamp: new Date().toISOString(),
  });
});

export default router;

// ============================================================================
// NAMED EXPORTS for shared modules (codePage.js needs these)
// ============================================================================

export { tokenStore, validateToken, ROUTER_CONFIG, hashIP, logAudit, sendError, sendSuccess };
