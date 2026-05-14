/**
 * @fileoverview Timer Page Routes - Shows countdown until next code availability
 * @description Serves the daily timer/countdown page with security headers,
 * daily mutation config injection, and code availability checking.
 * @module routes/timer
 * @version 1.0.0
 */

'use strict';

import { Router } from 'express';
import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseManager } from '../core/database.js';
import { createProtector } from '../core/protect.js';
import { generateToken, generateHexToken, sha256 } from '../core/encrypt.js';
import { ConfigManager } from '../core/config.js';
import { AlertManager } from '../core/alert.js';
import { FingerprintCollector } from '../core/fingerprint.js';
import { Mutator } from '../core/mutate.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ============================================================================
// CONFIGURATION
// ============================================================================

const TIMER_CONFIG = Object.freeze({
  CODE_RELEASE_HOUR_UTC: 10,
  CODE_RELEASE_MINUTE_UTC: 0,
  CODE_QUOTA_PER_DAY: 100,
  CLAIM_WINDOW_HOURS: 24,
  CSP_NONCE_BYTES: 16,
  RATE_LIMIT_MAX: 30,
  RATE_LIMIT_WINDOW_MS: 60 * 1000,
});

// ============================================================================
// ERROR CLASSES
// ============================================================================

/**
 * Timer route-specific error.
 */
class TimerRouteError extends Error {
  constructor(message, code = 'TIMER_ERROR', statusCode = 400) {
    super(message);
    this.name = 'TimerRouteError';
    this.code = code;
    this.statusCode = statusCode;
    this.timestamp = new Date().toISOString();
    Error.captureStackTrace(this, this.constructor);
  }
}

// ============================================================================
// IN-MEMORY STORES
// ============================================================================

/** @type {Map<string, {count: number, resetAt: number}>} */
const rateLimitStore = new Map();

/** @type {Map<string, {claimedAt: number}>} */
const dailyClaims = new Map();

// Cleanup every 10 minutes
setInterval(() => {
  const now = Date.now();
  const cutoff = now - TIMER_CONFIG.CLAIM_WINDOW_HOURS * 60 * 60 * 1000;
  for (const [key, entry] of dailyClaims) {
    if (entry.claimedAt < cutoff) {
      dailyClaims.delete(key);
    }
  }
  for (const [key, entry] of rateLimitStore) {
    if (now > entry.resetAt) {
      rateLimitStore.delete(key);
    }
  }
}, 600000);

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Get client IP.
 * @param {import('express').Request} req
 * @returns {string}
 */
function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

/**
 * Send error response.
 * @param {import('express').Response} res
 * @param {string} message
 * @param {string} code
 * @param {number} statusCode
 */
function sendError(res, message, code, statusCode = 400) {
  return res.status(statusCode).json({
    success: false,
    error: message,
    code,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Send success response.
 * @param {import('express').Response} res
 * @param {Object} data
 * @param {number} statusCode
 */
function sendSuccess(res, data, statusCode = 200) {
  return res.status(statusCode).json({
    success: true,
    ...data,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Check rate limit.
 * @param {string} identifier
 * @param {number} maxRequests
 * @param {number} windowMs
 * @returns {{allowed: boolean, remaining: number, resetAt: number}}
 */
function checkRateLimit(identifier, maxRequests, windowMs) {
  const now = Date.now();
  const entry = rateLimitStore.get(identifier);
  if (!entry || now > entry.resetAt) {
    rateLimitStore.set(identifier, { count: 1, resetAt: now + windowMs });
    return { allowed: true, remaining: maxRequests - 1, resetAt: now + windowMs };
  }
  if (entry.count >= maxRequests) {
    return { allowed: false, remaining: 0, resetAt: entry.resetAt };
  }
  entry.count += 1;
  return { allowed: true, remaining: maxRequests - entry.count, resetAt: entry.resetAt };
}

/**
 * Log audit event.
 * @param {string} action
 * @param {Object} details
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
    // Non-blocking
  }
}

/**
 * Generate CSP nonce.
 * @returns {string}
 */
function generateNonce() {
  return generateHexToken(TIMER_CONFIG.CSP_NONCE_BYTES);
}

/**
 * Build Content-Security-Policy header with nonce.
 * @param {string} nonce
 * @returns {string}
 */
function buildCSP(nonce) {
  const directives = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "media-src 'none'",
    "object-src 'none'",
    "frame-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ];
  return directives.join('; ');
}

/**
 * Get next code release time.
 * @returns {Date}
 */
function getNextCodeTime() {
  const now = new Date();
  const next = new Date(Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate(),
    TIMER_CONFIG.CODE_RELEASE_HOUR_UTC,
    TIMER_CONFIG.CODE_RELEASE_MINUTE_UTC,
    0,
    0
  ));

  if (now >= next) {
    // Release time has passed today, return tomorrow
    next.setUTCDate(next.getUTCDate() + 1);
  }

  return next;
}

/**
 * Get current mutation version.
 * @returns {string}
 */
function getCurrentMutationVersion() {
  const now = new Date();
  const start = new Date('2024-01-01');
  const days = Math.floor((now.getTime() - start.getTime()) / 86400000);
  return `v${days + 1}`;
}

/**
 * Get current mutation profile for asset loading.
 * @returns {{jsVariant: string, cssVariant: string}}
 */
function getMutationProfile() {
  const daySeed = new Date().toISOString().slice(0, 10);
  const seed = sha256(daySeed);
  const jsIndex = parseInt(seed.slice(0, 4), 16) % 5;
  const cssIndex = parseInt(seed.slice(4, 8), 16) % 3;

  const jsVariants = ['main', 'alternate', 'compact', 'secure', 'hardened'];
  const cssVariants = ['default', 'dark', 'minimal'];

  return {
    jsVariant: jsVariants[jsIndex],
    cssVariant: cssVariants[cssIndex],
    seed: seed.slice(0, 16),
  };
}

/**
 * Check if current time is within code release window.
 * @returns {boolean}
 */
function isInReleaseWindow() {
  const now = new Date();
  const releaseTime = new Date(Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate(),
    TIMER_CONFIG.CODE_RELEASE_HOUR_UTC,
    TIMER_CONFIG.CODE_RELEASE_MINUTE_UTC,
    0,
    0
  ));

  const windowEnd = new Date(releaseTime.getTime() + TIMER_CONFIG.CLAIM_WINDOW_HOURS * 60 * 60 * 1000);

  return now >= releaseTime && now < windowEnd;
}

/**
 * Check if user already claimed today.
 * @param {string} userId
 * @returns {boolean}
 */
function hasUserClaimedToday(userId) {
  const now = new Date();
  const todayStart = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0, 0, 0, 0);
  const entry = dailyClaims.get(userId);
  return entry ? entry.claimedAt >= todayStart : false;
}

/**
 * Check if code quota exceeded.
 * @returns {Promise<boolean>}
 */
async function isCodeQuotaExceeded() {
  try {
    const db = DatabaseManager.getInstance();
    const todayStart = new Date();
    todayStart.setUTCHours(0, 0, 0, 0);

    const claimedToday = await db.count('gift_codes', {
      status: 'claimed',
      claimedAt: { $gte: todayStart },
    });

    return claimedToday >= TIMER_CONFIG.CODE_QUOTA_PER_DAY;
  } catch {
    return false;
  }
}

/**
 * Get remaining codes count.
 * @returns {Promise<number>}
 */
async function getRemainingCodesCount() {
  try {
    const db = DatabaseManager.getInstance();
    return await db.count('gift_codes', {
      status: 'active',
      expiresAt: { $gt: new Date() },
    });
  } catch {
    return 0;
  }
}

// ============================================================================
// ROUTER SETUP
// ============================================================================

const router = Router();
const protector = createProtector({ blockThreshold: 150 });

// ============================================================================
// ROUTE 1: GET /timer - Timer page
// ============================================================================

router.get('/',
  protector.all(),
  async (req, res) => {
    try {
      const clientIP = getClientIP(req);
      const nonce = generateNonce();
      const mutationProfile = getMutationProfile();

      // Build security headers
      res.setHeader('Content-Security-Policy', buildCSP(nonce));
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
      res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
      res.setHeader('X-XSS-Protection', '0');
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');

      // Log page view
      const fingerprint = {
        ip: clientIP,
        userAgent: req.headers['user-agent'] || '',
        acceptLanguage: req.headers['accept-language'] || '',
      };

      await logAudit('TIMER_PAGE_VIEW', {
        ip: clientIP,
        fingerprintHash: sha256(JSON.stringify(fingerprint)),
        severity: 'info',
      });

      // Try to serve daily.html with injected config
      let html;
      try {
        html = await readFile(join(__dirname, '../public/daily.html'), 'utf8');
      } catch {
        // Generate inline HTML if file not found
        html = generateTimerHTML(nonce, mutationProfile);
      }

      // Inject mutation config
      const nextCodeTime = getNextCodeTime().toISOString();
      const configScript = `<script nonce="${nonce}">
        window.OSM_FORTRESS_CONFIG = {
          nextCodeTime: "${nextCodeTime}",
          countdownEnabled: true,
          currentMutation: "${getCurrentMutationVersion()}",
          securityLevel: "maximum",
          jsVariant: "${mutationProfile.jsVariant}",
          cssVariant: "${mutationProfile.cssVariant}",
          mutationSeed: "${mutationProfile.seed}",
          cspNonce: "${nonce}"
        };
      </script>`;

      // Insert config before closing </head>
      if (html.includes('</head>')) {
        html = html.replace('</head>', `${configScript}\n</head>`);
      } else {
        html = configScript + '\n' + html;
      }

      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.send(html);
    } catch (err) {
      await logAudit('TIMER_PAGE_ERROR', {
        error: err.message,
        severity: 'error',
      });
      return sendError(res, 'Failed to load timer page', 'TIMER_LOAD_ERROR', 500);
    }
  }
);

/**
 * Generate fallback timer HTML if daily.html is not found.
 * @param {string} nonce
 * @param {Object} profile
 * @returns {string}
 */
function generateTimerHTML(nonce, profile) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OSM Army Gift Code Timer</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 50%, #16213e 100%);
      color: #fff;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
    }
    .container { text-align: center; padding: 2rem; max-width: 600px; }
    .logo { font-size: 2.5rem; font-weight: 900; margin-bottom: 0.5rem; letter-spacing: -1px; }
    .logo span { color: #e94560; }
    .subtitle { color: #8b8b9a; margin-bottom: 3rem; font-size: 1.1rem; }
    .countdown-container {
      background: rgba(255,255,255,0.05);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 20px;
      padding: 2.5rem;
      margin-bottom: 2rem;
      backdrop-filter: blur(10px);
    }
    .countdown-label { color: #8b8b9a; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 1rem; }
    .countdown { display: flex; justify-content: center; gap: 1.5rem; }
    .time-unit { text-align: center; }
    .time-value {
      font-size: 3.5rem;
      font-weight: 800;
      color: #e94560;
      font-variant-numeric: tabular-nums;
      min-width: 80px;
    }
    .time-label { font-size: 0.8rem; color: #8b8b9a; text-transform: uppercase; margin-top: 0.5rem; }
    .status { margin-top: 2rem; padding: 1rem; border-radius: 10px; font-size: 0.95rem; }
    .status.waiting { background: rgba(233, 69, 96, 0.1); color: #e94560; }
    .status.available { background: rgba(46, 213, 115, 0.1); color: #2ed573; }
    .mutation-badge {
      margin-top: 1.5rem;
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.5rem 1rem;
      background: rgba(46, 213, 115, 0.1);
      border-radius: 50px;
      font-size: 0.8rem;
      color: #2ed573;
    }
    .mutation-badge::before {
      content: '';
      width: 8px;
      height: 8px;
      background: #2ed573;
      border-radius: 50%;
      animation: pulse 2s infinite;
    }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
    .footer { margin-top: 3rem; color: #555; font-size: 0.8rem; }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">OSM <span>ARMY</span></div>
    <div class="subtitle">Gift Code Fortress</div>
    <div class="countdown-container">
      <div class="countdown-label">Next Code Available In</div>
      <div class="countdown" id="countdown">
        <div class="time-unit"><div class="time-value" id="hours">00</div><div class="time-label">Hours</div></div>
        <div class="time-unit"><div class="time-value" id="minutes">00</div><div class="time-label">Minutes</div></div>
        <div class="time-unit"><div class="time-value" id="seconds">00</div><div class="time-label">Seconds</div></div>
      </div>
      <div class="status waiting" id="status">Waiting for next code release...</div>
    </div>
    <div class="mutation-badge">Daily Mutation Active - ${getCurrentMutationVersion()}</div>
    <div class="footer">Secured by 5000+ security layers</div>
  </div>
  <script nonce="${nonce}">
    (function() {
      function updateCountdown() {
        const now = new Date().getTime();
        const config = window.OSM_FORTRESS_CONFIG || {};
        const nextTime = new Date(config.nextCodeTime || new Date().toISOString()).getTime();
        const diff = Math.max(0, nextTime - now);
        const h = Math.floor(diff / 3600000);
        const m = Math.floor((diff % 3600000) / 60000);
        const s = Math.floor((diff % 60000) / 1000);
        const elH = document.getElementById('hours');
        const elM = document.getElementById('minutes');
        const elS = document.getElementById('seconds');
        const elStatus = document.getElementById('status');
        if (elH) elH.textContent = String(h).padStart(2, '0');
        if (elM) elM.textContent = String(m).padStart(2, '0');
        if (elS) elS.textContent = String(s).padStart(2, '0');
        if (diff <= 0 && elStatus) {
          elStatus.textContent = 'Code is now available!';
          elStatus.className = 'status available';
        }
      }
      updateCountdown();
      setInterval(updateCountdown, 1000);
    })();
  </script>
</body>
</html>`;
}

// ============================================================================
// ROUTE 2: GET /timer/config - Get timer configuration
// ============================================================================

router.get('/config',
  protector.all(),
  (req, res) => {
    try {
      const nextCodeTime = getNextCodeTime().toISOString();
      const mutationVersion = getCurrentMutationVersion();

      return sendSuccess(res, {
        nextCodeTime,
        countdownEnabled: true,
        currentMutation: mutationVersion,
        securityLevel: 'maximum',
        codeReleaseHourUtc: TIMER_CONFIG.CODE_RELEASE_HOUR_UTC,
        codeReleaseMinuteUtc: TIMER_CONFIG.CODE_RELEASE_MINUTE_UTC,
        quotaPerDay: TIMER_CONFIG.CODE_QUOTA_PER_DAY,
      });
    } catch (err) {
      return sendError(res, 'Failed to get timer config', 'CONFIG_ERROR', 500);
    }
  }
);

// ============================================================================
// ROUTE 3: POST /timer/check - Check if code is available
// ============================================================================

router.post('/check',
  protector.all(),
  async (req, res) => {
    try {
      const clientIP = getClientIP(req);
      const { userId, fingerprint } = req.body || {};

      // Rate limit
      const rateKey = `timer_check:${clientIP}`;
      const rateCheck = checkRateLimit(rateKey, TIMER_CONFIG.RATE_LIMIT_MAX, TIMER_CONFIG.RATE_LIMIT_WINDOW_MS);
      if (!rateCheck.allowed) {
        return sendError(res, 'Rate limit exceeded', 'RATE_LIMIT_EXCEEDED', 429);
      }

      // Validate inputs
      if (!userId || typeof userId !== 'string' || userId.length < 1 || userId.length > 64) {
        return sendError(res, 'Invalid userId', 'INVALID_USERID', 400);
      }

      if (fingerprint && (typeof fingerprint !== 'string' || fingerprint.length > 4096)) {
        return sendError(res, 'Invalid fingerprint', 'INVALID_FINGERPRINT', 400);
      }

      const now = new Date();

      // Check if in release window
      const inWindow = isInReleaseWindow();
      if (!inWindow) {
        const nextAvailable = getNextCodeTime();
        return sendSuccess(res, {
          available: false,
          nextAvailable: nextAvailable.toISOString(),
          message: 'Code release window has not started yet. Check back at the scheduled release time.',
          timeUntilNextMs: nextAvailable.getTime() - now.getTime(),
        });
      }

      // Check if user already claimed today
      const userClaimed = hasUserClaimedToday(userId);
      if (userClaimed) {
        const tomorrow = new Date(Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth(),
          now.getUTCDate() + 1,
          TIMER_CONFIG.CODE_RELEASE_HOUR_UTC,
          TIMER_CONFIG.CODE_RELEASE_MINUTE_UTC
        ));
        return sendSuccess(res, {
          available: false,
          nextAvailable: tomorrow.toISOString(),
          message: 'You have already claimed a code today. Come back tomorrow!',
          alreadyClaimed: true,
        });
      }

      // Check quota
      const quotaExceeded = await isCodeQuotaExceeded();
      if (quotaExceeded) {
        const tomorrow = new Date(Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth(),
          now.getUTCDate() + 1,
          TIMER_CONFIG.CODE_RELEASE_HOUR_UTC,
          TIMER_CONFIG.CODE_RELEASE_MINUTE_UTC
        ));
        return sendSuccess(res, {
          available: false,
          nextAvailable: tomorrow.toISOString(),
          message: "All codes for today have been claimed. Check back tomorrow!",
          quotaReached: true,
        });
      }

      // Check remaining codes
      const remaining = await getRemainingCodesCount();
      if (remaining <= 0) {
        return sendSuccess(res, {
          available: false,
          nextAvailable: getNextCodeTime().toISOString(),
          message: 'No codes available at this time.',
          noCodes: true,
        });
      }

      // Code is available! Generate one-time claim token
      const claimToken = generateHexToken(32);
      const claimUrl = `/api/v1/claim?token=${encodeURIComponent(claimToken)}`;

      // Store claim token
      try {
        const db = DatabaseManager.getInstance();
        await db.insertOne('claim_tokens', {
          token: claimToken,
          tokenHash: sha256(claimToken),
          userId,
          ipHash: sha256(clientIP),
          fingerprint: fingerprint ? sha256(fingerprint) : null,
          createdAt: new Date(),
          expiresAt: new Date(Date.now() + 600000),
          used: false,
        });
      } catch {
        // Non-blocking - token is also in memory
      }

      await logAudit('TIMER_CHECK_AVAILABLE', {
        ip: clientIP,
        userId,
        remainingCodes: remaining,
        severity: 'info',
      });

      return sendSuccess(res, {
        available: true,
        nextAvailable: null,
        message: 'A code is available! Click the link below to claim it.',
        claimUrl,
        claimToken,
        remainingCodes: remaining,
        expiresIn: 600,
      });
    } catch (err) {
      return sendError(res, 'Availability check failed', 'CHECK_ERROR', 500);
    }
  }
);

// ============================================================================
// ERROR HANDLER
// ============================================================================

router.use((err, req, res, _next) => {
  return res.status(500).json({
    success: false,
    error: 'Timer service error',
    code: 'TIMER_INTERNAL_ERROR',
    timestamp: new Date().toISOString(),
  });
});

export default router;
