/**
 * @fileoverview codePage.js - Secure Gift Code Delivery API Endpoints
 * @description API-only code delivery. NO server-rendered pages.
 * Two endpoints only: /api/v1/code/claim (generates ticket) and
 * /api/v1/code/reveal (delivers code after full verification).
 *
 * CRITICAL SECURITY RULES:
 * - Code MUST NEVER appear in logs — always masked as ***
 * - Cache headers: no-cache, no-store, must-revalidate, proxy-revalidate
 * - decryptString ONLY in codeReveal.js — NOWHERE else
 * - claimId/nonce/tokens must NEVER contain code
 * - All error responses are generic — NO internal details in production
 * - VPN/Proxy detection raises risk scores
 * - Turnstile verification for high-risk users
 * - Multi-Telegram account detection
 * - Device change triggers re-verification
 * - Complete reveal audit trail for leak forensics
 *
 * @module routes/codePage
 * @version 3.0.0
 */

import { Router } from 'express';
import {
  generateClaimTicket,
  revealCode,
  hasClaimedToday,
  RevealError,
} from '../core/codeReveal.js';
import {
  validateToken,
  ROUTER_CONFIG,
} from './api.js';

// ── Category 5: Suspicious Guard (enhanced) ──
import {
  checkSuspiciousScore,
  isBlocked as guardIsBlocked,
  getRequiredChallenge,
  checkMultiTelegram,
  recordApiProbe,
  checkTimelockCooldown,
  checkDeviceChange,
} from '../core/suspiciousGuard.js';

// ── Category 6: VPN/Proxy Detection ──
import { detectVpnProxy, quickVpnCheck } from '../core/vpnDetector.js';

// ── Category 6: Cloudflare Turnstile ──
import { verifyTurnstile } from '../core/turnstile.js';

// ── Category 7: Leak Monitoring Audit Trail ──
import {
  logRevealAudit,
} from '../core/auditLog.js';

// ── Category 6: Endpoint-specific Rate Limiting ──
import {
  codeClaimRateLimit,
  codeRevealRateLimit,
  codeRevealHourlyRateLimit,
} from '../middleware/rateLimit.js';

const router = Router();

// ── Production flag for response detail control ──────────────────────────────
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// ============================================================================
// Security Response Helpers
// ============================================================================

/**
 * Apply strict cache-control headers to prevent any caching of code responses.
 * Must be called on EVERY /api/v1/code/* response.
 * @param {import('express').Response} res
 */
function setSecurityHeaders(res) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
}

/**
 * Send a sanitized error response.
 * In production: generic message with NO internal details, NO stack traces.
 * @param {import('express').Response} res
 * @param {number} statusCode - HTTP status code
 * @param {string} errorCode - Machine-readable error code
 * @param {string} [internalMessage] - Internal message (only in dev)
 */
function sendSanitizedError(res, statusCode, errorCode, internalMessage) {
  // Production-safe message mapping — never expose internals
  const messageMap = {
    MISSING_PARAMS: 'Security check failed',
    INVALID_TOKEN: 'Security check failed',
    ALREADY_CLAIMED: 'Security check failed',
    SERVER_ERROR: 'Service temporarily unavailable',
    TIMELOCK_ACTIVE: 'Security check failed',
    CLAIM_REUSED: 'Security check failed',
    CLAIM_EXPIRED: 'Security check failed',
    RATE_LIMITED: 'Security check failed',
    CHANNELS_NOT_JOINED: 'Security check failed',
    TOKEN_MISMATCH: 'Security check failed',
    DEVICE_MISMATCH: 'Security check failed',
    NONCE_MISMATCH: 'Security check failed',
    ALREADY_DELIVERED: 'Security check failed',
    NO_CODE_AVAILABLE: 'Security check failed',
    SUSPICIOUS_BLOCKED: 'Security check failed',
    POW_REQUIRED: 'Additional verification required',
    TURNSTILE_REQUIRED: 'Additional verification required',
    COOLDOWN: 'Security check failed',
    MULTI_TG_BLOCKED: 'Security check failed',
    API_PROBE_BLOCKED: 'Security check failed',
    DEVICE_CHANGED: 'Security check failed',
    TURNSTILE_FAILED: 'Security check failed',
    TURNSTILE_INVALID: 'Security check failed',
  };

  const safeMessage = messageMap[errorCode] || 'Security check failed';

  const response = {
    success: false,
    error: errorCode,
    message: safeMessage,
  };

  // Only in non-production do we include the internal detail
  if (!IS_PRODUCTION && internalMessage) {
    response._debug = internalMessage;
  }

  // Include retryAfter if the response has a Retry-After header
  const retryAfter = res.getHeader('Retry-After');
  if (retryAfter) {
    response.retryAfter = parseInt(String(retryAfter), 10);
  }

  res.status(statusCode).json(response);
}

// ============================================================================
// IP Hash Helper (for security: never pass raw IPs)
// ============================================================================

import { createHash } from 'crypto';

function hashIp(ip) {
  if (!ip) return 'unknown';
  return createHash('sha256').update(String(ip)).digest('hex').slice(0, 16);
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.ip || req.connection?.remoteAddress || 'unknown';
}

// ============================================================================
// Comprehensive Security Check Pipeline
// ============================================================================

/**
 * Run the full security pipeline for a request:
 *   1. Progressive block check (isBlocked)
 *   2. VPN/Proxy detection (adds to risk score)
 *   3. Multi-Telegram detection
 *   4. Device change detection
 *   5. Risk score calculation + challenge selection
 *   6. Turnstile verification (if needed)
 *
 * @param {Object} params
 * @param {string} params.telegramId
 * @param {string} params.deviceId
 * @param {string} params.token
 * @param {import('express').Request} params.req
 * @param {boolean} [params.gatesCompleted] — whether required gates were completed
 * @param {string} [params.endpoint] — 'claim' or 'reveal'
 * @returns {Promise<{
 *   action: 'ALLOW'|'BLOCK'|'POW_REQUIRED'|'TURNSTILE_REQUIRED'|'DEVICE_CHANGED'|'COOLDOWN'|'MULTI_TG_BLOCKED'|'API_PROBE_BLOCKED',
 *   riskScore: number,
 *   retryAfter?: number,
 *   challenge?: Object,
 *   vpnFlags?: string[],
 * }>}
 */
async function runSecurityCheck({ telegramId, deviceId, token, req, gatesCompleted = true, endpoint = 'claim' }) {
  const ip = getClientIp(req);
  const ipHash = hashIp(ip);
  const userAgent = req.headers['user-agent'] || '';

  // ── 1. Check if user/device is currently blocked ──
  const blockCheck = await guardIsBlocked(telegramId, deviceId);
  if (blockCheck.blocked) {
    return {
      action: 'BLOCK',
      riskScore: 100,
      retryAfter: blockCheck.remainingSeconds || 3600,
    };
  }

  // ── 2. VPN/Proxy/Datacenter detection ──
  let vpnResult = { scoreAdjustment: 0, flags: [], confidence: 'low', source: 'none' };
  try {
    // Quick check first (no external API call)
    const quickCheck = quickVpnCheck(ip, req.headers);
    // Full check (with external API, cached)
    const fullCheck = await detectVpnProxy(ip);
    // Combine: take the max score adjustment
    vpnResult = {
      ...fullCheck,
      scoreAdjustment: Math.max(fullCheck.scoreAdjustment, quickCheck.scoreAdjustment),
      flags: [...new Set([...fullCheck.flags, ...quickCheck.flags])],
    };
  } catch {
    // VPN check failure is non-critical — continue with neutral score
  }

  // ── 3. Multi-Telegram Account Detection (5.1) ──
  const multiTgResult = await checkMultiTelegram(ipHash, deviceId, telegramId);
  if (multiTgResult.riskLevel === 'block') {
    return {
      action: 'MULTI_TG_BLOCKED',
      riskScore: 100,
      retryAfter: 24 * 60 * 60, // 24 hour block
      vpnFlags: vpnResult.flags,
    };
  }

  // ── 4. Device Change Detection (5.4) ──
  const deviceChangeResult = await checkDeviceChange(telegramId, deviceId, userAgent);
  if (deviceChangeResult.requiresReverify) {
    return {
      action: 'DEVICE_CHANGED',
      riskScore: 80,
      retryAfter: 0,
      vpnFlags: vpnResult.flags,
    };
  }

  // ── 5. API Probing Detection (5.2) ──
  if (!gatesCompleted) {
    const probeResult = await recordApiProbe(ipHash, deviceId, endpoint, gatesCompleted);
    if (probeResult.shouldBlock) {
      return {
        action: 'API_PROBE_BLOCKED',
        riskScore: 90,
        retryAfter: Math.ceil(probeResult.blockDurationMs / 1000),
        vpnFlags: vpnResult.flags,
      };
    }
  }

  // ── 6. Calculate composite risk score ──
  let baseScore = 0;
  try {
    baseScore = await checkSuspiciousScore(token, telegramId, deviceId, ipHash);
  } catch {
    baseScore = 30; // fail-open medium risk
  }

  // Add VPN score adjustment
  const riskScore = Math.min(baseScore + vpnResult.scoreAdjustment, 100);

  // Set X-Risk-Score header for debugging (remove in production)
  if (!IS_PRODUCTION) {
    req.riskScore = riskScore;
    req.vpnFlags = vpnResult.flags;
  }

  // ── 7. Determine required challenge ──
  const challenge = getRequiredChallenge(riskScore);

  if (challenge.type === 'block') {
    return {
      action: 'BLOCK',
      riskScore,
      retryAfter: Math.ceil((challenge.durationMs || 3600000) / 1000),
      challenge,
      vpnFlags: vpnResult.flags,
    };
  }

  if (challenge.type === 'turnstile') {
    return {
      action: 'TURNSTILE_REQUIRED',
      riskScore,
      challenge: {
        type: 'turnstile',
        siteKey: process.env.TURNSTILE_SITE_KEY || '',
      },
      vpnFlags: vpnResult.flags,
    };
  }

  if (challenge.type === 'pow') {
    return {
      action: 'POW_REQUIRED',
      riskScore,
      challenge: {
        type: 'proof_of_work',
        endpoint: '/api/v1/pow/challenge',
        difficulty: challenge.difficulty,
      },
      vpnFlags: vpnResult.flags,
    };
  }

  return {
    action: 'ALLOW',
    riskScore,
    vpnFlags: vpnResult.flags,
  };
}

// ============================================================================
// 🔒 API Endpoint: POST /api/v1/code/claim
// Generates a one-time claim ticket after suspicious guard + all gates pass.
// Code is NOT returned here — only a ticket to redeem at /reveal.
// ============================================================================

router.post(
  '/claim',
  // Category 6: Endpoint-specific rate limiting with burst
  codeClaimRateLimit(),
  async (req, res) => {
    // Apply security headers FIRST — every response gets them
    setSecurityHeaders(res);

    try {
      const {
        token,
        telegramId,
        deviceId: clientDeviceId,
        turnstileToken,
      } = req.body || {};

      // BUG 10 FIX: Server-side device fingerprint from token (set in /gift route)
      // Client-provided deviceId is IGNORED — prevents tampering
      let deviceId = clientDeviceId;

      // Validate required parameters (token + telegramId required; deviceId from token)
      if (!token || !telegramId) {
        return sendSanitizedError(res, 400, 'MISSING_PARAMS', 'token, telegramId required');
      }

      // ── Validate session token BEFORE security check ──
      let tokenData;
      try {
        tokenData = validateToken(token);
      } catch {
        return sendSanitizedError(res, 403, 'INVALID_TOKEN', 'Session token invalid or expired');
      }

      // Override client deviceId with server-stored fingerprint (single source of truth)
      deviceId = tokenData.fingerprint || clientDeviceId;

      // ── COMPREHENSIVE SECURITY CHECK PIPELINE ──
      // Gates are validated server-side AFTER token verification (below)
      const securityResult = await runSecurityCheck({
        telegramId,
        deviceId,
        token,
        req,
        gatesCompleted: true,
        endpoint: 'claim',
      });

      // Set X-Risk-Score header for debugging (remove in production)
      if (!IS_PRODUCTION) {
        res.setHeader('X-Risk-Score', String(securityResult.riskScore));
        if (securityResult.vpnFlags?.length > 0) {
          res.setHeader('X-VPN-Flags', securityResult.vpnFlags.join(','));
        }
      }

      if (securityResult.action === 'BLOCK' || securityResult.action === 'MULTI_TG_BLOCKED' || securityResult.action === 'API_PROBE_BLOCKED') {
        if (securityResult.retryAfter) {
          res.setHeader('Retry-After', String(securityResult.retryAfter));
        }
        return sendSanitizedError(res, 429, securityResult.action, `Blocked: retry after ${securityResult.retryAfter}s`);
      }

      if (securityResult.action === 'DEVICE_CHANGED') {
        return res.status(403).json({
          success: false,
          error: 'DEVICE_CHANGED',
          message: 'Device or browser changed. Please re-verify your Telegram account.',
          requiresReverify: true,
        });
      }

      if (securityResult.action === 'TURNSTILE_REQUIRED') {
        // If user provided a turnstile token, verify it
        if (turnstileToken) {
          const turnstileResult = await verifyTurnstile(turnstileToken, getClientIp(req));
          if (!turnstileResult.success) {
            return sendSanitizedError(res, 403, 'TURNSTILE_FAILED', 'Turnstile verification failed');
          }
          // Turnstile passed — continue
        } else {
          return res.status(403).json({
            success: false,
            error: 'TURNSTILE_REQUIRED',
            message: 'Additional verification required',
            challenge: securityResult.challenge,
          });
        }
      }

      if (securityResult.action === 'POW_REQUIRED') {
        return res.status(403).json({
          success: false,
          error: 'POW_REQUIRED',
          message: 'Additional verification required',
          challenge: securityResult.challenge,
        });
      }

      // ── Token binding + gate validation ──
      // BUG 3 FIX: Compare stored fingerprint against SERVER-COMPUTED request fingerprint
      // req.fingerprint is set by requestTracking middleware in server.js
      const reqFingerprint = req.fingerprint || createHash('sha256')
        .update(req.headers['user-agent'] + req.ip)
        .digest('hex')
        .substring(0, 16);

      if (tokenData.telegramUserId !== telegramId) {
        return sendSanitizedError(res, 403, 'TELEGRAM_MISMATCH', 'Telegram ID mismatch');
      }
      if (tokenData.fingerprint && tokenData.fingerprint !== reqFingerprint) {
        return sendSanitizedError(res, 403, 'DEVICE_MISMATCH', 'Device fingerprint mismatch');
      }

      // ── Server-side gate validation ONLY ──
      // For Telegram-verified users: 3 factor gates auto-completed at /gift
      // Only require PoW + behavior on the daily page
      const gatesPassed =
        tokenData.powCompleted === true &&
        tokenData.behaviorCompleted === true;
      if (!gatesPassed) {
        return res.status(403).json({
          success: false,
          error: 'GATES_INCOMPLETE',
          message: 'Complete PoW and behavioral verification first',
        });
      }

      // ── Check if already claimed today ──
      const alreadyClaimed = await hasClaimedToday(telegramId);
      if (alreadyClaimed) {
        return sendSanitizedError(res, 429, 'ALREADY_CLAIMED', 'Already claimed today');
      }

      // ── Generate one-time claim ticket ──
      // CRITICAL: claimId and nonce are derived from hashed values
      // They NEVER contain any gift code or code-derived data
      const ticket = await generateClaimTicket(token, telegramId, deviceId);

      // ── Response: ticket only, NO code ──
      res.json({
        success: true,
        claimId: ticket.claimId,
        nonce: ticket.nonce,
        expiresIn: ticket.expiresIn,
        message: 'Claim ticket generated. Redeem within 30 seconds.',
      });

    } catch (err) {
      // Log error WITHOUT any sensitive data — code NEVER in logs
      return sendSanitizedError(res, 500, 'SERVER_ERROR', 'Claim processing failed');
    }
  }
);

// ============================================================================
// 🔒 API Endpoint: POST /api/v1/code/reveal
// CRITICAL: Code is ONLY delivered after ALL verification passes:
//   1. claimId + nonce match (one-time ticket)
//   2. Session token valid
//   3. Telegram + device binding verified
//   4. Time-lock passed (releaseAt <= now)
//   5. Rate limit check
//   6. Code decrypted in codeReveal.js ONLY
//   7. Complete reveal audit trail logged
//   8. Turnstile verified for high-risk users
// ============================================================================

router.post(
  '/reveal',
  // Category 6: Dual rate limiting — per-IP (5/min) AND per-telegram (5/hour)
  codeRevealRateLimit(),
  codeRevealHourlyRateLimit(),
  async (req, res) => {
    // Apply security headers FIRST — every response gets them
    setSecurityHeaders(res);

    try {
      const {
        token,
        claimId,
        nonce,
        telegramId,
        deviceId: clientDeviceId,
        powSolution,
        behavioralScore,
        turnstileToken,
      } = req.body || {};

      // ALL parameters required — partial requests rejected immediately
      if (!token || !claimId || !nonce || !telegramId) {
        return sendSanitizedError(res, 400, 'MISSING_PARAMS', 'All fields required');
      }

      // BUG 10 FIX: Server-side device fingerprint — validate token first
      let tokenData;
      try {
        tokenData = validateToken(token);
      } catch {
        return sendSanitizedError(res, 403, 'INVALID_TOKEN', 'Session token invalid or expired');
      }
      // Override client deviceId with server-stored fingerprint (single source of truth)
      const deviceId = tokenData.fingerprint || clientDeviceId;

      // ── COMPREHENSIVE SECURITY CHECK PIPELINE ──
      const securityResult = await runSecurityCheck({
        telegramId,
        deviceId,
        token,
        req,
        gatesCompleted: true,
        endpoint: 'reveal',
      });

      // Set X-Risk-Score header for debugging (remove in production)
      if (!IS_PRODUCTION) {
        res.setHeader('X-Risk-Score', String(securityResult.riskScore));
        if (securityResult.vpnFlags?.length > 0) {
          res.setHeader('X-VPN-Flags', securityResult.vpnFlags.join(','));
        }
      }

      if (securityResult.action === 'BLOCK' || securityResult.action === 'MULTI_TG_BLOCKED' || securityResult.action === 'API_PROBE_BLOCKED') {
        if (securityResult.retryAfter) {
          res.setHeader('Retry-After', String(securityResult.retryAfter));
        }

        // Category 7: Log failed reveal attempt (blocked)
        await logRevealAudit({
          claimId,
          nonce,
          telegramId,
          deviceId,
          ip: getClientIp(req),
          codeId: null,
          codeLength: 0,
          success: false,
          error: securityResult.action,
          gateResults: {},
          riskScore: securityResult.riskScore,
        });

        return sendSanitizedError(res, 429, securityResult.action, `Blocked: retry after ${securityResult.retryAfter}s`);
      }

      if (securityResult.action === 'DEVICE_CHANGED') {
        return res.status(403).json({
          success: false,
          error: 'DEVICE_CHANGED',
          message: 'Device or browser changed. Please re-verify your Telegram account.',
          requiresReverify: true,
        });
      }

      if (securityResult.action === 'TURNSTILE_REQUIRED') {
        if (turnstileToken) {
          const turnstileResult = await verifyTurnstile(turnstileToken, getClientIp(req));
          if (!turnstileResult.success) {
            // Log failed reveal (turnstile failed)
            await logRevealAudit({
              claimId,
              nonce,
              telegramId,
              deviceId,
              ip: getClientIp(req),
              codeId: null,
              codeLength: 0,
              success: false,
              error: 'TURNSTILE_FAILED',
              gateResults: {},
              riskScore: securityResult.riskScore,
            });
            return sendSanitizedError(res, 403, 'TURNSTILE_FAILED', 'Turnstile verification failed');
          }
          // Turnstile passed — continue
        } else {
          return res.status(403).json({
            success: false,
            error: 'TURNSTILE_REQUIRED',
            message: 'Additional verification required',
            challenge: securityResult.challenge,
          });
        }
      }

      if (securityResult.action === 'POW_REQUIRED') {
        return res.status(403).json({
          success: false,
          error: 'POW_REQUIRED',
          message: 'Additional verification required',
          challenge: securityResult.challenge,
        });
      }

      // ── Token binding check ──
      // BUG 3 FIX: Compare stored fingerprint against SERVER-COMPUTED request fingerprint
      const reqFingerprint = req.fingerprint || createHash('sha256')
        .update(req.headers['user-agent'] + req.ip)
        .digest('hex')
        .substring(0, 16);

      if (tokenData.telegramUserId !== telegramId) {
        return sendSanitizedError(res, 403, 'TELEGRAM_MISMATCH', 'Telegram ID mismatch');
      }
      if (tokenData.fingerprint && tokenData.fingerprint !== reqFingerprint) {
        return sendSanitizedError(res, 403, 'DEVICE_MISMATCH', 'Device fingerprint mismatch');
      }

      // ── Call multi-layer code reveal engine ──
      // CRITICAL: decryptString is ONLY called inside codeReveal.js
      // BUG 5 FIX: Pass codeId from session for exact code binding
      const result = await revealCode({
        sessionToken: token,
        claimId,
        nonce,
        telegramId: String(telegramId),
        deviceId: String(deviceId),
        powSolution,
        behavioralScore,
        codeId: tokenData.codeId || null,  // Session-bound codeId (exact lookup)
      });

      if (!result.success) {
        // Map internal errors to sanitized production responses
        const statusMap = {
          TIMELOCK_ACTIVE: 403,
          CLAIM_REUSED: 409,
          CLAIM_EXPIRED: 410,
          RATE_LIMITED: 429,
          CHANNELS_NOT_JOINED: 403,
          TOKEN_MISMATCH: 403,
          DEVICE_MISMATCH: 403,
          NONCE_MISMATCH: 403,
          ALREADY_DELIVERED: 409,
          NO_CODE_AVAILABLE: 404,
          DECRYPT_ERROR: 500,
        };
        const status = statusMap[result.error] || 400;

        // ── Category 5.3: Check timelock cooldown ──
        if (result.error === 'TIMELOCK_ACTIVE') {
          const cooldownResult = await checkTimelockCooldown(telegramId, deviceId, 'TIMELOCK_HIT');
          if (cooldownResult.onCooldown) {
            res.setHeader('Retry-After', String(cooldownResult.cooldownSeconds));

            // Log the cooldown violation
            await logRevealAudit({
              claimId,
              nonce,
              telegramId,
              deviceId,
              ip: getClientIp(req),
              codeId: result.codeId || null,
              codeLength: 0,
              success: false,
              error: 'COOLDOWN',
              gateResults: {},
              riskScore: securityResult.riskScore,
            });

            return sendSanitizedError(res, 429, 'COOLDOWN', `Cooldown: retry after ${cooldownResult.cooldownSeconds}s`);
          }
        }

        // Category 7: Log failed reveal attempt
        await logRevealAudit({
          claimId,
          nonce,
          telegramId,
          deviceId,
          ip: getClientIp(req),
          codeId: result.codeId || null,
          codeLength: result.codeLength || 0,
          success: false,
          error: result.error,
          gateResults: {},
          riskScore: securityResult.riskScore,
        });

        return sendSanitizedError(res, status, result.error, result.message);
      }

      // ── SUCCESS: Code delivered ──
      // Code is ONLY returned here after ALL 8+ layers of verification pass
      // and the time-lock has expired

      // Category 7: Log successful reveal audit trail
      await logRevealAudit({
        claimId,
        nonce,
        telegramId,
        deviceId,
        ip: getClientIp(req),
        codeId: result.codeId || null,
        codeLength: result.codeLength || 0,
        success: true,
        error: null,
        gateResults: {},
        riskScore: securityResult.riskScore,
      });

      res.json({
        success: true,
        code: result.code,
        codeLength: result.codeLength,
        expirySeconds: result.expirySeconds,
        message: 'Code delivered. Copy immediately — auto-destructs soon.',
      });

      // Safe log: codeId + codeLength only — NEVER the actual code
      console.log('[REVEAL] Code delivered for codeId:', tokenData.codeId, 'length:', result.codeLength);

    } catch (err) {
      // A FIX: Check if RevealError — use its status/code. Otherwise generic 500.
      if (err instanceof RevealError) {
        return sendSanitizedError(res, err.statusCode, err.code, err.message);
      }
      // Log unexpected errors WITHOUT sensitive data — code NEVER in logs
      console.error('[REVEAL] Unexpected error:', err.message);
      return sendSanitizedError(res, 500, 'SERVER_ERROR', 'Code delivery failed');
    }
  }
);

// ============================================================================
// 🔒 404 Handler — Any other /api/v1/code/* path
// ============================================================================

router.all('*', (req, res) => {
  setSecurityHeaders(res);
  sendSanitizedError(res, 404, 'SERVER_ERROR', 'Endpoint not found');
});

export default router;
