/**
 * @fileoverview Authentication Routes - Admin login with maximum security
 * @description Multi-factor admin authentication with IP whitelist,
 * account lockout, TOTP 2FA, JWT session binding, and comprehensive audit logging.
 * All routes behind critical security checks.
 * @module routes/auth
 * @version 1.0.0
 */

'use strict';

import { Router } from 'express';
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import { DatabaseManager } from '../core/database.js';
import { createProtector } from '../core/protect.js';
import {
  hashPassword,
  verifyPassword,
  generateToken,
  generateHexToken,
  generateSessionId,
  jwtSign,
  jwtVerify,
  jwtDecode,
  hmacSHA512,
  sha256,
  secureCompare,
} from '../core/encrypt.js';
import { ConfigManager } from '../core/config.js';
import { AlertManager } from '../core/alert.js';
import { FingerprintVerifier } from '../core/fingerprint.js';

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

const AUTH_CONFIG = Object.freeze({
  LOGIN_RATE_LIMIT_MAX: 5,
  LOGIN_RATE_LIMIT_WINDOW_MS: 60 * 60 * 1000,
  MAX_FAILED_ATTEMPTS: 5,
  LOCKOUT_DURATION_MS: 60 * 60 * 1000,
  TEMP_TOKEN_EXPIRY_SECONDS: 300,
  JWT_EXPIRY_SECONDS: 3600,
  SESSION_INACTIVITY_MS: 30 * 60 * 1000,
  REFRESH_WINDOW_SECONDS: 300,
  ADMIN_IP_WHITELIST: (process.env.ADMIN_IP_WHITELIST || '127.0.0.1').split(',').map(s => s.trim()).filter(Boolean),
});

// ============================================================================
// ERROR CLASSES
// ============================================================================

/**
 * Authentication route-specific error.
 */
class AuthRouteError extends Error {
  constructor(message, code = 'AUTH_ERROR', statusCode = 401, details = {}) {
    super(message);
    this.name = 'AuthRouteError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
    this.timestamp = new Date().toISOString();
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * IP whitelist error.
 */
class IPWhitelistError extends AuthRouteError {
  constructor(ip) {
    super(`IP ${ip} not in whitelist`, 'IP_NOT_WHITELISTED', 403);
    this.ip = ip;
  }
}

/**
 * Account lockout error.
 */
class LockoutError extends AuthRouteError {
  constructor(retryAfterSeconds) {
    super('Account temporarily locked', 'ACCOUNT_LOCKED', 423);
    this.retryAfter = retryAfterSeconds;
  }
}

// ============================================================================
// IN-MEMORY STORES
// ============================================================================

/** @type {Map<string, {count: number, firstAttempt: number, locked: boolean, lockedUntil: number}>} */
const loginAttempts = new Map();

/** @type {Map<string, {tempToken: string, username: string, ip: string, createdAt: number, used: boolean}>} */
const tempTokens = new Map();

/** @type {Map<string, {adminId: string, ip: string, fingerprint: string, createdAt: number, lastActivity: number, revoked: boolean}>} */
const adminSessions = new Map();

/** @type {Map<string, {count: number, resetAt: number}>} */
const rateLimitStore = new Map();

// Periodic cleanup
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of loginAttempts) {
    if (entry.locked && now > entry.lockedUntil) {
      loginAttempts.delete(key);
    } else if (!entry.locked && now > entry.firstAttempt + AUTH_CONFIG.LOGIN_RATE_LIMIT_WINDOW_MS) {
      loginAttempts.delete(key);
    }
  }
  for (const [key, entry] of tempTokens) {
    if (now > entry.createdAt + AUTH_CONFIG.TEMP_TOKEN_EXPIRY_SECONDS * 1000) {
      tempTokens.delete(key);
    }
  }
  for (const [key, entry] of adminSessions) {
    if (now > entry.lastActivity + AUTH_CONFIG.SESSION_INACTIVITY_MS) {
      adminSessions.delete(key);
    }
  }
  for (const [key, entry] of rateLimitStore) {
    if (now > entry.resetAt) {
      rateLimitStore.delete(key);
    }
  }
}, 60000);

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Get client IP from request.
 * @param {import('express').Request} req
 * @returns {string}
 */
function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

/**
 * Send standardized error response.
 * @param {import('express').Response} res
 * @param {string} message
 * @param {string} code
 * @param {number} statusCode
 */
function sendError(res, message, code, statusCode = 401) {
  return res.status(statusCode).json({
    success: false,
    error: message,
    code,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Send standardized success response.
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
 * @returns {{allowed: boolean}}
 */
function checkRateLimit(identifier, maxRequests, windowMs) {
  const now = Date.now();
  const entry = rateLimitStore.get(identifier);
  if (!entry || now > entry.resetAt) {
    rateLimitStore.set(identifier, { count: 1, resetAt: now + windowMs });
    return { allowed: true };
  }
  if (entry.count >= maxRequests) return { allowed: false, retryAfter: Math.ceil((entry.resetAt - now) / 1000) };
  entry.count += 1;
  return { allowed: true };
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
      adminId: details.adminId || null,
      timestamp: new Date(),
      eventHash: generateHexToken(16),
    });
  } catch {
    // Non-blocking
  }
}

/**
 * Check if IP is in admin whitelist.
 * @param {string} ip
 * @returns {boolean}
 */
function isIPWhitelisted(ip) {
  if (AUTH_CONFIG.ADMIN_IP_WHITELIST.includes('*')) return true;
  if (AUTH_CONFIG.ADMIN_IP_WHITELIST.includes(ip)) return true;
  // Check CIDR ranges
  for (const entry of AUTH_CONFIG.ADMIN_IP_WHITELIST) {
    if (entry.includes('/')) {
      try {
        const [range, bits] = entry.split('/');
        const mask = parseInt(bits, 10);
        const ipParts = ip.split('.').map(Number);
        const rangeParts = range.split('.').map(Number);
        if (ipParts.length === 4 && rangeParts.length === 4) {
          const ipInt = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
          const rangeInt = (rangeParts[0] << 24) | (rangeParts[1] << 16) | (rangeParts[2] << 8) | rangeParts[3];
          const maskInt = mask === 0 ? 0 : ~((1 << (32 - mask)) - 1);
          if ((ipInt & maskInt) === (rangeInt & maskInt)) return true;
        }
      } catch {
        continue;
      }
    }
  }
  return false;
}

/**
 * Get admin credentials from config.
 * @returns {{usernameHash: string, passwordHash: string, totpSecret: string}}
 */
function getAdminCredentials() {
  try {
    const config = ConfigManager.getInstance ? ConfigManager.getInstance() : null;
    if (config) {
      return {
        usernameHash: config.getSecret('admin', 'username_hash') || process.env.ADMIN_USERNAME_HASH || '',
        passwordHash: config.getSecret('admin', 'password_hash') || process.env.ADMIN_PASSWORD_HASH || '',
        totpSecret: config.getSecret('admin', 'totp_secret') || process.env.ADMIN_TOTP_SECRET || '',
      };
    }
  } catch {
    // Fall through
  }
  return {
    usernameHash: process.env.ADMIN_USERNAME_HASH || '',
    passwordHash: process.env.ADMIN_PASSWORD_HASH || '',
    totpSecret: process.env.ADMIN_TOTP_SECRET || '',
  };
}

/**
 * Check account lockout status.
 * @param {string} identifier
 * @returns {{locked: boolean, retryAfter: number}}
 */
function checkLockout(identifier) {
  const record = loginAttempts.get(identifier);
  if (!record) return { locked: false, retryAfter: 0 };
  if (record.locked) {
    const now = Date.now();
    if (now < record.lockedUntil) {
      return { locked: true, retryAfter: Math.ceil((record.lockedUntil - now) / 1000) };
    }
    loginAttempts.delete(identifier);
    return { locked: false, retryAfter: 0 };
  }
  return { locked: false, retryAfter: 0 };
}

/**
 * Record failed login attempt.
 * @param {string} identifier
 */
function recordFailedAttempt(identifier) {
  const now = Date.now();
  const record = loginAttempts.get(identifier);
  if (!record) {
    loginAttempts.set(identifier, { count: 1, firstAttempt: now, locked: false, lockedUntil: 0 });
    return;
  }
  record.count += 1;
  if (record.count >= AUTH_CONFIG.MAX_FAILED_ATTEMPTS) {
    record.locked = true;
    record.lockedUntil = now + AUTH_CONFIG.LOCKOUT_DURATION_MS;
  }
}

/**
 * Verify TOTP code (simplified HOTP-based TOTP).
 * @param {string} secret
 * @param {string} code
 * @returns {boolean}
 */
function verifyTOTP(secret, code) {
  if (!secret || !code || !/^\d{6}$/.test(code)) return false;

  // TOTP: HMAC-SHA1 based time code
  const now = Math.floor(Date.now() / 1000);
  const timeStep = 30;

  // Check current and adjacent windows (clock skew tolerance)
  for (let offset = -1; offset <= 1; offset++) {
    const counter = Math.floor(now / timeStep) + offset;
    const counterBuf = Buffer.alloc(8);
    counterBuf.writeBigUInt64BE(BigInt(counter), 0);

    const key = Buffer.from(secret, 'base64');
    const hmac = createHash('sha1').update(key).update(counterBuf).digest();

    const offset_byte = hmac[hmac.length - 1] & 0x0f;
    const code_int = ((hmac[offset_byte] & 0x7f) << 24 |
      (hmac[offset_byte + 1] & 0xff) << 16 |
      (hmac[offset_byte + 2] & 0xff) << 8 |
      (hmac[offset_byte + 3] & 0xff)) % 1000000;

    const expectedCode = String(code_int).padStart(6, '0');
    if (secureCompare(expectedCode, code)) return true;
  }

  return false;
}

/**
 * Generate admin JWT token.
 * @param {string} adminId
 * @param {string} ip
 * @param {string} fingerprint
 * @returns {string} JWT token
 */
function generateAdminJWT(adminId, ip, fingerprint) {
  const secret = requireEnv('JWT_SECRET') || (process.env.NODE_ENV !== 'production' ? 'dev-jwt-secret' : undefined);
  return jwtSign(
    {
      sub: adminId,
      role: 'admin',
      ip: sha256(ip),
      fingerprint: fingerprint ? sha256(fingerprint) : '',
      jti: generateHexToken(16),
    },
    secret,
    {
      expiresInSeconds: AUTH_CONFIG.JWT_EXPIRY_SECONDS,
      issuer: 'osmarmy-fortress',
      audience: 'admin-panel',
    }
  );
}

/**
 * Verify admin JWT token.
 * @param {string} token
 * @returns {Object} Decoded payload
 * @throws {Error} If invalid
 */
function verifyAdminJWT(token) {
  const secret = requireEnv('JWT_SECRET') || (process.env.NODE_ENV !== 'production' ? 'dev-jwt-secret' : undefined);
  return jwtVerify(token, secret, {
    issuer: 'osmarmy-fortress',
    audience: 'admin-panel',
    clockToleranceSeconds: 60,
  });
}

/**
 * Extract JWT from request.
 * @param {import('express').Request} req
 * @returns {string|null}
 */
function extractJWT(req) {
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7);
  return req.cookies?.adminToken || null;
}

// ============================================================================
// MIDDLEWARE
// ============================================================================

/**
 * Admin authentication middleware.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {Function} next
 */
async function requireAdminAuth(req, res, next) {
  try {
    const token = extractJWT(req);
    if (!token) {
      return sendError(res, 'Authentication required', 'AUTH_REQUIRED', 401);
    }

    let payload;
    try {
      payload = verifyAdminJWT(token);
    } catch {
      return sendError(res, 'Invalid or expired token', 'TOKEN_INVALID', 401);
    }

    const clientIP = getClientIP(req);
    const ipHash = sha256(clientIP);

    // Verify IP binding
    if (payload.ip && !secureCompare(payload.ip, ipHash)) {
      await logAudit('ADMIN_IP_MISMATCH', {
        ip: clientIP,
        severity: 'critical',
      });
      return sendError(res, 'Session IP mismatch', 'IP_MISMATCH', 403);
    }

    // Check session in memory
    const session = adminSessions.get(token);
    if (!session || session.revoked) {
      return sendError(res, 'Session invalidated', 'SESSION_INVALID', 401);
    }

    // Check inactivity timeout
    const now = Date.now();
    if (now - session.lastActivity > AUTH_CONFIG.SESSION_INACTIVITY_MS) {
      adminSessions.delete(token);
      return sendError(res, 'Session expired due to inactivity', 'SESSION_EXPIRED', 401);
    }

    // Update activity
    session.lastActivity = now;

    req.adminId = payload.sub;
    req.adminSession = session;
    next();
  } catch {
    return sendError(res, 'Authentication failed', 'AUTH_FAILED', 500);
  }
}

// ============================================================================
// ROUTER SETUP
// ============================================================================

const router = Router();
const protector = createProtector({ blockThreshold: 100 });

// ============================================================================
// ROUTE 1: POST /auth/admin/login - Admin login (step 1)
// ============================================================================

router.post('/admin/login',
  protector.critical(),
  async (req, res) => {
    try {
      const clientIP = getClientIP(req);
      const { username, password } = req.body || {};

      // IP whitelist check FIRST (before password validation)
      if (!isIPWhitelisted(clientIP)) {
        await logAudit('ADMIN_LOGIN_IP_BLOCKED', {
          ip: clientIP,
          username: username ? sha256(username) : null,
          severity: 'critical',
        });
        try {
          const alertManager = new AlertManager();
          await alertManager.send('ADMIN_IP_VIOLATION', { ip: clientIP, username });
        } catch {
          // Non-blocking
        }
        return sendError(res, 'Access denied from this IP address', 'IP_NOT_AUTHORIZED', 403);
      }

      // Validate inputs
      if (!username || typeof username !== 'string' || username.length < 1 || username.length > 64) {
        return sendError(res, 'Invalid username', 'INVALID_USERNAME', 400);
      }
      if (!password || typeof password !== 'string' || password.length < 1 || password.length > 256) {
        return sendError(res, 'Invalid password', 'INVALID_PASSWORD', 400);
      }

      // Rate limit check
      const rateKey = `admin_login:${clientIP}`;
      const rateCheck = checkRateLimit(rateKey, AUTH_CONFIG.LOGIN_RATE_LIMIT_MAX, AUTH_CONFIG.LOGIN_RATE_LIMIT_WINDOW_MS);
      if (!rateCheck.allowed) {
        return sendError(res, `Too many login attempts. Try again in ${rateCheck.retryAfter}s.`, 'RATE_LIMITED', 429);
      }

      // Check account lockout
      const lockoutKey = `admin:${clientIP}:${username}`;
      const lockout = checkLockout(lockoutKey);
      if (lockout.locked) {
        return sendError(res, `Account locked. Try again in ${lockout.retryAfter}s.`, 'ACCOUNT_LOCKED', 423);
      }

      // Get credentials
      const creds = getAdminCredentials();

      // Validate username against hash
      let usernameValid = false;
      if (creds.usernameHash) {
        // Check if it's a stored hash or needs direct comparison
        if (creds.usernameHash.startsWith('$')) {
          usernameValid = verifyPassword(username, creds.usernameHash);
        } else {
          usernameValid = secureCompare(sha256(username), creds.usernameHash);
        }
      } else {
        // Fallback: compare against env var
        const expectedUsername = process.env.ADMIN_USERNAME || 'admin';
        usernameValid = secureCompare(username, expectedUsername);
      }

      // Validate password
      let passwordValid = false;
      if (creds.passwordHash) {
        passwordValid = verifyPassword(password, creds.passwordHash);
      } else {
        const expectedPassword = process.env.ADMIN_PASSWORD || '';
        passwordValid = secureCompare(password, expectedPassword);
      }

      if (!usernameValid || !passwordValid) {
        recordFailedAttempt(lockoutKey);

        await logAudit('ADMIN_LOGIN_FAILED', {
          ip: clientIP,
          usernameValid,
          passwordValid,
          severity: 'high',
        });

        const attempts = loginAttempts.get(lockoutKey);
        const attemptsLeft = AUTH_CONFIG.MAX_FAILED_ATTEMPTS - (attempts ? attempts.count : 0);

        return sendError(
          res,
          `Invalid credentials. ${Math.max(0, attemptsLeft)} attempts remaining.`,
          'INVALID_CREDENTIALS',
          401
        );
      }

      // Credentials valid - generate temp token for 2FA
      const tempToken = generateHexToken(32);
      const tempId = generateSessionId();

      tempTokens.set(tempId, {
        tempToken,
        username,
        ip: clientIP,
        createdAt: Date.now(),
        used: false,
      });

      await logAudit('ADMIN_LOGIN_STEP1', {
        ip: clientIP,
        usernameHash: sha256(username),
        severity: 'info',
      });

      return sendSuccess(res, {
        step: 2,
        tempToken: tempId,
        message: 'Enter 2FA code',
      });
    } catch (err) {
      await logAudit('ADMIN_LOGIN_ERROR', {
        error: err.message,
        severity: 'error',
      });
      return sendError(res, 'Login process failed', 'LOGIN_ERROR', 500);
    }
  }
);

// ============================================================================
// ROUTE 2: POST /auth/admin/2fa - Verify 2FA
// ============================================================================

router.post('/admin/2fa',
  protector.critical(),
  async (req, res) => {
    try {
      const clientIP = getClientIP(req);
      const { tempToken, code } = req.body || {};

      // Validate inputs
      if (!tempToken || typeof tempToken !== 'string') {
        return sendError(res, 'Temp token is required', 'TEMP_TOKEN_REQUIRED', 400);
      }
      if (!code || typeof code !== 'string' || !/^\d{6}$/.test(code)) {
        return sendError(res, '6-digit 2FA code is required', 'INVALID_2FA_CODE', 400);
      }

      // Verify temp token
      const tempRecord = tempTokens.get(tempToken);
      if (!tempRecord) {
        return sendError(res, 'Invalid or expired temp token', 'TEMP_TOKEN_INVALID', 401);
      }

      if (tempRecord.used) {
        return sendError(res, 'Temp token already used', 'TEMP_TOKEN_USED', 401);
      }

      if (Date.now() > tempRecord.createdAt + AUTH_CONFIG.TEMP_TOKEN_EXPIRY_SECONDS * 1000) {
        tempTokens.delete(tempToken);
        return sendError(res, 'Temp token expired', 'TEMP_TOKEN_EXPIRED', 401);
      }

      // Verify IP matches
      if (tempRecord.ip !== clientIP) {
        await logAudit('ADMIN_2FA_IP_MISMATCH', {
          ip: clientIP,
          expectedIp: tempRecord.ip,
          severity: 'critical',
        });
        return sendError(res, 'IP mismatch detected', 'IP_MISMATCH', 403);
      }

      // Verify TOTP
      const creds = getAdminCredentials();
      const totpSecret = creds.totpSecret || process.env.ADMIN_TOTP_SECRET;

      if (!totpSecret) {
        // If no TOTP configured, skip 2FA (development mode only)
        if (process.env.NODE_ENV === 'production') {
          return sendError(res, '2FA not configured on server', '2FA_NOT_CONFIGURED', 500);
        }
      } else {
        const totpValid = verifyTOTP(totpSecret, code);
        if (!totpValid) {
          await logAudit('ADMIN_2FA_FAILED', {
            ip: clientIP,
            severity: 'high',
          });
          return sendError(res, 'Invalid 2FA code', 'INVALID_2FA', 401);
        }
      }

      // Mark temp token as used
      tempRecord.used = true;
      tempTokens.delete(tempToken);

      // Create admin session
      const adminId = sha256(tempRecord.username);
      const fingerprint = req.headers['user-agent'] || '';
      const jwt = generateAdminJWT(adminId, clientIP, fingerprint);

      adminSessions.set(jwt, {
        adminId,
        ip: clientIP,
        ipHash: sha256(clientIP),
        fingerprint: fingerprint ? sha256(fingerprint) : '',
        createdAt: Date.now(),
        lastActivity: Date.now(),
        revoked: false,
      });

      await logAudit('ADMIN_LOGIN_SUCCESS', {
        ip: clientIP,
        adminId,
        severity: 'info',
      });

      // Set secure cookie
      res.cookie('adminToken', jwt, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: AUTH_CONFIG.JWT_EXPIRY_SECONDS * 1000,
      });

      return sendSuccess(res, {
        success: true,
        token: jwt,
        expiresAt: new Date(Date.now() + AUTH_CONFIG.JWT_EXPIRY_SECONDS * 1000).toISOString(),
      });
    } catch (err) {
      await logAudit('ADMIN_2FA_ERROR', {
        error: err.message,
        severity: 'error',
      });
      return sendError(res, '2FA verification failed', '2FA_ERROR', 500);
    }
  }
);

// ============================================================================
// ROUTE 3: POST /auth/admin/logout - Logout
// ============================================================================

router.post('/admin/logout',
  protector.critical(),
  requireAdminAuth,
  async (req, res) => {
    try {
      const token = extractJWT(req);
      const adminId = req.adminId;

      // Invalidate session
      if (token) {
        adminSessions.delete(token);
      }

      // Clear cookie
      res.clearCookie('adminToken', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
      });

      await logAudit('ADMIN_LOGOUT', {
        adminId,
        ip: getClientIP(req),
        severity: 'info',
      });

      return sendSuccess(res, {
        success: true,
        message: 'Logged out successfully',
      });
    } catch (err) {
      return sendError(res, 'Logout failed', 'LOGOUT_ERROR', 500);
    }
  }
);

// ============================================================================
// ROUTE 4: POST /auth/admin/refresh - Refresh token
// ============================================================================

router.post('/admin/refresh',
  protector.critical(),
  async (req, res) => {
    try {
      const currentToken = extractJWT(req);
      if (!currentToken) {
        return sendError(res, 'No token provided', 'TOKEN_REQUIRED', 401);
      }

      // Verify current token (allow expired with grace period)
      let payload;
      try {
        payload = verifyAdminJWT(currentToken);
      } catch {
        return sendError(res, 'Invalid token', 'TOKEN_INVALID', 401);
      }

      // Check session
      const session = adminSessions.get(currentToken);
      if (!session || session.revoked) {
        return sendError(res, 'Session invalidated', 'SESSION_INVALID', 401);
      }

      const clientIP = getClientIP(req);
      const ipHash = sha256(clientIP);

      // Verify IP binding
      if (payload.ip && !secureCompare(payload.ip, ipHash)) {
        return sendError(res, 'IP mismatch', 'IP_MISMATCH', 403);
      }

      // Issue new token (rotation)
      const fingerprint = req.headers['user-agent'] || '';
      const newToken = generateAdminJWT(payload.sub, clientIP, fingerprint);

      // Transfer session
      adminSessions.delete(currentToken);
      adminSessions.set(newToken, {
        adminId: payload.sub,
        ip: clientIP,
        ipHash,
        fingerprint: fingerprint ? sha256(fingerprint) : '',
        createdAt: Date.now(),
        lastActivity: Date.now(),
        revoked: false,
      });

      // Update cookie
      res.cookie('adminToken', newToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: AUTH_CONFIG.JWT_EXPIRY_SECONDS * 1000,
      });

      await logAudit('ADMIN_TOKEN_REFRESH', {
        adminId: payload.sub,
        ip: clientIP,
        severity: 'info',
      });

      return sendSuccess(res, {
        success: true,
        token: newToken,
        expiresAt: new Date(Date.now() + AUTH_CONFIG.JWT_EXPIRY_SECONDS * 1000).toISOString(),
      });
    } catch (err) {
      return sendError(res, 'Token refresh failed', 'REFRESH_ERROR', 500);
    }
  }
);

// ============================================================================
// ROUTE 5: GET /auth/admin/session - Check session
// ============================================================================

router.get('/admin/session',
  protector.critical(),
  requireAdminAuth,
  async (req, res) => {
    try {
      const clientIP = getClientIP(req);
      const adminId = req.adminId;
      const session = req.adminSession;

      const now = Date.now();
      const sessionAge = now - session.createdAt;
      const timeUntilExpiry = AUTH_CONFIG.SESSION_INACTIVITY_MS - (now - session.lastActivity);

      return sendSuccess(res, {
        valid: true,
        admin: true,
        ip: clientIP,
        ipHash: sha256(clientIP),
        adminId,
        since: new Date(session.createdAt).toISOString(),
        lastActivity: new Date(session.lastActivity).toISOString(),
        sessionAge: Math.floor(sessionAge / 1000),
        expiresIn: Math.max(0, Math.floor(timeUntilExpiry / 1000)),
      });
    } catch (err) {
      return sendError(res, 'Session check failed', 'SESSION_ERROR', 500);
    }
  }
);

// ============================================================================
// ERROR HANDLER
// ============================================================================

router.use((err, req, res, _next) => {
  return res.status(500).json({
    success: false,
    error: 'Authentication service error',
    code: 'AUTH_INTERNAL_ERROR',
    timestamp: new Date().toISOString(),
  });
});

export default router;
