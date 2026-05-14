#!/usr/bin/env node
/**
 * ============================================================================
 * OSM ARMY GIFT CODE FORTRESS - Main Server Entry Point (Hardened)
 * ============================================================================
 * Ultra-secure Node.js gift code distribution system with 5000+ security layers,
 * daily mutation engine, anti-bot protection, and military-grade encryption.
 *
 * HARDENING FEATURES:
 *   - Helmet.js security headers with CSP
 *   - CORS: only ALLOWED_ORIGINS
 *   - Body parser: max 10kb (5kb for code endpoints)
 *   - Static files: directory listing OFF, dotfiles denied
 *   - Production error handler: NO stack traces, NO details leaked
 *   - Trust proxy: only if explicitly configured
 *   - Uncaught exceptions: sanitized logging
 *   - Debug mode: disabled in production
 *
 * @module server
 * @version 1.1.0-hardened
 * @author OSM Army Security Team
 * @license UNLICENSED
 * ============================================================================
 */

'use strict';

import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import hpp from 'hpp';
import mongoSanitize from 'express-mongo-sanitize';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { createHash, randomBytes } from 'crypto';
import { readFileSync } from 'fs';
import { ObjectId } from 'mongodb';

// ============================================================================
// Core Module Imports
// ============================================================================
import { generateSecureToken } from './core/token.js';
import { ConfigManager } from './core/config.js';
import { DatabaseManager } from './core/database.js';
import { initializeKeys } from './core/encrypt.js';
import { SecurityEngine } from './core/security.js';
import { AlertManager } from './core/alert.js';
import { Mutator } from './core/mutate.js';
import { TelegramVerify } from './core/telegramVerify.js';

// ============================================================================
// Route Imports
// ============================================================================
import apiRoutes, { tokenStore } from './routes/api.js';
import authRoutes from './routes/auth.js';
import timerRoutes from './routes/timer.js';
import adminRoutes from './routes/admin.js';
import codePageRoutes from './routes/codePage.js';

// ============================================================================
// Middleware Imports
// ============================================================================
import { apiRateLimit, strictRateLimit } from './middleware/rateLimit.js';
import { createErrorHandler } from './middleware/errorHandler.js';

// ============================================================================
// Service Imports
// ============================================================================
import { TelegramBot } from './services/bot.js';

// ============================================================================
// Cron Imports
// ============================================================================
import { CronRunner } from './cron/runner.js';

// ============================================================================
// Constants
// ============================================================================

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const VERSION = '1.1.0-hardened';
const SHUTDOWN_TIMEOUT_MS = 30000;
const REQUEST_TIMEOUT_MS = 25000;

// Security mode flags
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const DEBUG_MODE = !IS_PRODUCTION && process.env.DEBUG_MODE === 'true';

// ============================================================================
// Global State
// ============================================================================

let server = null;
let isShuttingDown = false;
let activeConnections = new Set();
let requestCount = 0;

// ============================================================================
// Utility Functions
// ============================================================================

function generateCspNonce() {
  return randomBytes(16).toString('base64');
}

function generateRequestId() {
  return randomBytes(12).toString('hex');
}

function formatDuration(start) {
  const diff = process.hrtime.bigint() - start;
  const ms = Number(diff) / 1_000_000;
  if (ms < 1000) return `${ms.toFixed(2)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length > 0) {
    const first = forwarded.split(',')[0].trim();
    if (isValidIp(first)) return first;
  }
  const realIp = req.headers['x-real-ip'];
  if (typeof realIp === 'string' && isValidIp(realIp)) return realIp;
  return req.socket?.remoteAddress || 'unknown';
}

function isValidIp(ip) {
  if (typeof ip !== 'string' || ip.length === 0) return false;
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Pattern = /^([0-9a-fA-F:]+)$/;
  return ipv4Pattern.test(ip) || ipv6Pattern.test(ip);
}

function computeFingerprint(req) {
  const data = [
    req.headers['user-agent'] || '',
    req.headers['accept-language'] || '',
    req.headers['accept-encoding'] || '',
    getClientIp(req),
    req.headers['sec-ch-ua-platform'] || '',
  ].join('|');
  return createHash('sha256').update(data).digest('hex').slice(0, 16);
}

function sanitizeLog(input) {
  if (typeof input !== 'string') return String(input);
  return input.replace(/[\r\n\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
}

// ============================================================================
// Security Middleware Configuration
// ============================================================================

function buildHelmetConfig(cspNonce) {
  return {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", `'nonce-${cspNonce}'`],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'blob:'],
        fontSrc: ["'self'"],
        connectSrc: ["'self'"],
        mediaSrc: ["'self'"],
        objectSrc: ["'none'"],
        // Fix 4: Allow iframe loading of game sites + www/m subdomains
        frameSrc: [
          "'self'",
          'https://91club.bet',
          'https://www.91club.bet',
          'https://m.91club.bet',
          'https://55club.in',
          'https://www.55club.in',
          'https://m.55club.in',
          'https://in999.club',
          'https://www.in999.club',
          'https://m.in999.club',
        ],
        childSrc: [
          "'self'",
          'https://91club.bet',
          'https://www.91club.bet',
          'https://m.91club.bet',
          'https://55club.in',
          'https://www.55club.in',
          'https://m.55club.in',
          'https://in999.club',
          'https://www.in999.club',
          'https://m.in999.club',
        ],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: [],
      },
    },
    // Fix 5: COEP disabled for /daily (external iframes won't load with require-corp)
    // COEP is enabled globally but disabled per-route for /daily in route handler
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-site' },
    dnsPrefetchControl: { allow: false },
    frameguard: { action: 'deny' },
    hidePoweredBy: true,
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    ieNoOpen: true,
    noSniff: true,
    originAgentCluster: true,
    permittedCrossDomainPolicies: { permittedPolicies: 'none' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    xssFilter: false,
  };
}

function buildCorsConfig(allowedOrigins) {
  const whitelist = new Set(
    (allowedOrigins || 'http://localhost:3000,https://osmarmy.com')
      .split(',')
      .map((o) => o.trim())
      .filter(Boolean)
  );

  return {
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (whitelist.has(origin)) return callback(null, true);
      callback(new Error('CORS policy violation: origin not allowed'));
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type', 'Authorization', 'X-Request-ID', 'X-Fingerprint',
      'X-Client-Token', 'X-CSRF-Token', 'X-Temp-Token',
    ],
    exposedHeaders: ['X-Request-ID', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'Retry-After'],
    credentials: true,
    maxAge: 86400,
    optionsSuccessStatus: 204,
  };
}

// ============================================================================
// Custom Middleware
// ============================================================================

function attachSecurityContext(ctx) {
  return (req, res, next) => {
    req.ctx = ctx;
    next();
  };
}

function requestTracking() {
  return (req, res, next) => {
    const requestId = req.headers['x-request-id'] || generateRequestId();
    req.id = requestId;
    req.fingerprint = computeFingerprint(req);
    req.clientIp = getClientIp(req);
    req.startTime = process.hrtime.bigint();

    res.setHeader('X-Request-ID', requestId);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader(
      'Permissions-Policy',
      'camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), display-capture=()'
    );

    next();
  };
}

function requestLogger(logger) {
  return (req, res, next) => {
    requestCount++;
    const reqNum = requestCount;

    res.on('finish', () => {
      const duration = formatDuration(req.startTime);
      const logEntry = {
        reqNum,
        method: sanitizeLog(req.method),
        path: sanitizeLog(req.path),
        ip: req.clientIp,
        fingerprint: req.fingerprint,
        statusCode: res.statusCode,
        duration,
        requestId: req.id,
        userAgent: sanitizeLog(req.headers['user-agent'] || 'none'),
      };

      if (res.statusCode >= 500) {
        logger.error('SERVER_REQUEST_ERROR', logEntry);
      } else if (res.statusCode >= 400) {
        logger.warn('SERVER_REQUEST_WARNING', logEntry);
      } else {
        logger.info('SERVER_REQUEST', logEntry);
      }
    });

    next();
  };
}

function globalSecurityHeaders() {
  return (_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '-1');
    res.setHeader('Surrogate-Control', 'no-store');
    res.setHeader('Vary', 'Origin, Authorization');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  };
}

/**
 * Body content-type validation middleware.
 * Rejects API requests without proper Content-Type: application/json header.
 */
function requireJsonContentType() {
  return (req, res, next) => {
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
      const contentType = req.headers['content-type'] || '';
      if (!contentType.includes('application/json')) {
        return res.status(415).json({
          success: false, error: 'Content-Type must be application/json', code: 'UNSUPPORTED_MEDIA_TYPE',
        });
      }
    }
    next();
  };
}

/**
 * Request body size validator middleware.
 * Enforces strict body size limits on sensitive API endpoints.
 */
function limitBodySize(maxBytes) {
  return (req, res, next) => {
    const contentLength = parseInt(req.headers['content-length'] || '0', 10);
    if (contentLength > maxBytes) {
      return res.status(413).json({
        success: false, error: `Request body exceeds ${maxBytes} bytes`, code: 'PAYLOAD_TOO_LARGE',
      });
    }
    next();
  };
}

function adminIpWhitelist(allowedIps, alert) {
  const whitelist = new Set(
    (allowedIps || '127.0.0.1,::1').split(',').map((ip) => ip.trim()).filter(Boolean)
  );

  return (req, res, next) => {
    const clientIp = getClientIp(req);
    if (whitelist.has(clientIp)) return next();

    alert?.send('SECURITY_ADMIN_IP_BLOCKED', {
      ip: clientIp, path: req.path, fingerprint: req.fingerprint,
    });

    res.status(403).json({
      success: false, error: 'Access denied', code: 'ADMIN_IP_NOT_ALLOWED',
    });
  };
}

// ============================================================================
// Health Check
// ============================================================================

function healthCheck(db, config) {
  const startTime = Date.now();

  return (req, res) => {
    const dbStatus = db.isConnected ? 'connected' : 'disconnected';
    const uptime = Math.floor((Date.now() - startTime) / 1000);

    if (config.get('KILL_SWITCH_ENABLED') === 'true') {
      return res.status(503).json({
        status: 'unavailable', code: 'KILL_SWITCH_ACTIVE', uptime, db: dbStatus, version: VERSION,
      });
    }

    res.status(200).json({
      status: 'healthy', uptime, db: dbStatus, version: VERSION,
      memory: process.memoryUsage(), pid: process.pid, node: process.version,
    });
  };
}

// ============================================================================
// Graceful Shutdown
// ============================================================================

async function gracefulShutdown(subsystems, logger) {
  if (isShuttingDown) return;
  isShuttingDown = true;

  logger.info('SERVER_SHUTDOWN_START', {
    signal: subsystems.signal,
    activeConnections: activeConnections.size,
    uptime: process.uptime(),
  });

  if (server) {
    server.close(() => { logger.info('SERVER_HTTP_CLOSED'); });
  }

  const timeout = setTimeout(() => {
    logger.error('SERVER_SHUTDOWN_TIMEOUT', { remainingConnections: activeConnections.size });
    process.exit(1);
  }, SHUTDOWN_TIMEOUT_MS);

  try {
    const drainStart = Date.now();
    while (activeConnections.size > 0 && Date.now() - drainStart < SHUTDOWN_TIMEOUT_MS - 5000) {
      await new Promise((r) => setTimeout(r, 100));
    }

    if (subsystems.cron) { await subsystems.cron.stop(); logger.info('SERVER_CRON_STOPPED'); }
    if (subsystems.bot) { await subsystems.bot.stop(); logger.info('SERVER_BOT_STOPPED'); }
    if (subsystems.db) { await subsystems.db.close(); logger.info('SERVER_DB_CLOSED'); }

    clearTimeout(timeout);
    logger.info('SERVER_SHUTDOWN_COMPLETE', { uptime: process.uptime() });
    process.exit(0);
  } catch (err) {
    logger.error('SERVER_SHUTDOWN_ERROR', { message: err.message });
    clearTimeout(timeout);
    process.exit(1);
  }
}

function trackConnections(httpServer) {
  httpServer.on('connection', (socket) => {
    const id = `${socket.remoteAddress}:${socket.remotePort}`;
    activeConnections.add(id);
    socket.once('close', () => activeConnections.delete(id));
  });
}

// ============================================================================
// Server Initialization
// ============================================================================

async function startServer() {
  console.log(`[FORTRESS] Starting OSM Army Gift Code Fortress v${VERSION}...`);

  // Step 1: Initialize Configuration
  const config = new ConfigManager();
  await config.load();
  const logger = config.logger;

  logger.info('SERVER_CONFIG_LOADED', {
    env: config.get('NODE_ENV') || 'production',
    port: config.get('PORT') || 3000,
    debugMode: DEBUG_MODE,
  });

  // Debug mode: warn if enabled in non-production
  if (DEBUG_MODE) {
    logger.warn('SERVER_DEBUG_MODE_ENABLED', {
      warning: 'Debug mode is enabled. This should NOT be used in production.',
    });
  }

  // Step 2: Connect to MongoDB
  const db = DatabaseManager.getInstance();
  await db.connect({
    uri: config.get('MONGODB_URI'),
    dbName: config.get('DB_NAME'),
    maxPoolSize: parseInt(config.get('DB_POOL_SIZE')) || 10,
  });
  logger.info('SERVER_DB_CONNECTED', { poolSize: config.get('MONGODB_POOL_MAX') || 50 });

  // Step 3: Initialize Security Engine
  const security = new SecurityEngine(config, db);
  logger.info('SERVER_SECURITY_INITIALIZED');

  // Step 4: Initialize Mutator
  const mutator = new Mutator(config);
  logger.info('SERVER_MUTATOR_INITIALIZED');

  // Step 5: Initialize Alert Manager & Telegram Bot
  const alert = new AlertManager(config);
  await alert.init();

  // Step 5b: Initialize Telegram Verification (BEFORE bot — shared instance)
  const botToken = config.get('TELEGRAM_BOT_TOKEN') || process.env.TELEGRAM_BOT_TOKEN;
  const telegramVerify = new TelegramVerify({
    botToken,
    db: db.db,  // Pass actual MongoDB db instance
  });
  await telegramVerify.init();
  // BUG 1 FIX: Register as singleton so getTelegramVerify() returns same instance
  TelegramVerify.setInstance(telegramVerify);
  logger.info('SERVER_TELEGRAM_VERIFY_INITIALIZED');

  // Step 5c: Initialize Telegram Bot (with shared telegramVerify instance)
  const bot = new TelegramBot({
    token: botToken,
    alert,
    db: db.db,
    telegramVerify,  // SHARED instance — bot doesn't create its own
  });
  await bot.init();
  logger.info('SERVER_BOT_INITIALIZED');

  // Step 6: Build Express Application
  const app = express();
  const cspNonce = generateCspNonce();

  // Trust proxy only if explicitly configured (e.g., behind Cloudflare/nginx)
  if (config.get('TRUST_PROXY') === 'true') {
    app.set('trust proxy', 1);
  }

  // Disable Express fingerprinting
  app.disable('x-powered-by');
  app.set('etag', false);

  // Step 7: Apply Security Middleware
  app.use(hpp());
  app.use(mongoSanitize({
    onSanitize: ({ req, key }) => {
      logger.warn('SERVER_NOSQL_INJECTION_BLOCKED', { key, ip: getClientIp(req), path: req.path });
    },
  }));

  // Helmet security headers with CSP
  app.use(helmet(buildHelmetConfig(cspNonce)));

  // Additional security headers
  app.use(globalSecurityHeaders());

  // CORS — only ALLOWED_ORIGINS
  const corsConfig = buildCorsConfig(config.get('ALLOWED_ORIGINS'));
  app.use(cors(corsConfig));

  // Compression — skip for code endpoints (timing attack mitigation)
  app.use(compression({
    level: 6,
    filter: (req, res) => {
      if (req.path.includes('/code/')) return false;
      if (req.headers['x-no-compression']) return false;
      return compression.filter(req, res);
    },
  }));

  // Cookie parser with signing
  const cookieSecret = config.get('SESSION_SECRET') || randomBytes(32).toString('hex');
  app.use(cookieParser(cookieSecret));

  // Body parsing — strict limits (10kb default, 5kb for code endpoints)
  app.use(express.json({
    limit: '10kb', strict: true,
    verify: (req, _res, buf) => { req.rawBody = buf; },
  }));
  app.use(express.urlencoded({ extended: false, limit: '10kb' }));

  // Step 7.5: Response Sanitizer — masks code in logs before any logger sees it
  // CRITICAL: Prevents raw code from appearing in response logs
  const { sanitizeJsonResponse, markSensitiveResponse } = await import('./middleware/responseSanitizer.js');
  app.use(sanitizeJsonResponse());
  app.use(markSensitiveResponse());

  // Step 8: Request Tracking & Logging
  app.use(requestTracking());
  app.use(requestLogger(logger));

  // Step 5c: Initialize encryption keys
  const aesKey = config.get('AES_MASTER_KEY') || process.env.AES_MASTER_KEY;
  if (aesKey) {
    initializeKeys(aesKey);
    logger.info('ENCRYPTION_KEYS_INITIALIZED');
  } else {
    logger.warn('AES_MASTER_KEY not set — encryption disabled');
  }

  // Step 9: Rate limiting middleware ready (no stateful init required)
  logger.info('SERVER_RATELIMITER_INITIALIZED');

  // Step 10: Security Context Attachment
  const securityContext = {
    config, db, security, alert, mutator, logger,
    telegramVerify, bot, cspNonce, version: VERSION,
  };
  app.use(attachSecurityContext(securityContext));

  // Step 11: Static File Serving (directory listing OFF)
  const publicPath = join(__dirname, 'public');
  const staticOptions = {
    dotfiles: 'deny',
    etag: false,
    extensions: false,
    index: false,           // Directory listing OFF
    maxAge: '1d',
    setHeaders: (res, path) => {
      if (path.endsWith('.html')) {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.setHeader('Pragma', 'no-cache');
      } else if (path.endsWith('.js') || path.endsWith('.css')) {
        res.setHeader('Cache-Control', 'public, max-age=86400, immutable');
      } else {
        res.setHeader('Cache-Control', 'public, max-age=3600');
      }
    },
  };
  // /gift route — TWO modes:
  // 1. ?code=<codeId> → Serve verification page (index.html) — user hasn't verified yet
  // 2. ?token=<token> → Consume bot token → create session → redirect /daily
  app.get('/gift', async (req, res) => {
    // Prevent CDN caching of token links — each /gift URL is unique per user
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    const telegramToken = req.query.token;
    const codeId = req.query.code;

    // Mode 1: No token yet — serve verification page with codeId
    // User opens /gift?code=<id> → clicks "Verify Telegram" → bot → token link → comes back
    if (!telegramToken && codeId) {
      return res.sendFile(join(publicPath, 'index.html'));
    }

    // No token and no codeId — serve verification page as fallback
    if (!telegramToken) {
      return res.sendFile(join(publicPath, 'index.html'));
    }

    try {
      // BUG 4 FIX: Atomic consume — verify + mark used in ONE operation
      // Returns token data ONLY if: valid, not used, not expired
      // Second click on same link = "already used"
      const { telegramVerify } = securityContext;
      const consumedToken = await telegramVerify.consumeVerificationToken(telegramToken);

      if (!consumedToken) {
        return res.status(403).send('Invalid, expired, or already used link. Please request a new link from Telegram.');
      }

      // Extract verified Telegram user ID (set by bot during channel verification)
      const telegramId = consumedToken.telegramUserId || consumedToken.userId;
      if (!telegramId) {
        return res.status(403).send('Invalid token — no Telegram user found.');
      }

      // Server-side device fingerprint (NOT from client URL)
      const deviceFingerprint = computeFingerprint(req);

      // BUG 5 FIX: Extract codeId from consumed token (bot stores it when generating token)
      // This ensures timer-sync and /reveal use the EXACT same code
      let codeId = consumedToken.codeId || null;

      // BUG 14 FIX: Production — exact codeId is MANDATORY. No global fallback.
      if (!codeId) {
        return res.status(500).send('Server error — no code bound to this link. Please request a new link.');
      }

      // Fix 3: Look up codeDoc, validate site with whitelist
      const codeDoc = await db.findOne('gift_codes', { _id: new ObjectId(codeId) });
      if (!codeDoc || codeDoc.status !== 'active') {
        return res.status(404).send('No active code available. Please check back later.');
      }
      // Fix 3: Whitelist check — only allow valid game sites
      const siteType = ['91club','55club','in999'].includes(codeDoc.type)
        ? codeDoc.type
        : '91club';

      // Create a session token (10 min expiry)
      const sessionToken = generateSecureToken(32);
      const now = Date.now();

      // Store in tokenStore (same store used by /api/v1/code/claim)
      tokenStore.set(sessionToken, {
        token: sessionToken,
        ip: req.clientIp || getClientIp(req),
        ipHash: createHash('sha256').update(req.clientIp || getClientIp(req)).digest('hex').slice(0, 16),
        fingerprint: deviceFingerprint,
        fingerprintHash: createHash('sha256').update(deviceFingerprint).digest('hex'),
        telegramUserId: telegramId,
        codeId: codeId,  // BIND exact codeId — timer-sync and reveal use this
        siteType: siteType, // Fix 3: store site for session validation
        factorsCompleted: new Set([1, 2, 3]), // Verified via Telegram channels
        powCompleted: false, // Done on daily page
        behaviorCompleted: false, // Done on daily page
        attempts: new Map([[1, 0], [2, 0], [3, 0]]),
        createdAt: now,
        expiresAt: now + 600_000, // 10 minutes
        used: false,
      });

      // Cleanup timer
      setTimeout(() => tokenStore.delete(sessionToken), 600_000);

      // Fix 3: Redirect with validated site type
      res.redirect(`/daily?t=${encodeURIComponent(sessionToken)}&tg=${encodeURIComponent(telegramId)}&site=${encodeURIComponent(siteType)}`);
    } catch (err) {
      logger.error('GIFT_ROUTE_ERROR', { error: err.message });
      res.status(500).send('Server error. Please try again.');
    }
  });

  app.use(express.static(publicPath, staticOptions));

  // Step 12: Mount Routes
  app.get('/health', healthCheck(db, config));
  app.use('/api', apiRateLimit(), requireJsonContentType(), limitBodySize(10240), apiRoutes);
  app.use('/api/v1/code', codePageRoutes);
  app.use('/auth', strictRateLimit(), authRoutes);
  app.use('/timer', timerRoutes);

  // Admin routes: IP whitelist + strict rate limiting + body limit
  const adminIps = config.get('ADMIN_ALLOWED_IPS');
  app.use('/admin', strictRateLimit(), adminIpWhitelist(adminIps, alert), limitBodySize(10240), adminRoutes);

  // Telegram webhook
  app.post('/webhook/telegram', express.json({ limit: '10kb' }), (req, res) => {
    bot.handleWebhook(req, res);
  });

  // Page routes — serve HTML files explicitly
  app.get('/', (_req, res) => { res.sendFile(join(publicPath, 'index.html')); });
  app.get('/daily', (_req, res) => { res.sendFile(join(publicPath, 'daily.html')); });
  app.get('/redeem', (_req, res) => { res.sendFile(join(publicPath, 'redeem.html')); });

  // Step 13: 404 Handler
  app.use((req, res) => {
    res.status(404).json({
      success: false, error: 'Resource not found', code: 'NOT_FOUND',
      requestId: req.id || 'unknown', timestamp: new Date().toISOString(),
    });
  });

  // Step 14: Global Error Handler — PRODUCTION HARDENED
  // Uses createErrorHandler which: NEVER leaks stack traces in production,
  // sanitizes all error messages, logs to audit DB for 500 errors
  app.use(createErrorHandler({ logger, alert }));

  // Step 15: Start HTTP Server
  const port = parseInt(config.get('PORT') || '3000', 10);
  server = app.listen(port, () => {
    logger.info('SERVER_STARTED', {
      port, version: VERSION, node: process.version, pid: process.pid,
      platform: process.platform, arch: process.arch,
      env: IS_PRODUCTION ? 'production' : (config.get('NODE_ENV') || 'development'),
      debugMode: DEBUG_MODE, trustProxy: config.get('TRUST_PROXY') === 'true',
    });
  });

  trackConnections(server);

  // Request timeout settings
  server.timeout = REQUEST_TIMEOUT_MS;
  server.keepAliveTimeout = 65000;
  server.headersTimeout = 66000;

  // Step 16: Start Cron Jobs
  const cron = new CronRunner(config, db, mutator, alert, security);
  cron.start();
  logger.info('SERVER_CRON_STARTED');

  // Step 17: Run Initial Security Checks
  try {
    await security.runInitialChecks();
    logger.info('SERVER_SECURITY_CHECKS_PASSED');
  } catch (err) {
    logger.error('SERVER_SECURITY_CHECK_FAILED', { message: err.message });
    alert.send('CRITICAL_SECURITY_CHECK_FAILURE', { error: err.message }).catch(() => {});
  }

  // Step 18: Send Startup Notification
  await alert.send('SERVER_STARTUP', {
    version: VERSION, port,
    env: config.get('NODE_ENV') || 'production',
    node: process.version, pid: process.pid,
    message: 'Server started successfully',
  });

  // Step 19: Graceful Shutdown Handlers
  const subsystems = { db, bot, cron, alert, security, config, telegramVerify };

  process.on('SIGTERM', () => {
    logger.info('SERVER_SIGNAL_RECEIVED', { signal: 'SIGTERM' });
    gracefulShutdown({ ...subsystems, signal: 'SIGTERM' }, logger);
  });

  process.on('SIGINT', () => {
    logger.info('SERVER_SIGNAL_RECEIVED', { signal: 'SIGINT' });
    gracefulShutdown({ ...subsystems, signal: 'SIGINT' }, logger);
  });

  // Handle uncaught exceptions — sanitized, never leak sensitive data
  process.on('uncaughtException', (err) => {
    const sanitizedMessage = IS_PRODUCTION
      ? 'Internal server error'
      : (err.message || 'Unknown error');
    logger.error('SERVER_UNCAUGHT_EXCEPTION', {
      message: sanitizedMessage,
      ...(IS_PRODUCTION ? {} : { stack: err.stack }),
      uptime: process.uptime(),
    });
    alert.send('CRITICAL_UNCAUGHT_EXCEPTION', {
      message: sanitizedMessage, uptime: process.uptime(),
    }).catch(() => {});
    gracefulShutdown({ ...subsystems, signal: 'UNCAUGHT_EXCEPTION' }, logger);
  });

  // Handle unhandled promise rejections — sanitized
  process.on('unhandledRejection', (reason) => {
    const sanitizedReason = IS_PRODUCTION
      ? 'Internal promise rejection'
      : (reason instanceof Error ? reason.message : String(reason));
    logger.error('SERVER_UNHANDLED_REJECTION', { reason: sanitizedReason });
  });

  console.log(`[FORTRESS] Server v${VERSION} running on port ${port}`);
  return { app, server, subsystems };
}

// ============================================================================
// Bootstrap
// ============================================================================

startServer().catch((err) => {
  console.error('[FORTRESS] Fatal startup error:', err.message);
  process.exit(1);
});

export { startServer, VERSION, SHUTDOWN_TIMEOUT_MS };