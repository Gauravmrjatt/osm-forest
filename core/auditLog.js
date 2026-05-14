/**
 * @fileoverview Sanitized Audit Logger — Gift Code Delivery System
 *   + Category 7: Leak Monitoring & Forensics
 *
 * CRITICAL SECURITY RULES (enforced by design):
 *   1. Code  -> NEVER logged in plaintext. Replaced with length indicator or `***`.
 *   2. Token -> NEVER logged in full. First 8 chars + "..." only.
 *   3. claimId / nonce -> NEVER contain code values.
 *   4. telegramId / deviceId -> Hashed or truncated (first 6 + "...").
 *   5. decryptString() lives ONLY in codeReveal.js — this module never decrypts.
 *   6. reveal_audit stores codeId (reference) and codeLength — NEVER the code value.
 *
 * All log entries are structured JSON for machine parsing.
 * Cache headers: no-cache, no-store, must-revalidate, proxy-revalidate.
 */

import { createHash, randomUUID, randomBytes } from 'crypto';

// ----------------------------------------------------------------------------
// Constants
// ----------------------------------------------------------------------------

export const AuditEvent = Object.freeze({
  // Lifecycle
  CODE_DELIVERED: 'CODE_DELIVERED',
  CODE_CLAIMED:   'CODE_CLAIMED',
  CODE_EXPIRED:   'CODE_EXPIRED',
  CODE_REVOKED:   'CODE_REVOKED',

  // Security gates
  TIMELOCK_BLOCKED:    'TIMELOCK_BLOCKED',
  RATE_LIMIT_HIT:      'RATE_LIMIT_HIT',
  SUSPICIOUS_ACTIVITY: 'SUSPICIOUS_ACTIVITY',
  CHALLENGE_PASSED:    'CHALLENGE_PASSED',
  CHALLENGE_FAILED:    'CHALLENGE_FAILED',
  USER_BLOCKED:        'USER_BLOCKED',
  USER_UNBLOCKED:      'USER_UNBLOCKED',

  // Admin
  ADMIN_LOGIN:       'ADMIN_LOGIN',
  ADMIN_ACTION:      'ADMIN_ACTION',
  ADMIN_CODE_CREATE: 'ADMIN_CODE_CREATE',
  ADMIN_CODE_DELETE: 'ADMIN_CODE_DELETE',
  CONFIG_CHANGED:    'CONFIG_CHANGED',

  // System
  DECRYPT_ATTEMPT: 'DECRYPT_ATTEMPT',
  DECRYPT_SUCCESS: 'DECRYPT_SUCCESS',
  DECRYPT_FAILURE: 'DECRYPT_FAILURE',
  SYSTEM_ERROR:    'SYSTEM_ERROR',
});

export const LogLevel = Object.freeze({
  DEBUG:    'DEBUG',
  INFO:     'INFO',
  WARN:     'WARN',
  ERROR:    'ERROR',
  CRITICAL: 'CRITICAL',
});

/** Fields that must NEVER appear in logs — their presence triggers redaction. */
const SENSITIVE_FIELD_NAMES = new Set([
  'code', 'secret', 'plaintext', 'encrypted', 'cipher',
  'password', 'passphrase', 'privateKey', 'apiKey',
  'authorization', 'cookie', 'sessionSecret',
]);

/** Metadata fields that receive partial masking. */
const MASKABLE_FIELDS = Object.freeze({
  code:         'FULL_REDACT',
  token:        'TRUNCATE_8',
  telegramId:   'HASH_OR_TRUNCATE_6',
  deviceId:     'HASH_OR_TRUNCATE_6',
  apiKey:       'TRUNCATE_8',
  sessionToken: 'HASH_OR_TRUNCATE_6',
  ip:           'ANONYMIZE',
});

/** Collection names for leak monitoring */
const COLL_REVEAL_AUDIT  = 'reveal_audit';
const COLL_LEAK_INCIDENT = 'leak_incidents';
const COLL_CODE_ROTATION = 'code_rotations';

// ----------------------------------------------------------------------------
// MongoDB handle (for Category 7)
// ----------------------------------------------------------------------------

let _db = null;

/**
 * Initialise leak monitoring collections.
 * @param {import('mongodb').Db} db — connected MongoDB Db instance
 */
export function initLeakMonitor(db) {
  _db = db;
  // TTL: reveal audit entries kept for 90 days
  _db.collection(COLL_REVEAL_AUDIT).createIndex(
    { timestamp: 1 },
    { expireAfterSeconds: 86400 * 90 }
  );
  _db.collection(COLL_REVEAL_AUDIT).createIndex({ codeId: 1, timestamp: 1 });
  _db.collection(COLL_REVEAL_AUDIT).createIndex({ telegramIdHash: 1 });
  _db.collection(COLL_REVEAL_AUDIT).createIndex({ deviceIdHash: 1 });
  _db.collection(COLL_REVEAL_AUDIT).createIndex({ ipHash: 1 });

  _db.collection(COLL_LEAK_INCIDENT).createIndex({ codeId: 1 }, { unique: true, sparse: true });
  _db.collection(COLL_LEAK_INCIDENT).createIndex({ detectedAt: 1 });

  _db.collection(COLL_CODE_ROTATION).createIndex({ rotatedAt: 1 });
  _db.collection(COLL_CODE_ROTATION).createIndex({ oldCodeId: 1 });
}

function getColl(name) {
  if (!_db) return null;
  return _db.collection(name);
}

function quickHash(val) {
  if (!val) return 'null';
  return createHash('sha256').update(String(val)).digest('hex').slice(0, 16);
}

// ----------------------------------------------------------------------------
// Internal helpers
// ----------------------------------------------------------------------------

function hashValue(val) {
  if (!val) return null;
  return createHash('sha256').update(String(val)).digest('hex').slice(0, 16);
}

function truncate(val, n = 8) {
  if (!val) return null;
  const s = String(val);
  return s.length <= n ? `${s}...` : `${s.slice(0, n)}...`;
}

function anonymizeIp(ip) {
  if (!ip || typeof ip !== 'string') return null;
  if (ip.includes('.')) return ip.replace(/\.\d+$/, '.0');
  if (ip.includes(':')) {
    const parts = ip.split(':');
    return parts.slice(0, 4).join(':') + '::';
  }
  return truncate(ip, 6);
}

function maskField(key, value) {
  const strategy = MASKABLE_FIELDS[key];
  if (!strategy) return value;
  switch (strategy) {
    case 'FULL_REDACT':
      return value ? `[REDACTED:${String(value).length}chars]` : '[REDACTED:null]';
    case 'TRUNCATE_8':
      return truncate(value, 8);
    case 'HASH_OR_TRUNCATE_6':
      return hashValue(value) || truncate(value, 6);
    case 'ANONYMIZE':
      return anonymizeIp(value);
    default:
      return value;
  }
}

function sanitizeLogData(data) {
  if (data === null || data === undefined) return data;
  if (typeof data !== 'object') return data;
  if (Array.isArray(data)) return data.map((item) => sanitizeLogData(item));
  const sanitized = {};
  for (const [key, value] of Object.entries(data)) {
    const lowerKey = key.toLowerCase();
    if (SENSITIVE_FIELD_NAMES.has(lowerKey)) {
      sanitized[key] = value ? `[REDACTED:${String(value).length}chars]` : '[REDACTED:null]';
      continue;
    }
    if (MASKABLE_FIELDS[key]) {
      sanitized[key] = maskField(key, value);
      continue;
    }
    if (value !== null && typeof value === 'object') {
      sanitized[key] = sanitizeLogData(value);
      continue;
    }
    sanitized[key] = value;
  }
  return sanitized;
}

function buildEntry(level, event, data) {
  const entry = {
    v:     1,
    ts:    new Date().toISOString(),
    level,
    event,
    id:    randomUUID(),
    data:  sanitizeLogData(data),
  };
  if (data instanceof Error) {
    entry.data = { name: data.name, message: data.message };
  }
  return entry;
}

function emitLog(entry) {
  process.stdout.write(`${JSON.stringify(entry)}\n`);
}

// ----------------------------------------------------------------------------
// Public API — Core Logging
// ----------------------------------------------------------------------------

export function logAudit(event, data, level = LogLevel.INFO) {
  if (!event || typeof event !== 'string') {
    emitLog(buildEntry(LogLevel.ERROR, 'INVALID_AUDIT_CALL', { reason: 'Missing or invalid event name' }));
    return;
  }
  if (data && (data.code || data.secret || data.plaintext)) {
    const sanitized = sanitizeLogData(data);
    delete data.code;
    delete data.secret;
    delete data.plaintext;
    emitLog(buildEntry(LogLevel.CRITICAL, 'AUDIT_LEAK_PREVENTED', {
      event,
      reason: 'Raw code/secret was passed to logAudit — automatically redacted',
      originalKeys: Object.keys(data).filter((k) => SENSITIVE_FIELD_NAMES.has(k.toLowerCase())),
    }));
    emitLog(buildEntry(level, event, sanitized));
    return;
  }
  emitLog(buildEntry(level, event, data));
}

export function logCodeDelivery(claimId, codeDocId, codeLength, telegramIdMasked, durationMs) {
  if (claimId && String(claimId).length > 20 && /^[A-F0-9]+$/i.test(claimId)) {
    emitLog(buildEntry(LogLevel.WARN, 'SUSPECT_CLAIM_ID', {
      claimId: truncate(claimId, 8),
      reason: 'claimId resembles a code value — rejected from log',
    }));
    return;
  }
  emitLog(buildEntry(LogLevel.INFO, AuditEvent.CODE_DELIVERED, {
    claimId:    truncate(claimId, 12),
    codeDocId:  truncate(codeDocId, 12),
    codeLength,
    telegramId: maskField('telegramId', telegramIdMasked),
    durationMs,
    cacheControl: 'no-cache, no-store, must-revalidate, proxy-revalidate',
  }));
}

export function logSecurityAlert(event, details) {
  const level =
    (details?.riskScore > 85) ? LogLevel.CRITICAL :
    (details?.riskScore > 60) ? LogLevel.WARN :
    LogLevel.INFO;
  emitLog(buildEntry(level, event, {
    ...details,
    alertType: event,
    timestamp: new Date().toISOString(),
  }));
}

export function logAdminAction(adminId, action, details) {
  emitLog(buildEntry(LogLevel.INFO, AuditEvent.ADMIN_ACTION, {
    adminId:      hashValue(adminId),
    action,
    details:      sanitizeLogData(details || {}),
    source:       'auditLog',
    cacheControl: 'no-cache, no-store, must-revalidate, proxy-revalidate',
  }));
}

export function logDecryptLifecycle(phase, meta) {
  const eventMap = {
    attempt: AuditEvent.DECRYPT_ATTEMPT,
    success: AuditEvent.DECRYPT_SUCCESS,
    failure: AuditEvent.DECRYPT_FAILURE,
  };
  if (meta && (meta.code || meta.plaintext || meta.decrypted)) {
    emitLog(buildEntry(LogLevel.CRITICAL, 'DECRYPT_LOG_LEAK_BLOCKED', {
      reason: 'code/plaintex/decrypted field passed to logDecryptLifecycle — stripped',
      phase,
    }));
    const safe = { ...meta };
    delete safe.code;
    delete safe.plaintext;
    delete safe.decrypted;
    emitLog(buildEntry(LogLevel.INFO, eventMap[phase] || 'DECRYPT_UNKNOWN', safe));
    return;
  }
  emitLog(buildEntry(LogLevel.INFO, eventMap[phase] || 'DECRYPT_UNKNOWN', meta));
}

export function logAccessDenied(reason, context) {
  const event = reason === 'TIMELOCK_BLOCKED'
    ? AuditEvent.TIMELOCK_BLOCKED
    : AuditEvent.RATE_LIMIT_HIT;
  emitLog(buildEntry(LogLevel.WARN, event, {
    ...sanitizeLogData(context),
    denialType: reason,
    timestamp:  new Date().toISOString(),
  }));
}

export function maskCode(code) {
  if (!code || typeof code !== 'string' || code.length === 0) return '***';
  return '***';
}

// ----------------------------------------------------------------------------
// CATEGORY 7 — Leak Monitoring & Forensics
// ----------------------------------------------------------------------------

/**
 * 7.1 Record a complete reveal audit trail entry.
 *
 * Every /reveal creates an entry in 'reveal_audit':
 * {
 *   claimId, nonceHash (hashed),
 *   telegramIdHash: sha256(tgId).substring(0, 16),
 *   deviceIdHash:   sha256(device).substring(0, 16),
 *   ipHash:         sha256(ip).substring(0, 16),
 *   codeId:         codeDoc._id,     // NOT the code itself!
 *   codeLength:     32,              // only length
 *   timestamp:      Date,
 *   success:        true/false,
 *   error:          'TIMELOCK_ACTIVE' | null,
 *   gateResults:    { pow: true, behavioral: true, turnstile: false },
 *   riskScore:      15,              // at time of reveal
 * }
 *
 * @param {Object} params
 */
export async function logRevealAudit(params) {
  const {
    claimId,
    nonce,
    telegramId,
    deviceId,
    ip,
    codeId,
    codeLength,
    success,
    error = null,
    gateResults = {},
    riskScore = 0,
  } = params;

  const entry = {
    claimId:         claimId || null,
    nonceHash:       nonce ? quickHash(nonce) : null,
    telegramIdHash:  telegramId ? quickHash(telegramId) : null,
    deviceIdHash:    deviceId ? quickHash(deviceId) : null,
    ipHash:          ip ? quickHash(ip) : null,
    codeId:          codeId || null,
    codeLength:      codeLength || 0,
    timestamp:       new Date(),
    success:         !!success,
    error:           error,
    gateResults:     {
      pow:         !!gateResults.pow,
      behavioral:  !!gateResults.behavioral,
      turnstile:   !!gateResults.turnstile,
    },
    riskScore:       Math.min(Math.max(riskScore, 0), 100),
  };

  try {
    const coll = getColl(COLL_REVEAL_AUDIT);
    if (coll) await coll.insertOne(entry);
  } catch {
    // Non-critical
  }

  emitLog(buildEntry(
    success ? LogLevel.INFO : LogLevel.WARN,
    success ? AuditEvent.CODE_DELIVERED : AuditEvent.SUSPICIOUS_ACTIVITY,
    {
      type: 'REVEAL_AUDIT',
      claimId: truncate(claimId, 12),
      nonceHash: entry.nonceHash,
      telegramIdHash: entry.telegramIdHash,
      deviceIdHash: entry.deviceIdHash,
      ipHash: entry.ipHash,
      codeId: truncate(String(codeId), 12),
      codeLength,
      success: entry.success,
      error: entry.error,
      gateResults: entry.gateResults,
      riskScore: entry.riskScore,
    }
  ));

  return entry;
}

/**
 * 7.2 Code Leak Forensics.
 * If a leaked code is found: query reveal_audit for that codeId,
 * find FIRST reveal (earliest timestamp).
 *
 * @param {string} codeId
 * @returns {Promise<Object>}
 */
export async function investigateCodeLeak(codeId) {
  if (!codeId || !_db) {
    return { found: false, firstRevealedBy: null, firstRevealTime: null, totalReveals: 0, allReveals: [] };
  }

  try {
    const coll = getColl(COLL_REVEAL_AUDIT);
    if (!coll) return { found: false, firstRevealedBy: null, firstRevealTime: null, totalReveals: 0, allReveals: [] };

    const reveals = await coll
      .find(
        { codeId, success: true },
        { projection: { _id: 0, telegramIdHash: 1, deviceIdHash: 1, ipHash: 1, timestamp: 1, riskScore: 1 } }
      )
      .sort({ timestamp: 1 })
      .toArray();

    const totalReveals = reveals.length;
    if (totalReveals === 0) {
      return { found: false, firstRevealedBy: null, firstRevealTime: null, totalReveals: 0, allReveals: [] };
    }

    const firstReveal = reveals[0];

    await getColl(COLL_LEAK_INCIDENT).updateOne(
      { codeId },
      {
        $set: {
          codeId,
          firstRevealedBy: firstReveal.telegramIdHash,
          firstRevealTime: firstReveal.timestamp,
          totalReveals,
          detectedAt: new Date(),
          allReveals: reveals.map((r) => ({
            telegramIdHash: r.telegramIdHash,
            deviceIdHash: r.deviceIdHash,
            ipHash: r.ipHash,
            timestamp: r.timestamp,
            riskScore: r.riskScore,
          })),
        },
      },
      { upsert: true }
    );

    return {
      found: true,
      firstRevealedBy: firstReveal.telegramIdHash || null,
      firstRevealTime: firstReveal.timestamp ? firstReveal.timestamp.toISOString() : null,
      totalReveals,
      allReveals: reveals.map((r) => ({
        telegramIdHash: r.telegramIdHash,
        ipHash: r.ipHash,
        deviceIdHash: r.deviceIdHash,
        timestamp: r.timestamp ? r.timestamp.toISOString() : null,
      })),
    };
  } catch {
    return { found: false, firstRevealedBy: null, firstRevealTime: null, totalReveals: 0, allReveals: [] };
  }
}

/**
 * 7.2 (alt) Get stored leak incident.
 * @param {string} codeId
 */
export async function getLeakIncident(codeId) {
  if (!codeId || !_db) return null;
  try {
    return await getColl(COLL_LEAK_INCIDENT).findOne({ codeId }, { projection: { _id: 0 } });
  } catch { return null; }
}

/**
 * 7.3 Log a code rotation event.
 * @param {Object} params
 */
export async function logCodeRotation(params) {
  const { oldCodeId, newCodeId, reason = 'scheduled' } = params;

  const entry = {
    action: 'CODE_ROTATED',
    oldCodeId: oldCodeId || null,
    newCodeId: newCodeId || null,
    reason,
    rotatedAt: new Date(),
  };

  try {
    const coll = getColl(COLL_CODE_ROTATION);
    if (coll) await coll.insertOne(entry);
  } catch { /* non-critical */ }

  emitLog(buildEntry(LogLevel.INFO, AuditEvent.CODE_EXPIRED, {
    type: 'CODE_ROTATION',
    oldCodeId: truncate(String(oldCodeId), 12),
    newCodeId: truncate(String(newCodeId), 12),
    reason,
    rotatedAt: entry.rotatedAt.toISOString(),
  }));

  return entry;
}

/**
 * 7.4 Log an instant code expiry event (admin-triggered).
 * @param {Object} params
 */
export async function logInstantExpiry(params) {
  const { codeId, adminId } = params;

  const entry = {
    action: 'INSTANT_EXPIRY',
    codeId: codeId || null,
    adminIdHash: adminId ? quickHash(adminId) : null,
    expiredAt: new Date(),
  };

  try {
    const coll = getColl(COLL_CODE_ROTATION);
    if (coll) await coll.insertOne(entry);
  } catch { /* non-critical */ }

  emitLog(buildEntry(LogLevel.WARN, AuditEvent.CODE_REVOKED, {
    type: 'INSTANT_EXPIRY',
    codeId: truncate(String(codeId), 12),
    adminIdHash: entry.adminIdHash,
    expiredAt: entry.expiredAt.toISOString(),
    message: 'Code expired by admin — pending claims/reveals get NO_CODE_AVAILABLE',
  }));

  return entry;
}

/**
 * 7.3 Daily Code Rotation — Cron job handler.
 * @param {Object} params
 */
export async function performDailyCodeRotation(params) {
  const { codesCollection, autoGenerate = false } = params;

  if (!codesCollection) {
    return { rotated: false, expiredCount: 0, newCodeId: null, generatedCode: null };
  }

  try {
    const activeCodes = await codesCollection
      .find({ status: 'active' }, { projection: { _id: 1 } })
      .toArray();

    const now = new Date();
    const oldCodeIds = activeCodes.map((c) => c._id);
    let expiredCount = 0;

    if (oldCodeIds.length > 0) {
      const result = await codesCollection.updateMany(
        { _id: { $in: oldCodeIds } },
        { $set: { status: 'expired', expiredAt: now, expiredBy: 'daily_rotation' } }
      );
      expiredCount = result.modifiedCount || 0;
    }

    let generatedCode = null;
    if (autoGenerate) {
      generatedCode = generateRandomCode(32);
    }

    await logCodeRotation({
      oldCodeId: oldCodeIds.length > 0 ? oldCodeIds[0].toString() : null,
      newCodeId: generatedCode ? 'pending_encryption' : null,
      reason: 'scheduled_daily_rotation',
    });

    return { rotated: true, expiredCount, newCodeId: null, generatedCode };
  } catch (err) {
    emitLog(buildEntry(LogLevel.ERROR, AuditEvent.SYSTEM_ERROR, {
      type: 'CODE_ROTATION_FAILED',
      error: err.message,
    }));
    return { rotated: false, expiredCount: 0, newCodeId: null, generatedCode: null };
  }
}

/**
 * 7.4 Instant Code Expiry — Admin endpoint handler.
 * @param {string} codeId
 * @param {import('mongodb').Collection} codesCollection
 * @param {string} adminId
 */
export async function expireCodeInstantly(codeId, codesCollection, adminId) {
  if (!codeId || !codesCollection) {
    return { expired: false, previousStatus: null };
  }

  try {
    const result = await codesCollection.findOneAndUpdate(
      { _id: codeId, status: { $ne: 'expired' } },
      {
        $set: {
          status: 'expired',
          expiredAt: new Date(),
          expiredBy: 'admin',
          expiredByAdminId: adminId ? quickHash(adminId) : null,
        },
      },
      { returnDocument: 'before', projection: { status: 1 } }
    );

    const previousDoc = result.value || result;
    if (previousDoc) {
      await logInstantExpiry({ codeId, adminId });
      return { expired: true, previousStatus: previousDoc.status || null };
    }

    return { expired: false, previousStatus: null };
  } catch {
    return { expired: false, previousStatus: null };
  }
}

/**
 * Generate a random alphanumeric code of given length.
 * Caller MUST encrypt before storing.
 */
function generateRandomCode(length = 32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const randomValues = randomBytes(length);
  for (let i = 0; i < length; i++) {
    result += chars[randomValues[i] % chars.length];
  }
  return result;
}

// Default export
export default {
  // Core logging
  logAudit,
  logCodeDelivery,
  logSecurityAlert,
  logAdminAction,
  logDecryptLifecycle,
  logAccessDenied,
  maskCode,
  AuditEvent,
  LogLevel,
  // Category 7 — Leak Monitoring
  initLeakMonitor,
  logRevealAudit,
  investigateCodeLeak,
  getLeakIncident,
  logCodeRotation,
  logInstantExpiry,
  performDailyCodeRotation,
  expireCodeInstantly,
};
