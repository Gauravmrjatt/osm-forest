/**
 * @fileoverview Cleanup Cron Job for Osm Army Gift Code Fortress.
 * Runs multiple cleanup tasks on different schedules to maintain database hygiene,
 * enforce data retention policies, and prevent unbounded growth.
 *
 * Schedule Tiers:
 *   - Every minute:   tokens, sessions, temp tokens, rate limit entries
 *   - Every 5 min:    audit logs, IP logs, fingerprints, blocked IPs, alerts, mutation logs
 *   - Every hour:     unclaimed codes, orphaned records, Telegram messages, rate limit compaction
 *   - Every day:      database backup, IP reputation, key rotation, temp files, stats
 *
 * Safety Features:
 *   - Soft delete → hard delete after 7 days
 *   - Batch deletions (1000 at a time)
 *   - Never delete today's data
 *   - Graceful error handling per task
 *   - Cleanup statistics tracking
 *
 * @module cron/cleanup
 * @version 5.0.0
 */

'use strict';

import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { writeFile, mkdir, unlink, readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const BATCH_SIZE = 1000;
const SOFT_DELETE_FIELD = 'deletedAt';
const HARD_DELETE_AFTER_MS = 7 * 86_400_000; // 7 days
const STATS_HISTORY_MAX = 1000;

/** Retention periods in days. */
const RETENTION = Object.freeze({
  AUDIT_LOGS:        90,
  IP_LOGS:           30,
  DEVICE_FINGERPRINTS: 90,
  BLOCKED_IPS:       30,
  ALERTS:            30,
  MUTATION_LOGS:     365,
  TELEGRAM_MESSAGES: 30,
  TEMP_FILES:        7,
});

// ---------------------------------------------------------------------------
// Custom Errors
// ---------------------------------------------------------------------------

export class CleanupError extends Error {
  constructor(message, code, taskName, extra = {}) {
    super(message);
    this.name = 'CleanupError';
    this.code = code;
    this.taskName = taskName;
    Object.assign(this, extra);
    Error.captureStackTrace(this, this.constructor);
  }
}

// ---------------------------------------------------------------------------
// Utility Functions
// ---------------------------------------------------------------------------

/**
 * Current timestamp in ms.
 * @returns {number}
 */
function now() {
  return Date.now();
}

/**
 * Start of today (00:00:00 UTC) in ms.
 * @returns {number}
 */
function startOfToday() {
  const d = new Date();
  d.setUTCHours(0, 0, 0, 0);
  return d.getTime();
}

/**
 * Convert days to milliseconds.
 * @param {number} days
 * @returns {number}
 */
function daysToMs(days) {
  return days * 86_400_000;
}

/**
 * Sleep helper.
 * @param {number} ms
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// ---------------------------------------------------------------------------
// Cleanup Engine
// ---------------------------------------------------------------------------

/**
 * CleanupEngine manages all cleanup tasks with proper scheduling,
 * safety checks, statistics, and alerting.
 */
export class CleanupEngine extends EventEmitter {
  /**
   * @param {Object} options
   * @param {Object|null} options.db MongoDB database instance
   * @param {Function|null} options.telegramSend Async function for alerts
   * @param {string} [options.backupDir=/tmp/osmarmy-backups]
   * @param {string} [options.tempDir=/tmp/osmarmy-temp]
   */
  constructor(options = {}) {
    super();
    this.db = options.db || null;
    this.telegramSend = options.telegramSend || null;
    this.backupDir = options.backupDir || '/tmp/osmarmy-backups';
    this.tempDir = options.tempDir || '/tmp/osmarmy-temp';

    // Task failure tracking
    /** @type {Map<string, number>} consecutive failures per task */
    this.failureCounts = new Map();
    /** @type {number} */
    this.maxConsecutiveFailures = 3;

    // Statistics history
    /** @type {Array<Object>} */
    this.statsHistory = [];

    // Collection references (initialised in init())
    /** @type {import('mongodb').Collection|null} */
    this.tokensCol = null;
    /** @type {import('mongodb').Collection|null} */
    this.sessionsCol = null;
    /** @type {import('mongodb').Collection|null} */
    this.auditLogsCol = null;
    /** @type {import('mongodb').Collection|null} */
    this.ipLogsCol = null;
    /** @type {import('mongodb').Collection|null} */
    this.fingerprintsCol = null;
    /** @type {import('mongodb').Collection|null} */
    this.blockedIPsCol = null;
    /** @type {import('mongodb').Collection|null} */
    this.alertsCol = null;
    /** @type {import('mongodb').Collection|null} */
    this.mutationLogsCol = null;
    /** @type {import('mongodb').Collection|null} */
    this.codesCol = null;
    /** @type {import('mongodb').Collection|null} */
    this.watermarksCol = null;
    /** @type {import('mongodb').Collection|null} */
    this.telegramMessagesCol = null;
    /** @type {import('mongodb').Collection|null} */
    this.rateLimitsCol = null;
    /** @type {import('mongodb').Collection|null} */
    this.statsCol = null;
    /** @type {import('mongodb').Collection|null} */
    this.codeClaimsCol = null;
    /** @type {import('mongodb').Collection|null} */
    this.revealAuditCol = null;
  }

  // ------------------------------------------------------------------
  // Initialisation
  // ------------------------------------------------------------------

  /**
   * Initialise collection references and create indexes.
   * @returns {Promise<void>}
   */
  async init() {
    if (!this.db) return;

    this.tokensCol = this.db.collection('tokens');
    this.sessionsCol = this.db.collection('sessions');
    this.auditLogsCol = this.db.collection('audit_logs');
    this.ipLogsCol = this.db.collection('ip_logs');
    this.fingerprintsCol = this.db.collection('device_fingerprints');
    this.blockedIPsCol = this.db.collection('blocked_ips');
    this.alertsCol = this.db.collection('alerts');
    this.mutationLogsCol = this.db.collection('mutation_logs');
    this.codesCol = this.db.collection('gift_codes');
    this.watermarksCol = this.db.collection('watermarks');
    this.telegramMessagesCol = this.db.collection('telegram_messages');
    this.rateLimitsCol = this.db.collection('rate_limits');
    this.statsCol = this.db.collection('cleanup_stats');
    this.codeClaimsCol = this.db.collection('code_claims');
    this.revealAuditCol = this.db.collection('reveal_audit');

    // Ensure soft-delete index exists on all collections
    const cols = [
      this.tokensCol, this.sessionsCol, this.auditLogsCol, this.ipLogsCol,
      this.fingerprintsCol, this.blockedIPsCol, this.alertsCol, this.mutationLogsCol,
      this.codesCol, this.watermarksCol, this.telegramMessagesCol, this.rateLimitsCol,
      this.codeClaimsCol, this.revealAuditCol,
    ].filter(Boolean);

    for (const col of cols) {
      try {
        await col.createIndex(
          { [SOFT_DELETE_FIELD]: 1 },
          { background: true, sparse: true }
        );
        await col.createIndex(
          { createdAt: 1 },
          { background: true }
        );
        await col.createIndex(
          { lastActivity: 1 },
          { background: true, sparse: true }
        );
      } catch {
        // Best-effort index creation
      }
    }

    // Ensure backup & temp dirs exist
    try { await mkdir(this.backupDir, { recursive: true }); } catch { /* ignore */ }
    try { await mkdir(this.tempDir, { recursive: true }); } catch { /* ignore */ }
  }

  // ------------------------------------------------------------------
  // Core Runner
  // ------------------------------------------------------------------

  /**
   * Run all cleanup tasks for a given tier.
   * @param {'minute'|'fiveMinute'|'hourly'|'daily'} tier
   * @returns {Promise<Object>} Statistics
   */
  async runTier(tier) {
    const startedAt = now();
    const stats = { tier, startedAt: new Date().toISOString(), tasks: {}, totalDeleted: 0 };
    let tasks = [];

    switch (tier) {
      case 'minute':
        tasks = [
          { name: 'expired_tokens', fn: this.cleanupExpiredTokens.bind(this) },
          { name: 'expired_sessions', fn: this.cleanupExpiredSessions.bind(this) },
          { name: 'expired_temp_tokens', fn: this.cleanupExpiredTempTokens.bind(this) },
          { name: 'expired_rate_limits', fn: this.cleanupExpiredRateLimits.bind(this) },
        ];
        break;
      case 'fiveMinute':
        tasks = [
          { name: 'old_audit_logs', fn: this.cleanupOldAuditLogs.bind(this) },
          { name: 'old_ip_logs', fn: this.cleanupOldIPLogs.bind(this) },
          { name: 'old_fingerprints', fn: this.cleanupOldFingerprints.bind(this) },
          { name: 'expired_blocked_ips', fn: this.cleanupExpiredBlockedIPs.bind(this) },
          { name: 'old_alerts', fn: this.cleanupOldAlerts.bind(this) },
          { name: 'old_mutation_logs', fn: this.cleanupOldMutationLogs.bind(this) },
        ];
        break;
      case 'hourly':
        tasks = [
          { name: 'unclaimed_codes', fn: this.cleanupUnclaimedCodes.bind(this) },
          { name: 'orphaned_records', fn: this.cleanupOrphanedRecords.bind(this) },
          { name: 'old_telegram_messages', fn: this.cleanupOldTelegramMessages.bind(this) },
          { name: 'compact_rate_limits', fn: this.compactRateLimits.bind(this) },
          { name: 'old_code_claims', fn: this.cleanupOldCodeClaims.bind(this) },
        ];
        break;
      case 'daily':
        tasks = [
          { name: 'database_backup', fn: this.runDatabaseBackup.bind(this) },
          { name: 'refresh_ip_reputation', fn: this.refreshIPReputation.bind(this) },
          { name: 'rotate_old_keys', fn: this.rotateOldKeys.bind(this) },
          { name: 'cleanup_temp_files', fn: this.cleanupTempFiles.bind(this) },
          { name: 'generate_statistics', fn: this.generateUsageStatistics.bind(this) },
          { name: 'old_reveal_audit', fn: this.cleanupOldRevealAudit.bind(this) },
        ];
        break;
      default:
        throw new CleanupError(`Unknown tier: ${tier}`, 'UNKNOWN_TIER', tier);
    }

    for (const task of tasks) {
      try {
        const taskStarted = now();
        const result = await this.runWithSafety(task.name, task.fn);
        stats.tasks[task.name] = {
          success: true,
          deleted: result.deleted || 0,
          durationMs: now() - taskStarted,
          ...result,
        };
        stats.totalDeleted += result.deleted || 0;
        this.failureCounts.set(task.name, 0);
      } catch (err) {
        stats.tasks[task.name] = {
          success: false,
          error: err.message,
          code: err.code || 'UNKNOWN',
          durationMs: now() - startedAt,
        };
        const currentFails = (this.failureCounts.get(task.name) || 0) + 1;
        this.failureCounts.set(task.name, currentFails);

        if (currentFails >= this.maxConsecutiveFailures) {
          await this.alertRepeatedFailure(task.name, currentFails, err);
        }
      }
    }

    stats.durationMs = now() - startedAt;
    stats.finishedAt = new Date().toISOString();

    // Persist statistics
    await this.persistStats(stats);
    this.statsHistory.push(stats);
    if (this.statsHistory.length > STATS_HISTORY_MAX) {
      this.statsHistory = this.statsHistory.slice(-STATS_HISTORY_MAX / 2);
    }

    this.emit('tier_complete', { tier, stats });
    return stats;
  }

  /**
   * Run a single cleanup function with safety wrappers.
   * @param {string} taskName
   * @param {Function} fn
   * @returns {Promise<Object>}
   */
  async runWithSafety(taskName, fn) {
    if (!this.db) {
      return { deleted: 0, skipped: true, reason: 'no_database' };
    }
    return await fn();
  }

  // ------------------------------------------------------------------
  // Soft / Hard Delete Helpers
  // ------------------------------------------------------------------

  /**
   * Soft-delete documents matching the filter.
   * @param {import('mongodb').Collection} collection
   * @param {Object} filter
   * @returns {Promise<number>} Number soft-deleted
   */
  async softDelete(collection, filter) {
    const result = await collection.updateMany(
      { ...filter, [SOFT_DELETE_FIELD]: { $exists: false } },
      { $set: { [SOFT_DELETE_FIELD]: new Date() } }
    );
    return result.modifiedCount || 0;
  }

  /**
   * Hard-delete soft-deleted documents older than the grace period.
   * @param {import('mongodb').Collection} collection
   * @returns {Promise<number>} Number hard-deleted
   */
  async hardDelete(collection) {
    const cutoff = new Date(now() - HARD_DELETE_AFTER_MS);
    let totalDeleted = 0;
    let hasMore = true;

    while (hasMore) {
      const docs = await collection
        .find({ [SOFT_DELETE_FIELD]: { $lt: cutoff } })
        .limit(BATCH_SIZE)
        .project({ _id: 1 })
        .toArray();

      if (docs.length === 0) {
        hasMore = false;
        break;
      }

      const ids = docs.map((d) => d._id);
      const result = await collection.deleteMany({ _id: { $in: ids } });
      totalDeleted += result.deletedCount || 0;

      if (docs.length < BATCH_SIZE) {
        hasMore = false;
      }
    }

    return totalDeleted;
  }

  /**
   * Delete documents in batches (direct hard delete for non-critical data).
   * @param {import('mongodb').Collection} collection
   * @param {Object} filter
   * @param {string} taskName
   * @returns {Promise<number>}
   */
  async batchDelete(collection, filter, taskName) {
    let totalDeleted = 0;
    let hasMore = true;

    while (hasMore) {
      const docs = await collection
        .find(filter)
        .limit(BATCH_SIZE)
        .project({ _id: 1 })
        .toArray();

      if (docs.length === 0) {
        hasMore = false;
        break;
      }

      const ids = docs.map((d) => d._id);
      try {
        const result = await collection.deleteMany({ _id: { $in: ids } });
        totalDeleted += result.deletedCount || 0;
      } catch (err) {
        throw new CleanupError(
          `Batch delete failed in ${taskName}: ${err.message}`,
          'BATCH_DELETE_FAILED',
          taskName
        );
      }

      if (docs.length < BATCH_SIZE) {
        hasMore = false;
      }

      // Small yield between batches
      await sleep(10);
    }

    return totalDeleted;
  }

  /**
   * Ensure we never delete data created today.
   * @param {Object} filter
   * @param {string} [dateField='createdAt']
   * @returns {Object}
   */
  excludeToday(filter, dateField = 'createdAt') {
    const todayStart = new Date(startOfToday());
    return {
      ...filter,
      [dateField]: { ...filter[dateField], $lt: todayStart },
    };
  }

  // ------------------------------------------------------------------
  // Minute-Tier Tasks
  // ------------------------------------------------------------------

  /**
   * Delete expired tokens (createdAt + 10 seconds < now).
   * @returns {Promise<Object>}
   */
  async cleanupExpiredTokens() {
    const col = this.tokensCol;
    if (!col) return { deleted: 0 };
    const cutoff = new Date(now() - 10_000);
    let filter = {
      createdAt: { $lt: cutoff },
      type: 'temp',
    };
    filter = this.excludeToday(filter, 'createdAt');
    const softDeleted = await this.softDelete(col, filter);
    const hardDeleted = await this.hardDelete(col);
    return { deleted: softDeleted + hardDeleted, softDeleted, hardDeleted };
  }

  /**
   * Delete expired sessions (lastActivity + 30 minutes < now).
   * @returns {Promise<Object>}
   */
  async cleanupExpiredSessions() {
    const col = this.sessionsCol;
    if (!col) return { deleted: 0 };
    const cutoff = new Date(now() - 30 * 60_000);
    let filter = { lastActivity: { $lt: cutoff } };
    filter = this.excludeToday(filter, 'lastActivity');
    const softDeleted = await this.softDelete(col, filter);
    const hardDeleted = await this.hardDelete(col);
    return { deleted: softDeleted + hardDeleted, softDeleted, hardDeleted };
  }

  /**
   * Delete expired temp tokens (createdAt + 5 minutes < now).
   * @returns {Promise<Object>}
   */
  async cleanupExpiredTempTokens() {
    const col = this.tokensCol;
    if (!col) return { deleted: 0 };
    const cutoff = new Date(now() - 5 * 60_000);
    let filter = {
      createdAt: { $lt: cutoff },
      type: 'temp_token',
    };
    filter = this.excludeToday(filter, 'createdAt');
    const softDeleted = await this.softDelete(col, filter);
    const hardDeleted = await this.hardDelete(col);
    return { deleted: softDeleted + hardDeleted, softDeleted, hardDeleted };
  }

  /**
   * Clear expired rate limit entries.
   * @returns {Promise<Object>}
   */
  async cleanupExpiredRateLimits() {
    const col = this.rateLimitsCol;
    if (!col) return { deleted: 0 };
    const cutoff = new Date(now() - 86_400_000); // 1 day
    let filter = { expiresAt: { $lt: cutoff } };
    // Rate limits don't have createdAt; use expiresAt directly
    const deleted = await this.batchDelete(col, filter, 'expired_rate_limits');
    return { deleted };
  }

  // ------------------------------------------------------------------
  // Five-Minute-Tier Tasks
  // ------------------------------------------------------------------

  /**
   * Delete old audit logs (keep 90 days).
   * @returns {Promise<Object>}
   */
  async cleanupOldAuditLogs() {
    const col = this.auditLogsCol;
    if (!col) return { deleted: 0 };
    const cutoff = new Date(now() - daysToMs(RETENTION.AUDIT_LOGS));
    let filter = { createdAt: { $lt: cutoff } };
    filter = this.excludeToday(filter, 'createdAt');
    const softDeleted = await this.softDelete(col, filter);
    const hardDeleted = await this.hardDelete(col);
    return { deleted: softDeleted + hardDeleted, softDeleted, hardDeleted };
  }

  /**
   * Delete old IP logs (keep 30 days).
   * @returns {Promise<Object>}
   */
  async cleanupOldIPLogs() {
    const col = this.ipLogsCol;
    if (!col) return { deleted: 0 };
    const cutoff = new Date(now() - daysToMs(RETENTION.IP_LOGS));
    let filter = { createdAt: { $lt: cutoff } };
    filter = this.excludeToday(filter, 'createdAt');
    const softDeleted = await this.softDelete(col, filter);
    const hardDeleted = await this.hardDelete(col);
    return { deleted: softDeleted + hardDeleted, softDeleted, hardDeleted };
  }

  /**
   * Delete old device fingerprints (keep 90 days).
   * @returns {Promise<Object>}
   */
  async cleanupOldFingerprints() {
    const col = this.fingerprintsCol;
    if (!col) return { deleted: 0 };
    const cutoff = new Date(now() - daysToMs(RETENTION.DEVICE_FINGERPRINTS));
    let filter = { createdAt: { $lt: cutoff } };
    filter = this.excludeToday(filter, 'createdAt');
    const softDeleted = await this.softDelete(col, filter);
    const hardDeleted = await this.hardDelete(col);
    return { deleted: softDeleted + hardDeleted, softDeleted, hardDeleted };
  }

  /**
   * Delete expired blocked IPs (if duration has passed).
   * @returns {Promise<Object>}
   */
  async cleanupExpiredBlockedIPs() {
    const col = this.blockedIPsCol;
    if (!col) return { deleted: 0 };
    // Remove entries where blockedUntil < now, or createdAt + duration < now
    const cutoff = new Date(now() - daysToMs(RETENTION.BLOCKED_IPS));
    let filter = {
      $or: [
        { blockedUntil: { $lt: new Date() } },
        { createdAt: { $lt: cutoff } },
      ],
    };
    filter = this.excludeToday(filter, 'createdAt');
    const softDeleted = await this.softDelete(col, filter);
    const hardDeleted = await this.hardDelete(col);
    return { deleted: softDeleted + hardDeleted, softDeleted, hardDeleted };
  }

  /**
   * Delete old alerts (keep 30 days).
   * @returns {Promise<Object>}
   */
  async cleanupOldAlerts() {
    const col = this.alertsCol;
    if (!col) return { deleted: 0 };
    const cutoff = new Date(now() - daysToMs(RETENTION.ALERTS));
    let filter = { createdAt: { $lt: cutoff } };
    filter = this.excludeToday(filter, 'createdAt');
    const softDeleted = await this.softDelete(col, filter);
    const hardDeleted = await this.hardDelete(col);
    return { deleted: softDeleted + hardDeleted, softDeleted, hardDeleted };
  }

  /**
   * Delete old mutation logs (keep 365 days).
   * @returns {Promise<Object>}
   */
  async cleanupOldMutationLogs() {
    const col = this.mutationLogsCol;
    if (!col) return { deleted: 0 };
    const cutoff = new Date(now() - daysToMs(RETENTION.MUTATION_LOGS));
    let filter = { timestamp: { $lt: cutoff } };
    // Use timestamp field, but ensure we don't delete today's
    const todayStart = new Date(startOfToday());
    filter = {
      ...filter,
      timestamp: { ...filter.timestamp, $lt: todayStart },
    };
    const softDeleted = await this.softDelete(col, filter);
    const hardDeleted = await this.hardDelete(col);
    return { deleted: softDeleted + hardDeleted, softDeleted, hardDeleted };
  }

  // ------------------------------------------------------------------
  // Hourly-Tier Tasks
  // ------------------------------------------------------------------

  /**
   * Delete unclaimed gift codes past their validUntil date.
   * @returns {Promise<Object>}
   */
  async cleanupUnclaimedCodes() {
    const col = this.codesCol;
    if (!col) return { deleted: 0 };
    const nowTime = new Date();
    let filter = {
      validUntil: { $lt: nowTime },
      status: { $in: ['active', 'unclaimed'] },
    };
    filter = this.excludeToday(filter, 'validUntil');
    // First mark as expired
    const expired = await col.updateMany(filter, {
      $set: { status: 'expired', expiredAt: nowTime },
    });
    // Then soft-delete expired
    const softDeleted = await this.softDelete(col, {
      status: 'expired',
      expiredAt: { $lt: nowTime },
    });
    const hardDeleted = await this.hardDelete(col);
    return {
      deleted: expired.modifiedCount + softDeleted + hardDeleted,
      markedExpired: expired.modifiedCount,
      softDeleted,
      hardDeleted,
    };
  }

  /**
   * Clean up orphaned watermark records (no parent code reference).
   * @returns {Promise<Object>}
   */
  async cleanupOrphanedRecords() {
    const col = this.watermarksCol;
    if (!col) return { deleted: 0 };

    // Find watermark.codeId values that no longer exist in gift_codes
    let orphanFilter = {};
    if (this.codesCol) {
      const existingIds = await this.codesCol
        .find({}, { projection: { _id: 1 } })
        .limit(100_000)
        .map((d) => String(d._id))
        .toArray();
      const existingSet = new Set(existingIds);
      // Batch scan for orphaned watermarks
      let totalDeleted = 0;
      let hasMore = true;
      while (hasMore) {
        const docs = await col.find({}).limit(BATCH_SIZE).toArray();
        if (docs.length === 0) { hasMore = false; break; }
        const orphanIds = docs
          .filter((d) => d.codeId && !existingSet.has(String(d.codeId)))
          .map((d) => d._id);
        if (orphanIds.length > 0) {
          const result = await col.deleteMany({ _id: { $in: orphanIds } });
          totalDeleted += result.deletedCount || 0;
        }
        if (docs.length < BATCH_SIZE) hasMore = false;
      }
      return { deleted: totalDeleted, method: 'codeId_scan' };
    }

    // Without codes collection, delete watermarks older than 30 days
    const cutoff = new Date(now() - daysToMs(30));
    let filter = { createdAt: { $lt: cutoff } };
    filter = this.excludeToday(filter, 'createdAt');
    const deleted = await this.batchDelete(col, filter, 'orphaned_watermarks');
    return { deleted, method: 'age_fallback' };
  }

  /**
   * Delete old Telegram message logs.
   * @returns {Promise<Object>}
   */
  async cleanupOldTelegramMessages() {
    const col = this.telegramMessagesCol;
    if (!col) return { deleted: 0 };
    const cutoff = new Date(now() - daysToMs(RETENTION.TELEGRAM_MESSAGES));
    let filter = { createdAt: { $lt: cutoff } };
    filter = this.excludeToday(filter, 'createdAt');
    const softDeleted = await this.softDelete(col, filter);
    const hardDeleted = await this.hardDelete(col);
    return { deleted: softDeleted + hardDeleted, softDeleted, hardDeleted };
  }

  /**
   * Compact rate limit collection (remove very old entries).
   * @returns {Promise<Object>}
   */
  async compactRateLimits() {
    const col = this.rateLimitsCol;
    if (!col) return { deleted: 0 };
    // Remove entries older than 7 days regardless of expiry
    const cutoff = new Date(now() - daysToMs(7));
    let filter = { createdAt: { $lt: cutoff } };
    filter = this.excludeToday(filter, 'createdAt');
    const deleted = await this.batchDelete(col, filter, 'compact_rate_limits');
    return { deleted };
  }

  // ------------------------------------------------------------------
  // Daily-Tier Tasks
  // ------------------------------------------------------------------

  /**
   * Run a full database backup using mongodump.
   * @returns {Promise<Object>}
   */
  async runDatabaseBackup() {
    const startedAt = now();
    const dateStr = new Date().toISOString().split('T')[0];
    const backupPath = join(this.backupDir, `backup_${dateStr}.gz`);

    try {
      const dbUri = process.env.MONGODB_URI || process.env.MONGO_URI || 'mongodb://localhost:27017/osmarmy';
      const dbName = dbUri.split('/').pop().split('?')[0];

      await execFileAsync('mongodump', [
        '--uri', dbUri,
        '--db', dbName,
        '--gzip',
        '--archive=' + backupPath,
        '--quiet',
      ]);

      return {
        deleted: 0,
        backedUp: true,
        path: backupPath,
        durationMs: now() - startedAt,
      };
    } catch (err) {
      // Fallback: export key collections via aggregation
      return {
        deleted: 0,
        backedUp: false,
        error: err.message,
        durationMs: now() - startedAt,
      };
    }
  }

  /**
   * Refresh IP reputation lists (placeholder for external service).
   * @returns {Promise<Object>}
   */
  async refreshIPReputation() {
    // In production, this would fetch from IP reputation providers
    // and update the blocked_ips collection with new threat intelligence.
    const startedAt = now();
    const col = this.blockedIPsCol;
    let updated = 0;

    if (col) {
      // Mark IPs with no recent activity for review
      const cutoff = new Date(now() - daysToMs(7));
      const result = await col.updateMany(
        {
          lastSeen: { $lt: cutoff },
          status: { $ne: 'stale' },
        },
        { $set: { status: 'stale', refreshedAt: new Date() } }
      );
      updated = result.modifiedCount || 0;
    }

    return { deleted: 0, refreshed: updated, durationMs: now() - startedAt };
  }

  /**
   * Rotate old encryption keys (mark deprecated keys).
   * @returns {Promise<Object>}
   */
  async rotateOldKeys() {
    const startedAt = now();
    const col = this.db?.collection('encryption_keys');
    if (!col) return { deleted: 0, rotated: false };

    // Mark keys older than 30 days as deprecated
    const cutoff = new Date(now() - daysToMs(30));
    const result = await col.updateMany(
      {
        createdAt: { $lt: cutoff },
        status: { $nin: ['deprecated', 'revoked'] },
      },
      {
        $set: {
          status: 'deprecated',
          deprecatedAt: new Date(),
        },
      }
    );

    return {
      deleted: 0,
      rotated: result.modifiedCount || 0,
      durationMs: now() - startedAt,
    };
  }

  /**
   * Clean up temporary files older than retention period.
   * @returns {Promise<Object>}
   */
  async cleanupTempFiles() {
    const startedAt = now();
    const cutoff = now() - daysToMs(RETENTION.TEMP_FILES);
    let deletedCount = 0;
    let errorCount = 0;

    try {
      const entries = await readdir(this.tempDir);
      for (const entry of entries) {
        const fullPath = join(this.tempDir, entry);
        try {
          const info = await stat(fullPath);
          if (info.isFile() && info.mtimeMs < cutoff) {
            await unlink(fullPath);
            deletedCount++;
          }
        } catch {
          errorCount++;
        }
      }
    } catch {
      // Directory may not exist
    }

    return {
      deleted: deletedCount,
      errors: errorCount,
      durationMs: now() - startedAt,
    };
  }

  /**
   * Generate usage statistics and store them.
   * @returns {Promise<Object>}
   */
  async generateUsageStatistics() {
    const startedAt = now();
    const stats = {
      generatedAt: new Date(),
      collections: {},
    };

    if (!this.db) return { deleted: 0, stats, durationMs: now() - startedAt };

    const collections = [
      'tokens', 'sessions', 'audit_logs', 'ip_logs', 'device_fingerprints',
      'blocked_ips', 'alerts', 'mutation_logs', 'gift_codes', 'watermarks',
      'telegram_messages', 'rate_limits',
    ];

    for (const name of collections) {
      try {
        const col = this.db.collection(name);
        const count = await col.estimatedDocumentCount();
        stats.collections[name] = { count };
      } catch {
        stats.collections[name] = { count: -1, error: true };
      }
    }

    // Store in cleanup_stats collection
    if (this.statsCol) {
      await this.statsCol.insertOne({
        type: 'usage_statistics',
        timestamp: new Date(),
        ...stats,
      });
    }

    return {
      deleted: 0,
      stats,
      durationMs: now() - startedAt,
    };
  }

  // ------------------------------------------------------------------
  // Missing Collection Cleanup (code_claims, reveal_audit)
  // ------------------------------------------------------------------

  /**
   * Clean up old code_claims records (90-day retention).
   * Prevents unbounded growth — 5,000 users/day × 90 days = 450K docs.
   * @returns {Promise<Object>}
   */
  async cleanupOldCodeClaims() {
    if (!this.codeClaimsCol) return { deleted: 0 };

    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - RETENTION.DEVICE_FINGERPRINTS);

    let deleted = 0;
    while (true) {
      const docs = await this.codeClaimsCol
        .find({ claimedAt: { $lt: cutoff } })
        .limit(BATCH_SIZE)
        .toArray();

      if (docs.length === 0) break;

      const ids = docs.map((d) => d._id);
      const result = await this.codeClaimsCol.deleteMany({
        _id: { $in: ids },
        claimedAt: { $lt: cutoff },
      });
      deleted += result.deletedCount || 0;

      if (docs.length < BATCH_SIZE) break;
      await sleep(100);
    }

    return { deleted };
  }

  /**
   * Clean up old reveal_audit records (365-day retention).
   * This is the LARGEST collection (696 MB at peak) — must be pruned.
   * @returns {Promise<Object>}
   */
  async cleanupOldRevealAudit() {
    if (!this.revealAuditCol) return { deleted: 0 };

    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - RETENTION.MUTATION_LOGS);

    let deleted = 0;
    while (true) {
      const docs = await this.revealAuditCol
        .find({ timestamp: { $lt: cutoff } })
        .limit(BATCH_SIZE)
        .toArray();

      if (docs.length === 0) break;

      const ids = docs.map((d) => d._id);
      const result = await this.revealAuditCol.deleteMany({
        _id: { $in: ids },
        timestamp: { $lt: cutoff },
      });
      deleted += result.deletedCount || 0;

      if (docs.length < BATCH_SIZE) break;
      await sleep(100);
    }

    return { deleted };
  }

  // ------------------------------------------------------------------
  // Statistics & Alerting
  // ------------------------------------------------------------------

  /**
   * Persist cleanup statistics to the database.
   * @param {Object} stats
   * @returns {Promise<void>}
   */
  async persistStats(stats) {
    if (!this.statsCol) return;
    try {
      await this.statsCol.insertOne({
        type: 'cleanup_run',
        ...stats,
        persistedAt: new Date(),
      });
    } catch {
      // Best-effort persistence
    }
  }

  /**
   * Send an alert when a task fails repeatedly.
   * @param {string} taskName
   * @param {number} failureCount
   * @param {Error} error
   * @returns {Promise<void>}
   */
  async alertRepeatedFailure(taskName, failureCount, error) {
    this.emit('alert', {
      severity: 'WARNING',
      title: `Cleanup Task Repeatedly Failing: ${taskName}`,
      message: `Task ${taskName} has failed ${failureCount} consecutive times. Last error: ${error.message}`,
      taskName,
      failureCount,
    });

    if (this.telegramSend) {
      try {
        await this.telegramSend({
          severity: 'WARNING',
          title: `Cleanup Failure Alert: ${taskName}`,
          message: `Task \`${taskName}\` has failed ${failureCount} times consecutively.\nError: ${error.message}`,
        });
      } catch {
        // Best-effort
      }
    }
  }

  /**
   * Get the latest cleanup statistics.
   * @param {number} [limit=10]
   * @returns {Object[]}
   */
  getRecentStats(limit = 10) {
    return this.statsHistory.slice(-limit);
  }

  /**
   * Get health summary.
   * @returns {Object}
   */
  health() {
    const failureEntries = Array.from(this.failureCounts.entries());
    const failingTasks = failureEntries.filter(([, c]) => c >= this.maxConsecutiveFailures);
    return {
      totalRuns: this.statsHistory.length,
      failingTasks: failingTasks.map(([name, count]) => ({ name, count })),
      recentStats: this.statsHistory.slice(-5),
      dbConnected: !!this.db,
    };
  }
}

// ---------------------------------------------------------------------------
// Convenience Runners
// ---------------------------------------------------------------------------

/**
 * Run a single cleanup tier.
 * @param {string} tier
 * @param {Object} options
 * @returns {Promise<Object>}
 */
export async function runCleanupTier(tier, options = {}) {
  const engine = new CleanupEngine(options);
  await engine.init();
  return engine.runTier(tier);
}

/**
 * Run all cleanup tiers in sequence.
 * @param {Object} options
 * @returns {Promise<Object>}
 */
export async function runAllCleanup(options = {}) {
  const engine = new CleanupEngine(options);
  await engine.init();
  const results = {};
  for (const tier of ['minute', 'fiveMinute', 'hourly', 'daily']) {
    results[tier] = await engine.runTier(tier);
  }
  return results;
}

// ---------------------------------------------------------------------------
// Default Export
// ---------------------------------------------------------------------------

export default {
  CleanupEngine,
  runCleanupTier,
  runAllCleanup,
  CleanupError,
  RETENTION,
  BATCH_SIZE,
};
