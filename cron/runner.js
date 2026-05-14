/**
 * @fileoverview Central Cron Runner for Osm Army Gift Code Fortress.
 * Coordinates all scheduled tasks: daily mutation, multi-tier cleanup,
 * health checks, and system monitoring. Uses native Node.js timers for
 * scheduling (no external cron library) to maximise control and minimise
 * attack surface.
 *
 * Schedules:
 *   - Daily Mutation:    00:00:01 UTC (cron/mutate.js)
 *   - Cleanup Minute:    every 60 seconds (cron/cleanup.js)
 *   - Cleanup 5-Minute:  every 300 seconds
 *   - Cleanup Hourly:    every 3600 seconds
 *   - Cleanup Daily:     01:00 UTC
 *   - Health Check:      every 30 seconds
 *   - Stats Report:      every 6 hours
 *
 * Lifecycle:
 *   - start():   register all schedules
 *   - stop():    cancel all timers gracefully
 *   - status():  report active schedules and health
 *
 * @module cron/runner
 * @version 5.0.0
 */

'use strict';

import { EventEmitter } from 'node:events';
import { DailyMutationEngine, MUTATION_CRON_EXPR } from './mutate.js';
import { CleanupEngine } from './cleanup.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Cron schedule definitions. */
const SCHEDULES = Object.freeze({
  MUTATION:          { hour: 0, minute: 0, second: 1 },     // 00:00:01 UTC
  CLEANUP_DAILY:     { hour: 1, minute: 0, second: 0 },     // 01:00:00 UTC
  STATS_REPORT:      { hour: '*/6', minute: 0, second: 0 },  // every 6 hours
});

const MS_PER_SECOND = 1000;
const MS_PER_MINUTE = 60_000;
const MS_PER_HOUR   = 3_600_000;
const MS_PER_DAY    = 86_400_000;

// ---------------------------------------------------------------------------
// Custom Errors
// ---------------------------------------------------------------------------

export class CronRunnerError extends Error {
  constructor(message, code, extra = {}) {
    super(message);
    this.name = 'CronRunnerError';
    this.code = code;
    Object.assign(this, extra);
    Error.captureStackTrace(this, this.constructor);
  }
}

// ---------------------------------------------------------------------------
// Utility Functions
// ---------------------------------------------------------------------------

/**
 * Current UTC time components.
 * @returns {{hour:number,minute:number,second:number,ms:number}}
 */
function utcNow() {
  const d = new Date();
  return {
    hour:   d.getUTCHours(),
    minute: d.getUTCMinutes(),
    second: d.getUTCSeconds(),
    ms:     d.getUTCMilliseconds(),
  };
}

/**
 * Current UTC timestamp in ms.
 * @returns {number}
 */
function nowMs() {
  return Date.now();
}

/**
 * Calculate ms until a specific wall-clock time.
 * @param {number} targetHour UTC hour (0-23)
 * @param {number} targetMinute UTC minute (0-59)
 * @param {number} targetSecond UTC second (0-59)
 * @returns {number} Milliseconds until the target time
 */
function msUntilTime(targetHour, targetMinute, targetSecond) {
  const d = new Date();
  d.setUTCHours(targetHour, targetMinute, targetSecond, 0);
  const target = d.getTime();
  const now = Date.now();
  if (target <= now) {
    // Target already passed today: schedule for tomorrow
    return target + MS_PER_DAY - now;
  }
  return target - now;
}

/**
 * Calculate ms until next interval boundary.
 * @param {number} intervalMs
 * @returns {number}
 */
function msUntilNextInterval(intervalMs) {
  return intervalMs - (Date.now() % intervalMs);
}

/**
 * Sleep for N milliseconds.
 * @param {number} ms
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// ---------------------------------------------------------------------------
// Job Wrapper (handles errors, logging, timeout)
// ---------------------------------------------------------------------------

/**
 * Wrap an async job function with error handling, timeout, and logging.
 * @param {string} jobName
 * @param {Function} fn
 * @param {number} timeoutMs
 * @returns {Function}
 */
function wrapJob(jobName, fn, timeoutMs = 300_000) {
  return async function wrappedJob(context = {}) {
    const startedAt = nowMs();
    const jobId = `${jobName}_${startedAt}_${Math.floor(Math.random() * 10000)}`;

    context.emitter?.emit('job_start', { jobName, jobId, startedAt: new Date(startedAt).toISOString() });

    try {
      // Race against timeout
      const result = await Promise.race([
        fn(),
        new Promise((_, reject) =>
          setTimeout(() => reject(new CronRunnerError(
            `Job ${jobName} timed out after ${timeoutMs}ms`,
            'JOB_TIMEOUT'
          )), timeoutMs)
        ),
      ]);

      const durationMs = nowMs() - startedAt;
      context.emitter?.emit('job_success', {
        jobName,
        jobId,
        durationMs,
        result: result && typeof result === 'object'
          ? { success: result.success, deleted: result.deleted, version: result.version }
          : result,
      });

      return result;
    } catch (err) {
      const durationMs = nowMs() - startedAt;
      context.emitter?.emit('job_error', {
        jobName,
        jobId,
        durationMs,
        error: err.message,
        code: err.code || 'UNKNOWN',
      });

      // Attempt to alert via Telegram if configured
      if (context.telegramSend) {
        try {
          await context.telegramSend({
            severity: 'WARNING',
            title: `Cron Job Failed: ${jobName}`,
            message: `Job \`${jobName}\` (id: \`${jobId}\`) failed after ${durationMs}ms.\nError: ${err.message}`,
          });
        } catch {
          // Alert failure is non-critical
        }
      }

      return { success: false, error: err.message, code: err.code || 'UNKNOWN', jobName };
    }
  };
}

// ---------------------------------------------------------------------------
// Cron Runner
// ---------------------------------------------------------------------------

/**
 * CronRunner manages all scheduled jobs, their timers, and lifecycle.
 */
export class CronRunner extends EventEmitter {
  /**
   * @param {Object} options
   * @param {Object|null} options.db MongoDB database instance
   * @param {Function|null} options.telegramSend Async function for alerts
   * @param {string} [options.serverSecret]
   * @param {Function|null} options.cacheClear Callback to clear caches
   * @param {Function|null} options.keyRotate Callback to rotate keys
   * @param {Function|null} options.ipRefresh Callback to refresh IP lists
   * @param {boolean} [options.runMutation=true]
   * @param {boolean} [options.runCleanup=true]
   * @param {boolean} [options.runHealthChecks=true]
   */
  constructor(options = {}) {
    super();
    this.db = options.db || null;
    this.telegramSend = options.telegramSend || null;
    this.serverSecret = options.serverSecret || process.env.SERVER_SECRET || '';
    this.cacheClear = options.cacheClear || null;
    this.keyRotate = options.keyRotate || null;
    this.ipRefresh = options.ipRefresh || null;

    this.runMutation = options.runMutation !== false;
    this.runCleanup = options.runCleanup !== false;
    this.runHealthChecks = options.runHealthChecks !== false;

    // Engine instances
    /** @type {DailyMutationEngine|null} */
    this.mutationEngine = null;
    /** @type {CleanupEngine|null} */
    this.cleanupEngine = null;

    // Active timers
    /** @type {Map<string, NodeJS.Timeout>} */
    this.timers = new Map();

    // Execution history
    /** @type {Array<Object>} */
    this.history = [];
    /** @type {number} */
    this.maxHistory = 1000;

    // State
    this.started = false;
    this.startTime = null;
    this.jobsExecuted = 0;
    this.jobsFailed = 0;
  }

  // ------------------------------------------------------------------
  // Lifecycle
  // ------------------------------------------------------------------

  /**
   * Start all scheduled jobs.
   * @returns {Promise<void>}
   */
  async start() {
    if (this.started) {
      throw new CronRunnerError('CronRunner is already started', 'ALREADY_STARTED');
    }

    this.startTime = nowMs();
    this.started = true;

    // Initialise engines
    if (this.runMutation) {
      this.mutationEngine = new DailyMutationEngine({
        db: this.db,
        serverSecret: this.serverSecret,
        telegramSend: this.telegramSend,
        cacheClear: this.cacheClear,
        keyRotate: this.keyRotate,
        ipRefresh: this.ipRefresh,
      });
      await this.mutationEngine.init();
    }

    if (this.runCleanup) {
      this.cleanupEngine = new CleanupEngine({
        db: this.db,
        telegramSend: this.telegramSend,
      });
      await this.cleanupEngine.init();
    }

    // Register schedules
    this._scheduleDailyMutation();
    this._scheduleCleanupMinute();
    this._scheduleCleanupFiveMinute();
    this._scheduleCleanupHourly();
    this._scheduleCleanupDaily();
    this._scheduleHealthCheck();
    this._scheduleStatsReport();

    this.emit('started', {
      schedules: Array.from(this.timers.keys()),
      startedAt: new Date().toISOString(),
    });
  }

  /**
   * Stop all timers and clean up.
   * @returns {Promise<void>}
   */
  async stop() {
    this.emit('stopping');

    for (const [name, timer] of this.timers) {
      clearTimeout(timer);
      this.timers.delete(name);
    }

    // Cancel any in-flight jobs by emitting stop signal
    this.started = false;

    this.emit('stopped', {
      uptimeMs: this.startTime ? nowMs() - this.startTime : 0,
      jobsExecuted: this.jobsExecuted,
      jobsFailed: this.jobsFailed,
    });
  }

  // ------------------------------------------------------------------
  // Schedule Registration
  // ------------------------------------------------------------------

  /**
   * Schedule the daily mutation job (00:00:01 UTC).
   * @private
   */
  _scheduleDailyMutation() {
    if (!this.runMutation) return;
    const name = 'daily_mutation';

    const scheduleNext = () => {
      const delay = msUntilTime(
        SCHEDULES.MUTATION.hour,
        SCHEDULES.MUTATION.minute,
        SCHEDULES.MUTATION.second
      );

      const timer = setTimeout(async () => {
        if (!this.started) return;
        const result = await wrapJob(name, () => this.mutationEngine.run(), 600_000)({
          emitter: this,
          telegramSend: this.telegramSend,
        });
        this._recordResult(name, result);
        // Schedule next occurrence
        scheduleNext();
      }, delay);

      this._registerTimer(name, timer);
    };

    scheduleNext();
  }

  /**
   * Schedule cleanup minute tier (every 60 seconds).
   * @private
   */
  _scheduleCleanupMinute() {
    if (!this.runCleanup) return;
    const name = 'cleanup_minute';
    const interval = MS_PER_MINUTE;

    const scheduleNext = () => {
      const delay = msUntilNextInterval(interval);
      const timer = setTimeout(async () => {
        if (!this.started) return;
        const result = await wrapJob(
          name,
          () => this.cleanupEngine.runTier('minute'),
          120_000
        )({ emitter: this, telegramSend: this.telegramSend });
        this._recordResult(name, result);
        scheduleNext();
      }, delay);

      this._registerTimer(name, timer);
    };

    scheduleNext();
  }

  /**
   * Schedule cleanup five-minute tier (every 300 seconds).
   * @private
   */
  _scheduleCleanupFiveMinute() {
    if (!this.runCleanup) return;
    const name = 'cleanup_five_minute';
    const interval = 5 * MS_PER_MINUTE;

    const scheduleNext = () => {
      const delay = msUntilNextInterval(interval);
      const timer = setTimeout(async () => {
        if (!this.started) return;
        const result = await wrapJob(
          name,
          () => this.cleanupEngine.runTier('fiveMinute'),
          180_000
        )({ emitter: this, telegramSend: this.telegramSend });
        this._recordResult(name, result);
        scheduleNext();
      }, delay);

      this._registerTimer(name, timer);
    };

    scheduleNext();
  }

  /**
   * Schedule cleanup hourly tier (every 3600 seconds).
   * @private
   */
  _scheduleCleanupHourly() {
    if (!this.runCleanup) return;
    const name = 'cleanup_hourly';
    const interval = MS_PER_HOUR;

    const scheduleNext = () => {
      const delay = msUntilNextInterval(interval);
      const timer = setTimeout(async () => {
        if (!this.started) return;
        const result = await wrapJob(
          name,
          () => this.cleanupEngine.runTier('hourly'),
          300_000
        )({ emitter: this, telegramSend: this.telegramSend });
        this._recordResult(name, result);
        scheduleNext();
      }, delay);

      this._registerTimer(name, timer);
    };

    scheduleNext();
  }

  /**
   * Schedule cleanup daily tier (01:00 UTC).
   * @private
   */
  _scheduleCleanupDaily() {
    if (!this.runCleanup) return;
    const name = 'cleanup_daily';

    const scheduleNext = () => {
      const delay = msUntilTime(
        SCHEDULES.CLEANUP_DAILY.hour,
        SCHEDULES.CLEANUP_DAILY.minute,
        SCHEDULES.CLEANUP_DAILY.second
      );

      const timer = setTimeout(async () => {
        if (!this.started) return;
        const result = await wrapJob(
          name,
          () => this.cleanupEngine.runTier('daily'),
          600_000
        )({ emitter: this, telegramSend: this.telegramSend });
        this._recordResult(name, result);
        scheduleNext();
      }, delay);

      this._registerTimer(name, timer);
    };

    scheduleNext();
  }

  /**
   * Schedule health check (every 30 seconds).
   * @private
   */
  _scheduleHealthCheck() {
    if (!this.runHealthChecks) return;
    const name = 'health_check';
    const interval = 30_000;

    const scheduleNext = () => {
      const delay = msUntilNextInterval(interval);
      const timer = setTimeout(async () => {
        if (!this.started) return;
        const result = await wrapJob(
          name,
          () => this._runHealthCheck(),
          30_000
        )({ emitter: this, telegramSend: this.telegramSend });
        this._recordResult(name, result);
        scheduleNext();
      }, delay);

      this._registerTimer(name, timer);
    };

    scheduleNext();
  }

  /**
   * Schedule stats report (every 6 hours).
   * @private
   */
  _scheduleStatsReport() {
    const name = 'stats_report';
    const interval = 6 * MS_PER_HOUR;

    const scheduleNext = () => {
      const delay = msUntilNextInterval(interval);
      const timer = setTimeout(async () => {
        if (!this.started) return;
        const result = await wrapJob(
          name,
          () => this._runStatsReport(),
          60_000
        )({ emitter: this, telegramSend: this.telegramSend });
        this._recordResult(name, result);
        scheduleNext();
      }, delay);

      this._registerTimer(name, timer);
    };

    scheduleNext();
  }

  // ------------------------------------------------------------------
  // Timer Registry
  // ------------------------------------------------------------------

  /**
   * Register a named timer, replacing any existing one.
   * @param {string} name
   * @param {NodeJS.Timeout} timer
   * @private
   */
  _registerTimer(name, timer) {
    const existing = this.timers.get(name);
    if (existing) clearTimeout(existing);
    this.timers.set(name, timer);
  }

  // ------------------------------------------------------------------
  // Job Implementations
  // ------------------------------------------------------------------

  /**
   * Run a system health check across all subsystems.
   * @returns {Promise<Object>}
   * @private
   */
  async _runHealthCheck() {
    const checks = {
      mutationEngine: false,
      cleanupEngine: false,
      database: false,
      memoryUsage: 0,
      uptime: Math.floor((nowMs() - (this.startTime || nowMs())) / 1000),
    };

    if (this.mutationEngine) {
      const h = this.mutationEngine.health();
      checks.mutationEngine = h.hasProfile || h.serverSecretConfigured;
    }
    if (this.cleanupEngine) {
      const h = this.cleanupEngine.health();
      checks.cleanupEngine = h.dbConnected;
    }
    if (this.db) {
      try {
        await this.db.admin().ping();
        checks.database = true;
      } catch {
        checks.database = false;
      }
    }

    const mem = process.memoryUsage();
    checks.memoryUsage = {
      rss: mem.rss,
      heapTotal: mem.heapTotal,
      heapUsed: mem.heapUsed,
      external: mem.external,
    };

    const allHealthy = checks.mutationEngine && checks.cleanupEngine && checks.database;
    this.emit('health_check', { healthy: allHealthy, ...checks });

    if (!allHealthy && this.telegramSend) {
      await this.telegramSend({
        severity: 'WARNING',
        title: 'Health Check Alert',
        message: `System health check detected issues.\nMutation: ${checks.mutationEngine}\nCleanup: ${checks.cleanupEngine}\nDB: ${checks.database}`,
      });
    }

    return { success: allHealthy, checks };
  }

  /**
   * Run a periodic stats report.
   * @returns {Promise<Object>}
   * @private
   */
  async _runStatsReport() {
    const stats = {
      timestamp: new Date().toISOString(),
      uptime: Math.floor((nowMs() - (this.startTime || nowMs())) / 1000),
      jobsExecuted: this.jobsExecuted,
      jobsFailed: this.jobsFailed,
      activeTimers: this.timers.size,
      schedules: Array.from(this.timers.keys()),
      mutationEngine: this.mutationEngine ? this.mutationEngine.health() : null,
      cleanupEngine: this.cleanupEngine ? this.cleanupEngine.health() : null,
      memoryUsage: process.memoryUsage(),
    };

    this.emit('stats_report', stats);

    if (this.telegramSend) {
      await this.telegramSend({
        severity: 'INFO',
        title: 'Fortress Stats Report',
        message: `Uptime: ${stats.uptime}s | Jobs: ${stats.jobsExecuted} OK / ${stats.jobsFailed} failed | Timers: ${stats.activeTimers}`,
      });
    }

    return { success: true, stats };
  }

  // ------------------------------------------------------------------
  // Result Tracking
  // ------------------------------------------------------------------

  /**
   * Record a job execution result.
   * @param {string} jobName
   * @param {Object} result
   * @private
   */
  _recordResult(jobName, result) {
    this.jobsExecuted++;
    if (!result.success) this.jobsFailed++;

    this.history.push({
      jobName,
      success: result.success || false,
      timestamp: new Date().toISOString(),
      error: result.error || null,
      version: result.version || null,
      deleted: result.deleted || null,
    });

    if (this.history.length > this.maxHistory) {
      this.history = this.history.slice(-this.maxHistory / 2);
    }
  }

  // ------------------------------------------------------------------
  // Public Status & Health
  // ------------------------------------------------------------------

  /**
   * Get the current runner status.
   * @returns {Object}
   */
  status() {
    const recent = this.history.slice(-20);
    return {
      started: this.started,
      uptime: this.startTime ? Math.floor((nowMs() - this.startTime) / 1000) : 0,
      activeSchedules: Array.from(this.timers.keys()),
      jobsExecuted: this.jobsExecuted,
      jobsFailed: this.jobsFailed,
      recentExecutions: recent,
      mutationEngine: this.mutationEngine ? this.mutationEngine.health() : null,
      cleanupEngine: this.cleanupEngine ? this.cleanupEngine.health() : null,
    };
  }

  /**
   * Get the last N execution results.
   * @param {number} [n=20]
   * @returns {Object[]}
   */
  getHistory(n = 20) {
    return this.history.slice(-n);
  }

  /**
   * Trigger a job manually by name.
   * @param {string} jobName
   * @returns {Promise<Object>}
   */
  async triggerJob(jobName) {
    const jobMap = {
      daily_mutation:       () => this.mutationEngine?.run(),
      cleanup_minute:       () => this.cleanupEngine?.runTier('minute'),
      cleanup_five_minute:  () => this.cleanupEngine?.runTier('fiveMinute'),
      cleanup_hourly:       () => this.cleanupEngine?.runTier('hourly'),
      cleanup_daily:        () => this.cleanupEngine?.runTier('daily'),
      health_check:         () => this._runHealthCheck(),
      stats_report:         () => this._runStatsReport(),
    };

    const fn = jobMap[jobName];
    if (!fn) {
      throw new CronRunnerError(`Unknown job: ${jobName}`, 'UNKNOWN_JOB');
    }

    return wrapJob(jobName, fn, 600_000)({
      emitter: this,
      telegramSend: this.telegramSend,
    });
  }
}

// ---------------------------------------------------------------------------
// Singleton Factory
// ---------------------------------------------------------------------------

/** @type {CronRunner|null} */
let singletonRunner = null;

/**
 * Create and start the CronRunner singleton.
 * @param {Object} options
 * @returns {Promise<CronRunner>}
 */
export async function startCronRunner(options = {}) {
  if (singletonRunner) {
    await singletonRunner.stop();
  }
  singletonRunner = new CronRunner(options);
  await singletonRunner.start();
  return singletonRunner;
}

/**
 * Stop the singleton runner.
 * @returns {Promise<void>}
 */
export async function stopCronRunner() {
  if (singletonRunner) {
    await singletonRunner.stop();
    singletonRunner = null;
  }
}

/**
 * Get the current singleton instance (null if not started).
 * @returns {CronRunner|null}
 */
export function getCronRunner() {
  return singletonRunner;
}

// ---------------------------------------------------------------------------
// Default Export
// ---------------------------------------------------------------------------

export default {
  CronRunner,
  startCronRunner,
  stopCronRunner,
  getCronRunner,
  CronRunnerError,
};
