

// ============================================================================
// Enums
// ============================================================================

const Severity = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', INFO: 'info' };
const AutoAction = { BLOCK: 'block', THROTTLE: 'throttle', ALERT_ONLY: 'alert_only', KILL_SWITCH: 'kill_switch' };
const CHANNELS = { CRITICAL: 'critical', SECURITY: 'security', ALL: 'all' };

// ============================================================================
// Emoji Map for Severity Levels
// ============================================================================

const SEVERITY_EMOJIS = {
  [Severity.CRITICAL]: '\u{1F6A8}', // 🚨
  [Severity.HIGH]: '\u{26A0}\u{FE0F}', // ⚠️
  [Severity.MEDIUM]: '\u{1F7E1}', // 🟡
  [Severity.LOW]: '\u{1F535}', // 🔵
  [Severity.INFO]: '\u{1F7E2}'  // 🟢
};

const ACTION_EMOJIS = {
  [AutoAction.BLOCK]: '\u{1F6AB}', // 🚫
  [AutoAction.THROTTLE]: '\u{1F40C}', // 🐌
  [AutoAction.ALERT_ONLY]: '\u{1F4E2}', // 📢
  [AutoAction.KILL_SWITCH]: '\u{2620}\u{FE0F}'  // ☠️
};

// ============================================================================
// AlertManager Class
// ============================================================================

/**
 * Manages 500 alert types and sends instant Telegram notifications.
 * Implements rate limiting, escalation rules, cooldowns, and whitelists.
 *
 * @class
 */
export class AlertManager {
  /**
   * @param {Object} [options] - Configuration
   * @param {string} [options.botToken] - Telegram bot token
   * @param {Object} [options.channels] - Channel overrides
   * @param {Object} [options.db] - Database connection
   */
  constructor(options = {}) {
    this.botToken = options.botToken || process.env.FORTRESS_TELEGRAM_BOT_TOKEN || '';
    this.channels = {
      critical: options.channels?.critical || CHANNELS.CRITICAL,
      security: options.channels?.security || CHANNELS.SECURITY,
      all: options.channels?.all || CHANNELS.ALL
    };
    this.db = options.db || null;

    // Load all 500 alert types
    this.alertTypes = createAlertTypes();

    // Rate limiting per channel
    this.rateLimits = new Map();
    this.rateLimits.set(this.channels.critical, { count: 0, windowStart: 0 });
    this.rateLimits.set(this.channels.security, { count: 0, windowStart: 0 });
    this.rateLimits.set(this.channels.all, { count: 0, windowStart: 0 });

    // Cooldown tracking: alertId -> lastFiredTimestamp
    this.cooldowns = new Map();

    // Escalation tracking: alertId -> { count, firstSeen, lastSeen }
    this.escalations = new Map();

    // IP whitelist for suppression
    this.ipWhitelist = new Set(options.ipWhitelist || []);

    // Message queue for retry
    this.messageQueue = [];
    this.isProcessingQueue = false;

    // Alert history
    this.history = [];
    this.maxHistory = 10000;
  }

  /**
   * Initialise the alert manager.
   * @returns {Promise<void>}
   */
  async init() {
    // AlertManager is ready immediately; DB persistence is on-demand.
  }

  /**
   * Alias for init().
   * @param {...*} args
   * @returns {Promise<void>}
   */
  initialize(...args) { return this.init(...args); }

  /**
   * Send an alert by name (alias for triggerByName).
   * @param {string} name - Alert name
   * @param {Object} [context] - Additional context
   * @returns {Promise<{sent: boolean, alert: Object|null, error: string|null}>}
   */
  async send(name, context = {}) {
    return this.triggerByName(name, context);
  }

  // --------------------------------------------------------------------------
  // Core Alert Methods
  // --------------------------------------------------------------------------

  /**
   * Trigger an alert by ID.
   * @param {number} alertId - Alert type ID (1-500)
   * @param {Object} [context] - Additional context data
   * @param {string} [context.ip] - Source IP
   * @param {string} [context.userId] - User ID
   * @param {string} [context.sessionId] - Session ID
   * @param {string} [context.details] - Additional details
   * @param {string} [context.fingerprint] - Device fingerprint
   * @returns {Promise<{sent: boolean, alert: Object|null, error: string|null}>}
   */
  async trigger(alertId, context = {}) {
    const type = this.alertTypes[alertId];
    if (!type) {
      return { sent: false, alert: null, error: `Unknown alert ID: ${alertId}` };
    }

    // Check IP whitelist
    if (context.ip && this.ipWhitelist.has(context.ip)) {
      return { sent: false, alert: null, error: 'IP whitelisted' };
    }

    // Check cooldown
    if (this._isOnCooldown(alertId, type.cooldown)) {
      return { sent: false, alert: null, error: 'Alert on cooldown' };
    }

    // Build alert record
    const alert = this._buildAlert(type, context);

    // Check escalation
    const escalation = this._checkEscalation(alertId);
    if (escalation.escalated) {
      alert.severity = this._escalateSeverity(alert.severity);
      alert.escalation = escalation;
    }

    // Persist to DB
    if (this.db) {
      await this._persistAlert(alert).catch(() => {});
    }

    // Queue for Telegram
    const channels = this._getTargetChannels(alert.severity);
    for (const channelId of channels) {
      this._queueMessage(channelId, alert);
    }

    // Update cooldown and escalation
    this._updateCooldown(alertId);
    this._updateEscalation(alertId);

    // Add to history
    this._addToHistory(alert);

    // Process queue
    this._processQueue().catch(() => {});

    return { sent: true, alert, error: null };
  }

  /**
   * Trigger an alert by name.
   * @param {string} name - Alert name (e.g., 'SUSPICIOUS_IP')
   * @param {Object} [context] - Additional context
   * @returns {Promise<{sent: boolean, alert: Object|null, error: string|null}>}
   */
  async triggerByName(name, context = {}) {
    const entry = Object.values(this.alertTypes).find(a => a.name === name);
    if (!entry) {
      return { sent: false, alert: null, error: `Unknown alert name: ${name}` };
    }
    return this.trigger(entry.id, context);
  }

  /**
   * Trigger multiple alerts at once.
   * @param {number[]} alertIds - Array of alert IDs
   * @param {Object} [context] - Shared context
   * @returns {Promise<Object[]>} Results for each alert
   */
  async triggerMultiple(alertIds, context = {}) {
    const results = [];
    for (const id of alertIds) {
      const result = await this.trigger(id, context);
      results.push(result);
    }
    return results;
  }

  // --------------------------------------------------------------------------
  // Alert Building
  // --------------------------------------------------------------------------

  /**
   * Build a complete alert record.
   * @private
   */
  _buildAlert(type, context) {
    return {
      id: `${type.name}-${Date.now()}-${randomBytes(4).toString('hex')}`,
      typeId: type.id,
      name: type.name,
      description: type.desc,
      severity: type.severity,
      autoAction: type.action,
      context: {
        ip: context.ip || 'unknown',
        userId: context.userId || null,
        sessionId: context.sessionId || null,
        details: context.details || '',
        fingerprint: context.fingerprint || null,
        userAgent: context.userAgent || '',
        path: context.path || '',
        method: context.method || '',
        timestamp: new Date().toISOString()
      },
      firedAt: new Date().toISOString(),
      channel: this._getPrimaryChannel(type.severity)
    };
  }

  /**
   * Get primary channel for a severity level.
   * @private
   */
  _getPrimaryChannel(severity) {
    if (severity === Severity.CRITICAL) return this.channels.critical;
    if (severity === Severity.HIGH) return this.channels.security;
    return this.channels.all;
  }

  /**
   * Get all target channels for a severity.
   * Critical goes to all 3 channels.
   * High goes to security + all.
   * Others go to all channel only.
   * @private
   */
  _getTargetChannels(severity) {
    const targets = [];
    if (severity === Severity.CRITICAL) {
      targets.push(this.channels.critical, this.channels.security, this.channels.all);
    } else if (severity === Severity.HIGH) {
      targets.push(this.channels.security, this.channels.all);
    } else {
      targets.push(this.channels.all);
    }
    return [...new Set(targets)];
  }

  // --------------------------------------------------------------------------
  // Cooldown & Escalation
  // --------------------------------------------------------------------------

  /**
   * Check if alert is on cooldown.
   * @private
   */
  _isOnCooldown(alertId, cooldownSeconds) {
    if (cooldownSeconds <= 0) return false;
    const lastFired = this.cooldowns.get(alertId);
    if (!lastFired) return false;
    return (Date.now() - lastFired) < cooldownSeconds * 1000;
  }

  /**
   * Update cooldown for an alert.
   * @private
   */
  _updateCooldown(alertId) {
    this.cooldowns.set(alertId, Date.now());
  }

  /**
   * Check and update escalation state.
   * @private
   */
  _checkEscalation(alertId) {
    const state = this.escalations.get(alertId) || { count: 0, firstSeen: Date.now(), lastSeen: 0 };
    state.count++;
    state.lastSeen = Date.now();

    const timeWindow = 3600000; // 1 hour
    const isEscalated = state.count >= 5 && (state.lastSeen - state.firstSeen) < timeWindow;

    return {
      escalated: isEscalated,
      repeatCount: state.count,
      firstSeen: state.firstSeen,
      lastSeen: state.lastSeen
    };
  }

  /**
   * Update escalation tracking.
   * @private
   */
  _updateEscalation(alertId) {
    const existing = this.escalations.get(alertId);
    if (existing) {
      existing.count++;
      existing.lastSeen = Date.now();
    } else {
      this.escalations.set(alertId, { count: 1, firstSeen: Date.now(), lastSeen: Date.now() });
    }
  }

  /**
   * Escalate severity one level up.
   * @private
   */
  _escalateSeverity(current) {
    const order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL];
    const idx = order.indexOf(current);
    return idx < order.length - 1 ? order[idx + 1] : current;
  }

  // --------------------------------------------------------------------------
  // Telegram Integration
  // --------------------------------------------------------------------------

  /**
   * Queue a message for sending.
   * @private
   */
  _queueMessage(channelId, alert) {
    const text = this._formatTelegramMessage(alert);
    const keyboard = this._buildInlineKeyboard(alert);
    this.messageQueue.push({ channelId, text, keyboard, alert, retries: 0 });
  }

  /**
   * Format alert as Telegram message (Markdown).
   * @private
   */
  _formatTelegramMessage(alert) {
    const sevEmoji = SEVERITY_EMOJIS[alert.severity] || '\u{26AA}';
    const actEmoji = ACTION_EMOJIS[alert.autoAction] || '';

    let msg = `${sevEmoji} *${alert.name}*\n`;
    msg += `${actEmoji} *${alert.severity.toUpperCase()}* | Auto: ${alert.autoAction}\n`;
    msg += `\u{1F4DD} ${alert.description}\n\n`;

    if (alert.context.ip) msg += `\u{1F4BB} IP: \`${alert.context.ip}\`\n`;
    if (alert.context.userId) msg += `\u{1F464} User: \`${alert.context.userId}\`\n`;
    if (alert.context.sessionId) msg += `\u{1F510} Session: \`${alert.context.sessionId.slice(0, 16)}...\`\n`;
    if (alert.context.path) msg += `\u{1F4CE} Path: \`${alert.context.method} ${alert.context.path}\`\n`;
    if (alert.context.fingerprint) msg += `\u{1F5A9} FP: \`${alert.context.fingerprint.slice(0, 16)}...\`\n`;
    if (alert.context.userAgent) msg += `\u{1F4F1} UA: \`${alert.context.userAgent.slice(0, 60)}...\`\n`;
    if (alert.context.details) msg += `\n\u{1F4CB} Details: ${alert.context.details}\n`;

    if (alert.escalation?.escalated) {
      msg += `\n\u{23EB} *ESCALATED* (${alert.escalation.repeatCount}x repeats)\n`;
    }

    msg += `\n\u{1F551} ${alert.firedAt}`;
    msg += `\n\u{1F50E} ID: \`${alert.id.slice(0, 16)}\``;

    return msg;
  }

  /**
   * Build inline keyboard for quick actions.
   * @private
   */
  _buildInlineKeyboard(alert) {
    const buttons = [];

    if (alert.severity === Severity.CRITICAL || alert.severity === Severity.HIGH) {
      buttons.push([
        { text: '\u{1F6AB} Block IP', callback_data: `block:${alert.context.ip}` },
        { text: '\u{1F512} Revoke Session', callback_data: `revoke:${alert.context.sessionId}` }
      ]);
    }

    buttons.push([
      { text: '\u{1F4CB} Details', callback_data: `details:${alert.id}` },
      { text: '\u{2705} Ack', callback_data: `ack:${alert.id}` }
    ]);

    if (alert.severity === Severity.CRITICAL) {
      buttons.push([
        { text: '\u{2620}\u{FE0F} EMERGENCY SHUTDOWN', callback_data: `kill` }
      ]);
    }

    return { inline_keyboard: buttons };
  }

  /**
   * Process the message queue with rate limiting.
   * @private
   */
  async _processQueue() {
    if (this.isProcessingQueue) return;
    this.isProcessingQueue = true;

    while (this.messageQueue.length > 0) {
      const item = this.messageQueue[0];

      // Check rate limit
      if (!this._checkRateLimit(item.channelId)) {
        // Wait for rate limit window to reset
        await this._sleep(5000);
        continue;
      }

      // Send
      const sent = await this._sendTelegramMessage(item.channelId, item.text, item.keyboard);

      if (sent) {
        this._incrementRateLimit(item.channelId);
        this.messageQueue.shift(); // Remove from queue
      } else {
        item.retries++;
        if (item.retries >= MAX_RETRIES) {
          console.error(`Alert ${item.alert.name} failed after ${MAX_RETRIES} retries`);
          this.messageQueue.shift();
        } else {
          await this._sleep(RETRY_DELAY * item.retries);
          // Rotate to end of queue
          this.messageQueue.push(this.messageQueue.shift());
        }
      }
    }

    this.isProcessingQueue = false;
  }

  /**
   * Send a message via Telegram API.
   * @private
   */
  async _sendTelegramMessage(chatId, text, keyboard) {
    if (!this.botToken) {
      console.warn('Telegram bot token not configured, alert logged only');
      return true; // Don't retry
    }

    const payload = {
      chat_id: chatId,
      text,
      parse_mode: 'Markdown',
      reply_markup: keyboard
    };

    const body = JSON.stringify(payload);

    return new Promise((resolve) => {
      const options = {
        hostname: 'api.telegram.org',
        port: 443,
        path: `/bot${this.botToken}/sendMessage`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body)
        },
        timeout: 10000
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          try {
            const json = JSON.parse(data);
            resolve(json.ok === true);
          } catch {
            resolve(false);
          }
        });
      });

      req.on('error', () => resolve(false));
      req.on('timeout', () => { req.destroy(); resolve(false); });

      req.write(body);
      req.end();
    });
  }

  /**
   * Send a photo/document via Telegram.
   * @param {string} chatId - Target channel
   * @param {Buffer} file - File buffer
   * @param {string} caption - Caption text
   * @param {string} [filename='document.txt'] - File name
   * @returns {Promise<boolean>}
   */
  async sendDocument(chatId, file, caption, filename = 'document.txt') {
    if (!this.botToken) return false;

    const boundary = `----FormBoundary${randomBytes(8).toString('hex')}`;

    const parts = [];
    parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="chat_id"\r\n\r\n${chatId}\r\n`);
    parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="caption"\r\n\r\n${caption}\r\n`);
    parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="document"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`);

    const end = `\r\n--${boundary}--\r\n`;
    const body = Buffer.concat([
      Buffer.from(parts.join(''), 'utf8'),
      Buffer.isBuffer(file) ? file : Buffer.from(file, 'utf8'),
      Buffer.from(end, 'utf8')
    ]);

    return new Promise((resolve) => {
      const options = {
        hostname: 'api.telegram.org',
        port: 443,
        path: `/bot${this.botToken}/sendDocument`,
        method: 'POST',
        headers: {
          'Content-Type': `multipart/form-data; boundary=${boundary}`,
          'Content-Length': body.length
        },
        timeout: 15000
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          try {
            const json = JSON.parse(data);
            resolve(json.ok === true);
          } catch {
            resolve(false);
          }
        });
      });

      req.on('error', () => resolve(false));
      req.on('timeout', () => { req.destroy(); resolve(false); });

      req.write(body);
      req.end();
    });
  }

  // --------------------------------------------------------------------------
  // Rate Limiting
  // --------------------------------------------------------------------------

  /**
   * Check if a channel is within rate limits.
   * @private
   */
  _checkRateLimit(channelId) {
    const limit = this.rateLimits.get(channelId);
    if (!limit) return true;

    const now = Date.now();
    if (now - limit.windowStart > RATE_LIMIT_WINDOW) {
      limit.windowStart = now;
      limit.count = 0;
      return true;
    }

    return limit.count < RATE_LIMIT_MAX;
  }

  /**
   * Increment rate limit counter.
   * @private
   */
  _incrementRateLimit(channelId) {
    const limit = this.rateLimits.get(channelId);
    if (limit) limit.count++;
  }

  // --------------------------------------------------------------------------
  // IP Whitelist Management
  // --------------------------------------------------------------------------

  /**
   * Add an IP to the whitelist.
   * @param {string} ip - IP address
   */
  addToWhitelist(ip) {
    this.ipWhitelist.add(ip);
  }

  /**
   * Remove an IP from the whitelist.
   * @param {string} ip - IP address
   */
  removeFromWhitelist(ip) {
    this.ipWhitelist.delete(ip);
  }

  /**
   * Check if an IP is whitelisted.
   * @param {string} ip - IP address
   * @returns {boolean}
   */
  isWhitelisted(ip) {
    return this.ipWhitelist.has(ip);
  }

  // --------------------------------------------------------------------------
  // Alert Type Queries
  // --------------------------------------------------------------------------

  /**
   * Get an alert type by ID.
   * @param {number} id - Alert ID
   * @returns {Object|null}
   */
  getAlertType(id) {
    return this.alertTypes[id] || null;
  }

  /**
   * Get all alert types in a category.
   * @param {number} category - Category number (1-10)
   * @returns {Object[]}
   */
  getAlertsByCategory(category) {
    const start = (category - 1) * 50 + 1;
    const end = start + 49;
    const results = [];
    for (let i = start; i <= end; i++) {
      if (this.alertTypes[i]) results.push(this.alertTypes[i]);
    }
    return results;
  }

  /**
   * Get alerts by severity.
   * @param {string} severity - Severity level
   * @returns {Object[]}
   */
  getAlertsBySeverity(severity) {
    return Object.values(this.alertTypes).filter(a => a.severity === severity);
  }

  /**
   * Search alert types.
   * @param {string} query - Search query
   * @returns {Object[]}
   */
  searchAlerts(query) {
    const q = query.toLowerCase();
    return Object.values(this.alertTypes).filter(a =>
      a.name.toLowerCase().includes(q) || a.desc.toLowerCase().includes(q)
    );
  }

  /**
   * Get total alert count.
   * @returns {number}
   */
  getAlertCount() {
    return Object.keys(this.alertTypes).length;
  }

  /**
   * Get alert type statistics.
   * @returns {Object}
   */
  getStats() {
    const types = Object.values(this.alertTypes);
    const bySeverity = {};
    const byCategory = {};

    for (const a of types) {
      bySeverity[a.severity] = (bySeverity[a.severity] || 0) + 1;
      const cat = Math.ceil(a.id / 50);
      byCategory[cat] = (byCategory[cat] || 0) + 1;
    }

    return {
      total: types.length,
      bySeverity,
      byCategory,
      cooldownsActive: this.cooldowns.size,
      escalationsActive: this.escalations.size,
      queueLength: this.messageQueue.length,
      historyLength: this.history.length,
      whitelistedIPs: this.ipWhitelist.size
    };
  }

  // --------------------------------------------------------------------------
  // History & Persistence
  // --------------------------------------------------------------------------

  /**
   * Add alert to in-memory history.
   * @private
   */
  _addToHistory(alert) {
    this.history.unshift(alert);
    if (this.history.length > this.maxHistory) {
      this.history = this.history.slice(0, this.maxHistory);
    }
  }

  /**
   * Get alert history.
   * @param {Object} [filter] - Filter options
   * @param {string} [filter.severity] - Filter by severity
   * @param {string} [filter.name] - Filter by name
   * @param {number} [filter.limit=100] - Max results
   * @returns {Object[]}
   */
  getHistory(filter = {}) {
    let results = [...this.history];

    if (filter.severity) {
      results = results.filter(a => a.severity === filter.severity);
    }
    if (filter.name) {
      results = results.filter(a => a.name === filter.name);
    }

    return results.slice(0, filter.limit || 100);
  }

  /**
   * Persist alert to database.
   * @private
   */
  async _persistAlert(alert) {
    if (!this.db) return;
    await this.db.collection('alerts').insertOne({
      ...alert,
      _persistedAt: new Date()
    });
  }

  /**
   * Acknowledge an alert.
   * @param {string} alertId - Alert ID
   * @param {string} userId - Acknowledging user
   * @returns {boolean}
   */
  acknowledge(alertId, userId) {
    const alert = this.history.find(a => a.id === alertId);
    if (!alert) return false;
    alert.acknowledged = true;
    alert.acknowledgedBy = userId;
    alert.acknowledgedAt = new Date().toISOString();
    return true;
  }

  // --------------------------------------------------------------------------
  // Utility
  // --------------------------------------------------------------------------

  /**
   * Sleep helper.
   * @private
   */
  _sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
  }

  /**
   * Reset all cooldowns.
   */
  resetCooldowns() {
    this.cooldowns.clear();
  }

  /**
   * Reset all escalations.
   */
  resetEscalations() {
    this.escalations.clear();
  }

  /**
   * Clear the message queue.
   */
  clearQueue() {
    this.messageQueue = [];
  }

  /**
   * Get current queue length.
   * @returns {number}
   */
  getQueueLength() {
    return this.messageQueue.length;
  }
}

// ============================================================================
// Convenience Exports
// ============================================================================

export { Severity, AutoAction, CHANNELS };
export { SEVERITY_EMOJIS, ACTION_EMOJIS };

/**
 * Factory function.
 * @param {Object} [options] - Configuration
 * @returns {AlertManager}
 */
export function createAlertManager(options) {
  return new AlertManager(options);
}
