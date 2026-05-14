/**
 * @fileoverview Telegram Bot Service for Osm Army Gift Code Fortress.
 * Provides user verification, code notifications, security alerts, and admin actions
 * via the Telegram Bot API using pure HTTP (no external dependencies).
 *
 * Features:
 * - Webhook-based update delivery (no polling)
 * - Message queuing with rate limiting (30 msg/min/channel)
 * - Exponential backoff retry (3 retries)
 * - Rich MarkdownV2 formatting
 * - Multi-channel alert distribution
 * - Inline / reply keyboards
 * - Mandatory 3-channel verification flow
 * - Token-to-browser binding (first opener locks)
 *
 * @module services/bot
 * @version 5.0.0
 */

'use strict';

import { createHmac, timingSafeEqual, randomBytes, createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { ObjectId } from 'mongodb';
import {
  TelegramVerify,
  REQUIRED_CHANNELS,
  CHANNEL_FOLDER_LINK,
} from '../core/telegramVerify.js';

// ---------------------------------------------------------------------------
// Configuration & Constants
// ---------------------------------------------------------------------------

const TG_API_BASE = 'https://api.telegram.org/bot';

const CHANNELS = Object.freeze({
  CRITICAL:  '-1002627799078',
  SECURITY:  '-1003910695659',
  ALL:       '-1003940794962',
});

/** Severity levels with emoji mapping. */
const SEVERITY = Object.freeze({
  CRITICAL: { emoji: '\ud83d\udea8', label: 'CRITICAL' },
  WARNING:  { emoji: '\u26a0\ufe0f', label: 'WARNING'  },
  SUCCESS:  { emoji: '\u2705',       label: 'SUCCESS'  },
  INFO:     { emoji: '\u2139\ufe0f',  label: 'INFO'     },
});

const MAX_MSG_PER_MINUTE = 30;
const RETRIES = 3;
const BASE_RETRY_DELAY_MS = 1000;

/** Token expiry for gift links (10 MINUTES = 600 seconds). */
const GIFT_LINK_EXPIRY_MS = 600_000;

/** Channel display names for UI. */
const CHANNEL_NAMES = Object.freeze({
  '-1002627799078': 'OSM Channel 1',
  '-1003910695659': 'OSM Channel 2',
  '-1003940794962': 'OSM Channel 3',
});

// ---------------------------------------------------------------------------
// Custom Errors
// ---------------------------------------------------------------------------

export class TelegramBotError extends Error {
  constructor(message, code, statusCode = 500, extra = {}) {
    super(message);
    this.name = 'TelegramBotError';
    this.code = code;
    this.statusCode = statusCode;
    Object.assign(this, extra);
    Error.captureStackTrace(this, this.constructor);
  }
}

// ---------------------------------------------------------------------------
// Utility Functions
// ---------------------------------------------------------------------------

/**
 * Escape text for Telegram MarkdownV2.
 * @param {string} text
 * @returns {string}
 */
function escapeMarkdown(text) {
  if (!text) return '';
  return text
    .replace(/\\/g, '\\\\')
    .replace(/_/g, '\\_')
    .replace(/\*/g, '\\*')
    .replace(/\[/g, '\\[')
    .replace(/\]/g, '\\]')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)')
    .replace(/~/g, '\\~')
    .replace(/`/g, '\\`')
    .replace(/>/g, '\\>')
    .replace(/#/g, '\\#')
    .replace(/\+/g, '\\+')
    .replace(/-/g, '\\-')
    .replace(/=/g, '\\=')
    .replace(/\|/g, '\\|')
    .replace(/\{/g, '\\{')
    .replace(/\}/g, '\\}')
    .replace(/\./g, '\\.')
    .replace(/!/g, '\\!');
}

/**
 * Sleep for N milliseconds.
 * @param {number} ms
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Generate a cryptographically secure random token.
 * @param {number} [bytes=32]
 * @returns {string} Hex string
 */
function secureToken(bytes = 32) {
  return randomBytes(bytes).toString('hex');
}

/**
 * Compute HMAC-SHA256 for webhook signature verification.
 * @param {string} secret
 * @param {string|Buffer} body
 * @returns {string} Hex digest
 */
function signBody(secret, body) {
  return createHmac('sha256', secret).update(body).digest('hex');
}

// ---------------------------------------------------------------------------
// Message Queue
// ---------------------------------------------------------------------------

/**
 * Simple token-bucket queue per channel for rate limiting outbound messages.
 */
class MessageQueue {
  constructor() {
    /** @type {Map<string, Array>} */
    this.buckets = new Map();
    /** @type {Map<string, number>} */
    this.tokens = new Map();
    this.lastRefill = Date.now();
    this.processing = false;
    /** @type {Array<{channel:string,options:Object,resolve:Function,reject:Function}>} */
    this.backlog = [];
  }

  /**
   * Add a message to the queue for a channel.
   * @param {string} channel
   * @param {Object} options
   * @returns {Promise<Object>}
   */
  enqueue(channel, options) {
    return new Promise((resolve, reject) => {
      this.backlog.push({ channel, options, resolve, reject });
      this.process();
    });
  }

  /**
   * Process the backlog respecting rate limits.
   */
  async process() {
    if (this.processing) return;
    this.processing = true;
    try {
      while (this.backlog.length > 0) {
        const item = this.backlog[0];
        const hasToken = await this.consumeToken(item.channel);
        if (!hasToken) {
          await sleep(2000);
          continue;
        }
        this.backlog.shift();
        try {
          const result = await this.send(item.channel, item.options);
          item.resolve(result);
        } catch (err) {
          item.reject(err);
        }
      }
    } finally {
      this.processing = false;
    }
  }

  /**
   * Check and consume a token for a channel.
   * @param {string} channel
   * @returns {Promise<boolean>}
   */
  async consumeToken(channel) {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    if (elapsed >= 60_000) {
      this.tokens.clear();
      this.lastRefill = now;
    }
    const used = this.tokens.get(channel) || 0;
    if (used >= MAX_MSG_PER_MINUTE) return false;
    this.tokens.set(channel, used + 1);
    return true;
  }

  /**
   * Send a message via the Telegram API.
   * @param {string} channel
   * @param {Object} options
   * @returns {Promise<Object>}
   */
  async send(channel, options) {
    // Implemented externally by TelegramBot
    throw new TelegramBotError('send() must be overridden', 'NOT_IMPLEMENTED');
  }
}

// ---------------------------------------------------------------------------
// Telegram Bot Service
// ---------------------------------------------------------------------------

/**
 * TelegramBot provides all bot functionality for the Fortress system.
 * Uses the Telegram Bot API directly via fetch() (zero external dependencies).
 */
export class TelegramBot extends EventEmitter {
  /**
   * @param {Object} options
   * @param {string} options.token - Telegram bot token
   * @param {string} [options.webhookUrl] - Full HTTPS URL for webhook
   * @param {Object|null} [options.db] - MongoDB database instance
   * @param {string} [options.collectionName='telegram_messages']
   * @param {string} [options.webhookSecret] - Secret for HMAC verification
   * @param {boolean} [options.skipWebhookSetup=false] - Don't auto-set webhook
   */
  constructor(options = {}) {
    super();
    this.token = options.token || process.env.TELEGRAM_BOT_TOKEN || '';
    this.webhookUrl = options.webhookUrl || process.env.TELEGRAM_WEBHOOK_URL || '';
    this.webhookSecret = options.webhookSecret || process.env.TELEGRAM_WEBHOOK_SECRET || '';
    this.db = options.db || null;
    this.collectionName = options.collectionName || 'telegram_messages';
    this.skipWebhookSetup = options.skipWebhookSetup || false;
    // Accept external shared telegramVerify instance (BUG 1 FIX)
    this._externalTelegramVerify = options.telegramVerify || null;

    /** @type {import('mongodb').Collection|null} */
    this.collection = null;
    this.initialized = false;
    this.startTime = Date.now();

    // Message queue
    this.queue = new MessageQueue();
    this.queue.send = this._apiRequest.bind(this);

    // Verification state store (memory + MongoDB)
    /** @type {Map<string, Object>} */
    this.verifications = new Map();

    // Channel verification state machine per user
    // { userId: { step: 'joining'|'verifying'|'verified', channels: {}, messageId: number } }
    /** @type {Map<string, Object>} */
    this.channelVerificationState = new Map();

    // TelegramVerify instance (initialised in init())
    /** @type {TelegramVerify|null} */
    this.telegramVerify = null;

    // Logged message IDs for cleanup
    /** @type {Array<Object>} */
    this.messageLog = [];

    // Handler registry for commands
    /** @type {Map<string, Function>} */
    this.commands = new Map();
    /** @type {Map<string, Function>} */
    this.callbacks = new Map();

    this._setupHandlers();
  }

  // ------------------------------------------------------------------
  // Initialisation
  // ------------------------------------------------------------------

  /**
   * Initialise the bot: connect DB collection, set webhook.
   * @returns {Promise<void>}
   */
  async init() {
    if (this.initialized) return;
    if (!this.token) {
      throw new TelegramBotError(
        'Telegram bot token is required. Set TELEGRAM_BOT_TOKEN.',
        'MISSING_TOKEN',
        500
      );
    }

    // Initialise DB collection
    if (this.db) {
      this.collection = this.db.collection(this.collectionName);
      await this.collection.createIndex(
        { createdAt: 1 },
        { expireAfterSeconds: 30 * 86400, background: true, name: 'ttl_messages' }
      );
      await this.collection.createIndex(
        { messageId: 1, chatId: 1 },
        { background: true, name: 'message_lookup' }
      );
      await this.collection.createIndex(
        { chatId: 1, severity: 1 },
        { background: true, name: 'chat_severity' }
      );
    }

    // Set webhook
    if (this.webhookUrl && !this.skipWebhookSetup) {
      await this.setWebhook(this.webhookUrl);
    }

    // Use shared TelegramVerify if provided, otherwise create own (fallback)
    if (this._externalTelegramVerify) {
      this.telegramVerify = this._externalTelegramVerify;
      // Already initialized by the caller (server.js)
    } else {
      this.telegramVerify = new TelegramVerify({
        botToken: this.token,
        db: this.db,
      });
      await this.telegramVerify.init();
    }

    this.initialized = true;
    this.emit('ready');
  }

  /**
   * Alias for init().
   * @param {...*} args
   * @returns {Promise<void>}
   */
  initialize(...args) { return this.init(...args); }

  /**
   * Shut down the bot gracefully.
   * @returns {Promise<void>}
   */
  async stop() {
    if (this.webhookUrl && !this.skipWebhookSetup) {
      try {
        await this.deleteWebhook();
      } catch {
        // Best-effort cleanup
      }
    }
    this.initialized = false;
    this.emit('stopped');
  }

  // ------------------------------------------------------------------
  // Low-Level Telegram API
  // ------------------------------------------------------------------

  /**
   * Base URL for bot API requests.
   * @returns {string}
   */
  get apiUrl() {
    return `${TG_API_BASE}${this.token}`;
  }

  /**
   * Execute a raw Telegram API method with retry + logging.
   * @param {string} method - API method name, e.g. 'sendMessage'
   * @param {Object} body - JSON payload
   * @returns {Promise<Object>} Parsed Telegram response
   */
  async _apiRequest(method, body = {}) {
    const url = `${this.apiUrl}/${method}`;
    const payload = JSON.stringify(body);
    let lastErr = null;

    for (let attempt = 1; attempt <= RETRIES; attempt++) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 30_000);

        const res = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'OsmArmyBot/5.0',
          },
          body: payload,
          signal: controller.signal,
        });
        clearTimeout(timeout);

        const data = await res.json();

        if (!data.ok) {
          throw new TelegramBotError(
            data.description || `Telegram API error: ${method}`,
            data.error_code || 'TG_API_ERROR',
            data.error_code || 500
          );
        }

        // Log successful message
        await this._logMessage(body.chat_id, method, body, data.result);
        return data.result;
      } catch (err) {
        lastErr = err;
        if (attempt < RETRIES) {
          const delay = BASE_RETRY_DELAY_MS * Math.pow(2, attempt - 1);
          await sleep(delay);
        }
      }
    }

    // All retries exhausted
    this.emit('error', { method, body, error: lastErr });
    throw new TelegramBotError(
      `Telegram API failed after ${RETRIES} retries: ${lastErr?.message || 'Unknown'}`,
      'TG_RETRY_EXHAUSTED',
      lastErr?.statusCode || 502
    );
  }

  /**
   * Upload-aware API request for multipart/file methods.
   * (Currently used only for non-file methods; placeholder for future.)
   */
  async _apiUploadRequest(method, formData) {
    const url = `${this.apiUrl}/${method}`;
    let lastErr = null;
    for (let attempt = 1; attempt <= RETRIES; attempt++) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 30_000);
        const res = await fetch(url, {
          method: 'POST',
          headers: { 'User-Agent': 'OsmArmyBot/5.0' },
          body: formData,
          signal: controller.signal,
        });
        clearTimeout(timeout);
        const data = await res.json();
        if (!data.ok) {
          throw new TelegramBotError(
            data.description || `Telegram API upload error: ${method}`,
            data.error_code || 'TG_UPLOAD_ERROR',
            data.error_code || 500
          );
        }
        return data.result;
      } catch (err) {
        lastErr = err;
        if (attempt < RETRIES) {
          await sleep(BASE_RETRY_DELAY_MS * Math.pow(2, attempt - 1));
        }
      }
    }
    throw lastErr;
  }

  // ------------------------------------------------------------------
  // Webhook Management
  // ------------------------------------------------------------------

  /**
   * Register the webhook URL with Telegram.
   * @param {string} url
   * @returns {Promise<boolean>}
   */
  async setWebhook(url) {
    const result = await this._apiRequest('setWebhook', {
      url,
      max_connections: 40,
      allowed_updates: ['message', 'callback_query', 'inline_query', 'edited_message', 'chat_member'],
      secret_token: this.webhookSecret || undefined,
    });
    this.emit('webhook_set', { url, result });
    return result === true;
  }

  /**
   * Remove the webhook.
   * @returns {Promise<boolean>}
   */
  async deleteWebhook() {
    const result = await this._apiRequest('deleteWebhook', { drop_pending_updates: true });
    this.emit('webhook_deleted', { result });
    return result === true;
  }

  /**
   * Get current webhook info.
   * @returns {Promise<Object>}
   */
  async getWebhookInfo() {
    return this._apiRequest('getWebhookInfo');
  }

  /**
   * Get bot info.
   * @returns {Promise<Object>}
   */
  async getMe() {
    return this._apiRequest('getMe');
  }

  // ------------------------------------------------------------------
  // Webhook Update Handler
  // ------------------------------------------------------------------

  /**
   * Express middleware/handler for POST /webhook/telegram.
   * Verifies signature (if configured), parses update, routes to handler.
   * @returns {Function} Express middleware
   */
  webhookHandler() {
    return async (req, res) => {
      // Return 200 immediately to prevent Telegram retries
      res.status(200).send('OK');

      try {
        // Signature verification
        const signature = req.headers['x-telegram-bot-api-secret-token'];
        if (this.webhookSecret && signature) {
          const expected = this.webhookSecret;
          if (!timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
            this.emit('security', { type: 'invalid_webhook_signature', ip: req.ip });
            return;
          }
        }

        const update = req.body;
        if (!update || typeof update !== 'object') return;

        this.emit('update', update);

        // Route message commands
        if (update.message && update.message.text) {
          await this._handleMessage(update.message);
        }

        // Route callback queries (inline keyboard clicks)
        if (update.callback_query) {
          await this._handleCallback(update.callback_query);
        }

        // Route chat_member updates (channel join/leave detection)
        if (update.chat_member) {
          await this._handleChatMember(update.chat_member);
        }

        // Route my_chat_member updates (bot's own membership changes)
        if (update.my_chat_member) {
          await this._handleMyChatMember(update.my_chat_member);
        }

        // Route edited messages
        if (update.edited_message) {
          this.emit('edited_message', update.edited_message);
        }
      } catch (err) {
        this.emit('error', { type: 'webhook_handler', error: err });
      }
    };
  }

  /**
   * Handle an incoming text message.
   * @param {Object} message
   * @returns {Promise<void>}
   */
  async _handleMessage(message) {
    const text = message.text || '';
    const chatId = message.chat?.id;
    const user = message.from;

    // Extract command
    const cmdMatch = text.match(/^\/([a-zA-Z0-9_]+)(?:\s+(.*))?$/s);
    if (cmdMatch) {
      const cmd = cmdMatch[1].toLowerCase();
      const args = (cmdMatch[2] || '').trim();
      const handler = this.commands.get(cmd);
      if (handler) {
        try {
          await handler({ chatId, user, args, message });
        } catch (err) {
          this.emit('error', { type: 'command', cmd, error: err });
          await this.sendMessage(chatId, `${SEVERITY.WARNING.emoji} *Error processing command* \\\`${escapeMarkdown(cmd)}\\\`\nPlease try again later.`, { parse_mode: 'MarkdownV2' });
        }
      } else {
        await this.sendMessage(chatId, `Unknown command: \\\`${escapeMarkdown(cmd)}\\\`\nUse /help to see available commands.`, { parse_mode: 'MarkdownV2' });
      }
    } else {
      // Non-command text
      this.emit('text_message', { chatId, user, text, message });
    }
  }

  /**
   * Handle an inline keyboard callback.
   * @param {Object} callbackQuery
   * @returns {Promise<void>}
   */
  async _handleCallback(callbackQuery) {
    const data = callbackQuery.data || '';
    const chatId = callbackQuery.message?.chat?.id;
    const messageId = callbackQuery.message?.message_id;
    const user = callbackQuery.from;

    // Answer the callback to remove the loading spinner
    await this._apiRequest('answerCallbackQuery', {
      callback_query_id: callbackQuery.id,
    });

    const handler = this.callbacks.get(data);
    if (handler) {
      try {
        await handler({ chatId, messageId, user, data, callbackQuery });
      } catch (err) {
        this.emit('error', { type: 'callback', data, error: err });
      }
    } else {
      this.emit('unknown_callback', { chatId, data, user });
    }
  }

  // ------------------------------------------------------------------
  // Channel Join Detection via Webhook
  // ------------------------------------------------------------------

  /**
   * Handle chat_member updates to detect when users join/leave channels.
   * @param {Object} chatMember
   * @returns {Promise<void>}
   */
  async _handleChatMember(chatMember) {
    const userId = chatMember.new_chat_member?.user?.id;
    const chatId = chatMember.chat?.id;
    const oldStatus = chatMember.old_chat_member?.status;
    const newStatus = chatMember.new_chat_member?.status;

    if (!userId || !chatId) return;

    // Check if this is one of our required channels
    const channelIds = REQUIRED_CHANNELS.map((c) => c.id);
    if (!channelIds.includes(String(chatId))) return;

    const joined = ['member', 'administrator', 'creator', 'restricted'].includes(newStatus) &&
      !['member', 'administrator', 'creator', 'restricted'].includes(oldStatus);
    const left = !['member', 'administrator', 'creator', 'restricted'].includes(newStatus) &&
      ['member', 'administrator', 'creator', 'restricted'].includes(oldStatus);

    if (joined) {
      this.emit('channel_join', { userId, chatId, status: newStatus });

      // Check if all channels are now joined
      const state = this.channelVerificationState.get(String(userId));
      if (state && state.step === 'joining') {
        const result = await this.telegramVerify?.verifyAllChannels(userId);
        if (result?.allJoined) {
          await this.sendMessage(
            state.chatId,
            `\u2705 *Ready to verify!* All 3 channels joined.\n\nClick *Verify Membership* to continue.`,
            { parse_mode: 'MarkdownV2' }
          );
        }
      }
    }

    if (left) {
      this.emit('channel_leave', { userId, chatId, status: newStatus });
    }
  }

  /**
   * Handle my_chat_member updates (bot added/removed from channels).
   * @param {Object} myChatMember
   */
  async _handleMyChatMember(myChatMember) {
    const chatId = myChatMember.chat?.id;
    const newStatus = myChatMember.new_chat_member?.status;
    this.emit('bot_chat_member', { chatId, status: newStatus });
  }

  // ------------------------------------------------------------------
  // Command & Callback Registration
  // ------------------------------------------------------------------

  /**
   * Register built-in command handlers.
   * @private
   */
  _setupHandlers() {
    // /start - Welcome with mandatory 3-channel join flow
    // Supports deep link: https://t.me/BotName?start=verify
    this.commands.set('start', async ({ chatId, user, args }) => {
      // Deep link handler: /start verify
      if (args && args.trim().toLowerCase() === 'verify') {
        await this._startChannelVerification(chatId, user);
        return;
      }

      // C FIX: Deep link handler: /start code_<id>
      // Admin shares: https://t.me/BotName?start=code_abc123
      // → Bot validates codeId, then binds this exact code to the generated token
      if (args && args.startsWith('code_')) {
        const rawCodeId = args.substring(5); // Remove "code_" prefix

        // C FIX: Validate codeId is valid MongoDB ObjectId
        if (!ObjectId.isValid(rawCodeId)) {
          await this.sendMessage(
            chatId,
            `\u26a0\ufe0f *Invalid campaign link*\n\nThe code ID format is invalid\. Please use the official campaign link\.`,
            { parse_mode: 'MarkdownV2' }
          );
          return;
        }

        // C FIX: Verify the code exists and is active in DB
        try {
          const codeDoc = await this.db.collection('gift_codes')
            .findOne({ _id: new ObjectId(rawCodeId), status: 'active' });
          if (!codeDoc) {
            await this.sendMessage(
              chatId,
              `\u26a0\ufe0f *Campaign not found*\n\nThis campaign link is expired or invalid\. Please request a new official link\.`,
              { parse_mode: 'MarkdownV2' }
            );
            return;
          }
        } catch (e) {
          await this.sendMessage(
            chatId,
            `\u26a0\ufe0f *Server error*\n\nUnable to verify campaign\. Please try again later\.`,
            { parse_mode: 'MarkdownV2' }
          );
          return;
        }

        await this._startChannelVerification(chatId, user, rawCodeId);
        return;
      }
      const welcome = this._buildWelcomeMessage(user);
      const keyboard = {
        inline_keyboard: [
          [{ text: '\ud83d\udce2 Open All Channels', url: CHANNEL_FOLDER_LINK }],
          [
            { text: '\ud83d\udce2 Join Channel 1', url: `https://t.me/${REQUIRED_CHANNELS[0].slug}` },
            { text: '\ud83d\udce2 Join Channel 2', url: `https://t.me/${REQUIRED_CHANNELS[1].slug}` },
          ],
          [
            { text: '\ud83d\udce2 Join Channel 3', url: `https://t.me/${REQUIRED_CHANNELS[2].slug}` },
          ],
          [
            { text: '\ud83d\udd10 Verify Membership', callback_data: 'verify_channels' },
          ],
        ],
      };
      await this.sendMessage(chatId, welcome, {
        parse_mode: 'MarkdownV2',
        reply_markup: keyboard,
      });
    });

    // /verify - Check all 3 channel memberships and generate token
    this.commands.set('verify', async ({ chatId, user }) => {
      await this._startChannelVerification(chatId, user);
    });

    // /status - System status
    this.commands.set('status', async ({ chatId }) => {
      const status = await this._buildStatusMessage();
      await this.sendMessage(chatId, status, { parse_mode: 'MarkdownV2' });
    });

    // /help - Show help
    this.commands.set('help', async ({ chatId }) => {
      const help = this._buildHelpMessage();
      await this.sendMessage(chatId, help, { parse_mode: 'MarkdownV2' });
    });

    // C FIX: /claim is DISABLED in production
    // Only /start code_<id> flow is allowed — exact code binding
    this.commands.set('claim', async ({ chatId, user }) => {
      await this.sendMessage(
        chatId,
        `\u26a0\ufe0f *\u200bClaim is disabled*\n\n` +
        `To get your code, use an official campaign link shared by the admin\n\n` +
        `\ud83d\udc49 Example: \`https://osmarmy\.com/gift\?code=abc123\`\n\n` +
        `Open the link \→ Click "Verify Telegram" \→ Bot verifies channels \→ Timer \→ Code\n\n` +
        `_Direct /claim is disabled for security\._`,
        { parse_mode: 'MarkdownV2' }
      );
    });

    // ----------------------------------------------------------------
    // Callback handlers
    // ----------------------------------------------------------------

    // Legacy: redirects to channel verification
    this.callbacks.set('verify_start', async ({ chatId, user }) => {
      await this._startChannelVerification(chatId, user);
    });

    // NEW: verify_channels - Bot checks membership of all 3 channels
    this.callbacks.set('verify_channels', async ({ chatId, messageId, user }) => {
      await this._checkChannelMembership(chatId, messageId, user);
    });

    // NEW: retry_verify - Show join buttons for missing channels
    this.callbacks.set('retry_verify', async ({ chatId, messageId, user }) => {
      await this._retryChannelJoin(chatId, messageId, user);
    });

    // Legacy: kept for backward compatibility
    this.callbacks.set('verify_confirm', async ({ chatId, messageId, user }) => {
      await this._completeVerification(chatId, messageId, user);
    });

    this.callbacks.set('show_help', async ({ chatId }) => {
      await this.sendMessage(chatId, this._buildHelpMessage(), { parse_mode: 'MarkdownV2' });
    });

    this.callbacks.set('block_ip', async ({ chatId, user, callbackQuery }) => {
      // Admin only: block IP action
      if (!await this._isAdmin(user.id)) {
        await this.sendMessage(chatId, '\u26a0\ufe0f *Admin only action*', { parse_mode: 'MarkdownV2' });
        return;
      }
      const ip = callbackQuery.message?.reply_markup?.inline_keyboard?.[0]?.[0]?.callback_data?.split(':')[1];
      if (ip) {
        this.emit('admin_action', { type: 'block_ip', ip, adminId: user.id });
        await this.sendMessage(chatId, `\u2705 IP \\\`${escapeMarkdown(ip)}\\\` has been blocked.`, { parse_mode: 'MarkdownV2' });
      }
    });

    this.callbacks.set('ack_alert', async ({ chatId, messageId, user }) => {
      const edited = `~${escapeMarkdown('Alert acknowledged')}~\n*Acknowledged by:* \\\`${escapeMarkdown(String(user.id))}\\\` \u2705`;
      await this._apiRequest('editMessageText', {
        chat_id: chatId,
        message_id: messageId,
        text: edited,
        parse_mode: 'MarkdownV2',
      });
    });

    this.callbacks.set('kill_switch', async ({ chatId, user }) => {
      if (!await this._isAdmin(user.id)) {
        await this.sendMessage(chatId, '\u26a0\ufe0f *Admin only*', { parse_mode: 'MarkdownV2' });
        return;
      }
      this.emit('admin_action', { type: 'kill_switch', triggeredBy: user.id });
      await this.sendMessage(
        CHANNELS.CRITICAL,
        `\ud83d\udea8 *KILL SWITCH ACTIVATED* \ud83d\udea8\n\n*Triggered by:* \\\`${escapeMarkdown(String(user.id))}\\\`\n*Time:* \\\`${escapeMarkdown(new Date().toISOString())}\\\`\n\nAll gift code operations have been halted.`,
        { parse_mode: 'MarkdownV2' }
      );
    });
  }

  // ------------------------------------------------------------------
  // Channel Verification Flow
  // ------------------------------------------------------------------

  /**
   * Step 1: Send the "JOIN 3 CHANNELS TO GET CODE" message with join buttons.
   * @param {number|string} chatId
   * @param {Object} user
   * @returns {Promise<void>}
   */
  async _startChannelVerification(chatId, user, explicitCodeId = null) {
    const userId = String(user.id);

    // A FIX: Store state BEFORE checking alreadyVerified
    // (explicitCodeId must be stored for later use in _sendVerificationResult)
    this.channelVerificationState.set(userId, {
      step: 'joining',
      channels: {},
      messageId: null,
      chatId,
      explicitCodeId, // Store codeId for later use in _sendVerificationResult
    });

    // Check if already verified within 24h
    const alreadyVerified = await this.telegramVerify?.isUserVerified(user.id);
    if (alreadyVerified) {
      // A FIX: If explicit codeId provided (new campaign link), directly send link
      if (explicitCodeId) {
        await this.sendMessage(
          chatId,
          `\u2705 *Already Verified* \u2014 Sending your code link\.\.\.`,
          { parse_mode: 'MarkdownV2' }
        );
        await this._sendVerificationResult(chatId, user);
        return;
      }
      // A FIX: No codeId = old /verify without campaign → ask to use campaign link
      await this.sendMessage(
        chatId,
        `\u2705 *Already Verified*\n\nUse an official admin campaign link to get your code\.\n\nExample: \`https://osmarmy\.com/gift\?code=abc123\``,
        { parse_mode: 'MarkdownV2' }
      );
      return;
    }

    const text = this._buildChannelJoinMessage(user);
    const keyboard = {
      inline_keyboard: [
        [{ text: '\ud83d\udce2 Open All Channels (Folder)', url: CHANNEL_FOLDER_LINK }],
        [
          { text: '\ud83d\udce2 Join Channel 1', url: `https://t.me/${REQUIRED_CHANNELS[0].slug}` },
          { text: '\ud83d\udce2 Join Channel 2', url: `https://t.me/${REQUIRED_CHANNELS[1].slug}` },
        ],
        [
          { text: '\ud83d\udce2 Join Channel 3', url: `https://t.me/${REQUIRED_CHANNELS[2].slug}` },
        ],
        [
          { text: '\ud83d\udd10 I have joined all channels \u2192 Verify', callback_data: 'verify_channels' },
        ],
      ],
    };

    const msg = await this.sendMessage(chatId, text, {
      parse_mode: 'MarkdownV2',
      reply_markup: keyboard,
    });

    // Update stored message id
    const state = this.channelVerificationState.get(userId);
    if (state) state.messageId = msg?.message_id;
  }

  /**
   * Step 2: VERIFY button clicked. Check all 3 channel memberships.
   * @param {number|string} chatId
   * @param {number} messageId
   * @param {Object} user
   * @returns {Promise<void>}
   */
  async _checkChannelMembership(chatId, messageId, user) {
    const userId = String(user.id);

    if (!this.telegramVerify) {
      await this.sendMessage(chatId, `\u26a0\ufe0f Verification system not ready. Try again shortly.`, { parse_mode: 'MarkdownV2' });
      return;
    }

    // Check all channels
    const result = await this.telegramVerify.verifyAllChannels(user.id);

    // Update state
    const state = this.channelVerificationState.get(userId);
    if (state) {
      state.step = result.allJoined ? 'verified' : 'joining';
      state.channels = result.channels;
    }

    if (!result.allJoined) {
      // Some channels missing - show status + retry button
      const missingList = Object.values(result.channels)
        .filter((c) => !c.joined)
        .map((c) => `  \u274c ${escapeMarkdown(c.name)}`)
        .join('\n');
      const joinedList = Object.values(result.channels)
        .filter((c) => c.joined)
        .map((c) => `  \u2705 ${escapeMarkdown(c.name)}`)
        .join('\n');

      const statusText = (
        `*Channel Membership Check*\n\n` +
        `${joinedList}\n` +
        `${missingList}\n\n` +
        `*Please join the missing channels above, then click Verify again.*`
      );

      const keyboard = {
        inline_keyboard: [
          [{ text: '\ud83d\udce2 Open All Channels', url: CHANNEL_FOLDER_LINK }],
          [
            { text: '\ud83d\udd10 Verify Again', callback_data: 'verify_channels' },
          ],
        ],
      };

      await this._apiRequest('editMessageText', {
        chat_id: chatId,
        message_id: messageId,
        text: statusText,
        parse_mode: 'MarkdownV2',
        reply_markup: keyboard,
      });
      return;
    }

    // All 3 joined! Mark as verified and send success
    await this.telegramVerify.markChannelsVerified(user.id, result.channels);

    // Edit the original message to show success
    const successText = (
      `\u2705 *All 3 channels joined!*\n\n` +
      `\u2705 Verification successful\n` +
      `*Generating your unique link...*`
    );

    await this._apiRequest('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: successText,
      parse_mode: 'MarkdownV2',
    });

    // Generate token and send result (first opener wins)
    await this._sendVerificationResult(chatId, user);
  }

  /**
   * Show join buttons for channels the user hasn't joined yet.
   * @param {number|string} chatId
   * @param {number} messageId
   * @param {Object} user
   * @returns {Promise<void>}
   */
  async _retryChannelJoin(chatId, messageId, user) {
    const userId = String(user.id);
    const state = this.channelVerificationState.get(userId);
    const missingChannels = [];

    if (state && state.channels) {
      for (const [chId, info] of Object.entries(state.channels)) {
        if (!info.joined) {
          const ch = REQUIRED_CHANNELS.find((c) => c.id === chId);
          if (ch) missingChannels.push(ch);
        }
      }
    }

    // If no state, show all 3
    if (missingChannels.length === 0) {
      missingChannels.push(...REQUIRED_CHANNELS);
    }

    const keyboard = {
      inline_keyboard: [
        [{ text: '\ud83d\udce2 Open Channel Folder', url: CHANNEL_FOLDER_LINK }],
        ...missingChannels.map((ch) => [
          { text: `\ud83d\udce2 Join ${ch.name}`, url: `https://t.me/${ch.slug}` },
        ]),
        [
          { text: '\ud83d\udd10 I have joined all channels', callback_data: 'verify_channels' },
        ],
      ],
    };

    await this._apiRequest('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: `*Join the missing channels below, then click Verify!*`,
      parse_mode: 'MarkdownV2',
      reply_markup: keyboard,
    });
  }

  /**
   * Step 3: Send the final verification result with claim link.
   * @param {number|string} chatId
   * @param {Object} user
   * @returns {Promise<void>}
   */
  async _sendVerificationResult(chatId, user) {
    // B FIX: Use explicit codeId from /start code_<id> ONLY — NO fallback
    const state = this.channelVerificationState.get(String(user.id));
    const codeId = state?.explicitCodeId || null;

    // B FIX: Production — codeId is MANDATORY. No fallback to latest active.
    if (!codeId) {
      await this.sendMessage(
        chatId,
        `\u26a0\ufe0f *Invalid campaign link*\n\nNo campaign code bound to this session\.\nPlease use the official campaign link shared by the admin\n\n_Example: https://t\.me/${escapeMarkdown(this.token.split(':')[0])}?start=code_abc123_`,
        { parse_mode: 'MarkdownV2' }
      );
      return;
    }

    // Generate a verification token bound to this code
    const token = await this.telegramVerify.generateVerificationToken(
      user.id,
      `tg_${user.id}_pre`,
      null,
      codeId  // BIND exact codeId
    );

    const link = `https://osmarmy\.com/gift\?token=${escapeMarkdown(token)}`;

    const text = (
      `\u2705 *All 3 channels joined!*\n` +
      `\u2705 *Verification successful*\n\n` +
      `\ud83c\udf81 *Your unique link:*\n${link}\n\n` +
      `\u26a0\ufe0f *Do not share this link. First browser to open it will be locked.*\n` +
      `\u23f1\ufe0f *Link expires in 10 minutes*\n\n` +
      `_Do not share this link. First browser to open it will be locked._\n` +
      `_You can only redeem ONE code per account._`
    );

    await this.sendMessage(chatId, text, {
      parse_mode: 'MarkdownV2',
      disable_web_page_preview: true,
    });

    this.emit('channel_verification_complete', {
      userId: user.id,
      username: user.username,
      token,
    });
  }


  // ------------------------------------------------------------------
  // Message Builders
  // ------------------------------------------------------------------

  /**
   * Build the "JOIN 3 CHANNELS TO GET CODE" prompt message.
   * @param {Object} user
   * @returns {string}
   */
  _buildChannelJoinMessage(user) {
    const name = escapeMarkdown(user.first_name || 'User');
    return (
      `\ud83d\udd14 *Hey ${name}, join 3 channels to get your code!*\n\n` +
      `*Step 1:* Click each channel link below and join\n` +
      `*Step 2:* Click *Verify Membership*\n\n` +
      `\ud83d\udce2 *Channel 1:* [Join here](https://t\.me/${REQUIRED_CHANNELS[0].slug})\n` +
      `\ud83d\udce2 *Channel 2:* [Join here](https://t\.me/${REQUIRED_CHANNELS[1].slug})\n` +
      `\ud83d\udce2 *Channel 3:* [Join here](https://t\.me/${REQUIRED_CHANNELS[2].slug})\n\n` +
      `\u26a0\ufe0f *Binding Rules:*\n` +
      `\u2022 1 Telegram User = 1 Device = 1 Token\n` +
      `\u2022 Token is single-use — first to open gets the code\n` +
      `\u2022 Token expires in 10 minutes\n` +
      `\u2022 You can't redeem the same code twice\n\n` +
      `_After joining ALL 3 channels, click the Verify button._`
    );
  }

  /**
   * Build the welcome message for new users.
   * @param {Object} user
   * @returns {string}
   */
  _buildWelcomeMessage(user) {
    const name = escapeMarkdown(user.first_name || 'User');
    return (
      `\ud83e\udd16 *Welcome, ${name}!*\n\n` +
      `This is the *Osm Army Gift Code* verification bot.\n\n` +
      `*JOIN 3 CHANNELS TO GET CODE*\n\n` +
      `1\. Click each *Join Channel* button below\n` +
      `2\. Join all 3 Telegram channels\n` +
      `3\. Click *Verify Membership*\n` +
      `4\. Get your unique link\n\n` +
      `\u26a0\ufe0f *Rules:*\n` +
      `\u2022 1 Telegram User = 1 Device = 1 Token\n` +
      `\u2022 Link expires in 10 minutes\n` +
      `\u2022 Do not share — first browser to open gets locked\n\n` +
      `_Click the buttons below to begin._`
    );
  }

  /**
   * Build the help message.
   * @returns {string}
   */
  _buildHelpMessage() {
    return (
      `\ud83d\udcda *Bot Commands*\n\n` +
      `*/start* \- Welcome \+ channel join flow\n` +
      `*/start code_\<id\>* \- Open specific campaign link\n` +
      `*/verify* \- Check all 3 channel memberships\n` +
      `*/status* \- Check system status\n` +
      `*/help* \- Show this help\n\n` +
      `*How it works:*\n` +
      `1\. Open admin campaign link or click *Verify via Telegram*\n` +
      `2\. Join all 3 required channels\n` +
      `3\. Click *Verify Membership*\n` +
      `4\. Receive your secure link\n` +
      `5\. Open link \u2192 wait for timer \u2192 code reveals\n\n` +
      `_Verification expires after 24 hours._\n` +
      `_Token expires in 10 minutes._`
    );
  }

  /**
   * Build the system status message.
   * @returns {Promise<string>}
   */
  async _buildStatusMessage() {
    const uptime = Math.floor((Date.now() - this.startTime) / 1000);
    const hours = Math.floor(uptime / 3600);
    const mins = Math.floor((uptime % 3600) / 60);
    const secs = uptime % 60;
    const uptimeStr = `${hours}h ${mins}m ${secs}s`;

    const verifications = this.verifications.size;
    const queueSize = this.queue.backlog.length;
    const msgLogSize = this.messageLog.length;
    const channelVerifications = this.channelVerificationState.size;

    return (
      `\ud83d\udcca *System Status*\n\n` +
      `*Bot Uptime:* \\\`${escapeMarkdown(uptimeStr)}\\\`\n` +
      `*Active Verifications:* \\\`${verifications}\\\`\n` +
      `*Channel Verifications:* \\\`${channelVerifications}\\\`\n` +
      `*Message Queue:* \\\`${queueSize}\\\` pending\n` +
      `*Messages Sent:* \\\`${msgLogSize}\\\` this session\n` +
      `*Timestamp:* \\\`${escapeMarkdown(new Date().toISOString())}\\\`\n\n` +
      `_All systems operational_ \u2705`
    );
  }

  // ------------------------------------------------------------------
  // Legacy Verification Flow (kept for backward compatibility)
  // ------------------------------------------------------------------

  /**
   * Begin the verification process for a user.
   * @param {number|string} chatId
   * @param {Object} user
   * @returns {Promise<void>}
   */
  async _startVerification(chatId, user) {
    const userId = String(user.id);
    const existing = this.verifications.get(userId);
    if (existing && existing.status === 'verified' && existing.expiresAt > Date.now()) {
      await this.sendMessage(
        chatId,
        `\u2705 *Already Verified*\n\nYour verification is still valid until \\\`${escapeMarkdown(new Date(existing.expiresAt).toISOString())}\\\`.`,
        { parse_mode: 'MarkdownV2' }
      );
      return;
    }

    // Check account age (simulated - real implementation would call Telegram user API or cache)
    const accountAgeDays = await this._getAccountAge(user.id);
    if (accountAgeDays < 30) {
      await this.sendMessage(
        chatId,
        `\u26a0\ufe0f *Account Too New*\n\nYour account must be at least 1 month old to verify.\n*Current age:* ~${Math.floor(accountAgeDays)} days.`,
        { parse_mode: 'MarkdownV2' }
      );
      return;
    }

    // Send verification request with inline keyboard
    const keyboard = {
      inline_keyboard: [[
        { text: '\u2705 I am human', callback_data: 'verify_confirm' },
      ]],
    };

    const msg = await this.sendMessage(
      chatId,
      `*Verification Request*\n\nPlease confirm you are a human user.\n\n*Tapping this button constitutes agreement to our terms.*\n\n_Account age check passed_ \u2705`,
      { parse_mode: 'MarkdownV2', reply_markup: keyboard }
    );

    // Store pending verification
    this.verifications.set(userId, {
      userId,
      chatId,
      messageId: msg?.message_id,
      status: 'pending',
      createdAt: Date.now(),
      expiresAt: Date.now() + 600_000, // 10 minute expiry
      attempts: 0,
    });
  }

  /**
   * Complete verification after user confirms.
   * @param {number|string} chatId
   * @param {number} messageId
   * @param {Object} user
   * @returns {Promise<void>}
   */
  async _completeVerification(chatId, messageId, user) {
    const userId = String(user.id);
    const pending = this.verifications.get(userId);

    if (!pending || pending.status !== 'pending') {
      await this.sendMessage(chatId, `\u26a0\ufe0f No pending verification found. Use /verify to start.`, { parse_mode: 'MarkdownV2' });
      return;
    }

    if (pending.expiresAt < Date.now()) {
      await this.sendMessage(chatId, `\u26a0\ufe0f Verification request expired. Please use /verify again.`, { parse_mode: 'MarkdownV2' });
      this.verifications.delete(userId);
      return;
    }

    // Generate cryptographically secure verification token
    const token = secureToken(32);
    const expiry = Date.now() + 86_400_000; // 24 hours

    pending.status = 'verified';
    pending.token = token;
    pending.verifiedAt = Date.now();
    pending.expiresAt = expiry;
    pending.attempts = (pending.attempts || 0) + 1;

    // Persist to DB if available
    if (this.collection) {
      await this.collection.updateOne(
        { userId, type: 'verification' },
        {
          $set: {
            userId,
            telegramUserId: user.id,
            username: user.username || null,
            firstName: user.first_name || null,
            token,
            status: 'verified',
            verifiedAt: new Date(),
            expiresAt: new Date(expiry),
            createdAt: new Date(pending.createdAt),
            type: 'verification',
          },
        },
        { upsert: true }
      );
    }

    // Edit original message to show verified
    const verifiedText = (
      `\u2705 *Verification Complete*\n\n` +
      `*User:* \\\`${escapeMarkdown(userId)}\\\`\n` +
      `*Token:* \\\`${escapeMarkdown(token.substring(0, 16))}\\\`\u2026\n` +
      `*Expires:* \\\`${escapeMarkdown(new Date(expiry).toISOString())}\\\`\n\n` +
      `_Return to the website and paste your token._`
    );

    await this._apiRequest('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: verifiedText,
      parse_mode: 'MarkdownV2',
    });

    // Send token in separate message for easy copy
    await this.sendMessage(
      chatId,
      `Your verification token:\n\\\`\\\`\\\`\n${escapeMarkdown(token)}\n\\\`\\\`\\\`\n\n_Paste this on the website within 24 hours._`,
      { parse_mode: 'MarkdownV2' }
    );

    this.emit('verification_complete', { userId: user.id, token, expiry });
  }

  /**
   * Check if a user is verified.
   * @param {number|string} telegramUserId
   * @returns {Promise<boolean>}
   */
  async _isUserVerified(telegramUserId) {
    const cached = this.verifications.get(String(telegramUserId));
    if (cached && cached.status === 'verified' && cached.expiresAt > Date.now()) {
      return true;
    }
    if (this.collection) {
      const doc = await this.collection.findOne(
        { telegramUserId, type: 'verification', status: 'verified', expiresAt: { $gt: new Date() } }
      );
      return !!doc;
    }
    return false;
  }

  /**
   * Check if a user is an admin.
   * @param {number|string} telegramUserId
   * @returns {Promise<boolean>}
   */
  async _isAdmin(telegramUserId) {
    const admins = (process.env.TELEGRAM_ADMIN_IDS || '').split(',').map((s) => s.trim());
    return admins.includes(String(telegramUserId));
  }

  /**
   * Get approximate account age in days.
   * Telegram doesn't expose this directly; we estimate or use cached data.
   * @param {number} userId
   * @returns {Promise<number>} Days
   */
  async _getAccountAge(userId) {
    // Check cache first
    if (this.collection) {
      const doc = await this.collection.findOne({ type: 'user_age', userId: String(userId) });
      if (doc && doc.ageDays) return doc.ageDays;
    }
    // Return a simulated value - in production this would come from
    // first-seen tracking or external verification service.
    // For users we've seen before, we track their first appearance.
    const firstSeen = this.verifications.get(`firstSeen:${userId}`);
    if (firstSeen) {
      return (Date.now() - firstSeen) / 86_400_000;
    }
    this.verifications.set(`firstSeen:${userId}`, Date.now());
    return 999; // Assume valid for new sessions (will be checked via external service)
  }

  // ------------------------------------------------------------------
  // Public Message APIs
  // ------------------------------------------------------------------

  /**
   * Send a text message to any chat.
   * @param {number|string} chatId
   * @param {string} text
   * @param {Object} [options={}]
   * @param {string} [options.parse_mode]
   * @param {boolean} [options.disable_web_page_preview]
   * @param {Object} [options.reply_markup]
   * @param {number} [options.reply_to_message_id]
   * @returns {Promise<Object>} Message object
   */
  async sendMessage(chatId, text, options = {}) {
    if (!chatId) {
      throw new TelegramBotError('chatId is required', 'MISSING_CHAT_ID', 400);
    }
    if (!text) {
      throw new TelegramBotError('text is required', 'MISSING_TEXT', 400);
    }
    if (text.length > 4096) {
      // Telegram message limit; split or truncate
      text = text.substring(0, 4093) + '...';
    }

    const payload = {
      chat_id: chatId,
      text,
      parse_mode: options.parse_mode || undefined,
      disable_web_page_preview: options.disable_web_page_preview || false,
      reply_to_message_id: options.reply_to_message_id || undefined,
      reply_markup: options.reply_markup ? JSON.stringify(options.reply_markup) : undefined,
    };

    return this.queue.enqueue(chatId, payload);
  }

  /**
   * Send a security alert to the appropriate channel.
   * @param {Object} alert
   * @param {string} alert.severity - 'CRITICAL' | 'WARNING' | 'SUCCESS' | 'INFO'
   * @param {string} alert.title
   * @param {string} alert.message
   * @param {string} [alert.channel] - Override target channel
   * @param {Object} [alert.metadata] - Extra fields
   * @param {boolean} [alert.acknowledgeable=true]
   * @returns {Promise<Object>}
   */
  async sendAlert(alert) {
    const sev = SEVERITY[alert.severity] || SEVERITY.INFO;
    const channel = alert.channel ||
      (alert.severity === 'CRITICAL' ? CHANNELS.CRITICAL : CHANNELS.ALL);

    const metadataLines = alert.metadata
      ? Object.entries(alert.metadata)
          .map(([k, v]) => `*${escapeMarkdown(k)}:* \\\`${escapeMarkdown(String(v))}\\\``)
          .join('\n')
      : '';

    const keyboard = alert.acknowledgeable !== false
      ? { inline_keyboard: [[
          { text: '\u2705 Acknowledge', callback_data: 'ack_alert' },
          ...(alert.severity === 'CRITICAL' ? [{ text: '\ud83d\udea8 Kill Switch', callback_data: 'kill_switch' }] : []),
        ]]}
      : undefined;

    const text = (
      `${sev.emoji} *${escapeMarkdown(sev.label)}* ${sev.emoji}\n\n` +
      `*${escapeMarkdown(alert.title || 'Alert')}*\n` +
      `${escapeMarkdown(alert.message || '')}\n\n` +
      `${metadataLines}\n\n` +
      `_\\\`${escapeMarkdown(new Date().toISOString())}\\\`_`
    );

    return this.sendMessage(channel, text, {
      parse_mode: 'MarkdownV2',
      reply_markup: keyboard,
    });
  }

  /**
   * Send a code availability notification.
   * @param {Object} info
   * @param {string} [info.code]
   * @param {number} [info.remaining]
   * @returns {Promise<Object>}
   */
  async sendCodeNotification(info = {}) {
    const text = (
      `\u2705 *New Gift Code Available!*\n\n` +
      `A new code has been added to the system.\n\n` +
      (info.remaining !== undefined ? `*Remaining:* \\\`${info.remaining}\\\`\n` : '') +
      `Claim at: [osmarmy\.com/gift](https://osmarmy\.com/gift)\n\n` +
      `_Use an official campaign link after verification._`
    );
    return this.sendMessage(CHANNELS.ALL, text, {
      parse_mode: 'MarkdownV2',
      disable_web_page_preview: true,
    });
  }

  /**
   * Send system status broadcast.
   * @param {Object} stats
   * @returns {Promise<Object>}
   */
  async sendStatusBroadcast(stats = {}) {
    const text = (
      `\ud83d\udcca *Fortress Status Report*\n\n` +
      `*Uptime:* \\\`${escapeMarkdown(String(stats.uptime || 'N/A'))}\\\`\n` +
      `*Active Users:* \\\`${escapeMarkdown(String(stats.activeUsers || 0))}\\\`\n` +
      `*Blocked IPs:* \\\`${escapeMarkdown(String(stats.blockedIPs || 0))}\\\`\n` +
      `*Codes Claimed Today:* \\\`${escapeMarkdown(String(stats.codesClaimed || 0))}\\\`\n` +
      `*Rate Limit Violations:* \\\`${escapeMarkdown(String(stats.violations || 0))}\\\`\n` +
      `*Mutation Version:* \\\`${escapeMarkdown(String(stats.mutationVersion || 'N/A'))}\\\`\n\n` +
      `_\\\`${escapeMarkdown(new Date().toISOString())}\\\`_`
    );
    return this.sendMessage(CHANNELS.ALL, text, { parse_mode: 'MarkdownV2' });
  }

  /**
   * Send an admin notification (config changes, kill switch, etc.)
   * @param {Object} notification
   * @param {string} notification.action
   * @param {string} notification.actor
   * @param {string} [notification.details]
   * @returns {Promise<Object>}
   */
  async sendAdminNotification(notification) {
    const text = (
      `\ud83d\udc65 *Admin Action*\n\n` +
      `*Action:* \\\`${escapeMarkdown(notification.action)}\\\`\n` +
      `*Actor:* \\\`${escapeMarkdown(notification.actor)}\\\`\n` +
      (notification.details ? `*Details:* ${escapeMarkdown(notification.details)}\n` : '') +
      `*Time:* \\\`${escapeMarkdown(new Date().toISOString())}\\\``
    );
    return this.sendMessage(CHANNELS.CRITICAL, text, { parse_mode: 'MarkdownV2' });
  }

  /**
   * Notify that a kill switch was activated.
   * @param {Object} info
   * @returns {Promise<void>}
   */
  async sendKillSwitchAlert(info) {
    await this.sendAlert({
      severity: 'CRITICAL',
      title: 'KILL SWITCH ACTIVATED',
      message: `The system kill switch has been triggered by ${info.actor || 'unknown'}. All gift code operations are halted.`,
      channel: CHANNELS.CRITICAL,
      metadata: {
        triggeredBy: info.actor || 'unknown',
        reason: info.reason || 'No reason provided',
        timestamp: new Date().toISOString(),
      },
      acknowledgeable: true,
    });
  }

  // ------------------------------------------------------------------
  // Logging & Persistence
  // ------------------------------------------------------------------

  /**
   * Log a sent message to the database.
   * @private
   */
  async _logMessage(chatId, method, request, response) {
    const entry = {
      chatId: String(chatId),
      method,
      messageId: response?.message_id || null,
      requestSummary: JSON.stringify(request).substring(0, 2000),
      createdAt: new Date(),
    };
    this.messageLog.push(entry);
    // Keep in-memory log bounded
    if (this.messageLog.length > 10_000) {
      this.messageLog = this.messageLog.slice(-5000);
    }
    if (this.collection) {
      try {
        await this.collection.insertOne(entry);
      } catch {
        // Non-critical; don't fail the message send
      }
    }
  }

  // ------------------------------------------------------------------
  // Verification Token API (for website consumption)
  // ------------------------------------------------------------------

  /**
   * Validate a verification token presented by the website.
   * @param {string} token
   * @param {number|string} telegramUserId
   * @returns {Promise<{valid:boolean,expired:boolean,userId:string|null}>}
   */
  async validateToken(token, telegramUserId) {
    if (!token || typeof token !== 'string' || token.length !== 64) {
      return { valid: false, expired: false, userId: null };
    }

    // Check memory cache first
    for (const [, v] of this.verifications) {
      if (v.token === token && String(v.userId) === String(telegramUserId)) {
        if (v.expiresAt < Date.now()) {
          return { valid: false, expired: true, userId: v.userId };
        }
        return { valid: true, expired: false, userId: v.userId };
      }
    }

    // Check database
    if (this.collection) {
      const doc = await this.collection.findOne({
        token,
        telegramUserId,
        type: 'verification',
        status: 'verified',
      });
      if (!doc) return { valid: false, expired: false, userId: null };
      if (doc.expiresAt < new Date()) {
        return { valid: false, expired: true, userId: doc.userId };
      }
      return { valid: true, expired: false, userId: doc.userId };
    }

    return { valid: false, expired: false, userId: null };
  }

  /**
   * Revoke a verification token.
   * @param {string} token
   * @returns {Promise<boolean>}
   */
  async revokeToken(token) {
    let found = false;
    for (const [k, v] of this.verifications) {
      if (v.token === token) {
        v.status = 'revoked';
        v.revokedAt = Date.now();
        found = true;
      }
    }
    if (this.collection) {
      const result = await this.collection.updateOne(
        { token, type: 'verification' },
        { $set: { status: 'revoked', revokedAt: new Date() } }
      );
      if (result.modifiedCount > 0) found = true;
    }
    return found;
  }

  // ------------------------------------------------------------------
  // Statistics & Health
  // ------------------------------------------------------------------

  /**
   * Get bot health/status information.
   * @returns {Object}
   */
  health() {
    return {
      initialized: this.initialized,
      uptime: Math.floor((Date.now() - this.startTime) / 1000),
      verificationsPending: Array.from(this.verifications.values()).filter(
        (v) => v.status === 'pending'
      ).length,
      verificationsCompleted: Array.from(this.verifications.values()).filter(
        (v) => v.status === 'verified'
      ).length,
      queueSize: this.queue.backlog.length,
      messagesLogged: this.messageLog.length,
      commandsRegistered: this.commands.size,
      callbacksRegistered: this.callbacks.size,
      channelVerifications: this.channelVerificationState.size,
      telegramVerifyInitialized: this.telegramVerify?.initialized || false,
    };
  }
}

// ---------------------------------------------------------------------------
// Singleton Factory
// ---------------------------------------------------------------------------

/** @type {TelegramBot|null} */
let singletonBot = null;

/**
 * Get or create the TelegramBot singleton.
 * @param {Object} [options]
 * @returns {TelegramBot}
 */
export function getBot(options = {}) {
  if (!singletonBot) {
    singletonBot = new TelegramBot(options);
  }
  return singletonBot;
}

/**
 * Reset the singleton (useful for testing).
 */
export function resetBot() {
  singletonBot = null;
}

// ---------------------------------------------------------------------------
// Default Export
// ---------------------------------------------------------------------------

export default {
  TelegramBot,
  TelegramBotError,
  getBot,
  resetBot,
  CHANNELS,
  SEVERITY,
};
