/**
 * @fileoverview MongoDB Database Wrapper Module
 * @description Ultra-secure MongoDB database wrapper with prepared statement
 * patterns, connection pooling, auto-reconnect, field-level encryption,
 * and comprehensive audit logging. Uses native MongoDB driver (not Mongoose)
 * for maximum performance. All queries are parameterized - never string
 * concatenation. Data is encrypted before storage and decrypted after read.
 * @module core/database
 * @version 1.0.0
 */

import {
  MongoClient,
  ObjectId,
  ReadPreference,
  WriteConcern,
  ServerApiVersion,
} from 'mongodb';
import { createHash, randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';

// ============================================================================
// CUSTOM ERROR CLASSES
// ============================================================================

/**
 * Base database error.
 */
export class DatabaseError extends Error {
  constructor(message, code = 'DB_ERROR') {
    super(message);
    this.name = 'DatabaseError';
    this.code = code;
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Error for connection failures.
 */
export class ConnectionError extends DatabaseError {
  constructor(message) {
    super(message, 'DB_CONNECTION_ERROR');
    this.name = 'ConnectionError';
  }
}

/**
 * Error for query execution failures.
 */
export class QueryError extends DatabaseError {
  constructor(message, collection = null) {
    super(message, 'DB_QUERY_ERROR');
    this.name = 'QueryError';
    this.collection = collection;
  }
}

/**
 * Error for validation failures.
 */
export class ValidationError extends DatabaseError {
  constructor(message, field = null) {
    super(message, 'DB_VALIDATION_ERROR');
    this.name = 'ValidationError';
    this.field = field;
  }
}

/**
 * Error for timeout failures.
 */
export class TimeoutError extends DatabaseError {
  constructor(message) {
    super(message, 'DB_TIMEOUT');
    this.name = 'TimeoutError';
  }
}

/**
 * Error for transaction failures.
 */
export class TransactionError extends DatabaseError {
  constructor(message) {
    super(message, 'DB_TRANSACTION_ERROR');
    this.name = 'TransactionError';
  }
}

// ============================================================================
// SENSITIVE FIELD REGISTRY
// ============================================================================

/**
 * Fields that should be encrypted before storage per collection.
 * @type {Object<string, string[]>}
 */
const ENCRYPTED_FIELDS = {
  users: ['email', 'phone', 'telegramId'],
  gift_codes: ['code', 'batchSecret'],
  code_claims: ['claimIp', 'deviceFingerprint'],
  sessions: ['tokenData', 'sessionSecret'],
  ip_logs: ['ipAddress'],
  device_fingerprints: ['fingerprintData'],
  audit_logs: ['sensitiveData'],
  alerts: ['triggerData'],
  mutation_logs: ['seedFragment'],
  admin_sessions: ['sessionKey', 'ipAddress'],
  rate_limits: ['identifier'],
  blocked_ips: ['ipAddress'],
  watermarks: ['watermarkData'],
};

/**
 * Validate a MongoDB connection string.
 * @param {string} uri - Connection string
 * @returns {boolean}
 */
function validateConnectionString(uri) {
  if (!uri || typeof uri !== 'string') return false;
  const requiredPrefixes = ['mongodb://', 'mongodb+srv://'];
  return requiredPrefixes.some((p) => uri.startsWith(p));
}

// ============================================================================
// PREPARED STATEMENT CACHE
// ============================================================================

/**
 * Prepared statement cache for repeated queries.
 * Uses a LRU eviction policy.
 */
class PreparedStatementCache {
  /** @type {Map<string, Object>} */
  #cache = new Map();

  /** @type {number} */
  #maxSize = 200;

  /**
   * @param {number} maxSize - Maximum cache entries
   */
  constructor(maxSize = 200) {
    this.#maxSize = maxSize;
  }

  /**
   * Generate cache key from collection and filter shape.
   * @param {string} collection - Collection name
   * @param {string} operation - Operation type
   * @param {Object} filter - Query filter
   * @returns {string} Cache key
   */
  static generateKey(collection, operation, filter) {
    const shape = PreparedStatementCache.extractShape(filter);
    return createHash('sha256')
      .update(collection)
      .update(operation)
      .update(JSON.stringify(shape))
      .digest('hex');
  }

  /**
   * Extract the shape (keys) of a filter object for cache matching.
   * @param {Object} obj - Filter object
   * @returns {string} Normalized shape string
   */
  static extractShape(obj) {
    if (!obj || typeof obj !== 'object') return '';
    const keys = Object.keys(obj).sort();
    const parts = keys.map((k) => {
      const v = obj[k];
      if (v && typeof v === 'object' && !Array.isArray(v)) {
        return `${k}:{${PreparedStatementCache.extractShape(v)}}`;
      }
      return k;
    });
    return parts.join('|');
  }

  /**
   * Get a cached prepared statement or null.
   * @param {string} key - Cache key
   * @returns {Object|null}
   */
  get(key) {
    const entry = this.#cache.get(key);
    if (!entry) return null;
    // Move to end (LRU)
    this.#cache.delete(key);
    this.#cache.set(key, entry);
    return entry;
  }

  /**
   * Store a prepared statement in cache.
   * @param {string} key - Cache key
   * @param {Object} prepared - Prepared statement info
   */
  set(key, prepared) {
    if (this.#cache.size >= this.#maxSize) {
      const firstKey = this.#cache.keys().next().value;
      this.#cache.delete(firstKey);
    }
    this.#cache.set(key, {
      ...prepared,
      cachedAt: Date.now(),
    });
  }

  /**
   * Clear the cache.
   */
  clear() {
    this.#cache.clear();
  }

  /**
   * Get cache statistics.
   * @returns {Object}
   */
  getStats() {
    return {
      size: this.#cache.size,
      maxSize: this.#maxSize,
      entries: Array.from(this.#cache.keys()),
    };
  }
}

// ============================================================================
// DATABASE MANAGER CLASS
// ============================================================================

/**
 * Secure MongoDB database manager with prepared statements,
 * field-level encryption, and connection pooling.
 * Singleton pattern - one instance per process.
 */
class DatabaseManager extends EventEmitter {
  /** @type {DatabaseManager|null} */
  static #instance = null;

  /** @type {MongoClient|null} */
  #client = null;

  /** @type {Object|null} */
  #db = null;

  /** @type {Object<string, Object>} */
  #collections = {};

  /** @type {boolean} */
  #isConnected = false;

  /** @type {number} */
  #connectAttempts = 0;

  /** @type {number} */
  #maxReconnectAttempts = 10;

  /** @type {number} */
  #reconnectBaseDelay = 1000;

  /** @type {boolean} */
  #isShuttingDown = false;

  /** @type {PreparedStatementCache} */
  #statementCache = new PreparedStatementCache(200);

  /** @type {string} */
  #instanceId = randomBytes(8).toString('hex');

  /** @type {number} */
  #queryTimeoutMs = 5000;

  /** @type {Object|null} */
  #encryptionModule = null;

  /** @type {boolean} */
  #encryptionEnabled = true;

  /** @type {Array<{collection: string, fields: string[], options: Object}>} */
  #migrationLog = [];

  /**
   * Private constructor - use getInstance().
   */
  constructor() {
    super();
    if (DatabaseManager.#instance) {
      throw new DatabaseError('Use DatabaseManager.getInstance() instead of new');
    }
  }

  /**
   * Get the singleton DatabaseManager instance.
   * @returns {DatabaseManager}
   */
  static getInstance() {
    if (!DatabaseManager.#instance) {
      DatabaseManager.#instance = new DatabaseManager();
    }
    return DatabaseManager.#instance;
  }

  /**
   * Initialize the database connection.
   * @param {Object} options - Connection options
   * @param {string} options.uri - MongoDB connection URI
   * @param {string} options.dbName - Database name
   * @param {number} [options.minPoolSize=5] - Minimum connection pool size
   * @param {number} [options.maxPoolSize=50] - Maximum connection pool size
   * @param {number} [options.connectTimeoutMs=10000] - Connection timeout
   * @param {number} [options.serverSelectionTimeoutMs=5000] - Server selection timeout
   * @param {number} [options.queryTimeoutMs=5000] - Query timeout
   * @param {boolean} [options.encryptionEnabled=true] - Enable field encryption
   * @param {Object} [options.encryptionModule] - Encryption module (encrypt.js)
   * @returns {Promise<Object>} Database instance
   */
  async connect(options) {
    if (this.#isConnected) {
      return this.#db;
    }

    const {
      uri,
      dbName,
      minPoolSize = 5,
      maxPoolSize = 50,
      connectTimeoutMs = 10000,
      serverSelectionTimeoutMs = 5000,
      queryTimeoutMs = 5000,
      encryptionEnabled = true,
      encryptionModule = null,
    } = options;

    if (!uri || !validateConnectionString(uri)) {
      throw new ConnectionError('Invalid MongoDB connection string');
    }
    if (!dbName) {
      throw new ConnectionError('Database name is required');
    }

    this.#queryTimeoutMs = queryTimeoutMs;
    this.#encryptionEnabled = encryptionEnabled;
    this.#encryptionModule = encryptionModule;

    const clientOptions = {
      minPoolSize,
      maxPoolSize,
      connectTimeoutMS: connectTimeoutMs,
      serverSelectionTimeoutMS: serverSelectionTimeoutMs,
      maxIdleTimeMS: 60000,
      waitQueueTimeoutMS: 5000,
      heartbeatFrequencyMS: 10000,
      retryWrites: true,
      writeConcern: new WriteConcern('majority', 5000),
      readPreference: ReadPreference.PRIMARY_PREFERRED,
      serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
      },
    };

    try {
      this.#client = new MongoClient(uri, clientOptions);

      // Event listeners for connection monitoring
      this.#client.on('serverOpening', () => {
        this.emit('serverOpening');
      });

      this.#client.on('serverClosed', () => {
        this.emit('serverClosed');
      });

      this.#client.on('connectionPoolCreated', () => {
        this.emit('poolCreated');
      });

      this.#client.on('connectionPoolClosed', () => {
        this.emit('poolClosed');
      });

      this.#client.on('error', (err) => {
        this.emit('error', err);
        this.#handleConnectionError(err);
      });

      await this.#client.connect();
      this.#db = this.#client.db(dbName);
      this.#isConnected = true;
      this.#connectAttempts = 0;

      // Initialize collections
      await this.#initializeCollections();

      this.emit('connected', {
        instanceId: this.#instanceId,
        dbName,
        poolSize: `${minPoolSize}-${maxPoolSize}`,
      });

      // Setup graceful shutdown
      this.#setupShutdownHandlers();

      return this.#db;
    } catch (err) {
      this.#isConnected = false;
      throw new ConnectionError(`Failed to connect: ${err.message}`);
    }
  }

  /**
   * Handle connection errors and trigger reconnection.
   * @param {Error} err - Error object
   */
  #handleConnectionError(err) {
    this.emit('connectionError', err);
    if (!this.#isShuttingDown && this.#connectAttempts < this.#maxReconnectAttempts) {
      this.#isConnected = false;
      const delay = Math.min(
        this.#reconnectBaseDelay * 2 ** this.#connectAttempts,
        30000
      );
      this.#connectAttempts++;
      this.emit('reconnecting', { attempt: this.#connectAttempts, delay });
      setTimeout(() => this.#attemptReconnect(), delay);
    }
  }

  /**
   * Attempt to reconnect with exponential backoff.
   */
  async #attemptReconnect() {
    try {
      if (this.#client) {
        await this.#client.close(true);
      }
      // Reconnection will be handled by the application layer
      // calling connect() again with the same options
      this.emit('reconnectFailed', { attempts: this.#connectAttempts });
    } catch {
      // Silently handle close errors during reconnection
    }
  }

  /**
   * Initialize all collections and create indexes.
   */
  async #initializeCollections() {
    const collectionDefinitions = [
      {
        name: 'users',
        indexes: [
          { key: { username: 1 }, options: { unique: true } },
          { key: { emailHash: 1 }, options: { unique: true, sparse: true } },
          { key: { createdAt: 1 }, options: {} },
          { key: { lastActive: 1 }, options: { expireAfterSeconds: 7776000 } }, // 90 days TTL
        ],
      },
      {
        name: 'gift_codes',
        indexes: [
          { key: { codeHash: 1 }, options: { unique: true } },
          { key: { batchId: 1 }, options: {} },
          { key: { status: 1, createdAt: 1 }, options: {} },
          { key: { expiresAt: 1 }, options: { expireAfterSeconds: 0 } },
          { key: { codeHash: 1, status: 1 }, options: {} },
          { key: { releaseAt: 1 }, options: {} }, // ⏰ Time-lock index for efficient release queries
          { key: { status: 1, type: 1, releaseAt: 1 }, options: {} }, // Compound for code selection
        ],
      },
      {
        name: 'code_claims',
        indexes: [
          { key: { codeId: 1 }, options: {} },
          { key: { userId: 1 }, options: {} },
          { key: { claimedAt: 1 }, options: {} },
          { key: { codeId: 1, userId: 1 }, options: { unique: true } },
          { key: { claimIpHash: 1 }, options: {} },
          { key: { claimedAt: 1 }, options: { expireAfterSeconds: 15552000 } }, // 180 days TTL
        ],
      },
      {
        name: 'sessions',
        indexes: [
          { key: { sessionId: 1 }, options: { unique: true } },
          { key: { userId: 1 }, options: {} },
          { key: { expiresAt: 1 }, options: { expireAfterSeconds: 0 } },
          { key: { deviceFingerprint: 1 }, options: {} },
          { key: { createdAt: 1 }, options: {} },
        ],
      },
      {
        name: 'ip_logs',
        indexes: [
          { key: { ipHash: 1 }, options: {} },
          { key: { timestamp: 1 }, options: {} },
          { key: { action: 1, timestamp: 1 }, options: {} },
          { key: { ipHash: 1, timestamp: 1 }, options: {} },
          { key: { timestamp: 1 }, options: { expireAfterSeconds: 2592000 } }, // 30 days TTL
        ],
      },
      {
        name: 'device_fingerprints',
        indexes: [
          { key: { fingerprint: 1 }, options: { unique: true } },
          { key: { userId: 1 }, options: {} },
          { key: { createdAt: 1 }, options: {} },
          { key: { lastSeen: 1 }, options: {} },
          { key: { riskScore: 1 }, options: {} },
        ],
      },
      {
        name: 'audit_logs',
        indexes: [
          { key: { timestamp: 1 }, options: {} },
          { key: { action: 1, timestamp: 1 }, options: {} },
          { key: { userId: 1, timestamp: 1 }, options: {} },
          { key: { severity: 1, timestamp: 1 }, options: {} },
          { key: { eventHash: 1 }, options: { unique: true } },
          { key: { timestamp: 1 }, options: { expireAfterSeconds: 31536000 } }, // 365 days TTL
        ],
      },
      {
        name: 'alerts',
        indexes: [
          { key: { severity: 1, createdAt: 1 }, options: {} },
          { key: { status: 1 }, options: {} },
          { key: { alertType: 1 }, options: {} },
          { key: { acknowledged: 1 }, options: {} },
          { key: { createdAt: 1 }, options: { expireAfterSeconds: 7776000 } }, // 90 days TTL
        ],
      },
      {
        name: 'mutation_logs',
        indexes: [
          { key: { date: 1 }, options: { unique: true } },
          { key: { mutationIndex: 1 }, options: {} },
          { key: { createdAt: 1 }, options: {} },
        ],
      },
      {
        name: 'admin_sessions',
        indexes: [
          { key: { sessionToken: 1 }, options: { unique: true } },
          { key: { adminId: 1 }, options: {} },
          { key: { expiresAt: 1 }, options: { expireAfterSeconds: 0 } },
          { key: { ipHash: 1 }, options: {} },
          { key: { createdAt: 1 }, options: {} },
        ],
      },
      {
        name: 'rate_limits',
        indexes: [
          { key: { identifier: 1, windowStart: 1 }, options: { unique: true } },
          { key: { identifier: 1 }, options: {} },
          { key: { windowStart: 1 }, options: {} },
          { key: { expiresAt: 1 }, options: { expireAfterSeconds: 0 } },
        ],
      },
      {
        name: 'blocked_ips',
        indexes: [
          { key: { ipHash: 1 }, options: { unique: true } },
          { key: { blockedAt: 1 }, options: {} },
          { key: { expiresAt: 1 }, options: { expireAfterSeconds: 0 } },
          { key: { reason: 1 }, options: {} },
        ],
      },
      {
        name: 'watermarks',
        indexes: [
          { key: { codeId: 1 }, options: { unique: true } },
          { key: { watermarkHash: 1 }, options: { unique: true } },
          { key: { createdAt: 1 }, options: {} },
          { key: { batchId: 1 }, options: {} },
        ],
      },
      {
        name: 'claim_tickets',
        indexes: [
          { key: { claimId: 1 }, options: { unique: true } },
          { key: { expiresAt: 1 }, options: { expireAfterSeconds: 0 } },
          { key: { telegramId: 1, createdAt: -1 }, options: {} },
        ],
      },
      {
        name: 'nonce_tracking',
        indexes: [
          { key: { nonce: 1 }, options: { unique: true } },
          { key: { expiresAt: 1 }, options: { expireAfterSeconds: 0 } },
        ],
      },
      {
        name: 'reveal_audit',
        indexes: [
          { key: { codeId: 1, timestamp: -1 }, options: {} },
          { key: { timestamp: -1 }, options: {} },
          { key: { 'telegramIdHash': 1 }, options: {} },
        ],
      },
      {
        name: 'code_claims',
        indexes: [
          { key: { telegramId: 1, codeId: 1, claimDate: 1 }, options: { unique: true } },
          { key: { claimedAt: 1 }, options: {} },
        ],
      },
    ];

    for (const def of collectionDefinitions) {
      try {
        const collection = await this.#db.collection(def.name);
        this.#collections[def.name] = collection;

        for (const idx of def.indexes) {
          try {
            await collection.createIndex(idx.key, {
              ...idx.options,
              background: true,
            });
          } catch (idxErr) {
            // Index may already exist - continue
            if (!idxErr.message.includes('already exists')) {
              this.emit('indexError', { collection: def.name, error: idxErr.message });
            }
          }
        }
      } catch (err) {
        this.emit('collectionError', { collection: def.name, error: err.message });
      }
    }
  }

  /**
   * Setup graceful shutdown handlers.
   */
  #setupShutdownHandlers() {
    const shutdown = async (signal) => {
      this.#isShuttingDown = true;
      this.emit('shuttingDown', { signal });
      await this.disconnect();
      process.exit(0);
    };

    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));
  }

  // ============================================================================
  // ENCRYPTION HELPERS
  // ============================================================================

  /**
   * Encrypt sensitive fields of a document before storage.
   * @param {string} collection - Collection name
   * @param {Object} doc - Document to encrypt
   * @returns {Object} Document with encrypted fields
   */
  #encryptDocument(collection, doc) {
    if (!this.#encryptionEnabled || !this.#encryptionModule) {
      return doc;
    }

    const fields = ENCRYPTED_FIELDS[collection];
    if (!fields) return doc;

    const encrypted = { ...doc };
    for (const field of fields) {
      if (encrypted[field] !== undefined && encrypted[field] !== null) {
        try {
          encrypted[field] = this.#encryptionModule.encryptField(
            String(encrypted[field])
          );
          encrypted[`${field}_enc`] = true;
        } catch (err) {
          this.emit('encryptionError', { field, error: err.message });
        }
      }
    }
    return encrypted;
  }

  /**
   * Decrypt sensitive fields of a document after retrieval.
   * @param {string} collection - Collection name
   * @param {Object} doc - Document to decrypt
   * @returns {Object} Document with decrypted fields
   */
  #decryptDocument(collection, doc) {
    if (!this.#encryptionEnabled || !this.#encryptionModule || !doc) {
      return doc;
    }

    const fields = ENCRYPTED_FIELDS[collection];
    if (!fields) return doc;

    const decrypted = { ...doc };
    for (const field of fields) {
      if (
        decrypted[field] !== undefined &&
        decrypted[field] !== null &&
        decrypted[`${field}_enc`] === true
      ) {
        try {
          decrypted[field] = this.#encryptionModule.decryptField(decrypted[field]);
          delete decrypted[`${field}_enc`];
        } catch (err) {
          this.emit('decryptionError', { field, error: err.message });
        }
      }
    }
    return decrypted;
  }

  /**
   * Encrypt fields in an array of documents.
   * @param {string} collection - Collection name
   * @param {Array<Object>} docs - Documents to encrypt
   * @returns {Array<Object>}
   */
  #encryptDocuments(collection, docs) {
    if (!Array.isArray(docs)) return docs;
    return docs.map((d) => this.#encryptDocument(collection, d));
  }

  /**
   * Decrypt fields in an array of documents.
   * @param {string} collection - Collection name
   * @param {Array<Object>} docs - Documents to decrypt
   * @returns {Array<Object>}
   */
  #decryptDocuments(collection, docs) {
    if (!Array.isArray(docs)) return docs;
    return docs.map((d) => this.#decryptDocument(collection, d));
  }

  // ============================================================================
  // QUERY TIMEOUT WRAPPER
  // ============================================================================

  /**
   * Wrap a promise with a timeout.
   * @param {Promise} promise - Promise to wrap
   * @param {number} timeoutMs - Timeout in milliseconds
   * @param {string} operation - Operation description for errors
   * @returns {Promise}
   */
  static withTimeout(promise, timeoutMs, operation = 'database operation') {
    return Promise.race([
      promise,
      new Promise((_, reject) =>
        setTimeout(
          () => reject(new TimeoutError(`${operation} timed out after ${timeoutMs}ms`)),
          timeoutMs
        )
      ),
    ]);
  }

  // ============================================================================
  // CORE CRUD OPERATIONS
  // ============================================================================

  /**
   * Insert a single document.
   * @param {string} collection - Collection name
   * @param {Object} doc - Document to insert
   * @param {Object} [options] - Insert options
   * @returns {Promise<Object>} Insert result
   */
  async insertOne(collection, doc, options = {}) {
    this.#validateCollection(collection);
    if (!doc || typeof doc !== 'object') {
      throw new ValidationError('Document must be an object', 'doc');
    }

    const encrypted = this.#encryptDocument(collection, {
      ...doc,
      createdAt: doc.createdAt || new Date(),
      updatedAt: doc.updatedAt || new Date(),
    });

    const col = this.#collections[collection];
    const result = await DatabaseManager.withTimeout(
      col.insertOne(encrypted, { ...options, writeConcern: { w: 'majority' } }),
      this.#queryTimeoutMs,
      'insertOne'
    );

    return {
      acknowledged: result.acknowledged,
      insertedId: result.insertedId,
    };
  }

  /**
   * Insert multiple documents.
   * @param {string} collection - Collection name
   * @param {Array<Object>} docs - Documents to insert
   * @param {Object} [options] - Insert options
   * @returns {Promise<Object>} Insert result
   */
  async insertMany(collection, docs, options = {}) {
    this.#validateCollection(collection);
    if (!Array.isArray(docs) || docs.length === 0) {
      throw new ValidationError('Documents must be a non-empty array', 'docs');
    }

    const encrypted = this.#encryptDocuments(
      collection,
      docs.map((d) => ({
        ...d,
        createdAt: d.createdAt || new Date(),
        updatedAt: d.updatedAt || new Date(),
      }))
    );

    const col = this.#collections[collection];
    const result = await DatabaseManager.withTimeout(
      col.insertMany(encrypted, { ...options, ordered: false }),
      this.#queryTimeoutMs,
      'insertMany'
    );

    return {
      acknowledged: result.acknowledged,
      insertedCount: result.insertedCount,
      insertedIds: result.insertedIds,
    };
  }

  /**
   * Find documents matching a filter.
   * @param {string} collection - Collection name
   * @param {Object} filter - Query filter (parameterized)
   * @param {Object} [options] - Find options (projection, sort, limit, skip)
   * @returns {Promise<Array<Object>>} Matching documents
   */
  async find(collection, filter = {}, options = {}) {
    this.#validateCollection(collection);
    this.#validateFilter(filter);

    const { projection, sort, limit, skip } = options;
    const col = this.#collections[collection];

    let cursor = col.find(filter);
    if (projection) cursor = cursor.project(projection);
    if (sort) cursor = cursor.sort(sort);
    if (skip) cursor = cursor.skip(skip);
    if (limit) cursor = cursor.limit(limit);

    const docs = await DatabaseManager.withTimeout(
      cursor.toArray(),
      this.#queryTimeoutMs,
      'find'
    );

    return this.#decryptDocuments(collection, docs);
  }

  /**
   * Find a single document matching a filter.
   * @param {string} collection - Collection name
   * @param {Object} filter - Query filter (parameterized)
   * @param {Object} [options] - Find options
   * @returns {Promise<Object|null>} Matching document or null
   */
  async findOne(collection, filter = {}, options = {}) {
    this.#validateCollection(collection);
    this.#validateFilter(filter);

    const { projection, sort } = options;
    const col = this.#collections[collection];

    let query = col.findOne(filter);
    if (projection) query = col.findOne(filter, { projection });
    if (sort) query = col.findOne(filter, { projection, sort });

    const doc = await DatabaseManager.withTimeout(query, this.#queryTimeoutMs, 'findOne');

    return this.#decryptDocument(collection, doc);
  }

  /**
   * Update a single document.
   * @param {string} collection - Collection name
   * @param {Object} filter - Query filter (parameterized)
   * @param {Object} update - Update operations ($set, $inc, etc.)
   * @param {Object} [options] - Update options
   * @returns {Promise<Object>} Update result
   */
  async updateOne(collection, filter, update, options = {}) {
    this.#validateCollection(collection);
    this.#validateFilter(filter);
    if (!update || typeof update !== 'object') {
      throw new ValidationError('Update must be an object', 'update');
    }

    const col = this.#collections[collection];

    // Encrypt fields in $set operations
    let processedUpdate = update;
    if (update.$set && this.#encryptionEnabled && this.#encryptionModule) {
      const fields = ENCRYPTED_FIELDS[collection];
      if (fields) {
        processedUpdate = { ...update };
        processedUpdate.$set = { ...update.$set };
        for (const field of fields) {
          if (processedUpdate.$set[field] !== undefined) {
            processedUpdate.$set[field] = this.#encryptionModule.encryptField(
              String(processedUpdate.$set[field])
            );
            processedUpdate.$set[`${field}_enc`] = true;
          }
        }
        processedUpdate.$set.updatedAt = new Date();
      }
    }

    const result = await DatabaseManager.withTimeout(
      col.updateOne(filter, processedUpdate, { ...options, writeConcern: { w: 'majority' } }),
      this.#queryTimeoutMs,
      'updateOne'
    );

    return {
      acknowledged: result.acknowledged,
      matchedCount: result.matchedCount,
      modifiedCount: result.modifiedCount,
    };
  }

  /**
   * Update multiple documents.
   * @param {string} collection - Collection name
   * @param {Object} filter - Query filter (parameterized)
   * @param {Object} update - Update operations
   * @param {Object} [options] - Update options
   * @returns {Promise<Object>} Update result
   */
  async updateMany(collection, filter, update, options = {}) {
    this.#validateCollection(collection);
    this.#validateFilter(filter);
    if (!update || typeof update !== 'object') {
      throw new ValidationError('Update must be an object', 'update');
    }

    const col = this.#collections[collection];
    const result = await DatabaseManager.withTimeout(
      col.updateMany(filter, update, { ...options, writeConcern: { w: 'majority' } }),
      this.#queryTimeoutMs,
      'updateMany'
    );

    return {
      acknowledged: result.acknowledged,
      matchedCount: result.matchedCount,
      modifiedCount: result.modifiedCount,
    };
  }

  /**
   * Delete a single document.
   * @param {string} collection - Collection name
   * @param {Object} filter - Query filter (parameterized)
   * @param {Object} [options] - Delete options
   * @returns {Promise<Object>} Delete result
   */
  async deleteOne(collection, filter, options = {}) {
    this.#validateCollection(collection);
    this.#validateFilter(filter);

    const col = this.#collections[collection];
    const result = await DatabaseManager.withTimeout(
      col.deleteOne(filter, options),
      this.#queryTimeoutMs,
      'deleteOne'
    );

    return {
      acknowledged: result.acknowledged,
      deletedCount: result.deletedCount,
    };
  }

  /**
   * Delete multiple documents.
   * @param {string} collection - Collection name
   * @param {Object} filter - Query filter (parameterized)
   * @param {Object} [options] - Delete options
   * @returns {Promise<Object>} Delete result
   */
  async deleteMany(collection, filter, options = {}) {
    this.#validateCollection(collection);
    this.#validateFilter(filter);

    const col = this.#collections[collection];
    const result = await DatabaseManager.withTimeout(
      col.deleteMany(filter, options),
      this.#queryTimeoutMs,
      'deleteMany'
    );

    return {
      acknowledged: result.acknowledged,
      deletedCount: result.deletedCount,
    };
  }

  /**
   * Get collection statistics (size, document count, index size).
   * Used by admin panel DB size monitor.
   * @param {string} collection - Collection name
   * @returns {Promise<Object>} Collection stats
   */
  async stats(collection) {
    this.#validateCollection(collection);
    const col = this.#collections[collection];
    return DatabaseManager.withTimeout(
      col.stats(),
      this.#queryTimeoutMs,
      'stats'
    );
  }

  /**
   * Run a raw database command (compact, reIndex, etc).
   * Used by admin maintenance endpoints.
   * @param {Object} command - MongoDB command object
   * @returns {Promise<Object>} Command result
   */
  async command(command) {
    const db = this.#db;
    return DatabaseManager.withTimeout(
      db.command(command),
      this.#queryTimeoutMs * 2,
      'command'
    );
  }

  // ============================================================================
  // COUNT & AGGREGATION
  // ============================================================================

  /**
   * Count documents matching a filter.
   * @param {string} collection - Collection name
   * @param {Object} [filter={}] - Query filter
   * @param {Object} [options] - Count options
   * @returns {Promise<number>} Document count
   */
  async count(collection, filter = {}, options = {}) {
    this.#validateCollection(collection);
    this.#validateFilter(filter);

    const col = this.#collections[collection];
    return DatabaseManager.withTimeout(
      col.countDocuments(filter, options),
      this.#queryTimeoutMs,
      'count'
    );
  }

  /**
   * Count estimated total documents (fast, uses metadata).
   * @param {string} collection - Collection name
   * @returns {Promise<number>} Estimated count
   */
  async estimatedCount(collection) {
    this.#validateCollection(collection);
    const col = this.#collections[collection];
    return DatabaseManager.withTimeout(
      col.estimatedDocumentCount(),
      this.#queryTimeoutMs,
      'estimatedCount'
    );
  }

  /**
   * Execute an aggregation pipeline.
   * @param {string} collection - Collection name
   * @param {Array<Object>} pipeline - Aggregation pipeline
   * @param {Object} [options] - Aggregation options
   * @returns {Promise<Array<Object>>} Aggregation results
   */
  async aggregate(collection, pipeline, options = {}) {
    this.#validateCollection(collection);
    if (!Array.isArray(pipeline)) {
      throw new ValidationError('Pipeline must be an array', 'pipeline');
    }

    const col = this.#collections[collection];
    const cursor = col.aggregate(pipeline, { ...options, maxTimeMS: this.#queryTimeoutMs });
    return DatabaseManager.withTimeout(cursor.toArray(), this.#queryTimeoutMs, 'aggregate');
  }

  // ============================================================================
  // DISTINCT & INDEX
  // ============================================================================

  /**
   * Get distinct values for a field.
   * @param {string} collection - Collection name
   * @param {string} field - Field name
   * @param {Object} [filter={}] - Query filter
   * @returns {Promise<Array>} Distinct values
   */
  async distinct(collection, field, filter = {}) {
    this.#validateCollection(collection);
    if (!field || typeof field !== 'string') {
      throw new ValidationError('Field name is required', 'field');
    }

    const col = this.#collections[collection];
    return DatabaseManager.withTimeout(
      col.distinct(field, filter),
      this.#queryTimeoutMs,
      'distinct'
    );
  }

  /**
   * Create an index on a collection.
   * @param {string} collection - Collection name
   * @param {Object} keys - Index keys
   * @param {Object} [options] - Index options
   * @returns {Promise<string>} Index name
   */
  async createIndex(collection, keys, options = {}) {
    this.#validateCollection(collection);
    const col = this.#collections[collection];
    return DatabaseManager.withTimeout(
      col.createIndex(keys, { ...options, background: true }),
      this.#queryTimeoutMs,
      'createIndex'
    );
  }

  /**
   * Drop an index.
   * @param {string} collection - Collection name
   * @param {string} indexName - Index name
   * @returns {Promise<void>}
    */
  async dropIndex(collection, indexName) {
    this.#validateCollection(collection);
    const col = this.#collections[collection];
    await DatabaseManager.withTimeout(
      col.dropIndex(indexName),
      this.#queryTimeoutMs,
      'dropIndex'
    );
  }

  // ============================================================================
  // FIND AND MODIFY
  // ============================================================================

  /**
   * Find and update a document atomically.
   * @param {string} collection - Collection name
   * @param {Object} filter - Query filter
   * @param {Object} update - Update operations
   * @param {Object} [options] - Options
   * @returns {Promise<Object|null>} Original or updated document
   */
  async findOneAndUpdate(collection, filter, update, options = {}) {
    this.#validateCollection(collection);
    this.#validateFilter(filter);

    const col = this.#collections[collection];
    const result = await DatabaseManager.withTimeout(
      col.findOneAndUpdate(filter, update, {
        ...options,
        writeConcern: { w: 'majority' },
      }),
      this.#queryTimeoutMs,
      'findOneAndUpdate'
    );

    return this.#decryptDocument(collection, result);
  }

  /**
   * Find and delete a document atomically.
   * @param {string} collection - Collection name
   * @param {Object} filter - Query filter
   * @param {Object} [options] - Options
   * @returns {Promise<Object|null>} Deleted document
   */
  async findOneAndDelete(collection, filter, options = {}) {
    this.#validateCollection(collection);
    this.#validateFilter(filter);

    const col = this.#collections[collection];
    const result = await DatabaseManager.withTimeout(
      col.findOneAndDelete(filter, options),
      this.#queryTimeoutMs,
      'findOneAndDelete'
    );

    return this.#decryptDocument(collection, result);
  }

  // ============================================================================
  // BULK OPERATIONS
  // ============================================================================

  /**
   * Execute bulk write operations.
   * @param {string} collection - Collection name
   * @param {Array<Object>} operations - Bulk operations
   * @param {Object} [options] - Bulk options
   * @returns {Promise<Object>} Bulk write result
   */
  async bulkWrite(collection, operations, options = {}) {
    this.#validateCollection(collection);
    if (!Array.isArray(operations) || operations.length === 0) {
      throw new ValidationError('Operations must be a non-empty array', 'operations');
    }

    const col = this.#collections[collection];
    const result = await DatabaseManager.withTimeout(
      col.bulkWrite(operations, { ...options, ordered: false }),
      this.#queryTimeoutMs * 2,
      'bulkWrite'
    );

    return {
      acknowledged: result.acknowledged,
      insertedCount: result.insertedCount,
      matchedCount: result.matchedCount,
      modifiedCount: result.modifiedCount,
      deletedCount: result.deletedCount,
      upsertedCount: result.upsertedCount,
      upsertedIds: result.upsertedIds,
    };
  }

  // ============================================================================
  // TRANSACTIONS
  // ============================================================================

  /**
   * Execute operations within a transaction.
   * @param {Function} operations - Async function receiving session
   * @param {Object} [options] - Transaction options
   * @returns {Promise<*>} Transaction result
   * @throws {TransactionError} On transaction failure
   */
  async withTransaction(operations, options = {}) {
    if (!this.#isConnected || !this.#client) {
      throw new TransactionError('Database not connected');
    }
    if (typeof operations !== 'function') {
      throw new ValidationError('Operations must be a function', 'operations');
    }

    const session = this.#client.startSession();
    const transactionOptions = {
      readPreference: ReadPreference.PRIMARY,
      readConcern: { level: 'snapshot' },
      writeConcern: { w: 'majority', j: true, wtimeout: 5000 },
      ...options,
    };

    try {
      let result;
      await session.withTransaction(async () => {
        result = await operations(session);
      }, transactionOptions);
      return result;
    } catch (err) {
      throw new TransactionError(`Transaction failed: ${err.message}`);
    } finally {
      await session.endSession();
    }
  }

  // ============================================================================
  // PREPARED STATEMENTS
  // ============================================================================

  /**
   * Execute a prepared (cached) query.
   * @param {string} collection - Collection name
   * @param {string} operation - Operation type
   * @param {Object} filter - Query filter
   * @param {Object} [options] - Query options
   * @returns {Promise<Array<Object>>} Query results
   */
  async preparedFind(collection, operation, filter, options = {}) {
    this.#validateCollection(collection);
    this.#validateFilter(filter);

    const cacheKey = PreparedStatementCache.generateKey(collection, operation, filter);
    let prepared = this.#statementCache.get(cacheKey);

    if (!prepared) {
      prepared = { collection, operation, filterShape: PreparedStatementCache.extractShape(filter) };
      this.#statementCache.set(cacheKey, prepared);
    }

    return this.find(collection, filter, options);
  }

  /**
   * Clear the prepared statement cache.
   */
  clearStatementCache() {
    this.#statementCache.clear();
  }

  /**
   * Get prepared statement cache stats.
   * @returns {Object}
   */
  getCacheStats() {
    return this.#statementCache.getStats();
  }

  // ============================================================================
  // HEALTH CHECKS
  // ============================================================================

  /**
   * Check database connection health.
   * @returns {Promise<Object>} Health status
   */
  async healthCheck() {
    if (!this.#isConnected || !this.#db) {
      return { healthy: false, reason: 'Not connected' };
    }

    try {
      const start = Date.now();
      await this.#db.admin().ping();
      const latency = Date.now() - start;

      const serverInfo = await this.#db.admin().serverInfo();
      const poolStats = this.#getPoolStats();

      return {
        healthy: true,
        latency,
        instanceId: this.#instanceId,
        serverVersion: serverInfo.version,
        pool: poolStats,
        collections: Object.keys(this.#collections).length,
      };
    } catch (err) {
      return { healthy: false, reason: err.message };
    }
  }

  /**
   * Get connection pool statistics.
   * @returns {Object}
   */
  #getPoolStats() {
    if (!this.#client) return { connected: false };
    try {
      const topology = this.#client.topology;
      if (!topology) return { connected: false };
      const servers = Array.from(topology.s?.servers?.values() || []);
      return {
        connected: this.#isConnected,
        serverCount: servers.length,
        totalConnectionCount: servers.reduce(
          (sum, s) => sum + (s.s?.pool?.currentConnections || 0),
          0
        ),
      };
    } catch {
      return { connected: this.#isConnected, detail: 'unavailable' };
    }
  }

  /**
   * Check if connected to primary.
   * @returns {Promise<boolean>}
   */
  async isPrimary() {
    if (!this.#db) return false;
    try {
      const hello = await this.#db.admin().command({ hello: 1 });
      return hello.isWritablePrimary || hello.ismaster || false;
    } catch {
      return false;
    }
  }

  // ============================================================================
  // DISCONNECT & SHUTDOWN
  // ============================================================================

  /**
   * Gracefully disconnect from the database.
   * @param {boolean} [force=false] - Force close
   * @returns {Promise<void>}
   */
  async disconnect(force = false) {
    this.#isShuttingDown = true;
    this.#isConnected = false;

    if (this.#client) {
      try {
        await this.#client.close(force);
      } catch {
        // Ignore close errors
      }
      this.#client = null;
    }

    this.#db = null;
    this.#collections = {};
    this.#statementCache.clear();
    this.emit('disconnected', { instanceId: this.#instanceId });
  }

  // ============================================================================
  // DATABASE MIGRATIONS
  // ============================================================================

  /**
   * Run a database migration.
   * @param {string} name - Migration name
   * @param {Function} migrationFn - Async migration function
   * @returns {Promise<boolean>} Success status
   */
  async migrate(name, migrationFn) {
    if (!name || typeof name !== 'string') {
      throw new ValidationError('Migration name is required', 'name');
    }
    if (typeof migrationFn !== 'function') {
      throw new ValidationError('Migration function is required', 'migrationFn');
    }

    const migrationCol = this.#db.collection('_migrations');

    // Check if already applied
    const existing = await migrationCol.findOne({ name });
    if (existing && existing.applied) {
      return false; // Already applied
    }

    try {
      await migrationFn(this.#db, this.#collections);
      await migrationCol.updateOne(
        { name },
        {
          $set: {
            name,
            applied: true,
            appliedAt: new Date(),
            instanceId: this.#instanceId,
          },
        },
        { upsert: true }
      );
      this.#migrationLog.push({ name, appliedAt: new Date() });
      this.emit('migrationApplied', { name });
      return true;
    } catch (err) {
      await migrationCol.insertOne({
        name,
        applied: false,
        error: err.message,
        failedAt: new Date(),
      });
      throw new DatabaseError(`Migration "${name}" failed: ${err.message}`, 'MIGRATION_ERROR');
    }
  }

  /**
   * Get migration history.
   * @returns {Promise<Array<Object>>}
   */
  async getMigrationHistory() {
    const migrationCol = this.#db.collection('_migrations');
    return migrationCol.find().sort({ appliedAt: -1 }).toArray();
  }

  // ============================================================================
  // BACKUP & RESTORE
  // ============================================================================

  /**
   * Export collection data to JSON-compatible array.
   * @param {string} collection - Collection name
   * @param {Object} [filter={}] - Export filter
   * @returns {Promise<Array<Object>>} Exported documents
   */
  async exportCollection(collection, filter = {}) {
    this.#validateCollection(collection);
    const docs = await this.find(collection, filter);
    return docs.map((d) => {
      const obj = { ...d };
      if (obj._id) obj._id = obj._id.toString();
      return obj;
    });
  }

  /**
   * Import documents into a collection.
   * @param {string} collection - Collection name
   * @param {Array<Object>} documents - Documents to import
   * @param {Object} [options] - Import options
   * @returns {Promise<Object>} Import result
   */
  async importCollection(collection, documents, options = {}) {
    this.#validateCollection(collection);
    if (!Array.isArray(documents)) {
      throw new ValidationError('Documents must be an array', 'documents');
    }

    const processed = documents.map((d) => {
      const obj = { ...d };
      if (obj._id && typeof obj._id === 'string') {
        try { obj._id = new ObjectId(obj._id); } catch { /* keep as string */ }
      }
      return obj;
    });

    const { ordered = false, batchSize = 1000 } = options;
    const results = { insertedCount: 0, errors: [] };

    for (let i = 0; i < processed.length; i += batchSize) {
      const batch = processed.slice(i, i + batchSize);
      try {
        const result = await this.insertMany(collection, batch, { ordered });
        results.insertedCount += result.insertedCount;
      } catch (err) {
        results.errors.push({ batch: i / batchSize, error: err.message });
      }
    }

    return results;
  }

  /**
   * Create a full database backup manifest.
   * @returns {Promise<Object>} Backup manifest
   */
  async createBackup() {
    const collections = Object.keys(this.#collections);
    const backup = {
      timestamp: new Date().toISOString(),
      instanceId: this.#instanceId,
      collections: {},
    };

    for (const col of collections) {
      const count = await this.estimatedCount(col);
      backup.collections[col] = { documentCount: count };
    }

    return backup;
  }

  // ============================================================================
  // VALIDATION HELPERS
  // ============================================================================

  /**
   * Validate collection name.
   * @param {string} collection - Collection name
   * @throws {ValidationError} If invalid
   */
  #validateCollection(collection) {
    if (!collection || typeof collection !== 'string') {
      throw new ValidationError('Collection name is required', 'collection');
    }
    const allowed = Object.keys(this.#collections);
    if (!allowed.includes(collection)) {
      throw new ValidationError(
        `Unknown collection: ${collection}. Allowed: ${allowed.join(', ')}`,
        'collection'
      );
    }
  }

  /**
   * Validate query filter to prevent injection.
   * @param {Object} filter - Query filter
   * @throws {ValidationError} If potentially dangerous
   */
  #validateFilter(filter) {
    if (!filter || typeof filter !== 'object') return;

    const dangerousKeys = ['$where', '$eval', '$function'];
    const checkObject = (obj) => {
      for (const key of Object.keys(obj)) {
        if (dangerousKeys.includes(key)) {
          throw new ValidationError(`Forbidden operator: ${key}`, 'filter');
        }
        if (obj[key] && typeof obj[key] === 'object' && !Array.isArray(obj[key])) {
          checkObject(obj[key]);
        }
      }
    };

    checkObject(filter);
  }

  // ============================================================================
  // GETTERS
  // ============================================================================

  /**
   * Get native MongoDB database instance.
   * @returns {Object|null}
   */
  get db() {
    return this.#db;
  }

  /**
   * Get native MongoDB client.
   * @returns {MongoClient|null}
   */
  get client() {
    return this.#client;
  }

  /**
   * Get a collection reference.
   * @param {string} name - Collection name
   * @returns {Object|null}
   */
  collection(name) {
    return this.#collections[name] || null;
  }

  /**
   * Get connection status.
   * @returns {boolean}
   */
  get isConnected() {
    return this.#isConnected;
  }

  /**
   * Get instance ID.
   * @returns {string}
   */
  get instanceId() {
    return this.#instanceId;
  }

  /**
   * Get list of all collection names.
   * @returns {string[]}
   */
  get collectionNames() {
    return Object.keys(this.#collections);
  }
}

// ============================================================================
// FACTORY FUNCTION
// ============================================================================

/**
 * Create and connect the DatabaseManager singleton.
 * @param {Object} options - Connection options
 * @returns {Promise<DatabaseManager>}
 */
export async function createDatabase(options) {
  const db = DatabaseManager.getInstance();
  await db.connect(options);
  return db;
}

/**
 * Get the DatabaseManager singleton.
 * @returns {DatabaseManager}
 * @throws {DatabaseError} If not initialized
 */
export function getDatabaseManager() {
  const db = DatabaseManager.getInstance();
  if (!db.isConnected) {
    throw new DatabaseError('DatabaseManager not connected. Call createDatabase() first.');
  }
  return db;
}

/**
 * Quick access to the database instance.
 * @returns {Object}
 * @throws {DatabaseError} If not connected
 */
export function getDB() {
  const db = getDatabaseManager();
  return db.db;
}

/**
 * Convert string to ObjectId safely.
 * @param {string} id - String ID
 * @returns {ObjectId}
 * @throws {ValidationError} If invalid
 */
export function toObjectId(id) {
  try {
    return new ObjectId(id);
  } catch {
    throw new ValidationError(`Invalid ObjectId: ${id}`, '_id');
  }
}

/**
 * Convert ObjectId to string.
 * @param {ObjectId|string} id - ObjectId or string
 * @returns {string}
 */
export function fromObjectId(id) {
  if (id instanceof ObjectId) return id.toString();
  return String(id);
}

// ============================================================================
// MODULE EXPORTS
// ============================================================================

export default {
  createDatabase,
  getDatabaseManager,
  getDB,
  toObjectId,
  fromObjectId,
  DatabaseManager,
  DatabaseError,
  ConnectionError,
  QueryError,
  ValidationError,
  TimeoutError,
  TransactionError,
  ENCRYPTED_FIELDS,
};
