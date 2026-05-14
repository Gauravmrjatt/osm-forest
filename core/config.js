/**
 * @fileoverview Central Encrypted Configuration Module
 * @description Ultra-secure configuration with daily mutation seed generation.
 * All secrets are encrypted in memory using AES-256-GCM with a memory-derived key.
 * Supports 5000+ security layers across 10 mutation groups with daily rotation.
 * @module core/config
 * @version 1.0.0
 */

import { createHash, randomBytes, createCipheriv, createDecipheriv, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ============================================================================
// CUSTOM ERROR CLASSES
// ============================================================================

/**
 * Base configuration error.
 */
export class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Error for missing required environment variables.
 */
export class EnvValidationError extends ConfigError {
  constructor(vars) {
    super(`Missing required environment variables: ${vars.join(', ')}`);
    this.name = 'EnvValidationError';
    this.missingVars = vars;
  }
}

/**
 * Error for invalid configuration values.
 */
export class ConfigValidationError extends ConfigError {
  constructor(key, value, expected) {
    super(`Invalid config value for ${key}: got "${value}", expected ${expected}`);
    this.name = 'ConfigValidationError';
    this.key = key;
    this.value = value;
    this.expected = expected;
  }
}

/**
 * Error for mutation system failures.
 */
export class MutationError extends ConfigError {
  constructor(message) {
    super(`Mutation engine error: ${message}`);
    this.name = 'MutationError';
  }
}

// ============================================================================
// MEMORY KEY MANAGEMENT
// ============================================================================

let memoryKey = null;
let memoryKeyTimestamp = 0;
const KEY_LIFETIME_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Generate or rotate the in-memory encryption key.
 * Uses process-specific entropy + random bytes for defense in depth.
 * @returns {Buffer} 32-byte AES-256 key
 */
function getMemoryKey() {
  const now = Date.now();
  if (memoryKey && (now - memoryKeyTimestamp) < KEY_LIFETIME_MS) {
    return memoryKey;
  }

  const processEntropy = `${process.pid}-${process.hrtime.bigint()}-${now}-${process.version}`;
  const random = randomBytes(32);
  const hash1 = createHash('sha512').update(processEntropy).update(random).digest();
  const hash2 = createHash('sha512').update(hash1).update(randomBytes(16)).digest();
  memoryKey = hash2.subarray(0, 32);
  memoryKeyTimestamp = now;
  return memoryKey;
}

/**
 * Encrypt a secret value for in-memory storage.
 * @param {string} plaintext - Secret to encrypt
 * @returns {string} base64(iv:tag:ciphertext)
 */
function encryptInMemory(plaintext) {
  if (!plaintext || typeof plaintext !== 'string') return null;
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-gcm', getMemoryKey(), iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

/**
 * Decrypt an in-memory encrypted secret.
 * @param {string} ciphertext - base64(iv:tag:ciphertext)
 * @returns {string|null} Decrypted value or null
 */
function decryptInMemory(ciphertext) {
  if (!ciphertext || typeof ciphertext !== 'string') return null;
  try {
    const buf = Buffer.from(ciphertext, 'base64');
    if (buf.length < 33) return null;
    const iv = buf.subarray(0, 16);
    const tag = buf.subarray(16, 32);
    const encrypted = buf.subarray(32);
    const decipher = createDecipheriv('aes-256-gcm', getMemoryKey(), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
  } catch {
    return null;
  }
}

// ============================================================================
// ENVIRONMENT VARIABLE VALIDATION
// ============================================================================

/**
 * All required environment variables.
 * @type {string[]}
 */
const REQUIRED_ENV_VARS = [
  'PORT',
  'NODE_ENV',
  'SERVER_SECRET',
  'MONGODB_URI',
  'TELEGRAM_BOT_TOKEN',
  'AES_MASTER_KEY',
  'HMAC_SECRET',
  'JWT_SECRET',
  'SESSION_SECRET',
  'MUTATION_SEED_SALT',
  'MUTATION_DAILY_SALT',
  'MUTATION_HOURLY_SALT',
  'RATE_LIMIT_WINDOW_MS',
  'RATE_LIMIT_MAX_REQUESTS',
  'RATE_LIMIT_TOKEN_WINDOW_MS',
  'RATE_LIMIT_MAX_TOKENS',
  'DEVICE_FINGERPRINT_SALT',
  'WATERMARK_SECRET',
  'WATERMARK_SEED',
  'POW_DIFFICULTY_BASE',
  'POW_MAX_ATTEMPTS',
  'TOKEN_EXPIRY_SECONDS',
  'MAX_TOKENS_PER_IP_PER_HOUR',
  'ADMIN_USERNAME_HASH',
  'ADMIN_2FA_SECRET',
  'KILL_SWITCH_ENABLED',
  'SECURITY_LAYERS_COUNT',
  'TELEGRAM_CHANNEL_PRIMARY',
  'TELEGRAM_CHANNEL_SECONDARY',
  'TELEGRAM_CHANNEL_ALERTS',
];

/**
 * Validate all required environment variables are present.
 * @throws {EnvValidationError} If any required variables are missing
 */
function validateRequiredEnv() {
  const missing = REQUIRED_ENV_VARS.filter((v) => !process.env[v]);
  if (missing.length > 0) {
    throw new EnvValidationError(missing);
  }
}

/**
 * Parse and validate integer config value.
 * @param {string} raw - Raw env value
 * @param {string} key - Config key name
 * @param {number} min - Minimum allowed value
 * @param {number} max - Maximum allowed value
 * @returns {number} Parsed integer
 * @throws {ConfigValidationError} If invalid
 */
function parseIntEnv(raw, key, min, max) {
  const val = parseInt(raw, 10);
  if (Number.isNaN(val) || val < min || val > max) {
    throw new ConfigValidationError(key, raw, `integer ${min}-${max}`);
  }
  return val;
}

/**
 * Parse and validate a boolean env value.
 * @param {string} raw - Raw env value
 * @param {string} key - Config key name
 * @returns {boolean}
 */
function parseBoolEnv(raw, key) {
  const lowered = raw.toLowerCase().trim();
  if (lowered === 'true' || lowered === '1' || lowered === 'yes') return true;
  if (lowered === 'false' || lowered === '0' || lowered === 'no') return false;
  throw new ConfigValidationError(key, raw, 'boolean (true/false/1/0/yes/no)');
}

/**
 * Parse comma-separated list from env.
 * @param {string} raw - Raw env value
 * @returns {string[]}
 */
function parseListEnv(raw) {
  if (!raw) return [];
  return raw.split(',').map((s) => s.trim()).filter(Boolean);
}

// ============================================================================
// MUTATION ENGINE
// ============================================================================

/**
 * Mutation group definition.
 * @typedef {Object} MutationGroup
 * @property {string} name - Group name
 * @property {boolean} active - Whether group is active
 * @property {number} priority - Priority (1-10, lower = higher priority)
 * @property {string[]} validationRules - Active validation rule names
 * @property {string[]} algorithmVariants - Active algorithm variants
 * @property {number} layerOffset - Starting layer index
 * @property {Object} params - Group-specific parameters
 */

/**
 * Pre-defined 10 mutation groups × 500 layers = 5000 configurations.
 * Each group defines a category of security behavior that mutates daily.
 * @type {MutationGroup[]}
 */
const MUTATION_GROUPS = [
  {
    name: 'authentication_flow',
    active: true,
    priority: 1,
    validationRules: [
      'argon2id_strict', 'hmac_sha512_token', 'session_binding',
      'device_fingerprint_check', 'ip_consistency_verify',
      'temporal_decay_factor', 'replay_attack_prevention',
      'concurrent_session_limit', 'brute_force_backoff',
      'credential_stuffing_detection',
    ],
    algorithmVariants: ['variant_a', 'variant_b', 'variant_c', 'variant_d', 'variant_e'],
    layerOffset: 0,
    params: {
      sessionBindingMode: 'strict',
      maxConcurrentSessions: 3,
      tokenRotationInterval: 300,
      fingerprintSensitivity: 'high',
      temporalWindowSeconds: 30,
    },
  },
  {
    name: 'encryption_rotations',
    active: true,
    priority: 2,
    validationRules: [
      'aes_256_gcm_only', 'key_rotation_5min', 'iv_unique_per_operation',
      'auth_tag_verification', 'ciphertext_integrity_check',
      'key_derivation_hkdf', 'forward_secrecy_check',
      'memory_scrubbing', 'side_channel_resistance',
      'quantum_resistant_padding',
    ],
    algorithmVariants: ['aes_gcm_siv', 'chacha20_poly1305_mix', 'aes_gcm_hmac', 'encrypt_then_mac', 'hybrid_rsa_aes'],
    layerOffset: 500,
    params: {
      cipherMode: 'aes-256-gcm',
      keyRotationMinutes: 5,
      ivEntropyBits: 128,
      hkdfIterations: 10000,
      memoryScrubInterval: 60,
    },
  },
  {
    name: 'rate_limiting_patterns',
    active: true,
    priority: 3,
    validationRules: [
      'sliding_window_enforcement', 'token_bucket_strict',
      'ip_reputation_scoring', 'device_fingerprint_quota',
      'geographic_rate_adjustment', 'burst_protection',
      'distributed_sync_check', 'slowloris_mitigation',
      'adaptive_throttling', 'resource_exhaustion_guard',
    ],
    algorithmVariants: ['fixed_window', 'sliding_window', 'token_bucket', 'leaky_bucket', 'adaptive_rate'],
    layerOffset: 1000,
    params: {
      windowStrategy: 'sliding',
      burstTolerance: 5,
      ipReputationDecay: 0.9,
      geoMultiplierBase: 1.0,
      adaptiveSensitivity: 0.8,
    },
  },
  {
    name: 'ip_blocking_heuristics',
    active: true,
    priority: 4,
    validationRules: [
      'tor_exit_node_block', 'vpn_detection_score', 'proxy_chain_analysis',
      'asn_reputation_check', 'geolocation_mismatch', 'velocity_pattern_match',
      'botnet_signature_detection', 'residential_proxy_filter',
      'data_center_ip_flag', 'compromised_ip_database',
    ],
    algorithmVariants: ['strict_block', 'score_based', 'challenged_only', 'slow_mode', 'monitor_only'],
    layerOffset: 1500,
    params: {
      blockThreshold: 80,
      challengeThreshold: 50,
      monitorThreshold: 30,
      decayHours: 24,
      maxScore: 100,
    },
  },
  {
    name: 'device_fingerprinting',
    active: true,
    priority: 5,
    validationRules: [
      'canvas_fingerprint_hash', 'webgl_signature_check',
      'font_list_entropy', 'timezone_locale_verify',
      'navigator_property_integrity', 'screen_behavior_analysis',
      'audio_context_fingerprint', 'webrtc_leak_check',
      'touch_event_entropy', 'battery_api_behavior',
    ],
    algorithmVariants: ['full_fingerprint', 'partial_fingerprint', 'behavioral_only', 'passive_only', 'hybrid_mode'],
    layerOffset: 2000,
    params: {
      fingerprintComponents: 12,
      entropyThreshold: 8.0,
      driftTolerance: 0.15,
      behavioralWeight: 0.3,
      collectionMode: 'active_passive',
    },
  },
  {
    name: 'watermarking_system',
    active: true,
    priority: 6,
    validationRules: [
      'invisible_watermark_embed', 'frequency_domain_mark',
      'temporal_watermark_sync', 'geometric_distortion_resistance',
      'compression_aware_marking', 'collusion_resistance_check',
      'blind_detection_capability', 'multi_watermark_layering',
      'copyright_integrity_verify', 'steganographic_depth_check',
    ],
    algorithmVariants: ['dct_watermark', 'dwt_watermark', 'spread_spectrum', 'quantization_index', 'patchwork_method'],
    layerOffset: 2500,
    params: {
      watermarkStrength: 0.05,
      layerCount: 3,
      detectionThreshold: 0.7,
      resistanceLevel: 'high',
      syncInterval: 60,
    },
  },
  {
    name: 'pow_challenge_params',
    active: true,
    priority: 7,
    validationRules: [
      'difficulty_dynamic_adjust', 'nonce_uniqueness_check',
      'timestamp_freshness_verify', 'challenge_signature_valid',
      'solution_verification_strict', 'replay_nonce_rejection',
      'parallel_solve_detection', 'asic_resistance_check',
      'memory_hardness_verify', 'challenge_rate_limiting',
    ],
    algorithmVariants: ['sha256_pow', 'scrypt_pow', 'equihash_light', 'argon2id_pow', 'random_graph_pow'],
    layerOffset: 3000,
    params: {
      baseDifficulty: 4,
      maxDifficulty: 8,
      challengeExpiry: 120,
      nonceSize: 16,
      adjustmentFactor: 1.2,
    },
  },
  {
    name: 'telegram_integrity',
    active: true,
    priority: 8,
    validationRules: [
      'webhook_signature_verify', 'message_origin_check',
      'bot_token_rotation', 'channel_permission_verify',
      'message_deletion_policy', 'forward_protection',
      'admin_action_audit', 'rate_limit_per_chat',
      'command_validation_strict', 'inline_query_sanitize',
    ],
    algorithmVariants: ['strict_mode', 'relaxed_mode', 'maintenance_mode', 'emergency_mode', 'audit_only'],
    layerOffset: 3500,
    params: {
      webhookVerify: true,
      maxMessageAge: 60,
      tokenRotationDays: 7,
      commandRateLimit: 10,
      auditRetentionDays: 90,
    },
  },
  {
    name: 'database_security',
    active: true,
    priority: 9,
    validationRules: [
      'field_level_encryption', 'query_parameterization',
      'connection_pool_monitoring', 'write_concern_strict',
      'read_isolation_verify', 'audit_log_immutable',
      'backup_encryption_verify', 'index_integrity_check',
      'schema_validation_strict', 'change_stream_monitor',
    ],
    algorithmVariants: ['full_encryption', 'selective_encryption', 'transparent_encryption', 'application_encryption', 'hybrid_model'],
    layerOffset: 4000,
    params: {
      encryptionLevel: 'field',
      poolMin: 5,
      poolMax: 50,
      writeConcern: 'majority',
      auditImmutability: true,
      backupFrequencyHours: 6,
    },
  },
  {
    name: 'mutation_engine_self',
    active: true,
    priority: 10,
    validationRules: [
      'seed_entropy_verify', 'mutation_chain_integrity',
      'config_hash_mismatch_alert', 'layer_activation_verify',
      'cross_group_conflict_check', 'mutation_log_tamperproof',
      'fallback_config_valid', 'emergency_override_check',
      'mutation_timing_jitter', 'seed_rotation_verify',
    ],
    algorithmVariants: ['deterministic', 'entropy_augmented', 'chaos_mode', 'conservative', 'emergency_lockdown'],
    layerOffset: 4500,
    params: {
      seedEntropyMinBits: 256,
      chainVerification: true,
      fallbackEnabled: true,
      emergencyOverride: false,
      jitterMaxMs: 100,
    },
  },
];

// ============================================================================
// DAILY MUTATION SEED GENERATION
// ============================================================================

/**
 * Get the current date components for seed generation.
 * @returns {{year: string, month: string, day: string, hour: string, dayOfWeek: number}}
 */
function getDateComponents() {
  const now = new Date();
  const year = String(now.getFullYear());
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  const hour = String(now.getHours()).padStart(2, '0');
  const dayOfWeek = now.getDay(); // 0 = Sunday
  return { year, month, day, hour, dayOfWeek };
}

/**
 * Generate the daily mutation seed.
 * Formula: SHA512( SERVER_SECRET + date('Y-m-d-H') + dayOfWeek )
 * @param {string} serverSecret - The server secret
 * @returns {Buffer} 64-byte daily seed
 */
function generateDailySeed(serverSecret) {
  const { year, month, day, hour, dayOfWeek } = getDateComponents();
  const dateString = `${year}-${month}-${day}-${hour}`;
  const seed = createHash('sha512')
    .update(serverSecret)
    .update(dateString)
    .update(String(dayOfWeek))
    .digest();
  return seed;
}

/**
 * Generate the hourly mutation seed (extra protection layer).
 * Formula: SHA512( HOURLY_SALT + dailySeed + currentHour )
 * @param {string} hourlySalt - Hourly salt from env
 * @param {Buffer} dailySeed - Daily seed
 * @returns {Buffer} 64-byte hourly seed
 */
function generateHourlySeed(hourlySalt, dailySeed) {
  const now = new Date();
  const currentHour = String(now.getHours()).padStart(2, '0');
  const currentMinute = String(Math.floor(now.getMinutes() / 10) * 10).padStart(2, '0');
  return createHash('sha512')
    .update(hourlySalt)
    .update(dailySeed)
    .update(currentHour)
    .update(currentMinute)
    .digest();
}

/**
 * Get the daily config hash that determines which of 1500+ configs is active.
 * Uses first 4 bytes of daily seed as config selector index.
 * @param {Buffer} dailySeed - The daily seed
 * @returns {number} Config index (0-1499)
 */
function getDailyConfigIndex(dailySeed) {
  const index = dailySeed.readUInt32BE(0) % 1500;
  return index;
}

/**
 * Get the current mutation profile based on daily + hourly seeds.
 * Determines which algorithms, endpoints, validations are active.
 * @param {Buffer} dailySeed - Daily seed
 * @param {Buffer} hourlySeed - Hourly seed
 * @returns {Object} Mutation profile
 */
function generateMutationProfile(dailySeed, hourlySeed) {
  const profile = {
    timestamp: new Date().toISOString(),
    dailyConfigIndex: getDailyConfigIndex(dailySeed),
    activeGroups: [],
    activeLayers: [],
    algorithmSelections: {},
    validationActivations: {},
    paramOverrides: {},
  };

  MUTATION_GROUPS.forEach((group, groupIndex) => {
    if (!group.active) return;

    // Use daily seed to determine if group is fully active today
    const groupActiveByte = dailySeed[groupIndex % 64];
    const isFullyActive = (groupActiveByte & 0x80) !== 0;

    // Use hourly seed to select algorithm variant
    const variantIndex = hourlySeed[groupIndex % 64] % group.algorithmVariants.length;
    const selectedVariant = group.algorithmVariants[variantIndex];

    // Select validation rules based on combined seeds
    const validations = [];
    group.validationRules.forEach((rule, ruleIndex) => {
      const ruleByte = dailySeed[(groupIndex + ruleIndex) % 64];
      if ((ruleByte & 0x01) !== 0 || isFullyActive) {
        validations.push(rule);
      }
    });

    profile.activeGroups.push({
      name: group.name,
      priority: group.priority,
      fullyActive: isFullyActive,
      layerOffset: group.layerOffset,
    });

    // Activate layers for this group
    const layerCount = isFullyActive ? 500 : 250;
    for (let i = 0; i < layerCount; i++) {
      const layerId = group.layerOffset + i;
      const layerByte = dailySeed[i % 64] ^ hourlySeed[(i + groupIndex) % 64];
      if ((layerByte & 0x03) !== 0 || isFullyActive) {
        profile.activeLayers.push(layerId);
      }
    }

    profile.algorithmSelections[group.name] = selectedVariant;
    profile.validationActivations[group.name] = validations;
    profile.paramOverrides[group.name] = { ...group.params };
  });

  // Deduplicate active layers
  profile.activeLayers = [...new Set(profile.activeLayers)].sort((a, b) => a - b);
  profile.activeLayerCount = profile.activeLayers.length;

  return Object.freeze(profile);
}

// ============================================================================
// ENVIRONMENT PARSING
// ============================================================================

/**
 * Parse all environment variables into structured config.
 * Secrets are encrypted in memory immediately.
 * @returns {Object} Parsed configuration
 * @throws {EnvValidationError|ConfigValidationError}
 */
function parseEnvironment() {
  validateRequiredEnv();

  const ipBlacklist = parseListEnv(process.env.IP_BLACKLIST);
  const ipWhitelist = parseListEnv(process.env.IP_WHITELIST);

  return {
    server: {
      port: parseIntEnv(process.env.PORT, 'PORT', 1024, 65535),
      nodeEnv: process.env.NODE_ENV,
      serverSecret: encryptInMemory(process.env.SERVER_SECRET),
    },
    database: {
      mongodbUri: encryptInMemory(process.env.MONGODB_URI),
      retryWrites: parseBoolEnv(process.env.MONGODB_RETRY_WRITES || 'true', 'MONGODB_RETRY_WRITES'),
      maxPoolSize: parseIntEnv(process.env.MONGODB_MAX_POOL_SIZE || '50', 'MONGODB_MAX_POOL_SIZE', 5, 200),
      minPoolSize: parseIntEnv(process.env.MONGODB_MIN_POOL_SIZE || '5', 'MONGODB_MIN_POOL_SIZE', 1, 50),
      connectTimeoutMs: parseIntEnv(process.env.MONGODB_CONNECT_TIMEOUT || '10000', 'MONGODB_CONNECT_TIMEOUT', 1000, 60000),
      serverSelectionTimeoutMs: parseIntEnv(process.env.MONGODB_SELECTION_TIMEOUT || '5000', 'MONGODB_SELECTION_TIMEOUT', 1000, 30000),
      heartbeatFrequencyMs: parseIntEnv(process.env.MONGODB_HEARTBEAT || '10000', 'MONGODB_HEARTBEAT', 5000, 60000),
    },
    telegram: {
      botToken: encryptInMemory(process.env.TELEGRAM_BOT_TOKEN),
      channels: [
        process.env.TELEGRAM_CHANNEL_PRIMARY,
        process.env.TELEGRAM_CHANNEL_SECONDARY,
        process.env.TELEGRAM_CHANNEL_ALERTS,
      ],
    },
    security: {
      aesMasterKey: encryptInMemory(process.env.AES_MASTER_KEY),
      hmacSecret: encryptInMemory(process.env.HMAC_SECRET),
      jwtSecret: encryptInMemory(process.env.JWT_SECRET),
      sessionSecret: encryptInMemory(process.env.SESSION_SECRET),
      rateLimitWindowMs: parseIntEnv(process.env.RATE_LIMIT_WINDOW_MS, 'RATE_LIMIT_WINDOW_MS', 1000, 3600000),
      rateLimitMaxRequests: parseIntEnv(process.env.RATE_LIMIT_MAX_REQUESTS, 'RATE_LIMIT_MAX_REQUESTS', 1, 10000),
      rateLimitTokenWindowMs: parseIntEnv(process.env.RATE_LIMIT_TOKEN_WINDOW_MS, 'RATE_LIMIT_TOKEN_WINDOW_MS', 1000, 3600000),
      rateLimitMaxTokens: parseIntEnv(process.env.RATE_LIMIT_MAX_TOKENS, 'RATE_LIMIT_MAX_TOKENS', 1, 100000),
      ipBlacklist,
      ipWhitelist,
      deviceFingerprintSalt: encryptInMemory(process.env.DEVICE_FINGERPRINT_SALT),
      adminUsernameHash: process.env.ADMIN_USERNAME_HASH,
      admin2FASecret: encryptInMemory(process.env.ADMIN_2FA_SECRET),
      killSwitchEnabled: parseBoolEnv(process.env.KILL_SWITCH_ENABLED, 'KILL_SWITCH_ENABLED'),
      securityLayersCount: parseIntEnv(process.env.SECURITY_LAYERS_COUNT, 'SECURITY_LAYERS_COUNT', 1000, 10000),
    },
    mutation: {
      seedSalt: encryptInMemory(process.env.MUTATION_SEED_SALT),
      dailySalt: encryptInMemory(process.env.MUTATION_DAILY_SALT),
      hourlySalt: encryptInMemory(process.env.MUTATION_HOURLY_SALT),
      groups: MUTATION_GROUPS,
    },
    encryption: {
      watermarkSecret: encryptInMemory(process.env.WATERMARK_SECRET),
      watermarkSeed: encryptInMemory(process.env.WATERMARK_SEED),
      powDifficultyBase: parseIntEnv(process.env.POW_DIFFICULTY_BASE, 'POW_DIFFICULTY_BASE', 1, 10),
      powMaxAttempts: parseIntEnv(process.env.POW_MAX_ATTEMPTS, 'POW_MAX_ATTEMPTS', 1, 1000),
      tokenExpirySeconds: parseIntEnv(process.env.TOKEN_EXPIRY_SECONDS, 'TOKEN_EXPIRY_SECONDS', 1, 3600),
      maxTokensPerIpPerHour: parseIntEnv(process.env.MAX_TOKENS_PER_IP_PER_HOUR, 'MAX_TOKENS_PER_IP_PER_HOUR', 1, 10000),
    },
  };
}

// ============================================================================
// DEEP FREEZE UTILITY
// ============================================================================

/**
 * Recursively freeze an object and all its properties.
 * @param {Object} obj - Object to freeze
 * @returns {Object} Frozen object
 */
function deepFreeze(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  if (Object.isFrozen(obj)) return obj;

  const propNames = Object.getOwnPropertyNames(obj);
  propNames.forEach((name) => {
    const value = obj[name];
    if (value !== null && typeof value === 'object') {
      deepFreeze(value);
    }
  });

  return Object.freeze(obj);
}

// ============================================================================
// SAFE CONFIG ACCESS (NON-SECRET ONLY)
// ============================================================================

/**
 * Check if a key path points to a secret field.
 * @param {string[]} pathParts - Path parts
 * @returns {boolean}
 */
function isSecretPath(pathParts) {
  const secretKeys = [
    'serverSecret', 'mongodbUri', 'botToken', 'aesMasterKey',
    'hmacSecret', 'jwtSecret', 'sessionSecret', 'seedSalt',
    'dailySalt', 'hourlySalt', 'deviceFingerprintSalt',
    'watermarkSecret', 'watermarkSeed', 'admin2FASecret',
  ];
  return pathParts.some((part) => secretKeys.includes(part));
}

/**
 * Safely get a config value without exposing secrets.
 * @param {Object} config - Config object
 * @param {string} path - Dot-separated path (e.g., 'server.port')
 * @returns {*} Config value or undefined
 */
function safeGet(config, path) {
  const parts = path.split('.');
  if (isSecretPath(parts)) {
    return '[ENCRYPTED]';
  }
  let current = config;
  for (const part of parts) {
    if (current === null || current === undefined || typeof current !== 'object') {
      return undefined;
    }
    current = current[part];
  }
  return current;
}

/**
 * Get config for logging (scrubbed of all secrets).
 * @param {Object} config - Config object
 * @returns {Object} Scrubbed config
 */
function getScrubbedConfig(config) {
  const scrubbed = JSON.parse(JSON.stringify(config, (key, value) => {
    const secretKeys = [
      'serverSecret', 'mongodbUri', 'botToken', 'aesMasterKey',
      'hmacSecret', 'jwtSecret', 'sessionSecret', 'seedSalt',
      'dailySalt', 'hourlySalt', 'deviceFingerprintSalt',
      'watermarkSecret', 'watermarkSeed', 'admin2FASecret',
    ];
    if (secretKeys.includes(key)) {
      return '[ENCRYPTED]';
    }
    return value;
  }));
  return scrubbed;
}

// ============================================================================
// CONFIG BUILDER CLASS
// ============================================================================

/**
 * Central configuration manager with mutation engine.
 * Singleton pattern - only one instance exists per process.
 */
class ConfigManager {
  /** @type {ConfigManager|null} */
  static #instance = null;

  /** @type {Object|null} */
  #config = null;

  /** @type {Buffer|null} */
  #dailySeed = null;

  /** @type {Buffer|null} */
  #hourlySeed = null;

  /** @type {Object|null} */
  #mutationProfile = null;

  /** @type {number} */
  #initializedAt = 0;

  /** @type {string} */
  #instanceId = randomBytes(16).toString('hex');

  /**
   * Private constructor - use getInstance().
   */
  constructor() {
    if (ConfigManager.#instance) {
      throw new ConfigError('Use ConfigManager.getInstance() instead of new');
    }
  }

  /**
   * Get the singleton ConfigManager instance.
   * @returns {ConfigManager}
   */
  static getInstance() {
    if (!ConfigManager.#instance) {
      ConfigManager.#instance = new ConfigManager();
    }
    return ConfigManager.#instance;
  }

  /**
   * Initialize the configuration system.
   * Must be called once at startup before any other operations.
   * @returns {Object} Frozen configuration object
   * @throws {ConfigError} If initialization fails
   */
  initialize() {
    if (this.#config) {
      throw new ConfigError('Configuration already initialized');
    }

    try {
      const rawConfig = parseEnvironment();
      this.#dailySeed = generateDailySeed(process.env.SERVER_SECRET);
      this.#hourlySeed = generateHourlySeed(
        process.env.MUTATION_HOURLY_SALT,
        this.#dailySeed,
      );
      this.#mutationProfile = generateMutationProfile(this.#dailySeed, this.#hourlySeed);
      this.#initializedAt = Date.now();

      // Attach mutation methods to config
      const enhancedConfig = {
        ...rawConfig,
        _meta: {
          instanceId: this.#instanceId,
          initializedAt: new Date(this.#initializedAt).toISOString(),
          dailySeedHash: createHash('sha256').update(this.#dailySeed).digest('hex'),
          hourlySeedHash: createHash('sha256').update(this.#hourlySeed).digest('hex'),
          dailyConfigIndex: this.#mutationProfile.dailyConfigIndex,
          activeLayerCount: this.#mutationProfile.activeLayerCount,
          version: '1.0.0',
        },
        _methods: {
          getDailyConfigIndex: () => this.#mutationProfile.dailyConfigIndex,
          getActiveLayerCount: () => this.#mutationProfile.activeLayerCount,
          isLayerActive: (layerId) => this.#mutationProfile.activeLayers.includes(layerId),
          getMutationProfile: () => this.#mutationProfile,
          getActiveGroups: () => this.#mutationProfile.activeGroups,
          getAlgorithmSelection: (groupName) => this.#mutationProfile.algorithmSelections[groupName],
          getValidationActivations: (groupName) => this.#mutationProfile.validationActivations[groupName],
          getScrubbedConfig: () => getScrubbedConfig(rawConfig),
          safeGet: (path) => safeGet(rawConfig, path),
          reload: () => this.reload(),
          getInstanceId: () => this.#instanceId,
          getUptime: () => Date.now() - this.#initializedAt,
        },
      };

      this.#config = deepFreeze(enhancedConfig);
      return this.#config;
    } catch (err) {
      if (err instanceof ConfigError) throw err;
      throw new ConfigError(`Initialization failed: ${err.message}`);
    }
  }

  /**
   * Reload configuration and regenerate mutation seeds.
   * Use sparingly - triggers full re-initialization.
   * @returns {Object} New frozen configuration
   */
  reload() {
    this.#config = null;
    this.#dailySeed = null;
    this.#hourlySeed = null;
    this.#mutationProfile = null;
    this.#initializedAt = 0;
    return this.initialize();
  }

  /**
   * Load configuration from environment variables.
   * Provides a flat config object compatible with server.js usage.
   * @returns {ConfigManager} this for chaining
   */
  load() {
    this.#config = {
      MONGODB_URI: process.env.MONGODB_URI || process.env.DB_URI,
      DB_NAME: process.env.DB_NAME || 'osmarmy',
      DB_POOL_SIZE: process.env.MONGODB_POOL_SIZE || process.env.DB_POOL_SIZE,
      MONGODB_POOL_MAX: process.env.MONGODB_MAX_POOL_SIZE || '50',
      REDIS_URL: process.env.REDIS_URL || process.env.REDIS_URI,
      BOT_TOKEN: process.env.TELEGRAM_BOT_TOKEN || process.env.BOT_TOKEN,
      JWT_SECRET: process.env.JWT_SECRET,
      ENCRYPTION_KEY: process.env.AES_MASTER_KEY || process.env.ENCRYPTION_KEY,
      ADMIN_IP_ALLOWLIST: process.env.ADMIN_IP_ALLOWLIST,
      ADMIN_ALLOWED_IPS: process.env.ADMIN_ALLOWED_IPS,
      ADMIN_2FA_REQUIRED: process.env.ADMIN_2FA_REQUIRED === 'true',
      ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS || 'https://osmarmy.com',
      NODE_ENV: process.env.NODE_ENV || 'development',
      PORT: parseInt(process.env.PORT) || 3000,
      SERVER_SECRET: process.env.SERVER_SECRET,
      AES_MASTER_KEY: process.env.AES_MASTER_KEY,
      HMAC_SECRET: process.env.HMAC_SECRET,
      SESSION_SECRET: process.env.SESSION_SECRET,
      MUTATION_SEED_SALT: process.env.MUTATION_SEED_SALT,
      MUTATION_DAILY_SALT: process.env.MUTATION_DAILY_SALT,
      MUTATION_HOURLY_SALT: process.env.MUTATION_HOURLY_SALT,
      RATE_LIMIT_WINDOW_MS: process.env.RATE_LIMIT_WINDOW_MS,
      RATE_LIMIT_MAX_REQUESTS: process.env.RATE_LIMIT_MAX_REQUESTS,
      RATE_LIMIT_TOKEN_WINDOW_MS: process.env.RATE_LIMIT_TOKEN_WINDOW_MS,
      RATE_LIMIT_MAX_TOKENS: process.env.RATE_LIMIT_MAX_TOKENS,
      DEVICE_FINGERPRINT_SALT: process.env.DEVICE_FINGERPRINT_SALT,
      WATERMARK_SECRET: process.env.WATERMARK_SECRET,
      WATERMARK_SEED: process.env.WATERMARK_SEED,
      POW_DIFFICULTY_BASE: process.env.POW_DIFFICULTY_BASE,
      POW_MAX_ATTEMPTS: process.env.POW_MAX_ATTEMPTS,
      TOKEN_EXPIRY_SECONDS: process.env.TOKEN_EXPIRY_SECONDS,
      MAX_TOKENS_PER_IP_PER_HOUR: process.env.MAX_TOKENS_PER_IP_PER_HOUR,
      ADMIN_USERNAME_HASH: process.env.ADMIN_USERNAME_HASH,
      ADMIN_2FA_SECRET: process.env.ADMIN_2FA_SECRET,
      KILL_SWITCH_ENABLED: process.env.KILL_SWITCH_ENABLED,
      SECURITY_LAYERS_COUNT: process.env.SECURITY_LAYERS_COUNT,
      TELEGRAM_CHANNEL_PRIMARY: process.env.TELEGRAM_CHANNEL_PRIMARY,
      TELEGRAM_CHANNEL_SECONDARY: process.env.TELEGRAM_CHANNEL_SECONDARY,
      TELEGRAM_CHANNEL_ALERTS: process.env.TELEGRAM_CHANNEL_ALERTS,
      TELEGRAM_BOT_TOKEN: process.env.TELEGRAM_BOT_TOKEN,
      TRUST_PROXY: process.env.TRUST_PROXY,
      TURNSTILE_SITE_KEY: process.env.TURNSTILE_SITE_KEY,
      IP_HASH_SECRET: process.env.IP_HASH_SECRET,
      IP_BLACKLIST: process.env.IP_BLACKLIST,
      IP_WHITELIST: process.env.IP_WHITELIST,
      FACTOR1_SECRET: process.env.FACTOR1_SECRET,
      MONGODB_RETRY_WRITES: process.env.MONGODB_RETRY_WRITES,
      MONGODB_MAX_POOL_SIZE: process.env.MONGODB_MAX_POOL_SIZE,
      MONGODB_MIN_POOL_SIZE: process.env.MONGODB_MIN_POOL_SIZE,
      MONGODB_CONNECT_TIMEOUT: process.env.MONGODB_CONNECT_TIMEOUT,
      MONGODB_SELECTION_TIMEOUT: process.env.MONGODB_SELECTION_TIMEOUT,
      MONGODB_HEARTBEAT: process.env.MONGODB_HEARTBEAT,
    };
    this.logger = console;
    return this;
  }

  /**
   * Get a configuration value by key.
   * @param {string} key - Config key
   * @returns {*} Config value or undefined
   */
  get(key) {
    return this.config ? this.config[key] : undefined;
  }

  /**
   * Get a decrypted secret value.
   * @param {string} category - Config category
   * @param {string} key - Secret key name
   * @returns {string|null} Decrypted value or null
   */
  getSecret(category, key) {
    if (!this.#config) {
      throw new ConfigError('Configuration not initialized. Call initialize() first.');
    }
    if (!this.#config[category]) {
      throw new ConfigError(`Unknown config category: ${category}`);
    }
    const encrypted = this.#config[category][key];
    if (!encrypted) return null;
    if (encrypted === '[ENCRYPTED]') {
      throw new ConfigError(`Value at ${category}.${key} is not a valid encrypted secret`);
    }
    return decryptInMemory(encrypted);
  }

  /**
   * Get the raw config object.
   * @returns {Object}
   */
  get config() {
    return this.#config;
  }

  /**
   * Get the daily mutation seed.
   * @returns {Buffer|null}
   */
  get dailySeed() {
    return this.#dailySeed;
  }

  /**
   * Get the hourly mutation seed.
   * @returns {Buffer|null}
   */
  get hourlySeed() {
    return this.#hourlySeed;
  }

  /**
   * Get the current mutation profile.
   * @returns {Object|null}
   */
  get mutationProfile() {
    return this.#mutationProfile;
  }

  /**
   * Check if configuration is initialized.
   * @returns {boolean}
   */
  get isInitialized() {
    return this.#config !== null;
  }
}

// ============================================================================
// MUTATION PROFILE ACCESSOR FUNCTIONS
// ============================================================================

/**
 * Get the daily config hash that determines which of 1500+ configs is active.
 * @param {Buffer} dailySeed - Daily mutation seed
 * @returns {Object} Config hash info
 */
export function getDailyConfigHash(dailySeed) {
  if (!Buffer.isBuffer(dailySeed) || dailySeed.length !== 64) {
    throw new MutationError('Daily seed must be a 64-byte Buffer');
  }

  const index = dailySeed.readUInt32BE(0) % 1500;
  const secondaryIndex = dailySeed.readUInt32BE(4) % 1500;
  const tertiaryIndex = dailySeed.readUInt32BE(8) % 1500;

  return {
    primaryIndex: index,
    secondaryIndex,
    tertiaryIndex,
    combinedHash: createHash('sha256')
      .update(dailySeed)
      .update('config-selector')
      .digest('hex'),
    timestamp: new Date().toISOString(),
  };
}

/**
 * Get current mutation profile with full layer activation info.
 * @param {Buffer} dailySeed - Daily seed
 * @param {Buffer} hourlySeed - Hourly seed
 * @returns {Object} Full mutation profile
 */
export function getCurrentMutationProfile(dailySeed, hourlySeed) {
  if (!Buffer.isBuffer(dailySeed) || dailySeed.length !== 64) {
    throw new MutationError('Daily seed must be a 64-byte Buffer');
  }
  if (!Buffer.isBuffer(hourlySeed) || hourlySeed.length !== 64) {
    throw new MutationError('Hourly seed must be a 64-byte Buffer');
  }
  return generateMutationProfile(dailySeed, hourlySeed);
}

/**
 * Check if a specific security layer is currently active.
 * @param {number} layerId - Layer ID (0-4999)
 * @param {Object} profile - Mutation profile
 * @returns {boolean}
 */
export function isLayerActive(layerId, profile) {
  if (typeof layerId !== 'number' || layerId < 0 || layerId >= 5000) {
    throw new MutationError('Layer ID must be 0-4999');
  }
  if (!profile || !Array.isArray(profile.activeLayers)) {
    throw new MutationError('Invalid mutation profile');
  }
  return profile.activeLayers.includes(layerId);
}

/**
 * Get active mutation groups for the current period.
 * @param {Object} profile - Mutation profile
 * @returns {Array<Object>} Active groups with their configs
 */
export function getActiveMutationGroups(profile) {
  if (!profile || !Array.isArray(profile.activeGroups)) {
    throw new MutationError('Invalid mutation profile');
  }
  return profile.activeGroups.map((group) => ({
    ...group,
    algorithm: profile.algorithmSelections[group.name],
    validations: profile.validationActivations[group.name] || [],
    params: profile.paramOverrides[group.name] || {},
  }));
}

/**
 * Generate a deterministic layer activation sequence from seeds.
 * @param {Buffer} seed - Primary seed
 * @param {number} layerCount - Number of layers to generate
 * @param {number} totalLayers - Total available layers
 * @returns {number[]} Activated layer IDs
 */
export function generateLayerActivation(seed, layerCount, totalLayers = 5000) {
  if (!Buffer.isBuffer(seed) || seed.length < 32) {
    throw new MutationError('Seed must be a Buffer of at least 32 bytes');
  }
  if (typeof layerCount !== 'number' || layerCount < 1 || layerCount > totalLayers) {
    throw new MutationError(`Layer count must be 1-${totalLayers}`);
  }

  const activated = new Set();
  let offset = 0;

  while (activated.size < layerCount && offset < seed.length * 8) {
    const byteIndex = offset % seed.length;
    const bitIndex = Math.floor(offset / seed.length) % 8;
    const value = (seed[byteIndex] >> bitIndex) & 0xFF;
    const layerId = value % totalLayers;
    activated.add(layerId);
    offset++;
  }

  return [...activated].sort((a, b) => a - b);
}

// ============================================================================
// EXPORTS
// ============================================================================

export { ConfigManager, MUTATION_GROUPS, deepFreeze };

/**
 * Factory function to create and initialize the ConfigManager.
 * @returns {Object} Frozen configuration object
 * @throws {ConfigError} If initialization fails
 */
export function createConfig() {
  const manager = ConfigManager.getInstance();
  return manager.initialize();
}

/**
 * Get the initialized ConfigManager singleton.
 * @returns {ConfigManager}
 * @throws {ConfigError} If not initialized
 */
export function getConfigManager() {
  const manager = ConfigManager.getInstance();
  if (!manager.isInitialized) {
    throw new ConfigError('ConfigManager not initialized. Call createConfig() first.');
  }
  return manager;
}

/**
 * Quick access to config values.
 * @returns {Object} Frozen config
 * @throws {ConfigError} If not initialized
 */
export function getConfig() {
  const manager = getConfigManager();
  return manager.config;
}

/**
 * Get a decrypted secret.
 * @param {string} category - Category name
 * @param {string} key - Key name
 * @returns {string|null} Decrypted secret
 */
export function getSecret(category, key) {
  const manager = getConfigManager();
  return manager.getSecret(category, key);
}

/**
 * Get the current daily mutation seed.
 * @returns {Buffer}
 */
export function getDailySeed() {
  const manager = getConfigManager();
  return manager.dailySeed;
}

/**
 * Get the current hourly mutation seed.
 * @returns {Buffer}
 */
export function getHourlySeed() {
  const manager = getConfigManager();
  return manager.hourlySeed;
}

/**
 * Get the current mutation profile.
 * @returns {Object}
 */
export function getMutationProfile() {
  const manager = getConfigManager();
  return manager.mutationProfile;
}

export default {
  createConfig,
  getConfigManager,
  getConfig,
  getSecret,
  getDailySeed,
  getHourlySeed,
  getMutationProfile,
  getDailyConfigHash,
  getCurrentMutationProfile,
  isLayerActive,
  getActiveMutationGroups,
  generateLayerActivation,
  ConfigManager,
  MUTATION_GROUPS,
  deepFreeze,
  ConfigError,
  EnvValidationError,
  ConfigValidationError,
  MutationError,
};
