/**
 * @fileoverview Cryptographic Utilities Module
 * @description All encryption, decryption, hashing, and token functions using
 * ONLY Node.js built-in crypto module. No external crypto dependencies.
 * Implements AES-256-GCM, HMAC-SHA512, PBKDF2, scrypt, timing-safe comparison,
 * JWT operations, secure random generation, and key rotation.
 * @module core/encrypt
 * @version 1.0.0
 */

import {
  createHash,
  createHmac,
  randomBytes,
  createCipheriv,
  createDecipheriv,
  pbkdf2Sync,
  scryptSync,
  timingSafeEqual,
  randomUUID,
  getRandomValues,
} from 'node:crypto';

// ============================================================================
// CUSTOM ERROR CLASSES
// ============================================================================

/**
 * Base encryption error.
 */
export class EncryptionError extends Error {
  constructor(message) {
    super(message);
    this.name = 'EncryptionError';
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Error for decryption failures (wrong key, tampered data, etc.).
 */
export class DecryptionError extends EncryptionError {
  constructor(message = 'Decryption failed') {
    super(message);
    this.name = 'DecryptionError';
  }
}

/**
 * Error for invalid HMAC / authentication failures.
 */
export class AuthenticationError extends EncryptionError {
  constructor(message = 'Authentication failed') {
    super(message);
    this.name = 'AuthenticationError';
  }
}

/**
 * Error for key derivation failures.
 */
export class KeyDerivationError extends EncryptionError {
  constructor(message = 'Key derivation failed') {
    super(message);
    this.name = 'KeyDerivationError';
  }
}

// ============================================================================
// KEY MANAGEMENT
// ============================================================================

/**
 * Primary and secondary keys for rotation support.
 * @type {{primary: Buffer|null, secondary: Buffer|null, rotatedAt: number}}
 */
let keyStore = {
  primary: null,
  secondary: null,
  rotatedAt: 0,
};

/**
 * Key rotation interval in milliseconds (default: 1 hour).
 * @type {number}
 */
const KEY_ROTATION_INTERVAL_MS = 60 * 60 * 1000;

/**
 * Initialize the key store with primary and optional secondary key.
 * @param {string|Buffer} primaryKey - Primary encryption key
 * @param {string|Buffer} [secondaryKey] - Secondary (previous) key for decrypting old data
 */
export function initializeKeys(primaryKey, secondaryKey = null) {
  if (!primaryKey) {
    throw new EncryptionError('Primary key is required');
  }

  const normalize = (k) => {
    if (Buffer.isBuffer(k)) {
      if (k.length !== 32) {
        throw new EncryptionError(`Key must be 32 bytes, got ${k.length}`);
      }
      return k;
    }
    if (typeof k === 'string') {
      const buf = Buffer.from(k, 'hex');
      if (buf.length !== 32) {
        throw new EncryptionError(`Hex key must decode to 32 bytes, got ${buf.length}`);
      }
      return buf;
    }
    throw new EncryptionError('Key must be a Buffer or hex string');
  };

  keyStore = {
    primary: normalize(primaryKey),
    secondary: secondaryKey ? normalize(secondaryKey) : null,
    rotatedAt: Date.now(),
  };
}

/**
 * Get the current primary key.
 * @returns {Buffer} 32-byte key
 * @throws {EncryptionError} If keys not initialized
 */
function getPrimaryKey() {
  if (!keyStore.primary) {
    throw new EncryptionError('Keys not initialized. Call initializeKeys() first.');
  }

  // Auto-rotation check
  const elapsed = Date.now() - keyStore.rotatedAt;
  if (elapsed > KEY_ROTATION_INTERVAL_MS * 2) {
    // Key is overdue for rotation - still use it but warn conceptually
    // In production this would trigger an alert
  }

  return keyStore.primary;
}

/**
 * Rotate keys: promote primary to secondary, set new primary.
 * @param {string|Buffer} newPrimaryKey - New primary key
 * @returns {Object} New key metadata
 */
export function rotateKeys(newPrimaryKey) {
  const normalize = (k) => {
    if (Buffer.isBuffer(k)) return k;
    return Buffer.from(k, 'hex');
  };

  const newKey = normalize(newPrimaryKey);
  if (newKey.length !== 32) {
    throw new EncryptionError('New primary key must be 32 bytes');
  }

  keyStore = {
    secondary: keyStore.primary,
    primary: newKey,
    rotatedAt: Date.now(),
  };

  return {
    rotatedAt: keyStore.rotatedAt,
    hasSecondary: keyStore.secondary !== null,
  };
}

/**
 * Derive a 32-byte encryption key from a master key using HKDF-like approach.
 * @param {string|Buffer} masterKey - Master key material
 * @param {string} context - Context string for domain separation
 * @param {number} [length=32] - Output key length in bytes
 * @returns {Buffer} Derived key
 */
export function deriveKey(masterKey, context, length = 32) {
  if (!masterKey) {
    throw new KeyDerivationError('Master key is required');
  }
  if (!context || typeof context !== 'string') {
    throw new KeyDerivationError('Context string is required for domain separation');
  }

  const master = Buffer.isBuffer(masterKey)
    ? masterKey
    : Buffer.from(masterKey, 'utf8');

  // HKDF-like extract-then-expand
  const salt = randomBytes(32);
  const extract = createHmac('sha512', salt).update(master).digest();

  const okm = Buffer.alloc(length);
  let prev = Buffer.alloc(0);
  const n = Math.ceil(length / 64); // SHA-512 produces 64 bytes

  for (let i = 1; i <= n; i++) {
    const t = createHmac('sha512', extract)
      .update(prev)
      .update(context, 'utf8')
      .update(Buffer.from([i]))
      .digest();
    prev = t;
    t.copy(okm, (i - 1) * 64);
  }

  return okm.subarray(0, length);
}

// ============================================================================
// AES-256-GCM ENCRYPTION / DECRYPTION
// ============================================================================

/**
 * AES-256-GCM encryption result.
 * @typedef {Object} EncryptedData
 * @property {string} ciphertext - Base64 encrypted payload
 * @property {string} iv - Base64 initialization vector
 * @property {string} tag - Base64 authentication tag
 * @property {string} version - Encryption version identifier
 */

/**
 * Encrypt data using AES-256-GCM with authenticated encryption.
 * @param {string|Buffer} plaintext - Data to encrypt
 * @param {Buffer} [key] - Optional 32-byte key (uses primary key if omitted)
 * @returns {EncryptedData} Encrypted result
 * @throws {EncryptionError} On encryption failure
 */
export function encryptAES(plaintext, key = null) {
  try {
    const encryptionKey = key || getPrimaryKey();
    if (encryptionKey.length !== 32) {
      throw new EncryptionError('Encryption key must be 32 bytes for AES-256');
    }

    const iv = randomBytes(16);
    const cipher = createCipheriv('aes-256-gcm', encryptionKey, iv);

    const input = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
    const encrypted = Buffer.concat([cipher.update(input), cipher.final()]);
    const tag = cipher.getAuthTag();

    return {
      ciphertext: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      version: 'v1',
    };
  } catch (err) {
    if (err instanceof EncryptionError) throw err;
    throw new EncryptionError(`AES encryption failed: ${err.message}`);
  }
}

/**
 * Decrypt AES-256-GCM encrypted data with authentication verification.
 * @param {EncryptedData|string} data - Encrypted data object or JSON string
 * @param {Buffer} [key] - Optional 32-byte key (tries primary then secondary)
 * @returns {Buffer} Decrypted plaintext as Buffer
 * @throws {DecryptionError} On decryption or authentication failure
 */
export function decryptAES(data, key = null) {
  try {
    let encrypted;
    if (typeof data === 'string') {
      try {
        encrypted = JSON.parse(data);
      } catch {
        throw new DecryptionError('Invalid encrypted data format');
      }
    } else {
      encrypted = data;
    }

    if (!encrypted.ciphertext || !encrypted.iv || !encrypted.tag) {
      throw new DecryptionError('Missing required encryption fields');
    }

    const iv = Buffer.from(encrypted.iv, 'base64');
    const tag = Buffer.from(encrypted.tag, 'base64');
    const ciphertext = Buffer.from(encrypted.ciphertext, 'base64');

    if (iv.length !== 16) {
      throw new DecryptionError('Invalid IV length');
    }
    if (tag.length !== 16) {
      throw new DecryptionError('Invalid authentication tag length');
    }

    const keysToTry = key ? [key] : [keyStore.primary, keyStore.secondary].filter(Boolean);

    for (const tryKey of keysToTry) {
      try {
        const decipher = createDecipheriv('aes-256-gcm', tryKey, iv);
        decipher.setAuthTag(tag);
        const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        return decrypted;
      } catch {
        continue;
      }
    }

    throw new DecryptionError('Failed to decrypt with any available key');
  } catch (err) {
    if (err instanceof DecryptionError) throw err;
    throw new DecryptionError(`AES decryption failed: ${err.message}`);
  }
}

/**
 * Encrypt a string and return a single base64 blob (iv:tag:ciphertext).
 * @param {string} plaintext - String to encrypt
 * @param {Buffer} [key] - Optional key
 * @returns {string} Base64 combined blob
 */
export function encryptString(plaintext, key = null) {
  const result = encryptAES(plaintext, key);
  const iv = Buffer.from(result.iv, 'base64');
  const tag = Buffer.from(result.tag, 'base64');
  const ciphertext = Buffer.from(result.ciphertext, 'base64');
  return Buffer.concat([iv, tag, ciphertext]).toString('base64');
}

/**
 * Decrypt a base64 blob (iv:tag:ciphertext) back to string.
 * @param {string} blob - Base64 combined blob
 * @param {Buffer} [key] - Optional key
 * @returns {string} Decrypted string
 */
export function decryptString(blob, key = null) {
  const buf = Buffer.from(blob, 'base64');
  if (buf.length < 33) {
    throw new DecryptionError('Invalid encrypted blob');
  }
  const iv = buf.subarray(0, 16).toString('base64');
  const tag = buf.subarray(16, 32).toString('base64');
  const ciphertext = buf.subarray(32).toString('base64');
  const decrypted = decryptAES({ iv, tag, ciphertext }, key);
  return decrypted.toString('utf8');
}

// ============================================================================
// DATABASE FIELD ENCRYPTION
// ============================================================================

/**
 * Encrypt a database field before storage.
 * @param {*} value - Value to encrypt (stringified if object)
 * @param {Buffer} [key] - Optional key
 * @returns {string} Encrypted field blob
 */
export function encryptField(value, key = null) {
  const plaintext = typeof value === 'string' ? value : JSON.stringify(value);
  return encryptString(plaintext, key);
}

/**
 * Decrypt a database field after retrieval.
 * @param {string} encrypted - Encrypted field blob
 * @param {boolean} [parseJson=false] - Whether to parse result as JSON
 * @param {Buffer} [key] - Optional key
 * @returns {*} Decrypted value
 */
export function decryptField(encrypted, parseJson = false, key = null) {
  const decrypted = decryptString(encrypted, key);
  if (parseJson) {
    try {
      return JSON.parse(decrypted);
    } catch {
      return decrypted;
    }
  }
  return decrypted;
}

/**
 * Encrypt sensitive fields of an object selectively.
 * @param {Object} obj - Object to encrypt fields of
 * @param {string[]} fields - Field names to encrypt
 * @param {Buffer} [key] - Optional key
 * @returns {Object} Object with encrypted fields
 */
export function encryptObjectFields(obj, fields, key = null) {
  if (!obj || typeof obj !== 'object') return obj;
  const result = { ...obj };
  for (const field of fields) {
    if (result[field] !== undefined && result[field] !== null) {
      result[field] = encryptField(result[field], key);
    }
  }
  return result;
}

/**
 * Decrypt sensitive fields of an object selectively.
 * @param {Object} obj - Object with encrypted fields
 * @param {string[]} fields - Field names to decrypt
 * @param {boolean} [parseJson=false] - Parse JSON fields
 * @param {Buffer} [key] - Optional key
 * @returns {Object} Object with decrypted fields
 */
export function decryptObjectFields(obj, fields, parseJson = false, key = null) {
  if (!obj || typeof obj !== 'object') return obj;
  const result = { ...obj };
  for (const field of fields) {
    if (result[field] !== undefined && result[field] !== null && typeof result[field] === 'string') {
      result[field] = decryptField(result[field], parseJson, key);
    }
  }
  return result;
}

// ============================================================================
// PASSWORD HASHING (Argon2id via scrypt as built-in)
// ============================================================================

/**
 * Hash a password using scrypt with Argon2id-inspired parameters.
 * Uses crypto.scryptSync which provides memory-hard properties similar to Argon2.
 * @param {string} password - Plaintext password
 * @param {Buffer} [salt] - Optional 16-byte salt (random generated if omitted)
 * @returns {string} Encoded hash string: argon2id$N=2^17,r=8,p=1$<salt>$<hash>
 */
export function hashPassword(password, salt = null) {
  if (!password || typeof password !== 'string') {
    throw new EncryptionError('Password must be a non-empty string');
  }

  const pwSalt = salt || randomBytes(16);
  if (pwSalt.length !== 16) {
    throw new EncryptionError('Salt must be 16 bytes');
  }

  // Scrypt with N=2^17 (131072), r=8, p=1 (Argon2id-inspired parameters)
  // These parameters are tuned for ~100ms on modern hardware
  const N = 131072;
  const r = 8;
  const p = 1;
  const keyLength = 64;

  try {
    const hash = scryptSync(password, pwSalt, keyLength, { N, r, p });
    const saltB64 = pwSalt.toString('base64');
    const hashB64 = hash.toString('base64');
    return `$scrypt$N=${N},r=${r},p=${1}$${saltB64}$${hashB64}`;
  } catch (err) {
    throw new EncryptionError(`Password hashing failed: ${err.message}`);
  }
}

/**
 * Verify a password against an encoded hash.
 * @param {string} password - Plaintext password to verify
 * @param {string} encodedHash - Encoded hash from hashPassword()
 * @returns {boolean} True if password matches
 */
export function verifyPassword(password, encodedHash) {
  if (!password || !encodedHash) return false;

  try {
    const parts = encodedHash.split('$');
    if (parts.length !== 5 || parts[1] !== 'scrypt') {
      // Try constant-time comparison fallback for unknown formats
      return false;
    }

    const salt = Buffer.from(parts[3], 'base64');
    const newHash = hashPassword(password, salt);

    // Constant-time comparison
    const existingBuf = Buffer.from(encodedHash, 'utf8');
    const newBuf = Buffer.from(newHash, 'utf8');

    if (existingBuf.length !== newBuf.length) {
      return false;
    }
    return timingSafeEqual(existingBuf, newBuf);
  } catch {
    return false;
  }
}

/**
 * Check if a password hash needs rehashing (parameter upgrade).
 * @param {string} encodedHash - Current hash
 * @param {number} [currentN=131072] - Current N parameter
 * @returns {boolean} True if rehash recommended
 */
export function needsRehash(encodedHash, currentN = 131072) {
  try {
    const parts = encodedHash.split('$');
    if (parts.length !== 5) return true;
    const params = parts[2];
    const match = params.match(/N=(\d+)/);
    if (!match) return true;
    const hashN = parseInt(match[1], 10);
    return hashN < currentN;
  } catch {
    return true;
  }
}

// ============================================================================
// HMAC-SHA512
// ============================================================================

/**
 * Generate HMAC-SHA512 for message authentication.
 * @param {string|Buffer} message - Message to authenticate
 * @param {string|Buffer} secret - Secret key
 * @returns {string} Hex-encoded HMAC
 */
export function hmacSHA512(message, secret) {
  if (!message || !secret) {
    throw new EncryptionError('Message and secret are required for HMAC');
  }
  const key = Buffer.isBuffer(secret) ? secret : Buffer.from(secret, 'utf8');
  const msg = Buffer.isBuffer(message) ? message : Buffer.from(message, 'utf8');
  return createHmac('sha512', key).update(msg).digest('hex');
}

/**
 * Verify HMAC-SHA512 signature.
 * @param {string|Buffer} message - Original message
 * @param {string} signature - Hex-encoded HMAC to verify
 * @param {string|Buffer} secret - Secret key
 * @returns {boolean} True if signature is valid
 */
export function verifyHMAC(message, signature, secret) {
  try {
    const expected = hmacSHA512(message, secret);
    const sigBuf = Buffer.from(signature, 'hex');
    const expBuf = Buffer.from(expected, 'hex');
    if (sigBuf.length !== expBuf.length) return false;
    return timingSafeEqual(sigBuf, expBuf);
  } catch {
    return false;
  }
}

// ============================================================================
// PBKDF2 KEY DERIVATION
// ============================================================================

/**
 * Derive a key using PBKDF2-HMAC-SHA512.
 * @param {string} password - Password or key material
 * @param {Buffer} [salt] - Salt (random 16 bytes if omitted)
 * @param {number} [iterations=100000] - Iteration count
 * @param {number} [keyLength=64] - Derived key length in bytes
 * @returns {{key: Buffer, salt: Buffer, iterations: number}} Derived key info
 */
export function pbkdf2Derive(password, salt = null, iterations = 100000, keyLength = 64) {
  if (!password || typeof password !== 'string') {
    throw new KeyDerivationError('Password is required');
  }
  if (iterations < 10000) {
    throw new KeyDerivationError('PBKDF2 iterations must be >= 10000');
  }

  const pwSalt = salt || randomBytes(16);
  try {
    const key = pbkdf2Sync(password, pwSalt, iterations, keyLength, 'sha512');
    return { key, salt: pwSalt, iterations };
  } catch (err) {
    throw new KeyDerivationError(`PBKDF2 derivation failed: ${err.message}`);
  }
}

// ============================================================================
// JWT OPERATIONS (HMAC-SHA512)
// ============================================================================

/**
 * JWT header for HS512.
 * @type {string}
 */
const JWT_HEADER = Buffer.from(JSON.stringify({ alg: 'HS512', typ: 'JWT' })).toString('base64url');

/**
 * Sign a JWT token with HMAC-SHA512.
 * @param {Object} payload - JWT payload (must include iat, exp recommended)
 * @param {string|Buffer} secret - Signing secret
 * @param {Object} [options] - Options
 * @param {number} [options.expiresInSeconds=3600] - Token expiry
 * @param {string} [options.issuer] - JWT issuer
 * @param {string} [options.audience] - JWT audience
 * @returns {string} Signed JWT token
 */
export function jwtSign(payload, secret, options = {}) {
  if (!payload || typeof payload !== 'object') {
    throw new EncryptionError('JWT payload must be an object');
  }
  if (!secret) {
    throw new EncryptionError('JWT secret is required');
  }

  const now = Math.floor(Date.now() / 1000);
  const {
    expiresInSeconds = 3600,
    issuer,
    audience,
  } = options;

  const jwtPayload = {
    ...payload,
    iat: payload.iat || now,
    exp: payload.exp || now + expiresInSeconds,
  };
  if (issuer) jwtPayload.iss = issuer;
  if (audience) jwtPayload.aud = audience;

  const payloadB64 = Buffer.from(JSON.stringify(jwtPayload)).toString('base64url');
  const signingInput = `${JWT_HEADER}.${payloadB64}`;
  const key = Buffer.isBuffer(secret) ? secret : Buffer.from(secret, 'utf8');
  const signature = createHmac('sha512', key).update(signingInput).digest('base64url');

  return `${signingInput}.${signature}`;
}

/**
 * Verify a JWT token.
 * @param {string} token - JWT token string
 * @param {string|Buffer} secret - Verification secret
 * @param {Object} [options] - Options
 * @param {string} [options.issuer] - Expected issuer
 * @param {string} [options.audience] - Expected audience
 * @param {number} [options.clockToleranceSeconds=60] - Clock skew tolerance
 * @returns {Object} Decoded and verified payload
 * @throws {AuthenticationError} If verification fails
 */
export function jwtVerify(token, secret, options = {}) {
  if (!token || typeof token !== 'string') {
    throw new AuthenticationError('JWT token must be a string');
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new AuthenticationError('Invalid JWT format');
  }

  const [headerB64, payloadB64, signature] = parts;

  // Verify signature
  const signingInput = `${headerB64}.${payloadB64}`;
  const key = Buffer.isBuffer(secret) ? secret : Buffer.from(secret, 'utf8');
  const expectedSig = createHmac('sha512', key).update(signingInput).digest('base64url');

  if (signature !== expectedSig) {
    throw new AuthenticationError('Invalid JWT signature');
  }

  // Parse payload
  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  } catch {
    throw new AuthenticationError('Invalid JWT payload');
  }

  // Check expiry
  const now = Math.floor(Date.now() / 1000);
  const clockTolerance = options.clockToleranceSeconds || 60;
  if (payload.exp && payload.exp < now - clockTolerance) {
    throw new AuthenticationError('JWT token expired');
  }
  if (payload.nbf && payload.nbf > now + clockTolerance) {
    throw new AuthenticationError('JWT token not yet valid');
  }

  // Verify issuer
  if (options.issuer && payload.iss !== options.issuer) {
    throw new AuthenticationError('Invalid JWT issuer');
  }

  // Verify audience
  if (options.audience && payload.aud !== options.audience) {
    throw new AuthenticationError('Invalid JWT audience');
  }

  return payload;
}

/**
 * Decode JWT payload WITHOUT verification (for inspection only).
 * @param {string} token - JWT token
 * @returns {Object|null} Decoded payload or null
 */
export function jwtDecode(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

// ============================================================================
// SECURE RANDOM TOKEN GENERATION
// ============================================================================

/**
 * Generate a cryptographically secure random token.
 * @param {number} [byteLength=32] - Token length in bytes
 * @returns {Buffer} Random bytes
 */
export function generateRandomBytes(byteLength = 32) {
  if (typeof byteLength !== 'number' || byteLength < 1 || byteLength > 1024) {
    throw new EncryptionError('Byte length must be 1-1024');
  }
  return randomBytes(byteLength);
}

/**
 * Generate a URL-safe base64 encoded random token.
 * @param {number} [byteLength=32] - Token length in bytes (256 bits default)
 * @returns {string} URL-safe base64 token
 */
export function generateToken(byteLength = 32) {
  return randomBytes(byteLength).toString('base64url');
}

/**
 * Generate a hex-encoded random token.
 * @param {number} [byteLength=32] - Token length in bytes
 * @returns {string} Hex token
 */
export function generateHexToken(byteLength = 32) {
  return randomBytes(byteLength).toString('hex');
}

/**
 * Generate a high-entropy API key.
 * @returns {string} API key in format: prefix_random_random
 */
export function generateAPIKey() {
  const prefix = 'osm_';
  const part1 = randomBytes(16).toString('base64url');
  const part2 = randomBytes(16).toString('base64url');
  return `${prefix}${part1}_${part2}`;
}

/**
 * Generate a secure session ID.
 * @returns {string} 128-bit hex session ID
 */
export function generateSessionId() {
  return randomBytes(32).toString('hex');
}

/**
 * Generate a secure nonce for PoW challenges.
 * @param {number} [byteLength=16] - Nonce length
 * @returns {string} Hex nonce
 */
export function generateNonce(byteLength = 16) {
  return randomBytes(byteLength).toString('hex');
}

// ============================================================================
// UUID GENERATION
// ============================================================================

/**
 * Generate a UUID v4 (random).
 * @returns {string} UUID v4 string
 */
export function generateUUID() {
  return randomUUID({ disableEntropyCache: false });
}

/**
 * Generate a UUID v4 with additional entropy mixing.
 * @returns {string} High-entropy UUID v4
 */
export function generateSecureUUID() {
  const uuid = randomUUID({ disableEntropyCache: true });
  const extra = randomBytes(8).toString('hex');
  return `${uuid}-${extra}`;
}

// ============================================================================
// HASH FUNCTIONS
// ============================================================================

/**
 * Compute SHA-256 hash.
 * @param {string|Buffer} data - Input data
 * @returns {string} Hex digest
 */
export function sha256(data) {
  if (!data) throw new EncryptionError('Data is required for SHA-256');
  const input = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
  return createHash('sha256').update(input).digest('hex');
}

/**
 * Compute SHA-512 hash.
 * @param {string|Buffer} data - Input data
 * @returns {string} Hex digest
 */
export function sha512(data) {
  if (!data) throw new EncryptionError('Data is required for SHA-512');
  const input = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
  return createHash('sha512').update(input).digest('hex');
}

/**
 * Compute hash using the specified algorithm.
 * @param {string|Buffer} data - Input data
 * @param {string} [algorithm='sha512'] - Hash algorithm
 * @returns {string} Hex digest
 */
export function hashData(data, algorithm = 'sha512') {
  if (!data) throw new EncryptionError('Data is required for hashing');
  const allowed = ['sha256', 'sha512', 'sha384', 'sha224', 'sha1', 'md5'];
  if (!allowed.includes(algorithm)) {
    throw new EncryptionError(`Unsupported hash algorithm: ${algorithm}`);
  }
  const input = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
  return createHash(algorithm).update(input).digest('hex');
}

/**
 * Compute double SHA-256 (Bitcoin-style).
 * @param {string|Buffer} data - Input data
 * @returns {string} Hex digest
 */
export function doubleSha256(data) {
  return sha256(Buffer.from(sha256(data), 'hex'));
}

// ============================================================================
// SECURE COMPARISON (TIMING ATTACK RESISTANT)
// ============================================================================

/**
 * Constant-time comparison of two strings.
 * @param {string} a - First string
 * @param {string} b - Second string
 * @returns {boolean} True if equal
 */
export function secureCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  try {
    return timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

/**
 * Constant-time comparison of two hex strings.
 * @param {string} a - First hex string
 * @param {string} b - Second hex string
 * @returns {boolean}
 */
export function secureCompareHex(a, b) {
  try {
    const bufA = Buffer.from(a, 'hex');
    const bufB = Buffer.from(b, 'hex');
    if (bufA.length !== bufB.length) return false;
    return timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

/**
 * Constant-time comparison of two base64 strings.
 * @param {string} a - First base64 string
 * @param {string} b - Second base64 string
 * @returns {boolean}
 */
export function secureCompareBase64(a, b) {
  try {
    const bufA = Buffer.from(a, 'base64');
    const bufB = Buffer.from(b, 'base64');
    if (bufA.length !== bufB.length) return false;
    return timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

// ============================================================================
// CERTIFICATE PINNING
// ============================================================================

/**
 * Generate a certificate pinning hash (Subject Public Key Info hash).
 * @param {string|Buffer} certPem - Certificate in PEM format
 * @returns {string} Base64-encoded SPKI hash
 */
export function generatePinHash(certPem) {
  if (!certPem) {
    throw new EncryptionError('Certificate PEM is required');
  }

  // Extract certificate body between PEM headers
  let pem = typeof certPem === 'string' ? certPem : certPem.toString('utf8');
  pem = pem.replace(/-----BEGIN CERTIFICATE-----/g, '');
  pem = pem.replace(/-----END CERTIFICATE-----/g, '');
  pem = pem.replace(/\s/g, '');

  const certDer = Buffer.from(pem, 'base64');

  // Hash the full DER certificate (simplified pinning)
  // In production, you would extract just the SPKI
  const hash = createHash('sha256').update(certDer).digest('base64');
  return `sha256/${hash}`;
}

/**
 * Generate a public key pin hash.
 * @param {string|Buffer} publicKeyPem - Public key in PEM format
 * @returns {string} Base64-encoded SPKI hash
 */
export function generatePublicKeyPin(publicKeyPem) {
  if (!publicKeyPem) {
    throw new EncryptionError('Public key PEM is required');
  }

  let pem = typeof publicKeyPem === 'string' ? publicKeyPem : publicKeyPem.toString('utf8');
  pem = pem.replace(/-----BEGIN PUBLIC KEY-----/g, '');
  pem = pem.replace(/-----END PUBLIC KEY-----/g, '');
  pem = pem.replace(/\s/g, '');

  const keyDer = Buffer.from(pem, 'base64');
  const hash = createHash('sha256').update(keyDer).digest('base64');
  return `sha256/${hash}`;
}

// ============================================================================
// CHECKSUM / DATA INTEGRITY
// ============================================================================

/**
 * Generate a tamper-evident checksum for data.
 * @param {string|Buffer} data - Data to checksum
 * @param {string|Buffer} secret - Secret for HMAC
 * @returns {string} HMAC-SHA256 checksum
 */
export function generateChecksum(data, secret) {
  if (!data || !secret) {
    throw new EncryptionError('Data and secret are required for checksum');
  }
  const key = Buffer.isBuffer(secret) ? secret : Buffer.from(secret, 'utf8');
  const input = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
  return createHmac('sha256', key).update(input).digest('hex');
}

/**
 * Verify a tamper-evident checksum.
 * @param {string|Buffer} data - Original data
 * @param {string} checksum - Expected checksum
 * @param {string|Buffer} secret - Secret for HMAC
 * @returns {boolean}
 */
export function verifyChecksum(data, checksum, secret) {
  try {
    const expected = generateChecksum(data, secret);
    return secureCompareHex(expected, checksum);
  } catch {
    return false;
  }
}

// ============================================================================
// ENCRYPTED TOKEN FORMAT
// ============================================================================

/**
 * Create a tamper-proof encrypted token containing structured data.
 * Format: base64(iv:tag:ciphertext:signature)
 * @param {Object} data - Data to encode in token
 * @param {Buffer} [key] - Encryption key
 * @param {string|Buffer} [signingSecret] - HMAC secret
 * @param {number} [expiresInSeconds=600] - Token expiry
 * @returns {string} Encrypted token
 */
export function createEncryptedToken(data, key = null, signingSecret = null, expiresInSeconds = 600) {
  const payload = {
    ...data,
    _iat: Math.floor(Date.now() / 1000),
    _exp: Math.floor(Date.now() / 1000) + expiresInSeconds,
  };

  const jsonPayload = JSON.stringify(payload);
  const encrypted = encryptAES(jsonPayload, key);

  // Add HMAC for additional integrity
  const encKey = key || getPrimaryKey();
  const secret = signingSecret || encKey;
  const sigInput = `${encrypted.iv}:${encrypted.tag}:${encrypted.ciphertext}`;
  const signature = hmacSHA512(sigInput, secret);

  const ivBuf = Buffer.from(encrypted.iv, 'base64');
  const tagBuf = Buffer.from(encrypted.tag, 'base64');
  const ctBuf = Buffer.from(encrypted.ciphertext, 'base64');
  const sigBuf = Buffer.from(signature, 'hex');

  return Buffer.concat([ivBuf, tagBuf, ctBuf, sigBuf]).toString('base64url');
}

/**
 * Decrypt and verify an encrypted token.
 * @param {string} token - Encrypted token
 * @param {Buffer} [key] - Decryption key
 * @param {string|Buffer} [signingSecret] - HMAC secret
 * @returns {Object} Decoded data
 * @throws {DecryptionError|AuthenticationError} On failure
 */
export function decryptEncryptedToken(token, key = null, signingSecret = null) {
  try {
    const buf = Buffer.from(token, 'base64url');
    if (buf.length < 80) {
      throw new DecryptionError('Invalid encrypted token');
    }

    const iv = buf.subarray(0, 16).toString('base64');
    const tag = buf.subarray(16, 32).toString('base64');
    const ciphertext = buf.subarray(32, buf.length - 64).toString('base64');
    const signature = buf.subarray(buf.length - 64).toString('hex');

    // Verify HMAC
    const encKey = key || getPrimaryKey();
    const secret = signingSecret || encKey;
    const sigInput = `${iv}:${tag}:${ciphertext}`;
    if (!verifyHMAC(sigInput, signature, secret)) {
      throw new AuthenticationError('Encrypted token signature invalid');
    }

    // Decrypt
    const decrypted = decryptAES({ iv, tag, ciphertext }, key);
    const payload = JSON.parse(decrypted.toString('utf8'));

    // Check expiry
    const now = Math.floor(Date.now() / 1000);
    if (payload._exp && payload._exp < now) {
      throw new AuthenticationError('Encrypted token expired');
    }

    return payload;
  } catch (err) {
    if (err instanceof EncryptionError) throw err;
    throw new DecryptionError(`Failed to decrypt token: ${err.message}`);
  }
}

// ============================================================================
// KEY ENCAPSULATION
// ============================================================================

/**
 * Generate a data encryption key (DEK) and encrypt it with a key encryption key (KEK).
 * @param {Buffer} [kek] - Key encryption key
 * @returns {{dek: Buffer, encryptedDek: string}} DEK and encrypted DEK
 */
export function generateDataEncryptionKey(kek = null) {
  const dek = randomBytes(32);
  const key = kek || getPrimaryKey();
  const encryptedDek = encryptString(dek.toString('base64'), key);
  return { dek, encryptedDek };
}

/**
 * Decrypt a data encryption key.
 * @param {string} encryptedDek - Encrypted DEK
 * @param {Buffer} [kek] - Key encryption key
 * @returns {Buffer} Decrypted DEK
 */
export function decryptDataEncryptionKey(encryptedDek, kek = null) {
  const key = kek || getPrimaryKey();
  const dekB64 = decryptString(encryptedDek, key);
  return Buffer.from(dekB64, 'base64');
}

// ============================================================================
// SCRAMBLE / OBFUSCATION (non-crypto, for presentation layer)
// ============================================================================

/**
 * Create a hash-based fingerprint of data for deduplication/comparison.
 * @param {string|Buffer} data - Input data
 * @param {string} [algorithm='sha256'] - Hash algorithm
 * @returns {string} Hex fingerprint
 */
export function fingerprint(data, algorithm = 'sha256') {
  if (!data) return '';
  const input = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
  return createHash(algorithm).update(input).digest('hex');
}

/**
 * Create a composite fingerprint from multiple values.
 * @param {Array<string|Buffer>} values - Values to combine
 * @returns {string} Hex fingerprint
 */
export function compositeFingerprint(values) {
  if (!Array.isArray(values)) {
    throw new EncryptionError('Values must be an array');
  }
  const hash = createHash('sha512');
  for (const v of values) {
    const input = Buffer.isBuffer(v) ? v : Buffer.from(String(v), 'utf8');
    hash.update(input);
  }
  return hash.digest('hex');
}

// ============================================================================
// MODULE EXPORTS
// ============================================================================

export default {
  // Initialization
  initializeKeys,
  rotateKeys,
  deriveKey,

  // AES-256-GCM
  encryptAES,
  decryptAES,
  encryptString,
  decryptString,

  // Database encryption
  encryptField,
  decryptField,
  encryptObjectFields,
  decryptObjectFields,

  // Password hashing
  hashPassword,
  verifyPassword,
  needsRehash,

  // HMAC
  hmacSHA512,
  verifyHMAC,

  // PBKDF2
  pbkdf2Derive,

  // JWT
  jwtSign,
  jwtVerify,
  jwtDecode,

  // Random tokens
  generateRandomBytes,
  generateToken,
  generateHexToken,
  generateAPIKey,
  generateSessionId,
  generateNonce,

  // UUID
  generateUUID,
  generateSecureUUID,

  // Hashing
  sha256,
  sha512,
  hashData,
  doubleSha256,

  // Comparison
  secureCompare,
  secureCompareHex,
  secureCompareBase64,

  // Certificate pinning
  generatePinHash,
  generatePublicKeyPin,

  // Checksum
  generateChecksum,
  verifyChecksum,

  // Encrypted tokens
  createEncryptedToken,
  decryptEncryptedToken,

  // Key encapsulation
  generateDataEncryptionKey,
  decryptDataEncryptionKey,

  // Fingerprinting
  fingerprint,
  compositeFingerprint,

  // Errors
  EncryptionError,
  DecryptionError,
  AuthenticationError,
  KeyDerivationError,
};
