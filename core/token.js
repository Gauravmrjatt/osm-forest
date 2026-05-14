/**
 * @fileoverview Secure Token Generation Utilities
 * @description Cryptographically secure token generator for session tokens.
 * Uses Node.js crypto.randomBytes for entropy.
 * @module core/token
 * @version 1.0.0
 */

'use strict';

import { randomBytes } from 'crypto';

/**
 * Generate a cryptographically secure random token string.
 * @param {number} [length=32] - Number of random bytes to generate
 * @returns {string} Hex-encoded token string (length * 2 hex chars)
 */
export function generateSecureToken(length = 32) {
  return randomBytes(length).toString('hex');
}

export default { generateSecureToken };
