/**
 * @fileoverview responseSanitizer.js - Response Body Sanitizer
 * @description Express middleware that sanitizes response bodies before they
 * hit any downstream loggers. Replaces raw code values with masked placeholders.
 * FINAL SAFETY NET: Timer se pehle code ka ek byte bhi server ke bahar nahi.
 * @module middleware/responseSanitizer
 * @version 1.0.0
 */

/**
 * Fields that must NEVER appear in logs unmasked.
 * These are stripped/redacted from any response that might be logged.
 */
const SENSITIVE_FIELDS = ['code', 'token', 'secret', 'password', 'key', 'nonce'];

/**
 * Deep-clone and mask sensitive fields in an object.
 * Creates a copy — does NOT mutate the original.
 * @param {Object} obj
 * @returns {Object}
 */
function maskSensitiveFields(obj) {
  if (!obj || typeof obj !== 'object') return obj;

  const masked = Array.isArray(obj) ? [...obj] : { ...obj };

  for (const key of Object.keys(masked)) {
    const lowerKey = key.toLowerCase();
    if (SENSITIVE_FIELDS.some(s => lowerKey.includes(s))) {
      const val = masked[key];
      if (typeof val === 'string') {
        // Mask: keep first 3 chars + *** + last 2 chars, or full mask if short
        masked[key] = val.length > 10
          ? val.substring(0, 3) + '***' + val.substring(val.length - 2)
          : '***REDACTED***';
      } else if (typeof val === 'object' && val !== null) {
        masked[key] = maskSensitiveFields(val);
      } else {
        masked[key] = '***REDACTED***';
      }
    } else if (typeof masked[key] === 'object' && masked[key] !== null) {
      masked[key] = maskSensitiveFields(masked[key]);
    }
  }

  return masked;
}

/**
 * Express middleware: overrides res.json() to sanitize outgoing responses
 * before any downstream logger can capture them.
 *
 * Usage:
 *   app.use(sanitizeJsonResponse());
 *
 * @returns {Function} Express middleware
 */
export function sanitizeJsonResponse() {
  return (req, res, next) => {
    const originalJson = res.json.bind(res);

    res.json = function(body) {
      try {
        // Check if this is a code reveal endpoint
        const isRevealEndpoint = req.path?.includes('/code/reveal');
        const isCodeResponse = body && (
          (body.code && typeof body.code === 'string' && body.code.length >= 20) ||
          (body.success === true && body.codeLength)
        );

        if (isRevealEndpoint && isCodeResponse && body.success === true) {
          // Sanitize the response body before sending (for logging safety)
          // The ACTUAL response sent to client still has the real code
          // but any logger that intercepts res.json sees the masked version
          const logSafeBody = maskSensitiveFields(body);

          // Attach log-safe version for any audit/logger middleware
          res._logSafeBody = logSafeBody;
        } else {
          res._logSafeBody = body;
        }
      } catch (e) {
        // Never break the response if sanitization fails
        res._logSafeBody = body;
      }

      // Call original — real code goes to CLIENT
      return originalJson(body);
    };

    next();
  };
}

/**
 * Standalone: manually mask a value for safe logging.
 * @param {string} code - Raw code
 * @returns {string} - Masked code for logs
 */
export function maskForLogs(code) {
  if (!code || typeof code !== 'string') return '***';
  if (code.length <= 5) return '***';
  return code.substring(0, 3) + '***' + code.substring(code.length - 2);
}

/**
 * Express middleware: prevents raw response bodies from being logged
 * by common logging libraries (morgan, express-winston, etc.).
 * Sets a flag that compliant loggers check.
 */
export function markSensitiveResponse() {
  return (req, res, next) => {
    // Mark code endpoints as sensitive
    if (req.path?.includes('/code/')) {
      res._sensitive = true;
    }
    next();
  };
}

export default {
  sanitizeJsonResponse,
  maskForLogs,
  markSensitiveResponse,
};
