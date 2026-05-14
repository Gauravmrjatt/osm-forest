/**
 * @fileoverview Production-Safe Error Handler Middleware
 * @description Sanitizes ALL error responses to prevent information leakage:
 *   - Production: generic message ONLY (no stack traces, no error details)
 *   - Development: detailed error with stack trace for debugging
 *   - NEVER leaks codes, tokens, passwords, or internal paths
 *   - Logs sanitized errors (no sensitive data) to audit system
 *   - Sends critical alerts for 500+ errors
 *
 * CRITICAL SECURITY RULES:
 *   - NEVER include stack traces in production responses
 *   - NEVER include raw error messages that may contain sensitive data
 *   - NEVER log codes, tokens, or passwords in error handlers
 *   - All logged errors are sanitized before emission
 *
 * @module middleware/errorHandler
 * @version 1.0.0
 */

'use strict';

import { logAdminActionToDB, logSecurityAlert, sanitizeLogData } from '../core/auditLog.js';

// ----------------------------------------------------------------------------
// Configuration
// ----------------------------------------------------------------------------

const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const DEBUG_MODE = process.env.DEBUG_MODE === 'true' && !IS_PRODUCTION;

// Sensitive patterns that should NEVER appear in responses
const SENSITIVE_PATTERNS = [
  /[a-f0-9]{32,}/gi,           // Hex strings (potential codes, tokens)
  /[A-Z0-9]{16,}/g,            // Uppercase codes
  /\b[A-Za-z0-9+/]{40,}={0,2}\b/g, // Base64 strings
  /password[=:]\s*\S+/gi,      // Password leaks
  /token[=:]\s*\S+/gi,         // Token leaks
  /secret[=:]\s*\S+/gi,        // Secret leaks
  /mongodb(\+srv)?:\/\/[^:]+:[^@]+@/gi, // MongoDB URI with credentials
];

// Error codes safe to expose in production (generic only)
const SAFE_ERROR_CODES = new Set([
  'NOT_FOUND',
  'INVALID_REQUEST',
  'UNAUTHORIZED',
  'FORBIDDEN',
  'RATE_LIMIT_EXCEEDED',
  'VALIDATION_ERROR',
  'CONFLICT',
  'INTERNAL_ERROR',
  'SERVICE_UNAVAILABLE',
  'AUTH_REQUIRED',
  'TOKEN_INVALID',
  'SESSION_EXPIRED',
  'CSRF_MISSING',
  'CSRF_INVALID',
  'IP_NOT_AUTHORIZED',
  'TOTP_REQUIRED',
  'TOTP_INVALID',
  'REAUTH_REQUIRED',
]);

// ----------------------------------------------------------------------------
// Helper Functions
// ----------------------------------------------------------------------------

/**
 * Sanitize an error message to remove any potentially sensitive data.
 * @param {string} message - Raw error message.
 * @returns {string} Sanitized message safe for client exposure.
 */
function sanitizeErrorMessage(message) {
  if (!message || typeof message !== 'string') return 'An error occurred';

  let sanitized = message;

  // Remove potential sensitive patterns
  for (const pattern of SENSITIVE_PATTERNS) {
    sanitized = sanitized.replace(pattern, '[REDACTED]');
  }

  // Truncate overly long messages
  if (sanitized.length > 200) {
    sanitized = sanitized.slice(0, 200) + '...';
  }

  return sanitized;
}

/**
 * Determine HTTP status code from error.
 * @param {Error} err - Error object.
 * @returns {number} HTTP status code.
 */
function getStatusCode(err) {
  if (err.statusCode && typeof err.statusCode === 'number') return err.statusCode;
  if (err.status && typeof err.status === 'number') return err.status;
  if (err.code === 'NOT_FOUND') return 404;
  if (err.code === 'UNAUTHORIZED' || err.code === 'AUTH_REQUIRED') return 401;
  if (err.code === 'FORBIDDEN' || err.code === 'IP_NOT_AUTHORIZED') return 403;
  if (err.code === 'RATE_LIMIT_EXCEEDED') return 429;
  if (err.code === 'CONFLICT') return 409;
  if (err.code === 'VALIDATION_ERROR') return 400;
  if (err.code === 'SERVICE_UNAVAILABLE') return 503;
  return 500;
}

/**
 * Get safe error code for production response.
 * @param {Error} err - Error object.
 * @returns {string} Safe error code.
 */
function getSafeErrorCode(err) {
  const code = err.code || 'INTERNAL_ERROR';
  if (SAFE_ERROR_CODES.has(code)) return code;
  return 'INTERNAL_ERROR';
}

// ----------------------------------------------------------------------------
// Middleware Factory
// ----------------------------------------------------------------------------

/**
 * Create the global error handler middleware.
 * @param {object} options - Configuration options.
 * @param {object} options.logger - Logger instance (optional).
 * @param {object} options.alert - Alert manager instance (optional).
 * @returns {import('express').ErrorRequestHandler} Express error handler.
 */
export function createErrorHandler(options = {}) {
  const { logger, alert } = options;

  return async (err, req, res, _next) => {
    const statusCode = getStatusCode(err);
    const errorCode = getSafeErrorCode(err);
    const requestId = req.id || 'unknown';

    // Determine client-facing message
    let clientMessage;
    let clientDetail = null;

    if (statusCode >= 500) {
      // Server errors: NEVER expose details in production
      clientMessage = 'Internal server error';
    } else {
      // Client errors: sanitized message is safe
      clientMessage = sanitizeErrorMessage(err.message) || 'Request failed';
    }

    // In development mode (non-production), include debugging info
    if (!IS_PRODUCTION && DEBUG_MODE) {
      clientDetail = {
        message: err.message,
        stack: err.stack?.split('\n').slice(0, 5),
        code: err.code,
        statusCode,
      };
    }

    // Build sanitized log entry (NEVER includes raw codes, tokens, or passwords)
    const logEntry = {
      code: errorCode,
      statusCode,
      message: sanitizeErrorMessage(err.message),
      path: req.path || 'unknown',
      method: req.method || 'UNKNOWN',
      ip: req.clientIp || req.ip || 'unknown',
      requestId,
      timestamp: new Date().toISOString(),
    };

    // Log the error (stdout)
    if (logger) {
      if (statusCode >= 500) {
        logger.error('SERVER_EXCEPTION', logEntry);
      } else if (statusCode >= 400) {
        logger.warn('SERVER_REQUEST_WARNING', logEntry);
      }
    }

    // Send critical alerts for 500+ errors
    if (statusCode >= 500 && alert) {
      try {
        await alert.send('CRITICAL_SERVER_ERROR', {
          ...logEntry,
          errorType: err.name || 'Error',
        });
      } catch { /* non-blocking */ }
    }

    // Attempt to log to admin audit DB for 500 errors (non-blocking)
    if (statusCode >= 500) {
      try {
        await logAdminActionToDB('system', 'SYSTEM_ERROR', {
          errorCode,
          statusCode,
          path: req.path,
          method: req.method,
          ip: req.clientIp || req.ip,
          requestId,
          errorType: err.name || 'Error',
        });
      } catch { /* non-blocking */ }
    }

    // Send sanitized response
    const responseBody = {
      success: false,
      error: clientMessage,
      code: errorCode,
      requestId,
      timestamp: new Date().toISOString(),
    };

    // Only include detail in development mode
    if (clientDetail) {
      responseBody.detail = clientDetail;
    }

    // Set security headers on error responses too
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, proxy-revalidate');
    res.setHeader('X-Content-Type-Options', 'nosniff');

    res.status(statusCode).json(responseBody);
  };
}

/**
 * Express-async-handler wrapper: catches errors from async route handlers
 * and forwards them to the error handler middleware.
 * @param {Function} fn - Async route handler.
 * @returns {Function} Wrapped route handler.
 */
export function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

/**
 * 404 Not Found handler — returns sanitized response.
 * @returns {import('express').RequestHandler}
 */
export function notFoundHandler() {
  return (req, res) => {
    res.status(404).json({
      success: false,
      error: 'Resource not found',
      code: 'NOT_FOUND',
      requestId: req.id || 'unknown',
      timestamp: new Date().toISOString(),
    });
  };
}

/**
 * Catch-all for unhandled promise rejections in middleware.
 * Logs and forwards to error handler.
 * @returns {import('express').ErrorRequestHandler}
 */
export function unhandledRejectionHandler() {
  return (err, req, res, next) => {
    if (!err) return next();

    // Ensure the error has a status code
    if (!err.statusCode && !err.status) {
      err.statusCode = 500;
    }

    next(err);
  };
}

export default {
  createErrorHandler,
  asyncHandler,
  notFoundHandler,
  unhandledRejectionHandler,
};
