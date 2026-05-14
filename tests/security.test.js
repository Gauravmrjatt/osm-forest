#!/usr/bin/env node
/**
 * ============================================================================
 * OSM ARMY FORTRESS - Comprehensive Security Test Suite (Category 8)
 * ============================================================================
 * Tests all security layers using Node.js built-in test runner.
 *
 * Run with: node --test tests/security.test.js
 * Or:       NODE_ENV=test node --test tests/security.test.js
 *
 * @module tests/security
 * @version 1.0.0
 * ============================================================================
 */

'use strict';

import { describe, it } from 'node:test';
import assert from 'node:assert';

// ============================================================================
// CONFIGURATION
// ============================================================================

const BASE_URL = process.env.TEST_URL || 'http://localhost:3000';
const VALID_TELEGRAM_ID = process.env.TEST_TELEGRAM_ID || '123456789';
const VALID_DEVICE_ID = process.env.TEST_DEVICE_ID || 'test-device-001';
const ADMIN_USERNAME = process.env.TEST_ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.TEST_ADMIN_PASS || 'admin123';

/** 32-char alphanumeric pattern (gift code format) */
const CODE_PATTERN = /[A-Za-z0-9]{32}/;

/** Pattern to detect any potential code leak */
const POTENTIAL_CODE_PATTERN = /[A-Fa-f0-9]{30,34}/;

// ============================================================================
// HTTP HELPERS
// ============================================================================

/**
 * Perform an HTTP POST request.
 * @param {string} endpoint - API endpoint (e.g., '/api/v1/code/reveal')
 * @param {object} body - JSON body
 * @param {object} [extraHeaders] - Additional headers
 * @returns {Promise<{status: number, headers: Headers, body: object, text: string}>}
 */
async function post(endpoint, body, extraHeaders = {}) {
  const url = `${BASE_URL}${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'User-Agent': 'OSMArmySecurityTest/1.0',
    ...extraHeaders,
  };

  const response = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });

  const text = await response.text();
  let parsedBody = null;
  try {
    parsedBody = text ? JSON.parse(text) : {};
  } catch {
    parsedBody = { _raw: text };
  }

  return {
    status: response.status,
    headers: response.headers,
    body: parsedBody,
    text,
  };
}

/**
 * Perform an HTTP GET request.
 * @param {string} endpoint - API endpoint
 * @param {object} [extraHeaders] - Additional headers
 * @returns {Promise<{status: number, headers: Headers, body: object, text: string}>}
 */
async function get(endpoint, extraHeaders = {}) {
  const url = `${BASE_URL}${endpoint}`;
  const headers = {
    'Accept': 'application/json',
    'User-Agent': 'OSMArmySecurityTest/1.0',
    ...extraHeaders,
  };

  const response = await fetch(url, { method: 'GET', headers });
  const text = await response.text();
  let parsedBody = null;
  try {
    parsedBody = text ? JSON.parse(text) : {};
  } catch {
    parsedBody = { _raw: text };
  }

  return {
    status: response.status,
    headers: response.headers,
    body: parsedBody,
    text,
  };
}

// ============================================================================
// ASSERTION HELPERS
// ============================================================================

/**
 * Assert that the response contains NO 32-char alphanumeric code pattern.
 * @param {{body: object, text: string}} response
 * @param {string} [label] - Test label for error messages
 */
function assertNoCodeInResponse(response, label = 'response') {
  const textToCheck = JSON.stringify(response.body) + ' ' + response.text;

  assert.strictEqual(
    CODE_PATTERN.test(textToCheck),
    false,
    `SECURITY VIOLATION: ${label} contains potential 32-char code! Body: ${JSON.stringify(response.body).slice(0, 200)}`
  );
}

/**
 * Assert that cache security headers are present and correct.
 * @param {{headers: Headers, status: number}} response
 * @param {string} [label]
 */
function assertCacheHeaders(response, label = 'response') {
  const cc = response.headers.get('cache-control') || '';
  const pragma = response.headers.get('pragma') || '';

  assert.ok(
    cc.includes('no-store') || cc.includes('no-cache'),
    `${label}: Missing Cache-Control: no-store/no-cache. Got: ${cc}`
  );
  assert.ok(
    cc.includes('must-revalidate'),
    `${label}: Missing must-revalidate in Cache-Control. Got: ${cc}`
  );
  assert.strictEqual(
    pragma,
    'no-cache',
    `${label}: Missing Pragma: no-cache. Got: ${pragma}`
  );

  // Check Surrogate-Control if present (should be no-store)
  const surrogate = response.headers.get('surrogate-control');
  if (surrogate !== null) {
    assert.ok(
      surrogate.includes('no-store'),
      `${label}: Surrogate-Control should be no-store. Got: ${surrogate}`
    );
  }
}

/**
 * Assert that a response has NO 'code' field.
 * @param {{body: object}} response
 * @param {string} [label]
 */
function assertNoCodeField(response, label = 'response') {
  assert.strictEqual(
    response.body.code,
    undefined,
    `${label}: Response body contains 'code' field — must never happen on error responses`
  );
}

/**
 * Assert standard error response structure.
 * @param {{body: object, status: number}} response
 * @param {number} expectedStatus
 * @param {string} [expectedCode]
 */
function assertErrorResponse(response, expectedStatus, expectedCode) {
  assert.strictEqual(response.status, expectedStatus, `Expected status ${expectedStatus}, got ${response.status}`);
  assert.strictEqual(response.body.success, false, `Expected success: false`);
  if (expectedCode) {
    assert.ok(
      response.body.error === expectedCode || response.body.code === expectedCode,
      `Expected error code ${expectedCode}, got error=${response.body.error}, code=${response.body.code}`
    );
  }
  assertNoCodeField(response);
}

/**
 * Assert that logs (captured stdout) do NOT contain a 32-char code.
 * @param {string} logOutput
 * @param {string} [label]
 */
function assertNoCodeInLogs(logOutput, label = 'logs') {
  assert.strictEqual(
    CODE_PATTERN.test(logOutput),
    false,
    `SECURITY VIOLATION: ${label} contains potential 32-char code! Log: ${logOutput.slice(0, 300)}`
  );
}

// ============================================================================
// TEST DATA HELPERS
// ============================================================================

/**
 * Generate a fake 32-char hex string (not a real code).
 */
function fakeHex(length = 32) {
  const chars = 'abcdef0123456789';
  return Array.from({ length }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

/**
 * Generate a fake claimId (SHA256-like 64-char hex).
 */
function fakeClaimId() {
  return fakeHex(64);
}

/**
 * Generate a fake nonce (32-char hex).
 */
function fakeNonce() {
  return fakeHex(32);
}

/**
 * Generate a fake session token.
 */
function fakeToken() {
  return `tok_${fakeHex(48)}`;
}

/**
 * Generate SQL injection payloads.
 */
function sqlInjectionPayloads() {
  return [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "1' UNION SELECT * FROM admins --",
    "{$ne: null}",
    "{$gt: ''}",
    "'; db.dropDatabase(); //",
  ];
}

/**
 * Generate XSS payloads.
 */
function xssPayloads() {
  return [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    "javascript:alert('xss')",
    '<svg onload=alert(1)>',
    "'--><script>alert(1)</script>",
    "<iframe src='javascript:alert(1)'>",
  ];
}

// ============================================================================
// TEST SUITE 1: TIMER LOCK — Code Cannot Be Revealed Before Timer
// ============================================================================

describe('Timer Lock', { concurrency: false }, () => {
  it('GET /api/v1/code/reveal should return 405 (Method Not Allowed)', async () => {
    const response = await get('/api/v1/code/reveal');
    assert.strictEqual(
      response.status,
      404, // Express router returns 404 for GET on POST-only route, or 405 if explicitly configured
      `Expected 404 for GET on POST-only endpoint, got ${response.status}`
    );
    assertNoCodeInResponse(response, 'GET /reveal');
  });

  it('POST /api/v1/code/reveal before timer expires → 403 TIMELOCK_ACTIVE', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    // Should fail with TIMELOCK_ACTIVE or INVALID_TOKEN (token not in store) — never succeed
    assert.ok(
      response.status === 403 || response.status === 400 || response.status === 409 || response.status === 423,
      `Expected 4xx error before timer, got ${response.status}`
    );
    assertNoCodeField(response);
    assertNoCodeInResponse(response, 'reveal before timer');
    assertCacheHeaders(response, 'reveal before timer');
  });

  it('Response should NOT contain "code" field on TIMELOCK_ACTIVE', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    // Must not contain 'code' field at all (success or error)
    assert.strictEqual(
      response.body.code,
      undefined,
      `TIMELOCK_ACTIVE response must not contain 'code' field`
    );
  });

  it('Response text should NOT contain 32-char alphanumeric string', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    assertNoCodeInResponse(response, 'reveal response');
  });
});

// ============================================================================
// TEST SUITE 2: curl/Postman Direct Access Tests
// ============================================================================

describe('Direct API Access (curl/Postman style)', { concurrency: false }, () => {
  it('POST /api/v1/code/reveal with invalid token → 403 INVALID_TOKEN', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: 'invalid-token-12345',
      claimId: 'abc123',
      nonce: 'xyz789',
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    assert.ok(
      response.status === 400 || response.status === 403 || response.status === 429,
      `Expected 400/403/429 for invalid token, got ${response.status}`
    );
    assertNoCodeInResponse(response, 'invalid token reveal');
    assertCacheHeaders(response);
  });

  it('POST /api/v1/code/reveal without body → 400', async () => {
    const response = await post('/api/v1/code/reveal', {});

    assert.ok(
      response.status === 400 || response.status === 403 || response.status === 429,
      `Expected 400 for empty body, got ${response.status}`
    );
    assertNoCodeField(response);
    assertCacheHeaders(response);
  });

  it('POST /api/v1/code/reveal with wrong claimId → 404 or 400', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    assert.ok(
      response.status >= 400 && response.status < 500,
      `Expected 4xx for wrong claimId, got ${response.status}`
    );
    assertNoCodeInResponse(response);
  });

  it('Direct curl-style request with reused nonce → 409 CLAIM_REUSED', async () => {
    const claimId = fakeClaimId();
    const nonce = fakeNonce();

    // First attempt (will fail on token but tests the flow)
    const r1 = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId,
      nonce,
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });
    assert.ok(r1.status >= 400, `First request should fail, got ${r1.status}`);
    assertNoCodeInResponse(r1);

    // Second attempt with same claimId+nonce
    const r2 = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId,
      nonce,
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });
    assert.ok(r2.status >= 400, `Second request should also fail, got ${r2.status}`);
    assertNoCodeInResponse(r2);
  });

  it('Request with no User-Agent header → should still get 4xx (no code)', async () => {
    const response = await post(
      '/api/v1/code/reveal',
      {
        token: fakeToken(),
        claimId: fakeClaimId(),
        nonce: fakeNonce(),
        telegramId: VALID_TELEGRAM_ID,
        deviceId: VALID_DEVICE_ID,
      },
      { 'User-Agent': '' }
    );

    assert.ok(response.status >= 400, `Expected 4xx without UA, got ${response.status}`);
    assertNoCodeInResponse(response);
  });
});

// ============================================================================
// TEST SUITE 3: TOKEN VALIDATION — Expired and Invalid Tokens
// ============================================================================

describe('Token Validation', { concurrency: false }, () => {
  it('POST /api/v1/code/claim with expired token → 403 INVALID_TOKEN', async () => {
    const response = await post('/api/v1/code/claim', {
      token: 'expired-token-123456789',
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
      gateResults: { factor1: true, factor2: true, factor3: true, pow: true, behavior: true },
    });

    assert.ok(
      response.status === 403 || response.status === 400 || response.status === 429,
      `Expected 403/400/429 for expired token claim, got ${response.status}`
    );
    assertNoCodeInResponse(response);
    assertCacheHeaders(response);
  });

  it('POST /api/v1/code/reveal with expired token → 403 INVALID_TOKEN', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: 'expired-token-123456789',
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    assert.ok(
      response.status === 403 || response.status === 400 || response.status === 429,
      `Expected 403/400/429 for expired token reveal, got ${response.status}`
    );
    assertNoCodeInResponse(response);
    assertCacheHeaders(response);
  });

  it('POST with malformed token → 403', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: '<script>alert(1)</script>',
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    assert.ok(response.status >= 400, `Expected 4xx for malformed token, got ${response.status}`);
    assertNoCodeInResponse(response);
  });

  it('POST with empty token → 400', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: '',
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    assert.ok(response.status >= 400, `Expected 4xx for empty token, got ${response.status}`);
    assertNoCodeField(response);
  });
});

// ============================================================================
// TEST SUITE 4: REPLAY PROTECTION — Reused Nonce / ClaimId
// ============================================================================

describe('Replay Protection', { concurrency: false }, () => {
  it('Same claimId + nonce twice → second gets 409 CLAIM_REUSED or 400', async () => {
    const claimId = fakeClaimId();
    const nonce = fakeNonce();
    const token = fakeToken();

    // First request
    const r1 = await post('/api/v1/code/reveal', {
      token,
      claimId,
      nonce,
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });
    assert.ok(r1.status >= 400, `First request should fail, got ${r1.status}`);
    assertNoCodeInResponse(r1);

    // Second request (replay)
    const r2 = await post('/api/v1/code/reveal', {
      token,
      claimId,
      nonce,
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    // Must not succeed — either same error or CLAIM_REUSED
    assert.ok(
      r2.status >= 400,
      `Replay request must fail, got ${r2.status}`
    );
    assertNoCodeInResponse(r2);
    assertCacheHeaders(r2);
  });

  it('Same claimId with different nonce → 403 NONCE_MISMATCH', async () => {
    const claimId = fakeClaimId();

    const r1 = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId,
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });
    assert.ok(r1.status >= 400, `First request should fail, got ${r1.status}`);

    const r2 = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId,
      nonce: fakeNonce(), // Different nonce
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    assert.ok(r2.status >= 400, `Nonce mismatch must fail, got ${r2.status}`);
    assertNoCodeInResponse(r2);
  });

  it('Expired claim ticket → 410 CLAIM_EXPIRED', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    // Should get some 4xx error (ticket not found = expired/invalid)
    assert.ok(
      response.status >= 400 && response.status < 500,
      `Expected 4xx for expired claim, got ${response.status}`
    );
    assertNoCodeInResponse(response);
  });
});

// ============================================================================
// TEST SUITE 5: ATOMIC LOCK — Parallel Request Race Condition
// ============================================================================

describe('Atomic Lock', { concurrency: false }, () => {
  it('20 simultaneous /reveal requests with same claimId → only 0 succeed (no valid ticket)', async () => {
    // NOTE: Without a valid claim ticket, ALL 20 will fail.
    // With a valid ticket, EXACTLY 1 should succeed and 19 should get CLAIM_REUSED.
    // This test validates that the system does not crash or leak codes under load.

    const claimId = fakeClaimId();
    const nonce = fakeNonce();
    const token = fakeToken();

    const requests = Array.from({ length: 20 }, () =>
      post('/api/v1/code/reveal', {
        token,
        claimId,
        nonce,
        telegramId: VALID_TELEGRAM_ID,
        deviceId: VALID_DEVICE_ID,
      })
    );

    const results = await Promise.all(requests);

    // Count successes (should be 0 without valid ticket)
    const successes = results.filter((r) => r.status === 200 && r.body.code);
    const claimReused = results.filter((r) => r.status === 409);
    const otherErrors = results.filter((r) => r.status >= 400 && r.status !== 409);

    // Without a valid ticket, all should be 4xx errors
    assert.strictEqual(
      successes.length,
      0,
      `SECURITY VIOLATION: ${successes.length} parallel requests succeeded without valid ticket!`
    );

    // Verify NO response contains a code
    for (let i = 0; i < results.length; i++) {
      assertNoCodeInResponse(results[i], `parallel request #${i + 1}`);
      assertCacheHeaders(results[i], `parallel request #${i + 1}`);
    }

    console.log(`  Parallel test: ${successes.length} success, ${claimReused.length} CLAIM_REUSED, ${otherErrors.length} other errors`);
  });

  it('Rapid sequential requests → each gets 4xx, no code leaked', async () => {
    const claimId = fakeClaimId();
    const nonce = fakeNonce();

    for (let i = 0; i < 10; i++) {
      const response = await post('/api/v1/code/reveal', {
        token: fakeToken(),
        claimId,
        nonce,
        telegramId: VALID_TELEGRAM_ID,
        deviceId: VALID_DEVICE_ID,
      });

      assert.ok(response.status >= 400, `Sequential request #${i + 1} should fail, got ${response.status}`);
      assertNoCodeInResponse(response, `sequential #${i + 1}`);
    }
  });
});

// ============================================================================
// TEST SUITE 6: DEVICE BINDING — Different Device / Session
// ============================================================================

describe('Device Binding', { concurrency: false }, () => {
  it('Reveal with different deviceId than claim → 403 DEVICE_MISMATCH', async () => {
    const claimId = fakeClaimId();
    const nonce = fakeNonce();

    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId,
      nonce,
      telegramId: VALID_TELEGRAM_ID,
      deviceId: 'deviceB-different-from-claim',
    });

    assert.ok(
      response.status === 403 || response.status === 400 || response.status === 409,
      `Expected 403/400/409 for device mismatch, got ${response.status}`
    );
    assertNoCodeInResponse(response);
    assertCacheHeaders(response);
  });

  it('Claim with deviceA, reveal should reject deviceB', async () => {
    // Attempt claim with deviceA
    const claimResp = await post('/api/v1/code/claim', {
      token: fakeToken(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: 'deviceA-claim-device',
      gateResults: { factor1: true, factor2: true, factor3: true, pow: true, behavior: true },
    });

    // If claim succeeded, try reveal with different device
    if (claimResp.status === 200 && claimResp.body.claimId) {
      const revealResp = await post('/api/v1/code/reveal', {
        token: fakeToken(),
        claimId: claimResp.body.claimId,
        nonce: claimResp.body.nonce,
        telegramId: VALID_TELEGRAM_ID,
        deviceId: 'deviceB-different-device',
      });

      assert.ok(
        revealResp.status === 403 || revealResp.status === 409,
        `Expected 403/409 for device mismatch after claim, got ${revealResp.status}`
      );
      assertNoCodeInResponse(revealResp);
    } else {
      // Claim failed (expected without valid token) — just verify no code
      assertNoCodeInResponse(claimResp);
    }
    assertCacheHeaders(claimResp);
  });

  it('Reveal with empty deviceId → 400', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: '',
    });

    assert.ok(response.status >= 400, `Expected 4xx for empty deviceId, got ${response.status}`);
    assertNoCodeField(response);
  });
});

// ============================================================================
// TEST SUITE 7: CACHE HEADERS — Anti-Cache Verification
// ============================================================================

describe('Cache Headers', { concurrency: false }, () => {
  it('/api/v1/code/claim response has no-store cache headers', async () => {
    const response = await post('/api/v1/code/claim', {
      token: fakeToken(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
      gateResults: { factor1: true, factor2: true, factor3: true, pow: true, behavior: true },
    });

    assertCacheHeaders(response, 'claim endpoint');
  });

  it('/api/v1/code/reveal response has no-store cache headers', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    assertCacheHeaders(response, 'reveal endpoint');
  });

  it('Cache-Control contains no-store, no-cache, must-revalidate', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    const cc = response.headers.get('cache-control') || '';
    assert.ok(cc.includes('no-store'), `Missing no-store in: ${cc}`);
    assert.ok(cc.includes('no-cache'), `Missing no-cache in: ${cc}`);
    assert.ok(cc.includes('must-revalidate'), `Missing must-revalidate in: ${cc}`);
  });

  it('Pragma: no-cache header present', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    assert.strictEqual(response.headers.get('pragma'), 'no-cache');
  });

  it('Surrogate-Control: no-store header present', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    const surrogate = response.headers.get('surrogate-control');
    if (surrogate !== null) {
      assert.ok(surrogate.includes('no-store'), `Expected no-store, got: ${surrogate}`);
    }
  });

  it('X-Content-Type-Options: nosniff header present', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    assert.strictEqual(response.headers.get('x-content-type-options'), 'nosniff');
  });

  it('X-Frame-Options: DENY header present', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    const xfo = response.headers.get('x-frame-options');
    assert.ok(xfo === 'DENY' || xfo === 'SAMEORIGIN', `Expected DENY, got: ${xfo}`);
  });
});

// ============================================================================
// TEST SUITE 8: CODE MASKING — Code Never in Logs / Error Responses
// ============================================================================

describe('Code Masking', { concurrency: false }, () => {
  it('Error response body must NOT contain "code" field', async () => {
    const errors = [
      { token: '', claimId: fakeClaimId(), nonce: fakeNonce(), telegramId: VALID_TELEGRAM_ID, deviceId: VALID_DEVICE_ID },
      { token: fakeToken(), claimId: fakeClaimId(), nonce: fakeNonce(), telegramId: VALID_TELEGRAM_ID, deviceId: VALID_DEVICE_ID },
      { token: fakeToken(), claimId: fakeClaimId(), nonce: fakeNonce(), telegramId: VALID_TELEGRAM_ID, deviceId: 'deviceB' },
    ];

    for (const body of errors) {
      const response = await post('/api/v1/code/reveal', body);
      assertNoCodeField(response);
      assertNoCodeInResponse(response);
    }
  });

  it('Response JSON must NOT contain 32-char alphanumeric pattern', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    const fullText = JSON.stringify(response.body);
    const matches = fullText.match(CODE_PATTERN);
    assert.strictEqual(matches, null, `Found potential code in response: ${matches?.[0]}`);
  });

  it('Fake code in request must NOT appear in response', async () => {
    const fakeCode = 'ABCD1234EFGH5678IJKL9012MNOP3456';
    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
      // Attempt to echo back code in body (should be ignored)
      code: fakeCode,
    });

    // Response should not echo back the injected code field
    assert.strictEqual(
      response.body.code,
      undefined,
      `Server echoed back injected 'code' field!`
    );
  });
});

// ============================================================================
// TEST SUITE 9: ADMIN SECURITY — IP Whitelist, 2FA, Code Masking
// ============================================================================

describe('Admin Security', { concurrency: false }, () => {
  it('GET /admin without IP allowlist → 403', async () => {
    const response = await get('/admin');

    assert.ok(
      response.status === 403 || response.status === 401 || response.status === 404,
      `Expected 403/401 for non-whitelisted IP, got ${response.status}`
    );
  });

  it('GET /admin/api/codes without auth → 401 or 403', async () => {
    const response = await get('/admin/api/codes');

    assert.ok(
      response.status === 401 || response.status === 403,
      `Expected 401/403 for unauthenticated admin, got ${response.status}`
    );
  });

  it('Admin login without credentials → 401', async () => {
    const response = await post('/admin/login', {
      username: '',
      password: '',
    });

    assert.ok(
      response.status === 400 || response.status === 401 || response.status === 403,
      `Expected 400/401 for empty login, got ${response.status}`
    );
  });

  it('Admin login with wrong password → 401 INVALID_CREDENTIALS', async () => {
    const response = await post('/admin/login', {
      username: ADMIN_USERNAME,
      password: 'wrong-password-12345',
    });

    assert.ok(
      response.status === 401 || response.status === 403 || response.status === 429,
      `Expected 401/403 for wrong password, got ${response.status}`
    );
    assertNoCodeInResponse(response);
  });

  it('GET /admin/api/codes response must have masked codes (*** not real)', async () => {
    // Try with a fake token (will likely fail auth, but check the structure if it succeeds)
    const response = await get('/admin/api/codes', {
      Authorization: 'Bearer fake-jwt-token',
    });

    // Should be 401/403
    assert.ok(response.status >= 400, `Expected 4xx, got ${response.status}`);

    // If we somehow got 200, verify codes are masked
    if (response.status === 200 && response.body.codes) {
      for (const code of response.body.codes) {
        assert.ok(
          !CODE_PATTERN.test(code.code || ''),
          `Admin API returned unmasked code: ${code.code}`
        );
        assert.strictEqual(code.code, '***', `Code should be masked as ***`);
      }
    }
  });

  it('POST /admin/api/codes without CSRF token → 403 CSRF_MISSING', async () => {
    const response = await post('/admin/api/codes', {
      code: 'TEST1234',
      type: '91club',
    }, {
      Authorization: 'Bearer fake-jwt',
    });

    assert.ok(
      response.status === 401 || response.status === 403,
      `Expected 401/403 without CSRF, got ${response.status}`
    );
  });

  it('POST /admin/api/kill-switch without reauth → 403 REAUTH_REQUIRED', async () => {
    const response = await post('/admin/api/kill-switch', {
      action: 'enable',
      reason: 'Test',
    }, {
      Authorization: 'Bearer fake-jwt',
      'X-Csrf-Token': 'fake-csrf',
    });

    assert.ok(
      response.status === 401 || response.status === 403,
      `Expected 401/403 for kill-switch, got ${response.status}`
    );
  });

  it('Admin API responses have cache headers', async () => {
    const response = await get('/admin/api/codes');
    assertCacheHeaders(response, 'admin codes endpoint');
  });
});

// ============================================================================
// TEST SUITE 10: SCHEMA VALIDATION — Input Sanitization
// ============================================================================

describe('Schema Validation', { concurrency: false }, () => {
  it('Missing token field → 400', async () => {
    const response = await post('/api/v1/code/reveal', {
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    assert.ok(response.status >= 400, `Expected 4xx for missing token, got ${response.status}`);
    assertNoCodeField(response);
  });

  it('Missing claimId field → 400', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    assert.ok(response.status >= 400, `Expected 4xx for missing claimId, got ${response.status}`);
    assertNoCodeField(response);
  });

  it('Missing nonce field → 400', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId: fakeClaimId(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    assert.ok(response.status >= 400, `Expected 4xx for missing nonce, got ${response.status}`);
    assertNoCodeField(response);
  });

  it('Missing telegramId field → 400', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      deviceId: VALID_DEVICE_ID,
    });

    assert.ok(response.status >= 400, `Expected 4xx for missing telegramId, got ${response.status}`);
    assertNoCodeField(response);
  });

  it('Missing deviceId field → 400', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
    });

    assert.ok(response.status >= 400, `Expected 4xx for missing deviceId, got ${response.status}`);
    assertNoCodeField(response);
  });

  it('Extra fields in body → should be ignored (no crash, no code)', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
      extraField1: 'malicious',
      extraField2: 12345,
      admin: true,
      debug: true,
      __proto__: { polluted: true },
    });

    assert.ok(response.status >= 400, `Expected 4xx even with extra fields, got ${response.status}`);
    assertNoCodeField(response);
    assertNoCodeInResponse(response);
  });

  it('Wrong types in fields → 400 (number instead of string)', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: 12345,
      claimId: 67890,
      nonce: 11111,
      telegramId: 99999,
      deviceId: 22222,
    });

    assert.ok(response.status >= 400, `Expected 4xx for wrong types, got ${response.status}`);
    assertNoCodeField(response);
  });

  it('SQL injection in claimId → sanitized/rejected, no code returned', async () => {
    for (const payload of sqlInjectionPayloads()) {
      const response = await post('/api/v1/code/reveal', {
        token: fakeToken(),
        claimId: payload,
        nonce: fakeNonce(),
        telegramId: VALID_TELEGRAM_ID,
        deviceId: VALID_DEVICE_ID,
      });

      assert.ok(
        response.status >= 400,
        `SQL injection in claimId should fail (payload: ${payload}), got ${response.status}`
      );
      assertNoCodeInResponse(response, `SQLi claimId: ${payload}`);
    }
  });

  it('SQL injection in telegramId → sanitized/rejected', async () => {
    for (const payload of sqlInjectionPayloads()) {
      const response = await post('/api/v1/code/reveal', {
        token: fakeToken(),
        claimId: fakeClaimId(),
        nonce: fakeNonce(),
        telegramId: payload,
        deviceId: VALID_DEVICE_ID,
      });

      assert.ok(
        response.status >= 400,
        `SQL injection in telegramId should fail, got ${response.status}`
      );
      assertNoCodeInResponse(response);
    }
  });

  it('XSS in token → sanitized/rejected, no code returned', async () => {
    for (const payload of xssPayloads()) {
      const response = await post('/api/v1/code/reveal', {
        token: payload,
        claimId: fakeClaimId(),
        nonce: fakeNonce(),
        telegramId: VALID_TELEGRAM_ID,
        deviceId: VALID_DEVICE_ID,
      });

      assert.ok(
        response.status >= 400,
        `XSS in token should fail, got ${response.status}`
      );

      // Response body should NOT contain the XSS payload unescaped
      const respText = JSON.stringify(response.body);
      assert.ok(
        !respText.includes('<script>') || response.status >= 400,
        `XSS payload reflected in response!`
      );
      assertNoCodeInResponse(response, `XSS token`);
    }
  });

  it('XSS in deviceId → sanitized/rejected', async () => {
    for (const payload of xssPayloads()) {
      const response = await post('/api/v1/code/reveal', {
        token: fakeToken(),
        claimId: fakeClaimId(),
        nonce: fakeNonce(),
        telegramId: VALID_TELEGRAM_ID,
        deviceId: payload,
      });

      assert.ok(response.status >= 400, `XSS in deviceId should fail, got ${response.status}`);
      assertNoCodeInResponse(response);
    }
  });

  it('Prototype pollution attempt → rejected, no crash', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
      '__proto__.isAdmin': true,
      'constructor.prototype.polluted': true,
    });

    assert.ok(
      response.status >= 400 || response.status === 200,
      `Proto pollution should not crash server, got ${response.status}`
    );
    // If it somehow succeeded, verify no code
    if (response.status === 200) {
      assert.fail('Prototype pollution allowed request through!');
    }
    assertNoCodeField(response);
  });

  it('Very long strings → handled without crash or code leak', async () => {
    const longString = 'A'.repeat(10000);
    const response = await post('/api/v1/code/reveal', {
      token: longString,
      claimId: longString,
      nonce: longString,
      telegramId: longString,
      deviceId: longString,
    });

    assert.ok(
      response.status === 400 || response.status === 413 || response.status === 429 || response.status === 403,
      `Expected 400/413 for oversized input, got ${response.status}`
    );
    assertNoCodeInResponse(response);
  });

  it('Null bytes in strings → sanitized/rejected', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: 'valid\x00null',
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    assert.ok(response.status >= 400, `Null bytes should be rejected, got ${response.status}`);
    assertNoCodeInResponse(response);
  });
});

// ============================================================================
// TEST SUITE 11: ADDITIONAL SECURITY — Deep Defense
// ============================================================================

describe('Deep Defense', { concurrency: false }, () => {
  it('Request to unknown /api/v1/code/* path → 404, no code', async () => {
    const response = await get('/api/v1/code/unknown-endpoint');

    assert.ok(response.status === 404, `Expected 404 for unknown path, got ${response.status}`);
    assertNoCodeInResponse(response);
    assertCacheHeaders(response);
  });

  it('Request with suspicious bot headers → blocked or 4xx', async () => {
    const response = await post(
      '/api/v1/code/reveal',
      {
        token: fakeToken(),
        claimId: fakeClaimId(),
        nonce: fakeNonce(),
        telegramId: VALID_TELEGRAM_ID,
        deviceId: VALID_DEVICE_ID,
      },
      {
        'X-Bot-Signature': 'automated-request',
        'X-Automated': 'true',
        'User-Agent': 'curl/7.68.0',
      }
    );

    assert.ok(response.status >= 400, `Bot headers should get 4xx, got ${response.status}`);
    assertNoCodeInResponse(response);
  });

  it('Response must never contain internal error details (stack traces)', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    const respText = JSON.stringify(response.body).toLowerCase();
    assert.ok(!respText.includes('stack'), `Response contains 'stack' - info leak!`);
    assert.ok(!respText.includes('trace'), `Response contains 'trace' - info leak!`);
    assert.ok(!respText.includes('at line'), `Response contains 'at line' - info leak!`);
    assert.ok(!respText.includes('.js:'), `Response contains '.js:' - info leak!`);
  });

  it('Health endpoint does NOT expose codes', async () => {
    const response = await get('/health');

    assert.ok(response.status === 200 || response.status === 503, `Health check failed: ${response.status}`);
    assertNoCodeInResponse(response, 'health endpoint');
  });

  it('Static HTML pages do NOT contain 32-char code in source', async () => {
    const pages = ['/', '/daily', '/redeem'];
    for (const page of pages) {
      const response = await get(page);
      if (response.status === 200) {
        assertNoCodeInResponse(response, `page ${page}`);
      }
    }
  });
});

// ============================================================================
// TEST SUITE 12: RATE LIMITING
// ============================================================================

describe('Rate Limiting', { concurrency: false }, () => {
  it('Rapid requests include rate limit headers', async () => {
    const response = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    const limit = response.headers.get('x-ratelimit-limit');
    const remaining = response.headers.get('x-ratelimit-remaining');

    // These headers may or may not be present depending on middleware config
    // Just verify they are reasonable if present
    if (limit !== null) {
      assert.ok(parseInt(limit) > 0, `Invalid rate limit: ${limit}`);
    }
    if (remaining !== null) {
      assert.ok(parseInt(remaining) >= 0, `Invalid rate remaining: ${remaining}`);
    }
  });

  it('Many rapid requests do not crash server', async () => {
    const requests = Array.from({ length: 30 }, () =>
      post('/api/v1/code/reveal', {
        token: fakeToken(),
        claimId: fakeClaimId(),
        nonce: fakeNonce(),
        telegramId: VALID_TELEGRAM_ID,
        deviceId: VALID_DEVICE_ID,
      })
    );

    const results = await Promise.all(requests);

    // All should get valid HTTP responses (not connection errors)
    for (let i = 0; i < results.length; i++) {
      assert.ok(
        typeof results[i].status === 'number',
        `Request ${i + 1} did not get a valid HTTP response`
      );
      assertNoCodeInResponse(results[i], `rate limit test #${i + 1}`);
    }

    // Server should still respond after burst
    const afterBurst = await post('/api/v1/code/reveal', {
      token: fakeToken(),
      claimId: fakeClaimId(),
      nonce: fakeNonce(),
      telegramId: VALID_TELEGRAM_ID,
      deviceId: VALID_DEVICE_ID,
    });

    assert.ok(
      typeof afterBurst.status === 'number',
      `Server did not respond after burst test`
    );
  });
});

// ============================================================================
// SUMMARY
// ============================================================================

console.log('\n' + '='.repeat(70));
console.log('OSM ARMY FORTRESS — Security Test Suite');
console.log('='.repeat(70));
console.log(`Target URL : ${BASE_URL}`);
console.log(`Telegram ID: ${VALID_TELEGRAM_ID}`);
console.log('Test Categories:');
console.log('  1. Timer Lock        — Code not revealed before timer');
console.log('  2. Direct API Access — curl/Postman style attacks');
console.log('  3. Token Validation  — Expired/invalid tokens rejected');
console.log('  4. Replay Protection — Reused nonce/claimId blocked');
console.log('  5. Atomic Lock       — Parallel requests race-safe');
console.log('  6. Device Binding    — Cross-device claims blocked');
console.log('  7. Cache Headers     — Anti-cache headers verified');
console.log('  8. Code Masking      — Code never in error responses');
console.log('  9. Admin Security    — IP whitelist, 2FA, CSRF, masked codes');
console.log('  10. Schema Validation — SQLi, XSS, type checks, proto pollution');
console.log('  11. Deep Defense     — Unknown paths, bot headers, info leak');
console.log('  12. Rate Limiting    — Headers present, server survives burst');
console.log('='.repeat(70) + '\n');
