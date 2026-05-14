# Manual Security Test Checklist

> **Project:** OSM Army Gift Code Fortress
> **Category:** Category 8 — Security Testing
> **Version:** 1.0.0
> **Last Updated:** 2024-01-01

---

## Table of Contents

1. [Pre-Test Setup](#pre-test-setup)
2. [Timer Lock Tests](#timer-lock-tests)
3. [curl/Postman Tests](#curlpostman-tests)
4. [Parallel Request Test](#parallel-request-test)
5. [Admin Security Tests](#admin-security-tests)
6. [Browser DevTools Tests](#browser-devtools-tests)
7. [Network Traffic Tests](#network-traffic-tests)
8. [Mobile Browser Tests](#mobile-browser-tests)
9. [Cleanup & Sign-off](#cleanup--sign-off)

---

## Pre-Test Setup

| # | Step | Status |
|---|------|--------|
| 1 | Server running in production mode (`NODE_ENV=production`) | [ ] |
| 2 | New test code created (32-char alphanumeric, e.g., `ABCD1234EFGH5678IJKL9012MNOP3456`) | [ ] |
| 3 | Timer set to **1 minute** for testing (`timerDuration: 1`) | [ ] |
| 4 | Test Telegram account ready and joined all 3 channels | [ ] |
| 5 | Test device ID assigned (`deviceId=test-device-manual-001`) | [ ] |
| 6 | Browser: Chrome/Firefox with DevTools open | [ ] |
| 7 | Postman or `curl` available for direct API testing | [ ] |
| 8 | Admin panel IP allowlist includes test machine IP | [ ] |
| 9 | 2FA TOTP app configured for admin account | [ ] |
| 10 | MongoDB access to verify `claim_tickets` and `gift_codes` collections | [ ] |

**Command to start server in production mode:**
```bash
NODE_ENV=production PORT=3000 node server.js
```

---

## Timer Lock Tests

### 1.1 Daily Page Timer Display

| # | Step | Expected Result | Status |
|---|------|----------------|--------|
| 1 | Open `https://osmarmy.com/daily.html` | Timer shows `01:00` (or configured time) | [ ] |
| 2 | Verify countdown is actively decrementing | Seconds decrease every second | [ ] |
| 3 | Refresh page — timer should NOT reset | Timer continues from remaining time | [ ] |

### 1.2 DevTools Network Tab — No Early Code Leak

| # | Step | Expected Result | Status |
|---|------|----------------|--------|
| 4 | Open DevTools → **Network** tab | Network panel visible | [ ] |
| 5 | Clear network log | No previous requests shown | [ ] |
| 6 | Wait **10 seconds** while timer counts down | NO API call containing a 32-char code | [ ] |
| 7 | Check for `/api/v1/code/*` calls | No `/reveal` calls made automatically | [ ] |
| 8 | Wait another 20 seconds (30s total) | Still NO automatic code-reveal API calls | [ ] |

### 1.3 Page Source Inspection

| # | Step | Expected Result | Status |
|---|------|----------------|--------|
| 9 | Press `Ctrl+U` (View Page Source) | Source code opens in new tab | [ ] |
| 10 | Search for 32-char alphanumeric string (`Ctrl+F`) | **ZERO matches** for `XXXX0000XXXX0000XXXX0000XXXX0000` pattern | [ ] |
| 11 | Search for `"code":` or `code=` | No hardcoded code values | [ ] |
| 12 | Search for `releaseAt` or `unlock` | May exist but WITHOUT code value attached | [ ] |

### 1.4 localStorage / sessionStorage Check

| # | Step | Expected Result | Status |
|---|------|----------------|--------|
| 13 | DevTools → **Application** → **Local Storage** | Panel opens | [ ] |
| 14 | Check `localStorage` for any code keys | **NO** 32-char value stored | [ ] |
| 15 | Check `sessionStorage` | **NO** 32-char value stored | [ ] |
| 16 | Run in Console: `Object.values(localStorage).join('')` | Output does NOT contain 32-char alphanumeric | [ ] |
| 17 | Run in Console: `Object.values(sessionStorage).join('')` | Output does NOT contain 32-char alphanumeric | [ ] |

### 1.5 Cookie Check

| # | Step | Expected Result | Status |
|---|------|----------------|--------|
| 18 | DevTools → **Application** → **Cookies** | Cookie list visible | [ ] |
| 19 | Check all cookie values | **NO** cookie contains 32-char code | [ ] |
| 20 | Run in Console: `document.cookie` | Output does NOT contain 32-char alphanumeric | [ ] |

### 1.6 Timer Ends → Full Flow

| # | Step | Expected Result | Status |
|---|------|----------------|--------|
| 21 | Wait for timer to reach `00:00` | Timer shows "Time's up!" or similar | [ ] |
| 22 | Click "Claim Code" or trigger claim | `/api/v1/code/claim` called, returns `claimId` + `nonce` | [ ] |
| 23 | Verify claim response has NO `code` field | Response: `{claimId, nonce, expiresIn}` only | [ ] |
| 24 | Immediately call `/api/v1/code/reveal` with claim data | Returns `{code, codeLength, expirySeconds}` | [ ] |
| 25 | Verify received code is **32-char alphanumeric** | Code matches `/^[A-Za-z0-9]{32}$/` | [ ] |
| 26 | Code auto-destructs after expiry period | After `expirySeconds`, code disappears from UI | [ ] |

---

## curl/Postman Tests

### 2.1 Basic Reveal Without Body

```bash
curl -X POST https://osmarmy.com/api/v1/code/reveal \
  -H "Content-Type: application/json"
```

| # | Expected Result | Status |
|---|----------------|--------|
| 1 | HTTP Status: **400** | [ ] |
| 2 | Response has NO `code` field | [ ] |
| 3 | Response body: `{"success":false,"error":"MISSING_PARAMS",...}` | [ ] |
| 4 | `Cache-Control: no-store, no-cache, must-revalidate` present | [ ] |

### 2.2 Reveal with Invalid Token

```bash
curl -X POST https://osmarmy.com/api/v1/code/reveal \
  -H "Content-Type: application/json" \
  -d '{
    "token": "invalid-token-12345",
    "claimId": "abc123def456",
    "nonce": "xyz789",
    "telegramId": "123456789",
    "deviceId": "test-device-001"
  }'
```

| # | Expected Result | Status |
|---|----------------|--------|
| 5 | HTTP Status: **403** or **429** | [ ] |
| 6 | Response has NO `code` field | [ ] |
| 7 | Error code: `INVALID_TOKEN` or `SUSPICIOUS_BLOCKED` | [ ] |
| 8 | Response body does NOT contain 32-char string | [ ] |

### 2.3 Reveal with Expired Token

```bash
# Use a token from 30+ minutes ago
curl -X POST https://osmarmy.com/api/v1/code/reveal \
  -H "Content-Type: application/json" \
  -d '{
    "token": "tok_expired_30min_ago_hexhexhexhex",
    "claimId": "abc123def456",
    "nonce": "xyz789",
    "telegramId": "123456789",
    "deviceId": "test-device-001"
  }'
```

| # | Expected Result | Status |
|---|----------------|--------|
| 9 | HTTP Status: **403** | [ ] |
| 10 | Error code: `INVALID_TOKEN` or `TOKEN_EXPIRED` | [ ] |
| 11 | NO `code` in response | [ ] |

### 2.4 Reveal with Wrong claimId

```bash
curl -X POST https://osmarmy.com/api/v1/code/reveal \
  -H "Content-Type: application/json" \
  -d '{
    "token": "tok_valid_token_here_hexhexhexhex",
    "claimId": "wrongclaimid000000000000000000000000000000000000000000000000",
    "nonce": "correctnonce000000000000000000",
    "telegramId": "123456789",
    "deviceId": "test-device-001"
  }'
```

| # | Expected Result | Status |
|---|----------------|--------|
| 12 | HTTP Status: **400** or **409** | [ ] |
| 13 | NO `code` in response | [ ] |

### 2.5 Reveal with Reused Nonce

```bash
# First request (valid or invalid — must fail safely)
curl -X POST https://osmarmy.com/api/v1/code/reveal \
  -H "Content-Type: application/json" \
  -d '{"token":"tok_1","claimId":"same_claim_id_hexhex","nonce":"same_nonce_hex","telegramId":"123456789","deviceId":"dev1"}'

# Second request (identical)
curl -X POST https://osmarmy.com/api/v1/code/reveal \
  -H "Content-Type: application/json" \
  -d '{"token":"tok_1","claimId":"same_claim_id_hexhex","nonce":"same_nonce_hex","telegramId":"123456789","deviceId":"dev1"}'
```

| # | Expected Result | Status |
|---|----------------|--------|
| 14 | Both requests return 4xx (never 200 with code) | [ ] |
| 15 | Second request: **409 CLAIM_REUSED** or **400** | [ ] |
| 16 | NO `code` in either response | [ ] |

### 2.6 Different Nonce for Same claimId

```bash
curl -X POST https://osmarmy.com/api/v1/code/reveal \
  -H "Content-Type: application/json" \
  -d '{
    "token": "tok_1",
    "claimId": "same_claim_id_hexhexhexhex",
    "nonce": "DIFFERENT_nonce_hexhexhexhex",
    "telegramId": "123456789",
    "deviceId": "dev1"
  }'
```

| # | Expected Result | Status |
|---|----------------|--------|
| 17 | HTTP Status: **403 NONCE_MISMATCH** | [ ] |
| 18 | NO `code` in response | [ ] |

### 2.7 curl Without User-Agent (Bot Signal)

```bash
curl -X POST https://osmarmy.com/api/v1/code/reveal \
  -H "Content-Type: application/json" \
  -H "User-Agent: " \
  -d '{
    "token": "tok_test",
    "claimId": "claim_test",
    "nonce": "nonce_test",
    "telegramId": "123456789",
    "deviceId": "dev1"
  }'
```

| # | Expected Result | Status |
|---|----------------|--------|
| 19 | HTTP Status: **429** or **403** (suspicious guard) | [ ] |
| 20 | NO `code` in response | [ ] |

### 2.8 curl with Suspicious Bot Headers

```bash
curl -X POST https://osmarmy.com/api/v1/code/reveal \
  -H "Content-Type: application/json" \
  -H "X-Bot-Signature: true" \
  -H "X-Automated: script" \
  -d '{
    "token": "tok_test",
    "claimId": "claim_test",
    "nonce": "nonce_test",
    "telegramId": "123456789",
    "deviceId": "dev1"
  }'
```

| # | Expected Result | Status |
|---|----------------|--------|
| 21 | HTTP Status: **429** or **403** (blocked by suspicious guard) | [ ] |
| 22 | `Retry-After` header may be present | [ ] |
| 23 | NO `code` in response | [ ] |

---

## Parallel Request Test

### 3.1 Simultaneous /reveal Burst

```bash
#!/bin/bash
# save as: parallel_test.sh

CLAIM_ID="testclaim_1234567890123456789012345678"
NONCE="testnonce_1234567890123456789012345678"
TOKEN="tok_testparallel_1234567890abcdef"

# Fire 20 simultaneous requests
for i in {1..20}; do
  curl -s -X POST https://osmarmy.com/api/v1/code/reveal \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$TOKEN\",\"claimId\":\"$CLAIM_ID\",\"nonce\":\"$NONCE\",\"telegramId\":\"123456789\",\"deviceId\":\"dev1\"}" \
    -o "resp_$i.json" &
done
wait

# Check results
echo "=== Results ==="
grep -l '"success":true' resp_*.json | wc -l   # Should be 0
grep -l 'CLAIM_REUSED' resp_*.json | wc -l       # Should be ~19
grep -l 'ALREADY_DELIVERED' resp_*.json | wc -l  # Should be ~19
# Check NO response contains 32-char code
grep -E '[A-Za-z0-9]{32}' resp_*.json | grep -v 'claimId\|nonce\|token' | wc -l  # Should be 0
```

| # | Expected Result | Status |
|---|----------------|--------|
| 1 | **Only 1 request succeeds** (gets code) | [ ] |
| 2 | **19 requests get 409 CLAIM_REUSED** or **409 ALREADY_DELIVERED** | [ ] |
| 3 | **0 responses contain 32-char code** in error bodies | [ ] |
| 4 | All 20 responses have cache headers | [ ] |

### 3.2 Verify with Script

```bash
node -e "
const fs = require('fs');
let success = 0, reused = 0, other = 0, codeLeaked = 0;
for (let i = 1; i <= 20; i++) {
  const data = fs.readFileSync('resp_' + i + '.json', 'utf8');
  const obj = JSON.parse(data);
  if (obj.success === true && obj.code) success++;
  else if (obj.error === 'CLAIM_REUSED' || obj.error === 'ALREADY_DELIVERED') reused++;
  else other++;
  if (/[A-Za-z0-9]{32}/.test(data) && !obj.claimId && !obj.nonce) codeLeaked++;
}
console.log('Success:', success, '(expected 0 or 1)');
console.log('Reused:', reused, '(expected ~19)');
console.log('Other errors:', other);
console.log('Code leaks:', codeLeaked, '(expected 0)');
"
```

---

## Admin Security Tests

### 4.1 IP Allowlist

| # | Step | Expected Result | Status |
|---|------|----------------|--------|
| 1 | Access `/admin` from **non-whitelisted IP** | **403 IP_NOT_AUTHORIZED** | [ ] |
| 2 | Access `/admin` from **whitelisted IP** | Login page or dashboard loads | [ ] |
| 3 | Check server logs for blocked IP alert | Log entry: `ADMIN_AUTH_IP_BLOCKED` | [ ] |

### 4.2 Authentication

| # | Step | Expected Result | Status |
|---|------|----------------|--------|
| 4 | POST `/admin/login` with no body | **400** | [ ] |
| 5 | POST `/admin/login` with wrong password (1st try) | **401 INVALID_CREDENTIALS** | [ ] |
| 6 | POST `/admin/login` with wrong password (2nd try) | **401 INVALID_CREDENTIALS** | [ ] |
| 7 | POST `/admin/login` with wrong password (3rd try) | **401 INVALID_CREDENTIALS** | [ ] |
| 8 | POST `/admin/login` with wrong password (4th try) | **429 LOGIN_RATE_LIMITED** | [ ] |
| 9 | POST `/admin/login` with correct credentials + valid TOTP | **200** with JWT token | [ ] |
| 10 | POST `/admin/login` with correct credentials + wrong TOTP | **401 TOTP_INVALID** | [ ] |

### 4.3 CSRF Protection

| # | Step | Expected Result | Status |
|---|------|----------------|--------|
| 11 | POST `/admin/api/codes` **without** `X-CSRF-Token` header | **403 CSRF_MISSING** | [ ] |
| 12 | POST `/admin/api/codes` with mismatched CSRF token | **403 CSRF_INVALID** | [ ] |
| 13 | GET `/admin` → check `csrfToken` cookie is set | Cookie present with `HttpOnly; Secure; SameSite=strict` | [ ] |
| 14 | POST with correct CSRF double-submit (header + cookie) | Request proceeds to auth check | [ ] |

### 4.4 2FA (TOTP)

| # | Step | Expected Result | Status |
|---|------|----------------|--------|
| 15 | POST `/admin/setup-2fa` without auth | **401 AUTH_REQUIRED** | [ ] |
| 16 | POST `/admin/setup-2fa` with auth | Returns QR code + secret | [ ] |
| 17 | POST `/admin/verify-2fa` with wrong 6-digit code | **401 TOTP_INVALID** | [ ] |
| 18 | POST `/admin/verify-2fa` with correct 6-digit code | **200**, 2FA enabled | [ ] |
| 19 | POST `/admin/disable-2fa` without reauth | **403 REAUTH_REQUIRED** | [ ] |
| 20 | POST `/admin/disable-2fa` after reauth + valid TOTP | **200**, 2FA disabled | [ ] |

### 4.5 Admin Code Listing — Masking

| # | Step | Expected Result | Status |
|---|------|----------------|--------|
| 21 | GET `/admin/api/codes` with valid auth | **200**, list of codes returned | [ ] |
| 22 | Check `code` field in each item | Value is `***` (always masked) | [ ] |
| 23 | Verify NO code in response is 32-char alphanumeric | Zero unmasked codes | [ ] |
| 24 | Check `codeHash` field present (SHA256) | Yes, for verification purposes | [ ] |

### 4.6 Admin Dashboard

| # | Step | Expected Result | Status |
|---|------|----------------|--------|
| 25 | GET `/admin/api/dashboard` | Returns stats with masked/safe data | [ ] |
| 26 | Verify NO internal paths leaked | No `.js` file paths, no stack traces | [ ] |

### 4.7 Kill Switch

| # | Step | Expected Result | Status |
|---|------|----------------|--------|
| 27 | POST `/admin/api/kill-switch` without reauth | **403 REAUTH_REQUIRED** | [ ] |
| 28 | POST `/admin/api/kill-switch` with reauth, action=enable | **200**, kill switch enabled | [ ] |
| 29 | Access `/api/v1/code/reveal` while kill switch active | **503 KILL_SWITCH_ACTIVE** | [ ] |
| 30 | POST `/admin/api/kill-switch` with reauth, action=disable | **200**, service restored | [ ] |

---

## Browser DevTools Tests

### 5.1 JavaScript Console

| # | Step | Expected Result | Status |
|---|------|----------------|--------|
| 1 | Open `daily.html` | Page loads, timer visible | [ ] |
| 2 | Console: `document.querySelectorAll('*')` — search for code | No 32-char text nodes | [ ] |
| 3 | Console: Monitor all `fetch()` calls | No `/reveal` calls before timer ends | [ ] |
| 4 | Set breakpoint on `fetch()` | Breakpoint confirms no early calls | [ ] |

### 5.2 Local Override / Script Injection

| # | Step | Expected Result | Status |
|---|------|----------------|--------|
| 5 | Attempt to set `localStorage.code = 'FAKE1234...'` before timer | Stored but ignored by server | [ ] |
| 6 | Attempt to call `fetch('/api/v1/code/reveal')` manually before timer | Returns **403 TIMELOCK_ACTIVE** | [ ] |
| 7 | Attempt to modify `Date.now()` via console override | Server uses its own clock — still blocked | [ ] |

### 5.3 WebSocket / SSE Check

| # | Step | Expected Result | Status |
|---|------|----------------|--------|
| 8 | Check for WebSocket connections | None expected (uses HTTP only) | [ ] |
| 9 | Check for Server-Sent Events | None expected | [ ] |

---

## Network Traffic Tests

### 6.1 Intercept with Burp/OWASP ZAP (Optional)

| # | Step | Expected Result | Status |
|---|------|----------------|--------|
| 1 | Proxy browser through Burp Suite | All traffic visible | [ ] |
| 2 | Complete full claim flow | `/claim` → `/reveal` sequence observed | [ ] |
| 3 | Verify `/reveal` only called AFTER timer expiry | Timestamp of `/reveal` > `releaseAt` | [ ] |
| 4 | Check `/reveal` request contains `claimId` + `nonce` | Yes (ticket data, NOT the code) | [ ] |
| 5 | Check `/reveal` response contains `code` field ONLY on 200 | Error responses have NO `code` | [ ] |
| 6 | Replay `/reveal` request with same `claimId` + `nonce` | **409 CLAIM_REUSED** | [ ] |

### 6.2 SSL/TLS Verification

| # | Step | Expected Result | Status |
|---|------|----------------|--------|
| 7 | Verify HTTPS only (no HTTP on port 80) | Redirect or connection refused | [ ] |
| 8 | Check TLS version (`openssl s_client -connect`) | TLS 1.2+ required | [ ] |
| 9 | Check certificate validity | Valid, not expired | [ ] |
| 10 | Check HSTS header | `Strict-Transport-Security` present | [ ] |

---

## Mobile Browser Tests

### 7.1 Mobile Safari / Chrome

| # | Step | Expected Result | Status |
|---|------|----------------|--------|
| 1 | Open `daily.html` on iOS Safari | Timer renders correctly | [ ] |
| 2 | Complete full claim → reveal flow | Code delivered after timer | [ ] |
| 3 | Check code is copyable | Tap to copy works | [ ] |
| 4 | Verify code auto-destructs | Disappears after expiry | [ ] |

### 7.2 Incognito / Private Mode

| # | Step | Expected Result | Status |
|---|------|----------------|--------|
| 5 | Open in Incognito mode | Timer starts fresh (no cached data) | [ ] |
| 6 | Complete flow | Works normally | [ ] |
| 7 | Close and reopen Incognito | Previous code NOT accessible | [ ] |

---

## Cleanup & Sign-off

### 8.1 Data Cleanup

| # | Step | Status |
|---|------|--------|
| 1 | Delete test `claim_tickets` from MongoDB | [ ] |
| 2 | Delete test `audit_logs` entries | [ ] |
| 3 | Reset admin login attempt counters | [ ] |
| 4 | Disable kill switch if enabled | [ ] |

### 8.2 Test Summary

| Category | Tests | Passed | Failed |
|----------|-------|--------|--------|
| Pre-Test Setup | 10 | __ | __ |
| Timer Lock Tests | 26 | __ | __ |
| curl/Postman Tests | 23 | __ | __ |
| Parallel Request Test | 4 | __ | __ |
| Admin Security Tests | 30 | __ | __ |
| Browser DevTools Tests | 9 | __ | __ |
| Network Traffic Tests | 10 | __ | __ |
| Mobile Browser Tests | 7 | __ | __ |
| **TOTAL** | **119** | **__** | **__** |

### 8.3 Sign-off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Security Tester | ________________ | ________ | ___________ |
| DevOps Reviewer | ________________ | ________ | ___________ |
| Security Lead | ________________ | ________ | ___________ |

### 8.4 Final Checklist

- [ ] All 10 automated test categories pass (`node --test tests/security.test.js`)
- [ ] All manual tests documented above executed
- [ ] No 32-char code leaked in any error response
- [ ] No code found in page source, localStorage, or cookies
- [ ] Atomic lock verified (parallel test)
- [ ] Admin IP whitelist + 2FA + CSRF verified
- [ ] Rate limiting functional
- [ ] Kill switch operational
- [ ] Server logs reviewed for anomalies
- [ ] Production deployment approved

---

## Quick Reference: curl Commands

```bash
# 1. Health check
curl -s https://osmarmy.com/health | jq .

# 2. Reveal with invalid token (expect 403)
curl -s -X POST https://osmarmy.com/api/v1/code/reveal \
  -H "Content-Type: application/json" \
  -d '{"token":"invalid","claimId":"abc","nonce":"xyz","telegramId":"123","deviceId":"dev"}' | jq .

# 3. Reveal before timer (expect TIMELOCK_ACTIVE)
curl -s -X POST https://osmarmy.com/api/v1/code/reveal \
  -H "Content-Type: application/json" \
  -d '{"token":"tok_test","claimId":"claim_test","nonce":"nonce_test","telegramId":"123456789","deviceId":"test-device"}' | jq .

# 4. Admin login (expect 401 with wrong pass)
curl -s -X POST https://osmarmy.com/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrong"}' | jq .

# 5. Admin codes without auth (expect 401)
curl -s https://osmarmy.com/admin/api/codes | jq .

# 6. Parallel burst test (20 requests)
for i in {1..20}; do
  curl -s -X POST https://osmarmy.com/api/v1/code/reveal \
    -H "Content-Type: application/json" \
    -d '{"token":"tok_same","claimId":"claim_same","nonce":"nonce_same","telegramId":"123","deviceId":"dev"}' &
done; wait
```

---

*End of Manual Security Test Checklist — OSM Army Gift Code Fortress*
