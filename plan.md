# Hardening Plan v3.5 - Complete Lockdown

## 1. Admin Panel Lockdown
- [ ] 2FA mandatory (not optional)
- [ ] IP allowlist
- [ ] Admin API rate limit (10 req/min)
- [ ] CSRF protection
- [ ] Audit logs
- [ ] Code list/export: raw code NEVER shown

## 2. Server/Env Security
- [ ] .env rotation guide
- [ ] Directory listing OFF
- [ ] Debug mode OFF
- [ ] Error sanitization (no stack/code leak)

## 3. Reveal Endpoint Hardening
- [ ] POST only
- [ ] Strict JSON schema validation
- [ ] CORS: own domain only
- [ ] Origin/Referer check
- [ ] Cache no-store
- [ ] Response logs: code masked

## 4. Atomic + Replay Protection
- [ ] Redis claim tickets with 30s TTL
- [ ] Atomic used=false→true (SET NX/Redis transaction)
- [ ] Same claim_id/nonce repeat = block

## 5. Suspicious Verified Users
- [ ] Same IP/device → multiple TG IDs = risk/block
- [ ] Direct API probing = temp block
- [ ] Too many locked requests = cooldown
- [ ] User-agent/device change = re-verify

## 6. Bot/WAF Layer
- [ ] Cloudflare WAF rules
- [ ] Turnstile on suspicious users
- [ ] Rate limits on /timer-status, /claim, /reveal
- [ ] VPN/datacenter/proxy IP check

## 7. Leak Monitoring
- [ ] Every reveal: tg_id, IP, device, claim_id, timestamp
- [ ] Code leak → track who revealed first
- [ ] Daily code rotation
- [ ] Old code instant expiry

## 8. Security Test Suite
- [ ] DevTools check: timer se pehle code nahi
- [ ] curl/Postman: /reveal hit test
- [ ] Expired token test
- [ ] Reused nonce test
- [ ] Parallel 20 requests test
- [ ] Different device/session test
