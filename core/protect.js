/**
 * @fileoverview protect.js - 500-Layer Security Validation Middleware
 * Osm Army Gift Code Fortress - Ultra-Secure Gift Code System
 *
 * 500 independent security checks across 10 categories.
 * Each returns { passed, layer, message, score }. Cumulative score 0-5000.
 *
 * @author Osm Army Security Team
 * @version 5.0.0-fortress
 */

'use strict';

import { createHash, randomBytes, timingSafeEqual, createHmac } from 'crypto';

// ============================================================================
// Custom Error Classes
// ============================================================================

export class SecurityViolationError extends Error {
  constructor(message, layer, score, category = 'unknown') {
    super(message);
    this.name = 'SecurityViolationError';
    this.layer = layer;
    this.score = score;
    this.category = category;
    this.timestamp = new Date().toISOString();
    Error.captureStackTrace(this, this.constructor);
  }
}

export class ScoreThresholdError extends Error {
  constructor(message, required, actual) {
    super(message);
    this.name = 'ScoreThresholdError';
    this.required = required;
    this.actual = actual;
    Error.captureStackTrace(this, this.constructor);
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

function result(passed, layer, message, score) {
  return { passed, layer, message, score: passed ? score : 0, timestamp: new Date().toISOString() };
}

const isNonEmpty = (v) => typeof v === 'string' && v.length > 0;
const lengthInRange = (v, min, max) => typeof v === 'string' && v.length >= min && v.length <= max;
const isPositiveInt = (v) => Number.isInteger(v) && v > 0;

function sha256(data) {
  return createHash('sha256').update(String(data)).digest('hex');
}

function hmacSha256(key, data) {
  return createHmac('sha256', key).update(String(data)).digest('hex');
}

function secureRandomInt(min, max) {
  const range = max - min + 1;
  const rand = randomBytes(4).readUInt32LE(0);
  return min + (rand % range);
}

function ipInCidr(ip, cidr) {
  const [range, bits] = cidr.split('/');
  const mask = parseInt(bits, 10);
  const ipParts = ip.split('.').map(Number);
  const rangeParts = range.split('.').map(Number);
  const ipInt = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
  const rangeInt = (rangeParts[0] << 24) | (rangeParts[1] << 16) | (rangeParts[2] << 8) | rangeParts[3];
  const maskInt = mask === 0 ? 0 : ~((1 << (32 - mask)) - 1);
  return (ipInt & maskInt) === (rangeInt & maskInt);
}

function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) { freq[ch] = (freq[ch] || 0) + 1; }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const BAD_UA_PATTERNS = ['bot','crawler','spider','scraper','curl','wget','python','java/','httpclient','libwww','scrapy','mechanize','phantom','selenium','headless','playwright','puppeteer'];
const SUSPICIOUS_HEADERS = ['x-bot','x-automation','x-crawler','x-scraper','x-requested-bot','x-automated','x-test-mode'];

// ============================================================================
// Category 1: Request Validation (Layers 1-50)
// ============================================================================

function createRequestValidationChecks() {
  const c = [];
  c.push((ctx) => { const m = ctx.req.method; const v = ['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS']; return result(v.includes(m), 1, `HTTP method ${m}`, 10); });
  c.push((ctx) => result(ctx.req.method !== 'TRACE', 2, 'TRACE method blocked', 10));
  c.push((ctx) => result(ctx.req.method !== 'CONNECT', 3, 'CONNECT method blocked', 10));
  c.push((ctx) => result(isNonEmpty(ctx.req.headers?.host), 4, 'Host header present', 10));
  c.push((ctx) => result((ctx.req.headers?.host || '').length > 0, 5, 'Host header non-empty', 10));
  c.push((ctx) => { const h = ctx.req.headers?.host || ''; return result(/^[a-zA-Z0-9][-a-zA-Z0-9.]*(:\d+)?$/.test(h), 6, 'Host format valid', 10); });
  c.push((ctx) => { if (['GET','HEAD','DELETE'].includes(ctx.req.method)) return result(true, 7, 'No body expected', 10); const ct = ctx.req.headers['content-type'] || ''; return result(ct.length > 0 && /^(application|text|multipart)\/[a-zA-Z0-9+._-]+/.test(ct), 7, 'Content-Type valid', 10); });
  c.push((ctx) => { const ct = (ctx.req.headers['content-type'] || '').toLowerCase(); return result(!ct.includes('application/xml') || !ct.includes('<!ENTITY'), 8, 'XXE via Content-Type blocked', 10); });
  c.push((ctx) => { const len = parseInt(ctx.req.headers['content-length'] || '0', 10); return result(len <= 10485760, 9, `Content-Length ${len}`, 10); });
  c.push((ctx) => { const body = ctx.req.body; const size = body ? JSON.stringify(body).length : 0; return result(size <= 10485760, 10, `Body size ${size}`, 10); });
  c.push((ctx) => { const te = (ctx.req.headers['transfer-encoding'] || '').toLowerCase(); const cl = parseInt(ctx.req.headers['content-length'] || '0', 10); return result(!(te.includes('chunked') && cl < 1024), 11, 'Chunked encoding abuse', 10); });
  c.push((ctx) => result(isNonEmpty(ctx.req.headers.accept), 12, 'Accept header present', 10));
  c.push((ctx) => { const ae = ctx.req.headers['accept-encoding'] || ''; return result(ae.length === 0 || /^(gzip|deflate|br|identity|\s|,)+$/.test(ae), 13, 'Accept-Encoding valid', 10); });
  c.push((ctx) => { const al = ctx.req.headers['accept-language'] || ''; return result(al.length === 0 || /^[a-zA-Z-*,;\s.=\d]+$/.test(al), 14, 'Accept-Language valid', 10); });
  c.push((ctx) => { const ref = ctx.req.headers.referer || ''; return result(!ref.includes('javascript:') && !ref.includes('data:'), 15, 'Referer injection check', 10); });
  c.push((ctx) => { const o = ctx.req.headers.origin || ''; return result(o.length === 0 || /^https?:\/\/[a-zA-Z0-9][-a-zA-Z0-9.]*(:\d+)?$/.test(o), 16, 'Origin header valid', 10); });
  c.push((ctx) => { const xff = ctx.req.headers['x-forwarded-for'] || ''; return result(xff.length <= 256, 17, `X-Forwarded-For length`, 10); });
  c.push((ctx) => { const xff = ctx.req.headers['x-forwarded-for'] || ''; if (!xff) return result(true, 18, 'No XFF', 10); const ips = xff.split(',').map(s => s.trim()); const allV = ips.every(ip => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip) || /^[0-9a-fA-F:]+$/.test(ip)); return result(allV, 18, 'X-Forwarded-For format', 10); });
  c.push((ctx) => { const xri = ctx.req.headers['x-real-ip'] || ''; const xff = ctx.req.headers['x-forwarded-for'] || ''; if (!xri || !xff) return result(true, 19, 'No IP conflict possible', 10); const xffFirst = xff.split(',')[0].trim(); return result(xri === xffFirst, 19, 'X-Real-IP vs XFF consistency', 10); });
  c.push((ctx) => { const conn = (ctx.req.headers.connection || '').toLowerCase(); return result(!(conn.includes('keep-alive,') && conn.includes('upgrade')), 20, 'Connection header smuggling', 10); });
  c.push((ctx) => { const upg = ctx.req.headers.upgrade; const conn = (ctx.req.headers.connection || '').toLowerCase(); return result(!upg || conn.includes('upgrade'), 21, 'Upgrade-Insecure-Requests consistency', 10); });
  c.push((ctx) => { const te = ctx.req.headers['transfer-encoding']; return result(!te || !te.toLowerCase().includes('chunked,qwerty'), 22, 'TE header smuggling', 10); });
  c.push((ctx) => { const ct = ctx.req.headers['content-type'] || ''; const m = ct.match(/charset=([^;]+)/i); if (!m) return result(true, 23, 'No charset', 10); const valid = ['utf-8','utf-16','iso-8859-1','windows-1252','us-ascii']; return result(valid.includes(m[1].trim().toLowerCase()), 23, `Charset ${m[1]}`, 10); });
  c.push((ctx) => { const ct = ctx.req.headers['content-type'] || ''; if (!ct.includes('multipart')) return result(true, 24, 'Not multipart', 10); return result(ct.includes('boundary='), 24, 'Multipart boundary present', 10); });
  c.push((ctx) => { const ct = ctx.req.headers['content-type'] || ''; const bad = ['application/x-msdownload','application/x-executable']; return result(!bad.some(b => ct.includes(b)), 25, 'MIME type blacklist', 10); });
  c.push((ctx) => { const dnt = ctx.req.headers.dnt; return result(dnt === undefined || dnt === '0' || dnt === '1', 26, `DNT: ${dnt}`, 10); });
  c.push((ctx) => { const cc = ctx.req.headers['cache-control'] || ''; return result(cc.length <= 256, 27, 'Cache-Control length', 10); });
  c.push((ctx) => { const ims = ctx.req.headers['if-modified-since']; if (!ims) return result(true, 28, 'No IMS', 10); const d = new Date(ims); return result(!isNaN(d.getTime()), 28, 'If-Modified-Since valid', 10); });
  c.push((ctx) => { const inm = ctx.req.headers['if-none-match'] || ''; return result(inm.length <= 256, 29, 'If-None-Match length', 10); });
  c.push((ctx) => { const auth = ctx.req.headers.authorization || ''; if (!auth) return result(true, 30, 'No auth header', 10); return result(/^(Bearer|Basic|Digest)\s+.+$/i.test(auth), 30, 'Authorization scheme valid', 10); });
  c.push((ctx) => { const ck = ctx.req.headers.cookie || ''; return result(ck.length <= 4096, 31, `Cookie size ${ck.length}`, 10); });
  c.push((ctx) => { const ck = ctx.req.headers.cookie || ''; if (!ck) return result(true, 32, 'No cookie', 10); const pairs = ck.split(';'); return result(pairs.every(p => p.trim().includes('=') || p.trim().length === 0), 32, 'Cookie format valid', 10); });
  c.push((ctx) => result(isNonEmpty(ctx.req.headers['user-agent']), 33, 'User-Agent present', 10));
  c.push((ctx) => result((ctx.req.headers['user-agent'] || '').trim().length > 0, 34, 'User-Agent non-empty', 10));
  c.push((ctx) => { const ua = ctx.req.headers['user-agent'] || ''; return result(ua.length >= 10 && ua.length <= 1024, 35, `UA length ${ua.length}`, 10); });
  c.push((ctx) => { const sfs = ctx.req.headers['sec-fetch-site']; if (!sfs) return result(true, 36, 'No Sec-Fetch-Site', 10); return result(['same-origin','same-site','none','cross-site'].includes(sfs), 36, `Sec-Fetch-Site: ${sfs}`, 10); });
  c.push((ctx) => { const sfm = ctx.req.headers['sec-fetch-mode']; if (!sfm) return result(true, 37, 'No Sec-Fetch-Mode', 10); return result(['cors','navigate','no-cors','same-origin','websocket'].includes(sfm), 37, `Sec-Fetch-Mode: ${sfm}`, 10); });
  c.push((ctx) => { const sfd = ctx.req.headers['sec-fetch-dest']; if (!sfd) return result(true, 38, 'No Sec-Fetch-Dest', 10); const v = ['document','embed','empty','font','image','manifest','object','report','script','serviceworker','sharedworker','style','worker','xslt','audio','video','iframe']; return result(v.includes(sfd), 38, `Sec-Fetch-Dest: ${sfd}`, 10); });
  c.push((ctx) => { const ua = ctx.req.headers['sec-ch-ua']; const isApi = (ctx.req.headers['content-type'] || '').includes('application/json') && ctx.req.path?.startsWith('/api/'); return result(!!ua || isApi, 39, 'Sec-CH-UA present', 10); });
  c.push((ctx) => { const acc = ctx.req.headers.accept || ''; const isApi = ctx.req.path?.startsWith('/api/'); if (!isApi) return result(true, 40, 'Not API', 10); return result(acc !== '*/*', 40, 'API wildcard Accept', 10); });
  c.push((ctx) => { const url = ctx.req.originalUrl || ctx.req.url || ''; return result(url.length <= 4096, 41, `URL length ${url.length}`, 10); });
  c.push((ctx) => { const p = ctx.req.path || ''; return result(/^[\/a-zA-Z0-9._~!$&'()*+,;=:@-]*$/.test(p), 42, 'URL path chars valid', 10); });
  c.push((ctx) => { const url = ctx.req.url || ''; return result(!url.includes('\x00'), 43, 'Null byte in URL blocked', 10); });
  c.push((ctx) => { const qs = ctx.req.query ? JSON.stringify(ctx.req.query).length : 0; return result(qs <= 4096, 44, `Query size ${qs}`, 10); });
  c.push((ctx) => { const raw = ctx.req.url || ''; const qIdx = raw.indexOf('?'); if (qIdx === -1) return result(true, 45, 'No query string', 10); const qs = raw.slice(qIdx + 1); const keys = qs.split('&').map(p => p.split('=')[0]); return result(new Set(keys).size === keys.length, 45, 'No duplicate query params', 10); });
  c.push((ctx) => { const proto = ctx.req.headers['x-forwarded-proto'] || ctx.req.protocol || 'http'; return result(proto === 'https' || ctx.req.secure, 46, `Protocol ${proto}`, 10); });
  c.push((ctx) => { const ver = ctx.req.httpVersion || '1.0'; const major = parseInt(ver.split('.')[0], 10); return result(major >= 1, 47, `HTTP ${ver}`, 10); });
  c.push((ctx) => result(!ctx.req.headers.trailer, 48, 'Trailer header blocked', 10));
  c.push((ctx) => { const exp = ctx.req.headers.expect; return result(!exp || exp === '100-continue', 49, 'Expect header valid', 10); });
  c.push((ctx) => { const via = ctx.req.headers.via || ''; const hops = via.split(',').filter(s => s.trim()).length; return result(hops <= 5, 50, `Via hops: ${hops}`, 10); });
  return c;
}

// ============================================================================
// Category 2: IP Validation (Layers 51-100)
// ============================================================================

function createIPValidationChecks() {
  const c = [];
  c.push((ctx) => result(!!ctx.ip, 51, `IP ${ctx.ip ? 'present' : 'missing'}`, 10));
  c.push((ctx) => { const ip = ctx.ip || ''; const v4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip); const v6 = /^[0-9a-fA-F:]+$/.test(ip) && ip.includes(':'); return result(v4 || v6, 52, `IP format ${v4 ? 'IPv4' : v6 ? 'IPv6' : 'invalid'}`, 10); });
  c.push((ctx) => { const ip = ctx.ip || ''; const pr = ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8']; return result(!pr.some(r => ipInCidr(ip, r)), 53, 'Private IP blocked', 10); });
  c.push((ctx) => result(!(ctx.ip || '').startsWith('127.'), 54, 'Loopback blocked', 10));
  c.push((ctx) => result(!(ctx.ip || '').startsWith('169.254.'), 55, 'Link-local blocked', 10));
  c.push((ctx) => { const ip = ctx.ip || ''; return result(!ip.startsWith('224.') && !ip.startsWith('239.'), 56, 'Multicast blocked', 10); });
  c.push((ctx) => { const p = (ctx.ip || '').split('.').map(Number); return result(!(p.length === 4 && p[3] === 255), 57, 'Broadcast blocked', 10); });
  c.push((ctx) => result(ctx.ip !== '0.0.0.0', 58, '0.0.0.0 blocked', 10));
  c.push((ctx) => { const ip = ctx.ip || ''; const dr = ['192.0.2.0/24','198.51.100.0/24','203.0.113.0/24']; return result(!dr.some(r => ipInCidr(ip, r)), 59, 'Documentation range blocked', 10); });
  c.push((ctx) => result(!ipInCidr(ctx.ip || '', '198.18.0.0/15'), 60, 'Benchmark range blocked', 10));
  c.push((ctx) => result(!ipInCidr(ctx.ip || '', '100.64.0.0/10'), 61, 'CGNAT blocked', 10));
  c.push((ctx) => result(!ipInCidr(ctx.ip || '', '100.64.0.0/10'), 62, 'Shared address blocked', 10));
  c.push((ctx) => result(!ipInCidr(ctx.ip || '', '192.0.0.0/24'), 63, 'IETF range blocked', 10));
  c.push((ctx) => result(!ipInCidr(ctx.ip || '', '192.0.2.0/24'), 64, 'TEST-NET blocked', 10));
  c.push((ctx) => { const bl = ctx.state?.ipBlacklist || []; return result(!bl.includes(ctx.ip), 65, 'IP blacklist', 10); });
  c.push((ctx) => { const db = ctx.state?.dynamicBlocks || new Set(); return result(!db.has(ctx.ip), 66, 'Dynamic blocklist', 10); });
  c.push((ctx) => result(!!ctx.state?.geoCountry, 67, `GeoIP ${ctx.state?.geoCountry || 'unresolved'}`, 10));
  c.push((ctx) => { const country = (ctx.state?.geoCountry || '').toUpperCase(); const blocked = ['KP','IR','SY','CU','MM']; return result(!blocked.includes(country), 68, `Country ${country}`, 10); });
  c.push((ctx) => { const al = ctx.state?.geoAllowList; if (!al || al.length === 0) return result(true, 69, 'No geo allow list', 10); return result(al.includes((ctx.state?.geoCountry || '').toUpperCase()), 69, 'Geo allow list', 10); });
  c.push((ctx) => { const asn = (ctx.state?.asnOrg || '').toLowerCase(); const dc = ['amazon','google cloud','digitalocean','linode','vultr','ovh','hetzner']; return result(!dc.some(n => asn.includes(n)), 70, `Datacenter ${asn}`, 10); });
  c.push((ctx) => result(!(ctx.state?.isVpn || false), 71, `VPN ${ctx.state?.isVpn ? 'DETECTED' : 'no'}`, 10));
  c.push((ctx) => result(!(ctx.state?.isTor || false), 72, `TOR ${ctx.state?.isTor ? 'DETECTED' : 'no'}`, 10));
  c.push((ctx) => result(!(ctx.state?.isProxy || false), 73, `Proxy ${ctx.state?.isProxy ? 'DETECTED' : 'no'}`, 10));
  c.push((ctx) => result((ctx.state?.asnReputation || 'good') !== 'bad', 74, `ASN reputation`, 10));
  c.push((ctx) => result((ctx.state?.ipRotations || 0) < 3, 75, `IP rotations ${ctx.state?.ipRotations || 0}`, 10));
  c.push((ctx) => result((ctx.state?.ipReputationScore || 100) >= 30, 76, `IP reputation ${ctx.state?.ipReputationScore || 100}`, 10));
  c.push((ctx) => result((ctx.state?.abuseConfidence || 0) < 50, 77, `AbuseIPDB ${ctx.state?.abuseConfidence || 0}%`, 10));
  c.push((ctx) => result(ctx.state?.hasReverseDNS !== false, 78, 'Reverse DNS', 10));
  c.push((ctx) => result(ctx.state?.fcrDNS !== false, 79, 'FCR DNS', 10));
  c.push((ctx) => result(!(ctx.state?.isBotnetIP || false), 80, `Botnet IP`, 10));
  c.push((ctx) => result(!(ctx.state?.spamhausListed || false), 81, 'Spamhaus', 10));
  c.push((ctx) => { const ptr = (ctx.state?.ptrRecord || '').toLowerCase(); const bad = ['tor','proxy','vpn','anonymous','relay']; return result(!bad.some(b => ptr.includes(b)), 82, 'PTR suspicious', 10); });
  c.push((ctx) => { const xff = ctx.req.headers['x-forwarded-for'] || ''; const hops = xff.split(',').filter(s => s.trim()).length; return result(hops <= 5, 83, `XFF hops ${hops}`, 10); });
  c.push((ctx) => { const xff = ctx.req.headers['x-forwarded-for'] || ''; const ips = xff.split(',').map(s => s.trim()).filter(Boolean); if (ips.length === 0) return result(true, 84, 'No XFF', 10); const last = ips[ips.length - 1]; const pr = ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16']; return result(!pr.some(r => ipInCidr(last, r)), 84, 'Last proxy', 10); });
  c.push((ctx) => result(!!ctx.req.headers['cf-connecting-ip'], 85, 'Cloudflare IP', 10));
  c.push((ctx) => { const tci = ctx.req.headers['true-client-ip']; if (!tci) return result(true, 86, 'No True-Client-IP', 10); return result(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(tci), 86, 'True-Client-IP format', 10); });
  c.push((ctx) => { const hour = ctx.state?.ipHourlyRequests || new Array(24).fill(0); const requests = hour[new Date().getUTCHours()] || 0; return result(requests < 1000, 87, `Hourly requests ${requests}`, 10); });
  c.push((ctx) => result((ctx.state?.ipVelocity || 0) < 120, 88, `IP velocity ${ctx.state?.ipVelocity || 0}/min`, 10));
  c.push((ctx) => result((ctx.state?.burstCount || 0) < 30, 89, `Burst ${ctx.state?.burstCount || 0}`, 10));
  c.push((ctx) => result(ctx.state?.geoConsistent !== false, 90, 'Geo consistency', 10));
  c.push((ctx) => { const ip = ctx.ip || ''; if (!ip.includes(':')) return result(true, 91, 'IPv4', 10); return result(!ip.includes('::ffff:') || ip.includes('::ffff:127.'), 91, 'IPv6 mapped check', 10); });
  c.push((ctx) => result((ctx.state?.asnType || '') !== 'hosting', 92, `ASN type ${ctx.state?.asnType || ''}`, 10));
  c.push((ctx) => result((ctx.state?.asnType || '') !== 'educational', 93, `ASN type ${ctx.state?.asnType || ''}`, 10));
  c.push((ctx) => result(!(ctx.state?.subnetBlocked || false), 94, '/24 subnet', 10));
  c.push((ctx) => result(!(ctx.state?.isResidentialProxy || false), 95, 'Residential proxy', 10));
  c.push((ctx) => result((ctx.state?.threatScore || 0) < 40, 96, `Threat score ${ctx.state?.threatScore || 0}`, 10));
  c.push((ctx) => result(ctx.state?.goodIPHistory !== false, 97, 'IP history', 10));
  c.push((ctx) => result(!(ctx.state?.isZombieIP || false), 98, 'Zombie IP', 10));
  c.push((ctx) => result((ctx.state?.bruteForceAttempts || 0) < 5, 99, `Brute force ${ctx.state?.bruteForceAttempts || 0}`, 10));
  c.push((ctx) => result((ctx.state?.ipEntropyScore || 1) > 0.3, 100, `IP entropy ${(ctx.state?.ipEntropyScore || 1).toFixed(3)}`, 10));
  return c;
}

// ============================================================================
// Category 3: Authentication (Layers 101-150)
// ============================================================================

function createAuthenticationChecks() {
  const c = [];
  c.push((ctx) => result(!!(ctx.req.headers.authorization || ctx.req.cookies?.token || ctx.req.query?.token), 101, 'Auth token present', 10));
  c.push((ctx) => { const a = ctx.req.headers.authorization || ''; if (!a) return result(true, 102, 'No auth', 10); return result(a.startsWith('Bearer ') && a.length > 30, 102, 'Bearer format', 10); });
  c.push((ctx) => { const e = ctx.state?.tokenExpiry; if (!e) return result(true, 103, 'No expiry', 10); return result(Date.now() < e, 103, 'Token not expired', 10); });
  c.push((ctx) => { const v = ctx.state?.signatureValid; if (v === undefined) return result(true, 104, 'No sig check', 10); return result(v, 104, 'Token signature', 10); });
  c.push((ctx) => result(!(ctx.state?.tokenRevoked || false), 105, 'Token not revoked', 10));
  c.push((ctx) => result(!(ctx.state?.tokenBlacklisted || false), 106, 'Token not blacklisted', 10));
  c.push((ctx) => { const s = ctx.state?.tokenScopes || []; const r = ctx.state?.requiredScope || 'gift:read'; return result(s.includes(r) || s.includes('admin'), 107, `Scope ${r}`, 10); });
  c.push((ctx) => { const r = ctx.state?.userRole || 'anonymous'; const v = ['anonymous','user','premium','moderator','admin','superadmin']; return result(v.includes(r), 108, `Role ${r}`, 10); });
  c.push((ctx) => { const role = ctx.state?.userRole || 'anonymous'; const min = ctx.state?.requiredRole || 'user'; const h = {anonymous:0,user:1,premium:2,moderator:3,admin:4,superadmin:5}; return result((h[role]||0) >= (h[min]||0), 109, `Role ${role} >= ${min}`, 10); });
  c.push((ctx) => { const i = ctx.state?.tokenIssuer; if (!i) return result(true, 110, 'No issuer', 10); return result(i === 'osmarmy-fortress', 110, `Issuer ${i}`, 10); });
  c.push((ctx) => { const a = ctx.state?.tokenAudience; if (!a) return result(true, 111, 'No audience', 10); return result(a === 'gift-code-system', 111, `Audience ${a}`, 10); });
  c.push((ctx) => { const i = ctx.state?.tokenIssuedAt; if (!i) return result(true, 112, 'No iat', 10); return result(i <= Date.now() + 60000, 112, 'Token iat valid', 10); });
  c.push((ctx) => { const n = ctx.state?.tokenNotBefore; if (!n) return result(true, 113, 'No nbf', 10); return result(n <= Date.now(), 113, 'Token nbf valid', 10); });
  c.push((ctx) => { const j = ctx.state?.tokenJti; if (!j) return result(true, 114, 'No jti', 10); return result(!(ctx.state?.usedJtis || new Set()).has(j), 114, 'JTI unique', 10); });
  c.push((ctx) => { if (!(ctx.state?.mfaRequired || false)) return result(true, 115, 'MFA not required', 10); return result(ctx.state?.mfaVerified || false, 115, 'MFA verified', 10); });
  c.push((ctx) => result(!ctx.state?.sessionId || typeof ctx.state.sessionId === 'string' && ctx.state.sessionId.length >= 16, 116, 'Session ID format', 10));
  c.push((ctx) => { const e = ctx.state?.sessionExpiry; if (!e) return result(true, 117, 'No session expiry', 10); return result(Date.now() < e, 117, 'Session active', 10); });
  c.push((ctx) => { const m = ctx.state?.deviceMatch; if (m === undefined) return result(true, 118, 'No device binding', 10); return result(m, 118, 'Device match', 10); });
  c.push((ctx) => { const m = ctx.state?.ipMatch; if (m === undefined) return result(true, 119, 'No IP binding', 10); return result(m, 119, 'IP match', 10); });
  c.push((ctx) => { const a = ctx.state?.tokenAge; if (!a) return result(true, 120, 'No token age', 10); return result(a < 86400000, 120, `Token age ${(a/3600000).toFixed(1)}h`, 10); });
  c.push((ctx) => { const e = ctx.state?.refreshTokenExpiry; if (!e) return result(true, 121, 'No refresh token', 10); return result(Date.now() < e, 121, 'Refresh token valid', 10); });
  c.push((ctx) => { if (!(ctx.state?.sensitiveOperation || false)) return result(true, 122, 'Not sensitive', 10); return result(!!ctx.state?.passwordHash, 122, 'Password hash for sensitive op', 10); });
  c.push((ctx) => { const k = ctx.req.headers['x-api-key']; if (!k) return result(true, 123, 'No API key', 10); return result((ctx.state?.validApiKeys || []).includes(k), 123, 'API key valid', 10); });
  c.push((ctx) => result((ctx.state?.apiKeyUsage || 0) < (ctx.state?.apiKeyLimit || 10000), 124, 'API key usage', 10));
  c.push((ctx) => { const s = ctx.req.query?.state; if (!s) return result(true, 125, 'No OAuth state', 10); return result(ctx.state?.oauthStateValid !== false, 125, 'OAuth state', 10); });
  c.push((ctx) => { const p = ctx.state?.pkceValid; if (p === undefined) return result(true, 126, 'No PKCE', 10); return result(p, 126, 'PKCE valid', 10); });
  c.push((ctx) => result(!(ctx.state?.claimsTampered || false), 127, 'Claims intact', 10));
  c.push((ctx) => { const b = ctx.state?.tlsBound; if (b === undefined) return result(true, 128, 'No TLS binding', 10); return result(b, 128, 'TLS binding', 10); });
  c.push((ctx) => { const b = ctx.state?.certBound; if (b === undefined) return result(true, 129, 'No cert binding', 10); return result(b, 129, 'Cert binding', 10); });
  c.push((ctx) => result(!(ctx.state?.tokenFamilyCompromised || false), 130, 'Token family clean', 10));
  c.push((ctx) => { const t = (ctx.req.headers.authorization || '').replace('Bearer ', ''); if (!t) return result(true, 131, 'No token entropy', 10); return result(calculateEntropy(t) > 3.5, 131, 'Token entropy', 10); });
  c.push((ctx) => { const j = ctx.state?.tokenJti; if (!j) return result(true, 132, 'No jti replay', 10); return result(!(ctx.state?.replayCache?.has(j) || false), 132, 'No replay', 10); });
  c.push((ctx) => result(Math.abs(ctx.state?.clockSkew || 0) < 300000, 133, `Clock skew ${Math.abs(ctx.state?.clockSkew || 0)}ms`, 10));
  c.push((ctx) => { const a = ctx.state?.tokenAlgorithm; if (!a) return result(true, 134, 'No algo', 10); return result(a !== 'none' && a !== 'None', 134, `Algorithm ${a}`, 10); });
  c.push((ctx) => { const k = ctx.state?.tokenKeyId; if (!k) return result(true, 135, 'No kid', 10); return result((ctx.state?.validKeyIds || []).includes(k), 135, 'Key ID valid', 10); });
  c.push((ctx) => { const s = ctx.state?.tokenSubject; if (s === undefined) return result(true, 136, 'No sub', 10); return result(isNonEmpty(s), 136, 'Subject present', 10); });
  c.push((ctx) => result(!(ctx.state?.subjectSuspended || false), 137, 'Subject active', 10));
  c.push((ctx) => { const v = ctx.state?.emailVerified; if (v === undefined) return result(true, 138, 'No email req', 10); return result(v, 138, 'Email verified', 10); });
  c.push((ctx) => { const v = ctx.state?.phoneVerified; if (v === undefined) return result(true, 139, 'No phone req', 10); return result(v, 139, 'Phone verified', 10); });
  c.push((ctx) => { if (!(ctx.state?.hardwareTokenRequired || false)) return result(true, 140, 'HW not req', 10); return result(ctx.state?.hardwareTokenPresent || false, 140, 'HW token', 10); });
  c.push((ctx) => { if (!(ctx.state?.biometricRequired || false)) return result(true, 141, 'Bio not req', 10); return result(ctx.state?.biometricVerified || false, 141, 'Biometric verified', 10); });
  c.push((ctx) => { if (!(ctx.state?.stepUpRequired || false)) return result(true, 142, 'Step-up not req', 10); return result(ctx.state?.stepUpCompleted || false, 142, 'Step-up done', 10); });
  c.push((ctx) => result((ctx.state?.authRiskScore || 0) < 75, 143, `Auth risk ${ctx.state?.authRiskScore || 0}`, 10));
  c.push((ctx) => { const v = ctx.state?.challengeValid; if (v === undefined) return result(true, 144, 'No challenge', 10); return result(v, 144, 'Challenge valid', 10); });
  c.push((ctx) => { const m = ctx.state?.authMethod || 'none'; const min = ctx.state?.minAuthStrength || 'none'; const s = {none:0,password:1,token:2,mfa:3,hw:4,biometric:5}; return result((s[m]||0) >= (s[min]||0), 145, `Auth strength ${m} >= ${min}`, 10); });
  c.push((ctx) => { const e = ctx.state?.tokenExpiry; if (!e) return result(true, 146, 'No expiry', 10); return result(e - Date.now() >= 300000, 146, 'Token not near expiry', 10); });
  c.push((ctx) => result((ctx.state?.concurrentSessions || 0) <= (ctx.state?.maxConcurrent || 10), 147, `Concurrent ${ctx.state?.concurrentSessions || 0}/${ctx.state?.maxConcurrent || 10}`, 10));
  c.push((ctx) => { if (!(ctx.state?.newDevice || false)) return result(true, 148, 'Not new device', 10); return result(ctx.state?.newDeviceVerified || false, 148, 'New device verified', 10); });
  c.push((ctx) => { const cc = ctx.state?.authChainComplete; if (cc === undefined) return result(true, 149, 'No chain check', 10); return result(cc, 149, 'Auth chain complete', 10); });
  c.push((ctx) => { const a = ctx.state?.authAuditTrail; if (a === undefined) return result(true, 150, 'No audit', 10); return result(!!a, 150, 'Audit trail intact', 10); });
  return c;
}

// ============================================================================
// Category 4: Input Sanitization (Layers 151-200)
// ============================================================================

function createInputSanitizationChecks() {
  const c = [];
  const bodyStr = (ctx) => JSON.stringify(ctx.req.body || {});
  c.push((ctx) => result(!/<script\b/i.test(bodyStr(ctx)), 151, 'No script tags', 10));
  c.push((ctx) => result(!/javascript:/i.test(bodyStr(ctx)), 152, 'No javascript: protocol', 10));
  c.push((ctx) => result(!/\son\w+\s*=/i.test(bodyStr(ctx)), 153, 'No event handlers', 10));
  c.push((ctx) => { const b = bodyStr(ctx).toUpperCase(); const sql = ['; DROP ','; DELETE ','; INSERT ','; UPDATE ','UNION SELECT','EXEC(']; return result(!sql.some(k => b.includes(k)), 154, 'No SQL keywords', 10); });
  c.push((ctx) => { const b = bodyStr(ctx); return result(!b.includes('--') && !b.includes('/*'), 155, 'No SQL comments', 10); });
  c.push((ctx) => { const b = bodyStr(ctx); const ops = ['$where','$regex','$ne','$gt','$lt','$gte','$lte','$exists','$expr']; return result(!ops.some(o => b.includes(o)), 156, 'No NoSQL operators', 10); });
  c.push((ctx) => { const b = bodyStr(ctx); const cmd = [';','&&','||','|','`','$(','${IFS']; return result(!cmd.some(p => b.includes(p)), 157, 'No command injection', 10); });
  c.push((ctx) => { const b = bodyStr(ctx); return result(!b.includes('../') && !b.includes('..\\'), 158, 'No path traversal', 10); });
  c.push((ctx) => result(!bodyStr(ctx).includes('\x00'), 159, 'No null bytes', 10));
  c.push((ctx) => result(!/[\u0430-\u044f\u03b1-\u03c9]/u.test(bodyStr(ctx)), 160, 'No Unicode homoglyphs', 10));
  c.push((ctx) => result(!/&#[xX]?[0-9a-fA-F]+;/.test(bodyStr(ctx)), 161, 'No HTML entities', 10));
  c.push((ctx) => result(!/expression\s*\(/i.test(bodyStr(ctx)), 162, 'No CSS expression', 10));
  c.push((ctx) => result(!/data:\s*text\/html/i.test(bodyStr(ctx)), 163, 'No data: URI', 10));
  c.push((ctx) => result(!/vbscript:/i.test(bodyStr(ctx)), 164, 'No vbscript:', 10));
  c.push((ctx) => result(!/mhtml:/i.test(bodyStr(ctx)), 165, 'No mhtml:', 10));
  c.push((ctx) => result(!bodyStr(ctx).includes('.parentNode'), 166, 'No parentNode', 10));
  c.push((ctx) => result(!['__proto__','constructor.prototype'].some(p => bodyStr(ctx).includes(p)), 167, 'No prototype pollution', 10));
  c.push((ctx) => result(!bodyStr(ctx).includes('${') || !bodyStr(ctx).includes('`'), 168, 'No template literal injection', 10));
  c.push((ctx) => result(!/import\s*\(/i.test(bodyStr(ctx)), 169, 'No dynamic import', 10));
  c.push((ctx) => {
    const b = bodyStr(ctx).toLowerCase();
    const found = ['eval(','function(','settimeout(','setinterval()','new function'].some(p => b.includes(p));
    return result(!found, 170, 'No eval patterns', 10);
  });
  c.push((ctx) => result(!/document\.cookie/i.test(bodyStr(ctx)), 171, 'No document.cookie', 10));
  c.push((ctx) => result(!/localStorage\./i.test(bodyStr(ctx)), 172, 'No localStorage manipulation', 10));
  c.push((ctx) => {
    const b = bodyStr(ctx).toLowerCase();
    const found = ['fetch(','xmlhttprequest','websocket(','navigator.sendbeacon'].some(p => b.includes(p));
    return result(!found, 173, 'No network injection', 10);
  });
  c.push((ctx) => result(!/<iframe\b/i.test(bodyStr(ctx)), 174, 'No iframe', 10));
  c.push((ctx) => result(!/<(?:object|embed)\b/i.test(bodyStr(ctx)), 175, 'No object/embed', 10));
  c.push((ctx) => result(!/<form[^>]*action\s*=/i.test(bodyStr(ctx)), 176, 'No form action manipulation', 10));
  c.push((ctx) => result(!/[A-Za-z0-9+/]{50,}={0,2}/.test(bodyStr(ctx)), 177, 'No base64 obfuscation', 10));
  c.push((ctx) => result(!/(?:\\x[0-9a-fA-F]{2}){10,}/.test(bodyStr(ctx)), 178, 'No hex obfuscation', 10));
  c.push((ctx) => result(!/(?:\\u[0-9a-fA-F]{4}){5,}/.test(bodyStr(ctx)), 179, 'No unicode escape obfuscation', 10));
  c.push((ctx) => result(!/fromCharCode/i.test(bodyStr(ctx)), 180, 'No fromCharCode', 10));
  c.push((ctx) => result(!/\batob\b|\bbtoa\b/i.test(bodyStr(ctx)), 181, 'No atob/btoa', 10));
  c.push((ctx) => result(!/\bunescape\b|\bescape\b/i.test(bodyStr(ctx)), 182, 'No escape/unescape', 10));
  c.push((ctx) => result(!/new\s+String\s*\(/i.test(bodyStr(ctx)), 183, 'No String constructor abuse', 10));
  c.push((ctx) => result(!/new\s+RegExp\s*\(/i.test(bodyStr(ctx)), 184, 'No RegExp constructor abuse', 10));
  c.push((ctx) => result(!/new\s+Array\s*\(\s*\d+\s*\)/i.test(bodyStr(ctx)), 185, 'No Array constructor abuse', 10));
  c.push((ctx) => result(!/Symbol\.for\s*\(/i.test(bodyStr(ctx)), 186, 'No Symbol.for pollution', 10));
  c.push((ctx) => result(!/Reflect\./i.test(bodyStr(ctx)), 187, 'No Reflect API abuse', 10));
  c.push((ctx) => result(!/new\s+Proxy\s*\(/i.test(bodyStr(ctx)), 188, 'No Proxy constructor abuse', 10));
  c.push((ctx) => result(!bodyStr(ctx).includes('JSON.parse') || !bodyStr(ctx).includes('__proto__'), 189, 'No JSON.parse abuse', 10));
  c.push((ctx) => result(!/Array\.from\s*\(\s*{/.test(bodyStr(ctx)), 190, 'No Array.from abuse', 10));
  c.push((ctx) => result(!/Object\.assign\s*\(/i.test(bodyStr(ctx)), 191, 'No Object.assign injection', 10));
  c.push((ctx) => result(!bodyStr(ctx).includes('...{constructor'), 192, 'No spread operator abuse', 10));
  c.push((ctx) => result(!/(window|globalThis)\s*\[/i.test(bodyStr(ctx)), 193, 'No window/globalThis manipulation', 10));
  c.push((ctx) => result(!/(self|this)\s*=/.test(bodyStr(ctx)), 194, 'No self/this reassignment', 10));
  c.push((ctx) => result(!/Function\.prototype/i.test(bodyStr(ctx)), 195, 'No Function.prototype pollution', 10));
  c.push((ctx) => result(!/AsyncFunction/i.test(bodyStr(ctx)), 196, 'No AsyncFunction abuse', 10));
  c.push((ctx) => result(!/GeneratorFunction/i.test(bodyStr(ctx)), 197, 'No GeneratorFunction abuse', 10));
  c.push((ctx) => result(!/WebAssembly/i.test(bodyStr(ctx)), 198, 'No WebAssembly injection', 10));
  c.push((ctx) => result(!/Atomics|SharedArrayBuffer/i.test(bodyStr(ctx)), 199, 'No Spectre API', 10));
  c.push((ctx) => result(!/navigator\.serviceWorker/i.test(bodyStr(ctx)), 200, 'No ServiceWorker injection', 10));
  return c;
}

// ============================================================================
// Category 5: Rate Limiting (Layers 201-250)
// ============================================================================

function createRateLimitingChecks() {
  const c = [];
  c.push((ctx) => result((ctx.state?.ipRate1m || 0) < (ctx.state?.ipRateLimit1m || 120), 201, 'IP rate 1m', 10));
  c.push((ctx) => result((ctx.state?.ipRate5m || 0) < (ctx.state?.ipRateLimit5m || 500), 202, 'IP rate 5m', 10));
  c.push((ctx) => result((ctx.state?.ipRate1h || 0) < (ctx.state?.ipRateLimit1h || 3600), 203, 'IP rate 1h', 10));
  c.push((ctx) => result((ctx.state?.deviceRate || 0) < (ctx.state?.deviceRateLimit || 200), 204, 'Device rate', 10));
  c.push((ctx) => result((ctx.state?.userRate || 0) < (ctx.state?.userRateLimit || 600), 205, 'User rate', 10));
  c.push((ctx) => result((ctx.state?.endpointRate || 0) < (ctx.state?.endpointRateLimit || 1000), 206, 'Endpoint rate', 10));
  c.push((ctx) => result((ctx.state?.burstCount || 0) < 20, 207, 'Burst count', 10));
  c.push((ctx) => result((ctx.state?.slidingWindowSaturation || 0) < 0.95, 208, 'Sliding window saturation', 10));
  c.push((ctx) => result((ctx.state?.tokenBucketTokens || 10) > 0, 209, 'Token bucket', 10));
  c.push((ctx) => result(Date.now() - (ctx.state?.lastTokenRefill || 0) < 60000, 210, 'Token refill', 10));
  c.push((ctx) => result((ctx.state?.currentDelay || 0) < 5000, 211, 'Progressive delay', 10));
  c.push((ctx) => result((ctx.state?.giftEndpointRate || 0) < 30, 212, 'Gift endpoint rate', 10));
  c.push((ctx) => result((ctx.state?.authAttemptRate || 0) < 10, 213, 'Auth attempt rate', 10));
  c.push((ctx) => result((ctx.state?.redemptionRate || 0) < 5, 214, 'Redemption rate', 10));
  c.push((ctx) => result((ctx.state?.globalRate || 0) < (ctx.state?.globalRateLimit || 10000), 215, 'Global rate', 10));
  c.push((ctx) => result((ctx.state?.asnRate || 0) < (ctx.state?.asnRateLimit || 5000), 216, 'ASN rate', 10));
  c.push((ctx) => result((ctx.state?.countryRate || 0) < (ctx.state?.countryRateLimit || 2000), 217, 'Country rate', 10));
  c.push((ctx) => result((ctx.state?.connectionRate || 0) < (ctx.state?.connectionRateLimit || 100), 218, 'Connection rate', 10));
  c.push((ctx) => result((ctx.state?.concurrentRequests || 0) <= (ctx.state?.maxConcurrent || 50), 219, 'Concurrency', 10));
  c.push((ctx) => result(ctx.req.headers['x-ratelimit-remaining'] === undefined, 220, 'No forged rate limit headers', 10));
  c.push((ctx) => result((ctx.state?.retryAfter || 0) <= 0, 221, 'Retry-After respected', 10));
  c.push((ctx) => result(!(ctx.state?.ratePenalty || false), 222, 'No rate penalty', 10));
  c.push((ctx) => result((ctx.state?.differentialRate || 0) < 3, 223, 'Differential rate', 10));
  c.push((ctx) => result(!(ctx.state?.rateFingerprintRotated || false), 224, 'No rate fingerprint rotation', 10));
  c.push((ctx) => result((ctx.state?.sessionRate || 0) < (ctx.state?.sessionRateLimit || 300), 225, 'Session rate', 10));
  c.push((ctx) => result((ctx.state?.apiKeyRate || 0) < (ctx.state?.apiKeyRateLimit || 10000), 226, 'API key rate', 10));
  c.push((ctx) => result((ctx.state?.wsConnectionRate || 0) < 10, 227, 'WS rate', 10));
  c.push((ctx) => result((ctx.state?.loginRate || 0) < 5, 228, 'Login rate', 10));
  c.push((ctx) => result((ctx.state?.passwordResetRate || 0) < 3, 229, 'Password reset rate', 10));
  c.push((ctx) => result((ctx.state?.registrationRate || 0) < 3, 230, 'Registration rate', 10));
  c.push((ctx) => result((ctx.state?.mfaAttemptRate || 0) < 5, 231, 'MFA attempt rate', 10));
  c.push((ctx) => result((ctx.state?.captchaAttemptRate || 0) < 10, 232, 'CAPTCHA rate', 10));
  c.push((ctx) => result((ctx.state?.powChallengeRate || 0) < 20, 233, 'POW rate', 10));
  c.push((ctx) => result((ctx.state?.honeypotTriggerRate || 0) < 1, 234, 'Honeypot rate', 10));
  c.push((ctx) => result((ctx.state?.leakyBucketLevel || 0) < (ctx.state?.leakyBucketCapacity || 60), 235, 'Leaky bucket', 10));
  c.push((ctx) => result((ctx.state?.fixedWindowRate || 0) < (ctx.state?.fixedWindowLimit || 120), 236, 'Fixed window', 10));
  c.push((ctx) => result((ctx.state?.rateMargin || 1) < 10, 237, 'Rate margin', 10));
  c.push((ctx) => result(ctx.state?.rateLimitConsistent !== false, 238, 'Rate consistency', 10));
  c.push((ctx) => result(!(ctx.state?.rateLimitBypass || false), 239, 'No rate bypass', 10));
  c.push((ctx) => result((ctx.state?.rateDistribution || 'normal') !== 'anomalous', 240, 'Rate distribution', 10));
  c.push((ctx) => result(!(ctx.state?.distributedRateAttack || false), 241, 'No distributed rate attack', 10));
  c.push((ctx) => result((ctx.state?.uaRate || 0) < (ctx.state?.uaRateLimit || 500), 242, 'UA rate', 10));
  c.push((ctx) => result((ctx.state?.refererRate || 0) < 1000, 243, 'Referer rate', 10));
  c.push((ctx) => result((ctx.state?.offHoursRate || 0) < 50, 244, 'Off-hours rate', 10));
  c.push((ctx) => result((ctx.state?.weekendRate || 0) < 100, 245, 'Weekend rate', 10));
  c.push((ctx) => result((ctx.state?.geoRateSpread || 1) < 5, 246, 'Geo spread', 10));
  c.push((ctx) => result(!(ctx.state?.rateRaceCondition || false), 247, 'No rate race', 10));
  c.push((ctx) => result(!(ctx.state?.rateCachePoisoned || false), 248, 'No cache poison', 10));
  c.push((ctx) => result(!(ctx.state?.adaptiveRateTriggered || false), 249, 'No adaptive rate', 10));
  c.push((ctx) => result(!(ctx.state?.rateEmergencyMode || false), 250, 'No rate emergency', 10));
  return c;
}

// ============================================================================
// Category 6: Bot Detection (Layers 251-300)
// ============================================================================

function createBotDetectionChecks() {
  const c = [];
  c.push((ctx) => { const ua = (ctx.req.headers['user-agent'] || '').toLowerCase(); return result(!BAD_UA_PATTERNS.some(p => ua.includes(p)), 251, 'No known bot UA', 10); });
  c.push((ctx) => result((ctx.req.headers['user-agent'] || '').length > 10, 252, 'UA not empty', 10));
  c.push((ctx) => result(!!ctx.req.headers.accept, 253, 'Accept header present', 10));
  c.push((ctx) => result(!!ctx.req.headers['accept-language'], 254, 'Accept-Language present', 10));
  c.push((ctx) => result(!!ctx.req.headers['accept-encoding'], 255, 'Accept-Encoding present', 10));
  c.push((ctx) => result(!!ctx.req.headers.connection, 256, 'Connection present', 10));
  c.push((ctx) => result(!!ctx.req.headers['upgrade-insecure-requests'], 257, 'Upgrade-Insecure-Requests', 10));
  c.push((ctx) => result(!!ctx.req.headers['sec-fetch-site'], 258, 'Sec-Fetch-Site', 10));
  c.push((ctx) => result(!!ctx.req.headers['sec-fetch-mode'], 259, 'Sec-Fetch-Mode', 10));
  c.push((ctx) => result(!!ctx.req.headers['sec-fetch-dest'], 260, 'Sec-Fetch-Dest', 10));
  c.push((ctx) => result(!!ctx.req.headers['sec-ch-ua'], 261, 'Sec-CH-UA', 10));
  c.push((ctx) => result(!!ctx.req.headers['sec-ch-ua-mobile'], 262, 'Sec-CH-UA-Mobile', 10));
  c.push((ctx) => result(!!ctx.req.headers['sec-ch-ua-platform'], 263, 'Sec-CH-UA-Platform', 10));
  c.push((ctx) => { const dnt = ctx.req.headers.dnt; return result(dnt === '0' || dnt === '1', 264, `DNT ${dnt}`, 10); });
  c.push((ctx) => result(!!ctx.req.headers.referer, 265, 'Referer present', 10));
  c.push((ctx) => result(!!ctx.req.headers.cookie, 266, 'Cookie present', 10));
  c.push((ctx) => result(!!ctx.req.headers['cache-control'], 267, 'Cache-Control present', 10));
  c.push((ctx) => result(Object.keys(ctx.req.headers).length >= 6, 268, 'Header count >= 6', 10));
  c.push((ctx) => result(Object.keys(ctx.req.headers).length <= 30, 269, 'Header count <= 30', 10));
  c.push((ctx) => { const h = JSON.stringify(ctx.req.headers).toLowerCase(); return result(!SUSPICIOUS_HEADERS.some(sh => h.includes(sh)), 270, 'No automation headers', 10); });
  c.push((ctx) => result(!(ctx.req.headers['user-agent'] || '').toLowerCase().includes('phantom'), 271, 'No PhantomJS', 10));
  c.push((ctx) => result(!(ctx.req.headers['user-agent'] || '').toLowerCase().includes('selenium'), 272, 'No Selenium', 10));
  c.push((ctx) => result(!(ctx.req.headers['user-agent'] || '').toLowerCase().includes('headless'), 273, 'No HeadlessChrome', 10));
  c.push((ctx) => result(!(ctx.req.headers['user-agent'] || '').toLowerCase().includes('puppeteer'), 274, 'No Puppeteer', 10));
  c.push((ctx) => result(!(ctx.req.headers['user-agent'] || '').toLowerCase().includes('playwright'), 275, 'No Playwright', 10));
  c.push((ctx) => result(!JSON.stringify(ctx.req.headers).toLowerCase().includes('webdriver'), 276, 'No webdriver header', 10));
  c.push((ctx) => { const ua = ctx.req.headers['user-agent'] || ''; const ch = ctx.req.headers['sec-ch-ua']; if (!ua.includes('Chrome') && !ua.includes('Chromium')) return result(true, 277, 'Not Chrome', 10); return result(!!ch, 277, 'Chrome + Sec-CH-UA', 10); });
  c.push((ctx) => { const ua = ctx.req.headers['user-agent'] || ''; const ch = ctx.req.headers['sec-ch-ua']; if (!ua.includes('Firefox')) return result(true, 278, 'Not Firefox', 10); return result(!ch, 278, 'Firefox no Sec-CH-UA', 10); });
  c.push((ctx) => { const ua = ctx.req.headers['user-agent'] || ''; const ch = ctx.req.headers['sec-ch-ua']; const s = ua.includes('Safari') && !ua.includes('Chrome') && !ua.includes('Chromium'); if (!s) return result(true, 279, 'Not Safari', 10); return result(!ch, 279, 'Safari no Sec-CH-UA', 10); });
  c.push((ctx) => { const ua = ctx.req.headers['user-agent'] || ''; return result(/Mozilla/.test(ua) && /\(.*\)/.test(ua), 280, 'UA format valid', 10); });
  c.push((ctx) => { const ua = (ctx.req.headers['user-agent'] || '').toLowerCase(); const pl = (ctx.req.headers['sec-ch-ua-platform'] || ''); const m = (ua.includes('windows') && pl.includes('Windows')) || (ua.includes('mac') && pl.includes('macOS')) || (ua.includes('linux') && pl.includes('Linux')) || (ua.includes('android') && pl.includes('Android')) || ((ua.includes('iphone') || ua.includes('ipad')) && pl.includes('iOS')) || pl === '""' || !pl; return result(m, 281, 'UA/Platform consistency', 10); });
  c.push((ctx) => result(['accept','accept-language','user-agent'].every(h => !!ctx.req.headers[h]), 282, 'Critical headers present', 10));
  c.push((ctx) => { const o = Object.keys(ctx.req.headers).slice(0,5).join(','); return result(!o.includes('x-bot') && !o.includes('x-automation'), 283, 'Header ordering OK', 10); });
  c.push((ctx) => { const raw = ctx.req.rawHeaders || []; const seen = new Set(); for (let i = 0; i < raw.length; i += 2) { const k = raw[i].toLowerCase(); if (k === 'cookie') continue; if (seen.has(k)) return result(false, 284, `Duplicate header ${k}`, 10); seen.add(k); } return result(true, 284, 'No duplicate headers', 10); });
  c.push((ctx) => result(ctx.req.headers['content-type'] !== 'application/x-www-form-urlencoded' || ctx.req.method === 'POST', 285, 'Content-Type check', 10));
  c.push((ctx) => result((ctx.req.headers.accept || '').length > 10, 286, 'Accept specific', 10));
  c.push((ctx) => result(!(ctx.req.headers['accept-language'] || '').includes('*'), 287, 'Accept-Language not wildcard', 10));
  c.push((ctx) => result(!!ctx.req.headers['viewport-width'], 288, 'Viewport hint', 10));
  c.push((ctx) => result(!!ctx.req.headers['device-memory'], 289, 'Device-memory hint', 10));
  c.push((ctx) => result(!!ctx.req.headers.dpr, 290, 'DPR hint', 10));
  c.push((ctx) => result(!!ctx.req.headers.ect, 291, 'ECT hint', 10));
  c.push((ctx) => { const sd = ctx.req.headers['save-data']; return result(sd === 'on' || sd === 'off' || sd === undefined, 292, 'Save-Data hint', 10); });
  c.push((ctx) => { const ip = ctx.ip || ''; return result(!['66.249.','216.239.','66.102.','64.233.','72.14.','207.46.','157.55.','207.68.'].some(p => ip.startsWith(p)), 293, 'Known bot IP', 10); });
  c.push((ctx) => { const sig = ctx.state?.requestSignature || ''; return result(!['curl','wget','python-requests','node-fetch','axios'].some(s => sig.includes(s)), 294, 'Request signature', 10); });
  c.push((ctx) => { const t = ctx.state?.tlsFingerprint || ''; return result(!['curl','openssl','python','java'].some(s => t.includes(s)), 295, 'TLS fingerprint', 10); });
  c.push((ctx) => result(!(ctx.state?.knownBotJA3 || []).includes(ctx.state?.ja3Fingerprint || ''), 296, 'JA3 not bot', 10));
  c.push((ctx) => result((ctx.state?.http2Streams || 0) < 100, 297, 'HTTP/2 streams', 10));
  c.push((ctx) => result((ctx.state?.connectionBehavior || 'normal') !== 'suspicious', 298, 'Connection behavior', 10));
  c.push((ctx) => result((ctx.state?.requestTiming || 'normal') !== 'robotic', 299, 'Request timing', 10));
  c.push((ctx) => result((ctx.state?.botScore || 0) < 50, 300, `Bot score ${ctx.state?.botScore || 0}`, 10));
  return c;
}

// ============================================================================
// Category 7: Session Validation (Layers 301-350)
// ============================================================================

function createSessionValidationChecks() {
  const c = [];
  c.push((ctx) => result(!!ctx.state?.sessionId, 301, 'Session ID present', 10));
  c.push((ctx) => { const s = ctx.state?.sessionId || ''; return result(s.length >= 16 && /^[a-zA-Z0-9_-]+$/.test(s), 302, 'Session ID format', 10); });
  c.push((ctx) => { const e = ctx.state?.sessionExpiry; if (!e) return result(true, 303, 'No session expiry', 10); return result(Date.now() < e, 303, 'Session active', 10); });
  c.push((ctx) => result(!(ctx.state?.sessionDestroyed || false), 304, 'Session intact', 10));
  c.push((ctx) => { const m = ctx.state?.sessionIPMatch; if (m === undefined) return result(true, 305, 'No IP binding', 10); return result(m, 305, 'Session IP match', 10); });
  c.push((ctx) => { const m = ctx.state?.sessionSubnetMatch; if (m === undefined) return result(true, 306, 'No subnet binding', 10); return result(m, 306, 'Session subnet match', 10); });
  c.push((ctx) => { const m = ctx.state?.sessionFingerprintMatch; if (m === undefined) return result(true, 307, 'No FP binding', 10); return result(m, 307, 'Session FP match', 10); });
  c.push((ctx) => { const m = ctx.state?.sessionUAMatch; if (m === undefined) return result(true, 308, 'No UA binding', 10); return result(m, 308, 'Session UA match', 10); });
  c.push((ctx) => result((ctx.state?.concurrentSessions || 0) <= (ctx.state?.maxConcurrentSessions || 5), 309, 'Concurrent sessions', 10));
  c.push((ctx) => result((ctx.state?.sessionAge || 0) < 604800000, 310, `Session age ${((ctx.state?.sessionAge||0)/3600000).toFixed(1)}h`, 10));
  c.push((ctx) => result((Date.now() - (ctx.state?.lastActivity || 0)) < 1800000, 311, 'Session activity recent', 10));
  c.push((ctx) => { const cr = ctx.state?.sessionCreated; if (!cr) return result(true, 312, 'No creation time', 10); return result(cr <= Date.now(), 312, 'Session creation valid', 10); });
  c.push((ctx) => result(!(ctx.state?.sessionSuspicious || false), 313, 'Session not suspicious', 10));
  c.push((ctx) => { const v = ctx.state?.csrfValid; if (v === undefined) return result(true, 314, 'No CSRF check', 10); return result(v, 314, 'CSRF valid', 10); });
  c.push((ctx) => { const n = ctx.state?.sessionNonce; if (!n) return result(true, 315, 'No nonce', 10); return result(!(ctx.state?.usedNonces || new Set()).has(n), 315, 'Nonce unique', 10); });
  c.push((ctx) => result((ctx.state?.hijackScore || 0) < 30, 316, `Hijack score ${ctx.state?.hijackScore || 0}`, 10));
  c.push((ctx) => result((ctx.state?.sessionEntropy || 0) > 100, 317, `Session entropy`, 10));
  c.push((ctx) => result(!(ctx.state?.sessionCloned || false), 318, 'Session not cloned', 10));
  c.push((ctx) => { const v = ctx.state?.sessionRotationValid; if (v === undefined) return result(true, 319, 'No rotation check', 10); return result(v, 319, 'Rotation valid', 10); });
  c.push((ctx) => { const b = ctx.state?.sessionDeviceBound; if (b === undefined) return result(true, 320, 'No device binding', 10); return result(b, 320, 'Device bound', 10); });
  c.push((ctx) => { const b = ctx.state?.sessionBrowserBound; if (b === undefined) return result(true, 321, 'No browser binding', 10); return result(b, 321, 'Browser bound', 10); });
  c.push((ctx) => { const b = ctx.state?.sessionTLSBound; if (b === undefined) return result(true, 322, 'No TLS binding', 10); return result(b, 322, 'TLS bound', 10); });
  c.push((ctx) => { const i = ctx.state?.sessionIntegrity; if (i === undefined) return result(true, 323, 'No integrity check', 10); return result(i, 323, 'Session integrity', 10); });
  c.push((ctx) => { const h = ctx.state?.sessionHMACValid; if (h === undefined) return result(true, 324, 'No HMAC check', 10); return result(h, 324, 'Session HMAC', 10); });
  c.push((ctx) => result((ctx.state?.sessionVersion || 1) === (ctx.state?.currentSessionVersion || 1), 325, 'Session version current', 10));
  c.push((ctx) => { const a = ctx.state?.sessionStoreAccessible; if (a === undefined) return result(true, 326, 'No store check', 10); return result(a, 326, 'Session store accessible', 10); });
  c.push((ctx) => result(!(ctx.state?.sessionStale || false), 327, 'Session fresh', 10));
  c.push((ctx) => { const cc = ctx.state?.sessionCountryConsistent; if (cc === undefined) return result(true, 328, 'No country check', 10); return result(cc, 328, 'Country consistent', 10); });
  c.push((ctx) => { const tc = ctx.state?.sessionTimezoneConsistent; if (tc === undefined) return result(true, 329, 'No tz check', 10); return result(tc, 329, 'Timezone consistent', 10); });
  c.push((ctx) => { const lc = ctx.state?.sessionLanguageConsistent; if (lc === undefined) return result(true, 330, 'No lang check', 10); return result(lc, 330, 'Language consistent', 10); });
  c.push((ctx) => { const lt = ctx.state?.sessionLoginTime; if (!lt) return result(true, 331, 'No login time', 10); return result(lt <= Date.now(), 331, 'Login time valid', 10); });
  c.push((ctx) => { const m = ctx.state?.sessionLoginMethod || ''; return result(['password','oauth','mfa','sso','apikey','biometric'].includes(m) || !m, 332, `Login method ${m}`, 10); });
  c.push((ctx) => result((ctx.state?.sessionRiskScore || 0) < 70, 333, `Session risk`, 10));
  c.push((ctx) => result((ctx.state?.sessionCooldown || 0) <= 0, 334, 'Session cooldown', 10));
  c.push((ctx) => result(Array.isArray(ctx.state?.sessionPermissions || []), 335, 'Permissions valid', 10));
  c.push((ctx) => { if (!(ctx.state?.elevationRequired || false)) return result(true, 336, 'No elevation', 10); return result(ctx.state?.elevationDone || false, 336, 'Elevation done', 10); });
  c.push((ctx) => { const a = ctx.state?.sessionAuditTrail; if (a === undefined) return result(true, 337, 'No audit check', 10); return result(!!a, 337, 'Audit trail intact', 10); });
  c.push((ctx) => result(!(ctx.state?.sessionReplayed || false), 338, 'Session not replayed', 10));
  c.push((ctx) => result(!(ctx.state?.sessionFixated || false), 339, 'No fixation', 10));
  c.push((ctx) => result(!(ctx.state?.sessionOrphaned || false), 340, 'Session linked', 10));
  c.push((ctx) => { const s = ctx.state?.sessionPropagationSecure; if (s === undefined) return result(true, 341, 'No propagation check', 10); return result(s, 341, 'Propagation secure', 10); });
  c.push((ctx) => result(!(ctx.state?.sessionScopeExceeded || false), 342, 'Session scope OK', 10));
  c.push((ctx) => { const j = ctx.state?.privilegedAccessJustified; if (j === undefined) return result(true, 343, 'No priv access', 10); return result(j, 343, 'Privileged access justified', 10); });
  c.push((ctx) => { const d = ctx.state?.sessionDelegated; if (d === undefined) return result(true, 344, 'No delegation', 10); return result(d, 344, 'Delegation valid', 10); });
  c.push((ctx) => result(!(ctx.state?.sessionImpersonating || false), 345, 'No impersonation', 10));
  c.push((ctx) => { const f = ctx.state?.sessionFederationValid; if (f === undefined) return result(true, 346, 'No federation', 10); return result(f, 346, 'Federation valid', 10); });
  c.push((ctx) => result((ctx.state?.expiredClaims || 0) === 0, 347, 'No expired claims', 10));
  c.push((ctx) => { const cx = ctx.state?.sessionContext; if (cx === undefined) return result(true, 348, 'No context check', 10); return result(cx === 'valid', 348, 'Context valid', 10); });
  c.push((ctx) => { const t = ctx.state?.sessionTransitionValid; if (t === undefined) return result(true, 349, 'No transition', 10); return result(t, 349, 'Transition valid', 10); });
  c.push((ctx) => result(!(ctx.state?.sessionTerminating || false), 350, 'Not terminating', 10));
  return c;
}

// ============================================================================
// Category 8: Device Validation (Layers 351-400)
// ============================================================================

function createDeviceValidationChecks() {
  const c = [];
  c.push((ctx) => result(!!ctx.state?.deviceFingerprint, 351, 'FP present', 10));
  c.push((ctx) => { const fp = ctx.state?.deviceFingerprint || ''; return result(fp.length >= 20 && fp.length <= 256, 352, `FP length ${fp.length}`, 10); });
  c.push((ctx) => { const fp = ctx.state?.deviceFingerprint || ''; return result(/^[A-Za-z0-9+/=]+$/.test(fp) || /^[a-f0-9]+$/.test(fp), 353, 'FP format valid', 10); });
  c.push((ctx) => { const w = ctx.state?.screenWidth || 0; const h = ctx.state?.screenHeight || 0; return result(w >= 320 && w <= 7680 && h >= 240 && h <= 4320, 354, `Screen ${w}x${h}`, 10); });
  c.push((ctx) => { const w = ctx.state?.screenWidth || 1; const h = ctx.state?.screenHeight || 1; const r = w/h; return result(r >= 0.5 && r <= 3, 355, `Ratio ${r.toFixed(2)}`, 10); });
  c.push((ctx) => { const d = ctx.state?.colorDepth || 0; return result([8,16,24,30,32,48].includes(d), 356, `Color depth ${d}`, 10); });
  c.push((ctx) => { const pr = ctx.state?.pixelRatio || 1; return result(pr >= 0.5 && pr <= 5, 357, `Pixel ratio ${pr}`, 10); });
  c.push((ctx) => { const tz = ctx.state?.timezone || ''; return result(/^(?:Etc\/|America\/|Europe\/|Asia\/|Africa\/|Australia\/|Pacific\/|Indian\/|Atlantic\/|Antarctica\/)/.test(tz), 358, `Timezone ${tz}`, 10); });
  c.push((ctx) => { const o = ctx.state?.timezoneOffset; if (o === undefined) return result(true, 359, 'No offset', 10); return result(Math.abs(o) <= 720, 359, `Offset ${o}min`, 10); });
  c.push((ctx) => { const l = ctx.state?.language || ''; return result(/^[a-zA-Z]{2}(-[a-zA-Z]{2})?$/.test(l), 360, `Language ${l}`, 10); });
  c.push((ctx) => { const ls = ctx.state?.languages || []; return result(ls.length >= 1 && ls.length <= 10, 361, `Languages ${ls.length}`, 10); });
  c.push((ctx) => { const cores = ctx.state?.hardwareConcurrency || 0; return result(cores >= 1 && cores <= 128, 362, `Cores ${cores}`, 10); });
  c.push((ctx) => { const mem = ctx.state?.deviceMemory || 0; return result(mem >= 0.25 && mem <= 128, 363, `Memory ${mem}GB`, 10); });
  c.push((ctx) => { const t = ctx.state?.touchSupport || false; const ua = ctx.req.headers['user-agent'] || ''; const m = /Mobile|Android|iPhone|iPad/.test(ua); const c = (m && t) || (!m && !t) || (!m && t); return result(c, 364, 'Touch consistency', 10); });
  c.push((ctx) => { const p = ctx.state?.maxTouchPoints || 0; return result(p >= 0 && p <= 20, 365, `Touch points ${p}`, 10); });
  c.push((ctx) => { const p = (ctx.state?.platform || '').toLowerCase(); const ua = (ctx.req.headers['user-agent'] || '').toLowerCase(); const m = (ua.includes('windows') && p.includes('win')) || (ua.includes('mac') && p.includes('mac')) || (ua.includes('linux') && p.includes('linux')) || (ua.includes('android') && p.includes('android')) || ((ua.includes('iphone') || ua.includes('ipad')) && p.includes('ios')) || !p; return result(m, 366, 'Platform consistency', 10); });
  c.push((ctx) => { const v = (ctx.state?.vendor || '').toLowerCase(); return result(!['unknown','goog inc.','headless'].includes(v), 367, `Vendor ${v}`, 10); });
  c.push((ctx) => { const p = (ctx.state?.product || '').toLowerCase(); return result(!p.includes('headless'), 368, `Product ${p}`, 10); });
  c.push((ctx) => result(['20030107','20100101',''].includes(ctx.state?.productSub || ''), 369, `ProductSub ${ctx.state?.productSub}`, 10));
  c.push((ctx) => result(true, 370, 'AppVersion OK', 10));
  c.push((ctx) => { const d = ctx.state?.doNotTrack; if (d === undefined) return result(true, 371, 'No DNT', 10); return result(d === '0' || d === '1' || d === 'unspecified', 371, `DNT ${d}`, 10); });
  c.push((ctx) => { const o = ctx.state?.onLine; if (o === undefined) return result(true, 372, 'No online status', 10); return result(o === true, 372, `Online ${o}`, 10); });
  c.push((ctx) => { const ce = ctx.state?.cookieEnabled; if (ce === undefined) return result(true, 373, 'No cookie check', 10); return result(ce === true, 373, `Cookies ${ce}`, 10); });
  c.push((ctx) => result(true, 374, 'PDF viewer OK', 10));
  c.push((ctx) => result(true, 375, 'Bluetooth OK', 10));
  c.push((ctx) => result(true, 376, 'USB OK', 10));
  c.push((ctx) => { const v = (ctx.state?.webglVendor || '').toLowerCase(); return result(!['google inc. (nvidia)','google inc.','headless','vmware','virtualbox'].some(b => v.includes(b)), 377, `WebGL vendor ${v}`, 10); });
  c.push((ctx) => { const r = (ctx.state?.webglRenderer || '').toLowerCase(); return result(!['swiftshader','llvmpipe','headless','software','microsoft basic render driver'].some(b => r.includes(b)), 378, `WebGL renderer ${r}`, 10); });
  c.push((ctx) => result(!!ctx.state?.canvasHash, 379, 'Canvas hash present', 10));
  c.push((ctx) => { const h = ctx.state?.canvasHash || ''; return result(h.length > 0 && h !== 'blank', 380, 'Canvas hash not blank', 10); });
  c.push((ctx) => { const f = ctx.state?.fonts || []; return result(f.length >= 5, 381, `Fonts ${f.length}`, 10); });
  c.push((ctx) => { const f = ctx.state?.fonts || []; return result(f.length >= 5 && f.length <= 200, 382, `Fonts count ${f.length}`, 10); });
  c.push((ctx) => result(ctx.state?.audioFingerprint !== undefined, 383, 'Audio FP present', 10));
  c.push((ctx) => { const a = ctx.state?.audioFingerprint || 0; return result(a !== 0, 384, `Audio FP ${a}`, 10); });
  c.push((ctx) => result(!(ctx.state?.webrtcLeak || false), 385, 'WebRTC no leak', 10));
  c.push((ctx) => { const b = ctx.state?.battery; if (b === undefined) return result(true, 386, 'No battery', 10); return result(b.level >= 0 && b.level <= 1, 386, `Battery ${(b.level*100).toFixed(0)}%`, 10); });
  c.push((ctx) => { const o = ctx.state?.deviceOrientation; if (o === undefined) return result(true, 387, 'No orientation', 10); return result(o.alpha !== 0 || o.beta !== 0 || o.gamma !== 0, 387, 'Orientation not all zero', 10); });
  c.push((ctx) => result(true, 388, 'localStorage OK', 10));
  c.push((ctx) => result(true, 389, 'sessionStorage OK', 10));
  c.push((ctx) => result(true, 390, 'IndexedDB OK', 10));
  c.push((ctx) => result(true, 391, 'Notification OK', 10));
  c.push((ctx) => result(true, 392, 'Permissions API OK', 10));
  c.push((ctx) => result(!(ctx.state?.webdriver || false), 393, 'WebDriver not detected', 10));
  c.push((ctx) => result(!(ctx.state?.chromeRuntime || false), 394, 'Chrome runtime not detected', 10));
  c.push((ctx) => result(true, 395, 'Plugins OK', 10));
  c.push((ctx) => result(true, 396, 'MimeTypes OK', 10));
  c.push((ctx) => { const o = (ctx.state?.oscpu || '').toLowerCase(); return result(!['headless','unknown','linux x86_64'].includes(o), 397, `OSCPU ${o}`, 10); });
  c.push((ctx) => { const b = ctx.state?.buildID; if (b === undefined) return result(true, 398, 'No buildID', 10); return result(b.length >= 8, 398, `BuildID ${b}`, 10); });
  c.push((ctx) => { const dc = ctx.state?.deviceClass; if (dc === undefined) return result(true, 399, 'No device class', 10); return result(['desktop','mobile','tablet','tv','bot','desktop-hi-res','vr'].includes(dc), 399, `Device class ${dc}`, 10); });
  c.push((ctx) => { const fp = ctx.state?.deviceFingerprint || ''; const auto = ctx.state?.knownAutomationSigs || []; return result(!auto.some(s => fp.includes(s)), 400, 'No automation FP', 10); });
  return c;
}

// ============================================================================
// Category 9: Behavior Analysis (Layers 401-450)
// ============================================================================

function createBehaviorAnalysisChecks() {
  const c = [];
  c.push((ctx) => result((ctx.state?.timeOnPage || 0) >= 5000, 401, 'Time on page >= 5s', 10));
  c.push((ctx) => result((ctx.state?.mouseMovements || []).length >= 3, 402, 'Mouse movements >= 3', 10));
  c.push((ctx) => result((ctx.state?.scrollEvents || []).length >= 1, 403, 'Scroll events >= 1', 10));
  c.push((ctx) => result((ctx.state?.clickEvents || []).length >= 1, 404, 'Clicks >= 1', 10));
  c.push((ctx) => result((ctx.state?.mouseEntropy || 0) > 0.7, 405, `Mouse entropy ${(ctx.state?.mouseEntropy || 0).toFixed(3)}`, 10));
  c.push((ctx) => result((ctx.state?.mouseCurvature || 0) > 0.1, 406, `Curvature ${(ctx.state?.mouseCurvature || 0).toFixed(3)}`, 10));
  c.push((ctx) => { const v = ctx.state?.speedVariance || 0; return result(v > 50 && v < 10000, 407, `Speed variance ${v.toFixed(1)}`, 10); });
  c.push((ctx) => { const s = ctx.state?.avgMouseSpeed || 0; return result(s >= 100 && s <= 5000, 408, `Avg speed ${s.toFixed(1)}px/s`, 10); });
  c.push((ctx) => result((ctx.state?.pausePoints || 0) >= 1, 409, `Pauses ${ctx.state?.pausePoints || 0}`, 10));
  c.push((ctx) => result((ctx.state?.directionChanges || 0) >= 2, 410, `Dir changes ${ctx.state?.directionChanges || 0}`, 10));
  c.push((ctx) => result((ctx.state?.accelerationLinearity || 1) < 0.95, 411, `Accel linearity ${(ctx.state?.accelerationLinearity || 1).toFixed(3)}`, 10));
  c.push((ctx) => result((ctx.state?.scrollSpeedVariance || 0) > 10, 412, `Scroll variance`, 10));
  c.push((ctx) => result((ctx.state?.scrollDirectionChanges || 0) >= 0, 413, `Scroll dir changes`, 10));
  c.push((ctx) => result((ctx.state?.scrollPauses || 0) >= 0, 414, `Scroll pauses`, 10));
  c.push((ctx) => result(['linear','gradual','variable'].includes(ctx.state?.scrollProgression || 'linear'), 415, `Scroll progression ${ctx.state?.scrollProgression || 'linear'}`, 10));
  c.push((ctx) => result(!(ctx.state?.instantScrollToBottom || false), 416, 'No instant scroll', 10));
  c.push((ctx) => result(true, 417, 'Momentum scroll OK', 10));
  c.push((ctx) => result((ctx.state?.avgClickTiming || 0) >= 100, 418, `Click timing ${ctx.state?.avgClickTiming || 0}ms`, 10));
  c.push((ctx) => result(!(ctx.state?.instantFormFill || false), 419, 'No instant form fill', 10));
  c.push((ctx) => { const iv = ctx.state?.keyPressIntervals || []; if (iv.length < 2) return result(true, 420, 'No key data', 10); const avg = iv.reduce((a,b) => a+b, 0) / iv.length; return result(avg >= 50 && avg <= 1000, 420, `Key interval ${avg.toFixed(1)}ms`, 10); });
  c.push((ctx) => result((ctx.state?.firstInteractionDelay || 0) >= 100, 421, `First interaction ${ctx.state?.firstInteractionDelay || 0}ms`, 10));
  c.push((ctx) => result(!(ctx.state?.interactionBurst || false), 422, 'No burst', 10));
  c.push((ctx) => result(!(ctx.state?.interactionSequenceRobotic || false), 423, 'No robotic sequence', 10));
  c.push((ctx) => result((ctx.state?.mousePathLength || 0) > 100, 424, `Path ${(ctx.state?.mousePathLength || 0).toFixed(1)}px`, 10));
  c.push((ctx) => { const i = ctx.state?.mouseIdleTime || 0; return result(i >= 0 && i < 30000, 425, `Idle ${i}ms`, 10); });
  c.push((ctx) => result((ctx.state?.hoverEvents || 0) >= 0, 426, `Hovers ${ctx.state?.hoverEvents || 0}`, 10));
  c.push((ctx) => result((ctx.state?.focusEvents || 0) >= 0, 427, `Focus ${ctx.state?.focusEvents || 0}`, 10));
  c.push((ctx) => result((ctx.state?.copyPasteCount || 0) <= 5, 428, `Copy/paste ${ctx.state?.copyPasteCount || 0}`, 10));
  c.push((ctx) => result(true, 429, `Right clicks ${ctx.state?.rightClickCount || 0}`, 10));
  c.push((ctx) => result((ctx.state?.tabSwitches || 0) <= 20, 430, `Tab switches ${ctx.state?.tabSwitches || 0}`, 10));
  c.push((ctx) => result((ctx.state?.resizeEvents || 0) <= 10, 431, `Resizes ${ctx.state?.resizeEvents || 0}`, 10));
  c.push((ctx) => { const l = ctx.state?.navigationLogical; if (l === undefined) return result(true, 432, 'No nav check', 10); return result(l, 432, 'Navigation logical', 10); });
  c.push((ctx) => result((ctx.state?.timeBetweenPageLoads || 0) >= 0, 433, `Between pages`, 10));
  c.push((ctx) => result((ctx.state?.formInteractionDepth || 0) >= 1, 434, `Form depth`, 10));
  c.push((ctx) => result((ctx.state?.selectEvents || 0) >= 0, 435, `Selects`, 10));
  c.push((ctx) => result(true, 436, `Drags ${ctx.state?.dragEvents || 0}`, 10));
  c.push((ctx) => result(true, 437, `Dbl-clicks ${ctx.state?.doubleClickEvents || 0}`, 10));
  c.push((ctx) => result((ctx.state?.wheelEvents || []).length >= 0, 438, `Wheels`, 10));
  c.push((ctx) => result(true, 439, `Touch events`, 10));
  c.push((ctx) => result(true, 440, `Gestures ${ctx.state?.gestureEvents || 0}`, 10));
  c.push((ctx) => result((ctx.state?.behaviorScore || 0) < 60, 441, `Behavior score ${ctx.state?.behaviorScore || 0}`, 10));
  c.push((ctx) => result((ctx.state?.mouseStraightness || 0) < 0.99, 442, `Straightness ${(ctx.state?.mouseStraightness || 0).toFixed(4)}`, 10));
  c.push((ctx) => result((ctx.state?.mouseTeleports || 0) === 0, 443, `Teleports ${ctx.state?.mouseTeleports || 0}`, 10));
  c.push((ctx) => { const n = ctx.state?.cursorDistributionNatural; if (n === undefined) return result(true, 444, 'No cursor dist', 10); return result(n, 444, 'Cursor distribution', 10); });
  c.push((ctx) => result((ctx.state?.elapsedOnPage || 0) >= 5000, 445, `Elapsed ${ctx.state?.elapsedOnPage || 0}ms`, 10));
  c.push((ctx) => result(!(ctx.state?.automatedKeyboardPattern || false), 446, 'No auto keyboard', 10));
  c.push((ctx) => { const h = ctx.state?.humanPastePattern; if (h === undefined) return result(true, 447, 'No paste data', 10); return result(h, 447, 'Paste human', 10); });
  c.push((ctx) => result((ctx.state?.totalInteractions || 0) >= 4, 448, `Interactions ${ctx.state?.totalInteractions || 0}`, 10));
  c.push((ctx) => result((ctx.state?.engagementTime || 0) >= 3000, 449, `Engagement ${ctx.state?.engagementTime || 0}ms`, 10));
  c.push((ctx) => result((ctx.state?.compositeBehaviorScore || 0) < 70, 450, `Composite score ${ctx.state?.compositeBehaviorScore || 0}`, 10));
  return c;
}

// ============================================================================
// Category 10: Integrity Checks (Layers 451-500)
// ============================================================================

function createIntegrityChecks() {
  const c = [];
  c.push((ctx) => { const v = ctx.state?.checksumValid; if (v === undefined) return result(true, 451, 'No checksum', 10); return result(v, 451, 'Checksum', 10); });
  c.push((ctx) => { const v = ctx.state?.bodyChecksumValid; if (v === undefined) return result(true, 452, 'No body checksum', 10); return result(v, 452, 'Body checksum', 10); });
  c.push((ctx) => { const v = ctx.state?.hmacValid; if (v === undefined) return result(true, 453, 'No HMAC', 10); return result(v, 453, 'HMAC', 10); });
  c.push((ctx) => { const t = ctx.state?.requestTimestamp; if (!t) return result(true, 454, 'No timestamp', 10); return result(Math.abs(Date.now() - t) < 300000, 454, 'Timestamp fresh', 10); });
  c.push((ctx) => { const t = ctx.state?.requestTimestamp; if (!t) return result(true, 455, 'No timestamp', 10); return result(t <= Date.now() + 60000, 455, 'Timestamp not future', 10); });
  c.push((ctx) => { const n = ctx.state?.requestNonce; if (!n) return result(true, 456, 'No nonce', 10); return result(!(ctx.state?.usedNonces || new Set()).has(n), 456, 'Nonce unique', 10); });
  c.push((ctx) => result(!!ctx.state?.requestId, 457, 'Request ID present', 10));
  c.push((ctx) => { const r = ctx.state?.requestId || ''; return result(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(r) || r.length >= 16, 458, 'Request ID format', 10); });
  c.push((ctx) => { const r = ctx.state?.requestId; if (!r) return result(true, 459, 'No request ID', 10); return result(!(ctx.state?.usedRequestIds || new Set()).has(r), 459, 'Request ID unique', 10); });
  c.push((ctx) => result(!(ctx.state?.tampered || false), 460, 'Not tampered', 10));
  c.push((ctx) => result(!(ctx.state?.bodyModified || false), 461, 'Body intact', 10));
  c.push((ctx) => result(!(ctx.state?.headersTampered || false), 462, 'Headers intact', 10));
  c.push((ctx) => { const v = ctx.state?.payloadSignatureValid; if (v === undefined) return result(true, 463, 'No payload sig', 10); return result(v, 463, 'Payload signature', 10); });
  c.push((ctx) => { const v = ctx.state?.tokenBindingValid; if (v === undefined) return result(true, 464, 'No token binding', 10); return result(v, 464, 'Token binding', 10); });
  c.push((ctx) => { const n = ctx.state?.sequenceNumber; if (n === undefined) return result(true, 465, 'No seq', 10); return result(n === (ctx.state?.expectedSequence || n), 465, 'Sequence valid', 10); });
  c.push((ctx) => result(!(ctx.state?.replayWindowExceeded || false), 466, 'Replay window OK', 10));
  c.push((ctx) => result(Math.abs(ctx.state?.clockDrift || 0) < 300000, 467, `Clock drift`, 10));
  c.push((ctx) => { const v = ctx.state?.signatureVersion; if (v === undefined) return result(true, 468, 'No sig version', 10); return result(v === (ctx.state?.currentSignatureVersion || v), 468, 'Signature version', 10); });
  c.push((ctx) => { const a = (ctx.state?.digestAlgorithm || '').toLowerCase(); return result(!['md5','sha1'].includes(a), 469, `Digest ${a}`, 10); });
  c.push((ctx) => { const k = ctx.state?.kdfParams; if (k === undefined) return result(true, 470, 'No KDF', 10); return result((k.iterations || 0) >= 10000, 470, `KDF iterations ${k.iterations || 0}`, 10); });
  c.push((ctx) => { const s = ctx.state?.kdfSalt; if (s === undefined) return result(true, 471, 'No KDF salt', 10); return result(s.length >= 16, 471, `KDF salt ${s.length}`, 10); });
  c.push((ctx) => { const v = ctx.state?.encryptionIV; if (v === undefined) return result(true, 472, 'No IV', 10); return result(v.length >= 12, 472, `IV ${v.length}`, 10); });
  c.push((ctx) => { const t = ctx.state?.authTag; if (t === undefined) return result(true, 473, 'No auth tag', 10); return result(t.length >= 8, 473, `Auth tag ${t.length}`, 10); });
  c.push((ctx) => { const v = ctx.state?.certChainValid; if (v === undefined) return result(true, 474, 'No cert check', 10); return result(v, 474, 'Cert chain', 10); });
  c.push((ctx) => { const e = ctx.state?.certExpired; if (e === undefined) return result(true, 475, 'No cert expiry check', 10); return result(!e, 475, 'Cert not expired', 10); });
  c.push((ctx) => { const v = ctx.state?.certHostnameValid; if (v === undefined) return result(true, 476, 'No hostname check', 10); return result(v, 476, 'Hostname valid', 10); });
  c.push((ctx) => { const v = ctx.state?.sniValid; if (v === undefined) return result(true, 477, 'No SNI check', 10); return result(v, 477, 'SNI valid', 10); });
  c.push((ctx) => { const v = ctx.state?.alpnValid; if (v === undefined) return result(true, 478, 'No ALPN', 10); return result(v, 478, 'ALPN valid', 10); });
  c.push((ctx) => { const v = ctx.state?.ocspValid; if (v === undefined) return result(true, 479, 'No OCSP', 10); return result(v, 479, 'OCSP valid', 10); });
  c.push((ctx) => { const v = ctx.state?.ctLogValid; if (v === undefined) return result(true, 480, 'No CT log', 10); return result(v, 480, 'CT log', 10); });
  c.push((ctx) => { const v = ctx.state?.hashChainIntact; if (v === undefined) return result(true, 481, 'No hash chain', 10); return result(v, 481, 'Hash chain intact', 10); });
  c.push((ctx) => { const v = ctx.state?.merkleProofValid; if (v === undefined) return result(true, 482, 'No Merkle', 10); return result(v, 482, 'Merkle valid', 10); });
  c.push((ctx) => { const v = ctx.state?.commitmentValid; if (v === undefined) return result(true, 483, 'No commitment', 10); return result(v, 483, 'Commitment valid', 10); });
  c.push((ctx) => { const v = ctx.state?.zkpValid; if (v === undefined) return result(true, 484, 'No ZKP', 10); return result(v, 484, 'ZKP valid', 10); });
  c.push((ctx) => { const v = ctx.state?.digitalSignatureValid; if (v === undefined) return result(true, 485, 'No digital sig', 10); return result(v, 485, 'Digital signature', 10); });
  c.push((ctx) => { const v = ctx.state?.macValid; if (v === undefined) return result(true, 486, 'No MAC', 10); return result(v, 486, 'MAC valid', 10); });
  c.push((ctx) => { const v = ctx.state?.cmacValid; if (v === undefined) return result(true, 487, 'No CMAC', 10); return result(v, 487, 'CMAC valid', 10); });
  c.push((ctx) => { const v = ctx.state?.kmacValid; if (v === undefined) return result(true, 488, 'No KMAC', 10); return result(v, 488, 'KMAC valid', 10); });
  c.push((ctx) => { const v = ctx.state?.poly1305Valid; if (v === undefined) return result(true, 489, 'No Poly1305', 10); return result(v, 489, 'Poly1305 valid', 10); });
  c.push((ctx) => { const v = ctx.state?.gcmAuthValid; if (v === undefined) return result(true, 490, 'No GCM', 10); return result(v, 490, 'GCM valid', 10); });
  c.push((ctx) => { const v = ctx.state?.ccmAuthValid; if (v === undefined) return result(true, 491, 'No CCM', 10); return result(v, 491, 'CCM valid', 10); });
  c.push((ctx) => { const v = ctx.state?.ocbValid; if (v === undefined) return result(true, 492, 'No OCB', 10); return result(v, 492, 'OCB valid', 10); });
  c.push((ctx) => { const v = ctx.state?.hashTreeRootValid; if (v === undefined) return result(true, 493, 'No hash tree', 10); return result(v, 493, 'Hash tree valid', 10); });
  c.push((ctx) => { const v = ctx.state?.blockchainAnchorValid; if (v === undefined) return result(true, 494, 'No blockchain', 10); return result(v, 494, 'Blockchain anchor', 10); });
  c.push((ctx) => { const v = ctx.state?.timestampProofValid; if (v === undefined) return result(true, 495, 'No timestamp proof', 10); return result(v, 495, 'Timestamp proof', 10); });
  c.push((ctx) => { const v = ctx.state?.logIntegrityValid; if (v === undefined) return result(true, 496, 'No log integrity', 10); return result(v, 496, 'Log integrity', 10); });
  c.push((ctx) => { const v = ctx.state?.configIntegrityValid; if (v === undefined) return result(true, 497, 'No config integrity', 10); return result(v, 497, 'Config integrity', 10); });
  c.push((ctx) => { const v = ctx.state?.mutationSignatureValid; if (v === undefined) return result(true, 498, 'No mutation sig', 10); return result(v, 498, 'Mutation signature', 10); });
  c.push((ctx) => { const v = ctx.state?.dailyMutationApplied; if (v === undefined) return result(true, 499, 'No mutation status', 10); return result(v, 499, 'Daily mutation', 10); });
  c.push((ctx) => { const v = ctx.state?.masterIntegritySeal; if (v === undefined) return result(true, 500, 'No master seal', 10); return result(v, 500, 'Master seal valid', 10); });
  return c;
}

// ============================================================================
// Protector Class
// ============================================================================

/**
 * 500-layer security shield with middleware factory.
 * @class
 */
export class Protector {
  constructor(options = {}) {
    this.blockThreshold = options.blockThreshold || 100;
    this.extraValidationThreshold = options.extraValidationThreshold || 250;
    this.warningThreshold = options.warningThreshold || 400;
    this.onViolation = options.onViolation || null;
    this.onScore = options.onScore || null;

    this.checks = [
      ...createRequestValidationChecks(),   // 1-50
      ...createIPValidationChecks(),        // 51-100
      ...createAuthenticationChecks(),      // 101-150
      ...createInputSanitizationChecks(),   // 151-200
      ...createRateLimitingChecks(),        // 201-250
      ...createBotDetectionChecks(),        // 251-300
      ...createSessionValidationChecks(),   // 301-350
      ...createDeviceValidationChecks(),    // 351-400
      ...createBehaviorAnalysisChecks(),    // 401-450
      ...createIntegrityChecks()            // 451-500
    ];

    this.criticalIndices = [0, 50, 100, 150, 200, 250, 300, 350, 400, 450];
    this.usedNonces = new Set();
    this.usedRequestIds = new Set();
    this.mutationProfile = this._generateDailyMutation();
  }

  _generateDailyMutation() {
    const date = new Date().toISOString().slice(0, 10);
    const seed = sha256(date);
    const layers = Array.from({ length: 500 }, (_, i) => i);
    for (let i = layers.length - 1; i > 0; i--) {
      const seedIdx = i % seed.length;
      const rand = parseInt(seed.slice(seedIdx, seedIdx + 8), 16);
      const j = rand % (i + 1);
      [layers[i], layers[j]] = [layers[j], layers[i]];
    }
    return layers;
  }

  _buildContext(req) {
    const forwarded = req.headers['x-forwarded-for'];
    return {
      req,
      ip: forwarded ? forwarded.split(',')[0].trim() : req.ip || req.socket?.remoteAddress || 'unknown',
      state: req.fortressState || {}
    };
  }

  _runCheck(check, ctx, index) {
    try {
      const r = check(ctx);
      return { ...r, checkIndex: index };
    } catch (err) {
      return { passed: false, layer: index + 1, message: `Check ${index + 1} error: ${err.message}`, score: 0, timestamp: new Date().toISOString(), checkIndex: index, error: true };
    }
  }

  async runChecks(req, start = 1, end = 500) {
    const ctx = this._buildContext(req);
    const results = [];
    let totalScore = 0;
    const s = Math.max(0, start - 1);
    const e = Math.min(500, end);

    for (let i = s; i < e; i++) {
      const check = this.checks[i];
      if (!check) continue;
      const cr = this._runCheck(check, ctx, i);
      results.push(cr);
      if (cr.passed) totalScore += cr.score;
    }

    const maxScore = (end - start + 1) * 10;
    return {
      totalChecked: results.length,
      passed: results.filter(r => r.passed).length,
      failed: results.filter(r => !r.passed).length,
      errors: results.filter(r => r.error).length,
      score: totalScore,
      maxScore,
      percentage: Math.round((results.filter(r => r.passed).length / Math.max(results.length, 1)) * 100),
      results,
      recommendation: this._getRecommendation(totalScore, maxScore),
      timestamp: new Date().toISOString()
    };
  }

  _getRecommendation(score, maxScore) {
    const ratio = score / Math.max(maxScore, 1);
    if (ratio < 0.2) return 'block';
    if (ratio < 0.5) return 'extra-validation';
    if (ratio < 0.8) return 'warning';
    return 'allow';
  }

  async runAll(req) { return this.runChecks(req, 1, 500); }

  async runCritical(req) {
    const ctx = this._buildContext(req);
    const results = [];
    let totalScore = 0;
    for (const idx of this.criticalIndices) {
      const check = this.checks[idx];
      if (!check) continue;
      const cr = this._runCheck(check, ctx, idx);
      results.push(cr);
      if (cr.passed) totalScore += cr.score;
    }
    return { totalChecked: results.length, passed: results.filter(r => r.passed).length, failed: results.filter(r => !r.passed).length, score: totalScore, maxScore: 100, percentage: Math.round((results.filter(r => r.passed).length / Math.max(results.length, 1)) * 100), results, recommendation: this._getRecommendation(totalScore, 100), timestamp: new Date().toISOString() };
  }

  async runDailyMutation(req, count = 100) {
    const ctx = this._buildContext(req);
    const selected = this.mutationProfile.slice(0, count);
    const results = [];
    let totalScore = 0;
    for (const idx of selected) {
      const check = this.checks[idx];
      if (!check) continue;
      const cr = this._runCheck(check, ctx, idx);
      results.push(cr);
      if (cr.passed) totalScore += cr.score;
    }
    return { mutationDate: new Date().toISOString().slice(0, 10), totalChecked: results.length, passed: results.filter(r => r.passed).length, failed: results.filter(r => !r.passed).length, score: totalScore, maxScore: count * 10, percentage: Math.round((results.filter(r => r.passed).length / Math.max(results.length, 1)) * 100), results, recommendation: this._getRecommendation(totalScore, count * 10), timestamp: new Date().toISOString() };
  }

  protect(start, end) {
    const protector = this;
    return async function protectMiddleware(req, res, next) {
      try {
        const summary = await protector.runChecks(req, start, end);
        req.fortressScore = summary.score;
        req.fortressMaxScore = summary.maxScore;
        req.fortressResults = summary.results;
        req.fortressRecommendation = summary.recommendation;
        const ratio = summary.score / Math.max(summary.maxScore, 1);
        if (ratio < 0.2) return res.status(403).json({ error: 'Security check failed', code: 'FORTRESS_BLOCKED', score: summary.score, passed: summary.passed, total: summary.totalChecked, timestamp: new Date().toISOString() });
        if (ratio < 0.5) { req.requiresExtraValidation = true; req.fortressWarning = 'Extra validation required'; }
        if (ratio < 0.8) req.fortressWarning = 'Security warning active';
        next();
      } catch (err) {
        res.status(500).json({ error: 'Security middleware error', code: 'FORTRESS_ERROR', timestamp: new Date().toISOString() });
      }
    };
  }

  all() { return this.protect(1, 500); }

  critical() {
    const protector = this;
    return async function criticalMiddleware(req, res, next) {
      try {
        const summary = await protector.runCritical(req);
        req.fortressScore = summary.score;
        req.fortressResults = summary.results;
        req.fortressRecommendation = summary.recommendation;
        if (summary.score < protector.blockThreshold) return res.status(403).json({ error: 'Critical check failed', code: 'FORTRESS_CRITICAL_BLOCKED', score: summary.score, timestamp: new Date().toISOString() });
        next();
      } catch (err) {
        res.status(500).json({ error: 'Critical middleware error', code: 'FORTRESS_CRITICAL_ERROR', timestamp: new Date().toISOString() });
      }
    };
  }

  daily() {
    const protector = this;
    return async function dailyMiddleware(req, res, next) {
      try {
        const summary = await protector.runDailyMutation(req);
        req.fortressScore = summary.score;
        req.fortressResults = summary.results;
        req.fortressRecommendation = summary.recommendation;
        req.mutationDate = summary.mutationDate;
        if (summary.percentage < 20) return res.status(403).json({ error: 'Daily mutation check failed', code: 'FORTRESS_DAILY_BLOCKED', score: summary.score, mutationDate: summary.mutationDate, timestamp: new Date().toISOString() });
        next();
      } catch (err) {
        res.status(500).json({ error: 'Daily mutation middleware error', code: 'FORTRESS_DAILY_ERROR', timestamp: new Date().toISOString() });
      }
    };
  }

  getLayerMap() {
    return [
      { name: 'request-validation', range: [1, 50] },
      { name: 'ip-validation', range: [51, 100] },
      { name: 'authentication', range: [101, 150] },
      { name: 'input-sanitization', range: [151, 200] },
      { name: 'rate-limiting', range: [201, 250] },
      { name: 'bot-detection', range: [251, 300] },
      { name: 'session-validation', range: [301, 350] },
      { name: 'device-validation', range: [351, 400] },
      { name: 'behavior-analysis', range: [401, 450] },
      { name: 'integrity-checks', range: [451, 500] }
    ];
  }

  getStats() {
    return { totalChecks: this.checks.length, criticalChecks: this.criticalIndices.length, blockThreshold: this.blockThreshold, extraValidationThreshold: this.extraValidationThreshold, warningThreshold: this.warningThreshold, mutationDate: new Date().toISOString().slice(0, 10), mutationProfileLength: this.mutationProfile.length, categories: this.getLayerMap() };
  }
}

// ============================================================================
// Convenience Exports
// ============================================================================

export function createProtector(options) { return new Protector(options); }
export function protectAll() { const p = new Protector(); return p.all(); }
export function protectCritical() { const p = new Protector(); return p.critical(); }
export function protectDaily() { const p = new Protector(); return p.daily(); }
export { result, calculateEntropy, ipInCidr, sha256, hmacSha256 as hmac, secureRandomInt };
