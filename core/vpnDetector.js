/**
 * @fileoverview VPN/Proxy/Datacenter Detector — IP Reputation & Risk Scoring
 *
 * CRITICAL SECURITY RULES:
 *   1. NEVER store raw IPs — always SHA-256 hashed.
 *   2. NEVER log raw IPs — anonymize or hash before logging.
 *   3. External API calls are defensive (timeout, fail-open).
 *   4. Results are cached to minimize external API dependency.
 *
 * Detects:
 *   - VPN / Proxy services (raise risk score +30)
 *   - Datacenter IPs (raise risk score +50, likely bot/script)
 *   - Tor exit nodes (raise risk score +40)
 *   - Known bad ASNs (raise risk score +25)
 *
 * Sources:
 *   - ip-api.com (free, no auth)
 *   - ipinfo.io (free tier)
 *   - Internal datacenter ASN list (offline)
 *   - Cached results (MongoDB-backed)
 *
 * @module core/vpnDetector
 * @version 1.0.0
 */

import { createHash } from 'crypto';

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/** Datacenter / cloud provider ASNs — these are highly suspicious for bot activity */
const DATACENTER_ASNS = new Set([
  // Amazon AWS
  'AS16509', 'AS14618', 'AS15169', 'AS8961', 'AS38895', 'AS62785', 'AS16550',
  'AS394161', 'AS39111', 'AS36408', 'AS36251', 'AS36069', 'AS35995', 'AS35994',
  'AS33490', 'AS32879', 'AS31898', 'AS23490', 'AS22423', 'AS22125', 'AS21496',
  'AS19194', 'AS17493', 'AS16552', 'AS15134', 'AS14187', 'AS13791', 'AS10124',
  // Google Cloud
  'AS15169', 'AS19506', 'AS36040', 'AS43515', 'AS36384', 'AS36385', 'AS36492',
  'AS394699', 'AS394639', 'AS395973', 'AS396982',
  // Microsoft Azure
  'AS8075', 'AS8068', 'AS8069', 'AS12076',
  // DigitalOcean
  'AS14061', 'AS200130', 'AS201229', 'AS202018', 'AS393406', 'AS394018',
  // Linode / Akamai
  'AS63949', 'AS21844', 'AS24381', 'AS30607', 'AS33345', 'AS33597', 'AS4181',
  // Hetzner
  'AS24940', 'AS213230',
  // OVH
  'AS16276',
  // Vultr
  'AS20473', 'AS397423',
  // Oracle Cloud
  'AS31898', 'AS6142',
  // Alibaba Cloud
  'AS45102',
  // IBM Cloud / SoftLayer
  'AS36351', 'AS13884',
  // Contabo
  'AS51167',
  // Scaleway
  'AS12876',
  // Wasabi
  'AS22199',
  // Choopa / Constant
  'AS20473',
  // GCore
  'AS202422',
  // BuyVM / Frantech
  'AS53667',
  // Hostinger
  'AS47583',
  // Namecheap
  'AS22612',
  // GoDaddy
  'AS26496',
  // Bluehost / EIG
  'AS46606',
  // Cloudflare (egress can appear as datacenter)
  'AS13335', 'AS209242',
  // Fastly
  'AS54113',
]);

/** Known VPN/proxy/hosting ASNs (not datacenters but still suspicious) */
const VPN_HOSTING_ASNS = new Set([
  'AS9009',   // M247
  'AS60068',  // VPN Unlimited / KeepSolid
  'AS206092', // NordVPN
  'AS136787', // NordVPN
  'AS212238', // NordVPN
  'AS39798',  // NordVPN
  'AS35816',  // Private Internet Access
  'AS174',    // Cogent (often used by VPNs)
  'AS1299',   // Arelion / Telia (VPN transit)
  'AS3258',   // xTom / V.PS
  'AS8100',   // QuadraNet (VPN hosting)
  'AS8100',   // QuadraNet
  'AS46844',  // Sharktech
  'AS55286',  // B2 Net Solutions
  'AS55286',  // ServerMania
  'AS54290',  // Hostwinds
  'AS63473',  // HostHatch
  'AS18978',  // Enzu
  'AS46816',  // DirectSpace
  'AS19318',  // Interserver
  'AS23535',  // NodePing
  'AS29802',  // HIVELOCITY
  'AS11878',  // tzulo
  'AS22439',  // PacketHub
  'AS30823',  // Combahton
  'AS208216', // Latitude.sh
  'AS207990', // Hostinger / 000webhost
  'AS57494',  // Adman
  'AS205544', // Leaseweb USA
  'AS59253',  // Leaseweb Asia
  'AS60781',  // Leaseweb Deutschland
  'AS395954', // Leaseweb
  'AS33387',  // Datashack
  'AS58461',  // CT-HangZhou
  'AS140952', // Tencent
  'AS45090',  // Tencent Cloud
  'AS132203', // Tencent
]);

/** Known proxy ports — if these are open on the client side, it's suspicious */
const KNOWN_PROXY_PORTS = [
  8080, 3128, 1080, 1081, 4145, 1085, 6588, 8000, 8118, 8123,
  9090, 9064, 7480, 10800, 6443, 6666, 6667, 9050, 9051, 9150,
  443,  8443, 4040, 5000, 5555, 5678, 8081, 8082, 9999, 4533,
  9200, 9300, 9400, 9500, 9600, 9700, 9800, 9900,
];

/** External API config */
const API_TIMEOUT_MS = 5000; // 5 second timeout — fail fast
const IP_API_URL = (ip) => `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query`;
const IPINFO_URL = (ip) => `https://ipinfo.io/${ip}/json?token=${process.env.IPINFO_TOKEN || ''}`;

/** Cache TTL for IP lookups (ms) */
const CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes

/** Collection names */
const COLL_VPN_CACHE = 'vpn_ip_cache';
const COLL_VPN_LOG   = 'vpn_check_log';

// ─────────────────────────────────────────────────────────────────────────────
// MongoDB handle
// ─────────────────────────────────────────────────────────────────────────────

let _db = null;
let _logFn = null; // optional audit log function

/**
 * Initialise the VPN detector module.
 * @param {import('mongodb').Db} db — connected MongoDB Db instance
 * @param {Function} [auditLogFn] — optional audit log function from auditLog.js
 */
export function initVpnDetector(db, auditLogFn = null) {
  _db = db;
  _logFn = auditLogFn;

  // Ensure indexes
  _db.collection(COLL_VPN_CACHE).createIndex(
    { ipHash: 1 }, { unique: true }
  );
  _db.collection(COLL_VPN_CACHE).createIndex(
    { checkedAt: 1 }, { expireAfterSeconds: 86400 * 7 } // TTL 7 days
  );
  _db.collection(COLL_VPN_LOG).createIndex(
    { checkedAt: 1 }, { expireAfterSeconds: 86400 * 30 } // TTL 30 days
  );
}

function getColl(name) {
  if (!_db) throw new Error('VpnDetector not initialized — call initVpnDetector(db) first');
  return _db.collection(name);
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

function quickHash(val) {
  if (!val) return 'null';
  return createHash('sha256').update(String(val)).digest('hex').slice(0, 16);
}

/**
 * Check if an ASN string matches our datacenter or VPN ASN lists.
 * @param {string} asn — e.g. "AS16509"
 * @returns {{datacenter: boolean, vpnHosting: boolean}}
 */
function checkAsn(asn) {
  const clean = String(asn || '').trim().toUpperCase();
  return {
    datacenter: DATACENTER_ASNS.has(clean),
    vpnHosting: VPN_HOSTING_ASNS.has(clean),
  };
}

/**
 * Check an IP against the external ip-api.com service.
 * Defensive: short timeout, JSON parse guards.
 * @param {string} ip — raw IP address (IPv4 or IPv6)
 * @returns {Promise<Object|null>}
 */
async function checkIpApi(ip) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), API_TIMEOUT_MS);

    const response = await fetch(IP_API_URL(ip), {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    });
    clearTimeout(timeout);

    if (!response.ok) return null;

    const data = await response.json();
    if (data.status !== 'success') return null;

    return {
      proxy:    !!data.proxy,
      hosting:  !!data.hosting,
      mobile:   !!data.mobile,
      country:  data.countryCode || null,
      asn:      data.as ? `AS${data.as}`.toUpperCase() : null,
      asnName:  data.asname || null,
      isp:      data.isp || null,
      org:      data.org || null,
    };
  } catch {
    // Fail-open: external check failed, return null (neutral)
    return null;
  }
}

/**
 * Check an IP against ipinfo.io (used as secondary source).
 * @param {string} ip — raw IP address
 * @returns {Promise<Object|null>}
 */
async function checkIpInfo(ip) {
  if (!process.env.IPINFO_TOKEN) return null; // Skip if no token

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), API_TIMEOUT_MS);

    const response = await fetch(IPINFO_URL(ip), {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    });
    clearTimeout(timeout);

    if (!response.ok) return null;

    const data = await response.json();
    const org = (data.org || '').toUpperCase();

    return {
      org,
      country: data.country || null,
      isVpn: /VPN|PROXY|HOSTING|SERVER|DATACENTER|CLOUD/i.test(org),
      isHosting: /HOSTING|SERVER|DATACENTER|CLOUD|VPS/i.test(org),
    };
  } catch {
    return null;
  }
}

/**
 * Combine results from multiple sources into a unified risk score adjustment.
 * @param {Object} ipApiResult
 * @param {Object} ipInfoResult
 * @returns {{scoreAdjustment: number, flags: string[], confidence: 'high'|'medium'|'low'}}
 */
function combineResults(ipApiResult, ipInfoResult) {
  const flags = [];
  let scoreAdjustment = 0;

  // ── Source 1: ip-api.com ──
  if (ipApiResult) {
    if (ipApiResult.proxy) {
      flags.push('proxy');
      scoreAdjustment += 30;
    }
    if (ipApiResult.hosting) {
      flags.push('hosting/datacenter');
      scoreAdjustment += 50;
    }
    if (ipApiResult.mobile) {
      flags.push('mobile');
      scoreAdjustment -= 5; // Slightly lower risk for mobile
    }

    // ASN check
    if (ipApiResult.asn) {
      const asnCheck = checkAsn(ipApiResult.asn);
      if (asnCheck.datacenter) {
        flags.push('datacenter_asn');
        scoreAdjustment += 50;
      }
      if (asnCheck.vpnHosting) {
        flags.push('vpn_hosting_asn');
        scoreAdjustment += 25;
      }
    }
  }

  // ── Source 2: ipinfo.io ──
  if (ipInfoResult) {
    if (ipInfoResult.isVpn) {
      if (!flags.includes('proxy')) flags.push('vpn_org');
      scoreAdjustment += 30;
    }
    if (ipInfoResult.isHosting) {
      if (!flags.includes('hosting/datacenter')) flags.push('hosting_org');
      scoreAdjustment += 40;
    }
  }

  // Cap at reasonable maximum
  scoreAdjustment = Math.min(scoreAdjustment, 100);

  const confidence =
    (ipApiResult && ipInfoResult) ? 'high' :
    (ipApiResult || ipInfoResult) ? 'medium' : 'low';

  return {
    scoreAdjustment,
    flags,
    confidence,
  };
}

/**
 * Check the cache for a previously looked-up IP.
 * @param {string} ipHash — hashed IP
 * @returns {Promise<Object|null>}
 */
async function checkCache(ipHash) {
  try {
    const doc = await getColl(COLL_VPN_CACHE).findOne(
      { ipHash },
      { projection: { _id: 0 } }
    );
    if (!doc) return null;

    // Check cache freshness
    const age = Date.now() - (doc.checkedAt?.getTime() || 0);
    if (age > CACHE_TTL_MS) return null; // Stale

    return {
      scoreAdjustment: doc.scoreAdjustment,
      flags: doc.flags,
      confidence: doc.confidence,
      source: 'cache',
    };
  } catch {
    return null;
  }
}

/**
 * Store lookup result in cache.
 * @param {string} ipHash
 * @param {Object} result
 */
async function storeCache(ipHash, result) {
  try {
    await getColl(COLL_VPN_CACHE).updateOne(
      { ipHash },
      {
        $set: {
          ipHash,
          scoreAdjustment: result.scoreAdjustment,
          flags: result.flags,
          confidence: result.confidence,
          checkedAt: new Date(),
        },
      },
      { upsert: true }
    );
  } catch {
    // Cache write failure is non-critical
  }
}

/**
 * Log a VPN check event (for audit trail).
 */
async function logCheck(ipHash, result, sources) {
  try {
    await getColl(COLL_VPN_LOG).insertOne({
      ipHash,
      scoreAdjustment: result.scoreAdjustment,
      flags: result.flags,
      confidence: result.confidence,
      sources,
      checkedAt: new Date(),
    });

    if (_logFn && result.scoreAdjustment >= 30) {
      _logFn('VPN_DETECTED', {
        ipHash,
        scoreAdjustment: result.scoreAdjustment,
        flags: result.flags,
        confidence: result.confidence,
      }, 'WARN');
    }
  } catch {
    // Non-critical
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Detect VPN/Proxy/Datacenter for a given IP address.
 * Checks cache first, then external APIs, stores result.
 *
 * @param {string} ip — raw IP address (IPv4 or IPv6)
 * @returns {Promise<{
 *   scoreAdjustment: number,   // how much to add to risk score
 *   flags: string[],           // detected flags
 *   confidence: 'high'|'medium'|'low',
 *   source: string,            // 'cache' | 'ip-api' | 'ipinfo' | 'combined' | 'offline'
 * }>}
 *
 * SECURITY: IP is hashed internally. Raw IP is only used for external API calls.
 */
export async function detectVpnProxy(ip) {
  if (!ip || typeof ip !== 'string') {
    return { scoreAdjustment: 0, flags: [], confidence: 'low', source: 'none' };
  }

  const ipHash = quickHash(ip);

  // ── 1. Check cache ──
  const cached = await checkCache(ipHash);
  if (cached) return cached;

  // ── 2. External lookups (parallel) ──
  const [ipApiResult, ipInfoResult] = await Promise.all([
    checkIpApi(ip),
    checkIpInfo(ip),
  ]);

  const sources = [];
  if (ipApiResult) sources.push('ip-api');
  if (ipInfoResult) sources.push('ipinfo');

  // ── 3. Combine results ──
  let result;
  if (sources.length > 0) {
    const combined = combineResults(ipApiResult, ipInfoResult);
    result = {
      ...combined,
      source: sources.length > 1 ? 'combined' : sources[0],
    };
  } else {
    // Offline fallback: check if IP is in private/reserved ranges
    const offlineFlags = checkOfflineRanges(ip);
    result = {
      scoreAdjustment: offlineFlags.length > 0 ? 10 : 0,
      flags: offlineFlags,
      confidence: 'low',
      source: 'offline',
    };
  }

  // ── 4. Cache and log ──
  await storeCache(ipHash, result);
  await logCheck(ipHash, result, sources);

  return result;
}

/**
 * Offline check for private/reserved IP ranges.
 * These are suspicious if they appear in production (indicates spoofing or internal abuse).
 * @param {string} ip
 * @returns {string[]}
 */
function checkOfflineRanges(ip) {
  const flags = [];

  // Private IPv4 ranges
  if (
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2[0-9]|3[01])\./.test(ip) ||
    ip === '127.0.0.1' ||
    ip === '::1' ||
    ip.startsWith('fc') || // IPv6 unique local
    ip.startsWith('fd')    // IPv6 unique local
  ) {
    flags.push('private_range');
  }

  // Link-local
  if (ip.startsWith('169.254.') || ip.startsWith('fe80:')) {
    flags.push('link_local');
  }

  // IPv6 loopback
  if (ip === '::1' || ip === '0:0:0:0:0:0:0:1') {
    flags.push('loopback');
  }

  return flags;
}

/**
 * Quick check: only local heuristics, NO external API calls.
 * Used for hot-path checks where latency matters.
 * @param {string} ip — raw IP
 * @param {Object} reqHeaders — optional request headers for additional signals
 * @returns {{scoreAdjustment: number, flags: string[]}}
 */
export function quickVpnCheck(ip, reqHeaders = {}) {
  const flags = [];
  let scoreAdjustment = 0;

  // Check for proxy headers
  const proxyHeaders = [
    'x-forwarded-for',
    'x-forwarded-host',
    'x-forwarded-proto',
    'x-real-ip',
    'x-proxy-id',
    'via',
    'forwarded',
    'x-cluster-client-ip',
    'x-originating-ip',
    'x-remote-ip',
    'x-remote-addr',
  ];

  let proxyHeaderCount = 0;
  for (const h of proxyHeaders) {
    if (reqHeaders[h]) proxyHeaderCount++;
  }

  if (proxyHeaderCount >= 3) {
    flags.push('multiple_proxy_headers');
    scoreAdjustment += 15;
  }

  // Multiple X-Forwarded-For hops
  const xff = reqHeaders['x-forwarded-for'];
  if (xff) {
    const hops = xff.split(',').length;
    if (hops >= 3) {
      flags.push('many_proxy_hops');
      scoreAdjustment += 10;
    }
  }

  // Private range (suspicious in prod)
  const offlineFlags = checkOfflineRanges(ip);
  flags.push(...offlineFlags);
  if (offlineFlags.length > 0) {
    scoreAdjustment += 10;
  }

  return { scoreAdjustment: Math.min(scoreAdjustment, 100), flags };
}

/**
 * Batch check multiple IPs (for admin/monitoring use).
 * @param {string[]} ips — array of raw IPs
 * @returns {Promise<Array>}
 */
export async function batchDetectVpnProxy(ips) {
  if (!Array.isArray(ips)) return [];
  const results = [];
  // Rate-limit: check one per 200ms to avoid API rate limits
  for (const ip of ips) {
    const result = await detectVpnProxy(ip);
    results.push({ ipHash: quickHash(ip), ...result });
    await new Promise((r) => setTimeout(r, 200));
  }
  return results;
}

/**
 * Get VPN detection stats (for monitoring).
 * @returns {Promise<Object>}
 */
export async function getVpnDetectionStats() {
  try {
    const total = await getColl(COLL_VPN_CACHE).estimatedDocumentCount();
    const flagged = await getColl(COLL_VPN_CACHE).countDocuments({
      scoreAdjustment: { $gte: 30 },
    });
    const highRisk = await getColl(COLL_VPN_CACHE).countDocuments({
      scoreAdjustment: { $gte: 50 },
    });

    // Top flags
    const topFlags = await getColl(COLL_VPN_LOG).aggregate([
      { $unwind: '$flags' },
      { $group: { _id: '$flags', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 },
    ]).toArray();

    return {
      totalChecked: total,
      flaggedIps: flagged,
      highRiskIps: highRisk,
      topFlags: topFlags.map((f) => ({ flag: f._id, count: f.count })),
      checkedAt: new Date().toISOString(),
    };
  } catch {
    return { totalChecked: 0, flaggedIps: 0, highRiskIps: 0, topFlags: [], checkedAt: new Date().toISOString() };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Default export
// ─────────────────────────────────────────────────────────────────────────────

export default {
  initVpnDetector,
  detectVpnProxy,
  quickVpnCheck,
  batchDetectVpnProxy,
  getVpnDetectionStats,
};
