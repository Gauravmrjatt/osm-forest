/**
 * @fileoverview fingerprint.js - Browser Fingerprinting Service
 * Osm Army Gift Code Fortress - Ultra-Secure Gift Code System
 *
 * Creates unique device signatures from browser/client data.
 * Detects automation, virtual machines, and anomalous combinations.
 * Binds fingerprints to sessions and tokens for hijack detection.
 *
 * @author Osm Army Security Team
 * @version 5.0.0-fortress
 * @license Proprietary
 */

'use strict';

import { createHash, randomBytes, timingSafeEqual, createHmac } from 'crypto';

// ============================================================================
// Constants
// ============================================================================

/** System fonts to check for font fingerprinting */
const SYSTEM_FONTS = [
  'Arial', 'Arial Black', 'Arial Narrow', 'Arial Rounded MT Bold',
  'Book Antiqua', 'Bookman Old Style', 'Calibri', 'Cambria', 'Cambria Math',
  'Century', 'Century Gothic', 'Century Schoolbook', 'Comic Sans MS',
  'Consolas', 'Courier', 'Courier New', 'Garamond', 'Georgia',
  'Impact', 'Lucida Console', 'Lucida Sans Unicode', 'Microsoft Sans Serif',
  'Monospace', 'Palatino Linotype', 'Segoe Print', 'Segoe Script',
  'Segoe UI', 'Tahoma', 'Times', 'Times New Roman', 'Trebuchet MS',
  'Verdana', 'Webdings', 'Wingdings', 'Wingdings 2', 'Wingdings 3',
  'Abadi MT Condensed Light', 'Adobe Garamond Pro', 'Albertus MT',
  'Antiqua', 'Apex', 'Apple Chancery', 'Apple SD Gothic Neo',
  'Archer', 'Arial MT', 'Avant Garde', 'Avenir', 'Baskerville',
  'Batang', 'Bauhaus 93', 'Bell MT', 'Berlin Sans FB', 'Bernard MT Condensed',
  'Bickham Script Pro', 'Birch Std', 'Blackadder ITC', 'Bodoni MT',
  'Bodoni MT Poster Compressed', 'Bookman', 'Bradley Hand ITC', 'Britannic Bold',
  'Broadway', 'Browallia New', 'Brush Script MT', 'Caledonia', 'Calisto MT',
  'Candara', 'Castellar', 'Centaur', 'Chalkboard', 'Chalkduster',
  'Chaparral Pro', 'Charlemagne Std', 'Charter', 'Chicago', 'Clarendon',
  'Cochin', 'Colonna MT', 'Constantia', 'Cooper Black', 'Copperplate',
  'Corbel', 'Cordia New', 'Courier Std', 'Curlz MT', 'DaunPenh',
  'David', 'DejaVu Sans', 'DejaVu Serif', 'Didot', 'DIN',
  'Dominant', 'Ebrima', 'Edwardian Script ITC', 'Elephant',
  'Engravers MT', 'Eras ITC', 'Estrangelo Edessa', 'Euclid',
  'Euphemia', 'Eurostile', 'Footlight MT Light', 'Forte',
  'Franklin Gothic', 'Franklin Gothic Book', 'Freestyle Script',
  'French Script MT', 'Futura', 'Gabriola', 'Gadugi', 'Garamond Premr Pro',
  'Geneva', 'Gill Sans', 'Gill Sans MT', 'Gloucester MT Extra Condensed',
  'Goudy Old Style', 'Goudy Stout', 'Gulim', 'Haettenschweiler',
  'Harlow Solid Italic', 'Harrington', 'Helvetica', 'Helvetica Neue',
  'High Tower Text', 'Hiragino Kaku Gothic ProN', 'Hoefler Text',
  'HP Simplified', 'Humanst521 BT', 'Impact', 'Imprint MT Shadow',
  'Informal Roman', 'IrisUPC', 'Iskoola Pota', 'JasmineUPC',
  'Jokerman', 'Juice ITC', 'KaiTi', 'Kalinga', 'Kartika',
  'Khmer UI', 'KodchiangUPC', 'Kokila', 'Kozuka Gothic Pro',
  'Kristen ITC', 'Kunstler Script', 'Lao UI', 'Latha',
  'Leelawadee', 'Levenim MT', 'LiHei Pro', 'LilyUPC', 'Lithos Pro',
  'Lucida Bright', 'Lucida Calligraphy', 'Lucida Fax', 'Lucida Grande',
  'Lucida Handwriting', 'Lucida Sans', 'Maiandra GD', 'Malgun Gothic',
  'Mangal', 'Marlett', 'Matura MT Script Capitals', 'Meiryo',
  'Microsoft Himalaya', 'Microsoft JhengHei', 'Microsoft New Tai Lue',
  'Microsoft PhagsPa', 'Microsoft Tai Le', 'Microsoft Uighur',
  'Microsoft YaHei', 'Microsoft Yi Baiti', 'MingLiU',
  'MingLiU-ExtB', 'MingLiU_HKSCS', 'MingLiU_HKSCS-ExtB',
  'Miriam', 'Miriam Fixed', 'Mistral', 'Modern No. 20',
  'Mongolian Baiti', 'Monotype Corsiva', 'MS Gothic', 'MS Mincho',
  'MS Outlook', 'MS PGothic', 'MS PMincho', 'MS Reference Sans Serif',
  'MS Reference Specialty', 'MS UI Gothic', 'MT Extra',
  'MV Boli', 'Myanmar Text', 'Narkisim', 'News Gothic MT',
  'Niagara Engraved', 'Niagara Solid', 'NSimSun', 'Nyala',
  'OCR A Extended', 'Old English Text MT', 'Onyx', 'Open Sans',
  'Palace Script MT', 'Papyrus', 'Parchment', 'Perpetua',
  'Perpetua Titling MT', 'Plantagenet Cherokee', 'Playbill',
  'PMingLiU', 'PMingLiU-ExtB', 'Poor Richard',
  'Pristina', 'Rage Italic', 'Ravie', 'Rockwell', 'Rockwell Condensed',
  'Rockwell Extra Bold', 'Rod', 'Sakkal Majalla', 'Script MT Bold',
  'Segoe UI Emoji', 'Segoe UI Historic', 'Segoe UI Symbol',
  'Showcard Gothic', 'SimHei', 'Simplified Arabic', 'SimSun',
  'SimSun-ExtB', 'Sitka Banner', 'Sitka Display', 'Sitka Heading',
  'Sitka Small', 'Sitka Subheading', 'Sitka Text',
  'Snap ITC', 'Source Sans Pro', 'Source Serif Pro',
  'Stencil', 'Sylfaen', 'Symbol', 'Tahoma', 'Tempus Sans ITC',
  'Times New Roman PS', 'Traditional Arabic', 'Trebuchet MS',
  'Tw Cen MT', 'Tw Cen MT Condensed', 'Tw Cen MT Condensed Extra Bold',
  'Urdu Typesetting', 'Utsaah', 'Vani', 'Verdana', 'Verdana Ref',
  'Vijaya', 'Viner Hand ITC', 'Vivaldi', 'Vladimir Script',
  'Vrinda', 'Webdings', 'Wide Latin', 'Yu Gothic', 'Yu Mincho',
  'Zapf Chancery', 'Zapf Dingbats'
];

/** Known automation fingerprints (browser properties set by automation frameworks) */
const AUTOMATION_FINGERPRINTS = {
  selenium: [
    'cdc_adoQpoasnfa76pfcZLmcfl_',
    '__webdriver_evaluate',
    '__selenium_evaluate',
    '__selenium_unwrapped',
    '__webdriver_script_fn',
    '__$webdriverAsyncExecutor',
    '_Selenium_IDE_Recorder'
  ],
  puppeteer: [
    '_puppeteer',
    '__puppeteer_global',
    'pptr_',
    'cdp',
    'Runtime.evaluate',
    'Page.createIsolatedWorld'
  ],
  playwright: [
    '__playwright__',
    '_playwright_',
    'pw-',
    '__pw__',
    'playwright-timeline'
  ],
  phantomjs: [
    '_phantom',
    'callPhantom',
    '__phantomas',
    'Buffer'
  ],
  nightmare: [
    '__nightmare',
    ' Nightmare '
  ],
  headless: [
    'HeadlessChrome',
    'headless',
    'Headless'
  ]
};

/** VM detection signatures */
const VM_SIGNATURES = {
  userAgent: ['VirtualBox', 'VMware', 'Parallels', 'QEMU', 'KVM', 'Xen'],
  renderer: ['llvmpipe', 'LLVM', 'Software', 'Microsoft Basic Render Driver', 'SWR'],
  vendor: ['Google Inc. (NVIDIA)', 'Google Inc.', 'VMware', 'VirtualBox'],
  platform: ['Linux x86_64', 'Win32', 'MacIntel'],
  memory: { min: 2, suspicious: [0.5, 0.25, 4] },
  cores: { min: 1, suspicious: [1] }
};

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Create SHA-512 hash.
 * @param {string} data - Input data
 * @returns {string} Hex digest
 */
function sha512(data) {
  return createHash('sha512').update(String(data)).digest('hex');
}

/**
 * Create SHA-256 hash.
 * @param {string} data - Input data
 * @returns {string} Hex digest
 */
function sha256(data) {
  return createHash('sha256').update(String(data)).digest('hex');
}

/**
 * Create HMAC-SHA256.
 * @param {string} key - Secret key
 * @param {string} data - Input data
 * @returns {string} Hex digest
 */
function hmac256(key, data) {
  return createHmac('sha256', key).update(String(data)).digest('hex');
}

/**
 * Generate a cryptographically secure random ID.
 * @param {number} [length=32] - ID length
 * @returns {string} Random hex string
 */
function secureId(length = 32) {
  return randomBytes(length).toString('hex').slice(0, length);
}

/**
 * Check timing-safe string equality.
 * @param {string} a - First string
 * @param {string} b - Second string
 * @returns {boolean}
 */
function secureCompare(a, b) {
  if (a.length !== b.length) return false;
  try {
    const bufA = Buffer.from(a, 'utf8');
    const bufB = Buffer.from(b, 'utf8');
    return timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

/**
 * Compute simple hash for a set of detected fonts.
 * @param {string[]} fonts - Array of font names
 * @returns {string} Font hash
 */
function computeFontHash(fonts) {
  return sha256(fonts.sort().join('|'));
}

/**
 * Check if a combination is physically impossible (bot indicator).
 * @param {Object} fp - Fingerprint components
 * @returns {boolean}
 */
function isImpossibleCombination(fp) {
  // Mobile UA but desktop screen
  if (/Mobile|Android|iPhone/.test(fp.userAgent) && fp.screenWidth > 1920) return true;
  // iOS but Linux platform
  if (/iPhone|iPad/.test(fp.userAgent) && fp.platform === 'Linux') return true;
  // Android but macOS platform
  if (/Android/.test(fp.userAgent) && /Mac/.test(fp.platform)) return true;
  // Touch support but no mobile UA
  if (fp.maxTouchPoints > 0 && !/Mobile|Tablet|Touch/.test(fp.userAgent) && fp.screenWidth < 768) return true;
  // 8K screen on mobile device
  if (/Mobile/.test(fp.userAgent) && fp.screenWidth > 2560) return true;
  // Device memory too high for mobile
  if (/Mobile/.test(fp.userAgent) && fp.deviceMemory > 16) return true;
  // More cores than any mobile device
  if (/Mobile/.test(fp.userAgent) && fp.hardwareConcurrency > 16) return true;
  // iOS with WebGL vendor not Apple
  if (/iPhone|iPad/.test(fp.userAgent) && fp.webglVendor && !fp.webglVendor.includes('Apple')) return true;
  // Safari UA but Chrome WebGL vendor
  if (fp.userAgent.includes('Safari') && !fp.userAgent.includes('Chrome') && fp.webglVendor?.includes('Google')) return true;
  return false;
}

/**
 * Count how many automation signatures match.
 * @param {Object} components - Fingerprint components
 * @returns {{total: number, frameworks: Object<string, number>}}
 */
function detectAutomation(components) {
  const results = { total: 0, frameworks: {} };
  const flatComponents = JSON.stringify(components).toLowerCase();

  for (const [framework, signatures] of Object.entries(AUTOMATION_FINGERPRINTS)) {
    let matches = 0;
    for (const sig of signatures) {
      if (flatComponents.includes(sig.toLowerCase())) {
        matches++;
      }
    }
    if (matches > 0) {
      results.frameworks[framework] = matches;
      results.total += matches;
    }
  }

  return results;
}

/**
 * Detect virtual machine from fingerprint.
 * @param {Object} components - Fingerprint components
 * @returns {{isVM: boolean, confidence: number, indicators: string[]}}
 */
function detectVM(components) {
  const indicators = [];
  let confidence = 0;

  // Renderer-based detection
  const renderer = (components.webglRenderer || '').toLowerCase();
  for (const sig of VM_SIGNATURES.renderer) {
    if (renderer.includes(sig.toLowerCase())) {
      indicators.push(`VM renderer: ${sig}`);
      confidence += 30;
    }
  }

  // Vendor-based detection
  const vendor = (components.webglVendor || '').toLowerCase();
  for (const sig of VM_SIGNATURES.vendor) {
    if (vendor.includes(sig.toLowerCase())) {
      indicators.push(`VM vendor: ${sig}`);
      confidence += 20;
    }
  }

  // User-Agent detection
  const ua = (components.userAgent || '').toLowerCase();
  for (const sig of VM_SIGNATURES.userAgent) {
    if (ua.includes(sig.toLowerCase())) {
      indicators.push(`VM UA: ${sig}`);
      confidence += 40;
    }
  }

  // Memory-based detection
  if (components.deviceMemory !== undefined) {
    if (VM_SIGNATURES.memory.suspicious.includes(components.deviceMemory)) {
      indicators.push(`Suspicious memory: ${components.deviceMemory}GB`);
      confidence += 15;
    }
  }

  // Core count detection
  if (components.hardwareConcurrency === 1) {
    indicators.push('Single core (VM indicator)');
    confidence += 10;
  }

  // Canvas hash blank (common in VMs)
  if (components.canvasHash === 'blank' || !components.canvasHash) {
    indicators.push('Blank canvas hash');
    confidence += 10;
  }

  // Audio fingerprint zero (VM)
  if (components.audioFingerprint === 0 || components.audioFingerprint === null) {
    indicators.push('Zero/null audio fingerprint');
    confidence += 10;
  }

  return {
    isVM: confidence >= 40,
    confidence: Math.min(confidence, 100),
    indicators
  };
}

// ============================================================================
// FingerprintCollector Class
// ============================================================================

/**
 * Server-side fingerprint collector for the Osm Army Fortress system.
 * Collects, hashes, and validates browser/device fingerprints.
 *
 * @class
 */
export class FingerprintCollector {
  /**
   * @param {Object} [options] - Configuration
   * @param {string} [options.secretKey] - HMAC secret for fingerprint tokens
   * @param {Object} [options.db] - Database connection for persistence
   * @param {number} [options.stabilityThreshold=0.8] - Minimum stability score
   * @param {number} [options.anomalyThreshold=3] - Max anomalies before flagging
   */
  constructor(options = {}) {
    this.secretKey = options.secretKey || process.env.FORTRESS_FINGERPRINT_SECRET || secureId(64);
    this.db = options.db || null;
    this.stabilityThreshold = options.stabilityThreshold || 0.8;
    this.anomalyThreshold = options.anomalyThreshold || 3;

    /** @type {Map<string, Object>} In-memory fingerprint cache */
    this.cache = new Map();
    /** @type {Map<string, number>} Known automation signature cache */
    this.knownAutomationCache = new Map();
  }

  /**
   * Collect fingerprint from client-submitted data.
   * @param {Object} clientData - Client-side fingerprint data
   * @returns {Object} Complete fingerprint record
   */
  collect(clientData = {}) {
    // Validate input
    if (!clientData || typeof clientData !== 'object') {
      throw new TypeError('clientData must be an object');
    }

    const components = this._extractComponents(clientData);
    const hash = this._computeHash(components);
    const stability = this._computeStabilityScore(components);
    const anomalies = this._detectAnomalies(components);
    const automation = detectAutomation(components);
    const vmDetection = detectVM(components);

    const fingerprint = {
      id: secureId(16),
      hash,
      hashShort: hash.slice(0, 16),
      components,
      stability,
      anomalyCount: anomalies.length,
      anomalies,
      automationDetected: automation.total > 0,
      automationMatches: automation,
      vmDetected: vmDetection.isVM,
      vmConfidence: vmDetection.confidence,
      vmIndicators: vmDetection.indicators,
      isBot: automation.total > 0 || vmDetection.isVM || anomalies.length >= this.anomalyThreshold,
      botConfidence: Math.min(
        (automation.total * 10) + vmDetection.confidence + (anomalies.length * 15),
        100
      ),
      createdAt: new Date().toISOString(),
      version: '5.0.0'
    };

    return fingerprint;
  }

  /**
   * Extract individual fingerprint components from client data.
   * @param {Object} data - Raw client data
   * @returns {Object} Normalized components
   * @private
   */
  _extractComponents(data) {
    const c = data;
    return {
      // Canvas 2D
      canvasHash: this._validateString(c.canvasHash, 128),
      canvasText: this._validateString(c.canvasText, 64),

      // WebGL
      webglRenderer: this._validateString(c.webglRenderer, 128),
      webglVendor: this._validateString(c.webglVendor, 128),
      webglParams: this._validateString(c.webglParams, 256),
      webglExtensions: Array.isArray(c.webglExtensions) ? c.webglExtensions.slice(0, 50) : [],
      webglHash: this._validateString(c.webglHash, 128),

      // Fonts
      fonts: Array.isArray(c.fonts) ? c.fonts.filter(f => typeof f === 'string' && f.length <= 64).slice(0, 300) : [],
      fontHash: computeFontHash(Array.isArray(c.fonts) ? c.fonts : []),

      // Screen
      screenWidth: this._validateInt(c.screenWidth, 320, 16384),
      screenHeight: this._validateInt(c.screenHeight, 240, 8640),
      screenAvailWidth: this._validateInt(c.screenAvailWidth, 320, 16384),
      screenAvailHeight: this._validateInt(c.screenAvailHeight, 240, 8640),
      colorDepth: this._validateInt(c.colorDepth, 8, 48),
      pixelRatio: this._validateFloat(c.pixelRatio, 0.25, 5),

      // Navigator
      platform: this._validateString(c.platform, 64),
      userAgent: this._validateString(c.userAgent, 512),
      language: this._validateString(c.language, 16),
      languages: Array.isArray(c.languages) ? c.languages.slice(0, 10) : [],
      hardwareConcurrency: this._validateInt(c.hardwareConcurrency, 1, 256),
      deviceMemory: this._validateFloat(c.deviceMemory, 0.125, 128),

      // Timezone
      timezone: this._validateString(c.timezone, 64),
      timezoneOffset: this._validateInt(c.timezoneOffset, -720, 840),

      // Touch
      maxTouchPoints: this._validateInt(c.maxTouchPoints, 0, 20),
      touchSupport: !!c.touchSupport,

      // Plugins
      plugins: Array.isArray(c.plugins) ? c.plugins.slice(0, 50) : [],
      mimeTypes: Array.isArray(c.mimeTypes) ? c.mimeTypes.slice(0, 50) : [],
      pluginsHash: sha256(JSON.stringify(c.plugins || []).slice(0, 4096)),

      // WebRTC
      webrtcSupport: !!c.webrtcSupport,
      webrtcIpLeak: !!c.webrtcIpLeak,
      webrtcIps: Array.isArray(c.webrtcIps) ? c.webrtcIps.slice(0, 10) : [],

      // Audio
      audioFingerprint: typeof c.audioFingerprint === 'number' ? c.audioFingerprint : 0,
      audioChannelNumber: this._validateInt(c.audioChannelNumber, 1, 32),
      audioSampleRate: this._validateInt(c.audioSampleRate, 8000, 384000),
      audioMaxChannelCount: this._validateInt(c.audioMaxChannelCount, 1, 32),
      audioChannelCountMode: this._validateString(c.audioChannelCountMode, 32),

      // Battery
      batteryLevel: typeof c.batteryLevel === 'number' ? Math.max(0, Math.min(1, c.batteryLevel)) : null,
      batteryCharging: c.batteryCharging === true || c.batteryCharging === false ? c.batteryCharging : null,

      // Device orientation
      deviceOrientationSupport: !!c.deviceOrientationSupport,
      deviceMotionSupport: !!c.deviceMotionSupport,

      // Storage
      localStorage: !!c.localStorage,
      sessionStorage: !!c.sessionStorage,
      indexedDB: !!c.indexedDB,

      // Additional
      doNotTrack: this._validateString(c.doNotTrack, 32),
      cookieEnabled: !!c.cookieEnabled,
      pdfViewerEnabled: !!c.pdfViewerEnabled,
      bluetoothAvailable: !!c.bluetoothAvailable,
      usbAvailable: !!c.usbAvailable,
      oscpu: this._validateString(c.oscpu, 64),
      product: this._validateString(c.product, 64),
      productSub: this._validateString(c.productSub, 32),
      vendor: this._validateString(c.vendor, 64),
      vendorSub: this._validateString(c.vendorSub, 32),
      buildID: this._validateString(c.buildID, 32),
      devicePixelRatio: this._validateFloat(c.devicePixelRatio, 0.25, 5),
      innerWidth: this._validateInt(c.innerWidth, 320, 16384),
      innerHeight: this._validateInt(c.innerHeight, 240, 8640),
      outerWidth: this._validateInt(c.outerWidth, 320, 16384),
      outerHeight: this._validateInt(c.outerHeight, 240, 8640),
      deviceClass: this._classifyDevice(c)
    };
  }

  /**
   * Validate and sanitize a string value.
   * @param {*} value - Input value
   * @param {number} maxLength - Maximum length
   * @returns {string} Sanitized string
   * @private
   */
  _validateString(value, maxLength) {
    if (typeof value !== 'string') return '';
    return value.slice(0, maxLength).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '');
  }

  /**
   * Validate and sanitize an integer.
   * @param {*} value - Input value
   * @param {number} min - Minimum
   * @param {number} max - Maximum
   * @returns {number} Sanitized integer
   * @private
   */
  _validateInt(value, min, max) {
    const num = Number(value);
    if (!Number.isFinite(num) || !Number.isInteger(num)) return min;
    return Math.max(min, Math.min(max, num));
  }

  /**
   * Validate and sanitize a float.
   * @param {*} value - Input value
   * @param {number} min - Minimum
   * @param {number} max - Maximum
   * @returns {number} Sanitized float
   * @private
   */
  _validateFloat(value, min, max) {
    const num = Number(value);
    if (!Number.isFinite(num)) return min;
    return Math.max(min, Math.min(max, num));
  }

  /**
   * Classify device type from data.
   * @param {Object} data - Client data
   * @returns {string} Device class
   * @private
   */
  _classifyDevice(data) {
    const ua = (data.userAgent || '').toLowerCase();
    const w = data.screenWidth || 0;
    const touch = data.maxTouchPoints > 0;

    if (ua.includes('bot') || ua.includes('crawler')) return 'bot';
    if (ua.includes('mobile') && touch && w < 1024) return 'mobile';
    if ((ua.includes('tablet') || ua.includes('ipad')) && touch) return 'tablet';
    if (ua.includes('tv') || ua.includes('smarttv')) return 'tv';
    if (ua.includes('vr') || ua.includes('oculus')) return 'vr';
    if (w >= 2560) return 'desktop-hi-res';
    return 'desktop';
  }

  /**
   * Compute composite SHA-512 hash of all fingerprint components.
   * @param {Object} components - Fingerprint components
   * @returns {string} Composite hash
   * @private
   */
  _computeHash(components) {
    const parts = [
      components.canvasHash,
      components.webglRenderer,
      components.webglVendor,
      components.webglHash,
      components.fontHash,
      `${components.screenWidth}x${components.screenHeight}`,
      String(components.colorDepth),
      String(components.pixelRatio),
      components.platform,
      components.language,
      String(components.hardwareConcurrency),
      String(components.deviceMemory),
      components.timezone,
      String(components.timezoneOffset),
      String(components.maxTouchPoints),
      components.pluginsHash,
      String(components.audioFingerprint),
      String(components.batteryLevel),
      components.vendor
    ];
    return sha512(parts.join('|'));
  }

  /**
   * Compute stability score (how consistent the fingerprint is).
   * @param {Object} components - Fingerprint components
   * @returns {number} Stability score 0-1
   * @private
   */
  _computeStabilityScore(components) {
    let score = 1.0;

    // Canvas hash blank = less stable
    if (!components.canvasHash || components.canvasHash === 'blank') score -= 0.15;

    // Missing WebGL info = less stable
    if (!components.webglRenderer || !components.webglVendor) score -= 0.1;

    // No fonts detected = less stable
    if (components.fonts.length < 10) score -= 0.1;

    // Missing timezone = less stable
    if (!components.timezone) score -= 0.1;

    // Suspicious device memory values
    if ([0.25, 0.5].includes(components.deviceMemory)) score -= 0.1;

    // Single core = less stable (VM or very old device)
    if (components.hardwareConcurrency === 1) score -= 0.05;

    // Missing audio fingerprint = less stable
    if (components.audioFingerprint === 0) score -= 0.1;

    // Missing battery info (not critical, but reduces stability)
    if (components.batteryLevel === null) score -= 0.05;

    // Missing plugin info
    if (components.plugins.length === 0) score -= 0.05;

    return Math.max(0, score);
  }

  /**
   * Detect anomalies in fingerprint components.
   * @param {Object} components - Fingerprint components
   * @returns {string[]} List of anomaly descriptions
   * @private
   */
  _detectAnomalies(components) {
    const anomalies = [];

    if (isImpossibleCombination(components)) {
      anomalies.push('Impossible device/browser combination');
    }

    if (!components.canvasHash || components.canvasHash === 'blank') {
      anomalies.push('Blank canvas hash (headless browser indicator)');
    }

    if (components.audioFingerprint === 0) {
      anomalies.push('Zero audio fingerprint (automation indicator)');
    }

    if (components.webglRenderer?.toLowerCase().includes('swiftshader')) {
      anomalies.push('SwiftShader renderer (headless Chrome)');
    }

    if (components.webglRenderer?.toLowerCase().includes('llvmpipe')) {
      anomalies.push('LLVMpipe renderer (virtual machine)');
    }

    if (components.plugins.length === 0 && components.userAgent?.includes('Chrome')) {
      anomalies.push('No plugins in Chrome (automation indicator)');
    }

    if (components.maxTouchPoints > 10) {
      anomalies.push('Excessive touch points');
    }

    if (components.deviceMemory === 0.25 || components.deviceMemory === 0.5) {
      anomalies.push('Suspicious device memory (VM indicator)');
    }

    if (components.hardwareConcurrency > 128) {
      anomalies.push('Implausible core count');
    }

    if (Math.abs(components.timezoneOffset) > 720) {
      anomalies.push('Implausible timezone offset');
    }

    if (!components.timezone && components.language) {
      anomalies.push('Missing timezone with language present');
    }

    if (components.screenWidth > components.screenAvailWidth * 2) {
      anomalies.push('Screen width > 2x avail width');
    }

    return anomalies;
  }

  /**
   * Generate a fingerprint token (HMAC-signed base64 token).
   * @param {Object} fingerprint - Fingerprint record
   * @param {string} [sessionId] - Optional session ID to bind
   * @returns {string} Base64 fingerprint token
   */
  generateToken(fingerprint, sessionId = '') {
    const payload = {
      h: fingerprint.hash,
      t: Date.now(),
      s: sessionId,
      v: '5'
    };
    const json = JSON.stringify(payload);
    const signature = hmac256(this.secretKey, json);
    const token = Buffer.from(`${json}.${signature}`).toString('base64url');
    return token;
  }

  /**
   * Verify a fingerprint token.
   * @param {string} token - Base64 fingerprint token
   * @returns {{valid: boolean, payload: Object|null, error: string|null}}
   */
  verifyToken(token) {
    try {
      const decoded = Buffer.from(token, 'base64url').toString('utf8');
      const lastDot = decoded.lastIndexOf('.');
      if (lastDot === -1) {
        return { valid: false, payload: null, error: 'Invalid token format' };
      }
      const json = decoded.slice(0, lastDot);
      const signature = decoded.slice(lastDot + 1);
      const expected = hmac256(this.secretKey, json);

      if (!secureCompare(signature, expected)) {
        return { valid: false, payload: null, error: 'Invalid signature' };
      }

      const payload = JSON.parse(json);
      const age = Date.now() - payload.t;
      if (age > 86400000) {
        return { valid: false, payload, error: 'Token expired' };
      }

      return { valid: true, payload, error: null };
    } catch (err) {
      return { valid: false, payload: null, error: err.message };
    }
  }

  /**
   * Bind a fingerprint to a session.
   * @param {string} fingerprintHash - Fingerprint hash
   * @param {string} sessionId - Session ID
   * @returns {Object} Binding record
   */
  bindToSession(fingerprintHash, sessionId) {
    const binding = {
      fingerprintHash,
      sessionId,
      boundAt: new Date().toISOString(),
      token: this.generateToken({ hash: fingerprintHash }, sessionId)
    };

    if (this.db) {
      this._persistBinding(binding).catch(() => {});
    }

    this.cache.set(sessionId, { fingerprintHash, boundAt: binding.boundAt });
    return binding;
  }

  /**
   * Bind a fingerprint to an auth token.
   * @param {string} fingerprintHash - Fingerprint hash
   * @param {string} token - Auth token
   * @returns {Object} Binding record
   */
  bindToToken(fingerprintHash, token) {
    const binding = {
      fingerprintHash,
      tokenHash: sha256(token),
      boundAt: new Date().toISOString()
    };

    if (this.db) {
      this._persistTokenBinding(binding).catch(() => {});
    }

    return binding;
  }

  /**
   * Check if fingerprint changed mid-session.
   * @param {string} currentHash - Current fingerprint hash
   * @param {string} sessionId - Session ID
   * @returns {{changed: boolean, previous: string|null, confidence: number}}
   */
  async detectChange(currentHash, sessionId) {
    const cached = this.cache.get(sessionId);
    let previous = cached?.fingerprintHash || null;

    if (!previous && this.db) {
      previous = await this._getStoredFingerprint(sessionId);
    }

    if (!previous) {
      return { changed: false, previous: null, confidence: 0 };
    }

    const changed = !secureCompare(currentHash, previous);
    let confidence = 0;

    if (changed) {
      // Simple hamming-distance-like comparison
      let diff = 0;
      const maxLen = Math.max(currentHash.length, previous.length);
      for (let i = 0; i < maxLen; i++) {
        if (currentHash[i] !== previous[i]) diff++;
      }
      confidence = Math.round((diff / maxLen) * 100);
    }

    return { changed, previous, confidence };
  }

  /**
   * Get fingerprint stability rating as human-readable string.
   * @param {number} stability - Stability score 0-1
   * @returns {string}
   */
  getStabilityRating(stability) {
    if (stability >= 0.95) return 'excellent';
    if (stability >= 0.8) return 'good';
    if (stability >= 0.6) return 'moderate';
    if (stability >= 0.4) return 'poor';
    return 'unstable';
  }

  /**
   * Get bot verdict as human-readable string.
   * @param {number} confidence - Bot confidence 0-100
   * @returns {string}
   */
  getBotVerdict(confidence) {
    if (confidence >= 90) return 'confirmed_bot';
    if (confidence >= 70) return 'likely_bot';
    if (confidence >= 40) return 'suspicious';
    if (confidence >= 20) return 'low_risk';
    return 'human';
  }

  /**
   * Persist binding to database.
   * @param {Object} binding - Binding record
   * @private
   */
  async _persistBinding(binding) {
    if (!this.db) return;
    try {
      await this.db.collection('fingerprint_bindings').updateOne(
        { sessionId: binding.sessionId },
        { $set: binding },
        { upsert: true }
      );
    } catch (err) {
      console.error('Fingerprint binding persist failed:', err.message);
    }
  }

  /**
   * Persist token binding to database.
   * @param {Object} binding - Token binding record
   * @private
   */
  async _persistTokenBinding(binding) {
    if (!this.db) return;
    try {
      await this.db.collection('fingerprint_token_bindings').insertOne(binding);
    } catch (err) {
      console.error('Token binding persist failed:', err.message);
    }
  }

  /**
   * Get stored fingerprint for a session.
   * @param {string} sessionId - Session ID
   * @returns {Promise<string|null>}
   * @private
   */
  async _getStoredFingerprint(sessionId) {
    if (!this.db) return null;
    try {
      const doc = await this.db.collection('fingerprint_bindings').findOne(
        { sessionId },
        { projection: { fingerprintHash: 1 } }
      );
      return doc?.fingerprintHash || null;
    } catch {
      return null;
    }
  }

  /**
   * Calculate the font hash on the server side (for client-reported fonts).
   * @param {string[]} fonts - Detected font list
   * @returns {string} Font hash
   */
  computeFontHash(fonts) {
    return computeFontHash(fonts);
  }

  /**
   * Check if a user agent matches a known automation signature.
   * @param {string} userAgent - User-Agent string
   * @returns {{isAutomation: boolean, framework: string|null}}
   */
  checkAutomationUA(userAgent) {
    const ua = (userAgent || '').toLowerCase();
    for (const [framework, signatures] of Object.entries(AUTOMATION_FINGERPRINTS)) {
      if (signatures.some(s => ua.includes(s.toLowerCase()))) {
        return { isAutomation: true, framework };
      }
    }
    return { isAutomation: false, framework: null };
  }

  /**
   * Get the known automation fingerprints database.
   * @returns {Object}
   */
  getAutomationDatabase() {
    return { ...AUTOMATION_FINGERPRINTS };
  }

  /**
   * Get system fonts list.
   * @returns {string[]}
   */
  getSystemFontsList() {
    return [...SYSTEM_FONTS];
  }

  /**
   * Generate a complete fingerprint report.
   * @param {Object} fingerprint - Fingerprint record
   * @returns {Object} Human-readable report
   */
  generateReport(fingerprint) {
    return {
      id: fingerprint.id,
      hash: fingerprint.hashShort,
      deviceClass: fingerprint.components.deviceClass,
      stability: {
        score: fingerprint.stability,
        rating: this.getStabilityRating(fingerprint.stability)
      },
      anomalies: {
        count: fingerprint.anomalyCount,
        list: fingerprint.anomalies
      },
      automation: {
        detected: fingerprint.automationDetected,
        matches: fingerprint.automationMatches
      },
      vm: {
        detected: fingerprint.vmDetected,
        confidence: fingerprint.vmConfidence,
        indicators: fingerprint.vmIndicators
      },
      bot: {
        isBot: fingerprint.isBot,
        confidence: fingerprint.botConfidence,
        verdict: this.getBotVerdict(fingerprint.botConfidence)
      },
      browser: {
        userAgent: fingerprint.components.userAgent.slice(0, 100),
        platform: fingerprint.components.platform,
        language: fingerprint.components.language,
        timezone: fingerprint.components.timezone
      },
      display: {
        screen: `${fingerprint.components.screenWidth}x${fingerprint.components.screenHeight}`,
        colorDepth: fingerprint.components.colorDepth,
        pixelRatio: fingerprint.components.pixelRatio
      },
      hardware: {
        cores: fingerprint.components.hardwareConcurrency,
        memory: `${fingerprint.components.deviceMemory}GB`,
        touchPoints: fingerprint.components.maxTouchPoints
      },
      createdAt: fingerprint.createdAt
    };
  }
}

// ============================================================================
// FingerprintVerifier Class
// ============================================================================

/**
 * Verifies fingerprint tokens and manages fingerprint validation.
 *
 * @class
 */
export class FingerprintVerifier {
  /**
   * @param {Object} [options] - Configuration
   * @param {string} [options.secretKey] - Secret key for HMAC verification
   * @param {Object} [options.db] - Database connection
   */
  constructor(options = {}) {
    this.secretKey = options.secretKey || process.env.FORTRESS_FINGERPRINT_SECRET || '';
    this.db = options.db || null;
    this.allowedDrift = options.allowedDrift || 0.3; // 30% component change allowed
  }

  /**
   * Verify that a new fingerprint matches a stored one within tolerance.
   * @param {string} newHash - New fingerprint hash
   * @param {string} storedHash - Stored fingerprint hash
   * @returns {{match: boolean, similarity: number}}
   */
  verifyMatch(newHash, storedHash) {
    if (!newHash || !storedHash) return { match: false, similarity: 0 };

    // Direct match
    if (secureCompare(newHash, storedHash)) {
      return { match: true, similarity: 1.0 };
    }

    // Hamming-distance-like similarity for SHA-512 hex strings
    let matching = 0;
    const minLen = Math.min(newHash.length, storedHash.length);
    for (let i = 0; i < minLen; i++) {
      if (newHash[i] === storedHash[i]) matching++;
    }
    const similarity = matching / Math.max(newHash.length, storedHash.length);

    return { match: similarity >= (1 - this.allowedDrift), similarity };
  }

  /**
   * Verify a fingerprint change and determine if it is suspicious.
   * @param {Object} oldFP - Old fingerprint
   * @param {Object} newFP - New fingerprint
   * @returns {{suspicious: boolean, changes: string[], severity: string}}
   */
  analyzeChange(oldFP, newFP) {
    const changes = [];
    let severityScore = 0;

    // Compare critical components
    if (oldFP.components.canvasHash !== newFP.components.canvasHash) {
      changes.push('Canvas hash changed');
      severityScore += 10;
    }
    if (oldFP.components.webglRenderer !== newFP.components.webglRenderer) {
      changes.push('WebGL renderer changed');
      severityScore += 15;
    }
    if (oldFP.components.webglVendor !== newFP.components.webglVendor) {
      changes.push('WebGL vendor changed');
      severityScore += 15;
    }
    if (oldFP.components.fontHash !== newFP.components.fontHash) {
      changes.push('Font list changed');
      severityScore += 5;
    }
    if (oldFP.components.hardwareConcurrency !== newFP.components.hardwareConcurrency) {
      changes.push('Core count changed');
      severityScore += 20;
    }
    if (oldFP.components.deviceMemory !== newFP.components.deviceMemory) {
      changes.push('Memory changed');
      severityScore += 15;
    }
    if (oldFP.components.platform !== newFP.components.platform) {
      changes.push('Platform changed');
      severityScore += 25;
    }
    if (oldFP.components.screenWidth !== newFP.components.screenWidth ||
        oldFP.components.screenHeight !== newFP.components.screenHeight) {
      changes.push('Screen size changed');
      severityScore += 10;
    }
    if (oldFP.components.userAgent !== newFP.components.userAgent) {
      changes.push('User-Agent changed');
      severityScore += 20;
    }
    if (oldFP.components.language !== newFP.components.language) {
      changes.push('Language changed');
      severityScore += 5;
    }
    if (oldFP.components.timezone !== newFP.components.timezone) {
      changes.push('Timezone changed');
      severityScore += 15;
    }

    let severity = 'low';
    if (severityScore >= 80) severity = 'critical';
    else if (severityScore >= 50) severity = 'high';
    else if (severityScore >= 25) severity = 'medium';

    return {
      suspicious: severityScore >= 30,
      changes,
      severity,
      severityScore
    };
  }

  /**
   * Check if the environment is a known automation framework.
   * @param {Object} fingerprint - Fingerprint record
   * @returns {{isAutomated: boolean, framework: string|null, confidence: number}}
   */
  checkAutomation(fingerprint) {
    const auto = fingerprint.automationMatches || { total: 0, frameworks: {} };
    const isAutomated = auto.total > 0 || fingerprint.automationDetected;

    let framework = null;
    let maxMatches = 0;
    for (const [fw, count] of Object.entries(auto.frameworks || {})) {
      if (count > maxMatches) {
        maxMatches = count;
        framework = fw;
      }
    }

    return {
      isAutomated,
      framework,
      confidence: fingerprint.botConfidence || 0
    };
  }
}

// ============================================================================
// Export Constants and Utilities
// ============================================================================

export { SYSTEM_FONTS, AUTOMATION_FINGERPRINTS, VM_SIGNATURES };
export { sha512, sha256, hmac256, secureId, secureCompare };

/**
 * Quick utility: create a collector with default settings.
 * @returns {FingerprintCollector}
 */
export function createCollector() {
  return new FingerprintCollector();
}

/**
 * Quick utility: create a verifier with default settings.
 * @returns {FingerprintVerifier}
 */
export function createVerifier() {
  return new FingerprintVerifier();
}
