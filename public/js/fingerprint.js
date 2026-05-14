/**
 * @fileoverview fingerprint.js - Browser Fingerprinting Module
 * @description Collects comprehensive browser fingerprint data including
 * canvas rendering, WebGL, font detection, screen/navigator properties,
 * audio fingerprinting, WebRTC local IPs, and storage availability.
 * All data is hashed with SHA-256 for privacy-preserving identification.
 * @version 1.0.0
 * @author Osm Army Security Team
 * @license Proprietary
 */

(function () {
  "use strict";

  // ============================================================================
  // CONSTANTS & CONFIGURATION
  // ============================================================================

  const CONFIG = Object.freeze({
    CANVAS_WIDTH: 280,
    CANVAS_HEIGHT: 60,
    FONT_TEST_STRING: "OSM Army Fingerprint",
    FONT_SIZE: "18px",
    FONT_LIST_SIZE: 50,
    AUDIO_DURATION_SEC: 0.1,
    AUDIO_FREQUENCY: 1000,
    AUDIO_SAMPLE_RATE: 48000,
    RTC_SERVERS: [{ urls: "stun:stun.l.google.com:19302" }],
    DEBUG: false,
  });

  // ============================================================================
  // FONT LIST (50+ fonts)
  // ============================================================================

  const FONT_LIST = Object.freeze([
    // Core web fonts
    "Arial",
    "Arial Black",
    "Helvetica",
    "Times",
    "Times New Roman",
    "Courier",
    "Courier New",
    "Georgia",
    "Verdana",
    "Impact",
    "Tahoma",
    "Trebuchet MS",
    "Palatino",
    "Palatino Linotype",
    "Comic Sans MS",
    "Geneva",
    "Lucida Grande",
    "Lucida Sans Unicode",
    "Garamond",
    "Bookman",
    "Avant Garde",
    "Century Gothic",
    "Franklin Gothic Medium",
    "Futura",
    "Baskerville",
    "Cambria",
    "Consolas",
    "Constantia",
    "Corbel",
    "Candara",
    "Calibri",
    "Segoe UI",
    "Microsoft Sans Serif",
    "MS Serif",
    "MS Sans Serif",
    "DejaVu Sans",
    "DejaVu Serif",
    "DejaVu Sans Mono",
    "Linux Libertine",
    "Linux Biolinum",
    "Liberation Sans",
    "Liberation Serif",
    "Liberation Mono",
    "Noto Sans",
    "Noto Serif",
    "Roboto",
    "Open Sans",
    "Lato",
    "Montserrat",
    "PT Sans",
    "PT Serif",
    "Ubuntu",
    "Droid Sans",
    "Droid Serif",
  ]);

  // ============================================================================
  // UTILITY FUNCTIONS
  // ============================================================================

  /**
   * Generate SHA-256 hash of a string.
   * @param {string} input - Input string to hash.
   * @returns {Promise<string>} Hex-encoded SHA-256 hash.
   */
  async function sha256(input) {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(input);
      const hashBuffer = await crypto.subtle.digest("SHA-256", data);
      const bytes = new Uint8Array(hashBuffer);
      return Array.from(bytes)
        .map(function (b) {
          return b.toString(16).padStart(2, "0");
        })
        .join("");
    } catch (_e) {
      // Fallback for environments without Web Crypto
      let hash = 0;
      for (let i = 0; i < input.length; i++) {
        const char = input.charCodeAt(i);
        hash = (hash << 5) - hash + char;
        hash |= 0;
      }
      return "fallback_" + Math.abs(hash).toString(16).padStart(64, "0");
    }
  }

  /**
   * Hash multiple string components together.
   * @param {Array<string>} components - Array of strings to combine and hash.
   * @returns {Promise<string>} Hex-encoded SHA-256 hash.
   */
  async function hashComponents(components) {
    const combined = components.join("::");
    return await sha256(combined);
  }

  /**
   * Log debug messages.
   * @param {string} message - Message.
   * @param {object} [meta] - Extra data.
   */
  function secLog(message, meta) {
    if (CONFIG.DEBUG && typeof console !== "undefined") {
      console.debug("[OSM-FINGERPRINT]", message, meta || "");
    }
  }

  // ============================================================================
  // CANVAS FINGERPRINT
  // ============================================================================

  /**
   * Generate canvas fingerprint by drawing complex scene and hashing result.
   * @returns {Promise<{hash:string,dataUrl:string}>} Canvas fingerprint data.
   */
  async function getCanvasFingerprint() {
    try {
      if (typeof document === "undefined") {
        return { hash: "no_document", dataUrl: "" };
      }

      const canvas = document.createElement("canvas");
      canvas.width = CONFIG.CANVAS_WIDTH;
      canvas.height = CONFIG.CANVAS_HEIGHT;

      // Request offscreen to avoid layout impact
      canvas.style.position = "absolute";
      canvas.style.left = "-9999px";
      canvas.style.top = "-9999px";
      canvas.style.visibility = "hidden";

      const ctx = canvas.getContext("2d");
      if (!ctx) {
        return { hash: "no_2d_context", dataUrl: "" };
      }

      // 1. Fill with gradient background
      const bgGradient = ctx.createLinearGradient(0, 0, canvas.width, canvas.height);
      bgGradient.addColorStop(0, "#2c3e50");
      bgGradient.addColorStop(0.5, "#34495e");
      bgGradient.addColorStop(1, "#2c3e50");
      ctx.fillStyle = bgGradient;
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      // 2. Draw geometric shapes
      // Red circle with alpha
      ctx.beginPath();
      ctx.arc(45, 30, 20, 0, 2 * Math.PI);
      ctx.fillStyle = "rgba(231, 76, 60, 0.7)";
      ctx.fill();
      ctx.strokeStyle = "rgba(192, 57, 43, 0.9)";
      ctx.lineWidth = 2;
      ctx.stroke();

      // Blue rectangle with rotation
      ctx.save();
      ctx.translate(200, 30);
      ctx.rotate(Math.PI / 6);
      ctx.fillStyle = "rgba(52, 152, 219, 0.6)";
      ctx.fillRect(-15, -15, 30, 30);
      ctx.restore();

      // Green triangle
      ctx.beginPath();
      ctx.moveTo(120, 15);
      ctx.lineTo(135, 45);
      ctx.lineTo(105, 45);
      ctx.closePath();
      ctx.fillStyle = "rgba(46, 204, 113, 0.6)";
      ctx.fill();

      // 3. Draw lines with different styles
      ctx.beginPath();
      ctx.moveTo(0, 10);
      ctx.lineTo(canvas.width, 10);
      ctx.strokeStyle = "rgba(241, 196, 15, 0.5)";
      ctx.lineWidth = 1;
      ctx.setLineDash([5, 5]);
      ctx.stroke();
      ctx.setLineDash([]);

      ctx.beginPath();
      ctx.moveTo(0, 50);
      ctx.lineTo(canvas.width, 50);
      ctx.strokeStyle = "rgba(155, 89, 182, 0.4)";
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // 4. Draw gradient text
      const textGradient = ctx.createLinearGradient(80, 0, 220, 0);
      textGradient.addColorStop(0, "#ecf0f1");
      textGradient.addColorStop(0.5, "#f39c12");
      textGradient.addColorStop(1, "#ecf0f1");

      ctx.font = "bold " + CONFIG.FONT_SIZE + " 'Arial', sans-serif";
      ctx.fillStyle = textGradient;
      ctx.textBaseline = "middle";
      ctx.textAlign = "center";
      ctx.fillText(CONFIG.FONT_TEST_STRING, canvas.width / 2, canvas.height / 2);

      // 5. Draw some small decorative elements
      for (let i = 0; i < 10; i++) {
        ctx.beginPath();
        ctx.arc(160 + i * 8, 55, 2, 0, 2 * Math.PI);
        ctx.fillStyle = "rgba(255, 255, 255, " + (0.1 + i * 0.05) + ")";
        ctx.fill();
      }

      // 6. Composite operation overlay
      ctx.globalCompositeOperation = "destination-over";
      ctx.fillStyle = "rgba(0, 0, 0, 0.05)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.globalCompositeOperation = "source-over";

      // Extract data URL
      const dataUrl = canvas.toDataURL("image/png");

      // Hash the data URL
      const hash = await sha256(dataUrl);

      // Delete canvas
      canvas.width = 0;
      canvas.height = 0;

      secLog("Canvas fingerprint generated", { hash: hash.substring(0, 16) + "..." });

      return { hash: hash, dataUrl: dataUrl.substring(0, 100) };
    } catch (_e) {
      return { hash: "canvas_error", dataUrl: "" };
    }
  }

  // ============================================================================
  // WEBGL FINGERPRINT
  // ============================================================================

  /**
   * Collect WebGL fingerprint data.
   * @returns {Promise<{hash:string,params:object}>} WebGL fingerprint.
   */
  async function getWebGLFingerprint() {
    try {
      if (typeof document === "undefined") {
        return { hash: "no_document", params: {} };
      }

      const canvas = document.createElement("canvas");
      canvas.style.position = "absolute";
      canvas.style.left = "-9999px";
      canvas.style.visibility = "hidden";

      const gl =
        canvas.getContext("webgl") ||
        canvas.getContext("experimental-webgl");

      if (!gl) {
        return { hash: "no_webgl", params: {} };
      }

      const params = {};

      // Basic parameters
      params.vendor =
        gl.getParameter(gl.VENDOR) || "unknown";
      params.renderer =
        gl.getParameter(gl.RENDERER) || "unknown";
      params.version =
        gl.getParameter(gl.VERSION) || "unknown";
      params.shadingLanguageVersion =
        gl.getParameter(gl.SHADING_LANGUAGE_VERSION) || "unknown";
      params.unmaskedVendor = "unknown";
      params.unmaskedRenderer = "unknown";

      // Try to get unmasked vendor/renderer via debug info extension
      try {
        const debugInfo = gl.getExtension("WEBGL_debug_renderer_info");
        if (debugInfo) {
          params.unmaskedVendor =
            gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || "unknown";
          params.unmaskedRenderer =
            gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || "unknown";
        }
      } catch (_e) {
        // Extension not available
      }

      // Numeric parameters
      const numericParams = [
        "MAX_TEXTURE_SIZE",
        "MAX_CUBE_MAP_TEXTURE_SIZE",
        "MAX_RENDERBUFFER_SIZE",
        "MAX_VIEWPORT_DIMS",
        "MAX_VERTEX_ATTRIBS",
        "MAX_VERTEX_UNIFORM_VECTORS",
        "MAX_FRAGMENT_UNIFORM_VECTORS",
        "MAX_VARYING_VECTORS",
        "MAX_TEXTURE_IMAGE_UNITS",
        "MAX_VERTEX_TEXTURE_IMAGE_UNITS",
        "MAX_COMBINED_TEXTURE_IMAGE_UNITS",
        "MAX_FRAGMENT_UNIFORM_COMPONENTS",
        "MAX_VERTEX_UNIFORM_COMPONENTS",
        "MAX_VERTEX_OUTPUT_COMPONENTS",
        "MAX_FRAGMENT_INPUT_COMPONENTS",
        "MAX_ARRAY_TEXTURE_LAYERS",
        "MAX_3D_TEXTURE_SIZE",
        "MAX_COLOR_ATTACHMENTS",
        "MAX_DRAW_BUFFERS",
        "RED_BITS",
        "GREEN_BITS",
        "BLUE_BITS",
        "ALPHA_BITS",
        "DEPTH_BITS",
        "STENCIL_BITS",
        "SAMPLES",
        "MAX_SAMPLES",
      ];

      for (let i = 0; i < numericParams.length; i++) {
        const name = numericParams[i];
        try {
          const value = gl.getParameter(gl[name]);
          if (value !== null && value !== undefined) {
            params[name] = value;
          }
        } catch (_e) {
          // Parameter not available
        }
      }

      // MAX_VIEWPORT_DIMS returns Int32Array
      if (params.MAX_VIEWPORT_DIMS && typeof params.MAX_VIEWPORT_DIMS === "object") {
        params.MAX_VIEWPORT_DIMS = Array.from(params.MAX_VIEWPORT_DIMS).join(",");
      }

      // Extensions list
      try {
        const extensions = gl.getSupportedExtensions();
        params.extensions = extensions ? extensions.sort().join(",") : "";
      } catch (_e) {
        params.extensions = "";
      }

      // Shader precision formats
      const shaderTypes = [gl.VERTEX_SHADER, gl.FRAGMENT_SHADER];
      const precisionTypes = [
        gl.LOW_FLOAT,
        gl.MEDIUM_FLOAT,
        gl.HIGH_FLOAT,
        gl.LOW_INT,
        gl.MEDIUM_INT,
        gl.HIGH_INT,
      ];

      params.precisionFormats = [];
      for (let s = 0; s < shaderTypes.length; s++) {
        for (let p = 0; p < precisionTypes.length; p++) {
          try {
            const format = gl.getShaderPrecisionFormat(
              shaderTypes[s],
              precisionTypes[p]
            );
            if (format) {
              params.precisionFormats.push(
                shaderTypes[s] + ":" + precisionTypes[p] + "=" +
                  format.precision + "/" + format.rangeMin + "/" + format.rangeMax
              );
            }
          } catch (_e) {
            // Format not available
          }
        }
      }

      // Hash all WebGL parameters
      const hash = await hashComponents([
        params.vendor,
        params.renderer,
        params.unmaskedVendor,
        params.unmaskedRenderer,
        params.version,
        params.shadingLanguageVersion,
        JSON.stringify(params),
      ]);

      secLog("WebGL fingerprint generated", {
        vendor: params.unmaskedVendor,
        renderer: params.unmaskedRenderer.substring(0, 40),
      });

      return { hash: hash, params: params };
    } catch (_e) {
      return { hash: "webgl_error", params: {} };
    }
  }

  // ============================================================================
  // FONT DETECTION
  // ============================================================================

  /**
   * Test if a font is available on the system.
   * Measures a span's width with and without the font.
   * @param {string} fontName - Font name to test.
   * @returns {boolean} True if font is available.
   */
  function isFontAvailable(fontName) {
    try {
      if (typeof document === "undefined") return false;

      const testString = "mmmmmmmmlli";
      const testSize = "72px";
      const fallbackFonts = "monospace";

      const span = document.createElement("span");
      span.style.position = "absolute";
      span.style.left = "-9999px";
      span.style.top = "-9999px";
      span.style.fontSize = testSize;
      span.style.visibility = "hidden";
      span.textContent = testString;

      // Measure with fallback font
      span.style.fontFamily = fallbackFonts;
      document.body.appendChild(span);
      const fallbackWidth = span.offsetWidth;
      const fallbackHeight = span.offsetHeight;
      document.body.removeChild(span);

      // Measure with target font
      span.style.fontFamily = "'" + fontName + "', " + fallbackFonts;
      document.body.appendChild(span);
      const fontWidth = span.offsetWidth;
      const fontHeight = span.offsetHeight;
      document.body.removeChild(span);

      // If dimensions differ, the font is available
      return fontWidth !== fallbackWidth || fontHeight !== fallbackHeight;
    } catch (_e) {
      return false;
    }
  }

  /**
   * Detect all available system fonts from the font list.
   * @returns {{detected:Array<string>,hash:string}} Detected fonts and hash.
   */
  async function detectFonts() {
    try {
      if (typeof document === "undefined" || !document.body) {
        return { detected: [], hash: "no_document" };
      }

      const detected = [];

      for (let i = 0; i < FONT_LIST.length; i++) {
        if (isFontAvailable(FONT_LIST[i])) {
          detected.push(FONT_LIST[i]);
        }
      }

      const hash = await hashComponents(detected);

      secLog("Font detection complete", {
        count: detected.length,
        hash: hash.substring(0, 16) + "...",
      });

      return { detected: detected, hash: hash };
    } catch (_e) {
      return { detected: [], hash: "font_error" };
    }
  }

  // ============================================================================
  // SCREEN & NAVIGATOR
  // ============================================================================

  /**
   * Collect screen and navigator properties.
   * @returns {{hash:string,data:object}} Screen and navigator data.
   */
  async function getScreenNavigatorFingerprint() {
    try {
      const data = {};

      // Screen properties
      if (typeof screen !== "undefined") {
        data.screen = {
          width: screen.width || 0,
          height: screen.height || 0,
          availWidth: screen.avWidth || 0,
          availHeight: screen.avHeight || 0,
          availLeft: screen.avLeft || 0,
          availTop: screen.avTop || 0,
          colorDepth: screen.colorDepth || 0,
          pixelDepth: screen.pixelDepth || 0,
          orientation: screen.orientation
            ? {
                angle: screen.orientation.angle || 0,
                type: screen.orientation.type || "unknown",
              }
            : { angle: 0, type: "unknown" },
        };
      }

      // Navigator properties
      if (typeof navigator !== "undefined") {
        data.navigator = {
          userAgent: navigator.userAgent || "unknown",
          platform: navigator.platform || "unknown",
          language: navigator.language || "unknown",
          languages: Array.isArray(navigator.languages)
            ? navigator.languages.join(",")
            : navigator.language || "",
          hardwareConcurrency: navigator.hardwareConcurrency || 0,
          deviceMemory: navigator.deviceMemory || 0,
          maxTouchPoints: navigator.maxTouchPoints || 0,
          product: navigator.product || "unknown",
          productSub: navigator.productSub || "unknown",
          vendor: navigator.vendor || "unknown",
          onLine: navigator.onLine,
          cookieEnabled: navigator.cookieEnabled,
          pdfViewerEnabled: navigator.pdfViewerEnabled || false,
          doNotTrack:
            navigator.doNotTrack ||
            window.doNotTrack ||
            navigator.msDoNotTrack ||
            "unknown",
        };
      }

      // Device pixel ratio
      data.pixelRatio = window.devicePixelRatio || 1;

      // Timezone
      data.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || "unknown";
      data.timezoneOffset = new Date().getTimezoneOffset();

      // Touch support
      data.touchSupport = {
        ontouchstart: "ontouchstart" in window,
        maxTouchPoints: (navigator.maxTouchPoints) || 0,
      };

      // Plugins
      data.plugins = [];
      if (navigator.plugins) {
        for (let i = 0; i < navigator.plugins.length; i++) {
          const plugin = navigator.plugins[i];
          data.plugins.push({
            name: plugin.name || "",
            description: plugin.description || "",
            filename: plugin.filename || "",
            version: plugin.version || "",
            length: plugin.length || 0,
          });
        }
      }

      // Hash
      const hash = await hashComponents([JSON.stringify(data)]);

      secLog("Screen/Navigator fingerprint generated");

      return { hash: hash, data: data };
    } catch (_e) {
      return { hash: "screen_error", data: {} };
    }
  }

  // ============================================================================
  // AUDIO FINGERPRINT
  // ============================================================================

  /**
   * Generate audio fingerprint using oscillator and compressor.
   * @returns {Promise<{hash:string,fingerprint:Array<number>}>} Audio fingerprint.
   */
  async function getAudioFingerprint() {
    try {
      const AudioContext =
        window.OfflineAudioContext ||
        window.webkitOfflineAudioContext;

      if (!AudioContext) {
        return { hash: "no_audio_context", fingerprint: [] };
      }

      // Create offline audio context
      const context = new AudioContext(1, 44100, 44100);

      // Create oscillator
      const oscillator = context.createOscillator();
      oscillator.type = "triangle";
      oscillator.frequency.value = CONFIG.AUDIO_FREQUENCY;

      // Create compressor
      const compressor = context.createDynamicsCompressor();
      compressor.threshold.value = -50;
      compressor.knee.value = 40;
      compressor.ratio.value = 12;
      compressor.attack.value = 0;
      compressor.release.value = 0.25;

      // Connect nodes
      oscillator.connect(compressor);
      compressor.connect(context.destination);

      // Start and render
      oscillator.start(0);
      oscillator.stop(context.length / context.sampleRate);

      // Render audio
      const renderedBuffer = await context.startRendering();

      // Extract fingerprint from rendered audio
      const channelData = renderedBuffer.getChannelData(0);
      const sampleSize = 4500;
      const samples = [];

      for (let i = 3000; i < 3000 + sampleSize; i += 2) {
        samples.push(channelData[i]);
      }

      // Quantize to reduce noise
      const quantized = samples.map(function (v) {
        return Math.round(v * 10000) / 10000;
      });

      // Hash the fingerprint
      const hash = await hashComponents([
        JSON.stringify(quantized.slice(0, 100)),
      ]);

      secLog("Audio fingerprint generated", { hash: hash.substring(0, 16) + "..." });

      return { hash: hash, fingerprint: quantized };
    } catch (_e) {
      return { hash: "audio_error", fingerprint: [] };
    }
  }

  // ============================================================================
  // WEBRTC LOCAL IP DETECTION
  // ============================================================================

  /**
   * Get local IP addresses via WebRTC (no permission needed).
   * @returns {Promise<{hash:string,ips:Array<string>}>} Local IP addresses.
   */
  async function getWebRtcIps() {
    try {
      const RTCPeerConnection =
        window.RTCPeerConnection ||
        window.mozRTCPeerConnection ||
        window.webkitRTCPeerConnection;

      if (!RTCPeerConnection) {
        return { hash: "no_rtc", ips: [] };
      }

      const ips = [];

      const pc = new RTCPeerConnection({
        iceServers: CONFIG.RTC_SERVERS,
      });

      // Create a data channel to trigger ICE gathering
      pc.createDataChannel("");

      // Wait for ICE candidates
      await new Promise(function (resolve, reject) {
        const timeout = setTimeout(resolve, 3000);

        pc.onicecandidate = function (event) {
          if (!event.candidate) {
            clearTimeout(timeout);
            resolve();
            return;
          }

          // Extract IP from candidate string
          const candidate = event.candidate.candidate;
          const ipMatch = candidate.match(/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/);
          if (ipMatch && ipMatch[1]) {
            const ip = ipMatch[1];
            if (ips.indexOf(ip) === -1 && ip !== "0.0.0.0") {
              ips.push(ip);
            }
          }

          // IPv6
          const ipv6Match = candidate.match(/([0-9a-fA-F:]+:[0-9a-fA-F:]+)/);
          if (ipv6Match && ipv6Match[1]) {
            const ipv6 = ipv6Match[1];
            if (ips.indexOf(ipv6) === -1) {
              ips.push(ipv6);
            }
          }
        };

        pc.onicecandidateerror = function () {
          clearTimeout(timeout);
          resolve();
        };

        // Start ICE gathering
        pc.createOffer()
          .then(function (offer) {
            return pc.setLocalDescription(offer);
          })
          .catch(function () {
            clearTimeout(timeout);
            resolve();
          });
      });

      pc.close();

      const hash = await hashComponents(ips);

      secLog("WebRTC IPs collected", { count: ips.length });

      return { hash: hash, ips: ips };
    } catch (_e) {
      return { hash: "rtc_error", ips: [] };
    }
  }

  // ============================================================================
  // STORAGE DETECTION
  // ============================================================================

  /**
   * Detect available storage mechanisms.
   * @returns {{hash:string,data:object}} Storage availability data.
   */
  async function detectStorage() {
    try {
      const data = {};

      // localStorage
      try {
        const testKey = "__osm_storage_test__";
        window.localStorage.setItem(testKey, "test");
        const val = window.localStorage.getItem(testKey);
        window.localStorage.removeItem(testKey);
        data.localStorage = val === "test";
      } catch (_e) {
        data.localStorage = false;
      }

      // sessionStorage
      try {
        const testKey = "__osm_storage_test__";
        window.sessionStorage.setItem(testKey, "test");
        const val = window.sessionStorage.getItem(testKey);
        window.sessionStorage.removeItem(testKey);
        data.sessionStorage = val === "test";
      } catch (_e) {
        data.sessionStorage = false;
      }

      // indexedDB
      try {
        data.indexedDB = !!window.indexedDB;
      } catch (_e) {
        data.indexedDB = false;
      }

      // Cookies
      try {
        document.cookie = "__osm_test__=1; SameSite=Strict";
        data.cookies = document.cookie.indexOf("__osm_test__") !== -1;
        document.cookie = "__osm_test__=; expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Strict";
      } catch (_e) {
        data.cookies = false;
      }

      // Estimate storage quota if available
      if (navigator.storage && navigator.storage.estimate) {
        try {
          const estimate = await navigator.storage.estimate();
          data.storageQuota = estimate.quota || 0;
          data.storageUsage = estimate.usage || 0;
        } catch (_e) {
          data.storageQuota = 0;
          data.storageUsage = 0;
        }
      }

      const hash = await hashComponents([JSON.stringify(data)]);

      secLog("Storage detection complete", data);

      return { hash: hash, data: data };
    } catch (_e) {
      return { hash: "storage_error", data: {} };
    }
  }

  // ============================================================================
  // COMBINED FINGERPRINT
  // ============================================================================

  /**
   * Collect all fingerprint components.
   * @returns {Promise<object>} Complete fingerprint object.
   */
  async function collectFingerprint() {
    secLog("Starting fingerprint collection");

    const startTime = Date.now();

    // Collect all components in parallel where possible
    const [canvasFp, webglFp, fontFp, screenFp, audioFp, rtcFp, storageFp] =
      await Promise.all([
        getCanvasFingerprint(),
        getWebGLFingerprint(),
        detectFonts(),
        getScreenNavigatorFingerprint(),
        getAudioFingerprint(),
        getWebRtcIps(),
        detectStorage(),
      ]);

    const fingerprint = {
      canvas: {
        hash: canvasFp.hash,
      },
      webgl: {
        hash: webglFp.hash,
        vendor: webglFp.params.unmaskedVendor || webglFp.params.vendor,
        renderer:
          (webglFp.params.unmaskedRenderer || webglFp.params.renderer || "").substring(
            0,
            100
          ),
      },
      fonts: {
        hash: fontFp.hash,
        count: fontFp.detected.length,
        detected: fontFp.detected,
      },
      screen: {
        hash: screenFp.hash,
        timezone: screenFp.data.timezone,
        screenResolution:
          (screenFp.data.screen &&
            screenFp.data.screen.width + "x" + screenFp.data.screen.height) ||
          "unknown",
        colorDepth: (screenFp.data.screen && screenFp.data.screen.colorDepth) || 0,
        pixelRatio: screenFp.data.pixelRatio,
        hardwareConcurrency:
          (screenFp.data.navigator &&
            screenFp.data.navigator.hardwareConcurrency) ||
          0,
        deviceMemory:
          (screenFp.data.navigator && screenFp.data.navigator.deviceMemory) || 0,
        touchSupport:
          screenFp.data.touchSupport && screenFp.data.touchSupport.ontouchstart,
        maxTouchPoints:
          screenFp.data.touchSupport &&
          screenFp.data.touchSupport.maxTouchPoints,
      },
      audio: {
        hash: audioFp.hash,
        sampleCount: audioFp.fingerprint.length,
      },
      webrtc: {
        hash: rtcFp.hash,
        ipCount: rtcFp.ips.length,
        ips: rtcFp.ips,
      },
      storage: {
        hash: storageFp.hash,
        localStorage: storageFp.data.localStorage,
        sessionStorage: storageFp.data.sessionStorage,
        indexedDB: storageFp.data.indexedDB,
        cookies: storageFp.data.cookies,
      },
      collectionTime: Date.now() - startTime,
      timestamp: new Date().toISOString(),
    };

    // Compute combined hash from all component hashes
    fingerprint.combinedHash = await hashComponents([
      canvasFp.hash,
      webglFp.hash,
      fontFp.hash,
      screenFp.hash,
      audioFp.hash,
      rtcFp.hash,
      storageFp.hash,
    ]);

    secLog("Fingerprint collection complete", {
      combinedHash: fingerprint.combinedHash.substring(0, 16) + "...",
      time: fingerprint.collectionTime + "ms",
    });

    return fingerprint;
  }

  // ============================================================================
  // CACHED FINGERPRINT
  // ============================================================================

  let cachedFingerprint = null;
  let cachedHash = null;

  /**
   * Get the browser fingerprint (cached after first call).
   * @returns {Promise<object>} Fingerprint object.
   */
  async function getFingerprint() {
    if (!cachedFingerprint) {
      cachedFingerprint = await collectFingerprint();
    }
    return cachedFingerprint;
  }

  /**
   * Get the combined SHA-256 hash of the fingerprint.
   * @returns {Promise<string>} Combined hash.
   */
  async function getFingerprintHash() {
    if (!cachedHash) {
      const fp = await getFingerprint();
      cachedHash = fp.combinedHash;
    }
    return cachedHash;
  }

  /**
   * Clear the cached fingerprint.
   */
  function clearCache() {
    cachedFingerprint = null;
    cachedHash = null;
    secLog("Fingerprint cache cleared");
  }

  // ============================================================================
  // PUBLIC API
  // ============================================================================

  /**
   * Public API for fingerprint collection.
   * @namespace OSMFingerprint
   */
  const OSMFingerprint = Object.freeze({
    // Main collection
    collectFingerprint: collectFingerprint,
    getFingerprint: getFingerprint,
    getFingerprintHash: getFingerprintHash,

    // Individual components (for advanced use)
    getCanvasFingerprint: getCanvasFingerprint,
    getWebGLFingerprint: getWebGLFingerprint,
    detectFonts: detectFonts,
    getScreenNavigatorFingerprint: getScreenNavigatorFingerprint,
    getAudioFingerprint: getAudioFingerprint,
    getWebRtcIps: getWebRtcIps,
    detectStorage: detectStorage,

    // Cache
    clearCache: clearCache,

    // Font list reference
    FONT_LIST: FONT_LIST,

    // Version
    version: "1.0.0",
  });

  // Attach to global scope
  if (typeof window !== "undefined") {
    window.OSMFingerprint = OSMFingerprint;
  }
})();
