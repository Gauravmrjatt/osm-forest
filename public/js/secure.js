/**
 * @fileoverview secure.js - Anti-DevTools & Anti-Automation Protection
 * @description Client-side security module for the Osm Army Gift Code Fortress system.
 * Implements 14 DevTools detection methods, anti-automation checks, screenshot
 * protection, tab visibility tracking, and selective keyboard shortcut blocking.
 * This is the FIRST script that loads on every page. Maximum priority.
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
    API_BASE: "/api/v1",
    DEVTOOLS_ALERT_ENDPOINT: "/api/v1/alert/devtools",
    AUTOMATION_ALERT_ENDPOINT: "/api/v1/alert/automation",
    DETECTION_INTERVAL_MS: 1200,
    DEVTOOLS_THRESHOLD: 2,
    GRACE_PERIOD_MS: 3000,
    BLUR_DURATION_MS: 500,
    MAX_DETECTION_HISTORY: 50,
    COOLDOWN_MS: 15000,
    DEBUG: false,
  });

  const DETECTION_METHODS = Object.freeze({
    CONSOLE_API: "console_api",
    DEBUGGER_TIMING: "debugger_timing",
    WINDOW_DIMENSIONS: "window_dimensions",
    FIREBUG: "firebug",
    CHROME_DEVTOOLS: "chrome_devtools",
    ELEMENT_SIZE: "element_size",
    PERFORMANCE_PROFILER: "performance_profiler",
    ERROR_STACK: "error_stack",
    CONSOLE_TABLE: "console_table",
    TOSTRING_NATIVE: "tostring_native",
    IFRAME_CONSOLE: "iframe_console",
    DATE_CONSTRUCTOR: "date_constructor",
    FUNCTION_TOSTRING: "function_tostring",
    WORKER_DETECTION: "worker_detection",
  });

  // ============================================================================
  // SECURITY STATE (enclosed, not exposed globally)
  // ============================================================================

  const state = {
    devtoolsOpen: false,
    automationDetected: false,
    detectionCount: 0,
    warningShown: false,
    blocked: false,
    detectionHistory: [],
    tabSwitchCount: 0,
    lastTabSwitchTime: 0,
    keyboardBlocked: false,
    isRedeemPage: false,
    gracePeriodActive: false,
    cooldownActive: false,
    lastDetectionTime: 0,
    continuousDetectionInterval: null,
    consoleApiTriggered: false,
  };

  // ============================================================================
  // UTILITY FUNCTIONS
  // ============================================================================

  /**
   * Generate cryptographically secure random token for request signing.
   * @returns {string} Hex-encoded random bytes.
   */
  function generateSecureToken() {
    if (typeof crypto !== "undefined" && crypto.getRandomValues) {
      const arr = new Uint8Array(16);
      crypto.getRandomValues(arr);
      return Array.from(arr)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    }
    return Date.now().toString(36) + Math.random().toString(36).slice(2);
  }

  /**
   * Current timestamp in ISO format.
   * @returns {string} ISO 8601 timestamp.
   */
  function nowISO() {
    return new Date().toISOString();
  }

  /**
   * High-resolution timestamp.
   * @returns {number} Milliseconds since epoch (high precision where available).
   */
  function hrNow() {
    if (typeof performance !== "undefined" && performance.now) {
      return performance.timeOrigin
        ? performance.timeOrigin + performance.now()
        : Date.now();
    }
    return Date.now();
  }

  /**
   * Log security event (internal, obfuscated in production).
   * @param {string} level - Log level: debug, info, warn, error.
   * @param {string} message - Log message.
   * @param {object} [meta] - Additional metadata.
   */
  function secLog(level, message, meta = {}) {
    if (CONFIG.DEBUG && typeof console !== "undefined") {
      const prefix = "[OSM-SECURE]";
      const entry = { time: nowISO(), level, message, ...meta };
      switch (level) {
        case "debug":
          console.debug(prefix, entry);
          break;
        case "warn":
          console.warn(prefix, entry);
          break;
        case "error":
          console.error(prefix, entry);
          break;
        default:
          console.log(prefix, entry);
      }
    }
  }

  /**
   * Get current page path for context.
   * @returns {string} Current pathname.
   */
  function getPagePath() {
    return (
      (typeof window !== "undefined" && window.location && window.location.pathname) || "/"
    );
  }

  /**
   * Check if current page is the redeem page.
   * @returns {boolean} True if on redeem page.
   */
  function checkIsRedeemPage() {
    const path = getPagePath();
    return path.includes("/redeem") || path.includes("/gift");
  }

  // ============================================================================
  // DETECTION METHOD 1: Console API Detection
  // ============================================================================

  /**
   * Detect DevTools by overriding console.debug via defineGetter.
   * When DevTools is open, accessing console.debug triggers the getter.
   * @returns {boolean} True if DevTools detected.
   */
  function detectConsoleApi() {
    try {
      const originalDescriptor = Object.getOwnPropertyDescriptor(
        window.console,
        "debug"
      );
      let triggered = false;

      Object.defineProperty(window.console, "debug", {
        get: function () {
          triggered = true;
          state.consoleApiTriggered = true;
          return function () {};
        },
        configurable: true,
      });

      // Access console.debug to trigger the getter
      // eslint-disable-next-line no-unused-expressions
      window.console.debug;

      // Restore original
      if (originalDescriptor) {
        Object.defineProperty(window.console, "debug", originalDescriptor);
      } else {
        delete window.console.debug;
      }

      return triggered;
    } catch (_e) {
      return false;
    }
  }

  // ============================================================================
  // DETECTION METHOD 2: Debugger Timing
  // ============================================================================

  /**
   * Detect DevTools by measuring execution time of a debugger statement.
   * When DevTools is open, debugger statement pauses execution significantly.
   * @returns {boolean} True if DevTools detected (threshold > 100ms pause).
   */
  function detectDebuggerTiming() {
    try {
      const start = hrNow();
      // eslint-disable-next-line no-debugger
      debugger;
      const end = hrNow();
      const elapsed = end - start;
      // If debugger caused a pause > 100ms, DevTools is likely open
      return elapsed > 100;
    } catch (_e) {
      return false;
    }
  }

  // ============================================================================
  // DETECTION METHOD 3: Window Dimensions (outer vs inner)
  // ============================================================================

  /**
   * Detect DevTools by comparing outerHeight and innerHeight.
   * When DevTools is docked, innerHeight is significantly smaller than outerHeight.
   * @returns {boolean} True if dimension mismatch suggests DevTools.
   */
  function detectWindowDimensions() {
    try {
      if (typeof window === "undefined") return false;
      const diff = window.outerHeight - window.innerHeight;
      const widthDiff = window.outerWidth - window.innerWidth;
      // Threshold: > 160px height difference or > 160px width difference
      // indicates docked DevTools panel
      return diff > 160 || widthDiff > 160;
    } catch (_e) {
      return false;
    }
  }

  // ============================================================================
  // DETECTION METHOD 4: Firebug Detection
  // ============================================================================

  /**
   * Detect the legacy Firebug extension.
   * @returns {boolean} True if Firebug detected.
   */
  function detectFirebug() {
    try {
      return !!(
        window.console &&
        (window.console.firebug ||
          (window.console.exception && window.console.table))
      );
    } catch (_e) {
      return false;
    }
  }

  // ============================================================================
  // DETECTION METHOD 5: Chrome DevTools Detection
  // ============================================================================

  /**
   * Detect Chrome DevTools via chrome.devtools API or devtools.open property.
   * @returns {boolean} True if Chrome DevTools API accessible.
   */
  function detectChromeDevTools() {
    try {
      const hasChromeDevTools =
        window.chrome &&
        typeof window.chrome === "object" &&
        ((window.chrome.devtools &&
          typeof window.chrome.devtools === "object") ||
          (typeof window.devtools !== "undefined" &&
            window.devtools.open === true));
      return !!hasChromeDevTools;
    } catch (_e) {
      return false;
    }
  }

  // ============================================================================
  // DETECTION METHOD 6: Element Size Check
  // ============================================================================

  /**
   * Detect DevTools by creating a large off-screen element and monitoring
   * viewport changes. DevTools opening can alter the viewport size.
   * @returns {boolean} True if viewport changed suspiciously.
   */
  function detectElementSize() {
    try {
      // Only run after initial page load
      if (typeof document === "undefined" || !document.body) return false;

      const el = document.createElement("div");
      el.id = "__osm_size_check";
      el.style.cssText =
        "position:fixed;top:0;left:0;width:100%;height:100%;" +
        "pointer-events:none;z-index:-9999;opacity:0;overflow:hidden;";
      document.body.appendChild(el);

      const rect = el.getBoundingClientRect();
      const expectedWidth = window.innerWidth;
      const expectedHeight = window.innerHeight;

      document.body.removeChild(el);

      // If element dimensions don't match viewport, DevTools may have altered layout
      const widthDiff = Math.abs(rect.width - expectedWidth);
      const heightDiff = Math.abs(rect.height - expectedHeight);

      return widthDiff > 50 || heightDiff > 50;
    } catch (_e) {
      return false;
    }
  }

  // ============================================================================
  // DETECTION METHOD 7: Performance Profiler Detection
  // ============================================================================

  /**
   * Detect active performance profiler by checking if profiling overhead
   * is present in performance metrics.
   * @returns {boolean} True if profiler detected.
   */
  function detectPerformanceProfiler() {
    try {
      if (
        typeof performance === "undefined" ||
        !performance.getEntriesByType
      )
        return false;

      // Check for profiler-related entries
      const entries = performance.getEntriesByType("resource");
      // Look for suspiciously long script execution times
      const now =
        typeof performance.now === "function" ? performance.now() : 0;
      const timing =
        typeof performance.timing === "object" ? performance.timing : null;

      // If DOM processing took an abnormally long time relative to load,
      // a profiler may have been active
      if (
        timing &&
        timing.domComplete > 0 &&
        timing.domLoading > 0
      ) {
        const domTime = timing.domComplete - timing.domLoading;
        // DOM processing taking > 30 seconds suggests profiling overhead
        if (domTime > 30000) return true;
      }

      // Check if performance.mark shows profiler artifacts
      if (typeof performance.mark === "function") {
        const markName = "__osm_profiler_check";
        try {
          performance.mark(markName);
          const marks = performance.getEntriesByName(markName, "mark");
          if (marks.length > 0) {
            performance.clearMarks(markName);
          }
        } catch (_e2) {
          return true;
        }
      }

      return false;
    } catch (_e) {
      return false;
    }
  }

  // ============================================================================
  // DETECTION METHOD 8: Error Stack Size Detection
  // ============================================================================

  /**
   * Detect DevTools by analyzing error stack trace modifications.
   * DevTools sometimes modifies stack traces (adds frames, formatting).
   * @returns {boolean} True if stack appears modified.
   */
  function detectErrorStack() {
    try {
      // Create an error and inspect its stack
      const testError = new Error("__osm_stack_test");
      const stack = testError.stack;

      if (!stack || typeof stack !== "string") return false;

      const lines = stack.split("\n");

      // DevTools often adds extra formatting or frames
      // Normal stacks: 2-4 lines for this context
      // Modified stacks: more lines, different formatting
      if (lines.length > 8) return true;

      // Check for source map references that DevTools injects
      if (stack.includes("<anonymous>") && lines.length > 5) return true;

      return false;
    } catch (_e) {
      return false;
    }
  }

  // ============================================================================
  // DETECTION METHOD 9: console.table Override Detection
  // ============================================================================

  /**
   * Detect if console.table has been overridden (common DevTools indicator).
   * @returns {boolean} True if console.table appears overridden.
   */
  function detectConsoleTableOverride() {
    try {
      const tableFn = window.console.table;
      if (!tableFn || typeof tableFn !== "function") return false;

      const fnString = tableFn.toString();

      // Native console.table should contain specific signatures
      const nativeIndicators = [
        "[native code]",
        "function table",
        "{ [native code] }",
      ];

      const isNative = nativeIndicators.some((ind) => fnString.includes(ind));

      // If toString doesn't show native code, it may have been overridden
      if (!isNative && fnString.length > 100) {
        return true;
      }

      return false;
    } catch (_e) {
      return false;
    }
  }

  // ============================================================================
  // DETECTION METHOD 10: toString Detection on Native Functions
  // ============================================================================

  /**
   * Detect DevTools by checking if native function toString has been tampered.
   * Some DevTools extensions override Function.prototype.toString.
   * @returns {boolean} True if native toString appears modified.
   */
  function detectToStringNative() {
    try {
      // Test a known native function
      const fetchToString = window.fetch ? window.fetch.toString() : "";
      const consoleLogToString = window.console.log
        ? window.console.log.toString()
        : "";

      const nativePattern = /\[native code\]|\[native\scode\]/;

      const fetchIsNative = nativePattern.test(fetchToString);
      const consoleLogIsNative = nativePattern.test(consoleLogToString);

      // If fetch exists but toString doesn't show native, something tampered with it
      if (window.fetch && !fetchIsNative) return true;
      if (!consoleLogIsNative && consoleLogToString.length > 50) return true;

      // Also check Function.prototype.toString directly
      const fnProtoToString = Function.prototype.toString;
      const fnProtoString = fnProtoToString.call(fnProtoToString);
      if (!nativePattern.test(fnProtoString)) return true;

      return false;
    } catch (_e) {
      return false;
    }
  }

  // ============================================================================
  // DETECTION METHOD 11: Iframe Console Detection
  // ============================================================================

  /**
   * Detect DevTools by creating an iframe and checking its console.
   * DevTools sometimes attaches to iframes differently.
   * @returns {boolean} True if iframe console behavior is abnormal.
   */
  function detectIframeConsole() {
    try {
      if (typeof document === "undefined") return false;

      const iframe = document.createElement("iframe");
      iframe.style.display = "none";
      document.body.appendChild(iframe);

      const iframeWindow = iframe.contentWindow;
      let detected = false;

      if (iframeWindow && iframeWindow.console) {
        // Check if iframe console has been augmented by DevTools
        const iframeLog = iframeWindow.console.log;
        const iframeDir = iframeWindow.console.dir;

        // In some browsers, DevTools adds extra properties to iframe consoles
        if (
          iframeWindow.console.__proto__ &&
          Object.keys(iframeWindow.console.__proto__).length > 20
        ) {
          detected = true;
        }

        // Check if console.profile exists (DevTools feature)
        if (typeof iframeWindow.console.profile === "function") {
          // This exists in both cases, but check if it's native
          const profileStr = iframeWindow.console.profile.toString();
          if (!profileStr.includes("[native code]")) {
            detected = true;
          }
        }
      }

      document.body.removeChild(iframe);
      return detected;
    } catch (_e) {
      return false;
    }
  }

  // ============================================================================
  // DETECTION METHOD 12: Date Constructor Override Timing
  // ============================================================================

  /**
   * Detect DevTools by temporarily overriding Date and measuring timing.
   * Some DevTools extensions override Date constructor for profiling.
   * @returns {boolean} True if Date constructor appears overridden.
   */
  function detectDateConstructorOverride() {
    try {
      const OriginalDate = window.Date;
      const dateString = OriginalDate.prototype.constructor.toString();

      // Check if Date constructor shows native code
      const nativePattern = /\[native code\]|\[native\scode\]/;
      if (!nativePattern.test(dateString)) return true;

      // Timing-based check: compare performance.now() vs Date.now() drift
      if (typeof performance !== "undefined" && performance.now) {
        const perfStart = performance.now();
        const dateStart = Date.now();

        // Small computation to create measurable time difference
        let sum = 0;
        for (let i = 0; i < 10000; i++) {
          sum += i;
        }

        const perfEnd = performance.now();
        const dateEnd = Date.now();

        const perfDelta = perfEnd - perfStart;
        const dateDelta = dateEnd - dateStart;

        // If performance.now and Date.now diverge significantly,
        // a debugger may have paused execution
        const drift = Math.abs(perfDelta - dateDelta);
        if (drift > 50) return true;
      }

      return false;
    } catch (_e) {
      return false;
    }
  }

  // ============================================================================
  // DETECTION METHOD 13: Function.prototype.toString Detection
  // ============================================================================

  /**
   * Detect if Function.prototype.toString has been overridden by DevTools
   * or debugging extensions. This is a common tampering vector.
   * @returns {boolean} True if Function.prototype.toString is overridden.
   */
  function detectFunctionToString() {
    try {
      const fnToString = Function.prototype.toString;
      const toStringResult = fnToString.call(fnToString);

      // Should contain native code marker
      const nativePattern = /\[native code\]|\[native\scode\]/;
      if (!nativePattern.test(toStringResult)) return true;

      // Check if calling toString on a simple function works correctly
      function testFn() {
        return 42;
      }
      const simpleFnString = fnToString.call(testFn);
      if (!simpleFnString.includes("return 42")) return true;

      return false;
    } catch (_e) {
      return false;
    }
  }

  // ============================================================================
  // DETECTION METHOD 14: Worker-Based Detection
  // ============================================================================

  /**
   * Detect DevTools by running detection logic inside a Web Worker.
   * DevTools may not attach to workers the same way as main thread.
   * @returns {Promise<boolean>} True if DevTools detected via worker.
   */
  function detectWorkerBased() {
    return new Promise(function (resolve) {
      try {
        if (typeof Worker === "undefined") {
          resolve(false);
          return;
        }

        const workerScript = [
          "self.addEventListener('message', function(e) {",
          "  if (e.data === 'detect') {",
          "    var start = Date.now();",
          "    for (var i = 0; i < 1000000; i++) { var x = i * i; }",
          "    var elapsed = Date.now() - start;",
          "    self.postMessage({ type: 'result', elapsed: elapsed });",
          "  }",
          "});",
        ].join("\n");

        const blob = new Blob([workerScript], {
          type: "application/javascript",
        });
        const workerUrl = URL.createObjectURL(blob);
        const worker = new Worker(workerUrl);

        const timeout = setTimeout(function () {
          worker.terminate();
          URL.revokeObjectURL(workerUrl);
          resolve(false);
        }, 3000);

        worker.addEventListener("message", function (e) {
          clearTimeout(timeout);
          worker.terminate();
          URL.revokeObjectURL(workerUrl);

          if (e.data && e.data.type === "result") {
            // If worker took abnormally long, DevTools may be profiling
            resolve(e.data.elapsed > 500);
          } else {
            resolve(false);
          }
        });

        worker.addEventListener("error", function () {
          clearTimeout(timeout);
          URL.revokeObjectURL(workerUrl);
          resolve(false);
        });

        worker.postMessage("detect");
      } catch (_e) {
        resolve(false);
      }
    });
  }

  // ============================================================================
  // MASTER DETECTION ORCHESTRATOR
  // ============================================================================

  /**
   * Run all 14 DevTools detection methods.
   * @returns {Promise<object>} Detection results with method names and outcomes.
   */
  async function runAllDetections() {
    const results = {};

    // Synchronous methods (1-13)
    results[DETECTION_METHODS.CONSOLE_API] = detectConsoleApi();
    results[DETECTION_METHODS.DEBUGGER_TIMING] = detectDebuggerTiming();
    results[DETECTION_METHODS.WINDOW_DIMENSIONS] = detectWindowDimensions();
    results[DETECTION_METHODS.FIREBUG] = detectFirebug();
    results[DETECTION_METHODS.CHROME_DEVTOOLS] = detectChromeDevTools();
    results[DETECTION_METHODS.ELEMENT_SIZE] = detectElementSize();
    results[DETECTION_METHODS.PERFORMANCE_PROFILER] =
      detectPerformanceProfiler();
    results[DETECTION_METHODS.ERROR_STACK] = detectErrorStack();
    results[DETECTION_METHODS.CONSOLE_TABLE] = detectConsoleTableOverride();
    results[DETECTION_METHODS.TOSTRING_NATIVE] = detectToStringNative();
    results[DETECTION_METHODS.IFRAME_CONSOLE] = detectIframeConsole();
    results[DETECTION_METHODS.DATE_CONSTRUCTOR] =
      detectDateConstructorOverride();
    results[DETECTION_METHODS.FUNCTION_TOSTRING] = detectFunctionToString();

    // Asynchronous method (14)
    try {
      results[DETECTION_METHODS.WORKER_DETECTION] = await detectWorkerBased();
    } catch (_e) {
      results[DETECTION_METHODS.WORKER_DETECTION] = false;
    }

    return results;
  }

  /**
   * Count how many detection methods returned positive.
   * @param {object} results - Results from runAllDetections().
   * @returns {number} Count of positive detections.
   */
  function countPositiveDetections(results) {
    return Object.values(results).filter(Boolean).length;
  }

  /**
   * Get the names of all detection methods that returned positive.
   * @param {object} results - Results from runAllDetections().
   * @returns {string[]} Names of positive detection methods.
   */
  function getPositiveDetectionNames(results) {
    return Object.entries(results)
      .filter(function (_ref) {
        const detected = _ref[1];
        return !!detected;
      })
      .map(function (_ref2) {
        const name = _ref2[0];
        return name;
      });
  }

  // ============================================================================
  // ANTI-AUTOMATION DETECTION
  // ============================================================================

  /**
   * Comprehensive anti-automation detection.
   * Checks for Selenium, PhantomJS, Chrome automation, headless indicators.
   * @returns {object} Detection result with flags and details.
   */
  function detectAutomation() {
    const checks = {
      // Selenium / WebDriver
      navigatorWebdriver: false,
      callPhantom: false,
      phantomObject: false,

      // Chrome automation
      domAutomation: false,
      domAutomationController: false,

      // Headless indicators
      noLanguages: false,
      noPlugins: false,
      noChrome: false,
      permissionsApi: false,

      // Iframe / parent access
      inIframe: false,
      parentAccess: false,

      // Additional automation indicators
      seleniumMarker: false,
      webdriverMarker: false,
      headlessChrome: false,
    };

    try {
      // 1. navigator.webdriver (Selenium indicator)
      checks.navigatorWebdriver =
        typeof navigator !== "undefined" && navigator.webdriver === true;

      // 2. window.callPhantom (PhantomJS)
      checks.callPhantom = typeof window.callPhantom === "function";

      // 3. window._phantom
      checks.phantomObject = typeof window._phantom !== "undefined";

      // 4. window.domAutomation
      checks.domAutomation = !!window.domAutomation;

      // 5. window.domAutomationController
      checks.domAutomationController = !!window.domAutomationController;

      // 6. navigator.languages === undefined (headless)
      checks.noLanguages =
        typeof navigator !== "undefined" &&
        (navigator.languages === undefined ||
          (Array.isArray(navigator.languages) &&
            navigator.languages.length === 0));

      // 7. navigator.plugins.length === 0 (headless)
      checks.noPlugins =
        typeof navigator !== "undefined" &&
        navigator.plugins &&
        navigator.plugins.length === 0;

      // 8. window.chrome === undefined (Chromium check)
      // Note: Some legitimate browsers don't have window.chrome
      checks.noChrome =
        typeof window.chrome === "undefined" &&
        /Chrome|Chromium/.test(navigator.userAgent || "");

      // 9. Permissions API check (automation often fails this)
      if (
        typeof navigator !== "undefined" &&
        navigator.permissions &&
        navigator.permissions.query
      ) {
        try {
          navigator.permissions
            .query({ name: "notifications" })
            .then(function (result) {
              checks.permissionsApi = result.state === "prompt";
            })
            .catch(function () {
              checks.permissionsApi = true;
            });
        } catch (_e) {
          checks.permissionsApi = true;
        }
      }

      // 10. Iframe detection
      checks.inIframe = window.self !== window.top;

      // 11. Parent window access check
      try {
        // eslint-disable-next-line no-unused-expressions
        window.parent.location.href;
        checks.parentAccess = true;
      } catch (_e) {
        checks.parentAccess = false;
      }

      // 12. Selenium document markers
      checks.seleniumMarker =
        !!document.documentElement &&
        (document.documentElement.getAttribute("webdriver") !== null ||
          document.documentElement.getAttribute("driver-evaluate") !== null ||
          document.documentElement.getAttribute("selenium-evaluate") !== null);

      // 13. window.webdriver or window.__webdriver_script_fn
      checks.webdriverMarker =
        !!window.__webdriver_script_fn || !!window.webdriver;

      // 14. Headless Chrome indicators
      const ua = navigator.userAgent || "";
      checks.headlessChrome =
        /HeadlessChrome/.test(ua) ||
        (window.chrome &&
          window.chrome.runtime &&
          /Headless/.test(ua));
    } catch (_e) {
      // If any check throws, mark as suspicious
      checks.error = true;
    }

    // Determine overall automation verdict
    const automationFlags = [
      checks.navigatorWebdriver,
      checks.callPhantom,
      checks.phantomObject,
      checks.domAutomation,
      checks.domAutomationController,
      checks.seleniumMarker,
      checks.webdriverMarker,
      checks.headlessChrome,
    ];
    checks.automationDetected = automationFlags.some(Boolean);
    checks.automationScore = automationFlags.filter(Boolean).length;

    return checks;
  }

  // ============================================================================
  // SECURITY RESPONSE ACTIONS
  // ============================================================================

  /**
   * Send alert to server endpoint.
   * @param {string} endpoint - API endpoint path.
   * @param {object} payload - Alert data.
   */
  async function sendAlert(endpoint, payload) {
    try {
      const token = generateSecureToken();
      const body = JSON.stringify({
        ...payload,
        timestamp: nowISO(),
        path: getPagePath(),
        token: token,
      });

      await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-OSM-Sec-Token": token,
          "X-OSM-Sec-Time": String(Date.now()),
        },
        body: body,
        keepalive: true,
      });
    } catch (_e) {
      // Silent fail - don't expose server errors to attacker
      secLog("debug", "Alert send failed (expected in some contexts)");
    }
  }

  /**
   * Send DevTools detection alert to server.
   * @param {object} results - Detection results.
   * @param {number} count - Number of positive detections.
   */
  async function sendDevToolsAlert(results, count) {
    await sendAlert(CONFIG.DEVTOOLS_ALERT_ENDPOINT, {
      type: "devtools_detected",
      detectionCount: count,
      methods: getPositiveDetectionNames(results),
      userAgent: navigator.userAgent,
      screenResolution:
        (window.screen && window.screen.width) +
        "x" +
        (window.screen && window.screen.height),
    });
  }

  /**
   * Send automation detection alert to server.
   * @param {object} checks - Automation check results.
   */
  async function sendAutomationAlert(checks) {
    await sendAlert(CONFIG.AUTOMATION_ALERT_ENDPOINT, {
      type: "automation_detected",
      automationScore: checks.automationScore,
      checks: checks,
      userAgent: navigator.userAgent,
    });
  }

  /**
   * Blur all sensitive content on the page.
   */
  function blurSensitiveContent() {
    try {
      const sensitiveElements = document.querySelectorAll(
        ".osm-sensitive, .osm-code-display, .osm-gift-image, [data-osm-sensitive]"
      );
      sensitiveElements.forEach(function (el) {
        el.style.filter = "blur(20px)";
        el.style.transition = "filter 0.3s ease";
        el.style.pointerEvents = "none";
        el.setAttribute("data-osm-blurred", "true");
      });

      // Also add a CSS class to body for global blur state
      document.body.classList.add("osm-content-blurred");
    } catch (_e) {
      // Silent
    }
  }

  /**
   * Unblur sensitive content.
   */
  function unblurSensitiveContent() {
    try {
      const blurredElements = document.querySelectorAll(
        '[data-osm-blurred="true"]'
      );
      blurredElements.forEach(function (el) {
        el.style.filter = "";
        el.style.pointerEvents = "";
        el.removeAttribute("data-osm-blurred");
      });
      document.body.classList.remove("osm-content-blurred");
    } catch (_e) {
      // Silent
    }
  }

  /**
   * Show a warning overlay to the user.
   * @param {string} title - Warning title.
   * @param {string} message - Warning message.
   * @param {string} [type] - Warning type: warning | block.
   */
  function showWarningOverlay(title, message, type) {
    if (type === void 0) {
      type = "warning";
    }
    try {
      // Remove existing warning
      const existing = document.getElementById("__osm_warning_overlay");
      if (existing) existing.remove();

      const overlay = document.createElement("div");
      overlay.id = "__osm_warning_overlay";
      overlay.setAttribute("role", "alert");
      overlay.setAttribute("aria-live", "assertive");

      const isBlock = type === "block";
      const bgColor = isBlock ? "rgba(180,20,20,0.95)" : "rgba(200,130,0,0.92)";
      const borderColor = isBlock ? "#ff4444" : "#ffaa00";

      overlay.style.cssText =
        "position:fixed;top:20px;left:50%;transform:translateX(-50%);" +
        "max-width:480px;width:90%;padding:20px 24px;border-radius:12px;" +
        "z-index:999999;font-family:system-ui,-apple-system,sans-serif;" +
        "color:#fff;font-size:15px;line-height:1.5;box-shadow:0 8px 32px rgba(0,0,0,0.3);" +
        "border:2px solid " +
        borderColor +
        ";background:" +
        bgColor +
        ";";

      overlay.innerHTML =
        "<div style=\"font-weight:700;font-size:17px;margin-bottom:8px;\">" +
        "&#9888; " +
        title +
        "</div>" +
        "<div style=\"margin-bottom:12px;\">" +
        message +
        "</div>" +
        (isBlock
          ? ""
          : '<div style=\"font-size:12px;opacity:0.8;\">' +
            "Repeated violations will block access. Please close developer tools." +
            "</div>");

      // Close button
      const closeBtn = document.createElement("button");
      closeBtn.textContent = isBlock ? "OK" : "\u00d7";
      closeBtn.style.cssText =
        "position:absolute;top:8px;right:12px;background:none;border:none;" +
        "color:#fff;font-size:20px;cursor:pointer;padding:4px 8px;";
      closeBtn.onclick = function () {
        overlay.remove();
      };
      overlay.appendChild(closeBtn);

      document.body.appendChild(overlay);

      // Auto-dismiss warning (not block) after 8 seconds
      if (!isBlock) {
        setTimeout(function () {
          if (overlay.parentNode) overlay.remove();
        }, 8000);
      }
    } catch (_e) {
      // Silent
    }
  }

  /**
   * Block page access - show full-screen block overlay.
   */
  function blockPageAccess() {
    state.blocked = true;
    blurSensitiveContent();

    try {
      const existing = document.getElementById("__osm_block_overlay");
      if (existing) return;

      const overlay = document.createElement("div");
      overlay.id = "__osm_block_overlay";
      overlay.style.cssText =
        "position:fixed;top:0;left:0;width:100%;height:100%;" +
        "background:rgba(10,10,10,0.95);z-index:999998;" +
        "display:flex;align-items:center;justify-content:center;" +
        "font-family:system-ui,-apple-system,sans-serif;";

      overlay.innerHTML =
        '<div style="text-align:center;color:#fff;padding:20px;">' +
        '<div style="font-size:48px;margin-bottom:16px;">&#128683;</div>' +
        '<div style="font-size:22px;font-weight:700;margin-bottom:12px;">' +
        "Access Suspended" +
        "</div>" +
        '<div style="font-size:15px;opacity:0.8;max-width:400px;margin:0 auto;">' +
        "Developer tools or automation software has been detected. " +
        "Please close all developer tools and refresh the page to continue." +
        "</div>" +
        '<div style="margin-top:24px;font-size:12px;opacity:0.5;">' +
        "Security ID: " +
        generateSecureToken().slice(0, 8) +
        "</div></div>";

      document.body.appendChild(overlay);
    } catch (_e) {
      // Silent
    }
  }

  // ============================================================================
  // DEVTOOLS HANDLER
  // ============================================================================

  /**
   * Handle DevTools detection event.
   * @param {object} results - Full detection results.
   */
  async function handleDevToolsDetection(results) {
    const positiveCount = countPositiveDetections(results);
    const methodNames = getPositiveDetectionNames(results);

    secLog("warn", "DevTools detection triggered", {
      count: positiveCount,
      methods: methodNames,
    });

    // Record in history
    state.detectionHistory.push({
      time: Date.now(),
      count: positiveCount,
      methods: methodNames,
    });
    if (state.detectionHistory.length > CONFIG.MAX_DETECTION_HISTORY) {
      state.detectionHistory.shift();
    }

    state.detectionCount++;
    state.lastDetectionTime = Date.now();

    // First detection: warning
    if (state.detectionCount === 1 && !state.warningShown) {
      state.warningShown = true;
      state.gracePeriodActive = true;
      blurSensitiveContent();
      showWarningOverlay(
        "Developer Tools Detected",
        "Developer tools have been detected on this page. " +
          "For security reasons, gift code content is hidden while developer tools are open. " +
          "Please close developer tools to continue.",
        "warning"
      );
      await sendDevToolsAlert(results, positiveCount);

      // Grace period: auto-unblur after grace period if no more detections
      setTimeout(function () {
        state.gracePeriodActive = false;
        if (state.detectionCount < CONFIG.DEVTOOLS_THRESHOLD && !state.blocked) {
          unblurSensitiveContent();
        }
      }, CONFIG.GRACE_PERIOD_MS);
    }
    // Second+ detection: block
    else if (state.detectionCount >= CONFIG.DEVTOOLS_THRESHOLD && !state.blocked) {
      await sendDevToolsAlert(results, positiveCount);
      blockPageAccess();
      showWarningOverlay(
        "Access Blocked",
        "Developer tools usage has exceeded the allowed threshold. " +
          "Access to gift codes has been suspended. Please close developer tools and refresh.",
        "block"
      );
    } else if (state.devtoolsOpen) {
      // DevTools still open, keep blurred
      blurSensitiveContent();
    }

    state.devtoolsOpen = true;
  }

  /**
   * Handle DevTools close event (all detections negative).
   */
  function handleDevToolsClose() {
    if (state.devtoolsOpen) {
      secLog("info", "DevTools closed");
      state.devtoolsOpen = false;

      // Only unblur if not blocked and cooldown has passed
      if (!state.blocked && !state.cooldownActive) {
        unblurSensitiveContent();
      }
    }
  }

  // ============================================================================
  // AUTOMATION HANDLER
  // ============================================================================

  /**
   * Handle automation detection event.
   * @param {object} checks - Automation check results.
   */
  async function handleAutomationDetection(checks) {
    if (state.automationDetected || state.blocked) return;

    state.automationDetected = true;
    secLog("warn", "Automation detected", { score: checks.automationScore });

    await sendAutomationAlert(checks);
    blurSensitiveContent();
    blockPageAccess();
    showWarningOverlay(
      "Automation Detected",
      "Browser automation software (Selenium, Puppeteer, PhantomJS, or similar) " +
        "has been detected. Gift code access is not available through automated browsers. " +
        "Please use a standard browser to access gift codes.",
      "block"
    );
  }

  // ============================================================================
  // CONTINUOUS DETECTION LOOP
  // ============================================================================

  /**
   * Main continuous detection loop.
   * Runs all detection methods at configured intervals.
   */
  async function runContinuousDetection() {
    if (state.blocked || state.cooldownActive) return;

    // Run DevTools detection
    const results = await runAllDetections();
    const positiveCount = countPositiveDetections(results);

    if (positiveCount > 0) {
      await handleDevToolsDetection(results);
    } else {
      handleDevToolsClose();
    }

    // Run automation detection (every 3rd cycle to save resources)
    if (state.detectionCount % 3 === 0) {
      const automationChecks = detectAutomation();
      if (automationChecks.automationDetected) {
        await handleAutomationDetection(automationChecks);
      }
    }
  }

  /**
   * Start the continuous detection system.
   */
  function startContinuousDetection() {
    if (state.continuousDetectionInterval) return;

    state.continuousDetectionInterval = setInterval(
      runContinuousDetection,
      CONFIG.DETECTION_INTERVAL_MS
    );

    // Run immediately on start
    runContinuousDetection();
  }

  /**
   * Stop continuous detection.
   */
  function stopContinuousDetection() {
    if (state.continuousDetectionInterval) {
      clearInterval(state.continuousDetectionInterval);
      state.continuousDetectionInterval = null;
    }
  }

  // ============================================================================
  // TAB VISIBILITY TRACKING
  // ============================================================================

  /**
   * Initialize tab visibility tracking.
   * Monitors when user switches away from the tab.
   */
  function initTabVisibilityTracking() {
    if (typeof document === "undefined") return;

    function handleVisibilityChange() {
      const isHidden = document.visibilityState === "hidden";
      const timestamp = nowISO();

      if (isHidden) {
        state.tabSwitchCount++;
        state.lastTabSwitchTime = Date.now();

        secLog("info", "Tab hidden", {
          count: state.tabSwitchCount,
          time: timestamp,
        });

        // Blur sensitive content when tab is hidden
        blurSensitiveContent();

        // Send tab switch event to server
        sendAlert("/api/v1/alert/tab-switch", {
          type: "tab_hidden",
          tabSwitchCount: state.tabSwitchCount,
          timestamp: timestamp,
        }).catch(function () {});
      } else {
        secLog("info", "Tab visible", { time: timestamp });

        // Only unblur if not blocked and devtools not detected
        if (!state.blocked && !state.devtoolsOpen) {
          // Small delay to catch rapid tab switching
          setTimeout(function () {
            if (document.visibilityState === "visible" && !state.blocked) {
              unblurSensitiveContent();
            }
          }, 500);
        }
      }
    }

    document.addEventListener("visibilitychange", handleVisibilityChange);

    // Also listen for page show/hide events (mobile browsers)
    window.addEventListener("pagehide", function () {
      blurSensitiveContent();
      state.tabSwitchCount++;
    });

    window.addEventListener("pageshow", function () {
      if (!state.blocked && !state.devtoolsOpen) {
        setTimeout(unblurSensitiveContent, 300);
      }
    });
  }

  // ============================================================================
  // SCREENSHOT PROTECTION
  // ============================================================================

  /**
   * Initialize screenshot protection features.
   * Blurs content on focus loss, blocks drag on images.
   */
  function initScreenshotProtection() {
    if (typeof document === "undefined") return;

    // 1. Blur content when window loses focus
    window.addEventListener("blur", function () {
      blurSensitiveContent();
    });

    window.addEventListener("focus", function () {
      if (!state.blocked && !state.devtoolsOpen) {
        setTimeout(unblurSensitiveContent, 200);
      }
    });

    // 2. Detect PrintScreen key (keyCode 44)
    document.addEventListener("keydown", function (e) {
      if (e.keyCode === 44 || e.key === "PrintScreen" || e.key === "Snapshot") {
        secLog("warn", "PrintScreen detected");
        blurSensitiveContent();

        // Show brief warning
        showWarningOverlay(
          "Screenshot Detected",
          "Screenshots of gift codes are not permitted for security reasons.",
          "warning"
        );

        sendAlert("/api/v1/alert/screenshot", {
          type: "printscreen_key",
          key: e.key || e.keyCode,
        }).catch(function () {});
      }
    });

    // 3. Detect Ctrl+Shift+S or Cmd+Shift+S (screenshot shortcuts)
    document.addEventListener("keydown", function (e) {
      const isScreenshotShortcut =
        (e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === "S" || e.keyCode === 83);

      if (isScreenshotShortcut) {
        secLog("warn", "Screenshot shortcut detected");
        e.preventDefault();
        blurSensitiveContent();
        showWarningOverlay(
          "Screenshot Shortcut Blocked",
          "Screenshot shortcuts are disabled on this page for security reasons.",
          "warning"
        );
      }
    });

    // 4. Add CSS: user-select: none on code elements
    function addCodeProtectionStyles() {
      const style = document.createElement("style");
      style.textContent =
        ".osm-code-display, .osm-gift-image, .osm-sensitive, [data-osm-code] { " +
        "  -webkit-user-select: none !important; " +
        "  -moz-user-select: none !important; " +
        "  -ms-user-select: none !important; " +
        "  user-select: none !important; " +
        "  pointer-events: none !important; " +
        "}" +
        ".osm-content-blurred .osm-sensitive, " +
        ".osm-content-blurred .osm-code-display { " +
        "  filter: blur(20px) !important; " +
        "}";
      document.head.appendChild(style);
    }

    // 5. Prevent drag on code images
    document.addEventListener(
      "dragstart",
      function (e) {
        if (
          e.target &&
          (e.target.classList.contains("osm-gift-image") ||
            e.target.closest(".osm-code-display"))
        ) {
          e.preventDefault();
          return false;
        }
      },
      true
    );

    // 6. Context menu: allow but track
    document.addEventListener("contextmenu", function (e) {
      if (
        e.target &&
        (e.target.classList.contains("osm-sensitive") ||
          e.target.closest(".osm-code-display") ||
          e.target.closest("[data-osm-code]"))
      ) {
        // Allow context menu but add tracking
        secLog("info", "Context menu on sensitive element");
        sendAlert("/api/v1/alert/context-menu", {
          type: "context_menu_sensitive",
          tag: e.target.tagName,
        }).catch(function () {});
      }
    });

    addCodeProtectionStyles();
  }

  // ============================================================================
  // KEYBOARD SHORTCUT BLOCKING (SELECTIVE)
  // ============================================================================

  /**
   * Initialize selective keyboard shortcut blocking.
   * Blocks DevTools shortcuts only on redeem page.
   * Blocks view source on all pages.
   */
  function initKeyboardBlocking() {
    state.isRedeemPage = checkIsRedeemPage();

    document.addEventListener("keydown", function (e) {
      // Never block input elements
      const tag = (e.target && e.target.tagName) || "";
      const isInput =
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        (e.target && e.target.isContentEditable);
      if (isInput) return;

      const key = e.key || "";
      const keyCode = e.keyCode || e.which;
      const ctrl = e.ctrlKey;
      const shift = e.shiftKey;
      const meta = e.metaKey;
      const mod = ctrl || meta;

      // ---- ALL PAGES ----

      // Block Ctrl+U (View Source) - all pages
      if (mod && (key === "u" || key === "U" || keyCode === 85)) {
        e.preventDefault();
        secLog("info", "Ctrl+U blocked");
        return false;
      }

      // ---- REDEEM PAGE ONLY ----

      if (state.isRedeemPage) {
        // Block F12 (DevTools)
        if (keyCode === 123) {
          e.preventDefault();
          secLog("info", "F12 blocked on redeem page");
          return false;
        }

        // Block Ctrl+Shift+I (DevTools Inspector)
        if (mod && shift && (key === "i" || key === "I" || keyCode === 73)) {
          e.preventDefault();
          secLog("info", "Ctrl+Shift+I blocked");
          return false;
        }

        // Block Ctrl+Shift+J (DevTools Console)
        if (mod && shift && (key === "j" || key === "J" || keyCode === 74)) {
          e.preventDefault();
          secLog("info", "Ctrl+Shift+J blocked");
          return false;
        }

        // Block Ctrl+Shift+C (DevTools Element Inspector)
        if (mod && shift && (key === "c" || key === "C" || keyCode === 67)) {
          e.preventDefault();
          secLog("info", "Ctrl+Shift+C blocked");
          return false;
        }

        // Block Ctrl+S (Save Page)
        if (mod && (key === "s" || key === "S" || keyCode === 83) && !shift) {
          e.preventDefault();
          secLog("info", "Ctrl+S blocked on redeem page");
          return false;
        }

        // Block PrintScreen on redeem page
        if (keyCode === 44 || key === "PrintScreen") {
          e.preventDefault();
          blurSensitiveContent();
          secLog("info", "PrintScreen blocked on redeem page");
          return false;
        }
      }
    },
    true);
  }

  // ============================================================================
  // INITIALIZATION
  // ============================================================================

  /**
   * Initialize the security module.
   * Runs all detection systems and protection mechanisms.
   */
  function init() {
    // Check if we're in a browser environment
    if (typeof window === "undefined" || typeof document === "undefined") {
      return;
    }

    // Mark that security module is loaded
    state.loadedAt = Date.now();

    // Check if this is the redeem page
    state.isRedeemPage = checkIsRedeemPage();

    secLog("info", "OSM Secure module initializing", {
      path: getPagePath(),
      isRedeem: state.isRedeemPage,
    });

    // 1. Start continuous DevTools + automation detection
    startContinuousDetection();

    // 2. Initialize tab visibility tracking
    initTabVisibilityTracking();

    // 3. Initialize screenshot protection
    initScreenshotProtection();

    // 4. Initialize keyboard shortcut blocking
    initKeyboardBlocking();

    // 5. Run initial automation check immediately
    const initialAutomation = detectAutomation();
    if (initialAutomation.automationDetected) {
      handleAutomationDetection(initialAutomation);
    }

    // 6. Stop detection on page unload
    window.addEventListener("beforeunload", function () {
      stopContinuousDetection();
    });

    secLog("info", "OSM Secure module initialized");
  }

  // ============================================================================
  // PUBLIC API (exposed via window.OSMSecure)
  // ============================================================================

  /**
   * Public API for the security module.
   * @namespace OSMSecure
   */
  const OSMSecure = Object.freeze({
    /**
     * Get current security state.
     * @returns {object} Current state snapshot.
     */
    getState: function () {
      return {
        devtoolsOpen: state.devtoolsOpen,
        automationDetected: state.automationDetected,
        detectionCount: state.detectionCount,
        blocked: state.blocked,
        tabSwitchCount: state.tabSwitchCount,
        isRedeemPage: state.isRedeemPage,
      };
    },

    /**
     * Manually trigger a DevTools detection check.
     * @returns {Promise<object>} Detection results.
     */
    checkDevTools: async function () {
      const results = await runAllDetections();
      return {
        results: results,
        positiveCount: countPositiveDetections(results),
        methods: getPositiveDetectionNames(results),
      };
    },

    /**
     * Manually run automation detection.
     * @returns {object} Automation check results.
     */
    checkAutomation: function () {
      return detectAutomation();
    },

    /**
     * Get tab switch count.
     * @returns {number} Number of times user switched tabs.
     */
    getTabSwitchCount: function () {
      return state.tabSwitchCount;
    },

    /**
     * Manually blur sensitive content.
     */
    blurContent: blurSensitiveContent,

    /**
     * Manually unblur sensitive content.
     */
    unblurContent: unblurSensitiveContent,

    /**
     * Check if page is currently blocked.
     * @returns {boolean} True if access is blocked.
     */
    isBlocked: function () {
      return state.blocked;
    },

    /**
     * Get detection history.
     * @returns {Array} Array of detection events.
     */
    getDetectionHistory: function () {
      return state.detectionHistory.slice();
    },

    /**
     * Destroy the security module (stop all detection).
     */
    destroy: function () {
      stopContinuousDetection();
      unblurSensitiveContent();
      state.blocked = false;
      state.detectionCount = 0;
      state.warningShown = false;
    },

    // Expose detection method names for reference
    DETECTION_METHODS: DETECTION_METHODS,

    // Version
    version: "1.0.0",
  });

  // Attach to global scope
  if (typeof window !== "undefined") {
    window.OSMSecure = OSMSecure;
  }

  // Auto-initialize on DOM ready
  if (typeof document !== "undefined") {
    if (
      document.readyState === "complete" ||
      document.readyState === "interactive"
    ) {
      init();
    } else {
      document.addEventListener("DOMContentLoaded", init);
      // Fallback
      window.addEventListener("load", init);
    }
  }
})();
