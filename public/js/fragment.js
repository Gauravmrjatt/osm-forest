/**
 * @fileoverview fragment.js - Client-side 3-Factor Decryption Controller
 * @description Orchestrates the 3-factor authentication flow for gift code
 * decryption. Manages token validation, server proof (Factor 1), behavior
 * proof (Factor 2), browser fingerprint (Factor 3), and secure code reveal.
 * Provides progressive flow control with retry logic and comprehensive error
 * handling.
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
    // Token
    TOKEN_LENGTH: 43,
    TOKEN_PARAM: "token",

    // API endpoints
    API_VERIFY_TOKEN: "/api/v1/verify-token",
    API_FACTOR1: "/api/v1/factor/1",
    API_FACTOR2: "/api/v1/factor/2",
    API_FACTOR3: "/api/v1/factor/3",
    API_REVEAL: "/api/v1/reveal",

    // Retry
    RETRY_MAX_ATTEMPTS: 3,
    RETRY_BASE_DELAY_MS: 1000,
    RETRY_MAX_DELAY_MS: 8000,

    // Factor 1
    FACTOR1_MAX_RETRIES: 3,

    // Code reveal
    REVEAL_COUNTDOWN_SEC: 10,
    TOKEN_EXPIRY_BUFFER_MS: 60000,

    // Polling
    BEHAVIOR_POLL_INTERVAL_MS: 1000,
    BEHAVIOR_MAX_WAIT_MS: 120000,

    // Rate limit
    RATE_LIMIT_CHECK_INTERVAL_MS: 5000,

    DEBUG: false,
  });

  // ============================================================================
  // STATE MACHINE
  // ============================================================================

  const STEPS = Object.freeze({
    IDLE: "idle",
    VALIDATING: "validating",
    FACTOR1: "factor1",
    COLLECTING_BEHAVIOR: "collecting_behavior",
    FACTOR2: "factor2",
    COLLECTING_FINGERPRINT: "collecting_fingerprint",
    FACTOR3: "factor3",
    REVEALING: "revealing",
    COMPLETE: "complete",
    ERROR: "error",
    EXPIRED: "expired",
    BLOCKED: "blocked",
  });

  const state = {
    currentStep: STEPS.IDLE,
    token: null,
    tokenExpiry: null,
    factor1Attempts: 0,
    factor1Response: null,
    factor2Response: null,
    factor3Response: null,
    behaviorReady: false,
    fingerprintReady: false,
    countdownTimer: null,
    countdownRemaining: 0,
    pollingInterval: null,
    rateLimitTimer: null,
    rateLimitExpiry: null,
    errorMessage: null,
    flowStarted: false,
    factorResults: {
      factor1: false,
      factor2: false,
      factor3: false,
    },
  };

  // ============================================================================
  // UTILITY FUNCTIONS
  // ============================================================================

  /**
   * High-resolution timestamp.
   * @returns {number} Milliseconds since epoch.
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
   * ISO timestamp string.
   * @returns {string} ISO 8601 timestamp.
   */
  function nowISO() {
    return new Date().toISOString();
  }

  /**
   * Sleep utility for async delays.
   * @param {number} ms - Milliseconds to sleep.
   * @returns {Promise<void>}
   */
  function sleep(ms) {
    return new Promise(function (resolve) {
      setTimeout(resolve, ms);
    });
  }

  /**
   * Generate HMAC-SHA512 using Web Crypto API.
   * @param {string} key - HMAC key.
   * @param {string} message - Message to sign.
   * @returns {Promise<string>} Hex-encoded HMAC.
   */
  async function hmacSha512(key, message) {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(key);
    const messageData = encoder.encode(message);

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyData,
      { name: "HMAC", hash: "SHA-512" },
      false,
      ["sign"]
    );

    const signature = await crypto.subtle.sign("HMAC", cryptoKey, messageData);

    // Convert to hex
    const bytes = new Uint8Array(signature);
    return Array.from(bytes)
      .map(function (b) {
        return b.toString(16).padStart(2, "0");
      })
      .join("");
  }

  /**
   * Generate SHA-256 hash of a string.
   * @param {string} input - Input string.
   * @returns {Promise<string>} Hex-encoded SHA-256 hash.
   */
  async function sha256(input) {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const bytes = new Uint8Array(hashBuffer);
    return Array.from(bytes)
      .map(function (b) {
        return b.toString(16).padStart(2, "0");
      })
      .join("");
  }

  /**
   * Calculate exponential backoff delay.
   * @param {number} attempt - Attempt number (0-indexed).
   * @returns {number} Delay in milliseconds.
   */
  function backoffDelay(attempt) {
    const delay = Math.min(
      CONFIG.RETRY_BASE_DELAY_MS * Math.pow(2, attempt),
      CONFIG.RETRY_MAX_DELAY_MS
    );
    return delay + Math.floor(Math.random() * 500);
  }

  /**
   * Log debug messages.
   * @param {string} message - Message.
   * @param {object} [meta] - Extra data.
   */
  function secLog(message, meta) {
    if (CONFIG.DEBUG && typeof console !== "undefined") {
      console.debug("[OSM-FRAGMENT]", message, meta || "");
    }
  }

  // ============================================================================
  // UI HELPERS
  // ============================================================================

  /**
   * Update progress bar display.
   * @param {number} percent - Progress 0-100.
   * @param {string} message - Status message.
   * @param {string} [stepLabel] - Current step label.
   */
  function updateProgress(percent, message, stepLabel) {
    if (typeof document === "undefined") return;

    // Update progress bar if element exists
    const bar = document.getElementById("osm-progress-bar");
    const text = document.getElementById("osm-progress-text");
    const step = document.getElementById("osm-progress-step");
    const container = document.getElementById("osm-progress-container");

    if (container) container.style.display = "block";
    if (bar) {
      bar.style.width = Math.max(0, Math.min(100, percent)) + "%";
      bar.style.transition = "width 0.5s ease";
    }
    if (text) text.textContent = message;
    if (step) step.textContent = stepLabel || "";

    secLog("Progress: " + percent + "% - " + message);
  }

  /**
   * Show error message to user.
   * @param {string} title - Error title.
   * @param {string} message - Error description.
   * @param {object} [options] - Additional options.
   * @param {boolean} [options.retry=false] - Show retry button.
   * @param {boolean} [options.redirect=false] - Show redirect button.
    * @param {string} [options.redirectUrl="/gift"] - Redirect URL.
   */
  function showError(title, message, options) {
    if (options === void 0) options = {};
    if (typeof document === "undefined") return;

    const container = document.getElementById("osm-error-container");
    if (!container) return;

    const { retry = false, redirect = false, redirectUrl = "/gift" } = options;

    let html =
      '<div style="font-family:system-ui,sans-serif;padding:24px;' +
      "background:rgba(180,20,20,0.95);border-radius:12px;color:#fff;" +
      'border:2px solid #ff4444;text-align:center;">' +
      '<div style="font-size:36px;margin-bottom:12px;">&#10071;</div>' +
      '<div style="font-size:18px;font-weight:700;margin-bottom:8px;">' +
      title +
      "</div>" +
      '<div style="font-size:14px;opacity:0.9;margin-bottom:16px;">' +
      message +
      "</div>";

    if (retry) {
      html +=
        '<button id="osm-retry-btn" style="padding:10px 24px;' +
        "background:#fff;color:#b41414;border:none;border-radius:6px;" +
        'font-size:14px;font-weight:600;cursor:pointer;margin:4px;">' +
        "Retry" +
        "</button>";
    }

    if (redirect) {
      html +=
        '<a href="' +
        redirectUrl +
        '" style="display:inline-block;padding:10px 24px;' +
        "background:#444;color:#fff;border:none;border-radius:6px;" +
        'font-size:14px;font-weight:600;cursor:pointer;margin:4px;' +
        'text-decoration:none;">' +
        "Go Back" +
        "</a>";
    }

    html += "</div>";

    container.innerHTML = html;
    container.style.display = "block";

    // Hide progress
    const progressContainer = document.getElementById("osm-progress-container");
    if (progressContainer) progressContainer.style.display = "none";

    // Attach retry handler
    if (retry) {
      const retryBtn = document.getElementById("osm-retry-btn");
      if (retryBtn) {
        retryBtn.addEventListener("click", function () {
          container.style.display = "none";
          container.innerHTML = "";
          resetFlow();
          startDecryptionFlow();
        });
      }
    }
  }

  /**
   * Hide error display.
   */
  function hideError() {
    const container = document.getElementById("osm-error-container");
    if (container) {
      container.style.display = "none";
      container.innerHTML = "";
    }
  }

  /**
   * Update the code reveal display.
   * @param {string} imageUrl - URL of the code image.
   */
  function showCodeImage(imageUrl) {
    if (typeof document === "undefined") return;

    const container = document.getElementById("osm-code-container");
    if (!container) return;

    container.innerHTML =
      '<div style="text-align:center;">' +
      '<img src="' +
      imageUrl +
      '" alt="Gift Code" ' +
      'class="osm-gift-image osm-sensitive" ' +
      'style="max-width:100%;border-radius:8px;' +
      'box-shadow:0 4px 20px rgba(0,0,0,0.3);' +
      'user-select:none;pointer-events:none;" ' +
      'draggable="false">' +
      '<div id="osm-countdown" style="margin-top:16px;' +
      'font-family:system-ui,monospace;font-size:18px;' +
      'font-weight:700;color:#ff4444;"></div>' +
      "</div>";

    container.style.display = "block";
  }

  /**
   * Show expired message after countdown.
   */
  function showExpiredMessage() {
    const container = document.getElementById("osm-code-container");
    if (!container) return;

    container.innerHTML =
      '<div style="text-align:center;padding:24px;' +
      'background:rgba(0,0,0,0.8);border-radius:12px;color:#fff;">'+ 
      '<div style="font-size:48px;margin-bottom:16px;">&#8987;</div>' +
      '<div style="font-size:20px;font-weight:700;margin-bottom:12px;">' +
      "Code Expired" +
      "</div>" +
      '<div style="font-size:14px;opacity:0.8;">' +
      "The gift code display has expired for security reasons. " +
      "Please request a new code if needed." +
      "</div>" +
      '<a href="/gift" style="display:inline-block;margin-top:16px;' +
      "padding:10px 24px;background:#444;color:#fff;border-radius:6px;" +
      'text-decoration:none;font-weight:600;">' +
      "Back to Gift Page" +
      "</a></div>";
  }

  /**
   * Update countdown display.
   * @param {number} seconds - Remaining seconds.
   */
  function updateCountdown(seconds) {
    const el = document.getElementById("osm-countdown");
    if (!el) return;

    el.textContent = "Code expires in " + seconds + " second" + (seconds !== 1 ? "s" : "");

    if (seconds <= 3) {
      el.style.color = "#ff0000";
    } else if (seconds <= 5) {
      el.style.color = "#ff6600";
    }
  }

  /**
   * Start countdown timer for code reveal.
   * @returns {Promise<void>} Resolves when countdown completes.
   */
  function startCountdown() {
    return new Promise(function (resolve) {
      state.countdownRemaining = CONFIG.REVEAL_COUNTDOWN_SEC;
      updateCountdown(state.countdownRemaining);

      state.countdownTimer = setInterval(function () {
        state.countdownRemaining--;
        updateCountdown(state.countdownRemaining);

        if (state.countdownRemaining <= 0) {
          clearInterval(state.countdownTimer);
          state.countdownTimer = null;
          resolve();
        }
      }, 1000);
    });
  }

  // ============================================================================
  // TOKEN MANAGEMENT
  // ============================================================================

  /**
   * Get token from URL query parameter.
   * @returns {string|null} Token or null if not found.
   */
  function getTokenFromUrl() {
    try {
      if (typeof window === "undefined" || !window.location) return null;
      const params = new URLSearchParams(window.location.search);
      return params.get(CONFIG.TOKEN_PARAM);
    } catch (_e) {
      return null;
    }
  }

  /**
   * Validate token format.
   * Token must be base64url encoded, exactly 43 characters.
   * @param {string} token - Token to validate.
   * @returns {boolean} True if format is valid.
   */
  function validateTokenFormat(token) {
    if (!token || typeof token !== "string") return false;
    if (token.length !== CONFIG.TOKEN_LENGTH) return false;

    // Base64url regex: A-Z, a-z, 0-9, -, _
    const base64urlRegex = /^[A-Za-z0-9_-]+$/;
    return base64urlRegex.test(token);
  }

  /**
   * Verify token with server.
   * @param {string} token - Token to verify.
   * @returns {Promise<object>} Verification result.
   */
  async function verifyTokenWithServer(token) {
    const response = await fetch(CONFIG.API_VERIFY_TOKEN + "?token=" + encodeURIComponent(token), {
      method: "GET",
      headers: {
        "Accept": "application/json",
      },
    });

    if (!response.ok) {
      if (response.status === 404) {
        throw new Error("Token not found or already used");
      }
      if (response.status === 410) {
        throw new Error("Token expired");
      }
      throw new Error("Server error: " + response.status);
    }

    return await response.json();
  }

  /**
   * Check token expiry.
   * @returns {boolean} True if token has expired.
   */
  function isTokenExpired() {
    if (!state.tokenExpiry) return false;
    return Date.now() > state.tokenExpiry - CONFIG.TOKEN_EXPIRY_BUFFER_MS;
  }

  // ============================================================================
  // FACTOR 1 - SERVER PROOF (AUTO)
  // ============================================================================

  /**
   * Get the current day's seed from the server or compute locally.
   * Uses the server-provided seed if available, falls back to date-based.
   * @returns {Promise<string>} Daily seed string.
   */
  async function getDailySeed() {
    try {
      const response = await fetch("/api/v1/daily-seed", {
        method: "GET",
        headers: { "Accept": "application/json" },
      });

      if (response.ok) {
        const data = await response.json();
        if (data.seed) return data.seed;
      }
    } catch (_e) {
      // Fall back to local computation
    }

    // Fallback: compute from current UTC date (YYYYMMDD)
    const now = new Date();
    const year = now.getUTCFullYear();
    const month = String(now.getUTCMonth() + 1).padStart(2, "0");
    const day = String(now.getUTCDate()).padStart(2, "0");
    return "osm-seed-" + year + month + day;
  }

  /**
   * Execute Factor 1: Server proof via HMAC challenge-response.
   * @param {string} token - Gift code token.
   * @returns {Promise<object>} Server response.
   */
  async function executeFactor1(token) {
    state.currentStep = STEPS.FACTOR1;
    updateProgress(15, "Verifying server challenge...", "Factor 1/3");

    if (state.factor1Attempts >= CONFIG.FACTOR1_MAX_RETRIES) {
      throw new Error(
        "Too many Factor 1 attempts. Please refresh the page to try again."
      );
    }

    state.factor1Attempts++;

    // Get daily seed
    const dailySeed = await getDailySeed();
    const timestamp = Math.floor(Date.now() / 1000);

    // Generate HMAC: HMAC-SHA512(dailySeed + token + timestamp)
    const message = dailySeed + token + timestamp;
    const hmac = await hmacSha512(dailySeed, message);

    // Extract first 8 characters as response
    const response = hmac.substring(0, 8);
    state.factor1Response = response;

    secLog("Factor 1 generated response", { attempt: state.factor1Attempts });

    // Submit to server
    const result = await fetchWithRetry(CONFIG.API_FACTOR1, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-OSM-Token": token,
      },
      body: JSON.stringify({
        token: token,
        response: response,
        timestamp: timestamp,
        attempt: state.factor1Attempts,
      }),
    });

    if (!result.success) {
      if (result.reason === "invalid_response") {
        throw new Error(
          "Server verification failed. Please refresh and try again."
        );
      }
      if (result.reason === "rate_limited") {
        state.rateLimitExpiry = result.retryAfter;
        throw new Error("Rate limited. Please wait before trying again.");
      }
      throw new Error(result.message || "Factor 1 verification failed");
    }

    state.factorResults.factor1 = true;
    updateProgress(33, "Server verification complete", "Factor 1/3");
    secLog("Factor 1 passed");

    return result;
  }

  // ============================================================================
  // FACTOR 2 - BEHAVIOR PROOF
  // ============================================================================

  /**
   * Execute Factor 2: Behavior proof submission.
   * Waits for behavior data collection then submits.
   * @param {string} token - Gift code token.
   * @returns {Promise<object>} Server response.
   */
  async function executeFactor2(token) {
    state.currentStep = STEPS.FACTOR2;
    updateProgress(50, "Analyzing behavior patterns...", "Factor 2/3");

    // Ensure behavior tracking is initialized
    if (typeof window.OSMBehavior === "undefined") {
      throw new Error(
        "Behavior tracking module not loaded. Please refresh the page."
      );
    }

    // Start behavior tracking
    window.OSMBehavior.init();

    // Wait for minimum behavior data with progress updates
    const startWait = Date.now();
    let progress = 50;

    while (!window.OSMBehavior.hasMinimumData()) {
      const elapsed = Date.now() - startWait;

      if (elapsed > CONFIG.BEHAVIOR_MAX_WAIT_MS) {
        throw new Error(
          "Behavior collection timed out. Please interact with the page more."
        );
      }

      // Update progress (50% -> 66%)
      const behaviorProgress = window.OSMBehavior.getCollectionProgress();
      progress = 50 + (behaviorProgress / 100) * 16;
      updateProgress(
        Math.round(progress),
        "Collecting behavior data... " + behaviorProgress + "%",
        "Factor 2/3"
      );

      await sleep(CONFIG.BEHAVIOR_POLL_INTERVAL_MS);
    }

    updateProgress(66, "Behavior data collected, submitting...", "Factor 2/3");

    // Collect and submit behavior data
    const behaviorData = window.OSMBehavior.collectBehaviorData();
    if (!behaviorData) {
      throw new Error(
        "Insufficient behavior data. Please move your mouse, scroll, and click around the page."
      );
    }

    // Submit to server
    const result = await fetchWithRetry(CONFIG.API_FACTOR2, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-OSM-Token": token,
      },
      body: JSON.stringify(behaviorData),
    });

    if (!result.success) {
      if (result.reason === "bot_detected") {
        throw new Error(
          "Automated behavior detected. " +
            "Please interact with the page naturally using your mouse."
        );
      }
      if (result.reason === "insufficient_data") {
        throw new Error(
          "Insufficient interaction data. " +
            "Please spend more time on the page and interact naturally."
        );
      }
      if (result.reason === "rate_limited") {
        state.rateLimitExpiry = result.retryAfter;
        throw new Error("Rate limited. Please wait before trying again.");
      }
      throw new Error(result.message || "Behavior verification failed");
    }

    state.factorResults.factor2 = true;
    updateProgress(66, "Behavior verification complete", "Factor 2/3");
    secLog("Factor 2 passed");

    return result;
  }

  // ============================================================================
  // FACTOR 3 - FINGERPRINT
  // ============================================================================

  /**
   * Execute Factor 3: Browser fingerprint submission.
   * @param {string} token - Gift code token.
   * @returns {Promise<object>} Server response.
   */
  async function executeFactor3(token) {
    state.currentStep = STEPS.FACTOR3;
    updateProgress(75, "Verifying browser identity...", "Factor 3/3");

    // Ensure fingerprint module is loaded
    if (typeof window.OSMFingerprint === "undefined") {
      throw new Error(
        "Fingerprint module not loaded. Please refresh the page."
      );
    }

    // Collect fingerprint
    const fingerprint = await window.OSMFingerprint.getFingerprint();
    const fingerprintHash = await window.OSMFingerprint.getFingerprintHash();

    secLog("Fingerprint collected", { hash: fingerprintHash.substring(0, 16) + "..." });

    // Submit to server
    const result = await fetchWithRetry(CONFIG.API_FACTOR3, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-OSM-Token": token,
      },
      body: JSON.stringify({
        token: token,
        fingerprint: fingerprint,
        fingerprintHash: fingerprintHash,
        timestamp: Math.floor(Date.now() / 1000),
      }),
    });

    if (!result.success) {
      if (result.reason === "fingerprint_mismatch") {
        throw new Error(
          "Browser verification failed. " +
            "The browser fingerprint does not match. " +
            "Please use the same browser and device."
        );
      }
      if (result.reason === "rate_limited") {
        state.rateLimitExpiry = result.retryAfter;
        throw new Error("Rate limited. Please wait before trying again.");
      }
      throw new Error(result.message || "Browser verification failed");
    }

    state.factorResults.factor3 = true;
    updateProgress(85, "Browser verification complete", "Factor 3/3");
    secLog("Factor 3 passed");

    return result;
  }

  // ============================================================================
  // CODE REVEAL
  // ============================================================================

  /**
   * Reveal the gift code image.
   * Fetches code image from server and displays it with countdown.
   * @param {string} token - Gift code token.
   * @returns {Promise<void>}
   */
  async function revealCode(token) {
    state.currentStep = STEPS.REVEALING;
    updateProgress(90, "Retrieving your gift code...", "Revealing");

    // Build reveal URL with anti-caching token
    const cacheBuster = Date.now();
    const revealUrl =
      CONFIG.API_REVEAL +
      "?token=" +
      encodeURIComponent(token) +
      "&_=" +
      cacheBuster;

    // Fetch as blob to create object URL
    const response = await fetch(revealUrl, {
      method: "GET",
      headers: {
        "Accept": "image/png,image/jpeg,image/*",
        "X-OSM-Token": token,
      },
    });

    if (!response.ok) {
      if (response.status === 404) {
        throw new Error("Code not found or already claimed");
      }
      if (response.status === 410) {
        throw new Error("Code has expired");
      }
      throw new Error("Failed to retrieve code: " + response.status);
    }

    const blob = await response.blob();
    const imageUrl = URL.createObjectURL(blob);

    // Display code image
    showCodeImage(imageUrl);
    updateProgress(100, "Code revealed!", "Complete");

    state.currentStep = STEPS.COMPLETE;

    secLog("Code revealed");

    // Start countdown timer
    await startCountdown();

    // After countdown: remove image and show expired
    URL.revokeObjectURL(imageUrl);
    showExpiredMessage();

    secLog("Code reveal expired");
  }

  // ============================================================================
  // HTTP UTILITY
  // ============================================================================

  /**
   * Fetch with retry logic and exponential backoff.
   * @param {string} url - URL to fetch.
   * @param {object} options - Fetch options.
   * @returns {Promise<object>} Parsed JSON response.
   */
  async function fetchWithRetry(url, options) {
    let lastError;

    for (let attempt = 0; attempt < CONFIG.RETRY_MAX_ATTEMPTS; attempt++) {
      try {
        const response = await fetch(url, options);

        // Parse response
        const contentType = response.headers.get("content-type") || "";
        let data;

        if (contentType.includes("application/json")) {
          data = await response.json();
        } else {
          const text = await response.text();
          data = { success: response.ok, raw: text };
        }

        // Handle HTTP errors
        if (!response.ok) {
          if (response.status === 429) {
            // Rate limited
            const retryAfter = response.headers.get("Retry-After");
            return {
              success: false,
              reason: "rate_limited",
              retryAfter: retryAfter ? parseInt(retryAfter, 10) * 1000 : Date.now() + 60000,
              message: "Rate limited. Please wait.",
            };
          }

          if (response.status >= 500) {
            throw new Error("Server error: " + response.status);
          }

          return {
            success: false,
            ...data,
          };
        }

        return data;
      } catch (error) {
        lastError = error;

        // Don't retry on client errors (4xx except 429)
        if (error.message && error.message.includes("4") && !error.message.includes("429")) {
          throw error;
        }

        if (attempt < CONFIG.RETRY_MAX_ATTEMPTS - 1) {
          const delay = backoffDelay(attempt);
          secLog("Retry " + (attempt + 1) + "/" + CONFIG.RETRY_MAX_ATTEMPTS + " after " + delay + "ms");
          await sleep(delay);
        }
      }
    }

    throw new Error(
      "Request failed after " + CONFIG.RETRY_MAX_ATTEMPTS + " attempts: " + lastError.message
    );
  }

  // ============================================================================
  // RATE LIMIT HANDLING
  // ============================================================================

  /**
   * Wait until rate limit expires.
   * @returns {Promise<void>}
   */
  async function waitForRateLimit() {
    if (!state.rateLimitExpiry) return;

    const now = Date.now();
    const waitMs = state.rateLimitExpiry - now;

    if (waitMs <= 0) {
      state.rateLimitExpiry = null;
      return;
    }

    updateProgress(
      0,
      "Rate limited. Waiting " + Math.ceil(waitMs / 1000) + " seconds...",
      "Waiting"
    );

    await sleep(waitMs);
    state.rateLimitExpiry = null;
  }

  // ============================================================================
  // PROGRESSIVE FLOW CONTROLLER
  // ============================================================================

  /**
   * Start the complete 3-factor decryption flow.
   * Orchestrates all steps from token validation through code reveal.
   * @returns {Promise<void>}
   */
  async function startDecryptionFlow() {
    if (state.flowStarted) return;
    state.flowStarted = true;

    secLog("Starting decryption flow");

    try {
      // Step 1: Validate token
      state.currentStep = STEPS.VALIDATING;
      updateProgress(5, "Validating access token...", "Validating");

      const token = getTokenFromUrl();

      if (!token) {
        showError(
          "Missing Token",
          "No gift code token found. Please visit the gift page to request a code.",
          { redirect: true, redirectUrl: "/gift" }
        );
        state.currentStep = STEPS.ERROR;
        return;
      }

      if (!validateTokenFormat(token)) {
        showError(
          "Invalid Token",
          "The token format is invalid. Please check your link and try again.",
          { redirect: true, redirectUrl: "/gift" }
        );
        state.currentStep = STEPS.ERROR;
        return;
      }

      state.token = token;

      // Verify token with server
      try {
        const verification = await verifyTokenWithServer(token);
        state.tokenExpiry = verification.expiresAt
          ? new Date(verification.expiresAt).getTime()
          : null;

        if (isTokenExpired()) {
          showError(
            "Token Expired",
            "This gift code link has expired. Please request a new one.",
            { redirect: true, redirectUrl: "/gift" }
          );
          state.currentStep = STEPS.EXPIRED;
          return;
        }
      } catch (verifyError) {
        if (verifyError.message.includes("expired")) {
          showError(
            "Token Expired",
            "This gift code link has expired. Please request a new one.",
            { redirect: true, redirectUrl: "/gift" }
          );
          state.currentStep = STEPS.EXPIRED;
          return;
        }
        // Non-fatal: continue even if server verification fails
        secLog("Token verification warning: " + verifyError.message);
      }

      updateProgress(10, "Token validated", "Validated");

      // Step 2: Factor 1 (auto)
      await executeFactor1(token);

      // Step 3: Factor 2 (behavior)
      await executeFactor2(token);

      // Step 4: Factor 3 (fingerprint)
      await executeFactor3(token);

      // Step 5: Reveal code
      await revealCode(token);
    } catch (error) {
      secLog("Flow error: " + error.message, { step: state.currentStep });

      // Handle specific error types
      if (error.message.includes("expired")) {
        state.currentStep = STEPS.EXPIRED;
        showError(
          "Session Expired",
          error.message,
          { redirect: true, redirectUrl: "/gift" }
        );
      } else if (error.message.includes("Rate limited")) {
        // Wait and retry
        await waitForRateLimit();
        state.flowStarted = false;
        startDecryptionFlow();
      } else if (error.message.includes("bot") || error.message.includes("automated")) {
        state.currentStep = STEPS.BLOCKED;
        showError(
          "Bot Detection",
          error.message,
          { retry: true }
        );
      } else if (error.message.includes("Timed out") || error.message.includes("Network")) {
        showError(
          "Connection Error",
          "Network error: " + error.message + ". Please check your connection and retry.",
          { retry: true }
        );
      } else {
        showError(
          "Error",
          error.message,
          { retry: true }
        );
      }

      if (state.currentStep !== STEPS.EXPIRED && state.currentStep !== STEPS.BLOCKED) {
        state.currentStep = STEPS.ERROR;
      }
    }
  }

  /**
   * Reset the flow state for retry.
   */
  function resetFlow() {
    // Stop any active timers
    if (state.countdownTimer) {
      clearInterval(state.countdownTimer);
      state.countdownTimer = null;
    }
    if (state.pollingInterval) {
      clearInterval(state.pollingInterval);
      state.pollingInterval = null;
    }

    state.currentStep = STEPS.IDLE;
    state.factor1Attempts = 0;
    state.factor1Response = null;
    state.factor2Response = null;
    state.factor3Response = null;
    state.behaviorReady = false;
    state.fingerprintReady = false;
    state.countdownRemaining = 0;
    state.errorMessage = null;
    state.flowStarted = false;
    state.factorResults = { factor1: false, factor2: false, factor3: false };

    hideError();

    secLog("Flow reset");
  }

  /**
   * Cancel the active flow.
   */
  function cancelFlow() {
    resetFlow();
    state.flowStarted = true; // Prevent auto-restart

    // Stop behavior tracking
    if (typeof window.OSMBehavior !== "undefined") {
      window.OSMBehavior.stop();
    }

    updateProgress(0, "Cancelled", "");
    secLog("Flow cancelled");
  }

  // ============================================================================
  // DOM READY INITIALIZATION
  // ============================================================================

  /**
   * Check if all required modules are loaded.
   * @returns {boolean} True if all modules available.
   */
  function checkRequiredModules() {
    return (
      typeof window.OSMSecure !== "undefined" &&
      typeof window.OSMBehavior !== "undefined" &&
      typeof window.OSMFingerprint !== "undefined"
    );
  }

  /**
   * Wait for required modules to load.
   * @param {number} [timeoutMs=10000] - Maximum wait time.
   * @returns {Promise<boolean>} True if all modules loaded.
   */
  async function waitForModules(timeoutMs) {
    if (timeoutMs === void 0) timeoutMs = 10000;
    const start = Date.now();

    while (Date.now() - start < timeoutMs) {
      if (checkRequiredModules()) return true;
      await sleep(100);
    }

    return false;
  }

  /**
   * Auto-start the flow when page loads.
   */
  async function autoStart() {
    secLog("Auto-starting decryption flow");

    // Wait for all required modules
    const modulesReady = await waitForModules(15000);
    if (!modulesReady) {
      showError(
        "Loading Error",
        "Required modules failed to load. Please refresh the page.",
        { retry: true }
      );
      return;
    }

    // Small delay to let UI settle
    await sleep(500);

    // Start the flow
    await startDecryptionFlow();
  }

  // ============================================================================
  // SECURE CODE DISPLAY
  // ============================================================================

  /**
   * Show the securely fragmented code display.
   * Creates a container div, injects CSS into a <style> tag,
   * and injects HTML into the container.
   * @param {string} html - Fragmented HTML from server.
   * @param {string} css - Generated CSS with ::before rules.
   * @param {string} code - The actual code (stored for copy).
   * @returns {HTMLElement} The display container element.
   */
  function showCodeDisplay(html, css, code) {
    if (typeof document === "undefined") return null;

    // Find or create the secure display container
    let container = document.getElementById("_osm-secure-display");
    if (!container) {
      container = document.createElement("div");
      container.id = "_osm-secure-display-container";
      container.style.cssText =
        "text-align:center;padding:1.5rem;background:var(--bg-secondary);" +
        "border:1px solid var(--border);border-radius:var(--radius-sm);" +
        "min-height:80px;display:flex;align-items:center;justify-content:center;";
    }

    // Inject CSS
    let styleEl = document.getElementById("_osm-secure-style");
    if (!styleEl) {
      styleEl = document.createElement("style");
      styleEl.id = "_osm-secure-style";
      styleEl.type = "text/css";
      document.head.appendChild(styleEl);
    }
    styleEl.textContent = css;

    // Set the HTML content
    container.innerHTML = html;

    // Store the real code on a data attribute for copy access
    container.setAttribute("data-real-code", code);

    // Animate entrance
    container.style.opacity = "0";
    container.style.transform = "scale(0.95)";
    container.style.transition = "opacity 0.4s ease, transform 0.4s ease";

    requestAnimationFrame(function () {
      container.style.opacity = "1";
      container.style.transform = "scale(1)";
    });

    return container;
  }

  /**
   * Copy the gift code to the clipboard.
   * Uses navigator.clipboard.writeText() with fallback to
   * document.execCommand('copy').
   * @param {string} code - The code to copy.
   * @returns {Promise<boolean>} True if copy succeeded.
   */
  async function copyCodeToClipboard(code) {
    if (!code || typeof code !== "string") return false;

    try {
      // Primary: Modern Clipboard API
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(code);
        return true;
      }

      // Fallback: Create temporary textarea
      const textarea = document.createElement("textarea");
      textarea.value = code;
      textarea.style.cssText =
        "position:fixed;left:-9999px;top:-9999px;opacity:0;pointer-events:none;";
      document.body.appendChild(textarea);
      textarea.focus();
      textarea.select();

      const success = document.execCommand("copy");
      document.body.removeChild(textarea);
      return success;
    } catch (err) {
      secLog("Clipboard copy failed: " + err.message);
      return false;
    }
  }

  /**
   * Start the auto-destruct countdown for secure display.
   * 10-second countdown with visual progress bar.
   * At 0: blurs code, shows "Expired" message, removes DOM elements.
   * @param {HTMLElement} [codeElement] - The code display element.
   * @param {HTMLElement} [countdownElement] - Progress bar fill element.
   * @param {HTMLElement} [timeElement] - Time remaining text element.
   * @param {number} [durationMs] - Countdown duration in ms.
   */
  function startSecureAutoDestruct(
    codeElement,
    countdownElement,
    timeElement,
    durationMs
  ) {
    if (durationMs === void 0) durationMs = CONFIG.REVEAL_COUNTDOWN_SEC * 1000;

    const startTime = Date.now();
    const codeEl =
      codeElement || document.getElementById("_osm-secure-display");
    const fillEl =
      countdownElement || document.getElementById("_osm-progress-fill");
    const timeEl = timeElement || document.getElementById("_osm-time-text");
    const expiredEl = document.getElementById("_osm-expired");
    const mainContainer = document.getElementById("code-display-container");

    function tick() {
      const elapsed = Date.now() - startTime;
      const remaining = Math.max(0, durationMs - elapsed);
      const pct = (remaining / durationMs) * 100;

      if (fillEl) fillEl.style.width = pct + "%";
      if (timeEl) timeEl.textContent = (remaining / 1000).toFixed(1) + "s";

      if (remaining > 0) {
        requestAnimationFrame(tick);
      } else {
        // Auto-destruct: blur, then remove
        if (codeEl) {
          codeEl.style.filter = "blur(20px)";
          codeEl.style.opacity = "0.3";
          codeEl.style.transition = "all 0.5s ease";
        }

        setTimeout(function () {
          // Remove all code-related DOM elements
          if (codeEl) {
            codeEl.innerHTML = "";
            codeEl.removeAttribute("data-real-code");
          }

          // Hide main container, show expired
          if (mainContainer) {
            mainContainer.style.display = "none";
          }
          if (expiredEl) {
            expiredEl.style.display = "block";
          }

          // Remove the injected style tag
          const styleEl = document.getElementById("_osm-secure-style");
          if (styleEl && styleEl.parentNode) {
            styleEl.parentNode.removeChild(styleEl);
          }

          secLog("Secure display auto-destructed");
        }, 500);
      }
    }

    requestAnimationFrame(tick);
  }

  /**
   * Handle the copy button click event.
   * Copies the code, shows visual feedback, displays toast,
   * and logs the copy event for analytics.
   */
  async function handleCopyButtonClick() {
    // Get the real code from the display container
    const displayContainer = document.getElementById("_osm-secure-display");
    if (!displayContainer) return;

    const code = displayContainer.getAttribute("data-real-code");
    if (!code) return;

    const success = await copyCodeToClipboard(code);

    if (success) {
      // Visual feedback: button pulse + checkmark
      const btn = document.getElementById("_osm-copy-btn");
      if (btn) {
        btn.classList.add("_osm-copied");
        const textSpan = btn.querySelector("._osm-btn-text");
        if (textSpan) textSpan.textContent = "COPIED!";

        setTimeout(function () {
          btn.classList.remove("_osm-copied");
          if (textSpan) textSpan.textContent = "COPY CODE";
        }, 2000);
      }

      // Show toast notification
      showToastNotification("\u2705 Code copied to clipboard!", "success");

      // Analytics: log copy event
      try {
        fetch("/api/v1/log-copy", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            token: state.token,
            timestamp: new Date().toISOString(),
            step: state.currentStep,
          }),
        });
      } catch (_e) {
        // Non-fatal
      }
    } else {
      showToastNotification("\u274C Copy failed. Please type the code manually.", "error");
    }
  }

  /**
   * Show a toast notification message.
   * @param {string} message - Toast message.
   * @param {string} [type="info"] - Toast type: success, error, warning, info.
   */
  function showToastNotification(message, type) {
    if (type === void 0) type = "info";
    if (typeof document === "undefined") return;

    const container = document.getElementById("toast-container");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = "toast " + type;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(function () {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 4000);
  }

  /**
   * Fetch and display the secure code from the server.
   * Calls the server API to get fragmented HTML/CSS, then renders it.
   * @param {string} token - The access token.
   * @returns {Promise<void>}
   */
  async function fetchAndDisplaySecureCode(token) {
    try {
      const response = await fetch(
        "/api/v1/secure-display?token=" + encodeURIComponent(token),
        {
          method: "GET",
          headers: {
            Accept: "application/json",
            "X-OSM-Token": token,
          },
        }
      );

      if (!response.ok) {
        throw new Error("Failed to fetch secure display: " + response.status);
      }

      const data = await response.json();

      // Render the secure display
      showCodeDisplay(data.html, data.css, data.code);

      // Update the countdown element references if present
      startSecureAutoDestruct();

      // Attach copy button handler
      const copyBtn = document.getElementById("_osm-copy-btn");
      if (copyBtn) {
        copyBtn.addEventListener("click", handleCopyButtonClick);
      }

      secLog("Secure code display rendered", {
        strategy: data.meta && data.meta.strategy,
        spanCount: data.meta && data.meta.spanCount,
      });
    } catch (err) {
      secLog("Secure display failed, falling back to image: " + err.message);
      // Fall back to image-based reveal if secure display fails
      await revealCode(token);
    }
  }

  // ============================================================================
  // PUBLIC API
  // ============================================================================

  /**
   * Public API for the decryption controller.
   * @namespace OSMFragment
   */
  const OSMFragment = Object.freeze({
    // Flow control
    start: startDecryptionFlow,
    startDecryptionFlow: startDecryptionFlow,
    reset: resetFlow,
    resetFlow: resetFlow,
    cancel: cancelFlow,

    // Token
    getToken: function () {
      return state.token;
    },
    validateTokenFormat: validateTokenFormat,

    // Individual factors (for advanced use)
    executeFactor1: executeFactor1,
    executeFactor2: executeFactor2,
    executeFactor3: executeFactor3,
    revealCode: revealCode,

    // Secure display
    showCodeDisplay: showCodeDisplay,
    copyCodeToClipboard: copyCodeToClipboard,
    startSecureAutoDestruct: startSecureAutoDestruct,
    handleCopyButtonClick: handleCopyButtonClick,
    fetchAndDisplaySecureCode: fetchAndDisplaySecureCode,

    // State
    getState: function () {
      return {
        currentStep: state.currentStep,
        token: state.token ? state.token.substring(0, 8) + "..." : null,
        factorResults: { ...state.factorResults },
        factor1Attempts: state.factor1Attempts,
        isComplete: state.currentStep === STEPS.COMPLETE,
      };
    },
    getCurrentStep: function () {
      return state.currentStep;
    },
    isComplete: function () {
      return state.currentStep === STEPS.COMPLETE;
    },

    // Steps enum
    STEPS: STEPS,

    // Version
    version: "1.0.0",
  });

  // Attach to global scope
  if (typeof window !== "undefined") {
    window.OSMFragment = OSMFragment;
  }

  // Auto-start on DOM ready
  if (typeof document !== "undefined") {
    if (
      document.readyState === "complete" ||
      document.readyState === "interactive"
    ) {
      autoStart();
    } else {
      document.addEventListener("DOMContentLoaded", autoStart);
      window.addEventListener("load", autoStart);
    }
  }
})();
