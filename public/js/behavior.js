/**
 * @fileoverview behavior.js - Client-side Mouse/Scroll/Interaction Tracking
 * @description Captures and analyzes user interaction patterns including mouse
 * movements, scroll behavior, click patterns, and timing analysis. Computes
 * entropy scores, bot detection metrics, and submits behavior proofs to the
 * server as Factor 2 of the 3-factor authentication system.
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
    // Minimum thresholds for data collection
    MIN_MOUSE_MOVES: 50,
    MIN_CLICKS: 3,
    MIN_SCROLL_EVENTS: 2,
    MIN_INTERACTION_TIME_MS: 5000,

    // Tracking configuration
    MOUSE_SAMPLE_INTERVAL_MS: 16, // ~60fps sampling
    SCROLL_SAMPLE_INTERVAL_MS: 50,

    // Analysis thresholds
    TELEPORT_DISTANCE_PX: 500,
    PAUSE_THRESHOLD_MS: 200,
    SCROLL_PAUSE_THRESHOLD_MS: 500,
    BURST_EVENT_COUNT: 5,
    BURST_TIME_WINDOW_MS: 100,

    // Entropy / scoring
    ENTROPY_BUCKETS: 16,
    MAX_SPEED_CAP: 5000, // px/sec

    // Submission
    API_FACTOR2_ENDPOINT: "/api/v1/factor/2",
    SUBMISSION_RETRY_MAX: 3,
    SUBMISSION_RETRY_BASE_MS: 1000,

    // Display
    PROGRESS_UPDATE_INTERVAL_MS: 500,
    DEBUG: false,
  });

  // ============================================================================
  // STATE
  // ============================================================================

  /** @type {boolean} Whether tracking is active. */
  let trackingActive = false;

  /** @type {boolean} Whether minimum data has been collected. */
  let minimumMet = false;

  /** @type {boolean} Whether data has already been submitted. */
  let submitted = false;

  /** @type {number} Timestamp when tracking started. */
  let trackingStartTime = 0;

  /** @type {number} Timestamp of first user interaction. */
  let firstInteractionTime = 0;

  /** @type {number} Timestamp of last tracked event. */
  let lastEventTime = 0;

  /** @type {number} Page load timestamp. */
  let pageLoadTime = 0;

  // Mouse tracking state
  /** @type {Array<object>} Raw mouse move events. */
  let mouseMoves = [];

  /** @type {Array<object>} Mouse click events. */
  let mouseClicks = [];

  /** @type {Array<object>} Mouse down events. */
  let mouseDowns = [];

  /** @type {Array<object>} Mouse up events. */
  let mouseUps = [];

  /** @type {{x:number,y:number}|null} Last mouse position. */
  let lastMousePos = null;

  /** @type {number} Timestamp of last mouse move. */
  let lastMouseMoveTime = 0;

  // Scroll tracking state
  /** @type {Array<object>} Raw scroll events. */
  let scrollEvents = [];

  /** @type {number} Last scroll Y position. */
  let lastScrollY = 0;

  /** @type {number} Timestamp of last scroll. */
  let lastScrollTime = 0;

  // Burst detection state
  /** @type {Array<number>} Recent event timestamps. */
  let recentEventTimes = [];

  // Computed metrics cache
  /** @type {object|null} Cached computed metrics. */
  let cachedMetrics = null;

  // Progress display
  /** @type {number|null} Progress interval ID. */
  let progressInterval = null;

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
   * Euclidean distance between two points.
   * @param {number} x1 - First x coordinate.
   * @param {number} y1 - First y coordinate.
   * @param {number} x2 - Second x coordinate.
   * @param {number} y2 - Second y coordinate.
   * @returns {number} Distance in pixels.
   */
  function distance(x1, y1, x2, y2) {
    const dx = x2 - x1;
    const dy = y2 - y1;
    return Math.sqrt(dx * dx + dy * dy);
  }

  /**
   * Angle between two consecutive movement vectors.
   * @param {number} x1 - First point x.
   * @param {number} y1 - First point y.
   * @param {number} x2 - Mid point x.
   * @param {number} y2 - Mid point y.
   * @param {number} x3 - End point x.
   * @param {number} y3 - End point y.
   * @returns {number} Angle change in radians.
   */
  function angleChange(x1, y1, x2, y2, x3, y3) {
    const ax = x2 - x1;
    const ay = y2 - y1;
    const bx = x3 - x2;
    const by = y3 - y2;
    const dot = ax * bx + ay * by;
    const magA = Math.sqrt(ax * ax + ay * ay);
    const magB = Math.sqrt(bx * bx + by * by);
    if (magA === 0 || magB === 0) return 0;
    const cosTheta = Math.max(-1, Math.min(1, dot / (magA * magB)));
    return Math.acos(cosTheta);
  }

  /**
   * Calculate Shannon entropy of a probability distribution.
   * @param {Array<number>} probabilities - Probability values summing to 1.
   * @returns {number} Shannon entropy in bits.
   */
  function shannonEntropy(probabilities) {
    let entropy = 0;
    for (let i = 0; i < probabilities.length; i++) {
      const p = probabilities[i];
      if (p > 0) {
        entropy -= p * Math.log2(p);
      }
    }
    return entropy;
  }

  /**
   * Calculate mean of an array.
   * @param {Array<number>} arr - Number array.
   * @returns {number} Mean value.
   */
  function mean(arr) {
    if (!arr || arr.length === 0) return 0;
    let sum = 0;
    for (let i = 0; i < arr.length; i++) sum += arr[i];
    return sum / arr.length;
  }

  /**
   * Calculate standard deviation.
   * @param {Array<number>} arr - Number array.
   * @returns {number} Standard deviation.
   */
  function stdDev(arr) {
    if (!arr || arr.length < 2) return 0;
    const avg = mean(arr);
    let sumSq = 0;
    for (let i = 0; i < arr.length; i++) {
      const diff = arr[i] - avg;
      sumSq += diff * diff;
    }
    return Math.sqrt(sumSq / (arr.length - 1));
  }

  /**
   * Calculate coefficient of variation (stdDev / mean).
   * @param {Array<number>} arr - Number array.
   * @returns {number} CV value.
   */
  function coefficientOfVariation(arr) {
    const avg = mean(arr);
    if (avg === 0) return 0;
    return stdDev(arr) / avg;
  }

  /**
   * Log debug messages.
   * @param {string} message - Message to log.
   * @param {object} [meta] - Extra data.
   */
  function secLog(message, meta) {
    if (CONFIG.DEBUG && typeof console !== "undefined") {
      console.debug("[OSM-BEHAVIOR]", message, meta || "");
    }
  }

  // ============================================================================
  // MOUSE TRACKING
  // ============================================================================

  /**
   * Handle mouse move event.
   * @param {MouseEvent} e - Mouse event.
   */
  function handleMouseMove(e) {
    if (!trackingActive) return;

    const now = hrNow();

    // Throttle sampling to ~60fps
    if (now - lastMouseMoveTime < CONFIG.MOUSE_SAMPLE_INTERVAL_MS) return;

    // Record first interaction
    if (firstInteractionTime === 0) {
      firstInteractionTime = now;
    }
    lastEventTime = now;

    const pos = { x: e.clientX, y: e.clientY };

    const event = {
      type: "move",
      x: pos.x,
      y: pos.y,
      time: now,
      button: -1,
      target: e.target ? e.target.tagName : "UNKNOWN",
    };

    mouseMoves.push(event);
    lastMousePos = pos;
    lastMouseMoveTime = now;

    // Burst detection
    recordEventForBurst(now);

    // Invalidate cached metrics
    cachedMetrics = null;
  }

  /**
   * Handle mouse click event.
   * @param {MouseEvent} e - Mouse event.
   */
  function handleMouseClick(e) {
    if (!trackingActive) return;

    const now = hrNow();
    if (firstInteractionTime === 0) firstInteractionTime = now;
    lastEventTime = now;

    const event = {
      type: "click",
      x: e.clientX,
      y: e.clientY,
      time: now,
      button: e.button,
      target: e.target ? e.target.tagName : "UNKNOWN",
    };

    mouseClicks.push(event);

    recordEventForBurst(now);
    cachedMetrics = null;
  }

  /**
   * Handle mouse down event.
   * @param {MouseEvent} e - Mouse event.
   */
  function handleMouseDown(e) {
    if (!trackingActive) return;

    const now = hrNow();
    if (firstInteractionTime === 0) firstInteractionTime = now;
    lastEventTime = now;

    mouseDowns.push({
      type: "down",
      x: e.clientX,
      y: e.clientY,
      time: now,
      button: e.button,
      target: e.target ? e.target.tagName : "UNKNOWN",
    });

    recordEventForBurst(now);
    cachedMetrics = null;
  }

  /**
   * Handle mouse up event.
   * @param {MouseEvent} e - Mouse event.
   */
  function handleMouseUp(e) {
    if (!trackingActive) return;

    const now = hrNow();
    if (firstInteractionTime === 0) firstInteractionTime = now;
    lastEventTime = now;

    mouseUps.push({
      type: "up",
      x: e.clientX,
      y: e.clientY,
      time: now,
      button: e.button,
      target: e.target ? e.target.tagName : "UNKNOWN",
    });

    recordEventForBurst(now);
    cachedMetrics = null;
  }

  // ============================================================================
  // SCROLL TRACKING
  // ============================================================================

  /**
   * Handle scroll event.
   * @param {Event} _e - Scroll event (unused).
   */
  function handleScroll(_e) {
    if (!trackingActive) return;

    const now = hrNow();

    // Throttle scroll sampling
    if (now - lastScrollTime < CONFIG.SCROLL_SAMPLE_INTERVAL_MS) return;

    if (firstInteractionTime === 0) firstInteractionTime = now;
    lastEventTime = now;

    const currentY =
      window.scrollY || window.pageYOffset || document.documentElement.scrollTop || 0;
    const delta = currentY - lastScrollY;
    const direction = delta >= 0 ? "down" : "up";

    // Calculate speed
    const timeDelta = now - lastScrollTime;
    const speed = timeDelta > 0 ? Math.abs(delta) / (timeDelta / 1000) : 0;

    if (Math.abs(delta) > 0) {
      const event = {
        type: "scroll",
        position: { x: window.scrollX || 0, y: currentY },
        direction: direction,
        speed: Math.round(speed),
        time: now,
        delta: Math.abs(delta),
      };

      scrollEvents.push(event);
      lastScrollY = currentY;
      lastScrollTime = now;

      recordEventForBurst(now);
      cachedMetrics = null;
    }
  }

  // ============================================================================
  // BURST DETECTION
  // ============================================================================

  /**
   * Record event timestamp for burst detection.
   * A burst is >5 events in <100ms.
   * @param {number} timestamp - Event timestamp.
   */
  function recordEventForBurst(timestamp) {
    recentEventTimes.push(timestamp);

    // Remove timestamps outside the burst window
    const cutoff = timestamp - CONFIG.BURST_TIME_WINDOW_MS;
    while (
      recentEventTimes.length > 0 &&
      recentEventTimes[0] < cutoff
    ) {
      recentEventTimes.shift();
    }
  }

  /**
   * Check if current event rate indicates a burst.
   * @returns {boolean} True if burst detected.
   */
  function isBurstDetected() {
    return recentEventTimes.length >= CONFIG.BURST_EVENT_COUNT;
  }

  // ============================================================================
  // METRIC CALCULATIONS
  // ============================================================================

  /**
   * Calculate total mouse distance traveled.
   * @returns {number} Total distance in pixels.
   */
  function calculateTotalMouseDistance() {
    let total = 0;
    for (let i = 1; i < mouseMoves.length; i++) {
      total += distance(
        mouseMoves[i - 1].x,
        mouseMoves[i - 1].y,
        mouseMoves[i].x,
        mouseMoves[i].y
      );
    }
    return Math.round(total);
  }

  /**
   * Calculate speeds between consecutive mouse points.
   * @returns {Array<number>} Speeds in px/sec.
   */
  function calculateMouseSpeeds() {
    const speeds = [];
    for (let i = 1; i < mouseMoves.length; i++) {
      const dx = mouseMoves[i].x - mouseMoves[i - 1].x;
      const dy = mouseMoves[i].y - mouseMoves[i - 1].y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      const dt = mouseMoves[i].time - mouseMoves[i - 1].time;
      if (dt > 0) {
        const speed = dist / (dt / 1000);
        speeds.push(Math.min(speed, CONFIG.MAX_SPEED_CAP));
      }
    }
    return speeds;
  }

  /**
   * Count mouse direction changes.
   * A direction change is when the angle between consecutive segments > PI/4.
   * @returns {number} Direction change count.
   */
  function countDirectionChanges() {
    let changes = 0;
    for (let i = 2; i < mouseMoves.length; i++) {
      const angle = angleChange(
        mouseMoves[i - 2].x,
        mouseMoves[i - 2].y,
        mouseMoves[i - 1].x,
        mouseMoves[i - 1].y,
        mouseMoves[i].x,
        mouseMoves[i].y
      );
      if (angle > Math.PI / 4) {
        changes++;
      }
    }
    return changes;
  }

  /**
   * Count pause events (stops > 200ms).
   * @returns {number} Pause count.
   */
  function countMousePauses() {
    let pauses = 0;
    for (let i = 1; i < mouseMoves.length; i++) {
      const dt = mouseMoves[i].time - mouseMoves[i - 1].time;
      if (dt > CONFIG.PAUSE_THRESHOLD_MS) {
        pauses++;
      }
    }
    return pauses;
  }

  /**
   * Calculate Shannon entropy of mouse movement path directions.
   * Divides movement directions into buckets and computes entropy.
   * @returns {number} Normalized entropy score (0-1).
   */
  function calculatePathEntropy() {
    if (mouseMoves.length < 3) return 0;

    const buckets = new Array(CONFIG.ENTROPY_BUCKETS).fill(0);
    const totalSegments = mouseMoves.length - 1;

    for (let i = 1; i < mouseMoves.length; i++) {
      const dx = mouseMoves[i].x - mouseMoves[i - 1].x;
      const dy = mouseMoves[i].y - mouseMoves[i - 1].y;
      const angle = Math.atan2(dy, dx); // -PI to PI
      const normalizedAngle = (angle + Math.PI) / (2 * Math.PI); // 0 to 1
      const bucket = Math.min(
        Math.floor(normalizedAngle * CONFIG.ENTROPY_BUCKETS),
        CONFIG.ENTROPY_BUCKETS - 1
      );
      buckets[bucket]++;
    }

    const probabilities = buckets.map(function (count) {
      return count / totalSegments;
    });

    const maxEntropy = Math.log2(CONFIG.ENTROPY_BUCKETS);
    const entropy = shannonEntropy(probabilities);

    return Math.min(1, entropy / maxEntropy);
  }

  /**
   * Calculate curvature score of mouse path.
   * Higher = more curved/organic path. Lower = more straight/bot-like.
   * @returns {number} Curvature score (0-1).
   */
  function calculateCurvatureScore() {
    if (mouseMoves.length < 3) return 0;

    let totalCurvature = 0;
    let segments = 0;

    for (let i = 2; i < mouseMoves.length; i++) {
      const angle = angleChange(
        mouseMoves[i - 2].x,
        mouseMoves[i - 2].y,
        mouseMoves[i - 1].x,
        mouseMoves[i - 1].y,
        mouseMoves[i].x,
        mouseMoves[i].y
      );
      totalCurvature += angle;
      segments++;
    }

    // Normalize: avg angle change / PI (max possible is PI)
    if (segments === 0) return 0;
    return Math.min(1, (totalCurvature / segments) / Math.PI);
  }

  /**
   * Detect teleport events (instant large jumps > 500px).
   * @returns {number} Count of teleport events.
   */
  function countTeleportEvents() {
    let teleports = 0;
    for (let i = 1; i < mouseMoves.length; i++) {
      const dist = distance(
        mouseMoves[i - 1].x,
        mouseMoves[i - 1].y,
        mouseMoves[i].x,
        mouseMoves[i].y
      );
      const dt = mouseMoves[i].time - mouseMoves[i - 1].time;
      // Instant jump = large distance in very short time
      if (dist > CONFIG.TELEPORT_DISTANCE_PX && dt < 50) {
        teleports++;
      }
    }
    return teleports;
  }

  /**
   * Calculate total scroll distance.
   * @returns {number} Total pixels scrolled.
   */
  function calculateTotalScrollDistance() {
    let total = 0;
    for (let i = 0; i < scrollEvents.length; i++) {
      total += scrollEvents[i].delta;
    }
    return total;
  }

  /**
   * Count scroll direction changes.
   * @returns {number} Number of direction changes.
   */
  function countScrollDirectionChanges() {
    let changes = 0;
    for (let i = 1; i < scrollEvents.length; i++) {
      if (scrollEvents[i].direction !== scrollEvents[i - 1].direction) {
        changes++;
      }
    }
    return changes;
  }

  /**
   * Count scroll pauses (stops > 500ms = reading).
   * @returns {number} Pause count.
   */
  function countScrollPauses() {
    let pauses = 0;
    for (let i = 1; i < scrollEvents.length; i++) {
      const dt = scrollEvents[i].time - scrollEvents[i - 1].time;
      if (dt > CONFIG.SCROLL_PAUSE_THRESHOLD_MS) {
        pauses++;
      }
    }
    return pauses;
  }

  /**
   * Calculate scroll depth progression score.
   * 1.0 = perfect top-to-bottom reading. 0.0 = random jumps.
   * @returns {number} Depth progression score (0-1).
   */
  function calculateScrollDepthProgression() {
    if (scrollEvents.length < 2) return 0;

    let progressionScore = 0;
    let checks = 0;

    for (let i = 1; i < scrollEvents.length; i++) {
      const prevY = scrollEvents[i - 1].position.y;
      const currY = scrollEvents[i].position.y;
      const pageHeight =
        document.documentElement.scrollHeight - window.innerHeight;

      if (pageHeight <= 0) continue;

      // Check if scroll follows a natural top-to-bottom pattern
      // Small backtracking is normal, large jumps are suspicious
      const expectedDirection = prevY <= currY ? "down" : "up";
      const actualDirection = scrollEvents[i].direction;

      if (expectedDirection === actualDirection) {
        progressionScore += 1;
      } else {
        // Penalize direction changes proportionally
        const jumpSize = Math.abs(currY - prevY) / pageHeight;
        progressionScore += Math.max(0, 1 - jumpSize * 2);
      }
      checks++;
    }

    return checks > 0 ? progressionScore / checks : 0;
  }

  /**
   * Detect scroll momentum (smooth vs jerky).
   * @returns {number} Momentum score (0-1), higher = smoother.
   */
  function calculateScrollMomentum() {
    if (scrollEvents.length < 3) return 0;

    const speeds = scrollEvents.map(function (ev) {
      return ev.speed;
    });
    const speedStdDev = stdDev(speeds);
    const avgSpeed = mean(speeds);

    if (avgSpeed === 0) return 0;

    // Coefficient of variation of scroll speed
    const cv = speedStdDev / avgSpeed;

    // Lower CV = smoother scrolling = more human-like
    // Normalize: CV of 0 = smooth (1.0), CV of 3+ = jerky (0.0)
    return Math.max(0, Math.min(1, 1 - cv / 3));
  }

  /**
   * Calculate scroll speed variance.
   * @returns {number} Speed variance.
   */
  function calculateScrollSpeedVariance() {
    if (scrollEvents.length < 2) return 0;

    const speeds = scrollEvents.map(function (ev) {
      return ev.speed;
    });
    const avg = mean(speeds);
    if (avg === 0) return 0;

    return coefficientOfVariation(speeds);
  }

  /**
   * Count total burst events detected.
   * @returns {number} Burst count.
   */
  function countBursts() {
    if (recentEventTimes.length < CONFIG.BURST_EVENT_COUNT) return 0;
    // Return approximate number of bursts seen during tracking
    // We track the peak burst rate
    return Math.max(0, Math.floor((recentEventTimes.length - CONFIG.BURST_EVENT_COUNT) / 2));
  }

  // ============================================================================
  // COMPOSITE METRICS
  // ============================================================================

  /**
   * Compute all behavioral metrics.
   * @returns {object} Comprehensive metrics object.
   */
  function computeMetrics() {
    if (cachedMetrics) return cachedMetrics;

    const mouseSpeeds = calculateMouseSpeeds();
    const totalMouseDistance = calculateTotalMouseDistance();
    const interactionTimeMs =
      firstInteractionTime > 0 ? lastEventTime - firstInteractionTime : 0;

    const metrics = {
      // Timing
      pageLoadTime: pageLoadTime,
      firstInteractionTime: firstInteractionTime,
      interactionDelayMs: firstInteractionTime > 0 ? firstInteractionTime - pageLoadTime : 0,
      totalInteractionTimeMs: interactionTimeMs,
      lastEventTime: lastEventTime,

      // Mouse stats
      mouseMoveCount: mouseMoves.length,
      mouseClickCount: mouseClicks.length,
      mouseDownCount: mouseDowns.length,
      mouseUpCount: mouseUps.length,
      totalMouseDistancePx: totalMouseDistance,
      averageMouseSpeedPxPerSec: Math.round(mean(mouseSpeeds)),
      mouseSpeedVariance: coefficientOfVariation(mouseSpeeds),
      mouseDirectionChanges: countDirectionChanges(),
      mousePauseCount: countMousePauses(),
      mouseTeleportCount: countTeleportEvents(),

      // Mouse quality scores
      pathEntropy: parseFloat(calculatePathEntropy().toFixed(4)),
      curvatureScore: parseFloat(calculateCurvatureScore().toFixed(4)),

      // Scroll stats
      scrollEventCount: scrollEvents.length,
      totalScrollDistancePx: calculateTotalScrollDistance(),
      scrollDirectionChanges: countScrollDirectionChanges(),
      scrollPauseCount: countScrollPauses(),
      scrollDepthProgression: parseFloat(
        calculateScrollDepthProgression().toFixed(4)
      ),
      scrollMomentum: parseFloat(calculateScrollMomentum().toFixed(4)),
      scrollSpeedVariance: parseFloat(
        calculateScrollSpeedVariance().toFixed(4)
      ),

      // Burst detection
      burstDetected: isBurstDetected(),
      burstCount: countBursts(),

      // Summary
      interactionTimeSec: Math.round(interactionTimeMs / 1000),
      minimumRequirementsMet: checkMinimumRequirements(),
    };

    cachedMetrics = metrics;
    return metrics;
  }

  /**
   * Check if minimum data collection requirements are met.
   * @returns {boolean} True if minimum requirements met.
   */
  function checkMinimumRequirements() {
    const interactionTimeMs =
      firstInteractionTime > 0 ? lastEventTime - firstInteractionTime : 0;

    return (
      mouseMoves.length >= CONFIG.MIN_MOUSE_MOVES &&
      mouseClicks.length >= CONFIG.MIN_CLICKS &&
      scrollEvents.length >= CONFIG.MIN_SCROLL_EVENTS &&
      interactionTimeMs >= CONFIG.MIN_INTERACTION_TIME_MS
    );
  }

  /**
   * Check if minimum data for ANY submission is available (relaxed).
   * @returns {boolean} True if minimum submission requirements met.
   */
  function checkSubmissionMinimums() {
    const interactionTimeMs =
      firstInteractionTime > 0 ? lastEventTime - firstInteractionTime : 0;

    return (
      mouseMoves.length >= 3 &&
      scrollEvents.length >= 1 &&
      interactionTimeMs >= 5000 &&
      mouseClicks.length >= 1
    );
  }

  // ============================================================================
  // SCORING FUNCTIONS
  // ============================================================================

  /**
   * Calculate entropy score (0-1).
   * Higher = more human-like behavior.
   * @returns {number} Entropy score.
   */
  function getEntropyScore() {
    const metrics = computeMetrics();

    // Combine multiple factors into entropy score
    const entropy = metrics.pathEntropy; // 0-1
    const curvature = metrics.curvatureScore; // 0-1
    const scrollProgression = metrics.scrollDepthProgression; // 0-1
    const momentum = metrics.scrollMomentum; // 0-1

    // Weights
    const w1 = 0.35; // path entropy
    const w2 = 0.25; // curvature
    const w3 = 0.20; // scroll progression
    const w4 = 0.20; // scroll momentum

    const score = entropy * w1 + curvature * w2 + scrollProgression * w3 + momentum * w4;

    return parseFloat(Math.min(1, Math.max(0, score)).toFixed(4));
  }

  /**
   * Calculate bot score (0-100).
   * Higher = more likely a bot.
   * @returns {number} Bot score.
   */
  function getBotScore() {
    const metrics = computeMetrics();
    let score = 0;

    // Teleport events (instant jumps) - strong bot indicator
    if (metrics.mouseTeleportCount > 0) {
      score += Math.min(30, metrics.mouseTeleportCount * 10);
    }

    // Very low entropy (perfectly straight lines)
    if (metrics.pathEntropy < 0.2) {
      score += 25;
    }

    // Burst events (too many events too fast)
    if (metrics.burstDetected) {
      score += 20;
    }

    // No pauses (humans pause)
    if (metrics.mousePauseCount === 0 && mouseMoves.length > 10) {
      score += 15;
    }

    // Perfect scroll progression (bots scroll linearly)
    if (metrics.scrollDepthProgression > 0.95 && scrollEvents.length > 5) {
      score += 10;
    }

    // Very low curvature (only straight lines)
    if (metrics.curvatureScore < 0.05 && mouseMoves.length > 20) {
      score += 15;
    }

    // Excessive speed consistency (bots have uniform speed)
    if (metrics.mouseSpeedVariance < 0.1 && metrics.mouseMoveCount > 20) {
      score += 10;
    }

    return Math.min(100, Math.round(score));
  }

  /**
   * Get collection progress percentage.
   * @returns {number} Progress 0-100.
   */
  function getCollectionProgress() {
    const interactionTimeMs =
      firstInteractionTime > 0 ? lastEventTime - firstInteractionTime : 0;

    const progress = {
      mouseMoves: Math.min(1, mouseMoves.length / CONFIG.MIN_MOUSE_MOVES),
      clicks: Math.min(1, mouseClicks.length / CONFIG.MIN_CLICKS),
      scrolls: Math.min(1, scrollEvents.length / CONFIG.MIN_SCROLL_EVENTS),
      time: Math.min(1, interactionTimeMs / CONFIG.MIN_INTERACTION_TIME_MS),
    };

    const totalProgress =
      (progress.mouseMoves + progress.clicks + progress.scrolls + progress.time) / 4;

    return Math.min(100, Math.round(totalProgress * 100));
  }

  // ============================================================================
  // DATA COLLECTION & SUBMISSION
  // ============================================================================

  /**
   * Collect complete behavior data for submission.
   * @returns {object|null} Behavior data object or null if insufficient.
   */
  function collectBehaviorData() {
    if (!checkSubmissionMinimums()) {
      return null;
    }

    const metrics = computeMetrics();

    return {
      token: null, // Will be filled by caller
      timestamp: nowISO(),
      metrics: metrics,
      raw: {
        mouseMoves: mouseMoves.slice(),
        mouseClicks: mouseClicks.slice(),
        mouseDowns: mouseDowns.slice(),
        mouseUps: mouseUps.slice(),
        scrollEvents: scrollEvents.slice(),
      },
      scores: {
        entropyScore: getEntropyScore(),
        botScore: getBotScore(),
      },
    };
  }

  /**
   * Submit Factor 2 behavior proof to server.
   * @param {string} token - The gift code token.
   * @returns {Promise<object>} Server response.
   */
  async function submitFactor2(token) {
    if (submitted) {
      return { status: "already_submitted" };
    }

    if (!token || typeof token !== "string") {
      throw new Error("Invalid token: must be non-empty string");
    }

    const behaviorData = collectBehaviorData();
    if (!behaviorData) {
      throw new Error(
        "Insufficient behavior data: need more mouse moves, scrolls, clicks, or time"
      );
    }

    behaviorData.token = token;

    // Retry logic with exponential backoff
    let lastError;
    for (let attempt = 0; attempt < CONFIG.SUBMISSION_RETRY_MAX; attempt++) {
      try {
        const response = await fetch(CONFIG.API_FACTOR2_ENDPOINT, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-OSM-Token": token,
          },
          body: JSON.stringify(behaviorData),
        });

        if (!response.ok) {
          const errorText = await response.text();
          throw new Error(
            "HTTP " + response.status + ": " + errorText
          );
        }

        const result = await response.json();
        submitted = true;
        secLog("Factor 2 submitted successfully", result);
        return result;
      } catch (error) {
        lastError = error;
        const delay =
          CONFIG.SUBMISSION_RETRY_BASE_MS * Math.pow(2, attempt);
        secLog("Factor 2 submission attempt " + (attempt + 1) + " failed, retrying in " + delay + "ms");
        await new Promise(function (resolve) {
          return setTimeout(resolve, delay);
        });
      }
    }

    throw new Error(
      "Factor 2 submission failed after " + CONFIG.SUBMISSION_RETRY_MAX + " attempts: " + lastError.message
    );
  }

  // ============================================================================
  // PROGRESS DISPLAY
  // ============================================================================

  /**
   * Update progress display element.
   */
  function updateProgressDisplay() {
    const el = document.getElementById("entropy-meter");
    if (!el) return;

    const progress = getCollectionProgress();
    const entropy = getEntropyScore();
    const botScore = getBotScore();
    const minMet = checkMinimumRequirements();

    // Build display HTML
    let html = '<div style="font-family:system-ui,monospace;padding:12px;' +
      "background:#1a1a2e;border-radius:8px;color:#e0e0e0;" +
      'border:1px solid #333;">';

    // Progress bar
    html +=
      '<div style="margin-bottom:8px;font-size:13px;font-weight:600;">' +
      "Behavior Analysis" +
      "</div>";
    html +=
      '<div style="background:#333;height:8px;border-radius:4px;overflow:hidden;margin-bottom:8px;">' +
      '<div style="background:' +
      (minMet ? "#4caf50" : "#ff9800") +
      ";height:100%;width:" +
      progress +
      '%;transition:width 0.3s;"></div></div>';

    // Stats
    html +=
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:12px;">';
    html +=
      '<div>Progress: <span style="color:' +
      (minMet ? "#4caf50" : "#ff9800") +
      '">' +
      progress +
      "%</span></div>";
    html +=
      "<div>Moves: " +
      mouseMoves.length +
      "/" +
      CONFIG.MIN_MOUSE_MOVES +
      "</div>";
    html +=
      "<div>Clicks: " +
      mouseClicks.length +
      "/" +
      CONFIG.MIN_CLICKS +
      "</div>";
    html +=
      "<div>Scrolls: " +
      scrollEvents.length +
      "/" +
      CONFIG.MIN_SCROLL_EVENTS +
      "</div>";
    html +=
      '<div>Entropy: <span style="color:#64b5f6">' +
      (entropy * 100).toFixed(1) +
      "%</span></div>";
    html +=
      '<div>Bot: <span style="color:' +
      (botScore > 50 ? "#f44336" : "#4caf50") +
      '">' +
      botScore +
      "/100</span></div>";
    html += "</div>";

    // Status
    if (minMet) {
      html +=
        '<div style="margin-top:8px;color:#4caf50;font-size:12px;font-weight:600;">' +
        "&#10003; Minimum data collected" +
        "</div>";
    } else {
      html +=
        '<div style="margin-top:8px;color:#ff9800;font-size:12px;">' +
        "Collecting behavior data..." +
        "</div>";
    }

    html += "</div>";
    el.innerHTML = html;
  }

  /**
   * Start progress display updates.
   */
  function startProgressDisplay() {
    if (progressInterval) return;
    updateProgressDisplay();
    progressInterval = setInterval(
      updateProgressDisplay,
      CONFIG.PROGRESS_UPDATE_INTERVAL_MS
    );
  }

  /**
   * Stop progress display updates.
   */
  function stopProgressDisplay() {
    if (progressInterval) {
      clearInterval(progressInterval);
      progressInterval = null;
    }
  }

  // ============================================================================
  // EVENT LISTENERS
  // ============================================================================

  /**
   * Register all event listeners.
   */
  function registerEventListeners() {
    document.addEventListener("mousemove", handleMouseMove, { passive: true });
    document.addEventListener("click", handleMouseClick, { passive: true });
    document.addEventListener("mousedown", handleMouseDown, { passive: true });
    document.addEventListener("mouseup", handleMouseUp, { passive: true });
    document.addEventListener("scroll", handleScroll, { passive: true });
  }

  /**
   * Unregister all event listeners.
   */
  function unregisterEventListeners() {
    document.removeEventListener("mousemove", handleMouseMove);
    document.removeEventListener("click", handleMouseClick);
    document.removeEventListener("mousedown", handleMouseDown);
    document.removeEventListener("mouseup", handleMouseUp);
    document.removeEventListener("scroll", handleScroll);
  }

  // ============================================================================
  // INITIALIZATION
  // ============================================================================

  /**
   * Initialize behavior tracking.
   */
  function init() {
    if (typeof window === "undefined" || typeof document === "undefined") {
      return;
    }

    if (trackingActive) return;

    pageLoadTime = hrNow();
    trackingStartTime = pageLoadTime;
    trackingActive = true;
    submitted = false;
    minimumMet = false;

    // Reset all data
    mouseMoves = [];
    mouseClicks = [];
    mouseDowns = [];
    mouseUps = [];
    scrollEvents = [];
    lastMousePos = null;
    lastMouseMoveTime = 0;
    lastScrollY = window.scrollY || 0;
    lastScrollTime = 0;
    recentEventTimes = [];
    cachedMetrics = null;
    firstInteractionTime = 0;
    lastEventTime = 0;

    registerEventListeners();
    startProgressDisplay();

    secLog("Behavior tracking initialized");
  }

  /**
   * Stop behavior tracking.
   */
  function stop() {
    trackingActive = false;
    unregisterEventListeners();
    stopProgressDisplay();
    secLog("Behavior tracking stopped");
  }

  /**
   * Reset all tracking data.
   */
  function reset() {
    stop();
    submitted = false;
    minimumMet = false;
    init();
  }

  // ============================================================================
  // PUBLIC API
  // ============================================================================

  /**
   * Public API for behavior tracking.
   * @namespace OSMBehavior
   */
  const OSMBehavior = Object.freeze({
    // Initialization
    init: init,
    start: init,
    stop: stop,
    reset: reset,

    // Data collection
    collectBehaviorData: collectBehaviorData,

    // Submission
    submitFactor2: submitFactor2,

    // Scoring
    getEntropyScore: getEntropyScore,
    getBotScore: getBotScore,

    // Progress
    getCollectionProgress: getCollectionProgress,

    // Metrics
    getMetrics: computeMetrics,

    // Status
    isTracking: function () {
      return trackingActive;
    },
    isSubmitted: function () {
      return submitted;
    },
    hasMinimumData: function () {
      return checkMinimumRequirements();
    },

    // Raw data access (for debugging)
    getRawData: function () {
      return {
        mouseMoves: mouseMoves.slice(),
        mouseClicks: mouseClicks.slice(),
        mouseDowns: mouseDowns.slice(),
        mouseUps: mouseUps.slice(),
        scrollEvents: scrollEvents.slice(),
      };
    },

    // Config
    config: CONFIG,
    version: "1.0.0",
  });

  // Attach to global scope
  if (typeof window !== "undefined") {
    window.OSMBehavior = OSMBehavior;
  }
})();
