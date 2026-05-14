/**
 * @fileoverview behavior.js - Behavioral Analysis Engine
 * Osm Army Gift Code Fortress - Ultra-Secure Gift Code System
 *
 * Detects bots via mouse movement patterns, scroll behavior, and timing analysis.
 * Uses entropy calculations, curvature analysis, and adaptive thresholds.
 * Implements minimum interaction requirements before sensitive operations.
 *
 * @author Osm Army Security Team
 * @version 5.0.0-fortress
 * @license Proprietary
 */

'use strict';

import { createHash, randomBytes } from 'crypto';

// ============================================================================
// Constants
// ============================================================================

/** Minimum mouse movements before code reveal */
const MIN_MOUSE_MOVEMENTS = 3;
/** Minimum scroll events before code reveal */
const MIN_SCROLL_EVENTS = 1;
/** Minimum time on page in milliseconds */
const MIN_TIME_ON_PAGE = 5000;
/** Minimum click events before code reveal */
const MIN_CLICK_EVENTS = 1;

/** Human speed range in pixels/second (min, max) */
const HUMAN_SPEED_RANGE = { min: 100, max: 5000 };
/** Bot speed threshold - too consistent = bot */
const BOT_SPEED_VARIANCE_THRESHOLD = 50;
/** Minimum mouse entropy for human (Shannon) */
const MIN_HUMAN_ENTROPY = 0.7;
/** Minimum path curvature for human */
const MIN_HUMAN_CURVATURE = 0.1;
/** Maximum straightness for human (1.0 = perfectly straight) */
const MAX_HUMAN_STRAIGHTNESS = 0.99;

/** Bot score thresholds */
const BOT_SCORE_THRESHOLDS = {
  human: { max: 30, label: 'human' },
  suspicious: { max: 60, label: 'suspicious' },
  likelyBot: { max: 80, label: 'likely_bot' },
  bot: { max: 100, label: 'bot' }
};

/** Minimum key press interval for human (ms) */
const MIN_KEY_INTERVAL = 50;
/** Maximum key press interval for human (ms) */
const MAX_KEY_INTERVAL = 1000;
/** Minimum time to fill a form field for human (ms) */
const MIN_FORM_FILL_TIME = 500;
/** Minimum delay from page load to first interaction (ms) */
const MIN_FIRST_INTERACTION_DELAY = 100;
/** Maximum interactions per second before burst detection */
const MAX_INTERACTIONS_PER_SECOND = 20;

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Calculate Euclidean distance between two points.
 * @param {{x: number, y: number}} a - Point A
 * @param {{x: number, y: number}} b - Point B
 * @returns {number} Distance in pixels
 */
function distance(a, b) {
  const dx = a.x - b.x;
  const dy = a.y - b.y;
  return Math.sqrt(dx * dx + dy * dy);
}

/**
 * Calculate Shannon entropy of a sequence of values.
 * @param {number[]} values - Numeric sequence
 * @returns {number} Entropy value
 */
function shannonEntropy(values) {
  if (!values || values.length === 0) return 0;

  // Bin the values for entropy calculation
  const bins = 20;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  const histogram = new Array(bins).fill(0);

  for (const v of values) {
    const bin = Math.min(bins - 1, Math.floor(((v - min) / range) * bins));
    histogram[bin]++;
  }

  let entropy = 0;
  const total = values.length;
  for (const count of histogram) {
    if (count === 0) continue;
    const p = count / total;
    entropy -= p * Math.log2(p);
  }

  // Normalize by max entropy
  const maxEntropy = Math.log2(bins);
  return maxEntropy > 0 ? entropy / maxEntropy : 0;
}

/**
 * Calculate variance of an array.
 * @param {number[]} arr - Number array
 * @returns {number} Variance
 */
function variance(arr) {
  if (!arr || arr.length < 2) return 0;
  const mean = arr.reduce((s, v) => s + v, 0) / arr.length;
  const squaredDiffs = arr.map(v => (v - mean) ** 2);
  return squaredDiffs.reduce((s, v) => s + v, 0) / arr.length;
}

/**
 * Calculate standard deviation.
 * @param {number[]} arr - Number array
 * @returns {number} Standard deviation
 */
function stdDev(arr) {
  return Math.sqrt(variance(arr));
}

/**
 * Calculate coefficient of variation (normalized std dev).
 * @param {number[]} arr - Number array
 * @returns {number} CV value
 */
function coefficientOfVariation(arr) {
  const mean = arr.reduce((s, v) => s + v, 0) / arr.length;
  if (mean === 0) return 0;
  return stdDev(arr) / Math.abs(mean);
}

/**
 * Calculate linear regression slope and intercept.
 * @param {{x: number, y: number}[]} points - Data points
 * @returns {{slope: number, intercept: number, r2: number}}
 */
function linearRegression(points) {
  const n = points.length;
  if (n < 2) return { slope: 0, intercept: 0, r2: 0 };

  const sumX = points.reduce((s, p) => s + p.x, 0);
  const sumY = points.reduce((s, p) => s + p.y, 0);
  const sumXY = points.reduce((s, p) => s + p.x * p.y, 0);
  const sumXX = points.reduce((s, p) => s + p.x * p.x, 0);
  const sumYY = points.reduce((s, p) => s + p.y * p.y, 0);

  const denom = n * sumXX - sumX * sumX;
  if (denom === 0) return { slope: 0, intercept: 0, r2: 0 };

  const slope = (n * sumXY - sumX * sumY) / denom;
  const intercept = (sumY - slope * sumX) / n;

  const ssTot = sumYY - (sumY * sumY) / n;
  const ssRes = sumYY - intercept * sumY - slope * sumXY;
  const r2 = ssTot === 0 ? 0 : 1 - ssRes / ssTot;

  return { slope, intercept, r2: Math.abs(r2) };
}

/**
 * Clamp a value between min and max.
 * @param {number} v - Value
 * @param {number} min - Minimum
 * @param {number} max - Maximum
 * @returns {number}
 */
function clamp(v, min, max) {
  return Math.max(min, Math.min(max, v));
}

/**
 * Generate a secure random ID.
 * @param {number} [length=16] - ID length
 * @returns {string}
 */
function secureId(length = 16) {
  return randomBytes(length).toString('hex').slice(0, length);
}

// ============================================================================
// MouseAnalysis Module
// ============================================================================

/**
 * Analyzes mouse movement patterns for bot detection.
 */
class MouseAnalyzer {
  /**
   * @param {Object} [options] - Configuration
   * @param {number} [options.minHumanEntropy=0.7] - Minimum entropy threshold
   * @param {number} [options.minCurvature=0.1] - Minimum curvature threshold
   */
  constructor(options = {}) {
    this.minHumanEntropy = options.minHumanEntropy || MIN_HUMAN_ENTROPY;
    this.minCurvature = options.minCurvature || MIN_HUMAN_CURVATURE;
  }

  /**
   * Calculate movement entropy of a mouse path.
   * Humans: > 0.7, Bots: typically < 0.5 (straight/predictable paths)
   * @param {{x: number, y: number, t: number}[]} movements - Mouse positions
   * @returns {number} Entropy 0-1
   */
  calculateEntropy(movements) {
    if (!movements || movements.length < 3) return 0;

    const angles = this._extractAngles(movements);
    if (angles.length < 2) return 0;

    return shannonEntropy(angles);
  }

  /**
   * Calculate path curvature.
   * Humans have curves, bots tend toward straight lines.
   * @param {{x: number, y: number, t: number}[]} movements - Mouse positions
   * @returns {number} Curvature score
   */
  calculateCurvature(movements) {
    if (!movements || movements.length < 3) return 0;

    let totalCurvature = 0;
    let count = 0;

    for (let i = 1; i < movements.length - 1; i++) {
      const a = movements[i - 1];
      const b = movements[i];
      const c = movements[i + 1];

      // Calculate angle at point b
      const angle = this._angleAtPoint(a, b, c);
      totalCurvature += Math.abs(angle);
      count++;
    }

    return count > 0 ? totalCurvature / (count * Math.PI) : 0;
  }

  /**
   * Calculate speed variance across the path.
   * Humans: variable speed, Bots: constant or instant.
   * @param {{x: number, y: number, t: number}[]} movements - Mouse positions
   * @returns {{variance: number, avgSpeed: number, speeds: number[], cv: number}}
   */
  calculateSpeedVariance(movements) {
    if (!movements || movements.length < 2) {
      return { variance: 0, avgSpeed: 0, speeds: [], cv: 0 };
    }

    const speeds = [];
    for (let i = 1; i < movements.length; i++) {
      const dist = distance(movements[i - 1], movements[i]);
      const dt = movements[i].t - movements[i - 1].t;
      if (dt > 0) {
        speeds.push((dist / dt) * 1000); // px/s
      }
    }

    if (speeds.length === 0) return { variance: 0, avgSpeed: 0, speeds: [], cv: 0 };

    const avg = speeds.reduce((s, v) => s + v, 0) / speeds.length;
    const var_ = variance(speeds);
    const cv = coefficientOfVariation(speeds);

    return { variance: var_, avgSpeed: avg, speeds, cv };
  }

  /**
   * Count pause points in mouse path.
   * Humans pause to read/think. Bots rarely pause.
   * @param {{x: number, y: number, t: number}[]} movements - Mouse positions
   * @param {number} [thresholdMs=500] - Minimum pause duration
   * @returns {number} Number of pause points
   */
  countPausePoints(movements, thresholdMs = 500) {
    if (!movements || movements.length < 2) return 0;

    let pauses = 0;
    for (let i = 1; i < movements.length; i++) {
      const dt = movements[i].t - movements[i - 1].t;
      if (dt >= thresholdMs) {
        // Also check that position didn't change much (actual pause, not slow movement)
        const dist = distance(movements[i - 1], movements[i]);
        if (dist < 5) pauses++;
      }
    }
    return pauses;
  }

  /**
   * Count direction changes in path.
   * Humans change direction frequently. Bots tend to be direct.
   * @param {{x: number, y: number, t: number}[]} movements - Mouse positions
   * @param {number} [angleThreshold=0.5] - Minimum angle (radians) for direction change
   * @returns {number} Number of direction changes
   */
  countDirectionChanges(movements, angleThreshold = 0.5) {
    if (!movements || movements.length < 3) return 0;

    let changes = 0;
    for (let i = 2; i < movements.length; i++) {
      const prevAngle = Math.atan2(
        movements[i - 1].y - movements[i - 2].y,
        movements[i - 1].x - movements[i - 2].x
      );
      const currAngle = Math.atan2(
        movements[i].y - movements[i - 1].y,
        movements[i].x - movements[i - 1].x
      );
      const diff = Math.abs(currAngle - prevAngle);
      const normalizedDiff = Math.min(diff, 2 * Math.PI - diff);
      if (normalizedDiff > angleThreshold) changes++;
    }
    return changes;
  }

  /**
   * Calculate acceleration pattern (how non-linear the acceleration is).
   * Humans accelerate/decelerate non-linearly.
   * @param {{x: number, y: number, t: number}[]} movements - Mouse positions
   * @returns {{linearity: number, pattern: string}}
   */
  calculateAcceleration(movements) {
    if (!movements || movements.length < 3) {
      return { linearity: 1, pattern: 'unknown' };
    }

    const speeds = [];
    for (let i = 1; i < movements.length; i++) {
      const dist = distance(movements[i - 1], movements[i]);
      const dt = movements[i].t - movements[i - 1].t;
      if (dt > 0) speeds.push((dist / dt) * 1000);
    }

    if (speeds.length < 3) return { linearity: 1, pattern: 'unknown' };

    // Fit speed curve and measure R^2
    const points = speeds.map((s, i) => ({ x: i, y: s }));
    const { r2 } = linearRegression(points);

    const linearity = clamp(r2, 0, 1);
    let pattern = 'variable';
    if (linearity > 0.95) pattern = 'linear';
    else if (linearity > 0.8) pattern = 'semi_linear';
    else if (linearity < 0.3) pattern = 'chaotic';

    return { linearity, pattern };
  }

  /**
   * Calculate path straightness (1.0 = perfectly straight line).
   * @param {{x: number, y: number, t: number}[]} movements - Mouse positions
   * @returns {number} Straightness 0-1
   */
  calculateStraightness(movements) {
    if (!movements || movements.length < 2) return 0;

    const start = movements[0];
    const end = movements[movements.length - 1];
    const directDistance = distance(start, end);

    let pathLength = 0;
    for (let i = 1; i < movements.length; i++) {
      pathLength += distance(movements[i - 1], movements[i]);
    }

    if (pathLength === 0) return 0;
    return directDistance / pathLength;
  }

  /**
   * Count teleport events (instant large position changes).
   * @param {{x: number, y: number, t: number}[]} movements - Mouse positions
   * @param {number} [thresholdPx=200] - Minimum distance for teleport
   * @param {number} [thresholdMs=50] - Maximum time for teleport
   * @returns {number} Number of teleport events
   */
  countTeleports(movements, thresholdPx = 200, thresholdMs = 50) {
    if (!movements || movements.length < 2) return 0;

    let teleports = 0;
    for (let i = 1; i < movements.length; i++) {
      const dist = distance(movements[i - 1], movements[i]);
      const dt = movements[i].t - movements[i - 1].t;
      if (dist > thresholdPx && dt < thresholdMs) teleports++;
    }
    return teleports;
  }

  /**
   * Calculate total mouse path length in pixels.
   * @param {{x: number, y: number, t: number}[]} movements - Mouse positions
   * @returns {number} Path length
   */
  calculatePathLength(movements) {
    if (!movements || movements.length < 2) return 0;
    let length = 0;
    for (let i = 1; i < movements.length; i++) {
      length += distance(movements[i - 1], movements[i]);
    }
    return length;
  }

  /**
   * Calculate mouse idle time (longest period without movement).
   * @param {{x: number, y: number, t: number}[]} movements - Mouse positions
   * @returns {number} Idle time in ms
   */
  calculateIdleTime(movements) {
    if (!movements || movements.length < 2) return 0;

    let maxIdle = 0;
    for (let i = 1; i < movements.length; i++) {
      const idle = movements[i].t - movements[i - 1].t;
      if (idle > maxIdle) maxIdle = idle;
    }
    return maxIdle;
  }

  /**
   * Extract angles between consecutive segments.
   * @private
   */
  _extractAngles(movements) {
    const angles = [];
    for (let i = 2; i < movements.length; i++) {
      const dx1 = movements[i - 1].x - movements[i - 2].x;
      const dy1 = movements[i - 1].y - movements[i - 2].y;
      const dx2 = movements[i].x - movements[i - 1].x;
      const dy2 = movements[i].y - movements[i - 1].y;
      const angle1 = Math.atan2(dy1, dx1);
      const angle2 = Math.atan2(dy2, dx2);
      let diff = angle2 - angle1;
      while (diff <= -Math.PI) diff += 2 * Math.PI;
      while (diff > Math.PI) diff -= 2 * Math.PI;
      angles.push(Math.abs(diff));
    }
    return angles;
  }

  /**
   * Calculate angle at a point formed by three consecutive points.
   * @private
   */
  _angleAtPoint(a, b, c) {
    const ba = { x: a.x - b.x, y: a.y - b.y };
    const bc = { x: c.x - b.x, y: c.y - b.y };
    const dot = ba.x * bc.x + ba.y * bc.y;
    const magBA = Math.sqrt(ba.x * ba.x + ba.y * ba.y);
    const magBC = Math.sqrt(bc.x * bc.x + bc.y * bc.y);
    if (magBA === 0 || magBC === 0) return 0;
    return Math.acos(clamp(dot / (magBA * magBC), -1, 1));
  }
}

// ============================================================================
// ScrollAnalysis Module
// ============================================================================

/**
 * Analyzes scroll behavior for bot detection.
 */
class ScrollAnalyzer {
  /**
   * Calculate scroll speed variance.
   * Humans scroll at variable speeds; bots tend to be constant.
   * @param {{position: number, t: number}[]} scrolls - Scroll positions with timestamps
   * @returns {{variance: number, avgSpeed: number, speeds: number[], cv: number}}
   */
  calculateSpeedVariance(scrolls) {
    if (!scrolls || scrolls.length < 2) {
      return { variance: 0, avgSpeed: 0, speeds: [], cv: 0 };
    }

    const speeds = [];
    for (let i = 1; i < scrolls.length; i++) {
      const dp = Math.abs(scrolls[i].position - scrolls[i - 1].position);
      const dt = scrolls[i].t - scrolls[i - 1].t;
      if (dt > 0) speeds.push((dp / dt) * 1000); // px/s
    }

    if (speeds.length === 0) return { variance: 0, avgSpeed: 0, speeds: [], cv: 0 };

    const avg = speeds.reduce((s, v) => s + v, 0) / speeds.length;
    return { variance: variance(speeds), avgSpeed: avg, speeds, cv: coefficientOfVariation(speeds) };
  }

  /**
   * Count scroll direction changes.
   * @param {{position: number, t: number}[]} scrolls - Scroll positions
   * @returns {number} Number of direction changes
   */
  countDirectionChanges(scrolls) {
    if (!scrolls || scrolls.length < 3) return 0;

    let changes = 0;
    let lastDirection = 0; // -1 = up, 1 = down

    for (let i = 1; i < scrolls.length; i++) {
      const dir = scrolls[i].position > scrolls[i - 1].position ? 1 : -1;
      if (lastDirection !== 0 && dir !== lastDirection) changes++;
      lastDirection = dir;
    }
    return changes;
  }

  /**
   * Count scroll pauses (stops to read).
   * @param {{position: number, t: number}[]} scrolls - Scroll positions
   * @param {number} [thresholdMs=1000] - Minimum pause duration
   * @returns {number} Number of pauses
   */
  countPauses(scrolls, thresholdMs = 1000) {
    if (!scrolls || scrolls.length < 2) return 0;

    let pauses = 0;
    for (let i = 1; i < scrolls.length; i++) {
      const dt = scrolls[i].t - scrolls[i - 1].t;
      const dp = Math.abs(scrolls[i].position - scrolls[i - 1].position);
      if (dt >= thresholdMs && dp < 10) pauses++;
    }
    return pauses;
  }

  /**
   * Analyze scroll depth progression.
   * Humans: top to bottom. Bots: random jumps.
   * @param {{position: number, t: number}[]} scrolls - Scroll positions
   * @returns {{progression: string, monotonicity: number, jumps: number}}
   */
  analyzeDepthProgression(scrolls) {
    if (!scrolls || scrolls.length < 3) {
      return { progression: 'insufficient', monotonicity: 0, jumps: 0 };
    }

    let increases = 0;
    let decreases = 0;
    let jumps = 0;

    for (let i = 1; i < scrolls.length; i++) {
      const diff = scrolls[i].position - scrolls[i - 1].position;
      if (diff > 0) increases++;
      else if (diff < 0) decreases++;

      if (Math.abs(diff) > window?.innerHeight * 2 || 800) jumps++;
    }

    const total = scrolls.length - 1;
    const monotonicity = increases / Math.max(total, 1);

    let progression = 'variable';
    if (monotonicity > 0.95) progression = 'linear_down';
    else if (monotonicity > 0.8) progression = 'mostly_down';
    else if (monotonicity < 0.2) progression = 'mostly_up';
    else if (jumps > total * 0.3) progression = 'random_jumps';

    return { progression, monotonicity, jumps };
  }

  /**
   * Detect momentum scrolling (characteristic of mobile/touch devices).
   * @param {{position: number, t: number, velocity: number}[]} scrolls - Scroll positions with velocity
   * @returns {boolean}
   */
  detectMomentumScroll(scrolls) {
    if (!scrolls || scrolls.length < 3) return false;

    // Look for deceleration pattern after scroll stop
    for (let i = 2; i < scrolls.length; i++) {
      const v1 = scrolls[i - 2].velocity || 0;
      const v2 = scrolls[i - 1].velocity || 0;
      const v3 = scrolls[i].velocity || 0;
      if (v1 > v2 && v2 > v3 && v1 > 100 && v3 < 50) return true;
    }
    return false;
  }

  /**
   * Detect instant scroll to bottom (bot behavior).
   * @param {{position: number, t: number}[]} scrolls - Scroll positions
   * @param {number} pageHeight - Page height
   * @returns {boolean}
   */
  detectInstantScrollToBottom(scrolls, pageHeight) {
    if (!scrolls || scrolls.length < 2) return false;
    const start = scrolls[0].position;
    const end = scrolls[scrolls.length - 1].position;
    const time = scrolls[scrolls.length - 1].t - scrolls[0].t;
    return end > pageHeight * 0.9 && start < pageHeight * 0.1 && time < 500;
  }

  /**
   * Calculate total scroll distance.
   * @param {{position: number, t: number}[]} scrolls - Scroll positions
   * @returns {number}
   */
  calculateTotalDistance(scrolls) {
    if (!scrolls || scrolls.length < 2) return 0;
    let total = 0;
    for (let i = 1; i < scrolls.length; i++) {
      total += Math.abs(scrolls[i].position - scrolls[i - 1].position);
    }
    return total;
  }
}

// ============================================================================
// TimingAnalysis Module
// ============================================================================

/**
 * Analyzes timing patterns for bot detection.
 */
class TimingAnalyzer {
  /**
   * Analyze time intervals between actions.
   * @param {number[]} timestamps - Event timestamps in ms
   * @returns {{avgInterval: number, variance: number, cv: number, intervals: number[]}}
   */
  analyzeIntervals(timestamps) {
    if (!timestamps || timestamps.length < 2) {
      return { avgInterval: 0, variance: 0, cv: 0, intervals: [] };
    }

    const sorted = [...timestamps].sort((a, b) => a - b);
    const intervals = [];
    for (let i = 1; i < sorted.length; i++) {
      intervals.push(sorted[i] - sorted[i - 1]);
    }

    const avg = intervals.reduce((s, v) => s + v, 0) / intervals.length;
    return { avgInterval: avg, variance: variance(intervals), cv: coefficientOfVariation(intervals), intervals };
  }

  /**
   * Analyze form fill timing.
   * Humans take time; bots fill instantly.
   * @param {{field: string, startTime: number, endTime: number}[]} fields - Field fill events
   * @returns {{avgTime: number, suspiciousFields: string[], totalTime: number}}
   */
  analyzeFormFill(fields) {
    if (!fields || fields.length === 0) {
      return { avgTime: 0, suspiciousFields: [], totalTime: 0 };
    }

    let totalTime = 0;
    const suspiciousFields = [];

    for (const field of fields) {
      const time = field.endTime - field.startTime;
      totalTime += time;
      if (time < MIN_FORM_FILL_TIME) {
        suspiciousFields.push(field.field);
      }
    }

    const avgTime = totalTime / fields.length;
    return { avgTime, suspiciousFields, totalTime };
  }

  /**
   * Measure page load to first interaction delay.
   * @param {number} pageLoadTime - Page load timestamp
   * @param {number} firstInteraction - First interaction timestamp
   * @returns {number} Delay in ms
   */
  firstInteractionDelay(pageLoadTime, firstInteraction) {
    if (!pageLoadTime || !firstInteraction) return 0;
    return firstInteraction - pageLoadTime;
  }

  /**
   * Detect interaction bursts (too many interactions too fast).
   * @param {number[]} timestamps - Interaction timestamps
   * @param {number} [windowMs=1000] - Time window
   * @param {number} [threshold=MAX_INTERACTIONS_PER_SECOND] - Max interactions per window
   * @returns {{isBurst: boolean, maxInWindow: number}}
   */
  detectBurst(timestamps, windowMs = 1000, threshold = MAX_INTERACTIONS_PER_SECOND) {
    if (!timestamps || timestamps.length < 2) return { isBurst: false, maxInWindow: 0 };

    const sorted = [...timestamps].sort((a, b) => a - b);
    let maxInWindow = 0;

    for (let i = 0; i < sorted.length; i++) {
      let count = 1;
      for (let j = i + 1; j < sorted.length; j++) {
        if (sorted[j] - sorted[i] <= windowMs) count++;
        else break;
      }
      if (count > maxInWindow) maxInWindow = count;
    }

    return { isBurst: maxInWindow > threshold, maxInWindow };
  }

  /**
   * Analyze key press intervals.
   * @param {{key: string, timestamp: number}[]} keyEvents - Key press events
   * @returns {{avgInterval: number, variance: number, cv: number, botLike: boolean}}
   */
  analyzeKeyPresses(keyEvents) {
    if (!keyEvents || keyEvents.length < 3) {
      return { avgInterval: 0, variance: 0, cv: 0, botLike: false };
    }

    const sorted = [...keyEvents].sort((a, b) => a.timestamp - b.timestamp);
    const intervals = [];
    for (let i = 1; i < sorted.length; i++) {
      intervals.push(sorted[i].timestamp - sorted[i - 1].timestamp);
    }

    const avg = intervals.reduce((s, v) => s + v, 0) / intervals.length;
    const var_ = variance(intervals);
    const cv = coefficientOfVariation(intervals);

    // Bot-like: intervals too consistent (low CV) or too fast/slow
    const tooFast = avg < MIN_KEY_INTERVAL;
    const tooSlow = avg > MAX_KEY_INTERVAL * 3;
    const tooConsistent = cv < 0.1 && intervals.length > 5;
    const botLike = tooFast || tooConsistent || tooSlow;

    return { avgInterval: avg, variance: var_, cv, botLike };
  }

  /**
   * Analyze click timing patterns.
   * @param {{timestamp: number, x: number, y: number}[]} clicks - Click events
   * @returns {{avgInterval: number, variance: number, cv: number, botLike: boolean}}
   */
  analyzeClickTiming(clicks) {
    if (!clicks || clicks.length < 2) {
      return { avgInterval: 0, variance: 0, cv: 0, botLike: false };
    }

    const sorted = [...clicks].sort((a, b) => a.timestamp - b.timestamp);
    const intervals = [];
    for (let i = 1; i < sorted.length; i++) {
      intervals.push(sorted[i].timestamp - sorted[i - 1].timestamp);
    }

    const avg = intervals.reduce((s, v) => s + v, 0) / intervals.length;
    const cv = coefficientOfVariation(intervals);
    const botLike = avg < 50 || (cv < 0.05 && intervals.length > 3);

    return { avgInterval: avg, variance: variance(intervals), cv, botLike };
  }
}

// ============================================================================
// BehaviorProfile Module
// ============================================================================

/**
 * Maintains a historical behavior profile for a device/session.
 * Adaptive thresholds learn from user behavior over time.
 */
class BehaviorProfile {
  /**
   * @param {string} deviceId - Device/session identifier
   * @param {Object} [options] - Configuration
   * @param {number} [options.maxHistory=50] - Max historical sessions to keep
   * @param {number} [options.decayFactor=0.95] - Weight decay for old data
   */
  constructor(deviceId, options = {}) {
    this.deviceId = deviceId;
    this.maxHistory = options.maxHistory || 50;
    this.decayFactor = options.decayFactor || 0.95;

    /** @type {Object[]} Historical behavior records */
    this.history = [];
    /** @type {Object} Adaptive thresholds */
    this.thresholds = this._defaultThresholds();
    /** @type {number} Profile confidence (0-1) */
    this.confidence = 0;
    /** @type {string} ISO timestamp of last update */
    this.lastUpdated = new Date().toISOString();
  }

  /**
   * Get default thresholds.
   * @returns {Object}
   * @private
   */
  _defaultThresholds() {
    return {
      minMouseEntropy: MIN_HUMAN_ENTROPY,
      minCurvature: MIN_HUMAN_CURVATURE,
      maxStraightness: MAX_HUMAN_STRAIGHTNESS,
      minSpeedVariance: 50,
      minPausePoints: 1,
      minDirectionChanges: 2,
      maxAccelerationLinearity: 0.95,
      minScrollPauses: 0,
      minKeyInterval: MIN_KEY_INTERVAL,
      maxKeyInterval: MAX_KEY_INTERVAL,
      minFormFillTime: MIN_FORM_FILL_TIME,
      minFirstInteractionDelay: MIN_FIRST_INTERACTION_DELAY,
      maxInteractionsPerSecond: MAX_INTERACTIONS_PER_SECOND,
      minTimeOnPage: MIN_TIME_ON_PAGE,
      minMouseMovements: MIN_MOUSE_MOVEMENTS,
      minScrollEvents: MIN_SCROLL_EVENTS,
      minClicks: MIN_CLICK_EVENTS
    };
  }

  /**
   * Record a new behavior session.
   * @param {Object} behavior - Behavior analysis result
   */
  recordSession(behavior) {
    const record = {
      timestamp: new Date().toISOString(),
      mouseEntropy: behavior.mouse?.entropy || 0,
      mouseCurvature: behavior.mouse?.curvature || 0,
      speedVariance: behavior.mouse?.speedVariance?.variance || 0,
      pausePoints: behavior.mouse?.pausePoints || 0,
      directionChanges: behavior.mouse?.directionChanges || 0,
      accelerationLinearity: behavior.mouse?.acceleration?.linearity || 0,
      scrollVariance: behavior.scroll?.speedVariance?.variance || 0,
      scrollPauses: behavior.scroll?.pauses || 0,
      scrollDirectionChanges: behavior.scroll?.directionChanges || 0,
      timeOnPage: behavior.timing?.timeOnPage || 0,
      interactionCount: behavior.interactions?.total || 0,
      botScore: behavior.botScore || 0,
      verdict: behavior.verdict || 'unknown'
    };

    this.history.unshift(record);
    if (this.history.length > this.maxHistory) {
      this.history = this.history.slice(0, this.maxHistory);
    }

    this._updateThresholds();
    this.lastUpdated = new Date().toISOString();
  }

  /**
   * Update adaptive thresholds based on history.
   * @private
   */
  _updateThresholds() {
    if (this.history.length < 3) {
      this.confidence = this.history.length / 10;
      return;
    }

    const recent = this.history.slice(0, Math.min(20, this.history.length));

    // Update mouse entropy threshold (use 20th percentile of history)
    const entropies = recent.map(r => r.mouseEntropy).sort((a, b) => a - b);
    const p20 = entropies[Math.floor(entropies.length * 0.2)];
    this.thresholds.minMouseEntropy = Math.max(0.3, Math.min(MIN_HUMAN_ENTROPY, p20 * 0.8));

    // Update curvature threshold
    const curvatures = recent.map(r => r.mouseCurvature).sort((a, b) => a - b);
    this.thresholds.minCurvature = Math.max(0.01, curvatures[Math.floor(curvatures.length * 0.2)] * 0.8);

    // Update speed variance threshold
    const speeds = recent.map(r => r.speedVariance).sort((a, b) => a - b);
    this.thresholds.minSpeedVariance = Math.max(10, speeds[Math.floor(speeds.length * 0.3)]);

    // Update pause points threshold
    const pauses = recent.map(r => r.pausePoints);
    this.thresholds.minPausePoints = Math.max(0, Math.floor(pauses.reduce((s, v) => s + v, 0) / pauses.length * 0.5));

    this.confidence = Math.min(1, this.history.length / 20);
  }

  /**
   * Get current adaptive thresholds.
   * @returns {Object}
   */
  getThresholds() {
    return { ...this.thresholds };
  }

  /**
   * Check if behavior matches the historical profile.
   * @param {Object} behavior - Current behavior
   * @returns {{matches: boolean, deviations: string[], score: number}}
   */
  compareToProfile(behavior) {
    if (this.history.length < 3) {
      return { matches: true, deviations: [], score: 0 };
    }

    const deviations = [];
    let deviationScore = 0;

    // Check mouse entropy
    if (behavior.mouse?.entropy < this.thresholds.minMouseEntropy) {
      deviations.push(`Mouse entropy ${behavior.mouse.entropy.toFixed(3)} below adaptive threshold ${this.thresholds.minMouseEntropy.toFixed(3)}`);
      deviationScore += 15;
    }

    // Check curvature
    if (behavior.mouse?.curvature < this.thresholds.minCurvature) {
      deviations.push(`Curvature ${behavior.mouse.curvature.toFixed(3)} below adaptive threshold ${this.thresholds.minCurvature.toFixed(3)}`);
      deviationScore += 10;
    }

    // Check speed variance
    if ((behavior.mouse?.speedVariance?.variance || 0) < this.thresholds.minSpeedVariance) {
      deviations.push(`Speed variance below adaptive threshold`);
      deviationScore += 10;
    }

    // Check pause points
    if ((behavior.mouse?.pausePoints || 0) < this.thresholds.minPausePoints) {
      deviations.push(`Pause points below adaptive threshold`);
      deviationScore += 5;
    }

    // Check time on page
    if ((behavior.timing?.timeOnPage || 0) < this.thresholds.minTimeOnPage * 0.5) {
      deviations.push(`Time on page significantly below threshold`);
      deviationScore += 20;
    }

    const matches = deviationScore < 30;
    return { matches, deviations, score: deviationScore };
  }

  /**
   * Serialize the profile for storage.
   * @returns {Object}
   */
  serialize() {
    return {
      deviceId: this.deviceId,
      history: this.history.slice(0, 20),
      thresholds: this.thresholds,
      confidence: this.confidence,
      lastUpdated: this.lastUpdated
    };
  }

  /**
   * Load profile from serialized data.
   * @param {Object} data - Serialized profile
   */
  static deserialize(data) {
    const profile = new BehaviorProfile(data.deviceId);
    profile.history = data.history || [];
    profile.thresholds = data.thresholds || profile._defaultThresholds();
    profile.confidence = data.confidence || 0;
    profile.lastUpdated = data.lastUpdated || new Date().toISOString();
    return profile;
  }
}

// ============================================================================
// Main BehaviorAnalyzer Class
// ============================================================================

/**
 * Main behavior analysis engine. Orchestrates mouse, scroll, and timing
 * analysis to compute a composite bot score.
 *
 * @class
 */
export class BehaviorAnalyzer {
  /**
   * @param {Object} [options] - Configuration
   * @param {Object} [options.db] - Database for profile persistence
   * @param {number} [options.humanThreshold=30] - Score below which = human
   * @param {number} [options.suspiciousThreshold=60] - Score below which = suspicious
   * @param {number} [options.likelyBotThreshold=80] - Score below which = likely bot
   * @param {boolean} [options.useAdaptiveThresholds=true] - Use adaptive thresholds
   */
  constructor(options = {}) {
    this.db = options.db || null;
    this.humanThreshold = options.humanThreshold || BOT_SCORE_THRESHOLDS.human.max;
    this.suspiciousThreshold = options.suspiciousThreshold || BOT_SCORE_THRESHOLDS.suspicious.max;
    this.likelyBotThreshold = options.likelyBotThreshold || BOT_SCORE_THRESHOLDS.likelyBot.max;
    this.useAdaptiveThresholds = options.useAdaptiveThresholds !== false;

    this.mouseAnalyzer = new MouseAnalyzer(options);
    this.scrollAnalyzer = new ScrollAnalyzer();
    this.timingAnalyzer = new TimingAnalyzer();

    /** @type {Map<string, BehaviorProfile>} In-memory profiles */
    this.profiles = new Map();
  }

  /**
   * Analyze complete behavior data and return comprehensive results.
   * @param {Object} data - Client behavior data
   * @param {string} [deviceId] - Device identifier for profile tracking
   * @returns {Object} Complete behavior analysis
   */
  analyze(data, deviceId = '') {
    // Validate input
    if (!data || typeof data !== 'object') {
      return this._createResult(null, null, null, null, 100, 'invalid_data');
    }

    // Extract raw data
    const mouseData = data.mouseMovements || [];
    const scrollData = data.scrollEvents || [];
    const clickData = data.clickEvents || [];
    const keyData = data.keyEvents || [];
    const timingData = {
      pageLoadTime: data.pageLoadTime || 0,
      firstInteraction: data.firstInteraction || 0,
      formFields: data.formFields || [],
      interactionTimestamps: data.interactionTimestamps || []
    };

    const pageLoadTime = data.pageLoadTime || Date.now();
    const currentTime = data.currentTime || Date.now();
    const timeOnPage = currentTime - pageLoadTime;

    // Run sub-analyses
    const mouse = this._analyzeMouse(mouseData);
    const scroll = this._analyzeScroll(scrollData, data.pageHeight || 5000);
    const timing = this._analyzeTiming(timingData, timeOnPage);
    const interactions = this._analyzeInteractions(mouseData, scrollData, clickData, keyData, timeOnPage);

    // Compute composite score
    const botScore = this._computeBotScore(mouse, scroll, timing, interactions);
    const verdict = this._getVerdict(botScore);
    const meetsRequirements = this._checkRequirements(mouseData, scrollData, clickData, timeOnPage);

    const result = this._createResult(mouse, scroll, timing, interactions, botScore, verdict);
    result.meetsRequirements = meetsRequirements;
    result.timeOnPage = timeOnPage;
    result.deviceId = deviceId;

    // Adaptive profile
    if (deviceId && this.useAdaptiveThresholds) {
      const profile = this._getOrCreateProfile(deviceId);
      const comparison = profile.compareToProfile(result);
      result.profileComparison = comparison;

      // Increase bot score if behavior deviates from profile
      if (!comparison.matches && profile.confidence > 0.5) {
        result.botScore = Math.min(100, result.botScore + comparison.score);
        result.verdict = this._getVerdict(result.botScore);
      }

      profile.recordSession(result);
      this._persistProfile(profile).catch(() => {});
    }

    return result;
  }

  /**
   * Analyze mouse movements.
   * @private
   */
  _analyzeMouse(movements) {
    if (!movements || movements.length < 3) {
      return {
        entropy: 0,
        curvature: 0,
        speedVariance: { variance: 0, avgSpeed: 0, cv: 0 },
        pausePoints: 0,
        directionChanges: 0,
        acceleration: { linearity: 1, pattern: 'unknown' },
        straightness: 0,
        teleports: 0,
        pathLength: 0,
        idleTime: 0,
        movementCount: movements ? movements.length : 0
      };
    }

    const speeds = this.mouseAnalyzer.calculateSpeedVariance(movements);

    return {
      entropy: this.mouseAnalyzer.calculateEntropy(movements),
      curvature: this.mouseAnalyzer.calculateCurvature(movements),
      speedVariance: speeds,
      pausePoints: this.mouseAnalyzer.countPausePoints(movements),
      directionChanges: this.mouseAnalyzer.countDirectionChanges(movements),
      acceleration: this.mouseAnalyzer.calculateAcceleration(movements),
      straightness: this.mouseAnalyzer.calculateStraightness(movements),
      teleports: this.mouseAnalyzer.countTeleports(movements),
      pathLength: this.mouseAnalyzer.calculatePathLength(movements),
      idleTime: this.mouseAnalyzer.calculateIdleTime(movements),
      movementCount: movements.length
    };
  }

  /**
   * Analyze scroll events.
   * @private
   */
  _analyzeScroll(scrolls, pageHeight) {
    if (!scrolls || scrolls.length < 1) {
      return {
        eventCount: 0,
        speedVariance: { variance: 0, avgSpeed: 0, cv: 0 },
        directionChanges: 0,
        pauses: 0,
        depthProgression: { progression: 'none', monotonicity: 0, jumps: 0 },
        momentumScroll: false,
        instantScroll: false,
        totalDistance: 0
      };
    }

    const speedVar = this.scrollAnalyzer.calculateSpeedVariance(scrolls);
    const depthProg = this.scrollAnalyzer.analyzeDepthProgression(scrolls);

    return {
      eventCount: scrolls.length,
      speedVariance: speedVar,
      directionChanges: this.scrollAnalyzer.countDirectionChanges(scrolls),
      pauses: this.scrollAnalyzer.countPauses(scrolls),
      depthProgression: depthProg,
      momentumScroll: this.scrollAnalyzer.detectMomentumScroll(scrolls),
      instantScroll: this.scrollAnalyzer.detectInstantScrollToBottom(scrolls, pageHeight),
      totalDistance: this.scrollAnalyzer.calculateTotalDistance(scrolls)
    };
  }

  /**
   * Analyze timing patterns.
   * @private
   */
  _analyzeTiming(timing, timeOnPage) {
    const keyAnalysis = this.timingAnalyzer.analyzeKeyPresses(timing.keyEvents || []);
    const clickAnalysis = this.timingAnalyzer.analyzeClickTiming(timing.clickEvents || []);
    const formAnalysis = this.timingAnalyzer.analyzeFormFill(timing.formFields || []);
    const burstAnalysis = this.timingAnalyzer.detectBurst(timing.interactionTimestamps || []);
    const firstDelay = this.timingAnalyzer.firstInteractionDelay(
      timing.pageLoadTime,
      timing.firstInteraction
    );

    return {
      timeOnPage,
      firstInteractionDelay: firstDelay,
      keyPressAnalysis: keyAnalysis,
      clickAnalysis,
      formFillAnalysis: formAnalysis,
      burstAnalysis,
      instantFormFill: formAnalysis.suspiciousFields.length > 0,
      interactionBurst: burstAnalysis.isBurst
    };
  }

  /**
   * Analyze overall interaction patterns.
   * @private
   */
  _analyzeInteractions(mouseData, scrollData, clickData, keyData, timeOnPage) {
    const interactionTimestamps = [];

    if (mouseData) {
      for (const m of mouseData) {
        if (m.t) interactionTimestamps.push(m.t);
      }
    }
    if (scrollData) {
      for (const s of scrollData) {
        if (s.t) interactionTimestamps.push(s.t);
      }
    }
    if (clickData) {
      for (const c of clickData) {
        if (c.timestamp) interactionTimestamps.push(c.timestamp);
      }
    }
    if (keyData) {
      for (const k of keyData) {
        if (k.timestamp) interactionTimestamps.push(k.timestamp);
      }
    }

    const sorted = [...new Set(interactionTimestamps)].sort((a, b) => a - b);
    const intervalAnalysis = this.timingAnalyzer.analyzeIntervals(sorted);

    return {
      total: interactionTimestamps.length,
      mouseMovements: mouseData ? mouseData.length : 0,
      scrollEvents: scrollData ? scrollData.length : 0,
      clickEvents: clickData ? clickData.length : 0,
      keyEvents: keyData ? keyData.length : 0,
      uniqueTimestamps: sorted.length,
      avgInterval: intervalAnalysis.avgInterval,
      intervalVariance: intervalAnalysis.variance,
      intervalCV: intervalAnalysis.cv,
      interactionsPerSecond: timeOnPage > 0 ? interactionTimestamps.length / (timeOnPage / 1000) : 0
    };
  }

  /**
   * Compute composite bot score (0-100).
   * @private
   */
  _computeBotScore(mouse, scroll, timing, interactions) {
    let score = 0;
    let weights = 0;

    // === MOUSE ANALYSIS (weight: 35) ===
    // Low entropy = bot
    if (mouse.entropy < MIN_HUMAN_ENTROPY) {
      const severity = (MIN_HUMAN_ENTROPY - mouse.entropy) / MIN_HUMAN_ENTROPY;
      score += severity * 25;
    }
    weights += 25;

    // Low curvature = bot
    if (mouse.curvature < MIN_HUMAN_CURVATURE) {
      score += 15;
    }
    weights += 15;

    // Low speed variance = bot
    if (mouse.speedVariance.cv < 0.1 && mouse.movementCount > 5) {
      score += 10;
    }
    weights += 10;

    // High straightness = bot
    if (mouse.straightness > MAX_HUMAN_STRAIGHTNESS) {
      score += 10;
    }
    weights += 10;

    // Teleports = definite bot
    score += Math.min(mouse.teleports * 15, 30);
    weights += 10;

    // No pause points = suspicious
    if (mouse.pausePoints === 0 && mouse.movementCount > 20) {
      score += 5;
    }
    weights += 5;

    // === SCROLL ANALYSIS (weight: 20) ===
    // Instant scroll to bottom = bot
    if (scroll.instantScroll) {
      score += 15;
    }
    weights += 10;

    // Low scroll variance = bot
    if (scroll.speedVariance.cv < 0.05 && scroll.eventCount > 3) {
      score += 5;
    }
    weights += 5;

    // Random jumps = suspicious
    if (scroll.depthProgression.progression === 'random_jumps') {
      score += 5;
    }
    weights += 5;

    // === TIMING ANALYSIS (weight: 30) ===
    // Too fast first interaction = bot
    if (timing.firstInteractionDelay > 0 && timing.firstInteractionDelay < MIN_FIRST_INTERACTION_DELAY) {
      score += 10;
    }
    weights += 10;

    // Consistent key presses = bot
    if (timing.keyPressAnalysis.botLike) {
      score += 10;
    }
    weights += 10;

    // Instant form fill = bot
    if (timing.instantFormFill) {
      score += 5;
    }
    weights += 5;

    // Interaction burst = bot
    if (timing.burstAnalysis.isBurst) {
      score += 10;
    }
    weights += 5;

    // Too fast on page = suspicious
    if (timing.timeOnPage > 0 && timing.timeOnPage < MIN_TIME_ON_PAGE) {
      const severity = 1 - (timing.timeOnPage / MIN_TIME_ON_PAGE);
      score += severity * 10;
    }
    weights += 5;

    // === INTERACTION REQUIREMENTS (weight: 15) ===
    // Too few interactions
    if (interactions.total < 4) {
      score += Math.min((4 - interactions.total) * 5, 15);
    }
    weights += 10;

    // Too many interactions per second
    if (interactions.interactionsPerSecond > MAX_INTERACTIONS_PER_SECOND) {
      score += 5;
    }
    weights += 5;

    // Normalize score
    const normalized = weights > 0 ? (score / weights) * 100 : 0;
    return Math.min(100, Math.max(0, Math.round(normalized)));
  }

  /**
   * Get verdict from bot score.
   * @private
   */
  _getVerdict(score) {
    if (score <= this.humanThreshold) return 'human';
    if (score <= this.suspiciousThreshold) return 'suspicious';
    if (score <= this.likelyBotThreshold) return 'likely_bot';
    return 'bot';
  }

  /**
   * Check if minimum interaction requirements are met.
   * @private
   */
  _checkRequirements(mouseData, scrollData, clickData, timeOnPage) {
    const mouseCount = mouseData ? mouseData.length : 0;
    const scrollCount = scrollData ? scrollData.length : 0;
    const clickCount = clickData ? clickData.length : 0;

    return {
      mouseMovements: mouseCount >= MIN_MOUSE_MOVEMENTS,
      scrollEvents: scrollCount >= MIN_SCROLL_EVENTS,
      clicks: clickCount >= MIN_CLICK_EVENTS,
      timeOnPage: timeOnPage >= MIN_TIME_ON_PAGE,
      allMet: mouseCount >= MIN_MOUSE_MOVEMENTS &&
              scrollCount >= MIN_SCROLL_EVENTS &&
              clickCount >= MIN_CLICK_EVENTS &&
              timeOnPage >= MIN_TIME_ON_PAGE
    };
  }

  /**
   * Create the final result object.
   * @private
   */
  _createResult(mouse, scroll, timing, interactions, botScore, verdict) {
    const recommendation = this._getRecommendation(verdict);

    return {
      botScore,
      verdict,
      recommendation,
      thresholds: {
        human: this.humanThreshold,
        suspicious: this.suspiciousThreshold,
        likelyBot: this.likelyBotThreshold,
        bot: 100
      },
      mouse,
      scroll,
      timing,
      interactions,
      meetsRequirements: null, // Filled later
      timeOnPage: 0,
      profileComparison: null,
      deviceId: '',
      analyzedAt: new Date().toISOString(),
      version: '5.0.0'
    };
  }

  /**
   * Get action recommendation based on verdict.
   * @private
   */
  _getRecommendation(verdict) {
    switch (verdict) {
      case 'human':
        return { action: 'allow', requiresCaptcha: false, requiresPoW: false, message: 'Human user detected' };
      case 'suspicious':
        return { action: 'challenge', requiresCaptcha: true, requiresPoW: false, message: 'Suspicious behavior - CAPTCHA required' };
      case 'likely_bot':
        return { action: 'challenge', requiresCaptcha: true, requiresPoW: true, message: 'Likely bot - Proof of Work required' };
      case 'bot':
        return { action: 'block', requiresCaptcha: false, requiresPoW: false, message: 'Bot detected - Access denied' };
      default:
        return { action: 'challenge', requiresCaptcha: true, requiresPoW: false, message: 'Unknown - Extra validation required' };
    }
  }

  /**
   * Get or create a behavior profile for a device.
   * @private
   */
  _getOrCreateProfile(deviceId) {
    let profile = this.profiles.get(deviceId);
    if (!profile) {
      profile = new BehaviorProfile(deviceId);
      this.profiles.set(deviceId, profile);
      this._loadProfile(deviceId).catch(() => {});
    }
    return profile;
  }

  /**
   * Load profile from database.
   * @private
   */
  async _loadProfile(deviceId) {
    if (!this.db) return;
    try {
      const doc = await this.db.collection('behavior_profiles').findOne({ deviceId });
      if (doc) {
        const profile = BehaviorProfile.deserialize(doc);
        this.profiles.set(deviceId, profile);
      }
    } catch {
      // Silently fail
    }
  }

  /**
   * Persist profile to database.
   * @private
   */
  async _persistProfile(profile) {
    if (!this.db) return;
    try {
      await this.db.collection('behavior_profiles').updateOne(
        { deviceId: profile.deviceId },
        { $set: profile.serialize() },
        { upsert: true }
      );
    } catch {
      // Silently fail
    }
  }

  /**
   * Get behavior profile for a device.
   * @param {string} deviceId - Device identifier
   * @returns {BehaviorProfile|null}
   */
  getProfile(deviceId) {
    return this.profiles.get(deviceId) || null;
  }

  /**
   * Clear all in-memory profiles.
   */
  clearProfiles() {
    this.profiles.clear();
  }

  /**
   * Get statistics about the analyzer.
   * @returns {Object}
   */
  getStats() {
    return {
      profilesLoaded: this.profiles.size,
      thresholds: {
        human: this.humanThreshold,
        suspicious: this.suspiciousThreshold,
        likelyBot: this.likelyBotThreshold
      },
      adaptiveEnabled: this.useAdaptiveThresholds,
      minRequirements: {
        mouseMovements: MIN_MOUSE_MOVEMENTS,
        scrollEvents: MIN_SCROLL_EVENTS,
        timeOnPage: MIN_TIME_ON_PAGE,
        clicks: MIN_CLICK_EVENTS
      }
    };
  }
}

// ============================================================================
// Exports
// ============================================================================

export { MouseAnalyzer, ScrollAnalyzer, TimingAnalyzer, BehaviorProfile };
export {
  MIN_MOUSE_MOVEMENTS,
  MIN_SCROLL_EVENTS,
  MIN_TIME_ON_PAGE,
  MIN_CLICK_EVENTS,
  MIN_HUMAN_ENTROPY,
  HUMAN_SPEED_RANGE,
  MAX_INTERACTIONS_PER_SECOND,
  BOT_SCORE_THRESHOLDS
};

/**
 * Factory function to create a BehaviorAnalyzer.
 * @param {Object} [options] - Configuration
 * @returns {BehaviorAnalyzer}
 */
export function createBehaviorAnalyzer(options) {
  return new BehaviorAnalyzer(options);
}

/**
 * Quick analyze function - one-shot analysis without persistence.
 * @param {Object} data - Client behavior data
 * @returns {Object} Analysis result
 */
export function quickAnalyze(data) {
  const analyzer = new BehaviorAnalyzer({ useAdaptiveThresholds: false });
  return analyzer.analyze(data);
}
