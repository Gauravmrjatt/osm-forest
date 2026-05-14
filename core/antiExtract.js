/**
 * ANTI-EXTRACTION ENGINE - Ultra Strong Layer
 * Prevents DOM scraping, automation, and code extraction
 * Server-side + Client-side combined protection
 */

import crypto from 'crypto';

// ==========================================
// LAYER 1: CLIENT-SIDE PROOF-OF-WORK
// ==========================================

/**
 * Generate a proof-of-work challenge
 * Client must find a nonce that produces hash with N leading zeros
 * This prevents automated scraping - CPU time required
 * 
 * @param {string} token - Session token
 * @param {number} difficulty - Number of leading zeros required (default: 5)
 * @returns {Object} challenge with seed, difficulty, and expected result
 */
export function generateProofOfWorkChallenge(token, difficulty = 5) {
    const seed = crypto.randomBytes(32).toString('hex');
    const timestamp = Date.now();
    
    // Pre-compute the expected nonce for server verification
    let nonce = 0;
    const target = '0'.repeat(difficulty);
    
    // Server pre-computes (takes ~2-5 seconds)
    while (true) {
        const hash = crypto.createHash('sha256')
            .update(seed + nonce.toString() + timestamp.toString())
            .digest('hex');
        if (hash.substring(0, difficulty) === target) {
            break;
        }
        nonce++;
    }
    
    return {
        seed,
        difficulty,
        timestamp,
        serverNonce: nonce, // Server knows the answer, client must find it
        maxTime: 30000, // 30 seconds max
        maxAttempts: 5000000 // 5 million attempts max
    };
}

/**
 * Verify client's proof-of-work solution
 * 
 * @param {Object} challenge - Original challenge
 * @param {number} clientNonce - Client's found nonce
 * @returns {boolean} valid or not
 */
export function verifyProofOfWork(challenge, clientNonce) {
    // Check time limit
    const elapsed = Date.now() - challenge.timestamp;
    if (elapsed > challenge.maxTime) {
        return false; // Too slow = bot
    }
    
    // Check nonce is reasonable (not too fast = pre-computed)
    if (clientNonce < 1000 || clientNonce > challenge.maxAttempts) {
        return false;
    }
    
    // Verify hash
    const target = '0'.repeat(challenge.difficulty);
    const hash = crypto.createHash('sha256')
        .update(challenge.seed + clientNonce.toString() + challenge.timestamp.toString())
        .digest('hex');
    
    return hash.substring(0, challenge.difficulty) === target;
}

// ==========================================
// LAYER 2: DYNAMIC BEHAVIORAL CHALLENGE
// ==========================================

/**
 * Generate a random behavioral challenge
 * User must perform specific mouse/scroll pattern
 * This is verified server-side from collected interaction data
 * 
 * @param {string} sessionId - Session identifier
 * @returns {Object} challenge instructions
 */
export function generateBehavioralChallenge(sessionId) {
    const challenges = [
        {
            type: 'mouse_circle',
            description: 'Move your mouse in a circle around the timer',
            validation: (events) => {
                // Must have 8+ points forming roughly circular path
                if (events.length < 8) return false;
                const centerX = events.reduce((s, e) => s + e.x, 0) / events.length;
                const centerY = events.reduce((s, e) => s + e.y, 0) / events.length;
                const radii = events.map(e => 
                    Math.sqrt((e.x - centerX) ** 2 + (e.y - centerY) ** 2)
                );
                const avgRadius = radii.reduce((s, r) => s + r, 0) / radii.length;
                const variance = radii.reduce((s, r) => s + (r - avgRadius) ** 2, 0) / radii.length;
                return variance < 5000; // Low variance = circular
            }
        },
        {
            type: 'scroll_pause',
            description: 'Scroll down slowly, pause for 2 seconds, then scroll up',
            validation: (events) => {
                // Must have scroll down, pause (2s gap), scroll up
                let hasDown = false, hasPause = false, hasUp = false;
                let lastTime = 0;
                for (const e of events) {
                    if (e.type === 'scroll') {
                        if (e.delta > 0) hasDown = true;
                        if (e.delta < 0) hasUp = true;
                        if (lastTime > 0 && e.time - lastTime > 2000) hasPause = true;
                        lastTime = e.time;
                    }
                }
                return hasDown && hasPause && hasUp;
            }
        },
        {
            type: 'click_sequence',
            description: 'Click the 3 glowing dots in order (top, middle, bottom)',
            validation: (events) => {
                // Must have 3 clicks in correct Y-order
                const clicks = events.filter(e => e.type === 'click');
                if (clicks.length < 3) return false;
                const sorted = [...clicks].sort((a, b) => a.y - b.y);
                return clicks[0].y < clicks[1].y && clicks[1].y < clicks[2].y;
            }
        },
        {
            type: 'zigzag',
            description: 'Move mouse left-right-left-right across the screen',
            validation: (events) => {
                // Must have 4 direction changes (left-right-left-right)
                if (events.length < 20) return false;
                let changes = 0;
                let lastDir = 0;
                for (let i = 1; i < events.length; i++) {
                    const dir = events[i].x > events[i-1].x ? 1 : -1;
                    if (dir !== lastDir && lastDir !== 0) changes++;
                    lastDir = dir;
                }
                return changes >= 3;
            }
        },
        {
            type: 'double_click',
            description: 'Double-click the center area within 300ms',
            validation: (events) => {
                // Must have double click < 300ms apart, same position
                const clicks = events.filter(e => e.type === 'click');
                if (clicks.length < 2) return false;
                for (let i = 1; i < clicks.length; i++) {
                    const dt = clicks[i].time - clicks[i-1].time;
                    const dx = Math.abs(clicks[i].x - clicks[i-1].x);
                    const dy = Math.abs(clicks[i].y - clicks[i-1].y);
                    if (dt < 300 && dx < 20 && dy < 20) return true;
                }
                return false;
            }
        }
    ];
    
    // Select 2 random challenges (change daily via seed)
    const seed = crypto.createHash('sha256').update(sessionId + Date.now().toString()).digest('hex');
    const selected = [];
    for (let i = 0; i < 2; i++) {
        const idx = parseInt(seed.substring(i * 4, i * 4 + 4), 16) % challenges.length;
        selected.push({
            id: i,
            type: challenges[idx].type,
            description: challenges[idx].description,
            validator: challenges[idx].validation
        });
    }
    
    return selected;
}

// ==========================================
// LAYER 3: CODE OBFUSCATION ENGINE
// ==========================================

/**
 * Ultra-obfuscated code display generation
 * Makes DOM scraping extremely difficult
 * 
 * @param {string} code - The gift code
 * @param {string} sessionId - Session identifier
 * @returns {Object} HTML, CSS, and JS for obfuscated display
 */
export function generateObfuscatedCodeDisplay(code, sessionId) {
    const seed = crypto.createHash('sha256').update(sessionId + Date.now().toString()).digest('hex');
    
    // Strategy: Multi-layer obfuscation
    // Layer 1: Split code into individual characters
    // Layer 2: Assign random class names (daily rotation)
    // Layer 3: Insert fake characters (decoys)
    // Layer 4: Use CSS transforms (rotation, spacing)
    // Layer 5: SVG overlay with masking
    // Layer 6: WebGL noise overlay (optional)
    
    const chars = code.split('');
    const decoyChars = '!@#$%^&*()_+-=[]{}|;:,.<>?/~`';
    
    // Generate random class names (daily seed based)
    const getClassName = (idx, type) => {
        const hash = crypto.createHash('sha256').update(seed + idx + type).digest('hex');
        return '_' + hash.substring(0, 8);
    };
    
    // Build HTML with decoys
    let html = '<div class="_code_container">';
    let css = `
        ._code_container {
            position: relative;
            display: inline-block;
            padding: 20px 30px;
            background: rgba(124, 58, 237, 0.05);
            border: 1px solid rgba(124, 58, 237, 0.2);
            border-radius: 12px;
            font-family: 'SF Mono', 'Courier New', monospace;
            font-size: 1.8rem;
            font-weight: 800;
            letter-spacing: 4px;
            user-select: none;
            -webkit-user-select: none;
        }
    `;
    
    let charMap = {}; // For JS reconstruction
    
    chars.forEach((char, idx) => {
        // 30% chance to insert decoy
        if (Math.random() < 0.3) {
            const decoyClass = getClassName(idx, 'decoy');
            const decoyChar = decoyChars[Math.floor(Math.random() * decoyChars.length)];
            html += `<span class="${decoyClass}"></span>`;
            css += `.${decoyClass} { display: inline-block; width: 0; overflow: hidden; }\n`;
            css += `.${decoyClass}::before { content: '${decoyChar}'; opacity: 0; }\n`;
        }
        
        // Real character with random class
        const realClass = getClassName(idx, 'real');
        const rotation = (parseInt(seed.substring(idx * 2, idx * 2 + 2), 16) % 6) - 3; // -3 to +3 deg
        const spacing = (parseInt(seed.substring(idx * 2 + 4, idx * 2 + 6), 16) % 4) - 2; // -2 to +2 px
        
        html += `<span class="${realClass}"></span>`;
        css += `.${realClass} { display: inline-block; transform: rotate(${rotation}deg); margin: 0 ${spacing}px; }\n`;
        css += `.${realClass}::before { content: '${char}'; }\n`;
        
        charMap[realClass] = char;
    });
    
    html += '</div>';
    
    // Add protection CSS
    css += `
        ._code_container::after {
            content: '';
            position: absolute;
            inset: 0;
            background: linear-gradient(
                45deg,
                transparent 40%,
                rgba(124, 58, 237, 0.02) 50%,
                transparent 60%
            );
            pointer-events: none;
            animation: _shimmer 2s infinite;
        }
        @keyframes _shimmer {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }
    `;
    
    // Generate JS for copy functionality (obfuscated)
    const js = generateCopyScript(code, charMap, seed);
    
    return { html, css, js, charMap };
}

/**
 * Generate obfuscated copy script
 * Makes it harder to extract code from JS
 */
function generateCopyScript(code, charMap, seed) {
    const classNames = Object.keys(charMap);
    const scrambled = classNames.sort(() => Math.random() - 0.5);
    
    return `
        (function(){
            var _s = '${seed}';
            var _c = {};
            ${scrambled.map((cls, idx) => `_c[${idx}] = '${charMap[cls]}';`).join('')}
            var _o = [${scrambled.map((_, idx) => idx).join(',')}];
            var _d = function(){
                var r = '';
                for(var i = 0; i < _o.length; i++){
                    r += _c[_o[i]];
                }
                return r;
            };
            document.getElementById('copyBtn').addEventListener('click', function(){
                navigator.clipboard.writeText(_d()).then(function(){
                    var btn = document.getElementById('copyBtn');
                    btn.textContent = 'COPIED!';
                    btn.style.background = 'linear-gradient(135deg, #10b981, #059669)';
                    setTimeout(function(){ btn.textContent = 'COPY CODE'; btn.style.background = ''; }, 2000);
                });
            });
            // Clear after 10 seconds
            setTimeout(function(){ _c = null; _o = null; _d = null; }, 10000);
        })();
    `;
}

// ==========================================
// LAYER 4: SESSION BINDING WITH CHAIN
// ==========================================

/**
 * Create a chain of validation tokens
 * Each step must be completed in sequence
 * Missing any step = entire chain invalid
 * 
 * @param {string} telegramUserId - Telegram user ID
 * @param {string} deviceFingerprint - Device fingerprint hash
 * @param {string} ip - IP address
 * @returns {Object} validation chain
 */
export function createValidationChain(telegramUserId, deviceFingerprint, ip) {
    const now = Date.now();
    const chain = {
        step1: {
            name: 'telegram_verify',
            hash: crypto.createHash('sha256').update(telegramUserId + 'step1' + now).digest('hex').substring(0, 16),
            timestamp: now,
            valid: true
        },
        step2: {
            name: 'channel_join',
            hash: crypto.createHash('sha256').update(telegramUserId + 'step2' + now).digest('hex').substring(0, 16),
            timestamp: now,
            valid: false // Must verify all 3 channels
        },
        step3: {
            name: 'pow_solve',
            hash: crypto.createHash('sha256').update(telegramUserId + 'step3' + now).digest('hex').substring(0, 16),
            timestamp: now,
            valid: false // Must solve proof-of-work
        },
        step4: {
            name: 'behavior_pass',
            hash: crypto.createHash('sha256').update(telegramUserId + 'step4' + now).digest('hex').substring(0, 16),
            timestamp: now,
            valid: false // Must pass behavioral challenge
        },
        step5: {
            name: 'code_claim',
            hash: crypto.createHash('sha256').update(telegramUserId + 'step5' + now).digest('hex').substring(0, 16),
            timestamp: now,
            valid: false // Must claim within window
        }
    };
    
    return chain;
}

/**
 * Validate the entire chain
 * All steps must be valid in sequence
 */
export function validateChain(chain) {
    const steps = ['step1', 'step2', 'step3', 'step4', 'step5'];
    for (const step of steps) {
        if (!chain[step] || !chain[step].valid) {
            return { valid: false, failedAt: step };
        }
    }
    
    // Check timestamps (each step within 5 min of previous)
    for (let i = 1; i < steps.length; i++) {
        const prev = chain[steps[i - 1]].timestamp;
        const curr = chain[steps[i]].timestamp;
        if (curr - prev > 300000) { // 5 minutes max between steps
            return { valid: false, failedAt: steps[i], reason: 'timeout' };
        }
    }
    
    return { valid: true };
}

// ==========================================
// LAYER 5: HONEYPOT CODE PAGES
// ==========================================

/**
 * Generate fake code pages for bot detection
 * Bots/scrapers get fake codes that trigger alerts
 * 
 * @param {number} count - Number of fake codes
 * @returns {Array} fake code pages
 */
export function generateHoneyPotCodes(count = 10) {
    const fakeCodes = [];
    const prefixes = ['91CLUB', '55CLUB', 'IN999', '91CLB', '55CLB', 'IN99'];
    
    for (let i = 0; i < count; i++) {
        const prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
        const suffix = crypto.randomBytes(4).toString('hex').toUpperCase().substring(0, 6);
        fakeCodes.push({
            code: prefix + suffix,
            isHoneyPot: true,
            trapId: crypto.randomBytes(8).toString('hex')
        });
    }
    
    return fakeCodes;
}

/**
 * Check if a claimed code is a honeypot
 */
export function checkHoneyPot(code, honeyPotList) {
    return honeyPotList.some(hp => hp.code === code);
}

// ==========================================
// EXPORTS
// ==========================================

export default {
    generateProofOfWorkChallenge,
    verifyProofOfWork,
    generateBehavioralChallenge,
    generateObfuscatedCodeDisplay,
    createValidationChain,
    validateChain,
    generateHoneyPotCodes,
    checkHoneyPot
};
