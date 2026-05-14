/**
 * LONG CODE PROTECTION ENGINE
 * Special handling for 30-35 digit gift codes
 * Makes display, extraction, and manual copying extremely difficult
 * Piyush's worst nightmare
 */

import crypto from 'crypto';

/**
 * Split long code into visual segments with varying display strategies
 * Each segment uses different rendering technique
 * Only combined segments show full code - individual extraction is useless
 * 
 * @param {string} code - 30-35 digit code (e.g. "91CLUB55WELCOME2026BONUS999")
 * @param {string} sessionId - Unique session identifier
 * @returns {Object} { html, css, js, segments }
 */
export function generateSegmentedDisplay(code, sessionId) {
    const seed = crypto.createHash('sha256').update(sessionId + Date.now().toString()).digest('hex');
    
    // Split code into 5 segments (6-7 chars each)
    const segmentSize = Math.ceil(code.length / 5);
    const segments = [];
    for (let i = 0; i < code.length; i += segmentSize) {
        segments.push({
            index: segments.length,
            text: code.substring(i, Math.min(i + segmentSize, code.length)),
        });
    }
    
    // 5 different rendering strategies for each segment
    const strategies = [
        // Strategy 1: CSS ::before (invisible in HTML)
        (seg, cls) => {
            return {
                html: `<span class="${cls}" data-s="${seg.index}"></span>`,
                css: `.${cls}::before { content: '${escapeCSS(seg.text)}'; letter-spacing: 3px; }`,
            };
        },
        // Strategy 2: CSS ::after (different pseudo-element)
        (seg, cls) => {
            return {
                html: `<span class="${cls}" data-seg="${seg.index}"></span>`,
                css: `.${cls}::after { content: '${escapeCSS(seg.text)}'; letter-spacing: 3px; font-weight: 700; }`,
            };
        },
        // Strategy 3: CSS custom property (variable)
        (seg, cls) => {
            return {
                html: `<span class="${cls}" style="--c${seg.index}:'${escapeCSS(seg.text)}'"></span>`,
                css: `.${cls}::before { content: var(--c${seg.index}); letter-spacing: 3px; color: var(--accent-light); }`,
            };
        },
        // Strategy 4: SVG text path (rendered as vector)
        (seg, cls) => {
            const svgId = `_svg_${seg.index}_${seed.substring(0, 6)}`;
            return {
                html: `<svg class="${cls}" width="${seg.text.length * 18}" height="32" viewBox="0 0 ${seg.text.length * 18} 32"><text x="0" y="24" font-family="monospace" font-size="20" font-weight="700" fill="#ffffff" letter-spacing="3">${escapeXML(seg.text)}</text></svg>`,
                css: `.${cls} { display: inline-block; vertical-align: middle; margin: 0 4px; }`,
            };
        },
        // Strategy 5: CSS attr() function
        (seg, cls) => {
            return {
                html: `<span class="${cls}" data-code="${seg.text}"></span>`,
                css: `.${cls}::before { content: attr(data-code); letter-spacing: 3px; filter: blur(0); }`,
            };
        },
    ];
    
    let html = '<div class="_lc_container">';
    let css = `
        ._lc_container {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0;
            padding: 20px 15px;
            background: rgba(124, 58, 237, 0.05);
            border: 1px solid rgba(124, 58, 237, 0.2);
            border-radius: 12px;
            position: relative;
            overflow: hidden;
        }
        ._lc_container::before {
            content: '';
            position: absolute;
            inset: 0;
            background: linear-gradient(135deg, rgba(124, 58, 237, 0.08), transparent);
            pointer-events: none;
        }
        ._lc_segment {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-family: 'SF Mono', 'Courier New', monospace;
            font-size: 1.4rem;
            font-weight: 800;
            letter-spacing: 3px;
            position: relative;
            z-index: 1;
        }
        ._lc_separator {
            display: inline-flex;
            align-items: center;
            color: var(--accent);
            font-weight: 800;
            padding: 0 4px;
            position: relative;
            z-index: 1;
            font-size: 1.4rem;
            user-select: none;
        }
    `;
    
    segments.forEach((seg, i) => {
        const hash = crypto.createHash('sha256').update(seed + seg.index).digest('hex');
        const cls = `_lc_s${seg.index}_${hash.substring(0, 8)}`;
        const strategy = strategies[i % strategies.length];
        const result = strategy(seg, cls);
        
        html += `<span class="_lc_segment ${cls}">${result.html}</span>`;
        css += result.css;
        
        // Add separator between segments (except last)
        if (i < segments.length - 1) {
            html += `<span class="_lc_separator">-</span>`;
        }
    });
    
    html += '</div>';
    
    return { html, css, segments };
}

/**
 * Generate "Masked Display" - only shows last 5 digits, rest hidden
 * Forces user to use COPY button
 * 
 * @param {string} code - 30-35 digit code
 * @returns {Object} { html, css }
 */
export function generateMaskedDisplay(code) {
    const visible = code.substring(code.length - 5); // Last 5 chars visible
    const hiddenLength = code.length - 5; // 25-30 chars hidden
    
    return {
        html: `
            <div class="_mask_container">
                <div class="_mask_dots">${'•'.repeat(hiddenLength)}</div>
                <div class="_mask_visible">${visible}</div>
                <div class="_mask_hint">Code is too long to display. Use COPY button.</div>
            </div>
        `,
        css: `
            ._mask_container {
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 0.75rem;
                padding: 20px 15px;
                background: rgba(124, 58, 237, 0.05);
                border: 1px solid rgba(124, 58, 237, 0.2);
                border-radius: 12px;
            }
            ._mask_dots {
                font-family: 'SF Mono', monospace;
                font-size: 1.6rem;
                font-weight: 800;
                color: var(--text-dim);
                letter-spacing: 3px;
                user-select: none;
            }
            ._mask_visible {
                font-family: 'SF Mono', monospace;
                font-size: 1.6rem;
                font-weight: 800;
                color: var(--accent-light);
                letter-spacing: 4px;
                background: linear-gradient(135deg, #7c3aed, #8b5cf6);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }
            ._mask_hint {
                font-size: 0.75rem;
                color: var(--text-muted);
                text-align: center;
                margin-top: 0.5rem;
            }
        `,
    };
}

/**
 * Generate "Progressive Reveal" display
 * Code reveals 5 chars every 2 seconds (12+ seconds for full code)
 * Forces user to wait AND makes screenshot capture harder
 * 
 * @param {string} code - 30-35 digit code
 * @param {string} sessionId - Session identifier
 * @returns {Object} { html, css, js }
 */
export function generateProgressiveReveal(code, sessionId) {
    const seed = crypto.createHash('sha256').update(sessionId + Date.now().toString()).digest('hex');
    const chunkSize = 5;
    const chunks = [];
    
    for (let i = 0; i < code.length; i += chunkSize) {
        chunks.push(code.substring(i, Math.min(i + chunkSize, code.length)));
    }
    
    const cls = `_pr_${seed.substring(0, 8)}`;
    
    let html = `<div class="${cls}_container">`;
    html += `<div class="${cls}_counter">0 / ${code.length} digits revealed</div>`;
    
    chunks.forEach((chunk, i) => {
        html += `<span class="${cls}_chunk" data-chunk="${i}" style="opacity:0;filter:blur(10px)">${chunk}</span>`;
        if (i < chunks.length - 1) {
            html += `<span class="${cls}_sep">-</span>`;
        }
    });
    
    html += `<div class="${cls}_progress"><div class="${cls}_bar"></div></div>`;
    html += '</div>';
    
    const css = `
        .${cls}_container {
            display: flex;
            align-items: center;
            justify-content: center;
            flex-wrap: wrap;
            gap: 4px;
            padding: 20px 15px;
            background: rgba(124, 58, 237, 0.05);
            border: 1px solid rgba(124, 58, 237, 0.2);
            border-radius: 12px;
            min-height: 80px;
        }
        .${cls}_counter {
            width: 100%;
            text-align: center;
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-bottom: 8px;
        }
        .${cls}_chunk {
            font-family: 'SF Mono', monospace;
            font-size: 1.4rem;
            font-weight: 800;
            color: var(--accent-light);
            letter-spacing: 3px;
            transition: all 0.5s ease;
        }
        .${cls}_chunk._revealed {
            opacity: 1 !important;
            filter: blur(0) !important;
        }
        .${cls}_sep {
            color: var(--accent);
            font-weight: 800;
            font-size: 1.4rem;
            user-select: none;
        }
        .${cls}_progress {
            width: 100%;
            height: 4px;
            background: var(--border);
            border-radius: 2px;
            margin-top: 10px;
            overflow: hidden;
        }
        .${cls}_bar {
            height: 100%;
            width: 0%;
            background: var(--accent-gradient);
            border-radius: 2px;
            transition: width 0.5s ease;
        }
    `;
    
    // JS: Progressive reveal
    const js = `
        (function(){
            var chunks = document.querySelectorAll('.${cls}_chunk');
            var counter = document.querySelector('.${cls}_counter');
            var bar = document.querySelector('.${cls}_bar');
            var totalDigits = ${code.length};
            var revealed = 0;
            
            function revealNext(){
                var idx = Array.from(chunks).findIndex(function(c){ return !c.classList.contains('_revealed'); });
                if(idx === -1) return;
                
                chunks[idx].classList.add('_revealed');
                revealed += chunks[idx].textContent.length;
                counter.textContent = revealed + ' / ' + totalDigits + ' digits revealed';
                bar.style.width = ((revealed / totalDigits) * 100) + '%';
            }
            
            // Reveal one chunk every 2 seconds
            var interval = setInterval(function(){
                revealNext();
                if(Array.from(chunks).every(function(c){ return c.classList.contains('_revealed'); })){
                    clearInterval(interval);
                    counter.textContent = '✅ Full code revealed!';
                    counter.style.color = 'var(--success)';
                }
            }, 2000);
            
            // Start immediately
            revealNext();
        })();
    `;
    
    return { html, css, js, chunks };
}

/**
 * Generate "Copy-Only Mode" display
 * Code is COMPLETELY HIDDEN - only copy button shown
 * User MUST click copy to get code
 * Most secure option for long codes
 * 
 * @param {string} code - 30-35 digit code
 * @returns {Object} { html, css, js }
 */
export function generateCopyOnlyMode(code) {
    const seed = crypto.randomBytes(16).toString('hex');
    const cls = `_co_${seed.substring(0, 8)}`;
    
    return {
        html: `
            <div class="${cls}_container">
                <div class="${cls}_icon">🔒</div>
                <div class="${cls}_title">Your Code is Ready</div>
                <div class="${cls}_desc">
                    Your ${code.length}-digit code is secure and ready to copy.
                    <br>The code is too long to display safely.
                </div>
                <div class="${cls}_hint">
                    ⏱️ You have 10 seconds to copy the code
                </div>
            </div>
        `,
        css: `
            .${cls}_container {
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 0.75rem;
                padding: 30px 20px;
                background: rgba(16, 185, 129, 0.05);
                border: 1px solid rgba(16, 185, 129, 0.2);
                border-radius: 12px;
                text-align: center;
            }
            .${cls}_icon {
                font-size: 2.5rem;
                margin-bottom: 0.5rem;
            }
            .${cls}_title {
                font-size: 1.1rem;
                font-weight: 700;
                color: var(--success);
            }
            .${cls}_desc {
                font-size: 0.85rem;
                color: var(--text-secondary);
                line-height: 1.5;
            }
            .${cls}_hint {
                font-size: 0.75rem;
                color: var(--warning);
                margin-top: 0.5rem;
                padding: 8px 16px;
                background: rgba(245, 158, 11, 0.08);
                border-radius: 8px;
            }
        `,
        js: `
            // Copy-only: code is not in DOM, only in JS closure
            (function(){
                var code = '${escapeJS(code)}';
                document.getElementById('copyBtn').addEventListener('click', function(){
                    navigator.clipboard.writeText(code).then(function(){
                        var btn = document.getElementById('copyBtn');
                        btn.innerHTML = '✅ COPIED!';
                        btn.style.background = 'linear-gradient(135deg, #10b981, #059669)';
                        setTimeout(function(){ 
                            btn.innerHTML = '📋 COPY CODE'; 
                            btn.style.background = ''; 
                        }, 2000);
                    });
                });
                // Clear code from memory after 10 seconds
                setTimeout(function(){ code = null; }, 10000);
            })();
        `,
    };
}

/**
 * Select display strategy based on code length and security level
 * For 30-35 digit codes: Use the strongest protection
 * 
 * @param {string} code - Gift code
 * @param {string} sessionId - Session ID
 * @param {string} mode - 'segmented' | 'masked' | 'progressive' | 'copyonly'
 * @returns {Object} { html, css, js, mode }
 */
export function generateLongCodeDisplay(code, sessionId, mode = 'auto') {
    if (mode === 'auto') {
        // Auto-select based on code length
        if (code.length >= 30) {
            // For 30+ digit codes: use copy-only mode (most secure)
            // or segmented display with 5 different strategies
            const strategies = ['copyonly', 'segmented', 'progressive'];
            const seed = crypto.createHash('sha256').update(sessionId).digest('hex');
            const idx = parseInt(seed.substring(0, 4), 16) % strategies.length;
            mode = strategies[idx];
        } else {
            mode = 'segmented';
        }
    }
    
    switch (mode) {
        case 'copyonly':
            return { ...generateCopyOnlyMode(code), mode: 'copyonly' };
        case 'masked':
            return { ...generateMaskedDisplay(code), mode: 'masked' };
        case 'progressive':
            return { ...generateProgressiveReveal(code, sessionId), mode: 'progressive' };
        case 'segmented':
        default:
            return { ...generateSegmentedDisplay(code, sessionId), mode: 'segmented' };
    }
}

// ==========================================
// UTILITIES
// ==========================================

function escapeCSS(str) {
    return str.replace(/'/g, "\\'").replace(/\\/g, '\\\\');
}

function escapeXML(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function escapeJS(str) {
    return str.replace(/'/g, "\\'").replace(/\\/g, '\\\\').replace(/\n/g, '\\n');
}

// ==========================================
// EXPORTS
// ==========================================

export default {
    generateSegmentedDisplay,
    generateMaskedDisplay,
    generateProgressiveReveal,
    generateCopyOnlyMode,
    generateLongCodeDisplay,
};
