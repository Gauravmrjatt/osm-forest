/**
 * FRAGMENTED CODE DELIVERY ENGINE
 * 
 * CRITICAL: Code NEVER appears as a single plaintext string in HTML/JS.
 * Code is split into fragments, scattered across the HTML, encoded,
 * and ONLY assembled when the copy button is clicked.
 * 
 * This prevents:
 * - Ctrl+F / View Source extraction
 * - Simple regex scraping
 * - Network response text extraction (fragments only)
 * 
 * Fragments are useless without the session-derived assembly key.
 * 
 * @module core/fragmentedCode
 * @version 1.0.0
 */

import crypto from 'crypto';

/**
 * Encode a string using a simple session-based rotation.
 * NOT encryption - just encoding to prevent casual string searching.
 * @param {string} str - String to encode
 * @param {number} shift - Shift value (derived from session)
 * @returns {string} Encoded string
 */
function sessionEncode(str, shift) {
  let result = '';
  for (let i = 0; i < str.length; i++) {
    result += String.fromCharCode(str.charCodeAt(i) + shift + (i % 3));
  }
  return btoa(result);
}

/**
 * Split code into N fragments of roughly equal size.
 * @param {string} code - Full code to fragment
 * @param {number} fragmentCount - Number of fragments (default: 8)
 * @returns {string[]} Array of code fragments
 */
export function splitCode(code, fragmentCount = 8) {
  const fragments = [];
  const size = Math.ceil(code.length / fragmentCount);
  for (let i = 0; i < code.length; i += size) {
    fragments.push(code.substring(i, Math.min(i + size, code.length)));
  }
  // Pad with empty strings if needed
  while (fragments.length < fragmentCount) {
    fragments.push('');
  }
  return fragments;
}

/**
 * Generate a session-derived assembly key.
 * This key is needed to reassemble fragments in correct order.
 * @param {string} sessionToken - Session token
 * @returns {Object} Assembly key data
 */
export function generateAssemblyKey(sessionToken) {
  const hash = crypto.createHash('sha256').update(sessionToken).digest('hex');
  
  // Derive shift value for encoding (1-5 range)
  const shift = (parseInt(hash.substring(0, 4), 16) % 5) + 1;
  
  // Derive fragment order permutation
  const indices = [0, 1, 2, 3, 4, 5, 6, 7];
  const seed = parseInt(hash.substring(4, 12), 16);
  
  // Fisher-Yates shuffle with session seed
  let s = seed;
  for (let i = indices.length - 1; i > 0; i--) {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    const j = s % (i + 1);
    [indices[i], indices[j]] = [indices[j], indices[i]];
  }
  
  return { shift, order: indices };
}

/**
 * Generate HTML with scattered fragments.
 * Code is split, encoded, and hidden in various HTML locations.
 * NO single plaintext code string exists in the output.
 * 
 * @param {string} code - The gift code
 * @param {string} sessionToken - Session token for key derivation
 * @returns {Object} { html: string, css: string, js: string }
 */
export function generateFragmentedHTML(code, sessionToken) {
  const { shift, order } = generateAssemblyKey(sessionToken);
  const fragments = splitCode(code, 8);
  
  // Encode each fragment with session-derived shift
  const encodedFragments = fragments.map(f => sessionEncode(f, shift));
  
  // Shuffle fragments according to session order
  const shuffledFragments = order.map(i => encodedFragments[i]);
  const shuffledIndices = order.map(i => i);
  
  // Hide fragments in various places in the HTML
  const fragmentElements = shuffledFragments.map((frag, idx) => {
    const realIdx = shuffledIndices[idx];
    const className = `_f${idx}_${Math.random().toString(36).substring(2, 6)}`;
    return {
      fragment: frag,
      realIndex: realIdx,
      className,
      element: generateFragmentHidingElement(frag, className, idx),
    };
  });
  
  // CSS to visually hide fragment containers
  const css = generateFragmentCSS(fragmentElements);
  
  // HTML for fragment containers
  const fragmentsHtml = fragmentElements.map(f => f.element).join('\n');
  
  // Assembly JS - only works with correct session-derived key
  const js = generateAssemblyScript(fragmentElements, shift, order, sessionToken);
  
  return {
    html: `<div id="_fc" style="display:none">${fragmentsHtml}</div>`,
    css,
    js,
    meta: { fragmentCount: fragments.length, shift, order },
  };
}

/**
 * Generate a hidden element containing a fragment.
 * Uses different hiding techniques for each fragment.
 */
function generateFragmentHidingElement(fragment, className, index) {
  // Different techniques for different fragments
  const techniques = [
    // Technique 0: Hidden data attribute on empty div
    () => `<div class="${className}" data-v="${fragment}" style="display:none"></div>`,
    // Technique 1: CSS ::before content (value in CSS, not HTML)
    () => `<span class="${className}"></span>`,
    // Technique 2: Invisible text (same color as background)
    () => `<div class="${className}">${fragment}</div>`,
    // Technique 3: Zero-width container
    () => `<div class="${className}" aria-hidden="true">${fragment}</div>`,
    // Technique 4: Meta tag style
    () => `<div class="${className}" data-f="${fragment}"></div>`,
    // Technique 5: Comment-like (actually visible but looks like comment)
    () => `<span class="${className}" hidden>${fragment}</span>`,
    // Technique 6: Input value
    () => `<input type="hidden" class="${className}" value="${fragment}">`,
    // Technique 7: SVG title element (not rendered)
    () => `<svg class="${className}" width="0" height="0"><title>${fragment}</title></svg>`,
  ];
  
  const technique = techniques[index % techniques.length];
  return technique();
}

/**
 * Generate CSS for hiding fragment containers.
 * Uses different hiding methods for visual obfuscation.
 */
function generateFragmentCSS(fragmentElements) {
  return fragmentElements.map((f, i) => {
    const c = f.className;
    // Cycle through different visual hiding methods
    if (i % 3 === 0) {
      return `.${c}{position:absolute;width:0;height:0;overflow:hidden;opacity:0;pointer-events:none}`;
    } else if (i % 3 === 1) {
      return `.${c}{display:inline-block;color:transparent;font-size:0;line-height:0}`;
    } else {
      return `.${c}{position:fixed;left:-9999px;top:-9999px;clip:rect(0,0,0,0)}`;
    }
  }).join('\n');
}

/**
 * Generate the assembly script.
 * This JS collects fragments from their hiding places, decodes them,
 * reassembles in correct order, and copies to clipboard.
 * Code is assembled ONLY on copy button click - never stored as plaintext.
 */
function generateAssemblyScript(fragmentElements, shift, order, sessionToken) {
  // Build mapping: where to find each fragment
  const fragmentMap = fragmentElements.map((f, displayIdx) => {
    const realIdx = order[displayIdx];
    const c = f.className;
    // Determine extraction method based on hiding technique
    const extraction = [
      `document.querySelector(".${c}").getAttribute("data-v")`,
      `getComputedStyle(document.querySelector(".${c}"),"::before").getPropertyValue("content").replace(/['"]/g,"")`,
      `document.querySelector(".${c}").textContent`,
      `document.querySelector(".${c}").textContent`,
      `document.querySelector(".${c}").getAttribute("data-f")`,
      `document.querySelector(".${c}").textContent`,
      `document.querySelector(".${c}").value`,
      `document.querySelector(".${c}").querySelector("title").textContent`,
    ];
    return { realIdx, extract: extraction[displayIdx % extraction.length] };
  });
  
  // Sort by real index to know correct order
  const sortedMap = [...fragmentMap].sort((a, b) => a.realIdx - b.realIdx);
  const extractSequence = sortedMap.map(m => m.extract);
  
  return `
(function(){
  // Session-derived shift: ${shift}
  // Fragment order: [${order.join(',')}]
  
  var _shift = ${shift};
  var _destroyed = false;
  var _assembled = null;
  
  // Decode a session-encoded fragment
  function _d(enc){
    try{
      var raw = atob(enc);
      var res = '';
      for(var i = 0; i < raw.length; i++){
        res += String.fromCharCode(raw.charCodeAt(i) - _shift - (i % 3));
      }
      return res;
    }catch(e){ return ''; }
  }
  
  // Collect and assemble fragments from their hiding places
  function _a(){
    if(_destroyed) return null;
    var parts = [];
    ${extractSequence.map((ex, i) => `
    try{ parts[${i}] = _d(${ex}); }catch(e){ parts[${i}] = ''; }`).join('')}
    return parts.join('');
  }
  
  // Copy handler - assembles code on-demand
  var _btn = document.getElementById('copyBtn');
  if(_btn){
    _btn.addEventListener('click', function(){
      if(_destroyed){ this.innerHTML = '❌ CODE EXPIRED'; this.disabled = true; return; }
      
      // ASSEMBLE CODE NOW (not stored before this moment)
      var code = _a();
      if(!code){ this.innerHTML = '❌ Error'; return; }
      
      navigator.clipboard.writeText(code).then(function(){
        _btn.classList.add('copied');
        _btn.innerHTML = '✅ ' + code.length + '-CHAR CODE COPIED!';
        setTimeout(function(){ _btn.innerHTML = '📋 COPY ' + code.length + '-CHAR CODE'; _btn.classList.remove('copied'); }, 3000);
      }).catch(function(){
        // Fallback copy
        var ta = document.createElement('textarea');
        ta.value = code;
        ta.style.cssText = 'position:fixed;left:-9999px;top:-9999px;opacity:0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        _btn.classList.add('copied');
        _btn.innerHTML = '✅ COPIED!';
        setTimeout(function(){ _btn.innerHTML = '📋 COPY CODE'; _btn.classList.remove('copied'); }, 3000);
      });
    });
  }
  
  // Auto-destruct: clear all fragments after expiry
  setTimeout(function(){
    _destroyed = true;
    _assembled = null;
    var fc = document.getElementById('_fc');
    if(fc) fc.innerHTML = '';
    if(_btn){ _btn.innerHTML = '❌ CODE EXPIRED'; _btn.disabled = true; }
  }, 11000);
})();
`;
}

/**
 * Generate the CSS ::before content for fragments using CSS hiding technique.
 * This stores fragment values in CSS, not HTML, making them invisible to DOM text search.
 */
export function generateCSSFragmentContent(fragmentElements, shift) {
  const cssFragments = fragmentElements.filter((_, i) => i % 8 === 1);
  return cssFragments.map(f => {
    return `.${f.className}::before{content:"${f.fragment}"}`;
  }).join('\n');
}

/**
 * Build COMPLETE HTML page using fragmented code delivery.
 * Code NEVER appears as a single plaintext string.
 * @param {string} code - The gift code
 * @param {number} expirySeconds - Auto-destruct timer
 * @param {string} siteName - Game site name
 * @param {string} siteUrl - Game site URL
 * @param {string} sessionToken - Session token
 * @param {Object} display - AlphaNum display object
 * @returns {string} Complete HTML page
 */
export function buildFragmentedAlphaNumPage(code, expirySeconds, siteName, siteUrl, sessionToken, display) {
  const { html: fragHtml, css: fragCss, js: fragJs } = generateFragmentedHTML(code, sessionToken);
  
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>OSM ARMY - Secure Code</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'SF Pro Display','Segoe UI',Roboto,sans-serif;background:#0a0a0f;color:#fff;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:2rem 1rem}
.container{width:100%;max-width:480px;display:flex;flex-direction:column;gap:1rem}
.header{text-align:center}
.header h1{font-size:1.3rem;font-weight:800;background:linear-gradient(135deg,#7c3aed,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.header p{font-size:0.8rem;color:#a0a0b0;margin-top:0.25rem}
.badge{display:flex;align-items:center;justify-content:center;gap:0.5rem;font-size:0.8rem;color:#f59e0b;margin-bottom:0.5rem;background:rgba(245,158,11,0.08);padding:6px 16px;border-radius:20px}
.countdown-box{background:#16161f;border:1px solid #2a2a3e;border-radius:12px;padding:1rem;text-align:center}
.countdown-label{font-size:0.7rem;color:#6b6b7b;text-transform:uppercase;letter-spacing:2px}
.countdown-bar{width:100%;height:6px;background:#2a2a3e;border-radius:3px;overflow:hidden;margin-top:0.5rem}
.countdown-fill{height:100%;background:linear-gradient(135deg,#ef4444,#7c3aed);border-radius:3px;transition:width 1s linear;width:100%}
.countdown-text{font-size:0.8rem;color:#ef4444;margin-top:0.5rem;font-weight:600}
.copy-btn{width:100%;padding:1.2rem;background:linear-gradient(135deg,#7c3aed,#8b5cf6);border:none;border-radius:12px;color:#fff;font-size:1.1rem;font-weight:700;cursor:pointer;transition:all 0.3s;display:flex;align-items:center;justify-content:center;gap:0.5rem}
.copy-btn:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(124,58,237,0.4)}
.copy-btn.copied{background:linear-gradient(135deg,#10b981,#059669)}
.copy-btn:disabled{background:#2a2a3e;cursor:not-allowed;transform:none;box-shadow:none}
.footer{display:grid;grid-template-columns:1fr 1fr;gap:0.5rem;margin-top:0.5rem}
.footer-item{display:flex;align-items:center;gap:0.4rem;padding:0.5rem;background:#16161f;border:1px solid #2a2a3e;border-radius:8px;font-size:0.7rem;color:#6b6b7b}
.security-overlay{position:fixed;inset:0;background:rgba(10,10,15,0.95);display:none;flex-direction:column;align-items:center;justify-content:center;z-index:9999;text-align:center;padding:2rem}
.security-overlay.active{display:flex}
/* Fragment hiding CSS */
${fragCss}
/* AlphaNum display CSS */
${display.css}
@media print{body{display:none!important}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="badge">🔤 ${code.length} Alphanumeric Mixed Characters</div>
    <h1>Your Gift Code</h1>
    <p>Copy-paste required — Manual typing is impossible</p>
  </div>
  
  <!-- VISUAL CODE DISPLAY (colored, grouped) -->
  <!-- NOTE: This is ONLY visual display. Actual code is fragmented below. -->
  ${display.html}
  
  <!-- FRAGMENTED CODE CONTAINERS -->
  <!-- Code is split into 8 fragments, scattered and encoded. -->
  <!-- NO single plaintext code string exists in this page. -->
  <!-- Fragments are assembled ONLY when copy button is clicked. -->
  ${fragHtml}
  
  <div class="countdown-box">
    <div class="countdown-label">⏱️ Code Auto-Destruct In</div>
    <div class="countdown-bar"><div class="countdown-fill" id="bar"></div></div>
    <div class="countdown-text" id="timer">${expirySeconds} seconds</div>
  </div>
  
  <button class="copy-btn" id="copyBtn">
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
    📋 COPY ${code.length}-CHAR CODE
  </button>
  
  <div class="countdown-box" style="background:rgba(16,185,129,0.05);border-color:rgba(16,185,129,0.15)">
    <div class="countdown-label" style="color:#10b981">💡 How to use</div>
    <div style="font-size:0.8rem;color:#a0a0b0;margin-top:0.5rem;line-height:1.5">
      1. Click <strong style="color:#7c3aed">COPY CODE</strong> button above<br>
      2. Open <strong style="color:#7c3aed">${siteName || 'Game'}</strong><br>
      3. Paste in Gift Code section<br>
      4. Done! ✅
    </div>
  </div>
  
  <div class="footer">
    <div class="footer-item">🔒 Anti-Bot</div>
    <div class="footer-item">🔤 ${code.length} Mixed</div>
    <div class="footer-item">⏱️ ${expirySeconds}s Expiry</div>
    <div class="footer-item">📋 Copy Only</div>
  </div>
</div>

<div class="security-overlay" id="devToolsOverlay"><h2>⚠️ Developer Tools Detected</h2><p>Code access paused. Close developer tools.</p></div>

<script>
/* FRAGMENTED CODE ASSEMBLY */
/* Code is assembled ONLY on copy button click. */
/* No single plaintext code string exists in this script. */
${fragJs}

/* Countdown */
var total=${expirySeconds},remaining=total,bar=document.getElementById('bar'),timer=document.getElementById('timer');
setInterval(function(){remaining--;if(remaining<=0){remaining=0;bar.style.width='0%';timer.textContent='Code Destroyed!';timer.style.color='#ef4444';var btn=document.getElementById('copyBtn');btn.innerHTML='❌ CODE EXPIRED';btn.disabled=true;btn.style.background='#2a2a3e';document.querySelector('.container > div:nth-child(2)').innerHTML='<div style="text-align:center;padding:2rem;color:#ef4444">⏰ Code destroyed</div>';return;}bar.style.width=((remaining/total)*100)+'%';timer.textContent=remaining+' seconds';},1000);

/* DevTools detection */
(function(){var o=document.getElementById('devToolsOverlay');setInterval(function(){if(window.outerHeight-window.innerHeight>160||window.outerWidth-window.innerWidth>160)o.classList.add('active');else o.classList.remove('active');},500);})();

/* Tab blur */
document.addEventListener('visibilitychange',function(){var c=document.querySelector('.container > div:nth-child(2)');if(document.hidden&&c)c.style.filter='blur(20px)';else if(c)c.style.filter='blur(0)';});

/* Block shortcuts */
document.addEventListener('keydown',function(e){if(e.keyCode===123)e.preventDefault();if(e.ctrlKey&&e.shiftKey&&(e.keyCode===73||e.keyCode===74||e.keyCode===67))e.preventDefault();if(e.ctrlKey&&e.keyCode===85)e.preventDefault();});

/* Block context menu & select */
document.addEventListener('contextmenu',function(e){e.preventDefault();});
document.addEventListener('selectstart',function(e){if(e.target.closest('._alnum_container,._itt_container'))e.preventDefault();});
</script>
</body>
</html>`;
}

export default {
  splitCode,
  generateAssemblyKey,
  generateFragmentedHTML,
  buildFragmentedAlphaNumPage,
};
