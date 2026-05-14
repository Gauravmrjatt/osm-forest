/**
 * @fileoverview codeRenderer.js - Server-Side Code Renderer
 * @description Renders gift codes as complete HTML pages server-side.
 * This is the ONLY way code reaches the user. API NEVER returns code data.
 * Uses anti-scrape fragmentation, auto-destruct countdown, and copy protection.
 * @module core/codeRenderer
 * @version 2.0.0
 */

import { SecureCodeDisplay } from './secureDisplay.js';
import { AntiOCRGenerator } from './canvas.js';
import { WatermarkEngine } from './watermark.js';

const DEFAULT_EXPIRY = 10;

/**
 * CodeRenderer - Server-side renderer for secure code delivery.
 * All code rendering happens server-side. No code data ever touches the API JSON responses.
 */
class CodeRenderer {
  /**
   * Create a new CodeRenderer instance.
   * @param {object} [options] - Configuration options.
   * @param {number} [options.expirySeconds=10] - Auto-destruct countdown in seconds.
   */
  constructor(options = {}) {
    this.config = {
      expirySeconds: options.expirySeconds || DEFAULT_EXPIRY,
    };
  }

  /**
   * Render a complete code reveal page as an HTML string.
   * This is the primary delivery method. Code is embedded server-side.
   * @param {string} code - The plaintext gift code.
   * @param {string} sessionToken - Session token for anti-scrape class generation.
   * @param {string} [siteName='Site'] - Name of the site to show in iframe.
   * @param {string} [siteUrl=''] - URL to load in iframe.
   * @returns {string} Complete HTML page ready to send to client.
   */
  renderCodePage(code, sessionToken, siteName = 'Site', siteUrl = '') {
    const display = new SecureCodeDisplay({ expirySeconds: this.config.expirySeconds });
    const result = display.generateDisplayHTML(code, sessionToken);
    return this.generatePageHTML(code, siteName, siteUrl, this.config.expirySeconds, result);
  }

  /**
   * Render code as an anti-scrape HTML/CSS fragment (server-side only).
   * Does not include the full page wrapper. Useful for embedding elsewhere.
   * @param {string} code - The plaintext gift code.
   * @returns {{html: string, css: string}} Fragment HTML and CSS.
   */
  renderCodeHTML(code) {
    const display = new SecureCodeDisplay({ expirySeconds: this.config.expirySeconds });
    // Use a random session prefix for standalone rendering
    const dummyToken = Math.random().toString(36).slice(2) + Date.now().toString(36);
    const result = display.generateDisplayHTML(code, dummyToken);
    return {
      html: result.html,
      css: result.css,
    };
  }

  /**
   * Render code as a PNG image buffer (server-side only).
   * @param {string} code - The plaintext gift code.
   * @param {object} [options] - Image generation options.
   * @returns {Buffer} PNG image buffer.
   */
  renderCodeImage(code, options = {}) {
    const generator = new AntiOCRGenerator();
    const image = generator.generate(code, {
      width: options.width || 600,
      height: options.height || 200,
      noiseLevel: options.noiseLevel || 'high',
      fontDistortion: options.fontDistortion !== false,
      colorMutation: options.colorMutation !== false,
    });
    return image;
  }

  /**
   * Generate anti-scrape HTML fragment for a code.
   * Delegates to SecureCodeDisplay strategies.
   * @param {string} code - The plaintext gift code.
   * @returns {string} HTML fragment string.
   */
  generateAntiScrapeHTML(code) {
    const { html } = this.renderCodeHTML(code);
    return html;
  }

  /**
   * Generate client-side auto-destruct script.
   * Removes code from DOM after expiry and clears any variables.
   * @param {number} [expirySeconds] - Countdown duration in seconds.
   * @returns {string} JavaScript code string.
   */
  generateDestructScript(expirySeconds = this.config.expirySeconds) {
    return `
(function(){
  var TOTAL=${expirySeconds}*1000;
  var start=Date.now();
  var fill=document.getElementById("_osm-progress-fill");
  var timeText=document.getElementById("_osm-time-text");
  var display=document.getElementById("_osm-secure-display");
  var expired=document.getElementById("_osm-expired");
  var container=document.getElementById("code-display-container");
  var copyBtn=document.getElementById("_osm-copy-btn");
  var destroyed=false;
  function tick(){
    if(destroyed)return;
    var elapsed=Date.now()-start;
    var remaining=Math.max(0,TOTAL-elapsed);
    var pct=(remaining/TOTAL)*100;
    if(fill)fill.style.width=pct+"%";
    if(timeText)timeText.textContent=Math.ceil(remaining/1000)+"s";
    if(remaining>0){
      requestAnimationFrame(tick);
    }else{
      _osmDestroy();
    }
  }
  function _osmDestroy(){
    destroyed=true;
    if(display){
      display.style.filter="blur(20px)";
      display.style.opacity="0.3";
      display.style.transition="all 0.5s ease";
      setTimeout(function(){
        display.innerHTML="";
        if(container)container.classList.add("_osm-hidden");
        if(expired)expired.classList.remove("_osm-hidden");
      },500);
    }
    if(window._osmCode)window._osmCode=null;
    if(copyBtn){
      copyBtn.disabled=true;
      copyBtn.textContent="EXPIRED";
      copyBtn.style.opacity="0.5";
      copyBtn.style.cursor="not-allowed";
    }
    document.querySelectorAll("._osm-sensitive").forEach(function(el){
      el.textContent="";
      el.removeAttribute("data-code");
    });
  }
  if(document.readyState==="complete"||document.readyState==="interactive"){
    requestAnimationFrame(tick);
  }else{
    document.addEventListener("DOMContentLoaded",function(){requestAnimationFrame(tick);});
  }
})();`;
  }

  /**
   * Generate client-side copy-to-clipboard script.
   * @param {string} code - The code to copy.
   * @returns {string} JavaScript code string.
   */
  generateCopyScript(code) {
    const display = new SecureCodeDisplay({ expirySeconds: this.config.expirySeconds });
    return display.generateCopyScript(code);
  }

  /**
   * Generate countdown timer HTML fragment.
   * @param {number} [expirySeconds] - Countdown duration in seconds.
   * @returns {string} HTML string.
   */
  generateCountdownHTML(expirySeconds = this.config.expirySeconds) {
    return `
<div class="countdown-container" id="countdown-container">
  <div class="countdown-bar">
    <div class="countdown-fill" id="_osm-progress-fill" style="width:100%"></div>
  </div>
  <div class="countdown-text">
    <span class="countdown-label">Auto-destruct in</span>
    <span class="countdown-time" id="_osm-time-text">${expirySeconds}s</span>
  </div>
</div>
<div class="expired-message _osm-hidden" id="_osm-expired">
  <div class="expired-icon">&#128274;</div>
  <div class="expired-title">Code Expired</div>
  <div class="expired-desc">This code has self-destructed for security.</div>
</div>`;
  }

  /**
   * Generate the complete HTML page with embedded code.
   * This is the ONLY way code reaches the user. API NEVER returns code data.
   * @param {string} code - The plaintext gift code.
   * @param {string} siteName - Name of the site to show in iframe.
   * @param {string} siteUrl - URL to load in iframe.
   * @param {number} expirySeconds - Auto-destruct countdown duration.
   * @param {object} [secureDisplayResult] - Pre-generated result from SecureCodeDisplay.
   * @returns {string} Complete HTML page.
   */
  generatePageHTML(code, siteName, siteUrl, expirySeconds, secureDisplayResult = null) {
    if (!secureDisplayResult) {
      const display = new SecureCodeDisplay({ expirySeconds });
      secureDisplayResult = display.generateDisplayHTML(code, Math.random().toString(36));
    }

    const countdownHTML = this.generateCountdownHTML(expirySeconds);

    // Escape code for data-code attribute (must not be easily extractable)
    const escapedCodeForAttr = code
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');

    const iframeSection = siteUrl
      ? `
  <div class="iframe-section">
    <div class="iframe-header">
      <h3>&#127758; ${this._escapeHTML(siteName)}</h3>
    </div>
    <div class="iframe-container">
      <iframe src="${this._escapeHTML(siteUrl)}" sandbox="allow-scripts allow-same-origin allow-forms" loading="lazy" title="${this._escapeHTML(siteName)}"></iframe>
    </div>
  </div>`
      : '';

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="robots" content="noindex, nofollow, noarchive">
<title>Secure Code Reveal</title>
<style>
:root{--bg-primary:#1a0b2e;--bg-secondary:#2d1b4e;--bg-card:#24143d;--text-primary:#ffffff;--text-secondary:#b8a9c9;--accent:#ff6b35;--accent-hover:#ff8555;--success:#00d084;--danger:#ff3860;--border:rgba(255,255,255,0.08);--shadow:0 8px 32px rgba(0,0,0,0.4);}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg-primary);color:var(--text-primary);font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px}
.container{width:100%;max-width:720px;background:var(--bg-card);border:1px solid var(--border);border-radius:16px;box-shadow:var(--shadow);overflow:hidden}
.header{background:linear-gradient(135deg,var(--bg-secondary) 0%,var(--bg-primary) 100%);padding:24px;text-align:center;border-bottom:1px solid var(--border)}
.header h1{font-size:1.5rem;font-weight:700;margin-bottom:4px}
.header p{color:var(--text-secondary);font-size:0.875rem}
.code-section{padding:32px;text-align:center}
#code-display-container{transition:all .3s ease}
._osm-hidden{display:none!important}
.code-display{background:var(--bg-primary);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:20px;min-height:80px;display:flex;align-items:center;justify-content:center;font-size:32px;font-weight:700;letter-spacing:4px;position:relative;overflow-wrap:break-word}
${secureDisplayResult.css}
.copy-btn{background:var(--accent);color:#fff;border:none;border-radius:8px;padding:12px 28px;font-size:1rem;font-weight:600;cursor:pointer;transition:all .2s;display:inline-flex;align-items:center;gap:8px;margin-bottom:20px}
.copy-btn:hover{background:var(--accent-hover);transform:translateY(-1px)}
.copy-btn:active{transform:scale(0.98)}
.copy-btn:disabled{background:#555;cursor:not-allowed;opacity:0.5;transform:none}
.countdown-container{margin-bottom:20px}
.countdown-bar{width:100%;height:6px;background:rgba(255,255,255,0.1);border-radius:3px;overflow:hidden;margin-bottom:8px}
.countdown-fill{height:100%;background:linear-gradient(90deg,var(--accent),var(--danger));transition:width .1s linear;border-radius:3px}
.countdown-text{font-size:0.875rem;color:var(--text-secondary)}
.countdown-time{font-weight:700;color:var(--accent);margin-left:4px}
.expired-message{text-align:center;padding:40px 20px}
.expired-icon{font-size:3rem;margin-bottom:12px}
.expired-title{font-size:1.25rem;font-weight:700;color:var(--danger);margin-bottom:8px}
.expired-desc{color:var(--text-secondary);font-size:0.875rem}
.iframe-section{padding:0 32px 32px}
.iframe-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.iframe-header h3{font-size:1rem;color:var(--text-secondary)}
.iframe-container{width:100%;height:360px;border:1px solid var(--border);border-radius:12px;overflow:hidden;background:var(--bg-primary)}
.iframe-container iframe{width:100%;height:100%;border:none}
.footer{text-align:center;padding:16px;color:var(--text-secondary);font-size:0.75rem;border-top:1px solid var(--border)}
.toast-container{position:fixed;top:20px;right:20px;z-index:10000}
.toast{background:var(--success);color:#fff;padding:12px 20px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.3);font-weight:600;animation:slideIn .3s ease;margin-bottom:8px}
@keyframes slideIn{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>&#128272; Your Gift Code</h1>
    <p>Copy it now — this page will self-destruct in ${expirySeconds} seconds</p>
  </div>
  <div class="code-section">
    <div id="code-display-container">
      <div class="code-display _osm-sensitive" data-code="${escapedCodeForAttr}">
        ${secureDisplayResult.html}
      </div>
      <button class="copy-btn" id="_osm-copy-btn" type="button">
        <span class="_osm-btn-text">COPY CODE</span>
      </button>
      ${countdownHTML}
    </div>
  </div>
  ${iframeSection}
  <div class="footer">
    <p>Secure delivery via Osm Army Fortress &bull; Server-rendered &bull; Anti-scrape protected</p>
  </div>
</div>
<div class="toast-container" id="toast-container"></div>
<script>
${secureDisplayResult.js || ''}
</script>
</body>
</html>`;
  }

  /**
   * Escape a string for safe HTML text/attribute usage.
   * @param {string} str
   * @returns {string}
   * @private
   */
  _escapeHTML(str) {
    if (!str) return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
  }
}

export { CodeRenderer };
