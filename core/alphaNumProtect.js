/**
 * ALPHANUMERIC MIXED CODE PROTECTION ENGINE
 * Special protection for 30-35 character mixed codes (letters + numbers + symbols)
 * Examples: 91CLUB55WELCOME2026BONUS999, X7kP9mQ2wR5tY8uI0oL
 * 
 * Key advantage: User MUST use copy button - manual typing is impossible
 * Piyush cannot extract and manually type 35 mixed characters
 */

import crypto from 'crypto';

// Confusing character pairs - look similar but are different
const CONFUSING_PAIRS = [
  ['0', 'O'], ['1', 'l', 'I'], ['5', 'S'],
  ['2', 'Z'], ['6', 'G'], ['8', 'B'],
  ['n', 'h'], ['rn', 'm'], ['vv', 'w'],
  ['cl', 'd'], ['lJ', 'U'], ['CG', 'O'],
];

/**
 * Analyze code for confusing character patterns
 * Returns positions where confusion is possible
 */
export function analyzeConfusion(code) {
  const issues = [];
  for (let i = 0; i < code.length; i++) {
    for (const [correct, ...confused] of CONFUSING_PAIRS) {
      if (code[i] === correct || confused.includes(code[i])) {
        issues.push({
          position: i,
          char: code[i],
          couldBe: confused.includes(code[i]) ? correct : confused[0],
          reason: `'${code[i]}' looks like '${confused.includes(code[i]) ? correct : confused[0]}'`,
        });
      }
    }
  }
  return issues;
}

/**
 * Generate display with font that makes confusing chars distinct
 * Uses monospace font with character hints
 */
export function generateDistinctDisplay(code, sessionId) {
  const seed = crypto.createHash('sha256').update(sessionId + Date.now().toString()).digest('hex');
  const confusion = analyzeConfusion(code);
  
  // Split code into groups of 5 for readability
  const groups = [];
  for (let i = 0; i < code.length; i += 5) {
    groups.push(code.substring(i, Math.min(i + 5, code.length)));
  }
  
  let html = '<div class="_alnum_container">';
  html += '<div class="_alnum_header">🔤 30-35 Alphanumeric Mixed Code</div>';
  html += '<div class="_alnum_sub">Typing is impossible — Use COPY button</div>';
  html += '<div class="_alnum_code">';
  
  groups.forEach((group, gi) => {
    html += '<span class="_alnum_group">';
    for (let ci = 0; ci < group.length; ci++) {
      const globalIdx = gi * 5 + ci;
      const char = group[ci];
      const isLetter = /[a-zA-Z]/.test(char);
      const isNumber = /[0-9]/.test(char);
      const isConfusing = confusion.some(c => c.position === globalIdx);
      
      let charClass = '_alnum_char';
      if (isLetter) charClass += ' _alnum_letter';
      if (isNumber) charClass += ' _alnum_number';
      if (isConfusing) charClass += ' _alnum_confusing';
      
      // Add data attribute for type hint
      const typeHint = isLetter ? 'ABC' : isNumber ? '123' : 'SYM';
      html += `<span class="${charClass}" data-type="${typeHint}">${char}</span>`;
    }
    html += '</span>';
    // Add separator between groups
    if (gi < groups.length - 1) {
      html += '<span class="_alnum_gsep">-</span>';
    }
  });
  
  html += '</div>'; // end code
  
  // Show confusion warnings
  if (confusion.length > 0) {
    html += '<div class="_alnum_confuse_box">';
    html += '<div class="_alnum_confuse_title">⚠️ Look-alike characters detected:</div>';
    // Show first 3 unique issues
    const uniqueIssues = [];
    for (const issue of confusion) {
      if (!uniqueIssues.find(u => u.char === issue.char)) {
        uniqueIssues.push(issue);
        if (uniqueIssues.length >= 4) break;
      }
    }
    uniqueIssues.forEach(issue => {
      html += `<div class="_alnum_confuse_item">Position ${issue.position + 1}: '${issue.char}' looks like '${issue.couldBe}'</div>`;
    });
    html += '</div>';
  }
  
  // Length indicator
  html += `<div class="_alnum_length">${code.length} characters — Copy required</div>`;
  html += '</div>'; // end container
  
  const css = `
    ._alnum_container {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 0.75rem;
      padding: 20px 15px;
      background: rgba(124, 58, 237, 0.05);
      border: 1px solid rgba(124, 58, 237, 0.2);
      border-radius: 12px;
      max-width: 100%;
    }
    ._alnum_header {
      font-size: 0.85rem;
      font-weight: 700;
      color: var(--accent-light);
      text-align: center;
    }
    ._alnum_sub {
      font-size: 0.75rem;
      color: var(--text-muted);
      text-align: center;
    }
    ._alnum_code {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: center;
      gap: 4px;
      font-family: 'SF Mono', 'Fira Code', 'Courier New', monospace;
      font-size: 1.3rem;
      font-weight: 800;
      letter-spacing: 2px;
      padding: 12px 8px;
      background: rgba(10, 10, 15, 0.5);
      border-radius: 8px;
      width: 100%;
      overflow-x: auto;
    }
    ._alnum_group {
      display: inline-flex;
      gap: 2px;
      padding: 4px 6px;
      background: rgba(124, 58, 237, 0.08);
      border-radius: 6px;
    }
    ._alnum_gsep {
      color: var(--accent);
      font-weight: 800;
      padding: 0 2px;
      user-select: none;
    }
    ._alnum_char {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 22px;
      height: 32px;
      border-radius: 4px;
      position: relative;
    }
    /* Letters - colored blue */
    ._alnum_letter {
      color: #3b82f6;
      background: rgba(59, 130, 246, 0.1);
    }
    /* Numbers - colored green */
    ._alnum_number {
      color: #10b981;
      background: rgba(16, 185, 129, 0.1);
    }
    /* Confusing chars - colored orange with warning */
    ._alnum_confusing {
      color: #f59e0b;
      background: rgba(245, 158, 11, 0.15);
      border: 1px dashed rgba(245, 158, 11, 0.3);
      animation: _confusePulse 2s infinite;
    }
    @keyframes _confusePulse {
      0%, 100% { border-color: rgba(245, 158, 11, 0.3); }
      50% { border-color: rgba(245, 158, 11, 0.8); }
    }
    ._alnum_confuse_box {
      width: 100%;
      background: rgba(245, 158, 11, 0.05);
      border: 1px solid rgba(245, 158, 11, 0.15);
      border-radius: 8px;
      padding: 10px 12px;
      font-size: 0.75rem;
    }
    ._alnum_confuse_title {
      color: var(--warning);
      font-weight: 600;
      margin-bottom: 4px;
    }
    ._alnum_confuse_item {
      color: var(--text-muted);
      padding: 2px 0;
    }
    ._alnum_length {
      font-size: 0.8rem;
      color: var(--text-secondary);
      background: rgba(124, 58, 237, 0.08);
      padding: 6px 16px;
      border-radius: 20px;
      font-weight: 600;
    }
  `;
  
  return { html, css, confusion, groups };
}

/**
 * Generate "Impossible to Type" display
 * Emphasizes that 30-35 mixed chars cannot be manually typed
 */
export function generateImpossibleToType(code, siteName) {
  const groups = [];
  for (let i = 0; i < code.length; i += 5) {
    groups.push(code.substring(i, Math.min(i + 5, code.length)));
  }
  
  const html = `
    <div class="_itt_container">
      <div class="_itt_icon">🔒</div>
      <div class="_itt_title">30-35 Alphanumeric Mixed Code</div>
      <div class="_itt_subtitle">Manual typing is <strong>IMPOSSIBLE</strong></div>
      
      <div class="_itt_code_preview">
        <div class="_itt_dots">${'•'.repeat(code.length - 5)}</div>
        <div class="_itt_visible">${groups.slice(-1)[0]}</div>
      </div>
      
      <div class="_itt_reasons">
        <div class="_itt_reason">❌ ${code.length} characters too long to type</div>
        <div class="_itt_reason">❌ Mix of letters + numbers + confusion</div>
        <div class="_itt_reason">❌ '0' vs 'O', '1' vs 'l' look identical</div>
        <div class="_itt_reason">✅ <strong>Only copy-paste works!</strong></div>
      </div>
      
      <div class="_itt_site">Use in: <strong>${siteName || 'Game Site'}</strong></div>
    </div>
  `;
  
  const css = `
    ._itt_container {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 0.75rem;
      padding: 30px 20px;
      background: rgba(239, 68, 68, 0.05);
      border: 1px solid rgba(239, 68, 68, 0.15);
      border-radius: 12px;
      text-align: center;
    }
    ._itt_icon { font-size: 2.5rem; }
    ._itt_title { font-size: 1.1rem; font-weight: 700; color: var(--text-primary); }
    ._itt_subtitle { font-size: 0.9rem; color: #ef4444; font-weight: 600; }
    ._itt_code_preview {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 4px;
      padding: 12px;
      background: rgba(10, 10, 15, 0.5);
      border-radius: 8px;
      width: 100%;
    }
    ._itt_dots {
      font-family: monospace;
      font-size: 1.4rem;
      color: var(--text-dim);
      letter-spacing: 3px;
    }
    ._itt_visible {
      font-family: 'SF Mono', monospace;
      font-size: 1.4rem;
      font-weight: 800;
      color: var(--success);
      letter-spacing: 3px;
    }
    ._itt_reasons {
      width: 100%;
      text-align: left;
      background: rgba(10, 10, 15, 0.3);
      border-radius: 8px;
      padding: 12px 16px;
    }
    ._itt_reason {
      font-size: 0.8rem;
      color: var(--text-secondary);
      padding: 4px 0;
    }
    ._itt_reason strong { color: var(--success); }
    ._itt_site {
      font-size: 0.85rem;
      color: var(--text-muted);
      padding: 8px 16px;
      background: rgba(124, 58, 237, 0.08);
      border-radius: 20px;
    }
    ._itt_site strong { color: var(--accent-light); }
  `;
  
  return { html, css };
}

/**
 * Select best display mode for alphanumeric mixed code
 * 30-35 chars = strongest protection auto-selected
 */
export function selectAlphaNumDisplay(code, sessionId, siteName) {
  // Auto-select based on code characteristics
  const hasLetters = /[a-zA-Z]/.test(code);
  const hasNumbers = /[0-9]/.test(code);
  const hasConfusing = analyzeConfusion(code).length > 0;
  const isLong = code.length >= 30;
  const isMixed = hasLetters && hasNumbers;
  
  // For 30+ digit mixed alphanumeric = MAXIMUM protection
  if (isLong && isMixed) {
    // Use "impossible to type" display (most impactful for mixed long codes)
    return {
      type: 'impossible_type',
      ...generateImpossibleToType(code, siteName),
      meta: { length: code.length, mixed: true, confusing: hasConfusing },
    };
  }
  
  // For 20-29 chars with confusion
  if (code.length >= 20 && hasConfusing) {
    return {
      type: 'distinct_display',
      ...generateDistinctDisplay(code, sessionId),
      meta: { length: code.length, mixed, confusing: true },
    };
  }
  
  // Default: standard segmented
  return {
    type: 'distinct_display',
    ...generateDistinctDisplay(code, sessionId),
    meta: { length: code.length, mixed, confusing: false },
  };
}

/**
 * Generate copy protection JS for alphanumeric codes
 * Forces copy button usage - no manual typing possible
 */
export function generateAlphaNumCopyScript(code) {
  return `
    (function(){
      var code = '${code.replace(/'/g, "\\'")}';
      var codeLength = ${code.length};
      var destroyed = false;
      
      // CRITICAL: For 30+ alphanumeric mixed codes, copy is the ONLY way
      // Manual typing is impossible due to:
      // 1. Length (30-35 chars)
      // 2. Mixed letters + numbers
      // 3. Confusing characters (0 vs O, 1 vs l)
      
      document.getElementById('copyBtn').addEventListener('click', function(){
        if(destroyed || !code){
          this.innerHTML = '❌ CODE EXPIRED';
          return;
        }
        navigator.clipboard.writeText(code).then(function(){
          var btn = document.getElementById('copyBtn');
          btn.classList.add('copied');
          btn.innerHTML = '✅ ' + codeLength + ' CHARS COPIED!';
          // Show success message about manual typing being impossible
          var msg = document.createElement('div');
          msg.style.cssText = 'margin-top:8px;font-size:0.75rem;color:#10b981;text-align:center;';
          msg.innerHTML = '✅ Code copied! Manual typing not possible for ' + codeLength + '-char mixed code.';
          btn.parentNode.insertBefore(msg, btn.nextSibling);
          setTimeout(function(){ btn.innerHTML = '📋 COPY ' + codeLength + '-CHAR CODE'; }, 3000);
        });
      });
      
      // Auto-destruct
      setTimeout(function(){ code = null; destroyed = true; }, 11000);
    })();
  `;
}

export default {
  analyzeConfusion,
  generateDistinctDisplay,
  generateImpossibleToType,
  selectAlphaNumDisplay,
  generateAlphaNumCopyScript,
};
