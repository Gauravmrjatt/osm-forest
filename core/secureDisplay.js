/**
 * @fileoverview secureDisplay.js - Server-Side Secure Code Display Generator
 * @description Generates fragmented HTML that displays gift codes visually while
 * making them extremely difficult to scrape programmatically. Uses multiple
 * anti-scrape strategies including CSS ::before pseudo-elements, fake invisible
 * spans, random class names, and DOM obfuscation.
 * @version 1.0.0
 * @author Osm Army Security Team
 * @license Proprietary
 */

const crypto = require("crypto");

/**
 * SecureCodeDisplay - Server-side code fragment generator
 * Generates HTML/CSS/JS that displays codes securely against scraping.
 */
class SecureCodeDisplay {
  /**
   * Create a new SecureCodeDisplay instance.
   * @param {object} [options] - Configuration options.
   * @param {number} [options.fragmentMin=80] - Minimum total spans to generate.
   * @param {number} [options.fragmentMax=140] - Maximum total spans to generate.
   * @param {number} [options.fakeRatio=0.65] - Ratio of fake to real spans.
   * @param {number} [options.expirySeconds=10] - Auto-destruct countdown in seconds.
   */
  constructor(options = {}) {
    this.config = {
      fragmentMin: options.fragmentMin || 80,
      fragmentMax: options.fragmentMax || 140,
      fakeRatio: options.fakeRatio !== undefined ? options.fakeRatio : 0.65,
      expirySeconds: options.expirySeconds || 10,
    };

    // Daily salt for class name generation (changes every day)
    this.dailySalt = this._getDailySalt();

    // Strategy registry
    this.strategies = [
      this._strategyCharSpans.bind(this),
      this._strategyMixedSpans.bind(this),
      this._strategyGridShuffle.bind(this),
      this._strategyUnicodeVariations.bind(this),
      this._strategySvgTextPaths.bind(this),
      this._strategyCanvasRender.bind(this),
      this._strategyZIndexLayering.bind(this),
      this._strategyCommentHiding.bind(this),
      this._strategyAttributeEncoding.bind(this),
      this._strategyFlexOrderShuffle.bind(this),
      this._strategyNestedSpans.bind(this),
      this._strategyCssCounters.bind(this),
    ];
  }

  /**
   * ===================================================================
   * PUBLIC API
   * ===================================================================
   */

  /**
   * Generate the complete secure display payload.
   * @param {string} code - The gift code to display (e.g., "91CLUB55XYZ").
   * @param {string} sessionToken - Unique session token for this display.
   * @returns {{html: string, css: string, js: string}} The display payload.
   */
  generateDisplayHTML(code, sessionToken) {
    if (!code || typeof code !== "string") {
      throw new Error("Code must be a non-empty string");
    }
    if (!sessionToken || typeof sessionToken !== "string") {
      throw new Error("Session token must be a non-empty string");
    }

    // Generate unique session prefix for class names
    const sessionPrefix = this._hashSession(sessionToken);

    // Pick a random strategy
    const strategyIndex = this._pickStrategy(sessionToken);
    const strategy = this.strategies[strategyIndex];

    // Execute strategy to get fragments and CSS
    const result = strategy(code, sessionPrefix);

    // Generate the copy script
    const copyScript = this.generateCopyScript(code);

    // Generate auto-destruct script
    const destructScript = this.generateAutoDestructScript(
      this.config.expirySeconds,
      sessionPrefix
    );

    // Combine JS
    const js = `(function(){\n${copyScript}\n${destructScript}\n})();`;

    return {
      html: result.html,
      css: result.css,
      js: js,
      meta: {
        strategy: strategyIndex,
        strategyName: strategy.name,
        spanCount: result.spanCount || 0,
        expirySeconds: this.config.expirySeconds,
      },
    };
  }

  /**
   * Generate the clipboard copy script.
   * @param {string} code - The code to copy.
   * @returns {string} JavaScript code string.
   */
  generateCopyScript(code) {
    const escapedCode = this._escapeJSString(code);
    return `
  function _osmCopyCode(){
    var code="${escapedCode}";
    var btn=document.getElementById("_osm-copy-btn");
    if(navigator.clipboard&&navigator.clipboard.writeText){
      navigator.clipboard.writeText(code).then(function(){
        _osmShowCopyFeedback();
      }).catch(function(){
        _osmFallbackCopy(code);
      });
    }else{
      _osmFallbackCopy(code);
    }
  }
  function _osmFallbackCopy(text){
    var ta=document.createElement("textarea");
    ta.value=text;
    ta.style.cssText="position:fixed;left:-9999px;top:-9999px;opacity:0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    try{
      document.execCommand("copy");
      _osmShowCopyFeedback();
    }catch(e){}
    document.body.removeChild(ta);
  }
  function _osmShowCopyFeedback(){
    var btn=document.getElementById("_osm-copy-btn");
    if(btn){
      btn.classList.add("_osm-copied");
      var span=btn.querySelector("._osm-btn-text");
      if(span) span.textContent="COPIED!";
      setTimeout(function(){
        btn.classList.remove("_osm-copied");
        if(span) span.textContent="COPY CODE";
      },2000);
    }
    _osmShowToast("\u2705 Code copied to clipboard!");
  }
  function _osmShowToast(msg){
    var c=document.getElementById("toast-container");
    if(!c)return;
    var t=document.createElement("div");
    t.className="toast success";
    t.innerHTML="<span>"+msg+"</span>";
    c.appendChild(t);
    setTimeout(function(){t.remove();},4000);
  }
  document.addEventListener("DOMContentLoaded",function(){
    var btn=document.getElementById("_osm-copy-btn");
    if(btn)btn.addEventListener("click",_osmCopyCode);
  });`;
  }

  /**
   * Generate the auto-destruct countdown script.
   * @param {number} expirySeconds - Countdown duration.
   * @param {string} sessionPrefix - Session prefix for selectors.
   * @returns {string} JavaScript code string.
   */
  generateAutoDestructScript(expirySeconds, sessionPrefix) {
    return `
  (function(){
    var TOTAL=${expirySeconds}*1000;
    var start=Date.now();
    var fill=document.getElementById("_osm-progress-fill");
    var timeText=document.getElementById("_osm-time-text");
    var display=document.getElementById("_osm-secure-display");
    var expired=document.getElementById("_osm-expired");
    var container=document.getElementById("code-display-container");
    var codeVar=null;
    function tick(){
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
      // Clear any global code references
      codeVar=null;
      if(window._osmCode)window._osmCode=null;
      try{
        fetch("/api/v1/code-expired",{
          method:"POST",
          headers:{"Content-Type":"application/json"},
          body:JSON.stringify({action:"secure-display-expired"})
        });
      }catch(e){}
    }
    if(document.readyState==="complete"||document.readyState==="interactive"){
      requestAnimationFrame(tick);
    }else{
      document.addEventListener("DOMContentLoaded",function(){requestAnimationFrame(tick);});
    }
  })();`;
  }

  /**
   * ===================================================================
   * FRAGMENTATION STRATEGIES
   * ===================================================================
   */

  /**
   * Strategy 1: Per-character spans with CSS ::before
   * Each real character gets a span with data-i attribute.
   * CSS maps data-i to the character via ::before { content: "X" }
   */
  _strategyCharSpans(code, prefix) {
    const chars = code.split("");
    const classMap = {};
    const cssRules = [];
    const htmlParts = [];

    // Build class-to-char mapping
    chars.forEach((ch, idx) => {
      const cls = this._randomClass(prefix, `c${idx}`);
      const dataIdx = this._scrambleIndex(idx, code.length);
      classMap[dataIdx] = { char: ch, cls: cls };

      cssRules.push(
        `.${cls}[data-i="${dataIdx}"]::before{content:"${this._escapeCSSString(
          ch
        )}";font-family:system-ui,monospace;font-size:32px;font-weight:700;color:var(--text-primary);}`
      );
    });

    // Generate fragments: fake + real spans interleaved
    const totalSpans = this._randomInt(this.config.fragmentMin, this.config.fragmentMax);
    const fakeClass = this._randomClass(prefix, "fake");
    cssRules.push(`.${fakeClass}{display:none!important;}`);

    const realPositions = this._pickPositions(chars.length, totalSpans);
    let realIdx = 0;

    for (let i = 0; i < totalSpans; i++) {
      if (realPositions.includes(i) && realIdx < chars.length) {
        const entry = classMap[realIdx];
        htmlParts.push(
          `<span class="${entry.cls}" data-i="${realIdx}"></span>`
        );
        realIdx++;
      } else {
        const fakeChar = this._randomFakeChar();
        htmlParts.push(
          `<span class="${fakeClass}">${fakeChar}</span>`
        );
      }
    }

    return {
      html: `<div class="${this._randomClass(prefix, "display")}" id="_osm-secure-display">${htmlParts.join(
        ""
      )}</div>`,
      css: cssRules.join("\n"),
      spanCount: totalSpans,
    };
  }

  /**
   * Strategy 2: Mixed real/fake spans with z-index layering
   * Real characters are positioned over fake ones using z-index.
   */
  _strategyMixedSpans(code, prefix) {
    const chars = code.split("");
    const cssRules = [];
    const htmlParts = [];

    const containerClass = this._randomClass(prefix, "container");
    const realClass = this._randomClass(prefix, "real");
    const fakeClass = this._randomClass(prefix, "fake2");

    cssRules.push(
      `.${containerClass}{position:relative;display:inline-block;font-size:32px;font-weight:700;height:48px;line-height:48px;letter-spacing:4px;}`,
      `.${realClass}{position:relative;z-index:10;color:var(--text-primary);font-family:system-ui,monospace;font-size:32px;font-weight:700;}`,
      `.${fakeClass}{position:absolute;display:inline;color:transparent;z-index:1;font-size:32px;}`
    );

    chars.forEach((ch, idx) => {
      const uniqueReal = this._randomClass(prefix, `r${idx}`);
      const uniqueFake = this._randomClass(prefix, `f${idx}`);
      const fakeText = this._randomFakeChar() + this._randomFakeChar() + this._randomFakeChar();

      cssRules.push(
        `.${uniqueReal}{color:var(--text-primary);font-family:system-ui,monospace;font-size:32px;font-weight:700;}`,
        `.${uniqueFake}{display:none!important;}`
      );

      htmlParts.push(
        `<span class="${containerClass}">`,
        `<span class="${uniqueFake} ${fakeClass}">${fakeText}</span>`,
        `<span class="${uniqueReal} ${realClass}">${ch}</span>`,
        `</span>`
      );
    });

    return {
      html: `<div class="${this._randomClass(prefix, "display")}" id="_osm-secure-display">${htmlParts.join(
        ""
      )}</div>`,
      css: cssRules.join("\n"),
      spanCount: chars.length * 3,
    };
  }

  /**
   * Strategy 3: CSS Grid Shuffling
   * Visual order differs from DOM order via grid placement.
   */
  _strategyGridShuffle(code, prefix) {
    const chars = code.split("");
    const cssRules = [];
    const htmlParts = [];

    const gridClass = this._randomClass(prefix, "grid");
    const cellClass = this._randomClass(prefix, "cell");
    const fakeClass = this._randomClass(prefix, "fake3");

    cssRules.push(
      `.${gridClass}{display:grid;grid-template-columns:repeat(${chars.length},1fr);gap:4px;font-size:32px;font-weight:700;text-align:center;}`,
      `.${cellClass}{font-family:system-ui,monospace;font-size:32px;font-weight:700;color:var(--text-primary);}`,
      `.${fakeClass}{display:none!important;}`
    );

    // Shuffle visual positions
    const domOrder = chars.map((ch, i) => ({ ch, i }));
    const visualOrder = this._shuffleArray([...domOrder]);

    domOrder.forEach((item, idx) => {
      const uniqueCell = this._randomClass(prefix, `cell${idx}`);
      const visualPos = visualOrder.findIndex((v) => v.i === item.i);

      cssRules.push(
        `.${uniqueCell}{grid-column:${visualPos + 1};font-family:system-ui,monospace;font-size:32px;font-weight:700;color:var(--text-primary);}`
      );

      htmlParts.push(`<span class="${uniqueCell} ${cellClass}">${item.ch}</span>`);

      // Insert fake cells between real ones
      if (idx < domOrder.length - 1) {
        const fakeCell = this._randomClass(prefix, `fc${idx}`);
        cssRules.push(`.${fakeCell}{display:none!important;}`);
        htmlParts.push(
          `<span class="${fakeCell} ${fakeClass}">${this._randomFakeChar()}</span>`
        );
      }
    });

    return {
      html: `<div class="${gridClass}" id="_osm-secure-display">${htmlParts.join("")}</div>`,
      css: cssRules.join("\n"),
      spanCount: domOrder.length * 2 - 1,
    };
  }

  /**
   * Strategy 4: Unicode Variation Selectors
   * Injects invisible unicode characters to break simple text extraction.
   */
  _strategyUnicodeVariations(code, prefix) {
    const chars = code.split("");
    const cssRules = [];
    const htmlParts = [];

    const containerClass = this._randomClass(prefix, "unicode");
    const charClass = this._randomClass(prefix, "uchar");
    const fakeClass = this._randomClass(prefix, "fake4");

    cssRules.push(
      `.${containerClass}{font-family:system-ui,monospace;font-size:32px;font-weight:700;letter-spacing:4px;color:var(--text-primary);}`,
      `.${charClass}{display:inline;color:var(--text-primary);font-size:32px;font-weight:700;}`,
      `.${fakeClass}{display:none!important;}`
    );

    // Unicode variation selectors U+FE00-U+FE0F
    const variationSelector = (idx) => String.fromCharCode(0xfe00 + (idx % 16));

    chars.forEach((ch, idx) => {
      const uniqueChar = this._randomClass(prefix, `uc${idx}`);
      cssRules.push(
        `.${uniqueChar}::after{content:"${variationSelector(idx)}";font-size:0;visibility:hidden;}`
      );

      htmlParts.push(`<span class="${uniqueChar} ${charClass}">${ch}</span>`);

      // Insert spans with invisible variation selectors (hidden)
      const invSpan = this._randomClass(prefix, `iv${idx}`);
      cssRules.push(`.${invSpan}{display:none!important;}`);
      htmlParts.push(
        `<span class="${invSpan} ${fakeClass}">${this._randomFakeChar()}${variationSelector(idx)}</span>`
      );
    });

    return {
      html: `<div class="${containerClass}" id="_osm-secure-display">${htmlParts.join(
        ""
      )}</div>`,
      css: cssRules.join("\n"),
      spanCount: chars.length * 2,
    };
  }

  /**
   * Strategy 5: SVG Text Paths
   * Renders code using SVG <text> elements instead of HTML text.
   */
  _strategySvgTextPaths(code, prefix) {
    const chars = code.split("");
    const cssRules = [];

    const svgClass = this._randomClass(prefix, "svg");
    const fakeClass = this._randomClass(prefix, "fake5");

    cssRules.push(
      `.${svgClass}{display:block;margin:0 auto;max-width:100%;}`,
      `.${fakeClass}{display:none!important;}`
    );

    const charWidth = 28;
    const totalWidth = chars.length * charWidth + 20;
    const height = 52;

    const textElements = chars
      .map((ch, i) => {
        const x = 10 + i * charWidth;
        const encodedChar = this._escapeXML(ch);
        return `<text x="${x}" y="38" font-family="system-ui,monospace" font-size="32" font-weight="700" fill="#ffffff">${encodedChar}</text>`;
      })
      .join("");

    const svg = `<svg class="${svgClass}" id="_osm-secure-display" width="${totalWidth}" height="${height}" viewBox="0 0 ${totalWidth} ${height}" xmlns="http://www.w3.org/2000/svg">${textElements}</svg>`;

    // Wrap in a div for consistency
    const html = `<div style="text-align:center;">${svg}<span class="${fakeClass}" aria-hidden="true">${this._randomFakeChar()}</span></div>`;

    return {
      html: html,
      css: cssRules.join("\n"),
      spanCount: chars.length,
    };
  }

  /**
   * Strategy 6: Canvas Rendering with Overlay
   * Renders code to a canvas element with an invisible overlay grid.
   */
  _strategyCanvasRender(code, prefix) {
    const chars = code.split("");
    const cssRules = [];

    const wrapperClass = this._randomClass(prefix, "canvaswrap");
    const canvasClass = this._randomClass(prefix, "canvas");
    const overlayClass = this._randomClass(prefix, "overlay");
    const fakeClass = this._randomClass(prefix, "fake6");

    cssRules.push(
      `.${wrapperClass}{position:relative;display:inline-block;text-align:center;}`,
      `.${canvasClass}{display:block;margin:0 auto;border-radius:4px;}`,
      `.${overlayClass}{position:absolute;inset:0;pointer-events:none;}`,
      `.${fakeClass}{display:none!important;}`
    );

    // Generate canvas rendering script (client-side will render)
    // But we also embed the code data as data attributes for the client script
    const charWidth = 28;
    const totalWidth = chars.length * charWidth + 20;
    const height = 52;

    const html = `<div class="${wrapperClass}" id="_osm-secure-display">
  <canvas class="${canvasClass}" id="_osm-code-canvas" width="${totalWidth}" height="${height}" data-code="${this._escapeHTML(code)}"></canvas>
  <div class="${overlayClass}" aria-hidden="true"></div>
  <span class="${fakeClass}">${this._randomFakeChar()}</span>
</div>
<script>
(function(){
  var c=document.getElementById("_osm-code-canvas");
  if(!c)return;
  var ctx=c.getContext("2d");
  var code=c.getAttribute("data-code");
  ctx.clearRect(0,0,c.width,c.height);
  ctx.font="700 32px system-ui,monospace";
  ctx.fillStyle="#ffffff";
  for(var i=0;i<code.length;i++){
    ctx.fillText(code[i],10+i*28,38);
  }
})();
</script>`;

    return {
      html: html,
      css: cssRules.join("\n"),
      spanCount: 1,
    };
  }

  /**
   * Strategy 7: z-index Layering
   * Characters are stacked and positioned via CSS transforms.
   */
  _strategyZIndexLayering(code, prefix) {
    const chars = code.split("");
    const cssRules = [];
    const htmlParts = [];

    const containerClass = this._randomClass(prefix, "zcontainer");
    const layerClass = this._randomClass(prefix, "layer");
    const fakeClass = this._randomClass(prefix, "fake7");

    cssRules.push(
      `.${containerClass}{position:relative;display:inline-block;height:48px;line-height:48px;width:${
        chars.length * 32
      }px;}`,
      `.${layerClass}{position:absolute;top:0;font-family:system-ui,monospace;font-size:32px;font-weight:700;color:var(--text-primary);}`,
      `.${fakeClass}{display:none!important;}`
    );

    chars.forEach((ch, idx) => {
      const uniqueLayer = this._randomClass(prefix, `zl${idx}`);
      cssRules.push(`.${uniqueLayer}{left:${idx * 32}px;z-index:${10 + idx};}`);
      htmlParts.push(`<span class="${uniqueLayer} ${layerClass}">${ch}</span>`);
    });

    // Add fake layers underneath
    for (let i = 0; i < chars.length; i++) {
      const fakeLayer = this._randomClass(prefix, `zfl${i}`);
      cssRules.push(`.${fakeLayer}{display:none!important;}`);
      htmlParts.push(
        `<span class="${fakeLayer} ${fakeClass}">${this._randomFakeChar()}</span>`
      );
    }

    return {
      html: `<div class="${containerClass}" id="_osm-secure-display">${htmlParts.join(
        ""
      )}</div>`,
      css: cssRules.join("\n"),
      spanCount: chars.length * 2,
    };
  }

  /**
   * Strategy 8: HTML Comment Hiding
   * Injects real characters inside HTML comments that CSS reveals.
   */
  _strategyCommentHiding(code, prefix) {
    const chars = code.split("");
    const cssRules = [];
    const htmlParts = [];

    const revealClass = this._randomClass(prefix, "reveal");
    const fakeClass = this._randomClass(prefix, "fake8");

    cssRules.push(
      `.${revealClass}::before{content:attr(data-c);font-family:system-ui,monospace;font-size:32px;font-weight:700;color:var(--text-primary);}`,
      `.${fakeClass}{display:none!important;}`
    );

    chars.forEach((ch, idx) => {
      const uniqueReveal = this._randomClass(prefix, `rev${idx}`);
      cssRules.push(
        `.${uniqueReveal}::before{content:"${this._escapeCSSString(ch)}";font-family:system-ui,monospace;font-size:32px;font-weight:700;color:var(--text-primary);}`
      );
      htmlParts.push(`<span class="${uniqueReveal} ${revealClass}" data-c="${this._escapeHTML(ch)}"></span>`);
      // Fake
      const fc = this._randomClass(prefix, `f8${idx}`);
      cssRules.push(`.${fc}{display:none!important;}`);
      htmlParts.push(`<span class="${fc} ${fakeClass}">${this._randomFakeChar()}</span>`);
    });

    return {
      html: `<div class="${this._randomClass(prefix, "display")}" id="_osm-secure-display">${htmlParts.join(
        ""
      )}</div>`,
      css: cssRules.join("\n"),
      spanCount: chars.length * 2,
    };
  }

  /**
   * Strategy 9: Attribute Encoding
   * Characters stored in custom data attributes, revealed via CSS.
   */
  _strategyAttributeEncoding(code, prefix) {
    const chars = code.split("");
    const cssRules = [];
    const htmlParts = [];

    const attrClass = this._randomClass(prefix, "attr");
    const fakeClass = this._randomClass(prefix, "fake9");

    cssRules.push(
      `.${attrClass}::before{content:attr(data-v);font-family:system-ui,monospace;font-size:32px;font-weight:700;color:var(--text-primary);}`,
      `.${fakeClass}{display:none!important;}`
    );

    // Scramble the attribute name
    const attrNames = ["data-v", "data-x", "data-ch", "data-z"];
    const chosenAttr = attrNames[Math.floor(Math.random() * attrNames.length)];

    chars.forEach((ch, idx) => {
      const uniqueAttr = this._randomClass(prefix, `at${idx}`);
      cssRules.push(
        `.${uniqueAttr}::before{content:attr(${chosenAttr});font-family:system-ui,monospace;font-size:32px;font-weight:700;color:var(--text-primary);}`
      );
      htmlParts.push(`<span class="${uniqueAttr} ${attrClass}" ${chosenAttr}="${this._escapeHTML(ch)}"></span>`);
      // Fake
      const fc = this._randomClass(prefix, `f9${idx}`);
      cssRules.push(`.${fc}{display:none!important;}`);
      htmlParts.push(`<span class="${fc} ${fakeClass}">${this._randomFakeChar()}</span>`);
    });

    return {
      html: `<div class="${this._randomClass(prefix, "display")}" id="_osm-secure-display">${htmlParts.join(
        ""
      )}</div>`,
      css: cssRules.join("\n"),
      spanCount: chars.length * 2,
    };
  }

  /**
   * Strategy 10: Flex Order Shuffling
   * Uses CSS order property to rearrange characters visually.
   */
  _strategyFlexOrderShuffle(code, prefix) {
    const chars = code.split("");
    const cssRules = [];
    const htmlParts = [];

    const flexClass = this._randomClass(prefix, "flex");
    const itemClass = this._randomClass(prefix, "flexitem");
    const fakeClass = this._randomClass(prefix, "fake10");

    cssRules.push(
      `.${flexClass}{display:flex;font-family:system-ui,monospace;font-size:32px;font-weight:700;color:var(--text-primary);gap:4px;justify-content:center;}`,
      `.${itemClass}{font-family:system-ui,monospace;font-size:32px;font-weight:700;color:var(--text-primary);}`,
      `.${fakeClass}{display:none!important;}`
    );

    // Shuffle visual order using CSS order property
    const shuffled = this._shuffleArray(chars.map((ch, i) => ({ ch, i })));

    chars.forEach((ch, idx) => {
      const visualIdx = shuffled.findIndex((s) => s.i === idx);
      const uniqueItem = this._randomClass(prefix, `fi${idx}`);
      cssRules.push(
        `.${uniqueItem}{order:${visualIdx + 1};font-family:system-ui,monospace;font-size:32px;font-weight:700;color:var(--text-primary);}`
      );
      htmlParts.push(`<span class="${uniqueItem} ${itemClass}">${ch}</span>`);

      // Fake items
      const fc = this._randomClass(prefix, `ff10${idx}`);
      cssRules.push(`.${fc}{display:none!important;}`);
      htmlParts.push(`<span class="${fc} ${fakeClass}">${this._randomFakeChar()}</span>`);
    });

    return {
      html: `<div class="${flexClass}" id="_osm-secure-display">${htmlParts.join(
        ""
      )}</div>`,
      css: cssRules.join("\n"),
      spanCount: chars.length * 2,
    };
  }

  /**
   * Strategy 11: Nested Spans
   * Deeply nested span structures to confuse DOM parsers.
   */
  _strategyNestedSpans(code, prefix) {
    const chars = code.split("");
    const cssRules = [];
    const htmlParts = [];

    const nestClass = this._randomClass(prefix, "nest");
    const innerClass = this._randomClass(prefix, "inner");
    const fakeClass = this._randomClass(prefix, "fake11");

    cssRules.push(
      `.${nestClass}{display:inline;color:var(--text-primary);}`,
      `.${innerClass}{font-family:system-ui,monospace;font-size:32px;font-weight:700;color:var(--text-primary);}`,
      `.${fakeClass}{display:none!important;}`
    );

    chars.forEach((ch, idx) => {
      const depth = 2 + (idx % 3); // 2-4 levels deep
      const classes = [];
      for (let d = 0; d < depth; d++) {
        classes.push(this._randomClass(prefix, `n${idx}_${d}`));
        cssRules.push(
          `.${classes[d]}{display:inline;color:var(--text-primary);}`
        );
      }

      let nested = ch;
      for (let d = depth - 1; d >= 0; d--) {
        nested = `<span class="${classes[d]}">${nested}</span>`;
      }
      htmlParts.push(nested);

      // Fake nest
      const fc = this._randomClass(prefix, `fn${idx}`);
      cssRules.push(`.${fc}{display:none!important;}`);
      htmlParts.push(`<span class="${fc} ${fakeClass}">${this._randomFakeChar()}</span>`);
    });

    return {
      html: `<div class="${nestClass}" id="_osm-secure-display">${htmlParts.join(
        ""
      )}</div>`,
      css: cssRules.join("\n"),
      spanCount: chars.length * 4,
    };
  }

  /**
   * Strategy 12: CSS Counters
   * Uses CSS counter-reset and counter-increment to display characters.
   */
  _strategyCssCounters(code, prefix) {
    const chars = code.split("");
    const cssRules = [];
    const htmlParts = [];

    const counterClass = this._randomClass(prefix, "counter");
    const itemClass = this._randomClass(prefix, "citem");
    const fakeClass = this._randomClass(prefix, "fake12");

    const counterName = `_${this._randomString(6)}`;

    cssRules.push(
      `.${counterClass}{counter-reset:${counterName};font-family:system-ui,monospace;font-size:32px;font-weight:700;color:var(--text-primary);display:flex;gap:4px;justify-content:center;}`,
      `.${itemClass}{counter-increment:${counterName};}`,
      `.${fakeClass}{display:none!important;}`
    );

    chars.forEach((ch, idx) => {
      const uniqueItem = this._randomClass(prefix, `ci${idx}`);
      cssRules.push(
        `.${uniqueItem}::before{content:"${this._escapeCSSString(ch)}";font-family:system-ui,monospace;font-size:32px;font-weight:700;color:var(--text-primary);}`
      );
      htmlParts.push(`<span class="${uniqueItem} ${itemClass}"></span>`);

      // Fake items between
      const fc = this._randomClass(prefix, `f12${idx}`);
      cssRules.push(`.${fc}{display:none!important;}`);
      htmlParts.push(`<span class="${fc} ${fakeClass}">${this._randomFakeChar()}</span>`);
    });

    return {
      html: `<div class="${counterClass}" id="_osm-secure-display">${htmlParts.join(
        ""
      )}</div>`,
      css: cssRules.join("\n"),
      spanCount: chars.length * 2,
    };
  }

  /**
   * ===================================================================
   * UTILITY METHODS
   * ===================================================================
   */

  /**
   * Get a daily rotating salt string based on UTC date.
   * @returns {string} Daily salt.
   * @private
   */
  _getDailySalt() {
    const now = new Date();
    const year = now.getUTCFullYear();
    const month = String(now.getUTCMonth() + 1).padStart(2, "0");
    const day = String(now.getUTCDate()).padStart(2, "0");
    return `osm-salt-${year}${month}${day}-v1`;
  }

  /**
   * Hash a session token into a short prefix string.
   * @param {string} token - Session token.
   * @returns {string} Hashed prefix.
   * @private
   */
  _hashSession(token) {
    const hash = crypto
      .createHash("sha256")
      .update(token + this.dailySalt)
      .digest("hex");
    return "s" + hash.substring(0, 12);
  }

  /**
   * Pick a deterministic random strategy based on session token.
   * @param {string} token - Session token.
   * @returns {number} Strategy index.
   * @private
   */
  _pickStrategy(token) {
    const hash = crypto
      .createHash("sha256")
      .update("strategy" + token + this.dailySalt)
      .digest("hex");
    const value = parseInt(hash.substring(0, 8), 16);
    return value % this.strategies.length;
  }

  /**
   * Generate a random CSS class name.
   * @param {string} prefix - Session prefix.
   * @param {string} seed - Seed string for deterministic generation.
   * @returns {string} CSS class name.
   * @private
   */
  _randomClass(prefix, seed) {
    const hash = crypto
      .createHash("sha256")
      .update(prefix + seed + this.dailySalt)
      .digest("hex");
    // Use only letters (CSS classes must start with letter)
    const letters = hash
      .replace(/[^a-f]/g, "")
      .substring(0, 4);
    const numbers = hash
      .replace(/[^0-9]/g, "")
      .substring(0, 3);
    return `_${prefix}${letters}${numbers}`;
  }

  /**
   * Generate a random integer in range.
   * @param {number} min - Minimum value.
   * @param {number} max - Maximum value.
   * @returns {number} Random integer.
   * @private
   */
  _randomInt(min, max) {
    const buf = crypto.randomBytes(4);
    const val = buf.readUInt32LE(0);
    return min + (val % (max - min + 1));
  }

  /**
   * Pick random positions for real characters within total spans.
   * @param {number} realCount - Number of real characters.
   * @param {number} totalCount - Total span count.
   * @returns {number[]} Sorted array of positions.
   * @private
   */
  _pickPositions(realCount, totalCount) {
    const positions = [];
    const available = [];
    for (let i = 0; i < totalCount; i++) available.push(i);

    // Shuffle available
    for (let i = available.length - 1; i > 0; i--) {
      const j = this._randomInt(0, i);
      [available[i], available[j]] = [available[j], available[i]];
    }

    // Pick first realCount
    for (let i = 0; i < realCount; i++) {
      positions.push(available[i]);
    }

    return positions.sort((a, b) => a - b);
  }

  /**
   * Scramble index for data attributes.
   * @param {number} idx - Original index.
   * @param {number} length - Total length.
   * @returns {number} Scrambled index.
   * @private
   */
  _scrambleIndex(idx, length) {
    // Simple reversible shuffle: add prime offset
    const prime = 37;
    return (idx * prime) % Math.max(length + 1, length + 3);
  }

  /**
   * Shuffle an array using Fisher-Yates.
   * @param {Array} arr - Array to shuffle.
   * @returns {Array} Shuffled array.
   * @private
   */
  _shuffleArray(arr) {
    const result = [...arr];
    for (let i = result.length - 1; i > 0; i--) {
      const j = this._randomInt(0, i);
      [result[i], result[j]] = [result[j], result[i]];
    }
    return result;
  }

  /**
   * Generate a random fake character.
   * @returns {string} Fake character.
   * @private
   */
  _randomFakeChar() {
    const fakes =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
    return fakes[this._randomInt(0, fakes.length - 1)];
  }

  /**
   * Generate a random alphanumeric string.
   * @param {number} length - String length.
   * @returns {string} Random string.
   * @private
   */
  _randomString(length) {
    const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    for (let i = 0; i < length; i++) {
      result += chars[this._randomInt(0, chars.length - 1)];
    }
    return result;
  }

  /**
   * Escape a string for use in CSS content property.
   * @param {string} str - String to escape.
   * @returns {string} Escaped string.
   * @private
   */
  _escapeCSSString(str) {
    return str
      .replace(/\\/g, "\\\\")
      .replace(/"/g, '\\"')
      .replace(/'/g, "\\'")
      .replace(/\n/g, "\\A");
  }

  /**
   * Escape a string for use in JavaScript string literal.
   * @param {string} str - String to escape.
   * @returns {string} Escaped string.
   * @private
   */
  _escapeJSString(str) {
    return str
      .replace(/\\/g, "\\\\")
      .replace(/"/g, '\\"')
      .replace(/'/g, "\\'")
      .replace(/\n/g, "\\n")
      .replace(/\r/g, "\\r");
  }

  /**
   * Escape a string for use in HTML attribute.
   * @param {string} str - String to escape.
   * @returns {string} Escaped string.
   * @private
   */
  _escapeHTML(str) {
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#x27;");
  }

  /**
   * Escape a string for use in XML/SVG text.
   * @param {string} str - String to escape.
   * @returns {string} Escaped string.
   * @private
   */
  _escapeXML(str) {
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }
}

// ============================================================================
// EXPORT
// ============================================================================

module.exports = { SecureCodeDisplay };
