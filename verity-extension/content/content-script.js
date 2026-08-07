/**
 * content-script.js - Injected into all pages at document_start.
 * Responsible for initiating early URL scans, collecting DOM signals, and enforcing blocks.
 */

let isBlocked = false;
let blockObserver = null;

// 1. Signal Collection (Stage 1)
function collectSignals() {
  const text = document.body ? document.body.innerText.toLowerCase() : '';
  
  const hasPasswordInput = document.querySelector('input[type="password"]') !== null;
  const loginForms = Array.from(document.querySelectorAll('form')).filter(form => {
    return form.querySelector('input[type="password"]') !== null || 
           (form.action && form.action.toLowerCase().includes('login')) ||
           (form.id && form.id.toLowerCase().includes('login'));
  });
  
  const formActions = loginForms.map(form => form.action).filter(Boolean);

  // Scam heuristics
  const scamPhrases = ['act now', 'limited time', 'your account will be suspended', 'pay with gift card', 'click here to claim'];
  let scamMatch = scamPhrases.find(p => text.includes(p));

  // PUP heuristics
  let pupMatch = null;
  const scripts = document.scripts || [];
  for (let i = 0; i < scripts.length; i++) {
    const s = scripts[i].innerText || '';
    if (s.includes('eval(') && s.includes('unescape(')) {
      pupMatch = 'Obfuscated inline script detected';
      break;
    }
  }
  
  if (document.querySelectorAll('iframe[style*="opacity: 0"], iframe[style*="display: none"]').length > 3) {
    pupMatch = 'Excessive hidden iframes detected';
  }

  // Financial Context Engine
  const financialKeywords = ['upi', 'bank', 'banking', 'net banking', 'payment', 'checkout', 'wallet', 'credit card', 'debit card', 'cvv', 'otp', 'pin', 'kyc', 'refund', 'cashback', 'investment', 'crypto', 'trading'];
  let financialMatch = financialKeywords.filter(k => text.includes(k));

  // Credential Collection Detection
  const sensitiveInputs = Array.from(document.querySelectorAll('input')).filter(input => {
    const attr = ((input.name||'') + (input.id||'') + (input.type||'') + (input.placeholder||'')).toLowerCase();
    return attr.includes('password') || attr.includes('card') || attr.includes('cvv') || attr.includes('otp') || attr.includes('pin') || attr.includes('upi') || attr.includes('account');
  });

  return {
    hasPasswordInput: hasPasswordInput,
    loginFormCount: loginForms.length,
    formActions: formActions,
    scam: !!scamMatch,
    scamReason: scamMatch ? `Matches scam language: "${scamMatch}"` : null,
    pup: !!pupMatch,
    pupReason: pupMatch,
    financialMatches: financialMatch,
    hasCredentialCollection: sensitiveInputs.length > 0
  };
}

// 2. Early and Full Scans
function triggerImmediateUrlScan() {
  chrome.runtime.sendMessage({ action: 'ANALYZE_URL_ONLY', url: window.location.href });
}

function triggerFullScan() {
  const domSignals = collectSignals();
  chrome.runtime.sendMessage({ action: 'ANALYZE_FULL', url: window.location.href, domSignals: domSignals });
}

// 3. Listen for enforcement decisions from Background
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'ENFORCEMENT_DECISION') {
    if (message.decision.action === 'block') {
      isBlocked = true;
      injectOverlay(message.decision.verdict);
    } else if (message.decision.action === 'allow') {
      isBlocked = false;
      removeOverlay();
    }
  } else if (message.action === 'RE_ANALYZE') {
    // Fired on SPA client-side navigations
    isBlocked = false;
    removeOverlay();
    triggerImmediateUrlScan();
    // For SPA, DOM is already loaded, but wait a tick for frameworks to render
    setTimeout(triggerFullScan, 500); 
  }
});

// Start immediately AFTER listener is registered to prevent race conditions
triggerImmediateUrlScan();

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', triggerFullScan);
} else {
  triggerFullScan();
}


// 4. Strong Overlay Enforcement
function removeOverlay() {
  if (blockObserver) {
    blockObserver.disconnect();
    blockObserver = null;
  }
  const existing = document.getElementById('verity-security-host');
  if (existing) {
    existing.remove();
  }
  if (document.documentElement) {
    document.documentElement.style.overflow = '';
  }
}

function injectOverlay(verdict) {
  if (document.getElementById('verity-security-host')) {
    return; // Already blocked
  }

  // Freeze the underlying page
  if (document.documentElement) {
    document.documentElement.style.setProperty('overflow', 'hidden', 'important');
  }
  if (document.body) {
    document.body.style.setProperty('overflow', 'hidden', 'important');
  }

  const host = document.createElement('div');
  host.id = 'verity-security-host';
  // Use inline styles to guarantee full screen and solid background BEFORE shadow DOM
  host.style.setProperty('position', 'fixed', 'important');
  host.style.setProperty('top', '0', 'important');
  host.style.setProperty('left', '0', 'important');
  host.style.setProperty('width', '100vw', 'important');
  host.style.setProperty('height', '100vh', 'important');
  host.style.setProperty('z-index', '2147483647', 'important');
  host.style.setProperty('background-color', '#FAFAFA', 'important'); 
  
  const shadow = host.attachShadow({ mode: 'closed' });

  // Determine State
  const isDanger = verdict.action === 'block' || verdict.severity === 'danger';
  const stateColor = isDanger ? '#D32F2F' : '#F57C00';
  const stateIconColor = isDanger ? '#EF5350' : '#FFCA28';
  const stateTitle = isDanger ? 'Dangerous' : 'Suspicious';
  
  // Extract primary threat category
  let primaryCategory = 'Suspicious Website';
  if (verdict.categories) {
    if (verdict.categories.phishing.flagged) primaryCategory = 'Phishing';
    else if (verdict.categories.malware.flagged) primaryCategory = 'Malware';
    else if (verdict.categories.scamFraud.flagged) primaryCategory = 'Scam / Fraud';
  }

  const hardcodedCSS = `
    :host {
      display: block;
      width: 100vw;
      height: 100vh;
      margin: 0;
      padding: 0;
    }
    * {
      box-sizing: border-box;
    }
    .verity-overlay {
      width: 100%;
      height: 100%;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      display: flex;
      flex-direction: column;
      background-color: #FAFAFA;
      background-image: radial-gradient(circle at bottom left, rgba(245,124,0,0.05) 0%, transparent 40%),
                        radial-gradient(circle at bottom right, rgba(211,47,47,0.05) 0%, transparent 40%);
      color: #333;
      overflow-y: auto;
    }
    .verity-header {
      padding: 40px 60px;
      font-size: 26px;
      font-weight: 800;
      color: #D32F2F;
      display: flex;
      align-items: center;
      letter-spacing: -0.02em;
    }
    .verity-header-pipe {
      color: #ccc;
      margin: 0 12px;
      font-weight: 300;
    }
    .verity-header-sub {
      color: #444;
      font-weight: 400;
      font-size: 20px;
    }
    .verity-card-container {
      flex: 1;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 40px;
    }
    .verity-card {
      background: white;
      border-radius: 16px;
      box-shadow: 0 10px 40px rgba(0,0,0,0.05);
      display: flex;
      max-width: 950px;
      width: 100%;
      padding: 60px;
      gap: 60px;
      border: 1px solid #f0f0f0;
    }
    @media (max-width: 800px) {
      .verity-card {
        flex-direction: column;
        padding: 40px;
      }
    }
    .verity-card-left {
      flex: 0 0 280px;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .verity-alert-wrapper {
      width: 280px;
      height: 280px;
      border-radius: 50%;
      background: ${isDanger ? '#ffebee' : '#fff8e1'};
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .verity-alert-circle {
      width: 180px;
      height: 180px;
      border-radius: 50%;
      background: ${isDanger ? '#D32F2F' : '#FFA000'};
      border: 6px solid ${stateIconColor};
      display: flex;
      align-items: center;
      justify-content: center;
      color: white;
      font-size: 90px;
      font-weight: bold;
      box-shadow: 0 8px 16px rgba(0,0,0,0.1);
    }
    .verity-card-right {
      flex: 1;
      display: flex;
      flex-direction: column;
      justify-content: center;
    }
    .verity-status {
      margin: 0 0 10px 0;
      font-size: 36px;
      font-weight: 600;
      color: #333;
      letter-spacing: -0.01em;
    }
    .verity-status-highlight {
      color: ${stateColor};
    }
    .verity-url {
      color: #666;
      font-size: 16px;
      margin-bottom: 30px;
      font-family: monospace;
    }
    .verity-message {
      font-size: 17px;
      line-height: 1.6;
      color: #444;
      margin-bottom: 30px;
    }
    .verity-tags {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 40px;
    }
    .verity-tag {
      background: #f1f3f4;
      color: #333;
      padding: 8px 16px;
      border-radius: 6px;
      font-size: 14px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .verity-actions {
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: 20px;
      margin-bottom: 24px;
    }
    .verity-btn-secondary {
      background: transparent;
      border: none;
      color: #2962FF;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
    }
    .verity-btn-secondary:hover {
      text-decoration: underline;
    }
    .verity-btn-primary {
      background: #304FFE;
      color: white;
      border: none;
      border-radius: 30px;
      padding: 14px 40px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s, transform 0.1s;
    }
    .verity-btn-primary:hover {
      background: #1A237E;
    }
    .verity-btn-primary:active {
      transform: scale(0.98);
    }
    .verity-trust-msg {
      font-size: 13px;
      color: #888;
      text-align: right;
      margin: 0;
    }
  `;

  const styleTag = document.createElement('style');
  styleTag.textContent = hardcodedCSS;
  shadow.appendChild(styleTag);

  const container = document.createElement('div');
  container.className = 'verity-overlay';
  
  // Extract tags from reasons
  const tagsHtml = (verdict.reasons || ['High Risk Pattern Detected']).map(r => 
    `<span class="verity-tag">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
      ${r}
    </span>`
  ).join('');

  container.innerHTML = `
    <div class="verity-header">
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 12px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
      VERITY <span class="verity-header-pipe">|</span> <span class="verity-header-sub">Web Protection</span>
    </div>
    
    <div class="verity-card-container" id="main-view">
      <div class="verity-card">
        <div class="verity-card-left">
          <div class="verity-alert-wrapper">
            <div class="verity-alert-circle">!</div>
          </div>
        </div>
        
        <div class="verity-card-right">
          <h1 class="verity-status">Website status: <span class="verity-status-highlight">${stateTitle}</span></h1>
          <div class="verity-url">${window.location.href}</div>
          
          <p class="verity-message">
            ${isDanger 
              ? 'This site looks highly dangerous to us. It matches signatures of phishing, scams, or credential theft. We strongly recommend you do not proceed. Better safe than sorry!' : 
              'This site looks a little risky to us, so we flagged it just in case. Make sure you trust this site if you choose to proceed. Better safe than sorry!'}
          </p>
          
          <div class="verity-tags">
            ${tagsHtml}
            <span class="verity-tag" style="color: ${stateColor}; background: ${isDanger ? '#ffebee' : '#fff8e1'}">Risk Score: ${verdict.score}/100</span>
          </div>
          
          <div class="verity-actions">
            <button class="verity-btn-secondary" id="btn-proceed">Visit anyway</button>
            <button class="verity-btn-primary" id="btn-back">Go back</button>
          </div>
          
          <p class="verity-trust-msg">
            Choosing to visit this site will add the URL to your list of trusted overrides.
          </p>
        </div>
      </div>
    </div>

    <!-- Confirmation View -->
    <div class="verity-card-container" id="confirm-view" style="display: none;">
      <div class="verity-card" style="max-width: 600px; padding: 40px; flex-direction: column; gap: 20px;">
        <h1 class="verity-status" style="font-size: 28px;">Are you absolutely sure?</h1>
        <p class="verity-message" style="margin-bottom: 10px;">
          This website has been classified as <strong>${stateTitle}</strong>.<br><br>
          Proceeding may expose sensitive information such as passwords, financial details, or personal data.
        </p>
        <div class="verity-actions" style="margin-top: 20px;">
          <button class="verity-btn-secondary" id="btn-confirm-cancel">Cancel</button>
          <button class="verity-btn-primary" id="btn-confirm-proceed" style="background: #D32F2F;">Continue Anyway</button>
        </div>
      </div>
    </div>
  `;

  shadow.appendChild(container);

  // Event Listeners
  const mainView = shadow.querySelector('#main-view');
  const confirmView = shadow.querySelector('#confirm-view');
  
  shadow.querySelector('#btn-back').addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'chrome://newtab/';
    }
  });

  shadow.querySelector('#btn-proceed').addEventListener('click', () => {
    mainView.style.display = 'none';
    confirmView.style.display = 'flex';
  });

  shadow.querySelector('#btn-confirm-cancel').addEventListener('click', () => {
    confirmView.style.display = 'none';
    mainView.style.display = 'flex';
  });

  shadow.querySelector('#btn-confirm-proceed').addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'USER_OVERRIDE_ALLOW', url: window.location.href });
    removeOverlay();
  });
  
  const parent = document.documentElement || document.body;
  if (parent) {
    parent.appendChild(host);
  }

  if (!blockObserver && parent) {
    blockObserver = new MutationObserver((mutations) => {
      let removed = false;
      mutations.forEach(m => {
        m.removedNodes.forEach(n => {
          if (n === host || n.id === 'verity-security-host') {
            removed = true;
          }
        });
      });
      if (removed && isBlocked) {
        parent.appendChild(host);
        document.documentElement.style.setProperty('overflow', 'hidden', 'important');
      }
    });
    blockObserver.observe(parent, { childList: true });
  }
}
