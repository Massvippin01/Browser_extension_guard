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

// Start immediately
triggerImmediateUrlScan();

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', triggerFullScan);
} else {
  triggerFullScan();
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

  // Freeze scrolling on the document
  if (document.documentElement) {
    document.documentElement.style.setProperty('overflow', 'hidden', 'important');
  }

  const host = document.createElement('div');
  host.id = 'verity-security-host';
  host.style.setProperty('position', 'fixed', 'important');
  host.style.setProperty('top', '0', 'important');
  host.style.setProperty('left', '0', 'important');
  host.style.setProperty('width', '100vw', 'important');
  host.style.setProperty('height', '100vh', 'important');
  host.style.setProperty('z-index', '2147483647', 'important'); // Maximum safe z-index
  host.style.setProperty('background', 'rgba(0,0,0,0.5)', 'important');
  
  const shadow = host.attachShadow({ mode: 'closed' });

  // Inject Theme CSS
  const themeUrl = chrome.runtime.getURL('shared/theme.css');
  const themeLink = document.createElement('link');
  themeLink.rel = 'stylesheet';
  themeLink.type = 'text/css';
  themeLink.href = themeUrl;
  shadow.appendChild(themeLink);

  // Inject Overlay CSS
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.type = 'text/css';
  link.href = chrome.runtime.getURL('content/overlay.css');
  shadow.appendChild(link);

  const overlay = document.createElement('div');
  overlay.id = 'verity-security-overlay';
  
  const card = document.createElement('div');
  card.className = 'verity-card';

  const header = document.createElement('div');
  header.className = 'verity-header';
  
  const titleText = "Website blocked";

  header.innerHTML = `
    <div class="verity-icon danger">!</div>
    <div class="verity-title">${titleText}</div>
    <div style="margin-top: 12px; margin-bottom: 8px;">
      <div style="font-size: 12px; color: var(--text-secondary); text-transform: uppercase; font-weight: var(--font-weight-stat); letter-spacing: 0.05em;">Risk Score</div>
      <div style="font-size: 36px; font-weight: 700; color: var(--color-danger);">${verdict.riskScore !== undefined ? verdict.riskScore : verdict.score} <span style="font-size: 18px; color: var(--text-secondary);">/ 100</span></div>
    </div>
    <div style="font-size: 16px; font-weight: var(--font-weight-heading); color: var(--color-danger); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px;">🔴 ${verdict.severity ? verdict.severity.toUpperCase() : 'DANGEROUS'}</div>
    <div class="verity-url">${window.location.hostname}</div>
  `;
  card.appendChild(header);

  if (verdict.reasons && verdict.reasons.length > 0) {
    const reasonsTitle = document.createElement('div');
    reasonsTitle.style.fontWeight = 'var(--font-weight-stat)';
    reasonsTitle.style.marginBottom = '8px';
    reasonsTitle.style.color = 'var(--text-primary)';
    reasonsTitle.textContent = 'Verity detected characteristics commonly associated with phishing:';
    card.appendChild(reasonsTitle);

    const reasonsList = document.createElement('ul');
    reasonsList.className = 'verity-reasons';
    verdict.reasons.forEach(reason => {
      const li = document.createElement('li');
      li.textContent = reason;
      reasonsList.appendChild(li);
    });
    card.appendChild(reasonsList);
  }

  const actions = document.createElement('div');
  actions.className = 'verity-actions';
  
  const backBtn = document.createElement('button');
  backBtn.className = 'verity-btn verity-btn-primary';
  backBtn.id = 'verity-btn-back';
  backBtn.textContent = '← GO BACK';

  backBtn.addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'chrome://newtab/';
    }
  });

  const reportBtn = document.createElement('button');
  reportBtn.className = 'verity-btn verity-btn-secondary';
  reportBtn.style.color = 'var(--primary-blue)';
  reportBtn.style.textDecoration = 'none';
  reportBtn.style.fontWeight = 'var(--font-weight-stat)';
  reportBtn.textContent = 'VIEW SECURITY REPORT';
  reportBtn.addEventListener('click', () => {
    window.open(chrome.runtime.getURL('reports/report.html?url=' + encodeURIComponent(window.location.href)), '_blank');
  });

  const proceedBtn = document.createElement('button');
  proceedBtn.className = 'verity-btn verity-btn-secondary';
  proceedBtn.id = 'verity-btn-proceed';
  proceedBtn.textContent = 'PROCEED ANYWAY';
  
  // Two-step confirmation for proceed anyway
  proceedBtn.addEventListener('click', () => {
    if (proceedBtn.textContent === 'PROCEED ANYWAY') {
      proceedBtn.textContent = 'ARE YOU SURE?';
      proceedBtn.style.color = 'var(--color-danger)';
      proceedBtn.style.borderColor = 'var(--color-danger)';
    } else {
      chrome.runtime.sendMessage({ action: 'USER_OVERRIDE_ALLOW', url: window.location.href });
      removeOverlay();
    }
  });

  actions.appendChild(backBtn);
  actions.appendChild(reportBtn);
  actions.appendChild(proceedBtn);
  card.appendChild(actions);

  shadow.appendChild(overlay);
  
  // Attach directly to Document Element (<html>) so it works even if body is missing
  const parent = document.documentElement || document.body;
  if (parent) {
    parent.appendChild(host);
  }

  // Prevent circumvention by monitoring the DOM and re-injecting if the page deletes it
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
        parent.appendChild(host); // Force it back
        document.documentElement.style.setProperty('overflow', 'hidden', 'important');
      }
    });
    blockObserver.observe(parent, { childList: true });
  }
}
