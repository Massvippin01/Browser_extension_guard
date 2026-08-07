/**
 * content-script.js - Injected into all pages.
 * Responsible for collecting basic DOM signals and injecting the overlay when needed.
 */

// 1. Signal Collection (Stage 1)
// We collect characteristics of the page that could inform risk scoring.
// Note: We DO NOT read passwords or input values, only structural data.

function collectSignals() {
  const hasPasswordInput = document.querySelector('input[type="password"]') !== null;
  const loginForms = Array.from(document.querySelectorAll('form')).filter(form => {
    return form.querySelector('input[type="password"]') !== null || 
           form.action.toLowerCase().includes('login') ||
           form.id.toLowerCase().includes('login');
  });
  
  const formActions = loginForms.map(form => form.action).filter(Boolean);

  // Send signals to background if needed (for now we just log them in console for visibility during dev)
  if (loginForms.length > 0) {
    console.log('[Verity] Detected login form(s). Action URLs:', formActions);
  }

  // Scam heuristics
  const text = document.body ? document.body.innerText.toLowerCase() : '';
  const scamPhrases = ['act now', 'limited time', 'your account will be suspended', 'pay with gift card', 'click here to claim'];
  let scamMatch = scamPhrases.find(p => text.includes(p));

  // PUP heuristics
  let pupMatch = null;
  const scripts = document.scripts;
  for (let i = 0; i < scripts.length; i++) {
    const s = scripts[i].innerText || '';
    if (s.includes('eval(') && s.includes('unescape(')) {
      pupMatch = 'Obfuscated inline script detected';
      break;
    }
  }
  // Check for auto-download links or invisible iframes (lightweight PUP signals)
  if (document.querySelectorAll('iframe[style*="opacity: 0"], iframe[style*="display: none"]').length > 3) {
    pupMatch = 'Excessive hidden iframes detected';
  }

  // Financial Context Engine
  const financialKeywords = ['upi', 'bank', 'banking', 'net banking', 'payment', 'checkout', 'wallet', 'credit card', 'debit card', 'cvv', 'otp', 'pin', 'kyc', 'refund', 'cashback', 'investment', 'crypto', 'trading'];
  let financialMatch = financialKeywords.filter(k => text.includes(k));

  // Credential Collection Detection
  const sensitiveInputs = Array.from(document.querySelectorAll('input')).filter(input => {
    const attr = (input.name + input.id + input.type + input.placeholder).toLowerCase();
    return attr.includes('password') || attr.includes('card') || attr.includes('cvv') || attr.includes('otp') || attr.includes('pin') || attr.includes('upi') || attr.includes('account');
  });
  const hasCredentialCollection = sensitiveInputs.length > 0;

  return {
    hasPasswordInput: hasPasswordInput,
    loginFormCount: loginForms.length,
    formActions: formActions,
    scam: !!scamMatch,
    scamReason: scamMatch ? `Matches scam language: "${scamMatch}"` : null,
    pup: !!pupMatch,
    pupReason: pupMatch,
    financialMatches: financialMatch,
    hasCredentialCollection: hasCredentialCollection
  };
}

// Run collection after DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', collectSignals);
} else {
  collectSignals();
}


// 2. Overlay injection and signals listener
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'show_danger_overlay') {
    injectOverlay(message.verdict);
    sendResponse({ success: true });
  } else if (message.action === 'get_dom_signals') {
    sendResponse(collectSignals());
  }
});

/**
 * Injects the security overlay into the page.
 */
function injectOverlay(verdict) {
  // Prevent duplicate injections
  if (document.getElementById('verity-security-overlay')) {
    return;
  }

  // Construct UI in a Shadow DOM to isolate from host website CSS
  const host = document.createElement('div');
  host.id = 'verity-security-host';
  host.style.position = 'fixed';
  host.style.top = '0';
  host.style.left = '0';
  host.style.width = '100vw';
  host.style.height = '100vh';
  host.style.zIndex = '2147483647';
  
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
  
  // Dynamic Title based on categories
  const flaggedCats = [];
  if (verdict.categories) {
    if (verdict.categories.phishing.flagged) flaggedCats.push("Phishing");
    if (verdict.categories.malware.flagged) flaggedCats.push("Malware");
    if (verdict.categories.scamFraud.flagged) flaggedCats.push("Scam/Fraud");
    if (verdict.categories.suspicious.flagged) flaggedCats.push("Suspicious Software");
  }
  
  const titleText = flaggedCats.length > 0 ? (flaggedCats.join(" + ") + " Detected") : "Security Warning";

  header.innerHTML = `
    <div class="verity-icon danger">!</div>
    <div class="verity-title">Website blocked</div>
    <div style="margin-top: 12px; margin-bottom: 8px;">
      <div style="font-size: 12px; color: var(--text-secondary); text-transform: uppercase; font-weight: var(--font-weight-stat); letter-spacing: 0.05em;">Risk Score</div>
      <div style="font-size: 36px; font-weight: 700; color: var(--color-danger);">${verdict.riskScore !== undefined ? verdict.riskScore : verdict.score} <span style="font-size: 18px; color: var(--text-secondary);">/ 100</span></div>
    </div>
    <div style="font-size: 16px; font-weight: var(--font-weight-heading); color: var(--color-danger); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px;">${verdict.severity ? verdict.severity.toUpperCase() : 'DANGEROUS'}</div>
    <div class="verity-url">${window.location.hostname}</div>
  `;
  card.appendChild(header);

  if (verdict.reasons && verdict.reasons.length > 0) {
    const reasonsTitle = document.createElement('div');
    reasonsTitle.style.fontWeight = 'var(--font-weight-stat)';
    reasonsTitle.style.marginBottom = '8px';
    reasonsTitle.style.color = 'var(--text-primary)';
    reasonsTitle.textContent = 'Why?';
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
  backBtn.textContent = 'LEAVE SITE';

  backBtn.addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'about:blank';
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
  
  proceedBtn.addEventListener('click', () => {
    host.style.display = 'none';
  });

  actions.appendChild(backBtn);
  actions.appendChild(reportBtn);
  actions.appendChild(proceedBtn);
  card.appendChild(actions);

  // Real-vs-Fake side-by-side visual (Top 10 brands)
  const top10Brands = ['PayPal', 'Chase', 'Amazon', 'Apple', 'Google', 'Microsoft', 'Facebook', 'Netflix', 'Bank of America', 'Wells Fargo'];
  let brandMatch = null;
  if (verdict.reasons) {
    for (const reason of verdict.reasons) {
      const match = reason.match(/contains the name "([^"]+)"/);
      if (match) {
        brandMatch = match[1];
        break;
      }
    }
  }

  if (brandMatch && top10Brands.includes(brandMatch)) {
    const visualContainer = document.createElement('div');
    visualContainer.className = 'verity-visual-comparison';
    visualContainer.style.display = 'flex';
    visualContainer.style.gap = '16px';
    visualContainer.style.marginTop = '24px';
    visualContainer.style.justifyContent = 'center';

    const mockRealSvg = `data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="200" height="150" viewBox="0 0 200 150"><rect width="100%" height="100%" fill="%23f3f4f6"/><rect x="0" y="0" width="100%" height="30" fill="%233b82f6"/><text x="100" y="20" font-family="sans-serif" font-size="14" fill="white" text-anchor="middle">Official ${encodeURIComponent(brandMatch)} Site</text><rect x="40" y="50" width="120" height="80" rx="4" fill="white"/><line x1="50" y1="70" x2="150" y2="70" stroke="%23e2e8f0" stroke-width="2"/><line x1="50" y1="90" x2="150" y2="90" stroke="%23e2e8f0" stroke-width="2"/></svg>`;
    
    // Fallback if screenshot is missing
    const fakeSrc = verdict.screenshot || `data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="200" height="150" viewBox="0 0 200 150"><rect width="100%" height="100%" fill="%23fef2f2"/><text x="100" y="75" font-family="sans-serif" font-size="12" fill="%23ef4444" text-anchor="middle">Screenshot Unavailable</text></svg>`;

    visualContainer.innerHTML = `
      <div style="flex:1; text-align:center;">
        <div style="font-size:12px; color:var(--text-secondary); margin-bottom:8px; font-weight:var(--font-weight-stat); text-transform:uppercase;">Real Site</div>
        <img src="${mockRealSvg}" style="width:100%; max-width:200px; border:1px solid var(--border-color); border-radius:4px; box-shadow:var(--shadow-sm);">
      </div>
      <div style="flex:1; text-align:center;">
        <div style="font-size:12px; color:var(--text-secondary); margin-bottom:8px; font-weight:var(--font-weight-stat); text-transform:uppercase;">This Page (Fake)</div>
        <img src="${fakeSrc}" style="width:100%; max-width:200px; border:1px solid var(--border-color); border-radius:4px; box-shadow:var(--shadow-sm);">
      </div>
    `;
    card.insertBefore(visualContainer, actions);
  }

  shadow.appendChild(overlay);
  document.body.appendChild(host);
}
