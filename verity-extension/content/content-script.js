/**
 * content-script.js - Injected into all pages at document_start.
 * Responsible for initiating early URL scans, collecting DOM signals, and enforcing blocks.
 */

let isBlocked = false;
let blockObserver = null;
let statusBadgeHost = null;

// ─── Payment Field Detection ─────────────────────────────────────────────────

/**
 * Gets searchable metadata of an input — structural only, NEVER the value.
 */
function getInputMeta(input) {
  const labelText = (() => {
    if (input.id) {
      const lbl = document.querySelector(`label[for="${CSS.escape(input.id)}"]`);
      if (lbl) return lbl.innerText;
    }
    const parent = input.closest('label');
    return parent ? parent.innerText : '';
  })();
  return [
    input.type || '',
    input.name || '',
    input.id || '',
    input.autocomplete || '',
    input.placeholder || '',
    input.getAttribute('aria-label') || '',
    input.getAttribute('data-field') || '',
    labelText,
  ].join(' ').toLowerCase();
}

function detectPaymentFields() {
  const inputs = Array.from(document.querySelectorAll('input'));
  let card = false, cvv = false, expiry = false, upi = false,
      otp = false, pin = false, accountNumber = false;

  for (const input of inputs) {
    const m = getInputMeta(input);

    if (!card && (m.includes('cc-number') || m.includes('cardnumber') ||
      m.includes('card_number') || m.includes('card number') ||
      m.includes('card no') || m.includes('creditcard') || m.includes('debitcard') ||
      (m.includes('card') && !m.includes('gift') && !m.includes('id card') && !m.includes('aadhar'))))
      card = true;

    if (!cvv && (m.includes('cc-csc') || m.includes('cvv') || m.includes('cvc') ||
      m.includes('cvc2') || m.includes('security code') || m.includes('card code')))
      cvv = true;

    if (!expiry && (m.includes('cc-exp') || m.includes('expiry') ||
      m.includes('expiration') || m.includes('exp date') ||
      m.includes('valid thru') || m.includes('valid through')))
      expiry = true;

    if (!upi && (m.includes('upi') || m.includes('vpa') || m.includes('upi id')))
      upi = true;

    if (!otp && (m.includes('otp') || m.includes('one time') ||
      m.includes('tpin') || m.includes('transaction code')))
      otp = true;

    if (!pin && (m.includes('mpin') || m.includes('payment pin') ||
      m.includes('atm pin') || m.includes('debit pin') || m.includes('bank pin')))
      pin = true;

    if (!accountNumber && (m.includes('account number') || m.includes('account no') ||
      m.includes('acct') || m.includes('ifsc') || m.includes('bank account')))
      accountNumber = true;
  }

  return { card, cvv, expiry, upi, otp, pin, accountNumber };
}

function detectPaymentForm() {
  const paymentKeywords = ['payment', 'pay', 'checkout', 'billing', 'card', 'upi', 'transaction'];
  return Array.from(document.querySelectorAll('form')).some(form => {
    const meta = ((form.action||'') + (form.id||'') + (form.className||'')).toLowerCase();
    return paymentKeywords.some(k => meta.includes(k));
  });
}

// Known payment brand aliases for claimed-provider detection
const PAYMENT_BRAND_ALIASES = [
  ['PayPal', ['paypal']], ['Stripe', ['stripe']], ['Razorpay', ['razorpay']],
  ['PhonePe', ['phonepe', 'phone pe']], ['Google Pay', ['google pay', 'gpay']],
  ['Paytm', ['paytm']], ['Amazon Pay', ['amazon pay']], ['PayU', ['payu', 'payumoney']],
  ['CCAvenue', ['ccavenue']], ['BillDesk', ['billdesk']], ['Cashfree', ['cashfree']],
  ['Instamojo', ['instamojo']], ['Square', ['squareup']], ['Klarna', ['klarna']],
  ['Apple Pay', ['apple pay']], ['Mastercard', ['mastercard']], ['Visa', ['visa']],
  ['RuPay', ['rupay']], ['BHIM', ['bhim']], ['MobiKwik', ['mobikwik']],
];

function scanClaimedProviders() {
  const text = (document.body ? document.body.innerText : '').toLowerCase();
  return PAYMENT_BRAND_ALIASES
    .filter(([, aliases]) => aliases.some(a => text.includes(a)))
    .map(([name]) => name);
}

// 1. Signal Collection (Stage 1)
function collectSignals() {
  const text = document.body ? document.body.innerText.toLowerCase() : '';
  const currentHostname = window.location.hostname.toLowerCase().replace(/^www\./, '');

  // Major trusted domains — skip aggressive credential/financial synergy scoring.
  // These sites legitimately have login forms and financial terminology.
  const TRUSTED_DOMAINS = new Set([
    'github.com', 'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'linkedin.com', 'reddit.com', 'stackoverflow.com', 'wikipedia.org',
    'netflix.com', 'spotify.com', 'discord.com', 'slack.com', 'notion.so',
    'dropbox.com', 'zoom.us', 'atlassian.com', 'gitlab.com', 'bitbucket.org',
    'cloudflare.com', 'npmjs.com', 'pypi.org', 'docker.com', 'vercel.com',
    'netlify.com', 'heroku.com', 'digitalocean.com', 'aws.amazon.com',
    'portal.azure.com', 'console.cloud.google.com', 'firebase.google.com',
    'accounts.google.com', 'login.microsoftonline.com',
    // Indian government & major services
    'irctc.co.in', 'incometax.gov.in', 'mca.gov.in', 'uidai.gov.in',
    'epfindia.gov.in', 'onlinesbi.sbi', 'hdfcbank.com', 'icicibank.com',
    'axisbank.com', 'kotak.com', 'paytm.com', 'phonepe.com', 'razorpay.com'
  ]);

  const isTrustedDomain = TRUSTED_DOMAINS.has(currentHostname) ||
    [...TRUSTED_DOMAINS].some(d => currentHostname.endsWith('.' + d));

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
  // IMPORTANT: 'pin' removed — matches 'pinned' on GitHub/social sites.
  // Only specific, unambiguous financial terms are included.
  const financialKeywords = [
    'upi', 'net banking', 'credit card', 'debit card', 'cvv', 'otp',
    'kyc', 'atm pin', 'mpin', 'bank account', 'ifsc',
    'cashback', 'crypto', 'wallet'
  ];
  let financialMatch = isTrustedDomain ? [] : financialKeywords.filter(k => text.includes(k));

  // Credential Collection Detection
  // IMPORTANT: 'pin' and 'account' removed — too generic, causes false positives
  // on GitHub (search box name attribute), Stack Overflow, etc.
  const sensitiveInputs = isTrustedDomain ? [] : Array.from(document.querySelectorAll('input')).filter(input => {
    const attr = ((input.name||'') + (input.id||'') + (input.type||'') + (input.placeholder||'')).toLowerCase();
    return attr.includes('password') || attr.includes('cardnumber') || 
           attr.includes('cc-number') || attr.includes('cvv') || 
           attr.includes('cc-csc') || attr.includes('otp') || attr.includes('upi');
  });

  // ── Payment-specific signals ──
  const paymentFields    = detectPaymentFields();
  const hasPaymentForm   = detectPaymentForm();
  const claimedProviders = scanClaimedProviders();

  return {
    hasPasswordInput: isTrustedDomain ? false : hasPasswordInput,
    loginFormCount: isTrustedDomain ? 0 : loginForms.length,
    formActions,
    scam: !!scamMatch,
    scamReason: scamMatch ? `Matches scam language: "${scamMatch}"` : null,
    pup: !!pupMatch,
    pupReason: pupMatch,
    financialMatches: financialMatch,
    hasCredentialCollection: sensitiveInputs.length > 0,
    isTrustedDomain,
    // Payment Protection signals
    paymentFields: isTrustedDomain ? {} : paymentFields,
    hasPaymentForm: isTrustedDomain ? false : hasPaymentForm,
    claimedProviders,
    pageText:  text.substring(0, 3000),
    pageTitle: document.title || '',
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

// ─── Live Status Badge ──────────────────────────────────────────────────────

function injectStatusBadge() {
  if (document.getElementById('verity-status-badge-host')) return;

  const host = document.createElement('div');
  host.id = 'verity-status-badge-host';
  host.style.cssText = 'position:fixed;top:16px;right:16px;z-index:2147483646;pointer-events:auto;';
  statusBadgeHost = host;

  const shadow = host.attachShadow({ mode: 'closed' });

  const style = document.createElement('style');
  style.textContent = `
    .verity-badge {
      width: 22px;
      height: 22px;
      border-radius: 50%;
      background: #94a3b8;
      border: 2px solid rgba(255,255,255,0.7);
      box-shadow: 0 2px 8px rgba(0,0,0,0.25), 0 0 0 0 rgba(148,163,184,0.5);
      cursor: pointer;
      transition: transform 0.2s ease, box-shadow 0.2s ease, background 0.4s ease;
      position: relative;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .verity-badge:hover {
      transform: scale(1.15);
    }
    .verity-badge.pulse {
      animation: badgePulse 1.8s ease-out;
    }
    @keyframes badgePulse {
      0%   { box-shadow: 0 2px 8px rgba(0,0,0,0.25), 0 0 0 0 var(--pulse-color, rgba(148,163,184,0.6)); }
      60%  { box-shadow: 0 2px 8px rgba(0,0,0,0.25), 0 0 0 10px rgba(0,0,0,0); }
      100% { box-shadow: 0 2px 8px rgba(0,0,0,0.25), 0 0 0 0 rgba(0,0,0,0); }
    }
    .verity-badge-scanning {
      background: conic-gradient(#94a3b8 0%, #cbd5e1 50%, #94a3b8 100%);
      animation: spin 1.2s linear infinite;
    }
    @keyframes spin {
      from { transform: rotate(0deg); }
      to   { transform: rotate(360deg); }
    }
    .verity-tooltip {
      position: absolute;
      top: 28px;
      right: 0;
      background: rgba(15,23,42,0.95);
      color: #f8fafc;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 11px;
      font-weight: 500;
      line-height: 1.5;
      padding: 8px 12px;
      border-radius: 8px;
      white-space: nowrap;
      opacity: 0;
      pointer-events: none;
      transform: translateY(-4px);
      transition: opacity 0.2s, transform 0.2s;
      box-shadow: 0 4px 16px rgba(0,0,0,0.3);
      max-width: 240px;
      white-space: normal;
      text-align: left;
    }
    .verity-badge:hover .verity-tooltip {
      opacity: 1;
      transform: translateY(0);
    }
    .verity-badge-icon {
      font-size: 11px;
      line-height: 1;
      user-select: none;
    }
  `;
  shadow.appendChild(style);

  const badge = document.createElement('div');
  badge.className = 'verity-badge verity-badge-scanning';
  badge.innerHTML = `<div class="verity-tooltip">🛡️ Verity\nScanning…</div>`;
  shadow.appendChild(badge);

  // Append to documentElement immediately so it works at document_start
  const parent = document.documentElement || document.body;
  if (parent) parent.appendChild(host);

  // Re-attach after body is available
  if (!document.body) {
    document.addEventListener('DOMContentLoaded', () => {
      if (host.parentElement !== document.documentElement && document.documentElement) {
        document.documentElement.appendChild(host);
      }
    });
  }

  return shadow;
}

const badgeShadow = injectStatusBadge();

function updateStatusBadge(verdict) {
  if (!badgeShadow) return;
  const badge = badgeShadow.querySelector('.verity-badge');
  const tooltip = badgeShadow.querySelector('.verity-tooltip');
  if (!badge || !tooltip) return;

  // Stop scanning spin
  badge.className = 'verity-badge';

  const severity = verdict.severity || verdict.state || 'safe';
  const score = verdict.score || verdict.riskScore || 0;
  const shortener = verdict.shortenerDetected;
  const chain = verdict.redirectChain;

  let color, pulseColor, icon, label, detail;

  if (severity === 'danger') {
    color = '#ef4444';
    pulseColor = 'rgba(239,68,68,0.5)';
    icon = '🔴';
    label = 'DANGEROUS';
    detail = `Risk: ${score}/100`;
  } else if (severity === 'caution') {
    color = '#f59e0b';
    pulseColor = 'rgba(245,158,11,0.5)';
    icon = '🟡';
    label = 'SUSPICIOUS';
    detail = `Risk: ${score}/100`;
  } else {
    color = '#22c55e';
    pulseColor = 'rgba(34,197,94,0.4)';
    icon = '🟢';
    label = 'SAFE';
    detail = `Risk: ${score}/100`;
  }

  badge.style.background = color;
  badge.style.setProperty('--pulse-color', pulseColor);
  badge.classList.add('pulse');
  badge.addEventListener('animationend', () => badge.classList.remove('pulse'), { once: true });

  let chainHtml = '';
  if (shortener && chain && chain.length > 1) {
    const chainStr = chain.map(u => { try { return new URL(u).hostname; } catch(e) { return u; } }).join(' → ');
    chainHtml = `<div style="margin-top:4px;opacity:0.8;font-size:10px;">🔗 ${chainStr}</div>`;
  }

  tooltip.innerHTML = `
    <div><strong>🛡️ Verity</strong> — ${label}</div>
    <div style="opacity:0.8">${detail}</div>
    ${chainHtml}
  `;
}

// 3. Listen for enforcement decisions from Background
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'ENFORCEMENT_DECISION') {
    const verdict = message.decision.verdict;
    updateStatusBadge(verdict);
    if (message.decision.action === 'block') {
      isBlocked = true;
      // Hide badge when full block overlay is shown
      if (statusBadgeHost) statusBadgeHost.style.display = 'none';
      injectOverlay(verdict);
    } else if (message.decision.action === 'allow') {
      isBlocked = false;
      if (statusBadgeHost) statusBadgeHost.style.display = 'block';
      removeOverlay();
    } else if (message.decision.action === 'warn') {
      // Warn = keep badge visible, no full block
      if (statusBadgeHost) statusBadgeHost.style.display = 'block';
    }
  } else if (message.action === 'RE_ANALYZE') {
    // Fired on SPA client-side navigations
    isBlocked = false;
    removeOverlay();
    if (statusBadgeHost) statusBadgeHost.style.display = 'block';
    // Reset badge to scanning
    if (badgeShadow) {
      const badge = badgeShadow.querySelector('.verity-badge');
      if (badge) badge.className = 'verity-badge verity-badge-scanning';
    }
    triggerImmediateUrlScan();
    setTimeout(triggerFullScan, 500);
  } else if (message.action === 'DOWNLOAD_VERDICT') {
    injectDownloadWarning(message.payload);
  }
});

// Start immediately AFTER listener is registered to prevent race conditions
triggerImmediateUrlScan();

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', triggerFullScan);
} else {
  triggerFullScan();
}

// ─── Download Warning UI ────────────────────────────────────────────────────
let downloadWarningHost = null;

function injectDownloadWarning(payload) {
  removeDownloadWarning();

  const { filename, sourceHostname, signals, riskScore, severity, action, cancelled, chromeSaysDangerous } = payload;

  const isDanger = severity === 'danger' || action === 'block';

  const color   = isDanger ? '#ef4444' : '#f59e0b';
  const bgColor = isDanger ? 'rgba(30,10,10,0.97)' : 'rgba(30,25,10,0.97)';
  const icon    = isDanger ? '🛑' : '⚠️';
  const title   = isDanger
    ? (chromeSaysDangerous ? 'DANGEROUS DOWNLOAD' : 'HIGH-RISK DOWNLOAD BLOCKED')
    : 'SUSPICIOUS DOWNLOAD DETECTED';

  const signalsHtml = (signals || []).map(s =>
    `<div style="display:flex;align-items:flex-start;gap:8px;margin-bottom:5px;">
      <span style="color:${color};font-size:13px;flex-shrink:0;">✓</span>
      <span>${s}</span>
    </div>`
  ).join('');

  const cancelledNote = cancelled
    ? `<div style="margin-top:8px;padding:6px 10px;background:rgba(239,68,68,0.15);border-radius:6px;font-size:11px;color:#fca5a5;">Download cancelled by Verity.</div>`
    : (isDanger ? `<div style="margin-top:8px;padding:6px 10px;background:rgba(239,68,68,0.1);border-radius:6px;font-size:11px;color:#fca5a5;">Verity recommends cancelling this download manually.</div>` : '');

  const host = document.createElement('div');
  host.id = 'verity-download-warning-host';
  host.style.cssText = 'position:fixed;top:60px;right:16px;z-index:2147483645;pointer-events:auto;max-width:380px;width:380px;';
  downloadWarningHost = host;

  const shadow = host.attachShadow({ mode: 'closed' });
  shadow.innerHTML = `
    <style>
      .dw-panel {
        background: ${bgColor};
        border: 1.5px solid ${color};
        border-radius: 14px;
        padding: 18px 20px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        font-size: 12px;
        color: #f1f5f9;
        box-shadow: 0 8px 32px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.04);
        animation: slideIn 0.25s ease;
      }
      @keyframes slideIn {
        from { transform: translateX(110%); opacity: 0; }
        to   { transform: translateX(0); opacity: 1; }
      }
      .dw-header { display:flex; align-items:center; gap:10px; margin-bottom:12px; }
      .dw-icon { font-size:22px; }
      .dw-title { font-size:13px; font-weight:700; color:${color}; letter-spacing:0.5px; }
      .dw-meta { background:rgba(255,255,255,0.05); border-radius:8px; padding:10px 12px; margin-bottom:12px; }
      .dw-meta-row { display:flex; gap:6px; margin-bottom:5px; font-size:11px; }
      .dw-meta-label { color:#94a3b8; min-width:60px; flex-shrink:0; }
      .dw-meta-value { color:#e2e8f0; word-break:break-all; font-weight:500; }
      .dw-signals { margin-bottom:12px; font-size:11px; line-height:1.5; color:#cbd5e1; }
      .dw-score { display:flex; justify-content:space-between; align-items:center; }
      .dw-score-label { font-size:11px; color:#94a3b8; }
      .dw-score-value { font-size:15px; font-weight:700; color:${color}; }
      .dw-actions { display:flex; gap:10px; margin-top:14px; }
      .dw-btn { flex:1; padding:9px; border:none; border-radius:8px; cursor:pointer; font-size:12px; font-weight:600; transition: opacity 0.15s; }
      .dw-btn-dismiss { background:rgba(255,255,255,0.08); color:#e2e8f0; }
      .dw-btn-dismiss:hover { background:rgba(255,255,255,0.15); }
      .dw-btn-action { background:${color}; color:white; font-weight:700; }
      .dw-btn-action:hover { opacity:0.85; }
    </style>
    <div class="dw-panel">
      <div class="dw-header">
        <div class="dw-icon">${icon}</div>
        <div class="dw-title">${title}</div>
      </div>
      <div class="dw-meta">
        <div class="dw-meta-row"><div class="dw-meta-label">File:</div><div class="dw-meta-value">${filename || 'Unknown'}</div></div>
        <div class="dw-meta-row"><div class="dw-meta-label">Source:</div><div class="dw-meta-value">${sourceHostname || 'Unknown'}</div></div>
      </div>
      ${signalsHtml ? `<div class="dw-signals">${signalsHtml}</div>` : ''}
      <div class="dw-score">
        <span class="dw-score-label">Risk Score</span>
        <span class="dw-score-value">${riskScore} / 100</span>
      </div>
      ${cancelledNote}
      <div class="dw-actions">
        <button class="dw-btn dw-btn-dismiss" id="dw-dismiss">Dismiss</button>
        ${!cancelled ? `<button class="dw-btn dw-btn-action" id="dw-open-dl">↓ View Downloads</button>` : ''}
      </div>
    </div>
  `;

  shadow.getElementById('dw-dismiss')?.addEventListener('click', removeDownloadWarning);
  shadow.getElementById('dw-open-dl')?.addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'OPEN_DOWNLOADS_PAGE' });
  });

  document.documentElement.appendChild(host);

  // Auto-dismiss warn after 15s; danger stays until dismissed
  if (!isDanger) setTimeout(removeDownloadWarning, 15000);
}

function removeDownloadWarning() {
  if (downloadWarningHost) {
    downloadWarningHost.remove();
    downloadWarningHost = null;
  }
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
  const isPaymentPhishing = !!(verdict.paymentAnalysis && verdict.paymentAnalysis.isCriticalPaymentPhishing);
  const stateColor = isDanger ? '#D32F2F' : '#F57C00';
  const stateIconColor = isDanger ? '#EF5350' : '#FFCA28';
  const stateTitle = isPaymentPhishing ? 'Payment Phishing Blocked' : (isDanger ? 'Dangerous' : 'Suspicious');

  // Extract primary threat category
  let primaryCategory = 'Suspicious Website';
  if (isPaymentPhishing) primaryCategory = 'Payment Phishing';
  else if (verdict.categories) {
    if (verdict.categories.phishing && verdict.categories.phishing.flagged) primaryCategory = 'Phishing';
    else if (verdict.categories.malware && verdict.categories.malware.flagged) primaryCategory = 'Malware';
    else if (verdict.categories.scamFraud && verdict.categories.scamFraud.flagged) primaryCategory = 'Scam / Fraud';
  }

  const hardcodedCSS = `
    :host {
      display: block;
      width: 100vw;
      height: 100vh;
      margin: 0;
      padding: 0;
    }
    * { box-sizing: border-box; }
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
    .verity-header-pipe { color: #ccc; margin: 0 12px; font-weight: 300; }
    .verity-header-sub { color: #444; font-weight: 400; font-size: 20px; }
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
      .verity-card { flex-direction: column; padding: 40px; }
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
    .verity-status-highlight { color: ${stateColor}; }
    .verity-url { color: #666; font-size: 16px; margin-bottom: 30px; font-family: monospace; }
    .verity-message { font-size: 17px; line-height: 1.6; color: #444; margin-bottom: 30px; }
    .verity-tags { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 40px; }
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
    .verity-btn-secondary:hover { text-decoration: underline; }
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
    .verity-btn-primary:hover { background: #1A237E; }
    .verity-btn-primary:active { transform: scale(0.98); }
    .verity-trust-msg { font-size: 13px; color: #888; text-align: right; margin: 0; }
  `;

  const styleTag = document.createElement('style');
  styleTag.textContent = hardcodedCSS;
  shadow.appendChild(styleTag);

  const container = document.createElement('div');
  container.className = 'verity-overlay';

  const allReasons = [
    ...(verdict.reasons || []),
    ...(verdict.paymentAnalysis ? verdict.paymentAnalysis.reasons : []),
  ].filter(Boolean);

  const tagsHtml = (allReasons.length > 0 ? allReasons : ['High Risk Pattern Detected']).map(r =>
    `<span class="verity-tag">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
      ${r}
    </span>`
  ).join('');

  const paymentWarning = isPaymentPhishing
    ? `<p style="background:#ffebee;border:1px solid #ef9a9a;border-radius:8px;padding:12px 16px;color:#c62828;font-weight:600;margin-bottom:20px;">
        💳 Your payment information is at risk. Do NOT enter any card, UPI, CVV or OTP details.
       </p>`
    : '';

  let redirectChainHtml = '';
  if (verdict.shortenerDetected && verdict.redirectChain && verdict.redirectChain.length > 1) {
    let chainItems = verdict.redirectChain.map((url, i) => {
      let u;
      try { u = new URL(url).hostname; } catch(e) { u = url; }
      return `<div style="padding: 4px 0; font-family: monospace; font-size: 14px;">${i + 1}. ${u}</div>`;
    });
    let formattedChain = chainItems.join('<div style="color: #999; padding-left: 12px;">↓</div>');
    redirectChainHtml = `
      <div style="background: #f8f9fa; border: 1px solid #e0e0e0; border-radius: 8px; padding: 16px; margin-bottom: 24px;">
        <div style="font-weight: 600; margin-bottom: 12px; font-size: 14px; color: #555;">🔗 REDIRECT ANALYSIS</div>
        ${formattedChain}
      </div>
    `;
  }

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
          ${paymentWarning}
          ${redirectChainHtml}
          <p class="verity-message">
            ${isPaymentPhishing
              ? 'This page is impersonating a payment provider and attempting to collect your payment credentials. This is a payment phishing attack.'
              : isDanger
                ? 'This site looks highly dangerous to us. It matches signatures of phishing, scams, or credential theft. We strongly recommend you do not proceed.'
                : 'This site looks a little risky to us, so we flagged it just in case. Make sure you trust this site if you choose to proceed.'}
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
        ${isPaymentPhishing ? '<p style="color:#c62828;font-weight:600;">⚠️ This page is attempting to steal your payment information (card number, CVV, OTP). Proceeding is extremely risky.</p>' : ''}
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
