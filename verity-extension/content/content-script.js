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
  ['HDFC Bank', ['hdfc', 'hdfcbank', 'hdfc netbanking']], ['SBI', ['sbi', 'onlinesbi', 'sbi yono']],
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
    'upi', 'net banking', 'netbanking', 'credit card', 'debit card', 'cvv', 'otp',
    'kyc', 'atm pin', 'mpin', 'bank account', 'account number', 'ifsc',
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
function handleEnforcementVerdict(verdict) {
  if (!verdict) return;
  updateStatusBadge(verdict);
  if (verdict.action === 'block') {
    isBlocked = true;
    if (statusBadgeHost) statusBadgeHost.style.display = 'none';
    injectOverlay(verdict);
  } else if (verdict.action === 'allow') {
    isBlocked = false;
    if (statusBadgeHost) statusBadgeHost.style.display = 'block';
    removeOverlay();
  }
}

function triggerImmediateUrlScan() {
  chrome.runtime.sendMessage({ action: 'ANALYZE_URL_ONLY', url: window.location.href }, (response) => {
    if (chrome.runtime.lastError) return;
    if (response && response.verdict) {
      handleEnforcementVerdict(response.verdict);
    }
  });
}

function triggerFullScan() {
  const domSignals = collectSignals();
  chrome.runtime.sendMessage({ action: 'ANALYZE_FULL', url: window.location.href, domSignals: domSignals }, (response) => {
    if (chrome.runtime.lastError) return;
    if (response && response.verdict) {
      handleEnforcementVerdict(response.verdict);
    }
  });
}

// ─── Live Status Badge ──────────────────────────────────────────────────────

function injectStatusBadge() {
  if (window.self !== window.top) return null; // Skip floating status badge inside embedded iframes
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

function showPopupBlockedToast(hostname) {
  if (!badgeShadow) return;

  // Pulse badge with red glow
  const badge = badgeShadow.querySelector('.verity-badge');
  if (badge) {
    badge.style.setProperty('--pulse-color', 'rgba(239,68,68,0.7)');
    badge.classList.add('pulse');
    setTimeout(() => badge.classList.remove('pulse'), 2000);
  }

  let toast = badgeShadow.querySelector('#verity-popup-toast-box');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'verity-popup-toast-box';
    badgeShadow.appendChild(toast);
  }

  toast.innerHTML = `
    <style>
      .verity-toast-panel {
        position: fixed;
        top: 46px;
        right: 16px;
        background: rgba(15, 23, 42, 0.96);
        color: #f8fafc;
        border: 2px solid #ef4444;
        border-radius: 12px;
        padding: 12px 16px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        font-size: 12px;
        display: flex;
        align-items: center;
        gap: 12px;
        box-shadow: 0 10px 30px rgba(0,0,0,0.5), 0 0 15px rgba(239,68,68,0.4);
        z-index: 2147483647;
        transform-origin: top right;
        animation: toastExpandShrink 4.8s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        pointer-events: auto;
      }
      @keyframes toastExpandShrink {
        0%   { transform: scale(0.2) translateY(-20px); opacity: 0; }
        12%  { transform: scale(1.08) translateY(0); opacity: 1; }
        18%  { transform: scale(1) translateY(0); opacity: 1; }
        85%  { transform: scale(1) translateY(0); opacity: 1; }
        100% { transform: scale(0.2) translateY(-20px); opacity: 0; }
      }
    </style>
    <div class="verity-toast-panel">
      <span style="font-size:16px;">🚫</span>
      <div>
        <div style="font-weight:800;color:#ef4444;font-size:11px;letter-spacing:0.5px;">VERITY POP-UP BLOCKED</div>
        <div style="color:#cbd5e1;font-size:11px;word-break:break-all;">Blocked pop-under to <strong>${hostname || 'Tracker'}</strong></div>
      </div>
    </div>
  `;

  setTimeout(() => {
    if (toast) toast.innerHTML = '';
  }, 4500);
}

// Listen for window messages from main world
window.addEventListener('message', (event) => {
  if (event.data && event.data.action === 'VERITY_POPUP_BLOCKED') {
    let host = event.data.url;
    try { host = new URL(host).hostname; } catch(e) {}
    showPopupBlockedToast(host);
  }
});

function handleEnforcementVerdict(verdict) {
  if (!verdict) return;
  updateStatusBadge(verdict);
  if (verdict.action === 'block') {
    isBlocked = true;
    if (statusBadgeHost) statusBadgeHost.style.display = 'none';
    injectOverlay(verdict);
  } else if (verdict.action === 'allow') {
    isBlocked = false;
    if (statusBadgeHost) statusBadgeHost.style.display = 'block';
    removeOverlay();
  } else if (verdict.action === 'warn') {
    if (statusBadgeHost) statusBadgeHost.style.display = 'block';
  }
}

// 3. Listen for enforcement decisions from Background
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'POPUP_BLOCKED_TOAST') {
    showPopupBlockedToast(message.hostname || message.blockedUrl);
  } else if (message.action === 'ENFORCEMENT_DECISION') {
    handleEnforcementVerdict(message.decision.verdict);
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
        border: 2px solid ${color};
        border-radius: 16px;
        padding: 18px 20px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        font-size: 12px;
        color: #f1f5f9;
        box-shadow: 0 12px 40px rgba(0,0,0,0.6), 0 0 20px ${isDanger ? 'rgba(239,68,68,0.4)' : 'rgba(245,158,11,0.4)'};
        transform-origin: top right;
        animation: expandAndShrink 5s cubic-bezier(0.16, 1, 0.3, 1) forwards;
      }
      @keyframes expandAndShrink {
        0%   { transform: scale(0.2) translateY(-20px); opacity: 0; }
        12%  { transform: scale(1.06) translateY(0); opacity: 1; }
        18%  { transform: scale(1) translateY(0); opacity: 1; }
        85%  { transform: scale(1) translateY(0); opacity: 1; }
        100% { transform: scale(0.2) translateY(-20px); opacity: 0; }
      }
      .dw-header { display:flex; align-items:center; gap:10px; margin-bottom:12px; }
      .dw-icon { font-size:24px; animation: pulseIcon 1.5s infinite; }
      @keyframes pulseIcon {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.2); }
      }
      .dw-title { font-size:13px; font-weight:800; color:${color}; letter-spacing:0.5px; }
      .dw-meta { background:rgba(255,255,255,0.06); border-radius:10px; padding:10px 12px; margin-bottom:12px; }
      .dw-meta-row { display:flex; gap:6px; margin-bottom:5px; font-size:11px; }
      .dw-meta-label { color:#94a3b8; min-width:60px; flex-shrink:0; }
      .dw-meta-value { color:#e2e8f0; word-break:break-all; font-weight:600; }
      .dw-signals { margin-bottom:12px; font-size:11px; line-height:1.5; color:#cbd5e1; }
      .dw-score { display:flex; justify-content:space-between; align-items:center; }
      .dw-score-label { font-size:11px; color:#94a3b8; }
      .dw-score-value { font-size:16px; font-weight:900; color:${color}; }
      .dw-actions { display:flex; gap:10px; margin-top:14px; }
      .dw-btn { flex:1; padding:9px; border:none; border-radius:8px; cursor:pointer; font-size:12px; font-weight:600; transition: opacity 0.15s; }
      .dw-btn-dismiss { background:rgba(255,255,255,0.1); color:#e2e8f0; }
      .dw-btn-dismiss:hover { background:rgba(255,255,255,0.2); }
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

  setTimeout(() => {
    removeDownloadWarning();
  }, 5100);

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
  isBlocked = false;
  if (blockObserver) {
    blockObserver.disconnect();
    blockObserver = null;
  }
  const existing = document.getElementById('verity-security-host');
  if (existing) {
    existing.remove();
  }
  if (document.documentElement) {
    document.documentElement.style.removeProperty('overflow');
  }
  if (document.body) {
    document.body.style.removeProperty('overflow');
  }
  try {
    window.onbeforeunload = null;
  } catch (e) {}
}

function injectOverlay(verdict) {
  if (document.getElementById('verity-security-host')) {
    return; // Already blocked
  }

  // 1. Immediately HALT all network loading, page downloads & pending client redirects
  try {
    window.stop();
  } catch (e) {}

  // 2. Clear all active timeouts & intervals to kill delayed JS redirects
  try {
    let maxId = window.setTimeout(() => {}, 0);
    for (let i = 0; i <= maxId; i++) {
      window.clearTimeout(i);
      window.clearInterval(i);
    }
  } catch (e) {}

  // 3. Remove any <meta http-equiv="refresh"> redirect tags
  try {
    document.querySelectorAll('meta[http-equiv="refresh"]').forEach(el => el.remove());
  } catch (e) {}

  // 4. Set onbeforeunload handler to warn/halt navigation attempts
  try {
    window.onbeforeunload = function() {
      return "Navigation blocked by Verity Web Protection.";
    };
  } catch (e) {}

  // Freeze the underlying page scroll for main frame
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
      background-color: #F8FAFC;
      background-image: radial-gradient(circle at 10% 10%, rgba(239, 68, 68, 0.07), transparent 45%),
                        radial-gradient(circle at 90% 90%, rgba(37, 99, 235, 0.05), transparent 45%);
      color: #0F172A;
      overflow-y: auto;
    }
    .verity-header {
      padding: 32px 50px;
      font-size: 22px;
      font-weight: 800;
      color: #0F172A;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid rgba(226, 232, 240, 0.8);
      background: rgba(255, 255, 255, 0.8);
      backdrop-filter: blur(8px);
    }
    .verity-header-brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .verity-header-logo {
      width: 38px;
      height: 38px;
      border-radius: 10px;
      background: linear-gradient(135deg, #EF4444, #DC2626);
      color: white;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 20px;
      font-weight: 900;
      box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);
    }
    .verity-header-title {
      font-size: 20px;
      font-weight: 800;
      color: #0F172A;
      letter-spacing: -0.5px;
    }
    .verity-header-pipe { color: #CBD5E1; margin: 0 8px; font-weight: 300; }
    .verity-header-sub { color: #64748B; font-weight: 500; font-size: 15px; }
    .verity-header-badge {
      background: #FFEBEE;
      color: #DC2626;
      font-size: 12px;
      font-weight: 700;
      padding: 6px 14px;
      border-radius: 20px;
      border: 1px solid rgba(220, 38, 38, 0.2);
    }
    .verity-card-container {
      flex: 1;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 40px;
    }
    .verity-card {
      background: #FFFFFF;
      border-radius: 24px;
      box-shadow: 0 25px 60px -15px rgba(15, 23, 42, 0.08), 0 0 0 1px rgba(226, 232, 240, 0.9);
      display: flex;
      max-width: 960px;
      width: 100%;
      padding: 56px;
      gap: 50px;
      transition: transform 0.3s ease;
    }
    @media (max-width: 850px) {
      .verity-card { flex-direction: column; padding: 36px; gap: 30px; }
    }
    .verity-card-left {
      flex: 0 0 240px;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .verity-alert-wrapper {
      width: 220px;
      height: 220px;
      border-radius: 50%;
      background: ${isDanger ? 'rgba(254, 226, 226, 0.7)' : 'rgba(254, 243, 199, 0.7)'};
      display: flex;
      align-items: center;
      justify-content: center;
      position: relative;
      animation: pulseGlow 2.5s infinite ease-in-out;
    }
    @keyframes pulseGlow {
      0%, 100% { transform: scale(1); box-shadow: 0 0 0 0 ${isDanger ? 'rgba(239, 68, 68, 0.2)' : 'rgba(245, 158, 11, 0.2)'}; }
      50% { transform: scale(1.03); box-shadow: 0 0 0 16px rgba(0,0,0,0); }
    }
    .verity-alert-circle {
      width: 150px;
      height: 150px;
      border-radius: 50%;
      background: ${isDanger ? 'linear-gradient(135deg, #EF4444, #DC2626)' : 'linear-gradient(135deg, #F59E0B, #D97706)'};
      display: flex;
      align-items: center;
      justify-content: center;
      color: white;
      font-size: 72px;
      font-weight: 900;
      box-shadow: 0 10px 25px ${isDanger ? 'rgba(220, 38, 38, 0.4)' : 'rgba(217, 119, 6, 0.4)'};
    }
    .verity-card-right {
      flex: 1;
      min-width: 0;
      display: flex;
      flex-direction: column;
      justify-content: center;
    }
    .verity-status {
      margin: 0 0 8px 0;
      font-size: 32px;
      font-weight: 800;
      color: #0F172A;
      letter-spacing: -0.02em;
    }
    .verity-status-highlight { color: ${stateColor}; }
    .verity-url {
      color: #475569;
      font-size: 13px;
      margin-bottom: 20px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      word-break: break-all;
      overflow-wrap: anywhere;
      max-height: 85px;
      overflow-y: auto;
      background: #F8FAFC;
      padding: 10px 14px;
      border-radius: 10px;
      border: 1px solid #E2E8F0;
      display: flex;
      align-items: flex-start;
      gap: 8px;
    }
    .verity-message { font-size: 16px; line-height: 1.6; color: #334155; margin-bottom: 24px; font-weight: 400; }
    .verity-tags { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 32px; }
    .verity-tag {
      background: #F1F5F9;
      color: #334155;
      padding: 8px 14px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
      max-width: 100%;
      word-break: break-word;
      line-height: 1.4;
      border: 1px solid #E2E8F0;
    }
    .verity-actions {
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: 14px;
      margin-bottom: 16px;
    }
    .verity-btn-secondary {
      background: #FFFFFF;
      border: 1.5px solid #CBD5E1;
      color: #475569;
      padding: 12px 24px;
      border-radius: 12px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .verity-btn-secondary:hover {
      background: #F8FAFC;
      color: #0F172A;
      border-color: #94A3B8;
    }
    .verity-btn-primary {
      background: linear-gradient(135deg, #2563EB, #1D4ED8);
      color: white;
      border: none;
      border-radius: 12px;
      padding: 13px 32px;
      font-size: 15px;
      font-weight: 700;
      cursor: pointer;
      box-shadow: 0 4px 14px rgba(37, 99, 235, 0.35);
      transition: all 0.2s ease;
      display: inline-flex;
      align-items: center;
      gap: 8px;
    }
    .verity-btn-primary:hover {
      background: linear-gradient(135deg, #1D4ED8, #1E40AF);
      transform: translateY(-2px);
      box-shadow: 0 6px 20px rgba(37, 99, 235, 0.45);
    }
    .verity-btn-primary:active { transform: translateY(0); }
    .verity-trust-msg { font-size: 12px; color: #94A3B8; text-align: right; margin: 0; }
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
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#2563EB" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
      ${r}
    </span>`
  ).join('');

  const paymentWarning = isPaymentPhishing
    ? `<p style="background:#FFEBEE;border:1px solid #FECDD3;border-radius:10px;padding:12px 16px;color:#BE123C;font-weight:600;margin-bottom:20px;font-size:14px;">
        💳 <strong>Critical Payment Risk:</strong> Do NOT enter any card, UPI, CVV or OTP details on this website.
       </p>`
    : '';

  let redirectChainHtml = '';
  if (verdict.shortenerDetected && verdict.redirectChain && verdict.redirectChain.length > 1) {
    let chainItems = verdict.redirectChain.map((url, i) => {
      let u;
      try { u = new URL(url).hostname; } catch(e) { u = url; }
      return `<div style="padding: 4px 0; font-family: monospace; font-size: 13px;">${i + 1}. ${u}</div>`;
    });
    let formattedChain = chainItems.join('<div style="color: #94A3B8; padding-left: 12px;">↓</div>');
    redirectChainHtml = `
      <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 10px; padding: 16px; margin-bottom: 24px;">
        <div style="font-weight: 700; margin-bottom: 10px; font-size: 13px; color: #475569; letter-spacing: 0.5px;">🔗 REDIRECT CHAIN ANALYSIS</div>
        ${formattedChain}
      </div>
    `;
  }

  container.innerHTML = `
    <div class="verity-header">
      <div class="verity-header-brand">
        <div class="verity-header-logo">V</div>
        <div class="verity-header-title">VERITY <span class="verity-header-pipe">|</span> <span class="verity-header-sub">Web Protection</span></div>
      </div>
      <div class="verity-header-badge">${isDanger ? '🛑 Threat Blocked' : '⚠️ Warning'}</div>
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
          <div class="verity-url">🌐 <span>${window.location.href}</span></div>
          ${paymentWarning}
          ${redirectChainHtml}
          <p class="verity-message">
            ${isPaymentPhishing
              ? 'This website is attempting to impersonate a payment gateway to steal your payment credentials. We strongly recommend you do not proceed.'
              : isDanger
                ? 'This site matches signatures of phishing, scams, malvertising, or credential harvesting. Verity recommends returning to safety.'
                : 'This site exhibits suspicious patterns. Please make sure you trust the domain before proceeding.'}
          </p>

          <div class="verity-tags">
            ${tagsHtml}
            <span class="verity-tag" style="color: ${stateColor}; background: ${isDanger ? '#FFEBEE' : '#FEF3C7'}; border-color: rgba(239,68,68,0.2);">
              Risk Score: ${verdict.score}/100
            </span>
          </div>

          <div class="verity-actions">
            <button class="verity-btn-secondary" id="btn-proceed">⚠️ Visit Anyway</button>
            <button class="verity-btn-primary" id="btn-back">🛡️ Go Back to Safety</button>
          </div>

          <p class="verity-trust-msg">
            Choosing to visit this site will bypass protection for this tab.
          </p>
        </div>
      </div>
    </div>

    <!-- Confirmation View -->
    <div class="verity-card-container" id="confirm-view" style="display: none;">
      <div class="verity-card" style="max-width: 620px; padding: 48px; flex-direction: column; gap: 20px;">
        <h1 class="verity-status" style="font-size: 26px; color: #DC2626;">⚠️ Are you sure you want to proceed?</h1>
        ${isPaymentPhishing ? '<p style="color:#BE123C;font-weight:600;font-size:14px;">💳 Danger: Entering passwords, OTPs, or card details on this site puts your financial account at risk.</p>' : ''}
        <p class="verity-message" style="margin-bottom: 10px; font-size: 15px;">
          This website has been classified as <strong>${stateTitle}</strong>.<br><br>
          Bypassing protection exposes you to potential credential theft, phishing, or malvertising pop-unders.
        </p>
        <div class="verity-actions" style="margin-top: 20px; justify-content: space-between; gap: 12px;">
          <button class="verity-btn-primary" id="btn-confirm-cancel" style="flex: 1;">🛡️ Return to Safety</button>
          <button class="verity-btn-secondary" id="btn-confirm-proceed" style="background: #DC2626; color: white; border: none; font-weight: 700;">Proceed to Unsafe Site</button>
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
    isBlocked = false;
    chrome.runtime.sendMessage({ action: 'USER_OVERRIDE_ALLOW', url: window.location.href }, () => {
      removeOverlay();
      window.location.reload();
    });
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
