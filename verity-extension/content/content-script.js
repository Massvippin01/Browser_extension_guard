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
  if (!input) return '';
  const labelText = (() => {
    try {
      if (input.id && typeof input.id === 'string' && input.id.trim()) {
        const escapedId = typeof CSS !== 'undefined' && CSS.escape ? CSS.escape(input.id) : input.id;
        const lbl = document.querySelector(`label[for="${escapedId}"]`);
        if (lbl) return lbl.innerText || '';
      }
      const parent = input.closest ? input.closest('label') : null;
      return parent ? (parent.innerText || '') : '';
    } catch (e) {
      return '';
    }
  })();
  try {
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
  } catch (e) {
    return '';
  }
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
  ['HDFC Bank', ['hdfc', 'hdfcbank', 'hdfc netbanking', 'hdfc bank']],
  ['SBI', ['sbi', 'onlinesbi', 'sbi yono', 'state bank of india']],
  ['ICICI Bank', ['icici', 'icicibank', 'icici bank', 'icici netbanking']],
  ['PayPal', ['paypal']], ['Stripe', ['stripe']], ['Razorpay', ['razorpay']],
  ['PhonePe', ['phonepe', 'phone pe']], ['Google Pay', ['google pay', 'gpay']],
  ['Paytm', ['paytm']], ['Amazon Pay', ['amazon pay']], ['PayU', ['payu', 'payumoney']],
  ['CCAvenue', ['ccavenue']], ['BillDesk', ['billdesk']], ['Cashfree', ['cashfree']],
  ['Instamojo', ['instamojo']], ['Square', ['squareup']], ['Klarna', ['klarna']],
  ['Apple Pay', ['apple pay']], ['Mastercard', ['mastercard']], ['Visa', ['visa']],
  ['RuPay', ['rupay']], ['BHIM', ['bhim']], ['MobiKwik', ['mobikwik']],
];

let earlyRiskElevated = false;
let spaDebounceTimer = null;
let lastSpaScanTime = 0;
const SPA_MUTATION_THROTTLE_MS = 1500;

function scanClaimedProviders(pageText) {
  if (!pageText) return [];
  return PAYMENT_BRAND_ALIASES
    .filter(([, aliases]) => aliases.some(a => pageText.includes(a)))
    .map(([name]) => name);
}

// 1. Signal Collection (Stage 1) - Gated, Lighter Scan
function collectSignals() {
  const currentHostname = window.location.hostname.toLowerCase().replace(/^www\./, '');

  // Major trusted domains — skip aggressive credential/financial synergy scoring.
  const TRUSTED_DOMAINS = new Set([
    'github.com', 'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'amazon.in',
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
    'epfindia.gov.in', 'onlinesbi.sbi', 'sbi.co.in', 'hdfcbank.com', 'icicibank.com',
    'axisbank.com', 'kotak.com', 'paytm.com', 'phonepe.com', 'razorpay.com', 'indiatimes.com',
    'sbi.bank.in', 'hdfc.bank.in', 'axis.bank.in', 'pnb.bank.in', 'pnbindia.in', 'icici.bank.in', 'kotak.bank.in', 'canarabank.in', 'bobibanking.com'
  ]);

  const isTrustedDomain = TRUSTED_DOMAINS.has(currentHostname) ||
    [...TRUSTED_DOMAINS].some(d => currentHostname.endsWith('.' + d)) ||
    currentHostname.endsWith('.bank.in');

  const hasPasswordInput = document.querySelector('input[type="password"]') !== null;
  const paymentFields    = detectPaymentFields();
  const hasPaymentForm   = detectPaymentForm();
  const allLinks = Array.from(document.querySelectorAll('a[href]'));
  const hasUpiLink = allLinks.some(a => (a.href || '').toLowerCase().startsWith('upi://'));
  const hasPaymentOrOtp  = !!(paymentFields.card || paymentFields.cvv || paymentFields.otp || paymentFields.upi || paymentFields.pin || hasUpiLink);
  const hasSensitiveInputs = hasPasswordInput || hasPaymentOrOtp;



  // GATED SCAN: Only read body text if sensitive inputs exist or URL risk is elevated
  const shouldScanText = hasSensitiveInputs || earlyRiskElevated;
  let text = '';
  if (shouldScanText && document.body) {
    // Length-capped to 20,000 characters to prevent thread stalling on massive DOMs
    text = (document.body.innerText || '').slice(0, 20000).toLowerCase();
  }

  const loginForms = Array.from(document.querySelectorAll('form')).filter(form => {
    return form.querySelector('input[type="password"]') !== null ||
           (form.action && form.action.toLowerCase().includes('login')) ||
           (form.id && form.id.toLowerCase().includes('login'));
  });

  const formActions = loginForms.map(form => form.action).filter(Boolean);

  // Scam heuristics (only evaluated if text was scanned)
  const scamPhrases = ['act now', 'limited time', 'your account will be suspended', 'pay with gift card', 'click here to claim'];
  let scamMatch = text ? scamPhrases.find(p => text.includes(p)) : null;

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
  const financialKeywords = [
    'upi', 'net banking', 'netbanking', 'credit card', 'debit card', 'cvv', 'otp',
    'kyc', 'atm pin', 'mpin', 'bank account', 'account number', 'ifsc',
    'cashback', 'crypto', 'wallet'
  ];
  let financialMatch = (isTrustedDomain || !text) ? [] : financialKeywords.filter(k => text.includes(k));

  // Credential Collection Detection
  const sensitiveInputs = isTrustedDomain ? [] : Array.from(document.querySelectorAll('input')).filter(input => {
    const attr = ((input.name||'') + (input.id||'') + (input.type||'') + (input.placeholder||'')).toLowerCase();
    return attr.includes('password') || attr.includes('cardnumber') || 
           attr.includes('cc-number') || attr.includes('cvv') || 
           attr.includes('cc-csc') || attr.includes('otp') || attr.includes('upi');
  });

  // Extract structural text from title, form actions, and logo elements
  const logoElements = Array.from(document.querySelectorAll('img[alt], [aria-label], [class*="logo"], [id*="logo"]')).slice(0, 20);
  const logoAlts = logoElements.map(el => (el.getAttribute('alt') || el.getAttribute('aria-label') || el.title || '').trim()).filter(Boolean);
  const structuralText = [
    document.title || '',
    ...formActions,
    ...logoAlts
  ].join(' ').toLowerCase();

  // Cross-domain credential exfiltration check (credential form posting to different registered domain)
  let hasCrossDomainCredentialAction = false;
  let exfilTargetDomain = null;
  const currentHost = window.location.hostname.toLowerCase();
  function getBaseDomain(h) {
    if (!h) return '';
    const parts = h.split('.').filter(Boolean);
    if (parts.length <= 2) return h;
    return parts.slice(-2).join('.');
  }
  const pageBaseDomain = getBaseDomain(currentHost);

  for (const form of loginForms) {
    const action = form.getAttribute('action') || form.action;
    if (action && !action.startsWith('#') && !action.startsWith('javascript:')) {
      try {
        const resolved = new URL(action, window.location.href);
        const actionHost = resolved.hostname.toLowerCase();
        if (actionHost && actionHost !== currentHost) {
          const actionBase = getBaseDomain(actionHost);
          if (actionBase && pageBaseDomain && actionBase !== pageBaseDomain) {
            hasCrossDomainCredentialAction = true;
            exfilTargetDomain = actionHost;
            break;
          }
        }
      } catch {}
    }
  }

  // Claimed providers scan (using already-extracted text, no redundant read)
  const claimedProviders = scanClaimedProviders(text);

  return {
    hasPasswordInput: isTrustedDomain ? false : hasPasswordInput,
    loginFormCount: isTrustedDomain ? 0 : loginForms.length,
    formActions,
    structuralText: structuralText.substring(0, 2000),
    hasCrossDomainCredentialAction,
    exfilTargetDomain,
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
    hasUpiLink,
    pageText:  text.substring(0, 3000),
    pageTitle: document.title || '',
  };
}

// 2. Early and Full Scans

function triggerImmediateUrlScan() {
  chrome.runtime.sendMessage({ action: 'ANALYZE_URL_ONLY', url: window.location.href }, (response) => {
    if (chrome.runtime.lastError) return;
    if (response && response.verdict) {
      if (response.verdict.action === 'warn' || response.verdict.action === 'block' || (response.verdict.score || 0) >= 35) {
        earlyRiskElevated = true;
      }
      handleEnforcementVerdict(response.verdict);
    }
  });
}

function triggerFullScan() {
  try {
    const domSignals = collectSignals();
    chrome.runtime.sendMessage({ action: 'ANALYZE_FULL', url: window.location.href, domSignals: domSignals }, (response) => {
      if (chrome.runtime.lastError) return;
      if (response && response.verdict) {
        handleEnforcementVerdict(response.verdict);
      }
    });
  } catch (e) {
    console.error('[Verity] Error in triggerFullScan:', e);
  }
}

// Throttle SPA DOM mutations (1500ms debounce)
function handleSpaDomMutation() {
  const now = Date.now();
  if (now - lastSpaScanTime < SPA_MUTATION_THROTTLE_MS) {
    if (spaDebounceTimer) clearTimeout(spaDebounceTimer);
    spaDebounceTimer = setTimeout(() => {
      lastSpaScanTime = Date.now();
      triggerFullScan();
    }, SPA_MUTATION_THROTTLE_MS);
    return;
  }
  lastSpaScanTime = now;
  triggerFullScan();
}


// ─── Live Status Badge ──────────────────────────────────────────────────────


// ─── Design System & Production UI Implementation ───────────────────────────

const VERITY_UI_CSS = '/**\n * content/verity-ui.css - Production-Grade Shadow DOM Styles for Verity\n * Covers: Warning Overlay Dialog, Download Modal, Popup Toasts, Status Badge.\n * Design language: shadcn/ui, Linear, Vercel — calm, precise, trustworthy.\n */\n\n@font-face {\n  font-family: \'Inter Variable\';\n  font-style: normal;\n  font-weight: 100 900;\n  font-display: swap;\n  src: url(\'/shared/fonts/InterVariable.woff2\') format(\'woff2\');\n}\n\n/* ─── Design Tokens ────────────────────────────────────────────────────────── */\n:host,\n.verity-root,\n[data-theme="light"] {\n  --v-bg: #ffffff;\n  --v-fg: #09090b;\n  --v-card: #ffffff;\n  --v-card-fg: #09090b;\n  --v-muted: #f4f4f5;\n  --v-muted-fg: #52525b; /* 7.03:1 contrast */\n  --v-border: #e4e4e7;\n  --v-input: #e4e4e7;\n  --v-ring: #18181b;\n\n  --v-primary: #18181b;\n  --v-primary-fg: #fafafa;\n  --v-secondary: #f4f4f5;\n  --v-secondary-fg: #18181b;\n\n  --v-destructive: #dc2626;\n  --v-destructive-fg: #ffffff;\n  --v-destructive-subtle: #fef2f2;\n  --v-destructive-border: #fecaca;\n  --v-destructive-text: #991b1b;\n\n  --v-warning: #d97706;\n  --v-warning-fg: #ffffff;\n  --v-warning-subtle: #fffbeb;\n  --v-warning-border: #fde68a;\n  --v-warning-text: #92400e;\n\n  --v-success: #16a34a;\n  --v-success-fg: #ffffff;\n  --v-success-subtle: #f0fdf4;\n  --v-success-border: #bbf7d0;\n  --v-success-text: #166534;\n\n  --v-radius: 0.625rem;\n  --v-radius-sm: 0.375rem;\n  --v-radius-md: 0.5rem;\n  --v-radius-lg: 0.75rem;\n  --v-radius-full: 9999px;\n\n  --v-shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);\n  --v-shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1);\n  --v-shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -4px rgba(0, 0, 0, 0.1);\n  --v-shadow-dialog: 0 25px 50px -12px rgba(0, 0, 0, 0.25), 0 0 0 1px rgba(0, 0, 0, 0.08);\n\n  --v-font: \'Inter Variable\', \'Inter\', -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, \'Noto Sans\', system-ui, sans-serif;\n  --v-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;\n\n  --v-dur-fast: 120ms;\n  --v-dur-base: 200ms;\n  --v-ease-out: cubic-bezier(0.16, 1, 0.3, 1);\n}\n\n@media (prefers-color-scheme: dark) {\n  :host:not([data-theme="light"]),\n  .verity-root:not([data-theme="light"]) {\n    --v-bg: #09090b;\n    --v-fg: #fafafa;\n    --v-card: #121215;\n    --v-card-fg: #fafafa;\n    --v-muted: #27272a;\n    --v-muted-fg: #a1a1aa; /* 5.81:1 contrast */\n    --v-border: #27272a;\n    --v-input: #27272a;\n    --v-ring: #d4d4d8;\n\n    --v-primary: #fafafa;\n    --v-primary-fg: #18181b;\n    --v-secondary: #27272a;\n    --v-secondary-fg: #fafafa;\n\n    --v-destructive: #ef4444;\n    --v-destructive-fg: #09090b;\n    --v-destructive-subtle: rgba(239, 68, 68, 0.12);\n    --v-destructive-border: rgba(239, 68, 68, 0.3);\n    --v-destructive-text: #fca5a5;\n\n    --v-warning: #f59e0b;\n    --v-warning-fg: #09090b;\n    --v-warning-subtle: rgba(245, 158, 11, 0.12);\n    --v-warning-border: rgba(245, 158, 11, 0.3);\n    --v-warning-text: #fde68a;\n\n    --v-success: #22c55e;\n    --v-success-fg: #09090b;\n    --v-success-subtle: rgba(34, 197, 94, 0.12);\n    --v-success-border: rgba(34, 197, 94, 0.3);\n    --v-success-text: #86efac;\n\n    --v-shadow-dialog: 0 25px 50px -12px rgba(0, 0, 0, 0.7), 0 0 0 1px rgba(255, 255, 255, 0.08);\n  }\n}\n\n[data-theme="dark"] {\n  --v-bg: #09090b;\n  --v-fg: #fafafa;\n  --v-card: #121215;\n  --v-card-fg: #fafafa;\n  --v-muted: #27272a;\n  --v-muted-fg: #a1a1aa;\n  --v-border: #27272a;\n  --v-input: #27272a;\n  --v-ring: #d4d4d8;\n\n  --v-primary: #fafafa;\n  --v-primary-fg: #18181b;\n  --v-secondary: #27272a;\n  --v-secondary-fg: #fafafa;\n\n  --v-destructive: #ef4444;\n  --v-destructive-fg: #09090b;\n  --v-destructive-subtle: rgba(239, 68, 68, 0.12);\n  --v-destructive-border: rgba(239, 68, 68, 0.3);\n  --v-destructive-text: #fca5a5;\n\n  --v-warning: #f59e0b;\n  --v-warning-fg: #09090b;\n  --v-warning-subtle: rgba(245, 158, 11, 0.12);\n  --v-warning-border: rgba(245, 158, 11, 0.3);\n  --v-warning-text: #fde68a;\n\n  --v-success: #22c55e;\n  --v-success-fg: #09090b;\n  --v-success-subtle: rgba(34, 197, 94, 0.12);\n  --v-success-border: rgba(34, 197, 94, 0.3);\n  --v-success-text: #86efac;\n\n  --v-shadow-dialog: 0 25px 50px -12px rgba(0, 0, 0, 0.7), 0 0 0 1px rgba(255, 255, 255, 0.08);\n}\n\n/* ─── Host & Global Reset ──────────────────────────────────────────────────── */\n:host {\n  all: initial;\n  display: block;\n  font-family: var(--v-font);\n  font-size: 14px;\n  line-height: 1.5;\n  color: var(--v-fg);\n  -webkit-font-smoothing: antialiased;\n  -moz-osx-font-smoothing: grayscale;\n}\n\n*, *::before, *::after {\n  box-sizing: border-box;\n  margin: 0;\n  padding: 0;\n}\n\n/* ─── Custom Scrollbar (.v-scroll) ─────────────────────────────────────────── */\n.v-scroll {\n  overflow-y: auto;\n  overflow-x: hidden;\n  scrollbar-width: thin;\n  scrollbar-color: var(--v-border) transparent;\n  scrollbar-gutter: stable;\n  overscroll-behavior: contain;\n  transition: scrollbar-color var(--v-dur-base) var(--v-ease-out);\n}\n\n.v-scroll:hover {\n  scrollbar-color: var(--v-muted-fg) transparent;\n}\n\n.v-scroll::-webkit-scrollbar {\n  width: 8px;\n  height: 8px;\n  background: transparent;\n}\n\n.v-scroll::-webkit-scrollbar-track {\n  background: transparent;\n}\n\n.v-scroll::-webkit-scrollbar-thumb {\n  background-color: var(--v-border);\n  background-clip: padding-box;\n  border: 2px solid transparent;\n  border-radius: var(--v-radius-full);\n  transition: background-color var(--v-dur-base) var(--v-ease-out);\n}\n\n.v-scroll:hover::-webkit-scrollbar-thumb,\n.v-scroll:active::-webkit-scrollbar-thumb {\n  background-color: var(--v-muted-fg);\n}\n\n.v-scroll::-webkit-scrollbar-corner {\n  background: transparent;\n}\n\n/* ─── Buttons (.v-btn) ─────────────────────────────────────────────────────── */\n.v-btn {\n  display: inline-flex;\n  align-items: center;\n  justify-content: center;\n  gap: 8px;\n  font-family: inherit;\n  font-size: 13px;\n  font-weight: 500;\n  line-height: 1;\n  white-space: nowrap;\n  border-radius: var(--v-radius-md);\n  border: 1px solid transparent;\n  cursor: pointer;\n  user-select: none;\n  background: transparent;\n  color: var(--v-fg);\n  transition: background-color var(--v-dur-fast) var(--v-ease-out),\n              border-color var(--v-dur-fast) var(--v-ease-out),\n              color var(--v-dur-fast) var(--v-ease-out),\n              box-shadow var(--v-dur-fast) var(--v-ease-out),\n              transform var(--v-dur-fast) var(--v-ease-out);\n}\n\n.v-btn:focus-visible {\n  outline: 2px solid var(--v-ring);\n  outline-offset: 2px;\n}\n\n.v-btn:disabled,\n.v-btn[disabled] {\n  opacity: 0.5;\n  pointer-events: none;\n  cursor: not-allowed;\n}\n\n.v-btn-sm {\n  height: 32px;\n  padding: 0 12px;\n  font-size: 12px;\n}\n\n.v-btn-md {\n  height: 38px;\n  padding: 0 16px;\n  font-size: 13px;\n}\n\n.v-btn-lg {\n  height: 44px;\n  padding: 0 22px;\n  font-size: 14px;\n  font-weight: 600;\n}\n\n.v-btn-primary {\n  background-color: var(--v-primary);\n  color: var(--v-primary-fg);\n  box-shadow: var(--v-shadow-sm);\n}\n.v-btn-primary:hover {\n  opacity: 0.9;\n}\n.v-btn-primary:active {\n  transform: scale(0.98);\n}\n\n.v-btn-secondary {\n  background-color: var(--v-secondary);\n  color: var(--v-secondary-fg);\n}\n.v-btn-secondary:hover {\n  background-color: var(--v-border);\n}\n\n.v-btn-outline {\n  border-color: var(--v-border);\n  background: transparent;\n  color: var(--v-fg);\n}\n.v-btn-outline:hover {\n  background-color: var(--v-muted);\n}\n\n.v-btn-ghost {\n  background: transparent;\n  color: var(--v-muted-fg);\n}\n.v-btn-ghost:hover {\n  background-color: var(--v-muted);\n  color: var(--v-fg);\n}\n\n.v-btn-destructive {\n  background-color: var(--v-destructive);\n  color: var(--v-destructive-fg);\n  box-shadow: var(--v-shadow-sm);\n}\n.v-btn-destructive:hover {\n  opacity: 0.92;\n}\n\n/* ─── Badges / Pills (.v-badge) ────────────────────────────────────────────── */\n.v-badge {\n  display: inline-flex;\n  align-items: center;\n  gap: 6px;\n  padding: 3px 10px;\n  border-radius: var(--v-radius-full);\n  font-size: 12px;\n  font-weight: 600;\n  line-height: 1.3;\n  border: 1px solid transparent;\n  white-space: nowrap;\n}\n.v-badge-safe {\n  background-color: var(--v-success-subtle);\n  color: var(--v-success-text);\n  border-color: var(--v-success-border);\n}\n.v-badge-caution {\n  background-color: var(--v-warning-subtle);\n  color: var(--v-warning-text);\n  border-color: var(--v-warning-border);\n}\n.v-badge-danger {\n  background-color: var(--v-destructive-subtle);\n  color: var(--v-destructive-text);\n  border-color: var(--v-destructive-border);\n}\n\n/* ─── Monospace Chip (.v-chip-mono) ────────────────────────────────────────── */\n.v-chip-mono {\n  display: inline-flex;\n  align-items: center;\n  gap: 6px;\n  font-family: var(--v-mono);\n  font-size: 12px;\n  line-height: 1.4;\n  padding: 4px 10px;\n  border-radius: var(--v-radius-sm);\n  background-color: var(--v-muted);\n  border: 1px solid var(--v-border);\n  color: var(--v-fg);\n  word-break: break-all;\n  max-width: 100%;\n}\n.v-chip-mono-muted {\n  color: var(--v-muted-fg);\n  font-weight: 400;\n}\n.v-chip-mono-emphasis {\n  color: var(--v-fg);\n  font-weight: 700;\n}\n\n/* ─── Fullscreen Backdrop & Centered Dialog ────────────────────────────────── */\n.verity-overlay {\n  position: fixed;\n  inset: 0;\n  width: 100vw;\n  height: 100vh;\n  z-index: 2147483647;\n  display: flex;\n  align-items: center;\n  justify-content: center;\n  padding: 20px;\n  background-color: rgba(9, 9, 11, 0.72);\n  backdrop-filter: blur(12px);\n  -webkit-backdrop-filter: blur(12px);\n  overflow-y: auto;\n  overscroll-behavior: contain;\n}\n\n@supports not (backdrop-filter: blur(12px)) {\n  .verity-overlay {\n    background-color: rgba(9, 9, 11, 0.94);\n  }\n}\n\n.v-dialog-card {\n  position: relative;\n  width: 100%;\n  max-width: 620px;\n  max-height: calc(100vh - 40px);\n  display: flex;\n  flex-direction: column;\n  background-color: var(--v-card);\n  color: var(--v-card-fg);\n  border-radius: var(--v-radius-lg);\n  border: 1px solid var(--v-border);\n  box-shadow: var(--v-shadow-dialog);\n  overflow: hidden;\n  animation: vDialogEnter var(--v-dur-base) var(--v-ease-out) forwards;\n}\n\n.v-card-danger {\n  border-top: 3px solid var(--v-destructive);\n}\n.v-card-warning {\n  border-top: 3px solid var(--v-warning);\n}\n\n.v-dialog-inner {\n  padding: 32px 36px;\n  display: flex;\n  flex-direction: column;\n  overflow-y: auto;\n}\n\n/* Dialog Header Top */\n.v-dialog-header-top {\n  display: flex;\n  align-items: center;\n  justify-content: space-between;\n  margin-bottom: 20px;\n}\n\n.v-icon-badge-wrap {\n  display: flex;\n  align-items: center;\n  gap: 12px;\n}\n\n.v-icon-circle {\n  width: 44px;\n  height: 44px;\n  border-radius: var(--v-radius-full);\n  display: flex;\n  align-items: center;\n  justify-content: center;\n  flex-shrink: 0;\n}\n.v-icon-circle-danger {\n  background-color: var(--v-destructive-subtle);\n  color: var(--v-destructive);\n  border: 1px solid var(--v-destructive-border);\n}\n.v-icon-circle-warning {\n  background-color: var(--v-warning-subtle);\n  color: var(--v-warning);\n  border: 1px solid var(--v-warning-border);\n}\n\n.v-brand-mark {\n  display: flex;\n  align-items: center;\n  gap: 6px;\n  font-size: 11px;\n  font-weight: 600;\n  text-transform: uppercase;\n  letter-spacing: 0.05em;\n  color: var(--v-muted-fg);\n}\n\n/* Dialog Title & Message */\n.v-dialog-title {\n  font-size: 20px;\n  font-weight: 700;\n  line-height: 1.3;\n  color: var(--v-fg);\n  margin-bottom: 8px;\n  letter-spacing: -0.01em;\n}\n\n.verity-status-highlight {\n  font-weight: 700;\n}\n.v-card-danger .verity-status-highlight {\n  color: var(--v-destructive);\n}\n.v-card-warning .verity-status-highlight {\n  color: var(--v-warning);\n}\n\n.verity-message {\n  font-size: 14px;\n  line-height: 1.55;\n  color: var(--v-muted-fg);\n  margin-bottom: 16px;\n}\n\n/* Critical Alerts inside Dialog */\n.v-payment-alert {\n  display: flex;\n  align-items: flex-start;\n  gap: 10px;\n  padding: 12px 14px;\n  border-radius: var(--v-radius-md);\n  background-color: var(--v-destructive-subtle);\n  border: 1px solid var(--v-destructive-border);\n  color: var(--v-destructive-text);\n  font-size: 13px;\n  line-height: 1.45;\n  margin-bottom: 16px;\n}\n.v-payment-alert strong {\n  font-weight: 700;\n}\n\n/* Chain Box */\n.v-chain-box {\n  background-color: var(--v-muted);\n  border: 1px solid var(--v-border);\n  border-radius: var(--v-radius-md);\n  padding: 12px 14px;\n  margin-bottom: 16px;\n  font-size: 12px;\n}\n.v-chain-title {\n  font-weight: 600;\n  color: var(--v-muted-fg);\n  font-size: 11px;\n  text-transform: uppercase;\n  letter-spacing: 0.05em;\n  margin-bottom: 8px;\n}\n.v-chain-item {\n  font-family: var(--v-mono);\n  color: var(--v-fg);\n  padding: 2px 0;\n}\n\n/* Collapsible Accordion */\n.v-accordion-item {\n  border: 1px solid var(--v-border);\n  border-radius: var(--v-radius-md);\n  background-color: var(--v-card);\n  margin-bottom: 24px;\n  overflow: hidden;\n}\n\n.v-accordion-trigger {\n  display: flex;\n  align-items: center;\n  justify-content: space-between;\n  width: 100%;\n  padding: 12px 16px;\n  background: var(--v-muted);\n  border: none;\n  font-family: inherit;\n  font-size: 13px;\n  font-weight: 600;\n  color: var(--v-fg);\n  cursor: pointer;\n  text-align: left;\n  transition: background-color var(--v-dur-fast) var(--v-ease-out);\n}\n.v-accordion-trigger:hover {\n  background-color: var(--v-border);\n}\n.v-accordion-trigger:focus-visible {\n  outline: 2px solid var(--v-ring);\n  outline-offset: -2px;\n}\n\n.v-accordion-icon {\n  transition: transform var(--v-dur-base) var(--v-ease-out);\n  color: var(--v-muted-fg);\n}\n.v-accordion-trigger[aria-expanded="false"] .v-accordion-icon {\n  transform: rotate(-90deg);\n}\n\n.v-accordion-content {\n  padding: 10px 14px;\n  display: flex;\n  flex-direction: column;\n  gap: 8px;\n  max-height: 38vh;\n  transition: max-height var(--v-dur-base) var(--v-ease-out);\n}\n.v-accordion-trigger[aria-expanded="false"] + .v-accordion-content {\n  display: none;\n}\n\n/* Reason Rows (.verity-tag) */\n.verity-tag {\n  display: flex;\n  align-items: center;\n  gap: 10px;\n  padding: 8px 12px;\n  border-radius: var(--v-radius-sm);\n  background-color: var(--v-muted);\n  border: 1px solid var(--v-border);\n  color: var(--v-fg);\n  font-size: 13px;\n  line-height: 1.4;\n  word-break: break-word;\n}\n.v-reason-icon {\n  display: inline-flex;\n  align-items: center;\n  color: var(--v-muted-fg);\n  flex-shrink: 0;\n}\n.v-reason-text {\n  flex: 1;\n}\n.v-reason-dot {\n  width: 6px;\n  height: 6px;\n  border-radius: var(--v-radius-full);\n  flex-shrink: 0;\n}\n.v-dot-danger {\n  background-color: var(--v-destructive);\n}\n.v-dot-warning {\n  background-color: var(--v-warning);\n}\n\n.v-score-tag {\n  font-weight: 600;\n  font-size: 12px;\n  border-color: var(--v-border);\n  background: transparent;\n  color: var(--v-muted-fg);\n  justify-content: flex-end;\n}\n\n/* Action Rows */\n.v-dialog-actions {\n  display: flex;\n  align-items: center;\n  justify-content: flex-end;\n  gap: 12px;\n  margin-top: 4px;\n  margin-bottom: 12px;\n}\n\n.v-dialog-footer {\n  display: flex;\n  align-items: center;\n  justify-content: space-between;\n  padding-top: 14px;\n  border-top: 1px solid var(--v-border);\n  font-size: 11px;\n  color: var(--v-muted-fg);\n}\n.v-footer-brand {\n  display: flex;\n  align-items: center;\n  gap: 5px;\n}\n.v-footer-link {\n  color: var(--v-muted-fg);\n  text-decoration: underline;\n  cursor: pointer;\n  background: none;\n  border: none;\n  font-size: 11px;\n}\n.v-footer-link:hover {\n  color: var(--v-fg);\n}\n\n/* Confirmation View Cooldown Bar */\n.v-cooldown-bar {\n  position: relative;\n  width: 100%;\n  height: 3px;\n  background-color: var(--v-border);\n  border-radius: var(--v-radius-full);\n  overflow: hidden;\n  margin: 12px 0;\n}\n.v-cooldown-progress {\n  position: absolute;\n  top: 0;\n  left: 0;\n  height: 100%;\n  width: 0%;\n  background-color: var(--v-destructive);\n  transition: width 1500ms linear;\n}\n\n/* ─── Download Warning Modal ───────────────────────────────────────────────── */\n#verity-download-warning-host {\n  all: initial;\n  position: fixed;\n  top: 24px;\n  right: 24px;\n  z-index: 2147483645;\n  pointer-events: auto;\n  max-width: 400px;\n  width: calc(100vw - 32px);\n  font-family: var(--v-font);\n}\n\n.v-dw-card {\n  background-color: var(--v-card);\n  color: var(--v-card-fg);\n  border-radius: var(--v-radius-lg);\n  border: 1px solid var(--v-border);\n  box-shadow: var(--v-shadow-dialog);\n  padding: 20px;\n  display: flex;\n  flex-direction: column;\n  gap: 12px;\n  animation: vDialogEnter var(--v-dur-base) var(--v-ease-out) forwards;\n}\n\n.v-dw-header {\n  display: flex;\n  align-items: center;\n  justify-content: space-between;\n}\n\n.v-dw-title-row {\n  display: flex;\n  align-items: center;\n  gap: 10px;\n}\n\n.v-dw-title {\n  font-size: 14px;\n  font-weight: 700;\n  color: var(--v-fg);\n}\n\n.v-dw-meta {\n  display: flex;\n  flex-direction: column;\n  gap: 6px;\n  background-color: var(--v-muted);\n  border: 1px solid var(--v-border);\n  border-radius: var(--v-radius-md);\n  padding: 10px 12px;\n}\n\n.v-dw-row {\n  display: flex;\n  align-items: center;\n  gap: 8px;\n  font-size: 12px;\n}\n.v-dw-label {\n  color: var(--v-muted-fg);\n  width: 52px;\n  flex-shrink: 0;\n}\n\n/* ─── Popup Blocked Toast Stacking ─────────────────────────────────────────── */\n.v-toast-container {\n  position: fixed;\n  bottom: 24px;\n  right: 24px;\n  z-index: 2147483647;\n  display: flex;\n  flex-direction: column-reverse;\n  gap: 8px;\n  pointer-events: none;\n  max-width: 380px;\n  width: calc(100vw - 32px);\n}\n\n@media (max-width: 480px) {\n  .v-toast-container {\n    bottom: 16px;\n    right: 16px;\n    left: 16px;\n    width: auto;\n    align-items: center;\n  }\n}\n\n.v-toast-card {\n  pointer-events: auto;\n  background-color: var(--v-card);\n  color: var(--v-card-fg);\n  border-radius: var(--v-radius-md);\n  border: 1px solid var(--v-border);\n  box-shadow: var(--v-shadow-lg);\n  padding: 12px 14px;\n  display: flex;\n  align-items: center;\n  justify-content: space-between;\n  gap: 12px;\n  font-size: 13px;\n  line-height: 1.4;\n  animation: vDialogEnter var(--v-dur-base) var(--v-ease-out) forwards;\n  transition: transform var(--v-dur-base) var(--v-ease-out), opacity var(--v-dur-base) var(--v-ease-out);\n}\n\n.v-toast-content {\n  display: flex;\n  align-items: center;\n  gap: 10px;\n  min-width: 0;\n}\n.v-toast-icon {\n  color: var(--v-destructive);\n  flex-shrink: 0;\n}\n.v-toast-text {\n  overflow: hidden;\n  text-overflow: ellipsis;\n  white-space: nowrap;\n}\n\n.v-toast-dismiss {\n  border: none;\n  background: transparent;\n  color: var(--v-muted-fg);\n  cursor: pointer;\n  padding: 2px;\n  border-radius: var(--v-radius-sm);\n  display: flex;\n  align-items: center;\n  justify-content: center;\n  transition: color var(--v-dur-fast) var(--v-ease-out);\n}\n.v-toast-dismiss:hover {\n  color: var(--v-fg);\n}\n\n/* ─── Floating Page Status Badge ───────────────────────────────────────────── */\n.verity-badge {\n  width: 28px;\n  height: 28px;\n  border-radius: var(--v-radius-full);\n  background-color: var(--v-muted);\n  border: 1px solid var(--v-border);\n  box-shadow: var(--v-shadow-md);\n  cursor: pointer;\n  position: relative;\n  display: flex;\n  align-items: center;\n  justify-content: center;\n  transition: transform var(--v-dur-fast) var(--v-ease-out), box-shadow var(--v-dur-fast) var(--v-ease-out);\n}\n.verity-badge:hover {\n  transform: scale(1.1);\n}\n\n.verity-badge.safe {\n  background-color: var(--v-success-subtle);\n  border-color: var(--v-success-border);\n  color: var(--v-success-text);\n}\n.verity-badge.caution {\n  background-color: var(--v-warning-subtle);\n  border-color: var(--v-warning-border);\n  color: var(--v-warning-text);\n}\n.verity-badge.danger {\n  background-color: var(--v-destructive-subtle);\n  border-color: var(--v-destructive-border);\n  color: var(--v-destructive-text);\n}\n\n.verity-tooltip {\n  position: absolute;\n  top: 36px;\n  right: 0;\n  background-color: var(--v-primary);\n  color: var(--v-primary-fg);\n  font-family: var(--v-font);\n  font-size: 11px;\n  font-weight: 500;\n  line-height: 1.4;\n  padding: 8px 12px;\n  border-radius: var(--v-radius-sm);\n  white-space: normal;\n  width: 220px;\n  opacity: 0;\n  pointer-events: none;\n  transform: translateY(-4px);\n  transition: opacity var(--v-dur-fast) var(--v-ease-out), transform var(--v-dur-fast) var(--v-ease-out);\n  box-shadow: var(--v-shadow-md);\n  z-index: 50;\n}\n.verity-badge:hover .verity-tooltip {\n  opacity: 1;\n  transform: translateY(0);\n}\n\n/* ─── Responsive Media Queries ─────────────────────────────────────────────── */\n@media (max-width: 640px) {\n  .v-dialog-inner {\n    padding: 24px 20px;\n  }\n  .v-dialog-actions {\n    flex-direction: column-reverse;\n    align-items: stretch;\n  }\n  .v-btn-lg, .v-btn-md {\n    width: 100%;\n    justify-content: center;\n  }\n}\n\n/* ─── Prefers-Reduced-Motion ───────────────────────────────────────────────── */\n@media (prefers-reduced-motion: reduce) {\n  *, *::before, *::after {\n    animation-duration: 0.01ms !important;\n    animation-iteration-count: 1 !important;\n    transition-duration: 0.01ms !important;\n    scroll-behavior: auto !important;\n    transform: none !important;\n  }\n}\n';

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function extractDomainParts(urlString) {
  try {
    const url = new URL(urlString);
    const host = url.hostname.toLowerCase();
    const parts = host.split('.');
    if (parts.length <= 2) {
      return { host, subdomain: '', registeredDomain: host };
    }
    const secondTld = parts[parts.length - 2];
    const isMultiPartTld = ['co', 'gov', 'ac', 'com', 'org', 'net', 'edu'].includes(secondTld) && parts[parts.length - 1].length <= 3;
    const splitIndex = isMultiPartTld ? parts.length - 3 : parts.length - 2;
    if (splitIndex <= 0) {
      return { host, subdomain: '', registeredDomain: host };
    }
    const registeredDomain = parts.slice(splitIndex).join('.');
    const subdomain = parts.slice(0, splitIndex).join('.') + '.';
    return { host, subdomain, registeredDomain };
  } catch (e) {
    return { host: urlString, subdomain: '', registeredDomain: urlString };
  }
}

// ─── Floating Page Status Badge ─────────────────────────────────────────────

function injectStatusBadge() {
  if (window.self !== window.top) return null; // Skip iframes
  if (document.getElementById('verity-status-badge-host')) return null;

  const host = document.createElement('div');
  host.id = 'verity-status-badge-host';
  host.style.cssText = 'position:fixed;top:16px;right:16px;z-index:2147483646;pointer-events:auto;';
  statusBadgeHost = host;

  const shadow = host.attachShadow({ mode: 'open' });

  const styleEl = document.createElement('style');
  styleEl.textContent = VERITY_UI_CSS;
  shadow.appendChild(styleEl);

  const badge = document.createElement('div');
  badge.className = 'verity-badge';
  badge.innerHTML = `
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>
    </svg>
    <div class="verity-tooltip" role="tooltip">
      <div style="font-weight:700;margin-bottom:4px;display:flex;align-items:center;gap:6px;">
        <span>🛡️ VERITY</span>
        <span style="opacity:0.75;">| Security</span>
      </div>
      <div class="v-tooltip-desc">Evaluating page safety…</div>
    </div>
  `;
  shadow.appendChild(badge);

  const parent = document.documentElement || document.body;
  if (parent) parent.appendChild(host);

  return shadow;
}

const badgeShadow = injectStatusBadge();

function updateStatusBadge(verdict) {
  if (!badgeShadow) return;
  const badge = badgeShadow.querySelector('.verity-badge');
  const tooltipDesc = badgeShadow.querySelector('.v-tooltip-desc');
  if (!badge) return;

  const severity = verdict.severity || verdict.state || (verdict.action === 'block' ? 'danger' : (verdict.score >= 35 ? 'caution' : 'safe'));
  const score = verdict.score || verdict.riskScore || 0;

  badge.className = 'verity-badge ' + (severity === 'danger' ? 'danger' : (severity === 'caution' ? 'caution' : 'safe'));

  if (tooltipDesc) {
    if (severity === 'danger') {
      tooltipDesc.innerHTML = `<span style="color:#fca5a5;font-weight:700;">High Risk Detected</span><br>Risk Score: ${score}/100`;
    } else if (severity === 'caution') {
      tooltipDesc.innerHTML = `<span style="color:#fde68a;font-weight:700;">Suspicious Patterns Found</span><br>Risk Score: ${score}/100`;
    } else {
      tooltipDesc.innerHTML = `<span style="color:#86efac;font-weight:700;">Clean Reputation</span><br>Risk Score: ${score}/100`;
    }
  }
}

// ─── Popup Blocked Toast Stacking ───────────────────────────────────────────
let activeToasts = [];
let toastHostEl = null;

function ensureToastContainer() {
  if (toastHostEl && toastHostEl.isConnected) {
    return toastHostEl.shadowRoot.querySelector('.v-toast-container');
  }
  let host = document.getElementById('verity-toast-host');
  if (!host) {
    host = document.createElement('div');
    host.id = 'verity-toast-host';
    host.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:2147483647;pointer-events:none;';
    (document.documentElement || document.body).appendChild(host);
  }
  const shadow = host.attachShadow ? (host.shadowRoot || host.attachShadow({ mode: 'open' })) : host;
  if (!shadow.querySelector('style')) {
    const st = document.createElement('style');
    st.textContent = VERITY_UI_CSS;
    shadow.appendChild(st);
  }
  let container = shadow.querySelector('.v-toast-container');
  if (!container) {
    container = document.createElement('div');
    container.className = 'v-toast-container';
    container.setAttribute('aria-live', 'polite');
    container.id = 'verity-popup-toast-box';
    shadow.appendChild(container);
  }
  toastHostEl = host;
  return container;
}

function showPopupBlockedToast(hostname) {
  const container = ensureToastContainer();
  if (!container) return;

  // Max 3 toasts: remove oldest if limit reached
  while (activeToasts.length >= 3) {
    const oldest = activeToasts.shift();
    if (oldest && oldest.element) oldest.element.remove();
  }

  const toastCard = document.createElement('div');
  toastCard.className = 'v-toast-card';
  toastCard.innerHTML = `
    <div class="v-toast-content">
      <div class="v-toast-icon">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="m4.93 4.93 14.14 14.14"/></svg>
      </div>
      <div class="v-toast-text">
        <strong>Blocked pop-up:</strong> <span class="v-toast-host">${escapeHtml(hostname || 'Untrusted origin')}</span>
      </div>
    </div>
    <button type="button" class="v-toast-dismiss" aria-label="Dismiss">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
    </button>
  `;

  let remainingMs = 6000;
  let dismissTimer = null;
  let startTime = Date.now();

  function startTimer() {
    startTime = Date.now();
    dismissTimer = setTimeout(dismissToast, remainingMs);
  }

  function pauseTimer() {
    clearTimeout(dismissTimer);
    remainingMs -= (Date.now() - startTime);
    if (remainingMs < 500) remainingMs = 500;
  }

  function dismissToast() {
    clearTimeout(dismissTimer);
    toastCard.style.opacity = '0';
    toastCard.style.transform = 'translateY(6px)';
    setTimeout(() => {
      toastCard.remove();
      activeToasts = activeToasts.filter(t => t.element !== toastCard);
    }, 120);
  }

  toastCard.addEventListener('mouseenter', pauseTimer);
  toastCard.addEventListener('mouseleave', startTimer);
  toastCard.addEventListener('focusin', pauseTimer);
  toastCard.addEventListener('focusout', startTimer);

  toastCard.querySelector('.v-toast-dismiss')?.addEventListener('click', dismissToast);

  container.appendChild(toastCard);
  activeToasts.push({ element: toastCard, dismiss: dismissToast });
  startTimer();
}

function handleEnforcementVerdict(verdict) {
  if (!verdict) return;
  try { window.__verityLastVerdict = verdict; } catch (e) {}
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

// ─── Listeners from Background ──────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'POPUP_BLOCKED_TOAST') {
    showPopupBlockedToast(message.hostname || message.blockedUrl);
  } else if (message.action === 'ENFORCEMENT_DECISION') {
    handleEnforcementVerdict(message.decision.verdict);
  } else if (message.action === 'RE_ANALYZE') {
    isBlocked = false;
    removeOverlay();
    if (statusBadgeHost) statusBadgeHost.style.display = 'block';
    triggerImmediateUrlScan();
    setTimeout(triggerFullScan, 500);
  } else if (message.action === 'DOWNLOAD_VERDICT') {
    injectDownloadWarning(message.payload);
  } else if (message.action === 'OVERLAY_PREVIEW') {
    injectOverlay(message.verdict);
  }
});

triggerImmediateUrlScan();

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', triggerFullScan);
} else {
  triggerFullScan();
}

// ─── Download Warning Modal ─────────────────────────────────────────────────
let downloadWarningHost = null;

function injectDownloadWarning(payload) {
  removeDownloadWarning();

  const { filename, sourceHostname, signals, riskScore, severity, action, cancelled, chromeSaysDangerous } = payload;
  const isDanger = severity === 'danger' || action === 'block';

  const host = document.createElement('div');
  host.id = 'verity-download-warning-host';
  host.style.cssText = 'all:initial;position:fixed;top:24px;right:24px;z-index:2147483645;pointer-events:auto;max-width:400px;width:calc(100vw - 32px);';
  downloadWarningHost = host;

  const shadow = host.attachShadow({ mode: 'open' });

  const styleEl = document.createElement('style');
  styleEl.textContent = VERITY_UI_CSS;
  shadow.appendChild(styleEl);

  const card = document.createElement('div');
  card.className = `v-dw-card ${isDanger ? 'v-card-danger' : 'v-card-warning'}`;
  card.innerHTML = `
    <div class="v-dw-header">
      <div class="v-dw-title-row">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="${isDanger ? '#ef4444' : '#f59e0b'}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/></svg>
        <span class="v-dw-title">${isDanger ? (chromeSaysDangerous ? 'Dangerous File Blocked' : 'High-Risk Download Blocked') : 'Suspicious Download Detected'}</span>
      </div>
      <span class="v-badge ${isDanger ? 'v-badge-danger' : 'v-badge-caution'}">${isDanger ? 'Blocked' : 'Warning'}</span>
    </div>

    <div class="v-dw-meta">
      <div class="v-dw-row">
        <span class="v-dw-label">File:</span>
        <span class="v-chip-mono">${escapeHtml(filename || 'Unknown')}</span>
      </div>
      <div class="v-dw-row">
        <span class="v-dw-label">Source:</span>
        <span class="v-chip-mono">${escapeHtml(sourceHostname || 'Unknown')}</span>
      </div>
    </div>

    ${signals && signals.length > 0 ? `
      <div class="v-scroll" style="max-height: 120px; display: flex; flex-direction: column; gap: 6px;">
        ${signals.map(s => `
          <div class="verity-tag" style="padding: 6px 10px; font-size: 12px;">
            <span class="v-reason-icon"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg></span>
            <span class="v-reason-text">${escapeHtml(String(s))}</span>
          </div>
        `).join('')}
      </div>
    ` : ''}

    <div style="display:flex;justify-content:space-between;align-items:center;font-size:12px;color:var(--v-muted-fg);padding-top:4px;">
      <span>Evaluation score:</span>
      <span style="font-weight:700;color:${isDanger ? 'var(--v-destructive)' : 'var(--v-warning)'};">${riskScore || 0}/100</span>
    </div>

    ${cancelled ? '<div class="v-payment-alert" style="margin-bottom:0;padding:8px 12px;font-size:12px;">Download cancelled automatically by Verity.</div>' : ''}

    <div class="v-dialog-actions" style="margin-bottom:0;margin-top:6px;">
      ${!cancelled ? '<button type="button" class="v-btn v-btn-ghost v-btn-sm" id="dw-open-dl">View downloads</button>' : ''}
      <button type="button" class="v-btn v-btn-primary v-btn-sm" id="dw-dismiss">Dismiss</button>
    </div>
  `;

  shadow.appendChild(card);

  shadow.getElementById('dw-dismiss')?.addEventListener('click', removeDownloadWarning);
  shadow.getElementById('dw-open-dl')?.addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'OPEN_DOWNLOADS_PAGE' });
  });

  (document.documentElement || document.body).appendChild(host);

  // Auto-dismiss warn after 15s; danger stays until dismissed
  if (!isDanger) setTimeout(removeDownloadWarning, 15000);
}

function removeDownloadWarning() {
  if (downloadWarningHost) {
    downloadWarningHost.remove();
    downloadWarningHost = null;
  }
}

// ─── Warning Overlay Enforcement ────────────────────────────────────────────
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
  try { window.onbeforeunload = null; } catch (e) {}
}

function injectOverlay(verdict) {
  if (document.getElementById('verity-security-host')) {
    return; // Already blocked
  }

  // Halt active redirects and page loading
  try { window.stop(); } catch (e) {}
  try {
    let maxId = window.setTimeout(() => {}, 0);
    for (let i = 0; i <= maxId; i++) {
      window.clearTimeout(i);
      window.clearInterval(i);
    }
  } catch (e) {}
  try {
    document.querySelectorAll('meta[http-equiv="refresh"]').forEach(el => el.remove());
  } catch (e) {}
  try {
    window.onbeforeunload = function() {
      return "Navigation blocked by Verity Web Protection.";
    };
  } catch (e) {}

  // Lock scroll
  if (document.documentElement) {
    document.documentElement.style.setProperty('overflow', 'hidden', 'important');
  }
  if (document.body) {
    document.body.style.setProperty('overflow', 'hidden', 'important');
  }

  const host = document.createElement('div');
  host.id = 'verity-security-host';
  host.style.setProperty('all', 'initial', 'important');
  host.style.setProperty('position', 'fixed', 'important');
  host.style.setProperty('top', '0', 'important');
  host.style.setProperty('left', '0', 'important');
  host.style.setProperty('width', '100vw', 'important');
  host.style.setProperty('height', '100vh', 'important');
  host.style.setProperty('z-index', '2147483647', 'important');
  host.style.setProperty('pointer-events', 'auto', 'important');

  const isDanger = verdict.severity !== 'caution' && (verdict.action === 'block' || verdict.severity === 'danger');
  const isPaymentPhishing = !!(verdict.paymentAnalysis && verdict.paymentAnalysis.isCriticalPaymentPhishing);
  const stateTitle = isPaymentPhishing ? 'Payment Phishing Blocked' : (isDanger ? 'Dangerous' : 'Suspicious');

  host.dataset.action = verdict.action;
  host.dataset.score = String(verdict.score || verdict.riskScore || 0);
  host.dataset.stateTitle = stateTitle;

  const shadow = host.attachShadow({ mode: 'open' });

  const styleEl = document.createElement('style');
  styleEl.textContent = VERITY_UI_CSS;
  shadow.appendChild(styleEl);

  const overlayWrap = document.createElement('div');
  overlayWrap.className = 'verity-overlay';
  overlayWrap.setAttribute('role', 'alertdialog');
  overlayWrap.setAttribute('aria-modal', 'true');
  overlayWrap.setAttribute('aria-labelledby', 'verity-dialog-title');
  overlayWrap.setAttribute('aria-describedby', 'verity-dialog-desc');

  // Theme Sync
  chrome.storage.local.get(['theme'], (res) => {
    if (res && res.theme && res.theme !== 'system') {
      overlayWrap.setAttribute('data-theme', res.theme);
    }
  });

  const domainParts = extractDomainParts(window.location.href);

  const allReasons = (verdict.signals && verdict.signals.length > 0)
    ? verdict.signals.map(s => {
        if (s.id && typeof t === 'function') {
          return t(s.id, s.params);
        }
        return s.reason || s.id;
      })
    : [
        ...(verdict.reasons || []),
        ...(verdict.paymentAnalysis ? verdict.paymentAnalysis.reasons : []),
      ].filter(Boolean);

  const reasonsList = allReasons.length > 0 ? allReasons : ['Suspicious threat pattern detected'];

  overlayWrap.innerHTML = `
    <!-- Main View Dialog Card -->
    <div class="v-dialog-card ${isDanger ? 'v-card-danger' : 'v-card-warning'}" id="main-view">
      <div class="v-dialog-inner">
        <div class="v-dialog-header-top">
          <div class="v-icon-badge-wrap">
            <div class="v-icon-circle ${isDanger ? 'v-icon-circle-danger' : 'v-icon-circle-warning'}">
              ${isDanger
                ? '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m14.5 9.5-5 5"/><path d="m9.5 9.5 5 5"/></svg>'
                : '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>'
              }
            </div>
            <span class="verity-header-badge v-badge ${isDanger ? 'v-badge-danger' : 'v-badge-caution'}">
              ${isDanger ? '🛑 Threat Blocked' : '⚠️ Warning'}
            </span>
          </div>
          <div class="v-brand-mark">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/></svg>
            <span>VERITY</span>
          </div>
        </div>

        <h1 class="v-dialog-title" id="verity-dialog-title">
          Website status: <span class="verity-status-highlight">${escapeHtml(stateTitle)}</span>
        </h1>

        <p class="verity-message" id="verity-dialog-desc">
          ${isPaymentPhishing
            ? 'This website is attempting to impersonate a financial institution to steal your payment credentials.'
            : isDanger
              ? 'This website matches verified signatures of phishing, brand impersonation, or credential harvesting.'
              : 'This website exhibits unusual or unverified patterns. Verify the domain before proceeding.'}
        </p>

        <div class="v-chip-mono" style="margin-bottom: 20px;">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="color:var(--v-muted-fg);flex-shrink:0;" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/></svg>
          <span class="v-chip-mono-muted">${escapeHtml(domainParts.subdomain)}</span>
          <span class="v-chip-mono-emphasis">${escapeHtml(domainParts.registeredDomain)}</span>
          <span id="verity-url-display" style="display:none;">${escapeHtml(window.location.href)}</span>
        </div>

        <div id="verity-payment-warning-container"></div>
        <div id="verity-chain-container"></div>

        <div class="v-accordion-item">
          <button type="button" class="v-accordion-trigger" id="v-accordion-btn" aria-expanded="true">
            <span>Why we flagged this (${reasonsList.length})</span>
            <svg class="v-accordion-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>
          </button>
          <div class="v-accordion-content v-scroll" id="verity-tags-container"></div>
        </div>

        <div class="v-dialog-actions">
          <button type="button" class="v-btn v-btn-ghost v-btn-md" id="btn-proceed">Continue anyway</button>
          <button type="button" class="v-btn v-btn-primary v-btn-lg" id="btn-back">Take me to safety</button>
        </div>

        <div class="v-dialog-footer">
          <span class="v-footer-brand">Protected by VERITY Web Protection</span>
          <button type="button" class="v-footer-link" id="btn-report-site">Report an issue</button>
        </div>
      </div>
    </div>

    <!-- Confirmation View Dialog Card -->
    <div class="v-dialog-card v-card-danger" id="confirm-view" style="display: none; max-width: 540px;">
      <div class="v-dialog-inner">
        <div class="v-dialog-header-top">
          <div class="v-icon-badge-wrap">
            <div class="v-icon-circle v-icon-circle-danger">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>
            </div>
            <span class="v-badge v-badge-danger">High Risk Confirmation</span>
          </div>
        </div>

        <h2 class="v-dialog-title" style="color: var(--v-destructive);">Are you sure you want to proceed?</h2>
        <p class="verity-message">
          This site is classified as <strong id="verity-confirm-state">${escapeHtml(stateTitle)}</strong>.
          Bypassing protection exposes you to potential credential theft, phishing, or financial risk.
        </p>

        <div class="v-cooldown-bar"><div class="v-cooldown-progress" id="v-cooldown-fill"></div></div>

        <div class="v-dialog-actions" style="margin-top: 16px;">
          <button type="button" class="v-btn v-btn-outline v-btn-md" id="btn-confirm-cancel">Return to safety</button>
          <button type="button" class="v-btn v-btn-destructive v-btn-md" id="btn-confirm-proceed" disabled>Please wait (1.5s)...</button>
        </div>
      </div>
    </div>
  `;

  // Populate dynamic payment warning if present
  if (isPaymentPhishing) {
    const pwContainer = overlayWrap.querySelector('#verity-payment-warning-container');
    if (pwContainer) {
      pwContainer.innerHTML = `
        <div class="v-payment-alert">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;" aria-hidden="true"><rect width="20" height="14" x="2" y="5" rx="2"/><line x1="2" x2="22" y1="10" y2="10"/></svg>
          <div><strong>Critical Payment Risk:</strong> Do not enter any passwords, card numbers, UPI PINs, or OTPs on this page.</div>
        </div>
      `;
    }
  }

  // Populate redirect chain if present
  if (verdict.shortenerDetected && verdict.redirectChain && verdict.redirectChain.length > 1) {
    const chainContainer = overlayWrap.querySelector('#verity-chain-container');
    if (chainContainer) {
      const chainItems = verdict.redirectChain.map((u, i) => {
        let h;
        try { h = new URL(u).hostname; } catch(e) { h = u; }
        return `<div class="v-chain-item">${i + 1}. ${escapeHtml(h)}</div>`;
      }).join('<div style="color:var(--v-muted-fg);padding-left:8px;font-size:10px;">↓</div>');
      chainContainer.innerHTML = `
        <div class="v-chain-box">
          <div class="v-chain-title">Redirect Chain Analysis</div>
          ${chainItems}
        </div>
      `;
    }
  }

  // Populate reasons list inside accordion
  const tagsContainer = overlayWrap.querySelector('#verity-tags-container');
  if (tagsContainer) {
    for (const r of reasonsList) {
      const tagRow = document.createElement('div');
      tagRow.className = 'verity-tag';
      tagRow.innerHTML = `
        <span class="v-reason-icon">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
        </span>
        <span class="v-reason-text">${escapeHtml(String(r))}</span>
        <span class="v-reason-dot ${isDanger ? 'v-dot-danger' : 'v-dot-warning'}"></span>
      `;
      tagsContainer.appendChild(tagRow);
    }
    const scorePill = document.createElement('div');
    scorePill.className = 'verity-tag v-score-tag';
    scorePill.textContent = `Risk Score: ${verdict.score || 0}/100`;
    tagsContainer.appendChild(scorePill);
  }

  shadow.appendChild(overlayWrap);

  // Accordion Toggle Behavior
  const accordionBtn = shadow.querySelector('#v-accordion-btn');
  if (accordionBtn) {
    accordionBtn.addEventListener('click', () => {
      const expanded = accordionBtn.getAttribute('aria-expanded') === 'true';
      accordionBtn.setAttribute('aria-expanded', String(!expanded));
    });
  }

  // Navigation and Buttons
  const mainView = shadow.querySelector('#main-view');
  const confirmView = shadow.querySelector('#confirm-view');
  const cooldownFill = shadow.querySelector('#v-cooldown-fill');
  const btnConfirmProceed = shadow.querySelector('#btn-confirm-proceed');

  shadow.querySelector('#btn-back')?.addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'chrome://newtab/';
    }
  });

  shadow.querySelector('#btn-proceed')?.addEventListener('click', () => {
    if (isDanger) {
      mainView.style.display = 'none';
      confirmView.style.display = 'flex';
      shadow.querySelector('#btn-confirm-cancel')?.focus();

      // 1.5s Cooldown with Progress Sweep
      if (cooldownFill && btnConfirmProceed) {
        btnConfirmProceed.disabled = true;
        btnConfirmProceed.textContent = 'Please wait (1.5s)...';
        cooldownFill.style.width = '0%';
        requestAnimationFrame(() => {
          cooldownFill.style.width = '100%';
        });
        setTimeout(() => {
          btnConfirmProceed.disabled = false;
          btnConfirmProceed.textContent = 'Confirm, I understand the risk';
        }, 1500);
      }
    } else {
      // Direct caution override
      isBlocked = false;
      removeOverlay();
    }
  });

  shadow.querySelector('#btn-confirm-cancel')?.addEventListener('click', () => {
    confirmView.style.display = 'none';
    mainView.style.display = 'flex';
    shadow.querySelector('#btn-back')?.focus();
  });

  shadow.querySelector('#btn-confirm-proceed')?.addEventListener('click', () => {
    isBlocked = false;
    chrome.runtime.sendMessage({ action: 'USER_OVERRIDE_ALLOW', url: window.location.href }, () => {
      removeOverlay();
      window.location.reload();
    });
  });

  // Focus trap & Esc handling
  overlayWrap.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (isDanger) {
        // Block verdict does NOT dismiss on Esc
        e.preventDefault();
        shadow.querySelector('#btn-back')?.focus();
      } else {
        removeOverlay();
      }
    }
    if (e.key === 'Tab') {
      const activeCard = confirmView.style.display === 'flex' ? confirmView : mainView;
      const focusables = Array.from(activeCard.querySelectorAll('button:not([disabled]), [tabindex="0"]'));
      if (focusables.length === 0) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      if (e.shiftKey && shadow.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && shadow.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  });

  const parent = document.documentElement || document.body;
  if (parent) {
    parent.appendChild(host);
  }

  // Auto-focus primary safe action
  setTimeout(() => {
    shadow.querySelector('#btn-back')?.focus();
  }, 50);

  // Re-attachment Observer against hostile host pages
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
