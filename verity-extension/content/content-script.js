/**
 * content-script.js - Injected into all pages at document_start.
 * Responsible for initiating early URL scans, collecting DOM signals, and enforcing blocks.
 */

let isBlocked = false;
let blockObserver = null;
let statusBadgeHost = null;

// ─── Deep DOM & Shadow DOM Traversal ─────────────────────────────────────────

/**
 * Traverses standard DOM nodes and recursively pierces any open shadowRoot.
 * Guarantees discovery of form inputs, passwords, and payment fields inside Web Components.
 *
 * @param {string} selector - CSS selector
 * @param {Document|Element|ShadowRoot} [root=document] - Root node to query from
 * @returns {Element[]} Array of unique matched elements
 */
function querySelectorAllDeep(selector, root = (typeof document !== 'undefined' ? document : null)) {
  const resultSet = new Set();
  if (!root || typeof root.querySelectorAll !== 'function') return [];

  const visitedRoots = new WeakSet();

  function traverse(currentRoot) {
    if (!currentRoot || typeof currentRoot.querySelectorAll !== 'function' || visitedRoots.has(currentRoot)) {
      return;
    }
    visitedRoots.add(currentRoot);

    try {
      // 1. Direct matches within currentRoot
      const matches = currentRoot.querySelectorAll(selector);
      for (let i = 0; i < matches.length; i++) {
        resultSet.add(matches[i]);
      }

      // 2. If currentRoot has a shadowRoot directly attached
      if (currentRoot.shadowRoot && !visitedRoots.has(currentRoot.shadowRoot)) {
        traverse(currentRoot.shadowRoot);
      }

      // 3. Inspect descendants for open shadow roots
      const descendants = currentRoot.querySelectorAll('*');
      for (let i = 0; i < descendants.length; i++) {
        const desc = descendants[i];
        if (desc && desc.shadowRoot && !visitedRoots.has(desc.shadowRoot)) {
          traverse(desc.shadowRoot);
        }
      }
    } catch (_) {}
  }

  traverse(root);
  return Array.from(resultSet);
}

/**
 * Returns first matching element searching across light DOM and open shadow roots.
 */
function querySelectorDeep(selector, root = (typeof document !== 'undefined' ? document : null)) {
  const all = querySelectorAllDeep(selector, root);
  return all.length > 0 ? all[0] : null;
}

// ─── ClickFix & Fake Verification Attack Analyzer ─────────────────────────────

/**
 * Extracts visible page text including text inside open shadow roots.
 */
function getPageTextDeep(maxLength = 25000) {
  let combined = '';
  if (typeof document !== 'undefined' && document.body) {
    combined += (document.body.innerText || document.body.textContent || '') + ' ';
  }
  try {
    if (typeof document !== 'undefined') {
      const all = document.querySelectorAll('*');
      for (let i = 0; i < all.length; i++) {
        const el = all[i];
        if (el && el.shadowRoot) {
          combined += (el.shadowRoot.textContent || '') + ' ';
          if (combined.length > maxLength * 2) break;
        }
      }
    }
  } catch (_) {}

  return combined.slice(0, maxLength);
}

/**
 * Detects "ClickFix" fake human verification / browser check pages tricking users
 * into running malicious PowerShell / mshta commands via Win + R and Ctrl + V.
 *
 * @param {string} [customText] - Optional text to analyze instead of current DOM text
 * @returns {{ detected: boolean, lure: string|null, prompt: string|null, reason: string|null }}
 */
function detectClickFixAndFakeVerification(customText = null) {
  const rawText = customText !== null ? customText : getPageTextDeep();
  if (!rawText || typeof rawText !== 'string' || rawText.length < 10) {
    return { detected: false, lure: null, prompt: null, reason: null };
  }

  const text = rawText.toLowerCase();

  // Execution & clipboard lures
  const lures = [
    'win + r', 'win+r', 'windows key + r', 'windows + r',
    'ctrl + v', 'ctrl+v', 'powershell', 'mshta',
    'paste in run', 'paste into run', 'run box', 'press windows',
    'cmd.exe', 'powershell.exe'
  ];

  // Fake verification prompts
  const prompts = [
    'verify you are human', 'confirm you are human', 'verify that you are human',
    'browser check', 'cloudflare', 'i am not a robot', "i'm not a robot",
    'press allow to continue', 'click allow to continue', 'turn on notifications to verify',
    'human verification', 'robot verification', 'security check to proceed',
    'verify your browser', 'checking your browser'
  ];

  const matchedLure = lures.find(l => text.includes(l));
  const matchedPrompt = prompts.find(p => text.includes(p));

  if (matchedLure && matchedPrompt) {
    return {
      detected: true,
      lure: matchedLure,
      prompt: matchedPrompt,
      reason: `ClickFix lure detected: "${matchedLure}" combined with fake verification "${matchedPrompt}".`
    };
  }

  return { detected: false, lure: null, prompt: null, reason: null };
}

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
        const lbl = querySelectorDeep(`label[for="${escapedId}"]`);
        if (lbl) return lbl.innerText || lbl.textContent || '';
      }
      const parent = input.closest ? input.closest('label') : null;
      return parent ? (parent.innerText || parent.textContent || '') : '';
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
  const inputs = querySelectorAllDeep('input');
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
  return querySelectorAllDeep('form').some(form => {
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

function scanClaimedProviders(pageText) {
  if (!pageText) return [];
  return PAYMENT_BRAND_ALIASES
    .filter(([, aliases]) => aliases.some(a => pageText.includes(a)))
    .map(([name]) => name);
}


// ─── Cyber Fraud & Exfiltration Detection Helpers ───────────────────────────

function detectIllegalWebPinCollection() {
  const inputs = querySelectorAllDeep('input');
  const pinPattern = /(upi\s*pin|enter\s*mpin|atm\s*pin|transaction\s*pin|gpay\s*pin|phonepe\s*pin|paytm\s*pin|\bupi\s*code\b)/i;
  for (const input of inputs) {
    const meta = getInputMeta(input);
    if (pinPattern.test(meta)) {
      return { detected: true, phrase: meta.match(pinPattern)?.[0] || 'UPI PIN' };
    }
    const type = (input.type || '').toLowerCase();
    if (type === 'password' || type === 'number' || type === 'tel' || type === 'text') {
      const container = input.closest ? input.closest('div, form, p, section, li') : null;
      if (container) {
        const textSnippet = (container.innerText || container.textContent || '').slice(0, 300);
        if (pinPattern.test(textSnippet)) {
          return { detected: true, phrase: textSnippet.match(pinPattern)?.[0] || 'UPI PIN' };
        }
      }
    }
  }
  return { detected: false, phrase: null };
}

function detectUnverifiedUpiAndQr(currentHostname) {
  const allLinks = querySelectorAllDeep('a[href]');
  const hasUpiLink = allLinks.some(a => (a.href || '').toLowerCase().startsWith('upi://'));

  const qrElements = querySelectorAllDeep('img[src*="qr"], img[alt*="qr"], canvas, [class*="qr-code"], [id*="qr-code"], [class*="qrcode"], [id*="qrcode"]');
  const hasQr = qrElements.length > 0;

  const pageText = getPageTextDeep(10000);
  const vpaRegex = /[a-zA-Z0-9.\-_]{2,256}@(ybl|okhdfcbank|okaxis|okicici|paytm|ibl|upi|apl|axl|barodampay|idbi|kotak|pnb|federal|rbl|indus|yesbank)/i;
  const hasVpa = vpaRegex.test(pageText) || (allLinks.some(a => vpaRegex.test(a.href || '')));

  return {
    hasUpiLink,
    hasQr,
    hasVpa,
    detected: hasUpiLink || (hasVpa && (hasQr || pageText.toLowerCase().includes('upi') || pageText.toLowerCase().includes('scan to pay')))
  };
}

function detectKycAndAadhaarPanFraud(text) {
  if (!text) return { detected: false, phrase: null };
  const lowerText = text.toLowerCase();

  const urgencyPhrases = [
    'account will be blocked', 'account will be suspended', 'account blocked',
    'kyc suspended', 'kyc pending', 'update kyc', 'complete your kyc',
    'electricity disconnected', 'electricity connection', 'electricity connection will be disconnected',
    'pan card deactivated', 'pan card suspended', 'pan linked',
    'redeem reward points', 'income tax refund', 'customs parcel halted',
    'digital arrest', 'sim will be blocked', 'sim disconnected', 'cbi notice'
  ];
  const matchedUrgency = urgencyPhrases.find(p => lowerText.includes(p));

  const inputs = querySelectorAllDeep('input');
  let hasKycInput = false;
  let kycInputType = '';

  for (const input of inputs) {
    const meta = getInputMeta(input);
    const pattern = input.getAttribute('pattern') || '';
    if (/(pan\s*(card|no|number)|permanent\s*account\s*number)/i.test(meta) || /\[A-Z\]\{5\}/i.test(pattern) || /pancard|pan_no/i.test(meta)) {
      hasKycInput = true;
      kycInputType = 'PAN Number';
      break;
    }
    if (/(aadhaar|aadhar|uidai)\s*(no|number|card)?/i.test(meta) || /aadhaar|aadhar/i.test(meta)) {
      hasKycInput = true;
      kycInputType = 'Aadhaar Number';
      break;
    }
    if (/(customer\s*id|cif\s*(no|number)?|cust\s*id|client\s*id)/i.test(meta)) {
      hasKycInput = true;
      kycInputType = 'Customer/CIF ID';
      break;
    }
    if (/(limit\s*increase|credit\s*limit|reward\s*points\s*redeem|redeem\s*points)/i.test(meta)) {
      hasKycInput = true;
      kycInputType = 'Reward Points / Credit Limit';
      break;
    }
  }

  const hasKycInText = lowerText.includes('pan card') || lowerText.includes('aadhaar') || lowerText.includes('kyc update') || lowerText.includes('cif number');

  if (matchedUrgency && (hasKycInput || hasKycInText)) {
    return {
      detected: true,
      phrase: `${matchedUrgency}${kycInputType ? ` (${kycInputType})` : ''}`
    };
  }

  return { detected: false, phrase: null };
}

function detectPhishingKitWebhookExfil(hasSensitiveInputs) {
  if (!hasSensitiveInputs) return { detected: false, endpoint: null };

  const endpoints = [
    'api.telegram.org/bot',
    'discord.com/api/webhooks',
    'discordapp.com/api/webhooks',
    'script.google.com/macros/s/',
    'formspree.io',
    'getform.io',
    'webhook.site',
    'pipedream.net',
    'ngrok-free.app',
    'trycloudflare.com'
  ];

  const scripts = (typeof document !== 'undefined' && document.scripts) ? document.scripts : [];
  for (let i = 0; i < scripts.length; i++) {
    const s = (scripts[i].innerText || scripts[i].textContent || '').toLowerCase();
    const matched = endpoints.find(ep => s.includes(ep));
    if (matched) {
      return { detected: true, endpoint: matched };
    }
  }

  const forms = querySelectorAllDeep('form');
  for (const form of forms) {
    const action = ((form.getAttribute('action') || form.action || '')).toLowerCase();
    const matched = endpoints.find(ep => action.includes(ep));
    if (matched) {
      return { detected: true, endpoint: matched };
    }
  }

  const interactive = querySelectorAllDeep('[onsubmit], [onclick]');
  for (const el of interactive) {
    const handler = ((el.getAttribute('onsubmit') || '') + ' ' + (el.getAttribute('onclick') || '')).toLowerCase();
    const matched = endpoints.find(ep => handler.includes(ep));
    if (matched) {
      return { detected: true, endpoint: matched };
    }
  }

  return { detected: false, endpoint: null };
}

function detectHighPressureTimer(hasPaymentOrOtp) {
  if (!hasPaymentOrOtp) return false;
  const pageText = getPageTextDeep(6000);
  const timerRegex = /(\b0?[0-9]:[0-5][0-9]\b)\s*(remaining|left|expires|valid for|timeout)/i;
  if (timerRegex.test(pageText)) return true;

  const timerElements = querySelectorAllDeep('[id*="timer"], [class*="timer"], [id*="countdown"], [class*="countdown"], [id*="otp-timer"], [class*="otp-timer"], [id*="expires"], [class*="expires"]');
  return timerElements.length > 0;
}

function detectBitbFakeWindowAttack() {
  if (typeof window === 'undefined' || !window.location) return { detected: false };
  const currentHost = (window.location.hostname || '').toLowerCase().replace(/^www\./, '');

  const officialIdpDomains = [
    'accounts.google.com',
    'login.microsoftonline.com',
    'login.live.com',
    'appleid.apple.com',
    'github.com',
    'api.twitter.com',
    'twitter.com',
    'x.com'
  ];

  if (officialIdpDomains.some(d => currentHost === d || currentHost.endsWith('.' + d))) {
    return { detected: false };
  }

  const candidateElements = querySelectorAllDeep('div, span, p, a, b, strong, section, header, [role="dialog"], [class*="modal" i], [class*="popup" i], [class*="window" i]');
  const fakeUrlRegex = /https?:\/\/(accounts\.google\.com|login\.microsoftonline\.com|login\.live\.com|appleid\.apple\.com|github\.com\/login|api\.twitter\.com)[^\s"'>]*/i;

  let matchedFakeUrl = null;
  for (const el of candidateElements) {
    if (el.children && el.children.length > 8) continue;
    const txt = (el.innerText || el.textContent || '').trim();
    if (!txt || txt.length > 250) continue;
    const match = txt.match(fakeUrlRegex);
    if (match) {
      matchedFakeUrl = match[0];
      break;
    }
  }

  if (!matchedFakeUrl) {
    const fakeInputs = querySelectorAllDeep('input[readonly], input[disabled], [role="textbox"][aria-readonly="true"]');
    for (const inp of fakeInputs) {
      const val = (inp.value || inp.getAttribute('value') || '').trim();
      const match = val.match(fakeUrlRegex);
      if (match) {
        matchedFakeUrl = match[0];
        break;
      }
    }
  }

  if (!matchedFakeUrl) return { detected: false };

  const hasAuthInput = querySelectorDeep('input[type="password"], input[type="email"], input[name*="user" i], input[name*="login" i], input[name*="email" i], input[id*="email" i], input[id*="password" i]') !== null;
  const pageText = getPageTextDeep(6000).toLowerCase();
  const hasWindowChromeText = pageText.includes('sign in - google accounts') ||
                              pageText.includes('sign in to your account') ||
                              pageText.includes('microsoft — official home page') ||
                              pageText.includes('sign in with apple') ||
                              pageText.includes('sign in to github');

  if (hasAuthInput || hasWindowChromeText) {
    return {
      detected: true,
      fakeUrl: matchedFakeUrl,
      reason: `Browser-in-the-Browser fake address bar "${matchedFakeUrl}" rendered on unverified domain "${currentHost}"`
    };
  }

  return { detected: false };
}

function detectAitmReverseProxyDom() {
  if (typeof window === 'undefined' || !window.location) return { detected: false };
  const currentHost = (window.location.hostname || '').toLowerCase().replace(/^www\./, '');

  const officialIdpDomains = [
    'microsoft.com',
    'microsoftonline.com',
    'live.com',
    'google.com',
    'okta.com',
    'windowsazure.com',
    'office.com'
  ];

  if (officialIdpDomains.some(d => currentHost === d || currentHost.endsWith('.' + d))) {
    return { detected: false };
  }

  const proprietarySelectors = [
    'input[name="loginfmt"]',
    'input[name="otc"]',
    'input#i0116',
    'input#i0118',
    'input#identifierId'
  ];

  for (const sel of proprietarySelectors) {
    const el = querySelectorDeep(sel);
    if (el) {
      return {
        detected: true,
        selector: sel,
        reason: `Proprietary identity provider input "${sel}" detected on non-official domain "${currentHost}"`
      };
    }
  }

  return { detected: false };
}

function inspectQrPayload(rawValue, currentHost) {
  if (!rawValue || typeof rawValue !== 'string') return null;
  const lower = rawValue.trim().toLowerCase();

  if (lower.startsWith('upi://pay')) {
    return {
      detected: true,
      type: 'Unverified UPI Payment Deep-Link QR Code',
      rawValue
    };
  }

  if (lower.startsWith('http://') || lower.startsWith('https://')) {
    try {
      const parsed = new URL(rawValue);
      const qrHost = parsed.hostname.toLowerCase();
      const suspTlds = ['.xyz', '.monster', '.top', '.click', '.sbs', '.cfd', '.icu', '.live', '.buzz', '.pw'];
      const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(qrHost);
      const isSuspTld = suspTlds.some(tld => qrHost.endsWith(tld));

      if (isIp || isSuspTld || qrHost.includes('login') || qrHost.includes('verify') || qrHost.includes('update')) {
        return {
          detected: true,
          type: 'Suspicious / Phishing URL QR Code',
          rawValue
        };
      }
    } catch (_) {}
  }

  return null;
}

function detectQrFromDomAttributes() {
  const currentHost = (typeof window !== 'undefined' && window.location ? window.location.hostname : '').toLowerCase().replace(/^www\./, '');
  if (typeof globalThis !== 'undefined' && globalThis.__VERITY_TEST_QR_PAYLOAD__) {
    const testResult = inspectQrPayload(globalThis.__VERITY_TEST_QR_PAYLOAD__, currentHost);
    if (testResult) return testResult;
  }

  const qrElements = querySelectorAllDeep('[data-qr], [data-payload], img[alt*="qr" i], [class*="qr" i], [id*="qr" i]');
  for (const el of qrElements) {
    const rawValue = el.getAttribute('data-qr') || el.getAttribute('data-payload') || el.getAttribute('alt') || '';
    const result = inspectQrPayload(rawValue, currentHost);
    if (result) return result;
  }
  return null;
}

async function scanQrCodesOnPage() {
  if (typeof window === 'undefined') return null;
  const currentHost = (window.location.hostname || '').toLowerCase().replace(/^www\./, '');

  const attrResult = detectQrFromDomAttributes();
  if (attrResult) return attrResult;

  if ('BarcodeDetector' in window) {
    try {
      const detector = new window.BarcodeDetector({ formats: ['qr_code'] });
      const candidates = querySelectorAllDeep('img, canvas');
      const scanCandidates = [];
      for (const el of candidates) {
        const rect = el.getBoundingClientRect ? el.getBoundingClientRect() : { width: el.width || 0, height: el.height || 0 };
        const w = rect.width;
        const h = rect.height;
        if (w >= 80 && w <= 600 && h >= 80 && h <= 600) {
          scanCandidates.push(el);
          if (scanCandidates.length >= 5) break;
        }
      }

      for (const target of scanCandidates) {
        try {
          const barcodes = await detector.detect(target);
          for (const bc of barcodes) {
            const result = inspectQrPayload(bc.rawValue, currentHost);
            if (result) return result;
          }
        } catch (_) {}
      }
    } catch (_) {}
  }

  return null;
}

function extractBrandAssetUrls() {
  const urls = [];
  if (typeof document === 'undefined') return urls;
  try {
    const iconLinks = querySelectorAllDeep('link[rel*="icon" i], link[rel*="apple-touch-icon" i]');
    for (const link of iconLinks) {
      const href = link.getAttribute('href') || link.href;
      if (href && !href.startsWith('data:') && !href.startsWith('blob:')) {
        urls.push(href);
      }
    }
    const ogImages = querySelectorAllDeep('meta[property="og:image" i], meta[name="og:image" i], meta[property="twitter:image" i], meta[name="twitter:image" i]');
    for (const meta of ogImages) {
      const content = meta.getAttribute('content');
      if (content && !content.startsWith('data:') && !content.startsWith('blob:')) {
        urls.push(content);
      }
    }
    const imgs = querySelectorAllDeep('header img, nav img, form img, img[class*="logo" i], img[id*="logo" i], img[alt*="logo" i]');
    for (const img of imgs.slice(0, 15)) {
      const src = img.getAttribute('src') || img.src;
      if (src && !src.startsWith('data:') && !src.startsWith('blob:')) {
        urls.push(src);
      }
    }
  } catch (_) {}
  return urls;
}

function detectTechSupportRemoteScam(text) {
  if (!text) return { detected: false };
  const lower = text.toLowerCase();

  const remoteTools = ['anydesk', 'rustdesk', 'teamviewer', 'ultraviewer', 'quickassist', 'screenconnect', 'supremo', 'ammyy'];
  const matchedTool = remoteTools.find(tool => lower.includes(tool));
  if (!matchedTool) return { detected: false };

  const lureKeywords = [
    'customer care', 'helpline', 'toll free', 'toll-free', 'support number',
    'support executive', 'helpdesk', 'kyc verification', 'kyc update',
    'bank account blocked', 'electricity bill', 'call now', 'quick support',
    'refund department', 'income tax refund', 'digital arrest', 'police officer'
  ];
  const matchedLure = lureKeywords.find(lure => lower.includes(lure));
  if (!matchedLure) return { detected: false };

  return {
    detected: true,
    tool: matchedTool,
    lure: matchedLure,
    reason: `Prompting installation of remote access tool "${matchedTool}" alongside "${matchedLure}" lure`
  };
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

  const hasPasswordInput = querySelectorDeep('input[type="password"]') !== null;
  const paymentFields    = detectPaymentFields();
  const hasPaymentForm   = detectPaymentForm();
  const allLinks         = querySelectorAllDeep('a[href]');
  const hasUpiLink       = allLinks.some(a => (a.href || '').toLowerCase().startsWith('upi://'));
  const hasPaymentOrOtp  = !!(paymentFields.card || paymentFields.cvv || paymentFields.expiry || paymentFields.upi || paymentFields.otp || paymentFields.pin || hasUpiLink);
  const hasSensitiveInputs = hasPasswordInput || hasPaymentOrOtp;

  // Always read page text when body exists to scan for ClickFix, scam lures, and financial context
  let text = '';
  if (typeof document !== 'undefined' && document.body) {
    text = getPageTextDeep();
  }

  // ClickFix analysis
  const clickFix = detectClickFixAndFakeVerification(text);

  const loginForms = querySelectorAllDeep('form').filter(form => {
    return querySelectorDeep('input[type="password"]', form) !== null ||
           (form.action && form.action.toLowerCase().includes('login')) ||
           (form.id && form.id.toLowerCase().includes('login'));
  });

  const formActions = loginForms.map(form => form.action).filter(Boolean);

  // Scam heuristics
  const scamPhrases = [
    'act now', 'limited time', 'your account will be suspended', 'pay with gift card', 'click here to claim',
    'wait! your bonus is ready', 'your personal link is ready', 'stay & claim bonus', 'spin the wheel',
    'you have won', 'download is ready', 'claim bonus', 'claim reward'
  ];
  let scamMatch = text ? scamPhrases.find(p => text.includes(p)) : null;

  const bonusLurePhrases = [
    'wait! your bonus is ready', 'your personal link is ready', 'stay & claim bonus',
    'spin the wheel', 'you have won', 'download is ready'
  ];
  let bonusLureMatch = text ? bonusLurePhrases.find(p => text.includes(p)) : null;

  // PUP heuristics
  let pupMatch = null;
  const scripts = (typeof document !== 'undefined' && document.scripts) ? document.scripts : [];
  for (let i = 0; i < scripts.length; i++) {
    const s = scripts[i].innerText || scripts[i].textContent || '';
    if (s.includes('eval(') && s.includes('unescape(')) {
      pupMatch = 'Obfuscated inline script detected';
      break;
    }
  }

  if (querySelectorAllDeep('iframe[style*="opacity: 0"], iframe[style*="display: none"]').length > 3) {
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
  const sensitiveInputs = isTrustedDomain ? [] : querySelectorAllDeep('input').filter(input => {
    const attr = ((input.name||'') + (input.id||'') + (input.type||'') + (input.placeholder||'')).toLowerCase();
    return attr.includes('password') || attr.includes('cardnumber') || 
           attr.includes('cc-number') || attr.includes('cvv') || 
           attr.includes('cc-csc') || attr.includes('otp') || attr.includes('upi');
  });

  // Extract structural text from title, form actions, and logo elements
  const logoElements = querySelectorAllDeep('img[alt], [aria-label], [class*="logo"], [id*="logo"]').slice(0, 20);
  const logoAlts = logoElements.map(el => (el.getAttribute('alt') || el.getAttribute('aria-label') || el.title || '').trim()).filter(Boolean);
  const structuralText = [
    (typeof document !== 'undefined' ? document.title : '') || '',
    ...formActions,
    ...logoAlts
  ].join(' ').toLowerCase();

  // Cross-domain credential exfiltration check (credential form posting to different registered domain)
  let hasCrossDomainCredentialAction = false;
  let exfilTargetDomain = null;
  const currentHost = typeof window !== 'undefined' ? window.location.hostname.toLowerCase() : '';
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
        const resolved = new URL(action, typeof window !== 'undefined' ? window.location.href : 'http://localhost');
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

  // Brand Asset URLs for hotlinking / favicon spoof detection
  const brandAssetUrls = extractBrandAssetUrls();

  // Tech support / remote desktop scam detection
  const techSupportScam = detectTechSupportRemoteScam(text);

  // Browser-in-the-Browser fake window attack
  const bitb = detectBitbFakeWindowAttack();

  // AiTM reverse-proxy DOM signatures
  const aitmDom = detectAitmReverseProxyDom();

  // On-device QR / Quishing scan
  const qrScan = detectQrFromDomAttributes();

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
    scamBonusLure: !!bonusLureMatch,
    scamBonusLurePhrase: bonusLureMatch,
    pup: !!pupMatch,
    pupReason: pupMatch,
    financialMatches: financialMatch,
    hasCredentialCollection: sensitiveInputs.length > 0,
    isTrustedDomain,
    // ClickFix fake verification detection
    clickFixAttack: isTrustedDomain ? false : clickFix.detected,
    clickFixReason: isTrustedDomain ? null : clickFix.reason,
    clickFixLure: isTrustedDomain ? null : clickFix.lure,
    clickFixPrompt: isTrustedDomain ? null : clickFix.prompt,
    // Payment Protection signals
    paymentFields: isTrustedDomain ? {} : paymentFields,
    hasPaymentForm: isTrustedDomain ? false : hasPaymentForm,
    claimedProviders,
    brandAssetUrls,
    techSupportRemoteScam: isTrustedDomain ? false : techSupportScam.detected,
    techSupportRemoteScamReason: isTrustedDomain ? null : techSupportScam.reason,
    techSupportHelpline: isTrustedDomain ? null : (techSupportScam.tool + ' ' + techSupportScam.lure),
    bitbAttack: isTrustedDomain ? false : bitb.detected,
    bitbTarget: isTrustedDomain ? null : bitb.fakeUrl,
    bitbReason: isTrustedDomain ? null : bitb.reason,
    aitmReverseProxy: isTrustedDomain ? false : aitmDom.detected,
    aitmReason: isTrustedDomain ? null : aitmDom.reason,
    maliciousQrPayload: isTrustedDomain ? false : (qrScan ? qrScan.detected : false),
    maliciousQrType: isTrustedDomain ? null : (qrScan ? qrScan.type : null),
    hasUpiLink,
    pageText:  text.substring(0, 3000),
    pageTitle: (typeof document !== 'undefined' ? document.title : '') || '',
  };
}

// 2. Early and Full Scans

function triggerImmediateUrlScan() {
  if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) return;
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
  if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) return;
  try {
    lastKnownSensitiveSignature = getSensitiveDomSignature();
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

// ─── Debounced SPA MutationObserver (350ms) ──────────────────────────────────
let spaMutationObserver = null;
let spaDebounceTimer = null;
let lastKnownSensitiveSignature = '';

/**
 * Computes a fingerprint of all sensitive DOM fields, payment inputs, iframes, and ClickFix state.
 * Used to avoid redundant re-scans if mutations did not affect sensitive nodes.
 */
function getSensitiveDomSignature() {
  const inputs = querySelectorAllDeep('input');
  const forms = querySelectorAllDeep('form');
  const iframes = querySelectorAllDeep('iframe');
  const hasPassword = querySelectorDeep('input[type="password"]') !== null;
  const pf = detectPaymentFields();
  const paymentFieldSum = (pf.card ? 1 : 0) + (pf.cvv ? 2 : 0) + (pf.expiry ? 4 : 0) +
                          (pf.upi ? 8 : 0) + (pf.otp ? 16 : 0) + (pf.pin ? 32 : 0) +
                          (pf.accountNumber ? 64 : 0);
  const clickFix = detectClickFixAndFakeVerification();
  return `${inputs.length}:${forms.length}:${iframes.length}:${hasPassword}:${paymentFieldSum}:${clickFix.detected}`;
}

/**
 * Checks if a mutation added any <form>, <input>, or <iframe> elements.
 */
function hasRelevantAddedNodes(mutation) {
  if (mutation.type !== 'childList' || !mutation.addedNodes) return false;
  for (let i = 0; i < mutation.addedNodes.length; i++) {
    const node = mutation.addedNodes[i];
    if (node && node.nodeType === 1) { // Node.ELEMENT_NODE
      const tag = (node.tagName || '').toLowerCase();
      if (tag === 'form' || tag === 'input' || tag === 'iframe') {
        return true;
      }
      if (node.querySelector && node.querySelector('form, input, iframe')) {
        return true;
      }
      if (node.shadowRoot && node.shadowRoot.querySelector && node.shadowRoot.querySelector('form, input, iframe')) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Initializes a debounced (350ms) MutationObserver on document.documentElement.
 * Watches childList and subtree for dynamically mounted sensitive form, input, or iframe elements (SPAs).
 */
function initSpaMutationObserver() {
  if (typeof MutationObserver === 'undefined' || typeof document === 'undefined') return;
  const target = document.documentElement || document.body;
  if (!target) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', initSpaMutationObserver, { once: true });
    }
    return;
  }

  if (spaMutationObserver) return; // Already watching

  lastKnownSensitiveSignature = getSensitiveDomSignature();

  spaMutationObserver = new MutationObserver((mutations) => {
    if (isBlocked) return;

    let relevantChange = false;
    for (let i = 0; i < mutations.length; i++) {
      if (hasRelevantAddedNodes(mutations[i])) {
        relevantChange = true;
        break;
      }
    }

    if (relevantChange) {
      if (spaDebounceTimer) clearTimeout(spaDebounceTimer);
      spaDebounceTimer = setTimeout(() => {
        if (isBlocked) return;
        const currentSig = getSensitiveDomSignature();
        if (currentSig !== lastKnownSensitiveSignature) {
          lastKnownSensitiveSignature = currentSig;
          triggerFullScan();
        }
      }, 350);
    }
  });

  try {
    spaMutationObserver.observe(target, {
      childList: true,
      subtree: true
    });
  } catch (e) {
    console.error('[Verity] Failed to attach SPA MutationObserver:', e);
  }
}


// ─── Live Status Badge ──────────────────────────────────────────────────────


// ─── Verity Custom Font Loader (CSP-Safe ArrayBuffer Injection) ──────────────

let verityFontLoadPromise = null;
function ensureVerityFontLoaded() {
  if (typeof document === 'undefined' || !('fonts' in document)) {
    return Promise.resolve();
  }
  try {
    if (document.fonts.check('16px VerityInter')) {
      return Promise.resolve();
    }
  } catch (e) {}
  if (verityFontLoadPromise) {
    return verityFontLoadPromise;
  }
  verityFontLoadPromise = (async () => {
    try {
      const fontUrl = (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL)
        ? chrome.runtime.getURL('shared/fonts/InterVariable.woff2')
        : '/shared/fonts/InterVariable.woff2';
      const res = await fetch(fontUrl);
      if (!res.ok) return;
      const buffer = await res.arrayBuffer();
      const fontFace = new FontFace('VerityInter', buffer, {
        weight: '100 900',
        style: 'normal',
        display: 'swap'
      });
      const loadedFace = await fontFace.load();
      document.fonts.add(loadedFace);
    } catch (e) {
      // Font load error fallback gracefully
    }
  })();
  return verityFontLoadPromise;
}

if (typeof document !== 'undefined') {
  ensureVerityFontLoaded().catch(() => {});
}

// ─── Design System & Production UI Implementation ───────────────────────────

const VERITY_UI_CSS = `/**
 * content/verity-ui.css - Production-Grade Shadow DOM Styles for Verity
 * Covers: Warning Overlay Dialog, Download Modal, Popup Toasts, Status Badge.
 * Design language: shadcn/ui, Linear, Vercel — calm, precise, trustworthy.
 */

/* ─── Design Tokens ────────────────────────────────────────────────────────── */
:host,
.verity-root,
[data-theme="light"] {
  --v-bg: #ffffff;
  --v-fg: #09090b;
  --v-card: #ffffff;
  --v-card-fg: #09090b;
  --v-muted: #f4f4f5;
  --v-muted-fg: #52525b; /* 7.03:1 contrast */
  --v-border: #e4e4e7;
  --v-input: #e4e4e7;
  --v-ring: #18181b;

  --v-primary: #18181b;
  --v-primary-fg: #fafafa;
  --v-secondary: #f4f4f5;
  --v-secondary-fg: #18181b;

  --v-destructive: #dc2626;
  --v-destructive-fg: #ffffff;
  --v-destructive-subtle: #fef2f2;
  --v-destructive-border: #fecaca;
  --v-destructive-text: #991b1b;

  --v-warning: #d97706;
  --v-warning-fg: #ffffff;
  --v-warning-subtle: #fffbeb;
  --v-warning-border: #fde68a;
  --v-warning-text: #92400e;

  --v-success: #16a34a;
  --v-success-fg: #ffffff;
  --v-success-subtle: #f0fdf4;
  --v-success-border: #bbf7d0;
  --v-success-text: #166534;

  --v-radius: 0.625rem;
  --v-radius-sm: 0.375rem;
  --v-radius-md: 0.5rem;
  --v-radius-lg: 0.75rem;
  --v-radius-full: 9999px;

  --v-shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
  --v-shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1);
  --v-shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -4px rgba(0, 0, 0, 0.1);
  --v-shadow-dialog: 0 25px 50px -12px rgba(0, 0, 0, 0.25), 0 0 0 1px rgba(0, 0, 0, 0.08);

  --v-font: "VerityInter", system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans", sans-serif;
  --v-mono: ui-monospace, "SF Mono", "Cascadia Mono", Consolas, monospace;

  --v-dur-fast: 120ms;
  --v-dur-base: 200ms;
  --v-ease-out: cubic-bezier(0.16, 1, 0.3, 1);
}

@media (prefers-color-scheme: dark) {
  :host:not([data-theme="light"]),
  .verity-root:not([data-theme="light"]) {
    --v-bg: #09090b;
    --v-fg: #fafafa;
    --v-card: #121215;
    --v-card-fg: #fafafa;
    --v-muted: #27272a;
    --v-muted-fg: #a1a1aa; /* 5.81:1 contrast */
    --v-border: #27272a;
    --v-input: #27272a;
    --v-ring: #d4d4d8;

    --v-primary: #fafafa;
    --v-primary-fg: #18181b;
    --v-secondary: #27272a;
    --v-secondary-fg: #fafafa;

    --v-destructive: #ef4444;
    --v-destructive-fg: #09090b;
    --v-destructive-subtle: rgba(239, 68, 68, 0.12);
    --v-destructive-border: rgba(239, 68, 68, 0.3);
    --v-destructive-text: #fca5a5;

    --v-warning: #f59e0b;
    --v-warning-fg: #09090b;
    --v-warning-subtle: rgba(245, 158, 11, 0.12);
    --v-warning-border: rgba(245, 158, 11, 0.3);
    --v-warning-text: #fde68a;

    --v-success: #22c55e;
    --v-success-fg: #09090b;
    --v-success-subtle: rgba(34, 197, 94, 0.12);
    --v-success-border: rgba(34, 197, 94, 0.3);
    --v-success-text: #86efac;

    --v-shadow-dialog: 0 25px 50px -12px rgba(0, 0, 0, 0.7), 0 0 0 1px rgba(255, 255, 255, 0.08);
  }
}

[data-theme="dark"] {
  --v-bg: #09090b;
  --v-fg: #fafafa;
  --v-card: #121215;
  --v-card-fg: #fafafa;
  --v-muted: #27272a;
  --v-muted-fg: #a1a1aa;
  --v-border: #27272a;
  --v-input: #27272a;
  --v-ring: #d4d4d8;

  --v-primary: #fafafa;
  --v-primary-fg: #18181b;
  --v-secondary: #27272a;
  --v-secondary-fg: #fafafa;

  --v-destructive: #ef4444;
  --v-destructive-fg: #09090b;
  --v-destructive-subtle: rgba(239, 68, 68, 0.12);
  --v-destructive-border: rgba(239, 68, 68, 0.3);
  --v-destructive-text: #fca5a5;

  --v-warning: #f59e0b;
  --v-warning-fg: #09090b;
  --v-warning-subtle: rgba(245, 158, 11, 0.12);
  --v-warning-border: rgba(245, 158, 11, 0.3);
  --v-warning-text: #fde68a;

  --v-success: #22c55e;
  --v-success-fg: #09090b;
  --v-success-subtle: rgba(34, 197, 94, 0.12);
  --v-success-border: rgba(34, 197, 94, 0.3);
  --v-success-text: #86efac;

  --v-shadow-dialog: 0 25px 50px -12px rgba(0, 0, 0, 0.7), 0 0 0 1px rgba(255, 255, 255, 0.08);
}

/* ─── Host & Global Reset ──────────────────────────────────────────────────── */
:host {
  all: initial;
  display: block;
  font-family: var(--v-font);
  font-size: 14px;
  line-height: 1.5;
  color: var(--v-fg);
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

*, *::before, *::after {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
  font-family: inherit;
}

/* ─── Custom Scrollbar (.v-scroll) ─────────────────────────────────────────── */
.v-scroll {
  overflow-y: auto;
  overflow-x: hidden;
  scrollbar-width: thin;
  scrollbar-color: var(--v-border) transparent;
  scrollbar-gutter: stable;
  overscroll-behavior: contain;
  transition: scrollbar-color var(--v-dur-base) var(--v-ease-out);
}

.v-scroll:hover {
  scrollbar-color: var(--v-muted-fg) transparent;
}

.v-scroll::-webkit-scrollbar {
  width: 8px;
  height: 8px;
  background: transparent;
}

.v-scroll::-webkit-scrollbar-track {
  background: transparent;
}

.v-scroll::-webkit-scrollbar-thumb {
  background-color: var(--v-border);
  background-clip: padding-box;
  border: 2px solid transparent;
  border-radius: var(--v-radius-full);
  transition: background-color var(--v-dur-base) var(--v-ease-out);
}

.v-scroll:hover::-webkit-scrollbar-thumb,
.v-scroll:active::-webkit-scrollbar-thumb {
  background-color: var(--v-muted-fg);
}

.v-scroll::-webkit-scrollbar-corner {
  background: transparent;
}

/* ─── Buttons (.v-btn) ─────────────────────────────────────────────────────── */
.v-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  font-family: inherit;
  font-size: 13px;
  font-weight: 500;
  line-height: 1;
  white-space: nowrap;
  border-radius: var(--v-radius-md);
  border: 1px solid transparent;
  cursor: pointer;
  user-select: none;
  background: transparent;
  color: var(--v-fg);
  transition: background-color var(--v-dur-fast) var(--v-ease-out),
              border-color var(--v-dur-fast) var(--v-ease-out),
              color var(--v-dur-fast) var(--v-ease-out),
              box-shadow var(--v-dur-fast) var(--v-ease-out),
              transform var(--v-dur-fast) var(--v-ease-out);
}

.v-btn:focus-visible {
  outline: 2px solid var(--v-ring);
  outline-offset: 2px;
}

.v-btn:disabled,
.v-btn[disabled] {
  opacity: 0.5;
  pointer-events: none;
  cursor: not-allowed;
}

.v-btn-sm {
  height: 32px;
  padding: 0 12px;
  font-size: 12px;
}

.v-btn-md {
  height: 38px;
  padding: 0 16px;
  font-size: 13px;
}

.v-btn-lg {
  height: 44px;
  padding: 0 22px;
  font-size: 14px;
  font-weight: 600;
}

.v-btn-primary {
  background-color: var(--v-primary);
  color: var(--v-primary-fg);
  box-shadow: var(--v-shadow-sm);
}
.v-btn-primary:hover {
  opacity: 0.9;
}
.v-btn-primary:active {
  transform: scale(0.98);
}

.v-btn-secondary {
  background-color: var(--v-secondary);
  color: var(--v-secondary-fg);
}
.v-btn-secondary:hover {
  background-color: var(--v-border);
}

.v-btn-outline {
  border-color: var(--v-border);
  background: transparent;
  color: var(--v-fg);
}
.v-btn-outline:hover {
  background-color: var(--v-muted);
}

.v-btn-ghost {
  background: transparent;
  color: var(--v-muted-fg);
}
.v-btn-ghost:hover {
  background-color: var(--v-muted);
  color: var(--v-fg);
}

.v-btn-destructive {
  background-color: var(--v-destructive);
  color: var(--v-destructive-fg);
  box-shadow: var(--v-shadow-sm);
}
.v-btn-destructive:hover {
  opacity: 0.92;
}

/* ─── Badges / Pills (.v-badge) ────────────────────────────────────────────── */
.v-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 3px 10px;
  border-radius: var(--v-radius-full);
  font-size: 12px;
  font-weight: 600;
  line-height: 1.3;
  border: 1px solid transparent;
  white-space: nowrap;
}
.v-badge-safe {
  background-color: var(--v-success-subtle);
  color: var(--v-success-text);
  border-color: var(--v-success-border);
}
.v-badge-caution {
  background-color: var(--v-warning-subtle);
  color: var(--v-warning-text);
  border-color: var(--v-warning-border);
}
.v-badge-danger {
  background-color: var(--v-destructive-subtle);
  color: var(--v-destructive-text);
  border-color: var(--v-destructive-border);
}

/* ─── Monospace Chip (.v-chip-mono) ────────────────────────────────────────── */
.v-chip-mono {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-family: var(--v-mono);
  font-size: 12px;
  line-height: 1.4;
  padding: 4px 10px;
  border-radius: var(--v-radius-sm);
  background-color: var(--v-muted);
  border: 1px solid var(--v-border);
  color: var(--v-fg);
  word-break: break-all;
  overflow-wrap: anywhere;
  max-width: 100%;
}
.v-chip-mono-muted,
.v-chip-mono-subdomain,
.v-chip-mono-path {
  color: var(--v-muted-fg);
  font-weight: 400;
}
.v-chip-mono-emphasis,
.v-chip-mono-registered {
  color: var(--v-fg);
  font-weight: 600;
}

/* ─── Fullscreen Backdrop & Centered Dialog ────────────────────────────────── */
.verity-overlay {
  position: fixed;
  inset: 0;
  width: 100vw;
  height: 100vh;
  z-index: 2147483647;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
  background-color: rgba(9, 9, 11, 0.72);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  overflow-y: auto;
  overscroll-behavior: contain;
  font-family: var(--v-font);
}

@supports not (backdrop-filter: blur(12px)) {
  .verity-overlay {
    background-color: rgba(9, 9, 11, 0.94);
  }
}

.v-dialog-card {
  position: relative;
  width: 100%;
  max-width: 620px;
  max-height: calc(100vh - 40px);
  display: flex;
  flex-direction: column;
  background-color: var(--v-card);
  color: var(--v-card-fg);
  border-radius: var(--v-radius-lg);
  border: 1px solid var(--v-border);
  box-shadow: var(--v-shadow-dialog);
  overflow: hidden;
  animation: vDialogEnter var(--v-dur-base) var(--v-ease-out) forwards;
  font-family: var(--v-font);
}

.v-card-danger {
  border-top: 3px solid var(--v-destructive);
}
.v-card-warning {
  border-top: 3px solid var(--v-warning);
}

.v-dialog-inner {
  padding: 32px 36px;
  display: flex;
  flex-direction: column;
  overflow-y: auto;
}

/* Dialog Header Top */
.v-dialog-header-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 20px;
}

.v-icon-badge-wrap {
  display: flex;
  align-items: center;
  gap: 12px;
}

.v-icon-circle {
  width: 44px;
  height: 44px;
  border-radius: var(--v-radius-full);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}
.v-icon-circle-danger {
  background-color: var(--v-destructive-subtle);
  color: var(--v-destructive);
  border: 1px solid var(--v-destructive-border);
}
.v-icon-circle-warning {
  background-color: var(--v-warning-subtle);
  color: var(--v-warning);
  border: 1px solid var(--v-warning-border);
}

.v-brand-mark {
  display: flex;
  align-items: center;
  gap: 7px;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: normal;
  color: var(--v-fg);
}

/* Dialog Title & Message */
.v-dialog-title {
  font-family: var(--v-font);
  font-size: 20px;
  font-weight: 700;
  line-height: 1.3;
  color: var(--v-fg);
  margin-bottom: 8px;
  letter-spacing: -0.01em;
}

.verity-status-highlight {
  font-weight: 700;
}
.v-card-danger .verity-status-highlight {
  color: var(--v-destructive);
}
.v-card-warning .verity-status-highlight {
  color: var(--v-warning);
}

.verity-message {
  font-size: 14px;
  line-height: 1.55;
  color: var(--v-muted-fg);
  margin-bottom: 16px;
}

/* Critical Alerts inside Dialog */
.v-payment-alert {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 12px 14px;
  border-radius: var(--v-radius-md);
  background-color: var(--v-destructive-subtle);
  border: 1px solid var(--v-destructive-border);
  color: var(--v-destructive-text);
  font-size: 13px;
  line-height: 1.45;
  margin-bottom: 16px;
}
.v-payment-alert strong {
  font-weight: 700;
}

/* Chain Box */
.v-chain-box {
  background-color: var(--v-muted);
  border: 1px solid var(--v-border);
  border-radius: var(--v-radius-md);
  padding: 12px 14px;
  margin-bottom: 16px;
  font-size: 12px;
}
.v-chain-title {
  font-weight: 600;
  color: var(--v-muted-fg);
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 8px;
}
.v-chain-item {
  font-family: var(--v-mono);
  color: var(--v-fg);
  padding: 2px 0;
}

/* Collapsible Accordion */
.v-accordion-item {
  border: 1px solid var(--v-border);
  border-radius: var(--v-radius-md);
  background-color: var(--v-card);
  margin-bottom: 24px;
  overflow: hidden;
}

.v-accordion-trigger {
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  padding: 12px 16px;
  background: var(--v-muted);
  border: none;
  font-family: inherit;
  font-size: 13px;
  font-weight: 600;
  color: var(--v-fg);
  cursor: pointer;
  text-align: left;
  transition: background-color var(--v-dur-fast) var(--v-ease-out);
}
.v-accordion-trigger:hover {
  background-color: var(--v-border);
}
.v-accordion-trigger:focus-visible {
  outline: 2px solid var(--v-ring);
  outline-offset: -2px;
}

.v-accordion-icon {
  transition: transform var(--v-dur-base) var(--v-ease-out);
  color: var(--v-muted-fg);
}
.v-accordion-trigger[aria-expanded="false"] .v-accordion-icon {
  transform: rotate(-90deg);
}

.v-accordion-content {
  padding: 10px 14px;
  display: flex;
  flex-direction: column;
  gap: 8px;
  max-height: 38vh;
  transition: max-height var(--v-dur-base) var(--v-ease-out);
}
.v-accordion-trigger[aria-expanded="false"] + .v-accordion-content {
  display: none;
}

/* Reason Rows (.verity-tag) */
.verity-tag {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 12px;
  border-radius: var(--v-radius-sm);
  background-color: var(--v-muted);
  border: 1px solid var(--v-border);
  color: var(--v-fg);
  font-size: 13px;
  line-height: 1.4;
  word-break: break-word;
}
.v-reason-icon {
  display: inline-flex;
  align-items: center;
  color: var(--v-muted-fg);
  flex-shrink: 0;
}
.v-reason-text {
  flex: 1;
}
.v-reason-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  flex-shrink: 0;
  display: inline-block;
  vertical-align: middle;
}
.v-dot-danger {
  background-color: var(--v-destructive);
}
.v-dot-warning {
  background-color: var(--v-warning);
}

/* Quiet Score Footer */
.v-score-footer {
  margin-top: 10px;
  padding-top: 10px;
  border-top: 1px solid var(--v-border);
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.v-score-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 12px;
}
.v-score-label {
  color: var(--v-muted-fg);
  font-weight: 500;
}
.v-score-val {
  color: var(--v-fg);
  font-weight: 600;
  font-variant-numeric: tabular-nums;
  font-family: var(--v-mono);
}
.v-score-bar-track {
  width: 100%;
  height: 4px;
  border-radius: var(--v-radius-full);
  background-color: var(--v-border);
  overflow: hidden;
}
.v-score-bar-fill {
  height: 100%;
  border-radius: var(--v-radius-full);
  transition: width var(--v-dur-base) var(--v-ease-out);
}
.v-score-fill-danger {
  background-color: var(--v-destructive);
}
.v-score-fill-warning {
  background-color: var(--v-warning);
}

.v-score-tag {
  font-weight: 600;
  font-size: 12px;
  border-color: var(--v-border);
  background: transparent;
  color: var(--v-muted-fg);
  justify-content: flex-end;
}

/* Action Rows */
.v-dialog-actions {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 4px;
  margin-bottom: 12px;
}

.v-dialog-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding-top: 14px;
  border-top: 1px solid var(--v-border);
  font-size: 11px;
  color: var(--v-muted-fg);
}
.v-footer-brand {
  display: flex;
  align-items: center;
  gap: 5px;
}
.v-footer-link {
  color: var(--v-muted-fg);
  text-decoration: underline;
  cursor: pointer;
  background: none;
  border: none;
  font-size: 11px;
}
.v-footer-link:hover {
  color: var(--v-fg);
}

/* Confirmation View Cooldown Bar */
.v-cooldown-bar {
  position: relative;
  width: 100%;
  height: 3px;
  background-color: var(--v-border);
  border-radius: var(--v-radius-full);
  overflow: hidden;
  margin: 12px 0;
}
.v-cooldown-progress {
  position: absolute;
  top: 0;
  left: 0;
  height: 100%;
  width: 0%;
  background-color: var(--v-destructive);
  transition: width 1500ms linear;
}

/* ─── Download Warning Modal ───────────────────────────────────────────────── */
#verity-download-warning-host {
  all: initial;
  position: fixed;
  top: 24px;
  right: 24px;
  z-index: 2147483645;
  pointer-events: auto;
  max-width: 400px;
  width: calc(100vw - 32px);
  font-family: var(--v-font);
}

.v-dw-card {
  background-color: var(--v-card);
  color: var(--v-card-fg);
  border-radius: var(--v-radius-lg);
  border: 1px solid var(--v-border);
  box-shadow: var(--v-shadow-dialog);
  padding: 20px;
  display: flex;
  flex-direction: column;
  gap: 12px;
  animation: vDialogEnter var(--v-dur-base) var(--v-ease-out) forwards;
}

.v-dw-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.v-dw-title-row {
  display: flex;
  align-items: center;
  gap: 10px;
}

.v-dw-title {
  font-size: 14px;
  font-weight: 700;
  color: var(--v-fg);
}

.v-dw-meta {
  display: flex;
  flex-direction: column;
  gap: 6px;
  background-color: var(--v-muted);
  border: 1px solid var(--v-border);
  border-radius: var(--v-radius-md);
  padding: 10px 12px;
}

.v-dw-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
}
.v-dw-label {
  color: var(--v-muted-fg);
  width: 52px;
  flex-shrink: 0;
}

/* ─── Popup Blocked Toast Stacking ─────────────────────────────────────────── */
.v-toast-container {
  position: fixed;
  bottom: 24px;
  right: 24px;
  z-index: 2147483647;
  display: flex;
  flex-direction: column-reverse;
  gap: 8px;
  pointer-events: none;
  max-width: 380px;
  width: calc(100vw - 32px);
}

@media (max-width: 480px) {
  .v-toast-container {
    bottom: 16px;
    right: 16px;
    left: 16px;
    width: auto;
    align-items: center;
  }
}

.v-toast-card {
  pointer-events: auto;
  background-color: var(--v-card);
  color: var(--v-card-fg);
  border-radius: var(--v-radius-md);
  border: 1px solid var(--v-border);
  box-shadow: var(--v-shadow-lg);
  padding: 12px 14px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  font-size: 13px;
  line-height: 1.4;
  animation: vDialogEnter var(--v-dur-base) var(--v-ease-out) forwards;
  transition: transform var(--v-dur-base) var(--v-ease-out), opacity var(--v-dur-base) var(--v-ease-out);
}

.v-toast-content {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}
.v-toast-icon {
  color: var(--v-destructive);
  flex-shrink: 0;
}
.v-toast-text {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.v-toast-dismiss {
  border: none;
  background: transparent;
  color: var(--v-muted-fg);
  cursor: pointer;
  padding: 2px;
  border-radius: var(--v-radius-sm);
  display: flex;
  align-items: center;
  justify-content: center;
  transition: color var(--v-dur-fast) var(--v-ease-out);
}
.v-toast-dismiss:hover {
  color: var(--v-fg);
}

/* ─── Floating Page Status Badge ───────────────────────────────────────────── */
.verity-badge {
  width: 28px;
  height: 28px;
  border-radius: var(--v-radius-full);
  background-color: var(--v-muted);
  border: 1px solid var(--v-border);
  box-shadow: var(--v-shadow-md);
  cursor: pointer;
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: transform var(--v-dur-fast) var(--v-ease-out), box-shadow var(--v-dur-fast) var(--v-ease-out);
}
.verity-badge:hover {
  transform: scale(1.1);
}

.verity-badge.safe {
  background-color: var(--v-success-subtle);
  border-color: var(--v-success-border);
  color: var(--v-success-text);
}
.verity-badge.caution {
  background-color: var(--v-warning-subtle);
  border-color: var(--v-warning-border);
  color: var(--v-warning-text);
}
.verity-badge.danger {
  background-color: var(--v-destructive-subtle);
  border-color: var(--v-destructive-border);
  color: var(--v-destructive-text);
}

.verity-tooltip {
  position: absolute;
  top: 36px;
  right: 0;
  background-color: var(--v-primary);
  color: var(--v-primary-fg);
  font-family: var(--v-font);
  font-size: 11px;
  font-weight: 500;
  line-height: 1.4;
  padding: 8px 12px;
  border-radius: var(--v-radius-sm);
  white-space: normal;
  width: 220px;
  opacity: 0;
  pointer-events: none;
  transform: translateY(-4px);
  transition: opacity var(--v-dur-fast) var(--v-ease-out), transform var(--v-dur-fast) var(--v-ease-out);
  box-shadow: var(--v-shadow-md);
  z-index: 50;
}
.verity-badge:hover .verity-tooltip {
  opacity: 1;
  transform: translateY(0);
}

/* ─── Responsive Media Queries ─────────────────────────────────────────────── */
@media (max-width: 640px) {
  .v-dialog-inner {
    padding: 24px 20px;
  }
  .v-dialog-actions {
    flex-direction: column-reverse;
    align-items: stretch;
  }
  .v-btn-lg, .v-btn-md {
    width: 100%;
    justify-content: center;
  }
}

@media (max-width: 480px) {
  .verity-overlay {
    padding: 12px;
  }
  .v-dialog-inner {
    padding: 24px 18px;
  }
  .v-dialog-actions {
    flex-direction: column-reverse;
    align-items: stretch;
    gap: 10px;
  }
  .v-dialog-actions .v-btn {
    width: 100%;
    min-height: 44px;
    height: 44px;
    justify-content: center;
  }
}

/* ─── Prefers-Reduced-Motion ───────────────────────────────────────────────── */
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
    transform: none !important;
  }
}
`;

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
    const pathname = (url.pathname || '') + (url.search || '');
    let registeredDomain = host;
    let subdomain = '';

    if (typeof globalThis.getDomain === 'function') {
      const reg = globalThis.getDomain(host);
      if (reg) {
        registeredDomain = reg;
        if (host.length > reg.length && host.endsWith(reg)) {
          subdomain = host.slice(0, host.length - reg.length);
        }
      }
    } else {
      const parts = host.split('.');
      if (parts.length > 2) {
        const secondTld = parts[parts.length - 2];
        const isMultiPartTld = ['co', 'gov', 'ac', 'com', 'org', 'net', 'edu'].includes(secondTld) && parts[parts.length - 1].length <= 3;
        const splitIndex = isMultiPartTld ? parts.length - 3 : parts.length - 2;
        if (splitIndex > 0) {
          registeredDomain = parts.slice(splitIndex).join('.');
          subdomain = parts.slice(0, splitIndex).join('.') + '.';
        }
      }
    }
    return { host, subdomain, registeredDomain, path: pathname };
  } catch (e) {
    return { host: urlString, subdomain: '', registeredDomain: urlString, path: '' };
  }
}

// ─── Floating Page Status Badge ─────────────────────────────────────────────

function injectStatusBadge() {
  if (typeof window === 'undefined' || typeof document === 'undefined') return null;
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
  if (verdict.action === 'block' || (verdict.score || verdict.riskScore || 0) >= 70) {
    isBlocked = true;
    try { window.stop(); } catch (e) {}
    try {
      document.querySelectorAll('video, audio').forEach(media => {
        try {
          media.pause();
          media.muted = true;
          media.removeAttribute('autoplay');
          media.src = '';
          media.load();
        } catch (_) {}
      });
    } catch (_) {}
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
if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
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
}

// ─── Runtime Threat Interceptor Event Listener ──────────────────────────────
if (typeof window !== 'undefined') {
  window.addEventListener('__VERITY_RUNTIME_THREAT__', (event) => {
    const detail = event?.detail || {};
    const signal = detail.signal || 'SIG_PHISHING_KIT_WEBHOOK_EXFIL';

    if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
      chrome.runtime.sendMessage({
        action: 'RUNTIME_THREAT_DETECTED',
        signal: signal,
        detail: detail,
        url: window.location.href
      }).catch(() => {});
    }

    const threatScore = 95;
    const threatVerdict = {
      action: 'block',
      severity: 'danger',
      state: 'danger',
      score: threatScore,
      riskScore: threatScore,
      reasons: [
        signal === 'SIG_CLICKFIX_CLIPBOARD_ATTACK'
          ? 'Live ClickFix clipboard command execution attack blocked.'
          : signal === 'SIG_CLIPBOARD_ADDRESS_SWAP'
          ? 'Live clipboard crypto/UPI address swapper attack blocked.'
          : signal === 'SIG_ROGUE_PUSH_OR_SW_TRAP'
          ? 'Rogue push notification or service worker registration blocked.'
          : signal === 'SIG_UNTRUSTED_SCREEN_SHARE'
          ? 'Untrusted screen sharing capture attempt blocked.'
          : 'Phishing kit credential exfiltration endpoint blocked.'
      ],
      signals: [{ id: signal, score: threatScore }]
    };
    injectOverlay(threatVerdict);
  });
}

triggerImmediateUrlScan();
initSpaMutationObserver();

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      initSpaMutationObserver();
      triggerFullScan();
    });
  } else {
    initSpaMutationObserver();
    triggerFullScan();
  }
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
    document.body.style.removeProperty('display');
  }
  try { window.onbeforeunload = null; } catch (e) {}
}

function getOverlaySummary(verdict, isDanger, isPaymentPhishing) {
  if (typeof t !== 'function') {
    return isPaymentPhishing
      ? 'This site appears to be impersonating a payment provider or financial institution to capture sensitive credentials.'
      : isDanger
        ? 'This site showed warning signs that are common on unsafe pages.'
        : 'This site exhibits unusual patterns or unconfirmed security details. Exercise caution before interacting with it.';
  }
  if (isPaymentPhishing) {
    return t('OVERLAY_SUMMARY_PAYMENT');
  }
  const signals = verdict.signals || [];
  const signalIds = signals.map(s => String(s.id || ''));
  const categories = signals.map(s => String(s.category || ''));

  // Threat intelligence / blocklist hit (only here the word "verified" appears)
  const hasThreatIntel = signalIds.some(id => id.includes('INTEL') || id.includes('FEED') || id.includes('BLOCKLIST') || id.includes('REPUTATION')) ||
                         categories.includes('threat_intel');
  if (hasThreatIntel) {
    return t('OVERLAY_SUMMARY_THREAT_INTEL');
  }

  // Brand impersonation or credential collection
  const hasPhishing = signalIds.some(id => id.includes('BRAND') || id.includes('IMPERSONATION') || id.includes('CREDENTIAL') || id.includes('PASSWORD') || id.includes('LOGIN') || id.includes('PHISH')) ||
                      categories.includes('brand_impersonation') || categories.includes('dom_credentials') || categories.includes('payment_phishing');
  if (hasPhishing) {
    return t('OVERLAY_SUMMARY_PHISHING');
  }

  // Malvertising / popunder redirects
  const hasMalvertising = signalIds.some(id => id.includes('POPUNDER') || id.includes('MALVERTISING') || id.includes('REDIRECT')) ||
                          categories.includes('malvertising');
  if (hasMalvertising) {
    return t('OVERLAY_SUMMARY_MALVERTISING');
  }

  if (!isDanger) {
    return t('OVERLAY_SUMMARY_CAUTION');
  }

  return t('OVERLAY_SUMMARY_NEUTRAL');
}

function injectOverlay(verdict) {
  if (document.getElementById('verity-security-host')) {
    return; // Already blocked
  }

  // Eagerly ensure font is loaded
  ensureVerityFontLoaded();

  // Halt active redirects and page loading
  try { window.stop(); } catch (e) {}
  try {
    document.querySelectorAll('video, audio').forEach(media => {
      try {
        media.pause();
        media.muted = true;
        media.removeAttribute('autoplay');
        media.src = '';
        media.load();
      } catch (_) {}
    });
  } catch (_) {}
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

  // Lock scroll and hide body for blocked pages
  if (document.documentElement) {
    document.documentElement.style.setProperty('overflow', 'hidden', 'important');
  }
  if (document.body) {
    document.body.style.setProperty('overflow', 'hidden', 'important');
    if (isDanger) {
      document.body.style.setProperty('display', 'none', 'important');
    }
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
  const rawScore = verdict.score || verdict.riskScore || 0;
  host.dataset.score = String(rawScore);
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

  // Calmer sentence form title with key word emphasis only
  const titleHtml = isDanger
    ? `${escapeHtml(typeof t === 'function' ? t('OVERLAY_TITLE_BLOCK_PRE') : 'This site looks ')}<span class="verity-status-highlight">${escapeHtml(typeof t === 'function' ? t('OVERLAY_TITLE_BLOCK_WORD') : 'dangerous')}</span>`
    : `<span class="verity-status-highlight">${escapeHtml(typeof t === 'function' ? t('OVERLAY_TITLE_CAUTION_WORD') : 'Be careful')}</span>${escapeHtml(typeof t === 'function' ? t('OVERLAY_TITLE_CAUTION_POST') : ' on this site')}`;

  const summaryText = getOverlaySummary(verdict, isDanger, isPaymentPhishing);

  // Logo mark SVG with check cut-out
  const logoMarkSvg = (typeof ICONS !== 'undefined' && ICONS['logo-mark'])
    ? `<svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">${ICONS['logo-mark']}</svg>`
    : `<svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M12 2L4 5v6.09c0 5.05 3.41 9.76 8 10.91 4.59-1.15 8-5.86 8-10.91V5l-8-3zm-1.06 13.54l-3.24-3.24 1.41-1.41 1.83 1.83 4.24-4.24 1.41 1.41-5.65 5.65z" fill="currentColor"/></svg>`;

  const heroIconSvg = isDanger
    ? (typeof getIconSvg === 'function' ? getIconSvg('shield-x', { size: 22 }) : '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m14.5 9.5-5 5"/><path d="m9.5 9.5 5 5"/></svg>')
    : (typeof getIconSvg === 'function' ? getIconSvg('triangle-alert', { size: 22 }) : '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>');

  overlayWrap.innerHTML = `
    <!-- Main View Dialog Card -->
    <div class="v-dialog-card ${isDanger ? 'v-card-danger' : 'v-card-warning'}" id="main-view">
      <div class="v-dialog-inner">
        <div class="v-dialog-header-top">
          <div class="v-icon-badge-wrap">
            <div class="v-icon-circle ${isDanger ? 'v-icon-circle-danger' : 'v-icon-circle-warning'}">
              ${heroIconSvg}
            </div>
            <!-- Duplicate pill removed per design spec; element preserved hidden for compatibility -->
            <span class="verity-header-badge" style="display:none;" aria-hidden="true"></span>
          </div>
          <div class="v-brand-mark">
            ${logoMarkSvg}
            <span>VERITY</span>
          </div>
        </div>

        <h1 class="v-dialog-title" id="verity-dialog-title">${titleHtml}</h1>

        <p class="verity-message" id="verity-dialog-desc">
          ${escapeHtml(summaryText)}
        </p>

        <div class="v-chip-mono" style="margin-bottom: 20px;" title="${escapeHtml(domainParts.host + domainParts.path)}" aria-label="${escapeHtml(domainParts.host + domainParts.path)}">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="color:var(--v-muted-fg);flex-shrink:0;" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/></svg>
          <span class="v-chip-mono-muted v-chip-mono-subdomain">${escapeHtml(domainParts.subdomain)}</span><span class="v-chip-mono-emphasis v-chip-mono-registered">${escapeHtml(domainParts.registeredDomain)}</span><span class="v-chip-mono-muted v-chip-mono-path">${escapeHtml(domainParts.path)}</span>
          <span id="verity-url-display" style="display:none;">${escapeHtml(window.location.href)}</span>
        </div>

        <div id="verity-payment-warning-container"></div>
        <div id="verity-chain-container"></div>

        <div class="v-accordion-item">
          <button type="button" class="v-accordion-trigger" id="v-accordion-btn" aria-expanded="true">
            <span>${escapeHtml(typeof t === 'function' ? t('OVERLAY_WHY_FLAGGED', { count: reasonsList.length }) : `Why we flagged this (${reasonsList.length})`)}</span>
            <svg class="v-accordion-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>
          </button>
          <div class="v-accordion-content v-scroll" id="verity-tags-container"></div>
        </div>

        <div class="v-dialog-actions">
          <button type="button" class="v-btn v-btn-ghost v-btn-md" id="btn-proceed">${escapeHtml(typeof t === 'function' ? t('OVERLAY_BTN_PROCEED') : 'Continue anyway')}</button>
          <button type="button" class="v-btn v-btn-primary v-btn-lg" id="btn-back">${escapeHtml(typeof t === 'function' ? t('OVERLAY_BTN_SAFETY') : 'Take me to safety')}</button>
        </div>

        <div class="v-dialog-footer">
          <span class="v-footer-brand">${escapeHtml(typeof t === 'function' ? t('OVERLAY_PROTECTED_BY') : 'Protected by VERITY Web Protection')}</span>
          <button type="button" class="v-footer-link" id="btn-report-site">${escapeHtml(typeof t === 'function' ? t('OVERLAY_REPORT_ISSUE') : 'Report an issue')}</button>
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
            <span class="v-badge v-badge-danger">${escapeHtml(typeof t === 'function' ? t('OVERLAY_CONFIRM_BADGE') : 'High Risk Confirmation')}</span>
          </div>
        </div>

        <h2 class="v-dialog-title" style="color: var(--v-destructive);">${escapeHtml(typeof t === 'function' ? t('OVERLAY_CONFIRM_TITLE') : 'Are you sure you want to proceed?')}</h2>
        <p class="verity-message">
          ${escapeHtml(typeof t === 'function' ? t('OVERLAY_CONFIRM_DESC', { state: stateTitle.toLowerCase() }) : `This site is classified as ${stateTitle}. Bypassing protection exposes you to potential credential theft, phishing, or financial risk.`)}
        </p>

        <div class="v-cooldown-bar"><div class="v-cooldown-progress" id="v-cooldown-fill"></div></div>

        <div class="v-dialog-actions" style="margin-top: 16px;">
          <button type="button" class="v-btn v-btn-outline v-btn-md" id="btn-confirm-cancel">${escapeHtml(typeof t === 'function' ? t('OVERLAY_CONFIRM_CANCEL') : 'Return to safety')}</button>
          <button type="button" class="v-btn v-btn-destructive v-btn-md" id="btn-confirm-proceed" disabled>${escapeHtml(typeof t === 'function' ? t('OVERLAY_CONFIRM_WAIT', { seconds: '1.5' }) : 'Please wait (1.5s)...')}</button>
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

  // Populate reasons list inside accordion with category icons
  const tagsContainer = overlayWrap.querySelector('#verity-tags-container');
  if (tagsContainer) {
    const rawSignals = verdict.signals && verdict.signals.length > 0 ? verdict.signals : [];

    for (let idx = 0; idx < reasonsList.length; idx++) {
      const r = reasonsList[idx];
      const sig = rawSignals[idx] || {};
      const catId = sig.category || (typeof SIGNAL_CATEGORY_MAP !== 'undefined' ? SIGNAL_CATEGORY_MAP[sig.id] : null) || 'url';

      let iconName = 'info';
      switch (catId) {
        case 'url':
          iconName = 'link';
          break;
        case 'dom_credentials':
        case 'payment_phishing':
          iconName = 'key-round';
          break;
        case 'download':
          iconName = 'download';
          break;
        case 'ip_host':
        case 'malvertising':
          iconName = 'globe';
          break;
        case 'ml':
        case 'threat_intel':
        case 'brand_impersonation':
        case 'scam_language':
        case 'synergy':
          iconName = 'shield-alert';
          break;
        default:
          iconName = 'info';
          break;
      }

      const iconSvg = typeof getIconSvg === 'function'
        ? getIconSvg(iconName, { size: 14 })
        : `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">${(typeof ICONS !== 'undefined' && ICONS[iconName]) || '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>'}</svg>`;

      const tagRow = document.createElement('div');
      tagRow.className = 'verity-tag';
      tagRow.innerHTML = `
        <span class="v-reason-icon">${iconSvg}</span>
        <span class="v-reason-text">${escapeHtml(String(r))}</span>
        <span class="v-reason-dot ${isDanger ? 'v-dot-danger' : 'v-dot-warning'}"></span>
      `;
      tagsContainer.appendChild(tagRow);
    }

    // Quiet Risk Score Footer replacing old bordered box
    const scoreVal = Math.min(100, Math.max(0, Number(rawScore)));
    const scoreFooter = document.createElement('div');
    scoreFooter.className = 'v-score-footer';
    const scoreLabel = typeof t === 'function' ? t('OVERLAY_RISK_SCORE_LABEL') : 'Risk score';
    scoreFooter.innerHTML = `
      <div class="v-score-row">
        <span class="v-score-label">${escapeHtml(scoreLabel)}</span>
        <span class="v-score-val">${scoreVal} / 100</span>
      </div>
      <div class="v-score-bar-track">
        <div class="v-score-bar-fill ${isDanger ? 'v-score-fill-danger' : 'v-score-fill-warning'}" style="width: ${scoreVal}%;"></div>
      </div>
    `;
    tagsContainer.appendChild(scoreFooter);
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
        btnConfirmProceed.textContent = typeof t === 'function' ? t('OVERLAY_CONFIRM_WAIT', { seconds: '1.5' }) : 'Please wait (1.5s)...';
        cooldownFill.style.width = '0%';
        requestAnimationFrame(() => {
          cooldownFill.style.width = '100%';
        });
        setTimeout(() => {
          btnConfirmProceed.disabled = false;
          btnConfirmProceed.textContent = typeof t === 'function' ? t('OVERLAY_CONFIRM_PROCEED') : 'I understand the risks, proceed';
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
    if (parent.firstChild) {
      parent.insertBefore(host, parent.firstChild);
    } else {
      parent.appendChild(host);
    }
  }

  // Auto-focus primary safe action
  setTimeout(() => {
    shadow.querySelector('#btn-back')?.focus();
  }, 50);

  // Self-Healing Anti-Tamper Observer against hostile page scripts
  if (!blockObserver && document.documentElement) {
    blockObserver = new MutationObserver(() => {
      if (!isBlocked) return;
      const hostInDoc = document.getElementById('verity-security-host');
      if (!hostInDoc || !document.documentElement.contains(host)) {
        if (document.documentElement.firstChild) {
          document.documentElement.insertBefore(host, document.documentElement.firstChild);
        } else {
          document.documentElement.appendChild(host);
        }
      }
      if (host.style.display === 'none' || host.hidden) {
        host.style.setProperty('display', 'block', 'important');
        host.hidden = false;
      }
      if (isDanger && document.body && document.body.style.display !== 'none') {
        document.body.style.setProperty('display', 'none', 'important');
      }
      if (document.documentElement && document.documentElement.style.overflow !== 'hidden') {
        document.documentElement.style.setProperty('overflow', 'hidden', 'important');
      }
    });
    blockObserver.observe(document.documentElement, { childList: true, attributes: true, subtree: true });
  }
}

if (typeof globalThis !== 'undefined') {
  globalThis.querySelectorAllDeep = querySelectorAllDeep;
  globalThis.querySelectorDeep = querySelectorDeep;
  globalThis.getPageTextDeep = getPageTextDeep;
  globalThis.detectClickFixAndFakeVerification = detectClickFixAndFakeVerification;
  globalThis.detectPaymentFields = detectPaymentFields;
  globalThis.detectPaymentForm = detectPaymentForm;
  globalThis.getSensitiveDomSignature = getSensitiveDomSignature;
  globalThis.collectSignals = collectSignals;
  globalThis.extractBrandAssetUrls = extractBrandAssetUrls;
  globalThis.detectTechSupportRemoteScam = detectTechSupportRemoteScam;
  globalThis.detectBitbFakeWindowAttack = detectBitbFakeWindowAttack;
  globalThis.detectAitmReverseProxyDom = detectAitmReverseProxyDom;
  globalThis.scanQrCodesOnPage = scanQrCodesOnPage;
  globalThis.inspectQrPayload = inspectQrPayload;
  globalThis.detectQrFromDomAttributes = detectQrFromDomAttributes;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    querySelectorAllDeep,
    querySelectorDeep,
    getPageTextDeep,
    detectClickFixAndFakeVerification,
    detectPaymentFields,
    detectPaymentForm,
    getSensitiveDomSignature,
    collectSignals,
    extractBrandAssetUrls,
    detectTechSupportRemoteScam,
    detectBitbFakeWindowAttack,
    detectAitmReverseProxyDom,
    scanQrCodesOnPage,
    inspectQrPayload,
    detectQrFromDomAttributes,
  };
}



// ─── Active Cross-Origin & Webhook Submit Interceptor ───────────────────────
if (typeof document !== 'undefined') {
  document.addEventListener('submit', (event) => {
    const form = event.target;
    if (!form) return;

    const pf = detectPaymentFields();
    const hasPassword = querySelectorDeep('input[type="password"]', form) !== null ||
                        querySelectorDeep('input[type="password"]') !== null;
    const hasSensitive = hasPassword || pf.card || pf.cvv || pf.otp || pf.pin || pf.accountNumber;

    if (!hasSensitive) return;

    if (isBlocked) {
      event.preventDefault();
      event.stopPropagation();
      try { window.stop(); } catch (_) {}
      return;
    }

    let targetHost = '';
    try {
      const actionUrl = form.getAttribute('action') || form.action || '';
      if (actionUrl && !actionUrl.startsWith('#') && !actionUrl.startsWith('javascript:')) {
        targetHost = new URL(actionUrl, window.location.href).hostname.toLowerCase();
      }
    } catch (_) {}

    const currentHost = window.location.hostname.toLowerCase();
    const currentRoot = getBaseDomain(currentHost);
    const targetRoot = getBaseDomain(targetHost);

    const isCrossDomainExfil = !!(targetHost && targetRoot && currentRoot && targetRoot !== currentRoot);
    const webhookDetected = detectPhishingKitWebhookExfil(true).detected;
    const pinCollection = detectIllegalWebPinCollection().detected;

    if (isCrossDomainExfil || webhookDetected || pinCollection) {
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();
      try { window.stop(); } catch (_) {}

      const reasonMsg = webhookDetected ? 'Critical threat: Form transmits stolen data to external webhook/bot.' :
                        pinCollection ? 'Critical financial fraud: Illegal UPI PIN submission intercepted.' :
                        `Critical risk: Form transmits sensitive credentials to an untrusted external domain (${targetHost}).`;

      handleEnforcementVerdict({
        action: 'block',
        severity: 'danger',
        state: 'danger',
        score: 95,
        riskScore: 95,
        reasons: [reasonMsg]
      });
    }
  }, true);
}
