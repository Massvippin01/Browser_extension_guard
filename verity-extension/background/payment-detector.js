/**
 * payment-detector.js — Payment Website Protection
 *
 * Analyzes URL + DOM signals to detect payment phishing.
 * Spec: VERITY_PAYMENT_PROTECTION_ANTIGRAVITY_SPEC-1.md
 *
 * Privacy guarantee: Never reads or transmits actual field values.
 * Only detects structural presence of payment-related fields.
 */

import { isAllowlistedDomain } from '../shared/legit-domains.js';
import { getDomain } from '../shared/psl.js';
import { t } from '../shared/messages.js';

// ─── Payment intent keywords (page text scan) ───────────────────────────────
const PAYMENT_INTENT_KEYWORDS = [
  'pay now', 'make payment', 'complete payment', 'confirm payment',
  'checkout', 'place order', 'card payment', 'enter card details',
  'payment verification', 'secure payment', 'proceed to pay',
  'upi payment', 'wallet payment', 'bank transfer', 'transaction',
  'billing details', 'payment information', 'card details',
  'debit card', 'credit card', 'net banking', 'pay with'
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

function safeHostname(urlString) {
  try {
    return new URL(urlString).hostname.toLowerCase();
  } catch {
    return '';
  }
}

/**
 * Detect if a page is a payment page from DOM signals.
 * Returns: { isPaymentPage, paymentIntentScore, matchedKeywords }
 */
function detectPaymentIntent(domSignals) {
  if (!domSignals) return { isPaymentPage: false, paymentIntentScore: 0, matchedKeywords: [] };

  const pageText = (domSignals.pageText || '').toLowerCase();
  const matchedKeywords = PAYMENT_INTENT_KEYWORDS.filter(k => pageText.includes(k));

  // Payment field presence is itself strong intent evidence
  const fields = domSignals.paymentFields || {};
  const hasPaymentFields = !!(fields.card || fields.cvv || fields.expiry ||
                            fields.upi || fields.otp || fields.pin);

  const hasPaymentForm = !!(domSignals.hasPaymentForm);

  // Require actual structural fields or form for payment page classification
  // Raw keywords alone without any form or input fields do NOT make a payment page
  if (!hasPaymentFields && !hasPaymentForm) {
    return {
      isPaymentPage: false,
      paymentIntentScore: 0,
      matchedKeywords
    };
  }

  let score = 0;
  score += matchedKeywords.length * 8;
  if (hasPaymentFields) score += 30;
  if (hasPaymentForm)   score += 20;
  score = Math.min(score, 100);

  return {
    isPaymentPage: true,
    paymentIntentScore: score,
    matchedKeywords,
  };
}

/**
 * Detect which payment provider the page claims to be.
 * Only evaluated when payment intent/form is present.
 */
function detectClaimedProvider(domSignals, paymentBrands) {
  if (!domSignals || !paymentBrands) return { claimedProvider: null, confidence: 0 };

  // Require claim in page structure (title, form actions, headings, buttons, alt, logo URLs, structuralText)
  const pageTitle = (domSignals.pageTitle || '').toLowerCase();
  const formActions = Array.isArray(domSignals.formActions) ? domSignals.formActions.join(' ').toLowerCase() : '';
  const structuralText = (domSignals.structuralText || '').toLowerCase();
  const headingText = (domSignals.headingText || '').toLowerCase();
  const buttonLabels = (domSignals.buttonLabels || '').toLowerCase();
  const logoText = (domSignals.logoText || '').toLowerCase();
  const structuralContext = `${pageTitle} ${formActions} ${structuralText} ${headingText} ${buttonLabels} ${logoText}`.trim();

  const claimedArr = Array.isArray(domSignals.claimedProviders) ? domSignals.claimedProviders : [];

  let bestMatch = null;
  let bestScore = 0;

  for (const brand of paymentBrands) {
    let hits = 0;
    const brandNameLower = brand.name.toLowerCase();

    if (claimedArr.some(c => c.toLowerCase() === brandNameLower)) {
      hits += 3;
    }

    for (const alias of (brand.aliases || [])) {
      const aliasLower = alias.toLowerCase();
      if (structuralContext.includes(aliasLower)) {
        hits += 2;
      }
    }

    if (hits > bestScore) {
      bestScore = hits;
      bestMatch = brand;
    }
  }

  if (!bestMatch || bestScore === 0) return { claimedProvider: null, confidence: 0 };

  return {
    claimedProvider: bestMatch.name,
    claimedProviderObj: bestMatch,
    confidence: Math.min(bestScore * 25, 100),
  };
}

/**
 * Check if the actual domain matches the claimed payment provider's official domains.
 */
function verifyProviderDomain(hostname, claimedProviderObj, paymentBrands) {
  if (!hostname) return { officialDomainMatch: false, domainMismatch: true, isTrustedProvider: false };

  const currentRootDomain = getDomain(hostname) || hostname;

  // Check if hostname is ANY trusted payment provider
  const isTrustedProvider = isAllowlistedDomain(hostname) || (paymentBrands || []).some(brand =>
    (brand.domains || []).some(d => {
      const brandRoot = getDomain(d) || d;
      return hostname === d || hostname.endsWith('.' + d) || currentRootDomain === brandRoot;
    })
  );

  if (!claimedProviderObj) {
    return {
      officialDomainMatch: isTrustedProvider,
      domainMismatch: !isTrustedProvider,
      isTrustedProvider
    };
  }

  // Strict PSL root-domain matching for the claimed provider specifically
  const officialDomainMatch = (claimedProviderObj.domains || []).some(d => {
    const brandRoot = getDomain(d) || d;
    return hostname === d || hostname.endsWith('.' + d) || currentRootDomain === brandRoot;
  });

  return {
    officialDomainMatch,
    domainMismatch: !officialDomainMatch,
    isTrustedProvider,
  };
}

/**
 * Main entry point.
 * @param {string} url — Current page URL
 * @param {Object} domSignals — Signals from content script
 * @param {Array} paymentBrands — Loaded payment-brands.json
 * @returns {Object|null} paymentAnalysis — null if not a payment page
 */

/**
 * Detect cross-domain visual brand asset hotlinking (favicons, logos, og:image)
 * from official bank or payment gateway domains on an unverified origin.
 */
function detectBrandAssetHotlinkSpoof(hostname, domSignals, paymentBrands) {
  if (!domSignals || !Array.isArray(domSignals.brandAssetUrls) || !paymentBrands) return null;
  if (isAllowlistedDomain(hostname)) return null;

  const currentRoot = getDomain(hostname) || hostname;

  const knownBrandCdns = [
    { brand: 'PayPal', cdn: 'paypalobjects.com' },
    { brand: 'Stripe', cdn: 'stripe.network' },
    { brand: 'Stripe', cdn: 'stripe.com' },
    { brand: 'Razorpay', cdn: 'rzp.io' },
    { brand: 'Razorpay', cdn: 'razorpay.com' },
    { brand: 'HDFC Bank', cdn: 'hdfcbank.com' },
    { brand: 'SBI', cdn: 'onlinesbi.sbi' },
    { brand: 'SBI', cdn: 'sbi.co.in' },
    { brand: 'ICICI Bank', cdn: 'icicibank.com' },
    { brand: 'Axis Bank', cdn: 'axisbank.com' },
    { brand: 'Kotak Bank', cdn: 'kotak.com' },
    { brand: 'PhonePe', cdn: 'phonepe.com' },
    { brand: 'Paytm', cdn: 'paytm.com' }
  ];

  for (const assetUrl of domSignals.brandAssetUrls) {
    if (!assetUrl || typeof assetUrl !== 'string') continue;
    let assetHost = '';
    try {
      assetHost = new URL(assetUrl, 'https://' + hostname).hostname.toLowerCase();
    } catch (_) {
      continue;
    }
    if (!assetHost || assetHost === hostname) continue;

    const assetRoot = getDomain(assetHost) || assetHost;
    if (assetRoot === currentRoot) continue; // Same root domain is not cross-origin hotlink spoof

    // Check against known brand CDNs
    const matchedCdn = knownBrandCdns.find(c => assetHost === c.cdn || assetHost.endsWith('.' + c.cdn) || assetRoot === c.cdn);
    if (matchedCdn) {
      return {
        detected: true,
        brand: matchedCdn.brand,
        assetHost
      };
    }

    // Check against paymentBrands
    for (const brand of paymentBrands) {
      const isBrandDomain = (brand.domains || []).some(d => {
        const dRoot = getDomain(d) || d;
        return assetHost === d || assetHost.endsWith('.' + d) || assetRoot === dRoot;
      });
      if (isBrandDomain) {
        return {
          detected: true,
          brand: brand.name,
          assetHost
        };
      }
    }
  }

  return null;
}

export function analyzePaymentPage(url, domSignals, paymentBrands) {
  if (!url || !domSignals || !paymentBrands) return null;

  const hostname = safeHostname(url);
  const fields = domSignals.paymentFields || {};

  // 1. Payment intent
  const intentResult = detectPaymentIntent(domSignals);

  // 1b. UPI Debit Trap & Cashback Scam Detection
  const pageText = (domSignals.pageText || '').toLowerCase();
  const hasCashbackClaims = pageText.includes('cashback') || pageText.includes('claim refund') ||
                            pageText.includes('receive money') || pageText.includes('claim payment') ||
                            pageText.includes('prize winner') || pageText.includes('reward points');
  
  const hasUpiDebitLink = !!(domSignals.hasUpiLink || pageText.includes('upi://pay') || fields.upi);

  let isUpiTrap = false;
  if (hasCashbackClaims && hasUpiDebitLink && !isAllowlistedDomain(hostname)) {
    isUpiTrap = true;
  }

  // 1c. Digital Arrest / Utility Disconnection Scam Detection
  const isDigitalScam = (pageText.includes('electricity connection') || pageText.includes('will be disconnected') ||
                         pageText.includes('digital arrest') || pageText.includes('trai sim') ||
                         pageText.includes('cbi notice')) &&
                        (fields.otp || fields.card || fields.cvv || domSignals.hasPasswordInput) &&
                        !isAllowlistedDomain(hostname);

  const hasCyberFraudSignal = !!(
    domSignals.illegalWebPinCollection ||
    domSignals.unverifiedUpiCollection ||
    domSignals.highPressureTimer ||
    (domSignals.claimedProviders && domSignals.claimedProviders.length > 0) ||
    (domSignals.brandAssetUrls && domSignals.brandAssetUrls.length > 0)
  );

  if (!intentResult.isPaymentPage && !isUpiTrap && !isDigitalScam && !hasCyberFraudSignal) return null;

  // 2. Claimed provider detection (only for pages with payment intent or UPI trap)
  const providerResult = detectClaimedProvider(domSignals, paymentBrands);

  // 3. Domain verification
  const domainResult = verifyProviderDomain(
    hostname,
    providerResult.claimedProviderObj || null,
    paymentBrands
  );

  // 4. Build payment risk score and structured reasons
  let paymentScore = 0;
  const structuredReasons = [];

  // Card + CVV collection on suspicious (non-official) site
  if ((fields.card || fields.cvv) && domainResult.domainMismatch) {
    paymentScore += 50;
    structuredReasons.push({
      id: 'PAYMENT_CARD_CVV_UNVERIFIED',
      params: { hostname },
      score: 50
    });
  } else if (fields.card && fields.cvv) {
    paymentScore += 30;
    structuredReasons.push({
      id: 'PAYMENT_CARD_CVV_GENERIC',
      params: {},
      score: 30
    });
  }

  // OTP in payment context + mismatch
  if (fields.otp && domainResult.domainMismatch) {
    paymentScore += 30;
    structuredReasons.push({
      id: 'PAYMENT_OTP_UNVERIFIED',
      params: { hostname },
      score: 30
    });
  }

  // 0. Visual Brand Asset Hotlinking & Favicon Spoof (+85 pts)
  const assetHotlink = detectBrandAssetHotlinkSpoof(hostname, domSignals, paymentBrands);
  if (assetHotlink && domainResult.domainMismatch) {
    paymentScore += 85;
    structuredReasons.unshift({
      id: 'SIG_BRAND_ASSET_HOTLINK_SPOOF',
      params: { brand: assetHotlink.brand, assetHost: assetHotlink.assetHost },
      score: 85
    });
  }

  // 1. Strict PSL Payment Brand Mismatch (+75 pts)
  if (providerResult.claimedProvider && domainResult.domainMismatch) {
    paymentScore += 75;
    structuredReasons.push({
      id: 'SIG_PAYMENT_BRAND_MISMATCH',
      params: { claimedProvider: providerResult.claimedProvider, claimedBrand: providerResult.claimedProvider, hostname },
      score: 75
    });
  }

  // Fake payment brand impersonation (legacy compatibility)
  if (providerResult.claimedProvider && domainResult.domainMismatch) {
    paymentScore += 50;
    structuredReasons.push({
      id: 'PAYMENT_FAKE_PROVIDER',
      params: { claimedProvider: providerResult.claimedProvider, hostname },
      score: 50
    });
  }

  // 2. Illegal In-Browser UPI PIN / MPIN / ATM PIN Collection Trap (+90 pts)
  if (domSignals.illegalWebPinCollection && domainResult.domainMismatch) {
    paymentScore += 90;
    structuredReasons.unshift({
      id: 'SIG_ILLEGAL_WEB_PIN_COLLECTION',
      params: { phrase: domSignals.illegalWebPinReason || 'UPI PIN collection requested in browser' },
      score: 90
    });
  }

  // 3. Untrusted UPI Deep-Link / Fake QR Collection (+55 pts)
  if (domSignals.unverifiedUpiCollection && domainResult.domainMismatch) {
    paymentScore += 55;
    structuredReasons.push({
      id: 'SIG_UNVERIFIED_UPI_COLLECTION',
      params: { hostname },
      score: 55
    });
  }

  // 4. Fake Payment Countdown Timer (+30 pts)
  if (domSignals.highPressureTimer && domainResult.domainMismatch) {
    paymentScore += 30;
    structuredReasons.push({
      id: 'SIG_HIGH_PRESSURE_PAYMENT_TIMER',
      params: {},
      score: 30
    });
  }

  // Official domain mismatch
  if (domainResult.domainMismatch && providerResult.claimedProvider) {
    paymentScore += 25;
    structuredReasons.push({
      id: 'PAYMENT_DOMAIN_MISMATCH',
      params: { claimedProvider: providerResult.claimedProvider, hostname },
      score: 25
    });
  }

  // Unknown provider + payment fields
  if (!providerResult.claimedProvider && !domainResult.isTrustedProvider && intentResult.isPaymentPage) {
    paymentScore += 5;
    structuredReasons.push({
      id: 'PAYMENT_UNKNOWN_PROVIDER',
      params: {},
      score: 5
    });
  }

  // Payment form present
  if (domSignals.hasPaymentForm) {
    structuredReasons.push({
      id: 'PAYMENT_FORM_DETECTED',
      params: {},
      score: 0
    });
  }

  // 5. Critical override rule
  if (isUpiTrap) {
    paymentScore += 85;
    structuredReasons.unshift({
      id: 'SIG_UPI_DEBIT_TRAP',
      params: {},
      score: 85
    });
  }

  if (isDigitalScam && !domainResult.officialDomainMatch) {
    paymentScore += 75;
    structuredReasons.unshift({
      id: 'SIG_DIGITAL_ARREST_SCAM',
      params: {},
      score: 75
    });
  }

  const isCriticalPaymentPhishing = (
    (!domainResult.officialDomainMatch && (fields.card || fields.cvv || fields.otp || fields.pin)) ||
    (providerResult.claimedProvider && domainResult.domainMismatch) ||
    isUpiTrap ||
    isDigitalScam ||
    domSignals.illegalWebPinCollection ||
    domSignals.unverifiedUpiCollection
  );

  if (isCriticalPaymentPhishing) {
    paymentScore = Math.max(paymentScore, 85);
    structuredReasons.unshift({
      id: 'SIG_PAYMENT_PHISHING',
      params: {},
      score: 85
    });
  }

  paymentScore = Math.min(paymentScore, 100);

  // Render text strings for legacy callers via t(id, params)
  const reasons = structuredReasons.map(r => t(r.id, r.params));

  return {
    isPaymentPage: true,
    paymentIntentScore: intentResult.paymentIntentScore,
    paymentFields: fields,
    claimedProvider: providerResult.claimedProvider || null,
    officialDomainMatch: domainResult.officialDomainMatch,
    isTrustedProvider: domainResult.isTrustedProvider,
    domainMismatch: domainResult.domainMismatch,
    isCriticalPaymentPhishing,
    paymentRiskContribution: paymentScore,
    structuredReasons,
    reasons,
  };
}
