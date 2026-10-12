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

  // Mechanism Fix: Require a claim in page structure (document.title, form action, or logo alt/structural text),
  // NOT body text alone. Educational or news articles mentioning payment providers in body text must not trigger.
  const pageTitle = (domSignals.pageTitle || '').toLowerCase();
  const formActions = Array.isArray(domSignals.formActions) ? domSignals.formActions.join(' ').toLowerCase() : '';
  const structuralText = (domSignals.structuralText || '').toLowerCase();
  const structuralContext = `${pageTitle} ${formActions} ${structuralText}`.trim();

  if (!structuralContext) {
    return { claimedProvider: null, confidence: 0 };
  }

  let bestMatch = null;
  let bestScore = 0;

  for (const brand of paymentBrands) {
    let hits = 0;
    for (const alias of (brand.aliases || [])) {
      if (structuralContext.includes(alias.toLowerCase())) {
        hits++;
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
    confidence: Math.min(bestScore * 30, 100),
  };
}

/**
 * Check if the actual domain matches the claimed payment provider's official domains.
 */
function verifyProviderDomain(hostname, claimedProviderObj, paymentBrands) {
  if (!hostname) return { officialDomainMatch: false, domainMismatch: true, isTrustedProvider: false };

  // If the host is on the independent allowlist, it is inherently legitimate
  if (isAllowlistedDomain(hostname)) {
    return {
      officialDomainMatch: true,
      domainMismatch: false,
      isTrustedProvider: true
    };
  }

  // Check if hostname is ANY trusted payment provider
  const isTrustedProvider = (paymentBrands || []).some(brand =>
    (brand.domains || []).some(d => hostname === d || hostname.endsWith('.' + d))
  );

  if (!claimedProviderObj) {
    return {
      officialDomainMatch: isTrustedProvider,
      domainMismatch: !isTrustedProvider,
      isTrustedProvider
    };
  }

  // Check if hostname matches the CLAIMED provider specifically
  const officialDomainMatch = (claimedProviderObj.domains || []).some(d =>
    hostname === d || hostname.endsWith('.' + d)
  );

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

  if (!intentResult.isPaymentPage && !isUpiTrap && !isDigitalScam) return null; // Not a payment page — skip

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

  // Fake payment brand impersonation
  if (providerResult.claimedProvider && domainResult.domainMismatch) {
    paymentScore += 50;
    structuredReasons.push({
      id: 'PAYMENT_FAKE_PROVIDER',
      params: { claimedProvider: providerResult.claimedProvider, hostname },
      score: 50
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
    (!domainResult.officialDomainMatch && (fields.card || fields.cvv || fields.otp)) ||
    (providerResult.claimedProvider && domainResult.domainMismatch) ||
    isUpiTrap ||
    isDigitalScam
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
