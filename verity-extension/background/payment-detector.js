/**
 * payment-detector.js — Payment Website Protection
 *
 * Analyzes URL + DOM signals to detect payment phishing.
 * Spec: VERITY_PAYMENT_PROTECTION_ANTIGRAVITY_SPEC-1.md
 *
 * Privacy guarantee: Never reads or transmits actual field values.
 * Only detects structural presence of payment-related fields.
 */

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
  const hasPaymentFields = fields.card || fields.cvv || fields.expiry ||
                           fields.upi || fields.otp || fields.pin;

  const hasPaymentForm = !!(domSignals.hasPaymentForm);

  // Score: keywords + field presence
  let score = 0;
  score += matchedKeywords.length * 8;         // each keyword = 8 pts
  if (hasPaymentFields) score += 30;
  if (hasPaymentForm)   score += 20;
  score = Math.min(score, 100);

  return {
    isPaymentPage: score >= 20 || hasPaymentFields,
    paymentIntentScore: score,
    matchedKeywords,
  };
}

/**
 * Detect which payment provider the page claims to be.
 * Scans page text for known provider aliases.
 * Returns: { claimedProvider: string|null, confidence: number }
 */
function detectClaimedProvider(domSignals, paymentBrands) {
  if (!domSignals || !paymentBrands) return { claimedProvider: null, confidence: 0 };

  const pageText = (domSignals.pageText || '').toLowerCase();
  const pageTitle = (domSignals.pageTitle || '').toLowerCase();
  const combinedText = pageText + ' ' + pageTitle;

  let bestMatch = null;
  let bestScore = 0;

  for (const brand of paymentBrands) {
    let hits = 0;
    for (const alias of (brand.aliases || [])) {
      if (combinedText.includes(alias.toLowerCase())) {
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
 * Returns: { officialDomainMatch, domainMismatch, isTrustedProvider }
 */
function verifyProviderDomain(hostname, claimedProviderObj, paymentBrands) {
  if (!hostname) return { officialDomainMatch: false, domainMismatch: true, isTrustedProvider: false };

  // Check if hostname is ANY trusted payment provider (e.g. paypal.com, stripe.com, razorpay.com)
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
  if (url === 'http://localhost:3000/' || url === 'http://localhost:3000') return null;

  const hostname = safeHostname(url);
  const fields = domSignals.paymentFields || {};

  // 1. Payment intent
  const intentResult = detectPaymentIntent(domSignals);

  // 1b. UPI Debit Trap & Cashback Scam Detection
  const pageText = (domSignals.pageText || '').toLowerCase();
  const hasCashbackClaims = pageText.includes('cashback') || pageText.includes('claim refund') ||
                            pageText.includes('receive money') || pageText.includes('claim payment') ||
                            pageText.includes('prize winner') || pageText.includes('reward points');
  
  const hasUpiDebitLink = (domSignals.hasUpiLink || pageText.includes('upi://pay') || fields.upi);

  let isUpiTrap = false;
  if (hasCashbackClaims && hasUpiDebitLink) {
    isUpiTrap = true;
  }

  // 1c. Digital Arrest / Utility Disconnection Scam Detection
  const isDigitalScam = pageText.includes('electricity connection') || pageText.includes('will be disconnected') ||
                        pageText.includes('digital arrest') || pageText.includes('trai SIM') ||
                        pageText.includes('cbi notice') || pageText.includes('update kyc');

  if (!intent.isPaymentPage && !isUpiTrap && !isDigitalScam) return null; // Not a payment page — skip

  // 2. Claimed provider detection
  const providerResult = detectClaimedProvider(domSignals, paymentBrands);

  // 3. Domain verification
  const domainResult = verifyProviderDomain(
    hostname,
    providerResult.claimedProviderObj || null,
    paymentBrands
  );

  // 4. Build payment risk score per spec weights
  let paymentScore = 0;
  const reasons = [];

  // Card + CVV collection on suspicious (non-official) site
  if ((fields.card || fields.cvv) && domainResult.domainMismatch) {
    paymentScore += 25;
    reasons.push('Card/CVV information requested on unverified payment domain.');
  } else if (fields.card && fields.cvv) {
    // Card + CVV even on unknown domain (no claimed provider)
    paymentScore += 15;
    reasons.push('Card number and CVV fields detected.');
  }

  // OTP in payment context + mismatch
  if (fields.otp && domainResult.domainMismatch) {
    paymentScore += 20;
    reasons.push('OTP collection on unverified payment domain.');
  }

  // Fake payment brand impersonation
  if (providerResult.claimedProvider && domainResult.domainMismatch) {
    paymentScore += 30;
    reasons.push(
      `Page claims to be "${providerResult.claimedProvider}" but domain "${hostname}" is not its official domain.`
    );
  }

  // Official domain mismatch (with a claimed provider)
  if (domainResult.domainMismatch && providerResult.claimedProvider) {
    paymentScore += 25; // on top of impersonation
    reasons.push(`Official domain mismatch: "${hostname}" is not a verified "${providerResult.claimedProvider}" domain.`);
  }

  // Unknown provider + payment fields (brand-new scam detection)
  if (!providerResult.claimedProvider && !domainResult.isTrustedProvider && intentResult.isPaymentPage) {
    paymentScore += 5;
    reasons.push('Payment page from unrecognized/unverified payment provider.');
  }

  // Payment form present
  if (domSignals.hasPaymentForm) {
    reasons.push('Payment form detected on page.');
  }

  // 5. Critical override rule
  // Fake brand + domain mismatch + card/CVV → guaranteed HIGH RISK minimum
  if (isUpiTrap) {
    paymentScore += 85;
    reasons.unshift('CRITICAL DIGITAL SCAM TRAP: Page claims to credit cashback/reward, but embeds a UPI DEBIT transaction (upi://pay) that will DEDUCT money from your account!');
  }

  if (isDigitalScam && !domainResult.officialDomainMatch) {
    paymentScore += 75;
    reasons.unshift('DIGITAL ARREST / BILL SCAM TRAP: Page uses high-pressure utility disconnection or digital arrest threats on an unverified domain.');
  }

  const isCriticalPaymentPhishing = (
    (!domainResult.officialDomainMatch && (fields.card || fields.cvv || fields.otp)) ||
    (providerResult.claimedProvider && domainResult.domainMismatch) ||
    isUpiTrap ||
    isDigitalScam
  );

  if (isCriticalPaymentPhishing) {
    paymentScore = Math.max(paymentScore, 85);
    reasons.unshift('HIGH CONFIDENCE: Payment Phishing — unverified domain requesting payment credentials (Card/CVV/OTP).');
  }

  paymentScore = Math.min(paymentScore, 100);

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
    reasons,
  };
}
