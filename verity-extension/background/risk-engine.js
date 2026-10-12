import { isTrustedTopDomain } from './rules.js';
import { isAllowlistedDomain } from '../shared/legit-domains.js';
import { SIGNAL_CATEGORY_MAP, CATEGORY_CAPS, t } from '../shared/messages.js';

/**
 * Scaling factor for on-device ML score (0.0 = disabled, 1.0 = standard 0-25 pts).
 */
export let ML_WEIGHT = 1.0;

export function setMlWeight(w) {
  ML_WEIGHT = w;
}

/**
 * Central Verity Risk Engine
 * 
 * Implements:
 * 1. Strict Reason ID-based categorization and routing (no English text parsing).
 * 2. Documented category caps and total score clamp [0, 100].
 * 3. Convergence Rule: Block-level verdict requires >= 2 independent sources
 *    (url, ml, dom_credentials, download, threat_intel).
 * 4. DOM text phrases alone capped at Caution (scam_language cap: 20).
 * 5. Independent Allowlist capped at Caution (max 40) unless download or credential-exfil fires.
 */
export function calculateRisk(
  url,
  ruleSignals = [],
  mlScore = null,
  domSignals = null,
  threatIntel = null,
  redirectSignals = null,
  paymentAnalysis = null,
  downloadSignals = null,
  mlWeightOverride = null
) {
  const activeMlWeight = (mlWeightOverride !== null) ? mlWeightOverride : ML_WEIGHT;
  let hostname = '';
  try { hostname = new URL(url).hostname.toLowerCase(); } catch (e) {}

  // 0. Trusted Top Domain Protection Override
  if (isTrustedTopDomain(hostname) && (!threatIntel || !threatIntel.malware) && (!downloadSignals || !downloadSignals.chromeSaysDangerous)) {
    return {
      url,
      hostname,
      score: 0,
      riskScore: 0,
      severity: 'safe',
      state: 'safe',
      action: 'allow',
      reasons: [],
      signals: [],
      categories: {
        phishing: { flagged: false, confidence: 0, reason: null },
        malware: { flagged: false, source: null },
        scamFraud: { flagged: false, reason: null },
        suspicious: { flagged: false, reason: null }
      },
      paymentAnalysis: null,
      activeSources: []
    };
  }

  const rawSignals = [];
  const categories = {
    phishing: { flagged: false, confidence: 0, reason: null },
    malware: { flagged: false, source: null },
    scamFraud: { flagged: false, reason: null },
    suspicious: { flagged: false, reason: null }
  };

  // Helper to register an emitted signal
  const emitSignal = (id, params = {}, score = 0, source = 'url') => {
    const category = SIGNAL_CATEGORY_MAP[id] || 'url';
    const reasonText = t(id, params);
    rawSignals.push({
      id,
      params,
      score,
      category,
      source,
      reason: reasonText
    });
  };

  // ── 1. Process URL Heuristic Rule Signals ──────────────────────────────────
  ruleSignals.forEach(s => {
    if (!s.triggered) return;
    const sigId = s.id || 'SIG_URL_SUSPICIOUS';
    const source = (sigId === 'RULE_IP_BASED_URL') ? 'url' : 'url';
    emitSignal(sigId, s.params || {}, s.score || 0, source);
  });

  // ── 2. Process ML Signal ───────────────────────────────────────────────────
  if (activeMlWeight > 0 && mlScore !== null && mlScore > 30) {
    const mlScaled = Math.min(Math.round(mlScore * 0.25 * activeMlWeight), Math.round(25 * activeMlWeight));
    if (mlScaled > 0) {
      emitSignal('SIG_ML_PHISHING', { confidence: mlScore }, mlScaled, 'ml');
      categories.phishing.flagged = true;
      categories.phishing.confidence = mlScore;
    }
  }

  // ── 3. Process DOM Signals ─────────────────────────────────────────────────
  const isAllowlisted = isAllowlistedDomain(hostname);

  if (domSignals) {
    // A. DOM Brand Impersonation on unverified domain
    if (!domSignals.isTrustedDomain && !isAllowlisted) {
      const textAndTitle = ((domSignals.pageTitle || '') + ' ' + (domSignals.pageText || '')).toLowerCase();
      const brandKeywords = [
        { name: 'HDFC Bank', keywords: ['hdfc netbanking', 'hdfc bank', 'hdfcbank'] },
        { name: 'SBI', keywords: ['sbi netbanking', 'state bank of india', 'sbi yono', 'onlinesbi'] },
        { name: 'ICICI Bank', keywords: ['icici netbanking', 'icici bank', 'icicibank'] },
        { name: 'Axis Bank', keywords: ['axis bank', 'axisbank'] },
        { name: 'Kotak Bank', keywords: ['kotak bank', 'kotak mahindra'] },
        { name: 'PayPal', keywords: ['paypal'] },
        { name: 'Razorpay', keywords: ['razorpay'] },
        { name: 'Stripe', keywords: ['stripe checkout', 'stripe.com'] },
        { name: 'Paytm', keywords: ['paytm rewards', 'paytm cashback'] },
        { name: 'Netflix', keywords: ['netflix'] }
      ];

      for (const b of brandKeywords) {
        if (b.keywords.some(k => textAndTitle.includes(k))) {
          if (domSignals.hasCredentialCollection || domSignals.hasPasswordInput) {
            emitSignal('SIG_CONTENT_BRAND_IMPERSONATION', { brand: b.name }, 60, 'dom');
            categories.phishing.flagged = true;
            categories.phishing.reason = t('SIG_CONTENT_BRAND_IMPERSONATION', { brand: b.name });
            break;
          }
        }
      }
    }

    // B. Credential Fields on unverified domain
    if (!isAllowlisted) {
      if (domSignals.hasCredentialCollection) {
        emitSignal('SIG_CREDENTIAL_COLLECTION', {}, 15, 'dom');
      } else if (domSignals.hasPasswordInput) {
        emitSignal('SIG_PASSWORD_REQUEST', {}, 10, 'dom');
      }
      if (domSignals.loginFormCount > 0) {
        emitSignal('SIG_LOGIN_FORM', {}, 5, 'dom');
      }
    }

    // C. Scam Language / PUP
    if (domSignals.scam) {
      emitSignal('SIG_SCAM_LANGUAGE', { phrase: domSignals.scamReason }, 10, 'dom');
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = domSignals.scamReason;
    }
    if (domSignals.pup) {
      emitSignal('SIG_PUP', { details: domSignals.pupReason }, 5, 'dom');
      categories.suspicious.flagged = true;
      categories.suspicious.reason = domSignals.pupReason;
    }

    // D. Financial Context
    const highConfidenceFinancialTerms = ['cvv', 'otp', 'upi', 'kyc', 'atm pin', 'mpin', 'bank account', 'account number', 'ifsc', 'net banking', 'netbanking', 'credit card', 'debit card'];
    const hasHighConfidence = domSignals.financialMatches && domSignals.financialMatches.some(m => highConfidenceFinancialTerms.includes(m));

    if (!domSignals.isTrustedDomain && !isAllowlisted && domSignals.financialMatches && domSignals.financialMatches.length >= 2) {
      emitSignal('SIG_FINANCIAL_CONTEXT', { terms: domSignals.financialMatches.slice(0, 3).join(', ') }, 20, 'dom');
    }

    // E. Synergies
    const hasBrandSignal = rawSignals.some(s => s.category === 'brand_impersonation');
    if (hasBrandSignal && domSignals.hasCredentialCollection && !isAllowlisted) {
      emitSignal('SIG_SYNERGY_IMPERSONATION_CREDENTIALS', {}, 30, 'dom');
    } else if (!hasBrandSignal && domSignals.hasCredentialCollection && !isAllowlisted && domSignals.financialMatches && domSignals.financialMatches.length >= 2 && hasHighConfidence) {
      emitSignal('SIG_SYNERGY_FINANCIAL_CREDENTIALS', {}, 35, 'dom');
    }

    const isSuspiciousRedirect = redirectSignals && (redirectSignals.suspicious || (redirectSignals.shortenerDetected && redirectSignals.chain && redirectSignals.chain.length > 2));
    if (isSuspiciousRedirect && domSignals.hasCredentialCollection && !isAllowlisted) {
      emitSignal('SIG_SYNERGY_REDIRECT_CREDENTIALS', {}, 50, 'dom');
    }
  }

  // ── 4. Process Payment Protection Signals ──────────────────────────────────
  if (paymentAnalysis && paymentAnalysis.isPaymentPage && !isAllowlisted) {
    if (paymentAnalysis.structuredReasons && Array.isArray(paymentAnalysis.structuredReasons)) {
      paymentAnalysis.structuredReasons.forEach(r => {
        emitSignal(r.id, r.params || {}, r.score || 0, 'dom');
      });
    }
  }

  // ── 5. Process Threat Intelligence Signals ─────────────────────────────────
  if (threatIntel && threatIntel.malware) {
    emitSignal('THREAT_INTEL_MALWARE', { source: threatIntel.source }, 80, 'threat_intel');
    categories.malware.flagged = true;
    categories.malware.source = threatIntel.source;
  }

  // ── 6. Process Download Protection Signals ──────────────────────────────────
  if (downloadSignals && downloadSignals.analysisContext === 'download') {
    if (downloadSignals.chromeSaysDangerous) {
      emitSignal('DOWNLOAD_CHROME_DANGEROUS', {}, 90, 'download');
      categories.malware.flagged = true;
    }
    if (downloadSignals.executableDownload) {
      emitSignal('DOWNLOAD_EXECUTABLE', { filename: downloadSignals.filename }, downloadSignals.sourceDomainSuspicious ? 45 : 15, 'download');
    }
    if (downloadSignals.scriptDownload) {
      emitSignal('DOWNLOAD_SCRIPT', { filename: downloadSignals.filename, extension: downloadSignals.extension }, downloadSignals.sourceDomainSuspicious ? 40 : 15, 'download');
    }
    if (downloadSignals.installerDownload) {
      emitSignal('DOWNLOAD_INSTALLER', { filename: downloadSignals.filename, extension: downloadSignals.extension }, downloadSignals.sourceDomainSuspicious ? 50 : 35, 'download');
    }
    if (downloadSignals.doubleExtension) {
      emitSignal('DOWNLOAD_DOUBLE_EXTENSION', { apparentExtension: downloadSignals.apparentExtension, extension: downloadSignals.extension }, 55, 'download');
    }
    if (downloadSignals.misleadingFilename) {
      emitSignal('DOWNLOAD_MISLEADING_NAME', { keyword: downloadSignals.suspiciousKeyword }, 25, 'download');
    }
    if (downloadSignals.brandImpersonation) {
      emitSignal('DOWNLOAD_BRAND_IMPERSONATION', { brand: downloadSignals.brandImpersonationName }, 65, 'download');
      categories.phishing.flagged = true;
    }
    if (downloadSignals.sourceDomainMalicious) {
      emitSignal('DOWNLOAD_SOURCE_MALICIOUS', {}, 40, 'download');
      categories.malware.flagged = true;
    }
    if (downloadSignals.archiveDownload && downloadSignals.sourceDomainSuspicious) {
      emitSignal('DOWNLOAD_ARCHIVE', {}, 10, 'download');
    }
  }

  // ── 7. Group by Category and Apply Category Caps ───────────────────────────
  const pointsByCategory = {};
  const signals = [];
  const activeSources = new Set();

  for (const s of rawSignals) {
    const cat = s.category || 'url';
    pointsByCategory[cat] = (pointsByCategory[cat] || 0) + s.score;
    signals.push(s);

    if (s.score > 0) {
      if (['url', 'ip_host', 'malvertising', 'brand_impersonation'].includes(cat)) {
        activeSources.add('url');
      } else if (cat === 'ml') {
        activeSources.add('ml');
      } else if (['dom_credentials', 'payment_phishing'].includes(cat)) {
        activeSources.add('dom_credentials');
      } else if (cat === 'download') {
        activeSources.add('download');
      } else if (cat === 'threat_intel') {
        activeSources.add('threat_intel');
      }
    }
  }

  // Sum capped scores across categories
  let riskScore = 0;
  for (const [cat, rawPoints] of Object.entries(pointsByCategory)) {
    const cap = CATEGORY_CAPS[cat] !== undefined ? CATEGORY_CAPS[cat] : 30;
    const capped = Math.min(rawPoints, cap);
    riskScore += capped;
  }

  // Overall clamp [0, 100]
  riskScore = Math.min(Math.max(riskScore, 0), 100);

  // ── 8. Apply Convergence & Allowlist Rules ──────────────────────────────────
  // A. Independent Allowlist Rule:
  // Pages on legit_domains.json cap at Caution (max 40) unless download or credential-exfil fires
  const hasDangerousDownload = downloadSignals && (downloadSignals.chromeSaysDangerous || (downloadSignals.executableDownload && downloadSignals.sourceDomainMalicious));
  const hasCredentialExfil = false; // exfil monitoring signal flag

  if (isAllowlisted && !hasDangerousDownload && !hasCredentialExfil) {
    riskScore = Math.min(riskScore, 40);
  }

  // B. Convergence Rule:
  // A Block-level verdict (>= 70) must require independent evidence from at least TWO sources
  // (url, ml, dom_credentials, download, threat_intel).
  // Single-source signals (or DOM text alone) can add at most Caution-level score.
  if (riskScore >= 70) {
    const hasOverride = (threatIntel && threatIntel.malware) || (downloadSignals && downloadSignals.chromeSaysDangerous);
    if (!hasOverride && activeSources.size < 2) {
      // Demote to Caution
      riskScore = 65;
    }
  }

  // ── 9. Final Verdict Determination ─────────────────────────────────────────
  let severity = 'safe';
  let action = 'allow';

  if (riskScore >= 70 || (categories.malware.flagged && activeSources.has('threat_intel'))) {
    severity = 'danger';
    action = 'block';
  } else if (riskScore >= 35) {
    severity = 'caution';
    action = 'warn';
  }

  // Keep legacy category flag sync
  if (riskScore >= 70 && !categories.malware.flagged) {
    categories.phishing.flagged = true;
  }

  const reasons = signals.map(s => s.reason);

  return {
    score: riskScore,
    riskScore: riskScore,
    severity: severity,
    state: severity,
    action: action,
    signals: signals,
    categories: categories,
    reasons: reasons,
    ruleScore: pointsByCategory.url || 0,
    activeSources: Array.from(activeSources),
    redirectChain: redirectSignals ? redirectSignals.chain : null,
    shortenerDetected: redirectSignals ? redirectSignals.shortenerDetected : false,
    paymentAnalysis
  };
}
