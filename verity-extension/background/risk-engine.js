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
  if (isTrustedTopDomain(hostname) && (!threatIntel || !threatIntel.malware) && (!downloadSignals || !downloadSignals.chromeSaysDangerous) && (!domSignals || !domSignals.hasCrossDomainCredentialAction)) {
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
  (ruleSignals || []).forEach(s => {
    if (!s.triggered) return;
    const sigId = s.id || 'SIG_URL_SUSPICIOUS';
    const source = (sigId === 'RULE_IP_BASED_URL') ? 'url' : 'url';
    emitSignal(sigId, s.params || {}, s.score || 0, source);
  });

  // ── 2. Process ML Signal ───────────────────────────────────────────────────
  if (activeMlWeight > 0 && mlScore !== null && mlScore > 30) {
    const mlScaled = Math.min(Math.round(mlScore * 0.35 * activeMlWeight), Math.round(35 * activeMlWeight));
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

    // Cross-Domain Credential Exfiltration (must trigger even on allowlisted domains)
    if (domSignals.hasCrossDomainCredentialAction) {
      emitSignal('SIG_CROSS_DOMAIN_CREDENTIAL_EXFIL', { targetDomain: domSignals.exfilTargetDomain || 'external' }, 85, 'threat_intel');
      categories.phishing.flagged = true;
    }

    // Cyber Fraud & Exfiltration
    if (domSignals.kycCyberFraud && !isAllowlisted) {
      emitSignal('SIG_KYC_CYBER_FRAUD', { phrase: domSignals.kycCyberFraudReason || 'Fake KYC lure' }, 80, 'dom');
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = domSignals.kycCyberFraudReason || 'Fake KYC/Aadhaar/PAN cyber fraud lure detected';
    }
    if (domSignals.phishingKitWebhookExfil) {
      emitSignal('SIG_PHISHING_KIT_WEBHOOK_EXFIL', { endpoint: domSignals.webhookExfilEndpoint || 'Telegram/Discord webhook' }, 95, 'threat_intel');
      categories.phishing.flagged = true;
      categories.phishing.reason = 'Phishing kit exfiltration endpoint detected';
    }
    if (domSignals.techSupportRemoteScam && !isAllowlisted) {
      emitSignal('SIG_TECH_SUPPORT_REMOTE_SCAM', { helpline: domSignals.techSupportHelpline || 'helpline' }, 85, 'dom');
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = domSignals.techSupportRemoteScamReason || 'Remote desktop tech-support scam lure detected';
    }
    if (domSignals.untrustedScreenShare) {
      emitSignal('SIG_UNTRUSTED_SCREEN_SHARE', {}, 85, 'threat_intel');
      categories.phishing.flagged = true;
      categories.phishing.reason = 'Untrusted screen sharing capture attempt';
    }
    if (domSignals.bitbAttack && !isAllowlisted) {
      emitSignal('SIG_BITB_FAKE_WINDOW_ATTACK', { target: domSignals.bitbTarget || 'identity provider' }, 95, 'dom');
      categories.phishing.flagged = true;
      categories.phishing.reason = domSignals.bitbReason || 'Browser-in-the-Browser fake authentication window detected';
    }
    if (domSignals.aitmReverseProxy && !isAllowlisted) {
      emitSignal('SIG_AITM_REVERSE_PROXY_PHISH', { endpoint: domSignals.aitmReason || 'Proprietary IdP inputs' }, 95, 'dom');
      categories.phishing.flagged = true;
      categories.phishing.reason = 'AiTM reverse-proxy phishing kit detected';
    }
    if (domSignals.maliciousQrPayload && !isAllowlisted) {
      emitSignal('SIG_MALICIOUS_QR_PAYLOAD', { type: domSignals.maliciousQrType || 'Quishing' }, 85, 'dom');
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = 'Malicious QR code payload detected';
    }
    if (domSignals.clipboardAddressSwap) {
      emitSignal('SIG_CLIPBOARD_ADDRESS_SWAP', { type: domSignals.clipboardSwapType || 'Address' }, 95, 'dom');
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = 'Malicious clipboard address swapper detected';
    }
    if (domSignals.roguePushOrSwTrap) {
      emitSignal('SIG_ROGUE_PUSH_OR_SW_TRAP', {}, 75, 'dom');
      categories.suspicious.flagged = true;
      categories.suspicious.reason = 'Rogue push notification or service worker registration blocked';
    }

    // C. Scam Language / PUP / ClickFix
    if (domSignals.clickFixAttack) {
      emitSignal('SIG_CLICKFIX_CLIPBOARD_ATTACK', { phrase: domSignals.clickFixReason }, 85, 'dom');
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = domSignals.clickFixReason || 'ClickFix clipboard command lure detected';
    }
    if (domSignals.scamBonusLure) {
      emitSignal('SIG_SCAM_BONUS_LURE', { phrase: domSignals.scamBonusLurePhrase }, 55, 'dom');
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = domSignals.scamBonusLurePhrase || 'Fake bonus/reward lure detected';
    }
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

  // ── 4b. Process Redirect Protection Signals ────────────────────────────────
  if (redirectSignals && redirectSignals.structuredReasons && Array.isArray(redirectSignals.structuredReasons)) {
    redirectSignals.structuredReasons.forEach(r => {
      emitSignal(r.id, r.params || {}, r.score || 0, r.source || 'redirect');
    });
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
    if (downloadSignals.htmlSmuggling) {
      emitSignal('SIG_HTML_SMUGGLING_DOWNLOAD', { source: downloadSignals.originatingHostname || 'unverified' }, 50, 'download');
      categories.malware.flagged = true;
    }
    if (downloadSignals.remoteAccessScam) {
      emitSignal('SIG_REMOTE_ACCESS_SCAM_DOWNLOAD', { tool: downloadSignals.remoteAccessTool || 'remote access software' }, 90, 'download');
      categories.suspicious.flagged = true;
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
    if (downloadSignals.contentDispositionSpoofed) {
      emitSignal('DOWNLOAD_CONTENT_DISPOSITION_SPOOF', {}, 55, 'download');
      categories.malware.flagged = true;
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
      if (s.source === 'redirect') {
        activeSources.add('redirect');
      }
      if (['url', 'ip_host', 'malvertising', 'brand_impersonation'].includes(cat)) {
        if (s.source !== 'redirect') {
          activeSources.add('url');
        }
      } else if (cat === 'ml') {
        activeSources.add('ml');
      } else if (cat === 'dom_credentials') {
        activeSources.add('dom_credentials');
      } else if (cat === 'payment_phishing') {
        activeSources.add('payment_phishing');
      } else if (cat === 'download') {
        activeSources.add('download');
      } else if (cat === 'threat_intel') {
        activeSources.add('threat_intel');
      }
    }
  }

  // Combine capped scores across categories:
  // Sort category points descending: highest category takes full weight,
  // secondary categories add diminishing marginal risk (factor 0.4)
  // so saturation at 100 is not the normal outcome.
  const cappedScores = [];
  for (const [cat, rawPoints] of Object.entries(pointsByCategory)) {
    const cap = CATEGORY_CAPS[cat] !== undefined ? CATEGORY_CAPS[cat] : 30;
    const capped = Math.min(rawPoints, cap);
    if (capped > 0) cappedScores.push(capped);
  }
  cappedScores.sort((a, b) => b - a);

  const diminishingWeights = [1.0, 0.65, 0.40, 0.25, 0.15];
  let riskScore = 0;
  for (let i = 0; i < cappedScores.length; i++) {
    const weight = i < diminishingWeights.length ? diminishingWeights[i] : 0.10;
    riskScore += Math.round(cappedScores[i] * weight);
  }

  // Pairwise Synergy Bonuses
  const hasRedirect = !!(
    (redirectSignals && (
      redirectSignals.suspicious ||
      redirectSignals.shortenerDetected ||
      redirectSignals.hasShortener ||
      redirectSignals.suspiciousIntermediateDomain ||
      redirectSignals.finalDomainSuspicious ||
      redirectSignals.popunderSpawn ||
      redirectSignals.popunderDetected ||
      (redirectSignals.chain && redirectSignals.chain.length > 1) ||
      (redirectSignals.redirectCount && redirectSignals.redirectCount > 0)
    )) ||
    activeSources.has('redirect')
  );

  // - brand_impersonation + dom_credentials: +20 pts
  if ((pointsByCategory['brand_impersonation'] || 0) > 0 && (pointsByCategory['dom_credentials'] || 0) > 0) {
    riskScore += 20;
  }
  // - payment_phishing + dom_credentials: +25 pts
  if ((pointsByCategory['payment_phishing'] || 0) > 0 && (pointsByCategory['dom_credentials'] || 0) > 0) {
    riskScore += 25;
  }
  // - malvertising + (url or ml or redirect): +20 pts
  if ((pointsByCategory['malvertising'] || 0) > 0 && ((pointsByCategory['url'] || 0) > 0 || (pointsByCategory['ml'] || 0) > 0 || hasRedirect)) {
    riskScore += 20;
  }
  // - url + ml (both >= 20): +15 pts
  if ((pointsByCategory['url'] || 0) >= 20 && (pointsByCategory['ml'] || 0) >= 20) {
    riskScore += 15;
  }

  if (hasRedirect) {
    activeSources.add('redirect');
  }

  // Hard override floors (known malware, chrome dangerous download, credential exfil, clickfix, html smuggling, content disposition spoofing)
  const isSmugglingDanger = downloadSignals && downloadSignals.htmlSmuggling && (
    downloadSignals.executableDownload ||
    downloadSignals.scriptDownload ||
    downloadSignals.installerDownload ||
    downloadSignals.archiveDownload ||
    downloadSignals.isDangerousExtension
  );

  const isSpoofDanger = downloadSignals && downloadSignals.contentDispositionSpoofed && (
    downloadSignals.executableDownload ||
    downloadSignals.scriptDownload ||
    downloadSignals.installerDownload ||
    downloadSignals.archiveDownload ||
    downloadSignals.isDangerousExtension
  );

  const hasDangerousDownload = downloadSignals && (
    downloadSignals.chromeSaysDangerous ||
    (downloadSignals.executableDownload && downloadSignals.sourceDomainMalicious) ||
    isSmugglingDanger ||
    isSpoofDanger
  );
  const hasCredentialExfil = !!(domSignals && domSignals.hasCrossDomainCredentialAction);
  const hasMalwareIntel = !!(threatIntel && threatIntel.malware);
  const hasClickFix = !!(domSignals && domSignals.clickFixAttack);

  // Financial & Cyber-Fraud Overrides
  const hasIllegalWebPinCollection = rawSignals.some(s => s.id === 'SIG_ILLEGAL_WEB_PIN_COLLECTION') ||
                                    !!(domSignals && domSignals.illegalWebPinCollection);
  const hasPhishingKitWebhookExfil = rawSignals.some(s => s.id === 'SIG_PHISHING_KIT_WEBHOOK_EXFIL') ||
                                    !!(domSignals && domSignals.phishingKitWebhookExfil);
  const hasKycCyberFraud = rawSignals.some(s => s.id === 'SIG_KYC_CYBER_FRAUD') ||
                           !!(domSignals && domSignals.kycCyberFraud);
  const hasBrandAssetHotlinkSpoof = rawSignals.some(s => s.id === 'SIG_BRAND_ASSET_HOTLINK_SPOOF') ||
                                   (paymentAnalysis && paymentAnalysis.structuredReasons && paymentAnalysis.structuredReasons.some(r => r.id === 'SIG_BRAND_ASSET_HOTLINK_SPOOF'));
  const hasTechSupportRemoteScam = rawSignals.some(s => s.id === 'SIG_TECH_SUPPORT_REMOTE_SCAM') ||
                                   !!(domSignals && domSignals.techSupportRemoteScam);
  const hasRemoteAccessScamDownload = rawSignals.some(s => s.id === 'SIG_REMOTE_ACCESS_SCAM_DOWNLOAD') ||
                                     !!(downloadSignals && downloadSignals.remoteAccessScam);
  const hasUntrustedScreenShare = rawSignals.some(s => s.id === 'SIG_UNTRUSTED_SCREEN_SHARE') ||
                                  !!(domSignals && domSignals.untrustedScreenShare);
  const hasBitbAttack = rawSignals.some(s => s.id === 'SIG_BITB_FAKE_WINDOW_ATTACK') ||
                        !!(domSignals && domSignals.bitbAttack);
  const hasAitmReverseProxy = rawSignals.some(s => s.id === 'SIG_AITM_REVERSE_PROXY_PHISH') ||
                              !!(domSignals && domSignals.aitmReverseProxy);
  const hasClipboardAddressSwap = rawSignals.some(s => s.id === 'SIG_CLIPBOARD_ADDRESS_SWAP') ||
                                  !!(domSignals && domSignals.clipboardAddressSwap);
  const hasMaliciousQrPayload = rawSignals.some(s => s.id === 'SIG_MALICIOUS_QR_PAYLOAD') ||
                                !!(domSignals && domSignals.maliciousQrPayload);
  const hasRoguePushOrSwTrap = rawSignals.some(s => s.id === 'SIG_ROGUE_PUSH_OR_SW_TRAP') ||
                               !!(domSignals && domSignals.roguePushOrSwTrap);
  const hasPaymentBrandMismatch = rawSignals.some(s => s.id === 'SIG_PAYMENT_BRAND_MISMATCH') ||
                                 (paymentAnalysis && paymentAnalysis.domainMismatch && paymentAnalysis.claimedProvider);
  const hasPaymentOrCredentialDemand = !!(
    (domSignals && (domSignals.hasCredentialCollection || domSignals.hasPasswordInput || domSignals.paymentFields?.card || domSignals.paymentFields?.cvv || domSignals.paymentFields?.otp || domSignals.paymentFields?.pin)) ||
    (paymentAnalysis && (paymentAnalysis.paymentFields?.card || paymentAnalysis.paymentFields?.cvv || paymentAnalysis.paymentFields?.otp || paymentAnalysis.paymentFields?.pin))
  );
  const hasBrandMismatchWithCredentials = hasPaymentBrandMismatch && hasPaymentOrCredentialDemand && !isAllowlisted;

  const hasCyberFraudOverride =
    hasIllegalWebPinCollection ||
    hasPhishingKitWebhookExfil ||
    hasCredentialExfil ||
    hasKycCyberFraud ||
    hasBrandAssetHotlinkSpoof ||
    hasTechSupportRemoteScam ||
    hasRemoteAccessScamDownload ||
    hasUntrustedScreenShare ||
    hasBitbAttack ||
    hasAitmReverseProxy ||
    hasClipboardAddressSwap ||
    hasMaliciousQrPayload ||
    hasRoguePushOrSwTrap ||
    hasBrandMismatchWithCredentials;

  const suspTlds = [
    '.live', '.xyz', '.monster', '.top', '.click', '.sbs', '.cfd', '.icu', '.fun', '.site', '.online',
    '.pw', '.cc', '.ws', '.biz', '.vip', '.club', '.uno', '.bar', '.qpon', '.world',
    '.tk', '.ml', '.ga', '.cf', '.gq', '.rest', '.skin', '.hair', '.boats', '.quest', '.shop', '.buzz', '.lat', '.cyou'
  ];
  const hasSuspiciousTld = suspTlds.some(tld => hostname.endsWith(tld));
  const urlLower = (url || '').toLowerCase();
  const hasPopunderAdKeyword = urlLower.includes('utm_medium=popunder') ||
                              urlLower.includes('utm_medium=popup') ||
                              urlLower.includes('propellerads') ||
                              urlLower.includes('popunder') ||
                              urlLower.includes('popads');
  let isHexQuery = false;
  try {
    const parsed = new URL(url);
    isHexQuery = /^\?[a-f0-9]{16,64}$/i.test(parsed.search);
  } catch (_) {}

  const hasMalvertisingCriticalOverride =
    (pointsByCategory['malvertising'] || 0) >= 50 ||
    rawSignals.some(s => s.id === 'SIG_POPUNDER_SPAWN') ||
    (redirectSignals && (redirectSignals.popunderSpawn || redirectSignals.popunderDetected)) ||
    ((hasPopunderAdKeyword || isHexQuery) && hasSuspiciousTld);

  if (hasIllegalWebPinCollection) {
    riskScore = Math.max(riskScore, 95);
  } else if (hasPhishingKitWebhookExfil) {
    riskScore = Math.max(riskScore, 95);
  } else if (hasBitbAttack) {
    riskScore = Math.max(riskScore, 95);
  } else if (hasAitmReverseProxy) {
    riskScore = Math.max(riskScore, 95);
  } else if (hasClipboardAddressSwap) {
    riskScore = Math.max(riskScore, 95);
  } else if (hasBrandAssetHotlinkSpoof) {
    riskScore = Math.max(riskScore, 90);
  } else if (hasRemoteAccessScamDownload) {
    riskScore = Math.max(riskScore, 90);
  } else if (hasCredentialExfil) {
    riskScore = Math.max(riskScore, 90);
  } else if (hasBrandMismatchWithCredentials) {
    riskScore = Math.max(riskScore, 90);
  } else if (hasKycCyberFraud) {
    riskScore = Math.max(riskScore, 85);
  } else if (hasMaliciousQrPayload) {
    riskScore = Math.max(riskScore, 85);
  } else if (hasTechSupportRemoteScam) {
    riskScore = Math.max(riskScore, 85);
  } else if (hasUntrustedScreenShare) {
    riskScore = Math.max(riskScore, 85);
  } else if (hasClickFix) {
    riskScore = Math.max(riskScore, 85);
  } else if (hasRoguePushOrSwTrap) {
    riskScore = Math.max(riskScore, 80);
  } else if (downloadSignals && downloadSignals.chromeSaysDangerous) {
    riskScore = Math.max(riskScore, 90);
  } else if (isSmugglingDanger || isSpoofDanger) {
    riskScore = Math.max(riskScore, 75);
  } else if (hasMalwareIntel) {
    riskScore = Math.max(riskScore, 85);
  } else if (hasMalvertisingCriticalOverride) {
    riskScore = Math.max(riskScore, 85);
  }

  // Overall clamp [0, 100]
  riskScore = Math.min(Math.max(riskScore, 0), 100);

  // ── Step 4: Piracy & Clean Streaming Sites Protection ─────────────────────
  // Capped at max score 25 (SAFE / allow) when there are no phishing forms, no bank scams, and no ad rotators
  const hasPhishingForms = !!(domSignals && (domSignals.hasCredentialCollection || domSignals.hasPasswordInput || domSignals.loginFormCount > 0));
  const hasFakeBankOrScam = hasCyberFraudOverride || hasKycCyberFraud || hasTechSupportRemoteScam || hasBrandMismatchWithCredentials || hasIllegalWebPinCollection;
  const hasRotatorQuery = !!(url && (
    url.includes('utm_medium=popunder') ||
    url.includes('propellerads') ||
    url.includes('popads') ||
    url.includes('wigglepoploaderfast') ||
    /\?[a-f0-9]{16,64}/i.test(url)
  ));
  const isPurePiracyOrSuspiciousTld = signals.length > 0 && signals.every(s => 
    s.id === 'RULE_PIRACY_MEDIA' || 
    s.id === 'RULE_SUSPICIOUS_URL_PATTERN' ||
    s.id === 'SIG_URL_SUSPICIOUS'
  );

  if (isPurePiracyOrSuspiciousTld && !hasPhishingForms && !hasFakeBankOrScam && !hasRotatorQuery) {
    riskScore = Math.min(riskScore, 25);
  }

  // ── 8. Apply Convergence & Allowlist Rules ──────────────────────────────────
  // A. Independent Allowlist Rule:
  // Pages on legit_domains.json cap at Caution (max 40) unless dangerous download, credential-exfil, ClickFix, or malvertising override fires
  if (isAllowlisted && !hasDangerousDownload && !hasCredentialExfil && !hasPhishingKitWebhookExfil && !hasClickFix && !hasMalvertisingCriticalOverride && !hasRemoteAccessScamDownload && !hasBrandAssetHotlinkSpoof && !hasTechSupportRemoteScam && !hasBitbAttack && !hasAitmReverseProxy && !hasClipboardAddressSwap && !hasMaliciousQrPayload) {
    riskScore = Math.min(riskScore, 40);
  }

  // B. Convergence Rule:
  // A Block-level verdict (>= 70) strictly requires independent evidence from at least TWO sources
  // (url, ml, dom_credentials, download, threat_intel), unless a hard override fires.
  // Single-source signals can add at most Caution-level score (demoted to 65).
  // Malvertising corroborated by url (>= 20), ml (>= 15), or redirect can reach Block without dom_credentials.
  const isCorroboratedMalvertising = (pointsByCategory['malvertising'] || 0) >= 45 && (
    (pointsByCategory['url'] || 0) >= 20 ||
    (pointsByCategory['ml'] || 0) >= 15 ||
    hasRedirect
  );

  if (riskScore >= 70) {
    const hasOverride = hasMalwareIntel ||
      (downloadSignals && downloadSignals.chromeSaysDangerous) ||
      hasDangerousDownload ||
      hasCredentialExfil ||
      hasClickFix ||
      hasMalvertisingCriticalOverride ||
      hasCyberFraudOverride ||
      isCorroboratedMalvertising;
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

  const reasons = signals.map(s => s.reason).filter(Boolean);

  // ── Step 3.2: Unbreakable Invariants ───────────────────────────────────────
  // 1. Allowlisted domains without explicit active download/credential exfil must return score 0, allow, safe
  if (isAllowlisted && !hasDangerousDownload && !hasCredentialExfil) {
    return {
      url,
      hostname,
      score: 0,
      riskScore: 0,
      severity: 'safe',
      state: 'safe',
      action: 'allow',
      signals: [],
      categories: {
        phishing: { flagged: false, confidence: 0, reason: null },
        malware: { flagged: false, source: null },
        scamFraud: { flagged: false, reason: null },
        suspicious: { flagged: false, reason: null }
      },
      reasons: [],
      ruleScore: 0,
      activeSources: [],
      redirectChain: null,
      shortenerDetected: false,
      paymentAnalysis: null
    };
  }

  // 2. Zero reasons must mathematically force score = 0, action = allow, severity = safe
  if (!reasons || reasons.length === 0) {
    riskScore = 0;
    severity = 'safe';
    action = 'allow';
  }

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
