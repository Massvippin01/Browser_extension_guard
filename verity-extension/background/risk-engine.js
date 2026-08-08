import { isTrustedTopDomain } from './rules.js';

export function calculateRisk(url, ruleSignals = [], mlScore = null, domSignals = null, threatIntel = null, redirectSignals = null, paymentAnalysis = null, downloadSignals = null) {
  let hostname = '';
  try { hostname = new URL(url).hostname; } catch(e) {}

  // Trusted Top Domain Protection Override (prevents false positives on official auth infrastructure)
  if ((isTrustedTopDomain(hostname) || url === 'http://localhost:3000/' || url === 'http://localhost:3000') && (!threatIntel || !threatIntel.malware)) {
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
      paymentAnalysis: null
    };
  }

  let riskScore = 0;
  const signals = [];
  const categories = {
    phishing: { flagged: false, confidence: 0, reason: null },
    malware: { flagged: false, source: null },
    scamFraud: { flagged: false, reason: null },
    suspicious: { flagged: false, reason: null }
  };

  const addSignal = (category, score, reason) => {
    riskScore += score;
    signals.push({ category, score, reason });
  };

  // 1. URL Signals (0-30 points for normal rules)
  let urlScore = 0;
  let urlReasons = [];
  let malvertScore = 0;
  let malvertReasons = [];

  ruleSignals.forEach(s => {
    if (!s.triggered || !s.reason) return;
    // Malvertising / ad-redirect rules get their own high-confidence track
    if (s.reason.includes('ad-redirect') || s.reason.includes('asterisk') || 
        s.reason.includes('Extremely long URL') || s.reason.includes('encoded payload') ||
        s.reason.includes('tracking fingerprint') || s.reason.includes('redirect routing') ||
        s.reason.includes('randomly generated') || s.reason.includes('high-risk TLD') ||
        s.reason.includes('Unusually long URL') || s.reason.includes('tracking pattern') ||
        s.reason.includes('Tracking Network') || s.reason.includes('piracy') || s.reason.includes('media')) {
      malvertScore += Math.round(s.score * 0.85);
      malvertReasons.push(s.reason);
    } else if (!s.reason.includes('brand')) {
      // Normal URL signals (exclude brand — handled separately)
      const scaled = Math.min(Math.round(s.score * 0.3), 30);
      urlScore += scaled;
      urlReasons.push(s.reason);
    }
  });

  if (urlScore > 0) {
    urlScore = Math.min(urlScore, 30);
    addSignal('url', urlScore, urlReasons.join(' '));
  }

  // Malvertising signals — uncapped up to 85 points independently
  if (malvertScore > 0) {
    malvertScore = Math.min(malvertScore, 85);
    addSignal('malvertising', malvertScore, malvertReasons.join(' '));
    categories.suspicious.flagged = true;
    categories.suspicious.reason = malvertReasons[0];
  }

  // 2. Local ML Signals (0-25 points)
  if (mlScore !== null && mlScore > 30) {
    const mlScaled = Math.min(Math.round(mlScore * 0.25), 25);
    addSignal('ml', mlScaled, 'On-device ML model flagged structural phishing characteristics.');
    categories.phishing.flagged = true;
    categories.phishing.confidence = mlScore;
  }

  // 3. Brand Impersonation (0-60 points)
  const brandSignal = ruleSignals.find(s => s.triggered && s.reason && s.reason.includes('name'));
  if (brandSignal) {
    addSignal('brand_impersonation', 40, brandSignal.reason);
    categories.phishing.flagged = true;
    categories.phishing.reason = brandSignal.reason;
  }

  // 3b. Content-based Brand Impersonation (detects fake bank logins like HDFC NetBanking)
  if (domSignals && !domSignals.isTrustedDomain) {
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
      { name: 'Paytm', keywords: ['paytm rewards', 'paytm cashback', 'paytm'] },
      { name: 'Netflix', keywords: ['netflix'] }
    ];

    for (const b of brandKeywords) {
      if (b.keywords.some(k => textAndTitle.includes(k))) {
        if (domSignals.hasCredentialCollection || domSignals.hasPasswordInput) {
          addSignal('content_brand_impersonation', 60, `Page claims to be "${b.name}" while requesting login credentials on an unverified domain.`);
          categories.phishing.flagged = true;
          categories.phishing.reason = `Page claims to be "${b.name}" while requesting credentials on an unverified domain.`;
          break;
        }
      }
    }
  }

  // 4. DOM / Page Analysis (0-20 points) & Fake Login Detection
  if (domSignals) {
    let domScore = 0;
    const domReasons = [];
    
    if (domSignals.hasCredentialCollection) {
      domScore += 15;
      domReasons.push('Page requests sensitive credentials or payment information.');
    } else if (domSignals.hasPasswordInput) {
      domScore += 10;
      domReasons.push('Page requests a password.');
    }
    
    if (domSignals.loginFormCount > 0) {
      domScore += 5;
      domReasons.push('Login form detected.');
    }
    
    if (domScore > 0) {
      addSignal('dom_analysis', Math.min(domScore, 20), domReasons.join(' '));
    }
    
    if (domSignals.scam) {
      addSignal('scam_language', 10, domSignals.scamReason);
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = domSignals.scamReason;
    }
    if (domSignals.pup) {
      addSignal('pup', 5, domSignals.pupReason);
      categories.suspicious.flagged = true;
      categories.suspicious.reason = domSignals.pupReason;
    }
  }

  // 5. Financial Context Engine (0-20 points)
  // Require at least 2 specific financial terms to avoid false positives
  // from common words like 'trading', 'wallet', 'payment' on legitimate sites.
  const highConfidenceFinancialTerms = ['cvv', 'otp', 'upi', 'kyc', 'atm pin', 'mpin', 'bank account', 'account number', 'ifsc', 'net banking', 'netbanking', 'credit card', 'debit card'];
  const hasHighConfidenceFinancialTerm = domSignals && domSignals.financialMatches &&
    domSignals.financialMatches.some(m => highConfidenceFinancialTerms.includes(m));
  
  if (!domSignals?.isTrustedDomain && domSignals?.financialMatches?.length >= 2) {
    addSignal('financial_context', 20, `Financial terminology detected: ${domSignals.financialMatches.slice(0, 3).join(', ')}.`);
  }
  
  // Synergy Penalties — require strong corroborating evidence
  if (brandSignal && domSignals && domSignals.hasCredentialCollection && !domSignals.isTrustedDomain) {
    addSignal('synergy_impersonation_credentials', 30, 'High risk: Impersonating a trusted brand while requesting sensitive credentials.');
  } else if (!brandSignal && domSignals && domSignals.hasCredentialCollection && !domSignals.isTrustedDomain &&
             domSignals.financialMatches && domSignals.financialMatches.length >= 2 && hasHighConfidenceFinancialTerm) {
    // Must have 2+ financial terms AND at least one high-confidence term (cvv, otp, upi...)
    addSignal('synergy_financial_credentials', 35, 'High risk: Unverified site requesting financial credentials.');
  }
  
  const isSuspiciousRedirect = redirectSignals && (redirectSignals.suspicious || (redirectSignals.shortenerDetected && redirectSignals.chain && redirectSignals.chain.length > 2));
  if (isSuspiciousRedirect && domSignals && domSignals.hasCredentialCollection && !domSignals.isTrustedDomain) {
    addSignal('synergy_redirect_credentials', 50, 'Critical risk: Suspicious or multi-hop redirect routing to a credential collection page.');
  }

  // 8. Payment Protection (spec: VERITY_PAYMENT_PROTECTION_ANTIGRAVITY_SPEC-1.md)
  if (paymentAnalysis && paymentAnalysis.isPaymentPage) {
    const pa = paymentAnalysis;

    // Fake payment brand impersonation
    if (pa.claimedProvider && pa.domainMismatch) {
      addSignal('payment_brand_impersonation', 30,
        `Fake payment provider: page claims to be "${pa.claimedProvider}" but domain is not its official domain.`);
    }

    // Official domain mismatch (with claimed provider)
    if (pa.domainMismatch && pa.claimedProvider) {
      addSignal('payment_domain_mismatch', 25,
        `Payment domain mismatch: "${pa.claimedProvider}" is not served from its verified domain.`);
    }

    // Card + CVV on suspicious (non-official) site
    if ((pa.paymentFields.card || pa.paymentFields.cvv) && pa.domainMismatch) {
      addSignal('payment_card_cvv_mismatch', 25,
        'Card/CVV collection on unverified payment domain — high-confidence payment phishing signal.');
    }

    // OTP collection in payment context on unverified domain
    if (pa.paymentFields.otp && pa.domainMismatch) {
      addSignal('payment_otp_mismatch', 20,
        'OTP/verification code requested on unverified payment domain.');
    }

    // Unknown provider + payment page
    if (!pa.claimedProvider && !pa.isTrustedProvider) {
      addSignal('payment_unknown_provider', 5,
        'Payment page served from unrecognized payment provider.');
    }

    // Critical override: payment phishing → minimum score 80
    if (pa.isCriticalPaymentPhishing) {
      riskScore = Math.max(riskScore, 80);
      categories.phishing.flagged = true;
      categories.phishing.reason = 'High-confidence payment phishing detected.';
    }
  }

  // 6. Threat Intelligence (0-50 points)
  if (threatIntel && threatIntel.malware) {
    addSignal('threat_intel', 50, `Flagged as malicious by ${threatIntel.source}.`);
    categories.malware.flagged = true;
    categories.malware.source = threatIntel.source;
  }
  
  // 7. Redirect Intelligence
  if (redirectSignals && redirectSignals.analysisContext === 'redirect') {
    let penalty = 0;
    const redirectReasons = [];
    
    if (redirectSignals.shortenerDetected) {
      if (redirectSignals.crossDomainRedirectCount > 0) {
         penalty += 15;
         redirectReasons.push(`Shortened link redirects across ${redirectSignals.crossDomainRedirectCount} different domains.`);
      }
    }
    
    if (redirectSignals.excessiveRedirects) {
      penalty += 15;
      redirectReasons.push('Excessive redirects detected in the chain.');
    }
    
    if (redirectSignals.suspiciousIntermediateDomain) {
      penalty += 20;
      redirectReasons.push('Redirect chain contains a suspicious intermediate domain.');
    }
    
    if (redirectSignals.finalDomainSuspicious) {
      penalty += 25;
      redirectReasons.push('Final redirect destination is a suspicious domain.');
    }
    
    if (redirectSignals.httpsDowngrade) {
      penalty += 10;
      redirectReasons.push('Redirected from a secure HTTPS connection to an insecure HTTP site.');
    }
    
    if (redirectSignals.redirectLoop) {
      redirectReasons.push('Redirect loop detected.');
    }
    
    if (!redirectSignals.shortenerDetected && redirectSignals.crossDomainRedirectCount > 1) {
      penalty += 10;
      redirectReasons.push('Multiple cross-domain redirects detected.');
    }

    if (penalty > 0 || redirectReasons.length > 0) {
      addSignal('redirect', penalty, redirectReasons.join(' '));
    }
  }

  // 8. Download Protection Signals
  if (downloadSignals && downloadSignals.analysisContext === 'download') {
    let dlScore = 0;
    const dlReasons = [];

    // Chrome-confirmed dangerous — highest priority signal
    if (downloadSignals.chromeSaysDangerous) {
      dlScore += 60;
      dlReasons.push(`Chrome identified this download as dangerous (${downloadSignals.chromeDangerState}).`);
    }

    // Strong combo: executable/script from a suspicious or malicious source
    if ((downloadSignals.executableDownload || downloadSignals.scriptDownload) && downloadSignals.sourceDomainSuspicious) {
      dlScore += 35;
      dlReasons.push('Executable or script download from a suspicious source domain.');
    } else if (downloadSignals.executableDownload || downloadSignals.scriptDownload) {
      dlScore += 10;
      dlReasons.push(`High-risk file type downloaded (${downloadSignals.extension}).`);
    }

    // Installer download (APK, EXE, MSI) adds substantial risk when unverified
    if (downloadSignals.installerDownload && downloadSignals.sourceDomainSuspicious) {
      dlScore += 45;
      dlReasons.push('Installer/APK download from a suspicious source domain.');
    } else if (downloadSignals.installerDownload) {
      dlScore += 35;
      dlReasons.push(`Installer/APK file downloaded (${downloadSignals.extension}).`);
    }

    // Double extension — high risk regardless of source
    if (downloadSignals.doubleExtension) {
      dlScore += 50;
      dlReasons.push(`Double extension: file appears to be "${downloadSignals.apparentExtension}" but is actually "${downloadSignals.extension}".`);
    }

    // Misleading filename keyword
    if (downloadSignals.misleadingFilename && downloadSignals.suspiciousKeyword) {
      dlScore += 25;
      dlReasons.push(`Misleading filename pattern: "${downloadSignals.suspiciousKeyword}".`);
    }

    // Brand impersonation via filename (e.g. sbi_yono_rewards.apk not from sbi.co.in)
    if (downloadSignals.brandImpersonation) {
      dlScore += 65;
      dlReasons.push(`Filename impersonates "${downloadSignals.brandImpersonationName}" but download is not from their official domain.`);
      categories.phishing.flagged = true;
    }

    // Source domain explicitly malicious
    if (downloadSignals.sourceDomainMalicious) {
      dlScore += 40;
      dlReasons.push('Download source domain has been flagged as malicious.');
      categories.malware.flagged = true;
    }

    // Archive — supporting signal only (not auto-malware)
    if (downloadSignals.archiveDownload && downloadSignals.sourceDomainSuspicious) {
      dlScore += 8;
      dlReasons.push('Archive download from a suspicious source domain.');
    }

    // Redirect chain + executable combo
    if (downloadSignals.shortenerDetected && (downloadSignals.executableDownload || downloadSignals.scriptDownload)) {
      dlScore += 20;
      dlReasons.push('Executable download routed through a URL shortener.');
    }

    if (dlScore > 0) {
      addSignal('download_protection', Math.min(dlScore, 80), dlReasons.join(' '));
    }
  }

  riskScore = Math.min(Math.max(riskScore, 0), 100);

  // Determine Severity and Action
  let severity = "safe";
  let action = "allow";
  
  if (riskScore >= 70 || categories.malware.flagged) {
    severity = "danger";
    action = "block";
  } else if (riskScore >= 35) {
    severity = "caution";
    action = "warn";
  }

  // Generate aggregate reasons for legacy/overlay support
  const reasons = signals.map(s => s.reason);

  return {
    score: riskScore, // Map riskScore to legacy score property
    riskScore: riskScore,
    severity: severity,
    state: severity, // Map to legacy state property
    action: action, // ENFORCEMENT DECISION (allow, warn, block)
    signals: signals,
    categories: categories,
    reasons: reasons,
    ruleScore: urlScore, // For metrics logging
    redirectChain: redirectSignals ? redirectSignals.chain : null,
    shortenerDetected: redirectSignals ? redirectSignals.shortenerDetected : false
  };
}
