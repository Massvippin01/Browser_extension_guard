/**
 * risk-engine.js - Adaptive Risk Engine aggregating multiple independent signals.
 */

export function calculateRisk(url, ruleSignals = [], mlScore = null, domSignals = null, threatIntel = null, redirectSignals = null) {
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

  // 1. URL Signals (0-30 points)
  let urlScore = 0;
  let urlReasons = [];
  ruleSignals.forEach(s => {
    if (s.triggered && s.reason && !s.reason.includes('brand')) { // exclude brand from raw URL score
      const scaled = Math.min(Math.round(s.score * 0.3), 30);
      urlScore += scaled;
      urlReasons.push(s.reason);
    }
  });
  if (urlScore > 0) {
    urlScore = Math.min(urlScore, 30);
    addSignal('url', urlScore, urlReasons.join(' '));
  }

  // 2. Local ML Signals (0-25 points)
  if (mlScore !== null && mlScore > 30) {
    const mlScaled = Math.min(Math.round(mlScore * 0.25), 25);
    addSignal('ml', mlScaled, 'On-device ML model flagged structural phishing characteristics.');
    categories.phishing.flagged = true;
    categories.phishing.confidence = mlScore;
  }

  // 3. Brand Impersonation (0-40 points)
  const brandSignal = ruleSignals.find(s => s.triggered && s.reason && s.reason.includes('name'));
  if (brandSignal) {
    addSignal('brand_impersonation', 40, brandSignal.reason);
    categories.phishing.flagged = true;
    categories.phishing.reason = brandSignal.reason;
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
  if (domSignals && domSignals.financialMatches && domSignals.financialMatches.length > 0) {
    addSignal('financial_context', 20, `Financial terminology detected: ${domSignals.financialMatches.slice(0, 3).join(', ')}.`);
  }
  
  // Synergy Penalties
  if (brandSignal && domSignals && domSignals.hasCredentialCollection) {
    addSignal('synergy_impersonation_credentials', 30, 'High risk: Impersonating a trusted brand while requesting sensitive credentials.');
  } else if (!brandSignal && domSignals && domSignals.hasCredentialCollection && domSignals.financialMatches && domSignals.financialMatches.length > 0) {
    addSignal('synergy_financial_credentials', 35, 'High risk: Unverified site requesting financial credentials.');
  }
  if (redirectSignals && redirectSignals.suspicious && domSignals && domSignals.hasCredentialCollection) {
    addSignal('synergy_redirect_credentials', 30, 'High risk: Suspicious redirect routing to a credential collection page.');
  }

  // 6. Threat Intelligence (0-50 points)
  if (threatIntel && threatIntel.malware) {
    addSignal('threat_intel', 50, `Flagged as malicious by ${threatIntel.source}.`);
    categories.malware.flagged = true;
    categories.malware.source = threatIntel.source;
  }
  
  // 7. Redirect Intelligence
  if (redirectSignals && redirectSignals.suspicious) {
    addSignal('redirect', 20, redirectSignals.reason);
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
    ruleScore: urlScore // For metrics logging
  };
}
