/**
 * verdict.js - Combines rule signals, ML score, DOM heuristics, and Threat Intel into a multi-category verdict.
 */

function calculateRuleScore(ruleSignals) {
  let totalScore = 0;
  for (const signal of ruleSignals) {
    if (signal.triggered) {
      totalScore += signal.score;
    }
  }
  return Math.min(Math.max(totalScore, 0), 100);
}

/**
 * Calculates the final multi-category verdict.
 */
export function calculateVerdict(ruleSignals, mlScore = null, domSignals = null, threatIntel = null) {
  const ruleScore = calculateRuleScore(ruleSignals);
  
  let phishScore = ruleScore;
  if (mlScore !== null) {
    phishScore = Math.max(ruleScore, mlScore);
  }
  phishScore = Math.min(Math.max(phishScore, 0), 100);
  
  const phishingReasons = ruleSignals
    .filter(signal => signal.triggered && signal.reason)
    .map(signal => signal.reason);

  const categories = {
    phishing: { 
      flagged: phishScore >= 60, 
      confidence: phishScore, 
      reason: phishingReasons.join(' ') || null 
    },
    malware: { 
      flagged: false, 
      source: null 
    },
    scamFraud: { 
      flagged: false, 
      reason: null 
    },
    suspicious: { 
      flagged: false, 
      reason: null 
    }
  };

  if (threatIntel && threatIntel.malware) {
    categories.malware.flagged = true;
    categories.malware.source = threatIntel.source;
  }

  if (domSignals && domSignals.scam) {
    categories.scamFraud.flagged = true;
    categories.scamFraud.reason = domSignals.scamReason;
  }

  if (domSignals && domSignals.pup) {
    categories.suspicious.flagged = true;
    categories.suspicious.reason = domSignals.pupReason;
  }

  // Calculate overall state
  let state = "safe";
  
  if (categories.phishing.flagged || categories.malware.flagged || categories.scamFraud.flagged || categories.suspicious.flagged) {
    state = "danger";
  } else if (phishScore >= 30) {
    state = "caution";
  }

  let aggregatedReasons = [];
  if (categories.phishing.flagged) aggregatedReasons.push(`Phishing detected. ${categories.phishing.reason || ''}`.trim());
  else if (phishScore >= 30) aggregatedReasons.push(`Suspicious URL. ${categories.phishing.reason || ''}`.trim());
  
  if (categories.malware.flagged) aggregatedReasons.push(`Malware detected by ${categories.malware.source}`);
  if (categories.scamFraud.flagged) aggregatedReasons.push(`Scam pattern detected: ${categories.scamFraud.reason}`);
  if (categories.suspicious.flagged) aggregatedReasons.push(`Suspicious behavior detected: ${categories.suspicious.reason}`);

  return {
    score: phishScore, // Legacy mapping for popup UI
    overallState: state,
    state: state,      // Legacy mapping
    categories: categories,
    reasons: aggregatedReasons,
    ruleScore: ruleScore
  };
}
