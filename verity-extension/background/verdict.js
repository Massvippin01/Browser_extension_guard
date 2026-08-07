/**
 * verdict.js - Combines rule signals and ML score into a final risk verdict.
 */

/**
 * Normalizes a rule score, ensuring it does not exceed 100.
 * @param {Array} ruleSignals - Array of rule result objects: { score, reason, triggered }
 * @returns {number}
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
 * Calculates the final verdict.
 * @param {Array} ruleSignals - Array of rule result objects: { score, reason, triggered }
 * @param {number|null} mlScore - The optional machine learning score (0-100).
 * @returns {Object} { score: number, state: string, reasons: string[] }
 */
export function calculateVerdict(ruleSignals, mlScore = null) {
  const ruleScore = calculateRuleScore(ruleSignals);
  
  let finalScore = ruleScore;

  // TODO: STAGE 2
  // Replace this null value with the ONNX model inference result.
  // The ONNX model should return a normalized 0-100 risk score.
  // No changes to the rule engine or UI should be required.
  if (mlScore !== null) {
    // For Stage 2, we can decide how to weight the ML score vs Rule score.
    // E.g., finalScore = Math.max(ruleScore, mlScore) or an average.
    // For now, if provided, we'll just take the higher of the two.
    finalScore = Math.max(ruleScore, mlScore);
  }

  // Ensure final score is clamped between 0 and 100
  finalScore = Math.min(Math.max(finalScore, 0), 100);
  
  // Extract human-readable reasons from triggered rules
  const reasons = ruleSignals
    .filter(signal => signal.triggered && signal.reason)
    .map(signal => signal.reason);

  // Map score to state
  let state = "safe";
  if (finalScore >= 60) {
    state = "danger";
  } else if (finalScore >= 30) {
    state = "caution";
  }

  return {
    score: finalScore,
    state: state,
    reasons: reasons,
    ruleScore: ruleScore
  };
}
