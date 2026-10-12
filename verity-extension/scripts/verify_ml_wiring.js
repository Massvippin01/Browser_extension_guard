import fs from 'fs';
import * as re from '../background/risk-engine.js';

const mlScores = JSON.parse(fs.readFileSync('benchmark/ml_scores.json', 'utf8'));
const data = JSON.parse(fs.readFileSync('benchmark/test_urls.json', 'utf8'));
const testPhish = data.filter(d => d.split === 'test' && d.label === 'phishing').slice(0, 10);

console.log('=== PROVING ML CONTRIBUTION IS WIRED (10 SAMPLE URLs) ===');
for (let i = 0; i < testPhish.length; i++) {
  const u = testPhish[i].url;
  const v2Score = mlScores[u] ? mlScores[u].v2_score : 50;

  // With ML_WEIGHT = 0 (disabled)
  const verdictWeight0 = re.calculateRisk(u, [], v2Score, null, null, null, null, null, 0.0);
  const mlSignal0 = verdictWeight0.signals.find(s => s.category === 'ml');

  // With ML_WEIGHT = 1.0 (enabled)
  const verdictWeight1 = re.calculateRisk(u, [], v2Score, null, null, null, null, null, 1.0);
  const mlSignal1 = verdictWeight1.signals.find(s => s.category === 'ml');

  console.log(`[URL ${i+1}] ${u.substring(0, 65)}`);
  console.log(`  Raw v2 ML Probability Score: ${v2Score}/100`);
  console.log(`  ML Term (ML_WEIGHT = 0.0): ${mlSignal0 ? mlSignal0.score : 0} pts (Final Engine Risk Score: ${verdictWeight0.riskScore})`);
  console.log(`  ML Term (ML_WEIGHT = 1.0): ${mlSignal1 ? mlSignal1.score : 0} pts (Final Engine Risk Score: ${verdictWeight1.riskScore})`);
}
