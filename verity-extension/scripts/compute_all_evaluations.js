import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import * as rules from '../background/rules.js';
import * as re from '../background/risk-engine.js';
import brands from '../brands.json' with { type: 'json' };

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataPath = path.resolve(__dirname, '../benchmark/test_urls.json');
const mlScoresPath = path.resolve(__dirname, '../benchmark/ml_scores.json');

const items = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
const mlScores = JSON.parse(fs.readFileSync(mlScoresPath, 'utf8'));

console.log(`[Evaluator] Computing rule and ML signals for ${items.length} URLs...`);

const evaluated = [];

for (const item of items) {
  const u = item.url;
  const ml = mlScores[u] || { old_score: 0, v2_score: 0, v2_prob: 0.0 };

  const ruleResults = [
    { name: 'isIpBasedUrl', ...rules.isIpBasedUrl(u) },
    { name: 'hasMissingHttps', ...rules.hasMissingHttps(u) },
    { name: 'hasExcessiveSubdomains', ...rules.hasExcessiveSubdomains(u) },
    { name: 'hasBrandNameInWrongDomain', ...rules.hasBrandNameInWrongDomain(u, brands) },
    { name: 'hasSuspiciousUrlPattern', ...rules.hasSuspiciousUrlPattern(u) },
    { name: 'hasPunycodeOrKeywords', ...rules.hasPunycodeOrKeywords(u) },
    { name: 'hasFinancialKeywordInHostname', ...rules.hasFinancialKeywordInHostname(u, brands) },
    { name: 'hasBrandVariantMatch', ...rules.hasBrandVariantMatch(u, brands) },
    { name: 'hasMalvertisingPattern', ...rules.hasMalvertisingPattern(u) },
    { name: 'hasRandomLookingHostname', ...rules.hasRandomLookingHostname(u) },
    { name: 'hasAffiliateTrackerPattern', ...rules.hasAffiliateTrackerPattern(u) },
    { name: 'hasPiracyOrUnverifiedMediaPattern', ...rules.hasPiracyOrUnverifiedMediaPattern(u) }
  ];

  const firingRules = ruleResults.filter(r => r.triggered);
  const signals = ruleResults.map(r => ({ score: r.score, reason: r.reason, triggered: r.triggered }));

  // Rules-only score
  const rulesVerdict = re.calculateRisk(u, signals, null, null, null, null, null, null, 0.0);

  // Additive V2 (rules + ML up to 25 pts)
  const additiveVerdict = re.calculateRisk(u, signals, ml.v2_score, null, null, null, null, null, 1.0);

  // Old ML
  const oldMlVerdict = re.calculateRisk(u, signals, ml.old_score, null, null, null, null, null, 1.0);

  evaluated.push({
    ...item,
    rules_score: rulesVerdict.score,
    rules_verdict: rulesVerdict.action,
    firing_rules: firingRules.map(f => ({ name: f.name, score: f.score, reason: f.reason })),
    ml_v2_score: ml.v2_score,
    ml_v2_prob: ml.v2_prob,
    ml_old_score: ml.old_score,
    additive_v2_score: additiveVerdict.score,
    old_ml_combined_score: oldMlVerdict.score,
    max_fusion_score: Math.max(rulesVerdict.score, ml.v2_score)
  });
}

const outPath = path.resolve(__dirname, '../benchmark/evaluated_dataset.json');
fs.writeFileSync(outPath, JSON.stringify(evaluated, null, 2), 'utf8');
console.log(`[Evaluator] Wrote evaluated dataset to ${outPath}`);
