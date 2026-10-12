import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import * as rules from '../background/rules.js';
import * as re from '../background/risk-engine.js';
import brands from '../brands.json' with { type: 'json' };
import { extractRichFeatures } from '../background/rich-feature-extractor.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const freshUrlsPath = path.resolve(__dirname, '../benchmark/fresh_test_urls.json');
const items = JSON.parse(fs.readFileSync(freshUrlsPath, 'utf8'));

console.log('======================================================================');
console.log('🌟 VERITY FRESH BENCHMARK: ZERO-PRIOR-LEAKAGE DATED TEST SET');
console.log(`Evaluated: ${items.length} Fresh URLs (500 Safe, 350 Phishing, 250 Malware)`);
console.log('======================================================================\n');

// 1. Evaluate Rule Engine on each URL
const evaluated = [];

for (const item of items) {
  const u = item.url;
  const signals = [
    rules.isIpBasedUrl(u),
    rules.hasMissingHttps(u),
    rules.hasExcessiveSubdomains(u),
    rules.hasBrandNameInWrongDomain(u, brands),
    rules.hasSuspiciousUrlPattern(u),
    rules.hasPunycodeOrKeywords(u),
    rules.hasFinancialKeywordInHostname(u, brands),
    rules.hasBrandVariantMatch(u, brands),
    rules.hasMalvertisingPattern(u),
    rules.hasRandomLookingHostname(u),
    rules.hasAffiliateTrackerPattern(u),
    rules.hasPiracyOrUnverifiedMediaPattern(u)
  ];

  const verdict = re.calculateRisk(u, signals, null, null, null, null, null, null, 0.0);
  evaluated.push({
    ...item,
    score: verdict.score,
    action: verdict.action
  });
}

// 2. Bootstrap Confidence Intervals Helper
function bootstrapCI(subset, targetLabel, threshold = 35, nResamples = 1000) {
  const filtered = subset.filter(i => i.label === 'safe' || i.label === targetLabel);
  const n = filtered.length;
  if (n === 0) return null;

  let seed = 42;
  function rnd() {
    seed = (seed * 9301 + 49297) % 233280;
    return seed / 233280;
  }

  const f1s = [], precs = [], recs = [], fprs = [];

  for (let b = 0; b < nResamples; b++) {
    let tp = 0, fp = 0, tn = 0, fn = 0;
    for (let i = 0; i < n; i++) {
      const idx = Math.floor(rnd() * n);
      const row = filtered[idx];
      const isTarget = row.label === targetLabel;
      const flagged = row.score >= threshold;

      if (isTarget && flagged) tp++;
      else if (isTarget && !flagged) fn++;
      else if (!isTarget && flagged) fp++;
      else if (!isTarget && !flagged) tn++;
    }

    const prec = tp + fp > 0 ? tp / (tp + fp) : 0;
    const rec = tp + fn > 0 ? tp / (tp + fn) : 0;
    const f1 = prec + rec > 0 ? (2 * prec * rec) / (prec + rec) : 0;
    const fpr = fp + tn > 0 ? fp / (fp + tn) : 0;

    f1s.push(f1);
    precs.push(prec);
    recs.push(rec);
    fprs.push(fpr);
  }

  f1s.sort((a, b) => a - b);
  precs.sort((a, b) => a - b);
  recs.sort((a, b) => a - b);
  fprs.sort((a, b) => a - b);

  const mean = arr => arr.reduce((a, b) => a + b, 0) / arr.length;
  const p = (arr, q) => arr[Math.floor(q * arr.length)];

  return {
    f1: mean(f1s),
    f1CI: [p(f1s, 0.025), p(f1s, 0.975)],
    prec: mean(precs),
    precCI: [p(precs, 0.025), p(precs, 0.975)],
    rec: mean(recs),
    recCI: [p(recs, 0.025), p(recs, 0.975)],
    fpr: mean(fprs),
    fprCI: [p(fprs, 0.025), p(fprs, 0.975)]
  };
}

// 3. Compute Headline Metrics (Phishing only, overall & HTTPS-only)
const allItems = evaluated;
const httpsItems = evaluated.filter(i => i.url.startsWith('https://'));

console.log('======================================================================');
console.log('📌 HEADLINE METRICS: FRESH TEST PHISHING EVALUATION');
console.log('======================================================================');

const headlineResults = {
  overall_35: bootstrapCI(allItems, 'phishing', 35),
  overall_70: bootstrapCI(allItems, 'phishing', 70),
  https_35: bootstrapCI(httpsItems, 'phishing', 35),
  https_70: bootstrapCI(httpsItems, 'phishing', 70)
};

function printMetricsBlock(title, m) {
  console.log(`\n--- ${title} ---`);
  console.log(`  F1 Score:   ${(m.f1 * 100).toFixed(2)}% (95% CI: [${(m.f1CI[0] * 100).toFixed(2)}%, ${(m.f1CI[1] * 100).toFixed(2)}%])`);
  console.log(`  Precision:  ${(m.prec * 100).toFixed(2)}% (95% CI: [${(m.precCI[0] * 100).toFixed(2)}%, ${(m.precCI[1] * 100).toFixed(2)}%])`);
  console.log(`  Recall:     ${(m.rec * 100).toFixed(2)}% (95% CI: [${(m.recCI[0] * 100).toFixed(2)}%, ${(m.recCI[1] * 100).toFixed(2)}%])`);
  console.log(`  Benign FPR: ${(m.fpr * 100).toFixed(2)}% (95% CI: [${(m.fprCI[0] * 100).toFixed(2)}%, ${(m.fprCI[1] * 100).toFixed(2)}%])`);
}

printMetricsBlock('Headline: Fresh Phishing Overall (@ Threshold 35)', headlineResults.overall_35);
printMetricsBlock('Headline: Fresh Phishing Overall (@ Threshold 70)', headlineResults.overall_70);
printMetricsBlock('Headline: Fresh Phishing HTTPS-Only Subset (@ Threshold 35)', headlineResults.https_35);
printMetricsBlock('Headline: Fresh Phishing HTTPS-Only Subset (@ Threshold 70)', headlineResults.https_70);

// 4. Compute Malware Metrics Separately
console.log('\n======================================================================');
console.log('🦠 SEPARATE EVALUATION: FRESH MALWARE (URLhaus Feed)');
console.log('======================================================================');

const malwareResults = {
  overall_35: bootstrapCI(allItems, 'malware', 35),
  overall_70: bootstrapCI(allItems, 'malware', 70)
};

printMetricsBlock('Separate: Fresh Malware (@ Threshold 35)', malwareResults.overall_35);
printMetricsBlock('Separate: Fresh Malware (@ Threshold 70)', malwareResults.overall_70);

const fullOutput = {
  timestamp: new Date().toISOString(),
  datasetSummary: {
    total: items.length,
    safe: 500,
    phishing: 350,
    malware: 250,
    httpsSubset: httpsItems.length
  },
  headlinePhishing: headlineResults,
  separateMalware: malwareResults
};

const outPath = path.resolve(__dirname, '../benchmark/fresh_results.json');
fs.writeFileSync(outPath, JSON.stringify(fullOutput, null, 2), 'utf8');
console.log(`\nWrote complete fresh benchmark results to ${outPath}`);
