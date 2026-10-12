import fs from 'fs';
import path from 'path';
import { calculateRisk, ML_WEIGHT } from '../background/risk-engine.js';
import {
  isIpBasedUrl, hasMissingHttps, hasExcessiveSubdomains,
  hasBrandNameInWrongDomain, hasSuspiciousUrlPattern, hasPunycodeOrKeywords,
  hasFinancialKeywordInHostname, hasBrandVariantMatch, hasMalvertisingPattern,
  hasRandomLookingHostname, hasAffiliateTrackerPattern, hasPiracyOrUnverifiedMediaPattern
} from '../background/rules.js';

const brandsList = JSON.parse(fs.readFileSync(new URL('../brands.json', import.meta.url), 'utf8'));
const paymentBrands = JSON.parse(fs.readFileSync(new URL('../payment-brands.json', import.meta.url), 'utf8'));
const dataset = JSON.parse(fs.readFileSync(new URL('../benchmark/test_urls.json', import.meta.url), 'utf8'));
const mlScores = JSON.parse(fs.readFileSync(new URL('../benchmark/ml_scores.json', import.meta.url), 'utf8'));

const RULE_FUNCS = [
  { name: 'isIpBasedUrl', fn: (u) => isIpBasedUrl(u) },
  { name: 'hasMissingHttps', fn: (u) => hasMissingHttps(u) },
  { name: 'hasExcessiveSubdomains', fn: (u) => hasExcessiveSubdomains(u) },
  { name: 'hasBrandNameInWrongDomain', fn: (u) => hasBrandNameInWrongDomain(u, brandsList) },
  { name: 'hasSuspiciousUrlPattern', fn: (u) => hasSuspiciousUrlPattern(u) },
  { name: 'hasPunycodeOrKeywords', fn: (u) => hasPunycodeOrKeywords(u) },
  { name: 'hasFinancialKeywordInHostname', fn: (u) => hasFinancialKeywordInHostname(u, brandsList) },
  { name: 'hasBrandVariantMatch', fn: (u) => hasBrandVariantMatch(u, brandsList) },
  { name: 'hasMalvertisingPattern', fn: (u) => hasMalvertisingPattern(u) },
  { name: 'hasRandomLookingHostname', fn: (u) => hasRandomLookingHostname(u) },
  { name: 'hasAffiliateTrackerPattern', fn: (u) => hasAffiliateTrackerPattern(u) },
  { name: 'hasPiracyOrUnverifiedMediaPattern', fn: (u) => hasPiracyOrUnverifiedMediaPattern(u) }
];

function runRules(url) {
  const fired = [];
  const signals = [];
  for (const r of RULE_FUNCS) {
    const res = r.fn(url);
    signals.push(res);
    if (res.triggered) fired.push({ name: r.name, score: res.score, reason: res.reason });
  }
  return { signals, fired };
}

function computeMetrics(items, targetClass, threshold, scoreKey = 'score') {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (const item of items) {
    if (targetClass && item.label !== 'safe' && item.label !== targetClass) continue;
    const isMal = item.label !== 'safe';
    const predMal = item[scoreKey] >= threshold;

    if (isMal && predMal) tp++;
    else if (!isMal && predMal) fp++;
    else if (!isMal && !predMal) tn++;
    else if (isMal && !predMal) fn++;
  }

  const prec = tp + fp > 0 ? tp / (tp + fp) : 0;
  const rec = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = prec + rec > 0 ? (2 * prec * rec) / (prec + rec) : 0;
  const fpr = fp + tn > 0 ? fp / (fp + tn) : 0;

  return { precision: prec, recall: rec, f1, fpr, tp, fp, tn, fn };
}

// 1000 Bootstrap resamples for 95% Confidence Intervals
function bootstrapMetrics(items, targetClass, threshold, scoreKey = 'score', nBoot = 1000) {
  const filtered = targetClass
    ? items.filter(i => i.label === 'safe' || i.label === targetClass)
    : items;

  const n = filtered.length;
  const point = computeMetrics(filtered, targetClass, threshold, scoreKey);

  let seed = 12345;
  function random() {
    seed = (seed * 9301 + 49297) % 233280;
    return seed / 233280;
  }

  const precisions = [];
  const recalls = [];
  const f1s = [];
  const fprs = [];

  for (let b = 0; b < nBoot; b++) {
    const sample = [];
    for (let i = 0; i < n; i++) {
      const idx = Math.floor(random() * n);
      sample.push(filtered[idx]);
    }
    const m = computeMetrics(sample, targetClass, threshold, scoreKey);
    precisions.push(m.precision);
    recalls.push(m.recall);
    f1s.push(m.f1);
    fprs.push(m.fpr);
  }

  precisions.sort((a, b) => a - b);
  recalls.sort((a, b) => a - b);
  f1s.sort((a, b) => a - b);
  fprs.sort((a, b) => a - b);

  const getCi = (arr) => {
    const lower = arr[Math.floor(nBoot * 0.025)];
    const upper = arr[Math.floor(nBoot * 0.975)];
    return [lower, upper];
  };

  return {
    point,
    ci95: {
      precision: getCi(precisions),
      recall: getCi(recalls),
      f1: getCi(f1s),
      fpr: getCi(fprs)
    }
  };
}

function formatWithCi(metricName, bootRes) {
  const val = bootRes.point[metricName] * 100;
  const lower = bootRes.ci95[metricName][0] * 100;
  const upper = bootRes.ci95[metricName][1] * 100;
  return `${val.toFixed(2)}% [${lower.toFixed(2)}%, ${upper.toFixed(2)}%]`;
}

function main() {
  console.log('========================================================================================');
  console.log('🛡️  VERITY PHASE V2.1 BENCHMARK EVALUATION (HONEST REAL DATASET WITH 95% BOOTSTRAP CIs)');
  console.log('========================================================================================');

  const scoredData = dataset.map(item => {
    const { signals, fired } = runRules(item.url);
    const mlEntry = mlScores[item.url] || { old_score: null, v2_score: null };

    // Real production engine with v2 ML wired
    const verdict = calculateRisk(item.url, signals, mlEntry.v2_score, null, null, null, null, null, ML_WEIGHT);

    return {
      ...item,
      rulesFired: fired,
      score: verdict.score,
      signals: verdict.signals,
      reasons: verdict.reasons
    };
  });

  const testItems = scoredData.filter(d => d.split === 'test');
  const httpsTestItems = testItems.filter(d => d.url.startsWith('https://'));

  console.log(`\nEvaluated on held-out test set: ${testItems.length} total URLs (${httpsTestItems.length} HTTPS-only).`);
  console.log(`Test set distribution: Safe=${testItems.filter(i=>i.label==='safe').length}, Phishing=${testItems.filter(i=>i.label==='phishing').length}, Malware=${testItems.filter(i=>i.label==='malware').length}`);

  const evaluationResults = {};

  const categories = [
    { name: 'Phishing (Separately)', filter: 'phishing', items: testItems },
    { name: 'Malware (Separately)', filter: 'malware', items: testItems },
    { name: 'Overall (Phishing + Malware)', filter: null, items: testItems },
    { name: 'HTTPS-Only Phishing', filter: 'phishing', items: httpsTestItems }
  ];

  for (const cat of categories) {
    evaluationResults[cat.name] = {
      th35: bootstrapMetrics(cat.items, cat.filter, 35),
      th70: bootstrapMetrics(cat.items, cat.filter, 70)
    };
  }

  // Print results table
  for (const th of [35, 70]) {
    const key = `th${th}`;
    console.log(`\n========================================================================================`);
    console.log(`                   BENCHMARK METRICS @ THRESHOLD ${th} (WITH 95% BOOTSTRAP CIs)`);
    console.log(`========================================================================================`);
    console.log(`Category                    | Precision               | Recall                  | F1 Score                | Benign FPR`);
    console.log(`---------------------------------------------------------------------------------------------------------------------------------`);
    for (const cat of categories) {
      const bRes = evaluationResults[cat.name][key];
      const name = cat.name.padEnd(27);
      const prec = formatWithCi('precision', bRes).padEnd(23);
      const rec = formatWithCi('recall', bRes).padEnd(23);
      const f1 = formatWithCi('f1', bRes).padEnd(23);
      const fpr = formatWithCi('fpr', bRes);
      console.log(`${name} | ${prec} | ${rec} | ${f1} | ${fpr}`);
    }
  }

  // Worst-20 False Positives
  const benignTest = testItems.filter(i => i.label === 'safe');
  benignTest.sort((a, b) => b.score - a.score);
  const worst20Fp = benignTest.slice(0, 20);

  console.log('\n========================================================================================');
  console.log('                          WORST-20 FALSE POSITIVES (BENIGN URLs)');
  console.log('========================================================================================');
  worst20Fp.forEach((item, idx) => {
    console.log(`[FP #${idx + 1}] Score: ${item.score} | URL: ${item.url}`);
    console.log(`  Source: ${item.source} | Category: ${item.category}`);
    if (item.rulesFired.length > 0) {
      console.log(`  Rules Fired (${item.rulesFired.length}):`);
      item.rulesFired.forEach(r => console.log(`    - ${r.name} (+${r.score} pts): ${r.reason}`));
    }
    const mlSignal = item.signals.find(s => s.category === 'ml');
    if (mlSignal) {
      console.log(`    - ML Term (+${mlSignal.score} pts): On-device ML score`);
    }
  });

  // Worst-20 Misses (False Negatives on Phishing)
  const phishTest = testItems.filter(i => i.label === 'phishing');
  phishTest.sort((a, b) => a.score - b.score);
  const worst20Misses = phishTest.slice(0, 20);

  console.log('\n========================================================================================');
  console.log('                     WORST-20 PHISHING MISSES (FALSE NEGATIVES)');
  console.log('========================================================================================');
  worst20Misses.forEach((item, idx) => {
    console.log(`[Miss #${idx + 1}] Score: ${item.score} | URL: ${item.url}`);
    console.log(`  Source: ${item.source} | Category: ${item.category}`);
    if (item.rulesFired.length > 0) {
      console.log(`  Rules Fired (${item.rulesFired.length}):`);
      item.rulesFired.forEach(r => console.log(`    - ${r.name} (+${r.score} pts): ${r.reason}`));
    } else {
      console.log(`  Rules Fired: None (0 pts)`);
    }
    const mlSignal = item.signals.find(s => s.category === 'ml');
    if (mlSignal) {
      console.log(`    - ML Term (+${mlSignal.score} pts)`);
    }
  });

  // Per-Rule Contribution
  console.log('\n========================================================================================');
  console.log('                               PER-RULE FIRING SUMMARY');
  console.log('========================================================================================');
  const ruleStats = RULE_FUNCS.map(r => {
    const benignFires = benignTest.filter(item => item.rulesFired.some(rf => rf.name === r.name)).length;
    const phishFires = phishTest.filter(item => item.rulesFired.some(rf => rf.name === r.name)).length;
    return {
      'Rule Name': r.name,
      'Benign Fires': `${benignFires} / ${benignTest.length} (${(benignFires/benignTest.length*100).toFixed(1)}%)`,
      'Phish Fires': `${phishFires} / ${phishTest.length} (${(phishFires/phishTest.length*100).toFixed(1)}%)`,
      benignCount: benignFires,
      phishCount: phishFires
    };
  });
  console.table(ruleStats);

  // Save results to benchmark/results.json
  const outPath = path.resolve('benchmark/results.json');
  fs.writeFileSync(outPath, JSON.stringify({
    metadata: {
      timestamp: new Date().toISOString(),
      datasetSize: dataset.length,
      testSize: testItems.length,
      httpsTestSize: httpsTestItems.length,
      mlWeight: ML_WEIGHT
    },
    metrics: evaluationResults,
    worst20FalsePositives: worst20Fp.map(item => ({
      url: item.url,
      score: item.score,
      source: item.source,
      category: item.category,
      rulesFired: item.rulesFired,
      signals: item.signals
    })),
    worst20Misses: worst20Misses.map(item => ({
      url: item.url,
      score: item.score,
      source: item.source,
      category: item.category,
      rulesFired: item.rulesFired,
      signals: item.signals
    })),
    ruleStats
  }, null, 2), 'utf8');

  console.log(`\nSuccessfully saved full benchmark results to ${outPath}`);
}

main();
