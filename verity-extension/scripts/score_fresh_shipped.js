import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import * as rules from '../background/rules.js';
import * as re from '../background/risk-engine.js';
import brands from '../brands.json' with { type: 'json' };

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const freshUrlsPath = path.resolve(__dirname, '../benchmark/fresh_test_urls.json');
const items = JSON.parse(fs.readFileSync(freshUrlsPath, 'utf8'));

// Leakage check: strip source field before scorer sees anything
const strippedItems = items.map(item => ({
  url: item.url,
  label: item.label,
  sourceFeed: item.source, // kept ONLY for post-hoc reporting, NOT passed to scorer
  isHttps: item.url.startsWith('https://')
}));

console.log('======================================================================');
console.log('📊 SCORING FRESH_TEST_URLS WITH THE REAL SHIPPED SCORER');
console.log(`Evaluated: ${strippedItems.length} URLs (500 Safe, 350 Phishing, 250 Malware)`);
console.log('Pipeline: URL Rules + Category Caps + Convergence + Asymptotic Diminishing');
console.log('======================================================================\n');

// Evaluate shipped scorer on each URL
const evaluated = [];

for (const item of strippedItems) {
  const u = item.url;
  
  // Rule signals
  const ruleSignals = [
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

  // Calculate risk with real shipped risk engine (rules only at URL evaluation time, ML_WEIGHT=0 or test mode)
  // Let's test with ML_WEIGHT=0 (shipped standalone rule engine) and ML_WEIGHT=1 (with ONNX) if available
  const verdict = re.calculateRisk(u, ruleSignals, null, null, null, null, null, null, 0.0);
  
  evaluated.push({
    ...item,
    score: verdict.score,
    action: verdict.action,
    ruleScore: verdict.ruleScore,
    activeSources: verdict.activeSources
  });
}

// Bootstrap Confidence Intervals Helper
function bootstrapCI(subset, targetLabel, threshold = 35, nResamples = 1000) {
  const filtered = subset.filter(i => i.label === 'safe' || i.label === targetLabel);
  const n = filtered.length;
  if (n === 0) return null;

  const targetCount = subset.filter(i => i.label === targetLabel).length;
  if (targetCount === 0) {
    return {
      note: '0 target items in subset (denominator is 0)',
      count: 0,
      rec: 0,
      recCI: [0, 0]
    };
  }

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
    count: targetCount,
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

console.log('----------------------------------------------------------------------');
console.log('RECALL BREAKDOWN ON BURNED FRESH_TEST_URLS (DIAGNOSTIC ONLY)');
console.log('----------------------------------------------------------------------');

const feeds = [...new Set(evaluated.map(i => i.sourceFeed))];

for (const feed of feeds) {
  const feedItems = evaluated.filter(i => i.sourceFeed === feed);
  const feedLabel = feedItems[0].label;
  console.log(`\n📁 FEED: ${feed} (Label: ${feedLabel}, N=${feedItems.length})`);
  
  const httpItems = feedItems.filter(i => !i.isHttps);
  const httpsItems = feedItems.filter(i => i.isHttps);
  console.log(`   HTTP count: ${httpItems.length} | HTTPS count: ${httpsItems.length}`);

  if (feedLabel === 'safe') {
    const fpr35 = feedItems.filter(i => i.score >= 35).length / feedItems.length;
    const fpr70 = feedItems.filter(i => i.score >= 70).length / feedItems.length;
    console.log(`   FPR @ 35: ${(fpr35 * 100).toFixed(2)}% (${feedItems.filter(i => i.score >= 35).length}/${feedItems.length})`);
    console.log(`   FPR @ 70: ${(fpr70 * 100).toFixed(2)}% (${feedItems.filter(i => i.score >= 70).length}/${feedItems.length})`);
  } else {
    // Phishing or Malware
    for (const th of [35, 70]) {
      const flaggedOverall = feedItems.filter(i => i.score >= th).length;
      const recOverall = flaggedOverall / feedItems.length;
      
      const flaggedHttp = httpItems.filter(i => i.score >= th).length;
      const recHttp = httpItems.length > 0 ? flaggedHttp / httpItems.length : null;

      const flaggedHttps = httpsItems.filter(i => i.score >= th).length;
      const recHttps = httpsItems.length > 0 ? flaggedHttps / httpsItems.length : null;

      console.log(`   @ Threshold ${th}:`);
      console.log(`     Overall Recall: ${(recOverall * 100).toFixed(2)}% (${flaggedOverall}/${feedItems.length})`);
      if (recHttp !== null) {
        console.log(`     HTTP Recall:    ${(recHttp * 100).toFixed(2)}% (${flaggedHttp}/${httpItems.length})`);
      }
      if (recHttps !== null) {
        console.log(`     HTTPS Recall:   ${(recHttps * 100).toFixed(2)}% (${flaggedHttps}/${httpsItems.length})`);
      } else {
        console.log(`     HTTPS Recall:   N/A (0 HTTPS rows in feed)`);
      }
    }
  }
}

// Headline Phishing CIs
console.log('\n======================================================================');
console.log('HEADLINE PHISHING FEED (Phishing.Database Active Snapshot):');
console.log('======================================================================');

const phishItems = evaluated.filter(i => i.label === 'phishing');
const phishHttp = phishItems.filter(i => !i.isHttps);
const phishHttps = phishItems.filter(i => i.isHttps);

console.log(`Phishing Items: Total=${phishItems.length}, HTTP=${phishHttp.length}, HTTPS=${phishHttps.length}`);

const phishCI_35 = bootstrapCI(evaluated, 'phishing', 35);
const phishCI_70 = bootstrapCI(evaluated, 'phishing', 70);

console.log(`\nPhishing Recall @ 35: ${(phishCI_35.rec * 100).toFixed(2)}% [${(phishCI_35.recCI[0] * 100).toFixed(2)}%, ${(phishCI_35.recCI[1] * 100).toFixed(2)}%]`);
console.log(`Phishing Recall @ 70: ${(phishCI_70.rec * 100).toFixed(2)}% [${(phishCI_70.recCI[0] * 100).toFixed(2)}%, ${(phishCI_70.recCI[1] * 100).toFixed(2)}%]`);
console.log(`Benign FPR @ 35:      ${(phishCI_35.fpr * 100).toFixed(2)}% [${(phishCI_35.fprCI[0] * 100).toFixed(2)}%, ${(phishCI_35.fprCI[1] * 100).toFixed(2)}%]`);
console.log(`Benign FPR @ 70:      ${(phishCI_70.fpr * 100).toFixed(2)}% [${(phishCI_70.fprCI[0] * 100).toFixed(2)}%, ${(phishCI_70.fprCI[1] * 100).toFixed(2)}%]`);

// Save diagnostic report
const auditReport = {
  timestamp: new Date().toISOString(),
  burnedLabel: "BURNED (Examined and fixed against; diagnostic only)",
  sha256: "7aaad0c46f7dce36a8917644387c083da0a557a8b12c39f3b5f32e756da2ad29",
  summary: {
    total: items.length,
    safe: 500,
    phishing: 350,
    malware: 250
  },
  metrics: {
    phishing_at_35: phishCI_35,
    phishing_at_70: phishCI_70
  }
};

fs.writeFileSync(path.resolve(__dirname, '../benchmark/fresh_test_audit_report.json'), JSON.stringify(auditReport, null, 2), 'utf8');
console.log('\nWrote benchmark/fresh_test_audit_report.json');
