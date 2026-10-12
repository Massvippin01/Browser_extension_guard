import fs from 'fs';
import * as rules from '../background/rules.js';
import * as re from '../background/risk-engine.js';
import brands from '../brands.json' with { type: 'json' };

const data = JSON.parse(fs.readFileSync('benchmark/test_urls.json', 'utf8'));
const mlScores = JSON.parse(fs.readFileSync('benchmark/ml_scores.json', 'utf8'));

const testItems = data.filter(d => d.split === 'test');
const httpsTestItems = testItems.filter(d => d.url.startsWith('https://'));

function runEval(items, labelFilter, mode) {
  // mode: 'rules_only', 'rules_old_ml', 'rules_v2_ml', 'v2_ml_only'
  let tp35 = 0, fp35 = 0, tn35 = 0, fn35 = 0;
  let tp70 = 0, fp70 = 0, tn70 = 0, fn70 = 0;

  for (const item of items) {
    if (labelFilter && item.label !== 'safe' && item.label !== labelFilter) continue;
    const u = item.url;
    const mlInfo = mlScores[u] || { old_score: 0, v2_score: 0 };

    let score = 0;

    if (mode === 'v2_ml_only') {
      score = mlInfo.v2_score;
    } else {
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

      if (mode === 'rules_only') {
        const verdict = re.calculateRisk(u, signals, null, null, null, null, null, null, 0.0);
        score = verdict.score;
      } else if (mode === 'rules_old_ml') {
        const verdict = re.calculateRisk(u, signals, mlInfo.old_score, null, null, null, null, null, 1.0);
        score = verdict.score;
      } else if (mode === 'rules_v2_ml') {
        const verdict = re.calculateRisk(u, signals, mlInfo.v2_score, null, null, null, null, null, 1.0);
        score = verdict.score;
      }
    }

    const isTarget = item.label !== 'safe';
    if (isTarget) {
      if (score >= 35) tp35++; else fn35++;
      if (score >= 70) tp70++; else fn70++;
    } else {
      if (score >= 35) fp35++; else tn35++;
      if (score >= 70) fp70++; else tn70++;
    }
  }

  const calcMetrics = (tp, fp, tn, fn) => {
    const prec = tp + fp > 0 ? tp / (tp + fp) : 0;
    const rec = tp + fn > 0 ? tp / (tp + fn) : 0;
    const f1 = prec + rec > 0 ? (2 * prec * rec) / (prec + rec) : 0;
    const fpr = fp + tn > 0 ? fp / (fp + tn) : 0;
    return { prec, rec, f1, fpr, tp, fp, tn, fn };
  };

  return {
    th35: calcMetrics(tp35, fp35, tn35, fn35),
    th70: calcMetrics(tp70, fp70, tn70, fn70)
  };
}

const modes = ['rules_only', 'rules_old_ml', 'rules_v2_ml', 'v2_ml_only'];
const results = {};

for (const m of modes) {
  results[m] = {
    phishing: runEval(testItems, 'phishing', m),
    malware: runEval(testItems, 'malware', m),
    overall: runEval(testItems, null, m),
    httpsPhishing: runEval(httpsTestItems, 'phishing', m)
  };
}

console.log('========================================================================================');
console.log('                          ML ABLATION TABLE ON TEST SET');
console.log('========================================================================================');

for (const th of ['th35', 'th70']) {
  const thNum = th === 'th35' ? 35 : 70;
  console.log(`\n--- THRESHOLD ${thNum} ---`);
  console.log(`Mode                 | Phish F1 | Phish Rec | Benign FPR | HTTPS-Phish F1 | HTTPS-Phish FPR | Malware F1`);
  console.log(`--------------------------------------------------------------------------------------------------------`);
  for (const m of modes) {
    const ph = results[m].phishing[th];
    const hph = results[m].httpsPhishing[th];
    const mal = results[m].malware[th];
    const name = m.padEnd(20);
    const pF1 = (ph.f1 * 100).toFixed(2).padStart(8) + '%';
    const pRec = (ph.rec * 100).toFixed(2).padStart(9) + '%';
    const pFpr = (ph.fpr * 100).toFixed(2).padStart(10) + '%';
    const hpF1 = (hph.f1 * 100).toFixed(2).padStart(14) + '%';
    const hpFpr = (hph.fpr * 100).toFixed(2).padStart(15) + '%';
    const mF1 = (mal.f1 * 100).toFixed(2).padStart(10) + '%';
    console.log(`${name} | ${pF1} | ${pRec} | ${pFpr} | ${hpF1} | ${hpFpr} | ${mF1}`);
  }
}

// Check Decision Rule
// "Keep v2 only if rules+v2 beats rules-only on held-out F1 (HTTPS-only subset included) without raising benign FPR."
const rOnly35 = results['rules_only'].phishing.th35;
const rOnly70 = results['rules_only'].phishing.th70;
const rV2_35 = results['rules_v2_ml'].phishing.th35;
const rV2_70 = results['rules_v2_ml'].phishing.th70;

const rOnlyHttps35 = results['rules_only'].httpsPhishing.th35;
const rOnlyHttps70 = results['rules_only'].httpsPhishing.th70;
const rV2Https35 = results['rules_v2_ml'].httpsPhishing.th35;
const rV2Https70 = results['rules_v2_ml'].httpsPhishing.th70;

console.log('\n=== DECISION RULE EVALUATION ===');
console.log(`Overall Phish F1 @35: Rules=${(rOnly35.f1*100).toFixed(2)}% vs Rules+V2=${(rV2_35.f1*100).toFixed(2)}% (F1 diff: ${((rV2_35.f1 - rOnly35.f1)*100).toFixed(2)}%)`);
console.log(`Overall Phish F1 @70: Rules=${(rOnly70.f1*100).toFixed(2)}% vs Rules+V2=${(rV2_70.f1*100).toFixed(2)}% (F1 diff: ${((rV2_70.f1 - rOnly70.f1)*100).toFixed(2)}%)`);
console.log(`HTTPS Phish F1 @35:   Rules=${(rOnlyHttps35.f1*100).toFixed(2)}% vs Rules+V2=${(rV2Https35.f1*100).toFixed(2)}% (F1 diff: ${((rV2Https35.f1 - rOnlyHttps35.f1)*100).toFixed(2)}%)`);
console.log(`HTTPS Phish F1 @70:   Rules=${(rOnlyHttps70.f1*100).toFixed(2)}% vs Rules+V2=${(rV2Https70.f1*100).toFixed(2)}% (F1 diff: ${((rV2Https70.f1 - rOnlyHttps70.f1)*100).toFixed(2)}%)`);
console.log(`Benign FPR @35:       Rules=${(rOnly35.fpr*100).toFixed(2)}% vs Rules+V2=${(rV2_35.fpr*100).toFixed(2)}% (FPR diff: ${((rV2_35.fpr - rOnly35.fpr)*100).toFixed(2)}%)`);
console.log(`Benign FPR @70:       Rules=${(rOnly70.fpr*100).toFixed(2)}% vs Rules+V2=${(rV2_70.fpr*100).toFixed(2)}% (FPR diff: ${((rV2_70.fpr - rOnly70.fpr)*100).toFixed(2)}%)`);

const beatsF1 = (rV2_35.f1 > rOnly35.f1 || rV2_70.f1 > rOnly70.f1) && (rV2Https35.f1 > rOnlyHttps35.f1 || rV2Https70.f1 > rOnlyHttps70.f1);
const fprNotHigher = (rV2_35.fpr <= rOnly35.fpr) && (rV2_70.fpr <= rOnly70.fpr);

console.log(`\nDecision: ${beatsF1 && fprNotHigher ? 'KEEP V2 ML MODEL' : 'DROP V2 ML MODEL (STICK TO RULES-ONLY)'}`);

fs.writeFileSync('benchmark/ablation_results.json', JSON.stringify(results, null, 2), 'utf8');
console.log('Saved ablation results to benchmark/ablation_results.json');
