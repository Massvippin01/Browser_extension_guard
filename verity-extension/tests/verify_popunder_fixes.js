import test from 'node:test';
import assert from 'node:assert/strict';

import {
  isIpBasedUrl,
  hasMissingHttps,
  hasExcessiveSubdomains,
  hasBrandNameInWrongDomain,
  hasSuspiciousUrlPattern,
  hasPunycodeOrKeywords,
  hasFinancialKeywordInHostname,
  hasBrandVariantMatch,
  hasMalvertisingPattern,
  hasRandomLookingHostname,
  hasAffiliateTrackerPattern,
  hasPiracyOrUnverifiedMediaPattern
} from '../background/rules.js';
import { calculateRisk } from '../background/risk-engine.js';

function analyzeAllRules(url) {
  return [
    isIpBasedUrl(url),
    hasMissingHttps(url),
    hasExcessiveSubdomains(url),
    hasBrandNameInWrongDomain(url, []),
    hasSuspiciousUrlPattern(url),
    hasPunycodeOrKeywords(url),
    hasFinancialKeywordInHostname(url, []),
    hasBrandVariantMatch(url, []),
    hasMalvertisingPattern(url),
    hasRandomLookingHostname(url),
    hasAffiliateTrackerPattern(url),
    hasPiracyOrUnverifiedMediaPattern(url),
  ];
}

const TEST_CASES = [
  {
    name: 'Pop-Under Case 1 (PropellerAds / Popunder query on gambling .live)',
    url: 'https://ufa168rss.live/expert-tips?utm_source=propellerads&utm_medium=popunder&utm_campaign=dwt523og&cid=1134559171384193679&zid=9036000'
  },
  {
    name: 'Pop-Under Case 2 (Fake download trap on .xyz)',
    url: 'https://download.fastbytes.xyz/'
  },
  {
    name: 'Pop-Under Case 3 (Rotator shard with keyless hex query on .monster)',
    url: 'https://aar5n.wigglepoploaderfast.monster/?540267a373b920a51ea99c645c7f'
  }
];

test('Real-World Malvertising & Pop-Under URLs must return Risk Score >= 75 and Verdict BLOCK with dom_credentials = 0', () => {
  console.log('\n======================================================================');
  console.log('🛡️  VERITY POP-UNDER & MALVERTISING URL FIX VERIFICATION');
  console.log('======================================================================');

  for (const { name, url } of TEST_CASES) {
    const ruleSignals = analyzeAllRules(url);
    const triggeredSignals = ruleSignals.filter(s => s.triggered);

    // Pass with domSignals = null (0 DOM forms/credentials), no ML, no threat intel
    const verdict = calculateRisk(url, ruleSignals, null, null, null, null);

    console.log(`\nEvaluating: ${name}`);
    console.log(`URL: ${url}`);
    console.log(`Triggered Signals: [${triggeredSignals.map(s => s.id + ' (' + s.score + ' pts)').join(', ')}]`);
    console.log(`Final Risk Score: ${verdict.score} / 100`);
    console.log(`Severity: ${verdict.severity}`);
    console.log(`Action: ${verdict.action}`);
    console.log(`Reasons:`);
    verdict.reasons.forEach(r => console.log(`  - ${r}`));

    // Assertions required by user specification
    assert.ok(
      verdict.score >= 75,
      `Expected score >= 75 for ${url}, got ${verdict.score}`
    );
    assert.equal(
      verdict.action,
      'block',
      `Expected action === 'block' for ${url}, got ${verdict.action}`
    );
    assert.equal(
      verdict.severity,
      'danger',
      `Expected severity === 'danger' for ${url}, got ${verdict.severity}`
    );

    console.log(`✅ PASSED: ${name} correctly BLOCKED with score ${verdict.score} >= 75`);
  }
  console.log('\n======================================================================');
  console.log('✅ ALL 3 POP-UNDER MALVERTISING FAILURE CASES PROVEN BLOCKED');
  console.log('======================================================================\n');
});
