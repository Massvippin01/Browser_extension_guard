import test from 'node:test';
import assert from 'node:assert/strict';
import { MESSAGES, SIGNAL_CATEGORY_MAP, CATEGORY_CAPS, t } from '../shared/messages.js';
import { calculateRisk } from '../background/risk-engine.js';

test('Reason IDs: every ID in SIGNAL_CATEGORY_MAP has a catalog entry in MESSAGES', () => {
  const ids = Object.keys(SIGNAL_CATEGORY_MAP);
  assert.ok(ids.length > 0, 'SIGNAL_CATEGORY_MAP should not be empty');

  for (const id of ids) {
    assert.ok(
      typeof MESSAGES[id] === 'function',
      `Reason ID "${id}" must have a formatting function in MESSAGES catalog`
    );
    // Formatting with empty or sample params must return a non-empty string
    const rendered = t(id, { brand: 'TestBrand', count: 5, hostname: 'test.com' });
    assert.ok(
      typeof rendered === 'string' && rendered.length > 0,
      `t("${id}") must render a non-empty string, got: "${rendered}"`
    );
  }
});

test('Reason IDs: no signal lands in two risk categories unless explicitly specified', () => {
  const seenIds = new Set();
  for (const [id, category] of Object.entries(SIGNAL_CATEGORY_MAP)) {
    assert.ok(typeof category === 'string' && category.length > 0, `Category for "${id}" must be a string`);
    assert.ok(!seenIds.has(id), `Signal ID "${id}" appears multiple times in SIGNAL_CATEGORY_MAP`);
    seenIds.add(id);
  }
});

test('Reason IDs: each category has a documented cap and risk score cannot exceed 100', () => {
  const expectedCategories = [
    'url', 'ip_host', 'malvertising', 'brand_impersonation', 'ml',
    'dom_credentials', 'scam_language', 'payment_phishing', 'synergy',
    'download', 'threat_intel'
  ];

  for (const cat of expectedCategories) {
    assert.ok(
      typeof CATEGORY_CAPS[cat] === 'number' && CATEGORY_CAPS[cat] > 0,
      `Category "${cat}" must have a documented positive cap in CATEGORY_CAPS`
    );
  }

  // Generate extreme signals from all categories simultaneously
  const extremeSignals = Object.keys(SIGNAL_CATEGORY_MAP).map(id => ({
    id,
    params: { brand: 'Brand', count: 10 },
    score: 100,
    triggered: true,
    reason: t(id)
  }));

  const verdict = calculateRisk('https://extreme-attack-example.com/login', extremeSignals, 100);
  assert.ok(verdict.score <= 100, `Risk score must never exceed 100, got: ${verdict.score}`);
  assert.ok(verdict.riskScore <= 100, `riskScore must never exceed 100, got: ${verdict.riskScore}`);
  assert.equal(verdict.score, 100);
});
