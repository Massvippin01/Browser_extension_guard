import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateRisk } from '../background/risk-engine.js';
import { isAllowlistedDomain, LEGIT_DOMAINS } from '../shared/legit-domains.js';

test('Convergence Rule: Block-level verdict requires >= 2 independent sources', () => {
  // Case A: Single source alone (URL brand typosquat = 85 pts) without ML or DOM credentials
  const singleSourceSignals = [
    { id: 'RULE_BRAND_VARIANT_MATCH', params: { brand: 'PayPal' }, score: 85, triggered: true }
  ];
  const singleVerdict = calculateRisk('https://paypa1-update.com/account', singleSourceSignals, null, null);
  // Must be demoted to Caution because only 1 source contributed
  assert.equal(singleVerdict.action, 'warn', 'Single source must not block');
  assert.equal(singleVerdict.severity, 'caution');
  assert.ok(singleVerdict.score <= 65, `Single source score must be <= 65, got ${singleVerdict.score}`);

  // Case B: Two independent sources (URL typosquat + DOM credential collection)
  const domSignals = {
    isTrustedDomain: false,
    hasCredentialCollection: true,
    hasPasswordInput: true,
    loginFormCount: 1,
    pageTitle: 'Login',
    pageText: 'Enter your password'
  };
  const twoSourceVerdict = calculateRisk('https://paypa1-update.com/account', singleSourceSignals, null, domSignals);
  assert.equal(twoSourceVerdict.action, 'block', 'Two independent sources must produce block');
  assert.equal(twoSourceVerdict.severity, 'danger');
  assert.ok(twoSourceVerdict.score >= 70, `Two source score must be >= 70, got ${twoSourceVerdict.score}`);
});

test('Convergence Rule: DOM text phrases alone can add at most Caution, never Block', () => {
  const domSignals = {
    isTrustedDomain: false,
    hasCredentialCollection: false,
    hasPasswordInput: false,
    loginFormCount: 0,
    scam: true,
    scamReason: 'Electricity connection will be disconnected. Update KYC immediately.',
    financialMatches: ['kyc', 'otp', 'netbanking'],
    pageTitle: 'Notice',
    pageText: 'Electricity will be disconnected. Complete your KYC update and submit OTP.'
  };

  const verdict = calculateRisk('https://some-news-or-blog.com/advisory', [], null, domSignals);
  assert.notEqual(verdict.action, 'block', 'DOM text phrases alone must NEVER block');
  assert.ok(verdict.score < 70, `DOM text alone must score < 70, got: ${verdict.score}`);
});

test('Allowlist: independent allowlist domains cap at Caution unless download or exfil', () => {
  assert.ok(Array.isArray(LEGIT_DOMAINS) && LEGIT_DOMAINS.length > 0, 'LEGIT_DOMAINS should not be empty');

  // Verify allowlist matching on direct and subdomains
  assert.ok(isAllowlistedDomain('hdfcbank.com'), 'hdfcbank.com should be allowlisted');
  assert.ok(isAllowlistedDomain('netbanking.hdfcbank.com'), 'netbanking.hdfcbank.com should be allowlisted');
  assert.ok(isAllowlistedDomain('retail.onlinesbi.sbi'), 'retail.onlinesbi.sbi should be allowlisted');
  assert.ok(isAllowlistedDomain('amazon.in'), 'amazon.in should be allowlisted');
  assert.ok(isAllowlistedDomain('www.incometax.gov.in'), 'www.incometax.gov.in should be allowlisted');

  // Negative test
  assert.ok(!isAllowlistedDomain('fake-hdfcbank.com'), 'fake-hdfcbank.com must not be allowlisted');
  assert.ok(!isAllowlistedDomain('paytm-cashback-rewards.test'), 'paytm-cashback-rewards.test must not be allowlisted');

  // Allowlist cap test: Even with elevated heuristic or text signals, allowlisted domains cap at Caution (max 40)
  const aggressiveSignals = [
    { id: 'RULE_MISSING_HTTPS', score: 40, triggered: true },
    { id: 'RULE_SUSPICIOUS_URL_PATTERN', score: 40, triggered: true }
  ];
  const domSignals = {
    isTrustedDomain: true,
    hasCredentialCollection: true,
    hasPasswordInput: true,
    scam: true,
    scamReason: 'Update KYC'
  };

  const sbiVerdict = calculateRisk('https://retail.onlinesbi.sbi/login', aggressiveSignals, 80, domSignals);
  assert.notEqual(sbiVerdict.action, 'block', 'Allowlisted bank login must NEVER block');
  assert.ok(sbiVerdict.score <= 40, `Allowlisted domain score must cap at <= 40, got ${sbiVerdict.score}`);
});
