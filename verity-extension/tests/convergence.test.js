import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateRisk } from '../background/risk-engine.js';
import { isAllowlistedDomain, LEGIT_DOMAINS } from '../shared/legit-domains.js';
import { CATEGORY_CAPS } from '../shared/messages.js';

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

test('Score Architecture: each category alone at its cap must NEVER produce a Block verdict', () => {
  const categories = Object.keys(CATEGORY_CAPS);

  for (const cat of categories) {
    const cap = CATEGORY_CAPS[cat];
    assert.ok(cap < 70, `Category "${cat}" cap (${cap}) must be strictly < 70 to prevent single-category block`);

    const url = 'https://unverified-sample-host.org/test';
    const ruleSignals = [];
    let domSignals = null;
    let mlScore = null;
    let redirectSignals = null;
    let paymentAnalysis = null;
    let downloadSignals = null;
    let threatIntel = null;

    if (['url', 'ip_host', 'malvertising', 'brand_impersonation'].includes(cat)) {
      const sigMap = {
        url: 'RULE_MISSING_HTTPS',
        ip_host: 'RULE_IP_BASED_URL',
        malvertising: 'RULE_MALVERTISING_REDIRECT',
        brand_impersonation: 'RULE_BRAND_VARIANT_MATCH'
      };
      ruleSignals.push({ id: sigMap[cat], score: cap, triggered: true });
    } else if (cat === 'ml') {
      mlScore = 100;
    } else if (cat === 'dom_credentials') {
      domSignals = { hasCredentialCollection: true, hasPasswordInput: true, loginFormCount: 1 };
    } else if (cat === 'scam_language') {
      domSignals = { scam: true, scamReason: 'Urgent notice' };
    } else if (cat === 'payment_phishing') {
      paymentAnalysis = {
        isPaymentPage: true,
        structuredReasons: [{ id: 'PAYMENT_DOMAIN_MISMATCH', score: cap, params: { hostname: 'unverified-sample-host.org' } }]
      };
    } else if (cat === 'download') {
      downloadSignals = { analysisContext: 'download', executableDownload: true, sourceDomainSuspicious: true };
    }

    const verdict = calculateRisk(url, ruleSignals, mlScore, domSignals, threatIntel, redirectSignals, paymentAnalysis, downloadSignals);
    assert.notEqual(
      verdict.action,
      'block',
      `Category "${cat}" alone at its cap (${cap} pts) must NEVER produce a Block verdict`
    );
    assert.ok(verdict.score < 70, `Category "${cat}" alone score (${verdict.score}) must be < 70`);
  }
});

test('Real-world Malvertising URL: scores >= 70 (BLOCK) with corroborated signals', async () => {
  const { hasSuspiciousUrlPattern, hasMalvertisingPattern } = await import('../background/rules.js');
  const targetUrl = 'https://aar5n.wigglepoploaderfast.monster/?540267a373b920a51ea99c645c7f';

  const tldSignal = hasSuspiciousUrlPattern(targetUrl);
  const malvertisingSignal = hasMalvertisingPattern(targetUrl);

  assert.equal(tldSignal.triggered, true, 'TLD .monster should trigger');
  assert.equal(malvertisingSignal.triggered, true, 'Malvertising pattern should trigger');
  assert.equal(malvertisingSignal.score, 65, 'Malvertising score should be 65');

  const verdict = calculateRisk(targetUrl, [tldSignal, malvertisingSignal], null, null);
  assert.ok(verdict.score >= 70, `Score must be >= 70, got: ${verdict.score}`);
  assert.equal(verdict.action, 'block', `Action must be block, got: ${verdict.action}`);
  assert.equal(verdict.severity, 'danger', `Severity must be danger, got: ${verdict.severity}`);
});

test('Pairwise Synergy Bonuses: boost corroborated risk scores', () => {
  // brand_impersonation + dom_credentials (+20 pts)
  const brandSignal = [{ id: 'RULE_BRAND_VARIANT_MATCH', score: 55, triggered: true }];
  const domCredSignal = { isTrustedDomain: false, hasCredentialCollection: true, pageTitle: 'Login' };
  const brandCredVerdict = calculateRisk('https://example-phish.com', brandSignal, null, domCredSignal);
  assert.equal(brandCredVerdict.action, 'block');
  assert.ok(brandCredVerdict.score >= 70);

  // payment_phishing + dom_credentials (+25 pts)
  const paymentAnalysis = {
    isPaymentPage: true,
    structuredReasons: [{ id: 'PAYMENT_FAKE_PROVIDER', score: 65, params: { hostname: 'fake-pay.com' } }]
  };
  const paymentVerdict = calculateRisk('https://fake-pay.com', [], null, domCredSignal, null, null, paymentAnalysis);
  assert.equal(paymentVerdict.action, 'block');
  assert.ok(paymentVerdict.score >= 70);

  // malvertising + redirect (+20 pts) convergence to block
  const malvSignal = [{ id: 'RULE_MALVERTISING_REDIRECT', score: 65, triggered: true }];
  const redirectSignals = { chain: ['https://source.com', 'https://dest.monster'], redirectCount: 1, suspicious: true };
  const malvRedirectVerdict = calculateRisk('https://dest.monster', malvSignal, null, null, null, redirectSignals);
  assert.equal(malvRedirectVerdict.action, 'block');
  assert.ok(malvRedirectVerdict.score >= 70);

  // url + ml (both >= 20) (+15 pts)
  const urlSignals = [{ id: 'RULE_SUSPICIOUS_URL_PATTERN', score: 30, triggered: true }];
  const urlMlVerdict = calculateRisk('https://suspicious-ml.com', urlSignals, 80, null);
  // ml 80 scaled: 80 * 0.35 = 28 pts. url: 30 pts. Capped: 30 + round(28 * 0.65) = 48 + 15 = 63.
  assert.ok(urlMlVerdict.score >= 60);
});


