import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateRisk } from '../background/risk-engine.js';
import { isAllowlistedDomain } from '../shared/legit-domains.js';

test('Allowlist Abuse 1: Form on allowlisted domain posting credentials to a different registered domain must BLOCK', () => {
  // Scenario: Compromised or XSS-injected page on an allowlisted banking domain (e.g. hdfcbank.com)
  // has a credential form posting to an external attacker domain (attacker-exfil.com).
  const allowlistedHost = 'hdfcbank.com';
  assert.equal(isAllowlistedDomain(allowlistedHost), true, 'Domain must be allowlisted');

  const ruleSignals = [];
  const domSignals = {
    hasPasswordInput: true,
    hasCredentialCollection: true,
    hasCrossDomainCredentialAction: true,
    exfilTargetDomain: 'attacker-exfil.com',
    loginFormCount: 1,
    formActions: ['https://attacker-exfil.com/collect_credentials.php']
  };

  const verdict = calculateRisk(
    'https://' + allowlistedHost + '/login',
    ruleSignals,
    null,
    domSignals,
    null,
    null,
    null,
    null
  );

  // Must BLOCK, bypassing the allowlist 40-point cap
  assert.equal(verdict.action, 'block', 'Cross-domain credential exfiltration must BLOCK');
  assert.equal(verdict.severity, 'danger', 'Severity must be danger');
  assert.ok(verdict.score >= 70, `Score should be >= 70, got ${verdict.score}`);
  assert.ok(
    verdict.signals.some(s => s.id === 'SIG_CROSS_DOMAIN_CREDENTIAL_EXFIL'),
    'SIG_CROSS_DOMAIN_CREDENTIAL_EXFIL signal must be emitted'
  );
});

test('Allowlist Abuse 2: User-content subdomains (*.github.io, *.pages.dev, *.firebaseapp.com) must NOT inherit allowlist status', () => {
  // Test common user-controlled hosting platforms
  const userSubdomains = [
    'phish-login.github.io',
    'bank-verification.pages.dev',
    'urgent-kyc.firebaseapp.com',
    'support-portal.web.app',
    'secure-account.blogspot.com',
    'banking-alert.vercel.app',
    'fake-update.netlify.app'
  ];

  for (const host of userSubdomains) {
    const isAllowlisted = isAllowlistedDomain(host);
    assert.equal(isAllowlisted, false, `User-content subdomain "${host}" must NOT inherit allowlist status`);
  }
});

test('Allowlist Abuse 3: Download on allowlisted domain marked dangerous by Chrome must BLOCK', () => {
  const allowlistedHost = 'amazon.com';
  assert.equal(isAllowlistedDomain(allowlistedHost), true, 'Domain must be allowlisted');

  const ruleSignals = [];
  const domSignals = null;
  const downloadSignals = {
    analysisContext: 'download',
    chromeSaysDangerous: true,
    filename: 'malicious_invoice.exe'
  };

  const verdict = calculateRisk(
    'https://' + allowlistedHost + '/order',
    ruleSignals,
    null,
    domSignals,
    null,
    null,
    null,
    downloadSignals
  );

  // Must BLOCK with danger severity, bypassing allowlist cap
  assert.equal(verdict.action, 'block', 'Dangerous download on allowlisted site must BLOCK');
  assert.equal(verdict.severity, 'danger');
  assert.ok(verdict.score >= 70, `Score must be >= 70, got ${verdict.score}`);
  assert.ok(
    verdict.signals.some(s => s.id === 'DOWNLOAD_CHROME_DANGEROUS'),
    'DOWNLOAD_CHROME_DANGEROUS signal must be emitted'
  );
});

test('Allowlist Normal Semantics: Clean allowlisted domain caps at Caution even with suspicious signals', () => {
  const allowlistedHost = 'sbi.co.in';
  assert.equal(isAllowlistedDomain(allowlistedHost), true);

  // Inject multiple benign or noisy DOM signals on legitimate banking domain
  const ruleSignals = [];
  const domSignals = {
    hasPasswordInput: true,
    hasCredentialCollection: true,
    hasPaymentForm: true,
    loginFormCount: 1,
    hasCrossDomainCredentialAction: false,
    formActions: ['https://sbi.co.in/login']
  };

  const verdict = calculateRisk(
    'https://' + allowlistedHost + '/portal',
    ruleSignals,
    null,
    domSignals,
    null,
    null,
    null,
    null
  );

  // Allowlist cap strictly enforces max Caution (score <= 40, action allow or warn, never block)
  assert.ok(verdict.score <= 40, `Allowlisted domain score must be capped <= 40, got ${verdict.score}`);
  assert.notEqual(verdict.action, 'block', 'Allowlisted domain without exfil/malware must NEVER block');
});
