/**
 * tests/verify_nextgen_hardening.js
 * 
 * Verification Test Suite for Verity 2.0 Next-Generation Security Hardening:
 * 1. Brand favicon/logo hotlinking from official bank (hdfcbank.com) on untrusted domain -> BLOCK (>= 90)
 * 2. Tech-support / AnyDesk KYC remote desktop scam page -> BLOCK (>= 85)
 * 3. Runtime webhook exfiltration / ClickFix clipboard attack / Digital arrest screen share -> BLOCK (>= 85)
 * 4. Remote desktop scam tool download (AnyDesk.exe) from untrusted domain -> BLOCK (>= 90)
 * 5. DNR Blocker dynamic session rules functionality
 * 6. Legitimate domains 0 False Positives (ALLOW / score <= 40)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import { calculateRisk } from '../background/risk-engine.js';
import { analyzePaymentPage } from '../background/payment-detector.js';
import { analyzeDownload } from '../background/download/downloadAnalyzer.js';
import { blockDomainDnr, getBlockedDomainsDnr, resetDnrForTesting } from '../background/dnr-blocker.js';
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
  hasAffiliateTrackerPattern
} from '../background/rules.js';

const paymentBrands = JSON.parse(fs.readFileSync('payment-brands.json', 'utf8'));

function runUrlRules(url) {
  const rules = [
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
    hasAffiliateTrackerPattern
  ];
  return rules.map(fn => fn(url)).filter(r => r && r.triggered);
}

test('NextGen Case 1: Brand favicon/logo hotlinking from hdfcbank.com on http://secure-update-portal.com must BLOCK (Score >= 90)', () => {
  const url = 'http://secure-update-portal.com/banking/update';
  const ruleSignals = runUrlRules(url);

  const domSignals = {
    isTrustedDomain: false,
    pageTitle: 'Account Security Update',
    pageText: 'Please verify your credentials to retain account access.',
    hasPasswordInput: true,
    hasCredentialCollection: true,
    brandAssetUrls: [
      'https://www.hdfcbank.com/static/features/netbanking/logo.png',
      'https://www.hdfcbank.com/favicon.ico'
    ]
  };

  const paymentAnalysis = analyzePaymentPage(url, domSignals, paymentBrands);
  assert.ok(paymentAnalysis, 'Payment analysis should run for brand asset URLs');
  
  const hasHotlinkSpoof = paymentAnalysis.structuredReasons.some(r => r.id === 'SIG_BRAND_ASSET_HOTLINK_SPOOF');
  assert.ok(hasHotlinkSpoof, 'Payment analysis must detect SIG_BRAND_ASSET_HOTLINK_SPOOF');

  const verdict = calculateRisk(url, ruleSignals, null, domSignals, null, null, paymentAnalysis);

  console.log('\n--- NextGen Case 1: Brand Asset Hotlinking Spoof ---');
  console.log('URL:', url);
  console.log('Score:', verdict.score);
  console.log('Action:', verdict.action);
  console.log('Severity:', verdict.severity);
  console.log('Reasons:\n ', verdict.reasons.join('\n  '));

  assert.ok(verdict.score >= 90, `Score must be >= 90, got: ${verdict.score}`);
  assert.equal(verdict.action, 'block', `Action must be "block", got: ${verdict.action}`);
  assert.equal(verdict.severity, 'danger', `Severity must be "danger", got: ${verdict.severity}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_BRAND_ASSET_HOTLINK_SPOOF'), 'Verdict must include SIG_BRAND_ASSET_HOTLINK_SPOOF');
});

test('NextGen Case 2: Tech support / AnyDesk KYC scam page must BLOCK (Score >= 85)', () => {
  const url = 'http://customer-support-helpdesk.top/kyc-fix';
  const ruleSignals = runUrlRules(url);

  const domSignals = {
    isTrustedDomain: false,
    pageTitle: 'Bank Customer Support - Urgent KYC Helpdesk',
    pageText: 'Your bank account has been suspended due to pending KYC verification. Please install AnyDesk immediately and call our 24x7 customer care helpline to restore access.',
    techSupportRemoteScam: true,
    techSupportRemoteScamReason: 'Prompting installation of remote access tool "anydesk" alongside "customer care helpline" lure',
    techSupportHelpline: 'anydesk customer care helpline'
  };

  const verdict = calculateRisk(url, ruleSignals, null, domSignals, null, null, null);

  console.log('\n--- NextGen Case 2: Tech Support Remote Scam ---');
  console.log('URL:', url);
  console.log('Score:', verdict.score);
  console.log('Action:', verdict.action);
  console.log('Severity:', verdict.severity);
  console.log('Reasons:\n ', verdict.reasons.join('\n  '));

  assert.ok(verdict.score >= 85, `Score must be >= 85, got: ${verdict.score}`);
  assert.equal(verdict.action, 'block', `Action must be "block", got: ${verdict.action}`);
  assert.equal(verdict.severity, 'danger', `Severity must be "danger", got: ${verdict.severity}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_TECH_SUPPORT_REMOTE_SCAM'), 'Verdict must include SIG_TECH_SUPPORT_REMOTE_SCAM');
});

test('NextGen Case 3: Runtime webhook exfiltration and ClickFix clipboard attack must BLOCK (Score >= 95 / >= 85)', () => {
  // 3a. Runtime Webhook Exfiltration
  const webhookUrl = 'https://fake-login-form.com/login';
  const domSignalsWebhook = {
    isTrustedDomain: false,
    phishingKitWebhookExfil: true,
    webhookExfilEndpoint: 'https://discord.com/api/webhooks/987654321/token'
  };

  const verdictWebhook = calculateRisk(webhookUrl, [], null, domSignalsWebhook, null, null, null);
  assert.ok(verdictWebhook.score >= 95, `Webhook exfil score must be >= 95, got: ${verdictWebhook.score}`);
  assert.equal(verdictWebhook.action, 'block');
  assert.ok(verdictWebhook.signals.some(s => s.id === 'SIG_PHISHING_KIT_WEBHOOK_EXFIL'));

  // 3b. Live ClickFix Clipboard Injection Attack
  const clickFixUrl = 'https://captcha-solve-robot.click/verify';
  const domSignalsClickFix = {
    isTrustedDomain: false,
    clickFixAttack: true,
    clickFixReason: 'ClickFix clipboard payload detected: powershell -enc...'
  };

  const verdictClickFix = calculateRisk(clickFixUrl, [], null, domSignalsClickFix, null, null, null);
  assert.ok(verdictClickFix.score >= 85, `ClickFix score must be >= 85, got: ${verdictClickFix.score}`);
  assert.equal(verdictClickFix.action, 'block');
  assert.ok(verdictClickFix.signals.some(s => s.id === 'SIG_CLICKFIX_CLIPBOARD_ATTACK'));

  // 3c. Untrusted Screen Sharing Attempt (Digital Arrest / Tech-Support)
  const screenShareUrl = 'https://cyber-crime-cell-notice.xyz/court';
  const domSignalsScreen = {
    isTrustedDomain: false,
    untrustedScreenShare: true
  };

  const verdictScreen = calculateRisk(screenShareUrl, [], null, domSignalsScreen, null, null, null);
  assert.ok(verdictScreen.score >= 85, `Screen share score must be >= 85, got: ${verdictScreen.score}`);
  assert.equal(verdictScreen.action, 'block');
  assert.ok(verdictScreen.signals.some(s => s.id === 'SIG_UNTRUSTED_SCREEN_SHARE'));
});

test('NextGen Case 4: Remote Access Tool Download (AnyDesk.exe) from untrusted domain must BLOCK (Score >= 90)', async () => {
  const downloadItem = {
    url: 'http://fake-customer-care-portal.com/downloads/AnyDesk.exe',
    finalUrl: 'http://fake-customer-care-portal.com/downloads/AnyDesk.exe',
    filename: 'AnyDesk.exe',
    originatingHostname: 'fake-customer-care-portal.com',
    fileSize: 4500000
  };

  const { verdict, downloadSignals } = await analyzeDownload(downloadItem, null, calculateRisk, []);

  console.log('\n--- NextGen Case 4: Remote Desktop Download from Untrusted Origin ---');
  console.log('Filename:', downloadSignals.filename);
  console.log('Score:', verdict.score);
  console.log('Action:', verdict.action);
  console.log('Severity:', verdict.severity);
  console.log('Reasons:\n ', verdict.reasons.join('\n  '));

  assert.ok(downloadSignals.remoteAccessScam, 'downloadSignals must flag remoteAccessScam');
  assert.ok(verdict.score >= 90, `Verdict score must be >= 90, got: ${verdict.score}`);
  assert.equal(verdict.action, 'block', `Action must be "block", got: ${verdict.action}`);
  assert.equal(verdict.severity, 'danger', `Severity must be "danger", got: ${verdict.severity}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_REMOTE_ACCESS_SCAM_DOWNLOAD'), 'Verdict must include SIG_REMOTE_ACCESS_SCAM_DOWNLOAD');
});

test('NextGen Case 5: DNR Blocker dynamic session rules & rolling cap', async () => {
  resetDnrForTesting();

  // Test blocking a malicious domain
  const rule1 = await blockDomainDnr('malicious-rotator-test.xyz');
  assert.ok(rule1, 'Rule must be registered');
  assert.equal(rule1.action.type, 'block');
  assert.equal(rule1.condition.urlFilter, '||malicious-rotator-test.xyz^');

  // Verify blocked domains set
  const blocked = getBlockedDomainsDnr();
  assert.ok(blocked.has('malicious-rotator-test.xyz'));

  // Allowlisted domains must never be blocked by DNR
  const allowlistRule = await blockDomainDnr('google.com');
  assert.equal(allowlistRule, null, 'Allowlisted domains must return null and not be blocked');
  assert.ok(!blocked.has('google.com'));
});

test('NextGen Case 6: Legitimate Brand Gateways & Downloads (0 False Positives)', async () => {
  // Official HDFC Bank hosting its own assets
  const hdfcUrl = 'https://www.hdfcbank.com/personal';
  const hdfcDom = {
    isTrustedDomain: true,
    pageTitle: 'HDFC Bank - Personal Banking',
    brandAssetUrls: [
      'https://www.hdfcbank.com/static/features/netbanking/logo.png',
      'https://www.hdfcbank.com/favicon.ico'
    ]
  };
  const hdfcAnalysis = analyzePaymentPage(hdfcUrl, hdfcDom, paymentBrands);
  if (hdfcAnalysis) {
    assert.ok(
      !hdfcAnalysis.structuredReasons.some(r => r.id === 'SIG_BRAND_ASSET_HOTLINK_SPOOF'),
      'Official HDFC Bank domain must not flag asset hotlinking'
    );
  }
  const hdfcVerdict = calculateRisk(hdfcUrl, [], null, hdfcDom, null, null, hdfcAnalysis);
  assert.ok(hdfcVerdict.score <= 40, `HDFC Bank score must be <= 40, got: ${hdfcVerdict.score}`);
  assert.notEqual(hdfcVerdict.action, 'block');

  // Official AnyDesk Download
  const anydeskDownload = {
    url: 'https://download.anydesk.com/AnyDesk.exe',
    finalUrl: 'https://download.anydesk.com/AnyDesk.exe',
    filename: 'AnyDesk.exe',
    originatingHostname: 'anydesk.com',
    fileSize: 4500000
  };
  const { verdict: anydeskVerdict, downloadSignals } = await analyzeDownload(anydeskDownload, null, calculateRisk, []);
  assert.equal(downloadSignals.remoteAccessScam, false, 'Official AnyDesk domain must not flag remoteAccessScam');
});
