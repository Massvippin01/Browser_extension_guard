/**
 * tests/verify_zero_trust_defenses.js
 * 
 * DEFCON / Enterprise Zero-Trust Verification Suite for Verity 2.0:
 * 1. BitB Fake Google OAuth Window on untrusted domain -> BLOCK (Score >= 95)
 * 2. Evilginx3 / Modlishka AiTM Microsoft 365 Reverse Proxy -> BLOCK (Score >= 95)
 * 3. Quishing / Malicious QR Code Payload (UPI trap / phishing URL) -> BLOCK (Score >= 85)
 * 4. Clipboard Crypto/UPI Address Swapper (SIG_CLIPBOARD_ADDRESS_SWAP) -> BLOCK (Score >= 95)
 * 5. Legitimate Microsoft & Google OAuth URLs -> ALLOW (Score: 0, 0 False Positives)
 * 6. Rogue Push Notification & SW Registration Trap -> BLOCK (Score >= 80)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import { calculateRisk } from '../background/risk-engine.js';
import { analyzePaymentPage } from '../background/payment-detector.js';
import { hasAitmProxyUrlSignature } from '../background/rules.js';
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
    hasAffiliateTrackerPattern,
    hasAitmProxyUrlSignature
  ];
  return rules.map(fn => fn(url)).filter(r => r && r.triggered);
}

test('Zero-Trust Case 1: Browser-in-the-Browser (BitB) Fake OAuth Window must BLOCK (Score >= 95)', () => {
  const url = 'https://free-game-skins.xyz/claim';
  const ruleSignals = runUrlRules(url);

  const domSignals = {
    isTrustedDomain: false,
    pageTitle: 'Claim Rare Skins - Login with Google',
    hasPasswordInput: true,
    hasCredentialCollection: true,
    bitbAttack: true,
    bitbTarget: 'https://accounts.google.com/o/oauth2/auth',
    bitbReason: 'Browser-in-the-Browser fake address bar "https://accounts.google.com/o/oauth2/auth" rendered on unverified domain "free-game-skins.xyz"'
  };

  const verdict = calculateRisk(url, ruleSignals, null, domSignals, null, null, null);

  console.log('\n--- Zero-Trust Case 1: BitB Fake OAuth Window ---');
  console.log('URL:', url);
  console.log('Score:', verdict.score);
  console.log('Action:', verdict.action);
  console.log('Severity:', verdict.severity);
  console.log('Reasons:\n ', verdict.reasons.join('\n  '));

  assert.ok(verdict.score >= 95, `BitB score must be >= 95, got: ${verdict.score}`);
  assert.equal(verdict.action, 'block', `Action must be "block", got: ${verdict.action}`);
  assert.equal(verdict.severity, 'danger', `Severity must be "danger", got: ${verdict.severity}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_BITB_FAKE_WINDOW_ATTACK'), 'Verdict must include SIG_BITB_FAKE_WINDOW_ATTACK');
});

test('Zero-Trust Case 2: Evilginx3 / Modlishka AiTM Reverse Proxy must BLOCK (Score >= 95)', () => {
  const url = 'https://login-office365-portal.com/common/oauth2/v2.0/authorize?client_id=12345';
  const ruleSignals = runUrlRules(url);

  // URL rule should trigger on proprietary Microsoft IdP endpoint
  const aitmUrlSig = ruleSignals.find(s => s.id === 'SIG_AITM_REVERSE_PROXY_PHISH');
  assert.ok(aitmUrlSig, 'URL rules must detect AiTM proprietary endpoint signature');

  const domSignals = {
    isTrustedDomain: false,
    pageTitle: 'Sign in to your Microsoft Account',
    hasPasswordInput: true,
    hasCredentialCollection: true,
    aitmReverseProxy: true,
    aitmReason: 'Proprietary identity provider input "input[name=\\"loginfmt\\"]" detected on non-official domain "login-office365-portal.com"'
  };

  const verdict = calculateRisk(url, ruleSignals, null, domSignals, null, null, null);

  console.log('\n--- Zero-Trust Case 2: AiTM Reverse Proxy ---');
  console.log('URL:', url);
  console.log('Score:', verdict.score);
  console.log('Action:', verdict.action);
  console.log('Severity:', verdict.severity);
  console.log('Reasons:\n ', verdict.reasons.join('\n  '));

  assert.ok(verdict.score >= 95, `AiTM score must be >= 95, got: ${verdict.score}`);
  assert.equal(verdict.action, 'block', `Action must be "block", got: ${verdict.action}`);
  assert.equal(verdict.severity, 'danger', `Severity must be "danger", got: ${verdict.severity}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_AITM_REVERSE_PROXY_PHISH'), 'Verdict must include SIG_AITM_REVERSE_PROXY_PHISH');
});

test('Zero-Trust Case 3: Quishing / Malicious QR Code Payload must BLOCK (Score >= 85)', () => {
  const url = 'https://utility-bill-discount.top/pay';
  const ruleSignals = runUrlRules(url);

  const domSignals = {
    isTrustedDomain: false,
    pageTitle: 'Electricity Bill Instant Payment',
    pageText: 'Scan the QR code below using Google Pay or PhonePe to claim 50% cashback.',
    maliciousQrPayload: true,
    maliciousQrType: 'Unverified UPI Payment Deep-Link QR Code (upi://pay?pa=fraudster@ybl&am=25000)'
  };

  const paymentAnalysis = analyzePaymentPage(url, domSignals, paymentBrands);
  assert.ok(paymentAnalysis, 'Payment analysis should process malicious QR signal');
  assert.ok(paymentAnalysis.structuredReasons.some(r => r.id === 'SIG_MALICIOUS_QR_PAYLOAD'));

  const verdict = calculateRisk(url, ruleSignals, null, domSignals, null, null, paymentAnalysis);

  console.log('\n--- Zero-Trust Case 3: Malicious QR Payload (Quishing) ---');
  console.log('URL:', url);
  console.log('Score:', verdict.score);
  console.log('Action:', verdict.action);
  console.log('Severity:', verdict.severity);
  console.log('Reasons:\n ', verdict.reasons.join('\n  '));

  assert.ok(verdict.score >= 85, `QR payload score must be >= 85, got: ${verdict.score}`);
  assert.equal(verdict.action, 'block', `Action must be "block", got: ${verdict.action}`);
  assert.equal(verdict.severity, 'danger', `Severity must be "danger", got: ${verdict.severity}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_MALICIOUS_QR_PAYLOAD'), 'Verdict must include SIG_MALICIOUS_QR_PAYLOAD');
});

test('Zero-Trust Case 4: Clipboard Crypto/UPI Address Swapper must BLOCK (Score >= 95)', () => {
  const url = 'https://web3-airdrop-claim.live/connect';
  const ruleSignals = runUrlRules(url);

  const domSignals = {
    isTrustedDomain: false,
    clipboardAddressSwap: true,
    clipboardSwapType: 'ETH/EVM'
  };

  const verdict = calculateRisk(url, ruleSignals, null, domSignals, null, null, null);

  console.log('\n--- Zero-Trust Case 4: Clipboard Address Swapper ---');
  console.log('URL:', url);
  console.log('Score:', verdict.score);
  console.log('Action:', verdict.action);
  console.log('Severity:', verdict.severity);
  console.log('Reasons:\n ', verdict.reasons.join('\n  '));

  assert.ok(verdict.score >= 95, `Clipboard swapper score must be >= 95, got: ${verdict.score}`);
  assert.equal(verdict.action, 'block', `Action must be "block", got: ${verdict.action}`);
  assert.equal(verdict.severity, 'danger', `Severity must be "danger", got: ${verdict.severity}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_CLIPBOARD_ADDRESS_SWAP'), 'Verdict must include SIG_CLIPBOARD_ADDRESS_SWAP');
});

test('Zero-Trust Case 5: Legitimate Microsoft & Google OAuth URLs must ALLOW (Score: 0, 0 False Positives)', () => {
  // Official Microsoft OAuth URL
  const msUrl = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=official-app';
  const msSignals = runUrlRules(msUrl);
  const msAitm = msSignals.find(s => s.id === 'SIG_AITM_REVERSE_PROXY_PHISH');
  assert.equal(msAitm, undefined, 'Official Microsoft domain must never trigger AiTM proxy signature');

  const msVerdict = calculateRisk(msUrl, msSignals, 0, null, null, null, null);
  assert.equal(msVerdict.action, 'allow', `Microsoft OAuth must be allowed, got: ${msVerdict.action}`);
  assert.equal(msVerdict.score, 0, `Microsoft OAuth score must be 0, got: ${msVerdict.score}`);

  // Official Google OAuth URL
  const googleUrl = 'https://accounts.google.com/signin/v2/identifier';
  const googleSignals = runUrlRules(googleUrl);
  const googleAitm = googleSignals.find(s => s.id === 'SIG_AITM_REVERSE_PROXY_PHISH');
  assert.equal(googleAitm, undefined, 'Official Google domain must never trigger AiTM proxy signature');

  const googleVerdict = calculateRisk(googleUrl, googleSignals, 0, null, null, null, null);
  assert.equal(googleVerdict.action, 'allow', `Google OAuth must be allowed, got: ${googleVerdict.action}`);
  assert.equal(googleVerdict.score, 0, `Google OAuth score must be 0, got: ${googleVerdict.score}`);

  console.log('\n--- Zero-Trust Case 5: Legitimate OAuth Zero False Positives ---');
  console.log('Microsoft OAuth Score:', msVerdict.score, 'Action:', msVerdict.action);
  console.log('Google OAuth Score:', googleVerdict.score, 'Action:', googleVerdict.action);
  console.log('✅ 0 False Positives confirmed on official IdP domains.');
});

test('Zero-Trust Case 6: Rogue Push Notification & SW Registration Trap must BLOCK (Score >= 80)', () => {
  const url = 'https://aar5n.wigglepoploaderfast.monster/?push_prompt=1';
  const ruleSignals = runUrlRules(url);

  const domSignals = {
    isTrustedDomain: false,
    roguePushOrSwTrap: true
  };

  const verdict = calculateRisk(url, ruleSignals, null, domSignals, null, null, null);

  console.log('\n--- Zero-Trust Case 6: Rogue Push Notification / SW Trap ---');
  console.log('URL:', url);
  console.log('Score:', verdict.score);
  console.log('Action:', verdict.action);
  console.log('Severity:', verdict.severity);
  console.log('Reasons:\n ', verdict.reasons.join('\n  '));

  assert.ok(verdict.score >= 80, `Rogue push score must be >= 80, got: ${verdict.score}`);
  assert.equal(verdict.action, 'block', `Action must be "block", got: ${verdict.action}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_ROGUE_PUSH_OR_SW_TRAP'), 'Verdict must include SIG_ROGUE_PUSH_OR_SW_TRAP');
});
