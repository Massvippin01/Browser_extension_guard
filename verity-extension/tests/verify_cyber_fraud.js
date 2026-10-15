/**
 * tests/verify_cyber_fraud.js
 * 
 * Comprehensive Verification Suite for Verity 2.0 Cyber Fraud Defenses:
 * 1. Fake HDFC KYC update portal asking for PAN number and NetBanking password.
 * 2. Fake Razorpay/UPI checkout page on an unverified domain asking for UPI PIN or Credit Card/CVV.
 * 3. Phishing page exfiltrating credentials to a Telegram Bot API endpoint.
 * 4. Legitimate gateways (Razorpay, HDFC NetBanking) verifying 0 False Positives (SAFE / ALLOW).
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import { calculateRisk } from '../background/risk-engine.js';
import { analyzePaymentPage } from '../background/payment-detector.js';
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
import { isAllowlistedDomain } from '../shared/legit-domains.js';

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

test('Cyber Fraud Case 1: Fake HDFC KYC portal (PAN + NetBanking password + urgency lure) must BLOCK (Score >= 85)', () => {
  const url = 'http://hdfc-kyc-pan-update.xyz/login';
  const ruleSignals = runUrlRules(url);

  const domSignals = {
    isTrustedDomain: false,
    pageTitle: 'HDFC Bank NetBanking - Mandatory KYC Update',
    pageText: 'Your HDFC account will be blocked within 24 hours. Complete your KYC update and submit your PAN card number and NetBanking password to verify.',
    structuralText: 'HDFC Bank NetBanking - Mandatory KYC Update submit login hdfc logo',
    headingText: 'HDFC Bank NetBanking KYC Update',
    buttonLabels: 'Verify PAN & Login',
    claimedProviders: ['HDFC Bank'],
    hasPasswordInput: true,
    hasCredentialCollection: true,
    loginFormCount: 1,
    kycCyberFraud: true,
    kycCyberFraudReason: 'account will be blocked (PAN Number)',
    financialMatches: ['kyc', 'pan', 'netbanking']
  };

  const paymentAnalysis = analyzePaymentPage(url, domSignals, paymentBrands);
  const verdict = calculateRisk(url, ruleSignals, null, domSignals, null, null, paymentAnalysis);

  console.log('\n--- Case 1: Fake HDFC KYC Portal ---');
  console.log('URL:', url);
  console.log('Score:', verdict.score);
  console.log('Action:', verdict.action);
  console.log('Severity:', verdict.severity);
  console.log('Reasons:\n ', verdict.reasons.join('\n  '));

  assert.ok(verdict.score >= 85, `Score must be >= 85, got: ${verdict.score}`);
  assert.equal(verdict.action, 'block', `Action must be "block", got: ${verdict.action}`);
  assert.equal(verdict.severity, 'danger', `Severity must be "danger", got: ${verdict.severity}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_KYC_CYBER_FRAUD' || s.id === 'SIG_PAYMENT_BRAND_MISMATCH'));
});

test('Cyber Fraud Case 2: Fake Razorpay/UPI checkout page requesting in-browser UPI PIN must BLOCK (Score >= 95)', () => {
  const url = 'https://fast-recharge-offer.shop/pay';
  const ruleSignals = runUrlRules(url);

  const domSignals = {
    isTrustedDomain: false,
    pageTitle: 'Razorpay Secure Checkout - 90% Cashback',
    pageText: 'Special ₹10 Recharge Offer. Enter your 6-digit UPI PIN to claim cashback and verify transaction.',
    structuralText: 'Razorpay Secure Checkout - 90% Cashback razorpay secure checkout pay now',
    headingText: 'Razorpay Payment Gateway',
    buttonLabels: 'Authorize UPI Payment',
    claimedProviders: ['Razorpay'],
    paymentFields: { upi: true, pin: true },
    hasPaymentForm: true,
    illegalWebPinCollection: true,
    illegalWebPinReason: 'upi pin',
    financialMatches: ['upi', 'upi pin', 'cashback']
  };

  const paymentAnalysis = analyzePaymentPage(url, domSignals, paymentBrands);
  const verdict = calculateRisk(url, ruleSignals, null, domSignals, null, null, paymentAnalysis);

  console.log('\n--- Case 2: Fake Razorpay/UPI Checkout with Illegal UPI PIN ---');
  console.log('URL:', url);
  console.log('Score:', verdict.score);
  console.log('Action:', verdict.action);
  console.log('Severity:', verdict.severity);
  console.log('Reasons:\n ', verdict.reasons.join('\n  '));

  assert.ok(verdict.score >= 95, `Score must be >= 95, got: ${verdict.score}`);
  assert.equal(verdict.action, 'block', `Action must be "block", got: ${verdict.action}`);
  assert.equal(verdict.severity, 'danger', `Severity must be "danger", got: ${verdict.severity}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_ILLEGAL_WEB_PIN_COLLECTION'));
});

test('Cyber Fraud Case 3: Phishing page exfiltrating OTP to Telegram Bot API must BLOCK (Score >= 95)', () => {
  const url = 'https://secure-login-session.com/verify-otp';
  const ruleSignals = runUrlRules(url);

  const domSignals = {
    isTrustedDomain: false,
    pageTitle: 'Two-Factor Authentication Verification',
    pageText: 'Enter the One Time Password (OTP) sent to your mobile device to complete authentication.',
    hasSensitiveInputs: true,
    hasCredentialCollection: true,
    paymentFields: { otp: true },
    phishingKitWebhookExfil: true,
    webhookExfilEndpoint: 'api.telegram.org/bot123456:ABC/sendMessage',
    financialMatches: ['otp', 'verification']
  };

  const paymentAnalysis = analyzePaymentPage(url, domSignals, paymentBrands);
  const verdict = calculateRisk(url, ruleSignals, null, domSignals, null, null, paymentAnalysis);

  console.log('\n--- Case 3: Phishing Kit Exfiltration to Telegram Bot API ---');
  console.log('URL:', url);
  console.log('Score:', verdict.score);
  console.log('Action:', verdict.action);
  console.log('Severity:', verdict.severity);
  console.log('Reasons:\n ', verdict.reasons.join('\n  '));

  assert.ok(verdict.score >= 95, `Score must be >= 95, got: ${verdict.score}`);
  assert.equal(verdict.action, 'block', `Action must be "block", got: ${verdict.action}`);
  assert.equal(verdict.severity, 'danger', `Severity must be "danger", got: ${verdict.severity}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_PHISHING_KIT_WEBHOOK_EXFIL'));
});

test('Cyber Fraud Case 4: Legitimate Gateways & Banks must be ALLOWED (0 False Positives)', () => {
  // 1. Legitimate Razorpay checkout endpoint
  const razorpayUrl = 'https://checkout.razorpay.com/v1/checkout.js';
  assert.equal(isAllowlistedDomain(razorpayUrl), true, 'checkout.razorpay.com must be recognized as allowlisted');

  const razorpayDom = {
    isTrustedDomain: true,
    pageTitle: 'Razorpay Checkout',
    structuralText: 'Razorpay Checkout',
    paymentFields: { card: true, cvv: true, expiry: true },
    hasPaymentForm: true
  };
  const razorpayAnalysis = analyzePaymentPage(razorpayUrl, razorpayDom, paymentBrands);
  const razorpayVerdict = calculateRisk(razorpayUrl, [], null, razorpayDom, null, null, razorpayAnalysis);

  assert.equal(razorpayVerdict.action, 'allow', `Razorpay must be allow, got ${razorpayVerdict.action}`);
  assert.equal(razorpayVerdict.severity, 'safe', `Razorpay severity must be safe, got ${razorpayVerdict.severity}`);
  assert.ok(razorpayVerdict.score <= 40, `Razorpay score must be <= 40, got ${razorpayVerdict.score}`);

  // 2. Legitimate HDFC Bank NetBanking portal
  const hdfcUrl = 'https://netbanking.hdfcbank.com/netbanking/';
  assert.equal(isAllowlistedDomain(hdfcUrl), true, 'netbanking.hdfcbank.com must be recognized as allowlisted');

  const hdfcDom = {
    isTrustedDomain: true,
    pageTitle: 'Welcome to HDFC Bank NetBanking',
    structuralText: 'Welcome to HDFC Bank NetBanking Login Customer ID Password',
    hasPasswordInput: true,
    hasCredentialCollection: true,
    loginFormCount: 1,
    financialMatches: ['netbanking', 'login']
  };
  const hdfcAnalysis = analyzePaymentPage(hdfcUrl, hdfcDom, paymentBrands);
  const hdfcVerdict = calculateRisk(hdfcUrl, [], null, hdfcDom, null, null, hdfcAnalysis);

  assert.equal(hdfcVerdict.action, 'allow', `HDFC NetBanking must be allow, got ${hdfcVerdict.action}`);
  assert.equal(hdfcVerdict.severity, 'safe', `HDFC NetBanking severity must be safe, got ${hdfcVerdict.severity}`);
  assert.ok(hdfcVerdict.score <= 40, `HDFC NetBanking score must be <= 40, got ${hdfcVerdict.score}`);

  console.log('\n--- Case 4: Legitimate Gateways & Banks ---');
  console.log('Razorpay Score:', razorpayVerdict.score, 'Action:', razorpayVerdict.action);
  console.log('HDFC NetBanking Score:', hdfcVerdict.score, 'Action:', hdfcVerdict.action);
  console.log('✅ 0 False Positives confirmed on verified banking and payment processors.');
});
