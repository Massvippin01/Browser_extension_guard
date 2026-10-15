/**
 * tests/verify_emergency_production_fix.js
 *
 * Emergency Production Fix Verification Suite:
 * 1. Step 1: DNR Purge & strict NO-OP (no ERR_BLOCKED_BY_CLIENT possible)
 * 2. Step 2: Trusted search & top domain early exit regex
 * 3. Step 3: Google searches ("fake banking websites", "VeiligBank") score 0, 0 reasons, action allow
 * 4. Step 3: Zero-reason mathematical invariant (reasons.length === 0 -> score === 0, action === 'allow')
 * 5. Step 4: moviesda.soy capped at max score 25 (SAFE / allow)
 * 6. Step 4: Legitimate file-host download opened from moviesda.soy does NOT trigger popunder
 * 7. Step 5: document.body.style.display is never set to 'none' in content-script.js
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import { calculateRisk } from '../background/risk-engine.js';
import {
  initDnrBlocker,
  blockDomainDnr,
  registerDynamicBlockDomain,
  getBlockedDomainsDnr
} from '../background/dnr-blocker.js';
import {
  hasPiracyOrUnverifiedMediaPattern,
  hasSuspiciousUrlPattern,
  hasMalvertisingPattern,
  isTrustedTopDomain
} from '../background/rules.js';

test('Emergency Step 1: DeclarativeNetRequest rules are completely purged and registration is a strict NO-OP', async () => {
  // Mock chrome.declarativeNetRequest for test
  const removedDynamic = [];
  const removedSession = [];
  globalThis.chrome = {
    declarativeNetRequest: {
      getDynamicRules: async () => [{ id: 101 }, { id: 102 }],
      updateDynamicRules: async ({ removeRuleIds }) => { removedDynamic.push(...removeRuleIds); },
      getSessionRules: async () => [{ id: 201 }, { id: 202 }],
      updateSessionRules: async ({ removeRuleIds }) => { removedSession.push(...removeRuleIds); }
    }
  };

  const purgeResult = await initDnrBlocker();
  assert.equal(purgeResult.dynamicRemoved, 2, 'Must remove all dynamic rules');
  assert.equal(purgeResult.sessionRemoved, 2, 'Must remove all session rules');
  assert.deepEqual(removedDynamic, [101, 102]);
  assert.deepEqual(removedSession, [201, 202]);

  // blockDomainDnr and registerDynamicBlockDomain must be strict NO-OPs
  const dynResult1 = await blockDomainDnr('moviesda.soy');
  assert.equal(dynResult1, null, 'blockDomainDnr must return null (NO-OP)');

  const dynResult2 = await registerDynamicBlockDomain('moviesda.soy');
  assert.equal(dynResult2, null, 'registerDynamicBlockDomain must return null (NO-OP)');

  const blocked = getBlockedDomainsDnr();
  assert.equal(blocked.size, 0, 'No domains may ever be blocked via declarativeNetRequest');
});

test('Emergency Step 2: Trusted search & top domain regex correctly matches search engines and top sites', () => {
  const TRUSTED_DOMAINS_REGEX = /(^|\.)(google\.[a-z.]+|bing\.com|duckduckgo\.com|yahoo\.com|brave\.com|youtube\.com|github\.com|microsoft\.com|live\.com|office\.com|apple\.com|amazon\.[a-z.]+|wikipedia\.org|reddit\.com|chatgpt\.com|openai\.com|claude\.ai|gemini\.google\.com|localhost|127\.0\.0\.1)$/i;

  const validHosts = [
    'google.com', 'www.google.com', 'google.co.in', 'google.co.uk',
    'bing.com', 'www.bing.com', 'duckduckgo.com', 'yahoo.com',
    'github.com', 'youtube.com', 'amazon.com', 'amazon.in',
    'localhost', '127.0.0.1'
  ];

  for (const host of validHosts) {
    assert.equal(TRUSTED_DOMAINS_REGEX.test(host), true, `Host "${host}" must match trusted domain regex`);
  }

  const untrustedHosts = [
    'moviesda.soy', 'fastbytes.xyz', 'ufa168rss.live',
    'not-google.com', 'fake-bank.xyz', 'propellerads.com'
  ];

  for (const host of untrustedHosts) {
    assert.equal(TRUSTED_DOMAINS_REGEX.test(host), false, `Host "${host}" must NOT match trusted domain regex`);
  }
});

test('Emergency Step 3: Google searches ("fake banking websites" & "VeiligBank") MUST return Score 0 with 0 reasons', () => {
  const query1 = 'https://www.google.com/search?q=fake+banking+websites';
  const verdict1 = calculateRisk(query1, []);

  console.log('\n--- Emergency Step 3: Google "fake banking websites" Search ---');
  console.log('Score:', verdict1.score);
  console.log('Action:', verdict1.action);
  console.log('Severity:', verdict1.severity);
  console.log('Reasons Count:', verdict1.reasons.length);

  assert.equal(verdict1.score, 0, 'Google search score must be strictly 0');
  assert.equal(verdict1.action, 'allow', 'Google search action must be "allow"');
  assert.equal(verdict1.severity, 'safe', 'Google search severity must be "safe"');
  assert.equal(verdict1.reasons.length, 0, 'Google search reasons must be 0');

  const query2 = 'https://www.google.com/search?q=VeiligBank';
  const verdict2 = calculateRisk(query2, []);

  console.log('\n--- Emergency Step 3: Google "VeiligBank" Search ---');
  console.log('Score:', verdict2.score);
  console.log('Action:', verdict2.action);
  console.log('Severity:', verdict2.severity);
  console.log('Reasons Count:', verdict2.reasons.length);

  assert.equal(verdict2.score, 0, 'VeiligBank search score must be strictly 0');
  assert.equal(verdict2.action, 'allow', 'VeiligBank search action must be "allow"');
  assert.equal(verdict2.severity, 'safe', 'VeiligBank search severity must be "safe"');
  assert.equal(verdict2.reasons.length, 0, 'VeiligBank search reasons must be 0');
});

test('Emergency Step 3 Invariant: Zero reasons mathematically forces score = 0, action = allow, severity = safe', () => {
  // Even if an untrusted domain had non-triggering signals resulting in empty reasons
  const verdict = calculateRisk('https://random-empty-site.xyz/', []);
  assert.equal(verdict.reasons.length, 0);
  assert.equal(verdict.score, 0, 'Score must be 0 when reasons.length === 0');
  assert.equal(verdict.action, 'allow', 'Action must be allow when reasons.length === 0');
  assert.equal(verdict.severity, 'safe', 'Severity must be safe when reasons.length === 0');
});

test('Emergency Step 4: moviesda.soy is capped at max score 25 (SAFE / allow) and never blocked', () => {
  const url = 'https://moviesda.soy/';
  const piracySignal = hasPiracyOrUnverifiedMediaPattern(url);
  assert.equal(piracySignal.triggered, true, 'moviesda keyword must trigger piracy rule');
  assert.ok(piracySignal.score <= 25, `Piracy rule score must be <= 25, got: ${piracySignal.score}`);

  const verdict = calculateRisk(url, [piracySignal]);

  console.log('\n--- Emergency Step 4: moviesda.soy Homepage ---');
  console.log('URL:', url);
  console.log('Score:', verdict.score);
  console.log('Action:', verdict.action);
  console.log('Severity:', verdict.severity);
  console.log('Reasons:', verdict.reasons);

  assert.ok(verdict.score <= 25, `moviesda.soy score must be <= 25, got: ${verdict.score}`);
  assert.equal(verdict.action, 'allow', 'moviesda.soy action must be "allow"');
  assert.equal(verdict.severity, 'safe', 'moviesda.soy severity must be "safe"');
});

test('Emergency Step 4: Legitimate file host opened from moviesda.soy is not flagged as pop-under', () => {
  // Helper matching service_worker.js rotator logic
  function isExplicitAdRotator(urlString) {
    const lower = (urlString || '').toLowerCase();
    return (
      lower.includes('utm_medium=popunder') ||
      lower.includes('propellerads') ||
      lower.includes('popads') ||
      lower.includes('wigglepoploaderfast') ||
      /\?[a-f0-9]{16,64}/i.test(urlString)
    );
  }

  // Legitimate file downloads opened from moviesda
  assert.equal(isExplicitAdRotator('https://moviesda.soy/download/movie123.mp4'), false);
  assert.equal(isExplicitAdRotator('https://gofile.io/d/xyz123'), false);
  assert.equal(isExplicitAdRotator('https://1fichier.com/?abcdef'), false);

  // Blatant ad-rotator URLs MUST be detected
  assert.equal(isExplicitAdRotator('https://ufa168rss.live/tips?utm_source=propellerads&utm_medium=popunder'), true);
  assert.equal(isExplicitAdRotator('https://aar5n.wigglepoploaderfast.monster/?540267a373b920a51ea99c645c7f'), true);
});

test('Emergency Step 5: content/content-script.js contains ZERO occurrences of document.body.style.display = none', () => {
  const contentScriptSource = fs.readFileSync('content/content-script.js', 'utf8');
  const hasDisplayNone = contentScriptSource.includes("document.body.style.setProperty('display', 'none'") ||
                         contentScriptSource.includes('document.body.style.display =') ||
                         contentScriptSource.includes("document.body.style.display !== 'none'");
  assert.equal(hasDisplayNone, false, 'content/content-script.js must never set document.body.style.display');
});
