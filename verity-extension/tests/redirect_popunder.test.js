import test from 'node:test';
import assert from 'node:assert/strict';

// Set up mock chrome.storage.session for test environment
const mockStorage = {};
globalThis.chrome = {
  storage: {
    session: {
      get: async (key) => {
        if (!key) return { ...mockStorage };
        if (Array.isArray(key)) {
          const res = {};
          key.forEach(k => { if (mockStorage[k]) res[k] = mockStorage[k]; });
          return res;
        }
        const res = {};
        if (mockStorage[key]) res[key] = mockStorage[key];
        return res;
      },
      set: async (items) => {
        Object.assign(mockStorage, items);
      },
      remove: async (keys) => {
        const arr = Array.isArray(keys) ? keys : [keys];
        arr.forEach(k => delete mockStorage[k]);
      }
    }
  }
};

import {
  recordNavigationTarget,
  recordHop,
  getRedirectSignals,
  getRedirectSignalsAsync,
  hydrateFromStorage,
  pruneTab
} from '../background/redirect-analyzer.js';
import { calculateRisk } from '../background/risk-engine.js';
import { hasSuspiciousUrlPattern, hasMalvertisingPattern } from '../background/rules.js';

test('Pop-under Detection: newly spawned tab to different root domain emits SIG_POPUNDER_SPAWN (+40 pts)', () => {
  const sourceTabId = 101;
  const spawnedTabId = 202;
  const targetUrl = 'https://aar5n.wigglepoploaderfast.monster/?540267a373b920a51ea99c645c7f';

  // 1. Source tab is on a sketchy streaming site
  recordHop(sourceTabId, 'https://sketchy-streaming-portal.to/play/movie');

  // 2. Window.open creates navigation target
  recordNavigationTarget({
    sourceTabId,
    tabId: spawnedTabId,
    url: targetUrl,
    timeStamp: Date.now()
  });

  // 3. New tab navigates to the target pop-under URL within 3s
  recordHop(spawnedTabId, targetUrl);

  const signals = getRedirectSignals(spawnedTabId);
  assert.ok(signals !== null, 'Redirect signals should not be null for pop-under spawn');
  assert.equal(signals.popunderSpawn, true, 'popunderSpawn should be true');

  const popReason = signals.structuredReasons.find(r => r.id === 'SIG_POPUNDER_SPAWN');
  assert.ok(popReason.score >= 40, `SIG_POPUNDER_SPAWN must have score >= 40, got ${popReason.score}`);
  assert.equal(popReason.category, 'malvertising', 'SIG_POPUNDER_SPAWN category must be malvertising');
  assert.equal(popReason.source, 'redirect', 'SIG_POPUNDER_SPAWN source must be redirect');
  assert.equal(popReason.params.sourceDomain, 'sketchy-streaming-portal.to');
  assert.equal(popReason.params.targetDomain, 'wigglepoploaderfast.monster');

  // 4. Evaluate with calculateRisk
  const ruleSignals = [
    hasSuspiciousUrlPattern(targetUrl),
    hasMalvertisingPattern(targetUrl)
  ];
  const verdict = calculateRisk(targetUrl, ruleSignals, null, null, null, signals);
  assert.equal(verdict.action, 'block', 'Corroborated pop-under must reach BLOCK');
  assert.equal(verdict.severity, 'danger');
  assert.ok(verdict.score >= 70, `Score must be >= 70, got: ${verdict.score}`);
  assert.ok(verdict.activeSources.includes('redirect'), 'activeSources must include redirect');
});

test('Session Storage Mirroring: hop chains survive simulated service worker termination', async () => {
  const testTabId = 303;

  // Record a 3-hop redirect chain
  recordHop(testTabId, 'https://first-tracker.click/go');
  recordHop(testTabId, 'https://intermediate-rotator.buzz/cx/123');
  recordHop(testTabId, 'https://destination-lander.monster/land');

  // Verify stored in session storage mirror
  assert.ok(mockStorage['redirect_chain_' + testTabId], 'Must be mirrored in session storage');
  const storedData = mockStorage['redirect_chain_' + testTabId];
  assert.equal(storedData.chain.length, 3);

  // Hydrate into in-memory cache
  await hydrateFromStorage();
  const signals = await getRedirectSignalsAsync(testTabId);
  assert.ok(signals !== null);
  assert.equal(signals.redirectCount, 2);
  assert.equal(signals.chain.length, 3);
  assert.equal(signals.chain[2], 'https://destination-lander.monster/land');

  // Test pruning on tab close
  pruneTab(testTabId);
  assert.equal(mockStorage['redirect_chain_' + testTabId], undefined, 'Session storage entry must be removed on prune');
  assert.equal(getRedirectSignals(testTabId), null, 'In-memory entry must be removed on prune');
});

test('Same root domain navigation does NOT trigger pop-under flag', () => {
  const sourceTab = 401;
  const childTab = 402;

  recordHop(sourceTab, 'https://github.com/google/verity');
  recordNavigationTarget({
    sourceTabId: sourceTab,
    tabId: childTab,
    url: 'https://github.com/google/verity/issues/42',
    timeStamp: Date.now()
  });
  recordHop(childTab, 'https://github.com/google/verity/issues/42');

  const signals = getRedirectSignals(childTab);
  // Same domain, single hop -> null (clean navigation)
  assert.equal(signals, null, 'Same domain navigation should not trigger popunder flag');
});

test('Pop-under Detection: navigation occurring after 3 seconds does NOT trigger pop-under flag', () => {
  const sourceTab = 501;
  const childTab = 502;
  const targetUrl = 'https://unverified-lander.monster/';

  recordHop(sourceTab, 'https://streaming-site.to/watch');
  recordNavigationTarget({
    sourceTabId: sourceTab,
    tabId: childTab,
    url: 'about:blank',
    timeStamp: Date.now() - 4000 // 4 seconds ago (> 3s window)
  });

  recordHop(childTab, targetUrl);
  const signals = getRedirectSignals(childTab);
  assert.equal(signals, null, 'Expired spawn (> 3s) must not trigger pop-under flag');
});

test('Pop-under Detection: window.open about:blank that navigates within 3s triggers SIG_POPUNDER_SPAWN', () => {
  const sourceTab = 601;
  const childTab = 602;
  const targetUrl = 'https://fastrotator.monster/click';

  recordHop(sourceTab, 'https://sketchy-portal.xyz/home');
  recordNavigationTarget({
    sourceTabId: sourceTab,
    tabId: childTab,
    url: 'about:blank',
    timeStamp: Date.now()
  });

  // Navigates 500ms later to unverified destination
  recordHop(childTab, targetUrl);

  const signals = getRedirectSignals(childTab);
  assert.ok(signals !== null);
  assert.equal(signals.popunderSpawn, true);
  const sig = signals.structuredReasons.find(r => r.id === 'SIG_POPUNDER_SPAWN');
  assert.ok(sig, 'SIG_POPUNDER_SPAWN must be present');
  assert.ok(sig.score >= 40, `SIG_POPUNDER_SPAWN must have score >= 40, got ${sig.score}`);
  assert.equal(sig.category, 'malvertising');
});

test('Pop-under Detection: opening allowlisted domain does NOT trigger pop-under flag', () => {
  const sourceTab = 701;
  const childTab = 702;

  recordHop(sourceTab, 'https://sketchy-site.to/');
  recordNavigationTarget({
    sourceTabId: sourceTab,
    tabId: childTab,
    url: 'https://google.com/search?q=verity',
    timeStamp: Date.now()
  });
  recordHop(childTab, 'https://google.com/search?q=verity');

  const signals = getRedirectSignals(childTab);
  assert.equal(signals, null, 'Allowlisted destination must not trigger pop-under flag');
});

