import { 
  isIpBasedUrl, 
  hasMissingHttps, 
  hasExcessiveSubdomains, 
  hasBrandNameInWrongDomain, 
  hasSuspiciousUrlPattern 
} from './rules.js';

import { calculateRisk } from './risk-engine.js';
import { initializeModel, getMlScore } from './ml-scorer.js';
import { checkThreatIntel } from './threat-intel.js';
import { getRedirectSignals } from './redirect-analyzer.js';
import { saveToHistory } from './history.js';

let brandsListCache = null;
let trancoCache = null;

// Load allowlist
async function getAllowList() {
  if (trancoCache) return trancoCache;
  try {
    const url = chrome.runtime.getURL('tranco_1000.json');
    const res = await fetch(url);
    if (res.ok) {
      const list = await res.json();
      trancoCache = new Set(list);
      console.log('[Verity] Loaded Tranco allowlist:', trancoCache.size);
    }
  } catch (e) {
    console.warn('[Verity] Failed to load Tranco allowlist', e);
  }
  return trancoCache || new Set();
}

// Load brands from local JSON with caching
async function getBrandsList() {
  if (brandsListCache) return brandsListCache;
  try {
    const url = chrome.runtime.getURL('brands.json');
    const response = await fetch(url);
    if (response.ok) {
      brandsListCache = await response.json();
      console.log('[Verity] Loaded brands:', brandsListCache.length);
    }
  } catch (error) {
    console.error('[Verity] Error loading brands.json:', error);
  }
  return brandsListCache || [];
}

// Initialize on service worker startup
getBrandsList();
getAllowList();
initializeModel();

// Hot Reload logic
chrome.alarms.create('hotReloadBrands', { periodInMinutes: 60 });
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'hotReloadBrands') {
    try {
      // Stub URL for hot reload
      const res = await fetch('https://raw.githubusercontent.com/example/verity-brands/main/brands.json');
      if (res.ok) {
        const newBrands = await res.json();
        // Merge into cache (rudimentary merge for mock)
        if (Array.isArray(newBrands)) {
           brandsListCache = newBrands;
           console.log('[Verity] Hot-reloaded brands list.');
        }
      }
    } catch (e) {
      console.log('[Verity] Hot-reload failed (expected if stub URL offline). Proceeding with local cache.');
    }
  }
});

/**
 * Handles completed page navigations
 */
chrome.webNavigation.onCompleted.addListener(async (details) => {
  // Only process the main frame (top level navigation)
  if (details.frameId !== 0) return;

  const url = details.url;
  const tabId = details.tabId;

  // Ignore extension pages and internal browser pages
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) {
    return;
  }

  try {
    const startScoring = performance.now();
    const urlObj = new URL(url);
    const allowList = await getAllowList();

    // Check allowlist bypass
    let cleanHost = urlObj.hostname.replace(/^www\./, '');
    if (allowList.has(cleanHost)) {
      const scoringTimeMs = performance.now() - startScoring;
      await chrome.storage.session.set({
        [tabId.toString()]: {
          url: url,
          score: 0,
          state: 'safe',
          reasons: ['Domain is in the trusted Tranco Top 1000 list.'],
          ruleScore: 0,
          mlScore: null,
          mlAvailable: false,
          scoringTimeMs: scoringTimeMs,
          timestamp: Date.now()
        }
      });
      updateBadge(tabId, 'safe');
      return;
    }

    const brandsList = await getBrandsList();

    // Run all rules
    const ruleSignals = [
      isIpBasedUrl(url),
      hasMissingHttps(url),
      hasExcessiveSubdomains(url),
      hasBrandNameInWrongDomain(url, brandsList),
      hasSuspiciousUrlPattern(url)
    ];

    // Fetch DOM signals from the content script
    let domSignals = null;
    try {
      domSignals = await chrome.tabs.sendMessage(tabId, { action: 'get_dom_signals' });
    } catch (err) {
      console.warn(`[Verity] Could not get DOM signals for tab ${tabId}`);
    }

    // Get ML Score (null if unavailable or failed)
    const mlScore = await getMlScore(url, domSignals);

    // Get Redirect Signals
    const redirectSignals = getRedirectSignals(tabId);

    // Calculate initial verdict
    const verdict = calculateRisk(url, ruleSignals, mlScore, domSignals, null, redirectSignals);
    
    const scoringTimeMs = performance.now() - startScoring;
    
    let screenshotData = null;
    if (verdict.state === 'danger') {
      try {
        const tab = await chrome.tabs.get(tabId);
        screenshotData = await chrome.tabs.captureVisibleTab(tab.windowId, { format: 'png' });
      } catch (err) { }
    }
    verdict.screenshot = screenshotData;
    
    const saveVerdict = async (v, time) => {
      await chrome.storage.session.set({
        [tabId.toString()]: {
          url: url,
          score: v.score,
          state: v.state,
          categories: v.categories,
          reasons: v.reasons,
          ruleScore: v.ruleScore,
          mlScore: mlScore,
          mlAvailable: mlScore !== null,
          scoringTimeMs: time,
          timestamp: Date.now()
        }
      });
      updateBadge(tabId, v.severity || v.state);
      if (v.severity === 'danger' || v.state === 'danger') {
        try {
          await chrome.tabs.sendMessage(tabId, { action: 'show_danger_overlay', verdict: v });
        } catch (err) {}
      }
      // Save to history on every processed navigation
      await saveToHistory(v, url);
    };

    await saveVerdict(verdict, scoringTimeMs);

    // Second Wave: Threat Intel
    checkThreatIntel(url).then(async (threatIntel) => {
      if (threatIntel && threatIntel.malware) {
        const secondWaveTime = performance.now() - startScoring;
        const newVerdict = calculateRisk(url, ruleSignals, mlScore, domSignals, threatIntel, redirectSignals);
        newVerdict.screenshot = screenshotData;
        await saveVerdict(newVerdict, secondWaveTime);
      }
    });

  } catch (err) {
    console.error('[Verity] Error processing navigation:', err);
  }
});

/**
 * Updates the extension badge based on the state.
 */
function updateBadge(tabId, state) {
  let text = '';
  let color = '#000000';
  let stateName = 'safe';

  switch (state) {
    case 'safe':
      text = '✓';
      color = '#10b981'; // emerald
      stateName = 'safe';
      break;
    case 'caution':
      text = '!';
      color = '#f59e0b'; // amber
      stateName = 'caution';
      break;
    case 'danger':
      text = '!';
      color = '#ef4444'; // crimson
      stateName = 'danger';
      break;
  }

  chrome.action.setBadgeText({ text: text, tabId: tabId });
  chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
  chrome.action.setIcon({
    tabId: tabId,
    path: {
      "16": `icons/${stateName}_16.png`,
      "32": `icons/${stateName}_32.png`,
      "48": `icons/${stateName}_48.png`,
      "128": `icons/${stateName}_128.png`
    }
  });
}

// Clean up session storage when a tab is closed
chrome.tabs.onRemoved.addListener(async (tabId) => {
  await chrome.storage.session.remove(tabId.toString());
});

// Listener for Benchmark Mode
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'run_inference') {
    (async () => {
      try {
        const brandsList = await getBrandsList();
        const ruleSignals = [
          isIpBasedUrl(message.url),
          hasMissingHttps(message.url),
          hasExcessiveSubdomains(message.url),
          hasBrandNameInWrongDomain(message.url, brandsList),
          hasSuspiciousUrlPattern(message.url)
        ];
        const mlScore = await getMlScore(message.url, null);
        const verdict = calculateRisk(message.url, ruleSignals, mlScore, null, null, null);
        sendResponse({ score: verdict.riskScore });
      } catch (err) {
        sendResponse({ score: null });
      }
    })();
    return true; // Keep message channel open for async
  }
});
