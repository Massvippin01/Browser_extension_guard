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

// User explicit overrides mapping (url -> boolean)
const userOverrides = new Set();

// Load allowlist
async function getAllowList() {
  if (trancoCache) return trancoCache;
  try {
    const url = chrome.runtime.getURL('tranco_1000.json');
    const res = await fetch(url);
    if (res.ok) {
      const list = await res.json();
      trancoCache = new Set(list);
    }
  } catch (e) {}
  return trancoCache || new Set();
}

// Load brands
async function getBrandsList() {
  if (brandsListCache) return brandsListCache;
  try {
    const url = chrome.runtime.getURL('brands.json');
    const response = await fetch(url);
    if (response.ok) {
      brandsListCache = await response.json();
    }
  } catch (error) {}
  return brandsListCache || [];
}

getBrandsList();
getAllowList();
initializeModel();

// Core Analysis Engine
async function analyzeUrl(tabId, url, domSignals = null) {
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url === 'about:blank') {
    return;
  }

  // Check manual overrides (User clicked Proceed Anyway)
  const urlObj = new URL(url);
  if (userOverrides.has(urlObj.origin) || userOverrides.has(url)) {
    return; // Do not re-block
  }

  const startScoring = performance.now();
  const allowList = await getAllowList();

  // Allowlist bypass
  let cleanHost = urlObj.hostname.replace(/^www\./, '');
  if (allowList.has(cleanHost)) {
    const scoringTimeMs = performance.now() - startScoring;
    const v = {
      score: 0, state: 'safe', reasons: ['Domain is in the trusted Tranco Top 1000 list.'],
      ruleScore: 0, mlScore: null, mlAvailable: false, scoringTimeMs, timestamp: Date.now()
    };
    await saveVerdictAndEnforce(tabId, url, v, 'allow');
    return;
  }

  const brandsList = await getBrandsList();
  const ruleSignals = [
    isIpBasedUrl(url), hasMissingHttps(url), hasExcessiveSubdomains(url),
    hasBrandNameInWrongDomain(url, brandsList), hasSuspiciousUrlPattern(url)
  ];

  const redirectSignals = getRedirectSignals(tabId);
  
  // Calculate verdict based on what we have (DOM might be null for Early URL scan)
  const mlScore = await getMlScore(url, domSignals);
  const verdict = calculateRisk(url, ruleSignals, mlScore, domSignals, null, redirectSignals);
  verdict.scoringTimeMs = performance.now() - startScoring;

  await saveVerdictAndEnforce(tabId, url, verdict, verdict.action);

  // Trigger Threat Intel in background
  checkThreatIntel(url).then(async (threatIntel) => {
    if (threatIntel && threatIntel.malware) {
      const secondWaveTime = performance.now() - startScoring;
      const newVerdict = calculateRisk(url, ruleSignals, mlScore, domSignals, threatIntel, redirectSignals);
      newVerdict.scoringTimeMs = secondWaveTime;
      await saveVerdictAndEnforce(tabId, url, newVerdict, newVerdict.action);
    }
  });
}

// Ensure results are sent to UI layer
async function saveVerdictAndEnforce(tabId, url, v, action) {
  // Try to capture a screenshot for the report if it's dangerous
  if (action === 'block' && !v.screenshot) {
    try {
      const tab = await chrome.tabs.get(tabId);
      v.screenshot = await chrome.tabs.captureVisibleTab(tab.windowId, { format: 'png' });
    } catch(e) {}
  }

  await chrome.storage.session.set({
    [tabId.toString()]: {
      url: url,
      score: v.score,
      state: v.state,
      categories: v.categories,
      reasons: v.reasons,
      ruleScore: v.ruleScore,
      mlScore: v.mlScore,
      mlAvailable: v.mlAvailable,
      scoringTimeMs: v.scoringTimeMs,
      timestamp: Date.now()
    }
  });
  
  updateBadge(tabId, v.severity || v.state);
  
  try {
    await chrome.tabs.sendMessage(tabId, { action: 'ENFORCEMENT_DECISION', decision: { action: action, verdict: v } });
  } catch (err) {}

  await saveToHistory(v, url);
}

// Listeners from Content Script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'ANALYZE_URL_ONLY' && sender.tab) {
    analyzeUrl(sender.tab.id, message.url, null);
    sendResponse({ success: true });
  } else if (message.action === 'ANALYZE_FULL' && sender.tab) {
    analyzeUrl(sender.tab.id, message.url, message.domSignals);
    sendResponse({ success: true });
  } else if (message.action === 'USER_OVERRIDE_ALLOW') {
    userOverrides.add(message.url);
    const urlObj = new URL(message.url);
    userOverrides.add(urlObj.origin);
    if (sender.tab) {
       updateBadge(sender.tab.id, 'caution'); // Downgrade block badge to caution
    }
    sendResponse({ success: true });
  } else if (message.action === 'run_inference') {
    // Benchmark mode proxy
    (async () => {
      try {
        const brandsList = await getBrandsList();
        const ruleSignals = [
          isIpBasedUrl(message.url), hasMissingHttps(message.url),
          hasExcessiveSubdomains(message.url), hasBrandNameInWrongDomain(message.url, brandsList),
          hasSuspiciousUrlPattern(message.url)
        ];
        const verdict = calculateRisk(message.url, ruleSignals, null, null, null, null);
        sendResponse({ score: verdict.score });
      } catch (err) {
        sendResponse({ score: null });
      }
    })();
    return true; 
  }
});

// SPA Support: When history state updates, force content script to re-analyze
chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId === 0) {
    chrome.tabs.sendMessage(details.tabId, { action: 'RE_ANALYZE' }).catch(() => {});
  }
});

// Ensure badge updates when user switches tabs
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const data = await chrome.storage.session.get(activeInfo.tabId.toString());
  if (data[activeInfo.tabId.toString()]) {
    updateBadge(activeInfo.tabId, data[activeInfo.tabId.toString()].state);
  }
});

// Clean up session storage when a tab is closed
chrome.tabs.onRemoved.addListener(async (tabId) => {
  await chrome.storage.session.remove(tabId.toString());
});

// Badge update helper
function updateBadge(tabId, state) {
  let text = '';
  let color = '#000000';
  let stateName = 'safe';

  switch (state) {
    case 'safe':
      text = '✓'; color = '#10b981'; stateName = 'safe'; break;
    case 'caution':
      text = '!'; color = '#f59e0b'; stateName = 'caution'; break;
    case 'danger':
      text = '!'; color = '#ef4444'; stateName = 'danger'; break;
  }

  chrome.action.setBadgeText({ text: text, tabId: tabId });
  chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
  chrome.action.setIcon({
    tabId: tabId,
    path: {
      "16": \`icons/\${stateName}_16.png\`,
      "32": \`icons/\${stateName}_32.png\`,
      "48": \`icons/\${stateName}_48.png\`,
      "128": \`icons/\${stateName}_128.png\`
    }
  });
}
