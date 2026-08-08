/**
 * service_worker.js — Verity MV3 Service Worker
 *
 * Orchestrates all detection layers:
 *   URL Analysis → Redirect Analysis → DOM Signals → Brand Detection
 *   → Reputation → ML → Risk Engine → Enforcement Decision
 */

import { isIpBasedUrl, hasMissingHttps, hasExcessiveSubdomains, hasBrandNameInWrongDomain, hasSuspiciousUrlPattern, hasPunycodeOrKeywords, hasFinancialKeywordInHostname, hasBrandVariantMatch, hasMalvertisingPattern, hasRandomLookingHostname, hasAffiliateTrackerPattern, hasPiracyOrUnverifiedMediaPattern } from './background/rules.js';
import { detectTyposquatting } from './background/brand-detector.js';
import { getRedirectSignals, updateShorteners } from './background/redirect-analyzer.js';
import { calculateRisk } from './background/risk-engine.js';
import { getMlScore, initializeModel } from './background/ml-scorer.js';
import { checkReputation } from './background/reputation.js';
import { analyzePaymentPage } from './background/payment-detector.js';
import { initDownloadMonitor } from './background/download/downloadMonitor.js';

// ---------------------------------------------------------------------------
// Load brands list + payment brands at startup
// ---------------------------------------------------------------------------
let brandsList = [];
let paymentBrands = [];
let urlShorteners = [];

async function loadBrands() {
  try {
    const url = chrome.runtime.getURL('brands.json');
    const res = await fetch(url);
    if (res.ok) brandsList = await res.json();
  } catch (e) {
    console.warn('[Verity] Could not load brands.json:', e);
  }
}

async function loadPaymentBrands() {
  try {
    const url = chrome.runtime.getURL('payment-brands.json');
    const res = await fetch(url);
    if (res.ok) paymentBrands = await res.json();
  } catch (e) {
    console.warn('[Verity] Could not load payment-brands.json:', e);
  }
}

async function loadUrlShorteners() {
  try {
    const url = chrome.runtime.getURL('config/urlShorteners.json');
    const res = await fetch(url);
    if (res.ok) {
      const data = await res.json();
      urlShorteners = data.shorteners || [];
      updateShorteners(urlShorteners);
    }
  } catch (e) {
    console.warn('[Verity] Could not load urlShorteners.json:', e);
  }
}

// Trusted domains — never scan internal Chrome pages
function isInternalUrl(url) {
  return !url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:') || url.startsWith('data:') || url.startsWith('file://');
}

// ---------------------------------------------------------------------------
// Core Analysis Pipeline
// ---------------------------------------------------------------------------
async function analyzeUrl(url) {
  if (isInternalUrl(url)) return null;

  const ruleSignals = [
    isIpBasedUrl(url),
    hasMissingHttps(url),
    hasExcessiveSubdomains(url),
    hasBrandNameInWrongDomain(url, brandsList),
    hasSuspiciousUrlPattern(url),
    hasPunycodeOrKeywords(url),
    detectTyposquatting(url, brandsList),
    hasFinancialKeywordInHostname(url, brandsList),
    hasBrandVariantMatch(url, brandsList),
    hasMalvertisingPattern(url),
    hasRandomLookingHostname(url),
    hasAffiliateTrackerPattern(url),
    hasPiracyOrUnverifiedMediaPattern(url),
  ];

  return ruleSignals;
}

/**
 * Exported helper — computes URL rule signals for any URL.
 * Used by downloadMonitor to analyze the download source URL.
 */
function buildRuleSignals(url) {
  if (!url || isInternalUrl(url)) return [];
  return [
    isIpBasedUrl(url),
    hasMissingHttps(url),
    hasExcessiveSubdomains(url),
    hasBrandNameInWrongDomain(url, brandsList),
    hasSuspiciousUrlPattern(url),
    hasPunycodeOrKeywords(url),
    detectTyposquatting(url, brandsList),
    hasFinancialKeywordInHostname(url, brandsList),
    hasBrandVariantMatch(url, brandsList),
    hasMalvertisingPattern(url),
    hasRandomLookingHostname(url),
    hasAffiliateTrackerPattern(url),
    hasPiracyOrUnverifiedMediaPattern(url),
  ];
}

async function runFullAnalysis(tabId, url, domSignals) {
  if (isInternalUrl(url)) return null;

  const ruleSignals = await analyzeUrl(url);
  if (!ruleSignals) return null;

  // Parallel: ML score + reputation check
  const [mlScore, threatIntel] = await Promise.allSettled([
    getMlScore(url, domSignals),
    checkReputation(url),
  ]);

  const redirectSignals = getRedirectSignals(tabId);

  // Payment protection analysis
  const paymentAnalysis = analyzePaymentPage(url, domSignals, paymentBrands);

  const verdict = calculateRisk(
    url,
    ruleSignals,
    mlScore.status === 'fulfilled' ? mlScore.value : null,
    domSignals || null,
    threatIntel.status === 'fulfilled' ? threatIntel.value : null,
    redirectSignals,
    paymentAnalysis
  );

  verdict.url = url;
  verdict.paymentAnalysis = paymentAnalysis; // Attach for overlay
  return verdict;
}

// ---------------------------------------------------------------------------
// Search Result Analysis (Lightweight, No DOM, No ML)
// ---------------------------------------------------------------------------
async function analyzeSearchResult(url, tabId) {
  if (isInternalUrl(url)) return { state: 'safe', score: 0, reasons: [] };

  const ruleSignals = await analyzeUrl(url);
  if (!ruleSignals) return { state: 'safe', score: 0, reasons: [] };

  // For search results, we do not visit the page or run DOM/ML models.
  // We only run URL rules and check reputation.
  const threatIntelResponse = await checkReputation(url);
  
  // Create a minimal payment analysis result since we don't have DOM signals
  // We can't verify claiming provider, but we can verify domain rules
  const paymentAnalysis = null; 

  // We don't have redirect signals before clicking
  const redirectSignals = null;

  const verdict = calculateRisk(
    url,
    ruleSignals,
    null, // no ML score
    null, // no DOM signals
    threatIntelResponse,
    redirectSignals,
    paymentAnalysis
  );
  
  // Add search context
  verdict.analysisContext = 'search_result';
  verdict.url = url;

  return verdict;
}

// ---------------------------------------------------------------------------
// Store & Broadcast Verdict
// ---------------------------------------------------------------------------
async function storeAndEnforce(tabId, verdict, frameId = 0) {
  if (!verdict) return;

  // Persist for main frame popup
  if (frameId === 0) {
    const entry = {};
    entry[tabId.toString()] = verdict;
    await chrome.storage.session.set(entry).catch(() => {});
    updateBadge(tabId, verdict);
  }

  // Send enforcement decision to content script (target frameId if subframe)
  try {
    const options = frameId !== 0 ? { frameId } : {};
    await chrome.tabs.sendMessage(tabId, {
      action: 'ENFORCEMENT_DECISION',
      decision: {
        action: verdict.action,
        verdict: verdict,
        isIframe: frameId !== 0
      },
    }, options);
  } catch (e) {
    // Tab/frame may not have a content script yet — this is fine
  }
}

function updateBadge(tabId, verdict) {
  const state = verdict.severity || verdict.state || 'safe';
  const colors = { safe: '#22c55e', caution: '#f59e0b', danger: '#ef4444' };
  const texts = { safe: '', caution: '!', danger: '!!' };

  chrome.action.setBadgeBackgroundColor({ tabId, color: colors[state] || '#94a3b8' }).catch(() => {});
  chrome.action.setBadgeText({ tabId, text: texts[state] || '' }).catch(() => {});
}

// ---------------------------------------------------------------------------
// Pop-up / Pop-under Automatic Interceptor & Killer
// ---------------------------------------------------------------------------
chrome.tabs.onCreated.addListener(async (tab) => {
  if (!tab.openerTabId || !tab.id) return;
  const openerTabId = tab.openerTabId;

  const checkAndKillPopup = async (targetUrl) => {
    if (!targetUrl || isInternalUrl(targetUrl)) return;
    const ruleSignals = await analyzeUrl(targetUrl);
    if (!ruleSignals) return;
    const verdict = calculateRisk(targetUrl, ruleSignals);

    if (verdict.action === 'block' || verdict.score >= 70) {
      // 1. Instantly kill the pop-up window
      chrome.tabs.remove(tab.id).catch(() => {});

      // 2. Notify opener tab to render pop-up blocked notification toast
      let host = targetUrl;
      try { host = new URL(targetUrl).hostname; } catch (e) {}
      chrome.tabs.sendMessage(openerTabId, {
        action: 'POPUP_BLOCKED_TOAST',
        blockedUrl: targetUrl,
        hostname: host
      }).catch(() => {});
    }
  };

  if (tab.url && tab.url !== 'about:blank') {
    checkAndKillPopup(tab.url);
  } else if (tab.pendingUrl) {
    checkAndKillPopup(tab.pendingUrl);
  }
});

const userOverrideTabs = new Set();
const userOverrideDomains = new Set();

function isUserOverridden(tabId, url) {
  if (tabId && userOverrideTabs.has(tabId)) return true;
  if (url) {
    try {
      const host = new URL(url).hostname.toLowerCase();
      if (userOverrideDomains.has(host)) return true;
    } catch (e) {}
  }
  return false;
}

// ---------------------------------------------------------------------------
// Navigation Monitoring (Main Frame & Subframe / Iframe Scans)
// ---------------------------------------------------------------------------
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  const { tabId, url, frameId } = details;
  if (isInternalUrl(url)) return;

  if (isUserOverridden(tabId, url)) {
    const verdict = { action: 'allow', severity: 'safe', state: 'safe', score: 0, riskScore: 0, reasons: [], signals: [] };
    await storeAndEnforce(tabId, verdict, frameId);
    return;
  }

  const ruleSignals = await analyzeUrl(url);
  if (!ruleSignals) return;

  // Fast URL-only verdict
  const quickVerdict = calculateRisk(url, ruleSignals);
  quickVerdict.url = url;

  // Subframe rule: only enforce if dangerous (block threshold) to avoid disturbing clean embeds
  if (frameId !== 0 && quickVerdict.action !== 'block') {
    return;
  }

  await storeAndEnforce(tabId, quickVerdict, frameId);
});

// ---------------------------------------------------------------------------
// Network & Security Error Interceptor (SSL / Certificate / Connection Failures)
// ---------------------------------------------------------------------------
chrome.webNavigation.onErrorOccurred.addListener(async (details) => {
  const { tabId, url, error, frameId } = details;
  if (isInternalUrl(url)) return;

  const ruleSignals = await analyzeUrl(url);
  const verdict = calculateRisk(url, ruleSignals || []);
  
  // Force high-risk verdict for security/network failures
  verdict.riskScore = Math.max(verdict.riskScore || 0, 85);
  verdict.score = verdict.riskScore;
  verdict.severity = 'danger';
  verdict.state = 'danger';
  verdict.action = 'block';
  verdict.url = url;
  if (!verdict.reasons) verdict.reasons = [];
  verdict.reasons.push(`Security Error (${error}): Connection terminated due to untrusted security certificate or network block.`);

  // Subframe rule: only enforce if dangerous
  if (frameId !== 0 && verdict.action !== 'block') {
    return;
  }

  await storeAndEnforce(tabId, verdict, frameId);
});

// ---------------------------------------------------------------------------
// Navigation Committed Listener (Ensures block overlay renders on fresh page load)
// ---------------------------------------------------------------------------
chrome.webNavigation.onCommitted.addListener(async (details) => {
  const { tabId, frameId } = details;
  const storageResult = await chrome.storage.session.get(tabId.toString()).catch(() => ({}));
  const verdict = storageResult[tabId.toString()];
  if (verdict && verdict.action === 'block') {
    storeAndEnforce(tabId, verdict, frameId);
  }
});

// ---------------------------------------------------------------------------
// SPA / Client-side navigation re-analysis
// ---------------------------------------------------------------------------
chrome.webNavigation.onHistoryStateUpdated.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const { tabId, url } = details;
  if (isInternalUrl(url)) return;

  try {
    await chrome.tabs.sendMessage(tabId, { action: 'RE_ANALYZE' });
  } catch (e) {}
});

// ---------------------------------------------------------------------------
// Message Handler
// ---------------------------------------------------------------------------
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab ? sender.tab.id : null;
  const frameId = sender.frameId || 0;

  if (message.action === 'ANALYZE_URL_ONLY') {
    const url = message.url;
    if (isInternalUrl(url) || !tabId) {
      sendResponse({ verdict: null });
      return false;
    }

    if (isUserOverridden(tabId, url)) {
      const verdict = { action: 'allow', severity: 'safe', state: 'safe', score: 0, riskScore: 0, reasons: [], signals: [], url };
      storeAndEnforce(tabId, verdict, frameId);
      sendResponse({ verdict });
      return false;
    }

    analyzeUrl(url).then(ruleSignals => {
      if (!ruleSignals) {
        sendResponse({ verdict: null });
        return;
      }
      const verdict = calculateRisk(url, ruleSignals);
      verdict.url = url;
      storeAndEnforce(tabId, verdict, frameId);
      sendResponse({ verdict });
    }).catch(() => {
      sendResponse({ verdict: null });
    });
    return true; // Keep message channel open for async response
  }

  if (message.action === 'ANALYZE_FULL') {
    if (isUserOverridden(sender.tab.id, message.url)) {
      const verdict = { action: 'allow', severity: 'safe', state: 'safe', score: 0, riskScore: 0, reasons: [], signals: [], url: message.url };
      storeAndEnforce(sender.tab.id, verdict, frameId);
      sendResponse({ verdict });
      return false;
    }
    runFullAnalysis(sender.tab.id, message.url, message.domSignals).then(verdict => {
      if (verdict) {
        storeAndEnforce(sender.tab.id, verdict, frameId);
      }
      sendResponse({ verdict });
    }).catch(() => {
      sendResponse({ verdict: null });
    });
    return true; // Keep channel open
  }

  if (message.action === 'ANALYZE_SEARCH_RESULT') {
    analyzeSearchResult(message.url, sender.tab.id).then(verdict => {
      sendResponse({ verdict });
    }).catch(err => {
      console.error('[Verity] Error in analyzeSearchResult:', err);
      sendResponse({ verdict: null });
    });
    return true; // Keep channel open for async response
  }

  if (message.action === 'USER_OVERRIDE_ALLOW') {
    // User chose to proceed past warning — clear the block permanently for this tab and domain
    if (tabId) {
      userOverrideTabs.add(tabId);
      if (message.url) {
        try {
          const host = new URL(message.url).hostname.toLowerCase();
          userOverrideDomains.add(host);
        } catch (e) {}
      }

      const entry = {};
      entry[tabId.toString()] = { action: 'allow', severity: 'safe', state: 'safe', score: 0, riskScore: 0, reasons: [], signals: [] };
      chrome.storage.session.set(entry).then(() => {
        sendResponse({ success: true });
      }).catch(() => {
        sendResponse({ success: false });
      });
      updateBadge(tabId, { severity: 'safe' });
    }
    return true; // Keep channel open for async response
  }

  // Popup asks for current verdict
  if (message.action === 'OPEN_DOWNLOADS_PAGE') {
    chrome.tabs.create({ url: 'chrome://downloads/' }).catch(() => {});
    return false;
  }

  // Popup asks for current verdict
  if (message.action === 'GET_VERDICT') {
    const reqTabId = message.tabId;
    chrome.storage.session.get(reqTabId.toString()).then(result => {
      sendResponse(result[reqTabId.toString()] || null);
    }).catch(() => sendResponse(null));
    return true; // async response
  }

  // Run benchmark inference (used by popup benchmark tab)
  if (message.action === 'run_inference') {
    getMlScore(message.url, null).then(score => {
      sendResponse({ score });
    });
    return true;
  }

  return false;
});

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------
chrome.runtime.onInstalled.addListener(async () => {
  await loadBrands();
  await loadPaymentBrands();
  await loadUrlShorteners();
  await initializeModel();
  console.log('[Verity] Extension installed and ready.');
});

chrome.runtime.onStartup.addListener(async () => {
  await loadBrands();
  await loadPaymentBrands();
  await loadUrlShorteners();
  await initializeModel();
  console.log('[Verity] Extension started.');
});

// Also load brands on service worker wake (no event)
loadBrands().catch(() => {});
loadPaymentBrands().catch(() => {});
loadUrlShorteners().catch(() => {});

// ---------------------------------------------------------------------------
// Download Monitor Initialization
// ---------------------------------------------------------------------------
function initDownloadProtection() {
  initDownloadMonitor({
    brandsList,
    calculateRisk,
    buildRuleSignals,
  });
}

// Initialize after brands are loaded so impersonation detection works
Promise.all([
  loadBrands(),
  loadPaymentBrands(),
  loadUrlShorteners(),
]).then(() => {
  initDownloadProtection();
}).catch(() => {});
