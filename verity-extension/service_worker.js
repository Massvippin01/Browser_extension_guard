/**
 * service_worker.js — Verity MV3 Service Worker
 *
 * Orchestrates all detection layers:
 *   URL Analysis → Redirect Analysis → DOM Signals → Brand Detection
 *   → Reputation → ML → Risk Engine → Enforcement Decision
 */

import { isIpBasedUrl, hasMissingHttps, hasExcessiveSubdomains, hasBrandNameInWrongDomain, hasSuspiciousUrlPattern, hasPunycodeOrKeywords, hasFinancialKeywordInHostname, hasBrandVariantMatch, hasMalvertisingPattern, hasRandomLookingHostname, hasAffiliateTrackerPattern } from './background/rules.js';
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
async function storeAndEnforce(tabId, verdict) {
  if (!verdict) return;

  // Persist for popup
  const entry = {};
  entry[tabId.toString()] = verdict;
  await chrome.storage.session.set(entry).catch(() => {});

  // Send enforcement decision to content script
  try {
    await chrome.tabs.sendMessage(tabId, {
      action: 'ENFORCEMENT_DECISION',
      decision: {
        action: verdict.action,
        verdict: verdict,
      },
    });
  } catch (e) {
    // Tab may not have a content script yet — this is fine
  }

  // Update extension icon badge to reflect risk
  updateBadge(tabId, verdict);
}

function updateBadge(tabId, verdict) {
  const state = verdict.severity || verdict.state || 'safe';
  const colors = { safe: '#22c55e', caution: '#f59e0b', danger: '#ef4444' };
  const texts = { safe: '', caution: '!', danger: '!!' };

  chrome.action.setBadgeBackgroundColor({ tabId, color: colors[state] || '#94a3b8' }).catch(() => {});
  chrome.action.setBadgeText({ tabId, text: texts[state] || '' }).catch(() => {});
}

// ---------------------------------------------------------------------------
// Navigation Monitoring (URL-only fast scan on navigation start)
// ---------------------------------------------------------------------------
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const { tabId, url } = details;
  if (isInternalUrl(url)) return;

  const ruleSignals = await analyzeUrl(url);
  if (!ruleSignals) return;

  // Fast URL-only verdict (no DOM, no ML yet)
  const quickVerdict = calculateRisk(url, ruleSignals);
  quickVerdict.url = url;

  await storeAndEnforce(tabId, quickVerdict);
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

  if (message.action === 'ANALYZE_URL_ONLY') {
    const url = message.url;
    if (isInternalUrl(url) || !tabId) return false;

    analyzeUrl(url).then(ruleSignals => {
      if (!ruleSignals) return;
      const verdict = calculateRisk(url, ruleSignals);
      verdict.url = url;
      storeAndEnforce(tabId, verdict);
    });
    return false;
  }

  if (message.action === 'ANALYZE_FULL') {
    runFullAnalysis(sender.tab.id, message.url, message.domSignals).then(verdict => {
      if (verdict) {
        storeAndEnforce(sender.tab.id, verdict);
      }
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
    // User chose to proceed past warning — clear the block
    if (tabId) {
      const entry = {};
      entry[tabId.toString()] = { action: 'allow', severity: 'safe', state: 'safe', score: 0, riskScore: 0, reasons: [], signals: [] };
      chrome.storage.session.set(entry).catch(() => {});
      updateBadge(tabId, { severity: 'safe' });
    }
    return false;
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
