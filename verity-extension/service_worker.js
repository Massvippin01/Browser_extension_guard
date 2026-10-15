/**
 * service_worker.js — Verity MV3 Service Worker
 *
 * Orchestrates all detection layers:
 *   URL Analysis → Redirect Analysis → DOM Signals → Brand Detection
 *   → Reputation → ML → Risk Engine → Enforcement Decision
 */

import { isIpBasedUrl, hasMissingHttps, hasExcessiveSubdomains, hasBrandNameInWrongDomain, hasSuspiciousUrlPattern, hasPunycodeOrKeywords, hasFinancialKeywordInHostname, hasBrandVariantMatch, hasMalvertisingPattern, hasRandomLookingHostname, hasAffiliateTrackerPattern, hasPiracyOrUnverifiedMediaPattern, hasAitmProxyUrlSignature, isTrustedTopDomain } from './background/rules.js';
import { detectTyposquatting } from './background/brand-detector.js';
import { getRedirectSignals, getRedirectSignalsAsync, updateShorteners, recordNavigationTarget, hydrateFromStorage, pruneTab, isSuspiciousDomain } from './background/redirect-analyzer.js';
import { calculateRisk } from './background/risk-engine.js';
import { getMlScore, initializeModel } from './background/ml-scorer.js';
import { checkReputation } from './background/reputation.js';
import { analyzePaymentPage } from './background/payment-detector.js';
import { initDownloadMonitor } from './background/download/downloadMonitor.js';
import { validateMessageSender } from './background/message-validator.js';
import { isAllowlistedDomain } from './shared/legit-domains.js';
import { initDnrBlocker } from './background/dnr-blocker.js';
import { getDomain } from './shared/psl.js';
import { t } from './shared/messages.js';
export { validateMessageSender };

export function isSafeAllowlistedOrTopDomain(url) {
  if (!url) return false;
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    return isAllowlistedDomain(hostname) || isTrustedTopDomain(hostname);
  } catch (_) {
    return false;
  }
}

export function createSafeAllowVerdict(url) {
  return {
    url: url || '',
    score: 0,
    riskScore: 0,
    action: 'allow',
    severity: 'safe',
    state: 'safe',
    reasons: [],
    signals: [],
    categories: {
      phishing: { flagged: false, confidence: 0, reason: null },
      malware: { flagged: false, source: null },
      scamFraud: { flagged: false, reason: null },
      suspicious: { flagged: false, reason: null }
    },
    ruleScore: 0,
    activeSources: [],
    redirectChain: null,
    shortenerDetected: false,
    paymentAnalysis: null
  };
}

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

// Trusted internal browser schemes — never scan chrome:// or internal extension pages
function isInternalUrl(url) {
  if (!url) return true;
  return url.startsWith('chrome://') ||
         url.startsWith('chrome-extension://') ||
         url.startsWith('edge://') ||
         url.startsWith('about:') ||
         url.startsWith('data:');
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
    hasAitmProxyUrlSignature(url),
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
    hasAitmProxyUrlSignature(url),
  ];
}

async function runFullAnalysis(tabId, url, domSignals) {
  if (isInternalUrl(url)) return null;

  // Step 3.1: Force safe allow verdict on allowlisted / trusted top domains
  if (isSafeAllowlistedOrTopDomain(url)) {
    pruneTabRiskState(tabId);
    const safeVerdict = createSafeAllowVerdict(url);
    await storeAndEnforce(tabId, safeVerdict, 0);
    return safeVerdict;
  }

  // Delete stored risk state if tab navigated to a new hostname
  let tabState = await getTabRiskState(tabId);
  if (tabState && tabState.url) {
    try {
      const prevHost = new URL(tabState.url).hostname.toLowerCase();
      const curHost = new URL(url).hostname.toLowerCase();
      if (prevHost && curHost && prevHost !== curHost) {
        pruneTabRiskState(tabId);
        tabState = null;
      }
    } catch (_) {}
  }

  const ruleSignals = await analyzeUrl(url);
  if (!ruleSignals) return null;

  // Parallel: ML score + reputation check
  const [mlScore, threatIntel] = await Promise.allSettled([
    getMlScore(url, domSignals),
    checkReputation(url),
  ]);

  const redirectSignals = await getRedirectSignalsAsync(tabId);

  // If this tab was marked as popunder, preserve SIG_POPUNDER_SPAWN
  if (tabState && tabState.isPopunderTab && redirectSignals) {
    if (!redirectSignals.structuredReasons) redirectSignals.structuredReasons = [];
    if (!redirectSignals.structuredReasons.some(r => r.id === 'SIG_POPUNDER_SPAWN')) {
      redirectSignals.structuredReasons.push({
        id: 'SIG_POPUNDER_SPAWN',
        score: 75,
        category: 'malvertising',
        source: 'redirect',
        params: { sourceDomain: tabState.sourceDomain || 'external', targetDomain: tabState.targetDomain || '' }
      });
      redirectSignals.popunderSpawn = true;
    }
  }

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

  // Sticky High-Water Mark Rule:
  // ONLY merge if on the exact same hostname AND verdict has reasons!
  if (tabState && verdict.reasons && verdict.reasons.length > 0) {
    try {
      const prevHost = tabState.url ? new URL(tabState.url).hostname.toLowerCase() : '';
      const curHost = new URL(url).hostname.toLowerCase();
      if (prevHost && curHost && prevHost === curHost) {
        const prevMax = tabState.maxRiskScore || 0;
        if (prevMax > verdict.score || tabState.maxAction === 'block' || tabState.isPopunderTab) {
          verdict.score = Math.max(verdict.score, prevMax, tabState.isPopunderTab ? 85 : 0);
          verdict.riskScore = verdict.score;
          if (tabState.maxAction === 'block' || tabState.isPopunderTab || prevMax >= 70) {
            verdict.action = 'block';
            verdict.severity = 'danger';
            verdict.state = 'danger';
          } else if (tabState.maxAction === 'warn' || prevMax >= 35) {
            if (verdict.action !== 'block') {
              verdict.action = 'warn';
              verdict.severity = 'caution';
              verdict.state = 'caution';
            }
          }
        }
      }
    } catch (_) {}
  }

  // Unbreakable Invariant: 0 reasons must force score = 0, action = allow, severity = safe
  if (!verdict.reasons || verdict.reasons.length === 0) {
    verdict.score = 0;
    verdict.riskScore = 0;
    verdict.action = 'allow';
    verdict.severity = 'safe';
    verdict.state = 'safe';
  }

  await saveTabRiskState(tabId, {
    url,
    maxRiskScore: Math.max(tabState?.maxRiskScore || 0, verdict.score),
    maxAction: verdict.action,
    maxSeverity: verdict.severity,
    lastVerdict: verdict
  });

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

  // Step 3: Invariant: Allowlisted/trusted domains force score 0, allow, safe, 0 reasons
  if (isSafeAllowlistedOrTopDomain(verdict.url)) {
    verdict.score = 0;
    verdict.riskScore = 0;
    verdict.action = 'allow';
    verdict.severity = 'safe';
    verdict.state = 'safe';
    verdict.reasons = [];
    verdict.signals = [];
  } else if (!verdict.reasons || verdict.reasons.length === 0) {
    verdict.score = 0;
    verdict.riskScore = 0;
    verdict.action = 'allow';
    verdict.severity = 'safe';
    verdict.state = 'safe';
  }

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
// ---------------------------------------------------------------------------
// Persistent Per-Tab Risk State & Sticky High-Water Mark (MV3 Session Storage)
// ---------------------------------------------------------------------------
const tabRiskStates = new Map();

async function getTabRiskState(tabId) {
  if (!tabId) return null;
  const numId = typeof tabId === 'string' ? parseInt(tabId, 10) : tabId;
  let state = tabRiskStates.get(numId);
  if (!state && typeof chrome !== 'undefined' && chrome.storage && chrome.storage.session) {
    try {
      const res = await chrome.storage.session.get('tab_risk_state_' + numId);
      if (res && res['tab_risk_state_' + numId]) {
        state = res['tab_risk_state_' + numId];
        tabRiskStates.set(numId, state);
      }
    } catch (_) {}
  }
  return state;
}

async function saveTabRiskState(tabId, stateUpdates) {
  if (!tabId) return;
  const numId = typeof tabId === 'string' ? parseInt(tabId, 10) : tabId;
  const existing = await getTabRiskState(numId) || {};
  const merged = { ...existing, ...stateUpdates, tabId: numId, lastUpdated: Date.now() };
  tabRiskStates.set(numId, merged);
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.session) {
    const payload = {};
    payload['tab_risk_state_' + numId] = merged;
    chrome.storage.session.set(payload).catch(() => {});
  }
  return merged;
}

function pruneTabRiskState(tabId) {
  if (!tabId) return;
  const numId = typeof tabId === 'string' ? parseInt(tabId, 10) : tabId;
  tabRiskStates.delete(numId);
  tabRiskStates.delete(tabId);
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.session) {
    chrome.storage.session.remove(['tab_risk_state_' + numId, 'tab_risk_state_' + tabId]).catch(() => {});
  }
}

function checkPopunderMatch(sourceUrl, targetUrl) {
  if (!targetUrl || isInternalUrl(targetUrl)) return false;
  let sourceHost = '';
  let targetHost = '';
  try {
    if (sourceUrl) sourceHost = new URL(sourceUrl).hostname.toLowerCase();
    targetHost = new URL(targetUrl).hostname.toLowerCase();
  } catch (_) {
    return false;
  }
  const sourceRoot = sourceHost ? (getDomain(sourceHost) || sourceHost) : '';
  const targetRoot = targetHost ? (getDomain(targetHost) || targetHost) : '';

  if (sourceRoot && targetRoot && sourceRoot === targetRoot) {
    return false; // same root domain
  }

  const isTargetAllowlisted = isAllowlistedDomain(targetHost) || isAllowlistedDomain(targetRoot);
  if (isTargetAllowlisted) return false;

  // Step 4.2: SIG_POPUNDER_SPAWN must ONLY fire if the newly spawned tab's URL ALSO
  // matches an explicit ad-rotator/malvertising pattern:
  const lowerTarget = targetUrl.toLowerCase();
  const isExplicitAdRotator =
    lowerTarget.includes('utm_medium=popunder') ||
    lowerTarget.includes('propellerads') ||
    lowerTarget.includes('popads') ||
    lowerTarget.includes('wigglepoploaderfast') ||
    /\?[a-f0-9]{16,64}/i.test(targetUrl);

  if (isExplicitAdRotator) {
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Pop-up / Pop-under Automatic Interceptor & Click-Hijack Defuser
// ---------------------------------------------------------------------------
chrome.webNavigation.onCreatedNavigationTarget.addListener(async (details) => {
  recordNavigationTarget(details);
  const { sourceTabId, tabId, url } = details;
  if (!tabId) return;

  let sourceUrl = '';
  try {
    if (sourceTabId) {
      const srcTab = await chrome.tabs.get(sourceTabId).catch(() => null);
      if (srcTab && srcTab.url) sourceUrl = srcTab.url;
    }
  } catch (_) {}

  const targetUrl = url || '';
  if (targetUrl && !isInternalUrl(targetUrl)) {
    const isPopunder = checkPopunderMatch(sourceUrl, targetUrl);
    if (isPopunder) {
      let targetDomain = '';
      try { targetDomain = new URL(targetUrl).hostname; } catch (_) {}
      let sourceDomain = '';
      try { if (sourceUrl) sourceDomain = new URL(sourceUrl).hostname; } catch (_) {}

      await saveTabRiskState(tabId, {
        isPopunderTab: true,
        sourceDomain,
        targetDomain,
        maxRiskScore: 85,
        maxAction: 'block',
        maxSeverity: 'danger'
      });

      const ruleSignals = await analyzeUrl(targetUrl);
      const redirectSignals = await getRedirectSignalsAsync(tabId) || { structuredReasons: [] };
      if (!redirectSignals.structuredReasons) redirectSignals.structuredReasons = [];
      redirectSignals.structuredReasons.push({
        id: 'SIG_POPUNDER_SPAWN',
        score: 75,
        category: 'malvertising',
        source: 'redirect',
        params: { sourceDomain: sourceDomain || 'external', targetDomain }
      });
      redirectSignals.popunderSpawn = true;

      const verdict = calculateRisk(targetUrl, ruleSignals || [], null, null, null, redirectSignals);
      verdict.score = Math.max(verdict.score || 0, 85);
      verdict.riskScore = Math.max(verdict.riskScore || 0, 85);
      verdict.action = 'block';
      verdict.severity = 'danger';
      verdict.state = 'danger';
      verdict.url = targetUrl;
      await storeAndEnforce(tabId, verdict, 0);
    }
  }
});

chrome.tabs.onCreated.addListener(async (tab) => {
  if (!tab.id) return;
  const openerTabId = tab.openerTabId;
  const targetUrl = tab.url || tab.pendingUrl || '';

  if (openerTabId) {
    recordNavigationTarget({
      sourceTabId: openerTabId,
      tabId: tab.id,
      url: targetUrl,
      timeStamp: Date.now()
    });

    if (targetUrl && !isInternalUrl(targetUrl) && targetUrl !== 'about:blank') {
      let sourceUrl = '';
      try {
        const srcTab = await chrome.tabs.get(openerTabId).catch(() => null);
        if (srcTab && srcTab.url) sourceUrl = srcTab.url;
      } catch (_) {}

      if (checkPopunderMatch(sourceUrl, targetUrl)) {
        await saveTabRiskState(tab.id, {
          isPopunderTab: true,
          maxRiskScore: 85,
          maxAction: 'block',
          maxSeverity: 'danger'
        });
      }
    }
  }

  const checkAndKillPopup = async (urlToCheck) => {
    if (!urlToCheck || isInternalUrl(urlToCheck) || urlToCheck === 'about:blank') return;
    const ruleSignals = await analyzeUrl(urlToCheck);
    if (!ruleSignals) return;
    const redirectSignals = await getRedirectSignalsAsync(tab.id);
    const tabState = await getTabRiskState(tab.id);
    if (tabState && tabState.isPopunderTab && redirectSignals) {
      redirectSignals.popunderSpawn = true;
    }
    const verdict = calculateRisk(urlToCheck, ruleSignals, null, null, null, redirectSignals);

    if (verdict.action === 'block' || verdict.score >= 70 || tabState?.isPopunderTab) {
      verdict.action = 'block';
      verdict.severity = 'danger';
      verdict.state = 'danger';
      verdict.score = Math.max(verdict.score || 0, 85);
      verdict.riskScore = verdict.score;
      await storeAndEnforce(tab.id, verdict, 0);

      // Notify opener tab toast if opened as pop-up window
      let host = urlToCheck;
      try { host = new URL(urlToCheck).hostname; } catch (e) {}
      if (openerTabId) {
        chrome.tabs.sendMessage(openerTabId, {
          action: 'POPUP_BLOCKED_TOAST',
          blockedUrl: urlToCheck,
          hostname: host
        }).catch(() => {});
      }
    }
  };

  if (tab.url && tab.url !== 'about:blank') {
    checkAndKillPopup(tab.url);
  } else if (tab.pendingUrl) {
    checkAndKillPopup(tab.pendingUrl);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  pruneTab(tabId);
  pruneTabRiskState(tabId);
});

// ---------------------------------------------------------------------------
// Development-only allowlist gate for local harness debugging.
// Strictly FALSE in shipped production builds.
// ---------------------------------------------------------------------------
export const ENABLE_DEV_ALLOWLIST = false;

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

  // Step 3.1: Whenever a tab navigates with frameId === 0, DELETE all stored risk state, pop-under flags, and signals for that tabId!
  if (frameId === 0) {
    pruneTabRiskState(tabId);
    pruneTab(tabId);
  }

  // Step 3.1: If current tab's hostname is in legit_domains.js or isTrustedTopDomain, FORCE score 0, allow, safe
  if (isSafeAllowlistedOrTopDomain(url)) {
    const verdict = createSafeAllowVerdict(url);
    await storeAndEnforce(tabId, verdict, frameId);
    return;
  }

  if (ENABLE_DEV_ALLOWLIST && (url === 'http://localhost:3000/' || url === 'http://localhost:3000' || url === 'http://localhost:8080/' || url === 'http://localhost:8080')) {
    userOverrideTabs.delete(tabId);
    const verdict = createSafeAllowVerdict(url);
    await storeAndEnforce(tabId, verdict, frameId);
    return;
  }

  if (isUserOverridden(tabId, url)) {
    const verdict = createSafeAllowVerdict(url);
    await storeAndEnforce(tabId, verdict, frameId);
    return;
  }

  const ruleSignals = await analyzeUrl(url);
  if (!ruleSignals) return;

  const redirectSignals = await getRedirectSignalsAsync(tabId);
  const tabState = await getTabRiskState(tabId);

  if (tabState && tabState.isPopunderTab && redirectSignals) {
    if (!redirectSignals.structuredReasons) redirectSignals.structuredReasons = [];
    if (!redirectSignals.structuredReasons.some(r => r.id === 'SIG_POPUNDER_SPAWN')) {
      redirectSignals.structuredReasons.push({
        id: 'SIG_POPUNDER_SPAWN',
        score: 75,
        category: 'malvertising',
        source: 'redirect',
        params: { sourceDomain: tabState.sourceDomain || 'external', targetDomain: tabState.targetDomain || '' }
      });
      redirectSignals.popunderSpawn = true;
    }
  }

  // Fast URL-only verdict incorporating redirect signals
  const quickVerdict = calculateRisk(
    url,
    ruleSignals,
    null,
    null,
    null,
    redirectSignals
  );
  quickVerdict.url = url;

  // Sticky High-Water Mark Integration:
  // ONLY merge if on the exact same hostname AND quickVerdict has reasons!
  if (tabState && quickVerdict.reasons && quickVerdict.reasons.length > 0) {
    try {
      const prevHost = tabState.url ? new URL(tabState.url).hostname.toLowerCase() : '';
      const curHost = new URL(url).hostname.toLowerCase();
      if (prevHost && curHost && prevHost === curHost) {
        const prevMax = tabState.maxRiskScore || 0;
        if (tabState.isPopunderTab || tabState.maxAction === 'block' || prevMax >= 70) {
          quickVerdict.score = Math.max(quickVerdict.score, prevMax, 85);
          quickVerdict.riskScore = quickVerdict.score;
          quickVerdict.action = 'block';
          quickVerdict.severity = 'danger';
          quickVerdict.state = 'danger';
        } else if (tabState.maxAction === 'warn' || prevMax >= 35) {
          if (quickVerdict.action !== 'block') {
            quickVerdict.score = Math.max(quickVerdict.score, prevMax);
            quickVerdict.riskScore = quickVerdict.score;
            quickVerdict.action = 'warn';
            quickVerdict.severity = 'caution';
            quickVerdict.state = 'caution';
          }
        }
      }
    } catch (_) {}
  }

  // Invariant: zero reasons forces score 0
  if (!quickVerdict.reasons || quickVerdict.reasons.length === 0) {
    quickVerdict.score = 0;
    quickVerdict.riskScore = 0;
    quickVerdict.action = 'allow';
    quickVerdict.severity = 'safe';
    quickVerdict.state = 'safe';
  }

  await saveTabRiskState(tabId, {
    url,
    maxRiskScore: Math.max(tabState?.maxRiskScore || 0, quickVerdict.score),
    maxAction: quickVerdict.action,
    maxSeverity: quickVerdict.severity,
    lastVerdict: quickVerdict
  });

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

  // net::ERR_ABORTED is triggered by normal client redirects, link clicks, or cancelled prefetches,
  // NOT a security failure. Ignore ERR_ABORTED.
  if (error === 'net::ERR_ABORTED') return;

  let hostname = '';
  try { hostname = new URL(url).hostname.toLowerCase(); } catch (e) {}

  // Allowlisted domains must never be blocked by transient network errors
  if (isAllowlistedDomain(hostname)) return;

  // Only real security certificate failures should trigger a security warning
  const isCertSecurityError = error && (
    error.startsWith('net::ERR_CERT_') ||
    error.startsWith('net::ERR_SSL_')
  );
  if (!isCertSecurityError) return;

  const ruleSignals = await analyzeUrl(url);
  const verdict = calculateRisk(url, ruleSignals || []);
  
  // Force high-risk verdict for verified security/certificate failures
  verdict.riskScore = Math.max(verdict.riskScore || 0, 85);
  verdict.score = verdict.riskScore;
  verdict.severity = 'danger';
  verdict.state = 'danger';
  verdict.action = 'block';
  verdict.url = url;
  if (!verdict.reasons) verdict.reasons = [];
  verdict.reasons.push(t('SECURITY_ERROR_ABORTED', { error }));

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
  const { tabId, frameId, url } = details;
  if (frameId === 0) {
    if (url && isSafeAllowlistedOrTopDomain(url)) {
      pruneTabRiskState(tabId);
      const safeVerdict = createSafeAllowVerdict(url);
      await storeAndEnforce(tabId, safeVerdict, 0);
      return;
    }
  }
  const storageResult = await chrome.storage.session.get(tabId.toString()).catch(() => ({}));
  const verdict = storageResult[tabId.toString()];
  if (verdict && verdict.action === 'block') {
    if (verdict.url && isSafeAllowlistedOrTopDomain(verdict.url)) {
      const safeVerdict = createSafeAllowVerdict(verdict.url);
      storeAndEnforce(tabId, safeVerdict, frameId);
    } else {
      storeAndEnforce(tabId, verdict, frameId);
    }
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
// Pop-under & Navigation Target Tracking (window.open on sketchy sites)
// ---------------------------------------------------------------------------
if (chrome.webNavigation && chrome.webNavigation.onCreatedNavigationTarget) {
  chrome.webNavigation.onCreatedNavigationTarget.addListener((details) => {
    recordNavigationTarget(details);
  });
}

// Clean up tab tracking when tab closes
if (chrome.tabs && chrome.tabs.onRemoved) {
  chrome.tabs.onRemoved.addListener((tabId) => {
    pruneTab(tabId);
  });
}

// ---------------------------------------------------------------------------
// Message Handler
// ---------------------------------------------------------------------------
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const validation = validateMessageSender(sender, chrome.runtime.id, message);
  if (!validation.valid) {
    console.warn('[Verity] Rejected runtime message:', validation.reason, { sender, message });
    sendResponse({ error: 'Unauthorized message sender', reason: validation.reason });
    return false;
  }

  const tabId = sender.tab ? sender.tab.id : null;
  const frameId = sender.frameId || 0;

  if (message.action === 'ANALYZE_URL_ONLY') {
    const url = message.url;
    if (isInternalUrl(url) || !tabId) {
      sendResponse({ verdict: null });
      return false;
    }

    if (isSafeAllowlistedOrTopDomain(url)) {
      const verdict = createSafeAllowVerdict(url);
      storeAndEnforce(tabId, verdict, frameId);
      sendResponse({ verdict });
      return false;
    }

    if (isUserOverridden(tabId, url)) {
      const verdict = createSafeAllowVerdict(url);
      storeAndEnforce(tabId, verdict, frameId);
      sendResponse({ verdict });
      return false;
    }

    analyzeUrl(url).then(async (ruleSignals) => {
      if (!ruleSignals) {
        sendResponse({ verdict: null });
        return;
      }
      const redirectSignals = await getRedirectSignalsAsync(tabId);
      const tabState = await getTabRiskState(tabId);
      if (tabState && tabState.isPopunderTab && redirectSignals) {
        redirectSignals.popunderSpawn = true;
      }
      const verdict = calculateRisk(
        url,
        ruleSignals,
        null,
        null,
        null,
        redirectSignals
      );
      verdict.url = url;

      if (tabState && verdict.reasons && verdict.reasons.length > 0) {
        try {
          const prevHost = tabState.url ? new URL(tabState.url).hostname.toLowerCase() : '';
          const curHost = new URL(url).hostname.toLowerCase();
          if (prevHost && curHost && prevHost === curHost) {
            const prevMax = tabState.maxRiskScore || 0;
            if (prevMax > verdict.score || tabState.maxAction === 'block' || tabState.isPopunderTab) {
              verdict.score = Math.max(verdict.score, prevMax, tabState.isPopunderTab ? 85 : 0);
              verdict.riskScore = verdict.score;
              if (tabState.maxAction === 'block' || tabState.isPopunderTab || prevMax >= 70) {
                verdict.action = 'block';
                verdict.severity = 'danger';
                verdict.state = 'danger';
              }
            }
          }
        } catch (_) {}
      }

      if (!verdict.reasons || verdict.reasons.length === 0) {
        verdict.score = 0;
        verdict.riskScore = 0;
        verdict.action = 'allow';
        verdict.severity = 'safe';
        verdict.state = 'safe';
      }

      storeAndEnforce(tabId, verdict, frameId);
      sendResponse({ verdict });
    }).catch(() => {
      sendResponse({ verdict: null });
    });
    return true; // Keep message channel open for async response
  }

  if (message.action === 'ANALYZE_SUBFRAME_CREDENTIALS') {
    const targetTabId = tabId || (sender.tab ? sender.tab.id : null);
    if (!targetTabId) {
      sendResponse({ verdict: null });
      return false;
    }
    runFullAnalysis(targetTabId, message.url, message.domSignals).then(verdict => {
      if (verdict && (verdict.action === 'block' || (verdict.score || 0) >= 70)) {
        // Enforce immediately on the top-level tab
        storeAndEnforce(targetTabId, verdict, 0);
      }
      sendResponse({ verdict });
    }).catch(() => {
      sendResponse({ verdict: null });
    });
    return true; // Keep channel open
  }

  if (message.action === 'ANALYZE_FULL') {
    const targetTabId = sender.tab ? sender.tab.id : tabId;
    if (isSafeAllowlistedOrTopDomain(message.url)) {
      const verdict = createSafeAllowVerdict(message.url);
      if (targetTabId) storeAndEnforce(targetTabId, verdict, frameId);
      sendResponse({ verdict });
      return false;
    }
    if (targetTabId && isUserOverridden(targetTabId, message.url)) {
      const verdict = createSafeAllowVerdict(message.url);
      storeAndEnforce(targetTabId, verdict, frameId);
      sendResponse({ verdict });
      return false;
    }
    if (!targetTabId) {
      sendResponse({ verdict: null });
      return false;
    }
    runFullAnalysis(targetTabId, message.url, message.domSignals).then(verdict => {
      if (verdict) {
        storeAndEnforce(targetTabId, verdict, frameId);
      }
      sendResponse({ verdict });
    }).catch(() => {
      sendResponse({ verdict: null });
    });
    return true; // Keep channel open
  }

  if (message.action === 'RUNTIME_THREAT_DETECTED') {
    const targetTabId = tabId || (sender.tab ? sender.tab.id : null);
    const targetUrl = message.url || (sender.tab ? sender.tab.url : '');
    // If the domain is an allowlisted / trusted domain (e.g. Google), never trigger runtime threat
    if (targetUrl && isSafeAllowlistedOrTopDomain(targetUrl)) {
      sendResponse({ success: false, ignored: true });
      return false;
    }
    const threatSignal = message.signal || 'SIG_PHISHING_KIT_WEBHOOK_EXFIL';
    const threatScore = 95;
    const threatVerdict = {
      action: 'block',
      severity: 'danger',
      state: 'danger',
      score: threatScore,
      riskScore: threatScore,
      url: message.url || (sender.tab ? sender.tab.url : ''),
      reasons: [
        threatSignal === 'SIG_CLICKFIX_CLIPBOARD_ATTACK'
          ? 'Live ClickFix clipboard command execution attack blocked.'
          : threatSignal === 'SIG_CLIPBOARD_ADDRESS_SWAP'
          ? 'Live clipboard crypto/UPI address swapper attack blocked.'
          : threatSignal === 'SIG_ROGUE_PUSH_OR_SW_TRAP'
          ? 'Rogue push notification or service worker registration blocked.'
          : threatSignal === 'SIG_UNTRUSTED_SCREEN_SHARE'
          ? 'Untrusted screen sharing capture attempt blocked.'
          : 'Phishing kit credential exfiltration endpoint blocked.'
      ],
      signals: [{ id: threatSignal, score: threatScore }]
    };
    if (targetTabId) {
      storeAndEnforce(targetTabId, threatVerdict, 0);
    }
    sendResponse({ success: true, verdict: threatVerdict });
    return false;
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
  await hydrateFromStorage();
  console.log('[Verity] Extension installed and ready.');
});

chrome.runtime.onStartup.addListener(async () => {
  await loadBrands();
  await loadPaymentBrands();
  await loadUrlShorteners();
  await initializeModel();
  await hydrateFromStorage();
  await initDnrBlocker();
  console.log('[Verity] Extension started.');
});

// Also load brands and hydrate on service worker wake (no event)
loadBrands().catch(() => {});
loadPaymentBrands().catch(() => {});
loadUrlShorteners().catch(() => {});
hydrateFromStorage().catch(() => {});

// ---------------------------------------------------------------------------
// Download Monitor Initialization
// ---------------------------------------------------------------------------
function initDownloadProtection() {
  initDownloadMonitor({
    brandsList,
    getBrandsList: () => brandsList,
    calculateRisk,
    buildRuleSignals,
  });
}

// Synchronously register download listeners at top-level evaluation
initDownloadProtection();
initDnrBlocker().catch(() => {});

// Load brands asynchronously
Promise.all([
  loadBrands(),
  loadPaymentBrands(),
  loadUrlShorteners(),
]).catch(() => {});
