/**
 * redirect-analyzer.js - Enterprise-grade redirect tracking and Bitly unfurling.
 *
 * Implements:
 * 1. Persistent session storage mirroring for MV3 service worker lifetime.
 * 2. Navigation target origin tracking (window.open / new tab pop-unders).
 * 3. Fast in-memory Map cache with session storage fallback.
 * 4. Automatic SIG_POPUNDER_SPAWN (+40 pts) detection on cross-root-domain hops.
 */

import { getDomain } from '../shared/psl.js';
import { isAllowlistedDomain } from '../shared/legit-domains.js';
import { hasPiracyOrUnverifiedMediaPattern, hasMalvertisingPattern } from './rules.js';

// In-memory cache for fast, synchronous access
const redirectChains = new Map();
const spawnedTabs = new Map();

let SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 
  'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee'
]);
const MAX_REDIRECTS = 10;

export function updateShorteners(list) {
  if (list && Array.isArray(list)) {
    SHORTENERS = new Set(list.map(s => s.toLowerCase()));
  }
}

function getHostname(urlStr) {
  try {
    return new URL(urlStr).hostname.toLowerCase(); // hostname = no port
  } catch(e) {
    return "";
  }
}

function getHost(urlStr) {
  try {
    return new URL(urlStr).host.toLowerCase(); // host = hostname:port
  } catch(e) {
    return "";
  }
}

function getProtocol(urlStr) {
  try {
    return new URL(urlStr).protocol.toLowerCase();
  } catch(e) {
    return "";
  }
}

function isInternalUrl(url) {
  if (!url) return true;
  return url.startsWith('chrome://') ||
         url.startsWith('chrome-extension://') ||
         url.startsWith('edge://') ||
         url.startsWith('about:') ||
         url.startsWith('data:');
}

// ---------------------------------------------------------------------------
// Session Storage Mirroring (MV3 Service Worker Persistence)
// ---------------------------------------------------------------------------

function saveChainToStorage(tabId, data) {
  if (!tabId || typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.session) {
    return;
  }
  const key = 'redirect_chain_' + tabId;
  const payload = {};
  payload[key] = {
    chain: data.chain ? data.chain.slice(-MAX_REDIRECTS) : [],
    hasShortener: !!data.hasShortener,
    loopDetected: !!data.loopDetected,
    terminated: !!data.terminated,
    popunderSpawn: !!data.popunderSpawn,
    popunderSourceDomain: data.popunderSourceDomain || '',
    popunderTargetDomain: data.popunderTargetDomain || '',
    popunderElapsedMs: data.popunderElapsedMs || 0
  };
  chrome.storage.session.set(payload).catch(() => {});
}

function saveSpawnToStorage(tabId, spawnInfo) {
  if (!tabId || typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.session) {
    return;
  }
  const key = 'spawned_tab_' + tabId;
  const payload = {};
  payload[key] = {
    sourceTabId: spawnInfo.sourceTabId,
    createdAt: spawnInfo.createdAt,
    sourceUrl: spawnInfo.sourceUrl || '',
    initialUrl: spawnInfo.initialUrl || ''
  };
  chrome.storage.session.set(payload).catch(() => {});
}

export async function hydrateFromStorage() {
  if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.session) {
    return;
  }
  try {
    const all = await chrome.storage.session.get(null).catch(() => ({}));
    for (const [key, value] of Object.entries(all)) {
      if (key.startsWith('redirect_chain_')) {
        const tabId = parseInt(key.slice('redirect_chain_'.length), 10);
        if (!isNaN(tabId) && value && typeof value === 'object') {
          redirectChains.set(tabId, value);
        }
      } else if (key.startsWith('spawned_tab_')) {
        const tabId = parseInt(key.slice('spawned_tab_'.length), 10);
        if (!isNaN(tabId) && value && typeof value === 'object') {
          spawnedTabs.set(tabId, value);
        }
      }
    }
  } catch (e) {
    console.warn('[Verity] Hydration error from session storage:', e);
  }
}

export function pruneTab(tabId) {
  if (!tabId) return;
  const numId = typeof tabId === 'string' ? parseInt(tabId, 10) : tabId;
  redirectChains.delete(numId);
  redirectChains.delete(tabId);
  spawnedTabs.delete(numId);
  spawnedTabs.delete(tabId);
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.session) {
    chrome.storage.session.remove([
      'redirect_chain_' + tabId,
      'spawned_tab_' + tabId,
      'redirect_chain_' + numId,
      'spawned_tab_' + numId
    ]).catch(() => {});
  }
}

// ---------------------------------------------------------------------------
// Pop-under & Navigation Target Tracking
// ---------------------------------------------------------------------------

/**
 * Record creation of a new navigation target (tab opened via window.open, link, etc.)
 * @param {object} details - webNavigation.onCreatedNavigationTarget event details
 */
export function recordNavigationTarget(details) {
  if (!details || !details.tabId) return;
  const sourceTabId = details.sourceTabId;
  const tabId = details.tabId;
  const numTabId = typeof tabId === 'string' ? parseInt(tabId, 10) : tabId;
  const numSourceTabId = typeof sourceTabId === 'string' ? parseInt(sourceTabId, 10) : sourceTabId;
  const createdAt = details.timeStamp || Date.now();
  const initialUrl = details.url || '';

  let sourceUrl = '';
  if (numSourceTabId && (redirectChains.has(numSourceTabId) || redirectChains.has(sourceTabId))) {
    const srcChain = (redirectChains.get(numSourceTabId) || redirectChains.get(sourceTabId)).chain;
    if (srcChain && srcChain.length > 0) {
      sourceUrl = srcChain[srcChain.length - 1];
    }
  }

  const spawnInfo = {
    sourceTabId: numSourceTabId || sourceTabId,
    createdAt,
    sourceUrl,
    initialUrl
  };

  spawnedTabs.set(numTabId, spawnInfo);
  saveSpawnToStorage(numTabId, spawnInfo);

  // If sourceUrl wasn't in cache, resolve from chrome.tabs
  if (sourceTabId && !sourceUrl && typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.get) {
    try {
      const p = chrome.tabs.get(sourceTabId);
      if (p && typeof p.then === 'function') {
        p.then((tab) => {
          if (tab && tab.url) {
            spawnInfo.sourceUrl = tab.url;
            spawnedTabs.set(numTabId, spawnInfo);
            saveSpawnToStorage(numTabId, spawnInfo);
            if (initialUrl) {
              checkPopunderSpawn(numTabId, initialUrl);
            }
          }
        }).catch(() => {});
      } else {
        chrome.tabs.get(sourceTabId, (tab) => {
          if (tab && tab.url && !chrome.runtime.lastError) {
            spawnInfo.sourceUrl = tab.url;
            spawnedTabs.set(numTabId, spawnInfo);
            saveSpawnToStorage(numTabId, spawnInfo);
            if (initialUrl) {
              checkPopunderSpawn(numTabId, initialUrl);
            }
          }
        });
      }
    } catch (_) {}
  }

  if (initialUrl && initialUrl !== 'about:blank') {
    recordHop(numTabId, initialUrl, false);
    checkPopunderSpawn(numTabId, initialUrl);
  }
}

/**
 * Check if current tab is a newly spawned pop-under navigating across root domains.
 * @param {number} tabId
 * @param {string} currentUrl
 * @returns {boolean} true if popunder detected
 */
export function checkPopunderSpawn(tabId, currentUrl) {
  if (!tabId || !currentUrl || isInternalUrl(currentUrl)) return false;
  const numId = typeof tabId === 'string' ? parseInt(tabId, 10) : tabId;
  const spawnInfo = spawnedTabs.get(numId) || spawnedTabs.get(tabId);
  if (!spawnInfo) return false;

  const now = Date.now();
  const elapsed = now - (spawnInfo.createdAt || now);
  if (elapsed > 3000) {
    return false; // Beyond 3 seconds
  }

  let targetHost = '';
  try {
    targetHost = new URL(currentUrl).hostname.toLowerCase();
  } catch (e) {
    return false;
  }
  const targetRootDomain = getDomain(targetHost) || targetHost;

  // Resolve source domain
  let sourceUrl = spawnInfo.sourceUrl;
  const srcId = typeof spawnInfo.sourceTabId === 'string' ? parseInt(spawnInfo.sourceTabId, 10) : spawnInfo.sourceTabId;
  if (!sourceUrl && srcId && (redirectChains.has(srcId) || redirectChains.has(spawnInfo.sourceTabId))) {
    const srcData = redirectChains.get(srcId) || redirectChains.get(spawnInfo.sourceTabId);
    if (srcData && srcData.chain && srcData.chain.length > 0) {
      sourceUrl = srcData.chain[srcData.chain.length - 1];
      spawnInfo.sourceUrl = sourceUrl;
    }
  }

  let sourceHost = '';
  if (sourceUrl) {
    try {
      sourceHost = new URL(sourceUrl).hostname.toLowerCase();
    } catch (e) {}
  }
  const sourceRootDomain = sourceHost ? (getDomain(sourceHost) || sourceHost) : '';

  const isDifferentRootDomain = sourceRootDomain && targetRootDomain && sourceRootDomain !== targetRootDomain;
  const isOpenerAllowlisted = sourceHost ? isAllowlistedDomain(sourceHost) : false;
  const openerHasPiracy = sourceUrl ? hasPiracyOrUnverifiedMediaPattern(sourceUrl).triggered : false;

  const isTargetAllowlisted = isAllowlistedDomain(targetHost) || isAllowlistedDomain(targetRootDomain);
  const isTargetSuspicious = isSuspiciousDomain(currentUrl);
  const targetMalv = hasMalvertisingPattern(currentUrl);

  const suspTLDs = [
    '.monster', '.click', '.sbs', '.cfd', '.rest', '.icu', '.cyou', '.buzz',
    '.lat', '.skin', '.hair', '.boats', '.quest', '.shop', '.live', '.fun',
    '.xyz', '.zip', '.info', '.top', '.link', '.online', '.site', '.pw',
    '.cc', '.ws', '.biz', '.vip', '.club', '.uno', '.bar', '.qpon', '.world',
    '.tk', '.ml', '.ga', '.cf', '.gq'
  ];
  const hasSuspiciousTLD = suspTLDs.some(tld => targetHost.endsWith(tld));

  // If opener is unverified/piracy AND target navigates to different root domain matching malvertising, suspicious TLD, or redirect heuristic:
  const isPopunderPattern = isDifferentRootDomain && !isTargetAllowlisted &&
    (!isOpenerAllowlisted || openerHasPiracy) &&
    (isTargetSuspicious || hasSuspiciousTLD || targetMalv.triggered);

  if (isPopunderPattern || (isDifferentRootDomain && !isTargetAllowlisted && (isTargetSuspicious || hasSuspiciousTLD))) {
    let chainData = redirectChains.get(numId) || redirectChains.get(tabId);
    if (!chainData) {
      chainData = {
        chain: [currentUrl],
        hasShortener: false,
        loopDetected: false,
        terminated: false
      };
      redirectChains.set(numId, chainData);
    }
    chainData.popunderSpawn = true;
    chainData.popunderSourceDomain = sourceRootDomain;
    chainData.popunderTargetDomain = targetRootDomain;
    chainData.popunderElapsedMs = elapsed;

    saveChainToStorage(numId, chainData);
    return true;
  }

  return false;
}

// ---------------------------------------------------------------------------
// Redirect Hop Tracking
// ---------------------------------------------------------------------------

export function recordHop(tabId, url, isRedirect = false) {
  if (!tabId || !url || isInternalUrl(url)) return;

  if (!redirectChains.has(tabId)) {
    redirectChains.set(tabId, { 
      chain: [url], 
      hasShortener: false,
      loopDetected: false,
      terminated: false
    });
  } else {
    const data = redirectChains.get(tabId);
    if (!data.terminated) {
      // Avoid duplicate rapid fires for the same URL
      if (data.chain[data.chain.length - 1] !== url) {
        // Check for loop — same full URL appeared before
        if (data.chain.includes(url)) {
          data.loopDetected = true;
          data.terminated = true;
        }
        
        data.chain.push(url);
        
        if (data.chain.length > MAX_REDIRECTS) {
          data.terminated = true;
        }
      }
    }
  }
  
  const currentData = redirectChains.get(tabId);

  // Check if current hop is a shortener (match on bare hostname, ignoring port)
  const hostname = getHostname(url);
  if (SHORTENERS.has(hostname)) {
    currentData.hasShortener = true;
  }

  // Check for pop-under navigation
  checkPopunderSpawn(tabId, url);

  // Mirror to session storage
  saveChainToStorage(tabId, currentData);
}

// ---------------------------------------------------------------------------
// Domain Analysis & Signal Generation
// ---------------------------------------------------------------------------

// Heuristics for suspicious domains (applied to intermediate AND final domains)
export function isSuspiciousDomain(url) {
  let hostname = '';
  let pathname = '';
  try {
    const u = new URL(url);
    hostname = u.hostname.toLowerCase();
    pathname = u.pathname;
  } catch(e) { return false; }

  const suspTLDs = [
    '.monster', '.click', '.sbs', '.cfd', '.rest', '.icu', '.cyou', '.buzz',
    '.lat', '.skin', '.hair', '.boats', '.quest', '.shop', '.live', '.fun',
    '.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq',
    '.online', '.site', '.vip', '.club', '.uno', '.bar', '.cc', '.ws', '.qpon'
  ];
  const hasSuspiciousTLD = suspTLDs.some(tld => hostname.endsWith(tld));
  const isIP = /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(hostname);
  const hasSubdomains = hostname.split('.').length > 4;
  // Very long path = ad-redirect obfuscation
  const hasLongPath = pathname.length > 200;
  // Asterisk in URL = ad-redirect network fingerprint
  const hasAsterisk = pathname.includes('*');
  // Known ad-redirect path prefixes
  const hasAdPrefix = ['/cx/', '/rd/', '/redir/', '/click/', '/go/', '/track/'].some(p => pathname.startsWith(p));

  return hasSuspiciousTLD || isIP || hasSubdomains || hasLongPath || hasAsterisk || hasAdPrefix;
}

function buildSignalsFromData(data) {
  if (!data) return null;
  const chain = data.chain || [];
  const hasPopunder = !!data.popunderSpawn;
  if (chain.length <= 1 && !hasPopunder) return null;
  
  const redirectCount = Math.max(chain.length - 1, 0);
  
  // Use full host:port for uniqueness — localhost:3000 ≠ localhost:3001
  const uniqueHosts = new Set(chain.map(url => getHost(url)));
  const uniqueDomainCount = uniqueHosts.size;
  
  let crossDomainRedirectCount = 0;
  let httpsDowngrade = false;
  let suspiciousIntermediateDomain = false;
  
  for (let i = 0; i < chain.length - 1; i++) {
    const currentUrl = chain[i];
    const nextUrl = chain[i+1];
    
    // Cross-domain: compare full host including port
    const currHost = getHost(currentUrl);
    const nextHost = getHost(nextUrl);
    
    if (currHost !== nextHost) {
      crossDomainRedirectCount++;
    }
    
    if (getProtocol(currentUrl) === 'https:' && getProtocol(nextUrl) === 'http:') {
      httpsDowngrade = true;
    }
    
    // Check intermediate domains (not first, not last)
    if (i > 0 && i < chain.length - 1) {
      if (isSuspiciousDomain(currentUrl)) {
        suspiciousIntermediateDomain = true;
      }
    }
  }
  
  // Also check the final destination itself
  const finalUrl = chain.length > 0 ? chain[chain.length - 1] : '';
  const finalDomainSuspicious = finalUrl ? isSuspiciousDomain(finalUrl) : false;
  
  const excessiveRedirects = redirectCount > 3;

  const structuredReasons = [];
  if (hasPopunder) {
    structuredReasons.push({
      id: 'SIG_POPUNDER_SPAWN',
      score: 75,
      category: 'malvertising',
      source: 'redirect',
      params: {
        sourceDomain: data.popunderSourceDomain || 'external',
        targetDomain: data.popunderTargetDomain || ''
      }
    });
  }

  return {
    analysisContext: "redirect",
    shortenerDetected: data.hasShortener,
    redirectCount: redirectCount,
    uniqueDomainCount: uniqueDomainCount,
    crossDomainRedirectCount: crossDomainRedirectCount,
    excessiveRedirects: excessiveRedirects,
    suspiciousIntermediateDomain: suspiciousIntermediateDomain,
    finalDomainSuspicious: finalDomainSuspicious,
    httpsDowngrade: httpsDowngrade,
    redirectLoop: data.loopDetected,
    chain: chain,
    popunderSpawn: hasPopunder,
    popunderDetected: hasPopunder,
    structuredReasons: structuredReasons
  };
}

export function getRedirectSignals(tabId) {
  const numId = typeof tabId === 'string' ? parseInt(tabId, 10) : tabId;
  const data = redirectChains.get(numId) || redirectChains.get(tabId);
  return buildSignalsFromData(data);
}

export async function getRedirectSignalsAsync(tabId) {
  if (!tabId) return null;
  const numId = typeof tabId === 'string' ? parseInt(tabId, 10) : tabId;
  let data = redirectChains.get(numId) || redirectChains.get(tabId);
  if (!data && typeof chrome !== 'undefined' && chrome.storage && chrome.storage.session) {
    try {
      const res = await chrome.storage.session.get([
        'redirect_chain_' + tabId,
        'redirect_chain_' + numId,
        'spawned_tab_' + tabId,
        'spawned_tab_' + numId
      ]).catch(() => ({}));
      const chainKey = res['redirect_chain_' + tabId] ? ('redirect_chain_' + tabId) : ('redirect_chain_' + numId);
      const spawnKey = res['spawned_tab_' + tabId] ? ('spawned_tab_' + tabId) : ('spawned_tab_' + numId);
      if (res[chainKey]) {
        data = res[chainKey];
        redirectChains.set(numId, data);
      }
      if (res[spawnKey] && !spawnedTabs.has(numId)) {
        spawnedTabs.set(numId, res[spawnKey]);
      }
    } catch (_) {}
  }
  return buildSignalsFromData(data);
}

// ---------------------------------------------------------------------------
// Browser Event Listeners
// ---------------------------------------------------------------------------

if (typeof chrome !== 'undefined') {
  // Navigation Target Listener
  if (chrome.webNavigation && chrome.webNavigation.onCreatedNavigationTarget) {
    chrome.webNavigation.onCreatedNavigationTarget.addListener((details) => {
      recordNavigationTarget(details);
    });
  }

  // 1. webRequest for HTTP 301/302 level tracing (Server-side redirects)
  if (chrome.webRequest && chrome.webRequest.onBeforeRedirect) {
    chrome.webRequest.onBeforeRedirect.addListener(
      (details) => {
        if (details.type === "main_frame") {
          recordHop(details.tabId, details.url, true);
          recordHop(details.tabId, details.redirectUrl, true);
        }
      },
      { urls: ["<all_urls>"] }
    );
  }

  // 2. webNavigation for Client-side tracing (JS window.location / Meta refresh)
  if (chrome.webNavigation && chrome.webNavigation.onBeforeNavigate) {
    chrome.webNavigation.onBeforeNavigate.addListener((details) => {
      if (details.frameId !== 0) return;
      recordHop(details.tabId, details.url, false);
      checkPopunderSpawn(details.tabId, details.url);
    });
  }

  if (chrome.webNavigation && chrome.webNavigation.onCommitted) {
    chrome.webNavigation.onCommitted.addListener((details) => {
      if (details.frameId !== 0) return;
      
      if (details.transitionType === 'typed' || 
          details.transitionType === 'auto_bookmark' || 
          details.transitionType === 'generated' || 
          details.transitionQualifiers.includes('from_address_bar')) {
        const newData = { 
          chain: [details.url], 
          hasShortener: false,
          loopDetected: false,
          terminated: false
        };
        redirectChains.set(details.tabId, newData);
        saveChainToStorage(details.tabId, newData);
        
        const host = getHostname(details.url);
        if (SHORTENERS.has(host)) {
          newData.hasShortener = true;
          saveChainToStorage(details.tabId, newData);
        }
      }
    });
  }

  // 3. Tab Removal Listener (Cleanup)
  if (chrome.tabs && chrome.tabs.onRemoved) {
    chrome.tabs.onRemoved.addListener((tabId) => {
      pruneTab(tabId);
    });
  }
}

// Auto-hydrate from chrome.storage.session on startup / wake
hydrateFromStorage().catch(() => {});
