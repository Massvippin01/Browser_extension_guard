/**
 * redirect-analyzer.js - Enterprise-grade redirect tracking and Bitly unfurling.
 */

const redirectChains = new Map();

// Known shortener domains
const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 
  'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee'
]);

/**
 * Normalizes a URL to just its hostname for comparison
 */
function getHostname(urlStr) {
  try {
    return new URL(urlStr).hostname.toLowerCase();
  } catch(e) {
    return "";
  }
}

/**
 * Initialize or append to a chain
 */
function recordHop(tabId, url, isRedirect = false) {
  if (!redirectChains.has(tabId)) {
    redirectChains.set(tabId, { originalUrl: url, chain: [url], hasShortener: false });
  } else {
    const data = redirectChains.get(tabId);
    // Avoid duplicate rapid fires for the same URL
    if (data.chain[data.chain.length - 1] !== url) {
      data.chain.push(url);
    }
  }
  
  // Check if current hop is a shortener
  const host = getHostname(url);
  if (SHORTENERS.has(host)) {
    redirectChains.get(tabId).hasShortener = true;
  }
}

// 1. webRequest for HTTP 301/302 level tracing (Server-side redirects)
chrome.webRequest.onBeforeRedirect.addListener(
  (details) => {
    if (details.type === "main_frame") {
      recordHop(details.tabId, details.url, true);
      // Also log the destination it's going to
      recordHop(details.tabId, details.redirectUrl, true);
    }
  },
  { urls: ["<all_urls>"] }
);

// 2. webNavigation for Client-side tracing (JS window.location / Meta refresh)
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  recordHop(details.tabId, details.url, false);
});

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  
  // If the user explicitly typed a new URL or clicked a bookmark, reset the chain.
  if (details.transitionType === 'typed' || 
      details.transitionType === 'auto_bookmark' || 
      details.transitionType === 'generated' || 
      details.transitionQualifiers.includes('from_address_bar')) {
    redirectChains.set(details.tabId, { originalUrl: details.url, chain: [details.url], hasShortener: false });
    
    const host = getHostname(details.url);
    if (SHORTENERS.has(host)) {
      redirectChains.get(details.tabId).hasShortener = true;
    }
  }
});

export function getRedirectSignals(tabId) {
  const data = redirectChains.get(tabId);
  if (!data || data.chain.length <= 1) return null;
  
  const chainLength = data.chain.length;
  let scoreMultiplier = 1.0;
  let reasons = [];

  // 1. Hop count heuristic
  if (chainLength > 3) {
    scoreMultiplier *= 1.2;
    reasons.push(`Complex redirect chain: ${chainLength - 1} hops detected.`);
  }
  
  // 2. Shortener Payload heuristic
  const originalHost = getHostname(data.originalUrl);
  const finalHost = getHostname(data.chain[data.chain.length - 1]);
  
  if (data.hasShortener && originalHost !== finalHost) {
    scoreMultiplier *= 1.5; // High penalty for masking final destination
    reasons.push(`Masked payload: Link shortener redirected to a different domain (${finalHost}).`);
  } else if (originalHost !== finalHost && chainLength > 1) {
    scoreMultiplier *= 1.1;
    reasons.push(`Redirected away from original domain (${originalHost} -> ${finalHost}).`);
  }

  if (reasons.length > 0) {
    return { suspicious: true, multiplier: scoreMultiplier, reasons: reasons };
  }

  return null;
}
