/**
 * redirect-analyzer.js - Enterprise-grade redirect tracking and Bitly unfurling.
 */

const redirectChains = new Map();
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

function recordHop(tabId, url, isRedirect = false) {
  if (!redirectChains.has(tabId)) {
    redirectChains.set(tabId, { 
      chain: [url], 
      hasShortener: false,
      loopDetected: false,
      terminated: false
    });
  } else {
    const data = redirectChains.get(tabId);
    if (data.terminated) return;
    
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
  
  // Check if current hop is a shortener (match on bare hostname, ignoring port)
  const hostname = getHostname(url);
  if (SHORTENERS.has(hostname)) {
    redirectChains.get(tabId).hasShortener = true;
  }
}

// 1. webRequest for HTTP 301/302 level tracing (Server-side redirects)
chrome.webRequest.onBeforeRedirect.addListener(
  (details) => {
    if (details.type === "main_frame") {
      recordHop(details.tabId, details.url, true);
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
  
  if (details.transitionType === 'typed' || 
      details.transitionType === 'auto_bookmark' || 
      details.transitionType === 'generated' || 
      details.transitionQualifiers.includes('from_address_bar')) {
    redirectChains.set(details.tabId, { 
      chain: [details.url], 
      hasShortener: false,
      loopDetected: false,
      terminated: false
    });
    
    const host = getHostname(details.url);
    if (SHORTENERS.has(host)) {
      redirectChains.get(details.tabId).hasShortener = true;
    }
  }
});

// Heuristics for suspicious domains (applied to intermediate AND final domains)
function isSuspiciousDomain(url) {
  let hostname = '';
  let pathname = '';
  try {
    const u = new URL(url);
    hostname = u.hostname.toLowerCase();
    pathname = u.pathname;
  } catch(e) { return false; }

  const suspTLDs = [
    '.xyz', '.top', '.pw', '.tk', '.ml', '.rest', '.click', '.live',
    '.online', '.site', '.fun', '.vip', '.club', '.icu', '.sbs',
    '.uno', '.cfd', '.bar', '.monster', '.skin', '.cc', '.ws'
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

export function getRedirectSignals(tabId) {
  const data = redirectChains.get(tabId);
  if (!data || data.chain.length <= 1) return null;
  
  const chain = data.chain;
  const redirectCount = chain.length - 1;
  
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
  const finalUrl = chain[chain.length - 1];
  const finalDomainSuspicious = isSuspiciousDomain(finalUrl);
  
  const excessiveRedirects = redirectCount > 3;

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
    chain: chain
  };
}
