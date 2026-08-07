/**
 * redirect-analyzer.js - Tracks redirect chains to detect suspicious routing.
 */

const redirectChains = new Map();

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  
  if (!redirectChains.has(details.tabId)) {
    redirectChains.set(details.tabId, { originalUrl: details.url, chain: [details.url] });
  } else {
    redirectChains.get(details.tabId).chain.push(details.url);
  }
});

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  
  // If the user explicitly typed a new URL or clicked a bookmark, reset the chain.
  if (details.transitionType === 'typed' || details.transitionType === 'auto_bookmark' || details.transitionType === 'generated' || details.transitionQualifiers.includes('from_address_bar')) {
    redirectChains.set(details.tabId, { originalUrl: details.url, chain: [details.url] });
  }
});

export function getRedirectSignals(tabId) {
  const data = redirectChains.get(tabId);
  if (!data || data.chain.length <= 1) return null;
  
  const chainLength = data.chain.length;
  // Basic heuristic: more than 2 hops (e.g. A -> B -> C -> Final)
  if (chainLength > 3) {
    return { suspicious: true, reason: `Redirect warning: ${chainLength - 1} redirects detected.` };
  }
  
  // Detect if domain changed significantly (e.g. link shortener)
  try {
    const originalHost = new URL(data.originalUrl).hostname;
    const finalHost = new URL(data.chain[data.chain.length - 1]).hostname;
    if (originalHost !== finalHost && chainLength > 1) {
       // It's a redirect across domains. If it ends up at a suspicious site, it increases risk.
       return { suspicious: true, reason: `Redirect warning: Final destination (${finalHost}) differs from original link (${originalHost}).` };
    }
  } catch (e) {}

  return null;
}
