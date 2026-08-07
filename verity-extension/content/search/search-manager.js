import { GoogleAdapter } from './engines/google.js';
import { BingAdapter } from './engines/bing.js';
import { SearchUI } from './ui.js';

class SearchManager {
  constructor() {
    this.adapters = [GoogleAdapter, BingAdapter];
    this.activeAdapter = null;
    this.ui = new SearchUI();
    this.resultCache = new Map();     // url → verdict (persists across SPA navigations)
    this.processedElements = new WeakSet(); // tracks which DOM elements already have a badge
    this.debounceTimer = null;
    this.currentUrl = window.location.href;
  }

  init() {
    this._detectAdapter();
    if (!this.activeAdapter) return;

    console.log(`[Verity] Search protection active on: ${this.activeAdapter.name}`);

    // Initial scan after DOM settles
    this._scheduleScan(500);

    // Watch for DOM mutations (new results loading, infinite scroll)
    const observer = new MutationObserver(() => {
      this._scheduleScan(400);
    });
    observer.observe(document.body, { childList: true, subtree: true });

    // Watch for SPA URL changes (new search query in same tab)
    this._watchUrlChanges();
  }

  _detectAdapter() {
    for (const adapter of this.adapters) {
      if (adapter.isSearchPage()) {
        this.activeAdapter = adapter;
        return;
      }
    }
    this.activeAdapter = null;
  }

  // Detect when user searches a new query (History API SPA navigation)
  _watchUrlChanges() {
    // Poll for URL change every 500ms — lightweight and reliable
    setInterval(() => {
      const newUrl = window.location.href;
      if (newUrl !== this.currentUrl) {
        this.currentUrl = newUrl;
        console.log('[Verity] URL changed, re-checking adapter and rescanning...');

        // Re-detect adapter (in case user navigates away from search)
        this._detectAdapter();
        if (!this.activeAdapter) return;

        // Reset only the DOM element tracker so existing cache is reused
        // but all visible elements get re-evaluated for badge injection
        this.processedElements = new WeakSet();

        // Wait for the new results to render
        this._scheduleScan(1000);
      }
    }, 500);
  }

  _scheduleScan(delayMs) {
    clearTimeout(this.debounceTimer);
    this.debounceTimer = setTimeout(() => this.scanResults(), delayMs);
  }

  normalizeUrl(urlString) {
    try {
      const url = new URL(urlString);
      // Strip common tracking params that don't change security profile
      ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
       'ved', 'form', 'rlid', 'ref', 'fbclid', 'gclid'].forEach(p => url.searchParams.delete(p));
      // Normalize trailing slash
      let result = url.toString().replace(/\/$/, '');
      return result;
    } catch {
      return urlString;
    }
  }

  scanResults() {
    if (!this.activeAdapter) return;

    const results = this.activeAdapter.extractResults();
    console.log(`[Verity] Scanning ${results.length} results...`);

    for (const res of results) {
      if (!res.insertionPoint) continue;

      // Skip elements that already have a badge attached
      if (this.processedElements.has(res.element)) continue;

      const normUrl = this.normalizeUrl(res.url);

      if (this.resultCache.has(normUrl)) {
        // Instant inject from cache
        this.injectBadge(res, this.resultCache.get(normUrl));
      } else {
        // Mark immediately so we don't send duplicate messages while awaiting response
        this.processedElements.add(res.element);
        this.requestAnalysis(normUrl, res);
      }
    }
  }

  requestAnalysis(url, resultObj) {
    chrome.runtime.sendMessage(
      { action: 'ANALYZE_SEARCH_RESULT', url },
      (response) => {
        if (chrome.runtime.lastError) {
          console.error('[Verity] Message error:', chrome.runtime.lastError.message);
          return;
        }
        if (!response || !response.verdict) {
          console.warn('[Verity] No verdict received for', url);
          return;
        }

        console.log('[Verity] Verdict for', url, '→', response.verdict.severity, response.verdict.score);
        this.resultCache.set(url, response.verdict);
        this.injectBadge(resultObj, response.verdict);
      }
    );
  }

  injectBadge(resultObj, verdict) {
    // Final guard — check the actual DOM for an existing badge too
    if (resultObj.element.querySelector('.verity-search-indicator')) return;
    this.processedElements.add(resultObj.element);

    const badge = this.ui.createBadge(verdict);
    try {
      resultObj.insertionPoint.appendChild(badge);
      console.log('[Verity] Badge injected:', resultObj.url);
    } catch (e) {
      console.warn('[Verity] Failed to inject badge:', resultObj.url, e.message);
    }
  }
}

// Bootstrap: run once the DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => new SearchManager().init());
} else {
  new SearchManager().init();
}
