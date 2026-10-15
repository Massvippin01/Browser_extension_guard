/**
 * duckduckgo.js - DuckDuckGo search result adapter for Verity
 */

export const DuckDuckGoAdapter = {
  name: 'duckduckgo',

  isSearchPage() {
    return window.location.hostname.includes('duckduckgo.com') &&
           (window.location.search.includes('q=') || window.location.pathname.startsWith('/html'));
  },

  extractResults() {
    const results = [];
    const seen = new Set();

    // Strategy: query common DuckDuckGo result containers and title anchors
    // Modern DuckDuckGo uses article[data-testid="result"] or div.result
    const containers = document.querySelectorAll('article[data-testid="result"], li[data-layout="organic"], div.result, div.results_links_deep');

    containers.forEach((container, index) => {
      const anchor = container.querySelector('h2 a[data-testid="result-title-a"]') ||
                     container.querySelector('h2 a') ||
                     container.querySelector('a.result__a') ||
                     container.querySelector('a[data-testid="result-title-a"]') ||
                     container.querySelector('h2');

      if (!anchor) return;
      const url = anchor.href || (anchor.querySelector('a') && anchor.querySelector('a').href);
      if (!url || !url.startsWith('http')) return;

      // Skip internal DuckDuckGo links / ads / navigation
      if (/duckduckgo\.com\/(y\.js|aclk|feedback|settings)/.test(url)) return;

      if (seen.has(url)) return;
      seen.add(url);

      // Insertion point: put badge directly inside the h2 heading at the end
      const h2 = container.querySelector('h2') || anchor.closest('h2') || anchor;
      const insertionPoint = h2;

      const titleText = (h2 ? h2.innerText : anchor.innerText || '').trim();

      results.push({
        id: `verity-res-ddg-${index}`,
        url,
        title: titleText,
        snippet: '',
        position: index,
        element: container,
        insertionPoint
      });
    });

    // Fallback if no container matched: search for h2 anchors directly
    if (results.length === 0) {
      const h2Anchors = document.querySelectorAll('h2 a');
      h2Anchors.forEach((anchor, index) => {
        const url = anchor.href;
        if (!url || !url.startsWith('http') || url.includes('duckduckgo.com')) return;
        if (seen.has(url)) return;
        seen.add(url);

        const h2 = anchor.closest('h2') || anchor;
        results.push({
          id: `verity-res-ddg-fallback-${index}`,
          url,
          title: h2.innerText.trim(),
          snippet: '',
          position: index,
          element: h2.closest('article, li, div') || h2,
          insertionPoint: h2
        });
      });
    }

    return results;
  }
};
