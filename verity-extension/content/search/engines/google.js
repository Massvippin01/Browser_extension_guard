export const GoogleAdapter = {
  name: 'google',

  isSearchPage() {
    return (window.location.hostname.includes('google.') &&
           window.location.pathname.startsWith('/search')) ||
           window.location.pathname.includes('/demo/google-search');
  },

  extractResults() {
    const results = [];
    const seen = new Set();

    // Strategy: find all <h3> inside the search results column.
    // This is far more stable than div.g which Google changes frequently.
    const h3s = document.querySelectorAll('#search h3, #rso h3');

    h3s.forEach((h3, index) => {
      // The <h3> title is always wrapped in or adjacent to an <a> tag
      const anchor = h3.closest('a') ||
                     h3.querySelector('a') ||
                     h3.parentElement && h3.parentElement.closest('a');

      if (!anchor || !anchor.href) return;

      const url = anchor.href;

      // Must be an external http(s) link
      if (!url.startsWith('http')) return;

      // Skip all internal Google navigation links
      if (/google\.[a-z.]+\/(search|aclk|intl|accounts|policies|support|maps|images|shopping)/.test(url)) return;
      if (url.includes('youtube.com/results')) return;

      // Deduplicate by URL
      if (seen.has(url)) return;
      seen.add(url);

      // Find the best container element for this result
      // Try: data-hveid container (most reliable modern Google), then div.g, then h3's parent
      const container = h3.closest('[data-hveid]') ||
                        h3.closest('div.g') ||
                        h3.parentElement;

      // Insertion point: put badge directly inside the h3, at the end of the title
      const insertionPoint = h3;

      results.push({
        id: `verity-res-google-${index}`,
        url,
        title: h3.innerText.trim(),
        snippet: '',
        position: index,
        element: container || h3.parentElement,
        insertionPoint,
      });
    });

    return results;
  }
};
