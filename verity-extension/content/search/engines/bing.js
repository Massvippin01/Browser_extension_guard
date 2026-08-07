export const BingAdapter = {
  name: 'bing',

  isSearchPage() {
    return window.location.hostname.includes('bing.com') &&
           window.location.pathname.startsWith('/search');
  },

  extractResults() {
    const results = [];
    const seen = new Set();

    // Bing's search results use li.b_algo as the primary organic result container
    const items = document.querySelectorAll('li.b_algo');

    items.forEach((el, index) => {
      const anchor = el.querySelector('h2 > a') || el.querySelector('h2 a');
      if (!anchor || !anchor.href) return;

      const url = anchor.href;
      if (!url.startsWith('http')) return;
      if (url.includes('bing.com/search') || url.includes('bing.com/images')) return;

      if (seen.has(url)) return;
      seen.add(url);

      const title = anchor.innerText.trim();
      const snippetEl = el.querySelector('.b_caption p, .b_lineclamp2, .b_lineclamp3');
      const snippet = snippetEl ? snippetEl.innerText.trim() : '';

      // Insert right inside the h2 title at the end
      const insertionPoint = anchor.closest('h2') || anchor;

      results.push({
        id: `verity-res-bing-${index}`,
        url,
        title,
        snippet,
        position: index,
        element: el,
        insertionPoint,
      });
    });

    return results;
  }
};
