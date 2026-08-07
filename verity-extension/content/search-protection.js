/**
 * search-protection.js - Injects visual security indicators into search results.
 */

function scanSearchResults() {
  // Try to find search result links (Google often uses 'h3' inside 'a', or standard search containers)
  let links = [];
  if (window.location.hostname.includes('google.')) {
    links = Array.from(document.querySelectorAll('#search a')).filter(a => a.querySelector('h3'));
  } else if (window.location.hostname.includes('bing.')) {
    links = Array.from(document.querySelectorAll('#b_results h2 a'));
  }

  if (links.length === 0) return;

  const urlsToAnalyze = links.map(a => {
    // Avoid double scanning
    if (a.dataset.verityScanned) return null;
    a.dataset.verityScanned = "true";
    return { element: a, url: a.href };
  }).filter(Boolean);

  if (urlsToAnalyze.length === 0) return;

  // Ask background to score these URLs quickly (rules only, to prevent massive ML load)
  urlsToAnalyze.forEach(item => {
    chrome.runtime.sendMessage({ action: 'run_inference', url: item.url }, (response) => {
      if (response && response.score !== undefined) {
        addIndicator(item.element, response.score);
      }
    });
  });
}

function addIndicator(anchor, riskScore) {
  const indicator = document.createElement('span');
  indicator.style.marginLeft = '8px';
  indicator.style.fontSize = '12px';
  indicator.style.fontWeight = 'bold';
  indicator.style.padding = '2px 6px';
  indicator.style.borderRadius = '12px';
  indicator.style.verticalAlign = 'middle';
  
  if (riskScore >= 70) {
    indicator.textContent = 'DANGEROUS';
    indicator.style.backgroundColor = '#fef2f2'; // red-50
    indicator.style.color = '#ef4444';
    indicator.style.border = '1px solid #f87171';
  } else if (riskScore >= 35) {
    indicator.textContent = 'SUSPICIOUS';
    indicator.style.backgroundColor = '#fffbeb'; // amber-50
    indicator.style.color = '#f59e0b';
    indicator.style.border = '1px solid #fbbf24';
  } else {
    indicator.textContent = 'SAFE';
    indicator.style.backgroundColor = '#f0fdf4'; // green-50
    indicator.style.color = '#10b981';
    indicator.style.border = '1px solid #34d399';
  }

  // Insert after the title inside the anchor, or next to the anchor
  const heading = anchor.querySelector('h3, h2');
  if (heading) {
    heading.appendChild(indicator);
  } else {
    anchor.parentNode.insertBefore(indicator, anchor.nextSibling);
  }
}

// Observe DOM for infinite scrolling/dynamic loads
const observer = new MutationObserver(() => {
  scanSearchResults();
});
observer.observe(document.body, { childList: true, subtree: true });

// Initial scan
scanSearchResults();
