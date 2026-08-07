(async () => {
  try {
    const src = chrome.runtime.getURL('content/search/search-manager.js');
    await import(src);
  } catch (e) {
    console.error('[Verity] Failed to load search protection module:', e);
  }
})();
