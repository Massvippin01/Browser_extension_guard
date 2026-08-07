/**
 * history.js - Manages the persistence of threat history in chrome.storage.local
 */

export async function saveToHistory(verdict, url) {
  try {
    const data = await chrome.storage.local.get(['verityHistory']);
    let history = data.verityHistory || [];

    // Store metadata only, no sensitive values
    const entry = {
      timestamp: Date.now(),
      domain: new URL(url).hostname,
      riskScore: verdict.riskScore,
      severity: verdict.severity,
      reasons: verdict.reasons
    };

    history.unshift(entry);
    
    // Keep only last 500 entries to prevent infinite growth
    if (history.length > 500) {
      history = history.slice(0, 500);
    }

    await chrome.storage.local.set({ verityHistory: history });
  } catch (err) {
    console.error('[Verity] Error saving history:', err);
  }
}

export async function getHistory() {
  const data = await chrome.storage.local.get(['verityHistory']);
  return data.verityHistory || [];
}

export async function getTodayStats() {
  const history = await getHistory();
  const startOfDay = new Date();
  startOfDay.setHours(0, 0, 0, 0);

  const stats = {
    scanned: 0,
    safe: 0,
    suspicious: 0,
    dangerous: 0,
    blocked: 0
  };

  history.forEach(entry => {
    if (entry.timestamp >= startOfDay.getTime()) {
      stats.scanned++;
      if (entry.severity === 'safe') stats.safe++;
      if (entry.severity === 'caution') stats.suspicious++;
      if (entry.severity === 'danger') {
        stats.dangerous++;
        stats.blocked++; // We block dangerous sites by default
      }
    }
  });

  return stats;
}
