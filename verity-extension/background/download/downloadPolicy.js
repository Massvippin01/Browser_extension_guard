/**
 * downloadPolicy.js - Translates central risk verdict into supported Chrome actions.
 * Only uses APIs that actually exist. Never fakes blocking.
 */

/**
 * Apply policy based on verdict.
 * @param {number} downloadId - Chrome download ID
 * @param {object} verdict    - From calculateRisk()
 * @param {object} downloadSignals - Normalized download features
 * @returns {Promise<{ action: string, cancelled: boolean }>}
 */
export async function applyDownloadPolicy(downloadId, verdict, downloadSignals) {
  const action = verdict.action || verdict.severity;
  let cancelled = false;

  // Chrome-confirmed dangerous: always attempt cancel
  if (downloadSignals.chromeSaysDangerous) {
    cancelled = await tryCancelDownload(downloadId);
    return { action: 'block', cancelled, reason: 'chrome_danger' };
  }

  // Verity high-risk (block verdict from risk engine)
  if (action === 'block' || verdict.severity === 'danger') {
    // Only attempt cancel for executables, scripts, installers — not archives/docs
    if (downloadSignals.executableDownload || downloadSignals.scriptDownload || downloadSignals.installerDownload) {
      cancelled = await tryCancelDownload(downloadId);
    }
    return { action: 'block', cancelled, reason: 'verity_high_risk' };
  }

  // Caution/warn — notify but do not cancel
  if (action === 'warn' || verdict.severity === 'caution') {
    return { action: 'warn', cancelled: false, reason: 'verity_caution' };
  }

  // Safe / low risk — allow silently
  return { action: 'allow', cancelled: false, reason: 'verity_safe' };
}

/**
 * Attempt to cancel a download via Chrome API.
 * Returns true if successful, false if API does not support it.
 */
async function tryCancelDownload(downloadId) {
  if (!chrome.downloads) return false;
  try {
    if (chrome.downloads.cancel) {
      await chrome.downloads.cancel(downloadId);
      return true;
    }
  } catch (e) {
    // Download finished before cancel — remove file from disk & erase from history
    try {
      if (chrome.downloads.removeFile) await chrome.downloads.removeFile(downloadId);
      if (chrome.downloads.erase) await chrome.downloads.erase({ id: downloadId });
      return true;
    } catch (e2) {}
  }
  return false;
}
