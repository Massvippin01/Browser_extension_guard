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

  // HTML smuggling paired with risky extension or archive: pause and enforce block
  if (downloadSignals.htmlSmuggling && (downloadSignals.archiveDownload || downloadSignals.executableDownload || downloadSignals.scriptDownload || downloadSignals.installerDownload || downloadSignals.isDangerousExtension)) {
    if (typeof chrome !== 'undefined' && chrome.downloads && chrome.downloads.pause) {
      await chrome.downloads.pause(downloadId).catch(() => {});
    }
    if (action === 'block' || verdict.severity === 'danger') {
      cancelled = await tryCancelDownload(downloadId);
    }
    return { action: 'block', cancelled, reason: 'html_smuggling' };
  }

  // Content-Disposition spoofing (.pdf/.html URL resolving to executable/container): pause and enforce block
  if (downloadSignals.contentDispositionSpoofed && (downloadSignals.archiveDownload || downloadSignals.executableDownload || downloadSignals.scriptDownload || downloadSignals.installerDownload || downloadSignals.isDangerousExtension)) {
    if (typeof chrome !== 'undefined' && chrome.downloads && chrome.downloads.pause) {
      await chrome.downloads.pause(downloadId).catch(() => {});
    }
    if (action === 'block' || verdict.severity === 'danger') {
      cancelled = await tryCancelDownload(downloadId);
    }
    return { action: 'block', cancelled, reason: 'content_disposition_spoof' };
  }

  // Verity high-risk (block verdict from risk engine)
  if (action === 'block' || verdict.severity === 'danger') {
    // Attempt cancel for executables, scripts, installers, modern containers, and dangerous formats
    if (downloadSignals.executableDownload || downloadSignals.scriptDownload || downloadSignals.installerDownload || downloadSignals.isDangerousExtension || downloadSignals.archiveDownload) {
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
  if (typeof chrome === 'undefined' || !chrome.downloads) return false;
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
