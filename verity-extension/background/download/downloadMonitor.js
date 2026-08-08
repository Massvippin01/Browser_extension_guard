/**
 * downloadMonitor.js - Listens to Chrome Downloads API events.
 * Deduplicates by download ID, orchestrates analysis → policy → UI.
 * Cleans up sessions after downloads complete.
 */

import { analyzeDownload } from './downloadAnalyzer.js';
import { applyDownloadPolicy } from './downloadPolicy.js';

// In-memory session map: downloadId → { analyzed, timer }
const downloadSessions = new Map();
const CLEANUP_DELAY_MS = 5 * 60 * 1000; // 5 min

let _brandsList = [];
let _calculateRisk = null;
let _buildRuleSignals = null;

/**
 * Initialize the download monitor with shared dependencies.
 * Called once at service worker startup.
 */
export function initDownloadMonitor({ brandsList, calculateRisk, buildRuleSignals }) {
  _brandsList = brandsList;
  _calculateRisk = calculateRisk;
  _buildRuleSignals = buildRuleSignals;
  registerListeners();
}

function registerListeners() {
  if (!chrome.downloads) return;

  // Primary event: new download created
  chrome.downloads.onCreated.addListener(async (downloadItem) => {
    await handleDownloadCreated(downloadItem);
  });

  // Secondary: track state changes (e.g. danger flag added by Chrome later)
  chrome.downloads.onChanged.addListener(async (delta) => {
    if (delta.danger && delta.danger.current && delta.danger.current !== 'safe') {
      await handleDangerChange(delta);
    }
    // Clean up on terminal states
    if (delta.state && ['complete', 'interrupted'].includes(delta.state.current)) {
      scheduleCleanup(delta.id);
    }
  });
}

async function handleDownloadCreated(downloadItem) {
  const id = downloadItem.id;

  // Deduplicate — never analyze the same download twice
  if (downloadSessions.has(id)) return;
  downloadSessions.set(id, { analyzed: false, timer: null });

  try {
    await runAnalysis(downloadItem);
  } catch (e) {
    console.error('[Verity Download] Analysis error:', e);
    cleanup(id);
  }
}

async function handleDangerChange(delta) {
  const id = delta.id;
  // Query fresh download info
  const [item] = await chrome.downloads.search({ id });
  if (!item) return;

  const session = downloadSessions.get(id);
  if (session && !session.analyzed) {
    await runAnalysis(item);
  } else if (session && session.analyzed) {
    // Chrome upgraded the danger signal — re-notify if it's now dangerous
    const dangerous = ['dangerous', 'dangerousHost', 'dangerousUrl', 'dangerousContent'].includes(delta.danger.current);
    if (dangerous) {
      await notifyTab(item.tabId, {
        downloadId: id,
        filename: getBasename(item.filename),
        sourceHostname: safeHostname(item.referrer || item.url),
        signals: ['Chrome identified this download as dangerous.'],
        riskScore: 95,
        severity: 'danger',
        action: 'block',
        cancelled: false,
        chromeSaysDangerous: true,
      });
    }
  }
}

async function runAnalysis(downloadItem) {
  const id = downloadItem.id;
  const session = downloadSessions.get(id);
  if (!session || session.analyzed) return;
  session.analyzed = true;

  // Normalize the download object
  const normalized = {
    downloadId: id,
    filename: getBasename(downloadItem.filename),
    url: downloadItem.url || '',
    finalUrl: downloadItem.finalUrl || downloadItem.url || '',
    referrer: downloadItem.referrer || '',
    mimeType: downloadItem.mime || '',
    fileSize: downloadItem.fileSize || 0,
    danger: downloadItem.danger || 'unknown',
    tabId: downloadItem.tabId,
  };

  // Build URL rule signals for the source URL
  const sourceUrl = normalized.referrer || normalized.url;
  const ruleSignals = _buildRuleSignals ? _buildRuleSignals(sourceUrl) : [];

  const { verdict, downloadSignals } = await analyzeDownload(
    normalized,
    _brandsList,
    _calculateRisk,
    ruleSignals
  );

  const policy = await applyDownloadPolicy(id, verdict, downloadSignals);

  // Build detected signals list for UI
  const detectedSignals = buildSignalsList(downloadSignals);

  // Send verdict to the originating tab
  await notifyTab(downloadItem.tabId, {
    downloadId: id,
    filename: normalized.filename,
    sourceHostname: downloadSignals.sourceHostname,
    signals: detectedSignals,
    riskScore: verdict.riskScore || 0,
    severity: verdict.severity || 'safe',
    action: policy.action,
    cancelled: policy.cancelled,
    chromeSaysDangerous: downloadSignals.chromeSaysDangerous,
    redirectChain: downloadSignals.shortenerDetected ? (verdict.redirectChain || []) : null,
  });

  scheduleCleanup(id);
}

function buildSignalsList(ds) {
  const list = [];
  if (ds.chromeSaysDangerous)   list.push('Chrome identified this file as dangerous');
  if (ds.executableDownload)    list.push('Executable file (.exe/.com/.scr)');
  if (ds.scriptDownload)        list.push(`Script file (${ds.extension})`);
  if (ds.installerDownload)     list.push(`Installer file (${ds.extension})`);
  if (ds.archiveDownload)       list.push('Archive file — may contain executables');
  if (ds.doubleExtension)       list.push(`Double extension detected: "${ds.apparentExtension}" hidden by "${ds.extension}"`);
  if (ds.misleadingFilename && ds.suspiciousKeyword)
    list.push(`Misleading filename keyword: "${ds.suspiciousKeyword}"`);
  if (ds.brandImpersonation)    list.push(`Impersonates: ${ds.brandImpersonationName}`);
  if (ds.sourceDomainMalicious) list.push('Source domain flagged as malicious');
  if (ds.sourceDomainSuspicious && !ds.sourceDomainMalicious)
    list.push('Source domain uses suspicious TLD');
  if (ds.shortenerDetected)     list.push('URL shortener in download chain');
  if (ds.crossDomainRedirectCount > 1) list.push(`${ds.crossDomainRedirectCount} cross-domain redirects before download`);
  if (ds.hasUnicode)            list.push('Filename contains Unicode/confusable characters');
  return list;
}

async function notifyTab(tabId, payload) {
  if (!tabId || tabId < 0) return;

  // Only notify on warn/block — silent on allow
  if (payload.action === 'allow' && !payload.chromeSaysDangerous) return;

  try {
    await chrome.tabs.sendMessage(tabId, {
      action: 'DOWNLOAD_VERDICT',
      payload,
    });
  } catch (e) {
    // Tab may be closed or not have content script — silently ignore
  }
}

function scheduleCleanup(id) {
  const session = downloadSessions.get(id);
  if (!session) return;
  if (session.timer) clearTimeout(session.timer);
  session.timer = setTimeout(() => cleanup(id), CLEANUP_DELAY_MS);
}

function cleanup(id) {
  const session = downloadSessions.get(id);
  if (session && session.timer) clearTimeout(session.timer);
  downloadSessions.delete(id);
}

function getBasename(filepath) {
  if (!filepath) return '';
  return filepath.replace(/\\/g, '/').split('/').pop() || filepath;
}

function safeHostname(urlStr) {
  try { return new URL(urlStr).hostname; } catch { return urlStr || ''; }
}
