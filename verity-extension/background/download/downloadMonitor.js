/**
 * downloadMonitor.js - Listens to Chrome Downloads API events.
 * Deduplicates by download ID, orchestrates analysis → policy → UI.
 * Cleans up sessions after downloads complete.
 */

import { analyzeDownload } from './downloadAnalyzer.js';
import { applyDownloadPolicy } from './downloadPolicy.js';
import { isAllowlistedDomain } from '../../shared/legit-domains.js';

// In-memory session map: downloadId → { analyzed, timer, resolvedFilename, contentDispositionSpoofed }
const downloadSessions = new Map();
const CLEANUP_DELAY_MS = 5 * 60 * 1000; // 5 min

let _brandsList = [];
let _calculateRisk = null;
let _buildRuleSignals = null;

// Expanded dangerous file extension list (§1)
export const DANGEROUS_EXTENSIONS = new Set([
  '.exe', '.com', '.scr', '.cpl', '.dll',
  '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.sh',
  '.msi', '.msp', '.pkg', '.deb', '.rpm', '.dmg', '.apk', '.xapk', '.apkm', '.ipa',
  '.iso', '.img', '.vhd', '.vhdx', '.lnk', '.chm', '.one', '.reg', '.cab'
]);

export const ARCHIVE_EXTENSIONS = new Set([
  '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.cab', '.iso', '.img', '.vhd', '.vhdx'
]);

export function isDangerousExtension(ext) {
  if (!ext) return false;
  const normalized = ext.startsWith('.') ? ext.toLowerCase() : '.' + ext.toLowerCase();
  return DANGEROUS_EXTENSIONS.has(normalized);
}

export function isArchiveExtension(ext) {
  if (!ext) return false;
  const normalized = ext.startsWith('.') ? ext.toLowerCase() : '.' + ext.toLowerCase();
  return ARCHIVE_EXTENSIONS.has(normalized);
}

export function getFileExtension(filename) {
  if (!filename || typeof filename !== 'string') return '';
  const clean = filename.split('?')[0].split('#')[0].trim();
  const lastDot = clean.lastIndexOf('.');
  return lastDot >= 0 ? clean.slice(lastDot).toLowerCase() : '';
}

export function getUrlExtensions(urlStr) {
  const exts = [];
  if (!urlStr || typeof urlStr !== 'string') return exts;
  try {
    let clean = urlStr;
    if (clean.toLowerCase().startsWith('blob:')) clean = clean.slice(5);
    const parsed = new URL(clean);
    const base = parsed.pathname.split('/').pop() || '';
    const ext = getFileExtension(base);
    if (ext) exts.push(ext);
    for (const [, val] of parsed.searchParams.entries()) {
      if (val && typeof val === 'string' && val.includes('.')) {
        const qExt = getFileExtension(val);
        if (qExt) exts.push(qExt);
      }
    }
  } catch {}
  return exts;
}

export function getUrlExtension(urlStr) {
  const exts = getUrlExtensions(urlStr);
  const docLike = ['.pdf', '.html', '.htm', '.txt', '.doc', '.docx', '.xls', '.xlsx', '.png', '.jpg'];
  const docExt = exts.find(e => docLike.includes(e));
  return docExt || exts[0] || '';
}

export function checkContentDispositionSpoof(url, finalUrl, resolvedFilename) {
  const resolvedExt = getFileExtension(resolvedFilename);
  const isDangerousResolved = isDangerousExtension(resolvedExt) || isArchiveExtension(resolvedExt);
  if (!isDangerousResolved) return false;

  const docLike = ['.pdf', '.html', '.htm', '.txt', '.doc', '.docx', '.xls', '.xlsx', '.png', '.jpg'];
  const urlExts = [...getUrlExtensions(url), ...getUrlExtensions(finalUrl)];

  return urlExts.some(ext => docLike.includes(ext));
}

/**
 * Checks if a download is an HTML smuggling attempt via blob: or data: URIs
 * originating from an unverified (non-allowlisted) source (§3).
 */
export async function checkHtmlSmuggling(downloadItem) {
  const url = (downloadItem.url || '').toLowerCase();
  const finalUrl = (downloadItem.finalUrl || '').toLowerCase();
  const isBlobOrData = url.startsWith('blob:') || url.startsWith('data:') ||
                       finalUrl.startsWith('blob:') || finalUrl.startsWith('data:');

  if (!isBlobOrData) {
    return { isSmuggling: false, originatingUrl: '', originatingHostname: '' };
  }

  // Retrieve originating referrer or tab URL
  let originatingUrl = downloadItem.referrer || '';
  if (!originatingUrl && downloadItem.tabId && downloadItem.tabId >= 0) {
    try {
      if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.get) {
        const tab = await chrome.tabs.get(downloadItem.tabId);
        if (tab && tab.url) {
          originatingUrl = tab.url;
        }
      }
    } catch (_) {}
  }

  // If still empty and it's a blob: URI, extract origin from blob: URL
  if (!originatingUrl) {
    const raw = downloadItem.url || downloadItem.finalUrl || '';
    if (raw.toLowerCase().startsWith('blob:')) {
      try {
        const inner = raw.slice(5);
        if (inner.startsWith('http://') || inner.startsWith('https://')) {
          originatingUrl = inner;
        }
      } catch (_) {}
    }
  }

  const originatingHostname = safeHostname(originatingUrl);
  // Check against our verified allowlist (config/legit_domains.js)
  const isVerifiedAllowlisted = isAllowlistedDomain(originatingUrl) || (originatingHostname && isAllowlistedDomain(originatingHostname));

  return {
    isSmuggling: !isVerifiedAllowlisted,
    originatingUrl,
    originatingHostname
  };
}

/**
 * Initialize the download monitor with shared dependencies.
 * Called once at service worker startup.
 */
export function initDownloadMonitor({ brandsList, getBrandsList, calculateRisk, buildRuleSignals }) {
  _brandsList = brandsList;
  if (getBrandsList) _brandsList = getBrandsList;
  _calculateRisk = calculateRisk;
  _buildRuleSignals = buildRuleSignals;
  registerListeners();
}

function registerListeners() {
  if (typeof chrome === 'undefined' || !chrome.downloads) return;

  // Primary event: new download created
  chrome.downloads.onCreated.addListener(async (downloadItem) => {
    await handleDownloadCreated(downloadItem);
  });

  // Listener for determining filename (Content-Disposition resolution before file is written) (§2)
  if (chrome.downloads.onDeterminingFilename) {
    chrome.downloads.onDeterminingFilename.addListener((item, suggest) => {
      handleDeterminingFilename(item, suggest);
      return true; // asynchronous suggest resolution
    });
  }

  // Secondary: track state changes (Content-Disposition resolved filename or danger flag added by Chrome)
  chrome.downloads.onChanged.addListener(async (delta) => {
    if (delta.danger && delta.danger.current && delta.danger.current !== 'safe') {
      await handleDangerChange(delta);
    }
    if (delta.filename && delta.filename.current) {
      await handleFilenameChange(delta);
    }
    // Clean up on terminal states
    if (delta.state && ['complete', 'interrupted'].includes(delta.state.current)) {
      scheduleCleanup(delta.id);
    }
  });
}

export async function handleDeterminingFilename(downloadItem, suggest) {
  try {
    const id = downloadItem.id;
    const resolvedName = getBasename(downloadItem.filename, downloadItem.url);
    const resolvedExt = getFileExtension(resolvedName);
    const isContentDispositionSpoofed = checkContentDispositionSpoof(downloadItem.url, downloadItem.finalUrl, resolvedName);

    const smugglingInfo = await checkHtmlSmuggling(downloadItem);
    const isRiskySmuggle = smugglingInfo.isSmuggling && (isDangerousExtension(resolvedExt) || isArchiveExtension(resolvedExt));

    // Pause immediately if dangerous resolved extension, spoofed, or smuggled
    if (isContentDispositionSpoofed || isDangerousExtension(resolvedExt) || isRiskySmuggle) {
      if (typeof chrome !== 'undefined' && chrome.downloads && chrome.downloads.pause) {
        await chrome.downloads.pause(id).catch(() => {});
      }
    }

    if (typeof suggest === 'function') {
      suggest();
    }

    let session = downloadSessions.get(id);
    if (!session || !session.analyzed || session.resolvedFilename !== resolvedName || isContentDispositionSpoofed || isRiskySmuggle) {
      if (session) {
        session.analyzed = false;
        session.resolvedFilename = resolvedName;
        session.contentDispositionSpoofed = isContentDispositionSpoofed;
      }
      await runAnalysis(downloadItem, {
        resolvedFilename: resolvedName,
        contentDispositionSpoofed: isContentDispositionSpoofed,
        htmlSmuggling: smugglingInfo.isSmuggling,
        originatingHostname: smugglingInfo.originatingHostname,
        originatingUrl: smugglingInfo.originatingUrl
      });
    }
  } catch (e) {
    if (typeof suggest === 'function') {
      try { suggest(); } catch (_) {}
    }
  }
}

export async function handleFilenameChange(delta) {
  if (typeof chrome === 'undefined' || !chrome.downloads || !chrome.downloads.search) return;
  const [item] = await chrome.downloads.search({ id: delta.id });
  if (!item) return;

  const resolvedName = getBasename(delta.filename.current, item.url);
  const resolvedExt = getFileExtension(resolvedName);
  const isContentDispositionSpoofed = checkContentDispositionSpoof(item.url, item.finalUrl, resolvedName);

  const smugglingInfo = await checkHtmlSmuggling(item);
  const isRiskySmuggle = smugglingInfo.isSmuggling && (isDangerousExtension(resolvedExt) || isArchiveExtension(resolvedExt));

  if (isContentDispositionSpoofed || isDangerousExtension(resolvedExt) || isRiskySmuggle) {
    if (typeof chrome !== 'undefined' && chrome.downloads && chrome.downloads.pause) {
      await chrome.downloads.pause(delta.id).catch(() => {});
    }
  }

  let session = downloadSessions.get(delta.id);
  if (!session || !session.analyzed || session.resolvedFilename !== resolvedName || isContentDispositionSpoofed || isRiskySmuggle) {
    if (session) {
      session.analyzed = false;
      session.resolvedFilename = resolvedName;
      session.contentDispositionSpoofed = isContentDispositionSpoofed;
    }
    await runAnalysis(item, {
      resolvedFilename: resolvedName,
      contentDispositionSpoofed: isContentDispositionSpoofed,
      htmlSmuggling: smugglingInfo.isSmuggling,
      originatingHostname: smugglingInfo.originatingHostname,
      originatingUrl: smugglingInfo.originatingUrl
    });
  }
}

async function handleDownloadCreated(downloadItem) {
  const id = downloadItem.id;
  const basename = getBasename(downloadItem.filename, downloadItem.url);
  const ext = getFileExtension(basename);

  // Check HTML smuggling early
  const smugglingInfo = await checkHtmlSmuggling(downloadItem);
  const isRiskySmuggle = smugglingInfo.isSmuggling && (isDangerousExtension(ext) || isArchiveExtension(ext));

  const remoteTools = ['anydesk', 'rustdesk', 'ultraviewer', 'teamviewer', 'screenconnect', 'supremo', 'ammyy', 'quickassist'];
  const isRemoteAccessTool = remoteTools.some(t => basename.toLowerCase().includes(t));

  // If HTML smuggling, remote desktop tool, or dangerous extension, pause immediately
  if (isRiskySmuggle || isDangerousExtension(ext) || isRemoteAccessTool) {
    if (typeof chrome !== 'undefined' && chrome.downloads && chrome.downloads.pause) {
      await chrome.downloads.pause(id).catch(() => {});
    }
  }

  // Deduplicate — never analyze the same download twice
  if (downloadSessions.has(id)) return;
  downloadSessions.set(id, {
    analyzed: false,
    timer: null,
    resolvedFilename: basename,
    contentDispositionSpoofed: false
  });

  try {
    await runAnalysis(downloadItem, {
      htmlSmuggling: smugglingInfo.isSmuggling,
      originatingHostname: smugglingInfo.originatingHostname,
      originatingUrl: smugglingInfo.originatingUrl
    });
  } catch (e) {
    console.error('[Verity Download] Analysis error:', e);
    cleanup(id);
  }
}

async function handleDangerChange(delta) {
  if (typeof chrome === 'undefined' || !chrome.downloads || !chrome.downloads.search) return;
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

export async function runAnalysis(downloadItem, extraContext = {}) {
  const id = downloadItem.id;
  const resolvedName = extraContext.resolvedFilename || getBasename(downloadItem.filename, downloadItem.url);

  let session = downloadSessions.get(id);
  if (!session) {
    session = {
      analyzed: false,
      timer: null,
      resolvedFilename: resolvedName,
      contentDispositionSpoofed: !!extraContext.contentDispositionSpoofed
    };
    downloadSessions.set(id, session);
  } else if (session.analyzed) {
    return;
  }
  session.analyzed = true;
  session.resolvedFilename = resolvedName;

  // Detect HTML smuggling if not already evaluated
  const smugglingInfo = (extraContext.htmlSmuggling !== undefined)
    ? {
        isSmuggling: extraContext.htmlSmuggling,
        originatingHostname: extraContext.originatingHostname || '',
        originatingUrl: extraContext.originatingUrl || ''
      }
    : await checkHtmlSmuggling(downloadItem);

  const ext = getFileExtension(resolvedName);
  const isRiskyOrArchive = isDangerousExtension(ext) || isArchiveExtension(ext);
  if (smugglingInfo.isSmuggling && isRiskyOrArchive) {
    if (typeof chrome !== 'undefined' && chrome.downloads && chrome.downloads.pause) {
      await chrome.downloads.pause(id).catch(() => {});
    }
  }

  // Normalize the download object
  const normalized = {
    downloadId: id,
    filename: resolvedName,
    url: downloadItem.url || '',
    finalUrl: downloadItem.finalUrl || downloadItem.url || '',
    referrer: downloadItem.referrer || '',
    mimeType: downloadItem.mime || '',
    fileSize: downloadItem.fileSize || 0,
    danger: downloadItem.danger || 'unknown',
    tabId: downloadItem.tabId,
    contentDispositionSpoofed: !!extraContext.contentDispositionSpoofed,
    htmlSmuggling: smugglingInfo.isSmuggling,
    originatingHostname: smugglingInfo.originatingHostname,
    originatingUrl: smugglingInfo.originatingUrl,
  };

  // Build URL rule signals for the source URL
  const sourceUrl = normalized.originatingUrl || normalized.referrer || normalized.url;
  const ruleSignals = _buildRuleSignals ? _buildRuleSignals(sourceUrl) : [];

  const activeBrands = typeof _brandsList === 'function' ? _brandsList() : _brandsList;
  const { verdict, downloadSignals } = await analyzeDownload(
    normalized,
    activeBrands,
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
  if (ds.remoteAccessScam) list.push(`Remote desktop scam tool download (${ds.remoteAccessTool})`);
  if (ds.chromeSaysDangerous)   list.push('Chrome identified this file as dangerous');
  if (ds.htmlSmuggling)         list.push(`HTML smuggling: blob/data URI download from unverified origin (${ds.originatingHostname || 'external'})`);
  if (ds.contentDispositionSpoofed) list.push('Content-Disposition header spoofed document URL to executable/container');
  if (ds.executableDownload)    list.push('Executable file (.exe/.com/.scr/.lnk)');
  if (ds.scriptDownload)        list.push(`Script file (${ds.extension})`);
  if (ds.installerDownload)     list.push(`Installer file (${ds.extension})`);
  if (ds.archiveDownload)       list.push(`Archive / container file (${ds.extension})`);
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
  // Only notify on warn/block — silent on allow
  if (payload.action === 'allow' && !payload.chromeSaysDangerous) return;

  let targetTabId = tabId;
  if (!targetTabId || targetTabId < 0) {
    try {
      if (chrome.tabs && chrome.tabs.query) {
        const tabs = await chrome.tabs.query({ active: true });
        const activeTab = tabs && tabs[0];
        if (activeTab && activeTab.id) targetTabId = activeTab.id;
      }
    } catch {}
  }

  if (!targetTabId || targetTabId < 0) return;

  try {
    await chrome.tabs.sendMessage(targetTabId, {
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
  if (session.timer && typeof session.timer.unref === 'function') {
    session.timer.unref();
  }
}

function cleanup(id) {
  const session = downloadSessions.get(id);
  if (session && session.timer) clearTimeout(session.timer);
  downloadSessions.delete(id);
}

function getBasename(filepath, url) {
  if (filepath) {
    let base = filepath.replace(/\\/g, '/').split('/').pop();
    if (base && base.endsWith('.crdownload')) {
      base = base.slice(0, -11);
    }
    if (base) return base;
  }
  if (url) {
    try {
      let cleanUrl = url;
      if (cleanUrl.toLowerCase().startsWith('blob:')) cleanUrl = cleanUrl.slice(5);
      const pathname = new URL(cleanUrl).pathname;
      const base = pathname.split('/').pop();
      if (base && base.includes('.')) return base;
    } catch {}
  }
  return filepath || '';
}

function safeHostname(urlStr) {
  if (!urlStr) return '';
  try {
    let clean = urlStr;
    if (clean.toLowerCase().startsWith('blob:')) clean = clean.slice(5);
    return new URL(clean).hostname.toLowerCase();
  } catch {
    return urlStr || '';
  }
}

export {
  handleDownloadCreated,
  handleDangerChange,
  downloadSessions,
  getBasename,
  safeHostname
};
