/**
 * downloadAnalyzer.js - Combines all download signals into normalized risk features.
 * Reuses existing Verity modules: reputation, brand detector, redirect signals, risk engine.
 * Does NOT create a second risk engine.
 */

import { classifyFile } from './fileTypeAnalyzer.js';
import { analyzeFilename } from './filenameAnalyzer.js';
import { checkReputation } from '../reputation.js';
import { getRedirectSignals } from '../redirect-analyzer.js';
import { isAllowlistedDomain } from '../../shared/legit-domains.js';

/**
 * Extract hostname safely.
 * @param {string} urlString
 */
function safeHostname(urlString) {
  try { return new URL(urlString).hostname.toLowerCase(); } catch { return ''; }
}

/**
 * Analyze a download and produce a normalized risk features object (spec §16).
 *
 * @param {object} downloadItem - Normalized chrome.downloads.DownloadItem
 * @param {Array}  brandsList   - Loaded brands for impersonation detection
 * @param {Function} calculateRisk - The central Verity risk engine function
 * @param {Array}  ruleSignals  - Pre-computed URL rule signals for source URL
 * @returns {Promise<object>} verdict from the central risk engine
 */
export async function analyzeDownload(downloadItem, brandsList, calculateRisk, ruleSignals) {
  const {
    downloadId,
    filename,
    url,
    finalUrl,
    referrer,
    mimeType,
    fileSize,
    danger,
    tabId,
  } = downloadItem;

  // ── 1. File Type Analysis ──────────────────────────────────────────────────
  const fileType = classifyFile(filename, mimeType);

  // ── 2. Filename Analysis ───────────────────────────────────────────────────
  const filenameAnalysis = analyzeFilename(filename);

  // ── 3. Source URL Reputation ───────────────────────────────────────────────
  const sourceUrl = referrer || url || '';
  const finalUrlStr = finalUrl || url || '';
  const sourceHostname = safeHostname(sourceUrl);
  const finalHostname  = safeHostname(finalUrlStr);

  let threatIntel = null;
  if (sourceHostname) {
    try {
      threatIntel = await checkReputation(sourceUrl);
    } catch { /* fail safe */ }
  }

  // ── 4. Brand Impersonation via filename ────────────────────────────────────
  // Check if the filename contains a brand name (e.g. "Chrome_Update.exe" → Chrome)
  let brandImpersonation = false;
  let brandImpersonationName = null;
  if (brandsList && Array.isArray(brandsList)) {
    const lowerFilename = (filename || '').toLowerCase();
    for (const brand of brandsList) {
      const brandLower = (brand.name || '').toLowerCase();
      if (brandLower.length > 2 && lowerFilename.includes(brandLower)) {
        // Check it's not from the brand's own domain
        const isOfficialDomain = (brand.domains || []).some(d =>
          finalHostname === d || finalHostname.endsWith('.' + d)
        );
        if (!isOfficialDomain) {
          brandImpersonation = true;
          brandImpersonationName = brand.name;
          break;
        }
      }
    }
  }

  // ── 5. Redirect Signals ────────────────────────────────────────────────────
  let redirectSignals = null;
  if (tabId != null) {
    try {
      redirectSignals = getRedirectSignals(tabId);
    } catch { /* fail safe */ }
  }

  // ── 6. Chrome Danger State ─────────────────────────────────────────────────
  // Respect Chrome's own assessment — don't override it.
  const chromeDangerState = danger || 'unknown';
  const chromeSaysDangerous = ['dangerous', 'dangerousHost', 'uncommon', 'dangerousUrl', 'dangerousContent'].includes(chromeDangerState);

  // ── 7. Source Domain Risk Context ─────────────────────────────────────────
  const sourceDomainMalicious = !!(threatIntel && threatIntel.malware);
  // A domain is suspicious if: reputation flags it, OR it has a suspicious TLD
  const suspiciousTLDs = ['.xyz', '.top', '.pw', '.tk', '.ml', '.rest', '.click', '.online', '.site', '.fun'];
  const sourceDomainSuspicious = sourceDomainMalicious ||
    suspiciousTLDs.some(tld => sourceHostname.endsWith(tld)) ||
    suspiciousTLDs.some(tld => finalHostname.endsWith(tld));

  // ── 7b. HTML Smuggling Detection ──────────────────────────────────────────
  const urlLower = (url || '').toLowerCase();
  const finalUrlLower = (finalUrl || '').toLowerCase();
  const isBlobOrData = urlLower.startsWith('blob:') || urlLower.startsWith('data:') ||
                       finalUrlLower.startsWith('blob:') || finalUrlLower.startsWith('data:');

  const originatingUrl = downloadItem.originatingUrl || referrer || '';
  const originatingHost = downloadItem.originatingHostname || safeHostname(originatingUrl);
  const isAllowlistedOrigin = isAllowlistedDomain(originatingUrl) || isAllowlistedDomain(originatingHost);

  const htmlSmuggling = !!(downloadItem.htmlSmuggling ?? (isBlobOrData && !isAllowlistedOrigin));

  // ── 8. Build Normalized Download Risk Features (spec §16) ─────────────────
  const dangerousExtensionList = [
    '.exe', '.com', '.scr', '.cpl', '.dll',
    '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.sh',
    '.msi', '.msp', '.pkg', '.deb', '.rpm', '.dmg', '.apk', '.xapk', '.apkm', '.ipa',
    '.iso', '.img', '.vhd', '.vhdx', '.lnk', '.chm', '.one', '.reg', '.cab'
  ];
  const isDangerousExtension = dangerousExtensionList.includes((fileType.extension || '').toLowerCase());

  // Remote Desktop Scam Tool Detection
  const remoteTools = ['anydesk', 'rustdesk', 'ultraviewer', 'teamviewer', 'screenconnect', 'supremo', 'ammyy', 'quickassist'];
  const officialRemoteDomains = ['anydesk.com', 'teamviewer.com', 'rustdesk.com', 'ultraviewer.net', 'screenconnect.com', 'supremo.net', 'ammyy.com', 'microsoft.com'];
  const lowerFilename = (filename || '').toLowerCase();
  const matchedRemoteTool = remoteTools.find(t => lowerFilename.includes(t));
  const isOfficialRemoteDomain = officialRemoteDomains.some(d =>
    finalHostname === d || finalHostname.endsWith('.' + d) ||
    sourceHostname === d || sourceHostname.endsWith('.' + d)
  );
  const remoteAccessScam = !!(matchedRemoteTool && !isOfficialRemoteDomain);

  const downloadSignals = {
    analysisContext: 'download',
    remoteAccessScam,
    remoteAccessTool: matchedRemoteTool || null,
    // File type
    executableDownload: fileType.isExecutable,
    scriptDownload:     fileType.isScript,
    installerDownload:  fileType.isInstaller,
    archiveDownload:    fileType.isArchive,
    fileCategory:       fileType.category,
    extension:          fileType.extension,
    isDangerousExtension,
    // HTML Smuggling & Spoofing
    htmlSmuggling,
    originatingHostname: originatingHost,
    contentDispositionSpoofed: !!downloadItem.contentDispositionSpoofed,
    // Filename analysis
    doubleExtension:    filenameAnalysis.doubleExtension,
    misleadingFilename: filenameAnalysis.misleadingFilename,
    suspiciousKeyword:  filenameAnalysis.suspiciousKeyword,
    hasUnicode:         filenameAnalysis.hasUnicode,
    apparentExtension:  filenameAnalysis.apparentExtension,
    // Source analysis
    sourceDomainSuspicious,
    sourceDomainMalicious,
    // Brand
    brandImpersonation,
    brandImpersonationName,
    // Redirect
    shortenerDetected: !!(redirectSignals && redirectSignals.shortenerDetected),
    redirectCount:     redirectSignals ? redirectSignals.redirectCount : 0,
    crossDomainRedirectCount: redirectSignals ? redirectSignals.crossDomainRedirectCount : 0,
    // Chrome danger
    chromeDangerState,
    chromeSaysDangerous,
    // Raw data for display
    filename,
    sourceHostname: sourceHostname || finalHostname,
    fileSize,
  };

  // ── 9. Feed into Central Risk Engine ──────────────────────────────────────
  // Build DOM signals that represent the download context for the existing engine
  const downloadDomSignals = {
    isTrustedDomain: false,
    hasPasswordInput: false,
    loginFormCount: 0,
    formActions: [],
    scam: false,
    pup: false,
    financialMatches: [],
    hasCredentialCollection: false,
    paymentFields: {},
    hasPaymentForm: false,
    claimedProviders: [],
    pageText: '',
    pageTitle: filename || '',
  };

  const verdict = (typeof calculateRisk === 'function') ? calculateRisk(
    sourceUrl || finalUrlStr,
    ruleSignals || [],
    null,             // mlScore — not applicable for downloads
    downloadDomSignals,
    threatIntel,
    redirectSignals,
    null,             // paymentAnalysis — not applicable here
    downloadSignals   // new downloadSignals parameter
  ) : {
    score: 0,
    riskScore: 0,
    severity: 'safe',
    action: 'allow',
    signals: [],
    reasons: []
  };

  return { verdict, downloadSignals };
}
