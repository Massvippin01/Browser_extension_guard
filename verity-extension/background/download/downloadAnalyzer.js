/**
 * downloadAnalyzer.js - Combines all download signals into normalized risk features.
 * Reuses existing Verity modules: reputation, brand detector, redirect signals, risk engine.
 * Does NOT create a second risk engine.
 */

import { classifyFile } from './fileTypeAnalyzer.js';
import { analyzeFilename } from './filenameAnalyzer.js';
import { checkReputation } from '../reputation.js';
import { getRedirectSignals } from '../redirect-analyzer.js';

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

  // ── 8. Build Normalized Download Risk Features (spec §16) ─────────────────
  const downloadSignals = {
    analysisContext: 'download',
    // File type
    executableDownload: fileType.isExecutable,
    scriptDownload:     fileType.isScript,
    installerDownload:  fileType.isInstaller,
    archiveDownload:    fileType.isArchive,
    fileCategory:       fileType.category,
    extension:          fileType.extension,
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

  const verdict = calculateRisk(
    sourceUrl || finalUrlStr,
    ruleSignals || [],
    null,             // mlScore — not applicable for downloads
    downloadDomSignals,
    threatIntel,
    redirectSignals,
    null,             // paymentAnalysis — not applicable here
    downloadSignals   // new downloadSignals parameter
  );

  return { verdict, downloadSignals };
}
