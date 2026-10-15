/**
 * filenameAnalyzer.js - Analyzes filenames for deceptive patterns.
 * Double-extension detection, Unicode normalization, misleading naming.
 */

// Known safe extensions (left-side of double extension)
const DOCUMENT_LIKE_EXTENSIONS = new Set([
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.txt', '.jpg', '.jpeg', '.png', '.gif', '.mp4', '.mp3', '.zip'
]);

// High-risk extensions (right-side = real extension)
const HIGH_RISK_EXTENSIONS = new Set([
  '.exe', '.com', '.scr', '.cpl', '.dll', '.msi', '.msp',
  '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse',
  '.wsf', '.wsh', '.hta', '.sh', '.pkg', '.deb', '.rpm',
  '.dmg', '.iso', '.img', '.vhd', '.vhdx', '.lnk', '.chm',
  '.one', '.reg', '.cab'
]);

// Suspicious filename keywords: misleading update/security naming patterns
const SUSPICIOUS_FILENAME_KEYWORDS = [
  // Browser impersonation
  'chrome_update', 'chrome-update', 'chromeupdate',
  'firefox_update', 'firefox-update',
  'browser_update', 'browserupdate',
  // OS/Security impersonation
  'windows_update', 'windowsupdate', 'microsoft_update',
  'security_update', 'securityupdate', 'security-update',
  'system_update', 'critical_update',
  // Software impersonation
  'adobe_update', 'flashplayer', 'flash_player', 'java_update',
  // Financial lures
  'invoice', 'bank_statement', 'bank-statement', 'payment_receipt',
  'salary_slip', 'tax_return', 'tax-return',
  // Document lures
  'resume', 'cv_', '_cv', 'offer_letter', 'contract',
  'your_document', 'your-document',
];

/**
 * Analyze a filename for security signals.
 * @param {string} rawFilename
 * @returns {{ normalizedFilename, actualExtension, apparentExtension, doubleExtension, misleadingFilename, suspiciousKeyword, hasUnicode }}
 */
export function analyzeFilename(rawFilename) {
  if (!rawFilename) {
    return {
      normalizedFilename: '',
      actualExtension: '',
      apparentExtension: '',
      doubleExtension: false,
      misleadingExtension: false,
      misleadingFilename: false,
      suspiciousKeyword: null,
      hasUnicode: false,
    };
  }

  // 1. Unicode NFKC normalization (spec §10)
  const normalized = rawFilename.normalize('NFKC');
  const hasUnicode = normalized !== rawFilename || /[^\x00-\x7F]/.test(rawFilename);

  const lower = normalized.toLowerCase();

  // 2. Extension extraction — find last and second-last dot
  const parts = lower.split('.');
  // e.g. "invoice.pdf.exe" → parts = ["invoice", "pdf", "exe"]
  const actualExtension = parts.length >= 2 ? '.' + parts[parts.length - 1] : '';
  const apparentExtension = parts.length >= 3 ? '.' + parts[parts.length - 2] : '';

  // 3. Double extension detection
  const doubleExtension = !!(
    parts.length >= 3 &&
    apparentExtension &&
    DOCUMENT_LIKE_EXTENSIONS.has(apparentExtension) &&
    HIGH_RISK_EXTENSIONS.has(actualExtension)
  );

  const misleadingExtension = doubleExtension;

  // 4. Misleading filename keyword detection
  const normalizedForKeyword = lower.replace(/[\s\-_.]/g, '_');
  const suspiciousKeyword = SUSPICIOUS_FILENAME_KEYWORDS.find(k =>
    normalizedForKeyword.includes(k.replace(/[\s\-_.]/g, '_'))
  ) || null;

  const misleadingFilename = !!(suspiciousKeyword || doubleExtension);

  return {
    normalizedFilename: normalized,
    actualExtension,
    apparentExtension,
    doubleExtension,
    misleadingExtension,
    misleadingFilename,
    suspiciousKeyword,
    hasUnicode,
  };
}
