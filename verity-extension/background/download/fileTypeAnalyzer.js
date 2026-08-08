/**
 * fileTypeAnalyzer.js - Classifies file extensions and MIME types into risk categories.
 * Does NOT automatically classify as malicious — extension is a signal, not proof.
 */

const FILE_CATEGORIES = {
  CRITICAL_EXECUTABLE: 'CRITICAL_EXECUTABLE',
  HIGH_RISK_SCRIPT:    'HIGH_RISK_SCRIPT',
  HIGH_RISK_INSTALLER: 'HIGH_RISK_INSTALLER',
  ARCHIVE:             'ARCHIVE',
  DOCUMENT:            'DOCUMENT',
  MEDIA:               'MEDIA',
  IMAGE:               'IMAGE',
  TEXT:                'TEXT',
  UNKNOWN:             'UNKNOWN',
};

const EXTENSION_MAP = {
  // Critical Executables
  '.exe': FILE_CATEGORIES.CRITICAL_EXECUTABLE,
  '.com': FILE_CATEGORIES.CRITICAL_EXECUTABLE,
  '.scr': FILE_CATEGORIES.CRITICAL_EXECUTABLE,
  '.cpl': FILE_CATEGORIES.CRITICAL_EXECUTABLE,
  '.dll': FILE_CATEGORIES.CRITICAL_EXECUTABLE,

  // High-Risk Scripts
  '.bat': FILE_CATEGORIES.HIGH_RISK_SCRIPT,
  '.cmd': FILE_CATEGORIES.HIGH_RISK_SCRIPT,
  '.ps1': FILE_CATEGORIES.HIGH_RISK_SCRIPT,
  '.vbs': FILE_CATEGORIES.HIGH_RISK_SCRIPT,
  '.vbe': FILE_CATEGORIES.HIGH_RISK_SCRIPT,
  '.js':  FILE_CATEGORIES.HIGH_RISK_SCRIPT,
  '.jse': FILE_CATEGORIES.HIGH_RISK_SCRIPT,
  '.wsf': FILE_CATEGORIES.HIGH_RISK_SCRIPT,
  '.wsh': FILE_CATEGORIES.HIGH_RISK_SCRIPT,
  '.hta': FILE_CATEGORIES.HIGH_RISK_SCRIPT,
  '.sh':  FILE_CATEGORIES.HIGH_RISK_SCRIPT,

  // High-Risk Installers
  '.msi': FILE_CATEGORIES.HIGH_RISK_INSTALLER,
  '.msp': FILE_CATEGORIES.HIGH_RISK_INSTALLER,
  '.pkg': FILE_CATEGORIES.HIGH_RISK_INSTALLER,
  '.deb': FILE_CATEGORIES.HIGH_RISK_INSTALLER,
  '.rpm': FILE_CATEGORIES.HIGH_RISK_INSTALLER,
  '.dmg': FILE_CATEGORIES.HIGH_RISK_INSTALLER,

  // Archives
  '.zip': FILE_CATEGORIES.ARCHIVE,
  '.rar': FILE_CATEGORIES.ARCHIVE,
  '.7z':  FILE_CATEGORIES.ARCHIVE,
  '.iso': FILE_CATEGORIES.ARCHIVE,
  '.img': FILE_CATEGORIES.ARCHIVE,
  '.tar': FILE_CATEGORIES.ARCHIVE,
  '.gz':  FILE_CATEGORIES.ARCHIVE,
  '.cab': FILE_CATEGORIES.ARCHIVE,

  // Documents
  '.pdf':  FILE_CATEGORIES.DOCUMENT,
  '.doc':  FILE_CATEGORIES.DOCUMENT,
  '.docx': FILE_CATEGORIES.DOCUMENT,
  '.xls':  FILE_CATEGORIES.DOCUMENT,
  '.xlsx': FILE_CATEGORIES.DOCUMENT,
  '.ppt':  FILE_CATEGORIES.DOCUMENT,
  '.pptx': FILE_CATEGORIES.DOCUMENT,
  '.odt':  FILE_CATEGORIES.DOCUMENT,
  '.csv':  FILE_CATEGORIES.DOCUMENT,

  // Media
  '.mp3': FILE_CATEGORIES.MEDIA,
  '.mp4': FILE_CATEGORIES.MEDIA,
  '.avi': FILE_CATEGORIES.MEDIA,
  '.mov': FILE_CATEGORIES.MEDIA,
  '.mkv': FILE_CATEGORIES.MEDIA,
  '.wav': FILE_CATEGORIES.MEDIA,

  // Images
  '.jpg':  FILE_CATEGORIES.IMAGE,
  '.jpeg': FILE_CATEGORIES.IMAGE,
  '.png':  FILE_CATEGORIES.IMAGE,
  '.gif':  FILE_CATEGORIES.IMAGE,
  '.svg':  FILE_CATEGORIES.IMAGE,
  '.webp': FILE_CATEGORIES.IMAGE,

  // Text
  '.txt':  FILE_CATEGORIES.TEXT,
  '.json': FILE_CATEGORIES.TEXT,
  '.xml':  FILE_CATEGORIES.TEXT,
  '.html': FILE_CATEGORIES.TEXT,
  '.css':  FILE_CATEGORIES.TEXT,
};

// MIME types that strongly indicate executable/dangerous content
const DANGEROUS_MIME_PREFIXES = [
  'application/x-msdownload',
  'application/x-msdos-program',
  'application/octet-stream',
  'application/x-executable',
  'application/x-sh',
  'application/x-shellscript',
  'application/vnd.microsoft.portable-executable',
];

/**
 * Classify a file by extension and optional MIME type.
 * @param {string} filename
 * @param {string} [mimeType]
 * @returns {{ category: string, isExecutable: boolean, isScript: boolean, isInstaller: boolean, isArchive: boolean, extension: string }}
 */
export function classifyFile(filename, mimeType = '') {
  const normalized = (filename || '').normalize('NFKC').toLowerCase().trim();
  const lastDotIdx = normalized.lastIndexOf('.');
  const extension = lastDotIdx >= 0 ? normalized.slice(lastDotIdx) : '';

  const category = EXTENSION_MAP[extension] || FILE_CATEGORIES.UNKNOWN;

  // MIME type corroboration — if MIME strongly suggests executable, upgrade
  const mimeIsExecutable = DANGEROUS_MIME_PREFIXES.some(p => (mimeType || '').toLowerCase().startsWith(p));
  const effectiveCategory = (mimeIsExecutable && category === FILE_CATEGORIES.UNKNOWN)
    ? FILE_CATEGORIES.CRITICAL_EXECUTABLE
    : category;

  return {
    category: effectiveCategory,
    extension,
    isExecutable: effectiveCategory === FILE_CATEGORIES.CRITICAL_EXECUTABLE,
    isScript:    effectiveCategory === FILE_CATEGORIES.HIGH_RISK_SCRIPT,
    isInstaller: effectiveCategory === FILE_CATEGORIES.HIGH_RISK_INSTALLER,
    isArchive:   effectiveCategory === FILE_CATEGORIES.ARCHIVE,
    isDocument:  effectiveCategory === FILE_CATEGORIES.DOCUMENT,
    mimeIsExecutable,
  };
}

export { FILE_CATEGORIES };
