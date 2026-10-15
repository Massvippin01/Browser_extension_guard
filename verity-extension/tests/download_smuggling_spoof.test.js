import test from 'node:test';
import assert from 'node:assert/strict';

// Set up Chrome API mocks
const pausedDownloads = new Set();
const cancelledDownloads = new Set();
const erasedDownloads = new Set();
const tabsStore = new Map();
let mockDownloadsSearch = [];

globalThis.chrome = {
  downloads: {
    pause: async (id) => {
      pausedDownloads.add(id);
    },
    cancel: async (id) => {
      cancelledDownloads.add(id);
    },
    search: async (query) => {
      if (query && query.id !== undefined) {
        return mockDownloadsSearch.filter(d => d.id === query.id);
      }
      return mockDownloadsSearch;
    },
    erase: async (query) => {
      if (query && query.id !== undefined) {
        erasedDownloads.add(query.id);
      }
    },
    onCreated: { addListener: () => {} },
    onDeterminingFilename: { addListener: () => {} },
    onChanged: { addListener: () => {} }
  },
  tabs: {
    get: async (tabId) => {
      return tabsStore.get(tabId) || null;
    },
    sendMessage: async () => {}
  }
};

import {
  DANGEROUS_EXTENSIONS,
  ARCHIVE_EXTENSIONS,
  isDangerousExtension,
  isArchiveExtension,
  getFileExtension,
  getUrlExtension,
  checkContentDispositionSpoof,
  checkHtmlSmuggling,
  handleDeterminingFilename,
  handleFilenameChange,
  handleDownloadCreated,
  initDownloadMonitor
} from '../background/download/downloadMonitor.js';

import { analyzeDownload } from '../background/download/downloadAnalyzer.js';
import { applyDownloadPolicy } from '../background/download/downloadPolicy.js';
import { calculateRisk } from '../background/risk-engine.js';
import { classifyFile } from '../background/download/fileTypeAnalyzer.js';
import { analyzeFilename } from '../background/download/filenameAnalyzer.js';

// Initialize download monitor dependencies for test environment
initDownloadMonitor({
  brandsList: [],
  calculateRisk,
  buildRuleSignals: () => []
});

test('Dangerous Extensions (§1): contains all 16 expanded modern formats and scripts', () => {
  const targetExtensions = [
    '.iso', '.img', '.vhd', '.vhdx', '.dmg', '.lnk', '.hta',
    '.wsf', '.vbs', '.vbe', '.js', '.jse', '.chm', '.one', '.reg', '.cab'
  ];

  for (const ext of targetExtensions) {
    assert.strictEqual(
      DANGEROUS_EXTENSIONS.has(ext),
      true,
      `DANGEROUS_EXTENSIONS must include ${ext}`
    );
    assert.strictEqual(
      isDangerousExtension(ext),
      true,
      `isDangerousExtension("${ext}") must return true`
    );
    assert.strictEqual(
      isDangerousExtension(ext.replace('.', '')),
      true,
      `isDangerousExtension should accept dotless "${ext.replace('.', '')}"`
    );
  }
});

test('Dangerous Extensions (§1): classification into risk categories', () => {
  assert.strictEqual(classifyFile('test.lnk').isExecutable, true);
  assert.strictEqual(classifyFile('test.chm').isExecutable, true);
  assert.strictEqual(classifyFile('test.one').isExecutable, true);
  assert.strictEqual(classifyFile('test.hta').isScript, true);
  assert.strictEqual(classifyFile('test.wsf').isScript, true);
  assert.strictEqual(classifyFile('test.vbs').isScript, true);
  assert.strictEqual(classifyFile('test.vbe').isScript, true);
  assert.strictEqual(classifyFile('test.js').isScript, true);
  assert.strictEqual(classifyFile('test.jse').isScript, true);
  assert.strictEqual(classifyFile('test.reg').isScript, true);
  assert.strictEqual(classifyFile('test.dmg').isInstaller, true);
  assert.strictEqual(classifyFile('test.iso').isArchive, true);
  assert.strictEqual(classifyFile('test.img').isArchive, true);
  assert.strictEqual(classifyFile('test.vhd').isArchive, true);
  assert.strictEqual(classifyFile('test.vhdx').isArchive, true);
  assert.strictEqual(classifyFile('test.cab').isArchive, true);
});

test('Content-Disposition Spoofing (§2): checkContentDispositionSpoof correctly detects spoofed filenames', () => {
  // 1. URL ends in .pdf, resolved filename is .exe
  assert.strictEqual(
    checkContentDispositionSpoof('https://evil-host.com/invoice.pdf', '', 'invoice.exe'),
    true
  );

  // 2. URL ends in .html, resolved filename is .iso container
  assert.strictEqual(
    checkContentDispositionSpoof('https://evil-host.com/login.html', '', 'backup.iso'),
    true
  );

  // 3. Query string specifies .pdf, resolved filename is .vhd
  assert.strictEqual(
    checkContentDispositionSpoof('https://evil-host.com/download.php?doc=report.pdf', '', 'payload.vhd'),
    true
  );

  // 4. URL ends in .pdf, resolved is shortcut .lnk
  assert.strictEqual(
    checkContentDispositionSpoof('https://evil-host.com/document.pdf', '', 'special.lnk'),
    true
  );

  // 5. Benign: URL ends in .pdf and resolves to .pdf -> false
  assert.strictEqual(
    checkContentDispositionSpoof('https://legit.com/document.pdf', '', 'document.pdf'),
    false
  );

  // 6. Direct executable download: URL ends in .exe, resolves to .exe -> false (not spoofed via doc URL)
  assert.strictEqual(
    checkContentDispositionSpoof('https://example.com/installer.exe', '', 'installer.exe'),
    false
  );
});

test('Content-Disposition Spoofing (§2): onDeterminingFilename immediately pauses spoofed downloads', async () => {
  pausedDownloads.clear();
  const downloadItem = {
    id: 101,
    url: 'https://malicious-cdn.com/statement.pdf',
    filename: 'statement.iso', // resolved from Content-Disposition
    mime: 'application/x-iso9660-image'
  };

  let suggestCalled = false;
  await handleDeterminingFilename(downloadItem, () => {
    suggestCalled = true;
  });

  assert.strictEqual(suggestCalled, true, 'suggest callback must be invoked');
  assert.strictEqual(pausedDownloads.has(101), true, 'Download 101 must be paused immediately');
});

test('Content-Disposition Spoofing (§2): onChanged delta immediately pauses spoofed filename change', async () => {
  pausedDownloads.clear();
  const downloadId = 202;
  const originalItem = {
    id: downloadId,
    url: 'https://malicious-cdn.com/report.pdf',
    filename: 'report.pdf'
  };
  mockDownloadsSearch = [originalItem];

  const delta = {
    id: downloadId,
    filename: { current: 'report.exe', previous: 'report.pdf' }
  };

  await handleFilenameChange(delta);
  assert.strictEqual(pausedDownloads.has(downloadId), true, 'Download 202 must be paused upon resolving to .exe');
});

test('Content-Disposition Spoofing (§2): produces BLOCK verdict in risk engine', async () => {
  const downloadItem = {
    downloadId: 303,
    filename: 'document.iso',
    url: 'https://sketchy-site.top/download/document.pdf',
    contentDispositionSpoofed: true
  };

  const { verdict, downloadSignals } = await analyzeDownload(
    downloadItem,
    [],
    calculateRisk,
    []
  );

  assert.strictEqual(downloadSignals.contentDispositionSpoofed, true);
  assert.strictEqual(verdict.action, 'block', 'Content-Disposition spoof must yield BLOCK action');
  assert.strictEqual(verdict.severity, 'danger', 'Content-Disposition spoof must yield danger severity');
  assert.ok(verdict.score >= 75, `Score must be at least 75 (got ${verdict.score})`);
  assert.ok(verdict.signals.some(s => s.id === 'DOWNLOAD_CONTENT_DISPOSITION_SPOOF'));
});

test('HTML Smuggling (§3): detectHtmlSmuggling flags blob/data URIs from unverified origins', async () => {
  // 1. blob: URL from unverified external origin
  const unverifiedSmuggle = {
    url: 'blob:https://unverified-attack-site.xyz/550e8400-e29b-41d4-a716-446655440000',
    referrer: 'https://unverified-attack-site.xyz/landing.html'
  };
  const res1 = await checkHtmlSmuggling(unverifiedSmuggle);
  assert.strictEqual(res1.isSmuggling, true, 'Unverified blob download must be flagged as HTML smuggling');

  // 2. data: URI with unverified referrer
  const dataUriSmuggle = {
    url: 'data:application/zip;base64,UEsDBBQAAAAIA...',
    referrer: 'https://phishing-portal.com/'
  };
  const res2 = await checkHtmlSmuggling(dataUriSmuggle);
  assert.strictEqual(res2.isSmuggling, true, 'data: URI from unverified referrer must be flagged as HTML smuggling');

  // 3. blob: URL from originating tab on unverified domain
  tabsStore.set(777, { id: 777, url: 'https://piracy-stream.net/watch' });
  const tabSmuggle = {
    url: 'blob:https://piracy-stream.net/a1b2c3d4',
    tabId: 777
  };
  const res3 = await checkHtmlSmuggling(tabSmuggle);
  assert.strictEqual(res3.isSmuggling, true, 'blob: URI from unverified tab must be flagged');

  // 4. blob: URL from verified allowlisted origin (e.g. github.com)
  const allowlistedBlob = {
    url: 'blob:https://github.com/d94f298c-8519-4822-b91c-fa58992b8d00',
    referrer: 'https://github.com/torvalds/linux'
  };
  const res4 = await checkHtmlSmuggling(allowlistedBlob);
  assert.strictEqual(res4.isSmuggling, false, 'blob: from verified allowlisted domain must NOT be flagged as smuggling');
});

test('HTML Smuggling (§3): adds +50 risk score (SIG_HTML_SMUGGLING_DOWNLOAD) and reaches BLOCK when paired with risky extension or archive', async () => {
  // Test paired with .zip
  const zipSmuggle = {
    downloadId: 401,
    filename: 'invoice.zip',
    url: 'blob:https://evildomain.org/uuid',
    referrer: 'https://evildomain.org/',
    htmlSmuggling: true
  };

  const { verdict: zipVerdict } = await analyzeDownload(zipSmuggle, [], calculateRisk, []);
  assert.strictEqual(zipVerdict.action, 'block', 'HTML smuggling paired with .zip must BLOCK');
  assert.strictEqual(zipVerdict.severity, 'danger');
  assert.ok(zipVerdict.score >= 75, `Score must be >= 75 (got ${zipVerdict.score})`);
  assert.ok(zipVerdict.signals.some(s => s.id === 'SIG_HTML_SMUGGLING_DOWNLOAD'));

  // Test paired with .rar
  const rarSmuggle = {
    downloadId: 402,
    filename: 'payload.rar',
    url: 'data:application/octet-stream;base64,AAA...',
    referrer: 'https://evildomain.org/',
    htmlSmuggling: true
  };
  const { verdict: rarVerdict } = await analyzeDownload(rarSmuggle, [], calculateRisk, []);
  assert.strictEqual(rarVerdict.action, 'block', 'HTML smuggling paired with .rar must BLOCK');

  // Test paired with .7z
  const sevenZipSmuggle = {
    downloadId: 403,
    filename: 'archive.7z',
    url: 'blob:https://evildomain.org/uuid',
    referrer: 'https://evildomain.org/',
    htmlSmuggling: true
  };
  const { verdict: sevenZipVerdict } = await analyzeDownload(sevenZipSmuggle, [], calculateRisk, []);
  assert.strictEqual(sevenZipVerdict.action, 'block', 'HTML smuggling paired with .7z must BLOCK');

  // Test paired with .iso
  const isoSmuggle = {
    downloadId: 404,
    filename: 'image.iso',
    url: 'blob:https://evildomain.org/uuid',
    referrer: 'https://evildomain.org/',
    htmlSmuggling: true
  };
  const { verdict: isoVerdict } = await analyzeDownload(isoSmuggle, [], calculateRisk, []);
  assert.strictEqual(isoVerdict.action, 'block', 'HTML smuggling paired with .iso must BLOCK');
});

test('HTML Smuggling (§3): handleDownloadCreated immediately pauses when paired with risky extension or archive', async () => {
  pausedDownloads.clear();
  initDownloadMonitor({
    brandsList: [],
    calculateRisk,
    buildRuleSignals: () => []
  });

  const smuggledItem = {
    id: 505,
    filename: 'receipt.zip',
    url: 'blob:https://attacker-stealer.xyz/fedcba',
    referrer: 'https://attacker-stealer.xyz/'
  };

  await handleDownloadCreated(smuggledItem);
  assert.strictEqual(
    pausedDownloads.has(505),
    true,
    'Download 505 must be paused immediately on creation due to HTML smuggling paired with archive'
  );
});

test('HTML Smuggling (§3): legitimate blob download on allowlist is not paused or blocked', async () => {
  pausedDownloads.clear();
  const allowlistedBlob = {
    id: 606,
    filename: 'repo-master.zip',
    url: 'blob:https://github.com/abc-123',
    referrer: 'https://github.com/user/repo'
  };

  await handleDownloadCreated(allowlistedBlob);
  assert.strictEqual(
    pausedDownloads.has(606),
    false,
    'Allowlisted blob download on github.com must not be paused as smuggling'
  );
});
