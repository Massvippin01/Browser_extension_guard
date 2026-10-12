import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { extractRichFeatures } from '../background/rich-feature-extractor.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const testUrlsPath = path.resolve(__dirname, '../benchmark/test_urls.json');
const mlScoresPath = path.resolve(__dirname, '../benchmark/ml_scores.json');

const items = JSON.parse(fs.readFileSync(testUrlsPath, 'utf8'));
const testItems = items.filter(i => i.split === 'test');

// Seeded PRNG for reproducible 10 random rows per class
let seed = 12345;
function rnd() {
  seed = (seed * 9301 + 49297) % 233280;
  return seed / 233280;
}

function sampleN(arr, n) {
  const copy = [...arr];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(rnd() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy.slice(0, n);
}

// 1. Audit URL format statistics per class
console.log('======================================================================');
console.log('📊 FORMAT-CONFOUND AUDIT: TEST SET STRUCTURAL DISTRIBUTION');
console.log('======================================================================');

const classes = ['safe', 'phishing', 'malware'];
const stats = {};

for (const cls of classes) {
  const subset = testItems.filter(i => i.label === cls);
  let nonEmptyPathCount = 0;
  let hasQueryCount = 0;
  let totalUrlLen = 0;
  let totalPathLen = 0;

  for (const item of subset) {
    try {
      const u = new URL(item.url);
      const hasNonEmptyPath = u.pathname.length > 1; // more than just "/"
      const hasQuery = u.search.length > 0;
      if (hasNonEmptyPath) nonEmptyPathCount++;
      if (hasQuery) hasQueryCount++;
      totalUrlLen += item.url.length;
      totalPathLen += u.pathname.length;
    } catch {
      totalUrlLen += item.url.length;
    }
  }

  const n = subset.length;
  stats[cls] = {
    total: n,
    pctNonEmptyPath: ((nonEmptyPathCount / n) * 100).toFixed(2) + '%',
    pctWithQuery: ((hasQueryCount / n) * 100).toFixed(2) + '%',
    meanUrlLength: (totalUrlLen / n).toFixed(2),
    meanPathLength: (totalPathLen / n).toFixed(2)
  };
}

console.table(stats);

// Print 10 random rows per class
console.log('\n--- 10 Random Samples Per Class ---');
for (const cls of classes) {
  const subset = testItems.filter(i => i.label === cls);
  const sampled = sampleN(subset, 10);
  console.log(`\n[Class: ${cls.toUpperCase()}]`);
  sampled.forEach((item, idx) => {
    console.log(`  ${idx + 1}. [${item.source}] ${item.url}`);
  });
}

// Save audit summary
const auditSummary = {
  distribution: stats,
  timestamp: new Date().toISOString()
};
fs.writeFileSync(path.resolve(__dirname, '../benchmark/format_confound_audit.json'), JSON.stringify(auditSummary, null, 2), 'utf8');
console.log('\n[Audit] Saved format distribution to benchmark/format_confound_audit.json');
