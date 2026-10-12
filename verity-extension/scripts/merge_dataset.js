import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { getDomain } from '../shared/psl.js';
import { isAllowlistedDomain } from '../shared/legit-domains.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const testUrlsPath = path.resolve(__dirname, '../benchmark/test_urls.json');
const deepPath = path.resolve(__dirname, '../benchmark/benign_deep.json');

const baseItems = JSON.parse(fs.readFileSync(testUrlsPath, 'utf8'));
const deepItems = JSON.parse(fs.readFileSync(deepPath, 'utf8'));

// Tag base safe items as benign_bare
const updatedBase = baseItems.map(item => {
  if (item.label === 'safe') {
    return {
      ...item,
      benignType: 'benign_bare',
      isAllowlisted: isAllowlistedDomain(new URL(item.url).hostname)
    };
  }
  return {
    ...item,
    isAllowlisted: false
  };
});

// Domain assignments for deep items:
// If a domain is already in updatedBase, align with its existing split to prevent leakage
const existingDomainSplits = new Map();
for (const item of updatedBase) {
  existingDomainSplits.set(item.registeredDomain, item.split);
}

// Calculate dev/test counts to balance new domains
let devCount = updatedBase.filter(i => i.split === 'dev').length;
let testCount = updatedBase.filter(i => i.split === 'test').length;

const updatedDeep = [];
const deepDomainCounts = new Map();
for (const item of deepItems) {
  deepDomainCounts.set(item.registeredDomain, (deepDomainCounts.get(item.registeredDomain) || 0) + 1);
}

const assignedDeepSplits = new Map();
for (const [dom, count] of deepDomainCounts.entries()) {
  if (existingDomainSplits.has(dom)) {
    assignedDeepSplits.set(dom, existingDomainSplits.get(dom));
  } else {
    const split = devCount <= testCount ? 'dev' : 'test';
    assignedDeepSplits.set(dom, split);
    if (split === 'dev') devCount += count;
    else testCount += count;
  }
}

for (const item of deepItems) {
  const split = assignedDeepSplits.get(item.registeredDomain);
  updatedDeep.push({
    id: `deep_${item.id}`,
    url: item.url,
    label: 'safe',
    category: 'benign_deep',
    benignType: 'benign_deep',
    source: item.source,
    split: split,
    registeredDomain: item.registeredDomain,
    isAllowlisted: isAllowlistedDomain(new URL(item.url).hostname)
  });
}

const allItems = [...updatedBase, ...updatedDeep];

// Verify strict domain disjointness
const devDomains = new Set(allItems.filter(i => i.split === 'dev').map(i => i.registeredDomain));
const testDomains = new Set(allItems.filter(i => i.split === 'test').map(i => i.registeredDomain));
const overlap = [...devDomains].filter(d => testDomains.has(d));

if (overlap.length > 0) {
  throw new Error(`Domain leakage detected: ${overlap.length} domains overlap! Examples: ${overlap.slice(0, 5)}`);
}

console.log(`[Merge Verification] Zero domain overlap verified! Dev domains: ${devDomains.size}, Test domains: ${testDomains.size}`);
console.log(`Total URLs: ${allItems.length}`);

// Summary stats
const stats = {};
for (const item of allItems) {
  const key = `${item.label} [${item.split}]`;
  stats[key] = (stats[key] || 0) + 1;
}
console.table(stats);

const benignStats = {};
for (const item of allItems.filter(i => i.label === 'safe')) {
  const key = `${item.benignType} [${item.split}] (Allowlisted: ${item.isAllowlisted})`;
  benignStats[key] = (benignStats[key] || 0) + 1;
}
console.table(benignStats);

fs.writeFileSync(testUrlsPath, JSON.stringify(allItems, null, 2), 'utf8');
console.log(`Wrote unified dataset to ${testUrlsPath}`);
