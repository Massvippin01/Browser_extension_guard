import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { getDomain } from '../shared/psl.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const testUrlsPath = path.resolve(__dirname, '../benchmark/test_urls.json');

const priorItems = JSON.parse(fs.readFileSync(testUrlsPath, 'utf8'));
const priorDomains = new Set(priorItems.map(i => i.registeredDomain));
const priorUrls = new Set(priorItems.map(i => i.url));

console.log(`[Fresh Test Builder] Prior dataset has ${priorItems.length} URLs across ${priorDomains.size} unique registered domains.`);

async function buildFreshTest() {
  // 1. Fresh Tranco Sample from ranks 5,001 to 60,000 (strictly excluding prior domains)
  console.log('[Fresh Test Builder] Fetching Tranco list V999N for fresh benign sample...');
  const trancoRes = await fetch('https://tranco-list.eu/download/V999N/1000000');
  if (!trancoRes.ok) throw new Error(`Tranco HTTP ${trancoRes.status}`);
  const trancoText = await trancoRes.text();
  const trancoLines = trancoText.split('\n');

  const candidateBenign = [];
  for (let i = 0; i < trancoLines.length; i++) {
    const line = trancoLines[i].trim();
    if (!line) continue;
    const comma = line.indexOf(',');
    if (comma === -1) continue;
    const rank = parseInt(line.substring(0, comma), 10);
    const domain = line.substring(comma + 1).trim().toLowerCase();
    if (rank > 5000 && rank <= 80000) {
      const regDom = getDomain(domain) || domain;
      if (!priorDomains.has(regDom)) {
        candidateBenign.push({ domain, rank, regDom });
      }
    }
  }

  // Shuffle candidateBenign with fixed seed 777
  let seed = 777;
  function rnd() {
    seed = (seed * 9301 + 49297) % 233280;
    return seed / 233280;
  }
  for (let i = candidateBenign.length - 1; i > 0; i--) {
    const j = Math.floor(rnd() * (i + 1));
    [candidateBenign[i], candidateBenign[j]] = [candidateBenign[j], candidateBenign[i]];
  }

  const freshBenignDomains = new Set();
  const freshBenignItems = [];
  for (const item of candidateBenign) {
    if (freshBenignItems.length >= 500) break;
    if (!freshBenignDomains.has(item.regDom)) {
      freshBenignDomains.add(item.regDom);
      freshBenignItems.push({
        url: `https://${item.domain}/`,
        label: 'safe',
        category: 'tranco_fresh',
        source: 'tranco-list.eu:ranks_5k_80k_dated_2026-10-12',
        date: '2026-10-12',
        registeredDomain: item.regDom
      });
    }
  }
  console.log(`[Fresh Test Builder] Selected ${freshBenignItems.length} fresh benign URLs (0 prior domain overlap).`);

  // 2. Fresh Phishing Feed: Fetch live from Phishing.Database and OpenPhish
  console.log('[Fresh Test Builder] Fetching fresh active phishing feeds...');
  const phishRes = await fetch('https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt');
  let phishLines = [];
  if (phishRes.ok) {
    const txt = await phishRes.text();
    phishLines = txt.split('\n').map(l => l.trim()).filter(l => l.startsWith('http'));
    console.log(`[Fresh Test Builder] Downloaded ${phishLines.length} links from Phishing.Database.`);
  }

  // Also fetch OpenPhish
  const openRes = await fetch('https://openphish.com/feed.txt');
  if (openRes.ok) {
    const txt = await openRes.text();
    const opLines = txt.split('\n').map(l => l.trim()).filter(l => l.startsWith('http'));
    phishLines = [...opLines, ...phishLines];
    console.log(`[Fresh Test Builder] Added OpenPhish links, total pool: ${phishLines.length}`);
  }

  const freshPhishItems = [];
  const freshPhishDomains = new Set();

  for (const u of phishLines) {
    if (freshPhishItems.length >= 350) break;
    if (priorUrls.has(u)) continue;
    try {
      const hostname = new URL(u).hostname.toLowerCase();
      const regDom = getDomain(hostname) || hostname;
      if (!priorDomains.has(regDom) && !freshBenignDomains.has(regDom) && !freshPhishDomains.has(regDom)) {
        freshPhishDomains.add(regDom);
        freshPhishItems.push({
          url: u,
          label: 'phishing',
          category: 'phishing_fresh',
          source: 'phishing.database:active_today_dated_2026-10-12',
          date: '2026-10-12',
          registeredDomain: regDom
        });
      }
    } catch {}
  }
  console.log(`[Fresh Test Builder] Selected ${freshPhishItems.length} fresh phishing URLs (0 prior domain overlap).`);

  // 3. Fresh Malware Feed from URLhaus
  console.log('[Fresh Test Builder] Fetching fresh malware feed from URLhaus...');
  const urlhausRes = await fetch('https://urlhaus.abuse.ch/downloads/csv_recent/');
  const freshMalwareItems = [];
  const freshMalwareDomains = new Set();

  if (urlhausRes.ok) {
    const txt = await urlhausRes.text();
    const lines = txt.split('\n');
    for (const l of lines) {
      if (freshMalwareItems.length >= 250) break;
      if (!l || l.startsWith('#')) continue;
      const m = l.match(/^"([^"]+)","([^"]+)","([^"]+)"/);
      if (m && m[3] && m[3].startsWith('http')) {
        const u = m[3].trim();
        if (priorUrls.has(u)) continue;
        try {
          const hostname = new URL(u).hostname.toLowerCase();
          const regDom = getDomain(hostname) || hostname;
          if (!priorDomains.has(regDom) && !freshBenignDomains.has(regDom) && !freshPhishDomains.has(regDom) && !freshMalwareDomains.has(regDom)) {
            freshMalwareDomains.add(regDom);
            freshMalwareItems.push({
              url: u,
              label: 'malware',
              category: 'malware_fresh',
              source: 'urlhaus.abuse.ch:recent_dated_2026-10-12',
              date: '2026-10-12',
              registeredDomain: regDom
            });
          }
        } catch {}
      }
    }
  }
  console.log(`[Fresh Test Builder] Selected ${freshMalwareItems.length} fresh malware URLs (0 prior domain overlap).`);

  const allFresh = [...freshBenignItems, ...freshPhishItems, ...freshMalwareItems].map((item, idx) => ({
    id: `fresh_${idx + 1}`,
    ...item
  }));

  // Strict Disjointness Verification against all prior domains
  const freshDomains = new Set(allFresh.map(i => i.registeredDomain));
  const domainOverlap = [...freshDomains].filter(d => priorDomains.has(d));
  if (domainOverlap.length > 0) {
    throw new Error(`CRITICAL: Leakage detected in fresh test! ${domainOverlap.length} domains overlap with prior data: ${domainOverlap.slice(0, 5)}`);
  }
  console.log(`[Verification Passed] ZERO domain overlap between Fresh Test (${freshDomains.size} domains) and Prior Data (${priorDomains.size} domains)!`);

  const outPath = path.resolve(__dirname, '../benchmark/fresh_test_urls.json');
  fs.writeFileSync(outPath, JSON.stringify(allFresh, null, 2), 'utf8');
  console.log(`\nSuccessfully wrote ${allFresh.length} fresh URLs to ${outPath}`);
  console.log(`Counts: Safe=${freshBenignItems.length}, Phishing=${freshPhishItems.length}, Malware=${freshMalwareItems.length}`);
}

buildFreshTest().catch(console.error);
