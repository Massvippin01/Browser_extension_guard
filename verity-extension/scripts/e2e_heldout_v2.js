import puppeteer from 'puppeteer-core';
import path from 'path';
import fs from 'fs';
import os from 'os';
import dns from 'dns/promises';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const extPath = path.resolve(__dirname, '..');
const urlsPath = path.resolve(__dirname, '../benchmark/heldout_v2_urls.json');
const pages = JSON.parse(fs.readFileSync(urlsPath, 'utf8'));

const candidateBrowsers = [
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
].filter(p => fs.existsSync(p));

const browserExecutable = candidateBrowsers[0];

// Wilson Score Interval (95% CI)
export function wilsonScoreInterval(count, total, z = 1.95996) {
  if (total === 0) return { point: 0, lower: 0, upper: 0 };
  const p = count / total;
  const denominator = 1 + (z * z) / total;
  const centreAdjustedProbability = p + (z * z) / (2 * total);
  const adjustedStandardDeviation = Math.sqrt((p * (1 - p) + (z * z) / (4 * total)) / total);
  
  const lower = Math.max(0, (centreAdjustedProbability - z * adjustedStandardDeviation) / denominator);
  const upper = Math.min(1, (centreAdjustedProbability + z * adjustedStandardDeviation) / denominator);
  
  return {
    point: p * 100,
    lower: lower * 100,
    upper: upper * 100
  };
}

async function resolveDns(hostname) {
  try {
    const res = await dns.lookup(hostname);
    return { ok: true, ip: res.address };
  } catch (err) {
    return { ok: false, error: err.code || err.message };
  }
}

async function testPage(browser, pageEntry, timeoutMs = 25000) {
  const page = await browser.newPage();
  let requestedUrl = pageEntry.url;
  let finalUrl = requestedUrl;
  let status = 'pending';
  let errCode = null;

  try {
    // Set realistic viewport & user agent
    await page.setViewport({ width: 1280, height: 800 });
    const response = await page.goto(requestedUrl, {
      waitUntil: 'domcontentloaded',
      timeout: timeoutMs
    });

    finalUrl = page.url();
    // Allow content script / async analysis to settle
    await new Promise(r => setTimeout(r, 2500));

    // Extract live DOM state
    const domData = await page.evaluate(() => {
      const badgeHost = document.getElementById('verity-status-badge-host');
      const secHost = document.getElementById('verity-security-host');
      const contentScriptRan = !!badgeHost || !!secHost;

      // Check gating inputs
      const hasPassword = !!document.querySelector('input[type="password"]');
      const hasPayment = !!document.querySelector('input[name*="card" i], input[name*="cvv" i], input[name*="otp" i]');
      const allLinks = Array.from(document.querySelectorAll('a[href]'));
      const hasUpi = allLinks.some(a => (a.href || '').toLowerCase().startsWith('upi://'));
      const gateOn = hasPassword || hasPayment || hasUpi;

      let overlayFound = false;
      let action = 'allow';
      let score = 0;
      let stateTitle = 'Clean';
      let tags = [];

      if (secHost) {
        overlayFound = true;
        action = secHost.getAttribute('data-action') || 'unknown';
        score = parseInt(secHost.getAttribute('data-score') || '0', 10);
        stateTitle = secHost.getAttribute('data-state-title') || 'Warning';
        const shadow = secHost.shadowRoot;
        if (shadow) {
          tags = Array.from(shadow.querySelectorAll('.verity-tag')).map(t => t.textContent.trim());
        }
      }

      return {
        contentScriptRan,
        gateOn,
        overlayFound,
        action,
        score,
        stateTitle,
        tags
      };
    });

    status = 'reachable';
    return {
      success: true,
      data: {
        id: pageEntry.id,
        name: pageEntry.name,
        requestedUrl,
        finalUrl,
        category: pageEntry.category,
        source: pageEntry.source,
        allowlisted: pageEntry.allowlisted,
        contentScriptRan: domData.contentScriptRan,
        domScanGated: domData.gateOn,
        verdict: domData.action,
        score: domData.score,
        overlayShown: domData.overlayFound,
        stateTitle: domData.stateTitle,
        signals: domData.tags,
        status
      }
    };
  } catch (err) {
    errCode = err.message;
    return {
      success: false,
      requestedUrl,
      finalUrl,
      error: errCode
    };
  } finally {
    try { await page.close(); } catch (e) {}
  }
}

async function run() {
  console.log('======================================================================');
  console.log('🌟 VERITY HELD-OUT BENIGN E2E v2 EVALUATION');
  console.log(`Total Pages: ${pages.length} un-tuned live URLs`);
  console.log('======================================================================\n');

  // Stage clean extension
  const tempExtDir = path.join(os.tmpdir(), 'verity_ext_heldout_v2');
  if (fs.existsSync(tempExtDir)) fs.rmSync(tempExtDir, { recursive: true, force: true });
  fs.cpSync(extPath, tempExtDir, {
    recursive: true,
    filter: (src) => !src.includes('node_modules') && !src.includes('.git')
  });

  console.log(`[E2E v2] Launching headless Edge with staged extension...`);
  const browser = await puppeteer.launch({
    executablePath: browserExecutable,
    headless: 'new',
    args: [
      `--disable-extensions-except=${tempExtDir}`,
      `--load-extension=${tempExtDir}`,
      '--no-sandbox',
      '--disable-setuid-sandbox'
    ]
  });

  await new Promise(r => setTimeout(r, 2500));
  console.log('[E2E v2] Extension loaded. Commencing single-pass evaluation...\n');

  const reachablePages = [];
  const unreachablePages = [];

  for (let i = 0; i < pages.length; i++) {
    const entry = pages[i];
    process.stdout.write(`[${i + 1}/${pages.length}] Testing: ${entry.name} (${entry.url})... `);

    const res = await testPage(browser, entry, 25000);

    if (res.success) {
      const d = res.data;
      reachablePages.push(d);
      if (d.overlayShown) {
        console.log(`⚠️ OVERLAY: ${d.verdict.toUpperCase()} (Score: ${d.score})`);
      } else {
        console.log(`✅ CLEAN (Gate: ${d.domScanGated ? 'ON' : 'OFF'})`);
      }
    } else {
      console.log(`❌ FAILED (Attempt 1: ${res.error.split('\n')[0].slice(0, 50)})`);
      unreachablePages.push({
        entry,
        attempt1Error: res.error
      });
    }
  }

  await browser.close();

  // Retry unreachable pages once in headed Edge with 60 s timeout
  if (unreachablePages.length > 0) {
    console.log(`\n======================================================================`);
    console.log(`RETRYING ${unreachablePages.length} UNREACHABLE PAGES IN HEADED EDGE (60s TIMEOUT)...`);
    console.log(`======================================================================\n`);

    const headedBrowser = await puppeteer.launch({
      executablePath: browserExecutable,
      headless: false,
      args: [
        `--disable-extensions-except=${tempExtDir}`,
        `--load-extension=${tempExtDir}`,
        '--no-sandbox',
        '--disable-setuid-sandbox'
      ]
    });

    const finalUnreachable = [];

    for (let i = 0; i < unreachablePages.length; i++) {
      const item = unreachablePages[i];
      const entry = item.entry;
      process.stdout.write(`[Retry ${i + 1}/${unreachablePages.length}] ${entry.name}... `);

      const retryRes = await testPage(headedBrowser, entry, 60000);

      if (retryRes.success) {
        const d = retryRes.data;
        reachablePages.push(d);
        console.log(`✅ REACHABLE ON RETRY! (Gate: ${d.domScanGated ? 'ON' : 'OFF'})`);
      } else {
        let hostname = '';
        try { hostname = new URL(entry.url).hostname; } catch (e) {}
        const dnsRes = await resolveDns(hostname);
        console.log(`❌ STILL UNREACHABLE (${retryRes.error.split('\n')[0].slice(0, 45)}) | DNS: ${dnsRes.ok ? dnsRes.ip : dnsRes.error}`);
        finalUnreachable.push({
          id: entry.id,
          name: entry.name,
          requestedUrl: entry.url,
          category: entry.category,
          source: entry.source,
          allowlisted: entry.allowlisted,
          attempt1Error: item.attempt1Error,
          retryError: retryRes.error,
          dnsResult: dnsRes
        });
      }
    }

    await headedBrowser.close();
    unreachablePages.length = 0;
    unreachablePages.push(...finalUnreachable);
  }

  // Compute metrics with 95% Wilson intervals
  const totalReachable = reachablePages.length;
  const nonAllowlisted = reachablePages.filter(p => p.allowlisted === 'no');
  const gateOn = reachablePages.filter(p => p.domScanGated === true);

  // Overlays: Block (verdict === 'block') and Caution (verdict === 'warn')
  const allBlockCount = reachablePages.filter(p => p.overlayShown && p.verdict === 'block').length;
  const allCautionCount = reachablePages.filter(p => p.overlayShown && p.verdict === 'warn').length;

  const nonAllowBlockCount = nonAllowlisted.filter(p => p.overlayShown && p.verdict === 'block').length;
  const nonAllowCautionCount = nonAllowlisted.filter(p => p.overlayShown && p.verdict === 'warn').length;

  const gateOnBlockCount = gateOn.filter(p => p.overlayShown && p.verdict === 'block').length;
  const gateOnCautionCount = gateOn.filter(p => p.overlayShown && p.verdict === 'warn').length;

  const stats = {
    allReachable: {
      total: totalReachable,
      blockCount: allBlockCount,
      blockRate: wilsonScoreInterval(allBlockCount, totalReachable),
      cautionCount: allCautionCount,
      cautionRate: wilsonScoreInterval(allCautionCount, totalReachable)
    },
    nonAllowlistedOnly: {
      total: nonAllowlisted.length,
      blockCount: nonAllowBlockCount,
      blockRate: wilsonScoreInterval(nonAllowBlockCount, nonAllowlisted.length),
      cautionCount: nonAllowCautionCount,
      cautionRate: wilsonScoreInterval(nonAllowCautionCount, nonAllowlisted.length)
    },
    gateOnOnly: {
      total: gateOn.length,
      blockCount: gateOnBlockCount,
      blockRate: wilsonScoreInterval(gateOnBlockCount, gateOn.length),
      cautionCount: gateOnCautionCount,
      cautionRate: wilsonScoreInterval(gateOnCautionCount, gateOn.length)
    }
  };

  console.log('\n======================================================================');
  console.log('📊 EMPIRICAL HELD-OUT BENIGN E2E v2 RESULTS (95% WILSON INTERVALS)');
  console.log('======================================================================');
  console.log(`Reachable Pages:   ${totalReachable}/${pages.length}`);
  console.log(`Unreachable Pages: ${unreachablePages.length}/${pages.length} (listed separately, NOT treated as passes)`);

  function printRateBlock(title, group) {
    console.log(`\n--- ${title} (N=${group.total}) ---`);
    console.log(`  Block Overlay Rate:   ${group.blockRate.point.toFixed(2)}% (${group.blockCount}/${group.total}) [95% Wilson: ${group.blockRate.lower.toFixed(2)}% - ${group.blockRate.upper.toFixed(2)}%]`);
    console.log(`  Caution Overlay Rate: ${group.cautionRate.point.toFixed(2)}% (${group.cautionCount}/${group.total}) [95% Wilson: ${group.cautionRate.lower.toFixed(2)}% - ${group.cautionRate.upper.toFixed(2)}%]`);
  }

  printRateBlock('1. All Reachable Benign Pages', stats.allReachable);
  printRateBlock('2. Non-Allowlisted Pages Only', stats.nonAllowlistedOnly);
  printRateBlock('3. Gate-ON (Password/OTP Inputs) Only', stats.gateOnOnly);

  // List all failures (false positives)
  const falseBlocks = reachablePages.filter(p => p.overlayShown && p.verdict === 'block');
  const falseCautions = reachablePages.filter(p => p.overlayShown && p.verdict === 'warn');

  console.log('\n----------------------------------------------------------------------');
  console.log(`DETAILED AUDIT OF FALSE BLOCKS (N=${falseBlocks.length}):`);
  console.log('----------------------------------------------------------------------');
  if (falseBlocks.length === 0) {
    console.log('  None! Zero false blocks recorded.');
  } else {
    falseBlocks.forEach(fb => {
      console.log(`  • ${fb.name} (${fb.finalUrl})`);
      console.log(`    Score: ${fb.score} | Allowlisted: ${fb.allowlisted} | Gate-ON: ${fb.domScanGated}`);
      console.log(`    Signals: ${fb.signals.join('; ')}`);
    });
  }

  console.log('\n----------------------------------------------------------------------');
  console.log(`DETAILED AUDIT OF UNREACHABLE PAGES (N=${unreachablePages.length}):`);
  console.log('----------------------------------------------------------------------');
  if (unreachablePages.length === 0) {
    console.log('  None! All pages resolved and reached.');
  } else {
    unreachablePages.forEach(u => {
      console.log(`  • ${u.name} (${u.requestedUrl})`);
      console.log(`    DNS: ${u.dnsResult.ok ? u.dnsResult.ip : 'DNS FAILURE: ' + u.dnsResult.error}`);
      console.log(`    Error: ${u.retryError.split('\n')[0]}`);
    });
  }

  const finalOutput = {
    timestamp: new Date().toISOString(),
    datasetSummary: {
      totalProvided: pages.length,
      reachable: totalReachable,
      unreachable: unreachablePages.length
    },
    metrics: stats,
    failures: {
      falseBlocks,
      falseCautions
    },
    unreachablePages,
    reachablePages
  };

  const outPath = path.resolve(__dirname, '../benchmark/heldout_e2e_v2_results.json');
  fs.writeFileSync(outPath, JSON.stringify(finalOutput, null, 2), 'utf8');
  console.log(`\nWrote full results to ${outPath}`);
}

run().catch(console.error);
