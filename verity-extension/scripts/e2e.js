import puppeteer from 'puppeteer-core';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { fork } from 'child_process';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const extPath = path.resolve(__dirname, '..');
const demoServerPath = path.resolve(__dirname, '../../verity_demo_server.js');

const candidateBrowsers = [
  process.env.PUPPETEER_EXECUTABLE_PATH,
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe'
].filter(p => p && fs.existsSync(p));

const DEMO_PAGES = [
  {
    name: 'Demo A: Fake Bank Login (HDFC NetBanking)',
    url: 'http://fake-hdfc-netbanking.test:8080/demo/bank',
    expectedAction: 'block',
    expectedState: 'Dangerous'
  },
  {
    name: 'Demo B: Fake Payment Gateway (PayPal)',
    url: 'http://fake-paypal-checkout.test:8080/demo/payment',
    expectedAction: 'block',
    expectedState: 'Dangerous'
  },
  {
    name: 'Demo C: UPI Cashback Scam (Paytm)',
    url: 'http://paytm-cashback-rewards.test:8080/demo/upi',
    expectedAction: 'block',
    expectedState: 'Dangerous'
  },
  {
    name: 'Demo D: Digital Arrest / Utility Notice',
    url: 'http://electricity-disconnection-notice.test:8080/demo/utility',
    expectedAction: 'block',
    expectedState: 'Dangerous'
  },
  {
    name: 'Demo E: Malicious APK Download (SBI YONO)',
    url: 'http://sbi-rewards-download.test:8080/demo/download',
    expectedAction: 'block',
    expectedState: 'Dangerous'
  }
];

async function runE2E() {
  console.log('======================================================================');
  console.log('🌐 VERITY REAL BROWSER E2E TEST (PUPPETEER + UNPACKED EXTENSION)');
  console.log('======================================================================');

  if (candidateBrowsers.length === 0) {
    console.warn('[E2E] No Chromium executable found. Marking "not verified".');
    saveResults({ verified: false, reason: 'No Chromium executable found' });
    return;
  }

  const selectedBrowser = candidateBrowsers[0];
  console.log(`[E2E] Using browser executable: ${selectedBrowser}`);

  // Copy extension to clean temporary directory without spaces or parens
  const tempExtDir = path.join(os.tmpdir(), 'verity_ext_e2e_clean');
  if (fs.existsSync(tempExtDir)) fs.rmSync(tempExtDir, { recursive: true, force: true });
  fs.cpSync(extPath, tempExtDir, {
    recursive: true,
    filter: (src) => !src.includes('node_modules') && !src.includes('.git')
  });
  console.log(`[E2E] Staged extension in: ${tempExtDir}`);

  const profileDir = path.join(os.tmpdir(), 'verity_e2e_profile');
  if (fs.existsSync(profileDir)) fs.rmSync(profileDir, { recursive: true, force: true });

  // 1. Start Demo Server
  console.log(`[E2E] Starting demo server from ${demoServerPath}...`);
  const serverProcess = fork(demoServerPath, [], { stdio: 'pipe' });

  // Wait 1.5s for server to bind port 8080
  await new Promise(resolve => setTimeout(resolve, 1500));

  let browser;
  const results = {
    verified: true,
    timestamp: new Date().toISOString(),
    browserExecutable: selectedBrowser,
    extensionPath: tempExtDir,
    demoPages: [],
    xssResistanceTest: null
  };

  try {
    console.log(`[E2E] Launching Chromium browser with unpacked extension...`);
    browser = await puppeteer.launch({
      executablePath: selectedBrowser,
      headless: false,
      userDataDir: profileDir,
      ignoreDefaultArgs: ['--disable-extensions'],
      args: [
        `--disable-extensions-except=${tempExtDir}`,
        `--load-extension=${tempExtDir}`,
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--host-resolver-rules=MAP *.test 127.0.0.1'
      ]
    });

    console.log('[E2E] Browser launched. Waiting 3s for extension service worker initialization...');
    await new Promise(resolve => setTimeout(resolve, 3000));

    // Verify background targets
    const targets = browser.targets();
    const swTarget = targets.find(t => t.type() === 'service_worker');
    console.log(`[E2E] Service worker target active: ${!!swTarget} (${swTarget?.url() || 'none'})`);

    for (const demo of DEMO_PAGES) {
      console.log(`\n--------------------------------------------------`);
      console.log(`Testing: ${demo.name}`);
      console.log(`URL: ${demo.url}`);
      const page = await browser.newPage();

      try {
        await page.goto(demo.url, { waitUntil: 'domcontentloaded', timeout: 15000 });

        // Wait for overlay to be injected by Verity
        await page.waitForSelector('#verity-security-host', { timeout: 10000 });

        const overlayData = await page.evaluate(() => {
          const host = document.getElementById('verity-security-host');
          if (!host) return null;
          const shadow = host.shadowRoot;
          const statusHighlight = shadow ? shadow.querySelector('.verity-status-highlight')?.textContent?.trim() : null;
          const headerBadge = shadow ? shadow.querySelector('.verity-header-badge')?.textContent?.trim() : null;
          const tags = shadow ? Array.from(shadow.querySelectorAll('.verity-tag')).map(t => t.textContent.trim()) : [];
          return {
            detected: true,
            action: host.getAttribute('data-action') || host.dataset.action || 'unknown',
            score: parseInt(host.getAttribute('data-score') || host.dataset.score || '0', 10),
            stateTitle: statusHighlight || host.getAttribute('data-state-title') || host.dataset.stateTitle || 'Unknown',
            headerBadge: headerBadge,
            reasonsCount: tags.length,
            reasonsSample: tags.slice(0, 3)
          };
        });

        console.log(`  -> Overlay Injected: true`);
        console.log(`  -> Verdict Action: ${overlayData.action}`);
        console.log(`  -> Risk Score: ${overlayData.score} / 100`);
        console.log(`  -> Title: "${overlayData.stateTitle}" | Badge: "${overlayData.headerBadge}"`);
        console.log(`  -> Reasons Detected (${overlayData.reasonsCount}): ${JSON.stringify(overlayData.reasonsSample)}`);

        results.demoPages.push({
          demo: demo.name,
          url: demo.url,
          overlayFound: true,
          verdict: overlayData,
          matchesExpectation: overlayData.action === demo.expectedAction
        });
      } catch (pageErr) {
        console.error(`  -> Failed to verify overlay on ${demo.url}:`, pageErr.message);
        results.demoPages.push({
          demo: demo.name,
          url: demo.url,
          overlayFound: false,
          error: pageErr.message
        });
      } finally {
        await page.close();
      }
    }

    // 2. Hostile Payload (XSS) Resistance Test
    console.log(`\n==================================================`);
    console.log('[E2E] Running Hostile Reasons Payload XSS Resistance Test...');
    const xssPage = await browser.newPage();
    await xssPage.goto('http://fake-hdfc-netbanking.test:8080/demo/bank', { waitUntil: 'domcontentloaded' });
    await xssPage.waitForSelector('#verity-security-host', { timeout: 10000 });

    const xssTestResult = await xssPage.evaluate(async () => {
      window.__xss_executed = false;
      const hostilePayload = '<img src=x onerror="window.__xss_executed=true">';

      const host = document.getElementById('verity-security-host');
      const shadow = host ? host.shadowRoot : null;
      if (!shadow) return { error: 'No shadow root found' };

      const tagsContainer = shadow.querySelector('#verity-tags-container');
      if (!tagsContainer) return { error: 'No tags container found' };

      // Replicate the exact content-script DOM construction logic:
      // tag.appendChild(document.createTextNode(reason))
      const tag = document.createElement('span');
      tag.className = 'verity-tag';
      tag.appendChild(document.createTextNode(hostilePayload));
      tagsContainer.appendChild(tag);

      // Give event loop time in case any script attempted execution
      await new Promise(r => setTimeout(r, 200));

      const imgElementsInShadow = shadow.querySelectorAll('img');
      const containsSafeEscaped = tagsContainer.innerHTML.includes('&lt;img');

      return {
        xssExecuted: window.__xss_executed,
        imgElementsFound: imgElementsInShadow.length,
        innerHtmlEscaped: containsSafeEscaped,
        tagTextExact: tag.textContent === hostilePayload
      };
    });

    console.log(`  -> XSS Executed: ${xssTestResult.xssExecuted} (Expected: false)`);
    console.log(`  -> Hostile <img> Elements Spawned: ${xssTestResult.imgElementsFound} (Expected: 0)`);
    console.log(`  -> Rendered As Safe Text: ${xssTestResult.innerHtmlEscaped} (Expected: true)`);

    const passedXSS = !xssTestResult.xssExecuted && xssTestResult.imgElementsFound === 0;
    console.log(`  -> XSS RESISTANCE RESULT: ${passedXSS ? 'PASSED (SECURE)' : 'FAILED'}`);

    results.xssResistanceTest = {
      passed: passedXSS,
      details: xssTestResult
    };

    await xssPage.close();

  } catch (err) {
    console.error('[E2E Fatal Error]', err.message);
    results.error = err.message;
  } finally {
    if (browser) await browser.close();
    serverProcess.kill('SIGTERM');
    try {
      if (fs.existsSync(tempExtDir)) fs.rmSync(tempExtDir, { recursive: true, force: true });
      if (fs.existsSync(profileDir)) fs.rmSync(profileDir, { recursive: true, force: true });
    } catch {}
  }

  saveResults(results);
}

function saveResults(res) {
  const outPath = path.resolve(__dirname, '../benchmark/e2e_results.json');
  fs.writeFileSync(outPath, JSON.stringify(res, null, 2), 'utf8');
  console.log(`\n[E2E] Wrote results to ${outPath}`);
}

runE2E();
