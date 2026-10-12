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
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
].filter(p => fs.existsSync(p));

const DEMOS = [
  { id: 'A', name: 'Demo A: Fake Bank Login (HDFC NetBanking)', url: 'http://fake-hdfc-netbanking.test:8080/demo/bank' },
  { id: 'B', name: 'Demo B: Fake Payment Gateway (PayPal)', url: 'http://fake-paypal-checkout.test:8080/demo/payment' },
  { id: 'C', name: 'Demo C: UPI Cashback Scam (Paytm)', url: 'http://paytm-cashback-rewards.test:8080/demo/upi' },
  { id: 'D', name: 'Demo D: Digital Arrest / Utility Notice', url: 'http://electricity-disconnection-notice.test:8080/demo/utility' },
  { id: 'E', name: 'Demo E: Malicious APK Download (SBI YONO)', url: 'http://rewards-download.test:8080/demo/download' }
];

async function run() {
  console.log('=== REAL-BROWSER SIGNAL DUMP FOR DEMO A-E ===\n');

  // Stage clean extension
  const tempExtDir = path.join(os.tmpdir(), 'verity_ext_dump_clean');
  if (fs.existsSync(tempExtDir)) fs.rmSync(tempExtDir, { recursive: true, force: true });
  fs.cpSync(extPath, tempExtDir, {
    recursive: true,
    filter: (src) => !src.includes('node_modules') && !src.includes('.git')
  });

  // Start demo server
  const server = fork(demoServerPath, [], { stdio: 'pipe' });
  await new Promise(r => setTimeout(r, 1200));

  const browser = await puppeteer.launch({
    executablePath: candidateBrowsers[0],
    headless: 'new',
    args: [
      `--disable-extensions-except=${tempExtDir}`,
      `--load-extension=${tempExtDir}`,
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--host-resolver-rules=MAP *.test 127.0.0.1'
    ]
  });

  await new Promise(r => setTimeout(r, 2000));
  const swTarget = await browser.waitForTarget(t => t.type() === 'service_worker', { timeout: 10000 });
  const sw = await swTarget.worker();

  const dump = [];

  for (const d of DEMOS) {
    const page = await browser.newPage();
    try {
      await page.goto(d.url, { waitUntil: 'domcontentloaded', timeout: 10000 });
      await new Promise(r => setTimeout(r, 2000));

      // Extract verdict from service worker state or content host
      const hostData = await page.evaluate(() => {
        const host = document.getElementById('verity-security-host');
        if (!host) return null;
        return {
          detected: true,
          action: host.getAttribute('data-action') || 'unknown',
          score: parseInt(host.getAttribute('data-score') || '0', 10),
          title: host.getAttribute('data-state-title') || ''
        };
      });

      // Get real verdict calculated by service worker
      const swVerdict = await sw.evaluate(async (targetUrl) => {
        // Query SW internal tabs/verdicts or re-run SW analyzePage
        if (typeof globalThis.verityAnalyzePageForTest === 'function') {
          return await globalThis.verityAnalyzePageForTest(targetUrl);
        }
        return null;
      }, d.url);

      const score = hostData ? hostData.score : (d.id === 'E' ? 0 : 0);
      const action = hostData ? hostData.action : (d.id === 'E' ? 'none' : 'unknown');
      const margin = score - 70;

      console.log(`Demo ${d.id}: ${d.name}`);
      console.log(`  URL:    ${d.url}`);
      console.log(`  Action: ${action}`);
      console.log(`  Score:  ${score}/100 (Threshold: 70, Margin: ${margin >= 0 ? '+' + margin : margin} pts)`);
      if (hostData) console.log(`  State:  ${hostData.title}`);

      dump.push({
        demo: d.id,
        name: d.name,
        url: d.url,
        action,
        score,
        threshold: 70,
        margin,
        hostData
      });
    } catch (err) {
      console.error(`Error on Demo ${d.id}:`, err.message);
    } finally {
      await page.close();
    }
  }

  // Also test Demo E download interceptor
  console.log('\nTesting Demo E Download Interceptor...');
  const dlPage = await browser.newPage();
  await dlPage.goto('http://rewards-download.test:8080/demo/download', { waitUntil: 'domcontentloaded' });
  await sw.evaluate(async () => {
    if (chrome.downloads && chrome.downloads.download) {
      await chrome.downloads.download({
        url: 'http://rewards-download.test:8080/downloads/sbi_yono_rewards.apk',
        filename: 'sbi_yono_rewards.apk'
      });
    }
  });
  await new Promise(r => setTimeout(r, 2000));
  const dlWarning = await dlPage.evaluate(() => {
    const host = document.getElementById('verity-download-warning-host');
    return !!host;
  });
  console.log(`  Download Warning Modal Injected: ${dlWarning}`);
  await dlPage.close();

  await browser.close();
  server.kill();

  fs.writeFileSync(
    path.resolve(__dirname, '../benchmark/demo_signal_dump.json'),
    JSON.stringify({ timestamp: new Date().toISOString(), dump, dlWarning }, null, 2),
    'utf8'
  );
  console.log('\nWrote benchmark/demo_signal_dump.json');
}

run().catch(console.error);
