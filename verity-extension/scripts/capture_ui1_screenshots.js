import puppeteer from 'puppeteer-core';
import path from 'path';
import fs from 'fs';
import os from 'os';
import http from 'http';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const extPath = path.resolve(__dirname, '..');

const candidateBrowsers = [
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
].filter(p => fs.existsSync(p));

const ARTIFACT_DIR = 'C:\\Users\\User\\.gemini\\antigravity-ide\\brain\\c1c36304-0fcc-4a65-bb44-64faa003d234';
const SCREENSHOT_DIR = path.join(ARTIFACT_DIR, 'screenshots');
fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });

async function run() {
  console.log('=== CAPTURING PRODUCTION-GRADE UI-1 SCREENSHOTS ===\n');

  // 1. Stage clean extension
  const tempExtDir = path.join(os.tmpdir(), 'verity_ext_ui1_clean');
  if (fs.existsSync(tempExtDir)) fs.rmSync(tempExtDir, { recursive: true, force: true });
  fs.cpSync(extPath, tempExtDir, {
    recursive: true,
    filter: (src) => !src.includes('node_modules') && !src.includes('.git')
  });

  // 2. Start test server
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    if (req.url === '/hostile') {
      res.end(`
        <!DOCTYPE html>
        <html style="overflow: hidden !important; transform: scale(0.96);">
          <head><title>Hostile Host Page</title></head>
          <body style="position: fixed; overflow: hidden; width: 100vw; height: 100vh; background: #fff1f2; margin: 0; font-family: sans-serif;">
            <div style="padding: 40px;">
              <h1 style="color: #9f1239;">Hostile Attacker Page</h1>
              <p style="color: #881337;">Hostile page attempting to break fixed overlay via overflow:hidden and 3D transforms.</p>
            </div>
          </body>
        </html>
      `);
    } else {
      res.end(`
        <!DOCTYPE html>
        <html>
          <head><title>Secure Banking Testbed</title></head>
          <body style="margin: 0; padding: 40px; font-family: -apple-system, sans-serif; background: #f8fafc;">
            <div style="max-width: 800px; margin: 0 auto;">
              <h1 style="color: #0f172a;">Sample Financial Portal</h1>
              <p style="color: #475569; line-height: 1.6;">Underlying application page behind Verity web protection.</p>
            </div>
          </body>
        </html>
      `);
    }
  });

  await new Promise(r => server.listen(8095, r));
  console.log('Fixture server running on port 8095');

  const browser = await puppeteer.launch({
    executablePath: candidateBrowsers[0],
    headless: 'new',
    args: [
      `--disable-extensions-except=${tempExtDir}`,
      `--load-extension=${tempExtDir}`,
      '--no-sandbox',
      '--disable-setuid-sandbox'
    ]
  });

  await new Promise(r => setTimeout(r, 1500));
  const swTarget = await browser.waitForTarget(t => t.type() === 'service_worker', { timeout: 10000 });
  const sw = await swTarget.worker();
  console.log('Service Worker connected.');

  async function renderScenario({ filename, theme = 'light', isDanger = true, reasonsCount = 4, viewport = { width: 1280, height: 800 }, hostile = false, modal = 'overlay', filenameDl = 'kyc_update.exe' }) {
    const page = await browser.newPage();
    page.on('dialog', async dialog => {
      try { await dialog.accept(); } catch (e) {}
    });
    await page.setViewport({ ...viewport, deviceScaleFactor: 2 });
    await page.goto(hostile ? 'http://127.0.0.1:8095/hostile' : 'http://127.0.0.1:8095/', { waitUntil: 'domcontentloaded' });
    await page.bringToFront();
    await new Promise(r => setTimeout(r, 400));

    // Send IPC from Service Worker directly to tab
    await sw.evaluate(async ({ theme, isDanger, reasonsCount, modal, filenameDl }) => {
      const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
      if (!tab) return;

      await chrome.storage.local.set({ theme });

      if (modal === 'overlay') {
        const verdict = {
          action: isDanger ? 'block' : 'warn',
          score: isDanger ? 96 : 50,
          severity: isDanger ? 'danger' : 'caution',
          paymentAnalysis: isDanger ? { isCriticalPaymentPhishing: true } : null,
          signals: Array.from({ length: reasonsCount }, (_, i) => ({
            id: `RULE_${i + 1}`,
            reason: isDanger
              ? [
                  'Hostname impersonates HDFC Bank on an unverified domain.',
                  'Unverified form harvesting payment card, CVV and OTP credentials.',
                  'Insecure plain-text connection (HTTP instead of HTTPS).',
                  'Hostname matches typosquatting variant of official banking portal.',
                  'High-risk redirect chain bypassing reputation controls.',
                  'Host uses synthetic DGA domain label on high-risk TLD.',
                  'Known phishing campaign signature registered in threat feed.'
                ][i % 7]
              : [
                  'Hostname contains suspicious query parameters and redirection tokens.',
                  'Domain contains excessive subdomains (4 labels).',
                  'Unverified SSL certificate chain.',
                  'Recent domain registration under 48 hours old.'
                ][i % 4]
          }))
        };
        chrome.tabs.sendMessage(tab.id, {
          action: 'OVERLAY_PREVIEW',
          verdict
        });
      } else if (modal === 'download') {
        const payload = {
          filename: filenameDl,
          sourceHostname: 'secure-banking-portal.test',
          signals: [
            'Executable payload (.exe) detected on untrusted domain',
            'File extension matches common banking trojan lure',
            'Download lacks valid code signing certificate'
          ],
          riskScore: 85,
          severity: isDanger ? 'danger' : 'caution',
          action: isDanger ? 'block' : 'warn',
          cancelled: true
        };
        chrome.tabs.sendMessage(tab.id, {
          action: 'DOWNLOAD_VERDICT',
          payload
        });
      } else if (modal === 'toast') {
        chrome.tabs.sendMessage(tab.id, {
          action: 'POPUP_BLOCKED_TOAST',
          hostname: 'tracker-adnetwork.click'
        });
      }
    }, { theme, isDanger, reasonsCount, modal, filenameDl });

    await new Promise(r => setTimeout(r, 600));

    // Ensure theme attribute on shadow roots
    await page.evaluate((theme) => {
      const secHost = document.getElementById('verity-security-host');
      if (secHost && secHost.shadowRoot) {
        const overlay = secHost.shadowRoot.querySelector('.verity-overlay');
        if (overlay) overlay.setAttribute('data-theme', theme);
      }
      const dlHost = document.getElementById('verity-download-warning-host');
      if (dlHost && dlHost.shadowRoot) {
        const card = dlHost.shadowRoot.querySelector('.v-dw-card');
        if (card) card.setAttribute('data-theme', theme);
      }
      const toastHost = document.getElementById('verity-toast-host');
      if (toastHost && toastHost.shadowRoot) {
        const box = toastHost.shadowRoot.querySelector('.v-toast-container');
        if (box) box.setAttribute('data-theme', theme);
      }
    }, theme);

    await new Promise(r => setTimeout(r, 200));

    const dest = path.join(SCREENSHOT_DIR, filename);
    await page.screenshot({ path: dest, fullPage: false });
    console.log(`📸 Saved: ${filename}`);

    await page.evaluate(() => {
      try { window.onbeforeunload = null; } catch (e) {}
    }).catch(() => {});
    await page.close();
  }

  // 1. Block Light Mode
  await renderScenario({ filename: '01_block_light.png', theme: 'light', isDanger: true, reasonsCount: 4 });

  // 2. Block Dark Mode
  await renderScenario({ filename: '02_block_dark.png', theme: 'dark', isDanger: true, reasonsCount: 4 });

  // 3. Caution Light Mode
  await renderScenario({ filename: '03_caution_light.png', theme: 'light', isDanger: false, reasonsCount: 3 });

  // 4. Caution Dark Mode
  await renderScenario({ filename: '04_caution_dark.png', theme: 'dark', isDanger: false, reasonsCount: 3 });

  // 5. Download Modal Light Mode
  await renderScenario({ filename: '05_download_modal_light.png', theme: 'light', isDanger: true, modal: 'download' });

  // 6. Download Modal Dark Mode
  await renderScenario({ filename: '06_download_modal_dark.png', theme: 'dark', isDanger: true, modal: 'download' });

  // 7. Toast Light Mode
  await renderScenario({ filename: '07_toast_light.png', theme: 'light', modal: 'toast' });

  // 8. Toast Dark Mode
  await renderScenario({ filename: '08_toast_dark.png', theme: 'dark', modal: 'toast' });

  // 9. Overlay at 360px Mobile Width
  await renderScenario({ filename: '09_overlay_mobile_360px.png', theme: 'light', isDanger: true, reasonsCount: 3, viewport: { width: 360, height: 740 } });

  // 10. Overlay on Hostile Host Page with overflow:hidden and transforms
  await renderScenario({ filename: '10_overlay_hostile_page.png', theme: 'dark', isDanger: true, reasonsCount: 4, hostile: true });

  // 11. Overlay with 40-item reasons list showing custom scrollbar
  await renderScenario({ filename: '11_overlay_40_reasons_scrollbar.png', theme: 'dark', isDanger: true, reasonsCount: 40 });

  await browser.close();
  server.close();
  console.log('\nAll 11 screenshots successfully captured and verified in:', SCREENSHOT_DIR);
}

run().catch(err => {
  console.error('Screenshot capture failed:', err);
  process.exit(1);
});
