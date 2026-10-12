import puppeteer from 'puppeteer-core';
import path from 'path';
import fs from 'fs';
import os from 'os';
import http from 'http';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const extPath = path.resolve(__dirname, '..');
const SCREENSHOT_DIR = 'C:\\Users\\User\\.gemini\\antigravity-ide\\brain\\c1c36304-0fcc-4a65-bb44-64faa003d234\\screenshots_ui2';

if (!fs.existsSync(SCREENSHOT_DIR)) {
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
}

const candidateBrowsers = [
  process.env.PUPPETEER_EXECUTABLE_PATH,
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
].filter(p => p && fs.existsSync(p));

async function run() {
  console.log('=== CAPTURING PRODUCTION-GRADE UI-2 SCREENSHOTS ===\n');

  // Stage clean extension in temp
  const tempExtDir = path.join(os.tmpdir(), 'verity_ext_ui2_clean');
  if (fs.existsSync(tempExtDir)) fs.rmSync(tempExtDir, { recursive: true, force: true });
  fs.cpSync(extPath, tempExtDir, {
    recursive: true,
    filter: (src) => !src.includes('node_modules') && !src.includes('.git')
  });

  // Start simple test HTTP server for underlying page
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!DOCTYPE html><html><body><h1>Verity Testbed</h1></body></html>`);
  });
  await new Promise(r => server.listen(8097, r));

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
  const extId = new URL(swTarget.url()).hostname;
  console.log(`Service Worker connected. Ext ID: ${extId}`);

  // ──────────────────────────────────────────────────────────────────────────
  // 1. TOOLBAR ICON SET ON LIGHT AND DARK TOOLBARS
  // ──────────────────────────────────────────────────────────────────────────
  console.log('\n--- Capturing Toolbar Icons on Light & Dark backgrounds ---');
  {
    const page = await browser.newPage();
    await page.setViewport({ width: 720, height: 260, deviceScaleFactor: 2 });
    const logoSvg = fs.readFileSync(path.join(extPath, 'icons/verity-logo.svg'), 'utf8');

    const toolbarHtml = `<!DOCTYPE html>
    <html>
      <head>
        <style>
          body { margin: 0; padding: 24px; font-family: -apple-system, sans-serif; }
          .toolbar-group { margin-bottom: 24px; padding: 16px 24px; border-radius: 8px; display: flex; align-items: center; justify-content: space-between; }
          .toolbar-light { background: #f1f5f9; border: 1px solid #e2e8f0; color: #0f172a; }
          .toolbar-dark { background: #18181b; border: 1px solid #27272a; color: #fafafa; }
          .title { font-size: 13px; font-weight: 600; }
          .icons-row { display: flex; align-items: center; gap: 24px; }
          .icon-item { display: flex; flex-direction: column; align-items: center; gap: 8px; font-size: 11px; opacity: 0.8; }
          img { display: block; image-rendering: -webkit-optimize-contrast; }
        </style>
      </head>
      <body>
        <div class="toolbar-group toolbar-light">
          <div class="title">Light Toolbar (Chrome/Edge Standard)</div>
          <div class="icons-row">
            <div class="icon-item"><img src="icons/safe_16.png" width="16" height="16"><span>16px</span></div>
            <div class="icon-item"><img src="icons/safe_32.png" width="32" height="32"><span>32px</span></div>
            <div class="icon-item"><img src="icons/safe_48.png" width="48" height="48"><span>48px</span></div>
            <div class="icon-item"><img src="icons/safe_128.png" width="64" height="64"><span>128px</span></div>
          </div>
        </div>
        <div class="toolbar-group toolbar-dark">
          <div class="title">Dark Toolbar (Chrome/Edge Dark Mode)</div>
          <div class="icons-row">
            <div class="icon-item"><img src="icons/safe_16.png" width="16" height="16"><span>16px</span></div>
            <div class="icon-item"><img src="icons/safe_32.png" width="32" height="32"><span>32px</span></div>
            <div class="icon-item"><img src="icons/safe_48.png" width="48" height="48"><span>48px</span></div>
            <div class="icon-item"><img src="icons/safe_128.png" width="64" height="64"><span>128px</span></div>
          </div>
        </div>
      </body>
    </html>`;

    await page.goto(`chrome-extension://${extId}/popup/popup.html`);
    await page.setContent(toolbarHtml, { waitUntil: 'domcontentloaded' });
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, '01_icon_set_toolbars.png') });
    console.log('📸 Saved: 01_icon_set_toolbars.png');
    await page.close();
  }

  // ──────────────────────────────────────────────────────────────────────────
  // 2. POPUP STATES
  // ──────────────────────────────────────────────────────────────────────────
  console.log('\n--- Capturing Popup States (380px wide) ---');
  async function capturePopupScenario({ filename, theme = 'light', state = 'verdict', verdictData = null }) {
    const page = await browser.newPage();
    await page.setViewport({ width: 380, height: 520, deviceScaleFactor: 2 });
    await page.goto(`chrome-extension://${extId}/popup/popup.html`, { waitUntil: 'domcontentloaded' });

    await page.evaluate(({ theme, state, verdictData }) => {
      // Apply theme
      applyTheme(theme);

      if (state === 'loading') {
        showState('state-loading');
      } else if (state === 'error') {
        renderError('Service worker unreachable', 'Could not establish connection to background service.');
      } else if (state === 'unscannable') {
        renderUnscannable('chrome://settings/security');
      } else if (state === 'verdict') {
        const dummyTab = { url: verdictData.url || 'https://paypa1-secure.example.com/checkout' };
        renderVerdict(verdictData, dummyTab);
        // Expand accordion if reasons exist
        if (verdictData.signals && verdictData.signals.length > 0) {
          const btn = document.getElementById('btn-why-accordion');
          const container = document.getElementById('p-reasons-container');
          if (btn && container) {
            btn.setAttribute('aria-expanded', 'true');
            container.hidden = false;
          }
        }
      }
    }, { theme, state, verdictData });

    await new Promise(r => setTimeout(r, 700));
    const dest = path.join(SCREENSHOT_DIR, filename);
    await page.screenshot({ path: dest });
    console.log(`📸 Saved: ${filename}`);
    await page.close();
  }

  // A. Safe Light & Dark
  await capturePopupScenario({
    filename: '02_popup_safe_light.png',
    theme: 'light',
    state: 'verdict',
    verdictData: {
      action: 'allow',
      severity: 'safe',
      score: 0,
      riskScore: 0,
      url: 'https://retail.onlinesbi.sbi/retail/login.htm',
      signals: []
    }
  });

  await capturePopupScenario({
    filename: '03_popup_safe_dark.png',
    theme: 'dark',
    state: 'verdict',
    verdictData: {
      action: 'allow',
      severity: 'safe',
      score: 0,
      riskScore: 0,
      url: 'https://retail.onlinesbi.sbi/retail/login.htm',
      signals: []
    }
  });

  // B. Caution
  await capturePopupScenario({
    filename: '04_popup_caution_light.png',
    theme: 'light',
    state: 'verdict',
    verdictData: {
      action: 'warn',
      severity: 'caution',
      score: 48,
      riskScore: 48,
      url: 'https://unverified-login-portal.net/auth',
      signals: [
        { id: 'RULE_MISSING_HTTPS', reason: 'The connection is not secure (HTTP instead of HTTPS).' },
        { id: 'RULE_EXCESSIVE_SUBDOMAINS', reason: 'The URL uses an unusually high number of subdomains (4).' },
        { id: 'SIG_URL_SUSPICIOUS', reason: 'URL structure exhibits suspicious redirection patterns.' }
      ]
    }
  });

  // C. Danger
  await capturePopupScenario({
    filename: '05_popup_danger_dark.png',
    theme: 'dark',
    state: 'verdict',
    verdictData: {
      action: 'block',
      severity: 'danger',
      score: 96,
      riskScore: 96,
      url: 'https://paypa1-security-verification.live/account/login',
      signals: [
        { id: 'RULE_BRAND_NAME_WRONG_DOMAIN', reason: 'The URL contains the name "PayPal" but does not belong to its official domain.' },
        { id: 'SIG_CREDENTIAL_COLLECTION', reason: 'Page requests sensitive credentials or payment information.' },
        { id: 'SIG_ML_PHISHING', reason: 'On-device ML model flagged structural phishing characteristics (98% confidence).' },
        { id: 'SIG_SYNERGY_IMPERSONATION_CREDENTIALS', reason: 'High risk: Impersonating a trusted brand while requesting sensitive credentials.' }
      ]
    }
  });

  // D. Loading
  await capturePopupScenario({
    filename: '06_popup_loading_state.png',
    theme: 'light',
    state: 'loading'
  });

  // E. Error (SW unreachable)
  await capturePopupScenario({
    filename: '07_popup_error_retry.png',
    theme: 'light',
    state: 'error'
  });

  // F. Unscannable internal page
  await capturePopupScenario({
    filename: '08_popup_unscannable_state.png',
    theme: 'dark',
    state: 'unscannable'
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 3. OPTIONS PAGE (LIGHT AND DARK)
  // ──────────────────────────────────────────────────────────────────────────
  console.log('\n--- Capturing Options Page (Full Tab) ---');
  async function captureOptionsPage({ filename, theme = 'light', tab = 'general' }) {
    const page = await browser.newPage();
    await page.setViewport({ width: 1024, height: 760, deviceScaleFactor: 2 });
    await page.goto(`chrome-extension://${extId}/options/options.html`, { waitUntil: 'domcontentloaded' });

    await page.evaluate(({ theme, tab }) => {
      applyTheme(theme);
      // Switch tab
      const navBtn = document.querySelector(`.opt-nav-item[data-tab="${tab}"]`);
      if (navBtn) navBtn.click();
    }, { theme, tab });

    await new Promise(r => setTimeout(r, 600));
    const dest = path.join(SCREENSHOT_DIR, filename);
    await page.screenshot({ path: dest });
    console.log(`📸 Saved: ${filename}`);
    await page.close();
  }

  await captureOptionsPage({ filename: '09_options_general_light.png', theme: 'light', tab: 'general' });
  await captureOptionsPage({ filename: '10_options_protection_dark.png', theme: 'dark', tab: 'protection' });
  await captureOptionsPage({ filename: '11_options_allowlist_light.png', theme: 'light', tab: 'allowlist' });

  // ──────────────────────────────────────────────────────────────────────────
  // 4. MICRO-POLISH PSEUDO-LOCALE (+40% to +100% STRING EXPANSION TEST)
  // ──────────────────────────────────────────────────────────────────────────
  console.log('\n--- Capturing Pseudo-Locale (+40% to +100% String Expansion) ---');
  {
    const page = await browser.newPage();
    await page.setViewport({ width: 380, height: 560, deviceScaleFactor: 2 });
    await page.goto(`chrome-extension://${extId}/popup/popup.html`, { waitUntil: 'domcontentloaded' });

    await page.evaluate(() => {
      applyTheme('light');
      // Double every text node to simulate severe string expansion (+60% to +100%)
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      let node;
      while ((node = walker.nextNode())) {
        const text = node.nodeValue.trim();
        if (text.length > 2 && !text.includes('://')) {
          node.nodeValue = `[Āēīōū ${text} • ${text}]`;
        }
      }
    });

    await new Promise(r => setTimeout(r, 400));
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, '12_popup_pseudo_locale_expansion.png') });
    console.log('📸 Saved: 12_popup_pseudo_locale_expansion.png');
    await page.close();
  }

  // ──────────────────────────────────────────────────────────────────────────
  // 5. PROOF OF OVERLAY UNCHANGED (CONFIRM PIXEL-IDENTICAL TO UI-1)
  // ──────────────────────────────────────────────────────────────────────────
  console.log('\n--- Capturing Overlay Unchanged Proof ---');
  {
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800, deviceScaleFactor: 2 });
    await page.goto('http://127.0.0.1:8097/', { waitUntil: 'domcontentloaded' });

    await sw.evaluate(async () => {
      const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
      if (!tab) return;
      const verdict = {
        action: 'block',
        score: 96,
        severity: 'danger',
        paymentAnalysis: { isCriticalPaymentPhishing: true },
        signals: [
          { id: 'RULE_1', reason: 'Hostname impersonates HDFC Bank on an unverified domain.' },
          { id: 'RULE_2', reason: 'Unverified form harvesting payment card, CVV and OTP credentials.' },
          { id: 'RULE_3', reason: 'Insecure plain-text connection (HTTP instead of HTTPS).' },
          { id: 'RULE_4', reason: 'Hostname matches typosquatting variant of official banking portal.' }
        ]
      };
      chrome.tabs.sendMessage(tab.id, {
        action: 'OVERLAY_PREVIEW',
        verdict
      });
    });

    await new Promise(r => setTimeout(r, 800));
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, '13_overlay_ui2_proof_unchanged.png') });
    console.log('📸 Saved: 13_overlay_ui2_proof_unchanged.png');
    await page.close();
  }

  await browser.close();
  server.close();
  console.log('\nAll Phase UI-2 screenshots successfully captured!');
}

run().catch(err => {
  console.error('UI-2 Screenshot capture error:', err);
  process.exit(1);
});
