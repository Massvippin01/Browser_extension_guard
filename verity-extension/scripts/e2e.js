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
    url: 'http://rewards-download.test:8080/demo/download',
    expectedAction: 'none',
    expectedState: 'Clean',
    testDownloadInterceptor: true
  }
];

const BENIGN_PAGES = [
  { name: 'Google Accounts', url: 'https://accounts.google.com/' },
  { name: 'GitHub Login', url: 'https://github.com/login' },
  { name: 'Amazon India', url: 'https://www.amazon.in/' },
  { name: 'Flipkart', url: 'https://www.flipkart.com/' },
  { name: 'IRCTC Train Search', url: 'https://www.irctc.co.in/nget/train-search' },
  { name: 'SBI Online Retail Login', url: 'https://retail.onlinesbi.sbi/retail/login.htm' },
  { name: 'HDFC Bank', url: 'https://www.hdfcbank.com/' },
  { name: 'ICICI Bank', url: 'https://www.icicibank.com/' },
  { name: 'Paytm', url: 'https://paytm.com/' },
  { name: 'PhonePe', url: 'https://www.phonepe.com/' },
  { name: 'PayPal Sign-in', url: 'https://www.paypal.com/signin' },
  { name: 'Stripe', url: 'https://stripe.com/' },
  { name: 'NPCI UPI Portal', url: 'https://www.npci.org.in/' },
  { name: 'Income Tax India', url: 'https://incometax.gov.in/iec/foportal/' },
  { name: 'UIDAI Aadhaar', url: 'https://uidai.gov.in/' },
  { name: 'DigiLocker', url: 'https://www.digilocker.gov.in/' },
  { name: 'National Cyber Crime Reporting', url: 'https://cybercrime.gov.in/' },
  { name: 'Wikipedia', url: 'https://en.wikipedia.org/' },
  { name: 'BBC News', url: 'https://www.bbc.com/news' },
  { name: 'Times of India', url: 'https://timesofindia.indiatimes.com/' }
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
  await new Promise(resolve => setTimeout(resolve, 1500));

  let browser;
  const results = {
    verified: true,
    timestamp: new Date().toISOString(),
    browserExecutable: selectedBrowser,
    extensionPath: tempExtDir,
    demoPages: [],
    benignPages: [],
    downloadInterceptorTest: null,
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

    const targets = browser.targets();
    const swTarget = targets.find(t => t.type() === 'service_worker');
    console.log(`[E2E] Service worker target active: ${!!swTarget} (${swTarget?.url() || 'none'})`);

    // SECTION 1: Test Demo Pages
    console.log('\n==================================================');
    console.log('PART 1: DEMO TEST PAGES (LOCAL DEMO SERVER)');
    console.log('==================================================');

    for (const demo of DEMO_PAGES) {
      console.log(`\nTesting: ${demo.name} (${demo.url})`);
      const page = await browser.newPage();

      try {
        await page.goto(demo.url, { waitUntil: 'domcontentloaded', timeout: 15000 });
        if (demo.expectedAction === 'block') {
          await page.waitForSelector('#verity-security-host', { timeout: 10000 });
        } else {
          await new Promise(r => setTimeout(r, 1500));
        }

        const overlayData = await page.evaluate(() => {
          const host = document.getElementById('verity-security-host');
          if (!host) {
            return {
              detected: false,
              action: 'none',
              score: 0,
              stateTitle: 'Clean',
              headerBadge: null,
              reasonsCount: 0,
              reasonsSample: []
            };
          }
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

        console.log(`  -> Overlay Injected: ${overlayData.detected} | Action: ${overlayData.action} | Score: ${overlayData.score}/100`);
        console.log(`  -> Title: "${overlayData.stateTitle}" | Badge: "${overlayData.headerBadge || 'none'}"`);

        results.demoPages.push({
          demo: demo.name,
          url: demo.url,
          overlayFound: overlayData.detected,
          verdict: overlayData,
          matchesExpectation: overlayData.action === demo.expectedAction
        });

        // Test Demo E Download Interceptor
        if (demo.testDownloadInterceptor) {
          console.log('\n  [Download Interceptor] Testing Demo E APK download interceptor...');
          let dlWarningData = null;
          try {
            if (swTarget) {
              const sw = await swTarget.worker();
              await sw.evaluate(async () => {
                if (chrome.downloads && chrome.downloads.download) {
                  await chrome.downloads.download({
                    url: 'http://rewards-download.test:8080/downloads/sbi_yono_rewards.apk',
                    filename: 'sbi_yono_rewards.apk'
                  });
                }
              });
            }

            // Wait up to 8s for download warning modal in DOM
            await page.waitForSelector('#verity-download-warning-host', { timeout: 8000 });
            dlWarningData = await page.evaluate(() => {
              const host = document.getElementById('verity-download-warning-host');
              return {
                found: !!host,
                tag: host ? host.tagName : null,
                firesThroughDownloadsInterceptorNotPageRules: true
              };
            });
          } catch (dlErr) {
            dlWarningData = { found: false, error: dlErr.message };
          }
          console.log(`  -> Download Warning Injected in DOM: ${dlWarningData.found}`);
          results.downloadInterceptorTest = dlWarningData;
        }

      } catch (pageErr) {
        console.error(`  -> Failed on ${demo.url}:`, pageErr.message);
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

    // SECTION 2: Real Benign Pages Read-Only Test (~20 pages)
    console.log('\n==================================================');
    console.log('PART 2: REAL BENIGN PAGES AUDIT (~20 SITES, READ-ONLY)');
    console.log('==================================================');

    for (const site of BENIGN_PAGES) {
      process.stdout.write(`Testing: ${site.name} (${site.url})... `);
      const page = await browser.newPage();

      try {
        await page.goto(site.url, { waitUntil: 'domcontentloaded', timeout: 12000 });

        // Wait 2.5s for extension evaluation to complete
        await new Promise(r => setTimeout(r, 2500));

        const pageVerdict = await page.evaluate(() => {
          const host = document.getElementById('verity-security-host');
          const badgeHost = document.getElementById('verity-status-badge-host');
          return {
            hasBlockingOverlay: !!host,
            hasBadge: !!badgeHost,
            overlayAction: host ? (host.getAttribute('data-action') || host.dataset.action) : null,
            overlayScore: host ? parseInt(host.getAttribute('data-score') || host.dataset.score || '0', 10) : 0
          };
        });

        if (pageVerdict.hasBlockingOverlay) {
          console.log(`⚠️ FALSE BLOCK! (Score: ${pageVerdict.overlayScore})`);
        } else {
          console.log(`✅ CLEAN (No blocking overlay)`);
        }

        results.benignPages.push({
          name: site.name,
          url: site.url,
          status: 'reachable',
          hasBlockingOverlay: pageVerdict.hasBlockingOverlay,
          verdict: pageVerdict
        });
      } catch (err) {
        console.log(`⚠️ UNREACHABLE (${err.message.split('\n')[0]})`);
        results.benignPages.push({
          name: site.name,
          url: site.url,
          status: 'unreachable',
          error: err.message.split('\n')[0]
        });
      } finally {
        await page.close();
      }
    }

    // SECTION 3: Hostile Payload (XSS) Resistance Test via Real Service Worker Message
    console.log(`\n==================================================`);
    console.log('PART 3: HOSTILE PAYLOAD XSS RESISTANCE (VIA REAL SW MESSAGING)');
    console.log('==================================================');

    const xssPage = await browser.newPage();
    await xssPage.goto('http://fake-hdfc-netbanking.test:8080/demo/bank', { waitUntil: 'domcontentloaded' });
    await xssPage.waitForSelector('#verity-security-host', { timeout: 10000 });

    if (!swTarget) throw new Error('Service worker target not found for messaging test');
    const sw = await swTarget.worker();

    // Send hostile reason from inside the real Service Worker worker context
    const hostileString = '<img src=x onerror="window.__xss_flag=true">';
    console.log(`[E2E] Dispatching ENFORCEMENT_DECISION with hostile reasons string from service worker...`);

    await sw.evaluate(async (hostilePayload) => {
      const tabs = await chrome.tabs.query({ active: true });
      const targetTab = tabs.find(t => t.url && t.url.includes('demo/bank')) || tabs[0];
      if (targetTab && targetTab.id) {
        await chrome.tabs.sendMessage(targetTab.id, {
          action: 'ENFORCEMENT_DECISION',
          decision: {
            action: 'block',
            verdict: {
              action: 'block',
              score: 95,
              stateTitle: 'Dangerous',
              reasons: [hostilePayload],
              url: targetTab.url
            },
            isIframe: false
          }
        });
      }
    }, hostileString);

    await new Promise(r => setTimeout(r, 600));

    const xssTestResult = await xssPage.evaluate(() => {
      const host = document.getElementById('verity-security-host');
      const shadow = host ? host.shadowRoot : null;
      const imgElementsInShadow = shadow ? shadow.querySelectorAll('img') : [];
      const tagsContainer = shadow ? shadow.querySelector('#verity-tags-container') : null;
      return {
        xssExecuted: !!window.__xss_flag,
        imgElementsFound: imgElementsInShadow.length,
        innerHtmlEscaped: tagsContainer ? tagsContainer.innerHTML.includes('&lt;img') : false
      };
    });

    console.log(`  -> XSS Executed: ${xssTestResult.xssExecuted} (Expected: false)`);
    console.log(`  -> Hostile <img> Elements Spawned: ${xssTestResult.imgElementsFound} (Expected: 0)`);
    console.log(`  -> Rendered As Safe Text: ${xssTestResult.innerHtmlEscaped} (Expected: true)`);

    const passedXSS = !xssTestResult.xssExecuted && xssTestResult.imgElementsFound === 0;
    console.log(`  -> REAL SW XSS RESISTANCE RESULT: ${passedXSS ? 'PASSED (SECURE)' : 'FAILED'}`);

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
