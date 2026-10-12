import puppeteer from 'puppeteer-core';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const extPath = path.resolve(__dirname, '..');

const candidateBrowsers = [
  process.env.PUPPETEER_EXECUTABLE_PATH,
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
].filter(p => p && fs.existsSync(p));

const TARGET_SITES = [
  { name: 'Amazon India', url: 'https://www.amazon.in/' },
  { name: 'SBI Online Retail Login', url: 'https://retail.onlinesbi.sbi/retail/login.htm' },
  { name: 'HDFC Bank', url: 'https://www.hdfcbank.com/' },
  { name: 'Paytm', url: 'https://paytm.com/' },
  { name: 'Times of India', url: 'https://timesofindia.indiatimes.com/' }
];

async function main() {
  console.log('======================================================================');
  console.log('🔬 DIAGNOSING 5 FALSE BLOCKS WITH REAL EXTENSION EVIDENCE');
  console.log('======================================================================');

  if (candidateBrowsers.length === 0) {
    console.error('No Chromium executable found.');
    process.exit(1);
  }

  const selectedBrowser = candidateBrowsers[0];
  const tempExtDir = path.join(os.tmpdir(), 'verity_ext_diag_clean');
  if (fs.existsSync(tempExtDir)) fs.rmSync(tempExtDir, { recursive: true, force: true });
  fs.cpSync(extPath, tempExtDir, {
    recursive: true,
    filter: (src) => !src.includes('node_modules') && !src.includes('.git')
  });

  const profileDir = path.join(os.tmpdir(), 'verity_diag_profile');
  if (fs.existsSync(profileDir)) fs.rmSync(profileDir, { recursive: true, force: true });

  const browser = await puppeteer.launch({
    executablePath: selectedBrowser,
    headless: false,
    userDataDir: profileDir,
    ignoreDefaultArgs: ['--disable-extensions'],
    args: [
      `--disable-extensions-except=${tempExtDir}`,
      `--load-extension=${tempExtDir}`,
      '--no-sandbox'
    ]
  });

  await new Promise(r => setTimeout(r, 3000));
  const swTarget = browser.targets().find(t => t.type() === 'service_worker');
  const sw = swTarget ? await swTarget.worker() : null;

  const diagnoses = [];

  try {
    for (const site of TARGET_SITES) {
      console.log(`\nNavigating to: ${site.name} (${site.url})...`);
      const page = await browser.newPage();

      try {
        await page.goto(site.url, { waitUntil: 'domcontentloaded', timeout: 15000 });
        await new Promise(r => setTimeout(r, 3500));

        // 1. Capture DOM features collected by the real content script
        const domFeatures = await page.evaluate(() => {
          try {
            if (typeof collectSignals === 'function') {
              return collectSignals();
            }
          } catch (e) {}
          // Fallback manual read if function not globally scoped
          const host = document.getElementById('verity-security-host');
          return {
            hasBlockingOverlay: !!host,
            overlayScore: host ? parseInt(host.getAttribute('data-score') || '0', 10) : 0,
            overlayAction: host ? host.getAttribute('data-action') : null,
            pageTitle: document.title,
            inputsCount: document.querySelectorAll('input').length,
            passwordInputs: document.querySelectorAll('input[type="password"]').length,
            formsCount: document.forms.length
          };
        });

        // 2. Query the real service worker for stored session verdict and signals
        let swSessionData = null;
        if (sw) {
          swSessionData = await sw.evaluate(async (targetUrl) => {
            const tabs = await chrome.tabs.query({});
            const targetTab = tabs.find(t => t.url && (t.url === targetUrl || targetUrl.includes(new URL(t.url).hostname)));
            if (!targetTab) return { error: 'Tab not found in sw tabs list' };

            const allSession = await chrome.storage.session.get(null);
            const tabVerdict = allSession[targetTab.id.toString()] || null;

            return {
              tabId: targetTab.id,
              tabUrl: targetTab.url,
              sessionVerdict: tabVerdict
            };
          }, site.url);
        }

        // 3. Inspect overlay DOM elements directly
        const overlayDomDetails = await page.evaluate(() => {
          const host = document.getElementById('verity-security-host');
          if (!host) return { overlayPresent: false };
          const shadow = host.shadowRoot;
          return {
            overlayPresent: true,
            action: host.getAttribute('data-action'),
            score: parseInt(host.getAttribute('data-score') || '0', 10),
            stateTitle: shadow?.querySelector('.verity-status-highlight')?.textContent?.trim(),
            reasons: Array.from(shadow?.querySelectorAll('.verity-tag') || []).map(el => el.textContent.trim())
          };
        });

        // Format signals breakdown with source
        const sessionVerdict = swSessionData?.sessionVerdict;
        const rawSignals = sessionVerdict?.signals || [];
        
        const mappedSignals = rawSignals.map(sig => {
          let source = 'url';
          if (sig.category === 'dom_analysis' || sig.category === 'content_brand_impersonation' || sig.category === 'scam_language' || sig.category === 'financial_context') {
            source = 'dom';
          } else if (sig.category === 'ml') {
            source = 'ml';
          } else if (sig.category === 'download') {
            source = 'download';
          } else if (sig.category.startsWith('synergy')) {
            source = 'dom';
          }
          return {
            ruleOrId: sig.category,
            points: sig.score,
            category: sig.category,
            source: source,
            reason: sig.reason
          };
        });

        const diagnosisEntry = {
          name: site.name,
          url: site.url,
          finalScore: overlayDomDetails.score || sessionVerdict?.riskScore || sessionVerdict?.score || 0,
          action: overlayDomDetails.action || sessionVerdict?.action || 'unknown',
          overlayShown: overlayDomDetails.overlayPresent,
          signals: mappedSignals,
          reasonsFromOverlay: overlayDomDetails.reasons || [],
          domFeaturesSent: domFeatures,
          swSessionVerdict: sessionVerdict
        };

        diagnoses.push(diagnosisEntry);
        console.log(`  -> Action: ${diagnosisEntry.action} | Score: ${diagnosisEntry.finalScore}`);
        console.log(`  -> Fired Signals (${mappedSignals.length}):`);
        for (const s of mappedSignals) {
          console.log(`     * [${s.source.toUpperCase()}] ${s.category} (+${s.points} pts): ${s.reason}`);
        }

      } catch (siteErr) {
        console.error(`  -> Failed to diagnose ${site.url}:`, siteErr.message);
        diagnoses.push({
          name: site.name,
          url: site.url,
          error: siteErr.message
        });
      } finally {
        await page.close();
      }
    }

  } finally {
    await browser.close();
    try {
      if (fs.existsSync(tempExtDir)) fs.rmSync(tempExtDir, { recursive: true, force: true });
      if (fs.existsSync(profileDir)) fs.rmSync(profileDir, { recursive: true, force: true });
    } catch {}
  }

  const outPath = path.resolve(__dirname, '../benchmark/false_block_diagnosis.json');
  fs.writeFileSync(outPath, JSON.stringify(diagnoses, null, 2), 'utf8');
  console.log(`\n✅ Saved complete diagnosis to ${outPath}`);
}

main();
