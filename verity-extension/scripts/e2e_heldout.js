/**
 * scripts/e2e_heldout.js
 *
 * Runs the held-out benign E2E test on 62 real pages.
 * Records: requestedUrl, finalUrl, contentScriptRan, domScanGated,
 * verdict, score, overlayFound, signals, status.
 *
 * Calculates Block-overlay rate and Caution-overlay rate with 95% Wilson intervals.
 */

import puppeteer from 'puppeteer-core';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const extPath = path.resolve(__dirname, '..');
const browserPath = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';

export const HELDOUT_PAGES = [
  // ── Indian Banks & Fintechs (26 pages) ──────────────────────────────────
  { name: 'Union Bank of India', url: 'https://www.unionbankofindia.co.in/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Bank of India', url: 'https://bankofindia.co.in/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Indian Bank', url: 'https://www.indianbank.in/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Central Bank of India', url: 'https://www.centralbankofindia.co.in/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Indian Overseas Bank', url: 'https://www.iob.in/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'UCO Bank', url: 'https://www.ucobank.com/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Bank of Maharashtra', url: 'https://bankofmaharashtra.in/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Punjab & Sind Bank', url: 'https://punjabandsindbank.co.in/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Federal Bank', url: 'https://www.federalbank.co.in/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'South Indian Bank', url: 'https://www.southindianbank.com/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Karur Vysya Bank', url: 'https://www.kvb.co.in/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'City Union Bank', url: 'https://www.cityunionbank.com/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Tamilnad Mercantile Bank', url: 'https://www.tmb.in/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'RBL Bank', url: 'https://www.rblbank.com/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Bandhan Bank', url: 'https://www.bandhanbank.com/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'CSB Bank', url: 'https://www.csb.co.in/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'DCB Bank', url: 'https://www.dcbbank.com/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Dhanlaxmi Bank', url: 'https://www.dhanbank.com/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Nainital Bank', url: 'https://www.nainitalbank.co.in/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'IDBI Bank', url: 'https://www.idbibank.in/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Jammu & Kashmir Bank', url: 'https://www.jkbank.com/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Karnataka Bank', url: 'https://karnatakabank.com/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Saraswat Bank', url: 'https://www.saraswatbank.com/', category: 'bank_fintech', source: 'https://www.npci.org.in/what-we-do/upi/live-members' },
  { name: 'SVC Co-operative Bank', url: 'https://www.svcbank.com/', category: 'bank_fintech', source: 'https://www.npci.org.in/what-we-do/upi/live-members' },
  { name: 'AU Small Finance Bank', url: 'https://www.aubank.in/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },
  { name: 'Equitas Small Finance Bank', url: 'https://www.equitasbank.com/', category: 'bank_fintech', source: 'https://www.rbi.org.in/commonman/English/Scripts/BanksInIndia.aspx' },

  // ── State & Central Government Portals (12 pages) ─────────────────────────
  { name: 'Ministry of Finance', url: 'https://finmin.nic.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'Ministry of Home Affairs', url: 'https://www.mha.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'Ministry of External Affairs', url: 'https://www.mea.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'Department of Telecommunications', url: 'https://sancharsaathi.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'National Consumer Helpline', url: 'https://consumerhelpline.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'Passport Seva Portal', url: 'https://www.passportindia.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'Parivahan Sewa', url: 'https://parivahan.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'Ministry of Corporate Affairs', url: 'https://www.mca.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'EPFO Official Portal', url: 'https://www.epfindia.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'Goods & Services Tax Portal', url: 'https://www.gst.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'National Portal Services Directory', url: 'https://services.india.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },
  { name: 'Government e-Marketplace', url: 'https://gem.gov.in/', category: 'gov_portal', source: 'https://directory.gov.in/' },

  // ── E-Commerce & SaaS Entry / Login (12 pages) ────────────────────────────
  { name: 'Atlassian Account Login', url: 'https://id.atlassian.com/login', category: 'ecommerce_saas', source: 'https://tranco-list.eu/' },
  { name: 'Dropbox Login', url: 'https://www.dropbox.com/login', category: 'ecommerce_saas', source: 'https://tranco-list.eu/' },
  { name: 'Zoom Sign-in', url: 'https://zoom.us/signin', category: 'ecommerce_saas', source: 'https://tranco-list.eu/' },
  { name: 'Salesforce Login', url: 'https://login.salesforce.com/', category: 'ecommerce_saas', source: 'https://tranco-list.eu/' },
  { name: 'Canva Login', url: 'https://www.canva.com/login', category: 'ecommerce_saas', source: 'https://tranco-list.eu/' },
  { name: 'Shopify Accounts Login', url: 'https://accounts.shopify.com/', category: 'ecommerce_saas', source: 'https://tranco-list.eu/' },
  { name: 'Figma Login', url: 'https://www.figma.com/login', category: 'ecommerce_saas', source: 'https://tranco-list.eu/' },
  { name: 'Notion Login', url: 'https://www.notion.so/login', category: 'ecommerce_saas', source: 'https://tranco-list.eu/' },
  { name: 'Slack Sign-in', url: 'https://slack.com/signin', category: 'ecommerce_saas', source: 'https://tranco-list.eu/' },
  { name: 'GitHub Pricing & Checkout Entry', url: 'https://github.com/pricing', category: 'ecommerce_saas', source: 'https://tranco-list.eu/' },
  { name: 'eBay Sign-in', url: 'https://signin.ebay.com/', category: 'ecommerce_saas', source: 'https://tranco-list.eu/' },
  { name: 'Etsy Sign-in', url: 'https://www.etsy.com/signin', category: 'ecommerce_saas', source: 'https://tranco-list.eu/' },

  // ── News Pages with Fraud-Warning / Advisory Text (12 pages) ──────────────
  { name: 'The Hindu National Section', url: 'https://www.thehindu.com/news/national/', category: 'news_advisory', source: 'https://tranco-list.eu/' },
  { name: 'Indian Express Technology Section', url: 'https://indianexpress.com/section/technology/', category: 'news_advisory', source: 'https://tranco-list.eu/' },
  { name: 'NDTV India News', url: 'https://www.ndtv.com/india-news', category: 'news_advisory', source: 'https://tranco-list.eu/' },
  { name: 'Hindustan Times India News', url: 'https://www.hindustantimes.com/india-news', category: 'news_advisory', source: 'https://tranco-list.eu/' },
  { name: 'Economic Times Banking Section', url: 'https://economictimes.indiatimes.com/industry/banking/finance/banking', category: 'news_advisory', source: 'https://tranco-list.eu/' },
  { name: 'LiveMint Technology Section', url: 'https://www.livemint.com/technology', category: 'news_advisory', source: 'https://tranco-list.eu/' },
  { name: 'Deccan Herald National Section', url: 'https://www.deccanherald.com/national', category: 'news_advisory', source: 'https://tranco-list.eu/' },
  { name: 'The Tribune Nation Section', url: 'https://www.tribuneindia.com/news/nation', category: 'news_advisory', source: 'https://tranco-list.eu/' },
  { name: 'Business Standard Banking Section', url: 'https://www.business-standard.com/finance/banking', category: 'news_advisory', source: 'https://tranco-list.eu/' },
  { name: 'Outlook India National Section', url: 'https://www.outlookindia.com/national', category: 'news_advisory', source: 'https://tranco-list.eu/' },
  { name: 'Reuters Cybersecurity Section', url: 'https://www.reuters.com/technology/cybersecurity/', category: 'news_advisory', source: 'https://tranco-list.eu/' },
  { name: 'BBC Tech News Section', url: 'https://www.bbc.com/news/technology', category: 'news_advisory', source: 'https://tranco-list.eu/' }
];

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

export async function runHeldoutE2E(outputPath = 'benchmark/heldout_e2e_run1.json') {
  console.log('======================================================================');
  console.log('🌐 VERITY HELD-OUT BENIGN E2E EVALUATION (62 REAL SITES)');
  console.log('======================================================================');

  const tempExtDir = path.join(os.tmpdir(), 'verity_ext_heldout_stage');
  if (fs.existsSync(tempExtDir)) fs.rmSync(tempExtDir, { recursive: true, force: true });
  fs.cpSync(extPath, tempExtDir, { recursive: true, filter: src => !src.includes('node_modules') && !src.includes('.git') });

  const browser = await puppeteer.launch({
    executablePath: browserPath,
    headless: true,
    args: [
      `--disable-extensions-except=${tempExtDir}`,
      `--load-extension=${tempExtDir}`,
      '--no-sandbox',
      '--disable-dev-shm-usage'
    ]
  });

  console.log('[E2E] Waiting 3s for extension service worker initialization...');
  await new Promise(r => setTimeout(r, 3000));

  const results = [];

  for (let i = 0; i < HELDOUT_PAGES.length; i++) {
    const pageItem = HELDOUT_PAGES[i];
    console.log(`[${i + 1}/${HELDOUT_PAGES.length}] Testing: ${pageItem.name} (${pageItem.url})...`);
    
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });

    let reachable = false;
    let finalUrl = pageItem.url;
    let contentScriptRan = false;
    let domScanGated = 'gated_off';
    let overlayFound = false;
    let overlayAction = 'allow';
    let overlayScore = 0;
    let signals = [];
    let stateTitle = null;

    try {
      await page.goto(pageItem.url, { waitUntil: 'domcontentloaded', timeout: 15000 });
      reachable = true;
      finalUrl = page.url();

      // Wait 3s for extension message passing and analysis
      await new Promise(r => setTimeout(r, 3000));

      const evalData = await page.evaluate(() => {
        const host = document.getElementById('verity-security-host');
        const badgeHost = document.getElementById('verity-status-badge-host');
        const hasHost = !!host;
        const hasBadge = !!badgeHost;
        const scriptRan = hasHost || hasBadge || !!window.__verityContentScriptActive;

        const hasPassword = document.querySelector('input[type="password"]') !== null;
        const hasPaymentInput = Array.from(document.querySelectorAll('input')).some(inp => {
          const m = ((inp.name||'') + (inp.id||'') + (inp.type||'') + (inp.placeholder||'')).toLowerCase();
          return m.includes('card') || m.includes('cvv') || m.includes('upi') || m.includes('otp');
        });
        const scanGated = (hasPassword || hasPaymentInput) ? 'gated_on' : 'gated_off';

        let action = 'allow';
        let score = 0;
        let tags = [];
        let title = null;

        if (hasHost && host.shadowRoot) {
          action = host.getAttribute('data-action') || 'allow';
          score = parseInt(host.getAttribute('data-score') || '0', 10);
          tags = Array.from(host.shadowRoot.querySelectorAll('.verity-tag')).map(t => t.textContent.trim());
          title = host.shadowRoot.querySelector('.verity-status-highlight')?.textContent?.trim() || null;
        }

        return {
          scriptRan,
          scanGated,
          hasHost,
          action,
          score,
          tags,
          title
        };
      });

      contentScriptRan = evalData.scriptRan;
      domScanGated = evalData.scanGated;
      overlayFound = evalData.hasHost;
      overlayAction = evalData.action;
      overlayScore = evalData.score;
      signals = evalData.tags;
      stateTitle = evalData.title;

      const mark = overlayAction === 'block' ? '🛑 BLOCK' : (overlayAction === 'warn' ? '⚠️ CAUTION' : '✅ CLEAN');
      console.log(`   -> Status: ${mark} | Score: ${overlayScore} | Final URL: ${finalUrl} | ContentScript: ${contentScriptRan} | Gated: ${domScanGated}`);

    } catch (err) {
      reachable = false;
      console.warn(`   -> Unreachable / Timeout: ${err.message}`);
    } finally {
      await page.close();
    }

    results.push({
      name: pageItem.name,
      requestedUrl: pageItem.url,
      finalUrl,
      category: pageItem.category,
      source: pageItem.source,
      status: (reachable && contentScriptRan) ? 'reachable' : 'unreachable',
      contentScriptRan,
      domScanGated,
      overlayFound,
      verdict: overlayAction,
      score: overlayScore,
      signals,
      stateTitle
    });
  }

  await browser.close();

  // Summary statistics
  const reachablePages = results.filter(r => r.status === 'reachable');
  const totalReachable = reachablePages.length;
  const totalTested = results.length;
  const unreachableCount = totalTested - totalReachable;

  const blockCount = reachablePages.filter(r => r.overlayFound && r.verdict === 'block').length;
  const cautionCount = reachablePages.filter(r => r.overlayFound && r.verdict === 'warn').length;
  const cleanCount = reachablePages.filter(r => !r.overlayFound || r.verdict === 'allow').length;

  const blockInterval = wilsonScoreInterval(blockCount, totalReachable);
  const cautionInterval = wilsonScoreInterval(cautionCount, totalReachable);

  const summary = {
    timestamp: new Date().toISOString(),
    totalTested,
    totalReachable,
    unreachableCount,
    cleanCount,
    blockCount,
    cautionCount,
    blockOverlayRate: {
      measuredPercent: blockInterval.point,
      ci95Lower: blockInterval.lower,
      ci95Upper: blockInterval.upper
    },
    cautionOverlayRate: {
      measuredPercent: cautionInterval.point,
      ci95Lower: cautionInterval.lower,
      ci95Upper: cautionInterval.upper
    },
    results
  };

  const fullOutputPath = path.resolve(__dirname, '..', outputPath);
  fs.writeFileSync(fullOutputPath, JSON.stringify(summary, null, 2) + '\n');
  console.log(`\n[E2E] Saved held-out results to ${fullOutputPath}`);

  console.log('\n' + '='.repeat(60));
  console.log('📊 HELD-OUT BENIGN E2E SUMMARY REPORT:');
  console.log('='.repeat(60));
  console.log(`Total Tested:       ${totalTested}`);
  console.log(`Reachable:          ${totalReachable}`);
  console.log(`Unreachable:        ${unreachableCount}`);
  console.log(`Clean (Allow):      ${cleanCount} (${(cleanCount/totalReachable*100).toFixed(2)}%)`);
  console.log(`Block Overlays:     ${blockCount} (${blockInterval.point.toFixed(2)}% | 95% CI: [${blockInterval.lower.toFixed(2)}%, ${blockInterval.upper.toFixed(2)}%])`);
  console.log(`Caution Overlays:   ${cautionCount} (${cautionInterval.point.toFixed(2)}% | 95% CI: [${cautionInterval.lower.toFixed(2)}%, ${cautionInterval.upper.toFixed(2)}%])`);
  console.log('='.repeat(60));

  return summary;
}

if (process.argv[1] && process.argv[1].endsWith('e2e_heldout.js')) {
  const targetOut = process.argv[2] || 'benchmark/heldout_e2e_run2_tuned.json';
  runHeldoutE2E(targetOut).catch(console.error);
}
