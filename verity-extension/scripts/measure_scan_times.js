import puppeteer from 'puppeteer-core';
import fs from 'fs';

const candidateBrowsers = [
  process.env.PUPPETEER_EXECUTABLE_PATH,
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
].filter(p => p && fs.existsSync(p));

const TEST_PAGES = [
  { name: 'Times of India', url: 'https://timesofindia.indiatimes.com/' },
  { name: 'BBC News', url: 'https://www.bbc.com/news' },
  { name: 'Wikipedia', url: 'https://en.wikipedia.org/wiki/Phishing' }
];

async function measurePage(browser, pageInfo) {
  const page = await browser.newPage();
  try {
    await page.goto(pageInfo.url, { waitUntil: 'domcontentloaded', timeout: 20000 });
    await new Promise(r => setTimeout(r, 2000));

    // Measure Unconditional innerText scan time
    const unconditionalDuration = await page.evaluate(() => {
      const start = performance.now();
      const text = (document.body ? document.body.innerText : '').toLowerCase();
      const slice = text.substring(0, 3000);
      const kws = ['kyc', 'otp', 'upi', 'netbanking', 'cvv', 'act now', 'limited time'];
      const matches = kws.filter(k => slice.includes(k));
      const end = performance.now();
      return end - start;
    });

    // Measure Gated scan time (checks inputs first; skips innerText if no credentials)
    const gatedDuration = await page.evaluate(() => {
      const start = performance.now();
      const hasPassword = document.querySelector('input[type="password"]') !== null;
      const hasSensitive = document.querySelector('input[name*="card"], input[name*="cvv"], input[name*="otp"], input[name*="upi"]') !== null;
      const hasPaymentForm = document.querySelector('form[action*="pay"], form[action*="checkout"]') !== null;
      let text = '';
      if (hasPassword || hasSensitive || hasPaymentForm) {
        // Gated: only read capped text
        text = (document.body ? document.body.innerText : '').substring(0, 4000).toLowerCase();
      }
      const end = performance.now();
      return end - start;
    });

    return {
      name: pageInfo.name,
      url: pageInfo.url,
      unconditionalMs: unconditionalDuration,
      gatedMs: gatedDuration,
      speedup: (unconditionalDuration / Math.max(gatedDuration, 0.01)).toFixed(1) + 'x'
    };
  } catch (e) {
    return { name: pageInfo.name, error: e.message };
  } finally {
    await page.close();
  }
}

async function main() {
  const browser = await puppeteer.launch({
    executablePath: candidateBrowsers[0],
    headless: true
  });

  const results = [];
  for (const p of TEST_PAGES) {
    process.stdout.write(`Measuring ${p.name}... `);
    const r = await measurePage(browser, p);
    results.push(r);
    console.log(`Unconditional: ${r.unconditionalMs?.toFixed(2)}ms -> Gated: ${r.gatedMs?.toFixed(2)}ms (${r.speedup})`);
  }

  await browser.close();
  fs.writeFileSync('benchmark/scan_time_measurements.json', JSON.stringify(results, null, 2), 'utf8');
}

main();
