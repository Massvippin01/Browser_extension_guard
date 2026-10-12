import fs from 'fs';
import path from 'path';
import puppeteer from 'puppeteer-core';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const iconsDir = path.resolve(__dirname, '../icons');

const candidateBrowsers = [
  process.env.PUPPETEER_EXECUTABLE_PATH,
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
].filter(p => p && fs.existsSync(p));

// VERITY official mark: Shield with check in negative space
// Calm modern emerald/teal gradient with crisp dark/light contrast
function getSvg(themeColor = '#10b981', checkColor = '#ffffff') {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128">
  <defs>
    <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="${themeColor}" />
      <stop offset="100%" stop-color="#059669" />
    </linearGradient>
  </defs>
  <!-- Outer Shield Base -->
  <path d="M64 12 L106 28 C106 72 88 104 64 116 C40 104 22 72 22 28 Z" 
        fill="url(#shieldGrad)" />
  <!-- Negative Space / Cutout Checkmark -->
  <path d="M44 64 L56 76 L85 46" 
        stroke="${checkColor}" 
        stroke-width="12" 
        stroke-linecap="round" 
        stroke-linejoin="round" 
        fill="none" />
</svg>`;
}

async function run() {
  const svgContent = getSvg();
  fs.writeFileSync(path.join(iconsDir, 'verity-logo.svg'), svgContent, 'utf8');
  fs.writeFileSync(path.join(iconsDir, 'safe.svg'), svgContent, 'utf8');

  // Caution and Danger SVGs
  const cautionSvg = getSvg('#f59e0b');
  fs.writeFileSync(path.join(iconsDir, 'caution.svg'), cautionSvg, 'utf8');
  const dangerSvg = getSvg('#ef4444');
  fs.writeFileSync(path.join(iconsDir, 'danger.svg'), dangerSvg, 'utf8');

  console.log('Saved SVG brand assets.');

  const browser = await puppeteer.launch({
    executablePath: candidateBrowsers[0],
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const page = await browser.newPage();

  const sizes = [16, 32, 48, 128];
  for (const size of sizes) {
    const html = `<!DOCTYPE html>
    <html>
      <head>
        <style>
          body { margin: 0; padding: 0; background: transparent; overflow: hidden; display: flex; align-items: center; justify-content: center; }
          svg { width: ${size}px; height: ${size}px; }
        </style>
      </head>
      <body>
        ${svgContent}
      </body>
    </html>`;
    await page.setViewport({ width: size, height: size, deviceScaleFactor: 1 });
    await page.setContent(html, { waitUntil: 'domcontentloaded' });
    const dest = path.join(iconsDir, `safe_${size}.png`);
    await page.screenshot({ path: dest, omitBackground: true });
    console.log(`Generated ${dest} (${size}x${size})`);
  }

  await browser.close();
  console.log('Finished generating brand icons.');
}

run().catch(console.error);
