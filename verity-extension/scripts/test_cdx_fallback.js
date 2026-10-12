import { getDomain } from '../shared/psl.js';

async function fetchWithTimeout(url, opts = {}, timeoutMs = 3500) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...opts, signal: controller.signal });
    clearTimeout(id);
    return res;
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}

async function testSingleDomain(domain) {
  console.log(`Testing CDX for domain: ${domain}...`);
  try {
    const cdxUrl = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}/*&fl=original&collapse=urlkey&filter=statuscode:200&limit=5`;
    const res = await fetchWithTimeout(cdxUrl);
    if (res.ok) {
      const text = await res.text();
      const urls = text.trim().split('\n').filter(Boolean);
      console.log(`CDX Success for ${domain}: ${urls.length} URLs`);
      return { success: true, source: 'wayback-cdx', urls };
    }
    console.log(`CDX HTTP ${res.status} for ${domain}`);
  } catch (err) {
    console.log(`CDX Failed/Timed-out for ${domain}: ${err.message}`);
  }

  // Fallback: Direct crawl of homepage / sitemap
  console.log(`Running fallback crawl for ${domain}...`);
  try {
    const siteUrl = `https://${domain}/`;
    const res = await fetchWithTimeout(siteUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml'
      }
    }, 4000);
    if (res.ok) {
      const html = await res.text();
      // Extract links with paths and query params
      const linkRegex = /href=["'](https?:\/\/[^"'>\s]+|\/[a-zA-Z0-9_\-\.\/?&=%#]+)["']/gi;
      const found = new Set();
      let m;
      while ((m = linkRegex.exec(html)) !== null) {
        let u = m[1];
        if (u.startsWith('/')) {
          u = `https://${domain}${u}`;
        }
        try {
          const parsed = new URL(u);
          if (getDomain(parsed.hostname) === getDomain(domain) && parsed.pathname.length > 1) {
            found.add(u);
          }
        } catch {}
      }
      console.log(`Fallback Success for ${domain}: ${found.size} deep links found`);
      return { success: true, source: 'fallback:direct_crawl', urls: [...found] };
    }
  } catch (err) {
    console.log(`Fallback Failed for ${domain}: ${err.message}`);
  }

  return { success: false };
}

testSingleDomain('wikipedia.org')
  .then(() => testSingleDomain('github.com'))
  .then(() => process.exit(0));
