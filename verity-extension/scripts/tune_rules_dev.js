import fs from 'fs';
import brands from '../brands.json' with { type: 'json' };

const data = JSON.parse(fs.readFileSync('benchmark/test_urls.json', 'utf8'));
const devItems = data.filter(d => d.split === 'dev');
const safeDev = devItems.filter(d => d.label === 'safe');
const phishDev = devItems.filter(d => d.label === 'phishing');
const malwareDev = devItems.filter(d => d.label === 'malware');

function calcEntropy(str) {
  if (!str) return 0;
  const map = {};
  for (const c of str) map[c] = (map[c] || 0) + 1;
  let ent = 0;
  for (const c in map) {
    const p = map[c] / str.length;
    ent -= p * Math.log2(p);
  }
  return ent;
}

// Tuned candidate for hasRandomLookingHostname
function tunedRandomHostname(urlString) {
  let url;
  try { url = new URL(urlString); } catch(e) { return { triggered: false }; }
  if (!['http:', 'https:'].includes(url.protocol)) return { triggered: false };

  const hostname = url.hostname.toLowerCase();
  const safeLabels = new Set(['www', 'mail', 'api', 'cdn', 'static', 'assets', 'img', 'media', 'blog', 'shop', 'store', 'news', 'help', 'support', 'app', 'dev']);
  const parts = hostname.split('.');
  const labelsToCheck = parts.length > 1 ? parts.slice(0, -1) : parts;
  const tld = parts.length > 1 ? '.' + parts[parts.length - 1] : '';
  const suspTLDs = new Set(['.rest', '.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq', '.click', '.online', '.site', '.fun', '.icu', '.sbs', '.cfd', '.monster', '.skin', '.qpon']);

  for (const label of labelsToCheck) {
    if (safeLabels.has(label)) continue;

    // Split on hyphens to inspect tokens
    const subTokens = label.split('-');
    for (const tok of subTokens) {
      if (tok.length < 8) continue;
      
      // Hex hash check (e.g. md5 / uuid / random hex string)
      if (tok.length >= 16 && /^[0-9a-f]+$/i.test(tok)) {
        return { score: 65, reason: `Hostname "${hostname}" contains a hex hash label ("${tok}") — signature of ad-redirect & malware DGA infrastructure.`, triggered: true };
      }

      // Consonant cluster (6+ consecutive strict consonants without a,e,i,o,u,y)
      if (/[bcdfghjklmnpqrstvwxz]{6,}/i.test(tok)) {
        return { score: 65, reason: `Hostname "${hostname}" contains unpronounceable consonant sequence ("${tok}") — signature of ad-redirect & malware DGA infrastructure.`, triggered: true };
      }

      // Extreme low vowel ratio on long single tokens
      if (tok.length >= 10) {
        const vowels = (tok.match(/[aeiou]/g) || []).length;
        const vowelRatio = vowels / tok.length;
        const entropy = calcEntropy(tok);

        if (vowelRatio < 0.10 && tok.length >= 10) {
          return { score: 65, reason: `Hostname "${hostname}" contains a randomly generated label ("${tok}") — signature of ad-redirect & malware DGA infrastructure.`, triggered: true };
        }

        if (entropy > 3.6 && suspTLDs.has(tld)) {
          return { score: 65, reason: `Hostname "${hostname}" uses a synthetic DGA domain label ("${tok}") on a high-risk TLD.`, triggered: true };
        }
      }
    }
  }
  return { score: 0, reason: null, triggered: false };
}

// Tuned candidate for hasFinancialKeywordInHostname
function tunedFinancialKeyword(urlString, brandsList) {
  let url;
  try { url = new URL(urlString); } catch(e) { return { triggered: false }; }
  if (!['http:', 'https:'].includes(url.protocol)) return { triggered: false };

  const hostname = url.hostname.toLowerCase();

  // Known legitimate brands check
  if (brandsList && Array.isArray(brandsList)) {
    const isLegit = brandsList.some(brand =>
      brand.domains && brand.domains.some(d => hostname === d || hostname.endsWith('.' + d))
    );
    if (isLegit) return { score: 0, reason: null, triggered: false };
  }

  // Check known trusted/banking portals or established legitimate financial sites
  const knownLegitExact = new Set([
    'bhimupi.org.in', 'npci.org.in', 'investopedia.com', 'tradingview.com',
    'bankofamerica.com', 'chase.com', 'wellsfargo.com', 'citi.com', 'citibank.com',
    'capitalone.com', 'barclays.co.uk', 'hsbc.co.uk', 'lloydsbank.com',
    'hdfcbank.com', 'icicibank.com', 'axisbank.com', 'kotak.com', 'sbi.co.in', 'onlinesbi.sbi'
  ]);
  if (knownLegitExact.has(hostname) || [...knownLegitExact].some(d => hostname.endsWith('.' + d))) {
    return { score: 0, reason: null, triggered: false };
  }

  // Split hostname into labels excluding public suffix/TLD
  const parts = hostname.split('.');
  if (parts.length <= 1) return { score: 0, reason: null, triggered: false };
  // Check hostname labels up to the second-to-last (domain)
  const domainAndSubdomains = parts.slice(0, -1).join('.');

  const financialHostKeywords = [
    'netbanking', 'ibank', 'webwallet', 'wallet', 'kyc', 'upi',
    'paytm', 'phonepe', 'gpay', 'bhim'
  ];

  // Also check 'bank' or 'banking' but avoid benign substring matches like 'dbankcloud'
  for (const kw of financialHostKeywords) {
    if (domainAndSubdomains.includes(kw)) {
      return {
        score: 55,
        reason: `Hostname contains financial keyword "${kw}" on an unverified domain.`,
        triggered: true
      };
    }
  }

  // Check 'bank' / 'banking' on subdomains or with hyphen/token boundary
  const bankMatch = /(?:^|[-.])(?:net)?banking?(?:[-.]|$)/i.test(domainAndSubdomains) ||
                    /(?:[-.])bank(?:[-.]|$)/i.test(domainAndSubdomains);
  if (bankMatch) {
    return {
      score: 55,
      reason: `Hostname contains banking keyword on an unverified domain.`,
      triggered: true
    };
  }

  return { score: 0, reason: null, triggered: false };
}

console.log('=== EVALUATION ON DEV SPLIT ONLY ===');
const safeFPs = safeDev.filter(d => tunedRandomHostname(d.url).triggered);
const phishTPs = phishDev.filter(d => tunedRandomHostname(d.url).triggered);
const malwTPs = malwareDev.filter(d => tunedRandomHostname(d.url).triggered);

console.log('hasRandomLookingHostname (Tuned):');
console.log(`  Safe FP: ${safeFPs.length} / ${safeDev.length} (${(safeFPs.length/safeDev.length*100).toFixed(2)}%)`);
console.log(`  Phish TP: ${phishTPs.length} / ${phishDev.length} (${(phishTPs.length/phishDev.length*100).toFixed(2)}%)`);
console.log(`  Malware TP: ${malwTPs.length} / ${malwareDev.length} (${(malwTPs.length/malwareDev.length*100).toFixed(2)}%)`);
if (safeFPs.length > 0) console.log('  Safe FP examples:', safeFPs.slice(0, 5).map(d => d.url));

const finSafeFPs = safeDev.filter(d => tunedFinancialKeyword(d.url, brands).triggered);
const finPhishTPs = phishDev.filter(d => tunedFinancialKeyword(d.url, brands).triggered);
const finMalwTPs = malwareDev.filter(d => tunedFinancialKeyword(d.url, brands).triggered);

console.log('\nhasFinancialKeywordInHostname (Tuned):');
console.log(`  Safe FP: ${finSafeFPs.length} / ${safeDev.length} (${(finSafeFPs.length/safeDev.length*100).toFixed(2)}%)`);
console.log(`  Phish TP: ${finPhishTPs.length} / ${phishDev.length} (${(finPhishTPs.length/phishDev.length*100).toFixed(2)}%)`);
console.log(`  Malware TP: ${finMalwTPs.length} / ${malwareDev.length} (${(finMalwTPs.length/malwareDev.length*100).toFixed(2)}%)`);
if (finSafeFPs.length > 0) console.log('  Safe FP examples:', finSafeFPs.map(d => d.url));
