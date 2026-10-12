/**
 * rich-feature-extractor.js — Rich lexical URL feature extractor for ML inference.
 * Mathematically identical to training/retrain_model.py for parity.
 */

const SUSPICIOUS_TLDS = new Set([
  '.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq',
  '.site', '.online', '.rest', '.click', '.fun', '.info'
]);

const KEYWORDS = [
  'login', 'verify', 'secure', 'account', 'banking', 'update',
  'signin', 'wallet', 'claim', 'otp', 'support', 'auth', 'bill'
];

export function calculateEntropy(text) {
  if (!text || text.length === 0) return 0.0;
  const len = text.length;
  const freq = {};
  for (let i = 0; i < len; i++) {
    const c = text[i];
    freq[c] = (freq[c] || 0) + 1;
  }
  let ent = 0.0;
  for (const c in freq) {
    const p = freq[c] / len;
    ent -= p * Math.log2(p);
  }
  return ent;
}

export function extractRichFeatures(urlString) {
  let url = urlString;
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'http://' + url;
  }

  let hostname = '';
  let pathname = '';
  let search = '';
  try {
    const parsed = new URL(url);
    hostname = (parsed.hostname || '').toLowerCase();
    pathname = parsed.pathname || '';
    search = parsed.search || '';
  } catch (e) {
    hostname = '';
  }

  // 1. Lengths
  const urlLen = url.length;
  const hostLen = hostname.length;
  const pathLen = pathname.length;

  // 2. Digit ratios
  let digits = 0;
  for (let i = 0; i < urlLen; i++) {
    const code = url.charCodeAt(i);
    if (code >= 48 && code <= 57) digits++;
  }
  const digitRatio = digits / Math.max(urlLen, 1);

  let hostDigits = 0;
  for (let i = 0; i < hostLen; i++) {
    const code = hostname.charCodeAt(i);
    if (code >= 48 && code <= 57) hostDigits++;
  }
  const hostDigitRatio = hostDigits / Math.max(hostLen, 1);

  // 3. Host Entropy
  const hostEntropy = calculateEntropy(hostname);

  // 4. Special character counts
  const dotCount = (url.match(/\./g) || []).length;
  const hyphenCount = (url.match(/-/g) || []).length;
  const atCount = (url.match(/@/g) || []).length;
  const slashCount = (url.match(/\//g) || []).length;
  const queryCount = (url.match(/\?/g) || []).length;
  const equalCount = (url.match(/=/g) || []).length;

  // 5. Host token count (split by . and -)
  const hostTokens = hostname.split(/[\.-]/).length;

  // 6. Structural flags
  const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const isIp = ipv4Regex.test(hostname) ? 1.0 : 0.0;
  const isHttps = url.startsWith('https://') ? 1.0 : 0.0;

  const lastDoubleSlash = url.lastIndexOf('//');
  const doubleSlash = (lastDoubleSlash > 7) ? 1.0 : 0.0;

  // 7. Suspicious TLD & Keywords
  let isSuspiciousTld = 0.0;
  for (const tld of SUSPICIOUS_TLDS) {
    if (hostname.endsWith(tld)) {
      isSuspiciousTld = 1.0;
      break;
    }
  }

  const urlLower = url.toLowerCase();
  let keywordMatches = 0.0;
  for (const kw of KEYWORDS) {
    if (urlLower.includes(kw)) keywordMatches++;
  }

  return [
    urlLen, hostLen, pathLen, digitRatio, hostDigitRatio,
    hostEntropy, dotCount, hyphenCount, atCount, slashCount,
    queryCount, equalCount, hostTokens, isIp, isHttps,
    doubleSlash, isSuspiciousTld, keywordMatches
  ];
}
