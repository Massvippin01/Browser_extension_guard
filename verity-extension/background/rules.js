/**
 * rules.js - Pure functions for evaluating website authenticity.
 * Each function returns an object: { score: number, reason: string|null, triggered: boolean }
 * The score is a partial risk contribution (0-100).
 */

/**
 * Parses a URL string safely. Returns null if invalid.
 * @param {string} urlString
 * @returns {URL|null}
 */
function safeParseUrl(urlString) {
  try {
    return new URL(urlString);
  } catch (e) {
    return null;
  }
}

/**
 * Rule 1: Detect URLs using a raw IPv4 address as the hostname.
 * @param {string} urlString
 */
export function isIpBasedUrl(urlString) {
  const url = safeParseUrl(urlString);
  if (!url) return { score: 0, reason: null, triggered: false };
  
  // Exclude non-web schemes
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { score: 0, reason: null, triggered: false };
  }

  // Regex to match a standard IPv4 address
  const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  
  if (ipv4Regex.test(url.hostname)) {
    return {
      score: 80,
      reason: "The URL uses a raw IP address instead of a domain name.",
      triggered: true
    };
  }

  return { score: 0, reason: null, triggered: false };
}

/**
 * Rule 2: Flag pages that are not HTTPS (e.g., HTTP).
 * Ignores chrome://, file://, etc.
 * @param {string} urlString
 */
export function hasMissingHttps(urlString) {
  const url = safeParseUrl(urlString);
  if (!url) return { score: 0, reason: null, triggered: false };
  
  if (url.protocol === 'http:') {
    // Exclude localhost from missing HTTPS penalty usually, but for strictness we'll apply a moderate score.
    // If it's a known non-web protocol (like file:, chrome:, about:), we don't trigger.
    return {
      score: 40,
      reason: "The connection is not secure (HTTP instead of HTTPS).",
      triggered: true
    };
  }

  return { score: 0, reason: null, triggered: false };
}

/**
 * Rule 3: Flag URLs containing more than two subdomain levels.
 * e.g. a.b.example.com has 2 subdomains (a, b) and a base domain (example.com).
 * @param {string} urlString
 */
export function hasExcessiveSubdomains(urlString) {
  const url = safeParseUrl(urlString);
  if (!url) return { score: 0, reason: null, triggered: false };
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { score: 0, reason: null, triggered: false };
  }

  // Very basic approximation for base domains. 
  // We assume the last two parts form the registrable domain (e.g., example.com)
  // For domains like co.uk, it would be 3 parts. 
  // Limitation: A full PSL is needed for accuracy.
  const parts = url.hostname.split('.');
  
  // Basic heuristic: if > 4 parts, it's highly likely it has excessive subdomains (e.g. 1.2.3.example.com)
  if (parts.length > 4) {
    return {
      score: 30,
      reason: "The URL uses an unusually high number of subdomains.",
      triggered: true
    };
  }

  return { score: 0, reason: null, triggered: false };
}

/**
 * Rule 4: Brand Impersonation Rule
 * Detect when a protected brand name appears in the URL but the actual domain does not belong to that brand.
 * @param {string} urlString
 * @param {Array} brandsList - Array of objects { name: string, domains: string[] }
 */
export function hasBrandNameInWrongDomain(urlString, brandsList) {
  const url = safeParseUrl(urlString);
  if (!url) return { score: 0, reason: null, triggered: false };
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { score: 0, reason: null, triggered: false };
  }

  if (!brandsList || !Array.isArray(brandsList)) {
    return { score: 0, reason: null, triggered: false };
  }

  const hostname = url.hostname.toLowerCase();
  
  for (const brand of brandsList) {
    const brandNameLower = brand.name.toLowerCase();
    
    // Check if the hostname contains the brand name as a substring
    if (hostname.includes(brandNameLower)) {
      
      // Is the hostname actually one of the legitimate domains or a subdomain of it?
      const isLegit = brand.domains.some(legitDomain => {
        return hostname === legitDomain || hostname.endsWith('.' + legitDomain);
      });

      if (!isLegit) {
        return {
          score: 90,
          reason: `The URL contains the name "${brand.name}" but does not belong to its official domain.`,
          triggered: true
        };
      }
    }
  }

  return { score: 0, reason: null, triggered: false };
}

/**
 * Rule 5: Suspicious URL characteristics (@, excessive hyphens).
 * @param {string} urlString
 */
export function hasSuspiciousUrlPattern(urlString) {
  const url = safeParseUrl(urlString);
  if (!url) return { score: 0, reason: null, triggered: false };
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { score: 0, reason: null, triggered: false };
  }

  // A. Check for '@' symbol in the URL (which might be parsed as auth info by the browser)
  // The URL parser handles auth info, we can check username/password properties
  if (url.username || url.password) {
    return {
      score: 60,
      reason: "The URL contains suspicious credential syntax (e.g., '@' symbol) to hide the real destination.",
      triggered: true
    };
  }

  // B. Excessive hyphens in hostname
  const hyphenCount = (url.hostname.match(/-/g) || []).length;
  if (hyphenCount > 3) {
    return {
      score: 40,
      reason: "The hostname contains an unusually high number of hyphens, typical of deceptive sites.",
      triggered: true
    };
  }

  // C. Suspicious TLD patterns — commonly abused in phishing campaigns
  const suspiciousTlds = [
    '.tk', '.ml', '.ga', '.cf', '.gq',     // Free Freenom TLDs — highest abuse rate
    '.xyz', '.zip', '.info', '.top',        // High abuse generic TLDs
    '.click', '.link', '.online', '.site',  // Common phishing TLDs
    '.pw', '.cc', '.ws', '.biz',            // Known abuse-heavy TLDs
    '.icu', '.fun', '.vip', '.club',        // Often used in scam campaigns
    '.cyou', '.sbs', '.uno', '.cfd',        // New-era phishing TLDs
    '.monster', '.rest', '.skin', '.bar'    // Rare but seen in campaigns
  ];
  if (suspiciousTlds.some(tld => url.hostname.endsWith(tld))) {
    return {
      score: 30,
      reason: "The URL uses a top-level domain frequently associated with spam or abuse.",
      triggered: true
    };
  }

  return { score: 0, reason: null, triggered: false };
}

/**
 * Rule 5b: Ad-redirect / Malvertising URL Pattern Detection
 * Catches real-world ad redirect networks: very long encoded paths, * chars, /cx/ prefixes.
 * Example: wb.omegatootler.rest/cx/<1000-char-blob>
 * @param {string} urlString
 */
export function hasMalvertisingPattern(urlString) {
  const url = safeParseUrl(urlString);
  if (!url) return { score: 0, reason: null, triggered: false };
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { score: 0, reason: null, triggered: false };
  }

  const fullPath = url.pathname + url.search;
  const reasons = [];
  let score = 0;

  // A. Extremely long URL path — classic ad-redirect obfuscation
  // Normal URLs rarely exceed 200 chars of path. 500+ is a strong signal.
  if (fullPath.length > 500) {
    score += 45;
    reasons.push(`Extremely long URL path (${fullPath.length} chars) — typical of ad-redirect obfuscation.`);
  } else if (fullPath.length > 200) {
    score += 20;
    reasons.push('Unusually long URL path — possible redirect chain encoding.');
  }

  // B. Asterisk (*) characters in URL path — NOT valid URL chars, used by ad-redirect networks
  if (url.pathname.includes('*') || url.search.includes('*')) {
    score += 40;
    reasons.push('URL contains asterisk (*) characters — characteristic of ad-redirect tracking networks.');
  }

  // C. Known ad-redirect path prefixes (/cx/, /click/, /go/, /rd/, /redir/, /track/)
  const adPrefixes = ['/cx/', '/rd/', '/redir/', '/click/', '/go/', '/track/', '/redirect/', '/out/', '/r/'];
  if (adPrefixes.some(p => url.pathname.startsWith(p) || url.pathname.includes(p))) {
    score += 20;
    reasons.push('URL path matches known ad-redirect routing pattern.');
  }

  // D. Base64-like blob in path (long run of alphanumeric + _-* without word breaks)
  const base64Blob = /[A-Za-z0-9_\-*]{80,}/.test(url.pathname);
  if (base64Blob) {
    score += 25;
    reasons.push('URL path contains a long encoded payload (base64-like blob).');
  }

  // E. Multiple tracking/fingerprint query params (md=, fc=, cd=, pr= all together)
  const trackingParams = ['md=', 'fc=', 'cd=', 'pr=', 'cid=', 'uid=', 'tid=', 'rid='];
  const presentTrackers = trackingParams.filter(p => url.search.includes(p));
  if (presentTrackers.length >= 3) {
    score += 25;
    reasons.push(`URL contains multiple tracking fingerprint parameters (${presentTrackers.join(', ')}).`);
  }

  if (score > 0) {
    return {
      score: Math.min(score, 100),
      reason: reasons.join(' '),
      triggered: true
    };
  }

  return { score: 0, reason: null, triggered: false };
}

/**
 * Rule 5c: Random-looking hostname detection
 * Catches hostnames like: wb.omegatootler.rest, random-abc123.xyz, etc.
 * These are common in ad-redirect networks, malware C2, and malvertising.
 * @param {string} urlString
 */
export function hasRandomLookingHostname(urlString) {
  const url = safeParseUrl(urlString);
  if (!url) return { score: 0, reason: null, triggered: false };
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { score: 0, reason: null, triggered: false };
  }

  const hostname = url.hostname.toLowerCase();

  // Skip known-legitimate patterns
  const safePrefixes = ['www.', 'mail.', 'api.', 'cdn.', 'static.', 'assets.', 'img.', 'media.'];
  if (safePrefixes.some(p => hostname.startsWith(p))) {
    const base = hostname.replace(/^[a-z]+\./, '');
    // If the base part is a short recognizable word, skip
    if (base.split('.')[0].length < 12) return { score: 0, reason: null, triggered: false };
  }

  // Get the registrable-domain part (second-level domain label)
  const parts = hostname.split('.');
  const domainLabel = parts.length >= 2 ? parts[parts.length - 2] : parts[0];

  // A: Long domain label that doesn't look like a real word
  // Real brand domains are usually short and pronounceable
  if (domainLabel.length > 12) {
    // Check vowel ratio — real words have vowels. Random strings have very low or very high ratios.
    const vowels = (domainLabel.match(/[aeiou]/g) || []).length;
    const vowelRatio = vowels / domainLabel.length;
    // Too few vowels (< 15%) or mixed with digits strongly suggests random generation
    const hasDigitMix = /[0-9]/.test(domainLabel) && /[a-z]/.test(domainLabel);
    const looksRandom = vowelRatio < 0.15 || (hasDigitMix && domainLabel.length > 10);
    
    if (looksRandom) {
      return {
        score: 55,
        reason: `Hostname "${hostname}" appears to be randomly generated — common in ad-redirect and malware infrastructure.`,
        triggered: true
      };
    }
  }

  // B: Domain label contains a suspicious pattern of consonants/digits (no vowel words)
  // "omegatootler" — actually has vowels but is clearly not a real brand word.
  // Detect if it's a nonsense portmanteau or gibberish over 10 chars
  if (domainLabel.length > 10 && !/^(google|amazon|microsoft|facebook|youtube|twitter|instagram|netflix|apple|adobe|paypal|stripe|shopify|cloudflare|github|linkedin|reddit|discord|zoom|slack|notion|atlassian)/.test(domainLabel)) {
    // No known brand prefix — check if it's in a suspicious TLD
    const suspTLDs = ['.rest', '.xyz', '.top', '.pw', '.tk', '.ml', '.click', '.online', '.site', '.fun', '.live', '.vip', '.club', '.icu', '.sbs', '.uno', '.cfd', '.bar', '.monster', '.skin'];
    if (suspTLDs.some(tld => hostname.endsWith(tld))) {
      return {
        score: 50,
        reason: `Hostname "${hostname}" combines an unrecognized domain with a high-risk TLD.`,
        triggered: true
      };
    }
  }

  return { score: 0, reason: null, triggered: false };
}

/**
 * Rule 6: Punycode (homograph) and Suspicious Keywords
 * Detects xn-- domains and keywords like login, verify in the URL.
 * @param {string} urlString
 */
export function hasPunycodeOrKeywords(urlString) {
  const url = safeParseUrl(urlString);
  if (!url) return { score: 0, reason: null, triggered: false };
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { score: 0, reason: null, triggered: false };
  }

  // Punycode check
  if (url.hostname.includes('xn--')) {
    return {
      score: 85,
      reason: "The URL uses Punycode (IDN), which is often used in homograph attacks to spoof legitimate domains.",
      triggered: true
    };
  }

  // Keyword check — path/query/hostname for phishing signals
  const suspiciousKeywords = [
    // Auth / account
    'login', 'signin', 'sign-in', 'logon',
    // Verification
    'verify', 'verification', 'validate', 'confirm',
    // Security
    'secure', 'security', 'protect', 'alert',
    // Account actions
    'account', 'update', 'upgrade', 'recover', 'reset', 'suspend',
    // Financial
    'banking', 'netbanking', 'payment', 'recharge', 'refund', 'cashback',
    // Indian-specific
    'kyc', 'aadhar', 'pan', 'upi', 'otp',
    // Rewards / urgency
    'claim', 'reward', 'prize', 'offer', 'free', 'winner',
    // Support scams
    'helpdesk', 'support', 'customer-care'
  ];
  const fullUrl = url.pathname.toLowerCase() + url.search.toLowerCase() + url.hostname.toLowerCase();
  
  const foundKeywords = suspiciousKeywords.filter(k => fullUrl.includes(k));
  if (foundKeywords.length >= 2) {
    return {
      score: 40,
      reason: `URL contains multiple suspicious keywords: ${foundKeywords.slice(0, 4).join(', ')}.`,
      triggered: true
    };
  }

  return { score: 0, reason: null, triggered: false };
}

/**
 * Rule 7: Financial keyword in hostname (not path)
 * Detects when 'bank', 'banking', 'wallet', 'upi' appear in the actual hostname
 * alongside a non-standard domain (not a known legitimate bank domain).
 * @param {string} urlString
 * @param {Array} brandsList
 */
export function hasFinancialKeywordInHostname(urlString, brandsList) {
  const url = safeParseUrl(urlString);
  if (!url) return { score: 0, reason: null, triggered: false };
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { score: 0, reason: null, triggered: false };
  }

  const hostname = url.hostname.toLowerCase();

  // First check if it's a known-legitimate domain — skip if so
  if (brandsList && Array.isArray(brandsList)) {
    const isLegit = brandsList.some(brand =>
      brand.domains && brand.domains.some(d => hostname === d || hostname.endsWith('.' + d))
    );
    if (isLegit) return { score: 0, reason: null, triggered: false };
  }

  const financialHostKeywords = [
    'bank', 'banking', 'wallet', 'upi', 'netbanking', 'ibank',
    'payment', 'paytm', 'phonepe', 'gpay', 'bhim',
    'kyc', 'loan', 'finance', 'insurance', 'invest',
    'crypto', 'bitcoin', 'nft', 'demat', 'trading'
  ];
  const found = financialHostKeywords.find(k => hostname.includes(k));
  
  if (found) {
    return {
      score: 55,
      reason: `Hostname contains financial keyword "${found}" but is not a verified banking domain.`,
      triggered: true
    };
  }

  return { score: 0, reason: null, triggered: false };
}

/**
 * Rule 8: Brand variant list matching
 * Uses the 'variants' arrays in brands.json for fast exact-match typosquatting detection.
 * Catches known alternate spellings like 'icicl', 'hdfcbankl', etc.
 * @param {string} urlString
 * @param {Array} brandsList
 */
export function hasBrandVariantMatch(urlString, brandsList) {
  const url = safeParseUrl(urlString);
  if (!url) return { score: 0, reason: null, triggered: false };
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { score: 0, reason: null, triggered: false };
  }
  if (!brandsList || !Array.isArray(brandsList)) {
    return { score: 0, reason: null, triggered: false };
  }

  const hostname = url.hostname.toLowerCase().replace(/^www\./, '');

  for (const brand of brandsList) {
    // Skip if it's already a legitimate domain
    const isLegit = brand.domains && brand.domains.some(d =>
      hostname === d || hostname.endsWith('.' + d)
    );
    if (isLegit) continue;

    // Check variants array
    if (brand.variants && Array.isArray(brand.variants)) {
      for (const variant of brand.variants) {
        if (hostname.includes(variant.toLowerCase())) {
          return {
            score: 85,
            reason: `Hostname matches a known typosquat variant of "${brand.name}".`,
            triggered: true
          };
        }
      }
    }
  }

  return { score: 0, reason: null, triggered: false };
}
