import { getDomain, getPublicSuffix, getSubdomain } from '../shared/psl.js';
import { isAllowlistedDomain } from '../shared/legit-domains.js';
import { t } from '../shared/messages.js';

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
  if (!url) return { id: null, params: {}, score: 0, reason: null, triggered: false };
  
  // Exclude non-web schemes
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { id: null, params: {}, score: 0, reason: null, triggered: false };
  }

  // Regex to match a standard IPv4 address
  const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  
  if (ipv4Regex.test(url.hostname)) {
    return {
      id: 'RULE_IP_BASED_URL',
      params: { ip: url.hostname },
      score: 80,
      reason: t('RULE_IP_BASED_URL', { ip: url.hostname }),
      triggered: true
    };
  }

  return { id: null, params: {}, score: 0, reason: null, triggered: false };
}

/**
 * Rule 2: Flag pages that are not HTTPS (e.g., HTTP).
 * Ignores chrome://, file://, etc.
 * @param {string} urlString
 */
export function hasMissingHttps(urlString) {
  const url = safeParseUrl(urlString);
  if (!url) return { id: null, params: {}, score: 0, reason: null, triggered: false };
  
  if (url.protocol === 'http:') {
    return {
      id: 'RULE_MISSING_HTTPS',
      params: {},
      score: 40,
      reason: t('RULE_MISSING_HTTPS'),
      triggered: true
    };
  }

  return { id: null, params: {}, score: 0, reason: null, triggered: false };
}

/**
 * Rule 3: Flag URLs containing more than two subdomain levels.
 * e.g. a.b.example.com has 2 subdomains (a, b) and a base domain (example.com).
 * @param {string} urlString
 */
export function hasExcessiveSubdomains(urlString) {
  const url = safeParseUrl(urlString);
  if (!url) return { id: null, params: {}, score: 0, reason: null, triggered: false };
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { id: null, params: {}, score: 0, reason: null, triggered: false };
  }

  const subdomain = getSubdomain(url.hostname);
  if (subdomain) {
    const subParts = subdomain.split('.');
    if (subParts.length >= 3) {
      return {
        id: 'RULE_EXCESSIVE_SUBDOMAINS',
        params: { count: subParts.length },
        score: 30,
        reason: t('RULE_EXCESSIVE_SUBDOMAINS', { count: subParts.length }),
        triggered: true
      };
    }
  }

  return { id: null, params: {}, score: 0, reason: null, triggered: false };
}

const PHISHING_LURE_KEYWORDS = [
  'login', 'signin', 'sign-in', 'logon', 'log',
  'secure', 'security', 'sec', 'safe',
  'verify', 'verification', 'verif', 'val', 'auth',
  'update', 'upgrade', 'renew', 'recovery', 'recover', 'reset',
  'account', 'acct', 'myaccount', 'user', 'portal', 'client',
  'online', 'web', 'net', 'netbanking', 'banking', 'bank',
  'kyc', 'otp', 'pin', 'card', 'bill', 'pay', 'payment', 'wallet',
  'help', 'support', 'desk', 'care', 'service', 'services', 'serv',
  'alert', 'notice', 'confirm', 'confirmation', 'claim', 'reward',
  'mobile', 'app', 'access', 'connect', 'center', 'centre',
  'broadband', 'network', 'telecom', 'official', 'protect'
];

function escapeRegExp(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Checks if a candidate term matches a hostname, using remainder analysis:
 * - A delimiter-separated match (^|[-.])term([-.]|$) is always strong.
 * - An exact token match (empty remainder) is always strong.
 * - A concatenated substring match is strong ONLY if the remainder contains a phishing/lure keyword,
 *   a numeric/single-character prefix (e.g. 03chase, nfacebook), or common inflection suffix (e.g. whatsapper).
 * - A remainder that is another plain word (e.g. 'city' in 'cityunionbank') is weak and returns false.
 */
function isBrandMatchWithRemainder(hostname, term) {
  if (!term || term.length < 3) return false;

  // Case 1: Delimiter-separated token (^|[-.])term([-.]|$) -> STRONG
  const delimRegex = new RegExp(`(^|[-.])${escapeRegExp(term)}([-.]|$)`, 'i');
  if (delimRegex.test(hostname)) return true;

  // Case 2: Substring inside a token -> require remainder analysis
  if (!hostname.includes(term)) return false;

  const labels = hostname.split('.');
  for (const label of labels) {
    const tokens = label.split('-');
    for (const tok of tokens) {
      if (tok.includes(term)) {
        const idx = tok.indexOf(term);
        const prefix = tok.slice(0, idx);
        const suffix = tok.slice(idx + term.length);

        if (!prefix && !suffix) return true;

        const remainderParts = [prefix, suffix].filter(Boolean);
        const hasLure = remainderParts.some(part =>
          PHISHING_LURE_KEYWORDS.some(kw => part.includes(kw) || (kw.includes(part) && part.length >= 3))
        );
        const isNumericOrShortPrefix = /^[0-9]+$/.test(prefix) || (prefix.length === 1 && term.length >= 6);
        const isInflectionSuffix = /^(?:er|app|apps)$/.test(suffix);

        if (hasLure || isNumericOrShortPrefix || isInflectionSuffix) {
          return true;
        }
      }
    }
  }

  return false;
}

/**
 * Rule 4: Brand Impersonation Rule
 * Detect when a protected brand name appears in the URL but the actual domain does not belong to that brand.
 * @param {string} urlString
 * @param {Array} brandsList - Array of objects { name: string, domains: string[] }
 */
export function hasBrandNameInWrongDomain(urlString, brandsList) {
  const url = safeParseUrl(urlString);
  if (!url) return { id: null, params: {}, score: 0, reason: null, triggered: false };
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { id: null, params: {}, score: 0, reason: null, triggered: false };
  }

  if (!brandsList || !Array.isArray(brandsList)) {
    return { id: null, params: {}, score: 0, reason: null, triggered: false };
  }

  const hostname = url.hostname.toLowerCase();
  if (isAllowlistedDomain(hostname)) {
    return { id: null, params: {}, score: 0, reason: null, triggered: false };
  }
  
  for (const brand of brandsList) {
    const brandToken = brand.name.toLowerCase().replace(/\s+/g, '');
    const match = isBrandMatchWithRemainder(hostname, brandToken);
    
    if (match) {
      // Is the hostname actually one of the legitimate domains or a subdomain of it?
      const isLegit = brand.domains.some(legitDomain => {
        return hostname === legitDomain || hostname.endsWith('.' + legitDomain);
      });

      if (!isLegit) {
        return {
          id: 'RULE_BRAND_NAME_WRONG_DOMAIN',
          params: { brand: brand.name },
          score: 90,
          reason: t('RULE_BRAND_NAME_WRONG_DOMAIN', { brand: brand.name }),
          triggered: true
        };
      }
    }
  }

  return { id: null, params: {}, score: 0, reason: null, triggered: false };
}

/**
 * Rule 5: Suspicious URL characteristics (@, excessive hyphens).
 * @param {string} urlString
 */
export function hasSuspiciousUrlPattern(urlString) {
  const url = safeParseUrl(urlString);
  if (!url) return { id: null, params: {}, score: 0, reason: null, triggered: false };
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { id: null, params: {}, score: 0, reason: null, triggered: false };
  }

  // A. Check for '@' symbol in the URL (which might be parsed as auth info by the browser)
  if (url.username || url.password) {
    return {
      id: 'RULE_SUSPICIOUS_URL_PATTERN',
      params: { pattern: '@' },
      score: 60,
      reason: t('RULE_SUSPICIOUS_URL_PATTERN', { pattern: '@' }),
      triggered: true
    };
  }

  // B. Excessive hyphens in hostname
  const hyphenCount = (url.hostname.match(/-/g) || []).length;
  if (hyphenCount > 3) {
    return {
      id: 'RULE_SUSPICIOUS_URL_PATTERN',
      params: { pattern: 'hyphens', count: hyphenCount },
      score: 40,
      reason: t('RULE_SUSPICIOUS_URL_PATTERN', { pattern: 'hyphens', count: hyphenCount }),
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
    '.monster', '.rest', '.skin', '.bar',   // Rare but seen in campaigns
    '.qpon', '.world'                       // Commonly abused in ad-redirects
  ];
  const matchedTld = suspiciousTlds.find(tld => url.hostname.endsWith(tld));
  if (matchedTld) {
    return {
      id: 'RULE_SUSPICIOUS_URL_PATTERN',
      params: { pattern: 'tld', tld: matchedTld },
      score: 30,
      reason: t('RULE_SUSPICIOUS_URL_PATTERN', { pattern: 'tld', tld: matchedTld }),
      triggered: true
    };
  }

  return { id: null, params: {}, score: 0, reason: null, triggered: false };
}

export function isTrustedTopDomain(hostname) {
  if (!hostname) return false;
  const h = hostname.toLowerCase();
  const trustedList = [
    'google.com', 'youtube.com', 'gmail.com', 'microsoft.com', 'login.microsoftonline.com',
    'live.com', 'office.com', 'apple.com', 'icloud.com', 'amazon.com',
    'facebook.com', 'meta.com', 'instagram.com', 'github.com', 'linkedin.com',
    'twitter.com', 'x.com', 'netflix.com', 'paypal.com', 'stripe.com',
    'adobe.com', 'shopify.com', 'cloudflare.com', 'dropbox.com', 'zoom.us',
    'slack.com', 'atlassian.com', 'notion.so', 'wikipedia.org', 'yahoo.com',
    'bing.com', 'wordpress.com', 'reddit.com'
  ];
  return trustedList.some(d => h === d || h.endsWith('.' + d));
}

/**
 * Rule 5b: Ad-redirect / Malvertising URL Pattern Detection
 * Catches real-world ad redirect networks: very long encoded paths, * chars, /cx/ prefixes.
 * @param {string} urlString
 */
export function hasMalvertisingPattern(urlString) {
  const url = safeParseUrl(urlString);
  if (!url) return { id: null, params: {}, score: 0, reason: null, triggered: false };
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { id: null, params: {}, score: 0, reason: null, triggered: false };
  }

  // Exempt official trusted top domains (OAuth flow parameters are expected)
  if (isTrustedTopDomain(url.hostname)) {
    return { id: null, params: {}, score: 0, reason: null, triggered: false };
  }

  const fullPath = url.pathname + url.search;
  let score = 0;

  // A. Extremely long URL path — classic ad-redirect obfuscation
  if (fullPath.length > 500) {
    score += 55;
  } else if (fullPath.length > 200) {
    score += 20;
  }

  // B. Asterisk (*) characters in URL path
  if (url.pathname.includes('*') || url.search.includes('*')) {
    score += 40;
  }

  // C. Known ad-redirect path prefixes
  const adPrefixes = ['/cx/', '/rd/', '/redir/', '/click/', '/go/', '/track/', '/redirect/', '/out/', '/r/', '/partitial/', '/partial/', '/direct/', '/zone/', '/pop/', '/link2/', '/sl/', '/play/', '/watch/', '/stream/', '/embed/'];
  if (adPrefixes.some(p => url.pathname.startsWith(p) || url.pathname.includes(p))) {
    score += 30;
  }

  // Check for numeric/alpha campaign/media ID in path
  if (/\/[a-z]{2,12}\/([a-z]{0,4}[0-9]{5,12})/i.test(url.pathname)) {
    score += 30;
  }

  // D. Base64-like blob in path
  const base64Blob = /[A-Za-z0-9_\-*%]{80,}/.test(url.pathname);
  if (base64Blob) {
    score += 35;
  }

  // E. Multiple tracking/fingerprint query params
  const trackingParams = ['md=', 'fc=', 'cd=', 'pr=', 'cid=', 'uid=', 'tid=', 'rid='];
  const presentTrackers = trackingParams.filter(p => url.search.includes(p));
  if (presentTrackers.length >= 3) {
    score += 25;
  }

  // F. Mixed-case alphanumeric tracking token in path
  const pathClean = url.pathname.replace(/^\/|\/$/g, '');
  if (/^[A-Za-z0-9_-]{8,35}$/.test(pathClean)) {
    const hasUpper = /[A-Z]/.test(pathClean);
    const hasLower = /[a-z]/.test(pathClean);
    const hasNum = /[0-9]/.test(pathClean);
    if ((hasUpper && hasLower && hasNum) || (hasUpper && hasNum && pathClean.length >= 10)) {
      score += 45;
    }
  }

  if (score > 0) {
    return {
      id: 'RULE_MALVERTISING_REDIRECT',
      params: {},
      score: Math.min(score, 100),
      reason: t('RULE_MALVERTISING_REDIRECT'),
      triggered: true
    };
  }

  return { id: null, params: {}, score: 0, reason: null, triggered: false };
}

/**
 * Rule 5d: Affiliate Tracker / Ad Tracker URL Pattern Detection
 * @param {string} urlString
 */
export function hasAffiliateTrackerPattern(urlString) {
  const url = safeParseUrl(urlString);
  if (!url) return { id: null, params: {}, score: 0, reason: null, triggered: false };
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { id: null, params: {}, score: 0, reason: null, triggered: false };
  }

  let score = 0;
  const queryKeys = Array.from(url.searchParams.keys()).map(k => k.toLowerCase());
  const queryValues = Array.from(url.searchParams.values());
  
  const trackerKeywords = ['campaign_id', 'click_id', 'creative_id', 'aff_id', 'source', 'utm_source'];
  const presentTrackers = trackerKeywords.filter(k => queryKeys.includes(k));
  
  const genericTrackers = [
    'ymid', 'var', 'var_1', 'var_2', 'var_3', 'z', 'sz', 'zoneid', 'zone', 'pop', 'cost', 'rev',
    'p1', 'p2', 'p3', 'p4', 'p5', 'p6', 'p7', 'pub_rfid', 'pubid', 'sub1', 'sub2', 'clickid', 'aff_sub',
    's1', 's2', 's3', 'ab2r', 'rhd', 'sf', 'os_version', 'browser_version', 'platform', 'architecture'
  ];
  const presentGenericTrackers = genericTrackers.filter(k => queryKeys.includes(k));

  const parts = url.hostname.toLowerCase().split('.');
  const domainLabel = parts.length >= 2 ? parts[parts.length - 2] : parts[0];
  const isMixedDigitLabel = /^[a-z]{2,5}[0-9]{2,5}$/i.test(domainLabel);
  if (isMixedDigitLabel) {
    score += 25;
  }

  const uuidRegex = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
  const hashRegex = /^[a-f0-9]{32,64}$/i;
  const hasUuidOrHashValue = queryValues.some(v => uuidRegex.test(v) || hashRegex.test(v));
  
  const path = url.pathname.replace(/^\/|\/$/g, '');
  const pathIsUuid = uuidRegex.test(path);

  if (presentTrackers.length >= 2) score += 35;
  if (presentGenericTrackers.length >= 3) score += 45;
  else if (presentGenericTrackers.length >= 1) score += 25;

  if (hasUuidOrHashValue) score += 30;
  else if (pathIsUuid) score += 25;

  if (score >= 40) {
    return {
      id: 'RULE_AFFILIATE_TRACKER',
      params: {},
      score: Math.min(score + 25, 100),
      reason: t('RULE_AFFILIATE_TRACKER'),
      triggered: true
    };
  } else if (score > 0) {
    return {
      id: 'RULE_AFFILIATE_TRACKER',
      params: {},
      score: Math.min(score + 15, 100),
      reason: t('RULE_AFFILIATE_TRACKER'),
      triggered: true
    };
  }

  return { id: null, params: {}, score: 0, reason: null, triggered: false };
}

function calcLabelEntropy(str) {
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

/**
 * Rule 5c: Random-looking hostname detection
 * @param {string} urlString
 */
export function hasRandomLookingHostname(urlString) {
  const url = safeParseUrl(urlString);
  if (!url) return { id: null, params: {}, score: 0, reason: null, triggered: false };
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { id: null, params: {}, score: 0, reason: null, triggered: false };
  }

  const hostname = url.hostname.toLowerCase();
  const safeLabels = new Set(['www', 'mail', 'api', 'cdn', 'static', 'assets', 'img', 'media', 'blog', 'shop', 'store', 'news', 'help', 'support', 'app', 'dev']);
  const parts = hostname.split('.');
  const labelsToCheck = parts.length > 1 ? parts.slice(0, -1) : parts;
  const tld = parts.length > 1 ? '.' + parts[parts.length - 1] : '';
  const suspTLDs = new Set(['.rest', '.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq', '.click', '.online', '.site', '.fun', '.icu', '.sbs', '.cfd', '.monster', '.skin', '.qpon']);

  for (const label of labelsToCheck) {
    if (safeLabels.has(label)) continue;
    const subTokens = label.split('-');
    for (const tok of subTokens) {
      if (tok.length < 8) continue;

      if (tok.length >= 16 && /^[0-9a-f]+$/i.test(tok)) {
        return {
          id: 'RULE_RANDOM_LOOKING_HOSTNAME',
          params: { entropy: tok },
          score: 65,
          reason: t('RULE_RANDOM_LOOKING_HOSTNAME', { entropy: tok }),
          triggered: true
        };
      }

      if (/[bcdfghjklmnpqrstvwxz]{6,}/i.test(tok)) {
        return {
          id: 'RULE_RANDOM_LOOKING_HOSTNAME',
          params: { entropy: tok },
          score: 65,
          reason: t('RULE_RANDOM_LOOKING_HOSTNAME', { entropy: tok }),
          triggered: true
        };
      }

      if (tok.length >= 10) {
        const vowels = (tok.match(/[aeiouy]/g) || []).length;
        const vowelRatio = vowels / tok.length;
        const entropy = calcLabelEntropy(tok);

        if (vowelRatio < 0.12 && tok.length >= 10) {
          return {
            id: 'RULE_RANDOM_LOOKING_HOSTNAME',
            params: { entropy: tok },
            score: 65,
            reason: t('RULE_RANDOM_LOOKING_HOSTNAME', { entropy: tok }),
            triggered: true
          };
        }

        if (entropy > 3.6 && suspTLDs.has(tld)) {
          return {
            id: 'RULE_RANDOM_LOOKING_HOSTNAME',
            params: { entropy: tok },
            score: 65,
            reason: t('RULE_RANDOM_LOOKING_HOSTNAME', { entropy: tok }),
            triggered: true
          };
        }
      }
    }
  }

  return { id: null, params: {}, score: 0, reason: null, triggered: false };
}

/**
 * Rule 9: Piracy / Illegal Media Streaming & High-Risk TLD Rule
 * @param {string} urlString
 */
export function hasPiracyOrUnverifiedMediaPattern(urlString) {
  const url = safeParseUrl(urlString);
  if (!url) return { id: null, params: {}, score: 0, reason: null, triggered: false };
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { id: null, params: {}, score: 0, reason: null, triggered: false };
  }

  const hostname = url.hostname.toLowerCase();
  const piracyKeywords = [
    'tamilgun', 'moviesda', 'isaimini', 'tamilyogi', 'movierulz', 'bolly4u',
    'khatrimaza', 'filmywap', 'cinemavilla', '123movies', 'fmovies', 'putlocker',
    'piratebay', 'yts', 'eztv', 'rarbg', 'torrent', 'getintopc', 'oceanofgames',
    'crackpack', 'keygen', 'cracked', 'repack', 'fitgirl', 'skidrow'
  ];
  const highRiskMediaTLDs = ['.ninja', '.mov', '.film', '.video', '.download', '.xyz', '.top', '.click', '.world', '.site', '.work', '.rest', '.online'];

  const matchedKeyword = piracyKeywords.find(k => hostname.includes(k));
  const matchedTLD = highRiskMediaTLDs.find(tld => hostname.endsWith(tld));

  if (matchedKeyword && matchedTLD) {
    return {
      id: 'RULE_PIRACY_MEDIA',
      params: {},
      score: 85,
      reason: t('RULE_PIRACY_MEDIA'),
      triggered: true
    };
  } else if (matchedKeyword) {
    return {
      id: 'RULE_PIRACY_MEDIA',
      params: {},
      score: 60,
      reason: t('RULE_PIRACY_MEDIA'),
      triggered: true
    };
  } else if (matchedTLD && (url.pathname.includes('download') || url.pathname.includes('play') || url.pathname.includes('watch'))) {
    return {
      id: 'RULE_PIRACY_MEDIA',
      params: {},
      score: 50,
      reason: t('RULE_PIRACY_MEDIA'),
      triggered: true
    };
  }

  return { id: null, params: {}, score: 0, reason: null, triggered: false };
}

/**
 * Rule 6: Punycode (homograph) and Suspicious Keywords
 * @param {string} urlString
 */
export function hasPunycodeOrKeywords(urlString) {
  const url = safeParseUrl(urlString);
  if (!url) return { id: null, params: {}, score: 0, reason: null, triggered: false };
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { id: null, params: {}, score: 0, reason: null, triggered: false };
  }

  if (isTrustedTopDomain(url.hostname)) {
    return { id: null, params: {}, score: 0, reason: null, triggered: false };
  }

  // Punycode check
  if (url.hostname.includes('xn--')) {
    return {
      id: 'RULE_PUNYCODE_OR_KEYWORDS',
      params: { keywords: 'punycode' },
      score: 85,
      reason: t('RULE_PUNYCODE_OR_KEYWORDS', { keywords: 'punycode' }),
      triggered: true
    };
  }

  const suspiciousKeywords = [
    'login', 'signin', 'sign-in', 'logon',
    'verify', 'verification', 'validate', 'confirm',
    'secure', 'security', 'protect', 'alert',
    'account', 'update', 'upgrade', 'recover', 'reset', 'suspend',
    'banking', 'netbanking', 'payment', 'recharge', 'refund', 'cashback',
    'kyc', 'aadhar', 'pan', 'upi', 'otp',
    'claim', 'reward', 'prize', 'offer', 'free', 'winner',
    'helpdesk', 'support', 'customer-care'
  ];
  const fullUrl = url.pathname.toLowerCase() + url.search.toLowerCase() + url.hostname.toLowerCase();
  
  const foundKeywords = suspiciousKeywords.filter(k => fullUrl.includes(k));
  if (foundKeywords.length >= 2) {
    return {
      id: 'RULE_PUNYCODE_OR_KEYWORDS',
      params: { keywords: foundKeywords.slice(0, 4).join(', ') },
      score: 40,
      reason: t('RULE_PUNYCODE_OR_KEYWORDS', { keywords: foundKeywords.slice(0, 4).join(', ') }),
      triggered: true
    };
  }

  return { id: null, params: {}, score: 0, reason: null, triggered: false };
}

/**
 * Rule 7: Financial keyword in hostname
 * @param {string} urlString
 * @param {Array} brandsList
 */
export function hasFinancialKeywordInHostname(urlString, brandsList) {
  const url = safeParseUrl(urlString);
  if (!url) return { id: null, params: {}, score: 0, reason: null, triggered: false };
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { id: null, params: {}, score: 0, reason: null, triggered: false };
  }

  const hostname = url.hostname.toLowerCase();

  if (brandsList && Array.isArray(brandsList)) {
    const isLegit = brandsList.some(brand =>
      brand.domains && brand.domains.some(d => hostname === d || hostname.endsWith('.' + d))
    );
    if (isLegit) return { id: null, params: {}, score: 0, reason: null, triggered: false };
  }

  if (isAllowlistedDomain(hostname)) {
    return { id: null, params: {}, score: 0, reason: null, triggered: false };
  }

  const regDomain = getDomain(hostname) || hostname;
  const suffix = getPublicSuffix(hostname) || '';
  const domainLabel = suffix && regDomain.endsWith('.' + suffix)
    ? regDomain.slice(0, -(suffix.length + 1))
    : regDomain;
  const subdomain = getSubdomain(hostname) || '';
  const domainAndSubdomains = subdomain ? `${subdomain}.${domainLabel}` : domainLabel;

  const financialHostKeywords = [
    'netbanking', 'ibank', 'webwallet', 'wallet', 'kyc', 'upi',
    'paytm', 'phonepe', 'gpay', 'bhim'
  ];

  for (const kw of financialHostKeywords) {
    if (domainAndSubdomains.includes(kw)) {
      return {
        id: 'RULE_FINANCIAL_KEYWORD_HOSTNAME',
        params: { keyword: kw },
        score: 55,
        reason: t('RULE_FINANCIAL_KEYWORD_HOSTNAME', { keyword: kw }),
        triggered: true
      };
    }
  }

  const bankMatch = /(?:^|[-.])(?:net)?banking?(?:[-.]|$)/i.test(domainAndSubdomains) ||
                    /(?:[-.])bank(?:[-.]|$)/i.test(domainAndSubdomains);
  if (bankMatch) {
    return {
      id: 'RULE_FINANCIAL_KEYWORD_HOSTNAME',
      params: { keyword: 'banking' },
      score: 55,
      reason: t('RULE_FINANCIAL_KEYWORD_HOSTNAME', { keyword: 'banking' }),
      triggered: true
    };
  }

  return { id: null, params: {}, score: 0, reason: null, triggered: false };
}

/**
 * Rule 8: Brand variant list matching
 * @param {string} urlString
 * @param {Array} brandsList
 */
export function hasBrandVariantMatch(urlString, brandsList) {
  const url = safeParseUrl(urlString);
  if (!url) return { id: null, params: {}, score: 0, reason: null, triggered: false };
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { id: null, params: {}, score: 0, reason: null, triggered: false };
  }
  if (!brandsList || !Array.isArray(brandsList)) {
    return { id: null, params: {}, score: 0, reason: null, triggered: false };
  }

  const hostname = url.hostname.toLowerCase().replace(/^www\./, '');
  if (isAllowlistedDomain(hostname)) {
    return { id: null, params: {}, score: 0, reason: null, triggered: false };
  }

  for (const brand of brandsList) {
    const isLegit = brand.domains && brand.domains.some(d =>
      hostname === d || hostname.endsWith('.' + d)
    );
    if (isLegit) continue;

    if (brand.variants && Array.isArray(brand.variants)) {
      for (const variant of brand.variants) {
        const variantLower = variant.toLowerCase();
        const match = isBrandMatchWithRemainder(hostname, variantLower);

        if (match) {
          return {
            id: 'RULE_BRAND_VARIANT_MATCH',
            params: { brand: brand.name },
            score: 85,
            reason: t('RULE_BRAND_VARIANT_MATCH', { brand: brand.name }),
            triggered: true
          };
        }
      }
    }
  }

  return { id: null, params: {}, score: 0, reason: null, triggered: false };
}
