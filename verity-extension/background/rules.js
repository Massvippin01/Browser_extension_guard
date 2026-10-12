import { getDomain, getPublicSuffix, getSubdomain } from '../shared/psl.js';
import { isAllowlistedDomain } from '../shared/legit-domains.js';


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

  const subdomain = getSubdomain(url.hostname);
  if (subdomain) {
    const subParts = subdomain.split('.');
    if (subParts.length >= 3) {
      return {
        score: 30,
        reason: "The URL uses an unusually high number of subdomains.",
        triggered: true
      };
    }
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
    let match = false;
    
    // For short brand names (e.g. UPS, SBI), require a token boundary to avoid matching inside other words.
    // For longer names (e.g. netflix, paypal), a substring match is safe enough.
    if (brandNameLower.length <= 4) {
      const regex = new RegExp(`(^|[-.])${brandNameLower}([-.]|$)`, 'i');
      match = regex.test(hostname);
    } else {
      match = hostname.includes(brandNameLower);
    }
    
    if (match) {
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
    '.monster', '.rest', '.skin', '.bar',   // Rare but seen in campaigns
    '.qpon', '.world'                       // Commonly abused in ad-redirects
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
 * Example: wb.omegatootler.rest/cx/<1000-char-blob>
 * @param {string} urlString
 */
export function hasMalvertisingPattern(urlString) {
  const url = safeParseUrl(urlString);
  if (!url) return { score: 0, reason: null, triggered: false };
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { score: 0, reason: null, triggered: false };
  }

  // Exempt official trusted top domains (OAuth flow parameters are expected)
  if (isTrustedTopDomain(url.hostname)) {
    return { score: 0, reason: null, triggered: false };
  }

  const fullPath = url.pathname + url.search;
  const reasons = [];
  let score = 0;

  // A. Extremely long URL path — classic ad-redirect obfuscation
  // Normal URLs rarely exceed 200 chars of path. 500+ is a strong signal.
  if (fullPath.length > 500) {
    score += 55;
    reasons.push(`Extremely long URL path (${fullPath.length} chars) — typical of malicious obfuscation.`);
  } else if (fullPath.length > 200) {
    score += 20;
    reasons.push('Unusually long URL path — possible redirect chain encoding.');
  }

  // B. Asterisk (*) characters in URL path — NOT valid URL chars, used by ad-redirect networks
  if (url.pathname.includes('*') || url.search.includes('*')) {
    score += 40;
    reasons.push('URL contains asterisk (*) characters — characteristic of ad-redirect tracking networks.');
  }

  // C. Known ad-redirect path prefixes (/cx/, /click/, /go/, /rd/, /redir/, /track/, /partitial/, /play/)
  const adPrefixes = ['/cx/', '/rd/', '/redir/', '/click/', '/go/', '/track/', '/redirect/', '/out/', '/r/', '/partitial/', '/partial/', '/direct/', '/zone/', '/pop/', '/link2/', '/sl/', '/play/', '/watch/', '/stream/', '/embed/'];
  if (adPrefixes.some(p => url.pathname.startsWith(p) || url.pathname.includes(p))) {
    score += 30;
    reasons.push('URL path matches known ad-redirect / fake player routing pattern.');
  }

  // Check for numeric/alpha campaign/media ID in path (e.g. /partitial/5117867, /play/tt3930582)
  if (/\/[a-z]{2,12}\/([a-z]{0,4}[0-9]{5,12})/i.test(url.pathname)) {
    score += 30;
    reasons.push('URL path contains an ad-network campaign/media identifier.');
  }

  // D. Base64-like blob in path (long run of alphanumeric + _-* without word breaks)
  // Include % because it's often url-encoded base64 padding (e.g. %3D%3D for ==)
  const base64Blob = /[A-Za-z0-9_\-*%]{80,}/.test(url.pathname);
  if (base64Blob) {
    score += 35;
    reasons.push('URL path contains a long encoded payload (base64-like blob).');
  }

  // E. Multiple tracking/fingerprint query params (md=, fc=, cd=, pr= all together)
  const trackingParams = ['md=', 'fc=', 'cd=', 'pr=', 'cid=', 'uid=', 'tid=', 'rid='];
  const presentTrackers = trackingParams.filter(p => url.search.includes(p));
  if (presentTrackers.length >= 3) {
    score += 25;
    reasons.push(`URL contains multiple tracking fingerprint parameters (${presentTrackers.join(', ')}).`);
  }

  // F. Mixed-case alphanumeric tracking token in path (e.g. /bkNTV1YPIT4j)
  const pathClean = url.pathname.replace(/^\/|\/$/g, '');
  if (/^[A-Za-z0-9_-]{8,35}$/.test(pathClean)) {
    const hasUpper = /[A-Z]/.test(pathClean);
    const hasLower = /[a-z]/.test(pathClean);
    const hasNum = /[0-9]/.test(pathClean);
    if ((hasUpper && hasLower && hasNum) || (hasUpper && hasNum && pathClean.length >= 10)) {
      score += 45;
      reasons.push(`URL path contains an obfuscated tracking token ("/${pathClean}").`);
    }
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
 * Rule 5d: Affiliate Tracker / Ad Tracker URL Pattern Detection
 * Catches links like track.laros.world/<uuid>?source=...&campaign_id=...
 * @param {string} urlString
 */
export function hasAffiliateTrackerPattern(urlString) {
  const url = safeParseUrl(urlString);
  if (!url) return { score: 0, reason: null, triggered: false };
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { score: 0, reason: null, triggered: false };
  }

  let score = 0;
  const reasons = [];

  const queryKeys = Array.from(url.searchParams.keys()).map(k => k.toLowerCase());
  const queryValues = Array.from(url.searchParams.values());
  
  // 1. Explicit affiliate/ad tracker keys
  const trackerKeywords = ['campaign_id', 'click_id', 'creative_id', 'aff_id', 'source', 'utm_source'];
  const presentTrackers = trackerKeywords.filter(k => queryKeys.includes(k));
  
  // 2. Generic/Obfuscated ad network & fingerprinting keys
  const genericTrackers = [
    'ymid', 'var', 'var_1', 'var_2', 'var_3', 'z', 'sz', 'zoneid', 'zone', 'pop', 'cost', 'rev',
    'p1', 'p2', 'p3', 'p4', 'p5', 'p6', 'p7', 'pub_rfid', 'pubid', 'sub1', 'sub2', 'clickid', 'aff_sub',
    's1', 's2', 's3', 'ab2r', 'rhd', 'sf', 'os_version', 'browser_version', 'platform', 'architecture'
  ];
  const presentGenericTrackers = genericTrackers.filter(k => queryKeys.includes(k));

  // 3. Mixed letter-digit domain label check (e.g. ay267.com, wvdme.com)
  const parts = url.hostname.toLowerCase().split('.');
  const domainLabel = parts.length >= 2 ? parts[parts.length - 2] : parts[0];
  const isMixedDigitLabel = /^[a-z]{2,5}[0-9]{2,5}$/i.test(domainLabel);
  if (isMixedDigitLabel) {
    score += 25;
    reasons.push(`Domain label "${domainLabel}" matches synthetic ad-network domain pattern.`);
  }

  // 4. UUID or Hash detection in query values or path
  const uuidRegex = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
  const hashRegex = /^[a-f0-9]{32,64}$/i;
  
  const hasUuidOrHashValue = queryValues.some(v => uuidRegex.test(v) || hashRegex.test(v));
  
  const path = url.pathname.replace(/^\/|\/$/g, '');
  const pathIsUuid = uuidRegex.test(path);

  // Scoring Logic
  if (presentTrackers.length >= 2) {
    score += 35;
    reasons.push(`matches explicit tracking pattern (${presentTrackers.join(', ')})`);
  }
  
  if (presentGenericTrackers.length >= 3) {
    score += 45;
    reasons.push(`uses ad-network & device fingerprinting parameters (${presentGenericTrackers.slice(0, 4).join(', ')})`);
  } else if (presentGenericTrackers.length >= 1) {
    score += 25;
    reasons.push(`uses ad-network tracking variable (${presentGenericTrackers[0]})`);
  }

  if (hasUuidOrHashValue) {
    score += 30;
    reasons.push('contains a unique tracking identifier (UUID/Hash)');
  } else if (pathIsUuid) {
    score += 25;
    reasons.push('path is a unique tracking identifier');
  }

  // If score is high enough to be purely a tracker, classify it as malvertising context
  if (score >= 40) {
    return {
      score: score + 25,
      reason: `Ad/Affiliate tracking pattern detected: URL ${reasons.join(', ')}.`,
      triggered: true
    };
  } else if (score > 0) {
    return {
      score: score + 15,
      reason: `Ad/Affiliate tracking pattern detected: URL ${reasons.join(', ')}.`,
      triggered: true
    };
  }

  return { score: 0, reason: null, triggered: false };
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
 * Catches hostnames with high entropy, long hex hashes, or unpronounceable consonant clusters.
 * Tuned on dev set to avoid flagging dictionary words and hyphenated domain compounds.
 * @param {string} urlString
 */
export function hasRandomLookingHostname(urlString) {
  const url = safeParseUrl(urlString);
  if (!url) return { score: 0, reason: null, triggered: false };
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { score: 0, reason: null, triggered: false };
  }

  const hostname = url.hostname.toLowerCase();

  // Skip known-legitimate static prefixes
  const safeLabels = new Set(['www', 'mail', 'api', 'cdn', 'static', 'assets', 'img', 'media', 'blog', 'shop', 'store', 'news', 'help', 'support', 'app', 'dev']);

  const parts = hostname.split('.');
  const labelsToCheck = parts.length > 1 ? parts.slice(0, -1) : parts;
  const tld = parts.length > 1 ? '.' + parts[parts.length - 1] : '';
  const suspTLDs = new Set(['.rest', '.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq', '.click', '.online', '.site', '.fun', '.icu', '.sbs', '.cfd', '.monster', '.skin', '.qpon']);

  for (const label of labelsToCheck) {
    if (safeLabels.has(label)) continue;

    // Split on hyphens to inspect individual tokens
    const subTokens = label.split('-');
    for (const tok of subTokens) {
      if (tok.length < 8) continue;

      // Hex hash check (e.g. md5 / uuid / random hex string)
      if (tok.length >= 16 && /^[0-9a-f]+$/i.test(tok)) {
        return {
          score: 65,
          reason: `Hostname "${hostname}" contains a hex hash label ("${tok}") — signature of ad-redirect & malware DGA infrastructure.`,
          triggered: true
        };
      }

      // Consonant cluster (6+ consecutive consonants without vowel, treating y as semi-vowel)
      if (/[bcdfghjklmnpqrstvwxz]{6,}/i.test(tok)) {
        return {
          score: 65,
          reason: `Hostname "${hostname}" contains an unpronounceable consonant sequence ("${tok}") — signature of ad-redirect & malware DGA infrastructure.`,
          triggered: true
        };
      }

      // Extreme low vowel ratio or high entropy on long single tokens
      if (tok.length >= 10) {
        const vowels = (tok.match(/[aeiouy]/g) || []).length;
        const vowelRatio = vowels / tok.length;
        const entropy = calcLabelEntropy(tok);

        if (vowelRatio < 0.12 && tok.length >= 10) {
          return {
            score: 65,
            reason: `Hostname "${hostname}" contains a randomly generated label ("${tok}") — signature of ad-redirect & malware DGA infrastructure.`,
            triggered: true
          };
        }

        if (entropy > 3.6 && suspTLDs.has(tld)) {
          return {
            score: 65,
            reason: `Hostname "${hostname}" uses a synthetic DGA domain label ("${tok}") on high-risk TLD "${tld}".`,
            triggered: true
          };
        }
      }
    }
  }

  return { score: 0, reason: null, triggered: false };
}

/**
 * Rule 9: Piracy / Illegal Media Streaming & High-Risk TLD Rule
 * Detects known piracy domain keywords (tamilgun, moviesda, isaimini, tamilyogi, movierulz, khatrimaza, filmywap, torrent)
 * paired with high-risk streaming TLDs (.ninja, .mov, .xyz, .top, .click, .world, .site).
 * @param {string} urlString
 */
export function hasPiracyOrUnverifiedMediaPattern(urlString) {
  const url = safeParseUrl(urlString);
  if (!url) return { score: 0, reason: null, triggered: false };
  if (!['http:', 'https:'].includes(url.protocol)) {
    return { score: 0, reason: null, triggered: false };
  }

  const hostname = url.hostname.toLowerCase();
  
  // Piracy / Untrusted Software & Media Domain Keywords
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
      score: 85,
      reason: `Hostname "${hostname}" matches a known piracy/malvertising network signature ("${matchedKeyword}" on "${matchedTLD}").`,
      triggered: true
    };
  } else if (matchedKeyword) {
    return {
      score: 60,
      reason: `Hostname contains media piracy keyword "${matchedKeyword}" — frequently associated with malvertising pop-unders and dangerous downloads.`,
      triggered: true
    };
  } else if (matchedTLD && (url.pathname.includes('download') || url.pathname.includes('play') || url.pathname.includes('watch'))) {
    return {
      score: 50,
      reason: `Domain on "${matchedTLD}" offering media play/download — high malvertising risk.`,
      triggered: true
    };
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

  // Exempt official trusted top domains (Auth keywords on official domains are expected)
  if (isTrustedTopDomain(url.hostname)) {
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

  // Exempt established legitimate financial/banking domains via independent allowlist
  if (isAllowlistedDomain(hostname)) {
    return { score: 0, reason: null, triggered: false };
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
        score: 55,
        reason: `Hostname contains financial keyword "${kw}" on an unverified domain.`,
        triggered: true
      };
    }
  }

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
        const variantLower = variant.toLowerCase();
        let match = false;
        
        // Similar to the brand name rule, require token boundaries for very short variants
        if (variantLower.length <= 4) {
          const regex = new RegExp(`(^|[-.])${variantLower}([-.]|$)`, 'i');
          match = regex.test(hostname);
        } else {
          match = hostname.includes(variantLower);
        }

        if (match) {
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
