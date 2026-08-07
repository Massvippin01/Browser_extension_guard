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

  // C. Suspicious TLD patterns
  const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.zip', '.info'];
  if (suspiciousTlds.some(tld => url.hostname.endsWith(tld))) {
    return {
      score: 30,
      reason: "The URL uses a top-level domain frequently associated with spam or abuse.",
      triggered: true
    };
  }

  return { score: 0, reason: null, triggered: false };
}
