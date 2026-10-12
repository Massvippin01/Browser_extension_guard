import { getDomain, getPublicSuffix } from '../shared/psl.js';


/**
 * Calculates the Levenshtein distance between two strings.
 * Used for detecting typosquatting (e.g., paypa1 vs paypal).
 */
function levenshteinDistance(a, b) {
  const matrix = [];
  
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }
  
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) == a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(matrix[i - 1][j - 1] + 1, // substitution
                                Math.min(matrix[i][j - 1] + 1, // insertion
                                         matrix[i - 1][j] + 1)); // deletion
      }
    }
  }
  return matrix[b.length][a.length];
}

/**
 * Normalizes a hostname for brand comparison.
 * Strips www. and the TLD if possible to compare the root word.
 */
function normalizeHostname(hostname) {
  const clean = hostname.toLowerCase().replace(/^www\./, '');
  const domain = getDomain(clean);
  if (domain) {
    const suffix = getPublicSuffix(clean);
    if (suffix && domain.endsWith('.' + suffix)) {
      return domain.slice(0, -(suffix.length + 1)).replace(/[^a-z0-9]/g, '');
    }
    return domain.replace(/[^a-z0-9]/g, '');
  }
  return clean.replace(/[^a-z0-9]/g, '');
}

/**
 * Analyzes a hostname against a list of protected brands using Edit Distance.
 * @param {string} urlString 
 * @param {Array} brandsList 
 * @returns {Object} score and reason if triggered
 */
export function detectTyposquatting(urlString, brandsList) {
  try {
    const url = new URL(urlString);
    if (!['http:', 'https:'].includes(url.protocol)) return { score: 0, reason: null, triggered: false };

    const hostname = url.hostname.toLowerCase();
    const normalizedHost = normalizeHostname(hostname);
    
    // First, verify if it's already a legitimate domain
    for (const brand of brandsList) {
      if (brand.domains.some(legit => hostname === legit || hostname.endsWith('.' + legit))) {
        return { score: 0, reason: null, triggered: false }; // Legit site
      }
    }

    // Now check for typosquatting (Levenshtein distance <= 2)
    for (const brand of brandsList) {
      const brandName = brand.name.toLowerCase().replace(/\s+/g, '');
      
      // If the brand name is too short, edit distance of 1 might trigger false positives (e.g. 'box' vs 'fox')
      const threshold = brandName.length <= 4 ? 1 : 2;
      
      const distance = levenshteinDistance(normalizedHost, brandName);
      
      if (distance > 0 && distance <= threshold) {
        return {
          score: 85,
          reason: `High typosquatting risk: Domain closely resembles the protected brand "${brand.name}".`,
          triggered: true
        };
      }
    }
    
  } catch (e) {}
  
  return { score: 0, reason: null, triggered: false };
}
