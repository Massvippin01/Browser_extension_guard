import { getDomain } from './psl.js';
import legitData from '../config/legit_domains.json' with { type: 'json' };

export const LEGIT_DOMAINS = legitData;
const domainSet = new Set(legitData.map(d => d.domain.toLowerCase()));

/**
 * Checks whether a hostname or its registered domain matches the curated allowlist.
 * @param {string} hostname
 * @returns {boolean}
 */
export function isAllowlistedDomain(hostname) {
  if (!hostname) return false;
  const clean = hostname.toLowerCase();
  const regDomain = getDomain(clean) || clean;
  return domainSet.has(clean) || domainSet.has(regDomain);
}
