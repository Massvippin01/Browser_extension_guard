import { getDomain } from './psl.js';
import legitData from '../config/legit_domains.json' with { type: 'json' };

export const LEGIT_DOMAINS = legitData;
const domainSet = new Set(legitData.map(d => d.domain.toLowerCase()));

// Multi-tenant user-content hosting platforms where subdomains must NEVER inherit allowlist status
export const USER_CONTENT_PLATFORMS = [
  'github.io',
  'pages.dev',
  'firebaseapp.com',
  'web.app',
  'blogspot.com',
  'wordpress.com',
  'wixsite.com',
  'weebly.com',
  'vercel.app',
  'netlify.app',
  'workers.dev',
  'azurewebsites.net',
  'appspot.com',
  'cloudfront.net'
];

/**
 * Checks whether a hostname or its registered domain matches the curated allowlist.
 * Guarantees: User-content subdomains (*.github.io, *.pages.dev, etc.) NEVER inherit root allowlist.
 * @param {string} hostname
 * @returns {boolean}
 */
export function isAllowlistedDomain(hostname) {
  if (!hostname) return false;
  const clean = hostname.toLowerCase();

  // User-content subdomains on multi-tenant hosting platforms cannot inherit allowlist
  const isUserContentSubdomain = USER_CONTENT_PLATFORMS.some(platform =>
    clean.endsWith('.' + platform) && clean !== platform
  );
  if (isUserContentSubdomain) {
    return domainSet.has(clean);
  }

  const regDomain = getDomain(clean) || clean;
  return domainSet.has(clean) || domainSet.has(regDomain);
}

