import { getDomain, parse } from './psl.js';
import legitData from '../config/legit_domains.json' with { type: 'json' };

export const LEGIT_DOMAINS = legitData;
const domainSet = new Set(legitData.map(d => d.domain.toLowerCase()));

/**
 * Shared multi-tenant user-content hosts and path prefixes where user-generated
 * content is hosted under an otherwise trusted registered domain.
 * Each entry cites a documented source.
 */
export const SHARED_USER_CONTENT_PATHS = [
  {
    prefix: 'sites.google.com',
    source: 'Google Workspace: Multi-tenant user website publishing (support.google.com/sites)'
  },
  {
    prefix: 'docs.google.com/forms',
    source: 'Google Docs: Publicly accessible user-created web forms (support.google.com/docs)'
  },
  {
    prefix: 'forms.gle',
    source: 'Google Forms: URL shortener specifically resolving to user-generated Google forms'
  },
  {
    prefix: 'drive.google.com',
    source: 'Google Drive: Multi-tenant user file sharing and public download links (support.google.com/drive)'
  },
  {
    prefix: 'notion.site',
    source: 'Notion Labs: Multi-tenant user workspace web publishing (www.notion.so/help/public-pages-and-web-publishing)'
  },
  {
    prefix: 's3.amazonaws.com',
    source: 'Amazon Web Services: Multi-tenant S3 public object and static website hosting (docs.aws.amazon.com/AmazonS3)'
  },
  {
    prefix: 'storage.googleapis.com',
    source: 'Google Cloud: Multi-tenant GCS public bucket hosting (cloud.google.com/storage/docs)'
  },
  {
    prefix: 'blob.core.windows.net',
    source: 'Microsoft Azure: Multi-tenant Blob Storage public container hosting (learn.microsoft.com/azure/storage)'
  }
];

/**
 * Checks whether a URL or hostname matches the curated allowlist.
 * General mechanism guarantees:
 * 1. Hosts under the PSL PRIVATE section (e.g. *.github.io, *.pages.dev, *.firebaseapp.com)
 *    never inherit root allowlist status because private suffixes denote independent tenant boundaries.
 * 2. Shared-path user content hosts (sites.google.com, docs.google.com/forms, etc.) never inherit allowlist status.
 * 3. Only verified first-party ICANN registered domains or explicitly allowlisted exact hostnames inherit the cap.
 * 
 * @param {string} hostnameOrUrl
 * @returns {boolean}
 */
export function isAllowlistedDomain(hostnameOrUrl) {
  if (!hostnameOrUrl) return false;
  
  let hostname = '';
  let fullPath = '';
  try {
    if (hostnameOrUrl.includes('://')) {
      const parsedUrl = new URL(hostnameOrUrl);
      hostname = parsedUrl.hostname.toLowerCase();
      fullPath = hostname + parsedUrl.pathname.toLowerCase();
    } else {
      const slashIdx = hostnameOrUrl.indexOf('/');
      if (slashIdx !== -1) {
        hostname = hostnameOrUrl.substring(0, slashIdx).toLowerCase();
        fullPath = hostnameOrUrl.toLowerCase();
      } else {
        hostname = hostnameOrUrl.toLowerCase();
        fullPath = hostname;
      }
    }
  } catch (e) {
    hostname = hostnameOrUrl.toLowerCase();
    fullPath = hostname;
  }

  // 1. Check path-aware multi-tenant user content list
  for (const item of SHARED_USER_CONTENT_PATHS) {
    if (fullPath.startsWith(item.prefix) || fullPath.includes('://' + item.prefix)) {
      return false; // Multi-tenant user content never inherits allowlist
    }
  }

  // 2. PSL PRIVATE section detection:
  // Domains whose public suffix is marked private (e.g. github.io, pages.dev, vercel.app, azurewebsites.net)
  // are multi-tenant platforms where subdomains are untrusted third-party tenants.
  const pslInfo = parse(hostname, { allowPrivateDomains: true });
  if (pslInfo && pslInfo.isPrivate) {
    // If it's a private suffix tenant, it only matches if the EXACT full hostname is in domainSet
    return domainSet.has(hostname);
  }

  // 3. First-party ICANN domain matching
  const regDomain = getDomain(hostname) || hostname;
  return domainSet.has(hostname) || domainSet.has(regDomain);
}
