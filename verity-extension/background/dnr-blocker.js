/**
 * background/dnr-blocker.js — Declarative Net Request 0ms Network Layer Blocker
 *
 * Uses chrome.declarativeNetRequest session rules to block known malvertising,
 * pop-under rotators, and confirmed malicious domains in 0ms before any HTML loads.
 */

import { isAllowlistedDomain } from '../shared/legit-domains.js';

export const BASELINE_BLOCKED_DOMAINS = Object.freeze([
  'propellerads.com',
  'popads.net',
  'popcash.net',
  'adsterra.com',
  'clickadu.com',
  'hilltopads.net',
  'wigglepoploaderfast.monster',
  'ufa168rss.live',
  'fastbytes.xyz'
]);

let dynamicRuleCounter = 2000;
export const MAX_DYNAMIC_RULES = 500;
const registeredDomains = new Set();
const registeredRules = new Map();

/**
 * Reset state for test environments.
 */
export function resetDnrForTesting() {
  registeredDomains.clear();
  registeredRules.clear();
  dynamicRuleCounter = 2000;
}

/**
 * Returns a copy of currently registered blocked domains.
 */
export function getBlockedDomainsDnr() {
  return new Set(registeredDomains);
}

/**
 * Initializes baseline pop-under rotator rules on startup.
 */
export async function initDnrBlocker() {
  const addRules = BASELINE_BLOCKED_DOMAINS.map((domain, index) => {
    registeredDomains.add(domain);
    const rule = {
      id: 1000 + index,
      priority: 1,
      action: { type: 'block' },
      condition: {
        urlFilter: `||${domain}^`,
        resourceTypes: ['main_frame', 'sub_frame', 'script', 'xmlhttprequest', 'other']
      }
    };
    registeredRules.set(rule.id, rule);
    return rule;
  });

  if (typeof chrome === 'undefined' || !chrome.declarativeNetRequest || !chrome.declarativeNetRequest.updateSessionRules) {
    return addRules;
  }

  try {
    await chrome.declarativeNetRequest.updateSessionRules({
      removeRuleIds: addRules.map(r => r.id),
      addRules
    });
  } catch (err) {
    console.warn('[Verity DNR] Failed to set baseline session rules:', err);
  }

  return addRules;
}

/**
 * Dynamically registers a 0ms network block rule for a confirmed threat domain.
 * @param {string} domain 
 * @returns {Promise<object|null>} The registered rule object, or null if skipped
 */
export async function blockDomainDnr(domain) {
  if (!domain || typeof domain !== 'string') return null;

  const cleanDomain = domain.toLowerCase().trim().replace(/^www\./, '');
  if (!cleanDomain || isAllowlistedDomain(cleanDomain) || registeredDomains.has(cleanDomain)) {
    return null;
  }

  registeredDomains.add(cleanDomain);

  const ruleId = dynamicRuleCounter++;
  if (dynamicRuleCounter > 2000 + MAX_DYNAMIC_RULES) {
    dynamicRuleCounter = 2000;
  }

  const rule = {
    id: ruleId,
    priority: 2,
    action: { type: 'block' },
    condition: {
      urlFilter: `||${cleanDomain}^`,
      resourceTypes: ['main_frame', 'sub_frame', 'script', 'xmlhttprequest', 'other']
    }
  };
  registeredRules.set(ruleId, rule);

  if (typeof chrome !== 'undefined' && chrome.declarativeNetRequest && chrome.declarativeNetRequest.updateSessionRules) {
    try {
      await chrome.declarativeNetRequest.updateSessionRules({
        removeRuleIds: [ruleId],
        addRules: [rule]
      });
    } catch (err) {
      console.warn('[Verity DNR] Failed to register session rule for domain:', cleanDomain, err);
    }
  }

  return rule;
}
