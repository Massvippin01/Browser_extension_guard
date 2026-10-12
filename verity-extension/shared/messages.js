/**
 * shared/messages.js — ES Module wrapper for shared/messages.en.js
 * 
 * Allows background service worker and tests to import structured reason
 * IDs, translation function t(), and category mappings via standard ESM syntax,
 * while keeping messages.en.js as a pure classic script for content scripts.
 */

import './messages.en.js';

export const MESSAGES = globalThis.MESSAGES;
export const SIGNAL_CATEGORY_MAP = globalThis.SIGNAL_CATEGORY_MAP;
export const CATEGORY_CAPS = globalThis.CATEGORY_CAPS;
export const t = globalThis.t;

export default {
  MESSAGES,
  SIGNAL_CATEGORY_MAP,
  CATEGORY_CAPS,
  t
};
