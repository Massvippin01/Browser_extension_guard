/**
 * safe-dom.js — Helpers for secure DOM construction and string sanitization
 */

/**
 * Escapes characters with HTML meaning for safe string context.
 * Note: Verity standard is to construct DOM nodes directly (createElement + textContent).
 * @param {any} value
 * @returns {string}
 */
export function escapeHtml(value) {
  if (value == null) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Sanitizes plain text input by stripping ASCII control characters.
 * @param {any} value
 * @returns {string}
 */
export function sanitizeText(value) {
  if (value == null) return '';
  return String(value).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
}

/**
 * Creates a DOM element with safe textContent and optional class name.
 * @param {string} tag
 * @param {string} text
 * @param {string} [className]
 * @param {Document} [doc]
 * @returns {HTMLElement}
 */
export function createSafeElement(tag, text, className = '', doc = typeof document !== 'undefined' ? document : null) {
  if (!doc) throw new Error('Document context required');
  const el = doc.createElement(tag);
  if (className) el.className = className;
  el.textContent = text != null ? String(text) : '';
  return el;
}
