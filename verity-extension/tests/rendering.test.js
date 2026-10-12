import test from 'node:test';
import assert from 'node:assert/strict';
import { escapeHtml, sanitizeText, createSafeElement } from '../shared/safe-dom.js';

test('Escaping Helper: escapeHtml encodes dangerous HTML characters', () => {
  const xssPayload = '<script>alert("xss")</script>&<img src=\'x\' onerror="evil()"/>';
  const escaped = escapeHtml(xssPayload);

  assert.equal(escaped.includes('<script>'), false);
  assert.equal(escaped.includes('</script>'), false);
  assert.equal(escaped.includes('&lt;script&gt;'), true);
  assert.equal(escaped.includes('&amp;'), true);
  assert.equal(escaped.includes('&quot;'), true);
  assert.equal(escaped.includes('&#39;'), true);
});

test('Escaping Helper: escapeHtml handles null and non-string inputs safely', () => {
  assert.equal(escapeHtml(null), '');
  assert.equal(escapeHtml(undefined), '');
  assert.equal(escapeHtml(12345), '12345');
  assert.equal(escapeHtml('plain text'), 'plain text');
});

test('Sanitization Helper: sanitizeText strips control characters', () => {
  const dirty = 'SafeText\x00\x08With\x1FControlChars';
  const clean = sanitizeText(dirty);
  assert.equal(clean, 'SafeTextWithControlChars');
  assert.equal(sanitizeText(null), '');
});

test('Safe DOM Construction Helper: createSafeElement assigns pure textContent', () => {
  // Minimal DOM mock simulating Document and HTMLElement
  const mockDoc = {
    createElement(tagName) {
      return {
        tagName,
        className: '',
        textContent: '',
        children: []
      };
    }
  };

  const maliciousTitle = '<img src=x onerror=alert(1)>Malicious Site';
  const el = createSafeElement('div', maliciousTitle, 'threat-title', mockDoc);

  assert.equal(el.tagName, 'div');
  assert.equal(el.className, 'threat-title');
  // textContent stores the literal string rather than parsing HTML elements
  assert.equal(el.textContent, '<img src=x onerror=alert(1)>Malicious Site');
  assert.equal(el.children.length, 0);
});
