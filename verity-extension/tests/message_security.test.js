import test from 'node:test';
import assert from 'node:assert/strict';
import { validateMessageSender } from '../background/message-validator.js';

const EXTENSION_ID = 'verity-ext-id-12345';

test('Message Security: rejects missing or invalid sender runtime ID', () => {
  // Missing sender
  const r1 = validateMessageSender(null, EXTENSION_ID, { action: 'GET_STATE' });
  assert.equal(r1.valid, false);
  assert.equal(r1.reason, 'Invalid or missing sender runtime ID');

  // Mismatched runtime ID (external extension or untrusted page)
  const r2 = validateMessageSender({ id: 'attacker-extension-id' }, EXTENSION_ID, { action: 'GET_STATE' });
  assert.equal(r2.valid, false);
  assert.equal(r2.reason, 'Invalid or missing sender runtime ID');
});

test('Message Security: allows internal non-tab-scoped messages with valid runtime ID', () => {
  const sender = { id: EXTENSION_ID };
  const r = validateMessageSender(sender, EXTENSION_ID, { action: 'GET_SETTINGS' });
  assert.equal(r.valid, true);
  assert.equal(r.reason, null);
});

test('Message Security: enforces sender.tab on tab-scoped actions', () => {
  const senderNoTab = { id: EXTENSION_ID };

  for (const action of ['ANALYZE_URL_ONLY', 'ANALYZE_FULL', 'ANALYZE_SEARCH_RESULT', 'USER_OVERRIDE_ALLOW']) {
    const res = validateMessageSender(senderNoTab, EXTENSION_ID, { action });
    assert.equal(res.valid, false);
    assert.equal(res.reason, `Action ${action} requires a valid sender tab`);
  }

  // Sender with tab object and valid tabId
  const senderWithTab = {
    id: EXTENSION_ID,
    tab: { id: 42, url: 'https://example.com/' }
  };
  const validRes = validateMessageSender(senderWithTab, EXTENSION_ID, { action: 'ANALYZE_URL_ONLY' });
  assert.equal(validRes.valid, true);
  assert.equal(validRes.reason, null);
});

test('Message Security: USER_OVERRIDE_ALLOW tab validation', () => {
  const senderTab = {
    id: EXTENSION_ID,
    tab: { id: 101, url: 'https://phishing-site.com/login' }
  };

  // Rejects when message claims to override a different tab
  const tabMismatch = validateMessageSender(senderTab, EXTENSION_ID, {
    action: 'USER_OVERRIDE_ALLOW',
    tabId: 999, // Mismatched!
    url: 'https://phishing-site.com/login'
  });
  assert.equal(tabMismatch.valid, false);
  assert.equal(tabMismatch.reason, 'Tab ID mismatch in override request');

  // Rejects when URL hostname does not match sender tab URL hostname
  const hostMismatch = validateMessageSender(senderTab, EXTENSION_ID, {
    action: 'USER_OVERRIDE_ALLOW',
    tabId: 101,
    url: 'https://evil-spoof.com/login'
  });
  assert.equal(hostMismatch.valid, false);
  assert.equal(hostMismatch.reason, 'URL hostname mismatch with sender tab');

  // Rejects malformed URL
  const malformedUrl = validateMessageSender(senderTab, EXTENSION_ID, {
    action: 'USER_OVERRIDE_ALLOW',
    tabId: 101,
    url: ':::not-a-valid-url:::'
  });
  assert.equal(malformedUrl.valid, false);
  assert.equal(malformedUrl.reason, 'Malformed URL in override request');

  // Accepts when sender.id, sender.tab.id, and URL hostname match
  const validOverride = validateMessageSender(senderTab, EXTENSION_ID, {
    action: 'USER_OVERRIDE_ALLOW',
    tabId: 101,
    url: 'https://phishing-site.com/login'
  });
  assert.equal(validOverride.valid, true);
  assert.equal(validOverride.reason, null);
});
