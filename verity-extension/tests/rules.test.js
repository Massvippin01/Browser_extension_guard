import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isIpBasedUrl,
  hasMissingHttps,
  hasExcessiveSubdomains,
  hasBrandNameInWrongDomain,
  hasBrandVariantMatch,
  hasFinancialKeywordInHostname,
  hasPunycodeOrKeywords,
  hasRandomLookingHostname,
  hasSuspiciousUrlPattern,
  hasAffiliateTrackerPattern,
  hasMalvertisingPattern,
  hasPiracyOrUnverifiedMediaPattern,
  isTrustedTopDomain
} from '../background/rules.js';

test('Rule 1: isIpBasedUrl', () => {
  // Attack / Malicious case
  const attack = isIpBasedUrl('http://192.168.1.1/login');
  assert.equal(attack.triggered, true);
  assert.equal(attack.score, 80);

  // Benign case
  const benign = isIpBasedUrl('https://example.com/login');
  assert.equal(benign.triggered, false);
  assert.equal(benign.score, 0);

  // Invalid URL handling
  const invalid = isIpBasedUrl('not-a-url');
  assert.equal(invalid.triggered, false);
});

test('Rule 2: hasMissingHttps', () => {
  // Attack / Insecure HTTP
  const attack = hasMissingHttps('http://example.com/account');
  assert.equal(attack.triggered, true);
  assert.equal(attack.score, 40);

  // Benign HTTPS
  const benign = hasMissingHttps('https://example.com/account');
  assert.equal(benign.triggered, false);
  assert.equal(benign.score, 0);
});

test('Rule 3: hasExcessiveSubdomains', () => {
  // Attack (> 4 parts)
  const attack = hasExcessiveSubdomains('https://a.b.c.d.example.com/');
  assert.equal(attack.triggered, true);
  assert.equal(attack.score, 30);

  // Benign standard subdomain
  const benign = hasExcessiveSubdomains('https://portal.example.com/');
  assert.equal(benign.triggered, false);
  assert.equal(benign.score, 0);
});

test('Rule 4: hasBrandNameInWrongDomain', () => {
  const brands = [{ name: 'PayPal', domains: ['paypal.com'] }];

  // Attack: Brand name in unverified domain
  const attack = hasBrandNameInWrongDomain('https://paypal-login-security.com', brands);
  assert.equal(attack.triggered, true);
  assert.equal(attack.score, 90);

  // Benign: Legit brand domain
  const benign = hasBrandNameInWrongDomain('https://paypal.com/signin', brands);
  assert.equal(benign.triggered, false);
  assert.equal(benign.score, 0);
});

test('Rule 5: hasBrandVariantMatch', () => {
  const brands = [{ name: 'PayPal', domains: ['paypal.com'], variants: ['paypa1'] }];

  // Attack: Known typosquat variant
  const attack = hasBrandVariantMatch('https://paypa1-update.com', brands);
  assert.equal(attack.triggered, true);
  assert.equal(attack.score, 85);

  // Benign: Legit domain
  const benign = hasBrandVariantMatch('https://paypal.com/signin', brands);
  assert.equal(benign.triggered, false);
  assert.equal(benign.score, 0);
});

test('Rule 6: hasFinancialKeywordInHostname', () => {
  const brands = [];

  // Attack: Financial lure keyword in unknown domain
  const attack = hasFinancialKeywordInHostname('https://secure-banking-login.com', brands);
  assert.equal(attack.triggered, true);
  assert.equal(attack.score, 55);

  // Benign: Non-financial domain
  const benign = hasFinancialKeywordInHostname('https://recipes-cooking.org', brands);
  assert.equal(benign.triggered, false);
  assert.equal(benign.score, 0);
});

test('Rule 7: hasPunycodeOrKeywords', () => {
  // Attack: Punycode domain
  const attack = hasPunycodeOrKeywords('https://xn--pple-43d.com/');
  assert.equal(attack.triggered, true);

  // Benign: Trusted top domain or clean domain
  const benign = hasPunycodeOrKeywords('https://apple.com/');
  assert.equal(benign.triggered, false);
});

test('Rule 8: hasRandomLookingHostname', () => {
  // Attack: High-entropy consonant sequence
  const attack = hasRandomLookingHostname('https://qwrztpsdfghjk.com/');
  assert.equal(attack.triggered, true);

  // Benign: Dictionary-like domain
  const benign = hasRandomLookingHostname('https://simpleblog.org/');
  assert.equal(benign.triggered, false);
});

test('Rule 9: hasSuspiciousUrlPattern', () => {
  // Attack: '@' symbol embedded in URL credentials
  const attack = hasSuspiciousUrlPattern('https://admin@evil-domain.com/login');
  assert.equal(attack.triggered, true);

  // Benign: Clean URL
  const benign = hasSuspiciousUrlPattern('https://example.com/user/profile');
  assert.equal(benign.triggered, false);
});

test('Rule 10: hasAffiliateTrackerPattern', () => {
  // Attack: Explicit tracking query parameters
  const attack = hasAffiliateTrackerPattern('https://deals-hub.com/click?aff_id=123&campaign_id=456');
  assert.equal(attack.triggered, true);

  // Benign: Clean URL
  const benign = hasAffiliateTrackerPattern('https://example.com/catalog/shoes');
  assert.equal(benign.triggered, false);
});

test('Rule 11: hasMalvertisingPattern', () => {
  // Attack: Malvertising ad routing prefix
  const attack = hasMalvertisingPattern('https://ad-network.com/click/campaign-redirect-target');
  assert.equal(attack.triggered, true);

  // Benign: Standard news/content
  const benign = hasMalvertisingPattern('https://example.com/tech-news');
  assert.equal(benign.triggered, false);
});

test('Rule 12: hasPiracyOrUnverifiedMediaPattern', () => {
  // Attack: Piracy keyword pattern
  const attack = hasPiracyOrUnverifiedMediaPattern('https://thepiratebay-torrent-proxy.org/');
  assert.equal(attack.triggered, true);

  // Benign: Clean media site
  const benign = hasPiracyOrUnverifiedMediaPattern('https://example.com/videos');
  assert.equal(benign.triggered, false);
});

test('Rule 13: isTrustedTopDomain', () => {
  // Trusted top domains
  assert.equal(isTrustedTopDomain('google.com'), true);
  assert.equal(isTrustedTopDomain('youtube.com'), true);
  assert.equal(isTrustedTopDomain('microsoft.com'), true);

  // Untrusted / Phishing lookalike domains
  assert.equal(isTrustedTopDomain('google-auth-verify.com'), false);
  assert.equal(isTrustedTopDomain('evil-domain.net'), false);
  assert.equal(isTrustedTopDomain(''), false);
  assert.equal(isTrustedTopDomain(null), false);
});
