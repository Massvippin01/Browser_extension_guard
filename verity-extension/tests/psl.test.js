import test from 'node:test';
import assert from 'node:assert';
import { getDomain, getPublicSuffix, getSubdomain } from '../shared/psl.js';

test('PSL: extracts registered domain and public suffix for .co.uk', () => {
  assert.strictEqual(getDomain('bbc.co.uk'), 'bbc.co.uk');
  assert.strictEqual(getDomain('news.bbc.co.uk'), 'bbc.co.uk');
  assert.strictEqual(getDomain('a.b.c.bbc.co.uk'), 'bbc.co.uk');
  assert.strictEqual(getPublicSuffix('news.bbc.co.uk'), 'co.uk');
  assert.strictEqual(getSubdomain('news.bbc.co.uk'), 'news');
});

test('PSL: extracts registered domain and public suffix for .co.in', () => {
  assert.strictEqual(getDomain('sbi.co.in'), 'sbi.co.in');
  assert.strictEqual(getDomain('retail.sbi.co.in'), 'sbi.co.in');
  assert.strictEqual(getPublicSuffix('retail.sbi.co.in'), 'co.in');
  assert.strictEqual(getSubdomain('retail.sbi.co.in'), 'retail');
});

test('PSL: extracts registered domain and public suffix for .gov.in', () => {
  assert.strictEqual(getDomain('uidai.gov.in'), 'uidai.gov.in');
  assert.strictEqual(getDomain('auth.portal.uidai.gov.in'), 'uidai.gov.in');
  assert.strictEqual(getPublicSuffix('auth.portal.uidai.gov.in'), 'gov.in');
  assert.strictEqual(getSubdomain('auth.portal.uidai.gov.in'), 'auth.portal');
});

test('PSL: extracts registered domain and public suffix for .ac.in', () => {
  assert.strictEqual(getDomain('iitd.ac.in'), 'iitd.ac.in');
  assert.strictEqual(getDomain('cse.iitd.ac.in'), 'iitd.ac.in');
  assert.strictEqual(getPublicSuffix('cse.iitd.ac.in'), 'ac.in');
  assert.strictEqual(getSubdomain('cse.iitd.ac.in'), 'cse');
});

test('PSL: extracts registered domain and public suffix for .com.au', () => {
  assert.strictEqual(getDomain('anz.com.au'), 'anz.com.au');
  assert.strictEqual(getDomain('banking.anz.com.au'), 'anz.com.au');
  assert.strictEqual(getPublicSuffix('banking.anz.com.au'), 'com.au');
  assert.strictEqual(getSubdomain('banking.anz.com.au'), 'banking');
});
