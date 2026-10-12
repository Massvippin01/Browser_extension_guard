import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import { extractRichFeatures } from '../background/offscreen.js';

test('ML Parity: JavaScript extraction matches Python training extraction on fixed URLs', () => {
  const fixturesPath = new URL('./parity_fixtures.json', import.meta.url);
  const fixtures = JSON.parse(fs.readFileSync(fixturesPath, 'utf8'));

  assert.ok(fixtures.length > 0, 'Fixtures should contain test cases');

  for (const item of fixtures) {
    const jsFeatures = extractRichFeatures(item.url);
    const pyFeatures = item.features;

    assert.equal(
      jsFeatures.length,
      pyFeatures.length,
      `Feature vector length mismatch on URL: ${item.url}`
    );

    for (let i = 0; i < jsFeatures.length; i++) {
      const jsVal = jsFeatures[i];
      const pyVal = pyFeatures[i];
      const diff = Math.abs(jsVal - pyVal);

      assert.ok(
        diff < 1e-4,
        `Parity mismatch at feature index ${i} on URL ${item.url}: JS=${jsVal}, PY=${pyVal}, diff=${diff}`
      );
    }
  }
});
