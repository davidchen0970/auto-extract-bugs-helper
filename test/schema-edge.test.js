import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SEV, mapSev, sevFromBD } from '../src/core/schema.js';

test('S-03 mapSev does not recognise INFO (documented gap: coverity INFO rows uncounted)', () => {
	assert.equal(mapSev('INFO'), null);
});

test('S-04 sevFromBD buckets the full BlackDuck vocabulary', () => {
	assert.equal(sevFromBD('Critical'), SEV.CRITICAL);
	assert.equal(sevFromBD('High'), SEV.HIGH);
	assert.equal(sevFromBD('Medium'), SEV.MEDIUM);
	assert.equal(sevFromBD('Low'), SEV.LOW);
	assert.equal(sevFromBD(''), SEV.LOW);
	assert.equal(sevFromBD('not-a-severity'), SEV.INFO);
});

test('S-05 Moderate currently lands in INFO, not MEDIUM (documented gap)', () => {
	assert.equal(sevFromBD('Moderate'), SEV.INFO);
});
