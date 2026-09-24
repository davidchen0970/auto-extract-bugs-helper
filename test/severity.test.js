import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SEV, sevOrder, sevLabel, emptyTotals, mapSev, sevFromBD } from '../src/core/schema.js';

test('sevOrder ranks Critical > High > Medium > Low > Info', () => {
	assert.deepEqual(sevOrder, [SEV.CRITICAL, SEV.HIGH, SEV.MEDIUM, SEV.LOW, SEV.INFO]);
});

test('every severity constant has a display label', () => {
	for (const s of sevOrder) assert.ok(sevLabel[s]);
});

test('emptyTotals starts every bucket at zero', () => {
	const t = emptyTotals();
	assert.equal(t.total, 0);
	assert.equal(t.CRITICAL, 0);
	assert.equal(t.INFO, 0);
});

test('mapSev normalizes spelling and rejects unknowns', () => {
	assert.equal(mapSev(' critical '), SEV.CRITICAL);
	assert.equal(mapSev('MED'), SEV.MEDIUM);
	assert.equal(mapSev(null), null);
	assert.equal(mapSev('nonsense'), null);
});

test('sevFromBD buckets BlackDuck wording', () => {
	assert.equal(sevFromBD('Critical'), SEV.CRITICAL);
	assert.equal(sevFromBD('High'), SEV.HIGH);
	assert.equal(sevFromBD('Medium'), SEV.MEDIUM);
	assert.equal(sevFromBD('Low'), SEV.LOW);
	assert.equal(sevFromBD(''), SEV.LOW);
});
