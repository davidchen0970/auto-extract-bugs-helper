import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

// Per-type diffing the compare tab does: when a tarball holds BOTH Coverity and
// BlackDuck reports, runCompare() diffs each report type on its own and the results
// are shown one type at a time behind bookmark tabs. This exercises the pure helpers
// powering that loop (reportTypes / typeName / flattenBugs) plus the per-type
// bucket contract compareBugs() backs it with.

import { bugKey, compareBugs } from '../src/core/compare.js';

let flattenBugs, reportTypes, typeName;

before(async () => {
	// ui/compare.js imports DOM-touching UI modules, so stand up jsdom first (the
	// compare helpers themselves only read their pure inputs).
	const dom = new JSDOM('<!doctype html><html><body></body></html>');
	globalThis.window = dom.window;
	globalThis.document = dom.window.document;
	({ flattenBugs, reportTypes, typeName } = await import('../src/ui/compare.js'));
});

function cov(file, line, checker, extra) {
	return Object.assign({ src: 'coverity', sev: 'MEDIUM', file, line, type: 'X', checker }, extra || {});
}
function bd(cve, extra) {
	return Object.assign({ src: 'blackduck', sev: 'HIGH', cve }, extra || {});
}
function rep(type, bugs) {
	return { type, file: type + '.report', bugs: bugs || [] };
}

// ---------- reportTypes: which types must be diffed, and in what order ----------

test('reportTypes collects every type from both sides, Coverity first', () => {
	const a = [rep('coverity', []), rep('blackduck', [])];
	const b = [rep('blackduck', [])];
	assert.deepEqual(reportTypes(a, b), ['coverity', 'blackduck']);
});

test('reportTypes keeps one-side types; empty input gives empty', () => {
	assert.deepEqual(reportTypes([], [rep('coverity', [])]), ['coverity']);
	assert.deepEqual(reportTypes([rep('blackduck', [])], []), ['blackduck']);
	assert.deepEqual(reportTypes([], []), []);
});

test('reportTypes appends unknown types after known ones', () => {
	assert.deepEqual(reportTypes([rep('coverity', []), rep('future', [])], []), ['coverity', 'future']);
});

// ---------- typeName: tab labels and fallback for unexpected types ----------

test('typeName gives human labels for known types, passthrough for unknown', () => {
	assert.equal(typeName('coverity'), 'Coverity');
	assert.equal(typeName('blackduck'), 'BlackDuck');
	assert.equal(typeName('something-new'), 'something-new');
});

// ---------- flattenBugs: pull only the requested type's defects ----------

test('flattenBugs takes one type across several reports; unknown gives empty', () => {
	const a = cov('a.c', 1, 'CHK');
	const b1 = bd('CVE-1');
	const b2 = bd('CVE-2');
	const reps = [rep('coverity', [a]), rep('blackduck', [b1, b2])];
	assert.deepEqual(flattenBugs(reps, 'coverity'), [a]);
	assert.deepEqual(flattenBugs(reps, 'blackduck'), [b1, b2]);
	assert.deepEqual(flattenBugs(reps, 'missing-type'), []);
});

// ---------- the per-type loop in runCompare: buckets never bleed across types ----------

test('per-type loop: a Coverity change never lands in the BlackDuck buckets', () => {
	const aCov = [cov('a.c', 1, 'CHK', { desc: 'v1' })];
	const bCov = [cov('a.c', 1, 'CHK', { desc: 'v2' })];
	const dBdA = [bd('CVE-5', { cvss: '8.0' })];
	const dBdB = [bd('CVE-5', { cvss: '7.2' })];

	const dCoverity = compareBugs(aCov, bCov);   // only content changed -> changed
	const dBlackDuck = compareBugs(dBdA, dBdB);

	assert.equal(dCoverity.changed.length, 1);
	assert.equal(dCoverity.added.length, 0);
	assert.equal(dCoverity.removed.length, 0);

	assert.equal(dBlackDuck.changed.length, 1, 'Coverity change must not affect BlackDuck');
	assert.equal(dBlackDuck.added.length, 0);
	assert.equal(dBlackDuck.removed.length, 0);
});

test('a type present on only one side buckets entirely as removed / added', () => {
	const d1 = compareBugs([cov('a.c', 1, 'CHK')], []);
	assert.equal(d1.removed.length, 1);
	assert.equal(d1.added.length, 0);

	const d2 = compareBugs([], [cov('b.c', 1, 'CHK')]);
	assert.equal(d2.added.length, 1);
	assert.equal(d2.removed.length, 0);
});

// ---------- KNOWN LIMITATION: BlackDuck identity only uses the CVE ----------

test('KNOWN LIMITATION: two rows sharing a CVE collapse into one identity', () => {
	// A common case: one CVE hits several components (libssl / libcurl). The
	// identity only uses the cve, so both rows get the same bugKey and the Map
	// collapses them into one entry - under-counting distinct defects.
	const r1 = bd('CVE-2024-123', { component: 'libssl' });
	const r2 = bd('CVE-2024-123', { component: 'libcurl' });

	assert.equal(bugKey(r1), bugKey(r2), 'two rows with the same CVE share an identity');

	const diff = compareBugs([], [r1, r2]);
	assert.equal(diff.added.length, 1, 'the matching CVE collapses into one added row');
	// TODO: if each component should count as its own defect, fold component into the key.
});
