import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bugKey, bugFingerprint, compareBugs } from '../src/core/compare.js';

function cov(file, line, checker, extra) {
	return Object.assign({ src: 'coverity', file, line, type: 'X', checker }, extra);
}
function bd(cve, extra) {
	return Object.assign({ src: 'blackduck', cve }, extra);
}

test('P-05 identical identity with differing heavy code/events stays in the same bucket', () => {
	const a = cov('f.c', 7, 'CHK', {
		desc: 'same',
		events: [{ text: 'run 1' }],
		code: [{ file: 'f.c', items: [{ text: 'v1' }] }],
	});
	const b = cov('f.c', 7, 'CHK', {
		desc: 'same',
		events: [{ text: 'run 2' }],
		code: [{ file: 'f.c', items: [{ text: 'v2' }] }],
	});
	const diff = compareBugs([a], [b]);
	assert.equal(diff.same.length, 1); // code/events excluded from fingerprint
	assert.equal(diff.changed.length, 0);
});

test('P-03 same CVE across two components collapses to one identity (documented gap)', () => {
	const libssl = bd('CVE-2024-123', { component: 'libssl' });
	const libcurl = bd('CVE-2024-123', { component: 'libcurl' });
	assert.equal(bugKey(libssl), bugKey(libcurl), 'identity ignores component');
	assert.equal(compareBugs([], [libssl, libcurl]).added.length, 1);
});

test('P-02 a missing side is treated as an empty list', () => {
	assert.equal(compareBugs(null, undefined).added.length, 0);
	assert.equal(bugKey(null), '');
	assert.equal(bugFingerprint(undefined), 'undefined');
});
