import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCSVtext, parseBlackDuck } from '../src/core/blackduck.js';

test('B-03 quoted fields with escaped double quotes unescape to one quote', () => {
	const rows = parseCSVtext('"say ""hi""","next"\n');
	assert.equal(rows[0][0], 'say "hi"');
	assert.equal(rows[0][1], 'next');
});

test('B-04 a newline inside a quoted field stays in the same row', () => {
	const rows = parseCSVtext('"line1\nline2",x\n');
	assert.equal(rows.length, 1);
	assert.equal(rows[0][0], 'line1\nline2');
});

test('B-09 a trailing newline does not leave a phantom empty row', () => {
	assert.equal(parseCSVtext('a,b\n').length, 1);
	assert.equal(parseCSVtext('a,b\n\n').length, 1);
	assert.equal(parseCSVtext('').length, 0);
});

test('B-05 a header-only file yields an empty bug list with zero totals', () => {
	const r = parseBlackDuck('元件,漏洞編號,嚴重性,CVSS\n');
	assert.equal(r.bugs.length, 0);
	assert.equal(r.totals.total, 0);
	assert.equal(r.totals.HIGH, 0);
});

test('B-07 a short row yields empty strings, not a throw', () => {
	const r = parseBlackDuck('元件,漏洞編號,嚴重性,CWE\nfoo,CVE-2024-1,,');
	assert.equal(r.bugs.length, 1);
	assert.equal(r.bugs[0].component, 'foo');
	assert.equal(r.bugs[0].severity, undefined); // unknown column -> absent by design
	assert.equal(r.bugs[0].cwe, '');
});

test('B-08 fix status is normalised to uppercase', () => {
	const r = parseBlackDuck('元件,漏洞編號,修復狀態\nlib, CVE-2024-9, open\n');
	assert.equal(r.bugs[0].fix, 'OPEN');
});
