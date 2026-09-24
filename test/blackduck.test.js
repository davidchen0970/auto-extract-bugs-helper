import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCSVtext, parseBlackDuck } from '../src/core/blackduck.js';

test('parseCSVtext handles quoted commas and CRLF rows', () => {
	const rows = parseCSVtext('"a,b",c\r\nd,e\n');
	assert.deepEqual(rows[0], ['a,b', 'c']);
	assert.deepEqual(rows[1], ['d', 'e']);
});

test('parseCSVtext strips a UTF-8 BOM from the first field', () => {
	const rows = parseCSVtext('\uFEFFaa,bb\n');
	assert.equal(rows[0][0], 'aa');
});

test('parseBlackDuck maps headers, severities and totals', () => {
	const csv = [
		'元件,目前版本,漏洞編號,嚴重性,CVSS,修復狀態,CWE,短期建議版本,長期建議版本,說明,官方解法,暫時規避方式,已知攻擊程式',
		'libfoo,1.2.3,CVE-2024-1000,High,7.5,Open,CWE-79,1.2.4,2.0.0,描述,解法,繞過,N/A',
	].join('\n');
	const r = parseBlackDuck(csv);
	assert.equal(r.bugs.length, 1);
	assert.equal(r.bugs[0].src, 'blackduck');
	assert.equal(r.bugs[0].component, 'libfoo');
	assert.equal(r.bugs[0].version, '1.2.3');
	assert.equal(r.bugs[0].cve, 'CVE-2024-1000');
	assert.equal(r.bugs[0].cvss, '7.5');
	assert.equal(r.bugs[0].cwe, 'CWE-79');
	assert.equal(r.bugs[0].sev, 'HIGH');
	assert.equal(r.totals.total, 1);
	assert.equal(r.totals.HIGH, 1);
});
