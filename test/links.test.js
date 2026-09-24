import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cveHref, cveLink, cweHref, cweLink } from '../src/ui/util.js';

test('cveHref builds NVD url only for CVE ids', () => {
	assert.equal(cveHref('CVE-2024-1000'), 'https://nvd.nist.gov/vuln/detail/CVE-2024-1000');
	assert.equal(cveHref(' cve-2017-5638 '), 'https://nvd.nist.gov/vuln/detail/CVE-2017-5638');
	assert.equal(cveHref('BDSA-2017-3622'), '');
	assert.equal(cveHref(''), '');
	assert.equal(cveHref('some text'), '');
});

test('cveLink keeps BDSA as plain text, never an anchor', () => {
	assert.ok(cveLink('CVE-2024-1000').includes('href="https://nvd.nist.gov/vuln/detail/CVE-2024-1000"'));
	assert.ok(!cveLink('BDSA-2017-3622').includes('<a'));
	assert.equal(cveLink('BDSA-2017-3622'), 'BDSA-2017-3622');
}, {});

test('cweHref builds MITRE url from CWE-<n> or bare <n>', () => {
	assert.equal(cweHref('CWE-79'), 'https://cwe.mitre.org/data/definitions/79.html');
	assert.equal(cweHref('CWE-120'), 'https://cwe.mitre.org/data/definitions/120.html');
	assert.equal(cweHref('120'), 'https://cwe.mitre.org/data/definitions/120.html');
	assert.equal(cweHref('not-a-cwe'), '');
});

test('cweLink anchors valid CWE and escapes text', () => {
	const a = cweLink('CWE-787');
	assert.ok(a.includes('href="https://cwe.mitre.org/data/definitions/787.html"'));
	assert.equal(cweLink('not-a-cwe'), 'not-a-cwe');
});
