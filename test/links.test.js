import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cveHref, cveLink, cveOrgHref, cweHref, cweLink, kernelFixHref, ghAdvisoryHref, vulnersHref, googleAiUrl, cveExtLinks } from '../src/ui/util.js';

test('cveHref builds NVD url only for CVE ids', () => {
	assert.equal(cveHref('CVE-2024-1000'), 'https://nvd.nist.gov/vuln/detail/CVE-2024-1000');
	assert.equal(cveHref(' cve-2017-5638 '), 'https://nvd.nist.gov/vuln/detail/CVE-2017-5638');
	assert.equal(cveHref('BDSA-2017-3622'), '');
	assert.equal(cveHref(''), '');
	assert.equal(cveHref('some text'), '');
});

test('kernelFixHref searches upstream for a kernel CVE', () => {
	assert.equal(
		kernelFixHref('CVE-2025-1234', 'linux-kernel-5.15'),
		'https://github.com/torvalds/linux/search?q=CVE-2025-1234&type=commits');
});

test('kernelFixHref stays empty for non-kernel or non-CVE ids', () => {
	assert.equal(kernelFixHref('CVE-2025-1234', 'glibc'), '');
	assert.equal(kernelFixHref('BDSA-2017-3622', 'linux-kernel-5.15'), '');
	assert.equal(kernelFixHref('', 'linux-kernel-5.15'), '');
});

test('cveOrgHref builds cve.org url only for CVE ids', () => {
	assert.equal(cveOrgHref('CVE-2024-1000'), 'https://www.cve.org/CVERecord?id=CVE-2024-1000');
	assert.equal(cveOrgHref('BDSA-2017-3622'), '');
	assert.equal(cveOrgHref(''), '');
});

test('resolution lookups dereference only well-formed CVE ids', () => {
	assert.equal(ghAdvisoryHref('CVE-2024-1000'), 'https://github.com/advisories?query=CVE-2024-1000');
	assert.equal(vulnersHref('cve-2024-1000'), 'https://vulners.com/search?query=CVE-2024-1000');
	assert.equal(ghAdvisoryHref('BDSA-2017-3622'), '');
	assert.equal(vulnersHref('anything'), '');
});

test('googleAiUrl builds a "修復 方案" deep link only for CVE ids', () => {
	assert.equal(googleAiUrl('CVE-2024-1000'),
		'https://www.google.com/search?q=' + encodeURIComponent('CVE-2024-1000 修復 方案'));
	assert.equal(googleAiUrl('BDSA-2017-3622'), '');
});

test('cveExtLinks renders a reference row for CVE ids and nothing for BDSA', () => {
	const html = cveExtLinks('CVE-2024-1000');
	assert.ok(html.includes('class="kv cve-help"'));
	assert.ok(html.includes('class="xlnk x-cveorg"'));
	assert.ok(html.includes('class="xlnk x-gh"'));
	assert.ok(html.includes('class="xlnk x-vulners"'));
	assert.ok(html.includes('class="xlnk x-google"'));
	assert.ok(html.includes('>google 搜尋</a>'));
	assert.equal(cveExtLinks('BDSA-2017-3622'), '');
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
