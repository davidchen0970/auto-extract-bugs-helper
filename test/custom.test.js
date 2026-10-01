import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCustomCSV, looksLikeCustomCSV, cleanVulnId, normalizeCwe } from '../src/core/custom.js';
import { classifyReports } from '../src/core/classify.js';

const enc = (s) => new TextEncoder().encode(s);

// A representative English Black Duck SCA export.
const HEADER =
	'Used by,Component id,Version id,Origin id,Component name,Component version name,' +
	'Component origin name,Component origin id,Component origin version name,' +
	'Vulnerability id,Description,Published on,Updated on,Base score,Exploitability,Impact,' +
	'Vulnerability source,Remediation status,Status justification,Remediation target date,' +
	'Remediation actual date,Remediation comment,URL,Security Risk,Project path,Overall score,' +
	'CWE Ids,Solution available,Workaround available,Exploit available,CVSS Version,' +
	'Match type,Reachable,Vulnerability tags,CISA Vulnerability ID,CISA Exploit Added,' +
	'CISA Due Date,CISA Required Action,CISA Vulnerability Name';

const ROW = (vuln, component, sev, score) => [
	'', 'c1', 'v1', 'o1', component, '1.2.3', 'maven', component + ':1.2.3', '1.2.3',
	vuln, 'some description', '2026/1/1', '2026/1/2', score, '1.0', '2.0', 'NVD',
	'New', '', '', '', '', 'https://example/' + vuln, sev, 'Proj X', score,
	'"[CWE-22, CWE-200]"', 'true', 'false', 'false', 'CVSS 3.x', 'Exact', 'false', '',
	'', '', '', '', '',
].join(',');

const CSV = [HEADER, ROW('CVE-2026-1000', 'libfoo', 'HIGH', '7.5')].join('\n');

test('looksLikeCustomCSV only claims the English SCA format', () => {
	assert.equal(looksLikeCustomCSV(CSV), true);
	assert.equal(looksLikeCustomCSV('元件,漏洞編號,嚴重性\nlib,CVE-2024-1000,High\n'), false);
	assert.equal(looksLikeCustomCSV('a,b,c\n1,2,3\n'), false);
});

test('cleanVulnId strips trailing BDSA/CVE suffixes down to the primary id', () => {
	assert.equal(cleanVulnId('CVE-2020-15366 (BDSA-2020-3798)'), 'CVE-2020-15366');
	assert.equal(cleanVulnId('BDSA-2024-8408 (CVE-2024-50236)'), 'CVE-2024-50236');
	assert.equal(cleanVulnId('BDSA-2024-4090'), 'BDSA-2024-4090');
	assert.equal(cleanVulnId('CVE-2026-49356'), 'CVE-2026-49356');
});

test('normalizeCwe parses bracketed lists and de-duplicates', () => {
	assert.deepEqual(normalizeCwe('[CWE-22, CWE-200]'), ['CWE-22', 'CWE-200']);
	assert.deepEqual(normalizeCwe('[]'), []);
	assert.deepEqual(normalizeCwe('cwe-400'), ['CWE-400']);
});

test('parseCustomCSV maps all master columns onto top-level fields', () => {
	const r = parseCustomCSV(CSV);
	assert.equal(r.bugs.length, 1);
	const b = r.bugs[0];
	assert.equal(b.src, 'custom');
	assert.equal(b.component, 'libfoo');
	assert.equal(b.version, '1.2.3');
	assert.equal(b.cve, 'CVE-2026-1000');
	assert.equal(b.cveClean, 'CVE-2026-1000');
	assert.equal(b.cvss, '7.5');
	assert.equal(b.cwe, 'CWE-22, CWE-200');
	assert.deepEqual(b.cweList, ['CWE-22', 'CWE-200']);
	assert.equal(b.sev, 'HIGH');
	assert.equal(b.fix, 'NEW');
	assert.equal(b.securityRisk, 'HIGH');
	assert.equal(b.url, 'https://example/CVE-2026-1000');
	assert.equal(r.totals.total, 1);
	assert.equal(r.totals.HIGH, 1);
});

test('parseCustomCSV keeps every original column (full fidelity) in fields', () => {
	const b = parseCustomCSV(CSV).bugs[0];
	const keys = Object.keys(b.fields);
	// Header has 39 columns and every one must survive.
	assert.equal(keys.length, 39);
	for (const h of HEADER.split(',')) assert.ok(keys.includes(h.trim()), 'missing column ' + h);
	assert.equal(b.fields['Component name'], 'libfoo');
	assert.equal(b.fields['Security Risk'], 'HIGH');
	assert.equal(b.fields['URL'], 'https://example/CVE-2026-1000');
});

test('custom source wins over the lenient blackduck probe for English exports', async () => {
	const dom = new (await import('jsdom')).JSDOM('<!doctype html><html><body></body></html>');
	globalThis.window = dom.window;
	globalThis.document = dom.window.document;
	globalThis.DOMParser = dom.window.DOMParser;
	globalThis.Node = dom.window.Node;

	const entries = [
		{ name: 'vulnerabilities.csv', data: enc(CSV) },
		// plain english csv with CVSS in a data row should also land in custom, not be
		// dropped as an artifact or mis-parsed as blackduck.
		{ name: '_guidance_details.csv', data: enc(CSV) },
	];
	const { reports, artifacts } = classifyReports(entries);
	assert.equal(artifacts.length, 0);
	assert.equal(reports.length, 2);
	for (const r of reports) {
		assert.equal(r.type, 'custom');
		assert.equal(r.bugs.length, 1);
		assert.equal(r.bugs[0].component, 'libfoo');
	}
});
