import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

let classifyReports;

const enc = (s) => new TextEncoder().encode(s);

before(async () => {
	const dom = new JSDOM('<!doctype html><html><body></body></html>');
	globalThis.window = dom.window;
	globalThis.document = dom.window.document;
	globalThis.DOMParser = dom.window.DOMParser;
	globalThis.Node = dom.window.Node;
	({ classifyReports } = await import('../src/core/classify.js'));
});

const COV_HTML = (name, line) => `<html><body><table id="det"><tbody>
	<tr data-sev="MEDIUM">
		<td>1</td><td>2</td><td>3</td>
		<td>Deref<div class="sub">NULL_RETURNS</div></td>
		<td><span class="file">${name}<b>${line}</b></span></td>
		<td><div class="desc"><div>deref of null</div></div></td>
	</tr>
</tbody></table></body></html>`;

const BD_CSV = '元件,漏洞編號,嚴重性,CVSS\nlib,CVE-2024-1000,High,7.5\n';

test('K-01 classify splits coverity/bd reports from artifacts/other', () => {
	const entries = [
		{ name: 'Coverity.html', data: enc(COV_HTML('a.c', 7)) },
		{ name: 'BD_guidance_details.csv', data: enc(BD_CSV) },
		{ name: 'fw.bin', data: enc('NOT PARSABLE') },
		{ name: 'plain.csv', data: enc('a,b\n') },
	];
	const { reports, artifacts } = classifyReports(entries);
	assert.equal(reports.length, 2);
	assert.deepEqual(reports.map((r) => r.type).sort(), ['blackduck', 'coverity']);
	assert.equal(reports.find((r) => r.type === 'coverity').bugs.length, 1);
	assert.equal(reports.find((r) => r.type === 'blackduck').bugs.length, 1);
	assert.equal(artifacts.length, 2);
	assert.deepEqual(artifacts.map((a) => a.name).sort(), ['fw.bin', 'plain.csv']);
});

test('K-02 a coverity-named file whose content does not look like coverity is dropped', () => {
	const { reports, artifacts } = classifyReports([
		{ name: 'Coverity.html', data: enc('plain text, no defect table') },
	]);
	assert.equal(reports.length, 0);
	assert.equal(artifacts.length, 0); // pushed into neither bucket (documented behavior)
});

test('K-04 a bd-named file whose content does not look like blackduck is dropped', () => {
	const { reports, artifacts } = classifyReports([
		{ name: 'BD_guidance_details.csv', data: enc('Component,Version\nx,1.0') },
	]);
	assert.equal(reports.length, 0);
	assert.equal(artifacts.length, 0);
});

test('K-03 empty and null input yield empty buckets', () => {
	assert.deepEqual(classifyReports([]), { reports: [], artifacts: [] });
	assert.deepEqual(classifyReports(null), { reports: [], artifacts: [] });
});
