import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectReport, looksLikeCoverity, looksLikeBlackDuck, isTarBytes } from '../src/core/detect.js';

test('detectReport classifies by filename', () => {
	assert.equal(detectReport('firmware.bin'), 'artifact');
	assert.equal(detectReport('Coverity.html'), 'coverity');
	assert.equal(detectReport('BD_output.csv'), 'blackduck');
	assert.equal(detectReport('pages.html'), 'html');
	assert.equal(detectReport('data.csv'), 'csv');
	assert.equal(detectReport('notes.txt'), 'other');
});

test('looksLikeCoverity sniffs the defect table marker', () => {
	assert.equal(looksLikeCoverity('<html><table id="det"></table></html>'), true);
	assert.equal(looksLikeCoverity('plain text body'), false);
});

test('looksLikeBlackDuck matches CVE + severity wording', () => {
	assert.equal(looksLikeBlackDuck('CVE-2024-1000,severity,CVSS'), true);
	assert.equal(looksLikeBlackDuck('not a vuln list at all'), false);
});

test('isTarBytes recognises a ustar header, not plain html', () => {
	const tar = new Uint8Array(1024);
	tar.set(new TextEncoder().encode('ustar\0'), 257);
	assert.equal(isTarBytes(tar), true);

	const html = new TextEncoder().encode('<html><body>defects</body></html>');
	assert.equal(isTarBytes(html), false);
	assert.equal(isTarBytes(new Uint8Array(100)), false);
});
