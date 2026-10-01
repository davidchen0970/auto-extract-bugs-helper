import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectReport, looksLikeBlackDuck } from '../src/core/detect.js';

test('D-03 filename classification is case- and path-insensitive', () => {
	assert.equal(detectReport('A/B/COVERITY.HTML'), 'coverity');
	assert.equal(detectReport('R/app/FIRMWARE.BIN'), 'artifact');
	assert.equal(detectReport('x/BlackDuck.CSV'), 'blackduck');
});

test('D-04 looksLikeBlackDuck misses a BDSA-only report (documented gap)', () => {
	const csv = '元件,漏洞編號,嚴重性\nlib,BDSA-2017-3622,High\n';
	assert.equal(looksLikeBlackDuck(csv), false); // no CVE-20xx -> not detected
	assert.equal(looksLikeBlackDuck('元件,漏洞編號,severity\nlib,CVE-2024-1000,High\n'), true);
});
