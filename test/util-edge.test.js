import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cveHref, esc, fmtSize, shortName } from '../src/ui/util.js';

test('U-02 a malformed CVE (too few digits) yields no link', () => {
	assert.equal(cveHref('CVE-2024-1'), '');
	assert.equal(cveHref('CVE-2024-1234'), 'https://nvd.nist.gov/vuln/detail/CVE-2024-1234');
});

test('U-04 esc escapes HTML specials and keeps unicode/emoji', () => {
	assert.equal(esc('&<>"\''), '&amp;&lt;&gt;&quot;&#39;');
	assert.equal(esc('中文→🎯'), '中文→🎯');
	assert.equal(esc(null), '');
});

test('U-05 fmtSize covers boundary sizes', () => {
	assert.equal(fmtSize(0), '0 B');
	assert.equal(fmtSize(1023), '1023 B');
	assert.equal(fmtSize(1024), '1.0 KB');
	assert.equal(fmtSize(1024 * 1024), '1.0 MB');
	assert.equal(fmtSize(null), '');
});

test('U-06 shortName keeps only the basename', () => {
	assert.equal(shortName('dir/sub/file.txt'), 'file.txt');
	assert.equal(shortName('flat.txt'), 'flat.txt');
});
