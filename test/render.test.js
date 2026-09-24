import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

let renderMd;

before(async () => {
	globalThis.window = new JSDOM('<!doctype html><html><body></body></html>').window;
	({ renderMd } = await import('../src/ui/md.js'));
});

test('renderMd turns a markdown link into an anchor', () => {
	const out = renderMd('[2.34](https://ftp.gnu.org/gnu/glibc/)');
	assert.ok(out.includes('href="https://ftp.gnu.org/gnu/glibc/"'));
	assert.ok(out.includes('>2.34</a>'));
});

test('renderMd keeps bold and code', () => {
	const out = renderMd('**critical**: run `npm test`');
	assert.ok(out.includes('<strong>critical</strong>'));
	assert.ok(out.includes('<code>npm test</code>'));
});

test('renderMd strips script injection', () => {
	const out = renderMd('<script>alert(1)</script> hi');
	assert.ok(!out.toLowerCase().includes('<script'));
	assert.ok(!out.includes('alert(1)') || !out.includes('<script'));
	assert.ok(out.includes('hi'));
});
