import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseTar } from '../src/core/tar.js';

function makeFileTar(name, content) {
	const data = new TextEncoder().encode(content);
	const buf = new Uint8Array(1024);
	buf.set(new TextEncoder().encode(name), 0);
	// octal size field (12 bytes) at offset 124
	const sizeOct = data.length.toString(8).padStart(11, '0') + '\0';
	buf.set(new TextEncoder().encode(sizeOct), 124);
	buf[156] = 0x30; // typeflag '0' = regular file
	buf.set(data, 512);
	return buf;
}

test('parseTar reads a ustar file entry', () => {
	const buf = makeFileTar('src/main.js', 'export const x = 1;\n');
	const entries = parseTar(buf);
	assert.equal(entries.length, 1);
	assert.equal(entries[0].name, 'src/main.js');
	assert.equal(entries[0].type, 'file');
	assert.equal(entries[0].size, 20);
	assert.equal(new TextDecoder().decode(entries[0].data), 'export const x = 1;\n');
});

test('parseTar returns empty for a zeroed archive', () => {
	assert.deepEqual(parseTar(new Uint8Array(1024)), []);
});
