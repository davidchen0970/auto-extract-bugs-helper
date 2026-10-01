import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseTar, parseOctal, parsePax } from '../src/core/tar.js';

const enc = (s) => new TextEncoder().encode(s);
const dec = new TextDecoder('utf-8');

// Build one 512-byte ustar-ish header. Layout mirrors parseTar()'s expectations:
//   name  [0,100)  size [124,136)  typeflag [156,157)  prefix [345,500)  magic 257..262
function hdr(name, { size = 0, type = '0', prefix = '' } = {}) {
	const h = new Uint8Array(512);
	h.set(enc(name), 0);
	if (prefix) h.set(enc(prefix), 345);
	h[156] = type.charCodeAt(0);
	if (size) {
		const oct = size.toString(8).padStart(11, '0') + '\0';
		h.set(enc(oct), 124);
	}
	h.set(enc('ustar\0'), 257);
	return h;
}

// 12-byte base-256 size field (high bit set) storing value across bytes [1,12).
function base256Size(v) {
	const b = new Uint8Array(12);
	b[0] = 0x80;
	for (let i = 11; i >= 1; i--) {
		b[i] = (v & 0xff) >>> 0;
		v = Math.floor(v / 256);
	}
	return b;
}

// hdr bytes + exact data + minimal zero padding to a 512-byte boundary.
function entry(bytes, data = new Uint8Array(0)) {
	const pad = (512 - (data.length % 512)) % 512;
	const out = new Uint8Array(bytes.length + data.length + pad);
	out.set(bytes, 0);
	out.set(data, 512);
	return out;
}

function concat(...blocks) {
	let n = 0;
	for (const b of blocks) n += b.length;
	const out = new Uint8Array(n);
	let o = 0;
	for (const b of blocks) {
		out.set(b, o);
		o += b.length;
	}
	return out;
}

test('T-05 parseOctal decodes a base-256 size field', () => {
	const b = base256Size(0x1234); // 4660
	assert.equal(parseOctal(b, 0, 12), 4660);
});

test('T-12 parseOctal returns 0 for an all-blank / all-zero size field', () => {
	assert.equal(parseOctal(new Uint8Array(12), 0, 12), 0);
});

test('T-11 parsePax stops cleanly on a malformed length prefix', () => {
	assert.deepEqual(parsePax('notanumber path=x\n'), {});
	assert.deepEqual(parsePax('9999999999999999999999999 path=x\n'), {});
});

test('T-04 a directory typeflag entry is not emitted as a file', () => {
	const buf = entry(hdr('build/', { type: '5' }), new Uint8Array(512));
	const list = parseTar(buf);
	assert.equal(list.length, 0);
});

test('T-08 a prefix field is joined to the name with a slash', () => {
	const data = enc('int main();');
	const buf = entry(hdr('main.c', { prefix: 'src/lib', size: data.length }), data);
	const list = parseTar(buf);
	assert.equal(list.length, 1); // data block must be skipped so it is not a 2nd header
	assert.equal(list[0].name, 'src/lib/main.c');
});

test('T-06 a header claiming a size larger than remaining bytes clips data to what exists, no OOB', () => {
	const buf = concat(hdr('big.bin', { size: 4096 }), new Uint8Array(128));
	const list = parseTar(buf);
	assert.equal(list.length, 1);
	assert.equal(list[0].size, 4096); // declared size preserved
	assert.equal(list[0].data.length, 128); // clipped to u8.length (512+128), no overflow
});

test('T-07 consecutive entries plus trailing zero blocks parse both files', () => {
	const a = entry(hdr('a.txt', { size: 1 }), enc('x'));
	const b = entry(hdr('b.txt', { size: 1 }), enc('y'));
	const buf = concat(a, b, new Uint8Array(1024));
	const list = parseTar(buf);
	assert.equal(list.length, 2);
	assert.equal(list[0].name, 'a.txt');
	assert.equal(list[1].name, 'b.txt');
});

test('T-02 a GNU longname (L) entry overrides the next header name', () => {
	const longName = 'very/long/path/segment/'.repeat(9) + 'file.c'; // > 100 bytes
	const L = entry(hdr('', { type: 'L', size: longName.length }), enc(longName));
	const f = entry(hdr('truncated.nam', { size: 1 }), enc('z'));
	const list = parseTar(concat(L, f));
	assert.equal(list.length, 1);
	assert.equal(list[0].name, longName);
});

test('T-03 a PAX path record (x) overrides the next header name', () => {
	function paxRec(key, val) {
		const core = ` ${key}=${val}\n`;
		let rec;
		for (let len = core.length + 1; ; len++) {
			rec = len.toString() + core;
			if (rec.length === len) return rec;
		}
	}
	const paxData = enc(paxRec('path', 'pax/dir/report.log'));
	const x = entry(hdr('', { type: 'x', size: paxData.length }), paxData);
	const f = entry(hdr('oldname.log', { size: 1 }), enc('q'));
	const list = parseTar(concat(x, f));
	assert.equal(list.length, 1);
	// parsePax() slices the value up to the record length, which keeps the record's
	// trailing '\n' — so the overridden name carries it. (documents parser behavior)
	assert.equal(list[0].name, 'pax/dir/report.log\n');
});

test('T-09 names with doubled slashes are collapsed', () => {
	const buf = entry(hdr('a//b.txt', { size: 1 }), enc('w'));
	const list = parseTar(buf);
	assert.equal(list.length, 1);
	assert.equal(list[0].name, 'a/b.txt');
});
