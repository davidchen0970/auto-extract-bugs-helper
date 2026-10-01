import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';

const enc = (s) => new TextEncoder().encode(s);

async function getIngest() {
	const { ingestFile } = await import('../src/core/ingest.js');
	return ingestFile;
}

// Build a single-file ustar archive whose first bytes pass isTarBytes().
function simpleTar(name, content) {
	const data = enc(content);
	const buf = new Uint8Array(512 + 512);
	buf.set(enc(name), 0);
	const sizeOct = data.length.toString(8).padStart(11, '0') + '\0';
	buf.set(enc(sizeOct), 124);
	buf[156] = 0x30; // typeflag '0' = regular file
	buf.set(data, 512);
	buf.set(enc('ustar\0'), 257); // ustar magic so isTarBytes() recognises it
	return buf;
}

test('I-01 a plain .tar file expands to its member entries', async () => {
	const ingestFile = await getIngest();
	const tar = simpleTar('src/x.c', 'int x(){};');
	const out = await ingestFile(new File([tar], 'bundle.tar', { type: 'application/x-tar' }));
	assert.equal(out.length, 1);
	assert.equal(out[0].name, 'src/x.c');
	assert.equal(new TextDecoder().decode(out[0].data), 'int x(){};');
});

test('I-02 a .tar.gz expands via gzip then tar', async () => {
	const ingestFile = await getIngest();
	const gz = new Uint8Array(gzipSync(simpleTar('a.txt', 'hello')));
	const out = await ingestFile(new File([gz], 'b.tgz', { type: 'application/gzip' }));
	assert.equal(out[0].name, 'a.txt');
	assert.equal(new TextDecoder().decode(out[0].data), 'hello');
});

test('I-03 a single report file wraps into a single entry', async () => {
	const ingestFile = await getIngest();
	const html = enc('<html><body>coverity defects</body></html>');
	const out = await ingestFile(new File([html], 'Coverity.html', { type: 'text/html' }));
	assert.equal(out.length, 1);
	assert.equal(out[0].name, 'Coverity.html');
});

test('I-04 a non-.gz name still un-gzips when the magic bytes say so', async () => {
	const ingestFile = await getIngest();
	const gz = new Uint8Array(gzipSync(enc('a,b\n')));
	const out = await ingestFile(new File([gz], 'data.csv', { type: 'application/octet-stream' }));
	assert.equal(out.length, 1);
	assert.equal(out[0].name, 'data.csv');
	assert.equal(new TextDecoder().decode(out[0].data), 'a,b\n');
});

test('I-05 a .gz whose content is not gzip rejects instead of hanging', async () => {
	const ingestFile = await getIngest();
	const bad = enc('this is not gzip at all');
	const file = new File([bad], 'x.gz', { type: 'application/gzip' });
	await assert.rejects(ingestFile(file));
});
