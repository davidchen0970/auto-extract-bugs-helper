import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { decompressGzip } from '../src/core/gzip.js';

test('decompressGzip round-trips zlib output back to original bytes', async () => {
	const raw = new TextEncoder().encode('hello gzip → 中文');
	const gz = new Uint8Array(gzipSync(raw));
	const out = await decompressGzip(gz);
	assert.equal(new TextDecoder().decode(out), 'hello gzip → 中文');
});
