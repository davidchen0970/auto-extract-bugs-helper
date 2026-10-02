import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
const cweDir = path.join(here, '..', 'data', 'cwe');

const num = (e) => +e.id.replace(/CWE-/, '');

test('manifest is generated and every id resolves to a real, well-formed category file', async () => {
	const manifest = (await import(pathToFileURL(path.join(cweDir, 'index.js')).href)).default;
	const ids = Object.keys(manifest);
	assert.equal(ids.length, 939, 'manifest must map all 939 CWE ids');
	const uniq = new Set(ids);
	assert.equal(uniq.size, ids.length, 'duplicate id in manifest');

	for (const id of ids) {
		const file = manifest[id];
		const p = path.join(cweDir, file);
		assert.ok(fs.existsSync(p), `manifest -> missing file for ${id}: ${file}`);
		const mod = await import(pathToFileURL(p).href);
		const list = mod.default;
		assert.ok(Array.isArray(list), `${file} must export an array`);
		assert.ok(list.some((e) => e.id === id), `${file} lacks ${id}`);
	}
});

test('every referenced category file is internally consistent', async () => {
	const manifest = (await import(pathToFileURL(path.join(cweDir, 'index.js')).href)).default;
	const files = [...new Set(Object.values(manifest))];
	const flat = [];
	for (const f of files) {
		const list = (await import(pathToFileURL(path.join(cweDir, f)).href)).default;
		for (const e of list) {
			assert.ok(/^CWE-\d+$/.test(e.id), `${f} has malformed id ${e.id}`);
			assert.ok(typeof e.cat === 'string' && e.cat.length > 0, `${f}/${e.id} missing cat`);
			flat.push(e);
		}
	}
	assert.equal(flat.length, 939, 'sum of all category arrays must be 939');
	const uniq = new Set(flat.map((e) => e.id));
	assert.equal(uniq.size, flat.length, 'duplicate CWE id across folders');
	flat.sort((a, b) => +a.id.replace('CWE-', '') - +b.id.replace('CWE-', ''));
	flat.forEach((e, i, arr) => {
		if (i) assert.ok(num(arr[i]) > num(arr[i - 1]), `id not strictly ascending at ${e.id}`);
	});
});
