import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { fileURLToPath } from 'node:url';

async function loadHandbook() {
	const here = fileURLToPath(new URL('.', import.meta.url));
	const cweDir = path.join(here, '..', 'data', 'cwe');
	const manifest = (await import(pathToFileURL(path.join(cweDir, 'index.js')).href)).default;
	const files = [...new Set(Object.values(manifest))];
	const mods = await Promise.all(files.map((f) => import(pathToFileURL(path.join(cweDir, f)).href)));
	return mods.flatMap((m) => m.default).sort((a, b) => +a.id.replace('CWE-', '') - +b.id.replace('CWE-', ''));
}

const num = (e) => +e.id.replace(/CWE-/, '');
// Structural fields every entry must carry; the code examples only exist for completed entries
// (an Incomplete entry is an acknowledged placeholder, Deprecated may be terse).
const REQUIRED = ['cat', 'id', 'name', 'status', 'what', 'refs', 'tags'];
const EXAMPLE = ['problem', 'fixed', 'patch'];

test('the handbook is made of >900 { cat, ...entry } records', async () => {
	const entries = await loadHandbook();
	assert.ok(entries.length >= 900, `expected >= 900 entries, got ${entries.length}`);
	assert.ok(entries.every((e) => e.cat && e.id && /^CWE-\d+$/.test(e.id)), 'entry missing cat or malformed id');
});

test('every entry has required fields, and completed entries have examples', async () => {
	const entries = await loadHandbook();
	assert.equal(entries.length, 939, 'handbook must keep all 939 entries across the folders');
	for (const e of entries) {
		for (const k of REQUIRED) {
			assert.ok(e[k] != null && String(e[k]).length > 0, `${e.id} missing or empty '${k}'`);
		}
		if (e.status !== 'Incomplete' && e.status !== 'Deprecated') {
			for (const k of EXAMPLE) {
				assert.ok(String(e[k] || '').length > 0, `${e.id} missing or empty '${k}'`);
			}
			assert.ok(e.what.length >= 20, `${e.id} 'what' too thin`);
		}
	}
});

test('the handbook is sorted ascending and has no duplicate CWE ids', async () => {
	const entries = await loadHandbook();
	for (let i = 1; i < entries.length; i++) {
		assert.ok(num(entries[i]) > num(entries[i - 1]), `not ascending at index ${i} (${entries[i].id})`);
	}
	const uniq = new Set(entries.map((e) => e.id));
	assert.equal(uniq.size, entries.length, 'duplicate CWE ids across the handbook');
});
