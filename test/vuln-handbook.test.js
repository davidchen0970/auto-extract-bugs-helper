import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';

async function loadVulnHandbook() {
	const here = fileURLToPath(new URL('.', import.meta.url));
	const dir = path.join(here, '..', 'data', 'vuln');
	const manifest = (await import(pathToFileURL(path.join(dir, 'index.js')).href)).default;
	const files = [...new Set(Object.values(manifest))];
	const mods = await Promise.all(files.map((f) => import(pathToFileURL(path.join(dir, f)).href)));
	return mods.flatMap((m) => m.default);
}

const REQUIRED = ['key', 'cve', 'pkg', 'cat', 'name', 'what', 'recommendation'];

test('every vulnerability-handbook entry carries the required fields', async () => {
	const entries = await loadVulnHandbook();
	assert.ok(entries.length >= 1, `expected >= 1 entries, got ${entries.length}`);
	for (const e of entries) {
		for (const k of REQUIRED) {
			assert.ok(e[k] != null && String(e[k]).length > 0, `${e.key || '<no key>'} missing or empty '${k}'`);
		}
		assert.ok(e.what.length >= 20, `${e.key} 'what' too thin`);
	}
});

test('the composite key is the CVE@pkg combination and is unique', async () => {
	const entries = await loadVulnHandbook();
	for (const e of entries) {
		assert.equal(e.key, String(e.cve).toUpperCase() + '@' + e.pkg,
			`${e.key} key must be the CVE@pkg combination`);
	}
	const uniq = new Set(entries.map((e) => e.key));
	assert.equal(uniq.size, entries.length, 'duplicate composite keys across the handbook');
});
