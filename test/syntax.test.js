import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readdirSync, statSync } from 'node:fs';
import path from 'node:path';

function collectJs(dir, out) {
	for (const name of readdirSync(dir)) {
		const full = path.join(dir, name);
		if (statSync(full).isDirectory()) collectJs(full, out);
		else if (name.endsWith('.js')) out.push(full);
	}
}

const files = [];
collectJs(path.resolve('src'), files);
files.push(path.resolve('app.js'));

for (const f of files) {
	test(`node --check parses ${f}`, () => {
		assert.doesNotThrow(() => execFileSync('node', ['--check', f], { encoding: 'utf8' }));
	});
}
