import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { indentationViolations, tabcheckDir } from '../scripts/tabcheck.mjs';

test('tab-indent (src) has no violations', () => {
	const { scanned, violations, unparsable } = tabcheckDir('src');
	assert.ok(scanned >= 20, `expected >=20 first-party files, got ${scanned}`);
	assert.equal(unparsable.length, 0);
	assert.deepEqual(violations, []);
});

test('tabs are accepted', () => {
	assert.deepEqual(indentationViolations('function a() {\n\treturn 1;\n}\n'), []);
});

test('4-space JS indentation is a violation', () => {
	const v = indentationViolations('function a() {\n    return 1;\n}\n');
	assert.equal(v.length, 1);
	assert.equal(v[0].line, 2);
});

test('backtick inside a line comment does not open a template', () => {
	// Under a hand-rolled lexer this `` ` `` in a comment would swallow the following
	// space-indented line; the AST parser must treat it as a comment and flag it.
	const src = '// `\nfunction a() {\n    return 1;\n}\n';
	const v = indentationViolations(src);
	assert.equal(v.length, 1, 'the space-indented JS must still be reported');
	assert.equal(v[0].line, 3);
});

test('backtick inside a block comment does not open a template', () => {
	const src = 'function a() {\n  /*\n   * ` not a template\n   */\n\treturn 1;\n}\n';
	const v = indentationViolations(src);
	// the three block-comment lines are space-indented; they are plain JS comments
	// (not template text), so under the tab rule each is reported
	assert.equal(v.length, 3);
});

test('backtick inside single/double-quoted strings does not open a template', () => {
	const src = 'const a = "`";\nconst b = \'`\';\n\tfunction ok() {}\n';
	// no space-indented JS besides none -> no violations (quotes are not templates)
	assert.deepEqual(indentationViolations(src), []);
});

test('regex with braces inside a template interpolation does not pop out early', () => {
	const src = 'const n = `${ /}/.test(x) ? 1 : 0 }`;\nfunction a() {\n\treturn 1;\n}\n';
	assert.deepEqual(indentationViolations(src), []);
});

test('object-literal braces inside a template interpolation are kept together', () => {
	const src = 'const o = `${ () => ({ a: 1 }) }`;\nconst p = `${ {\n\tb: 2\n} }`;\n';
	// the `` b `` line uses a tab and the rest are single-line -> no violations
	assert.deepEqual(indentationViolations(src), []);
});

test('nested template literals spanning lines keep their HTML indentation allowed', () => {
	const src = [
		'export function e(items) {',
		'\tconst html = `',
		'    <div>',
		'\t\t${items.map((x) => `',
		'            <span>${x}</span>',
		'\t\t`)}',
		'    </div>',
		'\t`;',
		'\treturn html;',
		'}',
		''
	].join('\n');
	assert.deepEqual(indentationViolations(src), []);
});

test('HTML markup indented with spaces inside a template is allowed', () => {
	const src = 'const s = `\n  <div class="x">\n    ${y}\n  </div>\n`;\n';
	assert.deepEqual(indentationViolations(src), []);
});

test('empty / missing root is not a crash', () => {
	const dir = mkdtempSync(join(tmpdir(), 'tabcheck-empty-'));
	try {
		assert.deepEqual(tabcheckDir(dir).violations, []);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test('a realistic first-party file passes end-to-end (dir walk excludes vendor/)', () => {
	const dir = mkdtempSync(join(tmpdir(), 'tabcheck-good-'));
	try {
		writeFileSync(join(dir, 'ok.js'), 'export function ok() {\n\treturn `<i>${1}</i>`;\n}\n');
		// a vendored file indented with spaces must be skipped
		mkdirSync(join(dir, 'vendor'), { recursive: true });
		writeFileSync(join(dir, 'vendor', 'lib.js'), 'function v() {\n    return 1;\n}\n');
		const { violations } = tabcheckDir(dir);
		assert.deepEqual(violations, []);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});
