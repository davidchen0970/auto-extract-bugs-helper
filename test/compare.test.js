import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bugKey, bugFingerprint, compareBugs } from '../src/core/compare.js';

function cov(file, line, type, checker, extra) {
	return Object.assign({ src: 'coverity', sev: 'MEDIUM', file, line, type, checker }, extra || {});
}
function bd(cve, extra) {
	return Object.assign({ src: 'blackduck', sev: 'HIGH', cve }, extra || {});
}

test('bugKey: BlackDuck 用 CVE 當身份', () => {
	assert.equal(bugKey(bd('CVE-2024-0001')), 'bd:CVE-2024-0001');
	// trims surrounding whitespace to normalize the identity
	assert.equal(bugKey({ src: 'blackduck', cve: ' CVE-2024-0002 ' }), 'bd:CVE-2024-0002');
});

test('bugKey: Coverity 用 file + line + type + checker', () => {
	const a = bugKey({ src: 'coverity', file: 'a.c', line: 10, type: 'Deref', checker: 'NULL_RETURNS' });
	const b = bugKey({ src: 'coverity', file: '/x/a.c', line: 12, type: 'Deref', checker: 'NULL_RETURNS' });
	assert.notEqual(a, b, 'checker/type 相同但檔名或行號不同 → 視為不同身份');
	const c = bugKey({ src: 'coverity', file: 'a.c', line: 10, type: 'OVR', checker: 'OTHER' });
	assert.notEqual(a, c, 'checker 不同應為不同身份');
});

test('bugKey: 不具可行的物件回傳空字串', () => {
	assert.equal(bugKey(null), '');
});

test('compareBugs 分辨新增 / 移除 / 差異 / 相同', () => {
	const bugA = cov('a.c', 1, 'X', 'CHK', { desc: 'v1' });
	const bugBLastFile = cov('b.c', 2, 'Y', 'CHK', { desc: 'v1' });

	const changedA = cov('c.c', 3, 'Z', 'CHK', { desc: 'old text' });
	const changedB = cov('c.c', 3, 'Z', 'CHK', { desc: 'new text' });

	const sameA = bd('CVE-100');
	const sameB = bd('CVE-100');

	// A has: a.c, c.c (content A), CVE-100; B has: c.c (content B), CVE-100, b.c
	const diff = compareBugs([bugA, changedA, sameA], [changedB, sameB, bugBLastFile]);

	assert.equal(diff.removed.length, 1, '僅 A 的 a.c 應列為移除');
	assert.equal(diff.removed[0].file, 'a.c');

	assert.equal(diff.added.length, 1, '僅 B 的 b.c 應列為新增');
	assert.equal(diff.added[0].file, 'b.c');

	assert.equal(diff.changed.length, 1, 'c.c 兩邊都有但 desc 改變應列為差異');
	assert.equal(diff.changed[0].before.desc, 'old text');
	assert.equal(diff.changed[0].after.desc, 'new text');

	assert.equal(diff.same.length, 1, 'CVE-100 兩邊相同應用於相同');
});

test('compareBugs 空輸入', () => {
	const diff = compareBugs([], []);
	assert.equal(diff.added.length, 0);
	assert.equal(diff.removed.length, 0);
	assert.equal(diff.changed.length, 0);
	assert.equal(diff.same.length, 0);
});

test('bugFingerprint 反映內容差異', () => {
	const a = bd('CVE-1', { cvss: '9.8' });
	const b = bd('CVE-1', { cvss: '7.5' });
	assert.notEqual(bugFingerprint(a), bugFingerprint(b));
});

test('bugFingerprint 忽略沉重的 code / events 陣列', () => {
	const base = cov('a.c', 1, 'X', 'CHK', { desc: 'x' });
	const heavy1 = cov('a.c', 1, 'X', 'CHK', {
		desc: 'x',
		events: [{ tag: 'e1', text: 'long event' }],
		code: [{ file: 'a.c', items: [{ text: 'src v1' }] }],
	});
	const heavy2 = cov('a.c', 1, 'X', 'CHK', {
		desc: 'x',
		events: [{ tag: 'e2', text: 'different event' }],
		code: [{ file: 'a.c', items: [{ text: 'src v2' }] }],
	});
	// 只有執行路徑 / 原始碼片段不同 → 指紋相同（不判定為「內容差異」，省大量序列化）
	assert.equal(bugFingerprint(heavy1), bugFingerprint(heavy2));
	// 一般欄位（desc）不同 → 指紋不同
	assert.notEqual(bugFingerprint(heavy1), bugFingerprint(Object.assign({}, heavy2, { desc: 'y' })));
});
