import { $ } from './util.js';
// The handbook now ships a lot of category chunks. Each chunk is a stable
// `export default [...]` kept in ascending-CWE order, and the browser loads them
// all eagerly (a few hundred Base/Variant entries across the themed categories
// plus the v4.20 gap-fill batches).
// If it ever grows to hundreds/thousands, switch this to a lazy chunk loader that
// pulls `data/cwe/<category>.js` on first open instead of importing everything.
import authBypass from '../../data/cwe/auth/auth-bypass.js';
import auth from '../../data/cwe/auth/auth.js';
import brokenAccessControl from '../../data/cwe/auth/broken-access-control.js';
import concurrency from '../../data/cwe/resilience/concurrency.js';
import config from '../../data/cwe/resilience/config.js';
import cryptoExtra from '../../data/cwe/crypto/crypto-extra.js';
import cryptoHardening from '../../data/cwe/crypto/crypto-hardening.js';
import crypto from '../../data/cwe/crypto/crypto.js';
import errors from '../../data/cwe/resilience/errors.js';
import evalReflect from '../../data/cwe/web/eval-reflect.js';
import filesPaths from '../../data/cwe/web/files-paths.js';
import immutable from '../../data/cwe/resilience/immutable.js';
import inputValidation from '../../data/cwe/web/inputvalidation.js';
import logging from '../../data/cwe/resilience/logging.js';
import loggingFail from '../../data/cwe/resilience/logging-fail.js';
import memory from '../../data/cwe/native/memory.js';
import nullC from '../../data/cwe/native/null-c.js';
import pathVar from '../../data/cwe/web/path-var.js';
import permissions from '../../data/cwe/auth/permissions.js';
import resourceDos from '../../data/cwe/resilience/resource-dos.js';
import server from '../../data/cwe/resilience/server.js';
import session from '../../data/cwe/auth/session.js';
import webInclude from '../../data/cwe/web/web-include.js';
import webInjection from '../../data/cwe/web/web-injection.js';
import webMisc from '../../data/cwe/web/web-misc.js';
import gap01 from '../../data/cwe/expansion/gap-01.js';
import gap02 from '../../data/cwe/expansion/gap-02.js';
import gap03 from '../../data/cwe/expansion/gap-03.js';
import gap04 from '../../data/cwe/expansion/gap-04.js';
import gap05 from '../../data/cwe/expansion/gap-05.js';
import gap06 from '../../data/cwe/expansion/gap-06.js';
import gap07 from '../../data/cwe/expansion/gap-07.js';
import gap08 from '../../data/cwe/expansion/gap-08.js';
import gap09 from '../../data/cwe/expansion/gap-09.js';
import gap10 from '../../data/cwe/expansion/gap-10.js';
import gap11 from '../../data/cwe/expansion/gap-11.js';
import gap12 from '../../data/cwe/expansion/gap-12.js';
import gap13 from '../../data/cwe/expansion/gap-13.js';
import gap14 from '../../data/cwe/expansion/gap-14.js';
import gap15 from '../../data/cwe/expansion/gap-15.js';
import gap16 from '../../data/cwe/expansion/gap-16.js';

const CHUNKS = [
	{ category: 'input-validation', entries: inputValidation },
	{ category: 'web', entries: webMisc },
	{ category: 'crypto', entries: crypto },
	{ category: 'memory · native (C/C++)', entries: memory },
	{ category: 'auth / identity', entries: auth },
	{ category: 'concurrency · race', entries: concurrency },
	{ category: 'error handling', entries: errors },
	{ category: 'logging · leak', entries: logging },
	{ category: 'crypto · randomness', entries: cryptoExtra },
	{ category: 'session · state', entries: session },
	{ category: 'permissions · privileges', entries: permissions },
	{ category: 'web · include & assign', entries: webInclude },
	{ category: 'server · robustness', entries: server },
	{ category: 'broken access control', entries: brokenAccessControl },
	{ category: 'files · paths', entries: filesPaths },
	{ category: 'resource · dos', entries: resourceDos },
	{ category: 'crypto · hardening', entries: cryptoHardening },
	{ category: 'config · defaults', entries: config },
	{ category: 'assumed-immutable', entries: immutable },
	{ category: 'logging · fail (injection/monitor)', entries: loggingFail },
	{ category: 'C/C++ · null & init', entries: nullC },
	{ category: 'web · xss-server & xml', entries: webInjection },
	{ category: 'eval · reflection & nosql', entries: evalReflect },
	{ category: 'path traversal variants', entries: pathVar },
	{ category: 'auth bypass · trust', entries: authBypass },
	{ category: '補齊·組態/路徑 (CWE 5–56)', entries: gap01 },
	{ category: '補齊·路徑等價/注入 (CWE 57–151)', entries: gap02 },
	{ category: '補齊·中性化/編碼/轉型 (CWE 152–218)', entries: gap03 },
	{ category: '補齊·敏感資料/日誌/密碼/權限 (CWE 219–299)', entries: gap04 },
	{ category: '補齊·認證/密碼學/隨機數 (CWE 301–383)', entries: gap05 },
	{ category: '補齊·符號/邏輯/通道/例外 (CWE 386–483)', entries: gap06 },
	{ category: '補齊·敏感資訊/可寫性/惡意碼 (CWE 484–542)', entries: gap07 },
	{ category: '補齊·組態/資訊暴露/物件模型 (CWE 543–596)', entries: gap08 },
	{ category: '補齊·輸入驗證/認證/API (CWE 597–694)', entries: gap09 },
	{ category: '補齊·低階/記憶體/並行 (CWE 695–832)', entries: gap10 },
	{ category: '補齊·驗證/Android/通訊/Web (CWE 836–1056)', entries: gap11 },
	{ category: '補齊·程式碼/資料品質 (CWE 1057–1100)', entries: gap12 },
	{ category: '補齊·程式碼品質/文件/硬體 (CWE 1101–1221)', entries: gap13 },
	{ category: '補齊·硬體/韌體/密碼 (CWE 1222–1269)', entries: gap14 },
	{ category: '補齊·硬體/SoC/輸入驗證 (CWE 1270–1318)', entries: gap15 },
	{ category: '補齊·硬體/嵌入式/SoC/AI (CWE 1319–1434)', entries: gap16 },
];

// Flatten all chunks, tag each with its category, and keep the whole handbook
// sorted by CWE id ascending for a stable "由小到大" handbook order.
const CATALOG = CHUNKS
	.flatMap((chunk) => chunk.entries.map((e) => ({ cat: chunk.category, ...e })))
	.sort((a, b) => {
		const an = +a.id.replace(/CWE-/, '');
		const bn = +b.id.replace(/CWE-/, '');
		return an - bn;
	});

function el(tag, cls, text) {
	const n = document.createElement(tag);
	if (cls) n.className = cls;
	if (text != null) n.textContent = text;
	return n;
}

function codeBlock(label, lang, code) {
	const box = el('div', 'cwe-code');
	box.appendChild(el('div', 'cwe-code-tag', label + (lang ? ' (' + lang + ')' : '')));
	const pre = el('pre', 'cwe-pre');
	pre.appendChild(el('code', 'cwe-code-body', code == null ? '' : String(code)));
	box.appendChild(pre);
	return box;
}

// redmine-style rich unified-diff rendering: each line becomes a row with an old/new
// gutter line number and a colored code cell (green=added, red=removed, blue=hunk).
function diffBlock(patch) {
	let oldLine = null;
	let newLine = null;
	const pre = el('pre', 'cwe-pre diff-pre');
	const code = el('code', 'cwe-code-body diff');

	for (const line of String(patch == null ? '' : patch).split('\n')) {
		let type = 'context';
		let oldNumber = '';
		let newNumber = '';
		const hunk = line.match(/^@@\s+-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@/);

		if (hunk) {
			type = 'hunk';
			oldLine = +hunk[1];
			newLine = +hunk[2];
		} else if (/^(diff --git|index |--- |\+\+\+ |new file mode|deleted file mode|similarity index|rename (from|to) )/.test(line)) {
			type = 'meta';
		} else if (line[0] === '+' && line[1] !== '+') {
			type = 'added';
			newNumber = newLine ?? '';
			if (newLine !== null) newLine++;
		} else if (line[0] === '-' && line[1] !== '-') {
			type = 'removed';
			oldNumber = oldLine ?? '';
			if (oldLine !== null) oldLine++;
		} else if (line.startsWith('\\ No newline')) {
			type = 'notice';
		} else {
			oldNumber = oldLine ?? '';
			newNumber = newLine ?? '';
			if (oldLine !== null) oldLine++;
			if (newLine !== null) newLine++;
		}

		const row = el('span', 'diff-line diff-' + type);
		row.appendChild(el('span', 'diff-line-number diff-old', oldNumber));
		row.appendChild(el('span', 'diff-line-number diff-new', newNumber));
		row.appendChild(el('span', 'diff-code', line || ' '));
		code.appendChild(row);
	}
	pre.appendChild(code);

	const toolbar = el('div', 'diff-toolbar');
	toolbar.appendChild(el('strong', '', 'unified diff'));
	const box = el('div', 'cwe-diff diff-preview');
	box.appendChild(toolbar);
	box.appendChild(pre);
	return box;
}

function buildDetail(e) {
	const d = el('div', 'cwe-sheet');

	d.appendChild(el('h2', 'cwe-dt-head', e.id + ' — ' + e.name));
	const meta = el('div', 'cwe-dt-meta');
	meta.textContent = '類別: ' + (e.cat || '—') + ' · 語言: ' + (e.lang || '—') + ' · 狀態: ' + (e.status || '');
	d.appendChild(meta);

	const section = (label, node) => {
		const s = el('section', 'cwe-sec');
		s.appendChild(el('h3', 'cwe-label', label));
		s.appendChild(node);
		d.appendChild(s);
	};

	section('(a) 弱點是什麼', el('p', 'cwe-text', e.what));
	section('(b) 問題長怎樣', codeBlock('壞的寫法', e.lang, e.problem));
	section('(c) 解完會長怎樣', codeBlock('修好寫法', e.lang, e.fixed));
	section('(d) 範例 patch', diffBlock(e.patch));

	if (e.refs && e.refs.length) {
		d.appendChild(el('p', 'cwe-refs', '參考: ' + e.refs.join(' · ')));
	}

	return d;
}

// CWE 手冊詳情改用側邊 drawer 滑出（沿用缺陷詳情的 drawer）
function openCweSheet(e) {
	const db = $('drawer-body');
	db.innerHTML = '';
	db.appendChild(buildDetail(e));
	$('drawer-title').textContent = 'CWE 弱點手冊';
	$('drawer-copy').hidden = true;
	$('drawer-download').hidden = true;
	$('drawer').classList.add('open');
	$('drawer').setAttribute('aria-hidden', 'false');
	$('drawer-overlay').classList.add('show');
}

function renderList() {
	const q = ($('cwe-q').value || '').trim().toLowerCase();
	const hideDep = $('cwe-hide-deprecated').checked;

	const hits = CATALOG.filter((e) => {
		if (hideDep && e.status === 'Deprecated') return false;
		if (!q) return true;
		return (e.id + ' ' + e.name + ' ' + (e.tags || []).join(' ')).toLowerCase().includes(q);
	});

	const list = $('cwe-list');
	list.innerHTML = '';

	for (const e of hits) {
		const b = el('button', 'cwe-entry', e.id + ' — ' + e.name);
		b.appendChild(el('span', 'cwe-entry-sub', (e.cat || '') + ' · ' + e.lang + ' · ' + e.status));
		b.addEventListener('click', () => openCweSheet(e));
		list.appendChild(b);
	}
	if (!hits.length) list.appendChild(el('div', 'empty', '沒有符合的 CWE'));
}

export function initCwe() {
	$('cwe-q').addEventListener('input', renderList);
	$('cwe-hide-deprecated').addEventListener('change', renderList);
	renderList();
}

// 缺陷詳體的「說明」區塊用它展示該 CWE 的「弱點是什麼」解釋；查不到就回 null，由呼叫端退回 b.desc。
export function cweWhat(id) {
	if (!id) return null;
	const hit = CATALOG.find((e) => e.id === String(id));
	return hit ? hit.what : null;
}
