import { $ } from './util.js';
// The handbook now ships several category chunks. Each chunk is a stable
// `export default [...]` kept in ascending-CWE order, and the browser loads them
// all eagerly (54 entries today: memory 24, web 6, crypto 6, auth 8, input-validation 10).
// If it ever grows to hundreds/thousands, switch this to a lazy chunk loader that
// pulls `data/cwe/<category>.js` on first open instead of importing everything.
import inputValidation from '../../data/cwe/inputvalidation.js';
import auth from '../../data/cwe/auth.js';
import crypto from '../../data/cwe/crypto.js';
import memory from '../../data/cwe/memory.js';
import webMisc from '../../data/cwe/web-misc.js';

const CHUNKS = [
	{ category: 'input-validation', entries: inputValidation },
	{ category: 'web', entries: webMisc },
	{ category: 'crypto', entries: crypto },
	{ category: 'memory · native (C/C++)', entries: memory },
	{ category: 'auth / identity', entries: auth },
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
	section('(d) 範例 patch', codeBlock('unified diff', 'diff', e.patch));

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
