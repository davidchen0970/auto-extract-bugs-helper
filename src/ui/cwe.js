import { $ } from './util.js';
// PILOT: only one category are loaded. When the full catalog lands, this becomes a
// chunk loader that pulls `data/cwe/<category>.js` lazily on first open, so the
// browser never holds all ~944 entries / patches in memory up-front.
import inputValidation from '../../data/cwe/inputvalidation.js';

const CATALOG = inputValidation;

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

function renderDetail(e) {
	const d = $('cwe-detail');
	d.hidden = false;
	d.innerHTML = '';

	d.appendChild(el('h2', 'cwe-dt-head', e.id + ' — ' + e.name));
	const meta = el('div', 'cwe-dt-meta');
	meta.textContent = '語言: ' + (e.lang || '—') + ' · 狀態: ' + (e.status || '');
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
	const hidden = $('cwe-detail');
	hidden.hidden = true;

	for (const e of hits) {
		const b = el('button', 'cwe-entry', e.id + ' — ' + e.name);
		b.appendChild(el('span', 'cwe-entry-sub', e.lang + ' · ' + e.status));
		b.addEventListener('click', () => renderDetail(e));
		list.appendChild(b);
	}
	if (!hits.length) list.appendChild(el('div', 'empty', '沒有符合的 CWE'));
}

export function initCwe() {
	$('cwe-q').addEventListener('input', renderList);
	$('cwe-hide-deprecated').addEventListener('change', renderList);
	renderList();
}
