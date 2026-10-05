import { $ } from './util.js';
import { renderMd } from './md.js';

let catalog = null;
let catalogP = null;

function loadAll() {
	if (catalog) return Promise.resolve(catalog);
	if (!catalogP) {
		catalogP = (async () => {
			const manifest = (await import('../../data/cwe/index.js')).default;
			const files = [...new Set(Object.values(manifest))];
			const mods = await Promise.all(files.map((f) => import('../../data/cwe/' + f)));
			const list = mods.flatMap((m) => (m.default || []));
			list.sort((a, b) => +a.id.replace('CWE-', '') - +b.id.replace('CWE-', ''));
			catalog = list;
			return catalog;
		})();
	}
	return catalogP;
}

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

	const whatBlock = el('div', 'cwe-text');
	whatBlock.innerHTML = renderMd(e.what || '—');
	section('(a) 弱點是什麼', whatBlock);
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

// The handbook list. Data chunks are dynamic `import()`-ed only the first time this
// panel is actually shown (or searched / filtered), not at page load.
async function renderList() {
	const listEl = $('cwe-list');
	if (!catalog) listEl.innerHTML = '<div class="empty">載入 CWE 手冊…</div>';

	await loadAll();

	const q = ($('cwe-q').value || '').trim().toLowerCase();
	const hideDep = $('cwe-hide-deprecated').checked;
	const hits = catalog.filter((e) => {
		if (hideDep && e.status === 'Deprecated') return false;
		if (!q) return true;
		return (e.id + ' ' + e.name + ' ' + (e.tags || []).join(' ')).toLowerCase().includes(q);
	});

	listEl.innerHTML = '';
	for (const e of hits) {
		const b = el('button', 'cwe-entry');
		b.appendChild(el('span', 'cwe-entry-main', e.id + ' — ' + e.name));
		b.appendChild(el('span', 'cwe-entry-sub', (e.cat || '') + ' · ' + e.lang + ' · ' + e.status));
		b.addEventListener('click', () => openCweSheet(e));
		listEl.appendChild(b);
	}
	if (!hits.length) listEl.appendChild(el('div', 'empty', '沒有符合的 CWE'));
}

export function initCwe() {
	$('cwe-q').addEventListener('input', renderList);
	$('cwe-hide-deprecated').addEventListener('change', renderList);
	// Opening the handbook tab is the first real reason to touch the CWE payload; any
	// search / deprecated-filter input already implies the panel is in use and renderList()
	// lazy-loads by itself. Nothing is fetched until one of these fires.
	$('tab-cwe').addEventListener('click', renderList);
}

// Defect detail "CWE 說明": load only the single chunk owning `id` and return its
// what-text (null when the CWE is unknown to the handbook — caller falls back to b.desc).
export async function cweWhat(id) {
	if (!id) return null;
	const key = String(id);
	const manifest = (await import('../../data/cwe/index.js')).default;
	const file = manifest[key];
	if (!file) return null;
	const mod = await import('../../data/cwe/' + file);
	const hit = (mod.default || []).find((e) => e.id === key);
	return hit ? hit.what : null;
}
