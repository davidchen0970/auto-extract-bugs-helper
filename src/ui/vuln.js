import { $ } from './util.js';
import { renderMd } from './md.js';

export function pkgSlug(pkg) {
	return String(pkg || '')
		.trim()
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, '-')
		.replace(/^-+|-+$/g, '');
}

let catalog = null;
let catalogP = null;

function loadAll() {
	if (catalog) return Promise.resolve(catalog);
	if (!catalogP) {
		catalogP = (async () => {
			const manifest = (await import('../../data/vuln/index.js')).default;
			const files = [...new Set(Object.values(manifest))];
			const mods = await Promise.all(files.map((f) => import('../../data/vuln/' + f)));
			const list = mods.flatMap((m) => (m.default || []));
			list.sort((a, b) => String(a.key).localeCompare(String(b.key)));
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

function buildDetail(e) {
	const d = el('div', 'cwe-sheet');

	d.appendChild(el('h2', 'cwe-dt-head', e.key + ' — ' + e.name));
	const meta = el('div', 'cwe-dt-meta');
	const bits = [
		'套件: ' + (e.pkg || '—') + (e.version ? ' ' + e.version : ''),
		e.cvss ? 'CVSS: ' + e.cvss : '',
		'類別: ' + (e.cat || '—'),
	].filter(Boolean);
	meta.textContent = bits.join(' · ');
	d.appendChild(meta);

	const what = document.createElement('div');
	what.className = 'cwe-text';
	what.innerHTML = renderMd(e.what || '—');
	d.appendChild(what);

	if (e.recommendation) {
		const rec = document.createElement('section');
		rec.className = 'cwe-sec';
		rec.appendChild(el('h3', 'cwe-label', '因應建議'));
		const p = document.createElement('div');
		p.className = 'cwe-text';
		p.innerHTML = renderMd(e.recommendation);
		rec.appendChild(p);
		d.appendChild(rec);
	}

	if (e.refs && e.refs.length) {
		d.appendChild(el('p', 'cwe-refs', '參考: ' + e.refs.join(' · ')));
	}

	return d;
}

function openSheet(e) {
	const db = $('drawer-body');
	db.innerHTML = '';
	db.appendChild(buildDetail(e));
	$('drawer-title').textContent = 'AI 弱點手冊';
	$('drawer-copy').hidden = true;
	$('drawer-download').hidden = true;
	$('drawer').classList.add('open');
	$('drawer').setAttribute('aria-hidden', 'false');
	$('drawer-overlay').classList.add('show');
}

async function renderList() {
	const listEl = $('vuln-list');
	if (!catalog) listEl.innerHTML = '<div class="empty">載入 AI 弱點手冊…</div>';

	await loadAll();

	const q = ($('vuln-q').value || '').trim().toLowerCase();
	const hits = catalog.filter((e) => {
		if (!q) return true;
		const hay = [e.key, e.cve, e.pkg, e.name, e.cat, e.version,
			...(e.tags || []), e.what]
			.filter(Boolean).join(' ').toLowerCase();
		return hay.includes(q);
	});

	listEl.innerHTML = '';
	for (const e of hits) {
		const b = el('button', 'cwe-entry', e.key + ' — ' + e.name);
		b.appendChild(el('span', 'cwe-entry-sub',
			(e.pkg || '') + ' · CVSS ' + (e.cvss || '—') + ' · ' + (e.cat || '')));
		b.addEventListener('click', () => openSheet(e));
		listEl.appendChild(b);
	}
	if (!hits.length) listEl.appendChild(el('div', 'empty', '沒有符合的弱點'));
}

export function initVuln() {
	$('vuln-q').addEventListener('input', renderList);
	$('tab-vuln').addEventListener('click', renderList);
}

export async function vulnLookup(key) {
	if (!key) return null;
	const manifest = (await import('../../data/vuln/index.js')).default;
	const file = manifest[key];
	if (!file) return null;
	const mod = await import('../../data/vuln/' + file);
	return (Array.isArray(mod.default) ? mod.default : []).find((e) => e.key === key) || null;
}
