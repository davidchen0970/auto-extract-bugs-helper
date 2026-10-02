import { $ } from './util.js';
import { bugDetail } from './cards.js';
import { cweWhat } from './cwe.js';
import { renderMd } from './md.js';

let activeBug = null;

// Fill every "CWE 說明" cell (stamped data-cwe by cards.js) with the handbook text,
// loading exactly the chunk(s) that own those ids. The cell already shows b.desc, so a
// slow/unloaded chunk just upgrades the text in place; unknown CWEs keep the fallback.
function hydrateCweWhats(root) {
	const cells = Array.from(root.querySelectorAll('.cwe-what[data-cwe]'));
	const byId = new Map();
	for (const c of cells) {
		const id = c.getAttribute('data-cwe');
		if (!id) continue;
		if (!byId.has(id)) byId.set(id, []);
		byId.get(id).push(c);
	}
	for (const [id, group] of byId) {
		cweWhat(id).then((what) => {
			if (!what) return; // keep the desc fallback already rendered
			const html = renderMd(what);
			for (const c of group) c.innerHTML = html;
		}).catch(() => { /* keep fallback on load error */ });
	}
}

export function openDrawer(b, coord) {
	activeBug = b;
	$('drawer-body').innerHTML = bugDetail(b, coord);
	$('drawer-title').textContent = '缺陷詳情';
	$('drawer-copy').hidden = false;
	$('drawer-download').hidden = false;
	$('drawer').classList.add('open');
	$('drawer').setAttribute('aria-hidden', 'false');
	$('drawer-overlay').classList.add('show');
	hydrateCweWhats($('drawer-body'));
}

export function currentBug() {
	return activeBug;
}

export function closeDrawer() {
	$('drawer').classList.remove('open');
	$('drawer').setAttribute('aria-hidden', 'true');
	$('drawer-overlay').classList.remove('show');
}
