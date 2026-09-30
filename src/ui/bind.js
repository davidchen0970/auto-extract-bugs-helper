import { $ } from './util.js';
import { state } from './state.js';
import { loadFile } from './load.js';
import { renderList, lastPage } from './view.js';
import { closeDrawer, currentBug } from './drawer.js';
import { exportActive, exportBug, copyBug } from './export.js';
import { toggleTheme, focusSearch } from './theme.js';
import { bindCompare } from './compare.js';

export function bindUI() {
	const dz = $('dropzone'), fin = $('file-input');

	$('btn-open').addEventListener('click', () => fin.click());
	$('btn-browse').addEventListener('click', () => fin.click());
	fin.addEventListener('change', () => { if (fin.files[0]) loadFile(fin.files[0]); });

	$('btn-theme').addEventListener('click', toggleTheme);

	const mm = $('menu-toggle'), menu = $('menu');
	mm.addEventListener('click', () => {
		const open = menu.classList.toggle('open');
		mm.setAttribute('aria-expanded', String(open));
	});
	const closeMenu = () => { menu.classList.remove('open'); mm.setAttribute('aria-expanded', 'false'); };
	$('menu-open').addEventListener('click', () => { fin.click(); closeMenu(); });
	$('menu-theme').addEventListener('click', () => { toggleTheme(); closeMenu(); });
	document.addEventListener('click', (e) => {
		if (menu.classList.contains('open') && !e.target.closest('.menu, #menu-toggle')) closeMenu();
	});

	['dragenter', 'dragover'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add('drag'); }));
	['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove('drag'); }));
	dz.addEventListener('drop', (e) => {
		const f = e.dataTransfer.files && e.dataTransfer.files[0];
		if (f) loadFile(f);
	});

	document.addEventListener('click', (e) => {
		const sevBtn = e.target.closest('#sevseg button');
		if (sevBtn) {
			state.sevFilter = sevBtn.dataset.sev;
			state.page = 0;
			renderList();
			return;
		}
		if (e.target.closest('#btn-export')) { exportActive(); return; }
		if (e.target.id === 'pg-next') { if (state.page < lastPage()) { state.page++; renderList(); } return; }
		if (e.target.id === 'pg-prev') { if (state.page > 0) { state.page--; renderList(); } return; }
	});

	document.addEventListener('input', (e) => {
		if (e.target && e.target.id === 'q') { state.page = 0; renderList(); }
	});

	$('drawer-close').addEventListener('click', closeDrawer);
	$('drawer-copy').addEventListener('click', () => copyBug(currentBug()));
	$('drawer-download').addEventListener('click', () => exportBug(currentBug()));
	$('drawer-overlay').addEventListener('click', closeDrawer);
	bindCompare();

	document.addEventListener('keydown', (e) => {
		if (e.target && e.target.id === 'q' && (e.key === 'Enter' || e.key === 'ArrowDown' || e.key === 'PageDown')) {
			if (e.key === 'Enter') { state.page = lastPage(); renderList(); e.preventDefault(); }
		}

		const t = e.target;
		const typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' ||
			t.tagName === 'SELECT' || t.isContentEditable);
		if (e.key === 'Escape') { closeDrawer(); return; }
		if (typing) return;
		const k = e.key && e.key.toLowerCase();
		if (k === 's') { e.preventDefault(); focusSearch(); }
		else if (k === 'e') { e.preventDefault(); exportActive(); }
		else if (k === 't') { toggleTheme(); }
		else if (e.key === 'ArrowLeft' || e.key === 'PageUp') { if (state.page > 0) { state.page--; renderList(); e.preventDefault(); } }
		else if (e.key === 'ArrowRight' || e.key === 'PageDown') { if (state.page < lastPage()) { state.page++; renderList(); e.preventDefault(); } }
	});
}
