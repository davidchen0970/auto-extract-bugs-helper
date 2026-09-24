import { $, fmt, esc, sevColor } from './util.js';
import { state } from './state.js';
import { SEV, sevOrder, sevLabel } from '../core/index.js';
import { bugCard } from './cards.js';
import { openDrawer } from './drawer.js';

export function summaryFor(r) {
	return sevOrder.map((s) => ({ sev: s, n: r.totals[s] || 0 }));
}

export function filtersHTML() {
	const sevStops = ['ALL', SEV.CRITICAL, SEV.HIGH, SEV.MEDIUM, SEV.LOW, SEV.INFO];
	const segs = sevStops.map((s) => `<button class="${state.sevFilter === s ? 'on' : ''}" data-sev="${s}">${s === 'ALL' ? '全部' : sevLabel[s]}</button>`).join('');
	return `
    <div class="toolbar">
      <div class="search">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>
        <input id="q" type="text" placeholder="搜尋類型 / 位置 / CVE / 元件…">
      </div>
      <div class="seg" id="sevseg">${segs}</div>
      <span class="count" id="rcnt"></span>
      <div class="pager" style="margin:0">
        <button id="pg-prev" class="sm-v">‹ 上一頁</button>
        <span class="pgno" id="pgno"></span>
        <button id="pg-next" class="sm-v">下一頁 ›</button>
      </div>
    </div>`;
}

export function applyFilters(bugs) {
	const q = (($('q') && $('q').value) || '').toLowerCase().trim();
	const sv = state.sevFilter;
	return bugs.filter((b) => {
		if (sv !== 'ALL' && b.sev !== sv) return false;
		if (!q) return true;
		const hay = [b.cve, b.component, b.type, b.checker, b.category, b.cwe, b.file, b.fn, b.desc, b.key]
			.filter(Boolean).join(' ').toLowerCase();
		return hay.indexOf(q) >= 0;
	});
}

export function renderTabs() {
	const tabsEl = $('source-tabs');
	if (!state.reports.length) {
		tabsEl.innerHTML = '<div class="empty">未在歸檔中辨識出可解析的缺陷報表。</div>';
		return;
	}
	const dotColor = (r) => {
		if (r.type === 'coverity') return 'var(--high)';
		if (r.type === 'blackduck') return 'var(--info)';
		return 'var(--low)';
	};
	tabsEl.innerHTML = state.reports.map((r, i) => `
    <button class="tab ${i === state.current ? 'active' : ''}" data-i="${i}">
      <span class="dot" style="background:${dotColor(r)}"></span>
      ${esc(r.name)}<span class="mini">(${fmt(r.bugs.length)})</span>
    </button>`).join('') +
		'<button id="btn-export" class="btn sm" style="margin-left:auto">匯出 JSON</button>';
	tabsEl.querySelector('[data-i]') && tabsEl.querySelectorAll('[data-i]').forEach((b) =>
		b.addEventListener('click', () => { state.current = +b.dataset.i; state.page = 0; renderView(); renderTabs(); }));
}

export function renderView() {
	const r = state.reports[state.current];
	if (!r) return;
	const holder = $('source-views');
	holder.innerHTML = `
    <div class="cards">${summaryFor(r).map((c) => `
      <div class="card">
        <div class="card-n" style="color:${sevColor[c.sev]}">${fmt(c.n)}</div>
        <div class="card-l">${sevLabel[c.sev]}</div>
        <div class="sev-bar" style="background:${sevColor[c.sev]}"></div>
      </div>`).join('')}
      <div class="card"><div class="card-n">${fmt(r.bugs.length)}</div><div class="card-l">缺陷總數</div><div class="sev-bar" style="background:var(--accent)"></div></div>
    </div>
    ${filtersHTML()}
    <div class="buglist" id="buglist"></div>`;

	renderList();
}

export function filteredActive() {
	const r = state.reports[state.current];
	return applyFilters(r ? r.bugs : []);
}

export function renderList() {
	const r = state.reports[state.current];
	if (!r) return;
	const listEl = $('buglist');
	const seg = $('sevseg');
	if (seg) seg.querySelectorAll('button').forEach((b) => b.classList.toggle('on', b.dataset.sev === state.sevFilter));
	const shown = filteredActive();
	const per = state.perPage;
	const totalPages = Math.max(1, Math.ceil(shown.length / per));
	if (state.page > totalPages - 1) state.page = Math.max(0, totalPages - 1);
	const start = state.page * per;
	const slice = shown.slice(start, start + per);
	$('rcnt').textContent = `${fmt(shown.length)} 筆 / 共 ${fmt(r.bugs.length)}`;
	$('pgno').textContent = `第 ${fmt(state.page + 1)} / ${totalPages} 頁`;

	if (!slice.length) {
		listEl.innerHTML = '<div class="empty">沒有符合的缺陷。</div>';
	} else {
		listEl.innerHTML = slice.map((b, i) => bugCard(b, start + i, i)).join('');
		listEl.querySelectorAll('.bug').forEach((el) => {
			el.addEventListener('click', (e) => { if (!e.target.closest('button')) openDrawer(shown[+el.dataset.i], start + +el.dataset.i); });
		});
	}
}

export function lastPage() {
	const shown = filteredActive();
	return Math.max(1, Math.ceil(shown.length / state.perPage)) - 1;
}
