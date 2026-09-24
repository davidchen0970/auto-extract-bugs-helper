import {
	SEV,
	sevOrder,
	sevLabel,
	decompressGzip,
	parseTar,
	detectReport,
	looksLikeCoverity,
	looksLikeBlackDuck,
	parseCoverity,
	parseBlackDuck,
} from './src/core/index.js';

const $ = (id) => document.getElementById(id);
const fmt = (n) => (n == null ? '–' : Number(n).toLocaleString('en-US'));
function fmtSize(b) {
	if (b == null) return '';
	if (b < 1024) return b + ' B';
	const u = ['KB', 'MB', 'GB', 'TB'];
	let i = -1, v = b;
	do { v /= 1024; i++; } while (v >= 1024 && i < u.length - 1);
	return v.toFixed(1) + ' ' + u[i];
}
const esc = (s) => String(s ?? '').replace(/[&<>"']/g,
	(c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function toast(msg, isErr = false) {
	const t = $('toast');
	t.textContent = msg;
	t.className = 'toast' + (isErr ? ' err' : '');
	t.hidden = false;
	clearTimeout(t._tm);
	t._tm = setTimeout(() => (t.hidden = true), isErr ? 5200 : 2600);
}

const state = {
	raw: null,
	entries: [],
	reports: [],
	artifacts: [],
	current: 0,
	page: 0,
	perPage: 10,
	sevFilter: 'ALL',
};

async function loadFile(file) {
	const size = file.size;
	const gzHint = /\.(tar\.gz|tgz|gz)$/i.test(file.name);
	$('dropzone').hidden = true;
	$('workbench').hidden = false;
	$('source-tabs').innerHTML = '<div class="empty"><span class="spinner"></span>正在解析…</div>';
	$('archive-list').innerHTML = '<div class="empty"><span class="spinner"></span>讀取 tar 內容…</div>';
	$('archive-meta').textContent = fmtSize(size);

	try {
		const raw = await file.arrayBuffer();
		let u8 = new Uint8Array(raw);
		const isGz = gzHint || (u8[0] === 0x1f && u8[1] === 0x8b);
		if (isGz) {
			toast('正在解壓縮 gzip…');
			u8 = await decompressGzip(u8);
		}
		state.raw = u8;
		const t0 = performance.now();
		const entries = parseTar(u8);
		toast(`解析完成：${entries.length} 個檔案，耗時 ${(performance.now() - t0).toFixed(0)}ms`);
		classify(entries);
	} catch (err) {
		toast('解析失敗：' + (err && err.message ? err.message : err), true);
		console.error(err);
	}
}

function classify(entries) {
	const cov = [], bd = [], arts = [], other = [];
	for (const e of entries) {
		const kind = detectReport(e.name);
		if (kind === 'coverity') cov.push(e);
		else if (kind === 'blackduck') bd.push(e);
		else if (kind === 'artifact') arts.push(e);
		else if (kind === 'html' || kind === 'csv') other.push(e);
	}

	state.entries = entries;
	state.artifacts = arts;
	state.reports = [];

	for (const e of cov) {
		let htmlStr;
		try { htmlStr = new TextDecoder('utf-8').decode(e.data); } catch (_) { htmlStr = ''; }
		if (!looksLikeCoverity(htmlStr)) continue;
		const p = parseCoverity(htmlStr);
		state.reports.push({ type: 'coverity', file: e.name, size: e.size, ...p });
	}

	for (const e of bd) {
		let csvStr;
		try { csvStr = new TextDecoder('utf-8').decode(e.data); } catch (_) { csvStr = ''; }
		if (!looksLikeBlackDuck(csvStr)) continue;
		const p = parseBlackDuck(csvStr);
		state.reports.push({ type: 'blackduck', file: e.name, size: e.size, ...p });
	}

	for (const e of other) {
		try {
			const text = new TextDecoder('utf-8').decode(e.data);
			if (looksLikeCoverity(text)) {
				const p = parseCoverity(text);
				state.reports.push({ type: 'coverity', file: e.name, size: e.size, ...p });
			} else if (looksLikeBlackDuck(text)) {
				const p = parseBlackDuck(text);
				state.reports.push({ type: 'blackduck', file: e.name, size: e.size, ...p });
			} else {
				state.artifacts.push({ name: e.name, size: e.size, data: e.data, type: kind });
			}
		} catch (_) { }
	}

	renderArchive();
	renderTabs();
	if (state.reports.length) {
		state.current = 0;
		state.page = 0;
		renderView();
	}
}

function shortName(n) {
	return n.split('/').pop() || n;
}

function roleLabel(r) {
	if (r.type === 'coverity') return 'Coverity 缺陷報表';
	if (r.type === 'blackduck') return 'BlackDuck 弱點清單';
	if (r.type === 'artifact') return '建置產物';
	return '其他檔案';
}
function renderArchive() {
	const listEl = $('archive-list');
	const reportedFiles = new Set(state.reports.map((r) => r.file));
	const items = [...state.reports.map((r) => ({ name: r.file, type: r.type }))];
	const extra = state.artifacts.filter((a) => !reportedFiles.has(a.name));

	const all = [
		...items,
		...extra.map((a) => ({ name: a.name, type: a.type, size: a.size })),
	];
	if (all.length === 0) {
		listEl.innerHTML = '<div class="empty">此 tar 內沒有可解析的報表。支援 Coverity HTML 與 BlackDuck CSV。</div>';
		$('archive-meta').textContent = state.entries.length + ' 個檔案';
		return;
	}
	listEl.innerHTML = all.map((it) => `
    <div class="ar-item">
      <div class="ar-head">
        <span class="ar-name" title="${esc(it.name)}">${esc(it.name)}</span>
      </div>
      <div class="ar-tags"><span class="tagchip role">${roleLabel(it)}</span></div>
      <span class="ar-size">${fmtSize(it.size)}</span>
    </div>`).join('');
	$('archive-meta').textContent = state.entries.length + ' 個檔案';
}

function renderTabs() {
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

	$('source-views').querySelector('#btn-export') && null;

	const eb = $('btn-export');
	if (eb) eb.addEventListener('click', exportActive);
}

function summaryFor(r) {
	return sevOrder.map((s) => ({ sev: s, n: r.totals[s] || 0 }));
}
const sevColor = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)', INFO: 'var(--info)' };

function filtersHTML() {
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

function applyFilters(bugs) {
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

function renderView() {
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

function filteredActive() {
	const r = state.reports[state.current];
	return applyFilters(r ? r.bugs : []);
}

function renderList() {
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

function sevBadge(sev) { return `<span class="bug-sev">${sevLabel[sev] || sev}</span>`; }

function covCodeHtml(code) {
	if (!code || !code.length) return '';
	const linesHtml = (items) => items.map((it) =>
		it.k === 'line'
			? `<li class="src-line${it.hit ? ' hit' : ''}${it.ev ? ' ev' : ''}">`
			+ `<span class="ln">${esc(it.n)}</span><span class="code-txt">${esc(it.text)}</span></li>`
			: `<li class="src-ev">${esc(it.text)}</li>`,
	).join('');
	return code.map((snip) =>
		`<div class="code"><div class="snip-file">${esc(snip.file)}</div><ol class="src">${linesHtml(snip.items)}</ol></div>`,
	).join('');
}

function covHead(b, coord) {
	const loc = b.file ? `${esc(b.file)}:${b.line ? '<b>' + esc(b.line) + '</b>' : ''}` : '—';
	const fnHtml = b.fn ? `<span class="fn">· ${esc(b.fn)}()</span>` : '';
	const cat = b.category ? `<span class="bug-cat">${esc(b.category)}</span>` : '';
	const cwe = b.cwe ? `<span class="pill">${esc(b.cwe)}</span>` : '';
	return `<div class="bug-sum">
      <span class="bug-coord">#${coord + 1}</span>
      <div class="bug-row2">
        ${sevBadge(b.sev)}
        <span class="bug-type">${esc(b.type)}</span>
        ${b.checker ? `<span class="bug-chk">${esc(b.checker)}</span>` : ''}
        ${cat}${cwe}
      </div>
      <div class="bug-loc">${loc}${fnHtml}</div>
    </div>`;
}
function covBody(b) {
	const events = (b.events && b.events.length
		? `<ol class="events">${b.events.map((e) => `<li><b>${esc(e.tag)}</b> ${esc(e.text)}</li>`).join('')}</ol>`
		: '');
	return `<div class="bug-body">
      <div class="kv">
        <dt>位置</dt><dd>${esc(b.file)}${b.line ? ' : <b>' + esc(b.line) + '</b>' : ''}${b.fn ? '（' + esc(b.fn) + '）' : ''}</dd>
        <dt>類型</dt><dd>${esc(b.type)}${b.category ? ' · ' + esc(b.category) : ''}</dd>
        ${b.checker ? `<dt>Checker</dt><dd>${esc(b.checker)}</dd>` : ''}
        ${b.cwe ? `<dt>CWE</dt><dd>${esc(b.cwe)}</dd>` : ''}
        <dt>說明</dt><dd>${esc(b.desc || '—')}</dd>
      </div>
      ${events}
      ${covCodeHtml(b.code)}
    </div>`;
}

function bdHead(b, coord) {
	const fixPill = !b.fix ? '' : (b.fix.indexOf('PATCH') >= 0 ? 'pill ok' : 'pill ignore');
	const fixTxt = { PATCHED: '已修復', IGNORED: '已忽略', NONE: '未修復' };
	return `<div class="bug-sum">
      <span class="bug-coord">#${coord + 1}</span>
      <div class="bug-row2">
        ${sevBadge(b.sev)}
        <span class="bug-type">${esc(b.cve || 'CVE')}</span>
        <span class="pill">${esc(b.component)} ${esc(b.version || '')}</span>
        ${b.cvss ? `<span class="pill">CVSS ${esc(b.cvss)}</span>` : ''}
        ${b.cwe ? `<span class="pill">${esc(b.cwe)}</span>` : ''}
        ${fixPill ? `<span class="${fixPill}">${fixTxt[b.fix] || esc(b.fix)}</span>` : ''}
      </div>
      <div class="bug-loc">${b.component ? esc(b.component) + ' ' + esc(b.version || '') : '—'}</div>
    </div>`;
}
function bdBody(b) {
	return `<div class="bug-body">
      <div class="kv">
        ${b.short ? `<dt>短期建議</dt><dd>${esc(b.short)}</dd>` : ''}
        ${b.long ? `<dt>長期建議</dt><dd>${esc(b.long)}</dd>` : ''}
        ${b.exploit ? `<dt>已知攻擊程式</dt><dd>${esc(b.exploit) === 'N/A' ? '無' : esc(b.exploit)}</dd>` : ''}
        <dt>說明</dt><dd>${esc(b.desc || '—')}</dd>
        ${b.official ? `<dt>官方解法</dt><dd>${esc(b.official)}</dd>` : ''}
        ${b.workaround ? `<dt>暫時規避</dt><dd>${esc(b.workaround)}</dd>` : ''}
      </div>
    </div>`;
}

function bugCard(b, coord, idx) {
	const head = b.src === 'blackduck' ? bdHead(b, coord) : covHead(b, coord);
	return `<div class="bug sev-${b.sev}" data-i="${idx}">${head}</div>`;
}

function bugDetail(b, coord) {
	return `<div class="bug sev-${b.sev}">${(b.src === 'blackduck' ? bdHead(b, coord) : covHead(b, coord))}${(b.src === 'blackduck' ? bdBody(b) : covBody(b))}</div>`;
}

function openDrawer(b, coord) {
	$('drawer-body').innerHTML = bugDetail(b, coord);
	$('drawer').classList.add('open');
	$('drawer').setAttribute('aria-hidden', 'false');
	$('drawer-overlay').classList.add('show');
}
function closeDrawer() {
	$('drawer').classList.remove('open');
	$('drawer').setAttribute('aria-hidden', 'true');
	$('drawer-overlay').classList.remove('show');
}

function exportActive() {
	const r = state.reports[state.current];
	if (!r || !r.bugs.length) return toast('沒有可匯出資料', true);
	const blob = new Blob([JSON.stringify({ source: r.name, file: r.file, totals: r.totals, bugs: r.bugs }, null, 2)], { type: 'application/json' });
	download(blob, (shortName(r.file) || 'report') + '.bugs.json');
	toast('已匯出 JSON');
}
function download(blob, name) {
	const a = document.createElement('a');
	a.href = URL.createObjectURL(blob);
	a.download = name;
	document.body.appendChild(a);
	a.click();
	setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 400);
}

function bindUI() {
	const dz = $('dropzone'), fin = $('file-input');

	$('btn-open').addEventListener('click', () => fin.click());
	$('btn-browse').addEventListener('click', () => fin.click());
	fin.addEventListener('change', () => { if (fin.files[0]) loadFile(fin.files[0]); });

	$('btn-theme').addEventListener('click', toggleTheme);

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
		if (e.target.id === 'pg-next') { if (state.page < lastPage()) { state.page++; renderList(); } return; }
		if (e.target.id === 'pg-prev') { if (state.page > 0) { state.page--; renderList(); } return; }
	});
	document.addEventListener('input', (e) => {
		if (e.target && e.target.id === 'q') { state.page = 0; renderList(); }
	});
	document.addEventListener('keydown', (e) => {
		if (e.target && e.target.id === 'q' && (e.key === 'Enter' || e.key === 'ArrowDown' || e.key === 'PageDown')) {
			if (e.key === 'Enter') { state.page = lastPage(); renderList(); e.preventDefault(); }
		}
	});


	$('drawer-close').addEventListener('click', closeDrawer);
	$('drawer-overlay').addEventListener('click', closeDrawer);


	document.addEventListener('keydown', (e) => {
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
function toggleTheme() {
	const root = document.documentElement;
	if (root.dataset.theme === 'dark') delete root.dataset.theme;
	else root.dataset.theme = 'dark';
}
function focusSearch() {
	const el = $('q');
	if (el) { el.focus(); el.select(); }
}
function lastPage() {
	const shown = filteredActive();
	return Math.max(1, Math.ceil(shown.length / state.perPage)) - 1;
}

bindUI();
