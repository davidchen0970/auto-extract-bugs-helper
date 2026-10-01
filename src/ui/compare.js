import { $, fmt } from './util.js';
import { toast } from './toast.js';
import { bugCard } from './cards.js';
import { openDrawer } from './drawer.js';
import { ingestFile, classifyReports, compareBugs } from '../core/index.js';

// Comparison state (private to this module - not in the global state).
const cmp = {
	side: null,
	fileA: null,
	fileB: null,
};

const PAGES = ['open', 'compare', 'cwe'];
function switchPage(name) {
	for (const p of PAGES) {
		const page = $('page-' + p);
		const tab = $('tab-' + p);
		if (!page || !tab) continue;
		page.hidden = p !== name;
		tab.classList.toggle('active', p === name);
	}
}

function setSlotName(slot, name) {
	const el = $(slot + '-name');
	if (el) el.textContent = name;
}

function updateRun() {
	const run = $('compare-run');
	run.disabled = !(cmp.fileA && cmp.fileB);
}

export function flattenBugs(reports, type) {
	return reports.filter((r) => r.type === type).flatMap((r) => r.bugs || []);
}

// Human-readable labels for the two report types we know how to diff.
const TYPE_NAME = { coverity: 'Coverity', blackduck: 'BlackDuck' };
const TYPE_ORDER = ['coverity', 'blackduck'];
export function typeName(t) {
	return TYPE_NAME[t] || String(t);
}

// The set of report types present across both archives. A tarball / folder often
// mixes Coverity AND BlackDuck reports; the diff must run for each type, not just
// for the first report that happens to be parsed. bugKey already namespaces its
// identity by type ('cov:…' vs 'bd:…'), so comparing each type on its own is
// both correct and cheap.
export function reportTypes(aList, bList) {
	const seen = new Set();
	for (const r of aList || []) if (r && r.type) seen.add(r.type);
	for (const r of bList || []) if (r && r.type) seen.add(r.type);
	return TYPE_ORDER.filter((t) => seen.has(t)).concat([...seen].filter((t) => !TYPE_ORDER.includes(t)));
}

// HTML for one report type's summary + added/removed/changed sections.
function blockHtml(diff) {
	const added = diff.added || [];
	const removed = diff.removed || [];
	const changed = diff.changed || [];
	const same = diff.same || [];

	const groupHtml = (arr, renderer) => {
		let out = '';
		const len = arr.length;
		for (let i = 0; i < len; i++) out += renderer(arr[i], i);
		return out;
	};

	const addedHtml = added.length
		? groupHtml(added, (b, i) => '<div class="cmp-item">' + bugCard(b, i, i) + '</div>')
		: '<div class="empty">無新增缺陷</div>';

	const removedHtml = removed.length
		? groupHtml(removed, (b, i) => '<div class="cmp-item">' + bugCard(b, i, i) + '</div>')
		: '<div class="empty">無移除缺陷</div>';

	const changedHtml = changed.length
		? groupHtml(changed, (c, i) =>
			'<div class="cmp-item"><div class="cmp-split">' +
			'<div class="cmp-side" data-side-before="' + i + '"><div class="cmp-side-tag">報表 A（基準）</div>' + bugCard(c.before, i, i) + '</div>' +
			'<div class="cmp-side" data-side-after="' + i + '"><div class="cmp-side-tag">報表 B（現況）</div>' + bugCard(c.after, i, i) + '</div>' +
			'</div></div>')
		: '<div class="empty">無內容差異</div>';

	return '<div class="cmp-summary">' +
		'<div class="card cmp-card"><div class="card-n" style="color:var(--high)">' + fmt(added.length) + '</div><div class="card-l">新增</div></div>' +
		'<div class="card cmp-card"><div class="card-n" style="color:var(--ok)">' + fmt(removed.length) + '</div><div class="card-l">移除</div></div>' +
		'<div class="card cmp-card"><div class="card-n" style="color:var(--info)">' + fmt(changed.length) + '</div><div class="card-l">內容差異</div></div>' +
		'<div class="card cmp-card"><div class="card-n">' + fmt(same.length) + '</div><div class="card-l">相同</div></div>' +
		'</div>' +
		'<div class="cmp-section" data-list="added"><h3>新增 <span class="muted">僅存在於報表 B，點擊看詳細</span></h3><div class="cmp-group">' + addedHtml + '</div></div>' +
		'<div class="cmp-section" data-list="removed"><h3>移除 <span class="muted">僅存在於報表 A（基準），點擊看詳細</span></h3><div class="cmp-group">' + removedHtml + '</div></div>' +
		'<div class="cmp-section"><h3>內容差異 <span class="muted">兩邊都有但內容改變</span></h3><div class="cmp-group">' + changedHtml + '</div></div>';
}

// Render the diff results as BOOKMARK TABS — one tab per report type present in
// the archives. Only the active type's defect cards are ever in the DOM; switching
// tabs lazily renders that type on demand. That keeps the results page short and
// bounds peak memory even when a tarball holds both Coverity and BlackDuck with
// hundreds of defects each.
function renderResults(results) {
	const wrap = $('compare-results');
	wrap.hidden = false;

	if (!results || !results.length) {
		wrap.innerHTML = '<div class="empty">兩份檔案內都沒有可辨識的報表</div>';
		return;
	}

	// (btnIdx === i) so the first type is pre-selected; data-cmp-tab carries the
	// index into `results`, which renderType() resolves.
	const tabs = results.map((_r, i) =>
		'<button type="button" class="cmp-tab' + (i === 0 ? ' active' : '') + '" data-cmp-tab="' + i + '">' +
		typeName(results[i].type) +
		'</button>'
	).join('');

	wrap.innerHTML = '<div class="cmp-tabs">' + tabs + '</div><div class="cmp-pane"></div>';

	renderType(results, 0);

	wrap.querySelectorAll('.cmp-tab').forEach((btn) => {
		btn.addEventListener('click', () => renderType(results, +btn.dataset.cmpTab));
	});
}

// Swap the pane to a single report type (available lazily on tab switch, so the
// other types' DOM is freed as soon as the block is replaced).
function renderType(results, idx) {
	const wrap = $('compare-results');
	const pane = wrap.querySelector('.cmp-pane');
	if (!pane || !results[idx]) return;

	const { type, diff } = results[idx];
	pane.innerHTML = '<div class="cmp-block"><h3 class="cmp-type-title">' + typeName(type) + '</h3>' + blockHtml(diff) + '</div>';
	bindBlock(pane.querySelector('.cmp-block'), diff);

	wrap.querySelectorAll('.cmp-tab').forEach((b) => b.classList.toggle('active', +b.dataset.cmpTab === idx));
}

// Wire a single report-type block: drawer on added / removed cards and on each
// side of a changed bug.
function bindBlock(root, diff) {
	if (!root) return;
	const changed = diff.changed || [];
	bindCompareCards(root, 'added', diff.added || []);
	bindCompareCards(root, 'removed', diff.removed || []);
	root.querySelectorAll('[data-side-before]').forEach((el) => {
		const i = +el.dataset.sideBefore;
		if (changed[i]) el.addEventListener('click', () => openDrawer(changed[i].before, i));
	});
	root.querySelectorAll('[data-side-after]').forEach((el) => {
		const i = +el.dataset.sideAfter;
		if (changed[i]) el.addEventListener('click', () => openDrawer(changed[i].after, i));
	});
}

// Attach drawer-open to every bug card inside a section.
function bindCompareCards(root, listName, bugs) {
	root.querySelectorAll('[data-list="' + listName + '"] .bug').forEach((el, j) => {
		el.addEventListener('click', () => openDrawer(bugs[j], j));
	});
}

// Parse one side completely, then drop its raw bytes before the other side is
// parsed. Keeping both decompressed archives + their DOM parse trees alive at once
// is the main memory spike during a comparison.
async function parseSide(file) {
	const { reports } = classifyReports(await ingestFile(file));
	return reports;
}

async function runCompare() {
	if (!cmp.fileA || !cmp.fileB) return toast('請先選擇報表 A 與報表 B', true);
	const run = $('compare-run');
	run.disabled = true;
	run.textContent = '比對中…';
	try {
		// Sequential on purpose: repA's tarball bytes are released before repB is
		// read, so the two decompressed archives are never resident at the same time.
		const repA = await parseSide(cmp.fileA);
		const repB = await parseSide(cmp.fileB);

		if (!repA.length) { toast('無法解析報表 A', true); return; }
		if (!repB.length) { toast('無法解析報表 B', true); return; }

		// Diff EVERY report type found in the two archives (usually Coverity and
		// BlackDuck live side by side in one tarball), so no type is dropped.
		const types = reportTypes(repA, repB);
		const results = [];
		let nAdded = 0, nRemoved = 0, nChanged = 0;
		for (const type of types) {
			const diff = compareBugs(flattenBugs(repA, type), flattenBugs(repB, type));
			results.push({ type, diff });
			nAdded += diff.added.length;
			nRemoved += diff.removed.length;
			nChanged += diff.changed.length;
		}

		renderResults(results);
		toast('比對完成：新增 ' + fmt(nAdded) + '／移除 ' + fmt(nRemoved) + '／差異 ' + fmt(nChanged));
	} catch (err) {
		toast('比對失敗：' + (err && err.message ? err.message : err), true);
		console.error(err);
	} finally {
		run.disabled = !(cmp.fileA && cmp.fileB);
		run.textContent = '開始比對';
	}
}

function pickSlot(side) {
	const inp = $('cmp-file');
	cmp.side = side;
	inp.value = '';
	inp.click();
}

function onPick(file) {
	if (!file) return;
	if (cmp.side === 'a') {
		cmp.fileA = file;
		setSlotName('slot-a', file.name);
	} else {
		cmp.fileB = file;
		setSlotName('slot-b', file.name);
	}
	updateRun();
}

function bindSlot(slotEl, side) {
	['dragover', 'dragenter'].forEach((ev) => slotEl.addEventListener(ev, (e) => { e.preventDefault(); slotEl.classList.add('cmp-drag'); }));
	['dragleave', 'drop'].forEach((ev) => slotEl.addEventListener(ev, (e) => { e.preventDefault(); slotEl.classList.remove('cmp-drag'); }));
	slotEl.addEventListener('drop', (e) => {
		const f = e.dataTransfer.files && e.dataTransfer.files[0];
		if (f) {
			cmp.side = side;
			onPick(f);
		}
	});
}

function closeMobileMenu() {
	const m = $('menu');
	const btn = $('menu-toggle');
	if (m) m.classList.remove('open');
	if (btn) btn.setAttribute('aria-expanded', 'false');
}

export function bindCompare() {
	$('tab-open').addEventListener('click', () => switchPage('open'));
	$('tab-compare').addEventListener('click', () => switchPage('compare'));
	$('tab-cwe').addEventListener('click', () => switchPage('cwe'));
	$('menu-open').addEventListener('click', () => { switchPage('open'); closeMobileMenu(); });
	$('menu-compare').addEventListener('click', () => { switchPage('compare'); closeMobileMenu(); });
	$('btn-open').addEventListener('click', () => switchPage('open'));
	$('compare-run').addEventListener('click', runCompare);

	const fin = $('cmp-file');
	fin.addEventListener('change', () => { if (fin.files && fin.files[0]) onPick(fin.files[0]); });

	bindSlot($('slot-a'), 'a');
	bindSlot($('slot-b'), 'b');
	$('pick-a').addEventListener('click', (e) => { e.stopPropagation(); pickSlot('a'); });
	$('pick-b').addEventListener('click', (e) => { e.stopPropagation(); pickSlot('b'); });
	$('slot-a').addEventListener('click', () => pickSlot('a'));
	$('slot-b').addEventListener('click', () => pickSlot('b'));
}
