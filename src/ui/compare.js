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

function switchPage(name) {
	const open = name === 'open';
	$('page-open').hidden = !open;
	$('page-compare').hidden = open;
	$('tab-open').classList.toggle('active', open);
	$('tab-compare').classList.toggle('active', !open);
}

function setSlotName(slot, name) {
	const el = $(slot + '-name');
	if (el) el.textContent = name;
}

function updateRun() {
	const run = $('compare-run');
	run.disabled = !(cmp.fileA && cmp.fileB);
}

function flattenBugs(reports, type) {
	return reports.filter((r) => r.type === type).flatMap((r) => r.bugs || []);
}

function renderResults(diff) {
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

	const wrap = $('compare-results');
	wrap.hidden = false;
	wrap.innerHTML =
		'<div class="cmp-summary">' +
		'<div class="card cmp-card"><div class="card-n" style="color:var(--high)">' + fmt(added.length) + '</div><div class="card-l">新增</div></div>' +
		'<div class="card cmp-card"><div class="card-n" style="color:var(--ok)">' + fmt(removed.length) + '</div><div class="card-l">移除</div></div>' +
		'<div class="card cmp-card"><div class="card-n" style="color:var(--info)">' + fmt(changed.length) + '</div><div class="card-l">內容差異</div></div>' +
		'<div class="card cmp-card"><div class="card-n">' + fmt(same.length) + '</div><div class="card-l">相同</div></div>' +
		'</div>' +
		'<div class="cmp-section" data-list="added"><h3>新增 <span class="muted">僅存在於報表 B，點擊看詳細</span></h3><div class="cmp-group">' + addedHtml + '</div></div>' +
		'<div class="cmp-section" data-list="removed"><h3>移除 <span class="muted">僅存在於報表 A（基準），點擊看詳細</span></h3><div class="cmp-group">' + removedHtml + '</div></div>' +
		'<div class="cmp-section"><h3>內容差異 <span class="muted">兩邊都有但內容改變</span></h3><div class="cmp-group">' + changedHtml + '</div></div>';

	bindCompareCards(wrap, 'added', added);
	bindCompareCards(wrap, 'removed', removed);
	wrap.querySelectorAll('[data-side-before]').forEach((el) => {
		const i = +el.dataset.sideBefore;
		if (changed[i]) el.addEventListener('click', () => openDrawer(changed[i].before, i));
	});
	wrap.querySelectorAll('[data-side-after]').forEach((el) => {
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

		const typeA = repA[0].type;
		const typeB = repB[0].type;
		if (typeA !== typeB) {
			toast('兩個檔案的報表類型不同：請都用 Coverity 或都用 BlackDuck', true);
			return;
		}

		const diff = compareBugs(flattenBugs(repA, typeA), flattenBugs(repB, typeB));
		renderResults(diff);
		toast('比對完成：新增 ' + diff.added.length + '／移除 ' + diff.removed.length + '／差異 ' + diff.changed.length);
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
