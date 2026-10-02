import { $ } from './util.js';
import index from '../../data/cwe/index.js';

// The handbook ships ~41 chunks covering 900+ CWE entries, but the browser used to
// pull every one of them in eagerly at startup even when the user never opened the
// handbook nor expanded a defect. Each chunk stays a `export default [...]` file, but
// now it is loaded on demand:
//   - cweWhat(id)  → dynamic-import()s exactly the chunk owning that CWE id
//   - renderList()  → loads all chunks the first time the handbook is actually opened
// The tiny data/cwe/index.js manifest (id → chunk file) finds the right chunk without
// importing the heavy payloads (regenerate it via `node scripts/cwe-index.mjs`).

// [spec, category] pairs; spec is relative to data/cwe/.
const SPECS = [
	['web/inputvalidation.js', 'input-validation'],
	['web/web-misc.js', 'web'],
	['crypto/crypto.js', 'crypto'],
	['native/memory.js', 'memory · native (C/C++)'],
	['auth/auth.js', 'auth / identity'],
	['resilience/concurrency.js', 'concurrency · race'],
	['resilience/errors.js', 'error handling'],
	['resilience/logging.js', 'logging · leak'],
	['crypto/crypto-extra.js', 'crypto · randomness'],
	['auth/session.js', 'session · state'],
	['auth/permissions.js', 'permissions · privileges'],
	['web/web-include.js', 'web · include & assign'],
	['resilience/server.js', 'server · robustness'],
	['auth/broken-access-control.js', 'broken access control'],
	['web/files-paths.js', 'files · paths'],
	['resilience/resource-dos.js', 'resource · dos'],
	['crypto/crypto-hardening.js', 'crypto · hardening'],
	['resilience/config.js', 'config · defaults'],
	['resilience/immutable.js', 'assumed-immutable'],
	['resilience/logging-fail.js', 'logging · fail (injection/monitor)'],
	['native/null-c.js', 'C/C++ · null & init'],
	['web/web-injection.js', 'web · xss-server & xml'],
	['web/eval-reflect.js', 'eval · reflection & nosql'],
	['web/path-var.js', 'path traversal variants'],
	['auth/auth-bypass.js', 'auth bypass · trust'],
	['expansion/gap-01.js', '補齊·組態/路徑 (CWE 5–56)'],
	['expansion/gap-02.js', '補齊·路徑等價/注入 (CWE 57–151)'],
	['expansion/gap-03.js', '補齊·中性化/編碼/轉型 (CWE 152–218)'],
	['expansion/gap-04.js', '補齊·敏感資料/日誌/密碼/權限 (CWE 219–299)'],
	['expansion/gap-05.js', '補齊·認證/密碼學/隨機數 (CWE 301–383)'],
	['expansion/gap-06.js', '補齊·符號/邏輯/通道/例外 (CWE 386–483)'],
	['expansion/gap-07.js', '補齊·敏感資訊/可寫性/惡意碼 (CWE 484–542)'],
	['expansion/gap-08.js', '補齊·組態/資訊暴露/物件模型 (CWE 543–596)'],
	['expansion/gap-09.js', '補齊·輸入驗證/認證/API (CWE 597–694)'],
	['expansion/gap-10.js', '補齊·低階/記憶體/並行 (CWE 695–832)'],
	['expansion/gap-11.js', '補齊·驗證/Android/通訊/Web (CWE 836–1056)'],
	['expansion/gap-12.js', '補齊·程式碼/資料品質 (CWE 1057–1100)'],
	['expansion/gap-13.js', '補齊·程式碼品質/文件/硬體 (CWE 1101–1221)'],
	['expansion/gap-14.js', '補齊·硬體/韌體/密碼 (CWE 1222–1269)'],
	['expansion/gap-15.js', '補齊·硬體/SoC/輸入驗證 (CWE 1270–1318)'],
	['expansion/gap-16.js', '補齊·硬體/嵌入式/SoC/AI (CWE 1319–1434)'],
];

const loaded = new Map();   // spec -> entries[]
const CATALOG = [];        // merged catalog, filled once by ensureCatalog()
let building = null;       // single in-flight ensureCatalog() promise

async function loadChunk(spec) {
	if (!loaded.has(spec)) {
		const m = await import('../../data/cwe/' + spec);
		loaded.set(spec, m.default || []);
	}
	return loaded.get(spec);
}

// Load every chunk exactly once, tag each entry with its category, and keep the whole
// handbook sorted by CWE id ascending for a stable "由小到大" handbook order.
async function ensureCatalog() {
	if (CATALOG.length) return CATALOG;
	if (!building) {
		building = (async () => {
			for (const [spec, category] of SPECS) {
				for (const e of await loadChunk(spec)) CATALOG.push({ cat: category, ...e });
			}
			CATALOG.sort((a, b) => +a.id.replace(/CWE-/, '') - +b.id.replace(/CWE-/, ''));
		})().then(
			(res) => { building = null; return res; },
			(err) => { building = null; throw err; },
		);
	}
	return building;
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

	section('(a) 弱點是什麼', el('p', 'cwe-text', e.what));
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
	if (!CATALOG.length && !loaded.size) listEl.innerHTML = '<div class="empty">載入 CWE 手冊…</div>';

	await ensureCatalog();

	const q = ($('cwe-q').value || '').trim().toLowerCase();
	const hideDep = $('cwe-hide-deprecated').checked;
	const hits = CATALOG.filter((e) => {
		if (hideDep && e.status === 'Deprecated') return false;
		if (!q) return true;
		return (e.id + ' ' + e.name + ' ' + (e.tags || []).join(' ')).toLowerCase().includes(q);
	});

	listEl.innerHTML = '';
	for (const e of hits) {
		const b = el('button', 'cwe-entry', e.id + ' — ' + e.name);
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
	const spec = index[key];
	if (!spec) return null;
	const entries = await loadChunk(spec);
	const hit = entries.find((e) => e.id === key);
	return hit ? hit.what : null;
}
