import { $, esc } from './util.js';
import { bugDetail } from './cards.js';
import { cweWhat } from './cwe.js';
import { vulnLookup } from './vuln.js';
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

// "AI 研究結果" cells (stamped data-key + hidden by cards.js for CVSS+package
// defects with no authored aiResearch): look the「CVE@pkg」key up in the
// vulnerability handbook. When an entry exists, reveal the row and fill in the
// research explanation plus the actionable 因應建議; when there is no entry, still
// reveal the row with a short note so people know AI research is not available yet.
function renderResearchHTML(hit) {
	const expl = hit.what ? `<div class="cwe-text">${renderMd(hit.what)}</div>` : '';
	const reco = hit.recommendation
		? `<section class="cwe-sec"><h3 class="cwe-label">因應建議</h3><div class="cwe-text">${renderMd(hit.recommendation)}</div></section>`
		: '';
	return expl + reco || '<span class="muted">（AI 弱點手冊無詳細說明）</span>';
}

const MISS_NOTE = (key) =>
	`<span class="muted">（尚未有此筆的 AI 研究結果：AI 弱點手冊無 ${esc(key)} 條目，AI 產出後即會顯示）</span>`;

function hydrateAiResearch(root) {
	for (const c of root.querySelectorAll('.ai-research[data-key]')) {
		const key = c.getAttribute('data-key');
		const dt = c.previousElementSibling;
		if (!key || !dt || !dt.classList.contains('ai-research-row')) continue;
		vulnLookup(key).then((hit) => {
			dt.hidden = false;
			c.hidden = false;
			c.innerHTML = hit ? renderResearchHTML(hit) : MISS_NOTE(key);
		}).catch(() => { c.innerHTML = MISS_NOTE(key); });
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
	hydrateAiResearch($('drawer-body'));
}

export function currentBug() {
	return activeBug;
}

export function closeDrawer() {
	$('drawer').classList.remove('open');
	$('drawer').setAttribute('aria-hidden', 'true');
	$('drawer-overlay').classList.remove('show');
}
