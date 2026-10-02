import { esc, cveLink, cweLink, cveExtLinks } from './util.js';
import { renderMd } from './md.js';
import { sevLabel } from '../core/index.js';
import { pkgSlug } from './vuln.js';

// A "CWE 說明" cell. The handbook data is lazy-loaded now, so we stamp the id on the
// element and let drawer.js hydrate it in place with cweWhat(id) after openDrawer;
// b.desc is shown meanwhile so the detail opens instantly without waiting on a chunk.
function cweDescCell(id, fallback) {
	if (!id) return fallback;
	return `<span class="cwe-what" data-cwe="${esc(id)}">${fallback}</span>`;
}

export function sevBadge(sev) { return `<span class="bug-sev">${sevLabel[sev] || sev}</span>`; }

export function covCodeHtml(code) {
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

export function covHead(b, coord) {
	const loc = b.file ? `${esc(b.file)}:${b.line ? '<b>' + esc(b.line) + '</b>' : ''}` : '—';
	const fnHtml = b.fn ? `<span class="fn">· ${esc(b.fn)}()</span>` : '';
	const cat = b.category ? `<span class="bug-cat">${esc(b.category)}</span>` : '';
	const cwe = b.cwe ? `<span class="pill">${cweLink(b.cwe)}</span>` : '';
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

function researchRow(b) {
	if (b.aiResearch) return `<dt>AI 研究結果</dt><dd class="ai-research">${renderMd(b.aiResearch)}</dd>`;
	const isSca = b.src === 'custom' || b.src === 'blackduck';
	const cveId = b.cveClean || b.cve || '';
	const key = (isSca && cveId && b.component) ? cveId + '@' + pkgSlug(b.component) : '';
	if (!key) return '';
	return `<dt class="ai-research-row" hidden>AI 研究結果</dt><dd class="ai-research" data-key="${esc(key)}" hidden></dd>`;
}

export function covBody(b) {
	const events = (b.events && b.events.length
		? `<ol class="events">${b.events.map((e) => `<li><b>${esc(e.tag)}</b> ${esc(e.text)}</li>`).join('')}</ol>`
		: '');
	return `<div class="bug-body">
      <div class="kv det-kv">
        <dt>位置</dt><dd>${esc(b.file)}${b.line ? ' : <b>' + esc(b.line) + '</b>' : ''}${b.fn ? '（' + esc(b.fn) + '）' : ''}</dd>
        <dt>類型</dt><dd>${esc(b.type)}${b.category ? ' · ' + esc(b.category) : ''}</dd>
        ${b.checker ? `<dt>Checker</dt><dd>${esc(b.checker)}</dd>` : ''}
        ${b.cwe ? `<dt>CWE</dt><dd>${cweLink(b.cwe)}</dd>` : ''}
        <dt>CWE 說明</dt><dd>${cweDescCell(b.cwe, renderMd(b.desc || '—'))}</dd>
        ${researchRow(b)}
      </div>
      ${events}
      ${covCodeHtml(b.code)}
    </div>`;
}

export function bdHead(b, coord) {
	const fixPill = !b.fix ? '' : (b.fix.indexOf('PATCH') >= 0 ? 'pill ok' : 'pill ignore');
	const fixTxt = { PATCHED: '已修復', IGNORED: '已忽略', NONE: '未修復' };
	return `<div class="bug-sum">
      <span class="bug-coord">#${coord + 1}</span>
      <div class="bug-row2">
        ${sevBadge(b.sev)}
        <span class="bug-type">${cveLink(b.cve)}</span>
        <span class="pill">${esc(b.component)} ${esc(b.version || '')}</span>
        ${b.cvss ? `<span class="pill">CVSS ${esc(b.cvss)}</span>` : ''}
        ${b.cwe ? `<span class="pill">${cweLink(b.cwe)}</span>` : ''}
        ${fixPill ? `<span class="${fixPill}">${fixTxt[b.fix] || esc(b.fix)}</span>` : ''}
      </div>
      <div class="bug-loc">${b.component ? esc(b.component) + ' ' + esc(b.version || '') : '—'}</div>
    </div>`;
}

export function bdBody(b) {
	return `<div class="bug-body">
      <div class="kv det-kv">
        ${b.short ? `<dt>短期建議</dt><dd>${esc(b.short)}</dd>` : ''}
        ${b.long ? `<dt>長期建議</dt><dd>${esc(b.long)}</dd>` : ''}
        ${b.exploit ? `<dt>已知攻擊程式</dt><dd>${esc(b.exploit) === 'N/A' ? '無' : esc(b.exploit)}</dd>` : ''}
        <dt>CWE 說明</dt><dd>${cweDescCell(b.cwe, renderMd(b.desc || '—'))}</dd>
        ${researchRow(b)}
        ${b.official ? `<dt>官方解法</dt><dd>${renderMd(b.official)}</dd>` : ''}
        ${b.workaround ? `<dt>暫時規避</dt><dd>${esc(b.workaround)}</dd>` : ''}
      </div>
      ${cveHelpBlock(b)}
    </div>`;
}

export function cveHelpBlock(b) {
	return cveExtLinks(b.cveClean || b.cve);
}

export function customHead(b, coord) {
	const fixPill = !b.fix ? '' : (b.fix.indexOf('PATCH') >= 0 ? 'pill ok' : 'pill ignore');
	const cvss = b.cvss ? `<span class="pill">CVSS ${esc(b.cvss)}</span>` : '';
	const sec = b.securityRisk ? `<span class="pill">${esc(b.securityRisk)}</span>` : '';
	const cwePills = (b.cweList || []).map((c) => `<span class="pill">${cweLink(c)}</span>`).join('');
	return `<div class="bug-sum">
      <span class="bug-coord">#${coord + 1}</span>
      <div class="bug-row2">
        ${sevBadge(b.sev)}
        <span class="bug-type">${cveLink(b.cveClean || b.cve)}</span>
        <span class="pill">${esc(b.component)} ${esc(b.version || '')}</span>
        ${cvss}${sec}${cwePills}
        ${fixPill ? `<span class="${fixPill}">${esc(b.fix)}</span>` : ''}
      </div>
      <div class="bug-loc">${b.component ? esc(b.component) + ' ' + esc(b.version || '') : '—'}</div>
    </div>`;
}

// Raw columns that are already surfaced in the curated summary / description above,
// so the "匯出原始欄位" dump below only shows what isn't repeated elsewhere.
const CUSTOM_SURFACED = new Set([
	'Description', 'Component name', 'Component version name', 'Component origin name',
	'Component origin version name', 'Vulnerability id', 'Vulnerability source',
	'URL', 'Security Risk', 'Overall score', 'Base score', 'CVSS Version',
	'CWE Ids', 'Match type', 'Reachable', 'Project path',
	'Remediation status', 'Status justification',
	'Published on', 'Updated on',
]);

function customUrl(v) {
	return /^https?:\/\//i.test(v)
		? `<a target="_blank" rel="noopener noreferrer" href="${esc(v)}">${esc(v)}</a>`
		: esc(v);
}

export function customBody(b) {
	const comp = b.component ? esc(b.component) + (b.version ? ' ' + esc(b.version) : '') : '—';
	const weak = cveLink(b.cveClean || b.cve)
		+ (b.cve && b.cve !== b.cveClean ? ' <span class="muted">（' + esc(b.cve) + '）</span>' : '');
	const sev = sevBadge(b.sev)
		+ (b.securityRisk ? ' · ' + esc(b.securityRisk) : '')
		+ (b.cvss ? ' · CVSS ' + esc(b.cvss) : '');
	const meta = [
		['弱點編號', weak],
		['元件', comp + (b.originName ? ' <span class="muted">' + esc(b.originName) + '</span>' : '')],
		['嚴重性', sev],
		['修復狀態', b.fix + (b.justification ? ' — ' + esc(b.justification) : '')],
		['發布日期', esc(b.published)],
		['更新日期', esc(b.updated)],
		['弱點來源', esc(b.vulnSource)],
		['CWE', (b.cweList || []).map(cweLink).join('、')],
		['Project 路徑', b.project || '—'],
		['配對方式', esc(b.match) + (b.reachable && b.reachable !== 'false' ? ' · 可達=' + esc(b.reachable) : '')],
	].filter(([, v]) => v && v !== '—')
		.map(([label, val]) => `<dt>${label}</dt><dd>${val}</dd>`).join('');

	const desc = b.desc ? `<div class="desc-block">${renderMd(b.desc)}</div>` : '';

	let cweNote = '';
	const cwes = (b.cweList || []).filter(Boolean).slice(0, 1);
	if (cwes.length) cweNote = `<div class="kv det-kv"><dt>CWE 說明</dt><dd>${cweDescCell(cwes[0], '—')}</dd>${researchRow(b)}</div>`;

	const extraRows = Object.keys(b.fields || {})
		.filter((k) => !CUSTOM_SURFACED.has(k))
		.map((k) => ({ k, v: b.fields[k] }))
		.filter((f) => f.v);
	const extra = extraRows.map((f) => `<dt>${esc(f.k)}</dt><dd>${customUrl(f.v)}</dd>`).join('');

	return `<div class="bug-body">
		${meta ? `<div class="kv det-kv">${meta}</div>` : ''}
		${desc}
		${cweNote}
		${extra ? `<div class="fields-cap">匯出原始欄位（以下 ${extraRows.length} 欄）</div><div class="kv det-kv fields-all">${extra}</div>` : ''}
		${cveHelpBlock(b)}
	</div>`;
}

export function bugCard(b, coord, idx) {
	const head = b.src === 'blackduck' ? bdHead(b, coord)
		: b.src === 'custom' ? customHead(b, coord)
		: covHead(b, coord);
	return `<div class="bug sev-${b.sev}" data-i="${idx}">${head}</div>`;
}

export function bugDetail(b, coord) {
	let head, body;
	if (b.src === 'blackduck') { head = bdHead(b, coord); body = bdBody(b); }
	else if (b.src === 'custom') { head = customHead(b, coord); body = customBody(b); }
	else { head = covHead(b, coord); body = covBody(b); }

	return `<div class="bug sev-${b.sev}">${head}${body}</div>`;
}
