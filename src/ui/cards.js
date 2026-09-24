import { esc } from './util.js';
import { renderMd } from './md.js';
import { sevLabel } from '../core/index.js';

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

export function covBody(b) {
	const events = (b.events && b.events.length
		? `<ol class="events">${b.events.map((e) => `<li><b>${esc(e.tag)}</b> ${esc(e.text)}</li>`).join('')}</ol>`
		: '');
	return `<div class="bug-body">
      <div class="kv">
        <dt>位置</dt><dd>${esc(b.file)}${b.line ? ' : <b>' + esc(b.line) + '</b>' : ''}${b.fn ? '（' + esc(b.fn) + '）' : ''}</dd>
        <dt>類型</dt><dd>${esc(b.type)}${b.category ? ' · ' + esc(b.category) : ''}</dd>
        ${b.checker ? `<dt>Checker</dt><dd>${esc(b.checker)}</dd>` : ''}
        ${b.cwe ? `<dt>CWE</dt><dd>${esc(b.cwe)}</dd>` : ''}
        <dt>說明</dt><dd>${renderMd(b.desc || '—')}</dd>
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
        <span class="bug-type">${esc(b.cve || 'CVE')}</span>
        <span class="pill">${esc(b.component)} ${esc(b.version || '')}</span>
        ${b.cvss ? `<span class="pill">CVSS ${esc(b.cvss)}</span>` : ''}
        ${b.cwe ? `<span class="pill">${esc(b.cwe)}</span>` : ''}
        ${fixPill ? `<span class="${fixPill}">${fixTxt[b.fix] || esc(b.fix)}</span>` : ''}
      </div>
      <div class="bug-loc">${b.component ? esc(b.component) + ' ' + esc(b.version || '') : '—'}</div>
    </div>`;
}

export function bdBody(b) {
	return `<div class="bug-body">
      <div class="kv">
        ${b.short ? `<dt>短期建議</dt><dd>${esc(b.short)}</dd>` : ''}
        ${b.long ? `<dt>長期建議</dt><dd>${esc(b.long)}</dd>` : ''}
        ${b.exploit ? `<dt>已知攻擊程式</dt><dd>${esc(b.exploit) === 'N/A' ? '無' : esc(b.exploit)}</dd>` : ''}
        <dt>說明</dt><dd>${renderMd(b.desc || '—')}</dd>
        ${b.official ? `<dt>官方解法</dt><dd>${renderMd(b.official)}</dd>` : ''}
        ${b.workaround ? `<dt>暫時規避</dt><dd>${esc(b.workaround)}</dd>` : ''}
      </div>
    </div>`;
}

export function bugCard(b, coord, idx) {
	const head = b.src === 'blackduck' ? bdHead(b, coord) : covHead(b, coord);
	return `<div class="bug sev-${b.sev}" data-i="${idx}">${head}</div>`;
}

export function bugDetail(b, coord) {
	return `<div class="bug sev-${b.sev}">${(b.src === 'blackduck' ? bdHead(b, coord) : covHead(b, coord))}${(b.src === 'blackduck' ? bdBody(b) : covBody(b))}</div>`;
}
