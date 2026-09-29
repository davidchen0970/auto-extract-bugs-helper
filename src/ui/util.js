export const $ = (id) => document.getElementById(id);

export const fmt = (n) => (n == null ? '–' : Number(n).toLocaleString('en-US'));

export function fmtSize(b) {
	if (b == null) return '';
	if (b < 1024) return b + ' B';
	const u = ['KB', 'MB', 'GB', 'TB'];
	let i = -1, v = b;
	do { v /= 1024; i++; } while (v >= 1024 && i < u.length - 1);
	return v.toFixed(1) + ' ' + u[i];
}

export const esc = (s) => String(s ?? '').replace(/[&<>"']/g,
	(c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export function shortName(n) {
	return n.split('/').pop() || n;
}

function canonicalCve(id) {
	const m = /^CVE-(\d{4})-(\d{4,})$/i.exec(String(id || '').trim());
	return m ? 'CVE-' + m[1] + '-' + m[2] : '';
}

export function cveHref(id) {
	const c = canonicalCve(id);
	return c ? 'https://nvd.nist.gov/vuln/detail/' + c : '';
}
export function cweHref(id) {
	const m = /^(?:CWE-)?(\d{1,4})$/i.exec(String(id || '').trim());
	return m ? 'https://cwe.mitre.org/data/definitions/' + m[1] + '.html' : '';
}

export function cveOrgHref(id) { const c = canonicalCve(id); return c ? 'https://www.cve.org/CVERecord?id=' + c : ''; }
export function ghAdvisoryHref(id) { const c = canonicalCve(id); return c ? 'https://github.com/advisories?query=' + c : ''; }
export function vulnersHref(id) { const c = canonicalCve(id); return c ? 'https://vulners.com/search?query=' + c : ''; }

export function googleAiUrl(id) {
	const c = canonicalCve(id);
	return c ? 'https://www.google.com/search?q=' + encodeURIComponent(c + ' 修復 方案') : '';
}

export function cveExtLinks(id) {
	const lnk = (href, label, cls) => (href
		? `<a class="xlnk ${cls}" target="_blank" rel="noopener noreferrer" href="${href}">${label}</a>`
		: '');
	const refs = [
		lnk(cveOrgHref(id), 'CVE.org · 官方紀錄', 'x-cveorg'),
		lnk(ghAdvisoryHref(id), 'GitHub Advisory', 'x-gh'),
		lnk(vulnersHref(id), 'Vulners', 'x-vulners'),
		lnk(googleAiUrl(id), 'google 搜尋', 'x-google')].filter(Boolean);
	return refs.length
		? `<div class="kv cve-help"><dt>外部修復參考</dt><dd class="refs">${refs.join('')}</dd></div>`
		: '';
}

// Inner text (esced) or an anchor when the id dereferences safely.
export function cveLink(id) {
	const href = cveHref(id);
	return href
		? `<a class="cve-lnk" target="_blank" rel="noopener noreferrer" href="${href}">${esc(id || 'CVE')}</a>`
		: esc(id || 'CVE');
}
export function cweLink(id) {
	const href = cweHref(id);
	return href
		? `<a class="cwe-lnk" target="_blank" rel="noopener noreferrer" href="${href}">${esc(id)}</a>`
		: esc(id);
}

export function kernelFixHref(id, component) {
	if (!/kernel/i.test(String(component || '').trim())) return '';
	const c = canonicalCve(id);
	return c ? 'https://github.com/torvalds/linux/search?q=' + c + '&type=commits' : '';
}

export const sevColor = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)', INFO: 'var(--info)' };
