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

// Dereference an identifier to an authoritative URL, or '' if it is not one we
// know how to sum up. Never fabricate a link for unrecognised (e.g. BDSA) ids.
export function cveHref(id) {
	const m = /^CVE-(\d{4})-(\d{4,})$/i.exec(String(id || '').trim());
	return m ? 'https://nvd.nist.gov/vuln/detail/CVE-' + m[1] + '-' + m[2] : '';
}
export function cweHref(id) {
	const m = /^(?:CWE-)?(\d{1,4})$/i.exec(String(id || '').trim());
	return m ? 'https://cwe.mitre.org/data/definitions/' + m[1] + '.html' : '';
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

export const sevColor = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)', INFO: 'var(--info)' };
