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

export const sevColor = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)', INFO: 'var(--info)' };
