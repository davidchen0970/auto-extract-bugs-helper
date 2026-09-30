import { shortName } from './util.js';
import { state } from './state.js';
import { toast } from './toast.js';

function download(blob, name) {
	const a = document.createElement('a');
	a.href = URL.createObjectURL(blob);
	a.download = name;
	document.body.appendChild(a);
	a.click();
	setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 400);
}

export function exportActive() {
	const r = state.reports[state.current];
	if (!r || !r.bugs.length) return toast('沒有可匯出資料', true);
	const blob = new Blob([JSON.stringify({ source: r.name, file: r.file, totals: r.totals, bugs: r.bugs }, null, 2)], { type: 'application/json' });
	download(blob, (shortName(r.file) || 'report') + '.bugs.json');
	toast('已匯出 JSON');
}

export function exportBug(b) {
	if (!b) return toast('沒有可下載的缺陷', true);
	const id = b.cve || b.type || b.checker || b.file || 'bug';
	const name = 'bug-' + String(id).replace(/[^A-Za-z0-9._-]+/g, '-') + '.json';
	const blob = new Blob([JSON.stringify(b, null, 2)], { type: 'application/json' });
	download(blob, name);
	toast('已下載缺陷 JSON');
}

export async function copyBug(b) {
	if (!b) return toast('沒有可複製的缺陷', true);
	try {
		await navigator.clipboard.writeText(JSON.stringify(b, null, 2));
		toast('已複製缺陷 JSON');
	} catch (err) {
		toast('複製失敗（剪貼簿不可用）', true);
	}
}
