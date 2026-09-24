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
