import { SEV, emptyTotals, sevFromBD } from './schema.js';

export function parseCSVtext(str) {
	const rows = [];
	const n = str.length;
	let i = 0,
		row = [],
		field = '',
		inQuotes = false;
	if (str.charCodeAt(0) === 0xfeff) i = 1;
	while (i < n) {
		const c = str[i];
		if (inQuotes) {
			if (c === '"') {
				if (str[i + 1] === '"') {
					field += '"';
					i += 2;
				} else {
					inQuotes = false;
					i++;
				}
			} else {
				field += c;
				i++;
			}
		} else if (c === '"' && field === '') {
			inQuotes = true;
			i++;
		} else if (c === ',') {
			row.push(field);
			field = '';
			i++;
		} else if (c === '\n' || c === '\r') {
			if (c === '\r' && str[i + 1] === '\n') i++;
			i++;
			row.push(field);
			field = '';
			rows.push(row);
			row = [];
		} else {
			field += c;
			i++;
		}
	}
	if (field !== '' || row.length) {
		row.push(field);
		rows.push(row);
	}
	if (rows.length && rows[rows.length - 1].length === 1 && rows[rows.length - 1][0] === '') rows.pop();
	return rows;
}

export function parseBlackDuck(csvStr) {
	const rows = parseCSVtext(csvStr);
	if (!rows.length) return { totals: emptyTotals(), bugs: [] };
	const header = rows[0].map((h) => h.replace(/^\uFEFF/, '').trim());

	const idxOf = (arr, ...names) => {
		for (const nm of names) {
			const j = arr.indexOf(nm);
			if (j >= 0) return j;
		}
		for (const nm of names) {
			const j = arr.findIndex((h) => h && h.includes(nm));
			if (j >= 0) return j;
		}
		return -1;
	};

	const ci = idxOf(header, '元件');
	const vi = idxOf(header, '目前版本');
	const cv = idxOf(header, '漏洞編號');
	const sv = idxOf(header, '嚴重性');
	const cs = idxOf(header, 'CVSS');
	const fs = idxOf(header, '修復狀態');
	const cw = idxOf(header, 'CWE');
	const sh = idxOf(header, '短期建議版本');
	const lg = idxOf(header, '長期建議版本');
	const de = idxOf(header, '說明');
	const of = idxOf(header, '官方解法');
	const wb = idxOf(header, '暫時規避方式');
	const ex = idxOf(header, '已知攻擊程式');

	const bugs = [];
	const totals = emptyTotals();
	for (let r = 1; r < rows.length; r++) {
		const row = rows[r];
		const g = (j) => (j < 0 ? '' : (row[j] || '').trim());
		const sev = sevFromBD(g(sv));
		totals[sev]++;
		totals.total++;
		bugs.push({
			src: 'blackduck',
			sev,
			component: g(ci),
			version: g(vi),
			cve: g(cv),
			cvss: g(cs),
			fix: g(fs).trim().toUpperCase(),
			cwe: g(cw),
			short: g(sh),
			long: g(lg),
			desc: g(de),
			official: g(of),
			workaround: g(wb),
			exploit: g(ex),
		});
	}
	return { totals, categories: [], bugs, name: 'BlackDuck 元件弱點' };
}
