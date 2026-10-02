// Custom / generic defect-source parser ("自定義缺陷來源").
//
// Background: some SCA products export their vulnerability CSV with English column
// names (Black Duck SCA is the canonical example: Component name, Vulnerability id,
// Security Risk, Overall score, CWE Ids, …). The built-in blackduck parser only
// recognises the Chinese header names it was written against, so those English exports
// silently come out with every field empty and every severity collapsed to LOW.
//
// This parser is column-driven: it keeps the FULL row under `fields` (every original
// column name -> value, in header order) so nothing is ever dropped, and it also
// promotes the semantically meaningful columns to top-level `bug.*` so the existing
// cards / search / export / comparison all work out of the box.

import { SEV, emptyTotals, sevFromBD } from './schema.js';
import { parseCSVtext } from './blackduck.js';

// A stable identity token from a "Vulnerability id" cell, which can look like
// "CVE-2026-49356", "BDSA-2024-4090", "CVE-2020-15366 (BDSA-2020-3798)"
// or "CVE-2020-15366 (BDSA-2020-3798)". Prefer the leading CVE, else the
// BDSA id — enough for the CVE link and the comparison key.
export function cleanVulnId(id) {
	const s = String(id || '').trim();
	const cve = /(CVE-\d{4}-\d{4,})/i.exec(s);
	if (cve) return cve[1].toUpperCase();
	const bdsa = /(BDSA-\d{4}-\d+)/i.exec(s);
	if (bdsa) return bdsa[1].toUpperCase();
	return s;
}

// CWE cells look like "[CWE-22, CWE-200]" or "[]" or "CWE-400".
export function normalizeCwe(cw) {
	const cleaned = (String(cw || '').trim().match(/CWE-\d+/gi) || []).map((c) => c.toUpperCase());
	return Array.from(new Set(cleaned));
}

function sevFromScore(score) {
	const n = parseFloat(score);
	if (!isFinite(n)) return null;
	if (n >= 9.0) return SEV.CRITICAL;
	if (n >= 7.0) return SEV.HIGH;
	if (n >= 4.0) return SEV.MEDIUM;
	if (n > 0) return SEV.LOW;
	return null;
}

export function looksLikeCustomCSV(csvStr) {
	const head = String(csvStr || '').slice(0, 8000);
	return /Component name/i.test(head) &&
		/Vulnerability id/i.test(head) &&
		(/Security Risk/i.test(head) || /Overall score/i.test(head));
}

export function parseCustomCSV(csvStr) {
	const rows = parseCSVtext(csvStr);
	if (!rows.length) return { totals: emptyTotals(), bugs: [], name: '自定義缺陷來源' };
	const header = rows[0].map((h) => String(h || '').replace(/^\uFEFF/, '').trim());

	// Case-insensitive header lookup so the same exporter / column reordering stays fine.
	const idxOf = (names) => {
		for (const nm of names) {
			const j = header.findIndex((h) => h && h.toLowerCase() === nm.toLowerCase());
			if (j >= 0) return j;
		}
		for (const nm of names) {
			const j = header.findIndex((h) => h && h.toLowerCase().includes(nm.toLowerCase()));
			if (j >= 0) return j;
		}
		return -1;
	};

	const ci = idxOf(['Component name']);
	const vi = idxOf(['Component version name']);
	const on = idxOf(['Component origin name']);
	const cv = idxOf(['Vulnerability id', 'Vulnerability']);
	const de = idxOf(['Description']);
	const pb = idxOf(['Published on', 'Published date']);
	const up = idxOf(['Updated on', 'Updated date']);
	const bs = idxOf(['Base score']);
	const ov = idxOf(['Overall score']);
	const exe = idxOf(['Exploitability']);
	const imp = idxOf(['Impact']);
	const vas = idxOf(['Vulnerability source', 'Source']);
	const fs = idxOf(['Remediation status', 'Vulnerability status']);
	const sj = idxOf(['Status justification']);
	const td = idxOf(['Remediation target date', 'Target date']);
	const ad = idxOf(['Remediation actual date', 'Actual date']);
	const rc = idxOf(['Remediation comment']);
	const ur = idxOf(['URL']);
	const sr = idxOf(['Security Risk', 'Severity']);
	const pp = idxOf(['Project path', 'Project']);
	const cw = idxOf(['CWE Ids', 'CWE']);
	const so = idxOf(['Solution available']);
	const wb = idxOf(['Workaround available']);
	const eav = idxOf(['Exploit available']);
	const csv = idxOf(['CVSS Version']);
	const mt = idxOf(['Match type']);
	const rch = idxOf(['Reachable']);
	const tg = idxOf(['Vulnerability tags', 'Tags']);
	const cisa = {
		id: idxOf(['CISA Vulnerability ID']),
		exploit: idxOf(['CISA Exploit Added']),
		due: idxOf(['CISA Due Date']),
		action: idxOf(['CISA Required Action']),
		name: idxOf(['CISA Vulnerability Name']),
	};

	const bugs = [];
	const totals = emptyTotals();
	for (let r = 1; r < rows.length; r++) {
		const row = rows[r];
		const g = (j) => (j < 0 ? '' : (row[j] == null ? '' : String(row[j]).trim()));

		// Full fidelity: keep every original column (header order preserved).
		const fields = {};
		for (let c = 0; c < header.length; c++) {
			if (header[c]) fields[header[c]] = g(c);
		}

		const rawCve = g(cv);
		const cweList = normalizeCwe(g(cw));
		const scoreVal = g(ov) || g(bs);
		const secRiskRaw = g(sr);

		let sev = sevFromBD(secRiskRaw);
		if (secRiskRaw === '') sev = sevFromScore(scoreVal) || SEV.INFO;

		bugs.push({
			src: 'custom',
			aiResearch: '',
			sev,
			component: g(ci),
			version: g(vi),
			originName: g(on),
			cve: rawCve,
			cveClean: cleanVulnId(rawCve),
			desc: g(de),
			published: g(pb),
			updated: g(up),
			baseScore: g(bs),
			score: g(ov),
			cvss: scoreVal,
			exploitability: g(exe),
			impact: g(imp),
			vulnSource: g(vas),
			fix: g(fs).toUpperCase(),
			justification: g(sj),
			targetDate: g(td),
			actualDate: g(ad),
			comment: g(rc),
			url: g(ur),
			securityRisk: secRiskRaw,
			project: g(pp),
			cwe: cweList.join(', '),
			cweList,
			solution: g(so),
			workaround: g(wb),
			exploit: g(eav),
			cvssVersion: g(csv),
			match: g(mt),
			reachable: g(rch),
			tags: g(tg),
			cisa: {
				id: g(cisa.id),
				exploitAdded: g(cisa.exploit),
				dueDate: g(cisa.due),
				requiredAction: g(cisa.action),
				name: g(cisa.name),
			},
			fields,
		});

		totals[sev]++;
		totals.total++;
	}
	return { totals, categories: [], bugs, name: '自定義缺陷來源（Black Duck SCA 匯出）' };
}
