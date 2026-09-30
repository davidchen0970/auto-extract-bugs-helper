// Classify decompressed tar entries into a list of defect reports.
// Pure data - touches no UI state - so both single-file preview and the
// two-file comparison share the same classification logic.
import { detectReport, looksLikeCoverity, looksLikeBlackDuck } from './detect.js';
import { parseCoverity } from './coverity.js';
import { parseBlackDuck } from './blackduck.js';

function decode(u8) {
	try { return new TextDecoder('utf-8').decode(u8); } catch (_) { return ''; }
}

// Returns { reports, artifacts }:
//   reports:   parseable defect reports, each with
//              { type, file, size, name, bugs, totals, categories, ... }
//   artifacts: files matched as build artifacts, or files that could not be parsed
export function classifyReports(entries) {
	const cov = [], bd = [], arts = [], other = [];
	const list = entries || [];
	for (const e of list) {
		const kind = detectReport(e.name);
		if (kind === 'coverity') cov.push(e);
		else if (kind === 'blackduck') bd.push(e);
		else if (kind === 'artifact') arts.push(e);
		else if (kind === 'html' || kind === 'csv') other.push(e);
	}

	const reports = [];
	const artifacts = [];

	const pushCov = (e) => {
		const htmlStr = decode(e.data);
		if (!looksLikeCoverity(htmlStr)) return false;
		try {
			const p = parseCoverity(htmlStr);
			reports.push({ type: 'coverity', file: e.name, size: e.size, ...p });
			return true;
		} catch (_) { return false; }
	};

	const pushBd = (e) => {
		const csvStr = decode(e.data);
		if (!looksLikeBlackDuck(csvStr)) return false;
		try {
			const p = parseBlackDuck(csvStr);
			reports.push({ type: 'blackduck', file: e.name, size: e.size, ...p });
			return true;
		} catch (_) { return false; }
	};

	for (const e of cov) pushCov(e);
	for (const e of bd) pushBd(e);
	for (const e of other) {
		if (!pushCov(e) && !pushBd(e)) {
			artifacts.push({ name: e.name, size: e.size, data: e.data, type: detectReport(e.name) });
		}
	}
	for (const e of arts) artifacts.push({ name: e.name, size: e.size, data: e.data, type: 'artifact' });

	return { reports, artifacts };
}
