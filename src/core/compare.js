// Defect comparison: pick an identity credential by report type, then split
// defects into added / removed / content-changed.

const SEP = '\u0001';

// Pick an identity key for a defect based on report type (two sides share a key
// when they are "the same" defect).
//   - BlackDuck uses the CVE id (stable for the same vulnerability across versions).
//   - Coverity uses file + line + type + checker (exact line, file + checker).
export function bugKey(b) {
	if (!b) return '';
	if (b.src === 'blackduck') {
		return 'bd:' + String(b.cve || '').trim();
	}
	const part = (v) => String(v == null ? '' : v).trim();
	return 'cov:' + [part(b.file), part(b.line), part(b.type), part(b.checker)].join(SEP);
}

// The set of fields skipped from a fingerprint. For Coverity these hold large
// execution-path / highlighted-source blocks (line-by-line) that are expensive to
// serialize for every bug during a diff and rarely add meaning. Identity already
// pins file/line/type/checker, so a moved bug is still reflected in the key.
const COVERITY_HEAVY_FIELDS = new Set(['code', 'events']);

// Content fingerprint: equal identity but different fingerprint means the defect
// changed between the two sides (a "changed" defect).
//
// Built from a shallow copy that excludes the heavy arrays above so fingerprinting
// stays cheap in memory and time even for hundreds of defects.
export function bugFingerprint(b) {
	if (!b || typeof b !== 'object') return String(b);
	return JSON.stringify(heavyReduced(b));
}

function heavyReduced(b) {
	const out = {};
	for (const k of Object.keys(b)) {
		if (COVERITY_HEAVY_FIELDS.has(k)) continue;
		out[k] = b[k];
	}
	return out;
}

// Diff two defect lists and return the buckets:
//   - removed: only present in A (baseline) - disappeared / fixed
//   - added:   only present in B          - new
//   - changed: present on both sides but content changed (before / after)
//   - same:    present on both sides, identical content
export function compareBugs(aList, bList) {
	const A = (aList || []).slice();
	const B = (bList || []).slice();

	const mapA = new Map();
	const mapB = new Map();
	A.forEach((b) => mapA.set(bugKey(b), b));
	B.forEach((b) => mapB.set(bugKey(b), b));

	const removed = [];
	const added = [];
	const changed = [];
	const same = [];

	for (const [k, ba] of mapA) {
		if (!mapB.has(k)) removed.push(ba);
	}
	for (const [k, bb] of mapB) {
		const ba = mapA.get(k);
		if (!ba) {
			added.push(bb);
		} else if (bugFingerprint(ba) !== bugFingerprint(bb)) {
			changed.push({ key: k, before: ba, after: bb });
		} else {
			same.push(bb);
		}
	}

	return { added, removed, changed, same };
}
