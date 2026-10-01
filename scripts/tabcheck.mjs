import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from '@babel/parser';

// Indentation convention guard for first-party JavaScript (src/core, src/ui): code
// indentation uses tabs, not spaces. The single sanctioned exception is the text (quasis)
// inside a template literal, where the codebase indents HTML markup with spaces — so a
// line whose indentation belongs to template content is allowed to use spaces.
//
// We classify template content from the AST (@babel/parser) rather than a hand-rolled
// lexer so comments, string literals, regex literals and backslash escaping are handled by
// a real parser — a backtick in a comment or a string can never fake-open a template.
//
// Out of scope on purpose: vendored code (src/vendor/), data modules (data/),
// tests, and this tool itself.

const DEFAULT_ROOT = 'src';
const EXCLUDE = [/(^|[\\/])vendor[\\/]/];

function isFirstParty(rel) {
	return rel.endsWith('.js') && !EXCLUDE.some((re) => re.test(rel));
}

function walk(dir, base, out) {
	let entries;
	try {
		entries = fs.readdirSync(dir, { withFileTypes: true });
	} catch {
		return out; // missing/unreadable directory: nothing to walk
	}
	for (const entry of entries) {
		const abs = path.join(dir, entry.name);
		const rel = path.relative(base, abs);
		if (entry.isDirectory() && entry.name !== 'node_modules') walk(abs, base, out);
		else if (entry.isFile() && isFirstParty(rel)) out.push(abs);
	}
	return out;
}

// All template-text (quasi) source ranges as [start, end) byte offsets, from the AST.
function quasiRanges(source) {
	let ast;
	try {
		ast = parse(source, { sourceType: 'module' });
	} catch (err) {
		const msg = err && err.message ? err.message : String(err);
		throw new Error(`unparseable source (${msg})`);
	}
	const ranges = [];
	const visit = (node) => {
		if (!node || typeof node.type !== 'string') return;
		if (node.type === 'TemplateElement') ranges.push([node.start, node.end]);
		for (const key of Object.keys(node)) {
			const v = node[key];
			if (Array.isArray(v)) v.forEach(visit);
			else if (v && typeof v.type === 'string') visit(v);
		}
	};
	visit(ast);
	return ranges.sort((a, b) => a[0] - b[0]);
}

// Returns a predicate: is byte offset `off` inside any [start, end) template-text range?
function makeInTemplate(ranges) {
	return (off) => {
		let lo = 0, hi = ranges.length - 1;
		while (lo <= hi) {
			const mid = (lo + hi) >> 1;
			const [s, e] = ranges[mid];
			if (off < s) hi = mid - 1;
			else if (off >= e) lo = mid + 1;
			else return true;
		}
		return false;
	};
}

// Indentation violations for one source string: [{ line, text }]. A line whose very start
// lies inside template text (a quasi) is template content — quasis carry the leading
// whitespace before `${ ... }` as well — so it is exempt from the tab rule.
export function indentationViolations(source) {
	const inTemplate = makeInTemplate(quasiRanges(source));
	const lines = source.split('\n');
	const out = [];
	let base = 0;
	for (let i = 0; i < lines.length; i++) {
		const line = lines[i];
		if (!line.trim()) { base += line.length + 1; continue; }
		if (inTemplate(base)) { base += line.length + 1; continue; }
		if (/^ +\S/.test(line)) out.push({ line: i + 1, text: line.trim().slice(0, 64) });
		base += line.length + 1;
	}
	return out;
}

// Scan a directory tree (excluding vendor/) and report violations per file.
export function tabcheckDir(root) {
	const files = walk(root, root, []);
	const violations = [];
	const unparsable = [];
	let scanned = 0;
	for (const file of files) {
		let source;
		try { source = fs.readFileSync(file, 'utf8'); } catch { continue; }
		let fileViolations;
		try { fileViolations = indentationViolations(source); }
		catch (err) { unparsable.push([file, err.message]); continue; }
		scanned++;
		for (const v of fileViolations) violations.push({ file, ...v });
	}
	return { scanned, violations, unparsable, files };
}

// Allow running directly: `node scripts/tabcheck.mjs [root]`
export const isMain = process.argv[1] != null
	&& path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
	const { scanned, violations, unparsable } = tabcheckDir(process.argv[2] || DEFAULT_ROOT);
	let bad = false;
	for (const [file, msg] of unparsable) {
		console.error(`tabcheck: ${file}: ${msg}`);
		bad = true;
	}
	for (const v of violations) {
		console.log(`${v.file}:${v.line}: JavaScript indented with spaces (use tabs): ${v.text}`);
		bad = true;
	}
	if (bad) {
		if (violations.length) console.log(`\n${violations.length} indentation violation(s): first-party JS must indent with tabs.`);
		process.exit(1);
	}
	console.log(`OK: ${scanned} first-party source file(s) use tab indentation.`);
}
