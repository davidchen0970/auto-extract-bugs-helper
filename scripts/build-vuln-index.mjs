import { readdir, writeFile } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../data/vuln/', import.meta.url));
const INDEX = fileURLToPath(new URL('../data/vuln/index.js', import.meta.url));

const files = [];
async function walk(dir) {
	for (const ent of await readdir(dir, { withFileTypes: true })) {
		const p = join(dir, ent.name);
		if (ent.isDirectory()) await walk(p);
		else if (ent.isFile() && ent.name.endsWith('.js')) files.push(p);
	}
}

const toSlash = (p) => p.split(sep).join('/');

await walk(root);

const map = new Map();
const seen = new Set();
for (const f of files) {
	const mod = await import(pathToFileURL(f).href);
	for (const e of (Array.isArray(mod.default) ? mod.default : [])) {
		if (!e || !e.key) continue;
		if (seen.has(e.key)) {
			console.error('[warn] duplicate key in vuln index:', e.key, '->', toSlash(relative(root, f)));
		}
		seen.add(e.key);
		map.set(e.key, toSlash(relative(root, f)));
	}
}

const keys = [...map.keys()].sort();
const body = keys.map((k) => `\t${JSON.stringify(k)}: ${JSON.stringify(map.get(k))},`).join('\n');
const out = '// AI 弱點手冊 index — 「CVE編號@套件」組合金鑰 → 分類檔相對路徑（供 lazy import）\n'
	+ '// 此檔由 scripts/build-vuln-index.mjs 自動產生，請勿手動編輯。\n'
	+ 'export default {\n' + body + '\n};\n';

await writeFile(INDEX, out, 'utf8');
console.log('OK: 產生 data/vuln/index.js，共', keys.length, '筆');
