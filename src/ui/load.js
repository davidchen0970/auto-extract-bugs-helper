import { $, fmtSize } from './util.js';
import { state } from './state.js';
import { toast } from './toast.js';
import { renderArchive } from './archive.js';
import { renderTabs, renderView } from './view.js';
import { decompressGzip, parseTar, detectReport, looksLikeCoverity, looksLikeBlackDuck, parseCoverity, parseBlackDuck } from '../core/index.js';

export async function loadFile(file) {
	const size = file.size;
	const gzHint = /\.(tar\.gz|tgz|gz)$/i.test(file.name);
	$('dropzone').hidden = true;
	$('workbench').hidden = false;
	$('source-tabs').innerHTML = '<div class="empty"><span class="spinner"></span>正在解析…</div>';
	$('archive-list').innerHTML = '<div class="empty"><span class="spinner"></span>讀取 tar 內容…</div>';
	$('archive-meta').textContent = fmtSize(size);

	try {
		const raw = await file.arrayBuffer();
		let u8 = new Uint8Array(raw);
		const isGz = gzHint || (u8[0] === 0x1f && u8[1] === 0x8b);
		if (isGz) {
			toast('正在解壓縮 gzip…');
			u8 = await decompressGzip(u8);
		}
		state.raw = u8;
		const t0 = performance.now();
		const entries = parseTar(u8);
		toast(`解析完成：${entries.length} 個檔案，耗時 ${(performance.now() - t0).toFixed(0)}ms`);
		classify(entries);
	} catch (err) {
		toast('解析失敗：' + (err && err.message ? err.message : err), true);
		console.error(err);
	}
}

function classify(entries) {
	const cov = [], bd = [], arts = [], other = [];
	for (const e of entries) {
		const kind = detectReport(e.name);
		if (kind === 'coverity') cov.push(e);
		else if (kind === 'blackduck') bd.push(e);
		else if (kind === 'artifact') arts.push(e);
		else if (kind === 'html' || kind === 'csv') other.push(e);
	}

	state.entries = entries;
	state.artifacts = arts;
	state.reports = [];

	for (const e of cov) {
		let htmlStr;
		try { htmlStr = new TextDecoder('utf-8').decode(e.data); } catch (_) { htmlStr = ''; }
		if (!looksLikeCoverity(htmlStr)) continue;
		const p = parseCoverity(htmlStr);
		state.reports.push({ type: 'coverity', file: e.name, size: e.size, ...p });
	}

	for (const e of bd) {
		let csvStr;
		try { csvStr = new TextDecoder('utf-8').decode(e.data); } catch (_) { csvStr = ''; }
		if (!looksLikeBlackDuck(csvStr)) continue;
		const p = parseBlackDuck(csvStr);
		state.reports.push({ type: 'blackduck', file: e.name, size: e.size, ...p });
	}

	for (const e of other) {
		try {
			const text = new TextDecoder('utf-8').decode(e.data);
			if (looksLikeCoverity(text)) {
				const p = parseCoverity(text);
				state.reports.push({ type: 'coverity', file: e.name, size: e.size, ...p });
			} else if (looksLikeBlackDuck(text)) {
				const p = parseBlackDuck(text);
				state.reports.push({ type: 'blackduck', file: e.name, size: e.size, ...p });
			} else {
				state.artifacts.push({ name: e.name, size: e.size, data: e.data, type: kind });
			}
		} catch (_) { }
	}

	renderArchive();
	renderTabs();
	if (state.reports.length) {
		state.current = 0;
		state.page = 0;
		renderView();
	}
}
