import { $, fmtSize } from './util.js';
import { state } from './state.js';
import { toast } from './toast.js';
import { renderArchive } from './archive.js';
import { renderTabs, renderView } from './view.js';
import { ingestFile, classifyReports } from '../core/index.js';

export async function loadFile(file) {
	const size = file.size;
	$('dropzone').hidden = true;
	$('workbench').hidden = false;
	$('source-tabs').innerHTML = '<div class="empty"><span class="spinner"></span>正在解析…</div>';
	$('archive-list').innerHTML = '<div class="empty"><span class="spinner"></span>讀取內容…</div>';
	$('archive-meta').textContent = fmtSize(size);

	try {
		const t0 = performance.now();
		const entries = await ingestFile(file);
		toast(`已讀取：${file.name}，耗時 ${(performance.now() - t0).toFixed(0)}ms`);
		classify(entries);
	} catch (err) {
		toast('解析失敗：' + (err && err.message ? err.message : err), true);
		console.error(err);
	}
}

function classify(entries) {
	const { reports, artifacts } = classifyReports(entries);

	state.entries = entries;
	state.artifacts = artifacts;
	state.reports = reports;

	renderArchive();
	renderTabs();
	if (state.reports.length) {
		state.current = 0;
		state.page = 0;
		renderView();
	}
}
