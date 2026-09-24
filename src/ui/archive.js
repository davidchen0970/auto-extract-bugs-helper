import { $, esc, fmtSize } from './util.js';
import { state } from './state.js';

function roleLabel(r) {
	if (r.type === 'coverity') return 'Coverity 缺陷報表';
	if (r.type === 'blackduck') return 'BlackDuck 弱點清單';
	if (r.type === 'artifact') return '建置產物';
	return '其他檔案';
}

export function renderArchive() {
	const listEl = $('archive-list');
	const reportedFiles = new Set(state.reports.map((r) => r.file));
	const items = [...state.reports.map((r) => ({ name: r.file, type: r.type }))];
	const extra = state.artifacts.filter((a) => !reportedFiles.has(a.name));

	const all = [
		...items,
		...extra.map((a) => ({ name: a.name, type: a.type, size: a.size })),
	];
	if (all.length === 0) {
		listEl.innerHTML = '<div class="empty">此 tar 內沒有可解析的報表。支援 Coverity HTML 與 BlackDuck CSV。</div>';
		$('archive-meta').textContent = state.entries.length + ' 個檔案';
		return;
	}
	listEl.innerHTML = all.map((it) => `
    <div class="ar-item">
      <div class="ar-head">
        <span class="ar-name" title="${esc(it.name)}">${esc(it.name)}</span>
      </div>
      <div class="ar-tags"><span class="tagchip role">${roleLabel(it)}</span></div>
      <span class="ar-size">${fmtSize(it.size)}</span>
    </div>`).join('');
	$('archive-meta').textContent = state.entries.length + ' 個檔案';
}
