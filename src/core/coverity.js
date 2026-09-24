import { mapSev, emptyTotals } from './schema.js';

function stripHtml(str) {
	const d = document.createElement('div');
	d.innerHTML = str || '';
	return d.textContent.replace(/\s+/g, ' ').trim();
}

export function parseCoverity(htmlStr) {
	const doc = new DOMParser().parseFromString(htmlStr, 'text/html');
	const totals = { total: 0, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
	const categories = [];

	doc.querySelectorAll('table.compact tbody tr').forEach((tr) => {
		const tds = tr.querySelectorAll('td');
		if (tds.length < 4) return;
		categories.push({
			name: stripHtml((tds[0] || {}).textContent),
			HIGH: parseInt(tds[1].textContent, 10) || 0,
			MEDIUM: parseInt(tds[2].textContent, 10) || 0,
			LOW: parseInt(tds[3].textContent, 10) || 0,
		});
	});

	const bugs = [];
	const rows = doc.querySelectorAll('table#det tbody tr');
	rows.forEach((tr) => {
		try {
			const sev = (tr.getAttribute('data-sev') || 'LOW').toUpperCase();
			const tds = tr.querySelectorAll('td');
			if (tds.length < 6) return;

			const keyBox = tr.querySelector('.chk-done');
			const keyParts = (keyBox ? keyBox.getAttribute('data-k') || '' : '').split('|');

			const badge = tr.querySelector('.badge');
			const sevStr = badge ? badge.textContent.trim() : sev;
			const effSev = mapSev(sevStr) || mapSev(sev);
			if (effSev) {
				totals[effSev]++;
				totals.total++;
			}

			const typeTd = tds[3];
			const typeText = typeTd.childNodes
				? [...typeTd.childNodes]
					.filter((n) => n.nodeType === Node.TEXT_NODE)
					.map((n) => n.textContent)
					.join(' ')
					.trim()
				: stripHtml(typeTd.textContent).replace(/\s+/g, ' ').trim();
			const subs = [...typeTd.querySelectorAll('.sub')].map((s) => s.textContent.trim());
			const checker = (subs[0] || '').trim();
			const category = (subs[1] || '').trim();
			const cwe = (subs[2] || '').replace(/\s+/g, '').trim();

			const locTd = tds[4];
			const file = locTd.querySelector('.file') ? stripHtml(locTd.querySelector('.file').innerHTML) : '';
			const line = (locTd.querySelector('.file b') || {}).textContent || '';
			const fileOnly =
				file.replace(':' + line.replace(/^<b>|<\/b>$/g, ''), '') ||
				stripHtml(locTd.innerHTML).split('\n')[0].replace(/:\d+$/, '');
			const fn = (locTd.querySelector('.sub') || {}).textContent || '';

			const descTd = tds[5];
			const descDiv = descTd.querySelector('.desc');
			const descEl = descDiv ? descDiv.firstElementChild : null;
			const desc = descEl ? stripHtml(descEl.textContent) : descDiv ? stripHtml(descDiv.textContent).split('\n')[0] : '';

			const events = [];
			descTd.querySelectorAll('.events .ev').forEach((li) => {
				events.push({
					tag: (li.querySelector('b') || {}).textContent || '',
					text: li.textContent.replace(/^\d+\s*\.?\s*/, '').trim(),
				});
			});

			const code = [];
			descTd.querySelectorAll('.snippet').forEach((snip) => {
				const fileEl = snip.querySelector('.snip-file');
				const file = fileEl ? stripHtml(fileEl.textContent) : '';
				const items = [];
				[...snip.children].forEach((el) => {
					const cls = String(el.className || '');
					if (cls.split(/\s+/).indexOf('src-line') >= 0) {
						const lnEl = el.querySelector('.ln');
						const codeEl = el.querySelector('.code');
						items.push({
							k: 'line',
							n: lnEl ? lnEl.textContent.trim() : '',
							text: codeEl ? codeEl.textContent.replace(/\s+$/g, '') : '',
							hit: cls.split(/\s+/).indexOf('hit') >= 0,
							ev: cls.split(/\s+/).indexOf('ev-line') >= 0,
						});
					} else if (cls.split(/\s+/).indexOf('src-event') >= 0) {
						items.push({
							k: 'ev',
							text: el.textContent.replace(/\s+/g, ' ').trim(),
						});
					}
				});
				if (items.length) code.push({ file, items });
			});

			const clean = (s) => String(s || '').replace(/<.*?>/g, '').trim();
			bugs.push({
				src: 'coverity',
				sev: effSev,
				type: clean(typeText),
				checker: clean(checker),
				category: clean(category),
				cwe: clean(cwe),
				file: clean(fileOnly) || clean(file),
				line,
				fn: clean(fn),
				desc: clean(desc),
				events,
				code,
				key: keyParts.slice(0, 4).join(' | '),
			});
		} catch (e) {
		}
	});

	return { totals, categories, bugs, name: 'Coverity 靜態分析' };
}
