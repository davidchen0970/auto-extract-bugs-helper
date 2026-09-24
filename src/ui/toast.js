import { $ } from './util.js';

export function toast(msg, isErr = false) {
	const t = $('toast');
	t.textContent = msg;
	t.className = 'toast' + (isErr ? ' err' : '');
	t.hidden = false;
	clearTimeout(t._tm);
	t._tm = setTimeout(() => (t.hidden = true), isErr ? 5200 : 2600);
}
