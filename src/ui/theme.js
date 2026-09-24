import { $ } from './util.js';

export function toggleTheme() {
	const root = document.documentElement;
	if (root.dataset.theme === 'dark') delete root.dataset.theme;
	else root.dataset.theme = 'dark';
}

export function focusSearch() {
	const el = $('q');
	if (el) { el.focus(); el.select(); }
}
