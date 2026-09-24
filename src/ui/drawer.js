import { $ } from './util.js';
import { bugDetail } from './cards.js';

export function openDrawer(b, coord) {
	$('drawer-body').innerHTML = bugDetail(b, coord);
	$('drawer').classList.add('open');
	$('drawer').setAttribute('aria-hidden', 'false');
	$('drawer-overlay').classList.add('show');
}

export function closeDrawer() {
	$('drawer').classList.remove('open');
	$('drawer').setAttribute('aria-hidden', 'true');
	$('drawer-overlay').classList.remove('show');
}
