import { $ } from './util.js';
import { bugDetail } from './cards.js';

let activeBug = null;

export function openDrawer(b, coord) {
	activeBug = b;
	$('drawer-body').innerHTML = bugDetail(b, coord);
	$('drawer-title').textContent = '缺陷詳情';
	$('drawer-copy').hidden = false;
	$('drawer-download').hidden = false;
	$('drawer').classList.add('open');
	$('drawer').setAttribute('aria-hidden', 'false');
	$('drawer-overlay').classList.add('show');
}

export function currentBug() {
	return activeBug;
}

export function closeDrawer() {
	$('drawer').classList.remove('open');
	$('drawer').setAttribute('aria-hidden', 'true');
	$('drawer-overlay').classList.remove('show');
}
