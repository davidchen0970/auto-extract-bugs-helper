import { marked } from '../vendor/marked.esm.js';
import DOMPurify from '../vendor/purify.es.js';

// Render report text (untrusted) as markdown, then sanitize before injection.
export function renderMd(src) {
	const html = marked.parse(String(src == null ? '' : src));
	return DOMPurify.sanitize(html, { USE_PROFILES: { html: true } });
}
