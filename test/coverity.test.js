import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

let parseCoverity;

before(async () => {
	const dom = new JSDOM('<!doctype html><html><body></body></html>');
	globalThis.window = dom.window;
	globalThis.document = dom.window.document;
	globalThis.DOMParser = dom.window.DOMParser;
	globalThis.Node = dom.window.Node;
	({ parseCoverity } = await import('../src/core/coverity.js'));
});

test('parseCoverity reads a defect row into a bug', () => {
	const html = `<html><body>
		<table class="compact"><tbody><tr><td>Memory</td><td>0</td><td>1</td><td>2</td></tr></tbody></table>
		<table id="det"><tbody>
			<tr data-sev="HIGH">
				<td>1</td><td>2</td><td>3</td>
				<td>Buffer overrun<div class="sub">OVERFLOW.BF</div><div class="sub">Memory issues</div><div class="sub">CWE-120</div></td>
				<td><span class="file">src/x.c<b>42</b></span><div class="sub">fnX</div></td>
				<td><span class="badge">High</span><div class="desc"><div>reads past the end</div></div>
					<div class="events"><ol><li class="ev"><b>start</b> at line 42</li></ol></div>
					<div class="snippet"><span class="snip-file">src/x.c</span><span class="src-line hit"><span class="ln">42</span><span class="code">memcpy(d, s, n);</span></span></div>
				</td>
			</tr>
		</tbody></table>
	</body></html>`;

	const r = parseCoverity(html);
	assert.equal(r.bugs.length, 1);
	const b = r.bugs[0];
	assert.equal(b.src, 'coverity');
	assert.equal(b.sev, 'HIGH');
	assert.ok(b.type.includes('Buffer overrun'));
	assert.equal(b.checker, 'OVERFLOW.BF');
	assert.equal(b.category, 'Memory issues');
	assert.equal(b.cwe, 'CWE-120');
	assert.equal(r.totals.HIGH, 1);
	assert.equal(r.totals.total, 1);
	assert.ok(b.file.includes('src/x.c'));
	assert.equal(b.code.length, 1);
	assert.equal(b.code[0].file, 'src/x.c');
});
