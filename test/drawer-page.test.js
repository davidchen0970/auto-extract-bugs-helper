import { test, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

// Regression: clicking a defect card on a page after the first one used to open
// the wrong detail, because the card's data-i was the page-local slice index
// while the click handler treated it as a global index into the filtered list.
// Only page 0 worked by luck. This test drives the full render → click → drawer
// path on page 2 and asserts the drawer shows the defect that was clicked.

let dom, renderView, state;

const BODY = `
  <main class="workbench">
    <section class="panel sources">
      <div id="source-tabs"></div>
      <div id="source-views" class="source-views"></div>
    </section>
  </main>
  <div id="drawer-overlay" class="drawer-overlay"></div>
  <section id="drawer" class="drawer" aria-hidden="true">
    <header class="drawer-head"><div id="drawer-body"></div></header>
  </section>
`;

function makeReport(n) {
  return {
    name: 'report',
    file: 'report.html',
    type: 'coverity',
    totals: { MEDIUM: n },
    bugs: Array.from({ length: n }, (_, i) => ({
      src: 'coverity',
      sev: 'MEDIUM',
      file: `src/a${i}.c`,
      line: i + 1,
      type: `BugType-${i}`,
      checker: 'UNUSED_VALUE',
      category: 'Logic error',
      cwe: '563',
      desc: `defect ${i}`,
    })),
  };
}

before(async () => {
  dom = new JSDOM(`<!doctype html><html><body>${BODY}</body></html>`);
  globalThis.window = dom.window;
  globalThis.document = dom.window.document;
  ({ renderView } = await import('../src/ui/view.js'));
  ({ state } = await import('../src/ui/state.js'));
});

beforeEach(() => {
  state.reports = [makeReport(25)];
  state.current = 0;
  state.page = 0;
  state.perPage = 10;
  state.sevFilter = 'ALL';
  document.getElementById('drawer-body').innerHTML = '';
  document.getElementById('drawer').classList.remove('open');
});

function openNthCardOnPage(index) {
  renderView(); // build cards + toolbar + empty buglist into #source-views
  const card = document.querySelectorAll('#buglist .bug')[index];
  card.dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }));
  return document.getElementById('drawer-body').innerHTML;
}

test('first page opens the matching defect', () => {
  state.page = 0; // global index == page-local index, so this worked before the fix
  const html = openNthCardOnPage(4); // 5th card is global index 4
  assert.ok(html.includes('BugType-4'), 'drawer should show BugType-4, got: ' + html);
  assert.ok(html.includes('#5'), 'coord should be #5 (global index 4)');
});

test('second page opens the matching defect (was opening first-page bugs)', () => {
  state.page = 2; // 21st..25th bugs, global index 20..24
  const html = openNthCardOnPage(0); // first card on the page = BugType-20
  assert.ok(html.includes('BugType-20'), 'drawer should show BugType-20, got: ' + html);
  assert.ok(html.includes('#21'), 'coord should be #21 (global index 20)');
});

test('last card on a later page resolves to the correct global index', () => {
  state.page = 2;
  const html = openNthCardOnPage(4); // 25th bug, global index 24
  assert.ok(html.includes('BugType-24'), 'drawer should show BugType-24, got: ' + html);
  assert.ok(html.includes('#25'), 'coord should be #25 (global index 24)');
});
