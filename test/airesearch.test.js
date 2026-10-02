import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

let covBody, bdBody, bdHead, customBody, parseBlackDuck;
let lookupVuln;

// Body renderers pull in renderMd -> marked + DOMPurify, which need a window.
before(async () => {
	globalThis.window = new JSDOM('<!doctype html><html><body></body></html>').window;
	({ covBody, bdBody, bdHead, customBody } = await import('../src/ui/cards.js'));
	({ parseBlackDuck } = await import('../src/core/blackduck.js'));
	({ vulnLookup: lookupVuln } = await import('../src/ui/vuln.js'));
});

// ---- Real fixtures lifted from spx-826732-19.tar.gz -----------------------
// cov_output/spx-bmc-826732_spx-826732-19_coverity_guidance.html: the heaviest
// defect (ARRAY_VS_SINGLETON in ErrorHandleTask.c RasThread()). The aiResearch
// text is the "AI 研究結果" content that the new field is meant to carry.
const coverityDefect = {
	src: 'coverity',
	aiResearch: '`RasThread()` 在迴圈巡迴 `pRas->CPUCount` 時，把 `&iSeverity` 依 **`callee_ptr_arith`** ' +
		'當作單一物件傳入，離開緩衝區之後仍被索引，造成越界存取（CWE-119）。' +
		'研究建議：在 `wRet >= 1` 的分支先核對 `iSeverity` 是否仍在陣列長度內，並為 ' +
		'`iNeedRecovery` 分支補上邊界檢查。參考 [Coverity checker: ARRAY_VS_SINGLETON]' +
		'(https://scan.coverity.com) 的修補社群提交。',
	sev: 'HIGH',
	type: 'Out-of-bounds access',
	checker: 'ARRAY_VS_SINGLETON',
	category: 'Memory - corruptions',
	cwe: 'CWE-119',
	file: 'workspace/826732/Build/.build/AMDerrorhandle-13.23.0.0.0-src/data/ErrorHandleTask.c',
	line: '1008',
	fn: 'RasThread',
	desc: 'Access of memory past the end of a memory buffer',
	events: [
		{ tag: 'path', text: 'Condition "cpuNum < pRas->CPUCount", taking true branch.' },
		{ tag: 'address_of', text: 'Taking address with "&iSeverity" yields a singleton pointer.' },
		{ tag: 'callee_ptr_arith', text: 'Passing "&iSeverity" to function ...' },
	],
	code: [],
};

// bd_output/spx-bmc-826732_spx-826732-19_guidance_details.csv: CVE-2021-3773
// (Linux netfilter -> openvpn endpoint leak, CWE-200). Verified real row.
const blackduckBug = {
	src: 'blackduck',
	aiResearch: 'CVE-2021-3773 屬 Linux **netfilter** 缺陷，同網段攻擊者可藉其側寫 ' +
		'`openvpn` 連線端點資訊（CWE-200）。官方於 5.x 修復，' +
		'研究可先以防火牆規則攔掉非預期來源封包作為臨時緩解。詳見 ' +
		'[NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-3773)。',
	sev: 'CRITICAL',
	component: 'Linux Kernel',
	version: 'v5.4.278',
	cve: 'CVE-2021-3773',
	cvss: '9.8',
	cwe: 'CWE-200',
	fix: 'IGNORED',
	official: '',
	workaround: '',
	exploit: '',
	desc: 'A flaw in netfilter could allow a network-connected attacker to infer openvpn connection endpoint information for further use in traditional network attacks.',
};

// bd CSV also carries Black Duck SCA rows (BDSA-*) that map to the custom
// source (lodash prototype pollution). The custom body only surfaces aiResearch
// on the "CWE 說明" card, so it needs a cwes entry to appear.
const customBug = {
	src: 'custom',
	aiResearch: 'Lodash < 4.17.12 的 `defaultsDeep`/`set` 可被**原型污染**（CWE-20 / CWE-94），' +
		'經由 `__proto__` 覆寫物件屬性、有 RCE 風險。升級至 ' +
		'[4.17.12](https://github.com/lodash/lodash/releases/tag/4.17.12-npm) 即修復。',
	sev: 'HIGH',
	component: 'Lodash',
	version: '1.3.0',
	cve: 'BDSA-2019-2112',
	cveClean: 'BDSA-2019-2112',
	cvss: '8.8',
	cwe: 'CWE-20',
	cweList: ['CWE-20'],
	fix: 'PATCHED',
	desc: 'Lodash contains a prototype pollution flaw.',
	fields: {},
};

// Real header row of guidance_details.csv (with BOM) + one real data row.
const dataAttrCWE200 = 'data-cwe="CWE-200"';
const bdCsvRow = '\uFEFF元件,目前版本,漏洞編號,嚴重性,CVSS,修復狀態,CWE,短期建議版本,長期建議版本,說明,官方解法,暫時規避方式,已知攻擊程式\n'
	+ 'Linux Kernel,v5.4.278,CVE-2021-3773,CRITICAL,9.8,IGNORED,CWE-200,5.x,20260916,'
	+ 'A flaw in netfilter could allow a network-connected attacker to infer openvpn connection endpoint information.,,,\n';

test('covBody renders the "AI 研究結果" row as markdown when aiResearch is present', () => {
	const out = covBody(coverityDefect);
	assert.ok(out.includes('<dt>AI 研究結果</dt>'), 'covBody should show the AI research row');
	// markdown bold + link survived.
	assert.ok(out.includes('<strong>'), 'aiResearch bold markdown should be rendered');
	assert.ok(out.includes('href="https://scan.coverity.com"'), 'aiResearch markdown link should be rendered');
});

test('covBody omits the AI row when aiResearch is empty or missing', () => {
	for (const bug of [{ ...coverityDefect, aiResearch: '' }, { ...coverityDefect, aiResearch: undefined }, { ...coverityDefect, aiResearch: null }]) {
		const out = covBody(bug);
		assert.ok(!out.includes('AI 研究結果'), 'row must be absent when aiResearch is not a string');
	}
});

test('covBody sanitizes script injection inside aiResearch', () => {
	const bug = { ...coverityDefect, aiResearch: '<script>alert(1)</script> safe text' };
	const out = covBody(bug);
	// Both the tag and its payload must be stripped by renderMd's DOMPurify pass.
	assert.ok(!/<[^>]*script/i.test(out), 'script tag must not survive');
	assert.ok(!out.toLowerCase().includes('alert(1)'), 'script payload text must not survive');
	assert.ok(out.includes('safe text'), 'inert text next to the payload is still rendered');
});

test('AI 研究結果 renders block markdown (heading, list, code) from aiResearch', () => {
	const md = '## 風險\n\n- **根因**：越界寫 (CWE-787)\n- 建議：升級至已修復版本\n\n`pkg func()`';
	const out = covBody({ ...coverityDefect, aiResearch: md });
	assert.ok(/<h[23]>/.test(out) && out.includes('風險'), 'heading renders');
	assert.ok(out.includes('<ul>') && out.includes('<li>'), 'bullet list renders');
	assert.ok(/<code>/.test(out) && out.includes('pkg func()'), 'inline code renders');
});

test('bdBody renders the AI research row and its markdown link', () => {
	const out = bdBody(blackduckBug);
	assert.ok(out.includes('<dt>AI 研究結果</dt>'), 'bdBody should show the AI research row');
	assert.ok(out.includes('<strong>netfilter</strong>'), 'aiResearch bold markdown is rendered');
	assert.ok(out.includes('href="https://nvd.nist.gov/vuln/detail/CVE-2021-3773"'), 'aiResearch NVD link is rendered');
});

test('bdBody leaves the AI row hidden until a handbook entry supplies the explanation', () => {
	const out = bdBody({ ...blackduckBug, aiResearch: '' });
	assert.ok(out.includes('AI 研究結果'), 'the row slot exists for a CVSS+package defect');
	assert.ok(out.includes('data-key="CVE-2021-3773@linux-kernel"'), 'stamps the slugified CVE@pkg composite key');
	const dt = /<dt class="ai-research-row" hidden>/.exec(out);
	const dd = /<dd class="ai-research" data-key="CVE-2021-3773@linux-kernel" hidden>/.exec(out);
	assert.ok(dt && dd, 'the empty cell row starts hidden (有內容才顯示)');
});

test('customBody renders the AI row on the CWE card when it has a cwes entry', () => {
	const out = customBody(customBug);
	assert.ok(out.includes('<dt>AI 研究結果</dt>'), 'customBody should show the AI research row');
	assert.ok(out.includes('<code>defaultsDeep</code>'), 'aiResearch inline code markdown is rendered');
	assert.ok(out.includes('href="https://github.com/lodash/lodash/releases/tag/4.17.12-npm"'), 'aiResearch markdown link is rendered');
});

test('parsers seed every bug with an empty aiResearch field', async () => {
	const { bugs } = parseBlackDuck(bdCsvRow);
	assert.ok(bugs.length >= 1, 'real BlackDuck row should parse into at least one bug');
	for (const b of bugs) {
		assert.ok(Object.prototype.hasOwnProperty.call(b, 'aiResearch'), 'bug should carry aiResearch');
		assert.equal(b.aiResearch, '', 'aiResearch starts empty (filled by research later)');
	}
});

// Dedicated case for the real CVE-2021-3773 entry lifted from
// spx-826732-19.tar.gz bd_output/..._guidance_details.csv — the exact row the
// product shows as: Critical / CVE-2021-3773 / Linux Kernel v5.4.278 / CVSS 9.8
test('bdCard for the real CVE-2021-3773 entry renders head + AI research row', () => {
	const bd = {
		src: 'blackduck',
		aiResearch: 'CVE-2021-3773 屬 Linux **netfilter** 缺陷，同網段攻擊者可藉其側寫 `openvpn` 連線端點資訊（CWE-200）。官方於 5.x 修復，研究可先以防火牆規則攔掉非預期來源封包作為臨時緩解。',
		sev: 'CRITICAL',
		component: 'Linux Kernel',
		version: 'v5.4.278',
		cve: 'CVE-2021-3773',
		cvss: '9.8',
		cwe: 'CWE-200',
		fix: 'IGNORED',
		short: '5.x',
		long: '20260916',
		exploit: 'N/A',
		official: '',
		workaround: '',
		desc: 'A flaw in netfilter could allow a network-connected attacker to infer openvpn connection endpoint information for further use in traditional network attacks.',
	};

	const head = bdHead(bd, 0);
	assert.ok(head.includes('>Critical<'), 'severity badge for the row');
	assert.ok(head.includes('href="https://nvd.nist.gov/vuln/detail/CVE-2021-3773"'), 'CVE links to NVD');
	assert.ok(head.includes('>Linux Kernel v5.4.278</span>'), 'component + version pill');
	assert.ok(head.includes('>CVSS 9.8</span>'), 'CVSS pill');
	assert.ok(head.includes('href="https://cwe.mitre.org/data/definitions/200.html"'), 'CWE links to MITRE');
	assert.ok(head.includes('pill ignore'), 'IGNORED renders the 已忽略 pill');
	assert.ok(head.includes('>已忽略</span>'), 'fix text is 已忽略');

	const body = bdBody(bd);
	assert.ok(body.includes('<dt>AI 研究結果</dt>'), 'the entry carries the AI research row');
	assert.ok(body.includes('<strong>netfilter</strong>'), 'aiResearch bold markdown is rendered');
	assert.ok(body.includes('<code>openvpn</code>'), 'aiResearch inline-code markdown is rendered');
	assert.ok(body.includes(dataAttrCWE200), 'body records the CWE id for handbook hydration');
});

// The defect detail looks up the「CVE@pkg」key in the vulnerability handbook; the package
// name on the bug ("Linux Kernel") is slugified to match the handbook key (linux-kernel).
test('vulnLookup resolves the slugified composite key for the CVE-2021-3773 handbook entry', async () => {
	const hit = await lookupVuln('CVE-2021-3773@linux-kernel');
	assert.ok(hit, 'handbook holds the entry for the SCA row');
	assert.equal(hit.cve, 'CVE-2021-3773');
	assert.equal(hit.pkg, 'linux-kernel');
	assert.ok(/netfilter/.test(hit.what), 'entry carries the netfilter explanation');
	assert.ok(!(await lookupVuln('CVE-2021-3773@no-such-package')), 'unknown composite key resolves to null');
});
