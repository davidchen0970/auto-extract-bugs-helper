// PILOT CWE chunk — category: Improper Input Validation (web / input variants).
// One chunk = one category, <= 5 entries. Every entry:
//   what    : 簡短、繁中、白話+技術描述（(#) 弱點是什麼)
//   problem : 「壞的寫法」程式片段（(#) 問題長怎樣)
//   fixed   : 「修好的寫法」程式片段（(#) 解完會長怎樣)
//   patch   : problem → fixed 的統一 diff 文字（(#) 範例 patch)
//   lang    : 此條範例主力語言，依 CWE 類別選擇
//   status  : Complete | Incomplete | Deprecated
//   refs    : 參考（OWASP / MITRE 等）
//   tags    : 英文搜尋標籤
export default [
	{
		id: 'CWE-79',
		name: 'Cross-site Scripting (XSS)',
		lang: 'javascript',
		status: 'Complete',
		what: `跨站腳本（XSS）。伺服器把使用者輸入直接拼進 HTML 回應、未做輸出轉義，
攻擊者把惡意 <script> 或事件屬性注入頁面，讓它在別人的瀏覽器中執行。
最常見於把 query／表單輸入直接餵給 innerHTML 或拼進屬性。`,
		problem: `// 不安全寫法：把使用者輸入直接塞進 innerHTML，未轉義，<script>… 會被執行
function renderMessage(msg) {
  target.innerHTML = '<p>' + msg + '</p>';  // msg 可帶 <script>…，直接被執行
}`,
		fixed: `// 安全寫法：使用者輸入只當純文字處理，用 textContent 寫入
function renderMessage(msg) {
  const p = document.createElement('p');
  p.textContent = msg;      // 只當純文字，不會被當 HTML 執行
  target.appendChild(p);
}`,
		patch: `@@ -1 +1,4 @@
-  target.innerHTML = '<p>' + msg + '</p>';
+  const p = document.createElement('p');
+  p.textContent = msg;
+  target.appendChild(p);`,
		refs: ['OWASP-XSS', 'CWE-79'],
		tags: ['web', 'injection', 'output-encoding'],
	},
	{
		id: 'CWE-89',
		name: 'SQL Injection',
		lang: 'php',
		status: 'Complete',
		what: `SQL 注入。把使用者輸入用字串拼接直接塞進 SQL 敘述，
攻擊者能用 ' OR '1'='1 之類改寫查詢條件，甚至串更多敘述。
建議做法是把參數透過預備語句（prepared statement）分開傳遞。`,
		problem: `// 不安全寫法：字串拼接進 SQL，輸入可直接改寫查詢
$sql = "SELECT * FROM users WHERE name = '" . $_GET['name'] . "'";
$rows = $db->query($sql);`,
		fixed: `// 安全寫法：預備語句 + 參數綁定，輸入永遠是資料不是敘述
$stmt = $db->prepare("SELECT * FROM users WHERE name = ?");
$stmt->execute([$_GET['name']]);
$rows = $stmt->fetchAll();`,
		patch: `@@
-      $sql = "SELECT * FROM users WHERE name = '" . $_GET['name'] . "'";
-      $rows = $db->query($sql);
+      $stmt = $db->prepare("SELECT * FROM users WHERE name = ?");
+      $stmt->execute([$_GET['name']]);
+      $rows = $stmt->fetchAll();`,
		refs: ['OWASP-SQLi', 'CWE-89'],
		tags: ['web', 'sql', 'injection'],
	},
	{
		id: 'CWE-78',
		name: 'OS Command Injection',
		lang: 'python',
		status: 'Complete',
		what: `作業系統命令注入。把使用者輸入拼接成字串再交給外層 shell 執行，
攻擊者可拼 ; id 或 && 執行任意命令。
建議做法是不要經過 shell，改用帶參數清單的子行程呼叫，並嚴加校驗。`,
		problem: `# 不安全寫法：shell=True + 字串拼接，host 可能帶 ; rm -rf …
import subprocess
host = request.form["host"]
out = subprocess.check_output("ping -c 1 " + host, shell=True)`,
		fixed: `# 安全寫法：list 形式，不經外層 shell，且只允許網域/主機格式
import re, subprocess
host = request.form["host"]
if not re.fullmatch(r'[A-Za-z0-9.-]+', host): raise ValueError('bad host')
out = subprocess.check_output(["ping", "-c", "1", host])`,
		patch: `@@
-  out = subprocess.check_output("ping -c 1 " + host, shell=True)
+  if not re.fullmatch(r'[A-Za-z0-9.-]+', host): raise ValueError('bad host')
+  out = subprocess.check_output(["ping", "-c", "1", host])`,
		refs: ['OWASP-CommandInjection', 'CWE-78'],
		tags: ['os', 'rce', 'injection'],
	},
	{
		id: 'CWE-20',
		name: 'Improper Input Validation',
		lang: 'javascript',
		status: 'Complete',
		what: `缺少輸入驗證。輸入到信任邊界前沒有驗證型別、格式與允許清單，
壞值一路流到 SQL、路徑、數字運算等，常跟其他注入弱點有因果關係。
建議做法是在邊界做允許清單校驗。`,
		problem: `// 不安全寫法：unit 直接進查詢條件，沒有先校驗
function convert(unit) {
  return db.query("SELECT rate FROM units WHERE code = '" + unit + "'");
}`,
		fixed: `// 安全寫法：允許清單先校驗，再走參數化查詢
const VALID = new Set(['cm', 'm', 'ft', 'in']);
function convert(unit) {
  if (!VALID.has(unit)) throw new RangeError('unsupported: ' + unit);
  return db.query('SELECT rate FROM units WHERE code = ?', [unit]);
}`,
		patch: `@@
+  const VALID = new Set(['cm', 'm', 'ft', 'in']);
   function convert(unit) {
+    if (!VALID.has(unit)) throw new RangeError('unsupported: ' + unit);
-    return db.query("SELECT rate FROM units WHERE code = '" + unit + "'");
+    return db.query('SELECT rate FROM units WHERE code = ?', [unit]);
   }`,
		refs: ['OWASP', 'CWE-20'],
		tags: ['validation', 'whitelist'],
	},
	{
		id: 'CWE-94',
		name: 'Improper Control of Generation of Code (Code Injection)',
		lang: 'python',
		status: 'Complete',
		what: `程式碼／評估注入。把使用者輸入直接交給 eval()／exec() 之類
動態執行程式碼的機制，等於讓使用者執行任意程式碼。
建議做法是切勿對使用者輸入求值，改用允許清單 + 正規 API。`,
		problem: `# 不安全寫法：exec 使用者輸入，任意程式碼直接執行
mod = request.form['expr']
exec(mod)   # 輸 "__import__('os').system('id')" 即 RCE`,
		fixed: `# 安全寫法：不用 eval/exec，允許清單 + 正規動作用途
OPS = {'upper': str.upper, 'lower': str.lower, 'title': str.title}
op = request.form.get('op', 'upper')
if op not in OPS: raise ValueError('unknown op')
result = OPS[op](value)`,
		patch: `@@
-  exec(request.form['expr'])
+  OPS = {'upper': str.upper, 'lower': str.lower, 'title': str.title}
+  op = request.form.get('op', 'upper')
+  if op not in OPS: raise ValueError('unknown op')
+  result = OPS[op](value)`,
		refs: ['CWE-94', 'OWASP-RCE'],
		tags: ['rce', 'dynamic', 'injection'],
	},
	{
		id: 'CWE-22',
		name: 'Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)',
		lang: 'javascript',
		status: 'Complete',
		what: `路徑穿越（Path Traversal）。未對使用者輸入的路徑或檔名進行校驗，
攻擊者可傳入含有 ../ 的相對路徑，跨越預設目錄讀取或寫入系統上的敏感檔案（如 /etc/passwd）。
建議做法是使用 path.basename 取得純檔名，或校驗解析後的絕對路徑是否符合允許根目錄。`,
		problem: `// 不安全寫法：直接拼接使用者傳入的路徑，可被 ../ 穿越目錄
const fs = require('fs');
const path = require('path');

function getFile(req, res) {
  const filePath = path.join(__dirname, 'uploads', req.query.filename); // filename 可為 ../../../etc/passwd
  const content = fs.readFileSync(filePath, 'utf8');
  res.send(content);
}`,
		fixed: `// 安全寫法：限制僅取檔名，並驗證最終路徑是否仍在指定目錄下
const fs = require('fs');
const path = require('path');

function getFile(req, res) {
  const safeFilename = path.basename(req.query.filename); // 防範 ../
  const targetDir = path.join(__dirname, 'uploads');
  const filePath = path.join(targetDir, safeFilename);

  if (!filePath.startsWith(targetDir)) {
    throw new Error('Access denied');
  }
  const content = fs.readFileSync(filePath, 'utf8');
  res.send(content);
}`,
		patch: `@@
-  const filePath = path.join(__dirname, 'uploads', req.query.filename);
+  const safeFilename = path.basename(req.query.filename);
+  const targetDir = path.join(__dirname, 'uploads');
+  const filePath = path.join(targetDir, safeFilename);
+  if (!filePath.startsWith(targetDir)) throw new Error('Access denied');`,
		refs: ['OWASP-PathTraversal', 'CWE-22'],
		tags: ['file', 'path-traversal', 'validation'],
	},
	{
		id: 'CWE-611',
		name: 'Improper Restriction of XML External Entity Reference (XXE)',
		lang: 'python',
		status: 'Complete',
		what: `XML 外部實體注入（XXE）。解析 XML 時預設開啟了解析外部實體（DTD/External Entity）的功能，
攻擊者可藉由構造含有 SYSTEM "file:///..." 的惡意 XML 讀取伺服器內部檔案，甚至發動內網 SSRF。
建議做法是解析時完全禁用 DTD 與外部實體載入。`,
		problem: `# 不安全寫法：預設解析器會解析 XML 外部實體（XXE）
from lxml import etree

def parse_xml(xml_input):
    parser = etree.XMLParser() # 預設可能允許 resolve_entities
    return etree.fromstring(xml_input, parser)`,
		fixed: `# 安全寫法：關閉 DTD 與外部實體解析，或使用安全解析套件 defusedxml
from defusedxml import lxml as defused_lxml

def parse_xml(xml_input):
    return defused_lxml.fromstring(xml_input)`,
		patch: `@@
-from lxml import etree
+from defusedxml import lxml as defused_lxml

 def parse_xml(xml_input):
-    parser = etree.XMLParser()
-    return etree.fromstring(xml_input, parser)
+    return defused_lxml.fromstring(xml_input)`,
		refs: ['OWASP-XXE', 'CWE-611'],
		tags: ['xml', 'xxe', 'parser'],
	},
	{
		id: 'CWE-918',
		name: 'Server-Side Request Forgery (SSRF)',
		lang: 'javascript',
		status: 'Complete',
		what: `伺服器端請求偽造（SSRF）。應用程式接受使用者提供的 URL 並由伺服器端發起 HTTP 請求，
卻未驗證目標 IP/網域，導致攻擊者可利用伺服器權限存取內部網路（如 127.0.0.1、雲端 Metadata API）。
建議做法是將通訊協定僅限 HTTPS、只採允許清單中的網域，並禁止訪問內部私有 IP 網段。`,
		problem: `// 不安全寫法：未檢查 URL，攻擊者可輸入 http://169.254.169.254/ 或 http://127.0.0.1
async function fetchWebhook(userUrl) {
  const response = await fetch(userUrl);
  return await response.text();
}`,
		fixed: `// 安全寫法：僅信任允許清單中的網域，且只放行 HTTPS 協定
const ALLOWED_HOSTS = new Set(['api.example.com', 'hooks.example.com']);

async function fetchWebhook(userUrl) {
  const parsed = new URL(userUrl);
  if (parsed.protocol !== 'https:') throw new Error('Only HTTPS allowed');
  if (!ALLOWED_HOSTS.has(parsed.hostname)) throw new Error('Host not allowed');
  
  const response = await fetch(parsed.href);
  return await response.text();
}`,
		patch: `@@
+const ALLOWED_HOSTS = new Set(['api.example.com', 'hooks.example.com']);
 async function fetchWebhook(userUrl) {
+  const parsed = new URL(userUrl);
+  if (parsed.protocol !== 'https:') throw new Error('Only HTTPS allowed');
+  if (!ALLOWED_HOSTS.has(parsed.hostname)) throw new Error('Host not allowed');
-  const response = await fetch(userUrl);
+  const response = await fetch(parsed.href);`,
		refs: ['OWASP-SSRF', 'CWE-918'],
		tags: ['ssrf', 'network', 'validation'],
	},
	{
		id: 'CWE-113',
		name: 'Improper Neutralization of CRLF Sequences in HTTP Headers',
		lang: 'javascript',
		status: 'Complete',
		what: `HTTP 回應拆分 / CRLF 注入。把使用者輸入直接寫入 HTTP 標頭（Header）中，
未清洗 \\r (CR) 與 \\n (LF) 換行符號，攻擊者可藉此注入自訂標頭、偽造 Cookie，甚至拆分回應體發動 XSS。
建議做法是過濾或拒絕包含換行字元（\\r, \\n）的輸入。`,
		problem: `// 不安全寫法：直接將使用者輸入設定為 Header 值，未消毒 \\r\\n
function setCustomHeader(req, res) {
  const userRole = req.query.role; // 可能包含 "admin\\r\\nSet-Cookie: session=evil"
  res.setHeader('X-User-Role', userRole);
}`,
		fixed: `// 安全寫法：過濾換行符號，或對 Header 內容實施英數字元允許清單檢查
function setCustomHeader(req, res) {
  const userRole = req.query.role || '';
  if (!/^[a-zA-Z0-9_-]+$/.test(userRole)) {
    throw new Error('Invalid header value');
  }
  res.setHeader('X-User-Role', userRole);
}`,
		patch: `@@
 function setCustomHeader(req, res) {
-  const userRole = req.query.role;
-  res.setHeader('X-User-Role', userRole);
+  const userRole = req.query.role || '';
+  if (!/^[a-zA-Z0-9_-]+$/.test(userRole)) {
+    throw new Error('Invalid header value');
+  }
+  res.setHeader('X-User-Role', userRole);`,
		refs: ['OWASP-CRLF', 'CWE-113'],
		tags: ['crlf', 'http-header', 'injection'],
	},
	{
		id: 'CWE-90',
		name: 'Improper Neutralization of Special Elements used in an LDAP Query (LDAP Injection)',
		lang: 'javascript',
		status: 'Complete',
		what: `LDAP 注入。直接將使用者輸入以字串拼接方式組裝至 LDAP 查詢語法中，
攻擊者可利用特殊字元（如 *、(、)）改寫查詢邏輯，達到繞過登入驗證或列舉所有目錄資料的目的。
建議做法是對使用者輸入做 LDAP 特殊字元轉義處理，或使用安全 API。`,
		problem: `// 不安全寫法：直接字串拼接 LDAP 查詢，輸入可帶 * 或 )
function getLdapFilter(username) {
  return '(&(objectClass=user)(uid=' + username + '))';
}`,
		fixed: `// 安全寫法：對 LDAP 特殊字元（\\, *, (, ), \\0）進行轉義消毒
function escapeLDAPSearchFilter(input) {
  return input.replace(/\\\\/g, '\\\\5c')
              .replace(/\\*/g, '\\\\2a')
              .replace(/\\(/g, '\\\\28')
              .replace(/\\)/g, '\\\\29')
              .replace(/\\0/g, '\\\\00');
}

function getLdapFilter(username) {
  const safeUser = escapeLDAPSearchFilter(username);
  return '(&(objectClass=user)(uid=' + safeUser + '))';
}`,
		patch: `@@
+function escapeLDAPSearchFilter(input) {
+  return input.replace(/\\\\/g, '\\\\5c').replace(/\\*/g, '\\\\2a').replace(/\\(/g, '\\\\28').replace(/\\)/g, '\\\\29').replace(/\\0/g, '\\\\00');
+}
 function getLdapFilter(username) {
-  return '(&(objectClass=user)(uid=' + username + '))';
+  const safeUser = escapeLDAPSearchFilter(username);
+  return '(&(objectClass=user)(uid=' + safeUser + '))';`,
		refs: ['OWASP-LDAP', 'CWE-90'],
		tags: ['ldap', 'injection', 'sanitization'],
	},
];
