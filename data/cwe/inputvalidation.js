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
		id: 'CWE-19',
		name: 'Data Processing Errors',
		lang: 'c',
		status: 'Complete',
		what: `資料處理錯誤（Data Processing Errors）。凡是在把輸入資料進行格式化、剖析、轉換、排序或組合等一連串處理的環節中，
		因未正確處理型別、長度、分隔符號或格式而產生錯誤行為的弱點，都歸在此類別。它常是越界、邏輯誤判等具體弱點的上游根因，
		例如把使用者輸入直接當浮點數或長度欄位使用、剖析的回傳值未檢查。成因多半是預設資料格式永遠正確、忽略邊界與失敗分支。
		後果隨用途可能是資料外洩、越界讀寫或語意被改變。修法是在進入處理鏈前先做型別與格式校驗，並讓每個剖析步驟都清楚處理
		非預期輸入與失敗，再決定後續動作。`,
		problem: `// 不安全寫法：直接採信使用者提供的 len 做複製，len 超過緩衝區即越界讀取
#include <string.h>
int process(const char *buf, int len) {
    char out[64];
    memcpy(out, buf, len);      // len > 64 越界
    return 0;
}`,
		fixed: `// 安全寫法：先驗證長度與來源，才把資料送進下一步處理
#include <string.h>
int process(const char *buf, size_t len) {
    char out[64];
    if (buf == NULL || len > sizeof(out))   // 資料階段先校驗
        return -1;
    memcpy(out, buf, len);
    return 0;
}`,
		patch: `@@
-    memcpy(out, buf, len);      // len > 64 越界
+    if (buf == NULL || len > sizeof(out))
+        return -1;
+    memcpy(out, buf, len);`,
		refs: ['CWE-19'],
		tags: ['data', 'parsing', 'validation'],
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
		id: 'CWE-116',
		name: 'Improper Encoding or Escaping of Output',
		lang: 'javascript',
		status: 'Complete',
		what: `輸出編碼／轉義不當。送到下游（HTML、JS、SQL、Shell、JSON）的輸出被做了錯誤或不一致的轉義，或同一份資料在所有情境套用同一種編碼、
		在編碼後又做破壞性的修改，使「本該當資料」的字元仍有機會被下游當成語法。成因是沒有「一種消費端一種專屬編碼」的紀律，把多種情境混用同一套函式。
		後果往往擴散為各種注入弱點或資料毀損。修法是為每個消費端使用專屬且完整的編碼函式，全程只做一次正確的輸出編碼，避免再對已編碼結果做破壞性處理。`,
		problem: `// 不安全寫法：把已做 HTML 轉義的字串又放進 JS 字串，兩種情境套同一套編碼而失效
function build(data) {
  const e = data.replace(/</g, "&lt;");
  return '<script>var x = "' + e + '";</script>';
  // 雙引號未轉義可逃出字串注入；而 &lt; 在 JS 字串中不會被解回 <
}`,
		fixed: `// 安全寫法：JS 字串用 JS 專屬編碼跳引號與控制字元，前端再以 DOM 傳入
function build(data) {
  const j = String(data)
    .replace(/&/g, "\\u0026").replace(/</g, "\\u003c")
    .replace(/"/g, "\\u0022").replace(/'/g, "\\u0027");
  return '<script>var x = "' + j + '";</script>';
}`,
		patch: `@@
-  const e = data.replace(/</g, "&lt;");
+  const j = String(data)
+    .replace(/&/g, "\\u0026").replace(/</g, "\\u003c")
+    .replace(/"/g, "\\u0022").replace(/'/g, "\\u0027");
   return '<script>var x = "' + j + '";</script>';`,
		refs: ['OWASP', 'CWE-116'],
		tags: ['output-encoding', 'escaping', 'injection'],
	},
	{
		id: 'CWE-133',
		name: 'String Errors',
		lang: 'c',
		status: 'Complete',
		what: `字串類錯誤（String Errors）。這是一整類與「建立、修改、接合、測長與寫回字串」有關的弱點，涵蓋未終止字串、多位元組長度算錯、
		格式字串誤用與字串緩衝區溢位等。成因多以定長陣列手動組字串，卻沒顧 NUL 結尾與長度上限，尤其當字串長短受使用者輸入影響時。
		後果從越界寫入、當機到資訊外洩不一而足。修法是改用安全字串函式（strlcpy、snprintf、asprintf）或容器型字串，
		並每次都驗證來源長度與剩餘容量、確保結尾。`,
		problem: `// 不安全寫法：無上限地 sprintf 往定長陣列寫，來源過長即溢位、也無結尾保證
void greet(char *dst, size_t n, const char *name) {
    sprintf(dst, "Hello %s!", name);   // name 過長 → 溢出
}`,
		fixed: `// 安全寫法：用 snprintf 限制寫入量並確實 NUL 結尾
void greet(char *dst, size_t n, const char *name) {
    snprintf(dst, n, "Hello %s!", name);   // 最多寫 n-1，末尾補 '\\0'
}`,
		patch: `@@
-    sprintf(dst, "Hello %s!", name);
+    snprintf(dst, n, "Hello %s!", name);`,
		refs: ['CWE-133'],
		tags: ['string', 'buffer', 'format'],
	},
	{
		id: 'CWE-141',
		name: 'Improper Neutralization of Parameter/Argument Delimiters within a Data Value Variable',
		lang: 'python',
		status: 'Complete',
		what: `資料值內參數／引數分隔符號未被中立化。把資料值填進以分隔符（分號、逗號、冒號、管道）隔開多個參數或欄位的位置時，
		若值內含的分隔符沒先轉義或隔離，上層的「一個值」就會被下游拆成「多個值、多個欄位或引數」，悄悄改動命令、組態或標頭的結構。
		成因為用字串拼接把值直接拼進結構化欄位清單，卻沒界定值的邊界。後果常是屬性注入、標頭操弄與邏輯誤判。修法是對值內的任何分隔符
		做轉義或編碼，或改用不依賴分隔符的結構化容器來傳值。`,
		problem: `# 不安全寫法：把使用者設定值拼進分號分隔的組態字串，值內分號可注入新欄位
def apply(extra):
    line = "host=db;port=5432;" + extra   # extra="user=admin;pass=hax" 注入新欄位`,
		fixed: `# 安全寫法：值作為獨立字段，分隔符先被阻絕才接受
def apply(extra):
    if ";" in extra or "\\n" in extra:
        raise ValueError("delimiter not allowed")
    line = "host=db;port=5432;extra=" + extra`,
		patch: `@@
-    line = "host=db;port=5432;" + extra
+    if ";" in extra or "\\n" in extra:
+        raise ValueError("delimiter not allowed")
+    line = "host=db;port=5432;extra=" + extra`,
		refs: ['OWASP', 'CWE-141'],
		tags: ['delimiter', 'argument', 'injection'],
	},
	{
		id: 'CWE-147',
		name: 'Improper Neutralization of Input Terminators',
		lang: 'python',
		status: 'Complete',
		what: `輸入終止子未被中立化。某些協定或檔案格式以特定字元標示「一筆輸入到此結束」：一行記錄以換行（\\n）結束、C 字串以 NUL 終止、
		郵件標頭由 CRLF 或空行完結、URL 以 ? 或 # 分段。若使用者輸入內含這種終止子又沒先去除或消毒，提早出現的終止子會讓本筆輸入被截斷，
		剩餘內容被當成新的一筆或新指令，形同注入。常見後果是記錄偽造、標頭操弄與驗證繞過。成因為未在送入該元件前清洗終止子。修法是
		在輸入邊界過濾或轉義所有送往下游的終止字元，再用已消毒的形式做安全判定。`,
		problem: `# 不安全寫法：每條記錄以換行結束，輸入內含換行就被拆成多條新記錄
def append_line(file, entry):
    file.write(entry)               # entry 含 "\\n" 即注入新的一行指令`,
		fixed: `# 安全寫法：先拒絕含終止子（換行/歸位）的輸入，再寫入
def append_line(file, entry):
    if "\\n" in entry or "\\r" in entry:
        raise ValueError("terminator not allowed")
    file.write(entry + "\\n")`,
		patch: `@@
-    file.write(entry)
+    if "\\n" in entry or "\\r" in entry:
+        raise ValueError("terminator not allowed")
+    file.write(entry + "\\n")`,
		refs: ['OWASP', 'CWE-147'],
		tags: ['terminator', 'crlf', 'injection'],
	},
	{
		id: 'CWE-150',
		name: 'Improper Neutralization of Escape, Meta, or Control Sequences',
		lang: 'python',
		status: 'Complete',
		what: `跳脫序／元字元／控制字元未被中立化。輸入帶有終端機控制序列（\\x1b[...）、shell 元字元（; | & 或 $()）、或跳脫字元時，
		下游若把這些字元當控制訊號而非資料，就能被用來注入：直接印到終端造成控制字元攻擊、拼進 shell 造成命令注入、寫入設定檔則改寫語意。
		成因是未針對「會被特殊解讀的字元序列」做中立化後才放行。後果從記錄偽造、畫面竄改到任意命令執行。修法是使用允許清單限制字元集，
		或對該輸出情境做專屬且完整的轉義與編碼。`,
		problem: `# 不安全寫法：把輸入直接拼進要 source 的 shell 片段，$() 或 ; 就被執行
import os
expr = request.form["expr"]
os.system("bash -c 'x=" + expr + "'")   # expr="\$(id); rm -rf" 即執行`,
		fixed: `# 安全寫法：不經 shell 且只放行白名單字元，任何元字元直接拒絕
import re
expr = request.form["expr"]
if not re.fullmatch(r"[0-9A-Za-z_]+", expr):
    raise ValueError("meta chars not allowed")
conf["x"] = expr`,
		patch: `@@
-  os.system("bash -c 'x=" + expr + "'")
+  if not re.fullmatch(r"[0-9A-Za-z_]+", expr):
+      raise ValueError("meta chars not allowed")
+  conf["x"] = expr`,
		refs: ['OWASP', 'CWE-150'],
		tags: ['meta', 'escape', 'control', 'terminal'],
	},
	{
		id: 'CWE-156',
		name: 'Improper Neutralization of Whitespace',
		lang: 'javascript',
		status: 'Complete',
		what: `空白字元未被中立化。多數語法以空白切分語彙單位，程式若在比較前只移除部分空白、或下游以空白當分隔子，同一個名字就會在檢查與使用時
		對上不同的物件，或本應被擋的字串因帶空白而通過。例如黑名單比對時，輸入開頭或結尾的空格使路徑、指令名或網域名逃過檢查。成因為對空白
		做了不完整或不對稱的處理（只清一端、漏掉跳格或全形空白）。後果通常搭配路徑與資源比對弱點一起被利用。修法是先對所有 Unicode 空白做
		統一正規化（trim 兩端）並一致大小寫，再以同一表示做完全比較。`,
		problem: `// 不安全寫法：只清前端空白，尾端空白讓比對失準
function isBlocked(cmd) {
  return BANNED.has(cmd.trimStart());   // "rm "（尾端空白）不會命中而被放行執行
}`,
		fixed: `// 安全寫法：先將兩端所有型態空白 normalize，再小寫化做完全比對
function isBlocked(cmd) {
  return BANNED.has(cmd.trim().toLowerCase());
}`,
		patch: `@@
-  return BANNED.has(cmd.trimStart());
+  return BANNED.has(cmd.trim().toLowerCase());`,
		refs: ['OWASP', 'CWE-156'],
		tags: ['whitespace', 'bypass', 'comparison'],
	},
	{
		id: 'CWE-172',
		name: 'Encoding Error',
		lang: 'python',
		status: 'Complete',
		what: `編碼錯誤（Encoding Error）。系統對資料編碼做了錯誤假設、或在轉碼失敗時不予理會，導致位元組被誤判成另一字元集：
		例如把 UTF-8 當 Latin-1 解、忽略 decode 例外、或手動改位元組產生非法序列。這些異構編碼讓只對單一編碼做的黑名單被繞過：危險字元以
		另一種編碼呈現，到下游才被正確解出。成因是沒有固定單一編碼並嚴格處理解碼失敗。修法是全程以同一明確編碼操作，任何 decode 失敗以例外處理
		並拒絕，杜絕非法或異構序列流過安全判定。`,
		problem: `# 不安全寫法：假設一律 ascii 且忽略錯誤位元組，危險字元被吞或誤判
def as_text(b):
    return b.decode("ascii", errors="ignore")   # 非法/非 ASCII 被吞掉`,
		fixed: `# 安全寫法：固定 UTF-8 且嚴格驗證，解碼失敗立即拒絕
def decode_input(b):
    try:
        return b.decode("utf-8")     # 非法序列丟例外，不再 "忽略"
    except UnicodeDecodeError:
        raise ValueError("bad encoding")`,
		patch: `@@
-    return b.decode("ascii", errors="ignore")
+    try:
+        return b.decode("utf-8")
+    except UnicodeDecodeError:
+        raise ValueError("bad encoding")`,
		refs: ['OWASP', 'CWE-172'],
		tags: ['encoding', 'charset', 'bypass'],
	},
	{
		id: 'CWE-176',
		name: 'Improper Handling of Unicode Encoding',
		lang: 'python',
		status: 'Complete',
		what: `Unicode 編碼處理不當。程式未對 Unicode 的正規化形式（NFC/NFD/NFKC/NFKD）、全形半形字母與同碼異形字元統一處理，使本質相同的字串
		以不同的位元組表示。攻擊者用替代編碼或字形混淆（全形點、零寬空格、結合符）換掉關鍵字，字面黑名單比對就漏過去，後端卻解析成不同或
		原始的字，進而繞過驗證、目錄或規則。成因為比較、過濾與輸出階段各自用不同的編碼處理。修法是在信任邊界先把輸入 canonicalize（正規化到
		一種表示）並統一大小寫，再進行任何安全判定。`,
		problem: `# 不安全寫法：只做逐字元比對，沒有正規化；全形字能騙過黑名單
banned = {"<script>"}
def is_banned(s):
    return s in banned              # "＜script＞"（全形 < > ）不會命中`,
		fixed: `# 安全寫法：先 NFKC 正規化並小寫化，再用統一表示比對
import unicodedata
banned = {"<script>"}
def is_banned(s):
    norm = unicodedata.normalize("NFKC", s).lower()   # 全形→半形再比
    return norm in banned`,
		patch: `@@
-    return s in banned
+    import unicodedata
+    norm = unicodedata.normalize("NFKC", s).lower()
+    return norm in banned`,
		refs: ['OWASP', 'CWE-176'],
		tags: ['unicode', 'nfkc', 'bypass'],
	},
	{
		id: 'CWE-177',
		name: 'Improper Handling of URL Decoding',
		lang: 'javascript',
		status: 'Complete',
		what: `URL 解碼處理不當。應用對 URL 編碼做了不一致或多次的解碼，安全檢查在「未解碼」的字串上做、實際存取卻用「已解碼」的結果，導致
		%2e%2e%2f 這類編碼形式繞過路徑或驗證檢查。成因為解碼時機、次數與對象（path、query）不統一，或對同一段內容解碼兩次。後果是繞過目錄、
		讀寫非預期檔案。修法是先把 URL 完整解碼並正規化到內部的單一表示，之後所有安全判定都針對同一表示，且整個處理流只解碼一次。`,
		problem: `// 不安全寫法：存取用 decode 後的路徑，檢查卻用原始字串 → %2e%2e 逃過 ../ 判斷
async function read(req) {
  const u = new URL(req.url);
  if (u.query.includes('..')) throw new Error('blocked');
  return fs.readFile('/data/' + decodeURIComponent(u.query));
}`,
		fixed: `// 安全寫法：先統一解碼到單一表示，再用同一串做比對與存取
async function read(req) {
  const u = new URL(req.url);
  const p = decodeURIComponent(u.query);      // 先解碼出最終路徑
  if (p.includes('..')) throw new Error('blocked');   // 與存取用同一表示
  return fs.readFile('/data/' + p);
}`,
		patch: `@@
-  if (u.query.includes('..')) throw new Error('blocked');
-  return fs.readFile('/data/' + decodeURIComponent(u.query));
+  const p = decodeURIComponent(u.query);
+  if (p.includes('..')) throw new Error('blocked');
+  return fs.readFile('/data/' + p);`,
		refs: ['OWASP', 'CWE-177'],
		tags: ['url', 'decode', 'canonicalization'],
	},
	{
		id: 'CWE-184',
		name: 'Incomplete List of Disallowed Inputs',
		lang: 'javascript',
		status: 'Complete',
		what: `不完整的禁止清單（黑名單）。防禦只列出少數「不准出現」的字或字元來阻擋輸入，但清單本身不完整，攻擊者改用清單外的等價寫法就能通過：
		例如只擋 <script>、' 與 --，卻漏掉大小寫混合、HTML Entity、註解包裝、編碼變體或其他字元集。因為有害寫法不可窮舉，黑名單本質上擋不完，
		是多數注入類弱點的共通成因。修法應該以允許清單（白名單）與正規輸出編碼為主、黑名單僅作輔助；若必須比對，先正規化到單一表示再比。`,
		problem: `// 不安全寫法：黑名單只列幾種已知關鍵字，變體與編碼都能繞過
function sanitize(s) {
  return s.replace(/<script>/gi, "").replace(/'/g, "");
  // "&#60;script&#62;"、"< !--script-->" 或大小寫混合…都能通過
}`,
		fixed: `// 安全寫法：以允許字元集（白名單）整體拒絕，而不是逐個抓壞字
function sanitize(s) {
  const SAFE = /^[A-Za-z0-9_ ,.()\\-/?]+$/;
  return SAFE.test(s) ? s : null;   // 不在允許字元集的輸入一律拒絕
}`,
		patch: `@@
-  return s.replace(/<script>/gi, "").replace(/'/g, "");
+  const SAFE = /^[A-Za-z0-9_ ,.()\\-/?]+$/;
+  return SAFE.test(s) ? s : null;`,
		refs: ['OWASP', 'CWE-184'],
		tags: ['blacklist', 'allowlist', 'bypass', 'sanitization'],
	},
	{
		id: 'CWE-185',
		name: 'Incorrect Regular Expression',
		lang: 'python',
		status: 'Complete',
		what: `錯誤的正則表示式。用來做安全決定（驗證、過濾、允許清單）的正則本身有邏輯錯誤會造成誤判：缺錨點而只是 partial match 放行、誤用重疊量詞
		造成災難性回溯（ReDoS）、轉義不全使正則被注入、或 unanchored 讓惡意字串從中段匹配成功。成因為正則不是「完整描述」，也沒經反例測試。
		後果是驗證被繞過與正則 DoS。修法是使用完全錨定（^…$）與明確字元集、限制量詞上界，並以大量安全／不安全樣本驗證正則行為。`,
		problem: `# 不安全寫法：重疊量詞 (a|a)+ 遇上長序列會災難性回溯，拖垮 CPU
import re
def ok(s):
    return re.compile(r"^(a|a)+$").search(s) is not None   # 指數回溯`,
		fixed: `# 安全寫法：單一明確量詞，避免重疊／嵌套造成指數回溯
import re
def ok(s):
    return re.fullmatch(r"a+", s) is not None`,
		patch: `@@
-    return re.compile(r"^(a|a)+$").search(s) is not None
+    return re.fullmatch(r"a+", s) is not None`,
		refs: ['OWASP-ReDoS', 'CWE-185'],
		tags: ['regex', 'redos', 'validation'],
	},
	{
		id: 'CWE-187',
		name: 'Partial String Comparison',
		lang: 'c',
		status: 'Complete',
		what: `部分字串比較。安全相關檢查只比對了字串的一小段（前綴、子串），卻誤以為是完整相等：例如把前綴比對當精確比對、用相等長度的 strncmp
		而任一方較長、或只以 substring 檢查檔名或網域。攻擊者可讓輸入帶有「等價前綴」或「卡位字元」通過檢查，存取或授權到不同物件。成因是沒
		區分「前綴／包含」與「全串相等」兩種語意。修法是明確所需語意：全等就用全串比較與固定長度；若真要前綴，就各自驗證邊界（例如後面緊接 \\0 或分隔符）。`,
		problem: `// 不安全寫法：想檢查「以 admin 開頭允許」，實際放行了 admin2、admin-x
int is_admin(const char *tok) {
    return strncmp(tok, "admin", 5) == 0;   // 只比前 5 字元，後綴不限
}`,
		fixed: `// 安全寫法：要求完整相等，先比長度避免前綴僥倖通過
#include <string.h>
int is_admin(const char *tok) {
    size_t n = strlen(tok);
    return n == 5 && strncmp(tok, "admin", 5) == 0;
}`,
		patch: `@@
-    return strncmp(tok, "admin", 5) == 0;
+    size_t n = strlen(tok);
+    return n == 5 && strncmp(tok, "admin", 5) == 0;`,
		refs: ['CWE-187'],
		tags: ['partial-compare', 'strncmp', 'bypass'],
	},
	{
		id: 'CWE-188',
		name: 'Reliance on Data/Memory Layout',
		lang: 'c',
		status: 'Complete',
		what: `依賴資料／記憶體佈局。程式依賴結構體欄位順序、記憶體對齊、位元組序、int 寬度等「在某平台才成立」的假設來讀寫資料，例如直接
		sizeof 整個結構體送出去、用 memcpy 轉型別、或假設欄位緊密排列。更換平台、編譯器優化或使用者可操控的輸入一旦不符合假設便會失效，
		造成越界、型別混淆與未初始化漏洞。成因為把「開發環境的佈局」當成通則。修法是逐欄位封裝資料、不明文複製整個結構體的位元組，
		並對每個值的邊界與型別都做校驗。`,
		problem: `// 不安全寫法：把整個結構體當連續位元組送出，padding 與對齊讓內容錯位/洩漏
struct msg { char tag; int id; char data[8]; };
static void send_msg(int fd, struct msg *m) {
    write(fd, m, sizeof(*m));   // 含 padding 位元組；消費者解讀不同即型別混淆
}`,
		fixed: `// 安全寫法：逐欄位序列化並驗長度，不依賴結構佈局
static void send_msg(int fd, struct msg *m, size_t dlen) {
    if (dlen > 8) return;              // 校驗資料長度
    unsigned char b[13], n = 0;
    b[n++] = m->tag;
    b[n++] = (unsigned char) (m->id & 0xff);
    b[n++] = (unsigned char) (m->id >> 8);
    memcpy(b + n, m->data, dlen);
    write(fd, b, n + dlen);
}`,
		patch: `@@
-    write(fd, m, sizeof(*m));
+    if (dlen > 8) return;
+    unsigned char b[13], n = 0;
+    b[n++] = m->tag;
+    b[n++] = (unsigned char)(m->id & 0xff);
+    b[n++] = (unsigned char)(m->id >> 8);
+    memcpy(b + n, m->data, dlen);
+    write(fd, b, n + dlen);`,
		refs: ['CWE-188'],
		tags: ['memory-layout', 'struct', 'serialization'],
	},
	{
		id: 'CWE-229',
		name: 'Improper Handling of Values',
		lang: 'javascript',
		status: 'Complete',
		what: `值處理不當。下游收到的值可能來自使用者，程式卻沒有對每個值做對應的防護與失敗處理：超出範圍、負值、極值、型別不符或特殊值
		（NaN、Infinity、0）。成因是把值直接傳進只接受某範圍、或不該產生副作用的地方，又缺 default／失敗分支。後果依情境可能是陣列越界、
		指數放大、邏輯繞過或資源耗盡。修法是對每個值先校驗型別、範圍與語意，對非法值採取明確而又安全的拒絕或回退。`,
		problem: `// 不安全寫法：把使用者數字直接當運算量，負值／極值未被攔
function withdraw(balance, amount) {
  return balance - amount;          // amount 為負 → 反而加錢
}`,
		fixed: `// 安全寫法：先驗型別與合理範圍，才做帳務運算
function withdraw(balance, amount) {
  const n = Number(amount);
  if (!Number.isFinite(n) || n <= 0 || n > balance) throw new Error('invalid');
  return balance - n;
}`,
		patch: `@@
-  return balance - amount;
+  const n = Number(amount);
+  if (!Number.isFinite(n) || n <= 0 || n > balance) throw new Error('invalid');
+  return balance - n;`,
		refs: ['OWASP', 'CWE-229'],
		tags: ['values', 'range', 'validation'],
	},
	{
		id: 'CWE-232',
		name: 'Improper Handling of Undefined Values',
		lang: 'javascript',
		status: 'Complete',
		what: `未定義值處理不當。程式假定某個值一定存在，它卻可能是 undefined／null／未初始化，程式又在取值前沒檢查就做屬性存取或運算。
		常見於把可選參數、設定缺項、陣列越界取值、或沒回傳的函式結果直接拿來運算。後果是執行期例外、型別錯誤，或默默使用有風險的預設值
		放行不該放行的操作。成因為把「應該有」當必然。修法是在使用前明確檢查值存在、非 undefined，並提供安全預設或直接拒絕。`,
		problem: `// 不安全寫法：直接讀取可能不存在的欄位，undefined 一路被當真值使用
function ratelimited(user) {
  return user.plan.rate > 5;   // user.plan 可能 undefined → 例外或誤判
}`,
		fixed: `// 安全寫法：逐層檢查存在性並提供安全預設，不再拿 undefined 運算
function ratelimited(user) {
  const rate = user?.plan?.rate ?? 0;   // 缺欄給預設
  return rate > 5;
}`,
		patch: `@@
-  return user.plan.rate > 5;
+  const rate = user?.plan?.rate ?? 0;
+  return rate > 5;`,
		refs: ['OWASP', 'CWE-232'],
		tags: ['undefined', 'null', 'validation'],
	},
	{
		id: 'CWE-233',
		name: 'Improper Handling of Parameters',
		lang: 'c',
		status: 'Complete',
		what: `參數處理不當。函式或端點收到的參數在型別、個數、順序或語意上不符合契約，程式卻在未驗證的情況下使用，或只處理參數的其中一種可能：
		例如把整數參數直接當長度、把可選字串參數不檢查空字串就做 strcpy／拼網址。成因是預設「參數永遠存在且符合預期」，又多做隱含型別轉換。
		後果包含越界、型別混淆與邏輯錯誤。修法是對每個參數驗證存在性、型別與範圍，符合契約才執行；不合即回錯誤，不硬做轉換。`,
		problem: `// 不安全寫法：直接當長度使用來路不一致的參數，負值/缺失造成向下去越界
void copy(const char *src, int n) {
    char buf[32];
    memcpy(buf, src, n);   // n 為負 → 轉成巨量 size_t → 越界
}`,
		fixed: `// 安全寫法：參數型別一致，先校驗範圍再使用
void copy(const char *src, size_t n) {
    if (n > 32) return;            // 上界校驗
    memcpy(buf, src, n);
}`,
		patch: `@@
-void copy(const char *src, int n) {
-    memcpy(buf, src, n);
+void copy(const char *src, size_t n) {
+    if (n > 32) return;
+    memcpy(buf, src, n);
+}`,
		refs: ['OWASP', 'CWE-233'],
		tags: ['parameters', 'argument', 'validation'],
	},
	{
		id: 'CWE-238',
		name: 'Improper Handling of Incomplete Structural Elements',
		lang: 'c',
		status: 'Complete',
		what: `結構元素不完整處理不當。如記錄以中斷結尾、封包缺尾欄位、XML 標籤未閉合、結構體欄位沒填滿時，程式假設結構完整便直接處理缺失的部分。
		例如只收到幾個位元組的記錄還去讀整欄、或對可能為空的字串做 strcmp。後果是解析混亂、越界讀取或邏輯誤判。成因為未在處理前驗證
		「元素實際長度／邊界」。修法是每個結構元素在存取前，先確認其存在且長度足夠，不完整即中止。`,
		problem: `// 不安全寫法：只確認「有收到 1 個位元組」就把整份欄位當作已存在
int parse(const char *p, int got) {
    if (got < 1) return -1;
    return p[0] + p[1] + p[2];   // got 只有 1 時，後段越界
}`,
		fixed: `// 安全寫法：以實際取得長度為準，長度不足即停止
int parse(const char *p, int got) {
    if (got < 3) return -1;         // 需要 3 位元組才繼續
    return p[0] + p[1] + p[2];
}`,
		patch: `@@
-    if (got < 1) return -1;
+    if (got < 3) return -1;
     return p[0] + p[1] + p[2];`,
		refs: ['CWE-238'],
		tags: ['structure', 'parse', 'incomplete'],
	},
	{
		id: 'CWE-239',
		name: 'Failure to Handle Incomplete Element',
		lang: 'c',
		status: 'Complete',
		what: `對不完整元素失於應對。此弱點重在「漏掉對應有的處置」：串流讀入半個封包、截斷的 UTF-8 序列或不完整符記時，程式仍把資料當
		完整元素處理，例如把半個封包解析、把截斷字串做機密比對。成因為忽視「資料常會被截斷或維度不足」的常態。後果是壞資料被誤當合法輸入
		而繞過檢查、或結構誤判。修法是對結構化輸入先強制一個「驗證完整性 → 再處理內容」的階段，數量不足時明確失敗。`,
		problem: `// 不安全寫法：把「期望長度」當成「實際拿到量」來解析，got 較小也不管
int recv_unit(int fd, char *buf, size_t want) {
    ssize_t got = read(fd, buf, want);
    return parse(buf, want);   // want 是期望不是拿到量；got < want 沒檢查
}`,
		fixed: `// 安全寫法：數量不符即視為不完整、拒絕解析
int recv_unit(int fd, char *buf, size_t want) {
    ssize_t got = read(fd, buf, want);
    if (got != (ssize_t)want) return -1;   // 未取足完整元素
    return parse(buf, want);
}`,
		patch: `@@
     ssize_t got = read(fd, buf, want);
-    return parse(buf, want);
+    if (got != (ssize_t)want) return -1;
+    return parse(buf, want);`,
		refs: ['CWE-239'],
		tags: ['incomplete', 'parse', 'truncation'],
	},
	{
		id: 'CWE-240',
		name: 'Improper Handling of Inconsistent Structural Elements',
		lang: 'c',
		status: 'Complete',
		what: `結構元素不一致處理不當。結構內「自我宣稱」的長度／個數與實際資料不一致時，程式不交叉驗證就照宣稱值去讀寫。最著名的例子是
		Heartbleed：封包標頭宣稱的長度大於實際資料，伺服器照宣稱長度回傳，把記憶體中不相干的機密一起吐出。成因是信任欄位自我宣稱，
		而不以實際緩衝區／欄位大小為準。後果是越界讀寫、敏感的記憶體內容外洩。修法是永遠以「實際緩衝區容量」當上限，任何宣稱的長度都要
		先與可信的實際大小核對後才使用。`,
		problem: `// 不安全寫法：照封包宣稱的長度回傳，未與實際封存到的量核對
void reply(int fd, unsigned short claimed, char *hb) {
    write(fd, hb, claimed);   // claimed 被誇大 → 多讀/回傳越界位元組（Heartbleed）
}`,
		fixed: `// 安全寫法：回覆長度以「實際封存到的量」為上限，不採信宣稱值
void reply(int fd, unsigned short claimed, char *hb, size_t actual) {
    size_t n = claimed < actual ? claimed : actual;   // 用實際容量封頂
    write(fd, hb, n);
}`,
		patch: `@@
-void reply(int fd, unsigned short claimed, char *hb) {
-    write(fd, hb, claimed);
+void reply(int fd, unsigned short claimed, char *hb, size_t actual) {
+    size_t n = claimed < actual ? claimed : actual;
+    write(fd, hb, n);
+}`,
		refs: ['CWE-240'],
		tags: ['length', 'heartbleed', 'bounds'],
	},
	{
		id: 'CWE-474',
		name: 'Use of Obsolete Function',
		lang: 'c',
		status: 'Complete',
		what: `使用已過時／危險的函式。程式使用了公認不安全、難以安全使用的舊函式，如 gets()、sprintf()、strcpy()、mktemp()、asctime()
		等，它們不檢查或難以檢查長度／隨機性，極易造成緩衝區溢位與可猜測檔名。成因是沿用舊習慣或貪圖簡便。後果常是記憶體破壞、命令注入
		與身分冒用。修法是改用現代取代品（fgets、snprintf、strlcpy、mkostemp），並開啟編譯器警告與安全旗標（-Wformat=2、_FORTIFY_SOURCE）。`,
		problem: `// 不安全寫法：用 gets() 讀入，超長輸入直接覆蓋返回位址
char buf[16];
gets(buf);            // 無上限，溢位可被利用`,
		fixed: `// 安全寫法：用 fgets 限制讀入量並處理截斷
char buf[16];
if (fgets(buf, sizeof buf, stdin)) {
    /* 正常處理，超長會自動截斷 */
}`,
		patch: `@@
-char buf[16];
-gets(buf);
+char buf[16];
+if (fgets(buf, sizeof buf, stdin)) {
+    /* 正常處理，超長會自動截斷 */
+}`,
		refs: ['CWE-474', 'OWASP'],
		tags: ['obsolete', 'gets', 'buffer'],
	},
	{
		id: 'CWE-606',
		name: 'Unchecked Input for Loop Condition',
		lang: 'c',
		status: 'Complete',
		what: `迴圈條件取自未檢查的輸入。迴圈的次數、步進或終止條件由使用者輸入決定，卻沒先校驗；巨量、負值或零值輸入會讓迴圈失控，
		造成 CPU 耗盡、窮舉失敗或越界。成因是把它當成「只是數字」的高貴輸入直接採用。後果是拒絕服務或邏輯破壞。修法是把該輸入在用作迴圈上限前，
		先約束到非負且合理的允許範圍，並設定絕對上限與型別。`,
		problem: `// 不安全寫法：次數直接來自輸入，可為巨大或負值，迴圈大量或永不結束
for (size_t i = 0; i < count_from_input; i++) work(i);   // 無上限`,
		fixed: `// 安全寫法：先以固定上限封頂，再跑迴圈
size_t n = count_from_input;
if (n > MAX_ITEMS) n = MAX_ITEMS;           // 上限封頂
for (size_t i = 0; i < n; i++) work(i);`,
		patch: `@@
-  for (size_t i = 0; i < count_from_input; i++) work(i);
+  size_t n = count_from_input;
+  if (n > MAX_ITEMS) n = MAX_ITEMS;
+  for (size_t i = 0; i < n; i++) work(i);`,
		refs: ['CWE-606'],
		tags: ['loop', 'dos', 'count'],
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
		id: 'CWE-673',
		name: 'External Influence of Sphere Definition',
		lang: 'javascript',
		status: 'Complete',
		what: `「允許範圍（sphere）定義」受到外部影響。系統把「這筆請求能授權做哪些事」的邊界，交由可被使用者影響的輸入來圈定，而未在信任邊界固定：
		例如以輸入挑選請求使用的角色、以可選的 group／scope 動態框出授權範圍、或用外部提供的時間窗／帳號來擠進判定。攻擊者可選取更寬的範圍，
		執行本不授權的動作或碰觸他人的資源。成因是權限判定的邊界欄位被外部控制又無白名單。修法是讓授權範圍由伺服器端固定的原則決定，
		外部輸入只用於嚴格等值比對，絕不拿來擴大範圍。`,
		problem: `// 不安全寫法：讓客戶端指定「以何種 scope 執行」，未驗證就代入（可選最寬 'admin'）
async function run(user, body) {
  const scope = body.scope;                 // 由使用者選定的作用域
  const svc = services.for(scope, user.id);
  return svc.doSensitive(body.action);        // 高權限邊界被外部決定
}`,
		fixed: `// 安全寫法：作用域由伺服端依已知角色固定，外部只給操作鍵並做白名單對照
const SCOPE_BY_ROLE = { admin: 'admin', user: 'standard' };
async function run(user, body) {
  const scope = SCOPE_BY_ROLE[user.role] ?? 'guest';   // 伺服端已知角色決定範圍
  const action = PUBLIC_ACTIONS[body.action];
  if (!action || !services.for(scope, user.id)[action]) throw new Error('denied');
  return services.for(scope, user.id)[action]();
}`,
		patch: `@@
-  const scope = body.scope;
-  const svc = services.for(scope, user.id);
-  return svc.doSensitive(body.action);
+  const scope = SCOPE_BY_ROLE[user.role] ?? 'guest';
+  const action = PUBLIC_ACTIONS[body.action];
+  if (!action || !services.for(scope, user.id)[action]) throw new Error('denied');
+  return services.for(scope, user.id)[action]();`,
		refs: ['OWASP', 'CWE-673'],
		tags: ['authorization', 'scope', 'bypass'],
	},
	{
		id: 'CWE-686',
		name: 'Function Call With Incorrect Argument Type',
		lang: 'c',
		status: 'Complete',
		what: `函式呼叫使用錯誤的參數型別。呼叫時傳入與函式契約不符的引數（把浮點當整數、字串當長度、列舉亂傳），程式往往因此做錯解讀或越界；
		C 的隱含型別轉換使這類錯誤最難以察覺。成因是型別放寬與「看起來差不多」就塞進去的僥倖心態。後果是型別混淆、越界讀寫與錯誤邏輯。
		修法是嚴格型別並開啟型別檢查警告（-Wconversion、-Wsign-compare），避免隱含轉換。`,
		problem: `// 不安全寫法：把 signed 數量型別當 size_t 使用，負值 → 巨型配置/越界
void read_blob(long nbytes) {
    char *b = malloc((size_t)nbytes);        // nbytes 為負 → 巨型配置
    read_bytes(b, (size_t)nbytes);
}`,
		fixed: `// 安全寫法：型別一致並先校驗非負與上界，再看用
void read_blob(size_t nbytes) {
    if (nbytes == 0 || nbytes > MAX) return;   // 上界保護
    char *b = malloc(nbytes);
    read_bytes(b, nbytes);
}`,
		patch: `@@
-void read_blob(long nbytes) {
-    char *b = malloc((size_t)nbytes);
-    read_bytes(b, (size_t)nbytes);
+void read_blob(size_t nbytes) {
+    if (nbytes == 0 || nbytes > MAX) return;
+    char *b = malloc(nbytes);
+    read_bytes(b, nbytes);
+}`,
		refs: ['CWE-686'],
		tags: ['argument-type', 'sign', 'type'],
	},
	{
		id: 'CWE-691',
		name: 'Insufficient Control Flow Management',
		lang: 'javascript',
		status: 'Complete',
		what: `控制流程管理不足。程式用不良的手法組織分支與狀態轉移（過度使用全域旗標、狀態沒有版本），或在條件與動作之間缺少明確界定，
		使某些路徑誤執行不該執行的動作、或相同輸入在無關變因下改變結果。後果可能是驗證被繞過、重入或邏輯錯誤。成因是流程的耦合與可變的全域狀態。
		修法是讓控制流程結構化、每個狀態轉移都明確且最小，並移除未受保護的繞道路徑。`,
		problem: `// 不安全寫法：先開權再檢查，檢查不過的早退路徑不會撤銷已頒發的權限
function process(entry) {
  openLock(entry.key);                     // 先授權
  if (entry.required && !entry.ok) return; // 早退，但 lock 仍開著
  touch(critical);
}`,
		fixed: `// 安全寫法：全部檢查通過後才頒發權限，流程不再有漏洞出口
function process(entry) {
  if (entry.required && !entry.ok) return; // 先檢查
  openLock(entry.key);                     // 通過後才授權
  touch(critical);
}`,
		patch: `@@
-  openLock(entry.key);
-  if (entry.required && !entry.ok) return;
-  touch(critical);
+  if (entry.required && !entry.ok) return;
+  openLock(entry.key);
+  touch(critical);`,
		refs: ['OWASP', 'CWE-691'],
		tags: ['control-flow', 'state', 'logic'],
	},
	{
		id: 'CWE-697',
		name: 'Incorrect Comparison',
		lang: 'javascript',
		status: 'Complete',
		what: `不正確的比較。比較時用錯運算子、瞄錯欄位或未正規化兩端：用寬鬆相等（==）比型別不同的值、把顯示用的舍入值當安全判定、忽略大小寫、
		時區或前導零而使不同值被當相同（或相同被當不同）。後果是驗證被繞過、條件判定失準或授權誤判。成因是「比較語意」與「顯示語意」混用。
		修法是使用型別嚴格的比較（===），先將兩端正規化到一致的表示，並釐清「相等」的準確定義。`,
		problem: `// 不安全寫法：用 == 比數字與字串，'007' 與 7 視為相等，也易踩型別轉換
if (userInput == storedPin) grant();       // 型別相異卻相等 → 可偽造`,
		fixed: `// 安全寫法：兩端轉成同型別後用全等比較
if (String(userInput) === String(storedPin)) grant();   // 皆當字串、全等比較`,
		patch: `@@
-  if (userInput == storedPin) grant();
+  if (String(userInput) === String(storedPin)) grant();`,
		refs: ['OWASP', 'CWE-697'],
		tags: ['comparison', 'equality', 'bypass'],
	},
	{
		id: 'CWE-705',
		name: 'Incorrect Control Flow Scoping',
		lang: 'javascript',
		status: 'Complete',
		what: `控制流程作用域錯誤。條件、迴圈或區塊的邏輯歸屬錯置：else 連到錯的 if、初始化放在條件外、guard 包錯區塊，或受縮排誤導而把本屬別層的
		程式看成同一層，使該受某條件限制的程式仍執行、或該保證的步驟沒執行。後果是繞過限制或漏做保護。成因是大區塊與隱式結尾造成隸屬不清。
		修法是釐清每個分支的隸屬關係、用顯式括號與極小區塊，並以各分支邊界測試驗證。`,
		problem: `// 不安全寫法：else 因縮排而誤屬上方不同的 if，admin 條件分支被隸屬錯亂
if (user.role === 'admin')
  if (user.active) allowAdmin();
else
  deny();          // 此 else 綁到「第二個 if」，與 admin 條件無關`,
		fixed: `// 安全寫法：顯式括號讓每一層的隸屬完全明確
if (user.role === 'admin') {
  if (user.active) allowAdmin(); else denyAdmin();
} else {
  deny();
}`,
		patch: `@@
-if (user.role === 'admin')
-  if (user.active) allowAdmin();
-else
-  deny();
+if (user.role === 'admin') {
+  if (user.active) allowAdmin(); else denyAdmin();
+} else {
+  deny();
+}`,
		refs: ['OWASP', 'CWE-705'],
		tags: ['scoping', 'if-else', 'bypass'],
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
		id: 'CWE-1284',
		name: 'Improper Validation of Specified Quantity in Input',
		lang: 'c',
		status: 'Complete',
		what: `輸入指定數量驗證不當。輸入帶有「數量／計數」欄位（要讀多少筆、配多大、處理幾次），程式把這個數量拿來配置或做迴圈，卻沒跟實際
		資源交叉驗證：高估造成緩衝區／整數溢位，低估造成資料短缺、隨後越界讀。成因是信任自我宣稱的數量而不核對資源上限。修法是對數量做非負、
		型別與上限校驗，並以實際可用容量封頂、拒絕極值。`,
		problem: `// 不安全寫法：用輸入的筆數直接配置 + 填，count 過大即溢位
struct item *items = malloc(count * sizeof(*items));   // 數量不可信、可為巨量
for (size_t i = 0; i < count; i++) fill(items, i);`,
		fixed: `// 安全寫法：先對數量做型別與上限校驗，再以合理值配置
if (count <= 0 || count > MAX_ITEMS) return -1;    // 上界保護
struct item *items = calloc((size_t)count, sizeof(*items));
for (size_t i = 0; i < (size_t)count; i++) fill(items, i);`,
		patch: `@@
-  struct item *items = malloc(count * sizeof(*items));
+  if (count <= 0 || count > MAX_ITEMS) return -1;
+  struct item *items = calloc((size_t)count, sizeof(*items));
   for (size_t i = 0; i < count; i++) fill(items, i);`,
		refs: ['OWASP', 'CWE-1284'],
		tags: ['quantity', 'count', 'bounds'],
	},
	{
		id: 'CWE-1287',
		name: 'Improper Validation of Specified Index in Product',
		lang: 'c',
		status: 'Complete',
		what: `輸入指定索引／位置時驗證不當。程式接受使用者給的陣列索引、位移或下標，卻在確認它在界限內之前就拿去解參考，未處理負值、越過長度
		的情況，造成越界讀寫。成因是預設「外送的下標一定有效」。後果是緩衝區溢位、資訊外洩與當機。修法是先檢查索引落在 0 <= i < length
		（或位移在合法範圍）後才存取，並保持型別一致。`,
		problem: `// 不安全寫法：直接用外部索引取項，負值或過長就向下/向上越界
T pick(int idx) {
    return arr[idx];   // idx 為負或 >= size 越界`,
		fixed: `// 安全寫法：型別一致（size_t）並檢查範圍後才存取
T pick(size_t idx) {
    if (idx >= ARR_LEN) return sentinel;   // 範圍檢查
    return arr[idx];
}`,
		patch: `@@
-T pick(int idx) {
-    return arr[idx];
+T pick(size_t idx) {
+    if (idx >= ARR_LEN) return sentinel;
+    return arr[idx];
+}`,
		refs: ['OWASP', 'CWE-1287'],
		tags: ['index', 'bounds', 'oob'],
	},
];
