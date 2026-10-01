// CWE chunk — category: Web · XSS-server & XML & SSI injection.
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
		id: 'CWE-74',
		name: "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')",
		lang: 'javascript',
		status: 'Complete',
		what: `下游元件注入（Injection 母類別）。程式把上游（通常是使用者）提供的資料送到某個下游元件去解析或執行，
	卻沒有先把下游會當成語法意義的特殊元素中立化，例如直接把字串丟給 eval、條件式、模板引擎、命令列或另一個子系統的設定檔。
	於是「資料」被下游消費者改寫成「程式／結構」，成為 SQL、命令、模板、XPath 等各類具體注入的共同根源。
	成因是沒還原下游消費端的解析規則，又用字串拼接把值直接組進去。修法是用該下游元件的參數化／建構式介面傳值，
	並針對元件保留字元做輸出側轉義，絕不在別處「補救」。`,
		problem: `// 不安全寫法：把使用者字串直接塞進今後會被下游模板引擎重新解析的內容
function compose(fragment) {
  // fragment 若含 {{ config.password }} 這種模板控制字元，就重入下游樣板語法
  return "<div>" + fragment + "</div>";   // 資料與控制不分離
}`,
		fixed: `// 安全寫法：值由建構式／文字節點傳遞，模板引擎的控制字元不會被當成語法
function compose(fragment) {
  const node = document.createElement('div');
  node.textContent = fragment;       // 資料永遠只是文字，不被下游任何語法解析
  return node;
}`,
		patch: `@@
-  return "<div>" + fragment + "</div>";
+  const node = document.createElement('div');
+  node.textContent = fragment;
+  return node;`,
		refs: ['OWASP', 'CWE-74'],
		tags: ['injection', 'downstream', 'templating'],
	},
	{
		id: 'CWE-75',
		name: 'Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)',
		lang: 'python',
		status: 'Complete',
		what: `跨層面特殊元素未消毒（Special Element Injection）。某筆輸入被安全端當成「值層面」的資料，卻可藉保留字元重新進入下游的「控制層面」
	（從資料平面跳回指令平面），例如把值寫進設定檔後被 shell source、把值放進會被求值的欄位、或因換行／結尾字元產生新的指令片段。
	成因是同一個值沒有因其「消費端語法」做中立化，防禦只假設它永遠是資料。後果從資訊外洩到任意命令執行。
	修法是為每個最終消費端套用對應的轉義或允許字元集，使值在任何層面都不具語法意義。`,
		problem: `# 不安全寫法：把使用者輸入寫成設定行，之後若被 shell source()，值可重入指令層面
def set_limit(name, value):
    with open("/etc/app.conf", "a") as f:
        f.write(name + "=" + value + "\\n")
        # value 若為 "$(id)  ..." 或含 ';'、'|' 即被 shell 解成命令`,
		fixed: `# 安全寫法：逐值做允許字元集校驗，任何 shell／指令元字元一律拒絕
import re
def set_limit(name, value):
    if not re.fullmatch(r"[A-Za-z0-9_,.:@/-]+", value):
        raise ValueError("unsafe value")          # 值不可能帶出控制層面
    with open("/etc/app.conf", "a") as f:
        f.write(name + "=" + value + "\\n")`,
		patch: `@@
+import re
 def set_limit(name, value):
+    if not re.fullmatch(r"[A-Za-z0-9_,.:@/-]+", value):
+        raise ValueError("unsafe value")
     with open("/etc/app.conf", "a") as f:
-        f.write(name + "=" + value + "\\n")
+        f.write(name + "=" + value + "\\n")`,
		refs: ['OWASP', 'CWE-75'],
		tags: ['injection', 'plane', 'meta', 'command'],
	},
	{
		id: 'CWE-77',
		name: "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
		lang: 'python',
		status: 'Complete',
		what: `命令注入（Command Injection）。把使用者輸入拼接進要交給作業系統執行的命令字串，
	並經由 system()、subprocess(shell=True)、exec* 或呼叫 shell 的方式運行，輸入中的 ; | & $( ) \` 或換行
	便脫離「引數」變成「新命令」，達成任意指令執行。成因是有意／無意啟用外層 shell，並用字串組命令而不以清單傳引數。
	修法是絕不經過 shell，直接以「可執行檔＋引數陣列」的形式呼叫，同時用允許清單把輸入條件約束在合理格式。`,
		problem: `# 不安全寫法：字串拼接再進 shell，input 可帶 ; rm -rf / 或 $(id)
import subprocess
host = request.form["host"]
out = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)`,
		fixed: `# 安全寫法：list 形態不開外層 shell，且只放行主機名字元集合
import re, subprocess
host = request.form["host"]
if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
    raise ValueError("bad host")
out = subprocess.run(["ping", "-c", "1", host], capture_output=True)`,
		patch: `@@
-  out = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)
+  if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
+      raise ValueError("bad host")
+  out = subprocess.run(["ping", "-c", "1", host], capture_output=True)`,
		refs: ['OWASP-CommandInjection', 'CWE-77'],
		tags: ['command', 'rce', 'injection', 'os'],
	},
	{
		id: 'CWE-80',
		name: 'Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)',
		lang: 'php',
		status: 'Complete',
		what: `基礎 XSS。把使用者輸入直接注入網頁 HTML，而且沒有做完整輸出編碼，導致 <script>、<img onerror>、javascript: 開頭的字串等
	「腳本相關的 HTML」得以原樣進到使用者瀏覽器執行。成因是仰賴簡陋黑名單或乾脆不編碼，直接把輸入塞進 echo／innerHTML。
	它屬於 XSS 家族較基本的成員，仍可偷 cookie、竄改頁面。修法是在輸出邊界對所有 HTML 語法字元做完整轉義，
	或以 DOM textContent／樣板框架渲染取代字串拼接。`,
		problem: `<?php
// 不安全寫法：把 query 直接 echo 進 HTML，q 帶標籤即被執行
$q = $_GET['q'];
echo "<p>搜尋結果：$q</p>";   // 傳 ?q=<script>alert(1)</script> 即執行
?>`,
		fixed: `<?php
// 安全寫法：輸出端一律 htmlspecialchars 完整轉義，標籤只會被當純文字印出
$q = htmlspecialchars($_GET['q'] ?? '', ENT_QUOTES, 'UTF-8');
echo "<p>搜尋結果：$q</p>";
?>`,
		patch: `@@
  $q = $_GET['q'];
-  echo "<p>搜尋結果：$q</p>";
+  $q = htmlspecialchars($q ?? '', ENT_QUOTES, 'UTF-8');
+  echo "<p>搜尋結果：$q</p>";`,
		refs: ['OWASP-XSS', 'CWE-80'],
		tags: ['web', 'xss', 'output-encoding', 'html'],
	},
	{
		id: 'CWE-83',
		name: 'Improper Neutralization of Script in Attributes in a Web Page',
		lang: 'javascript',
		status: 'Complete',
		what: `屬性內腳本注入（Attribute-Based XSS）。把使用者輸入以字串拼接塞進 HTML 標籤屬性值，且未對引號、<、> 與 javascript: 做轉義，
		攻擊者可塞 javascript:alert(1) 或注入自己的屬性（如 onmouseover）來執行程式碼。未加引號的屬性（a=輸入+空格+更多屬性）最危險，
		空格就能中斷屬性，之後的任何屬性都能被攻擊者偽造。建議做法是徹底屬性轉義，或改用 textContent／建 DOM 節點由框架自動編碼。`,
		problem: `// 不安全寫法：URL 直接拼進未加引號的 href 屬性，輸入可中斷屬性後加事件 handler
function linkTo(url, text) {
  return '<a href=' + url + ' title=' + text + '>link</a>';
  // url 帶 "javascript:alert(1)" 或 "x onmouseover=alert(1)" 即觸發 XSS
}`,
		fixed: `// 安全寫法：建立節點用 setAttribute/textContent，值一律被當純文字與屬性值，不做 HTML 語法解析
function linkTo(url, text) {
  const a = document.createElement('a');
  a.setAttribute('href', url);   // 屬性值自動編碼，空格與引號不會中斷屬性
  a.textContent = text;          // 文字只當純文字，不會被當標籤執行
  return a;
}`,
		patch: `@@
-  return '<a href=' + url + ' title=' + text + '>link</a>';
+  const a = document.createElement('a');
+  a.setAttribute('href', url);
+  a.textContent = text;
+  return a;`,
		refs: ['OWASP-XSS', 'CWE-83'],
		tags: ['web', 'xss', 'attribute', 'output-encoding'],
	},
	{
		id: 'CWE-87',
		name: 'Improper Neutralization of Alternative XSS Syntax',
		lang: 'python',
		status: 'Complete',
		what: `替代 XSS 語法注入。清除腳本時只擋了最常見的 <script> 或雙引號、尖括號，卻漏掉 HTML entity、十六進位／十進位字元參照、
		反斜線、條件註解與各種事件處理器（event handler）等被瀏覽器寬鬆解析的替代語法，攻擊者靠這些不被攔截的寫法照樣觸發腳本。建議做法是
		用單一、完整的輸出編碼管線（如往 HTML 時統一做 &quot;&#x3C; 等完整轉義），別只做黑名單字面遮蔽。`,
		problem: `# 不安全寫法：只把 <script> 換掉，其他等效語法的攻擊輸入仍然通過伺服器渲染
def render(user_input):
    blocked = user_input.replace("<script>", "").replace("</script>", "")
    # 輸入 "<scr<script>ipt>alert(1)</scr</script>ipt>" 去掉 <script> 後仍是
    # 可執行的 <script>alert(1)</script>；&#x3C;script&#x3E; 照樣被瀏覽器解碼後執行
    return "<div>" + blocked + "</div>"`,
		fixed: `# 安全寫法：渲染階段對 HTML 語法意義的字元做完整轉義，別用黑名單替換
from html import escape
def render(user_input):
    # 把 < > & " ' 一次全轉義，任何 alternative XSS 語法都失去執行能力
    return "<div>" + escape(user_input, quote=True) + "</div>"`,
		patch: `@@
-    blocked = user_input.replace("<script>", "").replace("</script>", "")
-    return "<div>" + blocked + "</div>"
+    from html import escape
+    return "<div>" + escape(user_input, quote=True) + "</div>"`,
		refs: ['OWASP-XSS', 'CWE-87'],
		tags: ['web', 'xss', 'output-encoding', 'sanitization'],
	},
	{
		id: 'CWE-88',
		name: "Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')",
		lang: 'python',
		status: 'Complete',
		what: `引數注入（Argument Injection）。即使應用沒有啟用外層 shell、也沒讓輸入被當程式碼執行，
	只要把使用者輸入以字串拼接組命令列，攻擊者就能用「引數分隔」──把輸入存進以 '-' 開頭的新旗標、或塞進空白分隔的新引數──
	讓輸入不只是「一個引數的值」，而能觸發額外選項或檔案。例如把輸入當 grep 樣式，輸入以 - 開頭就變成選項而非樣式。
	成因是用字串組「命令＋引數」而非引數陣列。修法是永遠以 exec-array 傳遞引數，並常用裸單元 "--" 結束選項宣告，
	讓後續一律被當位置引數。`,
		problem: `# 不安全寫法：樣式拼成字串丟給 grep，樣式如果以 "-" 開頭會被當成旗標
import subprocess
pat = request.form["pattern"]
# pat = "-e x /etc/shadow --" → grep -e x /etc/shadow，讀到敏感檔
subprocess.run("grep " + pat, shell=False)`,
		fixed: `# 安全寫法：引數以 list 傳遞，並用 "--" 終結選項，輸入不會被當成旗標
import subprocess
pat = request.form["pattern"]
subprocess.run(["grep", "--", pat])   # "--" 之後一律是位置（樣式）引數`,
		patch: `@@
-  subprocess.run("grep " + pat, shell=False)
+  subprocess.run(["grep", "--", pat])`,
		refs: ['OWASP-CommandInjection', 'CWE-88'],
		tags: ['argument-injection', 'command', 'option', 'injection'],
	},
	{
		id: 'CWE-91',
		name: 'XML Injection (also referred to as Blind XPath Injection)',
		lang: 'python',
		status: 'Complete',
		what: `XML／XPath 注入。直接用字串拼接把使用者輸入組進 XML 文件或 XPath 查詢，未轉義 XML 保留字元（< > & ' "），
		攻擊者可注入自訂元素、偽造節點、閉合標籤、改寫結構；寫在 XPath 查詢時還能用特殊運算子達成盲注入列舉資料。
		建議做法是用 XML 建構工具／XML 資料綁定（如 lxml 絕不 hand-build XML），並對屬性值與文字節點做轉義，查詢偏好只用參數或固定準則。`,
		problem: `# 不安全寫法：把使用者名稱直接拼進 XML，可注入 </user><admin>...</admin> 或亂改結構
def to_xml(username):
    # username 帶 "</user><user priv='admin'>alice</user>" 就能塞進新的使用者節點
    return "<user><name>" + username + "</name></user>"`,
		fixed: `# 安全寫法：用 ElementTree 建構 XML，內容自動轉義，不再有字串拼接注入
from xml.sax.saxutils import escape
def to_xml(username):
    return "<user><name>%s</name></user>" % escape(username)`,
		patch: `@@
-    return "<user><name>" + username + "</name></user>"
+    from xml.sax.saxutils import escape
+    return "<user><name>%s</name></user>" % escape(username)`,
		refs: ['OWASP-XPathInjection', 'CWE-91'],
		tags: ['web', 'xml', 'xpath', 'injection'],
	},
	{
		id: 'CWE-97',
		name: 'Improper Neutralization of Server-Side Includes (SSI) Within a Web Page',
		lang: 'python',
		status: 'Complete',
		what: `伺服器端內嵌（SSI）注入。在啟用 Server-Side Includes 的 .shtml 頁面中直接用使用者輸入組出 <!--#include file="…" -->、
		<!--#exec cmd="…" --> 等指令，卻沒先限制，攻擊者可指向伺服器上的敏感檔，或搭配 #exec 執行作業系統命令跨入 RCE。
		建議做法是對包含檔名做允許清單＋僅允許預定義實體檔，或完全關閉 SSI、改用不含伺服器指令的樣板引擎。`,
		problem: `# 不安全寫法：把使用者輸入直接拼進 SSI #include 的 file 指令，可帶 ../../etc/passwd
file_path = request.args.get("file")
# 生成的 .shtml 若是 <!--#include file="../../../../etc/passwd" --> 即讀出系統檔內容
ssi_fragment = "<!--#include file=\\"" + file_path + "\\" -->"`,
		fixed: `# 安全寫法：接受使用者輸入的對照表鍵，最後只指向預先定義的實體檔，且禁用 #exec
FRAGMENTS = {"header": "/include/header.shtml", "footer": "/include/footer.shtml"}
key = request.args.get("frag", "header")
f = FRAGMENTS.get(key, "/include/header.shtml")   # 未命中也只回預設片段，永不讀外部檔名
render_ssi(f)`,
		patch: `@@
-file_path = request.args.get("file")
-ssi_fragment = "<!--#include file=\\"" + file_path + "\\" -->"
+FRAGMENTS = {"header": "/include/header.shtml", "footer": "/include/footer.shtml"}
+key = request.args.get("frag", "header")
+f = FRAGMENTS.get(key, "/include/header.shtml")
+render_ssi(f)`,
		refs: ['OWASP-SSIInjection', 'CWE-97'],
		tags: ['web', 'ssi', 'shtml', 'injection', 'include'],
	},
	{
		id: 'CWE-436',
		name: 'Interpretation Conflict',
		lang: 'javascript',
		status: 'Complete',
		what: `詮釋衝突（Interpretation Conflict）。同一段輸入被多個元件各用不同的規則解讀，而安全判斷（白名單、驗證、連結繞檢）用的是其中一種詮釋，
	實際執行卻用另一種──例如一次解碼、大小寫不敏感、路徑別名、正規化差異或 URL 組成分歧。攻擊者送出「安全端看起來無害」、執行端卻「有害」的形式，
	於是繞過檢查。成因是各層編碼／正規化規則不一致，又在不同階段取樣比對。修法是在信任邊界做一次、統一的 canonicalization，然後一律以正規化後的形式做比對，
	不讓同一資料被兩種語法各自消費。`,
		problem: `// 不安全寫法：攔檢看「原始字串」，讀檔卻用「已解碼字串」，電子成兩套詮釋
function serve(req) {
  const raw = req.url;
  if (raw.includes('..')) throw new Error('blocked');   // 安全端：還未解碼的原文
  return fs.readFile('/srv/docs/' + decodeURIComponent(raw));
  // %2e%2e%2f.. 在解碼後變成 ../，逃過對原文的檢查
}`,
		fixed: `// 安全寫法：先統一解碼與正規化到單一表示，再於同一表示上檢驗
function serve(req) {
  const decoded = decodeURIComponent(req.url);             // 先 canonicalize
  if (decoded.includes('..')) throw new Error('blocked'); // 與存取用同一種表示
  return fs.readFile('/srv/docs/' + decoded);
}`,
		patch: `@@
-  const raw = req.url;
-  if (raw.includes('..')) throw new Error('blocked');
-  return fs.readFile('/srv/docs/' + decodeURIComponent(raw));
+  const decoded = decodeURIComponent(req.url);
+  if (decoded.includes('..')) throw new Error('blocked');
+  return fs.readFile('/srv/docs/' + decoded);`,
		refs: ['OWASP', 'CWE-436'],
		tags: ['canonicalization', 'bypass', 'encoding'],
	},
	{
		id: 'CWE-451',
		name: 'User Interface (UI) Misrepresentation of Critical Information',
		lang: 'javascript',
		status: 'Complete',
		what: `關鍵資訊的 UI 誤導（UI Spoofing）。介面顯示網址、檔名、寄件者、安全狀態等重要資訊時與實際內容不一致，例如顯示看似無害的文字或網址卻連到別處、
	用全形／同形字（0/O、1/l）擾亂比對、隱藏真實 target，或複製貼上被變造的字串。攻擊者利用視覺混淆，誘使使用者授權或點選原本不會同意的操作，
	屬社交／介面欺騙。成因是「顯示的」與「實際使用的」資料非同源，或未在渲染前正規化比較。修法是直接以實際目標資料渲染、只顯示可核實的來源欄位（如 hostname），
	並對字形混淆做正規化。`,
		problem: `// 不安全寫法：顯示文字與 href 可分別由使用者控制，介面與實際目的地分道揚鑣
function renderLink({ text, href }) {
  return '<a href="' + href + '">' + text + '</a>';
  // 送出 text="前往銀行"、href="http://evil-ｅxample.net/x" 即以偽裝字誘使點擊
}`,
		fixed: `// 安全寫法：顯示內容一律派生自已核實的實際 href，不採信自稱的顯示文字
function renderLink({ href }) {
  const u = new URL(href);
  if (u.protocol !== 'https:') return null;       // 只看允許的實際目標
  return '<a href="' + u.href + '">' + u.hostname + '</a>'; // 顯示取自網址本身
}`,
		patch: `@@
-  return '<a href="' + href + '">' + text + '</a>';
+  const u = new URL(href);
+  if (u.protocol !== 'https:') return null;
+  return '<a href="' + u.href + '">' + u.hostname + '</a>';`,
		refs: ['OWASP', 'CWE-451'],
		tags: ['ui', 'spoofing', 'misrepresentation'],
	},
	{
		id: 'CWE-670',
		name: 'Always-Incorrect Control Flow Implementation',
		lang: 'javascript',
		status: 'Complete',
		what: `恆錯誤的控制流程實作。某條控制流程邏輯註定不會照預期作用──例如 if／else 條件永遠為真或恒假、用錯邏輯運算子、迴圈永不執行或永不停、
	該走的防護分支正好落在未執行處──使得重要的授權或檢查形同虛設。成因常是把 && 與 || 弄反、比較寫成永真的或然判斷，或因 operator precedence 錯配括號。
	後果是驗證被跳過、重複執行或功能整段失效。修法是簡化每個分支、用最小真值表思考、以正反測試驗證各條件可達性，並移除永不執行的死路徑。`,
		problem: `// 不安全寫法：條件恒真，角色檢查形同不存在，人人通過授權
function isPrivileged(role) {
  return role !== 'admin' || role !== 'root';   // 兩邊恒有一個成立 → 永遠 true
}
if (isPrivileged(req.user.role)) { grant(); }   // grant 對所有人都會執行`,
		fixed: `// 安全寫法：改為「其中一者成立才授權」，else 明確拒絕其餘身份
function isPrivileged(role) {
  return role === 'admin' || role === 'root';    // 只有這兩個才過
}
if (isPrivileged(req.user.role)) { grant(); } else { deny(); }`,
		patch: `@@
-  return role !== 'admin' || role !== 'root';
+  return role === 'admin' || role === 'root';
   if (isPrivileged(req.user.role)) { grant(); }
+  else { deny(); }`,
		refs: ['OWASP', 'CWE-670'],
		tags: ['control-flow', 'logic', 'bypass'],
	},
	{
		id: 'CWE-707',
		name: 'Improper Neutralization',
		lang: 'javascript',
		status: 'Complete',
		what: `不當的中立化（Improper Neutralization，注入類的根因）。「中立化」指讓下游元件不會把特殊元素誤當成語法意義的動作，
	包括輸入校驗、轉義、過濾、參數化與封裝。此弱點表示該做的中立化沒做、做錯、或做在不對的階段（太早針對與消費端不同的表示、或只在輸入端做而輸出端另行拼接）。
	結果不可信輸入以消費端看得懂的語法原樣抵達下游，成為 XSS、SQLi、命令注入等一切注入類弱點共通的起源。修法是辨識「各消費端如何解讀字元」，
	並在其各自輸出／消費邊界做正確且完整的中立化。`,
		problem: `// 不安全寫法：只在輸入端清洗一次，輸出端卻在另一條路徑重新拼回，中立化架在錯的層
function render(name) {
  const safe = name.replace(/<script>/gi, '');   // 輸入端黑名單清洗
  return '<div>' + safe + '</div>';              // 輸出端沒有自己的編碼，替身語法仍有效
}`,
		fixed: `// 安全寫法：把中立化做在各消費端的輸出邊界，統一完整轉義
function render(name) {
  return '<div>' + escapeHtml(name) + '</div>';  // < > & " ' 輸出時一次全轉義
}
function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}`,
		patch: `@@
-  const safe = name.replace(/<script>/gi, '');
-  return '<div>' + safe + '</div>';
+  return '<div>' + escapeHtml(name) + '</div>';
+  function escapeHtml(s) {
+    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
+      .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
+  }`,
		refs: ['OWASP', 'CWE-707'],
		tags: ['neutralization', 'injection', 'output-encoding'],
	},
	{
		id: 'CWE-1236',
		name: 'Improper Neutralization of Formula Elements in a CSV File',
		lang: 'python',
		status: 'Complete',
		what: `CSV 公式注入（CSV / Formula Injection）。把使用者輸入直接寫進 CSV，當某儲存格內容以 =、+、-、@ 開頭時，
	試算表（Excel、LibreOffice）會把內容當公式而非文字執行，例如 =HYPERLINK(...) 竊取資料、=cmd|' /C calc'!A0 在開啟時執行命令、或 @SUM 拉外部連結。
	成因是把 CSV 當純文字直接 join／拼，未對公式開頭字元防護。修法是對以 = + - @ 開頭的字串值加前置單引號、將公式語法中性化，
	或改用強制「純文字」格式的匯出方式，並讓使用者不得開啟不明來源的試算表。`,
		problem: `# 不安全寫法：欄位原樣寫入 CSV，開頭為 = 的儲存格會被試算表當公式執行
import csv, io
buf = io.StringIO(); w = csv.writer(buf)
w.writerow([name, email])
# name = "=HYPERLINK(\\"http://evil\\")" 開啟 CSV 即被觸發；=cmd|命令開頭亦可執行`,
		fixed: `# 安全寫法：對公式開頭字元做前置單引號／轉義，使儲存格僅被當文字
def cell(v):
    if isinstance(v, str) and (not v or v[0] in ('=', '+', '-', '@')):
        return "'" + v          # 前置 ' 讓試算表視為純文字
    return v
w.writerow([cell(name), cell(email)])`,
		patch: `@@
-  w.writerow([name, email])
+  def cell(v):
+      if isinstance(v, str) and (not v or v[0] in ('=', '+', '-', '@')):
+          return "'" + v
+      return v
+  w.writerow([cell(name), cell(email)])`,
		refs: ['OWASP', 'CWE-1236'],
		tags: ['csv', 'formula', 'injection', 'spreadsheet'],
	},
];
