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
];