// CWE chunk — 類別：特殊元素中性化、處理順序、編碼、數值轉型與可觀察差異 (Input Neutralization, Ordering, Encoding & Numeric/Observability).
// One chunk = one category. Every entry:
//   status  : Complete | Deprecated
//   refs    : MITRE / OWASP 等
export default [
	{
		id: 'CWE-152',
		name: 'Improper Neutralization of Macro Symbols',
		lang: 'python',
		status: 'Complete',
		what: `巨集符號未被中立化。程式的資料會送往下游元件，而下游把某些字元當成巨集符號解讀（例如批次檔的 %name%、
		m4/preprocessor 的 $id、LLM 提示詞裡的 {slot}、電子郵件的 placeholder token）。若來自上游的輸入含有這類符號
		又沒在中立化後再交出去，巨集字元及其包裹內容就會被代換、展開成非預期的值或指令，形同一種注入。成因是未在送往下游
		前把「會被當成巨集」的特殊字元轉義或隔離。後果依下游而定，可能是選單項目竄改、組態被重寫或命令被執行。修法是對
		巨集符號做專屬轉義，或讓資料透過不具巨集語意的容器傳遞，使任何巨集字眼都失去結構意義。`,
		problem: `# 不安全寫法：把輸入直接塞進會展開巨集的模板，slot 被代換
def render(tmpl, user_input):
    return tmpl.safe_substitute(_v=user_input)  # 輸入含 {slot} 即被展開`,
		fixed: `# 安全寫法：先阻絕整組巨集符號、或轉義後再代入模板
def render(tmpl, user_input):
    if "{" in user_input or "}" in user_input:
        raise ValueError("macro symbol not allowed")
    return tmpl.safe_substitute(_v=user_input)`,
		patch: `@@
  def render(tmpl, user_input):
+    if "{" in user_input or "}" in user_input:
+        raise ValueError("macro symbol not allowed")
      return tmpl.safe_substitute(_v=user_input)`,
		refs: ['CWE-152', 'OWASP'],
		tags: ['macro', 'template', 'injection'],
	},
	{
		id: 'CWE-153',
		name: 'Improper Neutralization of Substitution Characters',
		lang: 'python',
		status: 'Complete',
		what: `濁變／取代字元未被中立化。下游元件使用特殊的替換字元來代表「此處插入一個變數或參照」——shell 的 $VAR、
		字串替換函式的通配、組態展開器的 name 槽。若上游輸入含這類字元而未先中立化，替換字的位置就會被來自使用者的資料
		觸發，令原本的純資料被解讀成「取變數」或「插入外部值」，改變最後拼出的值。成因是沒把「會被下游解讀為取代語法」的
		字元過濾或轉義。後果常是組態、訊息或命令公式被竄改，沿下游可演變成注入或資訊外洩。修法是對取代字元做轉義，
		或避免讓使用者資料進入任何以取代符號解釋內容的函式，改以資料參數方式傳遞。`,
		problem: `# 不安全寫法：輸入含 'yes; rm -rf /' 直接接進 shell 字串，$() 與 ; 皆達意
import subprocess
def confirm(choice):
    return subprocess.check_output("echo "[job choice]"" + choice, shell=True)`,
		fixed: `# 安全寫法：不以 shell 展開、把值當單一引數，取代符無從解析
import subprocess
def confirm(choice):
    return subprocess.check_output(["echo", "ok:", choice])`,
		patch: `@@
  def confirm(choice):
-    return subprocess.check_output("echo " + choice, shell=True)
+    return subprocess.check_output(["echo", "ok:", choice])`,
		refs: ['CWE-153', 'OWASP'],
		tags: ['substitution', 'shell', 'injection'],
	},
	{
		id: 'CWE-154',
		name: 'Improper Neutralization of Variable Name Delimiters',
		lang: 'javascript',
		status: 'Complete',
		what: `變數名定界符未被中立化。下游語法用特定字元標示「變數名的邊界」（例如 %name%、[[var]]、{{var}}、
		$(name)），程式把資料拼進這種位置卻未消毒定界符，使用者輸入內的定界符就可提早關閉或展開成新的變數參照。
		典型後果是讓資料被當成「變數名」去取值、或插入任意的變數參照，揭露或改寫本屬內部的值。成因是把資料直接放進
		以定界符解析的下游而未轉義定界符本身。修法是轉義或拒絕所有定界符，或改用不靠定界符表示變數的安全 API
		傳遞值。`,
		problem: `// 不安全寫法：資料直接拼進以 [[...]] 定界的變數槽，輸入可展開任意變數
function expand(tmpl, who) {
  return tmpl.replace(/\\[\\[(\\w+)\\]\\]/g, (m, k) => who ? env[k] : k);
  return tmpl.replace('[[name]]', who);   // who=" ]][[ADMIN]]..." 注入變數參照
}`,
		fixed: `// 安全寫法：先封鎖定界符，再以固定關鍵字＝純值替換
function expand(tmpl, who) {
  if (/[\\[\\]]/.test(who)) throw new Error('delimiter not allowed');
  return tmpl.replace('[[name]]', who);
}`,
		patch: `@@
  function expand(tmpl, who) {
-  return tmpl.replace('[[name]]', who);
+  if (/[\\[\\]]/.test(who)) throw new Error('delimiter not allowed');
+  return tmpl.replace('[[name]]', who);
  }`,
		refs: ['CWE-154', 'OWASP'],
		tags: ['delimiter', 'variable', 'template'],
	},
	{
		id: 'CWE-155',
		name: 'Improper Neutralization of Wildcards or Matching Symbols',
		lang: 'javascript',
		status: 'Complete',
		what: `萬用字元／比對符未被中立化。下游系統（檔案系統、目錄列舉、資料查詢、存取控制）以 *、?、[abc] 這類萬用
		與比對符號做樣式比對。若使用者輸入帶有這些符號而未消毒，單一名稱就可能膨脹成匹配一堆檔案或記錄的樣式，觸發
		非預期的搜尋、刪除與列舉。成因是把資料直接交給做 global/pattern match 的下游而未轉義萬用字元。後果包括越權
		讀寫、目錄暴漏與昂貴的遞迴掃描。修法是對 * ? [ ] 等樣式字元做轉義，或改用「精確以字面值比對」的 API，
		讓輸入只匹配它自己，不具樣式語意。`,
		problem: `// 不安全寫法：把輸入當 glob 樣式使用，* 會擴張成大批檔案
function remove(target) {
  glob.sync(target).forEach(fs.unlinkSync);   // target = "*" 刪光所有檔案
}`,
		fixed: `// 安全寫法：封鎖樣式字元，改用字面路徑精確比對
function remove(target) {
  if (/[\\*\\?\\[\\]]/.test(target)) throw new Error('wildcard not allowed');
  if (fs.existsSync(target)) fs.unlinkSync(target);
}`,
		patch: `@@
  function remove(target) {
-  glob.sync(target).forEach(fs.unlinkSync);
+  if (/[\\*\\?\\[\\]]/.test(target)) throw new Error('wildcard not allowed');
+  if (fs.existsSync(target)) fs.unlinkSync(target);
  }`,
		refs: ['CWE-155', 'OWASP'],
		tags: ['wildcard', 'glob', 'pattern'],
	},
	{
		id: 'CWE-157',
		name: 'Failure to Sanitize Paired Delimiters',
		lang: 'javascript',
		status: 'Complete',
		what: `成對定界符未消毒。程式對「標記一群實體的啟始與結尾」的字元——圓括號、方括號、花括號——處理不當：
		只清了一半、或完全不處理。多數語法以配對括號界定作用域或分組（函式呼叫、數學運算式、資料容器），如果使用者
		輸入內的開頭括號沒有匹配的結尾括號、或相反，就會打亂回剖析結構，影響後續的比對、剖析與安全判定。成因是沒在
		送入下游前檢查括號數量成對並消毒。後果是語法解讀錯位、包圍了本不該包住的內容，促成注入或邏輯繞過。修法是在
		使用前確認開、閉括號數量一致且內容受控，或把資料以不會被當成分組符號的方式傳遞。`,
		problem: `// 不安全寫法：直接拼入數學運算式，未成對的括號可竄改式子結構
function calc(expr, user) {
  return eval(expr + ' + ' + user);   // user=")" 讓括號不平衡，改寫整式
}`,
		fixed: `// 安全寫法：先拒絕含括號的輸入，再以非 eval 的安全計算法
function calc(expr, user) {
  if (/[()]/.test(user)) throw new Error('delimiter not allowed');
  return safeArith(expr, user);       // 參數化、絕不 eval 字串
}`,
		patch: `@@
  function calc(expr, user) {
-  return eval(expr + ' + ' + user);
+  if (/[()]/.test(user)) throw new Error('delimiter not allowed');
+  return safeArith(expr, user);
  }`,
		refs: ['CWE-157', 'OWASP'],
		tags: ['delimiter', 'bracket', 'pair'],
	},
	{
		id: 'CWE-158',
		name: 'Improper Neutralization of Null Byte or NUL Character',
		lang: 'python',
		status: 'Complete',
		what: `NUL／空位元組未被中立化。輸入中的 NUL（0x00、\\0、%00）對多種下游元件是「內容結束」的記號：C 字串以
		NUL 終止、某些 C 函式看到 NUL 就停、部分檔案系統或協定也把 NUL 當分界。若在 NUL 之後又接了內容，程式常只處理
		NUL 前段而忽略後段，形成「檢查看得到、真正執行的卻不同」的不一致；歷史上的 NUL 字串截斷常用來繞過路徑檢查或
		副檔名過濾。成因是未在輸入邊界移除或驗證 NUL。後果是繞過驗證、使剖析錯位與安全判定失效。修法是明確拒絕含
		NUL 的輸入，或統一視 NUL 為資料不可信內容、被拿來當終止記號前即擋下。`,
		problem: `# 不安全寫法：NUL 前是合法副檔名，後面接上的腳本名被放行
def allow_upload(n):
    base, sep, ext = n.partition("\\0")
    return ext.lower().endswith(".png")   # n="a.png\\0x.py" 判定通過`,
		fixed: `# 安全寫法：直接把含 NUL 的輸入當非法拒絕
def allow_upload(n):
    if "\\0" in n:
        raise ValueError("NUL not allowed")
    return n.lower().endswith(".png")`,
		patch: `@@
  def allow_upload(n):
-    base, sep, ext = n.partition("\\0")
-    return ext.lower().endswith(".png")
+    if "\\0" in n:
+        raise ValueError("NUL not allowed")
+    return n.lower().endswith(".png")`,
		refs: ['CWE-158', 'OWASP'],
		tags: ['null-byte', 'nul', 'truncation'],
	},
	{
		id: 'CWE-160',
		name: 'Improper Neutralization of Leading Special Elements',
		lang: 'javascript',
		status: 'Complete',
		what: `開頭的特殊元素未被中立化。某些語法或協定把「位置在字串最前面」的元素賦予特殊意義，例如命令名稱前的
		空白是分隔、路徑前的斜線表示絕對路徑、數值前的加減號或表示符、字串前的引號。若資料以這類帶語意的字元開頭又未被
		消除或轉義，最早出現的特殊元素就會被下游當成結構而不是資料解讀，令後續內容的語意改變。常見濫用是加空格或跳格讓
		命令名、網域或路徑逃過前置比對。成因是未中立化出現在開頭的引導性棋語元素。修法是對每一個會當作引導符解析的
		字元做轉義與校驗，或在解析前先對引導元素做明確對待。`,
		problem: `// 不安全寫法：比對命令名時沒去首部空白，" ls" 反而通過黑名單
const BANNED = new Set(['ls', 'rm']);
function blocked(cmd) {
  return BANNED.has(cmd);   // cmd=" rm" 開頭空白 → 不會命中 → 放行執行
}`,
		fixed: `// 安全寫法：先脫去兩端空白再做完全比對，引導元素不再影響判定
function blocked(cmd) {
  return BANNED.has(cmd.trim());
}`,
		patch: `@@
  function blocked(cmd) {
-  return BANNED.has(cmd);
+  return BANNED.has(cmd.trim());
  }`,
		refs: ['CWE-160', 'OWASP'],
		tags: ['leading', 'whitespace', 'bypass'],
	},
	{
		id: 'CWE-161',
		name: 'Improper Neutralization of Multiple Leading Special Elements',
		lang: 'javascript',
		status: 'Complete',
		what: `多個連續的開頭特殊元素未被中立化。若安全檢查只處理「單一個」開頭特殊元素，攻擊者可堆疊多個同類或
		不同類的引導字元（多個空白、多層絕對路徑前綴、重複的跳脫）來耗盡那一次的消毒、讓後續內容照舊被正常解讀。
		與單一開頭元素的差別在於「數量不單一」——只清一次就清不乾淨。成因是消毒邏輯假定只會出現一個引導元素、
		沒用迴圈或正則一次重複剷除。後果是資料仍以帶語意的開頭進入下游，繞過比對與驗證。修法是使用會重複移除整個
		引導字元集合的消毒（以正則剷除所有前導字元），再做完全一致的比對。`,
		problem: `// 不安全寫法：只 remove 開頭一個空白，多個空白就漏過去
const BANNED = new Set(['rm']);
function blocked(cmd) {
  return BANNED.has(cmd.replace(/^ /, ''));   // "   rm"（3 個空白）清不完
}`,
		fixed: `// 安全寫法：用正則移除『所有』開頭空白，再做完全比對
function blocked(cmd) {
  return BANNED.has(cmd.replace(/^\\s+/, ''));
}`,
		patch: `@@
  function blocked(cmd) {
-  return BANNED.has(cmd.replace(/^ /, ''));
+  return BANNED.has(cmd.replace(/^\\s+/, ''));
  }`,
		refs: ['CWE-161', 'OWASP'],
		tags: ['leading', 'multiple', 'bypass'],
	},
	{
		id: 'CWE-162',
		name: 'Improper Neutralization of Trailing Special Elements',
		lang: 'javascript',
		status: 'Complete',
		what: `結尾的特殊元素未被中立化。語法常在字串或檔名的結尾也賦予特殊意義：結尾的斜線表示目錄、結尾的點、結尾的
		換行程重複結尾分隔符、以結尾哨兵判斷「已完整」。若資料尾端帶有這類字元卻沒被處理或消毒，下游會把結尾的字符當成
		結構解讀——例如以結尾點切副檔名、以尾斜線連結網域、或以換行截斷一筆記錄。攻擊者可在結尾塞入額外元素讓比對或
		後續拼串偏離預期。成因是消毒只針對內容中段或開頭，漏掉了唯一特殊化的結尾。修法是正規化並剝除或轉義所有結尾的
		特殊元素，再用統一的結尾狀態做比對與存取。`,
		problem: `// 不安全寫法：比對尾端副檔名時沒先剝結尾元素，"." 或尾斜線造成誤判
function isImg(p) {
  return p.endsWith('.png');   // p="logo.png/" 尾斜線、或 p="logo.png." 結尾點皆誤報
}`,
		fixed: `// 安全寫法：先剝除結尾元素再由副檔名精確判斷
function isImg(p) {
  return p.replace(/[./]+$/, '').endsWith('.png');
}`,
		patch: `@@
  function isImg(p) {
-  return p.endsWith('.png');
+  return p.replace(/[./]+$/, '').endsWith('.png');
  }`,
		refs: ['CWE-162', 'OWASP'],
		tags: ['trailing', 'suffix', 'bypass'],
	},
	{
		id: 'CWE-163',
		name: 'Improper Neutralization of Multiple Trailing Special Elements',
		lang: 'javascript',
		status: 'Complete',
		what: `多個連續的結尾特殊元素未被中立化。與 CWE-162 類似但強調「多個」：消毒只移除單一結尾元素、或只判斷一種
		結尾字符，攻擊者堆疊多個結尾字元（多個結尾點、多層尾斜線、結尾前的換行）讓單次處理清不乾淨。這些額外的結尾
		元素會在下游扮演它各自的結構角色，讓剖析、比對或資源定址與開發者預期不同。成因是消毒假定結尾元素最多出現
		一個、沒有以重複模式剷除整個結尾字元集。修法是以正則一次移除所有結尾特殊元素並正規化，再以統一的結尾表示做
		安全判定，避免殘留的任何結尾字符進入下游。`,
		problem: `// 不安全寫法：只移除一個結尾點，多個結尾點仍通過副檔名檢查
function isAllowedExt(f) {
  return f.replace(/\\.$/, '').endsWith('.exe_dot');
}`,
		fixed: `// 安全寫法：以正則移除『所有』結尾點，再判斷副檔名
function isAllowedExt(f) {
  return f.replace(/\\.+$/, '').endsWith('.png');
}`,
		patch: `@@
  function isAllowedExt(f) {
-  return f.replace(/\\.$/, '').endsWith('.exe_dot');
+  return f.replace(/\\.+$/, '').endsWith('.png');
  }`,
		refs: ['CWE-163', 'OWASP'],
		tags: ['trailing', 'multiple', 'suffix'],
	},
	{
		id: 'CWE-164',
		name: 'Improper Neutralization of Internal Special Elements',
		lang: 'javascript',
		status: 'Complete',
		what: `字串「內部」的特殊元素未被中立化。材料既不在開頭也不在結尾、而是出現在中段的特殊字符也有語法意義——
		路徑中以點表示「目前目錄」、以分號分隔欄位、以引號括起嵌入式字串、以跳脫字元開始控制序列。若僅在兩端做檢查
		而忽視中間內容，攻擊者在資料中部塞入這類元素就能改寫下游對該段的解讀，穿過只守首尾的消毒。成因是安全檢查的
		對象與下游真正解讀的位置不一致。修法是對整段資料（不只首尾）中的每個特殊元素都做轉義，並以能夠定位「內部極組件」
		的語法專屬編碼處理。`,
		problem: `// 不安全寫法：資料中段含控制字元，直接寫入關鍵值 // 影響下游剖析
function headerize(val) {
  return 'X-Field=' + val;   // val="a\\r\\nSet-Cookie:x=1" 中段 CRLF 改寫標頭
}`,
		fixed: `// 安全寫法：拒絕或轉義中段任何控制字元，再組標頭
function headerize(val) {
  if (/[\\r\\n]/.test(val)) throw new Error('control char in body');
  return 'X-Field=' + val;
}`,
		patch: `@@
  function headerize(val) {
+  if (/[\\r\\n]/.test(val)) throw new Error('control char in body');
    return 'X-Field=' + val;
  }`,
		refs: ['CWE-164', 'OWASP'],
		tags: ['internal', 'control', 'injection'],
	},
	{
		id: 'CWE-165',
		name: 'Improper Neutralization of Multiple Internal Special Elements',
		lang: 'javascript',
		status: 'Complete',
		what: `多處內部特殊元素未被中立化。資料中段同時存在多個會被下游解讀的特殊元素，而消毒只移除其中一種或只處理
		第一個找到的。攻擊者放入不同類型或多個同類的前捷字元，只要有一處殘留，就能維持改寫下游解讀的能力。與
		CWE-164 的差別在於「面廣、需重複清除」。成因是消毒用單一 replace 或只換第一處，未覆蓋字串內所有出現。
		修法是全程清除整個特殊字元集（以全域正則去掉每一處），再以語法專屬編碼讓資料在中段再多都等價於純資料。`,
		problem: `// 不安全寫法：只替換第一處引號，後續引號仍可竄改字串結構
function q(v) {
  return '"' + v.replace(/"/, '\\\\"') + '"';   // 只換第一個 "，"a" ," 第二個照舊
}`,
		fixed: `// 安全寫法：全域轉義每一處引號與控制字元
function q(v) {
  return '"' + String(v).replace(/"/g, '\\\\"').replace(/[\\r\\n]/g, '') + '"';
}`,
		patch: `@@
  function q(v) {
-  return '"' + v.replace(/"/, '\\\\"') + '"';
+  return '"' + String(v).replace(/"/g, '\\\\"').replace(/[\\r\\n]/g, '') + '"';
  }`,
		refs: ['CWE-165', 'OWASP'],
		tags: ['internal', 'multiple', 'escaping'],
	},
	{
		id: 'CWE-166',
		name: 'Improper Handling of Missing Special Element',
		lang: 'javascript',
		status: 'Complete',
		what: `「缺少」預期的特殊元素時處理不當。程式原假定輸入一定含有某個特殊元素——結尾的 NUL、成對的右括號、
		分隔的逗號、終止的換行——並依它判斷資料邊界與完整性，但輸入中可以缺少它。若程式把「缺少」當成「系統不足」或直接
		繼續，就可能在資料邊界判錯後越界讀取、把殘缺結構當完整物件、或以錯誤的字串終止方式往下走。常見成因是不檢查
		該元素是否存在，只會使用它。後果是越界讀、剖析錯位與非預期終止。修法是先檢查所需特殊元素確實存在、且位置與
		個數符合契約，缺了就明確失敗退回，不把缺件的資料偷渡進下一步。`,
		problem: `// 不安全寫法：直接移除成對符號、假設一定有 ''，缺右引號時切錯邊界
function splitOpts(line) {
  const s = line.indexOf("'") + 1;        // 沒引號 → s=0，拿下錯誤段
  const e = line.indexOf("'", s);          // 找不到 → e=-1 → 段錯誤
  return line.slice(s, line.indexOf("'", e + 1));
}`,
		fixed: `// 安全寫法：確認所需特殊元素存在才解析，否則拒絕
function splitOpts(line) {
  const s = line.indexOf("'");
  if (s < 0) throw new Error('missing quote');
  const e = line.indexOf("'", s + 1);
  if (e < 0) throw new Error('missing closing quote');
  return line.slice(s + 1, e);
}`,
		patch: `@@
  function splitOpts(line) {
-  const s = line.indexOf("'") + 1;
-  const e = line.indexOf("'", s);
-  return line.slice(s, line.indexOf("'", e + 1));
+  const s = line.indexOf("'");
+  if (s < 0) throw new Error('missing quote');
+  const e = line.indexOf("'", s + 1);
+  if (e < 0) throw new Error('missing closing quote');
+  return line.slice(s + 1, e);
  }`,
		refs: ['CWE-166', 'OWASP'],
		tags: ['missing', 'delimiter', 'parse'],
	},
	{
		id: 'CWE-167',
		name: 'Improper Handling of Additional Special Element',
		lang: 'javascript',
		status: 'Complete',
		what: `「多出」不必要的特殊元素時處理不當。輸入帶有預期之外的額外特殊元素，程式卻不檢查就整體接受：多出來的
		定界符會切出多一個欄位、多出的跳脫字元改變後續位元組、額外的引號提早關閉或開啟字串。重點在於程式「吸收」
		了多餘元素而沒防範其結構影響。常見成因是假定只會出現固定數量的特殊元素、多抽不受影響。後果是欄位對應錯位、
		注入額外欄位或標頭、剖析結果與預期不同。修法是校驗特殊元素的個數與位置必須完全符合預期，任何多於契約的元素
		一律拒絕，而不是默默接受。`,
		problem: `// 不安全寫法：不管有幾個欄位都全收，多出的逗號會多加一個值
function apply(role, line) {
  const parts = role.concat(':', line).split(',');   // line="a,b,c" → 意外的第三欄
  return parts[1] || '';
}`,
		fixed: `// 安全寫法：校驗欄位數固定，多出的分隔元素直接拒絕
function apply(role, line) {
  const parts = role.concat(':', line).split(',');
  if (parts.length !== 2) throw new Error('unexpected extra field');
  return parts[1] || '';
}`,
		patch: `@@
  function apply(role, line) {
    const parts = role.concat(':', line).split(',');
+  if (parts.length !== 2) throw new Error('unexpected extra field');
    return parts[1] || '';
  }`,
		refs: ['CWE-167', 'OWASP'],
		tags: ['extra', 'delimiter', 'field'],
	},
	{
		id: 'CWE-168',
		name: 'Improper Handling of Inconsistent Special Elements',
		lang: 'python',
		status: 'Complete',
		what: `特殊元素彼此不一致時處理不當。程式沒有處理輸入中「兩個以上特殊字元或保留字互不一致」的情況，例如開頭以
		
字串字元解析、結尾卻用另一套；或一欄宣稱一種分隔數、另一種編碼卻對到不同語義。因為程式只用其中一種觀點解讀，
		不一致的另一方會被忽略，產生檢查與實際使用對不上的裂口。標準的操控是引號不配對、大小寫混合的保留字、或多種
		定界符同串混用，讓某一道過濾只看得到其中一種形式。成因是未對整串的特殊元素做交叉的一致性校驗。修法是把所有
		特殊元素先正規化到單一語法表示，再以一致規則拒絕彼此衝突的輸入。`,
		problem: `# 不安全寫法：只擋半形引號，全形引號與半形混用即繞過（不一致未處理）
def safe(s):
    return '"' in s or "'" in s    # 全形引號「」不在內，半全混用照常通過`,
		fixed: `# 安全寫法：正規化全形到半形並小寫化，一致後再檢查
def safe(s):
    n = s.replace("「", '"').replace("」", '"')
    return '"' in n or "'" in n    # 正規化後任何形式都一致可比對`,
		patch: `@@
  def safe(s):
-    return '"' in s or "'" in s
+    n = s.replace('「', '"').replace('」', '"')
+    return '"' in n or "'" in n`,
		refs: ['CWE-168', 'OWASP'],
		tags: ['inconsistent', 'canonicalize', 'bypass'],
	},
	{
		id: 'CWE-173',
		name: 'Improper Handling of Alternate Encoding',
		lang: 'python',
		status: 'Complete',
		what: `替代編碼（對控制域仍「有效」的另一種編碼）處理不當。輸入以對下游控制域是合法的另一種編碼出現——例如
		UTF-16 的 <、URL 編碼的 %3C、HTML 實體、全形字元——而程式只針對「單一標準編碼」做安全檢查。因為這種替代
		形式對下游一樣有效，檢查與實際消費便產生分歧，危險字元以非預期編碼穿過過濾，到下游才被還原成原始意思。
		成因是防護只建立在一種編碼假設上、未把輸入正規化到單一表示。後果是繞過字面黑名單、頑固的注入與披露。
		修法是在信任邊界先把輸入依其宣告（或偵測）的編碼統一解碼成正規表示，之後所有的安全判定都針對同一個正規表示。`,
		problem: `# 不安全寫法：假設一律 latin-1 且忽略其他編碼，"％3c" URL 編碼繞過檢查
def has_script(s):
    return "<script>" in s    # s="%3Cscript%3E" 或以全形呈現皆不會命中`,
		fixed: `# 安全寫法：先統一 URL／全形正規化到單一表示，再判比
from urllib.parse import unquote
def has_script(s):
    n = unquote(s).replace("＜", "<").replace("＞", ">").lower()
    return "<script>" in n`,
		patch: `@@
  def has_script(s):
-    return "<script>" in s
+    from urllib.parse import unquote
+    n = unquote(s).replace('＜', '<').replace('＞', '>').lower()
+    return "<script>" in n`,
		refs: ['CWE-173', 'OWASP'],
		tags: ['alternate-encoding', 'canonicalize', 'bypass'],
	},
	{
		id: 'CWE-174',
		name: 'Double Decoding of the Same Data',
		lang: 'python',
		status: 'Complete',
		what: `同一份資料被解碼兩次。程式對同一份輸入做了兩次解碼，使兩次解碼之間的任何一層防護失去效力：第一次解碼
		產生結果，中間的過濾／消毒把它檢查乾淨，但第二次解碼又把它還原成含危險字元的原始形式。常見例子是對已妥善轉義的
		URL 或實體再解一次，檢查在「一次解碼後」做、實際使用卻又解回「一次解碼前」的表示。成因是解碼在多個階段重複
		進行、沒有「只解一次、用同一表示判定」。修法是全流程對同一份資料只解碼一次，解碼後固定住正規表示，所有檢查與
		使用都用同一個已解碼版本，杜絕二次解還原。`,
		problem: `# 不安全寫法：檢查用一次解碼、實際用兩次解碼的結果，兩個版本不一致
from urllib.parse import unquote
def read(req):
    once = unquote(req["q"])                 # 一次解碼
    if once != ".":                          # 檢查只看 once
        return open("/data/" + unquote(once))   # 又解一次 → 變回 . → 穿越`,
		fixed: `# 安全寫法：只解一次、用同一結果做檢查與存取
def read(req):
    once = unquote(req["q"])                 # 全流程只解一次
    if once == ".":
        raise ValueError("blocked")
    return open("/data/" + once)`,
		patch: `@@
  def read(req):
      once = unquote(req["q"])
      if once != ".":
-        return open("/data/" + unquote(once))
+        return open("/data/" + once)`,
		refs: ['CWE-174', 'OWASP'],
		tags: ['double-decode', 'canonicalize', 'bypass'],
	},
	{
		id: 'CWE-175',
		name: 'Improper Handling of Mixed Encoding',
		lang: 'python',
		status: 'Complete',
		what: `混合編碼處理不當。同一份輸入裡同時用了多種不同編碼拼在一起——半形＋全形、URL 編碼與 Unicode 常式、
		ASCII 與跳脫序列、或一個字串的前後段用不同字元集。程式預設只有單一種編碼，或對連續編碼區段沒有分段辨識，
		就無法一致地解讀，檢查與後端解讀看到不同的字。常見成因是假定輸入乾淨純一編碼、沒有統一的解碼與正規化步伐。
		後果是單段黑名單與比對被混編的等價形式繞過。修法是把整份輸入在信任邊界統一逐段解碼成正規的單一表示（並處理
		各段各自的編碼），之後安全判定只針對這個正規形式。`,
		problem: `# 不安全寫法：只擋純 ASCII 的小寫 script，混入全形與大寫即繞過
def clean(s):
    return s not in {"<script>"}   # "＜SCRIPT＞" 或 "s<script>" 混編皆不命中`,
		fixed: `# 安全寫法：NFKC 正規化 + 小寫後統一比對，混合編碼先歸一
import unicodedata
def clean(s):
    n = unicodedata.normalize("NFKC", s).lower()
    return "<script>" not in n`,
		patch: `@@
  def clean(s):
-    return s not in {"<script>"}
+    import unicodedata
+    n = unicodedata.normalize('NFKC', s).lower()
+    return "<script>" not in n`,
		refs: ['CWE-175', 'OWASP'],
		tags: ['mixed-encoding', 'unicode', 'canonicalize'],
	},
	{
		id: 'CWE-178',
		name: 'Improper Handling of Case Sensitivity',
		lang: 'javascript',
		status: 'Complete',
		what: `大小寫敏感性處理不當。程式在 MY 定資源或資源功能時，沒有一致地處理大小寫的差異：一個檢查點把大小寫視為
		不同（case-sensitive）、另一個卻視為相同（case-insensitive），同一資源在不同階段「對上」不同的事物，前後結果不一致。
		典型濫用是黑名單用大小寫敏感比較、而檔案系統或資料庫查詢對大小寫不敏感：輸入 "Admin"、"ADMIN" 就溜過以精確
		admin 為準的檢查。成因是大小寫處理在不同地方各行其是、沒有統一的歸一規則。修法是在信任邊界建立單一正規化原則
		（例如一律 lower-case 後再比對與存取），讓大小寫在任何位置都等價。`,
		problem: `// 不安全寫法：查詢大小寫不敏感、黑名單卻敏感，混用大寫就穿越檢查
function blocked(cmd) {
  return BANNED.has(cmd);   // cmd=Admin 不命中，資料庫對 name 又 case-insensitive
}`,
		fixed: `// 安全寫法：比對與存取一致都先小寫、用同一表示
function blocked(cmd) {
  return BANNED.has(cmd.toLowerCase());
}`,
		patch: `@@
  function blocked(cmd) {
-  return BANNED.has(cmd);
+  return BANNED.has(cmd.toLowerCase());
  }`,
		refs: ['CWE-178', 'OWASP'],
		tags: ['case-sensitivity', 'normalize', 'bypass'],
	},
	{
		id: 'CWE-179',
		name: 'Incorrect Behavior Order: Early Validation',
		lang: 'javascript',
		status: 'Complete',
		what: `行為順序錯誤：過早驗證。程式在「會修改輸入的保護機制」套用之前就先驗證輸入，等到輸入被保護機制修改後，
		才出現原本不存在於驗證時點的危險形式，驗證便形同被跳過。例如先檢查字串不含 "<" 才做 HTML 轉義或 URL 解碼，
		而解碼前引號／符號在驗證時還不存在、解碼後才冒出來；攻擊者讓「驗證前的輸入」看起來無害、卻在修改後變成有害，
		從而成功迴避檢查。後果是各種注入與路徑穿越的防禦失效。修法的原則是把驗證移到所有輸入修改之後做，確保被檢查的
		就是最終要使用的形式，以同一份結果進行校驗。`,
		problem: `// 不安全寫法：先檢查再解碼，解碼後才出現的危險字未被把關
function read(req) {
  const raw = req.query.q;
  if (raw.includes('..')) throw Error('blocked');   // 驗證此時
  const p = decodeURIComponent(raw);                // 之後才解碼 → %2e%2e 現在才現身
  return fs.readFile('/data/' + p);               // 檢查完全失去 --
}`,
		fixed: `// 安全寫法：先完成所有輸入修改（解碼），再對最終形式驗證
function read(req) {
  const p = decodeURIComponent(req.query.q);   // 先做修改
  if (p.includes('..')) throw Error('blocked');   // 對最終結果驗證
  return fs.readFile('/data/' + p);
}`,
		patch: `@@
  function read(req) {
    const raw = req.query.q;
-  if (raw.includes('..')) throw Error('blocked');
-  const p = decodeURIComponent(raw);
+  const p = decodeURIComponent(raw);            // 先修改再驗證
+  if (p.includes('..')) throw Error('blocked');
    return fs.readFile('/data/' + p);
  }`,
		refs: ['CWE-179', 'OWASP'],
		tags: ['ordering', 'early-validation', 'canonicalize'],
	},
	{
		id: 'CWE-180',
		name: 'Incorrect Behavior Order: Validate Before Canonicalize',
		lang: 'python',
		status: 'Complete',
		what: `行為順序錯誤：正規化前先驗證。程式在校驗之前先做完「正規化」（canonicalize）就變成無法偵測「在正規化後
		才失效」的資料——驗證端看到的是「pre-normalization」形式，而真正會被使用的資料是在正規化後才成立的，兩者對不上。
		正規化常包含解碼、路徑化簡、大小寫歸一、移除重複分隔等動作；若讓檢查跑在前頭，檢查通過的字符串在正規化後
		可能指向他人的資源或包含危險值。常見被操控的對象是路徑、網域名、檔案名與字串比較。修法是先正規化到信任邊界的
		單一表示後，再對這個已正規化形式做所有安全檢核，確保檢核與使用引用同一份資料。`,
		problem: `# 不安全寫法：先驗證路徑片段，才做正規化；檢查看不到正規化後的真實路徑
import posixpath
def read(req):
    p = req["path"]
    if "/" not in p:                      # 用未正規化值檢查
        return open("/srv/" + p)         # "../etc/passwd" 正規化後變真實路徑`,
		fixed: `# 安全寫法：先正規化成絕對路徑，再用指派允許目錄比對
def read(req):
    p = posixpath.abspath("/srv/" + req["path"])   # 先正規化
    if not p.startswith("/srv/"):
        raise ValueError("outside root")               # 對正規後值驗證
    return open(p)`,
		patch: `@@
  def read(req):
      p = req["path"]
-    if "/" not in p:
-        return open("/srv/" + p)
+    p = posixpath.abspath("/srv/" + p)
+    if not p.startswith("/srv/"):
+        raise ValueError("outside root")
+    return open(p)`,
		refs: ['CWE-180', 'OWASP'],
		tags: ['ordering', 'canonicalize', 'path'],
	},
	{
		id: 'CWE-181',
		name: 'Incorrect Behavior Order: Validate Before Filter',
		lang: 'python',
		status: 'Complete',
		what: `行為順序錯誤：過濾前先驗證。程式在資料「被過濾」之前就先驗證其合法，過濾步驟又會改變資料的內容或長度，
		使「過濾後才無效」或「過濾後才危險」的資料無法被後續驗證捕獲。例如先確認字串不含 "<"，之後再做大小寫轉換或
		移除空白，轉換後才出現的字串就穿過那一次檢查。原理與 CWE-179/180 相同：防護只針對「修改前的狀態」。成因是
		驗證與過濾的順序顛倒、沒有讓檢查對象與最終使用者一致。修法是先完成所有過濾／消毒（uni碼、去控制字元、正規化），
		再對過濾後的最終內容做驗證，並最好用「輸出時再編碼」的縱深防禦。`,
		problem: `# 不安全寫法：先檢查無 "<"，做 tar 之後才出現的字元被放行
def render(msg):
    if "<" not in msg:                    # 驗證此時
        msg = msg.replace("<", "&lt;")   # 過濾在驗證之後 → 兩者結果不一致
    return "<p>" + msg + "</p>"`,
		fixed: `# 安全寫法：先做過濾（輸出編碼），再對已過濾結果做任何判定
def render(msg):
    cleaned = msg.replace("<", "&lt;").replace(">", "&gt;")   # 先過濾
    return "<p>" + cleaned + "</p>"      # 只輸出已過濾者，不再重驗`,
		patch: `@@
  def render(msg):
-    if "<" not in msg:
-        msg = msg.replace("<", "&lt;")
+    cleaned = msg.replace("<", "&lt;").replace(">", "&gt;")
-    return "<p>" + msg + "</p>"
+    return "<p>" + cleaned + "</p>"`,
		refs: ['CWE-181', 'OWASP'],
		tags: ['ordering', 'filter', 'validate'],
	},
	{
		id: 'CWE-182',
		name: 'Collapse of Data into Unsafe Value',
		lang: 'javascript',
		status: 'Complete',
		what: `資料被「折疊」成不安全的數值。程式用某種方式過濾、壓縮或轉換資料，使它「塌縮」成一個違反安全性質的
		特定值：例如 1 個或多個不同的輸入被同化成同一個字串、數字或路徑（"."、""、0、閉合目錄），而這個共同值又是
		不安全、或用於特許判斷的。經典例子是路徑正規化把 "../../../" 坍縮成 "."，路徑檢查一旦放行 "." 就讓
		path traversal 成立；或把多種輸入映射到管理員可控制軸的同一個值。成因是「折疊」後的結果沒有再次檢核是否存在
		安全風險。修法是在任何會把多值坍縮成一值的動作之後，對折疊結果重新做允許清單式檢驗，並明確拒絕該主常危險的
		塌縮值。`,
		problem: `// 不安全寫法：把路徑坍縮成 '.' 視為通過，未再檢核該塌縮值的危險性
function base(p) {
  return path.normalize(p).replace(/^\\.+/,'.');   // allowed '.' -> /* path 指向根目錄
}`,
		fixed: `// 安全寫法：允許清單只認實際存在且位於指定根目錄的路徑，塌縮值一律拒絕
function base(p) {
  const n = path.normalize(p);
  if (n === '.' || !n.startsWith(ROOT)) throw Error('unsafe collapsed path');
  return n;
}`,
		patch: `@@
  function base(p) {
-  return path.normalize(p).replace(/^\\.+/,'.');
+  const n = path.normalize(p);
+  if (n === '.' || !n.startsWith(ROOT)) throw Error('unsafe collapsed path');
+  return n;
  }`,
		refs: ['CWE-182', 'OWASP'],
		tags: ['collapse', 'canonicalize', 'path'],
	},
	{
		id: 'CWE-183',
		name: 'Permissive List of Allowed Inputs',
		lang: 'javascript',
		status: 'Complete',
		what: `允許清單過於寬鬆。以「顯式列入、就允許」的允許清單（白名單）構築的防禦，因為把實際上不安全、或能導致
		不安全值的輸入也列了進去而失去意義。典型問題是清單只是「造成作用之輸入的部分列舉」、混雜與資料同屬的結構字元、
		或在允許字元集中多放了 <、>、'、編碼配對等可作惡的一員。白名單的價值在於「嚴格」，一旦過鬆就退回黑名單的
		處境，容許穿越、注入與判斷繞過，形成「這個清單擋得出卻又擋出結果」的矛盾。修法是只允許安全、語意明確的最小
		字元／值集合，任何不在清單裡的都拒絕；把結構性字元完全移出允許範圍。`,
		problem: `// 不安全寫法：白名單混入了可作弊的 '等字符，輸入可注入屬性
const OK = /^[\\w@.<>',;-]+$/;          // '.'、'<'、'>'、',' 等過度放行
function sanitize(s) { return OK.test(s) ? s : ''; }`,
		fixed: `// 安全寫法：只允許字、數字、'-'、'_' 與分隔點的最小集合
const OK = /^[A-Za-z0-9_.-]+$/;
function sanitize(s) { return OK.test(s) ? s : ''; }`,
		patch: `@@
-  const OK = /^[\\w@.<>',;-]+$/;
+  const OK = /^[A-Za-z0-9_.-]+$/;
   function sanitize(s) { return OK.test(s) ? s : ''; }`,
		refs: ['CWE-183', 'OWASP'],
		tags: ['allowlist', 'whitelist', 'permissive'],
	},
	{
		id: 'CWE-186',
		name: 'Overly Restrictive Regular Expression',
		lang: 'python',
		status: 'Complete',
		what: `過度嚴格的正則表示式。用來偵測或過濾危險值的正則把規則寫得太嚴、或比對對象錯誤，以致「本應被擋住的危險值」
		得不到觸發而不被偵測。例如以錯誤的錨點、拔錯的字元集或只匹配整個字串的一部分，讓表面合法的樣式無法 match 到
		實際有害的輸入；或正則保護羅列出特定但不足以窮舉的格式。與 CWE-183/184 相反也有辯證：太嚴常來自把允許清單
		誤用成過濾氣、或在偵測「不該出現什麼」時正則沒有完整描述所有形式。後果是驗證被繞過、危險輸入視為安全放行。
		修法是以「危險樣式」為出發點設計能被徹底觸發的審查邏輯，並以大量安全／危險樣本驗證不誤放、不過度。`,
		problem: `# 不安全寫法：只匹配單一型式的 '<script>'，其他形式皆漏（過度只守住一種）
import re
def is_bad(s):
    return re.search(r'<script>', s, re.I) is not None   # 其他標籤/形式全漏`,
		fixed: `# 安全寫法：搭配黑名單+允許字元白名單，危險值無可立足
import re
def is_bad(s):
    if re.search(r'<[^>]*\\b(?:script|style|iframe)\\b', s, re.I):
        return True
    return not re.fullmatch(r'[A-Za-z0-9 ,._-]*', s)`,
		patch: `@@
  import re
  def is_bad(s):
-    return re.search(r'<script>', s, re.I) is not None
+    if re.search(r'<[^>]*\\b(?:script|style|iframe)\\b', s, re.I):
+        return True
+    return not re.fullmatch(r'[A-Za-z0-9 ,._-]*', s)`,
		refs: ['CWE-186', 'OWASP'],
		tags: ['regex', 'overly-restrictive', 'bypass'],
	},
	{
		id: 'CWE-192',
		name: 'Integer Coercion Error',
		lang: 'c',
		status: 'Complete',
		what: `整數強制型轉錯誤。整數在型別轉型、擴充或截斷的過程中發生非預期的位元變化，導致所得數值與正確值不符。
		它是一族數值類弱點的上位分類，包含符號擴充（sign extension）、無號／帶號轉換、數值截斷等子項。本質是程式在
		變更型別寬度或正負號時，沒有確認原始值能被目標型別完整且無損地表示：把帶號轉無號、把 32 位元截到窄型別、
		或讓負數在擴寬時錯誤地符號延伸。被型轉過的值若拿來當長度、索引或容量，就會得到與真實量不符的數，演成緩衝溢位、
		越界或用錯的量。修法是在型轉前先驗證值能安全表示，以檢查閘擋掉會失真或反號的轉換，全程用一致且夠寬的型別。`,
		problem: `// 不安全寫法：32 位元帶號 width 隱式轉無號再用於比較，負值變成巨量
#include <stdint.h>
_Bool accept(uint32_t cap, int32_t width) {
    return width <= (int32_t)cap;   // width 為負 → 轉成極大無號 → 比較錯亂
}`,
		fixed: `// 安全寫法：型轉前先確認範圍、型別一致再比較
_Bool accept(uint32_t cap, int32_t width) {
    if (width < 0) return 0;              // 負值先攔，不讓 sign 污染
    return (uint32_t)width <= cap;
}`,
		patch: `@@
  _Bool accept(uint32_t cap, int32_t width) {
-    return width <= (int32_t)cap;
+    if (width < 0) return 0;
+    return (uint32_t)width <= cap;
  }`,
		refs: ['CWE-192', 'SEI CERT'],
		tags: ['integer', 'coercion', 'cast'],
	},
	{
		id: 'CWE-194',
		name: 'Unexpected Sign Extension',
		lang: 'c',
		status: 'Complete',
		what: `意外的符號擴充。程式對一個數值做運算時，把它轉換成較大的資料型別且做了符號擴充：當原數為負（最高位元為 1）
		時，擴寬的同時會把最高位元一直延伸成高位皆為 1，最後得到一個非預期、與「儲存後應有的窄值」不符的數。常見在把
		int8/int16 帶號值升為 int/位元遮罩、或把帶號窄型別值拿進無號寬型別前沒先遮罩低位。結果若當成長度、索引或
		位元遮罩使用，負值被符號擴充後會成為天大的無號值，引向越界、配錯大小。修法是在擴寬前先判定原數正負與範圍，
		對寬度與正負都有明確一致的規則，需要「位元圖樣」時先以無號窄型遮罩再擴充。`,
		problem: `// 不安全寫法：帶號 int8 為負時 (int)b 符號擴充，成為極大的正偏移
int8_t b = -1;                      // 0xFF
int size = (int)b;                  // -1 → 符號擴充成 0xFFFFFFFF(-1)
unsigned long n = (unsigned long)(size + 1);   // 變成超大無號 → 越界寫`,
		fixed: `// 安全寫法：先以無號遮罩保低位、或明確轉成無號窄值再擴充
int8_t b = -1;
unsigned long n = (unsigned long)(uint8_t)b;    // 0xFF → 255，無符號擴充`,
		patch: `@@
-  int8_t b = -1;
-  int size = (int)b;
-  unsigned long n = (unsigned long)(size + 1);
+  int8_t b = -1;
+  unsigned long n = (unsigned long)(uint8_t)b;   // 保低位無符號擴充`,
		refs: ['CWE-194', 'SEI CERT'],
		tags: ['sign-extension', 'integer', 'cast'],
	},
	{
		id: 'CWE-196',
		name: 'Unsigned to Signed Conversion Error',
		lang: 'c',
		status: 'Complete',
		what: `無號轉帶號錯誤。程式把無號原始型別轉成帶號型別；當無號值超過帶號型別所能表示的上限（例如超過 INT_MAX、
		或等同於帶號裡的負數位元圖樣）時，轉出的帶號值會變成負數或不符預期的值，違反「仍為原數」的假設。若一個很大的
		無號值（如從長度欄位讀來）被當帶號使用、或反過來把帶號函式的回傳當無號，數量與本就可能是負的特質會被誤判，
		影響迴圈上界、比較與配置計算。後果常是以負或巨量的值去算長度與索引而越界。修法是在型轉前先確認無號值落在
		帶號型別的可表示範圍內，超界即以失敗處理，或全程只用一致的型別避免轉換。`,
		problem: `// 不安全寫法：無號 len 直接轉帶號，大於 INT_MAX 便化為負數 → 迴圈條件錯亂
#include <stdint.h>
#include <limits.h>
_Bool fits(int *m, unsigned len) {
    return len <= (unsigned)INT_MAX;   // len 超大隱式轉成帶號負 → 條件誤判
}`,
		fixed: `// 安全寫法：在無號域先做範圍檢查（寬型別），才允許轉帶號
_Bool fits(int *m, unsigned len) {
    if (len > (unsigned)INT_MAX) return 0;   // 超界先拒絕，避免負值化
    int n = (int)len;
    return m != 0;
}`,
		patch: `@@
  _Bool fits(int *m, unsigned len) {
-    return len <= (unsigned)INT_MAX;
+    if (len > (unsigned)INT_MAX) return 0;
+    int n = (int)len;
+    return m != 0;
  }`,
		refs: ['CWE-196', 'SEI CERT'],
		tags: ['unsigned-signed', 'cast', 'range'],
	},
	{
		id: 'CWE-198',
		name: 'Use of Incorrect Byte Ordering',
		lang: 'c',
		status: 'Complete',
		what: `使用了錯誤的位元組序。程式處理來自上游的輸入時，忽略了大小端（big-endian 與 little-endian）的差別：直接把
		以特定位元組序編碼的數當成主機本機序去讀、或把主機序的值原封不動送給期望另一種序的下游。在大小端不同的機器
		或協定與主機序不同時，讀出或送出的會是「位元組排列反了」的錯誤數值。多數網路協定都規定用 big-endian，而許多
		本機 CPU 是 little-endian。後果是用到錯的值去算長度、大小或位址，產生配置、索引與邏輯上的錯誤。修法是對跨環境
		交換的數一律經過 ntohl/htonl、ntohs/htons 這類明確的位元組序轉換，再進行運算。`,
		problem: `// 不安全寫法：直接以本機序解讀封包長度，little-endian 機器讀 big-endian 欄位會顛倒
uint32_t parse_len(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, 4);        // 直接把 p 的 4 位元組當本機序 → 大小端反轉
    return v - 16;            // 用錯的量去算剩餘長度 → 越界`,
		fixed: `// 安全寫法：以明確的 ntohl 統一轉換成主機序再運算
uint32_t parse_len(const uint8_t *p) {
    uint32_t v = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                 ((uint32_t)p[2] << 8) | p[3];   // 固定 big-endian 解讀
    return v - 16;
}`,
		patch: `@@
  uint32_t parse_len(const uint8_t *p) {
-    uint32_t v;
-    memcpy(&v, p, 4);
+    uint32_t v = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
+                 ((uint32_t)p[2] << 8) | p[3];
      return v - 16;
  }`,
		refs: ['CWE-198', 'SEI CERT'],
		tags: ['endian', 'byte-order', 'network'],
	},
	{
		id: 'CWE-204',
		name: 'Observable Response Discrepancy',
		lang: 'javascript',
		status: 'Complete',
		what: `可觀察的回應差異。程式對「合法」與「非法」請求分別回傳可被區別的訊息、狀態碼或時間，使未授權的攻擊者
		從回應差異裡學到內部狀態或資源資訊。最常見的是登入或身分檢查：連帶不同的錯誤文案（"無此帳號" vs "密碼錯誤")、
		不同的 HTTP 狀態、不同的頁面長度或請求解回應皆不相同，反覆比對就能列舉有效帳號、推斷資源是否存在、或確認特定
		欄位的值。本質是回傳的內容對外部可觀察、並能從中洩漏不該被知道的內部判定。後果是帳號列舉、資源列舉與驗證過程
		被逆向。修法是對成功與所有失敗路徑回傳統一的訊息、狀態碼與行為（泛化的錯誤回應），隱藏具體失敗原因，非敏感地記錄於
		內部日誌。`,
		problem: `// 不安全寫法：依錯誤型別回傳不同訊息，非授權者可列舉帳號與欄位
function login(u, p) {
  const row = db.getUser(u);
  if (!row) return 'no such user';      // 洩漏帳號是否存在
  if (row.pw !== hash(p)) return 'bad password';   // 洩漏密碼是否錯誤
  return 'ok';
}`,
		fixed: `// 安全寫法：成功與所有失敗都回同一訊息，細節只進日誌
function login(u, p) {
  const row = db.getUser(u) || { pw: null };
  const ok = row.pw !== null && row.pw === hash(p);
  if (!ok) log('login failed');          // 內部日誌才留原因
  return ok ? 'ok' : 'invalid credentials';
}`,
		patch: `@@
  function login(u, p) {
-  const row = db.getUser(u);
-  if (!row) return 'no such user';
-  if (row.pw !== hash(p)) return 'bad password';
+  const row = db.getUser(u) || { pw: null };
+  const ok = row.pw !== null && row.pw === hash(p);
+  if (!ok) log('login failed');
-  return 'ok';
+  return ok ? 'ok' : 'invalid credentials';
  }`,
		refs: ['CWE-204', 'OWASP'],
		tags: ['user-enumeration', 'oracle', 'response'],
	},
	{
		id: 'CWE-206',
		name: 'Observable Internal Behavioral Discrepancy',
		lang: 'javascript',
		status: 'Complete',
		what: `可觀察的內部行為差異。程式把多個行為搭配成單一結果（如一次身分驗證、一次授權判定、一次比對），但組成它的
		個別行為又各自對外部「可被觀察」——只要攻擊者能分別觸發或測量其中一段，就能拆出內部的決策點或狀態。例子是在一次
		登入流程裡，用可測量的時間差區分出「帳號存在但密碼錯」（較早失敗）與「帳號存在且密碼對」（再多做一步），或以
		個別錯誤回應先偵測出幾個欄位各自是否正確。與 CWE-204 的區別在於這裡是「多個可觀察的子行為」而非單一回應。
		後果是把驗證拆成可逐一窮舉的片段。修法是讓各子行為的回應、時間與順序一致，把所有校驗盡量在一次不可拆解的動作中
		完成並回一致結果。`,
		problem: `// 不安全寫法：密碼錯誤與帳號存在但鎖定回不同行為，洩漏內部決策
function signin(u, p) {
  if (!db.exists(u)) return 1;                 // 不同碼→可觀察分支
  if (db.locked(u)) return 2;                 // 攻擊者逐一觸發辨識
  return db.match(u, p) ? 0 : 3;
}`,
		fixed: `// 安全寫法：整個驗證一次做完、回統一結果，內部決策無法拆分
function signin(u, p) {
  const ok = db.exists(u) && !db.locked(u) && db.match(u, p);
  log({ u, reason: ok ? 'ok' : 'denied' });   // 細節只入日誌
  return ok ? 0 : 3;
}`,
		patch: `@@
  function signin(u, p) {
-  if (!db.exists(u)) return 1;
-  if (db.locked(u)) return 2;
-  return db.match(u, p) ? 0 : 3;
+  const ok = db.exists(u) && !db.locked(u) && db.match(u, p);
+  log({ u, reason: ok ? 'ok' : 'denied' });
+  return ok ? 0 : 3;
  }`,
		refs: ['CWE-206', 'OWASP'],
		tags: ['side-channel', 'observability', 'auth'],
	},
	{
		id: 'CWE-207',
		name: 'Observable Behavioral Discrepancy With Equivalent Products',
		lang: 'javascript',
		status: 'Complete',
		what: `與等價產品的可觀察行為差異。程式運作的環境要求它「不該被識別出確實存在或身分」，它的功能與其它同類產品
		（等同行為）相同，但在某些可用來辨識的行為上與眾不同，攻擊者因此能偵測出「這裡跑的是哪一套」或「這個東西真實存在」。
		例如指紋識別 header、回應順序、預設欄位、錯誤格式或通訊協定細節與同功能產品不一致。當產品的存在或身分本該隱匿
		（防火牆、代理、WAF、專有實作）時，這項差異就打壞假名性。後果是暴露部署與標識，方便針對已知漏洞或繞過政策。
		修法是讓可被觀察的行為——回應、錯誤、規格細節——與同類標準實作保持一致、去除未掩蓋各異的指紋痕跡。`,
		problem: `// 不安全寫法：自家代理的錯誤與預設 header 獨特，暴露它是哪個產品
function direct(res, code) {
  res.setHeader('Server', 'FooProxy/1.0');   // explicit 廠牌指紋
  res.status(code);                            // 錯誤格式與主流產品不同
}`,
		fixed: `// 安全寫法：對外抹平品牌與錯誤細節，與同類產品無異
function direct(res, code) {
  res.removeHeader('Server');                  // 不洩漏身分
  res.status(equiv(code));                   // 錯誤格式對齊通用規格
}`,
		patch: `@@
  function direct(res, code) {
-  res.setHeader('Server', 'FooProxy/1.0');
+  res.removeHeader('Server');
-  res.status(code);
+  res.status(equiv(code));
  }`,
		refs: ['CWE-207', 'OWASP'],
		tags: ['fingerprint', 'identity', 'discrepancy'],
	},
	{
		id: 'CWE-211',
		name: 'Externally-Generated Error Message Containing Sensitive Information',
		lang: 'python',
		status: 'Complete',
		what: `外部產生的錯誤訊息含敏感資訊。程式執行某個動作觸發了「非自行生成或控制」、來自外界診斷系統的錯誤——程式語言
		直譯器原始例外、組態過於詳盡的資料庫或伺服器錯誤——而這些訊息常常夾帶內部敏感內容：堆疊追蹤、絕對路徑、SQL、
		連線字串、版本資訊、套件路徑或原始資料。若直接把該訊息回給使用者或寫進對外可見通道，就揭露了內部的實作細節、洩漏
		可供進一步攻擊的立足點。成因是把未經成分整理的例外或診斷輸直接外送。修法是取得錯誤後抽取出「通用化的錯誤碼或文案」，
		將詳細堆疊與內部內容只記入受控的伺服器端日誌，對外永遠回覆泛化的訊息。`,
		problem: `# 不安全寫法：直接把原始例外字串回給使用者，堆疊與 SQL 外洩
def lookup(q):
    try:
        return db.execute(q)
    except Exception as e:      # e.strerror 含 SQL／路徑／版本
        return render(str(e))`,
		fixed: `# 安全寫法：詳細訊息只進日誌，對外回泛化文案
def lookup(q):
    try:
        return db.execute(q)
    except Exception as e:
        log_stack(e)                 # 內部日誌保留細節
        return render("request failed")`,
		patch: `@@
  def lookup(q):
      try:
          return db.execute(q)
      except Exception as e:
-        return render(str(e))
+        log_stack(e)
+        return render("request failed")`,
		refs: ['CWE-211', 'OWASP'],
		tags: ['error-handling', 'information-exposure', 'stack-trace'],
	},
	{
		id: 'CWE-213',
		name: 'Exposure of Sensitive Information Due to Incompatible Policies',
		lang: 'javascript',
		status: 'Complete',
		what: `因政策不相容而洩漏敏感資訊。功能本身的行為與開發者的安全政策幾乎一致——把資訊暴露給某類受權限的角色本來
		「合理」，但資訊內容在另一位持有者（系統管理員、使用者、其他被處理資料的人）按其政策卻被視為敏感。典型是給管理介面
		展現在功能上屬於它權限內的使用者資料清單，但某些欄位（個資、他人憑證、內部位址）對同一位管理者依政策也不該看；
		或返回一欄一欄地回應用戶自身的連線資訊，卻超過他自己的資料政策範圍。後果是敏感資料以「政策相符」的名義實則越界外洩。
		修法是先界定每個角色「最小可看」的欄位並對照各自政策，功能輸出前依資料擁有者的政策過濾欄位、以最小暴露為準。`,
		problem: `// 不安全寫法：管理員查使用者，把所有欄位（含他人個資欄）整包回傳
function admin_get(u) {
  return db.findById(u);   // 回傳相含 pw_hash、SSN、私人 address
}`,
		fixed: `// 安全寫法：依角色最小可看欄位白名單過濾後才回傳
function admin_get(u) {
  const row = db.findById(u);
  return pick(row, ['id', 'name', 'created_at']);   // 只暴露授權欄位
}`,
		patch: `@@
  function admin_get(u) {
-  return db.findById(u);
+  const row = db.findById(u);
+  return pick(row, ['id', 'name', 'created_at']);
  }`,
		refs: ['CWE-213', 'OWASP'],
		tags: ['information-exposure', 'policy', 'access-control'],
	},
	{
		id: 'CWE-214',
		name: 'Invocation of Process Using Visible Sensitive Information',
		lang: 'python',
		status: 'Complete',
		what: `以「可見的敏感資訊」啟動行程。程式啟動另一個行程（子處理序）時，把敏感資料——密碼、金鑰、token、機密——
		放在命令列引數、或直接可見的環境變數裡。命令列參數幾乎對同一主機上其它能跑 ps／進程清單的行程可見，環境變數也常被
		子行程樹與某些身分可見；敏感值一旦如此可見，任何能列行程的使用者或其他帳號就被曝晒相遇到。後果是憑證與機密外洩、
		被旁觀者竊取後偽裝。修法是把秘密改由「不外傳的管道」傳遞：透過 stdin、以 file-descriptor／unix socket 傳送、
		或在行程內開啟受權限保護的檔案，而不要透過命令列或環境變數裸傳。`,
		problem: `# 不安全寫法：密碼直接當命令列引數傳給子行程，ps 即可窺見
import subprocess
subprocess.run(["helper", "--token", secret])   # secret 在 argv 可見`,
		fixed: `# 安全寫法：機密不走 argv，改經 stdin 傳入，讓子行程讀取
import subprocess
p = subprocess.run(["helper"], input=secret.encode(), capture_output=True)`,
		patch: `@@
-import subprocess
-# 不安全寫法：secret 在 argv 可見
-           subprocess.run(["helper", "--token", secret])
+# 安全寫法：機密走 stdin，argv 不再外洩
+import subprocess
+p = subprocess.run(["helper"], input=secret.encode(), capture_output=True)`,
		refs: ['CWE-214', 'OWASP'],
		tags: ['argv', 'secret', 'process-invocation'],
	},
	{
		id: 'CWE-215',
		name: 'Insertion of Sensitive Information Into Debugging Code',
		lang: 'python',
		status: 'Complete',
		what: `把敏感資訊寫進偵錯程式碼。開發時常會為了除錯，把登入 token、密碼、session、憑證或其它機密連同 internal
		state 打進日誌、print、trace 或 assert，卻沒在產品環境停用。若這些偵錯輸出來到實際環境仍存在或仍被觸發，敏感資訊
		便會寫入日誌、回給呼叫端或輸出到 stderr——多數情形他人可讀（日誌檔、監控系統、除錯端點）。後果是憑證與機密外洩
		給能碰日誌或輸出的對手方。修法絕不把機密寫進日誌，確定(DEBUG)所包覆的敏感輸出在 production 停用，並在正式版移除
		或遮罩任何 token、密碼相關的除錯輸出。`,
		problem: `# 不安全寫法：conditioning 除錯列印直接印出 token，竟保留在產品碼中
def on_auth(user, token):
    if DEBUG:
        print("login token:", token)      # DEBUG 未關 → 機密上 log
    issue(user, token)`,
		fixed: `# 安全寫法：機密永不進任何形式的輸出，除錯只列無敏感的字元
def on_auth(user, token):
    if DEBUG:
        print("login ok:", user)         # 不印 token
    issue(user, token)`,
		patch: `@@
  def on_auth(user, token):
      if DEBUG:
-        print("login token:", token)
+        print("login ok:", user)
      issue(user, token)`,
		refs: ['CWE-215', 'OWASP'],
		tags: ['debug', 'token', 'information-exposure'],
	},
	{
		id: 'CWE-217',
		name: 'DEPRECATED: Failure to Protect Stored Data from Modification',
		lang: 'c',
		status: 'Deprecated',
		what: `已棄置的條目。原指「未保護已儲存資料不被修改」，但此條目把多個不同的弱點混為一談、範圍過於籠統且語義
		難辨，已被取消。其原本涵蓋的光電明內容，現在分別歸納到 CWE-766（Critical Data Element Declared Public）與
		CWE-767（Access to Critical Private Variable via Public Method）兩條更精確的條目之下。使用手冊判讀時勿再採用
		CWE-217，應改查 CWE-766／CWE-767 兩項。`,
		problem: `// （已棄置）舊版語義：含糊地「未能保護儲存資料」涵蓋多重概念，無單一可靠範例`,
		fixed: `// 請改依 CWE-766（關鍵資料宣告為公開）與 CWE-767（由公開方法存取私有關鍵變數）分開處理`,
		patch: `@@
-  // CWE-217 已棄置：勿再以單一條目涵蓋「未保護儲存資料」
+  // 改用 CWE-766 與 CWE-767 兩條分開評估
+`,
		refs: ['CWE-217', 'CWE-766', 'CWE-767'],
		tags: ['deprecated', 'stored-data', 'access-control'],
	},
	{
		id: 'CWE-218',
		name: 'DEPRECATED: Failure to provide confidentiality for stored data',
		lang: 'c',
		status: 'Deprecated',
		what: `已棄置的條目。原指「未為已儲存資料提供機密性（confidentiality）」，但其內容與 CWE-493（Critical Public
		Variable Without Comment）相同，完全重複，因此本條目被取消、全部內容已移植到 CWE-493 下。編寫或審查時
		若看到「CWE-218」一律視同 CWE-493，不要再用舊編號兜出重複的評估與敘述，以維持資料庫與手冊的一致性。`,
		problem: `// （已棄置）CWE-218 是 CWE-493 的重複，不再賦予獨立範例`,
		fixed: `// 請直接以 CWE-493 評估「公開可能含機密／關鍵值的變數」問題`,
		patch: `@@
-  // CWE-218 已棄置：內容重複 CWE-493
+  // 一律以 CWE-493 為準
+`,
		refs: ['CWE-218', 'CWE-493'],
		tags: ['deprecated', 'confidentiality', 'duplicate'],
	},
];
