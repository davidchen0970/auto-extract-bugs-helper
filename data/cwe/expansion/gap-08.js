// CWE chunk — 類別:組態不當、資訊暴露與併發／物件模型缺陷
// code 內避免 `${` 以免汙染反引號字串。
export default [
	{
		id: 'CWE-543',
		name: 'Use of Singleton Pattern Without Synchronization in a Multithreaded Context',
		lang: 'java',
		status: 'Complete',
		what: `在多執行緒環境使用「未同步」的 Singleton 樣式建立共用資源。經典寫法是非靜態、採 lazy initialization：
		兩個以上的執行緒同時首次呼叫取得例項的方法時，都可能發現例項還是 null、各自 new 出一個物件，於是先後回傳
		兩份不同的例項。就算不至於建立兩份，也可能讓某個執行緒讀到「尚在建構中」的半成品狀態。後果是共享資源被
		重複建立、全域狀態被不同的執行緒看到不同版本，觸發競態與不一致。修法是讓「是否已建立 + 建立動作」在同一個
		同步邊界內完成：用 volatile + double-checked locking、static 內建 initialize-on-demand holder、或直接以
		final static 例項／enum 保證只有一份，把 thread-safety 交給 JVM 而非程序員手動把關。`,
		problem: `// 不安全寫法：lazy 建構沒有同步，兩支執行緒同時進來會各建一份例項
public class Registry {
    private static Registry instance;

    public static Registry get() {
        if (instance == null) {        // 兩條 thread 同時判斷為 null
            instance = new Registry(); // 各自建立，回傳不同物件
        }
        return instance;
    }
}`,
		fixed: `// 安全寫法：volatile + double-checked locking，建立動作在鎖內只執行一次
public class Registry {
    private static volatile Registry instance;

    public static Registry get() {
        Registry r = instance;
        if (r == null) {
            synchronized (Registry.class) {
                if ((r = instance) == null) {
                    instance = r = new Registry();
                }
            }
        }
        return r;
    }
}`,
		patch: `@@
  public class Registry {
-    private static Registry instance;
+    private static volatile Registry instance;

  public static Registry get() {
-    if (instance == null) {
-        instance = new Registry();
-    }
-    return instance;
+    Registry r = instance;
+    if (r == null) {
+        synchronized (Registry.class) {
+            if ((r = instance) == null) {
+                instance = r = new Registry();
+            }
+        }
+    }
+    return r;
  }
  }`,
		refs: ['CWE-543', 'CWE-609', 'OWASP'],
		tags: ['singleton', 'thread-safety', 'double-checked-locking', 'race-condition'],
	},
	{
		id: 'CWE-544',
		name: 'Missing Standardized Error Handling Mechanism',
		lang: 'javascript',
		status: 'Complete',
		what: `缺少「統一的錯誤處理機制」。程式沒有把錯誤處理收斂成單一、一致的方式，而是每一處 catch／else 各自為政：
		有的直接把例外吞掉、有的原封不動回傳內部細節、有的用不同的狀態碼或錯誤格式。同一種失敗在不同路徑表現不一致，
		對維護者是一團亂，也常衍生更多弱點——例如某路徑把堆疊／SQL 直接外洩，另一路徑卻載靜默失敗，除錯時找不到為何
		行為不同。修法是建立集中的錯誤處理層（統一攔截佇列、統一 log 決策、統一套用對外通用訊息與狀態碼），讓「該記錄的進
		日誌、該回傳的進回應」有單一定義，並在入口包一層全域 error handler。`,
		problem: `// 不安全寫法：網路層吞例外、路由層外洩細節，同一失敗兩種反應
app.get('/user/:id', (req, res, next) => {
  try {
    const u = db.get(req.params.id);
    if (!u) return res.sendStatus(404);
    res.json(u);
  } catch (e) {
    // 這裡靜默吞掉，呼叫端得到永遠的 undefined
  }
});

app.get('/order/:id', (req, res) => {
  try {
    res.json(db.order(req.params.id));
  } catch (e) {
    res.status(500).send(e.stack); // 另一處卻把內部堆疊外洩出去
  }
});`,
		fixed: `// 安全寫法：統一的 async wrapper + 集中 error handler，格式與記錄單一定義
const wrap = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res)).catch(next); // 所有錯誤送往集中層

app.use((err, req, res, next) => {
  logger.error('request failed', { path: req.path, err }); // 細節只留 server 端
  res.status(500).json({ error: 'internal error' });       // 對外一律通用格式
});

app.get('/user/:id', wrap(async (req, res) => {
  const u = db.get(req.params.id);
  if (!u) return res.sendStatus(404);
  res.json(u);
}));`,
		patch: `@@
-app.get('/user/:id', (req, res, next) => {
-  try {
-    const u = db.get(req.params.id);
-    if (!u) return res.sendStatus(404);
-    res.json(u);
-  } catch (e) { }
-});
-
-app.get('/order/:id', (req, res) => {
-  try {
-    res.json(db.order(req.params.id));
-  } catch (e) {
-    res.status(500).send(e.stack);
-  }
-});
+const wrap = (fn) => (req, res, next) =>
+  Promise.resolve(fn(req, res)).catch(next);
+app.use((err, req, res, next) => {
+  logger.error('request failed', { path: req.path, err });
+  res.status(500).json({ error: 'internal error' });
+});
+app.get('/user/:id', wrap(async (req, res) => {
+  const u = db.get(req.params.id);
+  if (!u) return res.sendStatus(404);
+  res.json(u);
+}));`,
		refs: ['CWE-544', 'CWE-209', 'OWASP'],
		tags: ['error-handling', 'consistent-errors', 'centralized-logging'],
	},
	{
		id: 'CWE-545',
		name: 'DEPRECATED: Use of Dynamic Class Loading',
		lang: 'javascript',
		status: 'Deprecated',
		what: `此條已被官方標記為 Deprecated：它部分與 CWE-470（使用來自不可信來源的外部可控制輸入來選擇要載入的程式碼）
		重疊，一部分描述的其實是「合法的程序員行為」，另一部分需要併入其它條目。官方不再建議直接把此 ID 拿來對映實際漏洞。
		若遇到「以外部資料決定要載入哪支程式／類別」的真實風險，請改用 CWE-470 對映，並遵循其修法：只載入明確、受信任、
		受白名單控管的目標，絕對不要以使用者可控字串直接拼接成類別名稱或路徑再動態載入／執行。`,
		problem: `// 潛在風險模式（正式對映請看 CWE-470）
const handlerName = req.query.handler;            // 使用者可控
const Handler = require('./handlers/' + handlerName); // 動態載入可被任意指定
new Handler(req, res);`,
		fixed: `// 防禦方式：白名單對應，絕不直接以輸入當類別／路徑
const HANDLERS = { profile: require('./handlers/profile'), help: require('./handlers/help') };
const handler = HANDLERS[req.query.handler] || HANDLERS.help; // 只挑白名單內成員
handler(req, res);`,
		patch: `@@
-const handlerName = req.query.handler;
-const Handler = require('./handlers/' + handlerName);
-new Handler(req, res);
+const HANDLERS = { profile: require('./handlers/profile'), help: require('./handlers/help') };
+const handler = HANDLERS[req.query.handler] || HANDLERS.help;
+handler(req, res);`,
		refs: ['CWE-545', 'CWE-470', 'OWASP'],
		tags: ['deprecated', 'dynamic-loading', 'whitelist'],
	},
	{
		id: 'CWE-547',
		name: 'Use of Hard-coded, Security-relevant Constants',
		lang: 'javascript',
		status: 'Complete',
		what: `用「硬編碼常數」而非「符號名稱」來表示安全相關的值：例如把密鑰、權限旗標、某項金額上限、
		一組可用的服務名稱直接寫字面值散佈在程式各處。安全政策或常數一旦更動，維護者要「記得」並逐一找到每一處一起改，
		漏掉任何一處就會出現不一致：有的檢查區用舊值、有的路徑用新值，等同留下一道繞道。修法是把安全相關值收斂成單一、
		具名、集中定義的常數或設定檔，各處以符號名稱引用，讓改動只發生在一處且保證全程式一致。`,
		problem: `// 不安全寫法：同一權限字串的字面值散落多處，改安全政策時容易漏改
app.delete('/admin/user', (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  users.remove(req.body.id);
});
app.get('/admin/config', (req, res) => {
  if (req.user.role != 'admin ') return res.sendStatus(403); // 打錯字又漏同步
  res.json(config);
});`,
		fixed: `// 安全寫法：把安全相關值集中成單一具名常數，各處一律引用符號
const Role = Object.freeze({ ADMIN: 'admin', USER: 'user' });

function isAdmin(u) {
  return u.role === Role.ADMIN; // 只有這一處寫字面值
}

app.delete('/admin/user', isAdminGuard, (req, res) => { users.remove(req.body.id); });
app.get('/admin/config', isAdminGuard, (req, res) => { res.json(config); });`,
		patch: `@@
+const Role = Object.freeze({ ADMIN: 'admin', USER: 'user' });
+function isAdmin(u) { return u.role === Role.ADMIN; }
+
 app.delete('/admin/user', (req, res) => {
-  if (req.user.role !== 'admin') return res.sendStatus(403);
+  if (!isAdmin(req.user)) return res.sendStatus(403);
   users.remove(req.body.id);
 });
 app.get('/admin/config', (req, res) => {
-  if (req.user.role != 'admin ') return res.sendStatus(403);
+  if (!isAdmin(req.user)) return res.sendStatus(403);
   res.json(config);
 });`,
		refs: ['CWE-547', 'OWASP'],
		tags: ['hardcoded', 'magic-constant', 'config', 'privilege-flag'],
	},
	{
		id: 'CWE-548',
		name: 'Exposure of Information Through Directory Listing',
		lang: 'python',
		status: 'Complete',
		what: `把「目錄內容清單」暴露給使用者。當一個資料夾裡沒有 index 檔（或沒有預設歡迎檔）時，伺服器開啟了
		Indexes／autoindex，就會回傳一份列出該目錄下所有資源的索引頁。攻擊者借此看到內部檔案名稱、備份檔、原始碼檔、
		暫存檔、.git 目錄等本不應公開的資源，等同拿到一張「該先打哪個」的地圖，大幅幫助資訊蒐集。修法是關閉自動索引
		功能：對「目錄」的請求一律回 403，不列出內容；同時把敏感性檔案（設定、備份、隱藏檔）移到 web 根目錄之外。`,
		problem: `# 不安全寫法：允許監看目錄時回傳完整的資源清單（autoindex 開啟）
import http.server
from http.server import SimpleHTTPRequestHandler

server = HTTPSServer(('', 8443), SimpleHTTPRequestHandler)
# 對沒有 index.html 的目錄,SimpleHTTPRequestHandler 預設列出所有檔名
# -> 攻擊者瀏覽 /backup/、/.git/ 就能看到內部結構
http.server.HTTPServer(('', 8080), SimpleHTTPRequestHandler).serve_forever()`,
		fixed: `# 安全寫法：對目錄請求一律拒回清單,敏感檔案也移出根目錄
import http.server

class SafeHandler(http.server.SimpleHTTPRequestHandler):
    def list_directory(self, path):           # 覆寫:不再列出
        self.send_error(403, 'forbidden')    # 目錄一律不公開
        return None

http.server.HTTPServer(('', 8080), SafeHandler).serve_forever()`,
		patch: `@@
+import http.server
+class SafeHandler(http.server.SimpleHTTPRequestHandler):
+    def list_directory(self, path):
+        self.send_error(403, 'forbidden')
+
-import http.server
-from http.server import SimpleHTTPRequestHandler
-server = HTTPServer(('', 8443), SimpleHTTPRequestHandler)
-http.server.HTTPServer(('', 8080), SimpleHTTPRequestHandler).serve_forever()
+http.server.HTTPServer(('', 8080), SafeHandler).serve_forever()`,
		refs: ['CWE-548', 'CWE-200', 'OWASP'],
		tags: ['directory-listing', 'enumeration', 'info-disclosure', 'autoindex'],
	},
	{
		id: 'CWE-549',
		name: 'Missing Password Field Masking',
		lang: 'html',
		status: 'Complete',
		what: `密碼輸入欄沒有做遮罩（masking）。網頁或 UI 把密碼輸入框做成普通文字輸入，輸入時每個字元都
		明文顯示在螢幕上；在公共環境、有旁人、有監視器或螢幕記錄時，攻擊者可透過肉眼觀看、螢幕截圖、側錄畫面來記下密碼。
		這是典型的「防側眼觀察」缺口。修法是採用密碼輸入控制項、把輸入以圓點／星號取代顯示，並可再加上「暫時顯示」需明確
		按鈕才呈現明文、同時關閉輸入法記錄與自動完成勿記憶密碼，從顯示面降低被偷窺的機率。`,
		problem: `<!-- 不安全寫法：密碼欄用一般文字輸入,輸入的每個字元都明文顯示在畫面上 -->
<form action="/login" method="post">
  <label>帳號 <input name="user" type="text"></label>
  <label>密碼 <input name="pass" type="text"></label> <!-- 明文顯示,旁人可偷看 -->
  <button>登入</button>
</form>`,
		fixed: `<!-- 安全寫法：密碼欄使用密碼輸入型別 + autocomplete=off,輸入值以圓點遮罩 -->
<form action="/login" method="post">
  <label>帳號 <input name="user" type="text" autocomplete="username"></label>
  <label>密碼 <input name="pass" type="password" autocomplete="new-password"
                 maxlength="64"></label>
  <button>登入</button>
</form>`,
		patch: `@@
   <label>帳號 <input name="user" type="text"></label>
-  <label>密碼 <input name="pass" type="text"></label>
+  <label>密碼 <input name="pass" type="password" autocomplete="new-password"></label>
   <button>登入</button>
 `,
		refs: ['CWE-549', 'CWE-200', 'OWASP'],
		tags: ['password', 'masking', 'shoulder-surfing', 'ui'],
	},
	{
		id: 'CWE-550',
		name: 'Server-generated Error Message Containing Sensitive Information',
		lang: 'python',
		status: 'Complete',
		what: `伺服器在特定失敗條件（網路錯誤、資料庫斷線、例外未處理等）下，回傳的錯誤訊息本身就含有敏感資訊。開發模式常見
		的 Debug、traceback、SQL 或檔案路徑被原樣吐回瀏覽器，攻擊者看到後即可推斷技術棧、資料表名、內部路徑或弱點位置。
		這大多是被困在一張「把例外細節直接當回應 body」的寫法所害。修法是區分「對外回應」與「內部記錄」：對外一律給通用、
		不洩結構的訊息，完整錯誤細節只寫入伺服器端日誌，並在正式環境關閉 debug／traceback 外送。`,
		problem: `# 不安全寫法：把例外字串(s_mome含 SQL/路徑/堆疊)直接塞進回應 body
from flask import Flask, jsonify
import traceback

app = Flask(__name__)

@app.errorhandler(Exception)
def on_error(e):
    # debug 專用:把完整堆疊、SQL、檔案路徑全部吐回給使用者
    return jsonify(error=str(e), trace=traceback.format_exc()), 500`,
		fixed: `# 安全寫法：細節進 server 端日誌,對外只回一句不洩結構的通用訊息
import logging
from flask import Flask, jsonify

log = logging.getLogger('app')
app = Flask(__name__)

@app.errorhandler(Exception)
def on_error(e):
    log.exception('request failed')          # 細節只在伺服器端日誌
    return jsonify(error='request failed'), 500   # 對外無內部結構`,
		patch: `@@
+import logging
+log = logging.getLogger('app')
+
 @app.errorhandler(Exception)
 def on_error(e):
-    return jsonify(error=str(e), trace=traceback.format_exc()), 500
+    log.exception('request failed')
+    return jsonify(error='request failed'), 500`,
		refs: ['CWE-550', 'CWE-209', 'OWASP'],
		tags: ['error-message', 'information-disclosure', 'traceback', 'debug'],
	},
	{
		id: 'CWE-551',
		name: 'Incorrect Behavior Order: Authorization Before Parsing and Canonicalization',
		lang: 'javascript',
		status: 'Complete',
		what: `行為順序錯誤：在「完整解析與正規化」之前就先做授權檢查。伺服器對要求的路徑只做了不完整的處理（例如還沒
		decode、還沒解析 path、還沒解完 . 與 ..），就用這個未正規化的字串比對權限。攻擊者只要用尚未正規化的變體——編碼過的字、
		大小寫不同、額外的斜線、路徑穿越片段——就能讓授權比較「看似不含敏路徑」卻在最後存取到原本不該碰的資源，等於繞過
		整個授權保護。修法是「先正規化再授權」：把路徑 decode、解析並攤平成標準型（並確認沒越出根），拿「最終會被存取的
		那個」路徑來做授權判定，順序絕不能顛倒。`,
		problem: `// 不安全寫法：先比對原始 URL,後才 decode 定位檔案 => 授權檢查看到的是失真路徑
const path = require('path');

app.get('/files/*', (req, res) => {
  const raw = req.params[0];
  if (raw.startsWith('/admin')) return res.sendStatus(403);   // 在解析前就授權
  const decoded = decodeURIComponent(raw);                     // 解析在授權"之後"
  res.sendFile(path.join(FILES_ROOT, decoded));               // %2e%2e%2f 可繞過檢查
});`,
		fixed: `// 安全寫法：先完整解析+正規化,確認留在根內,才拿「真正目的地」做授權
app.get('/files/*', (req, res) => {
  const decoded = decodeURIComponent(req.params[0]);           // 先解析
  const target = path.normalize(path.join(FILES_ROOT, decoded)); // 再正規化
  if (!target.startsWith(FILES_ROOT + path.sep)) return res.sendStatus(403); // 防越界
  if (target.startsWith(path.join(FILES_ROOT, 'admin'))) return res.sendStatus(403);
  res.sendFile(target);                                       // 授權用解析後的真實路徑
});`,
		patch: `@@
 app.get('/files/*', (req, res) => {
   const raw = req.params[0];
-  if (raw.startsWith('/admin')) return res.sendStatus(403);
   const decoded = decodeURIComponent(raw);
-  res.sendFile(path.join(FILES_ROOT, decoded));
+  const target = path.normalize(path.join(FILES_ROOT, decoded));
+  if (!target.startsWith(FILES_ROOT + path.sep)) return res.sendStatus(403);
+  if (target.startsWith(path.join(FILES_ROOT, 'admin'))) return res.sendStatus(403);
+  res.sendFile(target);
 });`,
		refs: ['CWE-551', 'CWE-178', 'OWASP'],
		tags: ['authorization-order', 'canonicalization', 'path-bypass', 'behavior-order'],
	},
	{
		id: 'CWE-553',
		name: 'Command Shell in Externally Accessible Directory',
		lang: 'bash',
		status: 'Complete',
		what: `把一支「命令殼／指令碼」放進了可由外部直接存取的目錄，例如把 .sh／.csh 檔丟進網站的 cgi-bin 或 web 可執行
		root 下。shell 與 CGI 的定位不同：CGI 主要只是「輸出 HTML」的介面，而 shell 是給使用者敲命令的直譯器。若讓 web 伺服器
		能直接執行或下載一支會被當成 shell 的指令稿，攻擊者便能透過 web 介面觸發它、以伺服器身分執行指令，是「在網頁伺服器上直接
		開命令執行」的極危險組態。修法是絕對不要把 shell 檔放在 web 可執行目中；改用受管控的 CGI 包裝、編譯過的可執行檔，且目錄
		與腳本權限最小化，僅授權給確有需要的處理程序。`,
		problem: `# 不安全寫法：把可被當成命令殼的指令稿放進可被 web 直接存取的目錄
public/cgi-bin/tools.sh:
  #!/bin/bash
  # 透過 web 觸發,等同在伺服器上開一個可下指令的 shell
  whoami; ls -la /; cat /etc/passwd

# 瀏覽器打 /cgi-bin/tools.sh 就能讓它以伺服器權限跑任意系統指令`,
		fixed: `# 安全寫法：web 可執行目錄不放 shell;用受管控的編譯處理器,權限最小化
server/bin/tools:
  # 經編譯、只做單一受限任務的可執行檔,不以 web shell 形式存在
  #public/cgi-bin 內只允許此編譯檔,並用最小權限帳號執行
  runuser -u cgi-user ./tools
  # 絕不將 tools.sh 這類直譯能力暴露給 web`,
		patch: `@@
-public/cgi-bin/tools.sh:
-  #!/bin/bash
-  whoami; ls -la /; cat /etc/passwd
+server/bin/tools:   # 編譯過的受限處理器,不放在可執行目錄
+  runuser -u cgi-user ./tools
+  # public/cgi-bin 不放命令殼`,
		refs: ['CWE-553', 'OWASP'],
		tags: ['cgi', 'command-shell', 'shell', 'web-exposure'],
	},
	{
		id: 'CWE-554',
		name: 'ASP.NET Misconfiguration: Not Using Input Validation Framework',
		lang: 'csharp',
		status: 'Complete',
		what: `這個 ASP.NET 的組態不當在於：應用沒有採用「輸入驗證框架」。程式直接接受 Request／表單／Route 送進來的外部值，
		沒有在進入業務邏輯前做正規化、驗證格式、型別與範圍的檢查，於是這些未經驗證的資料往下流進 SQL、HTML、命令等地方。
		此外若把 .NET 的 ValidateRequest／RequestValidation 關掉，連內建的請求驗證也被關閉，注入與 XSS 風險更高。
		修法是啟用且統一使用驗證機制：開啟 RequestValidation、對每個端點在入口處用正規驗證規則（長度、白名單字元、強型別
		模型繫結與 ModelState）檢查，未通過就直接拒絕，讓「非法／異常輸入」進不去業務處理。`,
		problem: `// 不安全寫法：直接把 Request 值當作可信任資料來用,沒套任何驗證
[HttpPost]
public ActionResult Save(int id, string name, string qty)
{
    // name / qty 直接取自外部,無格式或型別驗證
    db.Command("UPDATE item SET loc = " + qty + " WHERE id=" + id);
    ViewBag.Name = name;          // XSS:直接吐回 HTML
    return View();
}`,
		fixed: `// 安全寫法：用強型別模型與 ModelState 驗證,無效輸入在進業務前就被擋下
public class SaveModel
{
    [Required, StringLength(100, MinimumLength = 1)]
    public string Name { get; set; }
    [Range(1, int.MaxValue)]
    public int Qty { get; set; }
}

[HttpPost]
public ActionResult Save(int id, SaveModel m)
{
    if (!ModelState.IsValid) return View(new { error = "invalid input" });
    db.Execute("UPDATE item SET loc = @q WHERE id = @id",
              new { q = m.Qty, id });     // 參數化,且已通過驗證
    return View();
}`,
		patch: `@@
-[HttpPost]
-public ActionResult Save(int id, string name, string qty)
-{
-    db.Command("UPDATE item SET loc = " + qty + " WHERE id=" + id);
-    ViewBag.Name = name;
-    return View();
-}
+public class SaveModel
+{
+    [Required, StringLength(100, MinimumLength = 1)]
+    public string Name { get; set; }
+    [Range(1, int.MaxValue)]
+    public int Qty { get; set; }
+}
+
+[HttpPost]
+public ActionResult Save(int id, SaveModel m)
+{
+    if (!ModelState.IsValid) return View(new { error = "invalid input" });
+    db.Execute("UPDATE item SET loc = @q WHERE id = @id", new { q = m.Qty, id });
+    return View();
+}`,
		refs: ['CWE-554', 'CWE-20', 'OWASP'],
		tags: ['aspnet', 'input-validation', 'modelstate', 'configuration'],
	},
	{
		id: 'CWE-555',
		name: 'J2EE Misconfiguration: Plaintext Password in Configuration File',
		lang: 'java',
		status: 'Complete',
		what: `J2EE 應用的組態不當：把「明文密碼」直接寫進設定檔。資料庫連線的密碼、外部服務的密鑰被以明文形式放在
		web.xml、屬性檔或 JNDI 以外的設定裡；凡是能讀到設定檔的人（同機使用者、備份、原始碼 repo、設定檔洩漏）都能看到並竊取這些
		憑證。修法是不要把密碼放進設定檔：改用由 application server 提供的 DataSource／JNDI 連線，把連線憑證交給容器管理；
		或用外部的機密儲存（密鑰庫、環境變數、組態機密管理服務）加密保管，程式執行時才解密取用。`,
		problem: `# 不安全寫法：web.xml / jdbc.properties 明文存資料庫密碼
res/jdbc.properties:
  db.url = jdbc:mysql://db:3306/app
  db.user = appuser
  db.password = s3cret_plain         # 明文!任何讀到檔案者都拿得到密碼

// 程式直接讀設定檔字串當連線憑證
DriverManager.getConnection(props.getProperty("db.url"),
                          props.getProperty("db.user"),
                          props.getProperty("db.password"));`,
		fixed: `# 安全寫法：交給容器管理 DataSource,設定檔不含密碼
<!-- server.xml / web.xml 由容器代管憑證 -->
<web-app>
  <resource-ref>
    <res-ref-name>jdbc/mydb</res-ref-name>
    <res-type>javax.sql.DataSource</res-type>
  </resource-ref>
</web-app>

// 程式只用 JNDI 查 DataSource,看不到任何明文密碼
Context ctx = new InitialContext();
DataSource ds = (DataSource) ctx.lookup("java:comp/env/jdbc/mydb");
Connection c = ds.getConnection();`,
		patch: `@@
-res/jdbc.properties:
-  db.password = s3cret_plain
-resource ref:
-  <res-ref-name>jdbc/mydb</res-ref-name>
-  <res-type>javax.sql.DataSource</res-type>
-
-// 程式直接讀設定檔當連線憑證
-DriverManager.getConnection(props.getProperty("db.url"), props.getProperty("db.user"), props.getProperty("db.password"));
+Context ctx = new InitialContext();
+DataSource ds = (DataSource) ctx.lookup("java:comp/env/jdbc/mydb");
+Connection c = ds.getConnection();`,
		refs: ['CWE-555', 'CWE-256', 'OWASP'],
		tags: ['j2ee', 'plaintext-password', 'config-file', 'credentials'],
	},
	{
		id: 'CWE-556',
		name: 'ASP.NET Misconfiguration: Use of Identity Impersonation',
		lang: 'csharp',
		status: 'Complete',
		what: `ASP.NET 的組態不當：讓應用以「身分模擬（impersonation）」的某一個帳號（常是高權限的 Administrator）來執行。
		設定 impersonate=true 且 identity 指向 admin 帳號，會給應用超出所需的最低權限。一旦應用有任意程式碼執行（檔案上傳、注入、
		反序列化、目錄寫入）被利用，「被利用的是誰」就是那個高權限帳號，後果瞬間被放大成整個系統被拿下。修法是遵循最小權限：關閉
		不需要的 impersonation，用預設的低權限 Process／應用程式集區帳號執行；真有身分模擬需求也只模擬單一受限權限的帳號，並配合
		權限隔離讓攻擊者能獲得的權限降到最低。`,
		problem: `# 不安全寫法：IIS 設定讓應用以本機系統管理員身分模擬執行
<system.web>
  <identity impersonate="true" userName="DOMAIN\\Administrator"
            password="adminpwd" />
</system.web>
#明確用 admin 身分跑,應用一旦被 RCE,就等於以管理者在整個系統行動`,
		fixed: `# 安全寫法：關掉高權限模擬;用最小權限帳號併限制可寫範圍
<system.web>
  <identity impersonate="false" />
</system.web>
# 應用集區改用最小權限帳號,只能寫自己的暫存目錄
# 若仍需模擬:只模擬單一受限帳號並結合 ACL 限制,不被給 admin`,
		patch: `@@
 <system.web>
-  <identity impersonate="true" userName="DOMAIN\\\\Administrator" password="adminpwd" />
+  <identity impersonate="false" />
 </system.web>`,
		refs: ['CWE-556', 'CWE-250', 'OWASP'],
		tags: ['aspnet', 'impersonation', 'least-privilege', 'misconfiguration'],
	},
	{
		id: 'CWE-558',
		name: 'Use of getlogin() in Multithreaded Application',
		lang: 'c',
		status: 'Complete',
		what: `多執行緒程式呼叫 getlogin()。getlogin() 回傳的是「這個登入 session 的登入名」，它並非以每支執行緒的 uid
		各自運算，而是依賴全域的登入狀態／utmp；在多執行緒或多作業／多加強權切換的情境下，呼叫執行緒可能拿到「另一支執行緒／不自己」的
		登入名。如果把它拿來當身分判斷、存取控制或記錄用途，就會判錯主人，造成認證或不當授權。修法是不在做成身分決定時用它：改以執行緒
		已知的 uid 呼叫 getpwuid() 或直接持有以 uid 為基礎的識別，把「身分」由系統對該執行緒的授權中取得，而非依賴全域的 getlogin()。`,
		problem: `// 不安全寫法：多執行緒各自呼叫 getlogin() 判斷身份,可能拿到別支執行緒的登入名
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

void* worker(void* unused) {
    const char* login = getlogin();          // 全域登入名,非 per-thread
    if (strcmp(login, "root") == 0) {      // 身份判斷建立在可能錯誤的值上
        do_admin_thing();
    }
    return NULL;
}`,
		fixed: `// 安全寫法：以執行緒本身的 uid 查身份,不依賴全域的 getlogin()
#include <unistd.h>
#include <pwd.h>

void do_work_asis(uid_t uid) {
    struct passwd* pw = getpwuid(uid);      // 由該執行緒/作業的 uid 決定身份
    if (pw && (strcmp(pw->pw_name, "root") == 0)) {
        do_admin_thing();
    }
}`,
		patch: `@@
 void* worker(void* unused) {
-    const char* login = getlogin();
-    if (strcmp(login, "root") == 0) {
-        do_admin_thing();
-    }
+    struct passwd* pw = getpwuid(geteuid());   // 用實際 uid 而非全域登入名
+    if (pw && (strcmp(pw->pw_name, "root") == 0)) {
+        do_admin_thing();
+    }
     return NULL;
 }`,
		refs: ['CWE-558', 'CWE-362', 'OWASP'],
		tags: ['getlogin', 'multithreaded', 'privilege-check', 'race'],
	},
	{
		id: 'CWE-560',
		name: 'Use of umask() with chmod-style Argument',
		lang: 'c',
		status: 'Complete',
		what: `呼叫 umask() 時傳了「用 chmod 的思維」給錯的引數。umask 的引數不是「要設定哪些權限位元」，而是
		「要屏蔽／遮掉的權限位元」：兩者的對應是相反的（umask 要 0o022 才能讓新檔變成 0o644；若是 0o644 則反而把 owner
		的讀寫也遮掉）。把它當 chmod 用，比如傳一個代表「自己期望的完整權限」的位元，就會讓建立出來的檔案權限比預想的寬鬆或
		錯誤，敏感檔因此讓所有人可讀／可寫。修法是確認 umask() 的引數永遠是「應屏蔽的位元遮罩」，並把範例值（如 0o022／0o077）
		寫清楚，必要時建立後再以正確的 chmod 設定期望權限。`,
		problem: `# 不安全寫法：用 chmod 心態把「期望的權限」當成 umask 引數
#include <sys/stat.h>
#include <sys/types.h>

void make_conf(void) {
    // 以為 0644 表示「設定成 owner 讀寫、其餘唯讀」
    umask(0644);            // 錯!umask 要的是"屏蔽罩",0644 反而把 owner 也遮掉
    int fd = open("/etc/app.tmp", O_CREAT | O_WRONLY, 0666);
}`,
		fixed: `# 安全寫法：umask 引數用「應屏蔽的位元遮罩」
#include <sys/stat.h>
#include <sys/types.h>

void make_conf(void) {
    umask(0022);            // 屏蔽 group/other 的寫位元 -> 新檔 0644
    int fd = open("/etc/app.tmp", O_CREAT | O_WRONLY, 0666);
    // 若仍需嚴謹:建立後明確 fchmod(fd, 0640)
}`,
		patch: `@@
 void make_conf(void) {
-    umask(0644);            // 錯!當成 chmod 用
+    umask(0022);            // 用應屏蔽的位元遮罩
     int fd = open("/etc/app.tmp", O_CREAT | O_WRONLY, 0666);
 }`,
		refs: ['CWE-560', 'CWE-732', 'OWASP'],
		tags: ['umask', 'chmod', 'file-permissions', 'misc'],
	},
	{
		id: 'CWE-564',
		name: 'SQL Injection: Hibernate',
		lang: 'java',
		status: 'Complete',
		what: `透過 Hibernate 執行以「使用者輸入拼接」的動態 SQL：把輸入直接串進 HQL／原生 SQL 的字串再用 createQuery／
		createSQLQuery 執行。Hibernate 本身不會自動對「拼接字串」做參數化；攻擊者把輸入改成語句的一部份時，就可以改變整條查詢的
		語意，或追加 UNION／OR 來繞過驗證、外洩全表、或執行任意的 SQL 命令。修法是永遠改用「具名／位置參數」：用 HQL 的
		:param 搭配 setParameter()、或原生 SQL 的 ? 搭配 setXxx()，讓使用者輸入一律以參數帶入、由 Hibernate 代為轉義，絕不存
		在「憑空把字串併進 SQL」的途徑。`,
		problem: `// 不安全寫法：把使用者輸入字串拼接進 HQL 再執行
public User find(String login) {
    // login 來自 request,直接併入查詢 => ' OR '1'='1 可改寫語意
    Query q = session.createQuery(
        "from User u where u.login = '" + login + "'");
    return (User) q.uniqueResult();
}`,
		fixed: `// 安全寫法：一律用具名參數 :login,由 Hibernate 代為綁定轉義
public User find(String login) {
    Query q = session.createQuery(
        "from User u where u.login = :login");   // 參數化,無字串拼接
    q.setParameter("login", login);               // 輸入只當資料值進入
    return (User) q.uniqueResult();
}`,
		patch: `@@
 public User find(String login) {
-    Query q = session.createQuery(
-        "from User u where u.login = '" + login + "'");
+    Query q = session.createQuery("from User u where u.login = :login");
+    q.setParameter("login", login);
     return (User) q.uniqueResult();
 }`,
		refs: ['CWE-564', 'CWE-89', 'OWASP'],
		tags: ['sql-injection', 'hibernate', 'hql', 'parameterized-query'],
	},
	{
		id: 'CWE-566',
		name: 'Authorization Bypass Through User-Controlled SQL Primary Key',
		lang: 'java',
		status: 'Complete',
		what: `資料表裡含「不該讓該使用者存取的列」，但程式用「使用者可控的主鍵」直接查那一列、卻沒先驗證「這列是否屬於眼前
		這個使用者」。只要把主鍵換成別人的 id（例如 /order/1234 改成 /order/1235），就能查閱、修改或刪除原不該碰的紀錄，
		觸發縱向／橫向越權（IDOR／Iraq access control）。修法不能只信「主鍵」，要在查詢本身就把存取範圍夾出來：讓主鍵與
		物主條件同時進 WHERE，例如 where id=? and owner_id=?，或先以使用者的身分查可用範圍，確保任何請求都越不出使用者的權限集合。`,
		problem: `// 不安全寫法：只用使用者可控的主鍵查詢,完全沒有物主檢查
public Order getOrder(int orderId) {
    // orderId 由使用者帶入,換成別人的單號就能讀別人的訂單
    String sql = "SELECT * FROM orders WHERE order_id = " + orderId;
    return queryForObject(sql);
}`,
		fixed: `// 安全寫法：主鍵與物主條件同時進查詢,越不出使用者自己的範圍
public Order getOwnOrder(int orderId, int ownerId) {
    String sql = "SELECT * FROM orders WHERE order_id = ? AND owner_id = ?";
    List<Order> rows = query(sql, orderId, ownerId);   // 不會命在別人名下
    return rows.isEmpty() ? null : rows.get(0);        // 查無即回 null
}`,
		patch: `@@
-// 不安全寫法:只用使用者可控的主鍵查詢
-public Order getOrder(int orderId) {
-    String sql = "SELECT * FROM orders WHERE order_id = " + orderId;
-    return queryForObject(sql);
-}
+public Order getOwnOrder(int orderId, int ownerId) {
+    String sql = "SELECT * FROM orders WHERE order_id = ? AND owner_id = ?";
+    List<Order> rows = query(sql, orderId, ownerId);
+    return rows.isEmpty() ? null : rows.get(0);
+}`,
		refs: ['CWE-566', 'CWE-639', 'OWASP'],
		tags: ['idor', 'access-control', 'primary-key', 'horizontal-privilege'],
	},
	{
		id: 'CWE-568',
		name: 'finalize() Method Without super.finalize()',
		lang: 'java',
		status: 'Complete',
		what: `覆寫 finalize() 卻沒有呼叫 super.finalize()。父類別可能在 finalize() 裡做資源釋放或清理；子類別若不層層
		呼叫 super.finalize()，父類別的清理邏輯（握著的最後清理、關閉資源）永遠不會被執行，造成資源（尾端連線、檔案、原生
		記憶體）外洩，而且這種小漏要到 GC 之後、甚至為時已晚才出現。修的關鍵也不只是「補上 super.finalize()」而是呼叫順序：
		得在 try 裡做自己的清理、finally 裡呼叫 super.finalize()，以免自己的例外打斷父類別清理。並且要留意 finalize 整體已不被
		推薦——能用 try/finally 或 try-with-resources 就別依賴它。`,
		problem: `// 不安全寫法：覆寫 finalize 做本類清理,但忘了呼叫父類別的 finalize
public class FileHandle extends BaseResource {
    @Override
    protected void finalize() throws Throwable {
        close();                 // 只清理自己,父類別的釋放邏輯沒被呼叫
        // 少了 super.finalize(),BaseResource 的清理永不執行
    }
}`,
		fixed: `// 安全寫法：自己清理放 try,super.finalize()放 finally 保證父類發現
public class FileHandle extends BaseResource {
    @Override
    protected void finalize() throws Throwable {
        try {
            close();                 // 自己的清理
        } finally {
            super.finalize();       // 無論如何都讓父類別清理執行到
        }
    }
}`,
		patch: `@@
 public class FileHandle extends BaseResource {
     @Override
     protected void finalize() throws Throwable {
-        close();
+        try {
+            close();
+        } finally {
+            super.finalize();
+        }
     }
 }`,
		refs: ['CWE-568', 'CWE-404', 'OWASP'],
		tags: ['finalize', 'resource-cleanup', 'super-call', 'leak'],
	},
	{
		id: 'CWE-571',
		name: 'Expression is Always True',
		lang: 'javascript',
		status: 'Complete',
		what: `某個條件運算式恆為「真」。代表寫作的邏輯一定成立——例如比較符號寫錯（用了 || 而讓兩半永遠涵蓋全部）、
		比較到自身、或其它已不可能變假的運算式。程式員原意是「要檢查某個條件」，卻因為恆真而使該檢查形同虛設，後面該被擋下
		的路徑永遠不會被擋；若這是安全關卡，就等於整道檢查被繞過。恆真運算式也常是負責邏輯錯誤、copy-paste、運算元錯置的
		訊號。修法是重寫條件讓它真的能捕捉輸入變化，並用靜態分析工具（dead-branch、constant-condition）在 build 或 CI 時抓出
		this 類寫法加上對輸入分支的單元測試。`,
		problem: `// 不安全寫法：條件運算式兩半互補,任何輸入都為真 => 檢查形同虛設
function allowed(user) {
  // attempts 不管多少,這兩個分支恆取其一為真
  // 想表達"次數少於 5 才放行",卻寫成恆真的 ||
  if (user.attempts < 5 || user.attempts >= 5) {
    return true;          // 永遠放行,限速/鎖定的判斷被繞過
  }
  return false;
}`,
		fixed: `// 安全寫法：條件真正反映業務規則,輸入不同結果就不同
function allowed(user) {
  // 真正限制:嘗試次數少於 5 且帳戶未鎖定才放行
  return user.attempts < 5 && !user.locked;
}`,
		patch: `@@
 function allowed(user) {
-  if (user.attempts < 5 || user.attempts >= 5) {
-    return true;
-  }
-  return false;
+  return user.attempts < 5 && !user.locked;
 }`,
		refs: ['CWE-571', 'CWE-570', 'OWASP'],
		tags: ['always-true', 'constant-condition', 'logic-error', 'guard-bypass'],
	},
	{
		id: 'CWE-572',
		name: 'Call to Thread run() instead of start()',
		lang: 'java',
		status: 'Complete',
		what: `呼叫執行緒的 run() 而不是 start()。run() 只是「普通的執行體方法」，直接在「呼叫者自己的執行緒」同步執行，
		並不會開一條新的 thread；程式員以為在 launch 非同步跑任務，實際上它同步阻塞在呼叫者身上，新任務沒享受並行、呼叫者卡住、
		錯誤順序或資源釋放被拖到。修法是呼叫 start()，由 JVM 建立新執行緒再於其上執行 run()，雙方的非同步與並行語意才成立；
		若要純在當前 thread 執行，就取名 run 以外的明確方法，避免誤導。`,
		problem: `// 不安全寫法：呼叫 run()，任務在"呼叫者"執行緒同步跑,沒有新 thread
UserService svc = new UserService();
Thread t = new Thread(() -> svc.process());
t.run();                // 直接執行,卡住當前執行緒,並行語意失效
startWork();           // 要等 process 跑完才輪到,順序錯亂`,
		fixed: `// 安全寫法：呼叫 start()，由 JVM 在新執行緒上執行 run()
UserService svc = new UserService();
Thread t = new Thread(() -> svc.process());
t.start();              // 建立新 thread,非同步返回
registerCleanup(t);     // 目前執行緒不被阻塞`,
		patch: `@@
 Thread t = new Thread(() -> svc.process());
-t.run();
+t.start();`,
		refs: ['CWE-572', 'CWE-362', 'OWASP'],
		tags: ['thread-run', 'start-vs-run', 'concurrency', 'blocking'],
	},
	{
		id: 'CWE-574',
		name: 'EJB Bad Practices: Use of Synchronization Primitives',
		lang: 'java',
		status: 'Complete',
		what: `違反 Enterprise JavaBeans（EJB）規範：在 EJB 元件內自行使用同步原語（synchronized、lock、Wait／Notify、
		建立及管理 Thread）。容器才負責管理 EJB 的執行緒與交易模型，程序「自來水」去鎖、開 thread、Wait/Notify，會跟容器對
		作業的管理互相衝突，常見死結、公平性崩壞、交易被錯誤的鎖拖延。這也往往反映「EJB 被寫成有可變共享的狀態」而污染了代
		管使用者／無狀態的定位。修法是撰寫無狀態（stateless）且當執行緒安全的 EJB：不要持有共享可變欄位、不要用同步原語，需要非
		同步／長任務時改用容器提供的方式（@Asynchronous、MessageDriven、JMS），把管理權交回容器。`,
		problem: `// 不安全寫法：EJB 內用 synchronized 保護可變共享狀態,違反 EJB 規範
@Stateless
public class CounterBean {
    private int count;                       // 共享可變狀態本身就不該在 EJB
    public synchronized int next() {          // synchronized + Wait/Notify 違規
        while (count >= MAX) {
            try { wait(); } catch (InterruptedException e) {}
        }
        return count++;
    }
}`,
		fixed: `// 安全寫法：EJB 保持無狀態、交由容器管理,不碰同步或執行緒原語
@Stateless
public class CounterBean {
    // 無狀態:counter 存容器代管的來源(DB/快取),沒有任何執行緒共享欄位
    @Resource
    private DataSource ds;
    public int next() {
        // 資料遞增交給資料庫的單一動作,不靠自己鎖
        return dbNext(ds);   // INSERT ... WHERE ...; 由 DB 保證原子性
    }
}`,
		patch: `@@
 @Stateless
 public class CounterBean {
-    private int count;
-    public synchronized int next() {
-        while (count >= MAX) { try { wait(); } catch (InterruptedException e) {} }
-        return count++;
-    }
+    @Resource private DataSource ds;
+    public int next() {
+        return dbNext(ds);   // 共享狀態交給資料庫,容器不需管理自訂鎖
+    }
 }`,
		refs: ['CWE-574', 'CWE-376', 'OWASP'],
		tags: ['ejb', 'synchronization', 'static-model', 'container-management'],
	},
	{
		id: 'CWE-575',
		name: 'EJB Bad Practices: Use of AWT Swing',
		lang: 'java',
		status: 'Complete',
		what: `違反 Enterprise JavaBeans（EJB）規範：在 EJB 元件裡使用 AWT／Swing 的 GUI 類別。EJB 是在伺服器端、由容器
		管理的元件，根本沒有使用者介面；程式卻自己 import 了 java.awt 或建了 Swing 元件、開視窗或碰 EventQueue，
		既違反規範，也會在無顯示環境（headless）的伺服器上製造不必要的資源開銷與意外行為，還模糊了「介面與業務邏輯的邊界」。修法是把 EJB
		寫成純業務邏輯、不 import 任何 GUI 套件；展示層一律交給 Web（JSF／Servlet）或用戶端，EJB 只專注提供可被呼叫的商業服務。`,
		problem: `// 不安全寫法：EJB 內使用 AWT/Swing GUI 類別,違反無介面的規範
import javax.swing.*;

@Stateless
public class NotifyBean {
    public void alert(String msg) {
        JOptionPane pane = new JOptionPane();   // 伺服器端不該有 Swing GUI
        pane.showMessageDialog(null, msg);
    }
}`,
		fixed: `// 安全寫法：EJB 不碰 GUI,Swing/AWT 留在用戶端,伺服器只提供商業服務
@Stateless
public class NotifyBean {
    @Resource
    MessageDrivenContext ctx;   // 或以 JMS 通知

    public void alert(String msg) {
        ctx.setRollbackOnly();
        // 只發訊息,不建任何視窗 => 伺服器端無介面依賴
        jmsProducer.send(queue, msg);
    }
}`,
		patch: `@@
-import javax.swing.*;
 @Stateless
 public class NotifyBean {
     public void alert(String msg) {
-        JOptionPane pane = new JOptionPane();
-        pane.showMessageDialog(null, msg);
+        jmsProducer.send(queue, msg);   // 只發通知,不建立 GUI
     }
 }`,
		refs: ['CWE-575', 'CWE-376', 'OWASP'],
		tags: ['ejb', 'awt', 'swing', 'headless-server'],
	},
	{
		id: 'CWE-576',
		name: 'EJB Bad Practices: Use of Java I/O',
		lang: 'java',
		status: 'Complete',
		what: `違反 Enterprise JavaBeans（EJB）規範：在 EJB 元件中直接使用 java.io 套件自行讀寫檔案。容器期望 EJB 的資料持久化、
		交易與資源都由它管理，程式自行動手開檔、寫檔、或處理資料流，會繞開容器的管理、難以納入交易與 rollback，也可能寫入不受控
		的位置造成資料不一致或不當外洩，還使部署環境的檔案系統行為不可預測。修法是不要直接在 EJB 用 java.io 做持久化——把資料的保存
		改交給資料庫／JPA／JMS 這類容器認知的傳輸方式；真有小範圍的暫時性檔案操作需求，也要經由容器授權的路徑與交易範圍，而非自行
		開檔做主幹的資料存取。`,
		problem: `// 不安全寫法：EJB 直接用 java.io 自行寫檔當持久化
import java.io.*;

@Stateless
public class FileStoreBean {
    public void save(String id, String body) throws IOException {
        PrintWriter w = new PrintWriter(new FileWriter("/data/" + id));
        w.write(body);              // 自行 I/O,繞開容器交易與資源管理
        w.close();
    }
}`,
		fixed: `// 安全寫法：持久化交給容器管理的 JPA,而非自行 java.io
import javax.persistence.*;

@Stateless
public class DocBean {
    @PersistenceContext EntityManager em;
    public void save(String id, String body) {
        Doc doc = new Doc(id, body);
        em.persist(doc);           // 由容器納入交易,可 rollback
    }
}`,
		patch: `@@
-import java.io.*;
 @Stateless
-public class FileStoreBean {
-    public void save(String id, String body) throws IOException {
-        PrintWriter w = new PrintWriter(new FileWriter("/data/" + id));
-        w.write(body); w.close();
-    }
+public class DocBean {
+    @PersistenceContext EntityManager em;
+    public void save(String id, String body) {
+        em.persist(new Doc(id, body));
+    }
 }`,
		refs: ['CWE-576', 'CWE-376', 'OWASP'],
		tags: ['ejb', 'java-io', 'file-io', 'container-management'],
	},
	{
		id: 'CWE-577',
		name: 'EJB Bad Practices: Use of Sockets',
		lang: 'java',
		status: 'Complete',
		what: `違反 Enterprise JavaBeans（EJB）規範：在 EJB 元件中自行建立 socket 做原始的通訊端連線。容器有責任管理
		位資源與非同步、交易上下文；EJB 一頭自己 open socket、不透過容器的資源池與安全性控管，會阻塞容器執行緒、脫離整個交易的
		完整性，也可能把內部服務位址暴露給未受控的通訊路徑，而且這些連線還不被容器回收管理。修法是不要自己在 EJB 做 socket I/O：改用 JMS、
		Web Service、JCA 這類由容器管理連線的資源，把與外部系統的通訊統一進資源與交易框架；若真要自訂協定，就只在容器外（如
		獨立 MDB／閘道）隔離處理。`,
		problem: `// 不安全寫法：EJB 內自行 new Socket 與外部端點直接代對話
import java.net.*;
import java.io.*;

@Stateless
public class DirectCallBean {
    public String callRemote(String host, int port, String msg) throws IOException {
        try (Socket s = new Socket(host, port)) {      // 自己開 socket,無容器管理
            PrintWriter w = new PrintWriter(s.getOutputStream(), true);
            w.println(msg);
            return new String(s.getInputStream().readAllBytes());
        }
    }
}`,
		fixed: `// 安全寫法：以容器的 JMS 資源發訊息,連線與非同步交由容器
import javax.inject.Inject;
import javax.jms.*;

@Stateless
public class RemoteCallBean {
    @Inject @Resource(mappedName = "java:/jms/replies")
    private JMSContext jms;
    @Resource(mappedName = "java:/jms/queue/reply")
    private Queue reply;

    public String callRemote(String msg) {
        jms.createProducer().send(reply, msg);   // 不自行開 socket
        return jms.createConsumer(reply).receiveBody(String.class, 5000);
    }
}`,
		patch: `@@
-import java.net.*;
 @Stateless
 public class DirectCallBean {
-    public String callRemote(String host, int port, String msg) throws IOException {
-        try (Socket s = new Socket(host, port)) { ... }
-    }
+    @Resource(mappedName = "java:/jms/queue/reply") Queue reply;
+    @Resource JMSContext jms;
+    public String callRemote(String msg) {
+        jms.createProducer().send(reply, msg);
+        return jms.createConsumer(reply).receiveBody(String.class, 5000);
+    }
 }`,
		refs: ['CWE-577', 'CWE-376', 'OWASP'],
		tags: ['ejb', 'sockets', 'jms', 'resource-management'],
	},
	{
		id: 'CWE-578',
		name: 'EJB Bad Practices: Use of Class Loader',
		lang: 'java',
		status: 'Complete',
		what: `違反 Enterprise JavaBeans（EJB）規範：在 EJB 元件中直接碰 class loader（自行 Class.forName、new 一個
		ClassLoader、或改 loader 上下文）。容器用球動 class loader 來隔離跟管理部署；程式自作主張載入類別，可能載到錯的類別
		版本、繞過安全或身分隔離、使部署與升級的 classpath 無法如期對應，甚至成為把不可信流量當類別名而載入的入口。修法是不要動
		class loader：加上類別類型或開除由容器把 inject；真正需要動態載入時必要也以受控制、白名單的對映放在容器外處理，或改用
		CDI／JNDI 拿容器代管的執行個體。`,
		problem: `// 不安全寫法：EJB 內自行 Class.forName + 直接操作 class loader
@Stateless
public class LoaderBean {
    public Object make(String type) throws Exception {
        // type 可被呼叫端影響,動態載入類別
        Class<?> cls = Class.forName("com.app.plugins." + type);
        return cls.getDeclaredConstructor().newInstance();
    }
}`,
		fixed: `// 安全寫法：用容器管理的 CDI 介面,不碰 class loader
@Stateless
public class PluginBean {
    @Inject @Any Instance<Plugin> plugins;   // 由容器代管實例

    public Plugin make(String type) {
        // 只挑容器管理、已知的 Plugin 實例,不對字串做任意類別載入
        return plugins.select(new TypeQualifier(type)).get();
    }
}`,
		patch: `@@
 @Stateless
 public class LoaderBean {
-    public Object make(String type) throws Exception {
-        Class<?> cls = Class.forName("com.app.plugins." + type);
-        return cls.getDeclaredConstructor().newInstance();
-    }
+    @Inject @Any Instance<Plugin> plugins;
+    public Plugin make(String type) {
+        return plugins.select(new TypeQualifier(type)).get();
+    }
 }`,
		refs: ['CWE-578', 'CWE-376', 'OWASP'],
		tags: ['ejb', 'class-loader', 'dynamic-loading', 'container'],
	},
	{
		id: 'CWE-579',
		name: 'J2EE Bad Practices: Non-serializable Object Stored in Session',
		lang: 'java',
		status: 'Complete',
		what: `J2EE 把「無法序列化的物件」直接存成 HttpSession 屬性。Session 要能被容器拿去做 passivation、複製到叢集、
		或存回磁碟，就必須是可序列化的資料；一旦塞了不可序列化的物件，當容器要做 passivation／叢集複製／session 重新啟動時，無法把
		它寫到外部，連線與工作被中斷、狀態遺失或整條交易失敗。這也常讓開發者「以為 session 裡的狀態可安全保存」卻在叢集或
		停機恢復時才發現拿不回來。修法是只把可序列化物件（基本型別、String、以及實作 Serializable 的 DTO）放
		進 session；需要暫存共享物件時把它轉成可序列化資料再存、或存放在容器代管的物件中。`,
		problem: `// 不安全寫法：把不可序列化的服務/連線物件直接塞進 HttpSession
public void store(HttpServletRequest req, DataSource ds) {
    // 把 ds 這種不可序列化物件放進 session -> 叢集/passivation 會壞
    req.getSession().setAttribute("db", ds);
    req.getSession().setAttribute("ui", new NonSerializableUIThing());
}`,
		fixed: `// 安全寫法：session 只放可序列化物件,資源用 JNDI 重新查
public void store(HttpServletRequest req, Serializable meta) {
    // 只存可序列化的簡單資料
    req.getSession().setAttribute("meta", meta);
    // 資源類別不存 session,需要時由 JNDI 再取
}`,
		patch: `@@
 public void store(HttpServletRequest req, DataSource ds) {
-    req.getSession().setAttribute("db", ds);
-    req.getSession().setAttribute("ui", new NonSerializableUIThing());
+    req.getSession().setAttribute("meta", meta);
 }`,
		refs: ['CWE-579', 'CWE-664', 'OWASP'],
		tags: ['j2ee', 'session', 'serialization', 'cluster'],
	},
	{
		id: 'CWE-580',
		name: 'clone() Method Without super.clone()',
		lang: 'java',
		status: 'Complete',
		what: `覆寫 clone() 卻沒有呼叫 super.clone()。Object 的克隆是靠 super.clone() 先回傳「同類別、欄位值的快照」的
		物件，正確的 clone() 通常第一行就是回傳 super.clone()。若你自己 new 一個新物件、再手動搬欄位，就繞過了
		super.clone() 提供的正確型別與物件狀態基礎，可能在 clone 後得到型別錯、欄位沒複到、原生底層資源沒正確複製的物件，甚至違反
		clone 合約造成一堆場所以為「複製一份」其實拿到的是別的東西。修法是讓類別實作 Cloneable，clone() 內第一行就回傳 super.clone()，
		再依需要進行 deep copy，而不要自己 new 出來回傳。`,
		problem: `// 不安全寫法：clone() 自行 new 新物件手動搬欄位,未走 super.clone()
public class Account implements Cloneable {
    private String id;
    @Override public Account clone() {
        Account a = new Account();       // 沒有 super.clone()
        a.id = this.id;
        return a;                       // 型別/底層狀態的複製合約被繞過
    }
}`,
		fixed: `// 安全寫法：回傳 super.clone(),保證型別與欄位快照正確
public class Account implements Cloneable {
    private String id;
    @Override public Account clone() {
        try {
            return (Account) super.clone();   // 走 Object 的 clone
        } catch (CloneNotSupportedException e) {
            throw new AssertionError(e);
        }
    }
}`,
		patch: `@@
 public class Account implements Cloneable {
     @Override public Account clone() {
-        Account a = new Account();
-        a.id = this.id;
-        return a;
+        try {
+            return (Account) super.clone();
+        } catch (CloneNotSupportedException e) {
+            throw new AssertionError(e);
+        }
     }
 }`,
		refs: ['CWE-580', 'CWE-374', 'OWASP'],
		tags: ['clone', 'super-clone', 'cloneable', 'object-contract'],
	},
	{
		id: 'CWE-581',
		name: 'Object Model Violation: Just One of Equals and Hashcode Defined',
		lang: 'java',
		status: 'Complete',
		what: `違反 Java 物件模型：equals() 與 hashCode() 只覆寫了其中一個。Java 規定「相等的兩個物件其 hashCode 必
		須相等」。若你覆寫了 equals() 卻沒同步覆寫 hashCode()（或反過來），兩物件在 equals() 說的「相等」在 hashCode 上卻不相等；
		把它們塞進 HashSet／HashMap 時，就基於 hash 分成不同桶子，查詢就永遠驗不到兩者相等——重複的元素被重複加入、用 key 找
		不到原本加入的物件、去重失效、甚至少算資料。修法是兩者永遠一起覆寫，保證 equals() 為真的物件 return 相同的 hashCode，
		並用相等的欄位集合來推導兩者。`,
		problem: `// 不安全寫法：只覆寫 equals() 沒覆寫 hashCode()
public class User {
    private final String email;
    // equals 依 email 視相等...
    @Override public boolean equals(Object o) {
        return o instanceof User && email.equals(((User) o).email);
    }
    // ...卻沒有對應的 hashCode() => HashSet 無法去重/查得相等物件
}`,
		fixed: `// 安全寫法：equals 與 hashCode 用同一組欄位一起覆寫
public class User {
    private final String email;
    @Override public boolean equals(Object o) {
        return o instanceof User && email.equals(((User) o).email);
    }
    @Override public int hashCode() {
        return email.hashCode();   // 相等物件 => 相同 hash
    }
}`,
		patch: `@@
     @Override public boolean equals(Object o) {
         return o instanceof User && email.equals(((User) o).email);
     }
+    @Override public int hashCode() {
+        return email.hashCode();
+    }
 }`,
		refs: ['CWE-581', 'CWE-1093', 'OWASP'],
		tags: ['equals', 'hashcode', 'object-model', 'hashset'],
	},
	{
		id: 'CWE-582',
		name: 'Array Declared Public, Final, and Static',
		lang: 'java',
		status: 'Complete',
		what: `把一個陣列宣告成 public、final、static，以為這樣就不可變。其實底層它只把「陣列的參考」弄成 final，而陣列
		的『內容』依然是可變的——任何一支能存取到這個欄位的程式都能直接以「索引賦值」（WHITE_ORIGINS[0]=...）改掉內容。把它當
		「唯讀常數」用的地方全會被竄改：權限表、白名單、組態值任誰都能換成對自己有利的版本。修法是不要讓「可變內容」披著 public
		final static 的外衣：欄位改成 private，對外改提供 clone() 或 Collections.unmodifiableList 傳回不可變副本，確保呼叫端拿到的
		是不可變的暫存副本，而不是真正陣列本身。`,
		problem: `// 不安全寫法：public final static 陣列,內容仍可被任何程式改值
public class Config {
    // 以為是"唯讀常數"
    public static final String[] WHITE_ORIGINS = {
        "https://trusted.example"
    };
    // 任一支程式都能 Config.WHITE_ORIGINS[0] = "https://evil.example"
}`,
		fixed: `// 安全寫法：private 欄位,對外只給不可變副本
import java.util.*;

public class Config {
    private static final String[] WHITE_ORIGINS = { "https://trusted.example" };
    public static List<String> allowedOrigins() {
        return Collections.unmodifiableList(Arrays.asList(WHITE_ORIGINS.clone()));
    }
}`,
		patch: `@@
 public class Config {
-    public static final String[] WHITE_ORIGINS = { "https://trusted.example" };
+    private static final String[] WHITE_ORIGINS = { "https://trusted.example" };
+    public static List<String> allowedOrigins() {
+        return Collections.unmodifiableList(Arrays.asList(WHITE_ORIGINS.clone()));
+    }
 }`,
		refs: ['CWE-582', 'CWE-600', 'OWASP'],
		tags: ['public-array', 'mutable', 'constant', 'immutable'],
	},
	{
		id: 'CWE-583',
		name: 'finalize() Method Declared Public',
		lang: 'java',
		status: 'Complete',
		what: `把 finalize() 宣告成 public（而非常規的 protected）。finalize() 是「由 GC 在物件被收回前呼叫」的清理點，
		本應留在 protected，外部不該能自由呼叫；改成 public 之後，任何一支程式（mobile code、不可信片段）都能直接呼叫某物件的
		finalize()，讓清理在「物件仍被使用、仍是敏感狀態」的時刻搶先執行，導致物件被使用者自己破壞、資源被提前釋放或狀態錯亂。
		這是對 mobile code 安全編碼原則的違反。修法是保持 finalize() 為 protected（且使用時必要呼叫 super.finalize()），不把清理
		API 敞開給外部；更理想是不要 override finalize，改用 try-with-resources 或 Cleaner 管理資源。`,
		problem: `// 不安全寫法：public 化的 finalize(),任一支不可信程式都能提前叫它
public class Key {
    private byte[] secret;
    public void finalize() {         // public!外部可直接觸發清理
        Arrays.fill(secret, (byte) 0);
    }
    public byte[] use() { /* ... */ }
}`,
		fixed: `// 安全寫法：finalize 保持 protected,清理由 GC 依契約觸發
public class Key {
    private byte[] secret;
    @Override protected void finalize() {   // 對外不可直接呼叫
        Arrays.fill(secret, (byte) 0);
    }
    public byte[] use() { /* ... */ }
}`,
		patch: `@@
 public class Key {
     private byte[] secret;
-    public void finalize() {
+    @Override protected void finalize() {
         Arrays.fill(secret, (byte) 0);
     }
 }`,
		refs: ['CWE-583', 'CWE-13', 'OWASP'],
		tags: ['finalize', 'public-finalize', 'mobile-code', 'cleanup'],
	},
	{
		id: 'CWE-584',
		name: 'Return Inside Finally Block',
		lang: 'java',
		status: 'Complete',
		what: `在 finally 區塊內放一個 return（或拋例外以類似方式使用）。finally 的執行順序是「try 正常或例外後都會先跑」，
		若裡頭有 return，它會把 try 區正要拋出的任何例外「整個吞掉」，改以 finally 的 return 作為方法結果——異常丟不掉、呼叫端永遠
		以為成功了。尤其是把例外訊息、錯誤狀態藏起來的 finally-return，除錯困難，還可能讓被 try 內已偵察到的嚴重錯誤徹底隱形，
		副作用照做但結果說是好的。修法是不要在 finally 回傳值：把 return 移到 try/catch 之後，finally 只做資源釋放等清理動作，
		讓要傳出的例外與回傳值各自已確定。`,
		problem: `// 不安全寫法：finally 裡的 return 吞掉 try 拋出的例外
public boolean commit() {
    try {
        risky();           // 這裡拋 RuntimeException
        return true;
    } finally {
        close();          // 清理ok
        return false;     // 把上面的例外吞掉,呼叫端以為一切正常
    }
}`,
		fixed: `// 安全寫法：return 移到 try/catch 外,finally 只做清理
public boolean commit() {
    boolean ok;
    try {
        risky();
        ok = true;
    } finally {
        close();          // finally 不 return,只做資源清理
    }
    return ok;            // 例外自然往上拋、不會被吞
}`,
		patch: `@@
 public boolean commit() {
+    boolean ok;
     try {
         risky();
-        return true;
+        ok = true;
     } finally {
         close();
-        return false;
     }
+    return ok;
 }`,
		refs: ['CWE-584', 'CWE-396', 'OWASP'],
		tags: ['finally', 'return-in-finally', 'swallow-exception', 'cleanup'],
	},
	{
		id: 'CWE-585',
		name: 'Empty Synchronized Block',
		lang: 'java',
		status: 'Complete',
		what: `有 synchronized 區塊卻是空的：上鎖後沒有在 lock 保護下做任何實際的「讀取→判斷→寫入」，只是一段空架子或不觸及
		共享狀態的敘述，就釋放鎖。這樣形同沒上鎖——多支執行緒各跑進空區塊又出來，畫面「有同步」，真正會被改到的共享狀態卻是裸著被
		存取，競態照樣發生；而且還徒增鎖定與排隊的開銷，甚至讓人誤以為那一段已經受保護，把檢查東一塊西一塊放進空的 synchronized。修
		法是讓 synchronized 的範圍真實涵蓋到「共享資料的整個 read→check→write」臨界段；若真的沒有任何需保護的共享狀態，就把這個空同步
		區塊刪掉，別留空殼誤導。`,
		problem: `// 不安全寫法：synchronized 區塊是空的,真正共享狀態在鎖外被存取
public class Balance {
    private int balance;
    private final Object lock = new Object();

    public boolean decrement(int v) {
        synchronized (lock) {
            // 空的!沒有在鎖內做任何事
        }
        balance -= v;            // 真正會競態的更新卻在鎖外裸跑
        return true;
    }
}`,
		fixed: `// 安全寫法：把共享狀態的 read-check-write 整個包進 synchronized
public class Balance {
    private int balance;
    private final Object lock = new Object();

    public boolean decrement(int v) {
        synchronized (lock) {
            if (balance < v) return false;   // 讀取、判斷在鎖內
            balance -= v;                    // 寫入也在同一把鎖內
            return true;
        }
    }
}`,
		patch: `@@
     public boolean decrement(int v) {
         synchronized (lock) {
-            // 空的!
         }
-        balance -= v;
+        if (balance < v) return false;
+        balance -= v;
        return true;
     }`,
		refs: ['CWE-585', 'CWE-413', 'OWASP'],
		tags: ['synchronized', 'empty-block', 'critical-section', 'lock'],
	},
	{
		id: 'CWE-586',
		name: 'Explicit Call to Finalize()',
		lang: 'java',
		status: 'Complete',
		what: `從 finalizer 外部對物件「顯式呼叫」finalize()。finalize() 應只由 GC 在物件將被收回前呼叫一次；程式自己在使用中
		的部位去呼叫它，等同「手動觸發清理」：資源會被提前釋放、物件的內部狀態可能被清空（如把 sensitive bytes 抹零、關閉連接），可
		物件卻還繼續被拿去用。這既違反生命周期的契約，也可能讓不可信程式破壞某一還在場的物件；該物件之後若又被 GC 收回，甚至可能再
		被呼叫一次，造成雙重清理。修法是不要呼叫 finalize()：把資源釋放改成明確的 close()／try-with-resources／或 Java 9 的 Cleaner，由正當的清理路徑觸
		發，而不要把「該被 GC 管的清理」當普通方法叫出來。`,
		problem: `// 不安全寫法：外在程式直接呼叫物件.finalize(),提前觸發清理
public void finish(Cipher c) {
    byte[] zero = ...;
    c.finalize();                // 顯式呼叫!物件還可能再被使用,狀態已被清掉
}
// 之後同一物件被 GC 收可能再被 finalize,雙重清理/競態`,
		fixed: `// 安全寫法：不用 Finalize,改成明確的 close()/try-with-resources 讓正當清理路徑釋放資源
public void finish() {
    try (Cipher c = new Cipher()) {   // Cipher 實作 AutoCloseable
        c.process(raw);                  // 用完自動呼叫 close(),不是手動 finalize
    }
}`,
		patch: `@@
- public void finish(Cipher c) {
-     byte[] zero = ...;
-     c.finalize();            // 顯式呼叫不可
- }
+ public void finish() {
+     try (Cipher c = new Cipher()) {
+         c.process(raw);
+     }
+ }`,
		refs: ['CWE-586', 'CWE-404', 'OWASP'],
		tags: ['finalize', 'explicit-call', 'cleaner', 'lifecycle'],
	},
	{
		id: 'CWE-589',
		name: 'Call to Non-ubiquitous API',
		lang: 'c',
		status: 'Complete',
		what: `呼叫了「不是所有版本／平台都支援」的 API（non-ubiquitous）。程式用它覆蓋某種平台上新的或只有特定 glibc/libc、
		特定建構才存在的函式，卻沒有對其它版本做相容或防護。把它編到舊環境就回找不到符號或執行期行為難以預期，產生可移植性問題、
		不一致、甚至讓該路徑直接崩潰，你我應用的可用性（DoS）。修法是確認目標安裝面的 API 涵蓋範圍，改用一版都有的 API，或在呼叫前以
		feature 測試／版本檢查加上 fallback，確保對不支援的版本走另一條路。`,
		problem: `# 不安全寫法：用只在較新 libc 支援的 API,老環境直接跑不動
#include <stdio.h>
#include <string.h>

void send_reply(char* buf, size_t len) {
    // gets_s / vsnprintf_s 等 _s 族並非普遍存在於所有 libc
    errno_t e = memcpy_s(buf, len, "ok", 2);   // 未檢查目標平台是否有此 API
    if (e != 0) { /* 老平台 compile/執行可能直接失敗 */ }
}`,
		fixed: `# 安全寫法：用普遍的 API,或先做 feature 偵測再提供 fallback
#include <stdio.h>
#include <string.h>

void send_reply(char* buf, size_t len) {
#if defined(__STDC_LIB_EXT1__)               // 有 _s 族才用
    errno_t e = memcpy_s(buf, len, "ok", 2);
#else                                        // 否則走標準可移植寫法
    memcpy(buf, "ok", 2);
#endif
}`,
		patch: `@@
 void send_reply(char* buf, size_t len) {
-    errno_t e = memcpy_s(buf, len, "ok", 2);
-    if (e != 0) { }
+#if defined(__STDC_LIB_EXT1__)
+    errno_t e = memcpy_s(buf, len, "ok", 2);
+#else
+    memcpy(buf, "ok", 2);
+#endif
 }`,
		refs: ['CWE-589', 'CWE-477', 'OWASP'],
		tags: ['non-ubiquitous-api', 'portability', 'feature-detect', 'dos'],
	},
	{
		id: 'CWE-591',
		name: 'Sensitive Data Storage in Improperly Locked Memory',
		lang: 'c',
		status: 'Complete',
		what: `把敏感資料（密鑰、口令、token）存放進「未被正確鎖定」的記憶體：既沒有用 mlock()／mlockall() 把頁面鎖在實體
		RAM，或用了 mlock() 卻沒檢查回傳值（鎖失敗也當作成功），記憶體管理員便可能把這些頁面換出（swap）到磁碟上的換頁檔。換頁檔
		不必有系統權限的讀取途徑就可能被外部者翻出密鑰，等於把機密明文寫下遺在磁碟。修法是分配機密緩衝後呼叫 mlock()／mlockall()，
		檢查其回傳值確認真的鎖成功且在範圍內，用後先以確認優化器不會搬走的作法（secure_zero／volatile）抹零再釋放，並避免把機密放進
		系統可能換出的暫存區。`,
		problem: `# 不安全寫法：密鑰放 heap,既沒鎖定也沒有檢查鎖失敗
#include <stdlib.h>
#include <string.h>

void load_key(const char* secret) {
    char* buf = strdup(secret);       // 從 heap 分,沒有 mlock
    /* 有用的時間很長,期間頁面被換出去 => secret 落進 swap 碟上 */
    use(buf);
    free(buf);                        // 釋放前也沒抹零
}`,
		fixed: `# 安全寫法：機密頁 mlock 住、確認成功,用後抹零再換
#include <sys/mman.h>
#include <string.h>

void load_key(const char* secret) {
    size_t n = strlen(secret) + 1;
    char* buf = malloc(n);
    if (mlock(buf, n) != 0) {          // 鎖定失敗要察覺,不是默默繼續
        secure_deny(buf); return;
    }
    memcpy(buf, secret, n);
    use(buf);
    secure_zero(buf, n);               // 用先整頁抹零再 unlock/free
    munlock(buf, n);
    free(buf);
}`,
		patch: `@@
 void load_key(const char* secret) {
-    char* buf = strdup(secret);
-    use(buf);
-    free(buf);
+    size_t n = strlen(secret) + 1;
+    char* buf = malloc(n);
+    if (mlock(buf, n) != 0) { return; }
+    memcpy(buf, secret, n);
+    use(buf);
+    secure_zero(buf, n);
+    munlock(buf, n);
+    free(buf);
 }`,
		refs: ['CWE-591', 'CWE-316', 'OWASP'],
		tags: ['mlock', 'swap', 'sensitive-memory', 'key-material'],
	},
	{
		id: 'CWE-593',
		name: 'Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created',
		lang: 'c',
		status: 'Complete',
		what: `在 SSL 物件（SSL 連線）已經由某個 SSL_CTX 建立之後，才去修改那個 SSL_CTX。SSL_* 大部分參數是在建立連線時
		從 SSL_CTX 複製／決定下來的；連線建立後才改 CTX，存有的連線物件看不到修改、或看到一半的混亂狀態。尤其惡意的場是：程式以為
		「我一開始設定了驗證 callback／驗證模式」，卻是在建立連線之後才去改 SSL_CTX 的驗證設定，已有的連線沒套上，
		證書驗證形同沒跑，造成身分／認證繞過——連線仍連但驗證被沉默關掉。修法是把所有 SSL_CTX 設定（驗證模式、憑證、callback）都擺在
		任何 SSL 物件建立之前做完；需要不同設定就各自建立獨立的 SSL_CTX，不要在生前改共用 CTX。`,
		problem: `// 不安全寫法：先開連線才改 SSL_CTX 驗證設定 -> 既有連線的驗證形同沒有
SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
SSL* ssl = SSL_new(ctx);                       // 連線已由目前 CTX 建立
SSL_set_tlsext_host_name(ssl, host);          // ...
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, cb); // 太晚!這支 ssl 已被決定不套驗證
SSL_connect(ssl);                              // 完成連線,卻沒執行 peer 驗證`,
		fixed: `// 安全寫法：驗證設定在建立任何 SSL 物件前就緒,不同設定用各自 CTX
SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, cb);   // 設定在前
SSL_CTX_load_verify_locations(ctx, caFile, NULL);
SSL* ssl = SSL_new(ctx);                          // 建立即帶走正確的驗證設定
SSL_connect(ssl);`,
		patch: `@@
 SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
-SSL* ssl = SSL_new(ctx);
-SSL_set_tlsext_host_name(ssl, host);
-SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, cb);
+SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, cb);
+SSL_CTX_load_verify_locations(ctx, caFile, NULL);
+SSL* ssl = SSL_new(ctx);
 SSL_connect(ssl);`,
		refs: ['CWE-593', 'CWE-295', 'OWASP'],
		tags: ['openssl', 'ssl-ctx', 'verify', 'auth-bypass'],
	},
	{
		id: 'CWE-594',
		name: 'J2EE Framework: Saving Unserializable Objects to Disk',
		lang: 'java',
		status: 'Complete',
		what: `J2EE 容器要「把不可序列化的物件寫到磁碟」（session passivation、entity／stateful 物件的長期暫存）時，無法保證成功：
		容器靠 Java 序列化把記憶體狀態搬去磁碟，物件不能序列化就無法完整還原，或寫到一半才失敗。後果是可靠性問題——undefined state、
		交易進行錯誤地中斷、資料遺失——而且它往往在附況（叢集容錯、狀態恢復）才暴露，平時測不出。修法是讓進入容器持久化／passivation
		的物件都實作 Serializable（或轉成可序列化的 DTO／資料結構再交給容器），避免把不可序列化物件暫存磁碟；一時性的狀態就存在記憶體或
		session 有意義的範圍內，不在層要跨完整性保證時硬要「存」。`,
		problem: `# 不安全寫法：把不可序列化物件直接放進會 passivation/寫碟的容器狀態
@Stateful
public class ShoppingCart {
    private final CartClient client;         // 不可序列化
    // 容器對狀態做 passivation 存到硬碟時,無法把 client 寫出 => 存碟/恢復可能失敗
    public void add(String item) { client.push(item); }
}`,
		fixed: `# 安全寫法：被容器暫存的狀態只放可序列化物件,資源靠外部重找
@Stateful
public class ShoppingCart {
    private List<String> items = new ArrayList<>();   // Serializable
    @Transient CartClient client;                    // 不隨狀態持久化

    public void add(String item) {
        items.add(item);
    }
    @PostActivate void reinit() { client = buildClient(); }  // 恢復後重生資源
}`,
		patch: `@@
 @Stateful
 public class ShoppingCart {
-    private final CartClient client;
-    public void add(String item) { client.push(item); }
+    private List<String> items = new ArrayList<>();
+    @Transient CartClient client;
+    public void add(String item) { items.add(item); }
+    @PostActivate void reinit() { client = buildClient(); }
 }`,
		refs: ['CWE-594', 'CWE-579', 'OWASP'],
		tags: ['j2ee', 'serialization', 'passivation', 'stateful'],
	},
	{
		id: 'CWE-595',
		name: 'Comparison of Object References Instead of Object Contents',
		lang: 'java',
		status: 'Complete',
		what: `用「參考比較」（==）而不是「內容比較」（.equals()）去比較兩個物件。字串、包裝型別、集合這類以『值』為語意的
		物件，用 == 比的是兩者是不是「同一個實例」，而不是內容是否相同。結果是內容一模一樣的兩個物件（例如兩份來自不同來源的相同字串）
		被當成不同；反之強制讓系統「原本預期的相等」失準，驗證碼比對、去重、快取 key、基準判定都可能放行不該放行的或漏掉該視為相同者。
		修法是在需要比較「內容」時一律用 equals()／Objects.equals()，只有真的要比「是不是同一個物件」才用 ==，並對可能為 null 的一方用
		Objects.equals 防空。`,
		problem: `// 不安全寫法：用 == 比較字串/包裝型別的內容,兩個相同字串被當不同
String stored = loadStoredToken();
String given = computeToken(input);
if (stored == given) {          // 參考比較!兩個內容相同的 String 實例 !=
    grant();
}`,
		fixed: `// 安全寫法：內容比較用 equals / Objects.equals
String stored = loadStoredToken();
String given = computeToken(input);
if (Objects.equals(stored, given)) {   // 內容相同即相等,且防 null
    grant();
}`,
		patch: `@@
 String stored = loadStoredToken();
 String given = computeToken(input);
-if (stored == given) {
+if (Objects.equals(stored, given)) {
     grant();
 }`,
		refs: ['CWE-595', 'CWE-697', 'OWASP'],
		tags: ['reference-comparison', 'equals', 'identity', 'string'],
	},
	{
		id: 'CWE-596',
		name: 'DEPRECATED: Incorrect Semantic Object Comparison',
		lang: 'java',
		status: 'Deprecated',
		what: `此條已被官方標記為 Deprecated：它原本描述「不正確的語意層面物件比較」，但描述得含糊、不易與其它條目區分，也因
		領域特定考慮而「不適宜」給一個獨立 ID。官方不再建議直接以本 ID 對映實際漏洞；其最接近的對等條目是 CWE-1023（Incomplete Comparison
		with Missing Factors）與 CWE-697（Incorrect Comparison）。實質風險仍是「比較邏輯漏了關鍵因子、或比較的語意與預期不符」；遇到時請改用
		CWE-1023／CWE-697，並向上覆蓋：比較必須涵蓋確定兩個物件「相等」所需的全部欄位，且以 equals／語意比較而非身份或省略性比較。`,
		problem: `// 潛在錯誤示範:比較時漏了真正該比的欄位(正式對映看 CWE-1023)
public boolean sameSession(Session a, Session b) {
    if (a == null || b == null) return false;
    if (a.user == b.user) return true;   // 只比身份,漏掉真正判等的 id/旗標
    return a.user.equals(b.user);
}`,
		fixed: `// 完整比較:涵蓋判定相等的所有必要欄位
public boolean sameSession(Session a, Session b) {
    if (a == null || b == null) return false;
    return a.id.equals(b.id) && a.active == b.active && a.scope.equals(b.scope);
}`,
		patch: `@@
 public boolean sameSession(Session a, Session b) {
     if (a == null || b == null) return false;
-    return a.user.equals(b.user);
+    return a.id.equals(b.id) && a.active == b.active && a.scope.equals(b.scope);
 }`,
		refs: ['CWE-596', 'CWE-1023', 'OWASP'],
		tags: ['deprecated', 'comparison', 'equals', 'cwe-1023'],
	},
];
