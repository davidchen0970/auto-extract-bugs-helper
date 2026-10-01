// CWE chunk — category: Gap 批次04（補充條目：敏感資料存放 / 日誌 / 輸入處理 / 密碼 / 權限 / 憑證）.
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
		id: 'CWE-219',
		name: 'Storage of File with Sensitive Data Under Web Root',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `敏感檔案存放於 Web 根目錄之下（Storage of File with Sensitive Data Under Web Root）。程式把資料庫備份、含密碼的設定檔、
		金鑰或使用者上傳的私人檔案，直接放在網頁伺服器可經由 HTTP 直連的根目錄底下，又只靠「沒人知道網址」的隱晦保護，沒有配上真正的存取控制。
		成因為圖一時方便把檔案擺在靜態檔同一個根目錄，誤把「檔名難猜」當成防護，甚至漏關 list 目錄的功能。後果是任何人只要猜中或列舉到網址
		（/backup、db-dump.sql、.zip、.sql.gz、.env），就能未登入下載到機密；這些檔案還會被搜尋引擎索引、被掃描工具發現。修法是敏感檔案一律放置在
		Web 根目錄之外、不經由 HTTP 直連的位置，改由應用程式搭配驗證／授權動態讀取，並移除殘留的備份與暫存檔、關閉目錄列舉。`,
		problem: `// 不安全寫法：把含機密的備份檔放在靜態目錄，任何人可直接下載
const express = require('express');
const app = express();
app.use('/static', express.static('public'));
// public/backup/db.sql 內含明文密碼與個資，網址等同公開
// http://host/static/backup/db.sql 即可直接下載`,
		fixed: `// 安全寫法：敏感檔移到 web root 之外，經受保護的路由驗證後才送出
const fs = require('fs');
const path = require('path');
const VAULT = path.join(__dirname, '..', 'private');   // 不在靜態根下
app.get('/backup', requireAuth, (req, res) => {
  if (req.session.role !== 'admin') return res.sendStatus(403);
  res.download(path.join(VAULT, 'db.sql'));            // 驗證通過才給檔
});`,
		patch: `@@
-  app.use('/static', express.static('public'));
+  const VAULT = path.join(__dirname, '..', 'private');
+  app.get('/backup', requireAuth, (req, res) => {
+    if (req.session.role !== 'admin') return res.sendStatus(403);
+    res.download(path.join(VAULT, 'db.sql'));
+  });`,
		refs: ['CWE-219', 'OWASP-Files'],
		tags: ['sensitive-data', 'web-root', 'file-storage'],
	},
	{
		id: 'CWE-220',
		name: 'Storage of File With Sensitive Data Under FTP Root',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `敏感檔案存放於 FTP 根目錄之下（Storage of File With Sensitive Data Under FTP Root）。程式把密碼、金鑰、客戶資料這類敏感檔
		放在 FTP 伺服器的根目錄，卻未配上相符的存取控制——很多 FTP 伺服器預設允許匿名登入、或允許帳號讀取整個根下內容。成因為貪圖讓使用者經由
		FTP 方便取檔，而沒有為每個使用者建立可隔離的家目錄、更沒關掉徹余多的權限或匿名通道。後果是任何能連上該 FTP 站的人一登入就列得出整份
		機密檔、下載別人上傳的資料，等於把敏感檔直接公開。修法是為每個使用者建立專屬且隔離的目錄、以最小權限設定 ACL，並把敏感檔改放到 FTP 根
		之外由受控的通訊管道（HTTPS／SFTP＋授權）發送，FTP 本身則關閉匿名與過寬的權限。`,
		problem: `// 不安全寫法：把備份倒進 FTP 根目錄，還開啟匿名讀取
vsftpd: anonymous_enable=YES
# 根目錄 /srv/ftp 直接放 db_dump.sql + 使用者的私人上傳`,
		fixed: `// 安全寫法：FTP 只做可隔離的家目錄與最小權限，敏感檔由受控管道送出
vsftpd: anonymous_enable=NO
local_enable=YES
chroot_local_user=YES      // 每位使用者被鎖在自己家目錄
# 備份改由 app 搭配授權、透過 HTTPS 供應，不放 FTP 根`,
		patch: `@@
-  anonymous_enable=YES
-  # /srv/ftp 直接放 db_dump.sql
+  anonymous_enable=NO
+  local_enable=YES
+  chroot_local_user=YES`,
		refs: ['CWE-220', 'OWASP-Files'],
		tags: ['ftp', 'sensitive-data', 'file-storage'],
	},
	{
		id: 'CWE-223',
		name: 'Omission of Security-relevant Information',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `遺漏安全攸關的資訊（Omission of Security-relevant Information）。當警告或錯誤發生時，程式沒有記錄、或沒有顯示能用來判斷「這次動作
		是否安全、攻擊來自誰、性質為何」的關鍵資訊——像是請求來源 IP、使用者識別、失敗原因、操作內容、時間戳，甚至整個漏記。成因為只打簡短的 error、
		把安全事件當一般無關緊要的事件忽略、或忽略相關欄位來圖降低記錄成本。後果是管理者偵測不到入侵、把攻擊誤判成正常流量、無法還原責任歸屬，
		也無法證明某個動作真的安全。修法是為安全攸關的事件明確定義「要記哪些欄位」（時間、來源、動作、對象、結果），把驗證失敗、權限拒絕、機敏操作
		一律寫入不可竄改的稽核日誌，顯示給使用者的訊息再另行遮蔽。`,
		problem: `// 不安全寫法：失敗只回錯誤，沒留下來源、帳號與原因
catch (err) {
  res.sendStatus(403);           // 管理者沒有任何線索知道誰、做了什麼、為何被擋
}`,
		fixed: `// 安全寫法：把安全攸關欄位全部記進稽核日誌，才回遮蔽過的回應
catch (err) {
  audit.log({
    ts: Date.now(), src: req.ip, user: req.session?.uid,
    action: req.path, denied: true, reason: String(err)
  });
  res.sendStatus(403);           // 判定依據都留檔，使用者只拿到 403
}`,
		patch: `@@
  catch (err) {
+   audit.log({
+     ts: Date.now(), src: req.ip, user: req.session?.uid,
+     action: req.path, denied: true, reason: String(err)
+   });
    res.sendStatus(403);
  }`,
		refs: ['CWE-223', 'OWASP-Logging'],
		tags: ['logging', 'audit', 'security-events'],
	},
	{
		id: 'CWE-224',
		name: 'Obscured Security-relevant Information by Alternate Name',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `以別名遮蔽掉安全攸關資訊（Obscured Security-relevant Information by Alternate Name）。程式記錄安全攸關事件時，用的是當事實體的「別名／
		別稱」而不是官方一致的「標準名稱（canonical name）」。同一個使用者、主機或檔名，有時記別名有時記標準名，甚至不同碼員各自用不同的寫法（縮寫、
		大小寫、暱稱）。成因為沒有統一的名稱正規化程序，動態把別名寫進日誌時也不曾解析到標準名。後果是把同一個實體的記錄拆散在多個名字下拉不整，
		管理者比對、彙整與追蹤安全事件時漏算或重算，掩蓋真相、誤判責任。修法是在寫日誌前先把別名解析並正規化成唯一的標準名稱，所有判定與彙整都以
		標準名為基準。`,
		problem: `// 不安全寫法：有時記 user.loginName，有時記 user.nickname，同一人拆成兩串
function logFail(u) {
  logger.warn('login failed', key = u.nickname || u.loginName);   // 名稱不統一
}`,
		fixed: `// 安全寫法：一律先解析到標準使用者識別碼才寫進稽核日誌
function logFail(u) {
  const canonical = u.canonicalUid;                  // 統一的正規化識別碼
  logger.warn({ event: 'login_failed', user: canonical, ts: Date.now() });
}`,
		patch: `@@
 function logFail(u) {
-  logger.warn('login failed', key = u.nickname || u.loginName);
+  const canonical = u.canonicalUid;
+  logger.warn({ event: 'login_failed', user: canonical, ts: Date.now() });
 }`,
		refs: ['CWE-224', 'OWASP-Logging'],
		tags: ['logging', 'canonical', 'audit'],
	},
	{
		id: 'CWE-225',
		name: 'DEPRECATED: General Information Management Problems',
		lang: 'nodejavascript',
		status: 'Deprecated',
		what: `通用資訊管理問題（General Information Management Problems）——這是 MITRE 已停用（Deprecated）的里程碑性質條目，內容已被移往 CWE-199，
		在此僅保留說明與歷史脈絡。它概括一整群「程式對敏感資訊何時被揭露、揭露給誰、以及資訊在系統內部如何流動」把關不周的缺陷，包括把敏感資料帶進
		不該有的交付通道、日誌與備份帶出明文祕密、快取留住機敏內容等等。成因為沒有把「資訊的生命週期與信任邊界」納入設計。後果是機密經由非預期的路徑
		外流。實際修復請以具體的衍生條目對症下藥，例如先確認資料只在必要的信任邊界內移動、存放時加密、輸出做遮罩與白名單。`,
		problem: `// (支柱示例)：把整個多餘的中間計算結果連同敏感欄位一起送／記了下一個元件
res.json(computeAll(req));   // 把含密碼與內部結構的物件整包吐出`,
		fixed: `// (支柱示例修法)：只挑需要的欄位往下傳，敏感資料不透出信任邊界
res.json({ ok: true, total: sanitize(computeTotal(req)).public });
// 其餘敏感內容只進加密的伺服器端日誌`,
		patch: `@@
-   res.json(computeAll(req));
+   res.json({ ok: true, total: sanitize(computeTotal(req)).public });`,
		refs: ['CWE-225'],
		tags: ['deprecated', 'info-management', 'landmark'],
	},
	{
		id: 'CWE-230',
		name: 'Improper Handling of Missing Values',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `遺漏值處理不當（Improper Handling of Missing Values）。參數、欄位或引數「名字有被指定、值卻沒跟著來」——空字串、空白、null——程式
		在取得值之前就把它當成有內容來用，或在存在性與內容兩種語意之間混用。成因為把「鍵存在」直接當作「值有效」，沒區分缺值與 0／false／空串，
		又常忘了給安全預設與失敗分支。後果是拿空值或預設值繼續運算，造成邏輯誤判、越界或不當的授權決定——例如把空的密碼欄、空的篩選條件當成「不限」
		默默放行。修法是在使用前明確檢查「鍵是否存在且值非空白」，缺值時確切選擇安全預設或直接拒絕，並寫下明確的失敗處理。`,
		problem: `// 不安全寫法：欄位存在即沿用、不存在即給 undefined 繼續運算
function choose(user) {
  if (user) return user.plan;            // plan 未設定時回傳 undefined
  return db.plans.default();              // 連 user 不存在也直接給預設，未分開處理
}`,
		fixed: `// 安全寫法：缺值走明確的分支，空值不偷渡成「有值」
function choose(user) {
  if (user == null) throw new AuthError('no subject');      // 缺主體直接拒絕
  return user.plan ?? throw new ConfigError('plan missing'); // plan 缺值照樣停住
}`,
		patch: `@@
 function choose(user) {
-  if (user) return user.plan;
-  return db.plants.default();
+  if (user == null) throw new AuthError('no subject');
+  return user.team ?? throw new ConfigError('plan missing');
 }`,
		refs: ['CWE-230', 'OWASP-Validation'],
		tags: ['missing-values', 'null', 'validation'],
	},
	{
		id: 'CWE-231',
		name: 'Improper Handling of Extra Values',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `額外值處理不當（Improper Handling of Extra Values）。程式收到的值比預期的多——例如某鍵重覆出現多次、或一次收進比欄位多的數值——程式卻
		放任超額的資料。當多個來源的數值被縫進同一個欄位、或重覆鍵的其中一個被下來，攻擊者就能讓「使用者看得見的那個」與「後端實際採用／往下游傳的那個」
		不一致，形成邏輯繞過。成因為只取「第一個或最後一個」值的實作總是以偏概全，未對多餘的鍵或接收量做拒絕或明確統合。後果是參數汙染、驗證繞過、
		以及把未被檢查的額外值當成可信值送入後續處理。修法是對重覆鍵與超額數量先判定「允許結構」：要嘛明確拒絕、要嘛先在伺服器端做正規化的併集，
		再以單一、受檢查的值往下走。`,
		problem: `// 不安全寫法：直接採第一個或最後一個值，重覆鍵偷偷蓋掉前一個
function current(req) {
  const list = req.query.files;             // 可一次送多個 files=...
  return list && list[0];                 // 其他值沒被檢查、被忽略或漏送出
}`,
		fixed: `// 安全寫法：重覆出現的鍵視為異常，直接拒絕或正規化併集
function current(req) {
  const raw = req.query.files;
  const files = Array.isArray(raw) ? raw : [raw];
  if (files.length !== 1) throw new BadRequest('expected exactly one files');   // 多值拒絕
  return files[0];
}`,
		patch: `@@
 function current(req) {
-  const list = req.query.files;
-  return list && list[0];
+  const raw = req.query.files;
+  const files = Array.isArray(raw) ? raw : [raw];
+  if (files.length !== 1) throw new BadRequest('expected exactly one files');
+  return files[0];
 }`,
		refs: ['CWE-231', 'OWASP-Validation'],
		tags: ['extra-values', 'parameter-pollution', 'validation'],
	},
	{
		id: 'CWE-234',
		name: 'Failure to Handle Missing Parameter',
		lang: 'c',
		status: 'Complete',
		what: `未處理缺少的參數（Failure to Handle Missing Parameter）。函式、命令列或協定端點被呼叫時送出比契約還少的引數或不完整的參數組，程式卻在
		去驗證「參數是否存在、個數是否正確」之前就取用這些位置。在需要「從堆疊上 pop 出期望個數」的呼叫約定裡，缺引數仍會被當成有的引數彈出，導致讀到
		不存在的暫存值；可變參數的函式也可能在窮盡時把型別與個數當成未定義的內容使用。成因為假設呼叫方永遠補滿參數、又未對個數與型別做前置檢查。後果是
		型別混淆、讀到不存在的記憶體、未定義行為與衍生越界或當機。修法是每個函式在首行就確認「實際參數個數與型別符合契約」，不足或不符就立刻傳回錯誤，
		不偷用不確定存在的引數。`,
		problem: `// 不安全寫法：沒檢查參數是否存在就直接解開使用
double avg(int n, ...) {
  va_list ap; va_start(ap, n);
  double s = 0;
  for (int i = 0; i < n; i++) s += va_arg(ap, double);  // 呼叫方沒送 n 個時讀到未定義值
  va_end(ap); return s / n;
}
// avg(2, 3.0)  只送 1 個值也照跑，缺的第 2 個被當 0 或垃圾`,
		fixed: `// 安全寫法：參數個數由契約定義並在進入前驗證，缺件即失敗
double avg(size_t n, const double *vals) {
  if (n == 0 || vals == NULL) return NAN;      // 缺參數/空陣列直接拒絕
  double s = 0;
  for (size_t i = 0; i < n; i++) s += vals[i];
  return s / n;
}`,
		patch: `@@
-double avg(int n, ...) {
-  va_list ap; va_start(ap, n);
-  double s = 0;
-  for (int i = 0; i < n; i++) s += va_arg(ap, double);
-  va_end(ap); return s / n;
-}
+double avg(size_t n, const double *vals) {
+  if (n == 0 || vals == NULL) return NAN;
+  double s = 0;
+  for (size_t i = 0; i < n; i++) s += vals[i];
+  return s / n;
+}`,
		refs: ['CWE-234', 'OWASP-Validation'],
		tags: ['missing-parameter', 'variadic', 'validation'],
	},
	{
		id: 'CWE-235',
		name: 'Improper Handling of Extra Parameters',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `額外參數處理不當（Improper Handling of Extra Parameters）。程式收到的參數／欄位／同名前後的引數個數超過預期，卻沒有拒絕或明確處理多出來的
		部分。多數框架會把重覆鍵或超額的擕帶參數合併或擇一，導致「使用者填給某欄位的值」與「後端真正採用的那個值」不是同一個；雙重編碼、雙重送值也被用來
		繞過只檢查其中之一的邏輯。成因為預設樣板只往上層吐「滿足預期數」的參數，而沒把超額當作需要檢查的異常。後果是參數汙染、驗證繞過、以及多餘的
		剖析邏輯被當成可信輸入。修法是明訂每欄允收的個數與型別，超額即 4xx／錯誤，或者先做伺服器端統一的正規化再做後續判定。`,
		problem: `// 不安全寫法：直接沿用框架合併後的參數，多值被默默併起來
function filter(req) {
  const t = req.query.type;              // type=a&type=b → 取到合併或最後值
  return db.find(sqlOf(t));             // 額外的 type 沒被查驗
}`,
		fixed: `// 安全寫法：同欄重覆出現視為非法輸入，明確拒絕而非擇一拼湊
function filter(req) {
  const raw = req.query.type;
  if (Array.isArray(raw)) throw new BadRequest('duplicate type');   // 超額直接擋
  const ALLOWED = ['user', 'admin'];
  if (!ALLOWED.includes(raw)) throw new BadRequest('bad type');
  return db.find(sqlOf(raw));
}`,
		patch: `@@
 function filter(req) {
-  const t = req.query.type;
-  return db.find(sqlOf(t));
+  const raw = req.query.type;
+  if (Array.isArray(raw)) throw new BadRequest('duplicate type');
+  const ALLOWED = ['user', 'admin'];
+  if (!ALLOWED.includes(raw)) throw new BadRequest('bad type');
+  return db.find(sqlOf(raw));
 }`,
		refs: ['CWE-235', 'OWASP-Validation'],
		tags: ['extra-parameters', 'parameter-pollution', 'validation'],
	},
	{
		id: 'CWE-236',
		name: 'Improper Handling of Undefined Parameters',
		lang: 'python',
		status: 'Complete',
		what: `未定義參數處理不當（Improper Handling of Undefined Parameters）。收到一個產品根本「不支援、未定義」的參數／欄位時，程式沒有拒絕它，或在沒有
		處理它的預設分支之下，讓它的值悄悄影響到結果。有些實作會把未定義的參數直接塞進內部查詢或拼成選項；有些則在剖析時把不認識的欄位忽略，但略過前已拿它的
		值來做決策。成因為對參數清單沒有白名單、又沒有「識別並拒絕未知欄位」的嚴格剖析。後果是未知欄位被當成憑據或搜尋條件、或成為繞過檢查的載體，令產品在
		設計上不曾想過的輸入也就順著流入。修法是對每筆參數做「只有允許清單中的欄位才被讀取使用」的把關，發現未定義欄位就直接回錯誤，讓產品從不清楚該如何解的
		輸入保持受控制的拒絕。`,
		problem: `# 不安全寫法：把未定義的參數照樣拼進查詢條件使用
def lookup(req):
    extra = req.args.get("debug_sql")       # 產品沒定義過這欄位
    cond = "%s" % extra                    # 卻被當成過濾條件用進查詢
    return db.execute("select * from t where " + cond)`,
		fixed: `# 安全寫法：只接受白名單欄位，不認識的參數一律拒絕
ALLOWED = {"q", "page", "size"}
def lookup(req):
    unknown = set(req.args) - ALLOWED
    if unknown:
        raise BadRequest("unknown params: %r" % unknown)
    return db.execute("select * from t where q=?", (req.args.get("q"),))`,
		patch: `@@
 def lookup(req):
-    extra = req.args.get("debug_sql")
-    cond = "%s" % extra
-    return db.execute("select * from t where " + cond)
+    ALLOWED = {"q", "page", "size"}
+    unknown = set(req.args) - ALLOWED
+    if unknown:
+        raise BadRequest("unknown params: %r" % unknown)
+    return db.execute("select * from t where q=?", (req.args.get("q"),))`,
		refs: ['CWE-236', 'OWASP-Validation'],
		tags: ['undefined-parameter', 'whitelist', 'validation'],
	},
	{
		id: 'CWE-237',
		name: 'Improper Handling of Structural Elements',
		lang: 'c',
		status: 'Complete',
		what: `結構化元素處理不當（Improper Handling of Structural Elements）。輸入與「結構」有關——階層式檔名、巢狀引數、鍵值對、標籤化標記——程式在
		「剖析結構的邊界與層次」上出了問題，例如把帶分隔符的巢狀路徑直接當單一元件、沒處理多層資料被扁平化、或對片段順序錯亂的結構做了假設。成因為把結構化輸入
		當成扁平字串處理、又缺少一條「先正規化／定型結構、再以結構語意做判定」的階段。後果是存取到非預期的檔案或物件、命中的規則跟使用者預期不同，以及剖析在
		遇到畸形結構時未受控制。修法是先明確定義並驗證輸入結構（層數、元素個數、分隔符），把不符合的結構以明確失敗拒絕，再以定型後的結構做安全判定。`,
		problem: `// 不安全寫法：把巢狀路徑當單一字串拼進檔案存取，不檢查層次
int open_ref(const char *ref) {
    char buf[128];
    snprintf(buf, sizeof buf, "/data/%s", ref);  // ref="a/../../etc" 照拼
    return open(buf, O_RDONLY);
}`,
		fixed: `// 安全寫法：先要求 ref 是「單層名稱」結構，含路徑分隔或往上層一律拒絕
int open_ref(const char *ref) {
    if (ref == NULL || strchr(ref, '/') != NULL || strstr(ref, "..") != NULL)
        return -1;                       // 非單層結構不接受
    char buf[128];
    snprintf(buf, sizeof buf, "/data/%s", ref);
    return open(buf, O_RDONLY);
}`,
		patch: `@@
 int open_ref(const char *ref) {
+    if (ref == NULL || strchr(ref, '/') != NULL || strstr(ref, "..") != NULL)
+        return -1;
     char buf[128];
     snprintf(buf, sizeof buf, "/data/%s", ref);
     return open(buf, O_RDONLY);
 }`,
		refs: ['CWE-237', 'OWASP-Validation'],
		tags: ['structure', 'parse', 'validation'],
	},
	{
		id: 'CWE-241',
		name: 'Improper Handling of Unexpected Data Type',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `預期外資料型別處理不當（Improper Handling of Unexpected Data Type）。元素應該是指定型別（數字 0-9、布林），卻收到另一種型別（字母 A-Z、
		字串、物件、null），程式在「檢查型別」之前就逕行用原本的操作方式來處理它。成因為預設輸入永遠符合型別契約、又誤用隱含型別轉換與寬鬆的根本不等比較
		（如 0 == false、"" 假值）消化掉型別差異。後果是比較失準、轉型成越界索引或巨大整數、讓本該被擋的值因為「型別被偷偷轉換」而過關，或是直接觸發執行期例外。
		修法是對每個元素先以嚴格型別檢查確認它真的是預期型別與型態，不是就用明確錯誤拒絕，不做會改變語意的隱式轉換。`,
		problem: `// 不安全寫法：沒檢查型別就當數字比大小，"0" 或 [] 這類值造成誤判
function aboveLimit(v) {
  if (v > 10) return 'blocked';       // v=[] → 轉成 0；v="5x" = NaN 全放行
  return 'ok';
}`,
		fixed: `// 安全寫法：先嚴格確認型別與型態，不是數字就直接拒絕
function aboveLimit(v) {
  if (typeof v !== 'number' || !Number.isFinite(v)) throw new TypeError('not a number');
  return v > 10 ? 'blocked' : 'ok';
}`,
		patch: `@@
 function aboveLimit(v) {
+  if (typeof v !== 'number' || !Number.isFinite(v)) throw new TypeError('not a number');
-  if (v > 10) return 'blocked';
-  return 'ok';
+  return v > 10 ? 'blocked' : 'ok';
 }`,
		refs: ['CWE-241', 'OWASP-Validation'],
		tags: ['type-check', 'coercion', 'validation'],
	},
	{
		id: 'CWE-243',
		name: 'Creation of chroot Jail Without Changing Working Directory',
		lang: 'c',
		status: 'Complete',
		what: `建立 chroot 監獄後未切換工作目錄（Creation of chroot Jail Without Changing Working Directory）。程式以 chroot() 把執行環境限制在一個目錄內，呼叫
		成功後卻沒接著把「目前工作目錄」一併移進新根裡。若呼叫前的工作目錄在監獄之外，程序之後以相對路徑存取檔案、或持著舊的目錄描述符，就會落在監獄外。
		成因為只知呼叫 chroot() 而漏了它必須搭配 chdir() 的紀律，誤以為 chroot() 一呼叫就徹底隔離。後果是原本該被限制在 jail 內的程式仍能用 ".." 或已開啟
		的描述符存取外部的檔案，把權限隔離做得徒具形式。修法是在 chroot() 成功後立刻 chdir("/") 到新根內，並以最小權限開啟、關閉不必要描述符作為縱深防禦。`,
		problem: `// 不安全寫法：chroot() 之後沒切工作目錄，jail 內仍可逃到外面
void jail(const char *dir) {
    if (chroot(dir) == 0) {
        /* 忘了 chdir("/")：工作目錄仍在監獄外 */
        run_untracked();
    }
}`,
		fixed: `// 安全寫法：chroot() 成功後立即切到新根內，斷開舊路徑可及性
void jail(const char *dir) {
    if (chroot(dir) != 0) die("chroot");
    if (chdir("/") != 0) die("chdir");     // 工作目錄也移進 jail
    run_untracked();
}`,
		patch: `@@
     if (chroot(dir) == 0) {
+        if (chdir("/") != 0) die("chdir");
         run_untracked();
     }`,
		refs: ['CWE-243', 'OWASP'],
		tags: ['chroot', 'jail', 'sandbox'],
	},
	{
		id: 'CWE-244',
		name: "Improper Clearing of Heap Memory Before Release ('Heap Inspection')",
		lang: 'c',
		status: 'Complete',
		what: `釋放前未清除堆記憶體（Heap Inspection）。存密碼、金鑰、token 的堆積緩衝區在釋放或縮減前沒有先被清成空白。尤其用 realloc() 縮小緩衝區
		時，realloc 可能在原地直接縮小而保留未寫入部分的舊位元組，或把內容搬走卻留下原位置的舊值。這些殘留的機密位元組留在堆裡，之後被其他配置重用、或經由
		core dump／除錯輸出帶出去，攻擊者就有機會撿回密碼與金鑰。成因為釋放前不做不可最佳化的清除（explicit_bzero、SecureZeroMemory、OPENSSL_cleanse），又誤以為
		free 會幫你抹掉。修法是在釋放與縮減機密緩衝區之前，先用「編譯器不能最佳化消除」的方式把每個位元組確實清成 0，並以專責的密碼／金鑰管理 API 與受保護
		記憶體來承載機密。`,
		problem: `// 不安全寫法：直接 free，或用 realloc 縮小，殘留位元組留在堆中
char *secret = malloc(64);
read_secret(fd, secret, 64);          // 填入機密
secret = realloc(secret, 8);          // 縮小後，多出的 56 bytes 舊值可能還在堆上
... free(secret);                      // 沒先清除就交還`,
		fixed: `// 安全寫法：釋放/縮減前先用不可最佳化的方式清空整段機密
char *secret = malloc(64);
read_secret(fd, secret, 64);
secure_wipe(secret, 64);             // 例如 explicit_bzero 或 OPENSSL_cleanse
char *tmp = realloc(secret, 8);
secret = tmp;
... free(secret);`,
		patch: `@@
   read_secret(fd, secret, 64);
+  secure_wipe(secret, 64);            // 釋放前把位元組清成 0
   secret = realloc(secret, 8);`,
		refs: ['CWE-244', 'OWASP-Crypto'],
		tags: ['heap', 'sensitive-data', 'memory-scrubbing'],
	},
	{
		id: 'CWE-245',
		name: 'J2EE Bad Practices: Direct Management of Connections',
		lang: 'java',
		status: 'Complete',
		what: `J2EE 壞習慣：直接管理連線（Direct Management of Connections）。J2EE 應用自己建立與管理資料庫／連線池，而不是交給容器（Container）與 JNDI
		連線資源來管理。成因為在程式裡自己 new 出連線、自己負責關閉與服務分配，繞過了容器的連線池、交易與資源生命週期管理——容器無法再做資源回收、配額與監控。
		後果是連線未被正確關閉而外洩、耗盡資料庫連線造成拒絕服務，也難以做集中式的安全性與逾時管理。修法是透過 JNDI 取得容器管理的 DataSource／連線，讓容器握有
		連線池與密碼，程式在使用後一律於正確範圍（try-with-resources）內關閉。`,
		problem: `// 不安全寫法：直接在 DAO 內自己 new 連線並管理生命週期
public class Dao {
  public Result query(String sql) {
    Connection c = DriverManager.getConnection(url, user, pass);  // 自建連線
    Statement st = c.createStatement();                           // 容器不知情
    Result rs = st.executeQuery(sql);
    // 漏了 finally 關閉 → c 外洩
    return rs;
  }
}`,
		fixed: `// 安全寫法：向容器取用 JNDI DataSource（連線池），用 try-with-resources 關閉
@Resource(lookup = "java:comp/env/jdbc/MyDS")
private DataSource ds;
public Result query(String sql) throws SQLException {
  try (Connection c = ds.getConnection();
       PreparedStatement st = c.prepareStatement(sql);
       ResultSet rs = st.executeQuery()) {
    return rs;                        // 容器管理池與回收
  }
}`,
		patch: `@@
  public Result query(String sql) {
-    Connection c = DriverManager.getConnection(url, user, pass);
-    Statement st = c.createStatement();
-    Result rs = st.executeQuery(sql);
-    return rs;
+    try (Connection c = ds.getConnection();
+         PreparedStatement st = c.prepareStatement(sql);
+         ResultSet rs = st.executeQuery()) {
+      return rs;
+    }
  }`,
		refs: ['CWE-245', 'OWASP'],
		tags: ['j2ee', 'connection-pool', 'resources'],
	},
	{
		id: 'CWE-246',
		name: 'J2EE Bad Practices: Direct Use of Sockets',
		lang: 'java',
		status: 'Complete',
		what: `J2EE 壞習慣：直接使用 Socket（Direct Use of Sockets）。應用自己 new 出 socket、自己管理連線協定與通訊埠，而不是透過 J2EE 提供的 API（例如
		JMS、JCA、EJB 遠端、JNDI 資源）來完成通訊。成因為直接刻低階 socket 存取來做商務通訊，繞過了容器對安全、事務與資源的管理。後果是底層 TCP 連線未受容器
		控管，逾時、憑證、TLS 與資源配額都交給程式自行處理，容易漏錯、洩漏或把連線開成一整片，也難做集中式的安全控管。修法是改用對應的容器層面 API（JMS 訊息
		佇列、JCA 資源、HTTPS 可插座由應用伺服器管理）來完成跨系統通訊。`,
		problem: `// 不安全寫法：直接開 socket 拼私有協定來連後端服務
public void notify(byte[] payload) {
  Socket s = new Socket("back.broker", 4711);   // 自管連線與逾時
  s.getOutputStream().write(payload);
  // 沒設逾時、沒關連線、TLS/身分管在 code 外
}`,
		fixed: `// 安全寫法：改用容器管理的 JMS 資源寄送訊息
@Resource(mappedName = "java:comp/env/jms/NotificationQueue")
private QueueConnectionFactory factory;
public void notify(String msg) throws Exception {
  try (QueueConnection c = factory.createConnection();
       Session s = c.createSession(false, Session.AUTO_ACKNOWLEDGE)) {
    MessageProducer p = s.createProducer(queue);
    p.send(s.createTextMessage(msg));     // 連線與事務交給容器
  }
}`,
		patch: `@@
  public void notify(byte[] payload) {
-    Socket s = new Socket("back.broker", 4711);
-    s.getOutputStream().write(payload);
+    try (QueueConnection c = factory.createConnection();
+         Session s = c.createSession(false, Session.AUTO_ACKNOWLEDGE)) {
+      MessageProducer p = s.createProducer(queue);
+      p.send(s.createTextMessage(new String(payload, "UTF-8")));
+    }
  }`,
		refs: ['CWE-246', 'OWASP'],
		tags: ['j2ee', 'socket', 'jms'],
	},
	{
		id: 'CWE-247',
		name: 'DEPRECATED: Reliance on DNS Lookups in a Security Decision',
		lang: 'nodejavascript',
		status: 'Deprecated',
		what: `依賴 DNS 查詢來做安全決定（Reliance on DNS Lookups in a Security Decision）——這是 MITRE 已停用條目，因與 CWE-350 重複，內容已移往
		CWE-350，此處保留歷史脈絡。它講的是「把反向／正向 DNS 解析（IP→主機名）的結果拿來當驗證或授權依據」：DNS 查詢的結果可被第三方（連往的主機、遞迴解析器、
		使用者可控的環境）操控或快取污染，又不保證即時。攻擊者只要讓解析結果指向自己的主機或操縱名字，就能繞過以 IP／主機名為準的驗證。修法總結：不要用可被
		操控且會快取的 DNS 結果來下安全決定，身分判定靠憑證與密碼等強式證據。`,
		problem: `// (示例)：拿 rDNS 反查結果當「這是可信內網"w"放行」的依據
function allow(ip) {
  const host = reverseDns(ip);          // 結果可被污染或快取
  return host.endsWith('trusted.example');
}`,
		fixed: `// (示例修法)：身分判定不靠 DNS，改用憑證與密碼等強式證據
function allow(conn) {
  return await verifyClientCert(conn.peerCert);   // 憑證不可竄改，非 DNS
}`,
		patch: `@@
  function allow(ip) {
-    const host = reverseDns(ip);
-    return host.endsWith('trusted.example');
+    return await verifyClientCert(conn.peerCert);
  }`,
		refs: ['CWE-247'],
		tags: ['deprecated', 'dns', 'auth-by-ip'],
	},
	{
		id: 'CWE-249',
		name: 'DEPRECATED: Often Misused: Path Manipulation',
		lang: 'nodejavascript',
		status: 'Deprecated',
		what: `常被誤用的路徑操作（Often Misused: Path Manipulation）——這是 MITRE 已停用條目，因命名混淆得多個弱點意外併在一起，內容大多移往 CWE-785，
		此處僅保留歷史脈絡。它原本泛指「把外部影響的路徑用於檔案／目錄操作」的一連串問題，包括未限制到指定目錄、濫用相對路徑、隨意拼 path 字串等。成因為直接把
		輸入拼進路徑又未正規化與限制；後果是穿越目錄、覆寫或讀取非預期檔案。現代修法：解析出最終目標絕對路徑並驗證其落在允許根目錄內，只取純檔名（basename），
		關閉能影響路徑的特殊符號與編碼變體，必要時改以資料庫／物件鍵取代檔案路徑。`,
		problem: `// (示例)：直接以輸入拼路徑存取檔案，可被 ".." 穿越
content = fs.readFileSync(path.join(base, req.query.file));`,
		fixed: `// (示例修法)：只取純檔名，並驗證最終路徑仍在允許目錄內
const name = path.basename(req.query.file);
const target = path.join(base, name);
if (!target.startsWith(base)) throw new Error('denied');
content = fs.readFileSync(target);`,
		patch: `@@
-  content = fs.readFileSync(path.join(base, req.query.file));
+  const name = path.basename(req.query.file);
+  const target = path.join(base, name);
+  if (!target.startsWith(base)) throw new Error('denied');
+  content = fs.readFileSync(target);`,
		refs: ['CWE-249'],
		tags: ['deprecated', 'path', 'traversal'],
	},
	{
		id: 'CWE-256',
		name: 'Plaintext Storage of a Password',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `密碼以明文儲存（Plaintext Storage of a Password）。密碼以可讀的原文存在記憶體、檔案或資料庫欄位裡，例如存帳號密碼、或把加密用的主密碼
		存成明文。一旦資料庫外洩、備份流出、或程式被切片分析，密碼就一步到位可被使用；即使連線走加密傳輸，明文落盤一樣失守，且使用者跨站重用密碼時一瞭皆洩。
		成因為圖方便把密碼以原文落盤、又可掌原始碼還原。後果是資料外洩即帳號淪陷、連帶擴及密碼重用者的其他帳號。修法是密碼一律以「自帶隨機 salt 的強式
		單向雜湊（如 bcrypt／scrypt／argon2）」儲存，字串比較用常時等長比對，不在任何地方保留可還原的明文副本。`,
		problem: `// 不安全寫法：密碼原文寫進資料庫
const hash = password;                     // 明文落盤
await db.users.insertOne({ user, hash });`,
		fixed: `// 安全寫法：密碼經 bcrypt（帶隨機 salt）單向雜湊後才存
const hash = await bcrypt.hash(password, 12);   // 加鹽 + 單向
await db.users.insertOne({ user, hash });`,
		patch: `@@
-  const hash = password;
+  const hash = await bcrypt.hash(password, 12);
  await db.users.insertOne({ user, hash });`,
		refs: ['CWE-256', 'OWASP-Password'],
		tags: ['password', 'plaintext', 'hashing'],
	},
	{
		id: 'CWE-257',
		name: 'Storing Passwords in a Recoverable Format',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `以可還原的格式儲存密碼（Storing Passwords in a Recoverable Format）。密碼用「可逆」的方式存放——對稱式加密、編碼或雜湊後可還原的主密碼——
		而非不可逆的單向雜湊。可還原的加密其實比明文好不了多少：管理者或入侵者一旦拿到金鑰就能還原出原始密碼，且還原出的密碼可被拿來重用攻擊（credentials
		reuse）——不只外部攻擊者，連內部的惡意管理者都能拿它在別的系統上用。成因為誤以為「加密保存」就已安全，卻忽略金鑰與還原入口本身就是新弱點。後果是密碼
		可被還原再用於他人帳號與他站，把密碼政策的努力整個拆掉。修法是採不可逆的強式單向雜湊（加隨機 salt），不做任何可把密碼還原回明文的路徑。`,
		problem: `// 不安全寫法：用可逆的對稱加密存密碼，金鑰一洩即全面還原
const cipher = aesEncrypt(password, MASTER_KEY);   // 可解回明文
await db.users.insertOne({ user, pwd: cipher });`,
		fixed: `// 安全寫法：不可逆的單向雜湊 + 隨機 salt，無法還原只能用於比對
const salt = await crypto.randomBytes(16);
const hash = await scrypt(password, salt, 64);    // one-way
await db.users.insertOne({ user, pwd: hash, salt });`,
		patch: `@@
-  const cipher = aesEncrypt(password, MASTER_KEY);
-  await db.users.insertOne({ user, pwd: cipher });
+  const salt = await crypto.randomBytes(16);
+  const hash = await scrypt(password, salt, 64);
+  await db.users.insertOne({ user, pwd: hash, salt });`,
		refs: ['CWE-257', 'OWASP-Password'],
		tags: ['password', 'recoverable', 'hashing'],
	},
	{
		id: 'CWE-258',
		name: 'Empty Password in Configuration File',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `設定檔裡的空密碼（Empty Password in Configuration File）。軟體安裝或啟動時，用空字串當密碼寫進設定檔，或佔位符沒被實際值取代。空密碼等於
		毫無驗證：任何知道帳號的人、或能連上該介面的人，用「空」就能登入。成因為把密碼欄位留空、用預設空值給牆、或佔位符漏換造成執行期讀到空串而「通過」。
		後果是未授權登入、管理儀錶板被接管，常發生在監控、資料庫管理員與弱密碼預設的產品上。修法是安裝時強制產生並設定非空、夠強的密碼，設定檔不預留空密碼
		佔位，讀到空密鑰或空密碼時視為錯誤並拒絕啟動／拒絕繼續執行。`,
		problem: `// 不安全寫法：密碼欄位留成空字串，登入比對空串即過
const cfg = { dbUser: 'app', dbPass: '' };      // 空的資料庫密碼
const c = mysql.connect({ user: cfg.dbUser, password: cfg.dbPass });`,
		fixed: `// 安全寫法：讀到空密碼視為設定錯誤，強制要求真實值
const cfg = loadConfig();
if (!cfg.dbPass || cfg.dbPass.length < 12)
  throw new Error('refusing to start: empty/weak password');
const c = mysql.connect({ user: cfg.dbUser, password: cfg.dbPass });`,
		patch: `@@
   const cfg = { dbUser: 'app', dbPass: '' };
+  if (!cfg.dbPass || cfg.dbPass.length < 12)
+    throw new Error('refusing to start: empty/weak password');
   const c = mysql.connect({ user: cfg.dbUser, password: cfg.dbPass });`,
		refs: ['CWE-258', 'OWASP-Password'],
		tags: ['password', 'empty', 'config'],
	},
	{
		id: 'CWE-259',
		name: 'Use of Hard-coded Password',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `使用硬編碼密碼（Use of Hard-coded Password）。產品把一組固定的密碼寫死在程式碼裡，用在「本身對內驗證」或「連外通訊要用到的密鑰」。一旦
		有人反組譯、看原始碼或 git 歷史挖到這組值，知情者就能直接登入；且所有安裝共用同一組硬編碼值，切既可大規模被利用。後果是身分冒用、繞過驗證、甚至跨
		組織都被同一組密碼打透。修法是密碼移出程式碼——由環境變數、設定伺服器或 secret manager 注入並可輪換；若非保留內建值不可，就限制能接觸它的實體、並對該
		功能做嚴格存取控制，而不是放進每個人都看得到的碼裡。`,
		problem: `// 不安全寫法：密碼直接寫死在設定與原始碼
const ADMIN_PASSWORD = 'P@ssw0rd';                // 烙在 code / repo
if (candidate === ADMIN_PASSWORD) grantAdmin();`,
		fixed: `// 安全寫法：改用 env / secret manager 注入並比對雜湊
const pwHash = process.env.ADMIN_PWHASH;           // 送入環境，不入 repo
if (pwHash && await bcrypt.compare(candidate, pwHash)) grantAdmin();`,
		patch: `@@
-  const ADMIN_PASSWORD = 'P@ssw0rd';
-  if (candidate === ADMIN_PASSWORD) grantAdmin();
+  const pwHash = process.env.ADMIN_PWHASH;
+  if (pwHash && await bcrypt.compare(candidate, pwHash)) grantAdmin();`,
		refs: ['CWE-259', 'OWASP-Secrets'],
		tags: ['hardcoded', 'password', 'secrets'],
	},
	{
		id: 'CWE-260',
		name: 'Password in Configuration File',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `設定檔裡存密碼（Password in Configuration File）。密碼存在設定檔（.env、ini、yaml、XML、tomcat-users.xml）中，而該檔對「不必知道密碼的人」
		也可讀——包括備份、套裝、設定在 web root、或權限過寬讓其他帳號能開。成因為把密碼放進人人可見的設定檔、而該檔的權限與所在位置未受保護。後果是看到設定檔
		即可取得密碼、登入到其他系統；密碼重用時受害面更大。修法是不要在設定檔存未加密的密碼：改用環境變數、限定權限（600／屬主）＋由 secret manager 注入，
		且不把秘密寫進會被同步到版本控制的設定檔。`,
		problem: `// 不安全寫法：把管理員密碼寫進會被部署與供應的設定檔
// config.yml
db:
  user: root
  password: "Tr0ub4dor"      # 一般人/備份/Container 內可見`,
		fixed: `// 安全寫法：密碼由環境變數/secret 注入，設定檔只留參照
const dbPass = process.env.DB_PASSWORD;             // 部署工具注入
if (!dbPass) throw new Error('DB_PASSWORD unset');
mysql.connect({ user: 'root', password: dbPass });`,
		patch: `@@
-  password: "Tr0ub4dor"
+const dbPass = process.env.DB_PASSWORD;
+if (!dbPass) throw new Error('DB_PASSWORD unset');
+mysql.connect({ user: 'root', password: dbPass });`,
		refs: ['CWE-260', 'OWASP-Secrets'],
		tags: ['password', 'config', 'secrets'],
	},
	{
		id: 'CWE-261',
		name: 'Weak Encoding for Password',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `使用過弱的編碼藏密碼（Weak Encoding for Password）。拿微不足道的編碼來「藏」密碼——base64、簡單位元旋轉、ROT13、或可逆的字元代換——反而
		給人虛假的安全感。這些編碼完全不是加密，瞬間即可解回，破解也不需要任何工具能力。成因為把編碼當加密、誤認「看起來像亂碼」就有防護力。後果是密碼形同明文
		存放，外洩即被一步還原使用。修法是放棄一切「可逆的藏法」，改用自帶隨機 salt 的強式單向雜湊（bcrypt／scrypt／argon2），並明確拒絕這種可逆的視覺混淆。`,
		problem: `// 不安全寫法：把密碼 base64 後當成「加密」保存
const encoded = Buffer.from(password, 'utf8').toString('base64');   // 一秒解回
await db.users.insertOne({ user, pwd: encoded });`,
		fixed: `// 安全寫法：不用可逆編碼，用自帶 salt 的強式單向雜湊
const salt = await crypto.randomBytes(16);
const hash = await scrypt(password, salt, 64);       // one-way
await db.users.insertOne({ user, pwd: hash, salt });`,
		patch: `@@
-  const encoded = Buffer.from(password, 'utf8').toString('base64');
-  await db.users.insertOne({ user, pwd: encoded });
+  const salt = await crypto.randomBytes(16);
+  const hash = await scrypt(password, salt, 64);
+  await db.users.insertOne({ user, pwd: hash, salt });`,
		refs: ['CWE-261', 'OWASP-Password'],
		tags: ['password', 'weak-encoding', 'hashing'],
	},
	{
		id: 'CWE-262',
		name: 'Not Using Password Aging',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `未使用密碼老化（Not Using Password Aging）。系統沒有「強制密碼於一段期間後過期並要求重設」的機制，密碼可以無限期沿用同一組。成因為產品預設就
		不要求密碼更換、管理者也未啟用密碼策略。後果是被外洩或猜中的密碼可被無限次長期使用，攻擊者一次得手便終身可用，減少密碼的保護年限。修法是提供並落實密碼
		老化：對系統性與高風險帳號設定合理的最長使用期間、到時強制更換而不得沿用舊密碼，同時搭配強密碼要求與重複使用封鎖。不過密度過緊會造成可用性問題，要和緩的
		情境（例如較短的有效期只限高風險帳號）妥協。`,
		problem: `// 不安全寫法：密碼永不判過期，也沒有到期欄位
if (await bcrypt.compare(pw, user.hash)) login();   // 十年前的密碼仍有效`,
		fixed: `// 安全寫法：比對成功後再檢查密碼到期時間，過期要求重設
if (await bcrypt.compare(pw, user.hash)) {
  if (Date.now() > user.pwdExpiresAt)            // 密碼老化生效
    return forcePasswordReset(user);                 // 到其就強制換
  login();
}`,
		patch: `@@
   if (await bcrypt.compare(pw, user.hash)) {
+    if (Date.now() > user.pwdExpiresAt)
+      return forcePasswordReset(user);
     login();
   }`,
		refs: ['CWE-262', 'OWASP-Password'],
		tags: ['password', 'aging', 'policy'],
	},
	{
		id: 'CWE-263',
		name: 'Password Aging with Long Expiration',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `密碼老化但到期時間過長（Password Aging with Long Expiration）。系統有密碼老化機制，卻把到期期間定得太長，例如三年、五年甚至根本沒有實際上限。
		長到期期間讓外洩的密碼可被使用很久，也讓老化機制形同沒有。成因為把到期門檻或置頂抓得太鬆，低估帳號外洩與重用風險。後果是密碼的有效壽命遠超過資料被竊
		或被猜中所需，久了再被拿來用仍能登入。修法是設定符合情境的合理較短到期期間（視風險訂日數／月數），並把老化與強密碼、不重複、以及異常登入監控搭配，避免
		把長到期混進已聲稱合法權的機制裡。`,
		problem: `// 不安全寫法：自助「有效 10 年」，外洩密碼十年後仍可登入
user.pwdExpiresAt = Date.now() + 10 * 365 * 24 * 3600 * 1000;   // 太長`,
		fixed: `// 安全寫法：用符合情境的較短期間，並到其強制換新
const DA =
  90 * 24 * 3600 * 1000;                  // 90 天，視風險可更短
user.pwdExpiresAt = Date.now() + DA;`,
		patch: `@@
-  user.pwdExpiresAt = Date.now() + 10 * 365 * 24 * 3600 * 1000;
+  const DA = 90 * 24 * 3600 * 1000;
+  user.pwdExpiresAt = Date.now() + DA;`,
		refs: ['CWE-263', 'OWASP-Password'],
		tags: ['password', 'aging', 'expiration'],
	},
	{
		id: 'CWE-268',
		name: 'Privilege Chaining',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `權限鏈接（Privilege Chaining）。兩個各自原本無害的權限、角色、能力或權利，被加在一起後做的事「超過各別的允許」——例如「可開新帳號」＋「可選角色」
		連起來就能自封管理員。成因為授權模型只單獨檢查每個權限，卻沒思考權限組合的合成效果，也沒做「執行時最小權限」的負擔。後果是本不相容的特權被縫合成越權動作，
		逐步把權限「鏈」到最高位。修法是對每個敏感動作做整體能力的授權判定，檢查該角色「在組合下是否有權做這件事」，必要時把權限拆成不可合成的粒度、或用執行時最小權限
		並記錄權限指派者與脈絡。`,
		problem: `// 不安全寫法：各自判斷 canCreate 與 canAssign，合起來就能自立為 admin
if (user.canCreateGroups && canAssignRole(group, user.selectedRole)) {
  grant(group, user.selectedRole);      // 選 'admin' 就自封管理員 → 權限鏈
}`,
		fixed: `// 安全寫法：以「目標角色＋操作者」的整體能力作判，保守合成
async function canAssign(self, targetRole) {
  if (targetRole === 'admin')                          // 敏感值須頂層權限而非鏈起
    return self.role === 'owner';                     // 單一高權威來源
  return true;                                        // 一般角色再正常發放
}
if (await canAssign(user, req.body.role)) {
  await grant(user, req.body.role);
}`,
		patch: `@@
-  if (user.canCreateGroups && canAssignRole(group, user.selectedRole)) {
-    grant(group, user.selectedRole);
-  }
+  async function canAssign(self, targetRole) {
+    if (targetRole === 'admin') return self.role === 'owner';
+    return true;
+  }
+  if (await canAssign(user, req.body.role)) {
+    await grant(user, req.body.role);
+  }`,
		refs: ['CWE-268', 'OWASP-Privilege'],
		tags: ['privilege', 'chaining', 'access-control'],
	},
	{
		id: 'CWE-273',
		name: 'Improper Check for Dropped Privileges',
		lang: 'c',
		status: 'Complete',
		what: `未檢查權限是否成功降級（Improper Check for Dropped Privileges）。程式嘗試捨棄（drop）權限——setuid/seteuid、setgid、chroot——卻沒有檢查呼叫
		是否成功，或檢查方式錯。Unix 系統的過程權限一旦升到 root 就不會自動回降，drop 呼叫失敗仍繼續以原高權限往下跑，之後處理使用者輸入的任何漏洞都會以 root 執行。
		成因為沒驗 set*id 等呼叫的回傳值就當成功。後果是權限降級形同虛設，持續以特權身分運作，放大越界、注入等漏洞的影響。修法是在每次 drop 權限後檢查回傳值、
		財務底用直接檢查「現在 uid/gid 是否真為降級後目標（geteuid/getegid）」而不得夠，失敗即中止或盡速退出並終止作業。`,
		problem: `// 不安全寫法：setuid() 之後不回查是否成功，可能仍以 root 執行人輸入
int main(void) {
    setuid(getpwnam("nobody")->pw_uid);   // 未檢查回傳；失敗就仍 root
    process_untrusted_input();                 // → 越界等漏洞 = root 執行
}`,
		fixed: `// 安全寫法：降權成功後主動再驗證現行 uid 確實已低於臨界，不成即退出
int main(void) {
    uid_t u = getpwnam("nobody")->pw_uid;
    if (setuid(u) != 0) die("setuid");
    if (geteuid() != u)                  // 再確認實際身分
        die("privilege drop failed");
    process_untrusted_input();
}`,
		patch: `@@
     uid_t u = getpwnam("nobody")->pw_uid;
-    setuid(u);
+    if (setuid(u) != 0) die("setuid");
+    if (geteuid() != u) die("privilege drop failed");
     process_untrusted_input();`,
		refs: ['CWE-273', 'OWASP-Privilege'],
		tags: ['privilege-drop', 'setuid', 'least-privilege'],
	},
	{
		id: 'CWE-277',
		name: 'Insecure Inherited Permissions',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `繼承到不安全的權限（Insecure Inherited Permissions）。程式建立新物件（檔案、目錄、檔案桁、程序）時，會繼承「預設的一整組權限」——這些權限過寬
		或未受控，例如預設 umask 讓新建檔案 world-readable、把含密碼的暫存檔以 0666 建立。成因為沒有調整 umask、也沒有對每個新建物件明確指定最小權限。後果是可被其他
		使用者讀寫的檔案把機密外洩、或讓他人的檔案被篡改，尤其時常在環境變動後悄悄繼承「上一任」的寬鬆設定。修法是建立物件時明設定受限的權限（如檔案 0640、目錄
		0750），並以收緊的 umask（如 077）做預設，特別管好暫存目錄、密碼與金鑰檔。`,
		problem: `// 不安全寫法：靠默認繼承權限建立機密檔，可能開成全體可讀
const fs = require('fs');
fs.writeFileSync('/var/app/token.key', secret);   // umask 太鬆 → 其他帳號可讀`,
		fixed: `// 安全寫法：建立後立即設權限，並以收緊的 umask 做預設
const { mode, umask } = require('fs');
const old = umask(0o077);                      // 預設只限屬主
fs.writeFileSync('/var/app/token.key', secret);
fs.chmodSync('/var/app/token.key', 0o600);     // 明設最小權限
umask(old);`,
		patch: `@@
   const fs = require('fs');
+  const old = umask(0o077);
   fs.writeFileSync('/var/app/token.key', secret);
+  fs.chmodSync('/var/app/token.key', 0o600);
+  umask(old);`,
		refs: ['CWE-277', 'OWASP-Permissions'],
		tags: ['permissions', 'file', 'umask'],
	},
	{
		id: 'CWE-278',
		name: 'Insecure Preserved Inherited Permissions',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `保留了不安全的繼承權限（Insecure Preserved Inherited Permissions）。程式拿「來源物件原本的權限」來建立或保存目標物件——例如從壓縮檔（zip/tar）
		解檔時沿用封包內記的權限、複製檔案時連原本過寬的權限一起帶過去——卻沒讓使用者知道，或沒有使用者參與。成因為把來源的權限整體搬移、又誤以為「原本有」就安全。
		後果是原本該被限制的機密檔在解開／複製後變成其他使用者可讀或是可寫，資訊外洩與篡改風險放大。修法是解開封包與複製時，不以來源記的權限為準，改以「最小且受控」
		的既定權限來落檔，並告知或要求確認；遇到包內特別寬或特別特的權限一律以收緊為準。`,
		problem: `// 不安全寫法：解檔時沿用封包內的權限，包內 0777 就被整組帶出
const fs = require('fs');
fs.chmodSync(dest, entry.mode);        // entry.mode 來自 zip 內記錄，可為 0777`,
		fixed: `// 安全寫法：驗證過 plog 權限合理才採，過寬一律收緊到最小
function safeMode(m) {
  return (m & 0o600) === m ? m : 0o600;   // 只接受屬主 600 級，其餘一律 600
}
fs.chmodSync(dest, safeMode(entry.mode));`,
		patch: `@@
-  fs.chmodSync(dest, entry.mode);
+  function safeMode(m){ return (m & 0o600) === m ? m : 0o600; }
+  fs.chmodSync(dest, safeMode(entry.mode));`,
		refs: ['CWE-278', 'OWASP-Permissions'],
		tags: ['permissions', 'archive', 'inherit'],
	},
	{
		id: 'CWE-279',
		name: 'Incorrect Execution-Assigned Permissions',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `執行中設定的權限不符（Incorrect Execution-Assigned Permissions）。程式在執行過程中「另外設定」了某物件的權限，但其結果與使用者（互動期間下達或透過資源
		描敘）指定想要的權限不符。例如把檔名或路徑挪移後 chmod 落在別的地位、把相對路徑的檔案權限設錯、或在競爭視窗內設到非預期的物件，使得實際權限比約定允了的更寬。
		成因為權限作業不是對「使用者明確指向的那個物件」執行，又可能在路徑解析後才被替換（TOCTOU）。後果是想要的存取控制沒被落實、機密檔被設成可被非預期的帳號存取或改寫。
		修法是讓權限設在「與使用權相同的最終識別（open 時同時設定／以 fd 設權）」上，並在設定後驗證真正生效的權限符合最小與允約範圍。`,
		problem: `// 不安全寫法：以路徑 chmod 又可能被換名，且沒複核實際結果
fs.chmodSync('/var/app/' + userFilename, 0o777);   // 路徑可被抽換，設到非預期物件`,
		fixed: `// 安全寫法：開啟後以檔案描述設定權限（fd 不可被換名抽換）並複核
const fd = fs.openSync('/var/app/' + safeName, 'w', 0o600);
fs.fchmodSync(fd, 0o600);                         // 對同一 fd，無路徑競爭
fs.closeSync(fd);`,
		patch: `@@
-  fs.chmodSync('/var/app/' + userFilename, 0o777);
+  const fd = fs.openSync('/var/app/' + safeName, 'w', 0o600);
+  fs.fchmodSync(fd, 0o600);
+  fs.closeSync(fd);`,
		refs: ['CWE-279', 'OWASP-Permissions'],
		tags: ['permissions', 'chmod', 'right-owner'],
	},
	{
		id: 'CWE-283',
		name: 'Unverified Ownership',
		lang: 'c',
		status: 'Complete',
		what: `未驗證所有權（Unverified Ownership）。程式以他人擁有的資源（檔案、開啟的描述符、共享記憶體）做安全攸關的判斷或動作，卻沒有先驗證「這個資源確實是
		它原意所屬的那一個」。例如只憑檔名就把互斥檔當作「自己的／正確的」，別人便可預先建立同名的物件卡位、或把它換成自己是所有者的另一個檔，讓程式誤開到非預期資源。
		成因為信任名字或位址而不核對擁有者（uid）、型別與原始識別。後果是把別的帳號建立的資源當權威、覆寫或消耗他人的東西，權限與資料完整性受損。修法是在存取前驗證
		資源擁有者（fstat uid）相符、開啟時用不可被替代的方式（專屬創建旗標、鎖）確認「就是我要的那個」，再進行後續動作。`,
		problem: `// 不安全寫法：只憑路徑開啟互斥/設定檔，沒核對屬於誰
int grab(const char *path) {
    int fd = open(path, O_RDWR);        // 別人可預先放同名檔，這成了他的檔
    return fd;                           // 沒檢查 fstat().st_uid == 我的
}`,
		fixed: `// 安全寫法：開啟後用 fstat 驗證擁有者與型別，不符即拒絕
int grab(const char *path) {
    int fd = open(path, O_RDWR | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_uid != geteuid() || !S_ISREG(st.st_mode)) {
        close(fd); return -1;           // 非己有或非常規檔就放棄
    }
    return fd;
}`,
		patch: `@@
  int fd = open(path, O_RDWR);
-  return fd;
+  struct stat st;
+  if (fstat(fd, &st) != 0 || st.st_uid != geteuid() || !S_ISREG(st.st_mode)) {
+      close(fd); return -1;
+  }
+  return fd;`,
		refs: ['CWE-283', 'OWASP'],
		tags: ['ownership', 'file', 'race'],
	},
	{
		id: 'CWE-291',
		name: 'Reliance on IP Address for Authentication',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `以 IP 位址做身分驗證（Reliance on IP Address for Authentication）。系統用來源 IP 來證明、或支援「某個使用者真的是他」的判定。IP 位址本來就不是
		身分證據：它可以被偽造、透過代理／VPN／跳板被控制、被 DHCP 換發、能複製，而且不比對任何真實身分。成因為把「連線來自某個網段」誤當成「使用者可信」。
		後果是攻擊者只要配合位在信任網段內、或指定來源，就能以該身分登入或執行特權動作。修法是身分驗證只能依靠不可偽造的證據——密碼、OTP、憑證、工作階段 token——
		，IP 頂多用來做輔助的異常偵測，且絕不可單獨作為授權或驗證的唯一依據。`,
		problem: `// 不安全寫法：來源 IP 在信任網段就直接放行，不要求登入
function authenticate(req) {
  if (req.ip.startsWith('10.0.0.')) return { user: 'admin' };   // 偽造/代理即通過
  throw new Error('denied');
}`,
		fixed: `// 安全寫法：身分一律以不可偽造的憑證驗證，IP 不參與授權
async function authenticate(creds) {
  const user = await verifyPassword(creds.user, creds.password + creds.otp);  // 真實憑證
  if (!user) throw new Error('denied');
  return user;                                   // IP 只用於輔助監控，非判定依據
}`,
		patch: `@@
  function authenticate(req) {
-    if (req.ip.startsWith('10.0.0.')) return { user: 'admin' };
-    throw new Error('denied');
+    const user = await verifyPassword(creds.user, creds.password + creds.otp);
+    if (!user) throw new Error('denied');
+    return user;
  }`,
		refs: ['CWE-291', 'OWASP-Auth'],
		tags: ['auth-by-ip', 'spoofing', 'authentication'],
	},
	{
		id: 'CWE-292',
		name: 'DEPRECATED: Trusting Self-reported DNS Name',
		lang: 'nodejavascript',
		status: 'Deprecated',
		what: `信任自報的 DNS 名稱（Trusting Self-reported DNS Name）——MITRE 已停用條目，與 CWE-350 重複，內容已移往 CWE-350，此處保留歷史脈絡。
		它指程式把「某台機自報的主機名／網域名（realm、hostname）或來自使用者可控盒段的 DNS 名」拿來做憑證／身分判定。誰都能宣稱自己的名字，DNS 名字也不保證唯一
		或即時，被拿來當驗證或多合一很容易被冒充。後果是身分冒用、繞過基於名稱的授權。總之要以憑證等不可偽造的證據取代任何「依名字信任」的判定，並在信任邊界先對輸入
		名稱做正規化與額外驗證。`,
		problem: `// (示例)：直接可信連線自帶的 Hostname 來決定權限
if (req.get('host') === 'pay.internal.corp') grantPayment(req);   // 客戶端可改 header`,
		fixed: `// (示例修法)：以已驗證 TLS 憑證的 CN/SAN 或工作階段為準
if (peerCertMatches('pay.internal.corp', conn.peerCert)) grantPayment(conn);`,
		patch: `@@
-  if (req.get('host') === 'pay.internal.corp') grantPayment(req);
+  if (peerCertMatches('pay.internal.corp', conn.peerCert)) grantPayment(conn);`,
		refs: ['CWE-292'],
		tags: ['deprecated', 'dns', 'self-reported'],
	},
	{
		id: 'CWE-293',
		name: 'Using Referer Field for Authentication',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `以 Referer 欄位做驗證（Using Referer Field for Authentication）。程式要用 HTTP 的 Referer 標頭來驗證請求來自可信任的頁面、或當成訊息完整性的依據。
		Referer 是由瀏覽器／客戶端自行填入、任何人都能任改或取消的欄位，根本不保證「請求確實來自該處」，也不提供任何完整性。成因為誤把「Referer 寫成某網域」當作請求沒被
		篡改。後果是攻擊者只需把自己的請求帶上配好的 Referer 就能繞過防護（與 CSRF 建密防禦的前提恰恰相反）。修法是驗證與授權一律以真正的憑證與工作階段為據，Referer
		不可用來做安全性檢查，消息完整性用數位簽章／HMAC／二次 token 等真正機制。`,
		problem: `// 不安全寫法：拿 Referer 判斷請求是否來自內部管理頁
function adminAction(req) {
  if (req.get('referer') !== 'https://adm.corp/panel') throw new Error('forged');
  doAdmin(req);       // 攻擊者在自己的請求改 Referer 即可通過
}`,
		fixed: `// 安全寫法：改成憑證驗證 + 工作階段 + CSRF token，不信任 Referer
function adminAction(req) {
  if (!req.session || req.session.role !== 'admin') throw new Error('denied');
  if (!csrf.verify(req, req.body.csrf)) throw new Error('csrf');
  doAdmin(req);
}`,
		patch: `@@
  function adminAction(req) {
-    if (req.get('referer') !== 'https://adm.corp/panel') throw new Error('forged');
+    if (!req.session || req.session.role !== 'admin') throw new Error('denied');
+    if (!csrf.verify(req, req.body.csrf)) throw new Error('csrf');
     doAdmin(req);
  }`,
		refs: ['CWE-293', 'OWASP-CSRF'],
		tags: ['referer', 'auth-check', 'csrf'],
	},
	{
		id: 'CWE-296',
		name: "Improper Following of a Certificate's Chain of Trust",
		lang: 'nodejavascript',
		status: 'Complete',
		what: `未適當追隨憑證的信賴鏈（Certificate Chain of Trust）。程式在驗證對方憑證時，沒有從簽發者一路往上追回一條可信任根（trusted root），或追的方法有誤——
		例如直接接受了「自我簽署」或簽發者不明的憑證、把任何證書當成有效、或忽略中間 CA 的核驗。成因為以「信任憑證宣告的簽發者」代替「自己動手驗證整串到底」，沒建一份
		可信根清單。後果是攻擊者可用自行簽發、或憑無效中間 CA 發的憑證冒充任何主機，中間人竊聽與偽裝攻擊成功。修法是憑證驗證必須建構並驗證「由受信根簽發的完整鏈」、
		嚴格用系統／自訂且更新中的根清單，確認每個簽發者與證書都在有效期內、用途正確，並以起碼輸出的驗證錯誤即失敗關閉。`,
		problem: `// 不安全寫法：自行憑證接受任意憑證，簽發者也不核對
const tls = require('tls');
const socket = tls.connect({ host, port, rejectUnauthorized: false });   // 無驗證鏈`,
		fixed: `// 安全寫法：用嚴格 CA 驗證，只信任指定 root 架構→拒錯即斷線
const tls = require('tls');
const socket = tls.connect({
  host, port,
  rejectUnauthorized: true,                       // 達交要建完整鏈
  servername: host,
  ca: [ trustedRootPem ]                        // 只信受管 root
});
socket.on('error', () => socket.destroy());`,
		patch: `@@
-  const socket = tls.connect({ host, port, rejectUnauthorized: false });
+  const socket = tls.connect({
+    host, port, rejectUnauthorized: true, servername: host, ca: [ trustedRootPem ]
+  });
+  socket.on('error', () => socket.destroy());`,
		refs: ['CWE-296', 'OWASP-Crypto'],
		tags: ['tls', 'cert-chain', 'verification'],
	},
	{
		id: 'CWE-298',
		name: 'Improper Validation of Certificate Expiration',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `未驗證或不正確地驗證憑證到期（Certificate Expiration）。程式拿到憑證卻不看它的 notBefore／notAfter 有效期間，或時間檢查有誤（用本地時鐘、忽略
		時區、拿單向比較）。成因為直接把憑證「能解碼」當作「有效」，或時間比較沒顧及時鐘 skew。後果是「已過期／未生效」的憑證照常被接受，過期的憑證可能屬於已被撤銷的
		舊金鑰、或一組被更換的舊身分，讓中間人與偽冒有機可乘。修法是每個憑證在用途前都檢查「現在時間在 its validity window 內」，時間來源用可信且可同步的時鐘，並對
		CA、根與端點憑證都一致比對 notBefore／notAfter，時鐘偏差超限即判不信賴。`,
		problem: `// 不安全寫法：只解出憑證內容，不看 notAfter 就使用
const x509 = parseCert(peer.der);
doTlsHandshake(peer);                       // 沒檢查 x509.validFrom/validTo`,
		fixed: `// 安全寫法：確認現在時間落在 notBefore..notAfter 內才繼續
const x509 = parseCert(peer.der);
const now = Date.now();
if (now < x509.validFrom.getTime() || now > x509.validTo.getTime())
  throw new Error('certificate expired or not yet valid');
doTlsHandshake(peer);`,
		patch: `@@
  const x509 = parseCert(peer.der);
+  const now = Date.now();
+  if (now < x509.validFrom.getTime() || now > x509.validTo.getTime())
+    throw new Error('certificate expired or not yet valid');
  doTlsHandshake(peer);`,
		refs: ['CWE-298', 'OWASP-Crypto'],
		tags: ['certificate', 'expiration', 'tls'],
	},
	{
		id: 'CWE-299',
		name: 'Improper Check for Certificate Revocation',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `未或不正確地檢查憑證撤銷（Certificate Revocation）。程式沒有查 CRL、或沒有做 OCSP，或哪怕查了也把查不到／查漏當成「未撤銷」。成因為驗證時跳過嚴重
		（revoked）查詢、對 OCSP responder 連線失敗時「不過就放行」、或快取了太久的撤銷資訊。後果是被撤銷的憑證——已被竊金鑰、已離職身分仍被撤——照樣被信任，讓包含
		compromised 憑證的連線繼續成立，中間人利用被撤銷的金鑰仍被信任。修法是對每張必須撤銷檢查的等路憑證做 CRL／OCSP 查詢，任何查詢失敗或不再確認時以「失敗即失敗」（fail-closed）
		關閉，並正確快取並設撤銷狀態有效性時間。`,
		problem: `// 不安全寫法：憑證驗證完全跳過撤銷狀態
const ctx = tls.createSecureContext({});        // 未設定 CRL/OCSP 檢查
...                                    // revoked 憑證照常被接受`,
		fixed: `// 安全寫法：啟用撤銷檢查且 OCSP 連不上即失敗關閉
const ocsp = require('ocsp');
ocsp.check({ cert, issuer, skip: false }, (err, res) => {
  if (err || res.status !== 'good') throw new Error('revoked/undeterminable');
  proceed();
});`,
		patch: `@@
-  const ctx = tls.createSecureContext({});
+  ocsp.check({ cert, issuer, skip: false }, (err, res) => {
+    if (err || res.status !== 'good') throw new Error('revoked/undeterminable');
+    proceed();
+  });`,
		refs: ['CWE-299', 'OWASP-Crypto'],
		tags: ['certificate', 'revocation', 'tls'],
	},
];
