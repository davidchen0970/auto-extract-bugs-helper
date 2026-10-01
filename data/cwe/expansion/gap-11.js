// CWE chunk — 類別:驗證、Android 元件、通訊通道、Web 用戶端與架構/品質弱點
// code 內避免 `${` 以免汙染反引號字串。
export default [
	{
		id: 'CWE-836',
		name: 'Use of Password Hash Instead of Password for Authentication',
		lang: 'javascript',
		status: 'Complete',
		what: `以「密碼ㄉ雜湊值」取代「密碼」本身進行身分驗證。程式不檢查使用者真的輸入對的密碼，而是取
		「客戶端提交的密碼雜湊」與資料庫裡存的雜湊直接比對。它等於把雜湊當成通行證：任何人只要不傳
		「密碼」、改傳「那組雜湊」，只要與庫存雜湊相同就被放行，根本不用知道原密碼。攻擊者若從資料
		庫外流或其它管道取得雜湊，就能直接拿它冒充使用者登入；就算攔不得明文，雜湊也足以取代於認證，
		使「雜湊不可逆、所以安全」的假定失效。成因是把「驗證用的職責」錯放在上游而否真正在伺服器端
		拿使用者輸入去計算是安全的。修法是驗證永遠在信任端進行：使用者只傳密碼，伺服器取回帳號的 salt
		+ 正確的 slow hash（bcrypt/argon2）再比對，不允許客戶端自行決定一組雜湊來比。`,
		problem: `// 不安全寫法：直接拿客戶端提交的雜湊與庫存雜湊比對 => 雜湊本身就是通行證
function login(user, submittedHash) {
  const stored = db.find(user).passwordHash
  if (submittedHash === stored) return ok(user);  // 攻擊者拿到 stored 就能冒充
  return fail();
}`,
		fixed: `// 安全寫法：使用者只傳密碼，伺服器端以 salt + bcrypt 驗證 => 雜湊不可取代密碼
function login(user, plainPassword) {
  const rec = db.find(user);
  // bcrypt.compare 自動取出 hash 裡內嵌的 salt 重新算,再常時比對
  if (bcrypt.compareSync(plainPassword, rec.passwordHash)) return ok(user);
  return fail();
}`,
		patch: `@@
 function login(user, submittedHash) {
-  const stored = db.find(user).passwordHash
-  if (submittedHash === stored) return ok(user);
+  const rec = db.find(user);
+  if (bcrypt.compareSync(plainPassword, rec.passwordHash)) return ok(user);
   return fail();
 }`,
		refs: ['CWE-836', 'OWASP'],
		tags: ['password-hash', 'authentication', 'hash-comparison', 'precomputed'],
	},
	{
		id: 'CWE-837',
		name: 'Improper Enforcement of a Single, Unique Action',
		lang: 'javascript',
		status: 'Complete',
		what: `對「單一、唯一動作」的強制執行不當。系統要求某個動作只能被執行一次、或只能產生唯一一個結果
		（例如兌換一次優惠碼、轉帳一次、領取一次獎勵、鎖一次帳號），但程式沒有確實強制，或強制得不完整。
		只要沒有把「這個動作已做過」全域、且不可變地被記錄住並在每次執行前都被重新檢查，攻擊者可重複送出
		同一個請求（重放）、或在並行情境下同時 hit 多次，讓只該發生一次的事情發生多次。成因常是「檢查是
		否已執行」與「標記已執行」分開兩筆、沒有在資料庫端用唯一約束防治，或狀態只存於單一執行緒內的
		快取。後果是重複兌換、重複轉帳、超額發放等邏輯錯誤。修法是讓「執行＋標記」成為不可分割的動作：
		用資料庫的 unique 約束、原子性 increment/upsert、或帶條件式更新的 SQL，並在伺服器端對冪等鍵去重。`,
		problem: `// 不安全寫法：先檢查 redeem 表中沒有記錄,才 insert => 檢查與寫入之間可被並行重放
function redeem(code, uid) {
  const found = db.query("SELECT 1 FROM redeem WHERE code=? AND uid=?", [code, uid]);
  if (found) return fail("already used");
  db.run("INSERT INTO redeem(code, uid) VALUES (?, ?)", [code, uid]); // 並行下可插兩列
  return ok();
}`,
		fixed: `// 安全寫法：用資料庫唯一約束當最終防線,搭配 INSERT 失敗即代表已用過 => 不可能超領
db.run("CREATE TABLE redeem(code TEXT, uid TEXT, PRIMARY KEY(code, uid))");
function redeem(code, uid) {
  try {
    db.run("INSERT INTO redeem(code, uid) VALUES (?, ?)", [code, uid]); // 重放撞 PK => 拋錯
    return ok();
  } catch (e) {
    if (isUniqueViolation(e)) return fail("already used");
    throw e;
  }
}`,
		patch: `@@
 function redeem(code, uid) {
-  const found = db.query("SELECT 1 FROM redeem WHERE code=? AND uid=?", [code, uid]);
-  if (found) return fail("already used");
-  db.run("INSERT INTO redeem(code, uid) VALUES (?, ?)", [code, uid]);
-  return ok();
+  try {
+    db.run("INSERT INTO redeem(code, uid) VALUES (?, ?)", [code, uid]);
+    return ok();
+  } catch (e) {
+    if (isUniqueViolation(e)) return fail("already used");
+    throw e;
+  }
 }`,
		refs: ['CWE-837', 'OWASP'],
		tags: ['single-action', 'idempotency', 'replay', 'unique-constraint'],
	},
	{
		id: 'CWE-838',
		name: 'Inappropriate Encoding for Output Context',
		lang: 'javascript',
		status: 'Complete',
		what: `輸出內容使用了「不符合下游預期」的編碼。程式要輸出資料給下游元件時，指定或使用了某一種編碼，
		但下游真正期待的編碼是另一種：例如伺服器宣告輸出是 ISO-8859-1、下游卻以 UTF-8 解讀，或輸出的是
		HTML 但卻用「字面值」而非 HTML entity 跳脫。當兩邊的編碼／字元集對不上，特殊字元會被錯誤地交錯
		轉譯，原本該被當成「資料」的內容可能被下游當成「控制字元／結構」執行——最常見就是 SQL、HTML、JavaScript
		、URL 或 XML 該做相對應的字元 escaping 卻没做，變成注入（XSS、SQLi）的一種來源。成因是「隨手挑一種
		編碼」或預設編碼在系統升級後改變，兩端不一致。修法是明確指定、並嚴格對齊「該輸出上下文需要的編碼」，
		每個上下文（HTML、attribute、script、URL 等）用各自對應的 encode，並在兩端都宣告相同的字符集。`,
		problem: `// 不安全寫法：使用者輸入直接塞進 HTML 且沒有以 HTML 上下文編碼 => 會被當成標籤執行
function renderComment(text) {
  return "<p>" + text + "</p>";        // text 含 <script> 時原樣輸出,未做 HTML 編碼
}`,
		fixed: `// 安全寫法：以「HTML 內容上下文」正確跳脫特殊字元 => 輸入永遠被當資料,不會成結構
function escapeHtml(v) {
  return String(v)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#39;");
}
function renderComment(text) {
  return "<p>" + escapeHtml(text) + "</p>";
}`,
		patch: `@@
 function renderComment(text) {
-  return "<p>" + text + "</p>";
+  return "<p>" + escapeHtml(text) + "</p>";
 }`,
		refs: ['CWE-838', 'OWASP'],
		tags: ['encoding', 'output-context', 'escaping', 'xsx'],
	},
	{
		id: 'CWE-842',
		name: 'Placement of User into Incorrect Group',
		lang: 'javascript',
		status: 'Complete',
		what: `把使用者放入了錯誤的群組。程式或管理者在指派使用者時，把他放進與其意圖不符的權限群組：該放
		進「員工」組卻放進「管理員」組，或用「複製使用者」功能時從錯誤來源複製了群組成員關係。這會讓使用者
		獲得比預期更高的權限，或少了該有的權限——前者造成越權存取機密、後者造成功能無法用或不當拒絕。成因常見於
		批次建立帳號時的預設群組選錯、管理介面的下拉憑字而誤選、以及把「表示群組的字串」與「真正的群組身分」
		搞混。修法是任何群組指派都要有明確、可稽核的來源：指派後進行「意圖 vs 實際」的對照檢查，建立帳號
		需二次確認，並把群組身分以「程式可見的符號」而非人擇字串來表示，降低誤排。`,
		problem: `// 不安全寫法：由呼叫端自由傳入 groupId 字串,批次建立時誤傳 admin 就得到高權限
function createUser(name, email, groupId) {
  // groupId 來自管理介面選單,選錯或預設值有誤 => 被放進 admin 群組
  addMembership(userIdFor(name), groupId);
}`,
		fixed: `// 安全寫法：只允許以白名單符號對應到固定群組,並在指派後做「意圖 vs 實際」稽核
const GROUPS = { EMPLOYEE: "group-emp", APPROVER: "group-app", MANAGER: "group-mgr" };
function createUser(name, email, roleKey) {
  const groupId = GROUPS[roleKey];          // 只接受預先定義的符號,錯誤輸入直接失敗
  if (!groupId) throw new Error("unknown role");
  addMembership(userIdFor(name), groupId);
}`,
		patch: `@@
-function createUser(name, email, groupId) {
-  addMembership(userIdFor(name), groupId);
-}
+const GROUPS = { EMPLOYEE: "group-emp", APPROVER: "group-app", MANAGER: "group-mgr" };
+function createUser(name, email, roleKey) {
+  const groupId = GROUPS[roleKey];
+  if (!groupId) throw new Error("unknown role");
+  addMembership(userIdFor(name), groupId);
+}`,
		refs: ['CWE-842', 'OWASP'],
		tags: ['group-assignment', 'authorization', 'misgroup', 'privilege'],
	},
	{
		id: 'CWE-914',
		name: 'Improper Control of Dynamically-Identified Variables',
		lang: 'php',
		status: 'Complete',
		what: `對「動態識別的變數」控管不當。程式用「動態變數」語法（例如 PHP 的變數變數 $x = $name，
		或用字串去動態挑選與 create 一個變數）來讀寫變數，但該變數名的來源是使用者輸入或外部可控值，且未加
		限制。因為「變數名」直接決定了要對哪個變數下手，攻擊者只要能控制這個名稱，就等於能讀寫程式流程中共
		任意名字的變數——包括權限旗標、暫存狀態、使用者設定等——繞過原本的分支判定或授權。成因是「以外部值當變數
		名稱」又沒有白名單把能存取的變數集合限死。後果包括任意狀態被覆寫、保留變量的值被改、安全性決定被竄改。
		修法是不用「外部名為變數」這種間接，改用固定鍵的 map/關聯陣列並對鍵做白名單驗證，或把透過名字要找的
		資料來源換成受型別與存取控制保護的物件。`,
		problem: `<?php
// 不安全寫法：以使用者提供的鍵作為變數名動態寫入 => 可任意改其他變數
$is_admin = false;
$name = $_POST['key'];   // 攻擊者傳 name=is_admin & value=1
$$name = $_POST['value'];  // 直接就 $$is_admin = 1 => 變 $is_admin = 1
?>`,
		fixed: `<?php
// 安全寫法：用固定鍵的陣列並做白名單,不讓外部鍵進入變數命名空間
$state = [ 'is_admin' => false ];
$name = $_POST['key'];
if (!in_array($name, ['nickname', 'theme'], true)) { // 只允許白名單鍵
    http_response_code(400); exit;
}
$state[$name] = $_POST['value'];   // 寫的是受控 array,不碰其他變數
?>`,
		patch: `@@
-$name = $_POST['key'];
-$$name = $_POST['value'];
+$state = [ 'is_admin' => false ];
+$name = $_POST['key'];
+if (!in_array($name, ['nickname', 'theme'], true)) {
+    http_response_code(400); exit;
+}
+$state[$name] = $_POST['value'];`,
		refs: ['CWE-914', 'OWASP'],
		tags: ['variable-variables', 'dynamic-name', 'php', 'register-globals'],
	},
	{
		id: 'CWE-917',
		name: "Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')",
		lang: 'java',
		status: 'Complete',
		what: `運算式語言（EL）注入。程式在建構一段 EL 運算式（如 JavaServer Pages 的 EL、OGNL、SpEL 等）
		時，把上游提供的輸入直接拼接進去，卻沒有中和（neutralize）或未正確中和其中能改變 EL 語意的特殊元素。EL
		在伺服器端會被求值、甚至能存取物件的屬性與呼叫方法；若輸入能插進「.、方括號、屬性存取或方法呼叫語法」，
		攻擊者就可改寫整句 EL 讓它執行非預期的存取——例如求得 classLoader、讀取環境屬性、叫用竊取密碼的函式，
		造成屬性洩漏、反序列化、甚至遠端任意程式/表示執行。成因是把輸入當純資料直接字面拼接。修法是改用資料繫結／
		參數化 EL（把輸入當字面量 "Values" 而非 "表達式"）、對屬性名做白名單、並徹底避開把使用者輸入拼接成
		Expression 的做法。`,
		problem: `// 不安全寫法：把使用者輸入直接當 EL 字串求值,可注入屬性存取/方法呼叫
public Object eval(ELProcessor el, String name) {
    // name 傳 "x; ''.getClass().forName('java.lang.Runtime')" 等即可溢出語句語法
    return el.eval(name);
}`,
		fixed: `// 安全寫法：輸入視為普通資料(key),用受控的取值,不由使用者指定 EL 字串
public Object lookup(Map<String,Object> scope, String key) {
    if (!ALLOWED_KEYS.contains(key)) throw new IllegalArgumentException(key);
    return scope.get(key);          // 屬性來源是固定 map,非可求值的 EL
}`,
		patch: `@@
-public Object eval(ELProcessor el, String name) {
-    return el.eval(name);
-}
+public Object lookup(Map<String,Object> scope, String key) {
+    if (!ALLOWED_KEYS.contains(key)) throw new IllegalArgumentException(key);
+    return scope.get(key);
+}`,
		refs: ['CWE-917', 'OWASP'],
		tags: ['el-injection', 'ognl', 'spel', 'jsp'],
	},
	{
		id: 'CWE-920',
		name: 'Improper Restriction of Power Consumption',
		lang: 'c',
		status: 'Complete',
		what: `對「耗電量」的限制不當。程式運作在電力是受限資源（無法自動補充）的環境——嵌入式裝置、感測器、
		電池供電的物聯網節點——卻沒有好好控制自己每一次運作會消耗多少電力。若某個動作（密集運算、長ping、連續
		發送無線封包、保持高運算時脈）被外界觸發卻無配額限制，攻擊者可重複觸發把它變成「耗電放大」：把電池整
		顆榨乾、或把熱耗推到使裝置當機、誤動作。成因通常是「呼叫消費動作的次數只能靠外部節制」而自身沒有配額、節流
		或上限。後果是資源耗竭、可靠性下降、在關鍵裝置上造成長時間停機。修法是在能耗動作上設「條與期限」限制、對
		消耗電力較高的操作實行配額/節流/逾時、進入低功耗待命，並把未受控的外部觸發數過濾或隔離。`,
		problem: `// 不安全寫法：外部呼叫可直接重複觸發高耗電的無線傳輸動作,自身無任何限制
int send_bulk(const void *data, size_t n) {
    // 大量封包送出,沒有每日/每秒配額 => 攻擊者可狂送把電池耗乾
    return radio_send(data, (uint16_t)n);
}`,
		fixed: `// 安全寫法：對高耗電動作加配額,超額即降載/拒絕,讓受限電力用得可預期
static unsigned budget = MAX_TX_PER_CYCLE;
int send_bulk(const void *data, size_t n) {
    if (budget == 0) return -1;      // 本週期配額已用盡 => 拒發,保電
    radio_send(data, (uint16_t)n);
    budget--;
    if (budget == 0) enter_lowpower();  // 配額用完進入低功耗
    return 0;
}`,
		patch: `@@
 int send_bulk(const void *data, size_t n) {
-    return radio_send(data, (uint16_t)n);
+    if (budget == 0) return -1;
+    radio_send(data, (uint16_t)n);
+    budget--;
+    if (budget == 0) enter_lowpower();
+    return 0;
 }`,
		refs: ['CWE-920', 'OWASP'],
		tags: ['power-consumption', 'energy', 'battery', 'quota', 'embedded'],
	},
	{
		id: 'CWE-921',
		name: 'Storage of Sensitive Data in a Mechanism without Access Control',
		lang: 'javascript',
		status: 'Complete',
		what: `把敏感資料存放進「沒有內建存取控制」的機制。程式要保存機密（token、密碼、金鑰、個人資料）時，
		選擇了一個本身沒有存取控管的儲存位置——例如可被任何人讀取的暫存檔、可下載的靜態檔、無權限限制的共用目錄、
		或任何「在檔案系統／裝置層級就允許所有人存取」的地方。因為「存放的機制」根本攔不住別人，就算應用程式的授權邏輯
		再嚴，機密依然脫離了保護範圍而外洩。攻擊者只要知道路徑或列目錄就能直接讀走。成因是「只顧選個方便的地方
		存」卻沒有確認該位置本身是否受限。修法是讓機密落在「具備真正存取控管」的儲存裡：把檔案權限設成僅擁有者可
		讀寫、使用密碼庫（keyring、secure store）、或以 OS 級 ACL/權限 + 加密保護，並確認沒有任何別的路徑能略過。`,
		problem: `// 不安全寫法：把機密寫進公開可下載/世界可讀的位置,該機制本身沒有存取控管
function persistSecret(secret) {
  // public/ 是網站靜態根,任何人 GET /creds.txt 都能讀走
  fs.writeFileSync("public/creds.txt", secret, { mode: 0o644 });
}`,
		fixed: `// 安全寫法：放進僅擁有者可讀的私有路徑(或 OS 密碼庫),機密落在外界到不了的機制
function persistSecret(secret) {
  // .secrets/ 不在文件根且 mode 0600,只有執行身分可讀
  fs.mkdirSync(".secrets", { recursive: true, mode: 0o700 });
  fs.writeFileSync(".secrets/creds", secret, { mode: 0o600 });
}`,
		patch: `@@
-  fs.writeFileSync("public/creds.txt", secret, { mode: 0o644 });
+  fs.mkdirSync(".secrets", { recursive: true, mode: 0o700 });
+  fs.writeFileSync(".secrets/creds", secret, { mode: 0o600 });`,
		refs: ['CWE-921', 'OWASP'],
		tags: ['sensitive-data', 'access-control', 'secret-storage', 'exposed'],
	},
	{
		id: 'CWE-925',
		name: 'Improper Verification of Intent by Broadcast Receiver',
		lang: 'java',
		status: 'Complete',
		what: `Broadcast Receiver 未正確驗證 Intent 的來源。Android 應用程式用 BroadcastReceiver 接收廣播的
		Intent，卻沒有先驗證這個 Intent 到底是不是來自可信的傳送者。任何應用程式都可以送出一個「滿足過濾條件」的隱式
		廣播來觸發本地 receiver，因此只要 receiver 在處理前只信 Intent 的資料、不驗證其 source/authenticity，
		攻擊者便能冒名觸發敏感處理動態——重設狀態、修改本機資料、觸發本該只由系統或其他可信 app 發出的動作。成因是
		拿「隱式廣播」+「只比對 action 字串」就執行任務，缺乏 origin 鑑別。修法是改用僅內部可見的 explicit
		Intent（指定 Component 且不 export）、在前端就用"signature"或"signatureOrSystem"保護層級宣告 receiver，
		並在 onReceive 內對意圖的 source、元件、及資料做權限檢查後才處理。`,
		problem: `// 不安全寫法：全站可被非受控隱式 action 觸發,onReceive 不驗證傳送者身分
<receiver android:name=".MyReceiver" android:exported="true">
  <intent-filter><action android:name="com.app.action.RESET" /></intent-filter>
</receiver>` + `
class MyReceiver : BroadcastReceiver() {
  override fun onReceive(ctx: Context, intent: Intent) {
    // 不檢查誰送來;任何 app 送 RESET action 都會進這
    ctx.deleteDatabase("user.db")   // 敏感動作被冒名觸發
  }
}`,
		fixed: `// 安全寫法：receiver 不 export,僅收同 app' 的 explicit Intent => 外部觸不進來
<receiver android:name=".MyReceiver" android:exported="false" />

class MyReceiver : BroadcastReceiver() {
  override fun onReceive(ctx: Context, intent: Intent) {
    // 只被同 app 以 explicit component 觸發;並再驗證傳送者
    if (intent.action != "com.app.action.RESET") return
    ctx.deleteDatabase("user.db")
  }
}`,
		patch: `@@
-<receiver android:name=".MyReceiver" android:exported="true">
-  <intent-filter><action android:name="com.app.action.RESET" /></intent-filter>
-</receiver>
+<receiver android:name=".MyReceiver" android:exported="false" />`,
		refs: ['CWE-925', 'OWASP'],
		tags: ['broadcast-receiver', 'android', 'intent', 'origin-check'],
	},
	{
		id: 'CWE-926',
		name: 'Improper Export of Android Application Components',
		lang: 'java',
		status: 'Complete',
		what: `Android 應用程式元件被不當「導出(export)」。元件（Activity、Service、ContentProvider、
		BroadcastReceiver）被標成可被其他應用程式啟動或存取，卻沒有正確限制「哪些應用程式能啟動它、
		或存取的它藏的資料」。只要 android:exported="true"（或用含 intent-filter 時預設導出），其他 app 就
		能依它們的權限意圖呼叫進來；若元件又缺 permission 保護或做了過於權限放寬的授權，攻擊 app 就能啟動敏感
		畫面、過度觸發 service、或透過 ContentProvider 讀改不該碰的資料。成因常是「為了讓某功能被外部用」而
		整體 export，卻忽略了元件的敏感面。修法是只把真正需要跨 app 的元件 export，這類元件一律加權限保護與參數
		validate，其餘元件明確 android:exported="false"，不必要時絕不導出。`,
		problem: `// 不安全寫法：Activity 被 export 又無 permission,其他 app 可直接啟動敏感畫面
<activity android:name=".AdminActivity" android:exported="true" />`,
		fixed: `// 安全寫法：不需跨 app 存取的元件明確不導出,要導出的加 permission 保衛
<activity android:name=".AdminActivity"
          android:exported="false"
          android:permission="com.app.permission.ADMIN" />`,
		patch: `@@
-<activity android:name=".AdminActivity" android:exported="true" />
+<activity android:name=".AdminActivity"
+          android:exported="false"
+          android:permission="com.app.permission.ADMIN" />`,
		refs: ['CWE-926', 'OWASP'],
		tags: ['android-export', 'component', 'permission', 'content-provider'],
	},
	{
		id: 'CWE-927',
		name: 'Use of Implicit Intent for Sensitive Communication',
		lang: 'java',
		status: 'Complete',
		what: `用「隱式 Intent」進行敏感資料的傳輸。Android 應用程式以 implicit intent（只給 action/data、
		不指定目標元件）去送敏感資料給另一個元件或 app。系統會把這種 intent 分派給所有符合條件的 receiver
		（可含惡意 app）；傳送方不在乎「誰收到」，因此機密資料（金鑰、密碼、檔案 URI、個人資料）就可能被送到
		攻擊者控制的元件中。即使啟動成功的是「本該收的」app，插在中間的其他 app 也可能攔截到同一份。成因是用隱式
		intent 圖"彈給系統選"，來傳本該定向的敏感負載。修法是發敏感資料一律使用 explicit intent——明確指定 target
		Component/package——並以 Signature 層級的 permission 保衛 receiver、避免開 revealing 的 file:// Uri。
		唯一的出口是內容資料最好改經受信任的 provider 存取。`,
		problem: `// 不安全寫法：隱式 intent 送 API 金鑰=> 系統可能分派給惡意 app
fun sendKey() {
  val i = Intent("com.app.action.RECEIVE_KEY")
  i.putExtra("key", apiKey)         // 沒有指定元件的隱式訊息
  startActivity(i)                  // 任何處理該 action 的 app 都可能收到
}`,
		fixed: `// 安全寫法：explicit intent 指出 target 元件,且用 Signature 權限保護 receiver
fun sendKey() {
  val i = Intent(this, SecretReceiver::class.java)   // 明確指定本 app 元件
  i.putExtra("key", apiKey)
  sendBroadcast(i, "com.app.permission.SECRET")    // 並以 signature 權限收
}`,
		patch: `@@
-  val i = Intent("com.app.action.RECEIVE_KEY")
+  val i = Intent(this, SecretReceiver::class.java)
   i.putExtra("key", apiKey)
-  startActivity(i)
+  sendBroadcast(i, "com.app.permission.SECRET")`,
		refs: ['CWE-927', 'OWASP'],
		tags: ['implicit-intent', 'android', 'sensitive-data', 'explicit-intent'],
	},
	{
		id: 'CWE-939',
		name: 'Improper Authorization in Handler for Custom URL Scheme',
		lang: 'java',
		status: 'Complete',
		what: `自訂 URL scheme 的處理常式授權不當。應用程式註冊了一個自訂 scheme（例如 myapp://、bank://）
		的 handler，讓深連結能進入 app 的某些介面或動作，但卻沒有正確限制「谁可以用這個 scheme 觸發該 handler」。
		自訂 scheme 是全域可被任意其他 app／頁面呼叫的（沒有內建的身分隔離），只要 handler 直接把 scheme 的 host/
		path/參數當成可信任的指令，攻擊者便能從網頁或另一 app 發 myapp://pay?amount=9999 這類連結去觸發
		CSR 狀的動作。成因是「有 scheme 就能進 → 有 scheme 就信任」而没有驗證發起端與 payload。修法是 handler
		一律把它當「不可信的深連結」：驗證來源可信任性、強力驗證 host/path、不自動執行危險之動作、對敏感動作要求再
		確認/回呼，並避免在行洪 context 動態執行不可信的傳值。`,
		problem: `// 不安全寫法：深連結 handler 直接信任 scheme 的 path/參數,無來源與權限驗證
fun onDeepLink(intent: Intent) {
  val uri = intent.data ?: return           // 可來自網頁 myapp://pay?to=X&amount=9999
  if (uri.host == "pay") doPayment(uri.getQueryParameter("to"),
                                  uri.getQueryParameter("amount").toLong())
}`,
		fixed: `// 安全寫法：超過入門驗證後才做動作,敏感操作改內部再確認,不在深連結直接放行
fun onDeepLink(intent: Intent, userId: String) {
  val uri = intent.data ?: return
  // 只當啟頁參考;對 pay 這類敏感 host,不採信 scheme 即執行
  if (uri.host == "pay") {
    confirmAndPayLater(userId, uri.getQueryParameter("to"))  // 改用已驗證身分+需再確認
  }
}`,
		patch: `@@
-fun onDeepLink(intent: Intent) {
-  val uri = intent.data ?: return
-  if (uri.host == "pay") doPayment(uri.getQueryParameter("to"),
-                                  uri.getQueryParameter("amount").toLong())
-}
+fun onDeepLink(intent: Intent, userId: String) {
+  val uri = intent.data ?: return
+  if (uri.host == "pay") {
+    confirmAndPayLater(userId, uri.getQueryParameter("to"))
+  }
+}`,
		refs: ['CWE-939', 'OWASP'],
		tags: ['custom-url-scheme', 'deep-link', 'android', 'authorization'],
	},
	{
		id: 'CWE-940',
		name: 'Improper Verification of Source of a Communication Channel',
		lang: 'node',
		status: 'Complete',
		what: `對「通訊通道來源」的驗證不當。程式建立一個通訊通道（socket、WebSocket、HTTP 傳入請求、RPC）
		來處理某個由「某位 actor 發起」的請求，卻沒有驗證這份請求是否真的來自預期的那個來源（對的 origin、對的
		peer、對的瀏覽器頁面、或對的機器）。只要不驗證來源，任何能發出該類請求的人都被當成同一個人：跨站台攻擊可
		藉「瀏覽器自動帶上 cookie/session」的請求冒名進來，或另一個頁面可連到你的 WebSocket。後果是身分偽裝、
		判定誤用、敏感動作被非法觸發。成因是只驗證「內容/機會」而不驗證「發起端」。修法是認真驗證通道的 origin/
		Origin header/來源身分，使用附帶的驗證（session、token、mTLS、host check），並對內部動作再以已驗證身分
		做授權。`,
		problem: `// 不安全寫法：WebSocket 只認連線,不檢查 Origin => 任意第三方頁面都能連上並當成同用戶
const WebSocket = require("ws");
const wss = new WebSocket.Server({ port: 8080 });
wss.on("connection", (ws) => {
  // 沒有驗證 ws 的來源/身分,任何頁面連上都當可信端
  ws.on("message", (m) => handleAdminCommand(m));
});`,
		fixed: `// 安全寫法：驗證 Origin 並為連線關聯已登入身分,再依身分授權動作
const WebSocket = require("ws");
const wss = new WebSocket.Server({ noServer: true });
wss.on("connection", (ws, req, session) => {
  if (!isTrustedOrigin(req.headers.origin)) { ws.close(1008); return; }
  if (!session) { ws.close(1008); return; }               // 來源與身分都驗證
  ws.on("message", (m) => handleAdminCommand(m, session.user));
});`,
		patch: `@@
  wss.on("connection", (ws) => {
-  ws.on("message", (m) => handleAdminCommand(m));
+  if (!isTrustedOrigin(req.headers.origin)) { ws.close(1008); return; }
+  if (!session) { ws.close(1008); return; }
+  ws.on("message", (m) => handleAdminCommand(m, session.user));
  });`,
		refs: ['CWE-940', 'OWASP'],
		tags: ['source-verification', 'websocket', 'origin', 'spoofing'],
	},
	{
		id: 'CWE-941',
		name: 'Incorrectly Specified Destination in a Communication Channel',
		lang: 'node',
		status: 'Complete',
		what: `通訊通道的「目標」被錯指。程式建立通訊通道以向某個 actor 發起「外送」的請求，但卻沒有正確
		指定該請求真正的目的地——用了可被改變或拼錯的位址、拿使用者輸入當 host、或沒檢查解析出的目標是否與預期相符。
		一旦目的地被打錯或可控，機密資料就會被送到攻擊者控制的伺服器（把端點名、代理、重定向、或"官方域名"誤拼成
		近似的惡意主機），或該收的人收不到而洩給另一方。成因是「位址由外部可控」且沒有持久單一真值。後果包括機密
		exfiltration、後置處理（webhook、回呼）被打劫、供應鏈被誤連到冒名端點。修法是收斂目標位址為不可變設定
		（白名單的 host/port）、驗證 TLS/憑證主體、拒絕使用者傳遞網址可指到不期望領域，並對重定向再檢查。`,
		problem: `// 不安全寫法：webhook 目標直接採用使用者提供的網址 => 可能把機密外送到攻擊者主機
function notify(url, payload) {
  fetch(url, { method: "POST", body: JSON.stringify(payload) }); // url 可在白名單外亂指
}`,
		fixed: `// 安全寫法：目標位址來自固定設定並在送前驗證來源 ==> 防外送可被劫
function notify(hook, payload) {
  const dest = WEBHOOK_URLS[hook];            // 只允許預先定義的端點
  if (!dest || !dest.startsWith("https://trusted.example/")) return;
  fetch(dest, { method: "POST", body: JSON.stringify(payload) });
}`,
		patch: `@@
-function notify(url, payload) {
-  fetch(url, { method: "POST", body: JSON.stringify(payload) });
-}
+function notify(hook, payload) {
+  const dest = WEBHOOK_URLS[hook];
+  if (!dest || !dest.startsWith("https://trusted.example/")) return;
+  fetch(dest, { method: "POST", body: JSON.stringify(payload) });
+}`,
		refs: ['CWE-941', 'OWASP'],
		tags: ['destination', 'webhook', 'ssrf', 'transport'],
	},
	{
		id: 'CWE-942',
		name: 'Permissive Cross-domain Security Policy with Untrusted Domains',
		lang: 'node',
		status: 'Complete',
		what: `跨網域安全原則放太寬、還包含不受信任的網域。程式用某種「web 用戶端保護機制」(Content
		Security Policy、crossdomain.xml、CORS 白名單)宣告「允許與哪些來源通訊」，但這些原則允許清單裡塞進了
		不受信任、甚至使用者可控的網域。瀏覽器或 Flash/JS 客戶端會據此放行對這些網域的存取；只要名單含一個惡意或
		可被註冊的網域，攻擊者就能從它發出請求、讀回資料、載入不被期望的內容——打破「應用程式信任某些來源」的信任界。
		成因是「多加幾個來源圖方便」或用了過寬的萬用字元/使用者輸入來組 policy。修法是讓跨網域清單最少、只含真正
		受控的網域、配合明確的 scheme/host/port、禁止盲目的 * 與動態串使用者網域、並用 CSP 的指定 host 而非
		大放寬的來源來許可信。`,
		problem: `// 不安全寫法：將使用者輸入的網域直接拼進 CORS 白名單 => 攻擊者可把自己域名加進信
function cors(origin) {
  // origin 可為 "https://evil.com",直接放進可存取清單 => 任何網域都能讀回應
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
}`,
		fixed: `// 安全寫法：檢查網域落在固定白名單才反射 => 不信任動態網域
const ALLOWED = new Set(["https://app.example.com", "https://admin.example.com"]);
function cors(origin) {
  if (!ALLOWED.has(origin)) return;                 // 非白單來源直接不給存取
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
}`,
		patch: `@@
 function cors(origin) {
-  res.setHeader("Access-Control-Allow-Origin", origin);
+  if (!ALLOWED.has(origin)) return;
+  res.setHeader("Access-Control-Allow-Origin", origin);
   res.setHeader("Access-Control-Allow-Credentials", "true");
 }`,
		refs: ['CWE-942', 'OWASP'],
		tags: ['cors', 'csp', 'cross-origin', 'origin'],
	},
	{
		id: 'CWE-1004',
		name: "Sensitive Cookie Without 'HttpOnly' Flag",
		lang: 'javascript',
		status: 'Complete',
		what: `敏感的 Cookie 未加上 HttpOnly 旗標。程式用 cookie 儲存敏感資訊（session id、token）時，沒有把
		cookie 標上 HttpOnly，於是 JavaScript(document.cookie) 也能讀到它。只要最近端任何一處發生 XSS，攻擊者就能透過
		document.cookie 把 session 偷走，即使沒有 XSS，任何能注入 script 的第三方也極易把它撈走取得登入鐘。HttpOnly
		的作用是「讓瀏覽器層級的 document.cookie 看不見它」，把它跟指令式弱點隔離，是縱深防禦裡扨輕成本的一層。成因是
		「網站不靠 JS 直接用 cookie」就忘了設旗標、或框架預設沒開。修法是所有含敏感性質的 cookie 一律加上 Secure +
		HttpOnly + SameSite，只在真正需要以 JS 讀取的、非機密的 cookie 才不放——並盡量改用 httpOnly 的 session cookie
		與免 JS 存取的機制。`,
		problem: `// 不安全寫法：設置 session cookie 卻沒有 HttpOnly => XSS 時 document.cookie 可竊走
function login(req, res, sid) {
  res.setHeader("Set-Cookie", "session=" + sid + "; Path=/; SameSite=Lax");
}`,
		fixed: `// 安全寫法：敏感 cookie 加 HttpOnly + Secure + SameSite => JS 看不到、只能經 HTTP 帶
function login(req, res, sid) {
  res.setHeader("Set-Cookie",
    "session=" + sid + "; Path=/; HttpOnly; Secure; SameSite=Strict");
}`,
		patch: `@@
-  res.setHeader("Set-Cookie", "session=" + sid + "; Path=/; SameSite=Lax");
+  res.setHeader("Set-Cookie",
+    "session=" + sid + "; Path=/; HttpOnly; Secure; SameSite=Strict");`,
		refs: ['CWE-1004', 'OWASP'],
		tags: ['httponly', 'cookie', 'xss', 'session-hijacking'],
	},
	{
		id: 'CWE-1007',
		name: 'Insufficient Visual Distinction of Homoglyphs Presented to User',
		lang: 'javascript',
		status: 'Complete',
		what: `提供給使用者的「同形字(homoglyph)」缺少視覺上的區別。程式把某些識別字/文字顯示給使用者時，
		顯示機制（字型、版面、色彩重疊）沒有讓使用者容易看出「看起來一模一樣／極相似的字形其實是不同字元」——例如拉丁字母
		'l' 與數字 '1'、O 與 0、或 Unicode 的希里爾 'а' 與拉丁 'a'、及全形/半形變化。使用者若碰上看似熟悉卻
		實際不同的識別字，就可能被誘導把「看起來對」的內容當成「真的對」而弄錯——例如把偽造的網域、路徑、命令或帳號當成
		真的、點到惡意目標，形成社交工程式的失敗。成因是顯示層若字集/字型混用好讓不同 code point 呈現成同型。修法是
		選用能把 homoglyph 區分開的字集/渲染、強制標記、或將本該一致的字串規範化成唯一表示法（NFKC 正規化、禁止混淆
		碼點），並在關鍵識別字處以不受字型混淆的方式呈現。`,
		problem: `// 不安全寫法：把"看起來相同"但碼點不同的字直接顯示,不區分同形異義字
function showDomain(name) {
  // "paypal.com" 的 p 被換成希里爾 'р'(U+0440) 時,視覺上與真網域難分
  return "<strong>" + name + "</strong>";
}`,
		fixed: `// 安全寫法：正規化/過濾混淆碼點,以單一表示法識別,避免同形字混入
function showDomain(name) {
  const clean = name.normalize("NFKC").replace(CONFUSABLE_RE, ""); // 清除混淆 code point
  return "<strong>" + clean + "</strong>";
}`,
		patch: `@@
 function showDomain(name) {
-  return "<strong>" + name + "</strong>";
+  const clean = name.normalize("NFKC").replace(CONFUSABLE_RE, "");
+  return "<strong>" + clean + "</strong>";
 }`,
		refs: ['CWE-1007', 'OWASP'],
		tags: ['homoglyph', 'unicode', 'confusable', 'phishing'],
	},
	{
		id: 'CWE-1021',
		name: 'Improper Restriction of Rendered UI Layers or Frames',
		lang: 'javascript',
		status: 'Complete',
		what: `對「渲染的 UI 層／frame」的限制不當。網頁應用程式沒有（或不正確地）限制「哪些 frame 或 UI 層可以
		繪製它」、也沒有把「屬於別的應用程式／網域」的 window 限制在 renderer 外。最常見是 clickjacking(UI 重疊)：
		攻擊頁在你必須信任的應用程式外層疊了一個透明 frame，誘你點「看似無害的按鈕」，實際上點到下方真正的敏感鈕——
		因為目標應用程式沒設 X-Frame-Options/CSP frame-ancestors，允許自己被任意網域包在 frame 中。另一面是不同
		網域的 frame 彼此可以透過 onClick 等把使用者視線誤導對敏感操作。成因是沒宣告「我能被誰嵌套」的保護。修法是回應
		X-Frame-Options: DENY/SAMEORIGIN 或用 CSP 的 frame-ancestors 明確只許可信來源，並對真正需要嵌入的
		領域控制 frame 數與事件浮現、以 friend sender/同源存取落地。`,
		problem: `// 不安全寫法：回應沒帶 frame 限制 -> 受害網頁可被嵌進攻擊頁的透明 iframe 而 clickjacking
function renderPage(res, html) {
  res.setHeader("Set-Frame-Options", "");   // 完全沒擋;任何網域都能 frame 它
  res.send(html);
}`,
		fixed: `// 安全寫法：CSP frame-ancestors 只許站台來源,程式不許被第三方嵌套 => 消 clickjacking
function renderPage(res, html) {
  res.setHeader("Content-Security-Policy", "frame-ancestors 'self'");
  res.send(html);
}`,
		patch: `@@
 function renderPage(res, html) {
-  res.setHeader("Set-Frame-Options", "");
+  res.setHeader("Content-Security-Policy", "frame-ancestors 'self'");
   res.send(html);
 }`,
		refs: ['CWE-1021', 'OWASP'],
		tags: ['clickjacking', 'framebusting', 'frame-ancestors', 'ui-overlay'],
	},
	{
		id: 'CWE-1022',
		name: 'Use of Web Link to Untrusted Target with window.opener Access',
		lang: 'javascript',
		status: 'Complete',
		what: `用「保留 window.opener 存取」的連結導向不受信任的外部站(reverse tabnabbing)。網站把連往自身可否
		入控土地之外的外部站點的超連結設定成讓新開的 window 仍保有可存取 window.opener 的能力——也就是 <a target="_blank">
		預設會把 opener 留在新視窗給外部頁。外部站收到控制後，可以修改安全性敏感的 window.opener 屬性，最典型是把
		window.opener.location 換成釣魚頁或利用該站點新開的登入樣式，讓使用者回到"原分頁"時落在冒名站而洩漏密碼。
		成因是「開新視窗卻又把 opener 留給外部站」。修法是給任何會開啟外部 site 的連結加 rel="noopener noreferrer"
		(或根據 CSP 延伸 fonte whereno opener)，或改用 new window 另見不帶 opener 的方式 / 用 javascript 做成
		about:blank 中介，務使新視窗拋棄 opener 的存取。`,
		problem: `// 不安全寫法：連結開新分頁卻沒設 noopener => 外部站可改 window.opener.location 導去釣魚頁
<a href="https://external.example/x" target="_blank">更多資訊</a>`,
		fixed: `// 安全寫法：加上 rel="noopener noreferrer" => 新視窗無法再動 opener 的安全性屬
<a href="https://external.example/x" target="_blank" rel="noopener noreferrer">更多資訊</a>`,
		patch: `@@
-<a href="https://external.example/x" target="_blank">更多資訊</a>
+<a href="https://external.example/x" target="_blank" rel="noopener noreferrer">更多資訊</a>`,
		refs: ['CWE-1022', 'OWASP'],
		tags: ['reverse-tabnabbing', 'window-opener', 'noopener', 'cover'],
	},
	{
		id: 'CWE-1024',
		name: 'Comparison of Incompatible Types',
		lang: 'javascript',
		status: 'Complete',
		what: `對「不相容型別」進行比較。程式在兩個實體之間做比較，但兩者在型別上並不相容、無法保證直接比較能
		得到正確結果。典型如 JavaScript 的 == 隱含型別轉換(把 "0"、""、null、false 互相"撞成一類")，或把字串
		與數字、布林與數字、不同長度的位元詮釋拿去相等/排序，結果取決於"語言裡隱含的怪規格"而非資料真實。這會造成
		看起來的相等或順序與意圖不合：把字串 "10" 與數字 10 看成相等、把 "2" 看成等於 true、或把敏感值與 falsy
		值混過邊界，進而造成錯誤的分支、授權誤判或檢查被繞過。成因是沒有先約束型別就比較。修法一律用嚴格、型別明確的
		比較(=== 且先轉成同型別)、避免依賴隱式 coerc，需要相等先明確 normalize 型別，對可控輸入在比較前先驗證 type。`,
		problem: `// 不安全寫法：== 隱含轉型 => 型別不合的值被誤判相等,敏感性檢查被繞過
function isAdmin(flag) {
  // "0"|0|null|false 在 == 下都與 false 相撞 => 非預期相等
  if (flag == false) return false;
  return true;
}`,
		fixed: `// 安全寫法：先限定型別再用嚴格比較 => 只在真確 bool 時成立
function isAdmin(flag) {
  if (typeof flag !== "boolean") return false;   // 型別不合就拒絕,不做隱含轉型
  return flag === true;
}`,
		patch: `@@
 function isAdmin(flag) {
-  if (flag == false) return false;
-  return true;
+  if (typeof flag !== "boolean") return false;
+  return flag === true;
 }`,
		refs: ['CWE-1024', 'OWASP'],
		tags: ['type-comparison', 'coercion', 'strict-equal', 'js-weird'],
	},
	{
		id: 'CWE-1025',
		name: 'Comparison Using Wrong Factors',
		lang: 'c',
		status: 'Complete',
		what: `比較時用錯了「因子」。程式對兩個實體做比較，但它比較的卻是「錯誤的因子或特性」——例如要比身分
		(identity)卻比了名字、要比大小卻比了指標位址、要比陣列元素卻只比了容得大小、要比 socket 是否同一對象卻比了
		local 位址。比較一但在"看起來相近但不是決定因素"的屬性上，會得到看似合理但實際錯的結果：把兩個不同實體誤判成
		相同(安全*granted)、或把該相等的誤判為不相同(不相信包含)。後果是授權混淆、去重失敗、憑證錯配或繞過邊界。成因是
		「拿最容易的欄位(名字/位址/型別)當判等鍵」。修法是先用真正代表 identity 的欄位/等物件(如 pointer、handle、
		ID、hash 且夠長)做比較、比對正確的資料尺寸與欄位，並確認用的因子與「被判定之語義」一致再比較。`,
		problem: `// 不安全寫法：用 struct 的"名字"而非內容判兩結構相同 => 內容改過仍被判相等
struct Acct { char name[32]; double bal; };
int same(struct Acct *a, struct Acct *b) {
    return strcmp(a->name, b->name) == 0;   // bal 不同也被當同帳戶
}`,
		fixed: `// 安全寫法：用代表身分的 id 判等,並把內容欄位也納入 => 比較因子真正對應本體
struct Acct { uint64_t id; char name[32]; double bal; };
int same(struct Acct *a, struct Acct *b) {
    return a->id == b->id;                    // id 才是 identity; name/bal 不同不影響身分
}`,
		patch: `@@
 int same(struct Acct *a, struct Acct *b) {
-    return strcmp(a->name, b->name) == 0;
+    return a->id == b->id;
 }`,
		refs: ['CWE-1025', 'OWASP'],
		tags: ['wrong-factor', 'comparison', 'identity', 'equality'],
	},
	{
		id: 'CWE-1037',
		name: 'Processor Optimization Removal or Modification of Security-critical Code',
		lang: 'c',
		status: 'Complete',
		what: `處理器最佳化移除或修改了「安全關鍵」的程式碼。開發者把某個安全保護機制建進程式(例如用於抵擋
		side-channel 的隨機延遲、清除密鑰的 memset、或刻意保持的"額外工作")，但編譯器最佳化(或 JIT、CPU 最佳化)在
		最佳化時判斷"結果沒差"就把它移除或改掉——典型是 memset(buf, 0, len) 清除祕密密鑰被最佳化"死代碼"刪除、或隨機
		時間延遲被捨掉，使原本"要費電/費時的保護"變成零。後果是保護機制形同虛設，憑證密鑰殘留在記憶體、時序側通道不被掩蔽，
		導致密鑰外洩或時序攻防門洞。成因是沒告訴編譯器"這個副作業有意義"。修法是使用編譯器保證不清除的清除手段(volatile、
		explicit_bzero/OPENSSL_cleanse、sec_clear/防最佳化函式)，並對 side-channel 用 constant-time 資料流、配合硬體層
		還不得最佳化掉的安全原語。`,
		problem: `// 不安全寫法：用 memset 清除密鑰,最佳化可視其為"死寫入"而整段移除 => 密鑰殘留
void wipe(char *key, size_t n) {
    memset(key, 0, n);   // 之後 key 不再被讀 => 編譯器可刪掉,祕密沒被清除
}`,
		fixed: `// 安全寫法：以 volatile 指標/明確 io 致編譯器不可移除的清除 => 確確實實抹掉密鑰
typedef void *(*volatile wipe_fn)(void *, int, size_t);
void wipe(char *key, size_t n) {
    static wipe_fn v = (wipe_fn)memset;   // 經由 volatile 函式指標 => 無法當死碼移除
    v(key, 0, n);
    __asm__ __volatile__("" : : "r"(key) : "memory");
}`,
		patch: `@@
 void wipe(char *key, size_t n) {
-    memset(key, 0, n);
+    static wipe_fn v = (wipe_fn)memset;
+    v(key, 0, n);
+    __asm__ __volatile__("" : : "r"(key) : "memory");
 }`,
		refs: ['CWE-1037', 'OWASP'],
		tags: ['optimizer', 'dead-store', 'side-channel', 'wipe'],
	},
	{
		id: 'CWE-1041',
		name: 'Use of Redundant Code',
		lang: 'c',
		status: 'Complete',
		what: `使用冗贛的代碼。程式含有多個函式、方法、流程、宏等，其中其代碼內容幾乎相同、或維持業重複的
		邏輯。冗餘最大的風險在它背叛「延控性」：當規則某處需要修(CWE-402、登入校驗、管控列表)時只修其中一份、其他
		"看起來一樣"的份沒有同步，於是某些路徑還是舊(易)版本，安全修正被抄漏，形成"某條 sup逻辑仍不防"的死角；此外
		多份互異代表單點修正容易不一致，bug 修正不完整。成因通常是 copy-paste 而未抽成共用體。修法是以單一來源抽
		公用/共用函式把重複邏輯收歸到一處，讓修補只修一份、天然同步，並用工具去找"幾乎相同"的重複(DRY/Clone
		Detection)能及早改。`,
		problem: `// 不安全寫法：兩處重複實作"驗證 token",只修 A 不修 B => 修正不同步留漏洞
int valid_a(const char *t) { return t && strlen(t) >= 8; }
int valid_b(const char *t) { return t && strlen(t) >= 8; }   // 跟 a 一樣,copy-paste 重複
// 之後只把 valid_a 改嚴格,valid_b 還是舊版 => 那條路徑仍鬆`,
		fixed: `// 安全寫法：把規則抽成單一共用函式,修補只改一份 => 全部呼叫處同步生效
int valid(const char *t) {
    return t && strlen(t) >= 12 && has_upper(t) && has_digit(t);
}
int valid_a(const char *t) { return valid(t); }   // 全走同一份規則
int valid_b(const char *t) { return valid(t); }`,
		patch: `@@
-int valid_a(const char *t) { return t && strlen(t) >= 8; }
-int valid_b(const char *t) { return t && strlen(t) >= 8; }
+int valid(const char *t) {
+    return t && strlen(t) >= 12 && has_upper(t) && has_digit(t);
+}
+int valid_a(const char *t) { return valid(t); }
+int valid_b(const char *t) { return valid(t); }`,
		refs: ['CWE-1041', 'OWASP'],
		tags: ['redundant-code', 'duplication', 'divergence', 'copy-paste'],
	},
	{
		id: 'CWE-1042',
		name: 'Static Member Data Element outside of a Singleton Class Element',
		lang: 'java',
		status: 'Complete',
		what: `在非 singleton 類別裡使用 static(且非 final)的成員資料。class 元素一定要是"整個程式只能用一次
		(singleton)"時才適合把一份可變的 static 欄位放進去；若 parent class 不是 singleton，卻又有 non-final static
		欄位，就代表"這份可變全域"在各個實例/各方被斟酌共享。每當某個路徑改到它,其它所有"看起來獨立"的使用全部被波及，
		而且因為處處共享,初始化的時序、多執行緒的順序都把狀態搞混,一個執行位置改了另一執行的前提就垮。若這類共享狀態又帶著
		安全啟示(權限、預設、快取判斷),就會把一個請求的結果漏到另一個。修法是把此類 static non-final 資料降成實例欄位，
		或真要用全域就以 singleton(私有建構+單例) + 同步介面來封裝，避免人人直改同一份。`,
		problem: `// 不安全寫法：非 singleton 類別卻有可變 static 全域 => 各實例/各執行緒共享被亂改
public class Session {
    public static boolean breach = false;   // 非 final static;某處設 true 影響全部 Session
    public int uid;
}`,
		fixed: `// 安全寫法：把可變狀態降為實例欄位,與物件身分綁在一起 => 不跨實例互相汙染
public class Session {
    private boolean breach;      // 每個 Session 自有
    public int uid;
    public synchronized void flag() { this.breach = true; }
    public synchronized boolean isBreached() { return this.breach; }
}`,
		patch: `@@
 public class Session {
-    public static boolean breach = false;
+    private boolean breach;
     public int uid;
+    public synchronized void flag() { this.breach = true; }
+    public synchronized boolean isBreached() { return this.breach; }
 }`,
		refs: ['CWE-1042', 'OWASP'],
		tags: ['static-member', 'singleton', 'global-state', 'shared-state'],
	},
	{
		id: 'CWE-1043',
		name: 'Data Element Aggregating an Excessively Large Number of Non-Primitive Elements',
		lang: 'python',
		status: 'Complete',
		what: `資料元素聚合了「過多」的非基本型別子元素。程式使用一個資料結構(資料表、資料類)帶有極大量的
		子元素，而這些子元素又全部是非基本型別(struct/物件/巢狀聚合)而非基本標量。一旦元素規模大到難以審視，任何人(含
		審計者/工具)都無法快速確認這些欄位的敏感度、來源與流向，安全修補就容易漏掉其中某幾個;而且大而深的聚合也讓複製/比較
		/序列化成本高、邊界錯誤(sum 過深)與記憶體耗用放大的風險放大。成因是"永來越多欄位"地擴張單一資料與而未模組化。
		修法是合理的拆分成具單一職責的小 data 類/子結構,只聚合必要的欄位、讓態多的子元素進入子物件,並對資料太深/太大做
		設計約束,減少要把全部變量管理一次的情況。`,
		problem: `# 不安全寫法：單一構造體聚合幾十個非基本型別子物件 => 難以審視,修補易漏、開銷大
class Monster:
    # 一口氣裝幾十個子物件欄位,每個又各自是 source/config/credential...
    def __init__(self, sub_a, sub_b, sub_c, sub_d, ...):   # 數十個物件參數全部進同一個
        self.a = UserConfig(); self.b = CredsHolder(); ...      # 規模巨大,欄位流向不清`,
		fixed: `# 安全寫法：拆成互含職責分明的小型資料類,只在頂層聚合必要子結構 => 清楚、好管控
class AccountData:
    def __init__(self, profile, creds_ref, prefs):
        self.profile = profile     # 每個子結構職責單一,規模受控、欄位易同治
        self.creds = creds_ref
        self.prefs = prefs`,
		patch: `@@
-    def __init__(self, sub_a, sub_b, sub_c, sub_d, ...):
-        self.a = UserConfig(); self.b = CredsHolder(); ...
+    def __init__(self, profile, creds_ref, prefs):
+        self.profile = profile
+        self.creds = creds_ref
+        self.prefs = prefs`,
		refs: ['CWE-1043', 'OWASP'],
		tags: ['data-aggregation', 'large-structure', 'fan-in', 'maintainability'],
	},
	{
		id: 'CWE-1044',
		name: 'Architecture with Number of Horizontal Layers Outside of Expected Range',
		lang: 'c',
		status: 'Complete',
		what: `架構的「水平層數」落在預期範圍之外。系統的分層(UI、controller、service、dao…)裡實際的水平層數
		過多或過少，超出本來設計的合理範圍。過少的層常代表"一大物厚")把邏輯、存取、命令全揉在少數幾層 => 授權/驗證這些
		"橫切"又容易被漏或繞;層數過多則讓資料跨越多層被反复轉換，資料的來源與信任邊界不透明,每個邊界都可被你自己的
		另一 path 繞過,且每層的存取控制不一致 => 越權、身分錯位更容易出現。成因是架構在無意間增生或塌縮層,失去有心分界。
		修法是刻意維持設計裡明確、單一的水平層數，把橫切安全(驗證、授權、編碼)做成獨立跨層層或統一在此入口執行,讓"是哪一層
		該把關"清楚可審,並在架構層重建各層的職責責任邊界與序列。`,
		problem: `// 不安全寫法：把存取邏輯、驗證與資料直接寫在呼單層 => 層數塌縮,責任集中易漏把關
void handle(void) {
    parse_input(req);            // controller 直接在 Ad to...
    // 却直接在這一層做了 data access 又驗權又存取資料 => 全疊一層
    if (query_db_by(req->user)) permit(req);   // cache 環/權限都在同墆,邊界不清
}`,
		fixed: `// 安全寫法：把處理拆成明確的 representation / service(驗權) / repository 三層
void handler(Request *r, Store *store) {
    if (!r->session || acl_allow(r->session)) { deny(r); return; }   // 層界就地在授權層
    data_out = repository_fetch(store, r->id);                        // 資料層職責單一
    respond(r, render(data_out));                                     // 表示層職責單一
}`,
		patch: `@@
 void handle(void) {
-    parse_input(req);
-    if (query_db_by(req->user)) permit(req);
+    if (!r->session || acl_allow(r->session)) { deny(r); return; }
+    data_out = repository_fetch(store, r->id);
+    respond(r, render(data_out));
 }`,
		refs: ['CWE-1044', 'OWASP'],
		tags: ['layering', 'architecture', 'horizontal-layer', 'separation'],
	},
	{
		id: 'CWE-1045',
		name: 'Parent Class with a Virtual Destructor and a Child Class without a Virtual Destructor',
		lang: 'cpp',
		status: 'Complete',
		what: `父類別有 virtual destructor、子類別卻沒有。父類別宣告了 virtual ~Base()，而繼承它的某個子類別沒
		有自己的 virtual(或被漏掉) destructor。C++ 的規則:當你透過 Base* 解構(DELETE a Base* 指向 Derived)，
		必須使基類的 destructor 為 virtual 且連鎖呼叫到子類別;若只有父類 virtual、子類没 virtual(或不是同 virtual
		鏈),DELETE 經父指標時只會解構"父"的部分,子類別新增的資源(動態配置、handle、緩衝)沒被釋放,造成
		partial destruction -> 記憶體外洩、資源沒關、甚至 use-after-釋放。成因是繼承層裡漏掉 virtual 修飾。修法是讓
		繼承鏈中每個未決的可刪除類別帶 virtual destructor(virtual ~Derived() override)，或用 virtual 基底統一規格、非多型
		類盡量避免被當指標 delete，常態下讓 delete 只在正確型別進行。`,
		problem: `// 不安全寫法：Derived 沒 virtual destructor,透過 Base* delete 時只解父不會解子 -> 子資源漏
class Base { public: virtual ~Base() {} };
class Derived : public Base {
  public: char *buf;
  Derived() : buf(new char[64]) {}
  ~Derived() { delete[] buf; }      // 缺 virtual => 經 Base* delete 不會呼叫到
};
void f(Base *b) { delete b; }      // 只解 Base 部分,buf 洩露`,
		fixed: `// 安全寫法：子類別 destructor 亦為 virtual(且 override),delete 父指標時連鎖解全鏈
class Derived : public Base {
  public: char *buf;
  Derived() : buf(new char[64]) {}
  virtual ~Derived() override { delete[] buf; }   // virtual + override,保證被叫到
};
void f(Base *b) { delete b; }      // 現在整鏈都解 => 無洩漏/無半解`,
		patch: `@@
   Derived() : buf(new char[64]) {}
-  ~Derived() { delete[] buf; }
+  virtual ~Derived() override { delete[] buf; }`,
		refs: ['CWE-1045', 'OWASP'],
		tags: ['virtual-destructor', 'cpp', 'inheritance', 'leak'],
	},
	{
		id: 'CWE-1046',
		name: 'Creation of Immutable Text Using String Concatenation',
		lang: 'java',
		status: 'Complete',
		what: `用字串串接來建立「immutable(不可變)」的文字。程式用不可變字串(Java/String、C#/string、或
		類似 immutable 型別)反覆做 + 串接(或 +=)來累積一份較長文字，例如在大迴圈或組合大量區塊時寫 result += piece。
		因為字串不可變，每次 + 都會額外配置一個全新字串再拷貝兩邊,於是迴圈 n 次就是 O(n^2) 的複製與分配,而大輸入要
		(限制/格式)時就把記憶體用爆、每次配置還把機密片段留在 heap 上,資源耗竭又加深洩漏面。相較 appendable/mutable
		的建構器(StringBuilder/Buffer)只配置一次、就地增量,既省又少留副本。成因是不分 immutable 型別就貪連。修法是遇到
		累積性的字串建造改用可變型別(StringBuilder、join/stream 收集),不要在 hot loop 對不可變字串做串接。`,
		problem: `// 不安全寫法：不可變 String 在迴圈一再 + => 每次分配新串,O(n^2) 且留下眾多暫時副本
String build(List<String> parts) {
    String out = "";
    for (String p : parts) {
        out = out + p;      // 每次 + 都開新 String 並複製舊的 => 貴且留副本
    }
    return out;
}`,
		fixed: `// 安全寫法：改用可變的 StringBuilder 就地累積 => 少分配、不留暫緩擲副本
String build(List<String> parts) {
    StringBuilder out = new StringBuilder();
    for (String p : parts) {
        out.append(p);      // 可變 buffer,就地增長 => O(n)、副本最少
    }
    return out.toString();
}`,
		patch: `@@
-String build(List<String> parts) {
-    String out = "";
-    for (String p : parts) {
-        out = out + p;
-    }
-    return out;
-}
+String build(List<String> parts) {
+    StringBuilder out = new StringBuilder();
+    for (String p : parts) {
+        out.append(p);
+    }
+    return out.toString();
+}`,
		refs: ['CWE-1046', 'OWASP'],
		tags: ['string-concat', 'immutable-string', 'stringbuilder', 'allocations', 'dos'],
	},
	{
		id: 'CWE-1047',
		name: 'Modules with Circular Dependencies',
		lang: 'node',
		status: 'Complete',
		what: `模組之間存在「循環依賴」。程式含有一組模組,其中某個模組的參考(indirect/直接)又繞回它自己,
		形成 A 依賴 B、B 又(間接)依賴 A 的圈。循環依賴在載入序上會在"彼此都還未就緒"時就互取,常造成一份模組在
		半初始化狀態就被另一份拿去用(拿到的還是 undefined/空物件),而這份半狀態是「只有初始順序不同次」的 -> 初始化順序一
		錯就讀到未準備的匯出,安全初始化(設定 ACL、載入密鑰、註冊 receiver)被順序拖垮而漏設。動態/執行期才對模組做
		的這些"依賴對方現已 ready"的最後反而是 flaky。成因是模組職責沒拆分、相互欠解而自結成環。修法是解除環:把共用的
		base 抽成第三方無環模組、依賴沿一方向化(DAG)、透過注入把正向依賴倒轉,讓依賴圖無圈、初期化順序確定。`,
		problem: `// 不安全寫法：A 需要 B、B 又在頂層音符 require A => 載入順序造成半初始化
// a.js
const B = require("./b");
class A { start() { return B.helper(); } }   // 執行期才用 B
module.exports = new A();

// b.js
const A = require("./a");   // 頂層就 require A => 與 a 頂層 require b 成環
// 在 a 尚未把 A 建好時,這裡 A 可能是 undefined => 註冊拿到壞狀態`,
		fixed: `// 安全寫法：把共用的核心抽成低層模組、高層間取倒轉依賴 => 依賴圖成非環 DAG
// core.js
module.exports = { helper() { return "ok"; } };   // 無依賴的公用層
// a.js   (只依賴 core,不再依賴 b)
const core = require("./core");
class A { start() { return core.helper(); } }
module.exports = new A();
// b.js   (也依賴 core,不回頭依賴 a)
const core = require("./core");
module.exports = { run() { return core.helper(); } }`,
		patch: `@@
-// b.js
-const A = require("./a");     // 頂層 require => 成環
+// core.js
+module.exports = { helper() { return "ok"; } };
+// b.js
+const core = require("./core");     // 只依賴無環 core
-module.exports = { ... 用 A ... }`,
		refs: ['CWE-1047', 'OWASP'],
		tags: ['circular-dependency', 'modules', 'initialization', 'topological'],
	},
	{
		id: 'CWE-1048',
		name: 'Invokable Control Element with Large Number of Outward Calls',
		lang: 'c',
		status: 'Complete',
		what: `一個「可呼叫的 control element」帶有過多的「向外呼叫」。程式裡的某個可呼叫體(大型函式/方法)參考了
		極大量的其他 application 物件——即 Fan-Out 過大的呼叫。這麼多外部呼叫把這個函式變成一個巨型"呼叫中樞",它要協調太多
		對象,很易把"該對哪些對象做安全處理"漏掉其中一個(只驗證多數、漏驗少數);再者 Fan-Out 大代表任何一個被呼叫對象
		改變異(source/參數/信任),影響都會匯集於此,變更權耗大且不確定。若其中某些向外的呼叫傳遞的是敏感資料或可挑高權,就更
		容易因"邊界不清"漏給來路。成因是沒把重職責拆開。修法是降低 Fan-Out:把 function 拆成單一職責的小函式、將向外的
		呼叫收斂到少數 高階協調/注入的依賴上,讓每個呼叫的來源與必要性可審、每筆外部資料都經明確驗證。`,
		problem: `// 不安全寫法：單一 validate() 直接呼叫幾十個外部物件 => Fan-Out 過大,易漏把關
int validate(void) {
    check_a(a); check_b(b); check_c(c); check_d(d); // 幾十個
    check_e(e); check_f(f); /* ... 一直蔓延 ... */ check_zz(zz);
    return 0;
}`,
		fixed: `// 安全寫法：把職責拆給小函式,各函式只叫少量依賴 => 每個外部呼叫都可審、不漏
int validate_payload(void) {
    return check_identity(&session)   // 拆小後每個只協調少數對象
        && sanitize_fields(&input)
        && acl_gate(&acls(&session));
}`,
		patch: `@@
-int validate(void) {
-    check_a(a); check_b(b); check_c(c); check_d(d);
-    check_e(e); check_f(f); check_zz(zz);
-    return 0;
-}
+int validate_payload(void) {
+    return check_identity(&session)
+        && sanitize_fields(&input)
+        && acl_gate(&acls(&session));
+}`,
		refs: ['CWE-1048', 'OWASP'],
		tags: ['fan-out', 'outward-call', 'decomposition', 'high-coupling'],
	},
	{
		id: 'CWE-1049',
		name: 'Excessive Data Query Operations in a Large Data Table',
		lang: 'sql',
		status: 'Complete',
		what: `對大型資料表進行過度繁重的查詢操作。程式在一張很大的資料表上執行帶大量的 JOIN 與子查詢的資料查詢,
		這種查詢在資料量大時每多一個 join/子查詢就會讓執行成本被放得很大、且鎖與暫存區也隨之放大。causing 它取得資料時
		把大範圍資料表全部掃過,回應時間與資料庫負載都被"放成不受控"。若這類查詢又被使用者可控條件所觸發,攻擊者可在此做成
		資源耗竭(CWE 400 家族)與 DoS;就算不是蓄意,慢查詢也會拖垮共享庫中其它服務。成因是沒考慮資料規模就塞多重 join/子
		查詢/巢狀 select。修法是限制 join/子查詢數量、為關聯欄位建 index、把複雜查詢拆成有限多次簡單查詢或用分頁/limit 縮小
		每次取回行數,並為成本設配額與逾時遏制失控。`,
		problem: `-- 不安全寫法：大表上塞大量 join + 巢狀子查詢,資料多時全掃、成本爆表
SELECT * FROM orders o
  JOIN customers c ON o.cid=c.id
  JOIN items i ON o.iid=i.id
  JOIN addresses a ON c.aid=a.id
  JOIN payments p ON o.pid=p.id
  WHERE o.ts > (SELECT MAX(ts) FROM audit WHERE region = (SELECT ... ));`,
		fixed: `-- 安全寫法：關聯欄位建 index + 拆簡單查詢 + limit/分頁 => 每次成本受控
CREATE INDEX ix_orders_cid ON orders(cid);
CREATE INDEX ix_orders_ts  ON orders(ts);
SELECT o.id FROM orders o USE INDEX(ix_orders_ts)
 WHERE o.ts > :since ORDER BY o.ts DESC LIMIT 100;`,
		patch: `@@
-SELECT * FROM orders o
-  JOIN customers c ON o.cid=c.id
-  JOIN items i ON o.iid=i.id
-  JOIN addresses a ON c.aid=a.id
-  JOIN payments p ON o.pid=p.id
-  WHERE o.ts > (SELECT MAX(ts) FROM audit ...);
+CREATE INDEX ix_orders_cid ON orders(cid);
+CREATE INDEX ix_orders_ts  ON orders(ts);
+SELECT o.id FROM orders o USE INDEX(ix_orders_ts)
+ WHERE o.ts > :since LIMIT 100;`,
		refs: ['CWE-1049', 'OWASP'],
		tags: ['sql', 'query-cost', 'join', 'dos', 'large-table'],
	},
	{
		id: 'CWE-1050',
		name: 'Excessive Platform Resource Consumption within a Loop',
		lang: 'c',
		status: 'Complete',
		what: `在迴圈內過度消耗「平台資源」。程式的迴圈體或迴圈條件裡直接或間接保護著某個會消耗平台資源的
		control element——例如每次都開 channel/鎖/訊息/取得 fd/建立 session/分配記憶體——這類資源若在每一輪都重複消耗卻又沒
		在同時重複釋放、或數量隨迴圈數線性放大,循環次數一受控就快速把平台資源(fd、鎖、session)耗到枯竭,做成 DoS。
		尤其是 file descriptor、處理量、鎖積滿很快到系統 max。成因是"迎圈邊做事邊配資源"而未把它提出圈外或節流。修法是
		把資源的取得移到迴圈外單次建立、在圈內 reuse,並以同步/配額限制可同時存在的資源數+處理訊時即釋放,對"每次迴圈
		都 open/session"的地方進行消除或池化。`,
		problem: `// 不安全寫法：迴圈裡每輪都開新 fd 卻到最後才收 => fd 累積爆滿、資源耗竭
for (int i = 0; i < n; i++) {
    int fd = open(path, O_RDONLY);   // 每輪開一個 fd,並未每輪 close
    process(fd);                        // n 大時 fd 快速耗盡 => open 失敗/DoS
}`,
		fixed: `// 安全寫法：把珍貴資源提出圈外沿用/池化,每份用完立刻釋放 => 消耗受控
int fd = open(path, O_RDONLY);        // 圈外開一次
for (int i = 0; i < n; i++) {
    process_same_fd(fd);              // 圈內重用同一份,不再每輪配新
}
close(fd);                             // 用完一定釋
void process_same_fd(int fd) { /* lseek/讀同一 fd */ }`,
		patch: `@@
+int fd = open(path, O_RDONLY);
 for (int i = 0; i < n; i++) {
-    int fd = open(path, O_RDONLY);
-    process(fd);
+    process_same_fd(fd);
 }
+close(fd);`,
		refs: ['CWE-1050', 'OWASP'],
		tags: ['resource-loop', 'fd', 'session', 'dos', 'resource-exhaustion'],
	},
	{
		id: 'CWE-1051',
		name: 'Initialization with Hard-Coded Network Resource Configuration Data',
		lang: 'python',
		status: 'Complete',
		what: `用「寫死的網路資源設定值」來初始化資料。程式初始化某些資料時,用的是寫死的(hard-coded)值來
		識別網路資源——把 IP、port、主機名、資格(以及 URL 的 user 部分)直接烙印在程式碼裡。寫死代表它不被受署部變更,也
		不驗證:當環境(deployment)不同、或上游 host 被換掉時,程式仍連住"程式寫死的舊/錯地址",資料就送去錯的機器、或被
		針對"程式內已知目標"的攻擊引導;若寫死值還含憑證/密鑰,更是直接把祕密烙進可反編譯影像。成因是"圖方便把環境設定
		寫進碼"。修法是改由組態/環境變數/config 檔在部署層提供位址,啟動時驗證主機落在白名單並配合 TLS 驗證主體,讓
		"連哪、以誰身分"在運維層可改、在實機層一致,且敏感連線資訊不放原始碼。`,
		problem: `# 不安全寫法：把網路位址/憑證寫死在原始碼 => 部署後改不了、且資料可能送錯/密鑰外洩
def connect_db():
    conn = psycopg2.connect(host="192.168.1.7", port=5432,
                            user="app", password="P@ssw0rdHardcoded")  # 寫死且含明文密碼`,
		fixed: `# 安全寫法：位址與憑證由環境/組態提供,並對 host 做白名單驗證 => 可部署、不留祕密在碼
import os
DB = {"host": os.environ["DB_HOST"], "port": os.environ["DB_PORT"],
      "user": os.environ["DB_USER"], "password": os.environ["DB_PASS"]}
def connect_db():
    if DB["host"] not in ALLOWED_DB_HOSTS: raise SystemExit("bad host")
    conn = psycopg2.connect(**DB)   # 祕密來自環境,不在影像`,
		patch: `@@
-def connect_db():
-    conn = psycopg2.connect(host="192.168.1.7", port=5432,
-                            user="app", password="P@ssw0rdHardcoded")
+import os
+DB = {"host": os.environ["DB_HOST"], "port": os.environ["DB_PORT"],
+      "user": os.environ["DB_USER"], "password": os.environ["DB_PASS"]}
+def connect_db():
+    if DB["host"] not in ALLOWED_DB_HOSTS: raise SystemExit("bad host")
+    conn = psycopg2.connect(**DB)`,
		refs: ['CWE-1051', 'OWASP'],
		tags: ['hardcoded-host', 'network-config', 'credential-in-code', 'deployment'],
	},
	{
		id: 'CWE-1052',
		name: 'Excessive Use of Hard-Coded Literals in Initialization',
		lang: 'javascript',
		status: 'Complete',
		what: `初始化時過度使用「寫死的字面值」。程式初始化某個資料元素時用的是 hard-coded 字面值,而且它不是
		簡單的整數或 static constant,而是包含秘密/地址/標識/臨再碼這種"非單純常數"的寫死值。這類值一旦被烙進程式/設定
		,全都變成"影像內秘密":憑證、API key、seed、magic 位址只認它,anti-brute/授權都建立在此,一旦外流(反編譯、
		log、binary 字串掃)全部失效;換環境時更是全寫死不能被受署變,還把"這值該是可配參數"的職責漏了。成因是"寫死圖簡便"
		而未分常數/組態/密鑰管理。修法是:一般常數做成具名 const;而秘密/易變標識使用密鑰管理(secret store、env、設定檔
		)並走私 字形式的初始化,杜絕祕密以字面值落板。`,
		problem: `// 不安全寫法：把辨識/機密的字面直寫進程式 => 秘密落板、換環境不可改
function init() {
  const billingKey = "sk_live_7f28...";      // 非單純常數,是會外流的密鑰字面
  const region   = "us-east-1-17";          // 標識值寫死,部署無從改
  configure(billingKey, region);
}`,
		fixed: `// 安全寫法：共用常數具名,秘密走環境/密鑰管理,初始化時不帶字面祕密
const REGION = "us-east-1";                  // 單純、具名的常數
function init() {
  const billingKey = process.env.BILLING_KEY;   // 秘密從外部注入,不落板
  if (!billingKey) throw new Error("missing BILLING_KEY");
  configure(billingKey, REGION);
}`,
		patch: `@@
-function init() {
-  const billingKey = "sk_live_7f28...";
-  const region   = "us-east-1-17";
-  configure(billingKey, region);
-}
+const REGION = "us-east-1";
+function init() {
+  const billingKey = process.env.BILLING_KEY;
+  if (!billingKey) throw new Error("missing BILLING_KEY");
+  configure(billingKey, REGION);
+}`,
		refs: ['CWE-1052', 'CWE-798', 'OWASP'],
		tags: ['hardcoded-literal', 'secret', 'magic-value', 'config'],
	},
	{
		id: 'CWE-1053',
		name: 'Missing Documentation for Design',
		lang: 'python',
		status: 'Complete',
		what: `缺少「代表『設計長怎樣』」的文件。程式/系統沒有能說明它是「如何被設計」的文件——缺設計文件、
		架構描述或決策記錄(ADR)。當安全規則(誰該驗證、信任邊界何在、權限如何分層、輸入假定)沒有明文記錄,後續改了
		"看起來無關"的地方就很易在不了解設計之下破壞它:把原本"該在入口統一驗權"的地位連到錯處、把信任假設破壞錯,審計時
		也無從判定某個行為是"故意"還是"意外"。成因是不把設計成文而只留程式碼。修法是為架構、模組、權限與安全決策撰寫
		設計/架構文件與記錄(ADR),把不變之處(trust bounomn、用例不變式)寫下並在關鍵變革強制文檔同步,讓修正者在改前
		能參考設計預期,降低對安全邊界的誤破壞。`,
		problem: `# 不安全寫法：跨越權限/信任邏輯全埋在 code,沒有任何設計文件 => 改動時無從對照正確邊界
def transfer(*, session, amount, target):
    if not session.is_admin:                 # 這個驗權為什麼擺這層、該不該有更多,全沒記載
        raise Forbidden()
    # 之後有人"重構"把它移走時,沒有設計文件可提醒這是刻意邊界`,
		fixed: `# 安全寫法：把信任邊界/權責寫進設計文件(ADR),並在程式強調意圖,讓改動可對照
# docs/adr-07-transfer-acl.md
#   決策: transfer 一律在 service 層以 session.is_admin gate,絕不後移到 UI。
#   目的: 讓所有轉帳走同一驗權點,不被任何呈現分路繞過。
def transfer(*, session, amount, target):
    assert_user_is_admin(session)          # 對應 ADR-07,意圖成文、可審核`,
		patch: `@@
 def transfer(*, session, amount, target):
-    if not session.is_admin:
-        raise Forbidden()
+    assert_user_is_admin(session)   # 對應 ADR-07 明文的信任邊界`,
		refs: ['CWE-1053', 'OWASP'],
		tags: ['documentation', 'design', 'architecture-doc', 'trust-boundary'],
	},
	{
		id: 'CWE-1054',
		name: 'Invocation of a Control Element at an Unnecessarily Deep Horizontal Layer',
		lang: 'java',
		status: 'Complete',
		what: `架構某一層呼叫了它「相鄰更內的一層之外」的深層。程式某層所呼叫的代碼位在比『隔壁層還要深』
		的層(跳過了至少一層),而被跳過的這一層又不是"任何水平層都能參考的垂直公用層"。當表示層直接伸手進資料層、或 service
		直接到 "深層內部物件",深層內對"資料格式/內部狀態"的處理就變成可被除預期呼叫的方式——它跳過的層可能是"本來該負責
		驗權/編碼/完整性檢查"的責任層,因此那些橫切保護沒被執行,深層的安全前提可能被繞過;伺服器內部呼叫卻缺了該有入口。
		成因是繞層直呼,架構層感被破壞。修法是只用相鄰層介面、把跨層呼叫收斂到需執行的層再逐層轉一,或把確實可跨層的
		建做成"垂直公用層"併以明確介面與權限限制。`,
		problem: `// 不安全寫法：表示/controller 直接呼叫資料層內部,跳層 => 該層的原篩遺漏、深層前提被繞
class UserController {
    public String profile(User u) {
        // 直接跳到資料層的 raw 物件,跳過 service 層該做的權限與遮罩
        return db.row("SELECT * FROM users WHERE id = " + u.id).dump();
    }
}`,
		fixed: `// 安全寫法：依層序只呼叫相鄰層,權限/編碼在 service 層處理,再叫資料層
class UserService {
    public Profile profile(long id, Principal p) {
        acl.require(p, "profile:read");          // service 層責權由相鄰層做
        UserRow r = repo.find(id);               // 只跟相鄰的 repo 對話
        return mask(r);                        // 遮罩敏感欄位後回傳
    }
}`,
		patch: `@@
-public String profile(User u) {
-    return db.row("SELECT * FROM users WHERE id = " + u.id).dump();
-}
+public Profile profile(long id, Principal p) {
+    acl.require(p, "profile:read");
+    UserRow r = repo.find(id);
+    return mask(r);
+}`,
		refs: ['CWE-1054', 'OWASP'],
		tags: ['layer-skipping', 'horizontal-layer', 'layering', 'trust-boundary'],
	},
	{
		id: 'CWE-1055',
		name: 'Multiple Inheritance from Concrete Classes',
		lang: 'cpp',
		status: 'Complete',
		what: `從「多個 concrete(具體可實例化)類別」同時繼承。類別繼承自多於一個 non-abstract 的具體類別
		(multiple concrete inheritance)。多個具體父類各帶實作的欄位/狀態/函式,子類一次繼了兩份"真實實作",狀態與方發
		的語義會重疊、虛函式/命名撞名、與析構/初始化順序不清(也常配合 CWE-1045 語題)。安全上,不同父類各自的
		member 與常式若對同一概念做不同實作(如存取控制),子類要處理的"哪個版本生效、順序誰先"就易弄錯,若其中一側沒有
		保持預期保護(把權限根在一個父類、另一父類殘潰)便會繞過。多數問題源於過度繼承、介面混入沒被用。修法是
		盡量「繼承一個具象類 + 以 interface/abstract 表達其餘協定」、平行組合重複行為,避免同時解下多份具體實作,讓初始化
		與方法解析單一明確。`,
		problem: `// 不安全寫法：子類一次繼兩個具體實作類別 => 狀態/方法語義重疊、保護可能繞過
class FileWorker {
  public: void touch() { /* 實作 A */ }
};
class UIDriver  {
  public: void touch() { /* 實作 B,沒檢查權限 */ }
};
class Both : public FileWorker, public UIDriver { };  // 兩份具體實作同時進來,語義混淆`,
		fixed: `// 安全寫法：只繼一個具象類,其餘用 interface 表達 => 單一實作、無重疊權限
class FileWorker { public: virtual void touch() = 0; };
class RealFile : public FileWorker { public: void touch() override { /* 實作含 ACL */ } };
class UIEvent { public: virtual void render() = 0; };
class Both : public UIEvent {
  FileWorker &fw;          // 用組合代理單一實作,不再同時繼兩份具體
  public: void render() override { fw.touch(); }
};`,
		patch: `@@
-class FileWorker { public: void touch() { } };
-class UIDriver  { public: void touch() { } };
-class Both : public FileWorker, public UIDriver { };
+class FileWorker { public: virtual void touch() = 0; };
+class RealFile : public FileWorker { public: void touch() override { } };
+class Both : public UIEvent { FileWorker &fw; public: void render() override { fw.touch(); } };`,
		refs: ['CWE-1055', 'OWASP'],
		tags: ['multiple-inheritance', 'cpp', 'composition', 'inheritance'],
	},
	{
		id: 'CWE-1056',
		name: 'Invokable Control Element with Variadic Parameters',
		lang: 'c',
		status: 'Complete',
		what: `「可呼叫的 control element」帶有可變個數(vararg)的參數。某個 named-callable 或 method 的簽名
		支援變動數量(varadic)的參數/引數——C 的 ... (va_list)、或不設定到底幾個的彈性簽名。可變參數最大的風險在它有
		「型別與數量都只能靠呼叫端自行正確傳」的額定前提:avance linkage 時一旦呼叫處與定義處的型別/元素數對不上(多傳一個
		、少傳一個、或把指標/整數送成另一型類),va_arg 讀到的就是錯的、還一路越界讀,造成未定義行為、stack 亂跳,是
		format-string、func ptr 錯傳等 family 的源頭;舊編譯器也很難查出。成因是"為了彈性"使用 varargs 卻無法強制校驗。
		修法是避免 varadic 簽名,改用固定型別的參數(如 array/vector、count+陣列的固定長)、用明確的 struct 帶長,必要時用編譯期
		檢查(printf-like attribute)讓編譯器稽核型別,並內部對數量做左右界檢查。`,
		problem: `// 不安全寫法：用可變參數任意接值,count 與傳入數若對不上就亂讀 => 越界/未定義行為
#include <stdarg.h>
long sum_ints(int n, ...) {
    va_list ap; va_start(ap, n);
    long s = 0;
    for (int i = 0; i < n; i++) s += va_arg(ap, int); // 呼叫端多/少傳就誤讀
    va_end(ap); return s;
}
// sum_ints(3, 1, 2, 3, 9999) 多傳一個也吃不下檢查 => 危險`,
		fixed: `// 安全寫法：改用固定長度的陣列 + 明確 length => 數量與型別都可檢查
long sum_ints(const int *v, size_t n) {
    long s = 0;
    for (size_t i = 0; i < n; i++) s += v[i];  // 邊界可控、型別分明
    return s;
}
// 呼叫端給 {1,2,3} 與 3 => 不會因 varargs 誤配而越界`,
		patch: `@@
-long sum_ints(int n, ...) {
-    va_list ap; va_start(ap, n);
-    long s = 0;
-    for (int i = 0; i < n; i++) s += va_arg(ap, int);
-    va_end(ap); return s;
-}
+long sum_ints(const int *v, size_t n) {
+    long s = 0;
+    for (size_t i = 0; i < n; i++) s += v[i];
+    return s;
+}`,
		refs: ['CWE-1056', 'OWASP'],
		tags: ['variadic', 'vararg', 'format-string', 'signature'],
	},
];
