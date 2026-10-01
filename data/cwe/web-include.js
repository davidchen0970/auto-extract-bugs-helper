// CWE chunk — category: Web · Include & Reference & Mass Assignment.
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
		id: 'CWE-98',
		name: 'Improper Control of Filename for Include/Require Statement in PHP Program',
		lang: 'php',
		status: 'Complete',
		what: `PHP 檔案包含弱點（本地/遠端檔案包含）。把使用者輸入的字串直接拼進 include、require、include_once 等指令，
		未先限定檔名只能落在允許的目錄，攻擊者可用 ../ 或絕對路徑把伺服器上的敏感檔（如 .env、/etc/passwd）讀進來，
		甚至搭配資料流包裝（php://、data://）改為遠端載入並執行任意 PHP。建議做法是建立檔名到實體檔的對照表，只允許
		預先定義的枚舉值，永不直接使用使用者輸入作為包含路徑。`,
		problem: `<?php
// 不安全寫法：使用者輸入直接進 include，page 可帶 ../../config.php 或遠端 URL
$page = $_GET['page'];
include "templates/" . $page . ".php";   // 例如 ?page=../../config 讀到設定檔內容`,
		fixed: `<?php
// 安全寫法：只允許對照表內預先定義的檔名，使用者輸入永遠不會當成路徑
$pages = ['home' => 'home.php', 'about' => 'about.php', 'help' => 'help.php'];
$key   = $_GET['page'] ?? 'home';
$file  = $pages[$key] ?? 'home.php';     // 沒命中就回到預設頁
include __DIR__ . '/templates/' . $file;`,
		patch: `@@
-$page = $_GET['page'];
-include "templates/" . $page . ".php";
+$pages = ['home' => 'home.php', 'about' => 'about.php', 'help' => 'help.php'];
+$key   = $_GET['page'] ?? 'home';
+$file  = $pages[$key] ?? 'home.php';
+include __DIR__ . '/templates/' . $file;`,
		refs: ['OWASP-PHPFileInclusion', 'CWE-98'],
		tags: ['php', 'lfi', 'include', 'rfi'],
	},
	{
		id: 'CWE-610',
		name: 'Externally Controlled Reference to a Resource in Another Sphere',
		lang: 'java',
		status: 'Complete',
		what: `外部控制資源參照。程式用使用者提供的名稱／識別字去參照另一信任領域（sphere）內的資源，
		例如用請求參數直接拼類別名稱做反射 newInstance、或照參數動態選取內部服務方法，卻沒做允許清單，
		讓外部攻擊者能觸及本不該對外開放的內部程式碼資源。建議做法是用列舉／白名單對應後的固定常數去
		參照資源，把使用者輸入擋在決策之外，並限制可被反射或呼叫的類別／方法集合。`,
		problem: `// 不安全寫法：用請求參數當類別名做反射，攻擊者可命名任意類別使其建構
String className = request.getParameter("handler");
Object handler = Class.forName(className).getDeclaredConstructor().newInstance(); // 可能指向內部資源`,
		fixed: `// 安全寫法：白名單對應，輸入只挑固定 handler，不會建立任意類別
Map<String, Supplier<Handler>> registry = Map.of(
    "render", RenderHandler::new,
    "export", ExportHandler::new);
Handler handler = registry.getOrDefault(request.getParameter("handler"), RenderHandler::new).get();`,
		patch: `@@
-String className = request.getParameter("handler");
-Object handler = Class.forName(className).getDeclaredConstructor().newInstance();
+Map<String, Supplier<Handler>> registry = Map.of(
+    "render", RenderHandler::new,
+    "export", ExportHandler::new);
+Handler handler = registry.getOrDefault(request.getParameter("handler"), RenderHandler::new).get();`,
		refs: ['OWASP-InsecureDeserialization', 'CWE-610'],
		tags: ['reference', 'reflection', 'whitelist', 'rdir'],
	},
	{
		id: 'CWE-829',
		name: 'Inclusion of Functionality from an Untrusted Control Sphere',
		lang: 'javascript',
		status: 'Complete',
		what: `含入不受信任領域的功能。把第三方函式庫或腳本直接從不受控的 CDN、隨手抓的網址甚至注入的 URL
		載入頁面或應用，卻沒有設定資源完整度（SRI）或固定信任來源。只要載入來源被攻陷或挾持（supply-chain），
		攻擊者就能塞任何 JS 在你的網頁裡執行，等同拿到整站權限。建議做法是只從受信任領域載入、固定版本，
		並加上 SRI hash 讓瀏覽器驗證內容一致，或乾脆本地套件化後才發布。`,
		problem: `<!-- 不安全寫法：raw 網址直接載別人主機上的 JS，內容完全不受控制 -->
<script src="https://some-random-cdn.example/widgets.min.js"></script>
<script>
  // 若該來源被挾持，等同你的頁面執行攻擊者程式碼
  window.initAnalytics("UA-...");
</script>`,
		fixed: `<!-- 安全寫法：只從受信任領域載入，並用 SRI hash 強制驗證內容 -->
<script src="https://static.example.com/cdn/widgets@3.2.1.min.js"
        integrity="sha384-AbCdEf..." crossorigin="anonymous"></script>
<script nonce="rAnd0m">
  // 載入來源固定且經過完整性驗證，才敢讓它帶權限執行
  window.initAnalytics("UA-...");
</script>`,
		patch: `@@
-<script src="https://some-random-cdn.example/widgets.min.js"></script>
+<script src="https://static.example.com/cdn/widgets@3.2.1.min.js"
+        integrity="sha384-AbCdEf..." crossorigin="anonymous"></script>`,
		refs: ['OWASP-SupplyChain', 'CWE-829'],
		tags: ['supply-chain', 'sri', 'third-party', 'cdn'],
	},
	{
		id: 'CWE-915',
		name: 'Improperly Controlled Modification of Dynamically-Determined Object Attributes',
		lang: 'ruby',
		status: 'Complete',
		what: `物件大量賦值（Mass Assignment）。框架直接拿請求 body 的所有欄位一次灌進模型，未用 whitelist 過濾；
		Rails 的 params[:user] 會把人傳的每個鍵都塞給 User 屬性命中，攻擊者僅需在 body 偷帶 role=admin 或
		is_admin=true 就能把自己升級成管理者。建議做法是只在 model 上宣告 attr_accessible / 強制類型，
		並用 params.require().permit() 明列出客戶端可指定的欄位，敏感旗標一律不允許由請求設定。`,
		problem: `# 不安全寫法：直接把整個 params[:user] 丟給 create，含 role/admin 全部接受
def create
  # body 帶 {"user": {"name": "alice", "role": "admin"}} 即被寫入
  User.create(params[:user])
end`,
		fixed: `# 安全寫法：只 permit 白名單欄位，role/is_admin 不會從請求被寫入
def create
  safe = params.require(:user).permit(:name, :email)
  User.create(safe)          # role、is_admin 等敏感欄位被忽略
end`,
		patch: `@@
-  User.create(params[:user])
+  safe = params.require(:user).permit(:name, :email)
+  User.create(safe)`,
		refs: ['Rails-MassAssignment', 'CWE-915'],
		tags: ['mass-assignment', 'rails', 'params', 'authorization'],
	},
];
