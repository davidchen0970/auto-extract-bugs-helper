// CWE chunk — 類別:輸入驗證、認證與 API 使用弱點（Input Validation, Authentication & API Misuse）
// 補齊官方 v4.20 中手冊原本缺漏的 Base/Variant 條目
export default [
	{
		id: 'CWE-597',
		name: 'Use of Wrong Operator in String Comparison',
		lang: 'java',
		status: 'Complete',
		what: `用錯運算子比對字串。在 Java 這種把字串視為物件的語言，用 == 比對兩個 String 是在比「參考是否
		指向同一個物件」，不是在比內容；兩個內容相同但分屬不同物件的字串用 == 會得到 false。成因為混淆了「身分
		比較」與「值比較」——尤其從 C 遷移或習慣 C== 的開發者容易沿用；即使字面值相同，new String() 或執行期拼接
		仍可能產生不同參考。後果是身分驗證、白名單、密碼或 cookie 值比對被判成不符而繞過，或反方向誤放行，屬身分
		信任／認證邏輯層的漏洞。修法是字串一律用 .equals()，且把常數字串放前、可變輸入放後（並視需要 equalsIgnoreCase），
		避免空值例外與誤判。`,
		problem: `// 不安全寫法：用 == 比對 String，比的是物件參考不是內容
String input = request.getParameter("pwd");
if (input == storedPassword) {   // 內容相同但非同一個物件 → 恆 false
    grantAccess();
}`,
		fixed: `// 安全寫法：比內容用 .equals()，常數放前面避免空值
String input = request.getParameter("pwd");
if (storedPassword.equals(input)) {   // 內容相同即 true
    grantAccess();
}`,
		patch: `@@
-  if (input == storedPassword) {
+  if (storedPassword.equals(input)) {`,
		refs: ['CWE-597', 'OWASP'],
		tags: ['string-compare', 'authentication-bypass', 'java'],
	},
	{
		id: 'CWE-599',
		name: 'Missing Validation of OpenSSL Certificate',
		lang: 'c',
		status: 'Complete',
		what: `使用 OpenSSL 卻沒驗證憑證。程式用 SSL_connect／SSL_accept 建立加密連線之後就直接送資料，沒有呼叫
		SSL_get_verify_result() 檢查憑證驗證結果，或呼叫了卻忽略非 OK 的回傳。成因是把「連線已加密」誤當成「對端已被
		信任」：TLS 只保證傳輸保密，不會自己替你決定對端憑證是否可信。後果是中間人攻擊——攻擊者用自己的自簽或偽造
		憑證偽裝成伺服器，客戶端因為「加密通道建立成功」就信任它，機密被竊聽或流量被篡改。修法是在握手完成後呼叫
		SSL_get_verify_result() 確認回傳 X509_V_OK，否則中止連線；並以 SSL_VERIFY_PEER 設定正確的驗證模式。`,
		problem: `// 不安全寫法：建立加密通道後直接使用，從不確認憑證驗證結果
SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
SSL_set_fd(ssl, fd);
if (SSL_connect(ssl) == 1) {        // 只檢查握手成功
    send_request(ssl, secret);      // 對端憑證可能根本沒被信任
}`,
		fixed: `// 安全寫法：握手後檢查 SSL_get_verify_result()，非 OK 就中止
if (SSL_connect(ssl) != 1) { fail(); }
long r = SSL_get_verify_result(ssl);
if (r != X509_V_OK) {               // 憑證未通過驗證 → 拒絕使用連線
    SSL_shutdown(ssl);
    fail();
}
send_request(ssl, secret);`,
		patch: `@@
  if (SSL_connect(ssl) == 1) {
-     send_request(ssl, secret);
+     long r = SSL_get_verify_result(ssl);
+     if (r != X509_V_OK) { SSL_shutdown(ssl); fail(); }
+     send_request(ssl, secret);
  }`,
		refs: ['CWE-599', 'OWASP'],
		tags: ['tls', 'openssl', 'mitm', 'certificate'],
	},
	{
		id: 'CWE-600',
		name: 'Uncaught Exception in Servlet',
		lang: 'java',
		status: 'Complete',
		what: `Servlet 未捕捉的例外外洩。Servlet／controller 程式碼只對部分例外做 try-catch，未處理的例外（尤其
		RuntimeException）一路漏到容器或應用程式伺服器，容器把完整的堆疊追蹤與內部細節——類別名稱、檔案與行號、
		資料結構、資料庫錯誤訊息——直接回傳給使用者。成因為只在程式內層零星抓例外，沒在呈現層做全域攔截，又讓開發
		期的錯誤輸出原樣出現在正式環境。後果是洩漏敏感除錯資訊，攻擊者可據以推斷架構、框架版本與內部路徑，大幅降低
		探查與構築攻擊的成本。修法是在最外層用統一例外處理（全域 filter／@ControllerAdvice／攔截器）攔住所有例外，
		對外一律回傳泛化訊息、詳細內容只寫入伺服器端日誌。`,
		problem: `// 不安全寫法：只抓了部分例外，UncheckedException 漏到容器外洩堆疊
protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
    try {
        process(req);
    } catch (IOException e) {          // 只抓 IO，其它例外照漏
        resp.getWriter().write(e.toString());
    }
}`,
		fixed: `// 安全寫法：外層統一入口攔所有例外，細節寫日誌、對外泛化
@ExceptionHandler(Exception.class)
public String onError(Exception e) {
    logger.error("uncaught error", e);   // 細節只進日誌
    return "error-view";                  // 對外顯示泛化頁面
}`,
		patch: `@@
-  } catch (IOException e) { resp.getWriter().write(e.toString()); }
+  @ExceptionHandler(Exception.class)
+  public String onError(Exception e) {
+      logger.error("uncaught error", e);
+      return "error-view";
+  }`,
		refs: ['CWE-600', 'OWASP'],
		tags: ['exception-handling', 'information-disclosure', 'javaee'],
	},
	{
		id: 'CWE-603',
		name: 'Use of Client-Side Authentication',
		lang: 'node',
		status: 'Complete',
		what: `把身分驗證放在客戶端做。程式把驗證邏輯寫在瀏覽器端 JavaScript 或客戶端程式裡，伺服器端只依賴
		客戶端執行完後的回報或憑證結果。成因為為了「少一次來回」或誤信介面工作正常就代表通過驗證，而忽略客戶端
		程式碼完全受攻擊者控制的事實。後果是任何人只要修改客戶端——繞過程式裡的驗證判斷、直接呼叫 API——就等於
		繞過伺服器端身分驗證，存取本該受保護的功能與資料，屬身分信任層級的徹底失守。修法是所有身分驗證與授權判定
		一律放在伺服器端，客戶端只負責收集並傳遞憑證，伺服器每次都以憑證重新驗證並依權限決定可否執行。`,
		problem: `// 不安全寫法：驗證邏輯在用戶端，瀏覽器/呼叫端可自由跳過
function login() {
  if (password === 'secret') {       // 在瀏覽器裡比對 → 任何人都能改這行程式
    getClientSideTicket();            // 伺服器信任這個 tick
  }
}`,
		fixed: `// 安全寫法：驗證只在伺服器做，客戶端只送憑證、不回驗證結果
fetch('/api/login', {
  method: 'POST',
  body: JSON.stringify({ user, password })   // 由伺服器重新驗證身份
}).then(r => r.json()).then(r => sessionStore(r.serverSession));`,
		patch: `@@
-  function login() {
-    if (password === 'secret') { getClientSideTicket(); }
-  }
+  fetch('/api/login', { method: 'POST',
+    body: JSON.stringify({ user, password }) })
+    .then(r => r.json()).then(r => sessionStore(r.serverSession));`,
		refs: ['CWE-603', 'OWASP'],
		tags: ['client-side-auth', 'authentication', 'server-side'],
	},
	{
		id: 'CWE-605',
		name: 'Multiple Binds to the Same Port',
		lang: 'c',
		status: 'Complete',
		what: `同一個埠允許多個 socket 綁定。程式在開啟監聽 socket 時用了 SO_REUSEADDR（甚至 SO_REUSEPORT）等
		旗標，允許其他 socket 同時綁定同一個 port，沒有做排他占用。成因為想支援快速重啟或並行接受連線而放寬了綁定，
		卻忽略「誰先綁定誰就是該埠的擁有者」。後果是攻擊者可以先把自己的服務綁到原本要給正式服務的埠，正式服務
		綁不上去，或流量被引導到攻擊者控制的端點——即埠竊佔／偽冒，把該埠廉供的服務偷走或假冒。修法是對正式
		對外服務的埠關閉可重複綁定旗標、綁定採用排他（Windows 的 SO_EXCLUSIVEADDRUSE），並確保該埠不被低權限者預先
		占用。`,
		problem: `// 不安全寫法：SO_REUSEADDR 放行重複綁定，別人可先佔同一埠
int fd = socket(AF_INET, SOCK_STREAM, 0);
int one = 1;
setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
bind(fd, &addr, sizeof(addr));    // 攻擊者可先綁同一埠 → 竊佔`,
		fixed: `// 安全寫法：關掉可重複綁定旗標，確保該埠被本服務排他占用
int fd = socket(AF_INET, SOCK_STREAM, 0);
int zero = 0;
setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &zero, sizeof(zero));  // 排他
if (bind(fd, &addr, sizeof(addr)) != 0) { handle_occupied(); }`,
		patch: `@@
-  int one = 1;
-  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
+  int zero = 0;
+  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &zero, sizeof(zero));
   bind(fd, &addr, sizeof(addr));`,
		refs: ['CWE-605', 'OWASP'],
		tags: ['socket', 'port-hijack', 'bind'],
	},
	{
		id: 'CWE-607',
		name: 'Public Static Final Field References Mutable Object',
		lang: 'java',
		status: 'Complete',
		what: `public static final 欄位引用到可變物件。程式把 static final 欄位宣告成 public 或 protected，而它指
		向的卻是可變物件——陣列、List、Map、Set、StringBuilder 等。成因是誤以為 final 就代表「內容不會變」：其實
		final 只保證參考本身不能重新指派，被參考物件的內容仍然可以修改。後果是任何套件或外部程式碼都能直接改動這個
		全域常數所指物件的內容，破壞「這是一個常數」的假設、污染共享全域狀態，讓其他依賴它的類別建立錯誤假設而
		產生邏輯錯誤或資料污染。修法是改用不可變型別（String、Collections.unmodifiableX、List.of）、把欄位改 private
		經由只回讀複本的 getter 暴露，或用深拷貝隔離。`,
		problem: `// 不安全寫法：public static final 指向可變的 List，隨處可改內容
public static final List<String> ADMINS = new ArrayList<>();
ADMINS.add("alice");   // 別人也能 ADMINS.add(...) / clear() → 常數被污染`,
		fixed: `// 安全寫法：用包裝的不可變 List，或私有 + 唯讀 getter
private static final List<String> ADMINS = List.of("alice", "bob");
// List.of 本身已不可變，經由唯讀 getter 暴露，別處改不到內容
public static List<String> admins() { return ADMINS; }`,
		patch: `@@
-  public static final List<String> ADMINS = new ArrayList<>();
-  ADMINS.add("alice");
+  private static final List<String> ADMINS = List.of("alice", "bob");
+  public static List<String> admins() { return List.copyOf(ADMINS); }`,
		refs: ['CWE-607', 'SEI CERT'],
		tags: ['mutable-static', 'global-state', 'java'],
	},
	{
		id: 'CWE-608',
		name: 'Struts: Non-private Field in ActionForm Class',
		lang: 'java',
		status: 'Complete',
		what: `Struts ActionForm 的欄位沒宣告 private。ActionForm 是薄的資料傳輸 bean，若欄位被宣告成 package-private、
		protected 或 public，其它類別就能不經 setter／getter 直接讀寫。成因為偷懶公開欄位、讓框架自動反射填值，而省去
		封裝。後果是破壞資料隱蔽：別處程式可繞過 setter 的型別轉換與驗證邏輯直接改欄位，跳過清理與格式檢查，或把不該
		曝露的內部狀態洩漏出去，擴大被誤用與被污染的攻擊面。修法是把所有欄位宣告 private，一律透過 setter 賦值，並在
		setter 內做型別、長度與格式的驗證與消毒。`,
		problem: `// 不安全寫法：ActionForm 欄位沒 private，隨處可繞過驗證直接改
class LoginForm extends ActionForm {
    String username;      // package-private → 別處可直接寫，無驗證
    String password;
    boolean isAdmin;      // 攻擊者可直接改 true`,
		fixed: `// 安全寫法：欄位 private，寫入一律走 setter 驗證
class LoginForm extends ActionForm {
    private String username;
    private boolean isAdmin;
    public void setUsername(String u) {
        if (!validUsername(u)) throw new ValidationException();
        this.username = u;
    }
    public boolean getAdmin() { return isAdmin; }   // 不提供 setter，權限不可改`,
		patch: `@@
-  class LoginForm extends ActionForm {
-      String username;
-      String password;
-      boolean isAdmin;
+  class LoginForm extends ActionForm {
+      private String username;
+      private boolean isAdmin;
+      public void setUsername(String u) {
+          if (!validUsername(u)) throw new ValidationException();
+          this.username = u;
+      }
+      public boolean getAdmin() { return isAdmin; }`,
		refs: ['CWE-608', 'OWASP'],
		tags: ['struts', 'actionform', 'encapsulation'],
	},
	{
		id: 'CWE-609',
		name: 'Double-Checked Locking',
		lang: 'java',
		status: 'Complete',
		what: `Double-checked locking（雙重檢查鎖定）使用不當。程式想在取 lazy 單例時「先檢查、再上鎖、鎖內再檢查、
		才建構」，以避免每次取值都上鎖；但這個沒有正確發布（publication）的寫法在現行記憶體模型中不安全。因為沒有
		volatile／atomic 範圍同步，建構實例的寫操作可能被編譯器或處理器重排，別的執行緒會在物件建構完成之前就讀到
		「半初始化」的參考。成因為誤以為同步只需要在「第一次建立」那一刻，忽略記憶體可見性與重排。後果是併發下取到
		未完成建構的實例，使用未初始化的欄位，破壞單例的唯一性與狀態正確性。修法是讓該欄位宣告 volatile、改用
		初始化即建立的單例，或用 lazy holder（class 載入機制的載入順序）取代需要手動檢查的寫法。`,
		problem: `// 不安全寫法：無 volatile 的 double-checked locking，實例可能半建構被讀到
static Singleton instance;
static Singleton get() {
    if (instance == null) {              // 第一次檢查（未同步）
        synchronized (Singleton.class) {
            if (instance == null) {
                instance = new Singleton();  // 建構寫出可能被重排到賦值之後
            }
        }
    }
    return instance;                 // 另一執行緒可能讀到未完成的 instance
}`,
		fixed: `// 安全寫法：把欄位加 volatile，或乾脆改用初始化即建立/holder
static volatile Singleton instance;   // volatile 保證建構完成才可見
static Singleton get() {
    if (instance == null) {
        synchronized (Singleton.class) {
            if (instance == null) instance = new Singleton();
        }
    }
    return instance;
}`,
		patch: `@@
-  static Singleton instance;
+  static volatile Singleton instance;`,
		refs: ['CWE-609', 'OWASP'],
		tags: ['double-checked-locking', 'singleton', 'volatile', 'concurrency'],
	},
	{
		id: 'CWE-612',
		name: 'Improper Authorization of Index Containing Sensitive Information',
		lang: 'python',
		status: 'Complete',
		what: `對含敏感資訊的搜尋索引授權不當。系統把私人或機密文件——使用者個資、未發布資料、法律文書——索引进
		搜尋引擎（Elasticsearch ／Solr ／內建查詢表），卻沒有像限制原始文件一樣限制「誰能查這個索引」。成因為索引
		是另建的貯存，建置時只複製了文件內容而沒帶上原本的存取控制清單，搜尋 API 也只驗證「能登入」而不驗證「能看
		其中哪一筆」。後果是機密被未獲授權的人用搜尋查出來而外洩。修法是套用文件層級的 ACL：建立索引時保留權限，
		每次查詢逐筆過濾結果並附來源授權，並避免索引那些根本不該被搜尋的敏感欄位。`,
		problem: `# 不安全寫法：把未過濾的文件內容索引进來，查詢也不做逐筆授權
index_bulk([
    {"id": doc.id, "content": doc.body}      # 私人文件原文進索引
])
@app.route('/search')
def search():
    return elastic.search(q=request.args['q'], size=50)   # 誰都能查到任何私人文件`,
		fixed: `# 安全寫法：保留 ACL；查詢據目前使用者過濾可見文件
index_bulk([{"id": doc.id, "acl": doc.allowed, "content": idx(doc)}])
@app.route('/search')
def search():
    hits = elastic.search(q=request.args['q'], size=50)
    allowed = {doc.id for doc in acl_for(user)}
    return [h for h in hits if h.id in allowed]           # 逐筆授權過濾`,
		patch: `@@
-  index_bulk([{"id": doc.id, "content": doc.body}])
+  index_bulk([{"id": doc.id, "acl": doc.allowed, "content": idx(doc)}])
  @app.route('/search')
  def search():
-      return elastic.search(q=request.args['q'], size=50)
+      hits = elastic.search(q=request.args['q'], size=50)
+      allowed = {doc.id for doc in acl_for(user)}
+      return [h for h in hits if h.id in allowed]`,
		refs: ['CWE-612', 'OWASP'],
		tags: ['search-index', 'acl', 'authorization', 'information-disclosure'],
	},
	{
		id: 'CWE-614',
		name: "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
		lang: 'java',
		status: 'Complete',
		what: `HTTPS 工作階段的敏感 cookie 沒設 Secure。程式建立 session cookie 或驗證 cookie 時，沒有把它加上
		Secure 旗標，因此瀏覽器在可以同時對該 host 開 HTTP 的環境下，仍可能在明文通道上回送這個 cookie。成因為
		誤以為「我們主要在 HTTPS 沒差」而漏設，或伺服器沒統一在所有 Set-Cookie 加上 Secure。後果是若網站也提供 HTTP
		或發生降級，工作階段 cookie 就可能在明文傳輸中被中間人攔截，工作階段被竊取、身分被偽冒。修法是敏感 cookie
		一律加上 Secure（並用心肅 HttpOnly），讓瀏覽器只在安全連線下回送；同時可用 HSTS 逼迫維持 HTTPS。`,
		problem: `// 不安全寫法：session cookie 沒設 Secure，明文連線也可回送
Cookie c = new Cookie("session", token);
c.setHttpOnly(true);           // 但沒 setSecure(true)
response.addCookie(c);`,
		fixed: `// 安全寫法：加上 Secure（並留 HttpOnly），只允許經安全連線回送
Cookie c = new Cookie("session", token);
c.setSecure(true);             // ⦳只有 https 才回送
c.setHttpOnly(true);
response.addCookie(c);`,
		patch: `@@
  Cookie c = new Cookie("session", token);
  c.setHttpOnly(true);
+ c.setSecure(true);
  response.addCookie(c);`,
		refs: ['CWE-614', 'OWASP'],
		tags: ['cookie', 'secure-flag', 'session', 'transport'],
	},
	{
		id: 'CWE-616',
		name: 'Incomplete Identification of Uploaded File Variables (PHP)',
		lang: 'php',
		status: 'Complete',
		what: `PHP 用舊式作法判斷上傳檔變數而識別不完整。老程式用 $varname、$varname_size、$varname_name、
		$varname_type 這組以「檔名前置字首」展開的全域變數來判斷哪個檔案被上傳，而不是用超全域 $_FILES。成因為
		遵循舊文件（register_globals 時代）的寫法，把「變數存在」當成「確有上傳檔」。後果是這些變數是一般的變數，
		攻擊者可透過 query 或表單參數覆寫它們，讓程式誤以為某個（非真正上傳的、或攻擊者指定的）檔案是上傳檔而加以
		處理或移動，繞過驗證或讀寫未授權的檔案。修法是改用 $_FILES 超全域並依欄位名稱陣列索引取值，再用
		is_uploaded_file() 驗證、move_uploaded_file() 移動。`,
		problem: `<?php
// 不安全寫法：靠 $varname 等舊式全域變數辨識上傳檔，可被參數覆寫
if (isset($photo)) {
    move_uploaded_file($photo_tmp_name, 'up/' . $photo_name);  // 變數可被偽造
}`,
		fixed: `<?php
// 安全寫法：只用 $_FILES 超全域，且以 is_uploaded_file 驗證
if (isset($_FILES['photo']) && is_uploaded_file($_FILES['photo']['tmp_name'])) {
    move_uploaded_file($_FILES['photo']['tmp_name'], 'up/' . $_FILES['photo']['name']);
}`,
		patch: `@@
-  if (isset($photo)) { move_uploaded_file($photo_tmp_name, 'up/' . $photo_name); }
+  if (isset($_FILES['photo']) && is_uploaded_file($_FILES['photo']['tmp_name'])) {
+      move_uploaded_file($_FILES['photo']['tmp_name'], 'up/' . $_FILES['photo']['name']);
+  }`,
		refs: ['CWE-616', 'OWASP'],
		tags: ['php', 'file-upload', 'superglobal', 'variable-override'],
	},
	{
		id: 'CWE-618',
		name: 'Exposed Unsafe ActiveX Method',
		lang: 'javascript',
		status: 'Complete',
		what: `ActiveX 控制項暴露了危險方法。本該只用於瀏覽器內的 ActiveX 控制項，其 COM Automation 介面中把一些
		會越過瀏覽器安全模型（區域／網域信任邊界）的危險動作——任意檔案讀寫、操作登錄檔、啟動 shell——暴露成可從
		script 呼叫的方法。成因為為了功能便把這些方法設為對網頁腳本可呼叫（AllowForScripting 或介面反射未篩掉），
		未理解腳本本尊在瀏覽器中做不到的事不該對網頁開放。後果是網頁（尤其被 XSS）直接觸發本機端動作，變成本機
		任意程式碼執行或檔案破壞。修法是只對網頁暴露最小、安全的子集，危險方法不要透過 Automation 對腳本開放，
		並以嚴格的 zone／網域與白名單約束。`,
		problem: `// 不安全寫法：控制項把危險方法暴露給網頁腳本呼叫
var ctl = new ActiveXObject("Legacy.FileControl");
ctl.deleteFile("C:\\\\boot.ini");     // 任何網頁都能調用，越過瀏覽器區域模型的安全邊界`,
		fixed: `// 安全寫法：不透過 Automation 對網頁暴露危險方法，網頁只能調用安全子集
var box = new ActiveXObject("Legacy.FileViewer");   // 只暴露顯示文件的安全子集方法
box.openReadOnly(safePath);`,
		patch: `@@
-  var ctl = new ActiveXObject("Legacy.FileControl");
-  ctl.deleteFile("C:\\\\boot.ini");
+  var box = new ActiveXObject("Legacy.FileViewer");
+  box.openReadOnly(safePath);`,
		refs: ['CWE-618', 'MOZILLA'],
		tags: ['activex', 'com', 'code-execution', 'browser-security'],
	},
	{
		id: 'CWE-619',
		name: "Dangling Database Cursor ('Cursor Injection')",
		lang: 'python',
		status: 'Complete',
		what: `資料庫游標未正確關閉而「懸空」。程式開啟名為選取或預存程式的游標後，在部分路徑沒有關閉——拋例外、
		return 或提前分支時漏了 close，又沒用 finally 或 context manager——游標仍持著當時的連線與權限「掛」在那裡。
		成因是資源生命週期管理不當、錯誤路徑沒釋放。後果是這種沒被關的游標可能被同一資料庫的其他使用者或連線以
		原先賦予的權限繼續存取（dangling cursor），讓原本受限的資料被越權讀取，也持續佔用連線與伺服器資源，最終耗竭
		服務。修法是以 with／context manager 或 try–finally 結構保證游標與連線一旦用完必定關閉，並用最小權限的
		資料庫帳號進行查詢。`,
		problem: `# 不安全寫法：中途 return 沒帶 finally，游標一路開著沒關
def lookup(conn, rows):
    cur = conn.cursor()
    cur.execute("SELECT ... FROM accounts")
    for _ in range(rows):
        val = cur.fetchone()        # 萬一 fetch 中途有例外，cur 永不關
        if val is None: return []   # 這裡 return 直接漏掉 cur.close()
        ...
    return out`,
		fixed: `# 安全寫法：用 context manager 確保游標與連線必定釋放
def lookup(conn, rows):
    with conn.cursor() as cur:          # 離開區塊自動 close
        cur.execute("SELECT ... FROM accounts")
        return [normalize(r) for r in cur.fetchmany(rows)]`,
		patch: `@@
-  def lookup(conn, rows):
-      cur = conn.cursor()
-      cur.execute("SELECT ... FROM accounts")
-      for _ in range(rows):
-          val = cur.fetchone()
-          if val is None: return []
-          ...
-      return out
+  def lookup(conn, rows):
+      with conn.cursor() as cur:
+          cur.execute("SELECT ... FROM accounts")
+          return [normalize(r) for r in cur.fetchmany(rows)]`,
		refs: ['CWE-619', 'OWASP'],
		tags: ['database-cursor', 'resource-leak', 'lifetime'],
	},
	{
		id: 'CWE-620',
		name: 'Unverified Password Change',
		lang: 'python',
		status: 'Complete',
		what: `設定新密碼時沒先驗證身分。程式在允許使用者「變更密碼」時，不要求先證明自己知道原密碼或具備另一種
		認證因素；若重設流程又欠缺安全、綁定帳號的重設權杖機制，就等於任何能取得工作階段或觸發該流程的人都可隨意
		替受害者改密碼。成因為把「登入後一般改密」與「安全重設」混在一起，或重設 token 太弱、未綁定帳號且時效過長。
		後果是攻擊者把受害者的密碼改成自己知道的值，成功登出後便完全接管帳號。修法是變更密碼一律要求提供原密碼
		（或多因素），重設則用一次性、時效短、綁定帳號且為伺服器側亂數的權杖，並在變更後作廢舊 session。`,
		problem: `# 不安全寫法：改密碼不用原密碼或任何驗證，憑 session 就直接改
@app.post('/api/password')
def change_pwd():
    newp = request.form['new_password']
    update_user(session_user, bcrypt(newp))     # 不看原密碼/不需 MFA`,
		fixed: `# 安全寫法：先驗證原密碼（或第二因素）才准變更
@app.post('/api/password')
def change_pwd():
    if not check(old := request.form['password'], session_user):
        return 'forbidden', 403                 # 驗證不過就不給改
    newp = request.form['new_password']
    update_user(session_user, bcrypt(newp))`,
		patch: `@@
  @app.post('/api/password')
  def change_pwd():
-      newp = request.form['new_password']
+      if not check(request.form['password'], session_user):
+          return 'forbidden', 403
+      newp = request.form['new_password']
       update_user(session_user, bcrypt(newp))`,
		refs: ['CWE-620', 'OWASP'],
		tags: ['password-change', 'authentication', 'account-takeover'],
	},
	{
		id: 'CWE-621',
		name: 'Variable Extraction Error',
		lang: 'php',
		status: 'Complete',
		what: `變數抽取（extract）錯誤。程式用外部輸入決定要把資訊解包（unpack）進哪些變數名，例如直接對
		$_GET／$_POST 呼叫 extract()，卻沒有先驗證這些名稱都是合法可接受的。成因為為了「方便」把整個請求的鍵值直接
		當成變數建進當前符號表，忽略攻擊者可控制變數名。後果是攻擊者能用表單或 query 參數覆寫底層重要變數——登入旗標、
		資料庫連線、include 路徑、使用者的 role——使程式的判斷與分支被竄改，繞過驗證與邏輯。修法是絕不對未信任輸入
		做 extract()／動態變數，改為明確白名單——只從 $_GET／$_POST 中取出預期的鍵並逐一驗證型別與取值。`,
		problem: `<?php
// 不安全寫法：把整個 $_GET 解包成變數，使用者可指定變數名覆寫
extract($_GET);            // 送 is_admin=1 就把 $is_admin 覆蓋掉
if ($is_admin) { grant(); }`,
		fixed: `<?php
// 安全寫法：只讀白名單上的鍵，且絕不讓其覆寫內部旗標
$user = $_GET['user'] ?? '';
$id   = intval($_GET['id'] ?? 0);          // 只取出預期的鍵，逐個驗證
// 內部權限旗標不使用 extract，也不接受來自請求`,
		patch: `@@
-  extract($_GET);
-  if ($is_admin) { grant(); }
+  $user = $_GET['user'] ?? '';
+  $id   = intval($_GET['id'] ?? 0);`,
		refs: ['CWE-621', 'OWASP'],
		tags: ['extract', 'variable-override', 'php', 'logic-bypass'],
	},
	{
		id: 'CWE-622',
		name: 'Improper Validation of Function Hook Arguments',
		lang: 'c',
		status: 'Complete',
		what: `對「使用者可存取的 API 函式」掛鉤卻沒驗證引數。程式把自己的檢查或額外邏輯以 hook／wrapper 的方式包在
		使用者可以呼叫的 API 函式外面，但在進入 hook 時沒有先落實驗證這些引數。成因為假設「進到 hook 的引數已經被
		上游驗證」，實際上引數內容完全由呼叫端送出，可能含未預期的類型、長度或值。後果是這些未驗證的引數原樣流入
		內層受保護的 API，形成結果性弱點——越界、型別混淆、注入、錯誤的權限參數被套用。修法是在 hook 進來的入口對
		每個引數做完整且獨立的驗證（型別、範圍、格式、非空），不以上游假設取代自身確認。`,
		problem: `// 不安全寫法:hook 直接把未驗證的引數送進內層受保護 API
void on_file_access(const char *path, int mode) {
    real_fs_open(path, mode);   // path 可能越界/含 ..,mode可能是任意位元
}`,
		fixed: `// 安全寫法:進 hook 先驗證 path 與 mode,再送進內層
void on_file_access(const char *path, int mode) {
    if (!is_allowed_path(path)) return;      // 驗證路徑
    if ((mode & ~VALID_MODES) != 0) return;  // 驗證 flags
    real_fs_open(path, mode);
}`,
		patch: `@@
  void on_file_access(const char *path, int mode) {
-     real_fs_open(path, mode);
+     if (!is_allowed_path(path)) return;
+     if ((mode & ~VALID_MODES) != 0) return;
+     real_fs_open(path, mode);
  }`,
		refs: ['CWE-622', 'OWASP'],
		tags: ['api-hook', 'argument-validation', 'wrapper'],
	},
	{
		id: 'CWE-623',
		name: 'Unsafe ActiveX Control Marked Safe For Scripting',
		lang: 'javascript',
		status: 'Complete',
		what: `不安全的 ActiveX 控制項被標為「Safe for Scripting」。控制項本該只用於受限情境，卻在登錄或透過
		IObjectSafety 標記自己被聲明為「對網頁腳本安全」，於是任意網站都能經 script 呼叫它的方法。成因是註冊或
		升級控制項時置標錯誤——為了減少腳本警告直接標成安全，而沒逐一檢視每個方法是否真的安全。後果是原本只會由
		特定網域使用的功能，變成任何網頁瀏覽器編輯器頁面抓到就能觸發；若該控制項又含有本機操作方法，便可能造成本機
		影響或冒充合法網站動作。修法是不把控制項標為 Safe for Scripting，或使用像 IObjectSafety 明確僅對可信網域
		開放，並縮小暴露的方法集合。`,
		problem: `// 不安全寫法:控制項登錄成 Safe for Scripting,任何網站都能調用
// (IDL 把介面標成特異) 或呼叫 SetInterfaceSafetyOptions 對網頁全開
SetInterfaceSafetyOptions(iid, INTERFACESAFE_FOR_UNTRUSTED_CALLER, 0xff);  // 全部放行`,
		fixed: `// 安全寫法:不標 Safe for Scripting,只對可信網域/白名單開放
SetInterfaceSafetyOptions(iid, INTERFACESAFE_FOR_UNTRUSTED_CALLER, 0);  // 禁止網頁自由呼叫`,
		patch: `@@
-  SetInterfaceSafetyOptions(iid, INTERFACESAFE_FOR_UNTRUSTED_CALLER, 0xff);
+  SetInterfaceSafetyOptions(iid, INTERFACESAFE_FOR_UNTRUSTED_CALLER, 0);`,
		refs: ['CWE-623', 'OWASP'],
		tags: ['activex', 'safe-for-scripting', 'com'],
	},
	{
		id: 'CWE-624',
		name: 'Executable Regular Expression Error',
		lang: 'php',
		status: 'Complete',
		what: `可執行正規表示式錯誤。程式使用的 regex（正則）一方面組件中含使用者可控的輸入，另一方面又允許使用者
		透過修改齊某個「可執行」的旗標（例如舊 PCRE 的 /e 修飾）讓比對或取代過程執行程式碼。成因為把使用者輸入直接
		拼進 pattern，又開啟了會執行取代字串的旗標，或讓 pattern modifier 可被外部控制。後果是取代／比對的內容被當成
		程式碼執行，變成任意 PHP 程式碼執行（RCE）、命令注入那一類出來。修法是禁用 /e 這類可執行修飾旗標、不允許使用
		者控制 pattern 或旗標，改用安全的 preg_replace_callback 並完整驗證使用者輸入。`,
		problem: `<?php
// 不安全寫法:把使用者輸入併進 pattern,再用 /e 讓取代內容以程式執行
$pattern = '/^CMD:' . $_GET['cmd'] . '$/e';   // /e 把取代字串當 PHP 執行
$out = preg_replace($pattern, '', $input);    // 可執行組件含使用者輸入`,
		fixed: `<?php
// 安全寫法:不用 /e,改用回撥並驗證輸入;pattern 固定不可由使用者的建
$pattern = '/^CMD:(.+)$/';                    // 結構固定,資料由群組承接
$out = preg_replace_callback($pattern, function ($m) {
    return safe_transform($m[1]);             // 用回撥處理,不執行任意碼
}, $input);`,
		patch: `@@
-  $pattern = '/^CMD:' . $_GET['cmd'] . '$/e';
-  $out = preg_replace($pattern, '', $input);
+  $pattern = '/^CMD:(.+)$/';
+  $out = preg_replace_callback($pattern, function ($m) {
+      return safe_transform($m[1]);
+  }, $input);`,
		refs: ['CWE-624', 'OWASP'],
		tags: ['regex', 'code-execution', 'pcre', 'injection'],
	},
	{
		id: 'CWE-625',
		name: 'Permissive Regular Expression',
		lang: 'python',
		status: 'Complete',
		what: `過度寛鬆的正規表示式。程式用 regex 來驗證輸入，卻沒有把允許的字元集合縮得夠嚴——例如用 .*、
		漏掉開頭結尾錨點、或字元類別範圍畫得太寛——原本只要「數字與空白」的檢查放行了比預期寛得多的值。成因為簽規則
		以「至少一個任意字元」或未錨定的比對方式寫，未把驗證力道設計成精確的最小允許集。後果是原本用作白名單或輸入
		正規化關卡的 regex 放行本該被拒的輸入，配合下游的 DO scheduler（SQL、路徑、指令）時，就可能形成注入或被誤執行。
		修法是讓 regex 以 ^……$ 錨定，把字元集合列出來並限制長度，明確只接受預期的形式。`,
		problem: `# 不安全寫法:regex太寛:.任意字元+未錨定,放行任何內容
if re.search(r'[a-z]+', ident):        # 含中文/符號/空字串前後都算符合
    query = f"SELECT * FROM t WHERE k='{ident}'"   # 寬鬆放行 → 注入面`,
		fixed: `# 安全寫法:錨定路徑並框住允許集合與長度
ALLOWED = re.compile(r'^[A-Za-z0-9_]{1,32}$')    # 只接受字母數字底線、定長
if not ALLOWED.match(ident):
    return 400
query = "SELECT * FROM t WHERE k=%s"   # 配合參數化查詢更韌`,
		patch: `@@
-  if re.search(r'[a-z]+', ident):
-      query = f"SELECT * FROM t WHERE k='{ident}'"
+  if not re.match(r'^[A-Za-z0-9_]{1,32}$', ident):
+      return 400
+  query = "SELECT * FROM t WHERE k=%s"`,
		refs: ['CWE-625', 'OWASP'],
		tags: ['regex', 'whitelist', 'input-validation'],
	},
	{
		id: 'CWE-626',
		name: 'Null Byte Interaction Error (Poison Null Byte)',
		lang: 'c',
		status: 'Complete',
		what: `空字元（null byte）交互錯誤。程式把含內嵌 \\0 的資料在不同「表示」之間傳遞——例如一個帶長度的字串
		或緩衝被轉交給一個以 NUL 結尾的 C 字串介面——時沒有一致地處理。C 字串函式（strlen、strcmp、fopen、exec 等）
		會在遇到 \\0 就停止，因此「長度表示」認得的較長內容與「C 字串表示」看到的截斷內容不同。成因是語言的帶長度
		字串語意與 C 的 null-terminate 語意混用不一致，又未在邊界前檢查 null byte。後果是比對／驗證看到的是 \\0 之前
		的部份而放行，實際系統呼叫卻處理 \\0 之後（攻擊者控制）的內容，形成 poison null byte 的過濾繞過。修法是
		在進入 C 介面前明確拒絕含 null byte 的輸入、統一以長度判別，並驗證。`,
		problem: `// 不安全寫法:把可能含內嵌 \\0 的輸入誤當純字串交給檔案開啟
size_t n;
char input[MAX];                // 內容可能是 "safe.php\0../../../etc/passwd"
read(fd, input, &n);
strncpy(path, input, n); path[n] = '\\0';
open(path, O_RDONLY);          // fopen 在 \\0 停住 → 處理的其實是後段路徑`,
		fixed: `// 安全寫法:先檢查並拒絕含 null byte 的輸入
read(fd, input, &n);
if (memchr(input, '\\0', n)) { reject(); }   // 有 null byte 直接拒絕
input[n] = '\\0';
open(input, O_RDONLY);`,
		patch: `@@
  read(fd, input, &n);
+ if (memchr(input, '\\0', n)) { reject(); }
  input[n] = '\\0';
  open(input, O_RDONLY);`,
		refs: ['CWE-626', 'SEI CERT'],
		tags: ['null-byte', 'poison-null', 'path-traversal', 'c-string'],
	},
	{
		id: 'CWE-627',
		name: 'Dynamic Variable Evaluation',
		lang: 'node',
		status: 'Complete',
		what: `動態變數求值。程式所處的語言允許使用者影響執行期的變數名（或函式名）並據此動態讀寫——例如 JS 用
		全域物件鍵、eval；PHP 用 $$var；Python 用 globals()／locals()／eval；Ruby 用 instance_variable_set。成因為直接用
		使用者輸入做「可變名稱」索引進全域符號表或執行期求值，沒有把名稱控在受控的白名單。後果是攻擊者可以讀寫任意
		變數——覆寫組態、登入旗標、密鑰——甚至呼叫任意函式，變成任意程式碼執行（RCE）。修法是絕不把使用者輸入當
		變數名求值：改用預先定義欄位的 map／陣列鍵存取、以白名單逐一檢查名稱，或改用資料結構存放而不動用動態求值。`,
		problem: `// 不安全寫法:用使用者輸入當全域物件鍵,可讀寫/觸發任意屬性
function mutateConfig(key, value) {
  globalThis[key] = value;      // 使用者傳 process.nextTick 函式名可呼叫/覆寫
}
// 或 eval('config.' + userKey) 這種動態求值更是 RCE`,
		fixed: `// 安全寫法:只允許白名單鍵,用資料結構而非動態名稱
const ALLOWED = new Set(['theme', 'locale', 'timezone']);
function mutateConfig(key, value) {
  if (!ALLOWED.has(key)) throw new Error('forbidden key');
  config[key] = value;          // 永不把輸入當變數名或 eval`,
		patch: `@@
-  function mutateConfig(key, value) {
-    globalThis[key] = value;
+  const ALLOWED = new Set(['theme', 'locale', 'timezone']);
+  function mutateConfig(key, value) {
+    if (!ALLOWED.has(key)) throw new Error('forbidden key');
+    config[key] = value;
   }`,
		refs: ['CWE-627', 'OWASP'],
		tags: ['dynamic-eval', 'variable-injection', 'rce', 'code-execution'],
	},
	{
		id: 'CWE-641',
		name: 'Improper Restriction of Names for Files and Other Resources',
		lang: 'go',
		status: 'Complete',
		what: `對檔案／資源名稱的命名未加限制。程式用上游元件來的輸入（URL、表單欄位、參數）拼出檔案名稱或資源
		路徑，卻沒有把結果名限制在合理範圍。成因為直接以使用者可控的輸入組 path，沒拒絕 ../、空字元、斜線或特殊字元的
		檔名。後果是路徑穿越：../ 可把寫入或讀取帶出 web 根目錄，讀到敏感檔、覆蓋重要檔案、或把內容寫到任意位置；
		配合寫入也可能形成遠端檔案寫入與後續執行。修法是採用 allow 清單允許的字元集與型別、拒絕 / 與 ..、取獨立
		basename、統一以 filepath.Base／Clean 正規化，並僅存放在受控目錄內。`,
		problem: `// 不安全寫法:直接用使用者輸入組路徑,可 ../ 逃出目錄
name := r.URL.Query().Get("file")
data, err := os.ReadFile(filepath.Join(storageDir, name))   // name=../../etc/passwd`,
		fixed: `// 安全寫法:只取 basename+白名單字元,檔名落在受控目錄頂層
name := r.URL.Query().Get("file")
name = filepath.Base(name)                       // 剝掉所有目錄成份(.. 也去)
if !validNameRe.MatchString(name) { return 400 }
data, err := os.ReadFile(filepath.Join(storageDir, name))`,
		patch: `@@
   name := r.URL.Query().Get("file")
+  name = filepath.Base(name)
+  if !validNameRe.MatchString(name) { return 400 }
   data, err := os.ReadFile(filepath.Join(storageDir, name))`,
		refs: ['CWE-641', 'CWE-22'],
		tags: ['path-traversal', 'filename', 'input-validation'],
	},
	{
		id: 'CWE-643',
		name: "Improper Neutralization of Data within XPath Expressions ('XPath Injection')",
		lang: 'java',
		status: 'Complete',
		what: `XPath 注入。程式用外部輸入動態組出一段 XPath 運算式，用來從 XML 資料庫取值，卻沒有對輸入做中性化或
		轉義。成因為直接把使用者輸入以字串串進 XPath 述句，沒有把「查詢結構」與「資料」分開。後果是攻擊者可控制查詢
		結構本身——例如輸入 ' or '1'='1 讓條件恆真，或利用 ． 與述句延伸，把整個 XML 文件中原本不該給它的節點都讀
		出來，繞過驗證與授權判斷。修法是使用參數化／變數綁定的 XPath API，將輸入當成變數值而非拼進述句，並對輸入做
		型別與格式驗證。`,
		problem: `// 不安全寫法:把使用者輸入拼進 XPath 字串
XPath xp = XPathFactory.newInstance().newXPath();
String user = req.getParameter("user");
String x = "//user[name='" + user + "']/password/text()";   // ' or '1'='1 繞過`,
		fixed: `// 安全寫法:用 XPath 變數綁定,資料與結構分離
XPath xp = XPathFactory.newInstance().newXPath();
xp.setXPathVariableResolver(v -> { if ("u".equals(v.getLocalName())) return req.getParameter("user"); return null; });
String x = "//user[name=$u]/password/text()";      // 輸入是變數,不會改變結構`,
		patch: `@@
-  String x = "//user[name='" + xp + "']/password/text()";
+  xp.setXPathVariableResolver(v -> "u".equals(v.getLocalName())
+      ? req.getParameter("user") : null);
+  String x = "//user[name=$u]/password/text()";`,
		refs: ['CWE-643', 'OWASP'],
		tags: ['xpath', 'injection', 'xml', 'parameterization'],
	},
	{
		id: 'CWE-644',
		name: 'Improper Neutralization of HTTP Headers for Scripting Syntax',
		lang: 'node',
		status: 'Complete',
		what: `HTTP 回應標頭中的腳本語法沒有中性化。程式把使用者輸入原樣放進回應標頭（自訂 header、Set-Cookie、
		Location、echo 用的 header），而某些可解析原始標頭的瀏覽器組件（如舊版 Flash、ActiveX）會把標頭內容當成腳本
		或指令來處理。成因為直接把反射的輸入塞進標頭，沒先驗證與轉義，也未留意會解析標頭的下游組件。後果是 header
		injection／response splitting（塞入 CRLF 造假標頭），或反射型 script 在能解析標頭的組件中被執行，形成跨站腳本
		等攻擊。修法是不把未驗證的輸入放進任何回應標頭，需要反射時先對 CR／LF 與標頭值做驗證並編碼轉義。`,
		problem: `// 不安全寫法:把使用者輸入直接塞進回應標頭,可注入 CRLF/腳本
app.get('/file', (req, res) => {
  res.setHeader('X-Filename', req.query.name);   // name 含 \\r\\n 可造 header/腳本
  res.send(data);
});`,
		fixed: `// 安全寫法:標頭值先清洗,拒絕 CR/LF,並白名單格式
const clean = String(req.query.name || '').replace(/[\\r\\n]/g, '');
if (!/^[\\w.-]{1,64}$/.test(clean)) return res.status(400).end();
res.setHeader('X-Filename', clean);
res.send(data);`,
		patch: `@@
   app.get('/file', (req, res) => {
-    res.setHeader('X-Filename', req.query.name);
+    const clean = String(req.query.name || '').replace(/[\\r\\n]/g, '');
+    if (!/^[\\w.-]{1,64}$/.test(clean)) return res.status(400).end();
+    res.setHeader('X-Filename', clean);
     res.send(data);
   });`,
		refs: ['CWE-644', 'OWASP'],
		tags: ['http-header', 'response-splitting', 'header-injection'],
	},
	{
		id: 'CWE-645',
		name: 'Overly Restrictive Account Lockout Mechanism',
		lang: 'python',
		status: 'Complete',
		what: `帳戶鎖定機制過度嚴格。為了防暴力破解設了「連續失敗 N 次就鎖定帳號」，但門檻設太低、鎖定時間太長、
		又把整份帳號跨來源鎖住，或機制反向加料（任意來源失敗都累計到帳號上）。成因為誤把「來源 IP／工作階段」跟「帳號
		全域」當成同一個鎖定單位，又沒做速率限制式的漸進延遲。後果是攻擊者可刻意用一批錯誤嘗試把受害者的帳號鎖死，
		是蓄意的帳號級拒絕服務（DoS）：合法的使用者進不去，系統反而幫攻擊者造成可用性喪失。修法是鎖定「來源 IP／用戶端
		手指紋」而不是整個帳號、採用漸進延遲與速率限制、加入 captcha 或二次驗證，並設定合理的失敗上限與鎖定時間。`,
		problem: `# 不安全寫法:任何來源錯 3 次就把整個帳號鎖 24 小時,可被蓄意鎖死
if login_fails[user] >= 3:
    lock_account(user, hours=24)        # 攻擊者每個帳號試錯 3 次就全部被鎖`,
		fixed: `# 安全寫法:鎖來源 IP/裝置並採漸進延遲,不鎖整個帳號
fails = fail_policy.fails_for(ip)       # 依來源統計
delay = min(2 ** fails, 300)           # 漸進延遲,不實鎖
sleep(delay / 10)
rate_limit_for(ip)                      # 單純針對來源做速率限制`,
		patch: `@@
-  if login_fails[user] >= 3:
-      lock_account(user, hours=24)
+  fails = fail_policy.fails_for(ip)
+  delay = min(2 ** fails, 300)
+  sleep(delay / 10)
+  rate_limit_for(ip)`,
		refs: ['CWE-645', 'OWASP'],
		tags: ['account-lockout', 'denial-of-service', 'rate-limiting'],
	},
	{
		id: 'CWE-646',
		name: 'Reliance on File Name or Extension of Externally-Supplied File',
		lang: 'php',
		status: 'Complete',
		what: `依賴外部檔案的檔名或副檔名來決定行為。程式允許檔案上傳後，僅憑檔名或副檔名來判斷它該如何被處理、
		存放在哪、或要不要執行，而沒有驗證內容本身的真實型別。成因為把「使用者可控制的檔名／副檔名」當成可信的型別
		標記，未對檔案內容做偵測。後果是攻擊者上傳一個帶 .php／.jsp 等可執行副檔名、內容實為 shell 的檔案，若它落入
		web 根目錄並被當腳本執行就成了 RCE；反之副檔名不符也可能被誤分類或誤觸發處理。修法是以內容（magic bytes／
		finfo）偵測真實 MIME 而非副檔名，用伺服器產生的隨機檔名，並存放到 web 根目錄之外、確保不被當可執行路徑。`,
		problem: `<?php
// 不安全寫法:只看副檔名決定處理,filename 來自使用者
$ext = strtolower(pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION));
if (in_array($ext, ['jpg', 'png'])) {
    move_uploaded_file($_FILES['f']['tmp_name'], 'uploads/' . $_FILES['f']['name']);   // .php 可改名混入
}`,
		fixed: `<?php
// 安全寫法:以內容偵測 MIME,伺服器產隨機檔名存 web 根之外
$mime = mime_content_type($_FILES['f']['tmp_name']);
if (!in_array($mime, ['image/jpeg', 'image/png'])) die('reject');
$name = bin2hex(random_bytes(16)) . '.img';
move_uploaded_file($_FILES['f']['tmp_name'], '/srv/uploads/' . $name);   // web 根之外`,
		patch: `@@
-  $ext = strtolower(pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION));
-  if (in_array($ext, ['jpg', 'png'])) {
-      move_uploaded_file($_FILES['f']['tmp_name'], 'uploads/' . $_FILES['f']['name']);
-  }
+  $mime = mime_content_type($_FILES['f']['tmp_name']);
+  if (!in_array($mime, ['image/jpeg', 'image/png'])) die('reject');
+  $name = bin2hex(random_bytes(16)) . '.img';
+  move_uploaded_file($_FILES['f']['tmp_name'], '/srv/uploads/' . $name);`,
		refs: ['CWE-646', 'CWE-434'],
		tags: ['file-upload', 'extension', 'mime', 'rce'],
	},
	{
		id: 'CWE-647',
		name: 'Use of Non-Canonical URL Paths for Authorization Decisions',
		lang: 'java',
		status: 'Complete',
		what: `用非正規化（non-canonical）的 URL 路徑做授權決定。程式以「URL 是正規的」為前提來劃分授權命名空間：
		授權層比對時看的是某種正規化後的路徑，後端的路由／處理卻用另一份（未正規化或重複解碼）的字串。成因為路徑
		正規化不足——過濾器先 decode 一次，處理器又 decode 一次，或沒先統一處理 ..、重複 //、%2e 編碼。後果是攻擊者可
		用非正規路徑（%2e%2e、//content、/secret/../public 等）讓授權檢查看到 A、實際處理到 B，繞過存取控制。修法是在
		授權決定前先完成一次正規化，並用這同一份正規化後的路徑來做授權與路由（單一解碼點、單一 normalizer）。`,
		problem: `// 不安全寫法:授權看 decode 後的結果,路由卻用原始路徑 → 兩邊路徑不一致
String raw = req.getRequestURI();
if (!raw.startsWith("/admin")) { allow(); }        // 攻 clever: /%61dmin 或其他編碼繞過前綴檢查
service.dispatch(raw);                             // 路由又用原始路徑`,
		fixed: `// 安全寫法:先一次正規化,授權與路由都用同一份路徑
String canonical = new URI(req.getRequestURI()).normalize().getPath();
if (!isAdminPath(canonical) && !auth.hasRight(user, canonical)) { deny(); }
service.dispatch(canonical);   // 檢查與路由共用同一份正規化路徑`,
		patch: `@@
-  String raw = req.getRequestURI();
-  if (!raw.startsWith("/admin")) { allow(); }
-  service.dispatch(raw);
+  String canonical = new URI(req.getRequestURI()).normalize().getPath();
+  if (!isAdminPath(canonical) && !auth.hasRight(user, canonical)) { deny(); }
+  service.dispatch(canonical);`,
		refs: ['CWE-647', 'OWASP'],
		tags: ['canonicalization', 'url-path', 'authorization-bypass'],
	},
	{
		id: 'CWE-648',
		name: 'Incorrect Use of Privileged APIs',
		lang: 'python',
		status: 'Complete',
		what: `特權 API 的使用不正確。程式呼叫需要額外權限的 function／呼叫，卻不合該 API 對呼叫方式的要求——例如該
		在提權前做身分與完整性確認、該帶特定參數與權限位元、該以專用帳號執行．而程式簡化或錯誤地呼叫。成因為沒有遵
		照特權 API 的契約（先驗證、先降權、參數正確），或不了解該介面的權限模型。後果是攻擊者可藉錯誤呼叫順序、缺失的
		檢查或錯誤的權限旗標，讓系統在比預期更高的權限下執行動作，甚至提升權限或任意碼執行。修法是嚴格依 API 宣告的
		需求呼叫：呼叫前驗證身分與輸入、採最小權限、正確帶權限參數、檢查並處理每個回傳，避免以提升後的權限做非必要
		的操作。`,
		problem: `# 不安全寫法:無驗證就呼叫特權 API 並忽略回傳/setuid 執行
os.setuid(0)                     # 粗暴升到 root
run_with_root(req.data)           # req.data 未驗證,且未檢查回傳,直接以 root 執行
if result_signals == None: pass   # 檢查形同虛設`,
		fixed: `# 安全寫法:先驗證資料/身分,採最小權限,檢查回傳
check_privilege(user, required_role)
if not valid_payload(req.data): return deny
os.setuid(PRIVILEGED_GUARD)      # 專用、最小權限帳號
rc = run_safe(req.data,inspect=True)
if rc.failed: log_and_fail(rc.code)   # 仔細處理回傳與權限`,
		patch: `@@
-  os.setuid(0)
-  run_with_root(req.data)
+  check_privilege(user, required_role)
+  if not valid_payload(req.data): return deny
+  os.setuid(PRIVILEGED_GUARD)
+  rc = run_safe(req.data, inspect=True)
+  if rc.failed: log_and_fail(rc.code)`,
		refs: ['CWE-648', 'SEI CERT'],
		tags: ['privileged-api', 'privilege-escalation', 'least-privilege'],
	},
	{
		id: 'CWE-649',
		name: 'Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking',
		lang: 'php',
		status: 'Complete',
		what: `只用混淆或加密保護安全相關輸入，卻沒有完整性檢查。程式把某些「不該被外部改動」的輸入——用戶端的角色、
		權限、價格、session 內容——用 base64、簡易自製混淆或可逆加密包起來，就假設它安全可靠。成因為誤把「看不懂」
		當成「改不了」：混淆與可逆加密都不保證輸入未被篡改。後果是攻擊者只要解出格式、把自己想要的角色（user→admin）、
		價格、授權旗標改掉再包回去，伺服器並無從偵測，直接以此受竄改的輸入做授權或計價決策。修法是為每個此類輸入
		加 HMAC／MAC 簽章（金鑰只在伺服器），或乾脆把決策狀態存在伺服器端 session，不交給用戶端攜帶，並對影響授權的
		每個欄位驗證完整性與來源。`,
		problem: `<?php
// 不安全寫法:只用 base64/可逆密碼包住權限欄位,沒有任何簽章
$role = base64_encode(serialize(['user' => 'alice', 'role' => 'user']));
setcookie('ticket', $role);          // 對手解開竄改 role=admin 再包回,伺服器無從發現`,
		fixed: `<?php
// 安全寫法:加伺服器端 HMAC 簽章驗證完整性,金鑰不落地
$secret = get_server_key();
$data = json_encode(['user'=>'alice','role'=>'user']);
$mac  = hash_hmac('sha256', $data, $secret);
setcookie('ticket', base64_encode($data . '.' . $mac));   // 驗證時先查 MAC`,
		patch: `@@
-  $role = base64_encode(serialize(['user' => 'alice', 'role' => 'user']));
-  setcookie('ticket', $role);
+  $data = json_encode(['user'=>'alice','role'=>'user']);
+  $mac  = hash_hmac('sha256', $data, get_server_key());
+  setcookie('ticket', base64_encode($data . '.' . $mac));`,
		refs: ['CWE-649', 'OWASP'],
		tags: ['integrity', 'hmac', 'client-side-state', 'tampering'],
	},
	{
		id: 'CWE-650',
		name: 'Trusting HTTP Permission Methods on the Server Side',
		lang: 'node',
		status: 'Complete',
		what: `伺服器端信任「HTTP 方法」的語意來做許可控管。程式的防護假設「用 GET 造訪的 URI 不會改狀態」，於是把
		存取控制只套在 POST／DELETE 等，以為 GET 是唯讀而放行。成因為把 method 名稱當成「會不會改狀態」的可靠判別，
		而實務上許多應用仍把會造成狀態變更的動作放在 GET 的 query 參數裡觸發。後果是攻擊者用 GET 帶參數即可執行同樣
		會改資源的動作，繞過只鎖非 GET 方法的防護，進行資源修改或刪除攻擊。修法是不要信任方法語意的字面，對每個會改
		狀態的動作都做一致的授權與 CSRF 保護，且統一改用 POST 這類不該有副作用的語意來實際變更狀態。`,
		problem: `// 不安全寫法:只鎖非 GET,以為 GET 不會改狀態 → 繞過
app.use((req, res, next) => {
  if (req.method !== 'GET') { authorize(req); }   // GET 直接放行
  next();
});
// GET /api/delete?id=5 便能用 query 觸發刪除而不被檢查`,
		fixed: `// 安全寫法:不依 method 判斷,所有影響狀態的動作都一致授權+CSRF
app.delete('/api/delete/:id', (req, res) => {
  authorize(req);                       // 一律授權,不分 method
  if (!validCsrf(req)) return res.status(403).end();
  removeResource(req.params.id);
});`,
		patch: `@@
-  app.use((req, res, next) => {
-    if (req.method !== 'GET') { authorize(req); }
-    next();
-  });
+  app.delete('/api/delete/:id', (req, res) => {
+    authorize(req);
+    if (!validCsrf(req)) return res.status(403).end();
+    removeResource(req.params.id);
+  });`,
		refs: ['CWE-650', 'OWASP'],
		tags: ['http-method', 'authorization-bypass', 'state-change'],
	},
	{
		id: 'CWE-651',
		name: 'Exposure of WSDL File Containing Sensitive Information',
		lang: 'python',
		status: 'Complete',
		what: `暴露載有敏感資訊的 WSDL 檔。Web 服務架構常需要把一份 WSDL 對外公開，用來描述有哪些公開可呼叫的服務、
		呼叫方該怎麼呼叫它們——期望哪些參數、回傳什麼型別。成因為為了自動化整合把完整 WSDL 直接放到可公開讀取的
		位置，或讓所有未驗證的請求都能取到它。後果是 WSDL 把可用的端點、方法簽章、參數與資料型別全部揭示出來，
		大幅降低攻擊者探測與建構攻擊的成本，也助長未保護方法被枚舉與濫用。修法是僅對已授權的消費端公開必要的最小
		介面描述，移除過多的內部分析與執行項目，並以網路隔離或檔案層級的存取控管限制 WSDL 的可讀性。`,
		problem: `# 不安全寫法:把含所有端點/型別的 WSDL 原樣公開且不需授權
@app.get('/service?wsdl')
def wsdl():
    return full_wsdl              # 含全部方法、參數與內部名稱`,
		fixed: `# 安全寫法:僅授權消費端可取得最小介面描述
@app.get('/service?wsdl')
def wsdl():
    if not client.is_partner(request): return 403
    return minimal_wsdl           # 只含必要方法與公開型別`,
		patch: `@@
  @app.get('/service?wsdl')
  def wsdl():
-      return full_wsdl
+      if not client.is_partner(request): return 403
+      return minimal_wsdl`,
		refs: ['CWE-651', 'OWASP'],
		tags: ['wsdl', 'web-service', 'information-disclosure'],
	},
	{
		id: 'CWE-652',
		name: "Improper Neutralization of Data within XQuery Expressions ('XQuery Injection')",
		lang: 'python',
		status: 'Complete',
		what: `XQuery 注入。程式用外部輸入動態組出 XQuery 運算式，用來從 XML 資料庫取值，卻沒對輸入做中性化或轉義。
		成因為把使用者輸入直接字串串進 XQuery 述句，未將查詢結構與資料分離、未採用參數綁定。後果是攻擊者能控制 XQuery
		的結構——塞入 ' or 恒真條件、或延伸 for／if 述句——把整份 XML 文件中不該被讀的節點撈出，繞過驗證與授權邏輯，
		也可做邏輯誤判。修法是使用支援變數／參數繫結（解析變欄）的 XQuery API，把輸入當變數值而不拼進述句，並驗證其型別
		與格式。`,
		problem: `# 不安全寫法:把輸入拼進 XQuery 字串
q = doc.xquery("for $u in //users where $u/name='" + user + \
              "' return $u/password")    # ' 結尾或 or 注入改結構`,
		fixed: `# 安全寫法:用變數綁定,輸入是值而非述句結構
query = doc.prepare("for $u in //users where $u/name=$name return $u/password")
query.bind("name", user)                 # 輸入只當變數值,不影響 XQuery 結構`,
		patch: `@@
-  q = doc.xquery("for $u in //users where $u/name='" + user + "' return $u/password")
+  query = doc.prepare("for $u in //users where $u/name=$name return $u/password")
+  query.bind("name", user)`,
		refs: ['CWE-652', 'OWASP'],
		tags: ['xquery', 'injection', 'xml', 'parameterization'],
	},
	{
		id: 'CWE-654',
		name: 'Reliance on a Single Factor in a Security Decision',
		lang: 'python',
		status: 'Complete',
		what: `安全決定只靠單一因素。防護機制僅憑「單一條件」或「單一物件／實體的真確性」就決定是否授權存取受保護的
		資源或功能，例如只查一組 SQL 條件、只信單一 token、只憑來源 IP、只比一顆密碼。成因為把複雜的授權決策壓縮成
		一個片面檢查，寄望那唯一因素不會被竊取或偽造。後果是只要那一個因素被盜、被猜到或被重放就整個放行，缺乏深度
		防禦，風險全部集中在單點，資料或功能被未授權入侵。修法是對高風險決定要求多因素——知道（密碼／PIN）、持有（裝置／
		OTP）、生理（生物特徵），或加上來源、時點與行為異常等第二層條件一起評估，並做異常偵測。`,
		problem: `# 不安全寫法:只憑單一條件就授權高風險操作
def authorize(req):
    if req['token'] == trusted_token:      # 只有一個因素,被偷/重放即通過
        return True
    return False`,
		fixed: `# 安全寫法:高風險決定要求多因素/多條件,並納入異常偵測
def authorize(req):
    ok_know = verify_possession(req['otp'], user.device)
    ok_hold = verify_biometric(req['face'], user)      # 知識+持有+生理
    ok_src  = source_is_expected(req)                  # 加上來源/行為異常判斷
    return ok_know and ok_hold and ok_src and not anomaly_detected(req)`,
		patch: `@@
  def authorize(req):
-      if req['token'] == trusted_token:
-          return True
-      return False
+      ok_know = verify_possession(req['otp'], user.device)
+      ok_hold = verify_biometric(req['face'], user)
+      ok_src  = source_is_expected(req)
+      return ok_know and ok_hold and ok_src and not anomaly_detected(req)`,
		refs: ['CWE-654', 'OWASP'],
		tags: ['multi-factor', 'authorization', 'single-factor'],
	},
	{
		id: 'CWE-683',
		name: 'Function Call With Incorrect Order of Arguments',
		lang: 'c',
		status: 'Complete',
		what: `呼叫函式時引數順序錯誤。呼叫端把某個函式的引數以不正確的順序傳入——把記憶體複製來源與目的地對調、
		把長度與指標對調、或把名字近似型別相同的參數互換。成因為函式簽名的參數型別相近（都是指標、都是整數），開發圖快
		想不起順序就套用想當然。後果是函式對「錯位」的參數作業，例如 memcpy(dst, src, n) 寫成 memcpy(src, dst, n)，
		會把來源與目的地覆寫、長度解讀成錯誤上限，造成緩衝區溢位、內容破壞或未定義行為。修法是使用具名／帶意函式、
		查對宣告順序，落實型別與範圍檢查，並以單元測試驗證呼叫的結果。`,
		problem: `// 不安全寫法:引數順序對調 → 長度上限被誤用/緩衝溢位
// memcpy 簽名是 memcpy(dest, src, n)
char buf[8];
memcpy(buf, buf + 2, 6);            // 想把內容前移,卻把 src/dst 概念錯位,且 n 誤用成 buf 大小
char src[4] = "ABC";
memcpy(src, buf, sizeof(src));       // 想複製的一段長度,卻把 n 解讀成完整緩衝 → 溢位`,
		fixed: `// 安全寫法:依宣告順序傳(dest, src, n)並核對長度
memcpy(buf, src, sizeof(buf));        // 長度是目標緩衝上限,確認不超過
// 或改用 strncpy_s/snprintf 等附帶 size 的函式降低誤用機率`,
		patch: `@@
-  memcpy(buf, src, sizeof(buf));
+  memcpy(buf, src, n);               // n 是真正要複製的長度(受目標 buffer 容量限制)
+  if (sizeof(dst) < n) reject();`,
		refs: ['CWE-683', 'SEI CERT'],
		tags: ['argument-order', 'function-call', 'buffer-overflow'],
	},
	{
		id: 'CWE-685',
		name: 'Function Call With Incorrect Number of Arguments',
		lang: 'c',
		status: 'Complete',
		what: `呼叫函式時引數個數錯誤。呼叫端在呼叫某個函式時傳了太多或少於宣告的引數。在 C 這類未做強制原型檢查或
		使用可變參數的場合，多或少一個引數不會在編譯期被攔下。成因為誤用可變參數函式（printf 家族）時格式與實際引數
		對不起來、或 prototype 疏漏、以不合符約的呼叫方式呼叫函式。後果是少了引數時被讀到未初始化或無關的堆疊內容、
		多了引數則破壞呼叫慣例（ABI）謬誤，整體造成未定義行為與結果性弱點——資訊外洩、崩潰或繞過邏輯。修法是嚴格對照
		函式宣告提供正確數目與型別的引數，開啟編譯器原型檢查與警告，避免把不確切的個數依賴在可變參數上。`,
		problem: `// 不安全寫法:可變參數的個數與型別錯,少讀/多讀堆疊內容
printf("User: %s age: %d\\n", name);            // 少給一個 %d 的引數 → 讀 stack garbage
char *s = myapi(a, b);                          // 但 myapi 其實需要三個參數`,
		fixed: `// 安全寫法:格式與引數數目一對一
printf("User: %s age: %d\\n", name, age);       // %d 有對應引數
char *s = myapi(a, b, flags);                   // 依宣告給足三個參數`,
		patch: `@@
-  printf("User: %s age: %d\\n", name);
+  printf("User: %s age: %d\\n", name, age);
  ...
-  char *s = myapi(a, b);
+  char *s = myapi(a, b, flags);`,
		refs: ['CWE-685', 'SEI CERT'],
		tags: ['argument-count', 'format-string', 'undefined-behavior'],
	},
	{
		id: 'CWE-687',
		name: 'Function Call With Incorrectly Specified Argument Value',
		lang: 'c',
		status: 'Complete',
		what: `呼叫函式時指定了錯誤的引數值。呼叫端呼叫某函式時，雖然順序與個數都對，卻傳入了「內容錯誤」的值——錯的
		布林旗標、錯的列舉、錯的權限位元、錯的偏移量。成因為邏輯疏忽或把不易記住的旗標／權限值寫錯，或把字面常數
		用得想當然。後果是函式在錯誤的安全參數下運行，例如把關掉安全選項的旗標設成開、把寫入權限套到不該開放的檔案、
		把大小寫旗標弄顛倒；結果是檔案權限錯誤、安全檢查被關閉或過度授權，形成可見的結果性弱點。修法是使用具名常數與
		正確型別、加分關鍵盤註明、以 enum／bitmask 型別強制合法值，並經 code review 與測試驗證旗標效果。`,
		problem: `// 不安全寫法:旗標/權限值寫錯,反而關掉安全性或放得太寬
chmod(path, 0222);                 // 想要並表全域可寫?其實該 0644,誤給全域可寫可讀it
set_cookie(secure=false);           // 把 secure 旗標誤設 false → cookie 走明文`,
		fixed: `// 安全寫法:用具名常數並註明語意,權限精確
chmod(path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);   // 明確列出 0644
set_cookie(secure=true);           // https 敏感 cookie 維持 secure`,
		patch: `@@
-  chmod(path, 0222);
+  chmod(path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  ...
-  set_cookie(secure=false);
+  set_cookie(secure=true);`,
		refs: ['CWE-687', 'SEI CERT'],
		tags: ['argument-value', 'flags', 'permissions'],
	},
	{
		id: 'CWE-688',
		name: 'Function Call With Incorrect Variable or Reference as Argument',
		lang: 'c',
		status: 'Complete',
		what: `呼叫函式時傳入錯誤的變數或參考當引數。呼叫端呼叫某函式的其中一個參數時選錯了對象——把想傳的整數
		傳成取了位址的指標、把這個緩衝誤傳成那個緩衝、把本來要傳的值錯誤地傳成參考（或反之）。成因為名稱相似（bufA／bufB、
		struct 欄位長得像）、或型別都用可變分量的指標以致編譯器無法分辨、或誤用取址／取值運算。後果是函式對「錯誤的
		記憶體位置或錯誤的型別」作業，讀寫未初始化或不相干的資料，造成型別混淆、緩衝破壞與未定義行為。修法是讓變數命名
		有明確語意差別、對介面用強型別與標註、開啟編譯器型別與轉型警告，並以單元測試驗證每個引數實際指到的對象。`,
		problem: `// 不安全寫法:誤把 a_index 想成 b_index 的參考/指標傳錯對象
int a_index, b_index;
apply_offset(&b_index, value);     // 本來想改 a_index,卻傳了 b_index 的位址
char small[8], large[64];
fill(small, large);                // 想填 large 卻傳了 small,size 用錯 → 溢位`,
		fixed: `// 安全寫法:明確指向目標變數,並核對型別與長度
apply_offset(&a_index, value);     // 指向真正要改的變數
if (sizeof(small) >= data_len) fill(small_n, data);  else reject();`,
		patch: `@@
-  apply_offset(&b_index, value);
+  apply_offset(&a_index, value);
  ...
-  fill(small, large);
+  if (sizeof(small) >= data_len) fill(small_buffer, large, data_len); else reject();`,
		refs: ['CWE-688', 'SEI CERT'],
		tags: ['argument-reference', 'type-confusion', 'wrong-variable'],
	},
	{
		id: 'CWE-694',
		name: 'Use of Multiple Resources with Duplicate Identifier',
		lang: 'c',
		status: 'Complete',
		what: `多個資源用了重覆的識別碼。程式在「識別碼必須唯一」的場合，卻讓多個不同的資源共用同一個識別碼——例如多
		個連線、多個解釋、多個物件都以同一把 key／序號／索引登記，而沒有保證唯一。成因為識別碼產生器碰撞、重置或重用已
		釋放的識別碼，或把本該唯一的資源 ID 共用成常數。後果是兩個不同資源被誤認為是同一個：查到的資料被配錯、狀態互相
		覆蓋、授權被套到錯對象上，產生資料竄改或存取錯位的安全後果。修法是確保每個資源取得全域／語氣範圍內獨一無二的識別
		碼，使用遞增 count、UUID 或回號回收後不立刻重用，並在建置時檢查碰撞與唯一性。`,
		problem: `// 不安全寫法:多個連線/物件用同一個 id 登記 → 互搶與覆寫
int conn1 = register_conn(100);
int conn2 = register_conn(100);     // 兩個不同連線共用識別碼 100
send(conn1, "admin");               // lookup(100) 不確定傳給哪一條`,
		fixed: `// 安全寫法:由全域計數器/獨特來源配發唯一識別碼
static int next_id = 1;
int conn1 = register_conn(next_id++);   // 每個連線識別碼保證唯一
int conn2 = register_conn(next_id++);
send(conn1, "admin");`,
		patch: `@@
-  int conn1 = register_conn(100);
-  int conn2 = register_conn(100);
+  // 改用「全域遞增計數器」配發唯一識別碼,保證不重複
+  static int next_id = 1;
+  int conn1 = register_conn(next_id++);
+  int conn2 = register_conn(next_id++);`,
		refs: ['CWE-694', 'SEI CERT'],
		tags: ['duplicate-id', 'resource-management', 'uniqueness'],
	},
];
