// CWE chunk — 類別:組態誤設與路徑解析弱點（Config Misconfiguration & Path Resolution Versions）
// 補齊官方 v4.20 中手冊原本缺漏的 Base/Variant 條目
export default [
	{
		id: 'CWE-5',
		name: 'J2EE Misconfiguration: Data Transmission Without Encryption',
		lang: 'java',
		status: 'Complete',
		what: `J2EE 組態誤設：資料未加密傳輸（Data Transmission Without Encryption）。程式把敏感資料——帳號、卡號、
		密碼等——透過一般 HTTP（明文）或弱式加密通道送進網路，而未要求 HTTPS／SSL。傳輸途中封包的內容可被中間者
		窺視或篡改：明文資料任由抓包的人直接讀取，弱式加密則可被暴力或降低安全強度攻擊攻破，竄改後回傳給發送端。
		成因是伺服器未強制導向安全協定、Cookie 未設定 Secure 旗標，又直接把機密寫回 Body。修法是在伺服器端強制
		HTTPS 並將所有 HTTP 請求 307／301 導向 HTTPS、Cookie 一律加 Secure／HttpOnly，且不在回應 Body 內回顯機密。`,
		problem: `// 不安全寫法：在一般 HTTP servlet 明文傳輸與回顯敏感資料
protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
    String card = req.getParameter("card");          // 明文進出網路
    resp.getWriter().write("OK " + card);           // 卡號直接回傳
}`,
		fixed: `// 安全寫法：強制永久導向 HTTPS，並不再把機密寫回回應
protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
    if (!"https".equalsIgnoreCase(req.getScheme())) {
        String url = "https://" + req.getServerName() + req.getRequestURI();
        resp.encodeRedirectURL(url);
        resp.sendRedirect(url);
        return;
    }
    // 只有安全通道才處理，且不回顯機密
}`,
		patch: `@@
-    String card = req.getParameter("card");
-    resp.getWriter().write("OK " + card);
+    if (!"https".equalsIgnoreCase(req.getScheme())) {
+        String url = "https:// + req.getServerName() + req.getRequestURI();
+        resp.sendRedirect(url);
+        return;
+    }`,
		refs: ['CWE-5', 'OWASP'],
		tags: ['tls', 'j2ee', 'misconfiguration', 'transport'],
	},
	{
		id: 'CWE-6',
		name: 'J2EE Misconfiguration: Insufficient Session-ID Length',
		lang: 'java',
		status: 'Complete',
		what: `J2EE 組態誤設：工作階段 ID 長度不足（Insufficient Session-ID Length）。伺服器將工作階段 ID 設成太短的
		值，例如 8 個字元又只含小寫字母，使可能的工作階段 ID 空間過小。成因是組態用的熵太少——長度太短或字元集
		太窄——而系統又預設「夠隨機」。後果是攻擊者能以暴力或生日攻擊等方式猜到有效的工作階段 ID，從而挾持他人工作階段
		（session hijacking）、身分偽造或重放。修法是把工作階段 ID 增加到足夠長（通常是至少 128 位元）並使用
		Session ID Generator 產生的高位元亂數，同時配合 Set-Cookie 加上 Secure／HttpOnly 與隨機值的伺服端驗證。`,
		problem: `// 不安全寫法：自訂極短的 8 字元工作階段 ID，可窮舉猜中
String sid = generate8CharSessionId(request);   // 空間只有 36^8，可暴力
response.addCookie(new Cookie("JSESSIONID", sid));`,
		fixed: `// 安全寫法：交由容器產生至少 128 位元的高熵隨機工作階段 ID
HttpSession session = request.getSession(true);   // 容器產生的長 ID + 高熵亂數
String sid = session.getId();
Cookie c = new Cookie("JSESSIONID", sid);
c.setSecure(true);
c.setHttpOnly(true);
response.addCookie(c);`,
		patch: `@@
-String sid = generate8CharSessionId(request);
-response.addCookie(new Cookie("JSESSIONID", sid));
+HttpSession session = request.getSession(true);
+Cookie c = new Cookie("JSESSIONID", session.getId());
+c.setSecure(true); c.setHttpOnly(true);
+response.addCookie(c);`,
		refs: ['CWE-6', 'OWASP'],
		tags: ['session', 'session-id', 'entropy', 'j2ee'],
	},
	{
		id: 'CWE-7',
		name: 'J2EE Misconfiguration: Missing Custom Error Page',
		lang: 'java',
		status: 'Complete',
		what: `J2EE 組態誤設：缺少自訂錯誤頁（Missing Custom Error Page）。應用程式沒有為 HTTP 錯誤碼（404、500 等）
		設定自訂錯誤網頁，而是在 web.xml／容器未設定 error-page，因而把框架或容器的預設錯誤回應送回給使用者。預設錯誤頁
		常夾帶大量對攻擊者有用的系統細節：完整堆疊追蹤、程式碼行號、外部資源路徑、SQL 語句或專用套件版本。成因是「錯誤
		回應只是除錯工具」的假設，直接把伺服器內部的擲回訊息原封不動地吐給使用者。修法是在 web.xml 為每類錯誤碼與例外
		設定自訂錯誤頁，透過 JSP errorPage／filter 攔擷例外，對外提供精簡且不揭露內部結構的錯誤頁，詳細資訊只寫進
		服務端的 log。`,
		problem: `// 不安全寫法：未設定 error-page，500 錯誤直接攤開伺服器內部細節給使用者
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee">
  <!-- 無 <error-page>，容器預設錯誤頁會印出堆疊與路徑 -->
</web-app>`,
		fixed: `// 安全寫法：為每個錯誤碼與例外指定自訂錯誤頁，不洩漏內部細節
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee">
  <error-page>
    <error-code>500</error-code>
    <location>/errors/server.html</location>
  </error-page>
  <error-page>
    <exception-type>java.lang.Throwable</exception-type>
    <location>/errors/server.html</location>
  </error-page>
</web-app>`,
		patch: `@@
-  <!-- 無 <error-page>，容器預設錯誤頁會印出堆疊與路徑 -->
+  <error-page>
+    <error-code>500</error-code>
+    <location>/errors/server.html</location>
+  </error-page>`,
		refs: ['CWE-7', 'OWASP'],
		tags: ['error-page', 'info-leak', 'j2ee', 'stack-trace'],
	},
	{
		id: 'CWE-8',
		name: 'J2EE Misconfiguration: Entity Bean Declared Remote',
		lang: 'java',
		status: 'Complete',
		what: `J2EE 組態誤設：實體 Bean 被宣告為遠端（Entity Bean Declared Remote）。當企業 bean 暴露遠端介面時，
		該介面通常會連帶把 getter／setter 等讀寫 bean 資料的方法一起對外用 RMI／CORBA 公開。任何能連上這些
		介面的呼叫端就可讀取敏感欄位或違反應用預期地改寫資料。成因是「遠端範圍」與「可呼叫方法」沒有分開評估，
		把本該只在伺服器內部使用的資料存取方法順手向外暴露。後果是敏感資訊外洩、資料在違反商業規則下被篡改，
		並可做為其他弱點的上游。修法是儲存層 bean 只在同層使用本機介面、移除 @Remote／不要實作遠端介面，
		並對真正需要遠端的地方只暴露最小化、不含原始 getter／setter 的服務介面。`,
		problem: `// 不安全寫法：實體 bean 實作遠端介面，get/set 資料方法被外部呼叫端直接使用
@Remote
public interface AccountRemote extends javax.ejb.EJBObject {
    double getBalance() throws RemoteException;    // 外部可任意讀寫 bean 資料
    void setBalance(double b) throws RemoteException;
}`,
		fixed: `// 安全寫法：改為本機介面，資料存取只限伺服器內層使用
@Local
public interface AccountLocal {
    double getBalance();
    void adjust(double delta);     // 只暴露受業務規則約束的操作
}`,
		patch: `@@
-@Remote
-public interface AccountRemote extends javax.ejb.EJBObject {
-    double getBalance() throws RemoteException;
-    void setBalance(double b) throws RemoteException;
-}
+@Local
+public interface AccountLocal {
+    double getBalance();
+    void adjust(double delta);
+}`,
		refs: ['CWE-8', 'OWASP'],
		tags: ['ejb', 'remote', 'j2ee', 'access-control'],
	},
	{
		id: 'CWE-9',
		name: 'J2EE Misconfiguration: Weak Access Permissions for EJB Methods',
		lang: 'java',
		status: 'Complete',
		what: `J2EE 組態誤設：EJB 方法權限過寬（Weak Access Permissions for EJB Methods）。企業 bean 的方法沒有被賦予
		足夠嚴格的宣告式權限，例如方法未標註任何 @RolesAllowed、或錯誤使用了 @PermitAll／未在描述子聲明角色限制，
		於是原本該受保護的更新、退款等操作對所有呼叫者開放。成因是把權限只做在 Web 層或資料庫層，或想節省組態而放任
		bean 方法無視角色。後果是所有能觸及該 bean 的使用者——含一般帳號或從另一入口繞進來的呼叫端——都能呼叫高權限動作，
		篡改資料、拉升權限或繞過商業控制。修法是為每個 EJB 方法依最少特權原則指定角色（@RolesAllowed 或 ejb-jar
		描述子的 role-link），並以注解／組態雙重核對宣告層面確實生效。`,
		problem: `// 不安全寫法：方法未宣告角色限制，任何呼叫端都能執行退款等高權限動作
@Stateless
public class PaymentBean {
    @PermitAll
    public boolean refund(double amount) { ... }   // 誰都能退款
}`,
		fixed: `// 安全寫法：以最少特權原則明確限定可呼叫的角色
@Stateless
public class PaymentBean {
    @RolesAllowed("finance-admin")    // 只有此角色能用
    public boolean refund(double amount) { ... }
}`,
		patch: `@@
-    @PermitAll
+    @RolesAllowed("finance-admin")
     public boolean refund(double amount) { ... }`,
		refs: ['CWE-9', 'OWASP'],
		tags: ['ejb', 'authorization', 'roles', 'access-control'],
	},
	{
		id: 'CWE-11',
		name: 'ASP.NET Misconfiguration: Creating Debug Binary',
		lang: 'csharp',
		status: 'Complete',
		what: `ASP.NET 組態誤設：產出除錯二進位檔（Creating Debug Binary）。應用程式以 DEBUG 模式建置，或 web.config
		把 <compilation debug="true"/>、<trace enabled="true"/> 打開，讓執行檔與執行期回應夾帶大量除錯資訊。成因為
		把組態留在開發預設、沒有在發行時切回 Release。後果是回應訊息、堆疊追蹤與符號細節把系統內部結構、變數值與
		航線摘要交給駭客，等於免費提供發動攻擊所需的系統資訊。修法是在發行環境設 <compilation debug="false"/>/<trace
		enabled="false"/>，以 Release 設定建置與部署，用組態轉換（Web.config transforms）鎖定正式環境不開啟除錯輸出。`,
		problem: `// 不安全寫法：正式站仍保留除錯與追蹤，錯誤與狀態細節直接送給外部
<compilation debug="true" targetFramework="4.7.2" />
<trace enabled="true" localOnly="false" />   <!-- 追蹤結果可被遠端讀取 -->`,
		fixed: `// 安全寫法：發行環境關閉除錯與追蹤，改用發行組態
<compilation debug="false" targetFramework="4.7.2" />
<trace enabled="false" />`,
		patch: `@@
-<compilation debug="true" targetFramework="4.7.2" />
-<trace enabled="true" localOnly="false" />
+<compilation debug="false" targetFramework="4.7.2" />
+<trace enabled="false" />`,
		refs: ['CWE-11', 'OWASP'],
		tags: ['aspnet', 'debug', 'misconfiguration', 'info-leak'],
	},
	{
		id: 'CWE-12',
		name: 'ASP.NET Misconfiguration: Missing Custom Error Page',
		lang: 'csharp',
		status: 'Complete',
		what: `ASP.NET 組態誤設：缺少自訂錯誤頁（Missing Custom Error Page）。應用沒有啟用自訂錯誤網頁，
		customErrors 設為 Off 或未設定 mode，於是一發生錯誤就把 ASP.NET 執行環境在生命期間收集的詳情
		（堆疊、路徑、套件版本、SQL 內容）原樣送回給瀏覽器。成因是「錯誤回應只有開發者看得到」的誤解，
		或在正式環境沿用 Off 預設。後果是駭客可從框架內建回應裡挖出結構與版本等細節，用來瞄準已知弱點或
		探測後端。修法是將 <customErrors mode="On"> 同時提供 defaultRedirect 指向只含通用訊息的自訂頁，
		只在本機開發時顧及除錯。`,
		problem: `// 不安全寫法：customErrors 關閉，錯誤直接把 .NET 框架的完整細節送回瀏覽器
<customErrors mode="Off" />   <!-- 500 錯誤會吐出堆疊與內部資訊 -->`,
		fixed: `// 安全寫法：開啟自訂錯誤並統一導向僅含通用訊息的自訂頁
<customErrors mode="On" defaultRedirect="/error/secure.html" />`,
		patch: `@@
-<customErrors mode="Off" />
+<customErrors mode="On" defaultRedirect="/error/secure.html" />`,
		refs: ['CWE-12', 'OWASP'],
		tags: ['aspnet', 'error-page', 'info-leak', 'stack-trace'],
	},
	{
		id: 'CWE-13',
		name: 'ASP.NET Misconfiguration: Password in Configuration File',
		lang: 'csharp',
		status: 'Complete',
		what: `ASP.NET 組態誤設：密碼放在組態檔裡（Password in Configuration File）。資料庫連線或服務的密碼以明文
		寫在 web.config、App.config 或 appSettings 鍵值裡，連線字串欄滿密碼或金鑰。成因是「組態檔只在伺服器端、
		不屬攻擊面」的誤解，也因貪圖好改。後果是任何能讀到組態檔的人——備份、共用磁碟、設定洩漏、上傳疏失——
		就直接取得受保護資源的存取憑證，成為不需解密的流量目標；風險還隨密碼在多個環境重複而放大。修法是不要把
		明文密碼放進組態：用 aspnet_regiis -pe 把 section 加密、改用受保護組態（Protected Configuration / DPAPI、
		憑證）存放，連線字串用支援金鑰儲存的 connection string 提供者。`,
		problem: `// 不安全寫法：明文密碼直接躺在組態檔，讀得到檔就取得資料庫存取權
<appSettings>
  <add key="DbUser" value="sa" />
  <add key="DbPassword" value="hunter2_secret" />
</appSettings>`,
		fixed: `// 安全寫法：用受保護組態加密，組態檔只存放已被加密的區段
<connectionStrings configProtectionProvider="RsaProtectedConfigurationProvider">
  <EncryptedData>
    <CipherData>
      <CipherValue>AQAAANCMnd8BFdERjHoAwE/…（已加密位元組）</CipherValue>
    </CipherData>
  </EncryptedData>
</connectionStrings>`,
		patch: `@@
-<add key="DbUser" value="sa" />
-<add key="DbPassword" value="hunter2_secret" />
+<connectionStrings configProtectionProvider="RsaProtectedConfigurationProvider">
+  <EncryptedData>… 已加密 …</EncryptedData>
+</connectionStrings>`,
		refs: ['CWE-13', 'OWASP'],
		tags: ['aspnet', 'password', 'config', 'credentials'],
	},
	{
		id: 'CWE-24',
		name: "Path Traversal: '../filedir'",
		lang: 'python',
		status: 'Complete',
		what: `路徑穿越變體：'../filedir'。程式用外部輸入組出應落在受限目錄內的檔名，卻沒有在中性化 '../'
		這類往上跳一層的序列。攻擊注入 '../' 加上檔名，把路徑往上帶出受限制的目錄，讀取設定檔、/etc/passwd 之流。
		成因是「以輸入拼路徑」且未在解析後重新確認仍困在根目錄。修法是把輸入先 normpath 後，驗證其絕對路徑仍以
		允許根目錄字首開頭，或只用 basename 抽取純檔名。`,
		problem: `# 不安全寫法：直接把使用者名稱拼進目錄作存取，name 可帶 ../ 跳出目錄
def read(directory, name):
    p = os.path.join(directory, name)     # name = "../secret.txt" 就越下限
    return open(p).read()`,
		fixed: `# 安全寫法：正規化後必須仍落在允許根目錄內
def read(directory, name):
    root = os.path.realpath(directory)
    p = os.path.realpath(os.path.join(root, name))
    if not p.startswith(root + os.sep):
        raise ValueError("blocked")
    return open(p).read()`,
		patch: `@@
-    p = os.path.join(directory, name)
+    root = os.path.realpath(directory)
+    p = os.path.realpath(os.path.join(root, name))
+    if not p.startswith(root + os.sep):
+        raise ValueError("blocked")
     return open(p).read()`,
		refs: ['CWE-24', 'OWASP-PathTraversal'],
		tags: ['path-traversal', 'file', 'dotdot'],
	},
	{
		id: 'CWE-26',
		name: "Path Traversal: '/dir/../filename'",
		lang: 'python',
		status: 'Complete',
		what: `路徑穿越變體：'/dir/../filename'。使用者輸入了以「目錄／../檔名」形式出現的相對路徑——先指名一個目錄
		再用 ../ 跳回，再加檔名——來繞過「檔名必須落在允許目錄」的檢查。成因是程式只擋檔名首碼、不擋路徑本身，或接受
		'dir/../' 這類以目錄名開頭的序列而未做解析。後果是解析後實際指向根目錄之外、指向允許目錄之外的檔案，造成任意檔
		讀寫。修法是把輸入當路徑做 realpath 正規化，再檢驗正規化後的絕對路徑仍以允許根目錄為字首。`,
		problem: `# 不安全寫法：只看檔名沒看出 'dir/../' 已帶路徑穿越
def read(name):
    if name.startswith("/"): raise ValueError("no abs")   # 漏擋 dir/../name
    p = os.path.join(BASE, name)                          # 解析後跳出 BASE
    return open(p).read()`,
		fixed: `# 安全寫法：正規化絕對路徑並限定在 BASE 底下
def read(name):
    p = os.path.realpath(os.path.join(BASE, name))
    if not p.startswith(os.path.realpath(BASE) + os.sep):
        raise ValueError("blocked")
    return open(p).read()`,
		patch: `@@
-    if name.startswith("/"): raise ValueError("no abs")
     p = os.path.join(BASE, name)
+    p = os.path.realpath(p)
+    if not p.startswith(os.path.realpath(BASE) + os.sep):
+        raise ValueError("blocked")
     return open(p).read()`,
		refs: ['CWE-26', 'OWASP-PathTraversal'],
		tags: ['path-traversal', 'file', 'dotdot'],
	},
	{
		id: 'CWE-27',
		name: "Path Traversal: 'dir/../../filename'",
		lang: 'python',
		status: 'Complete',
		what: `路徑穿越變體：'dir/../../filename'。此例採用多個內部 '../' 序列，例如 'dir/../../etc/passwd'，一次往上
		跳多層，顯示程式對單一 '../' 做了部分過濾但對多層未擋、或根本沒解析。多層 ../ 擴大了「跳出受限目錄」的有效
		範圍，也更常命中系統機敏檔。成因同樣是把輸入當字串拼路徑、未在解析後重新確認範圍。修法須對輸入做完整路徑正規化，
		檢驗正規化結果仍為允許根目錄的子路徑，而不是嘗試逐欄位擋掉某一層 '../'。`,
		problem: `# 不安全寫法：只擋單一 '../'，多層序列沒被擋住
def read(name):
    if "../" not in name:                  # 擋不到 'dir/../../x'
        return open(os.path.join(BASE, name)).read()
    raise ValueError("blocked")`,
		fixed: `# 安全寫法：不數 '../' 層數，直接正規化後驗證根目錄
def read(name):
    p = os.path.realpath(os.path.join(BASE, name))
    if not p.startswith(os.path.realpath(BASE) + os.sep):
        raise ValueError("blocked")
    return open(p).read()`,
		patch: `@@
-    if "../" not in name:
-        return open(os.path.join(BASE, name)).read()
-    raise ValueError("blocked")
+    p = os.path.realpath(os.path.join(BASE, name))
+    if not p.startswith(os.path.realpath(BASE) + os.sep):
+        raise ValueError("blocked")
+    return open(p).read()`,
		refs: ['CWE-27', 'OWASP-PathTraversal'],
		tags: ['path-traversal', 'file', 'multi-dotdot'],
	},
	{
		id: 'CWE-28',
		name: "Path Traversal: '..\\filedir'",
		lang: 'python',
		status: 'Complete',
		what: `路徑穿越變體：'..\\filedir'（反斜線）。Windows 環境的目錄分隔是反斜線，注入 '..\\'（點點反斜線）即可
		往上跳目錄。程式若只過濾 '/' 形式或只擋檔案系統前端的字元，卻沒處理 '\\'，就會把 '../' 的反斜線版本漏掉。
		成因是路徑處理只針對單一分隔形式而未在平台層正規化。修法是依實際文件系統用 os.path.realpath／normpath 把
		反斜線與正斜線統一處理，再以允許根目錄字首驗證。`,
		problem: `# 不安全寫法：只擋正斜線 '../'，Windows 反斜線 '..\\' 直接通過
def read(name):
    if "../" in name: raise ValueError("blocked")   # '..\\secret' 沒被擋
    return open(os.path.join(BASE, name)).read()`,
		fixed: `# 安全寫法：統一正規化兩類分隔並校驗根目錄字首
def read(name):
    p = os.path.normpath(os.path.join(BASE, name))
    if p != os.path.commonpath([p, BASE]):        # 爬出 BASE 即拒
        raise ValueError("blocked")
    return open(p).read()`,
		patch: `@@
-    if "../" in name: raise ValueError("blocked")
+    p = os.path.normpath(os.path.join(BASE, name))
+    if p != os.path.commonpath([p, BASE]):
+        raise ValueError("blocked")
     return open(p).read()`,
		refs: ['CWE-28', 'OWASP-PathTraversal'],
		tags: ['path-traversal', 'backslash', 'windows', 'file'],
	},
	{
		id: 'CWE-30',
		name: "Path Traversal: '\\dir\\..\\filename'",
		lang: 'python',
		status: 'Complete',
		what: `路徑穿越變體：'\\dir\\..\\filename'（前導反斜線點點）。輸入以前導反斜線開頭，再接目錄與 '..\\' 與檔名，
		例如 '\\data\\..\\secret.txt'。前導反斜線可被理解為所屬磁碟／根目錄之下的路徑，配合 '..\\' 就能跳離限制目錄。
		成因是程式只檢查路徑的「前半段」或只檢查 '..' 字面，未做反斜線與整串路徑的解析。修法是對整條輸入做反斜線、
		正斜線與點點的正規化後再驗證落在允許根目錄。`,
		problem: `# 不安全寫法：僅過慮 '/' 開頭，漏掉以反斜線開頭又帶 ..\\ 的路徑
def read(name):
    if name.startswith("/"): raise ValueError("no abs")   # '\\x\\..\\f' 通過
    return open(os.path.join(BASE, name)).read()`,
		fixed: `# 安全寫法：連同反斜線形式一起正規化後校驗根目錄
def read(name):
    p = os.path.normpath(os.path.join(BASE, name.replace("\\\\", "/")))
    if p != os.path.commonpath([p, BASE]):
        raise ValueError("blocked")
    return open(p).read()`,
		patch: `@@
-    if name.startswith("/"): raise ValueError("no abs")
+    p = os.path.normpath(os.path.join(BASE, name.replace("\\\\", "/")))
+    if p != os.path.commonpath([p, BASE]):
+        raise ValueError("blocked")
     return open(p).read()`,
		refs: ['CWE-30', 'OWASP-PathTraversal'],
		tags: ['path-traversal', 'backslash', 'file'],
	},
	{
		id: 'CWE-31',
		name: "Path Traversal: 'dir\\..\\..\\filename'",
		lang: 'python',
		status: 'Complete',
		what: `路徑穿越變體：'dir\\..\\..\\filename'（多層內部反斜線點點）。輸入以一個目錄名開頭後接多個 '..\\'，
		如 'dir\\..\\..\\etc\\passwd'。只擋單一 '..\\' 或只擋某一分隔形式的檢查會漏掉多層、或反斜線與正斜線混用的
		寫法。成因是未對整條路徑做正規化與「仍在允許目錄下」的驗證。修法一律對輸入做路徑正規化後與允許根目錄比較，
		而不是數 '../' 出現幾次。`,
		problem: `# 不安全寫法：只檢查一次反斜線點點，多層序列放行
def read(name):
    if "..\\\\" not in name:                 # 'x\\\\..\\\\..\\\\f' 只有含即不擋
        return open(os.path.join(BASE, name)).read()
    raise ValueError("blocked")`,
		fixed: `# 安全寫法：不數層數，正規化後驗證根目錄字首
def read(name):
    p = os.path.normpath(os.path.join(BASE, name))
    if p != os.path.commonpath([p, BASE]):
        raise ValueError("blocked")
    return open(p).read()`,
		patch: `@@
-    if "..\\\\" not in name:
-        return open(os.path.join(BASE, name)).read()
-    raise ValueError("blocked")
+    p = os.path.normpath(os.path.join(BASE, name))
+    if p != os.path.commonpath([p, BASE]):
+        raise ValueError("blocked")
+    return open(p).read()`,
		refs: ['CWE-31', 'OWASP-PathTraversal'],
		tags: ['path-traversal', 'backslash', 'file'],
	},
	{
		id: 'CWE-32',
		name: "Path Traversal: '...' (Triple Dot)",
		lang: 'python',
		status: 'Complete',
		what: `路徑穿越變體：'...'。有些過濾器只移除 '../' 或單一形式的點點，但攻擊端改用三個點 '...'，在特定檔案系統
		或擴充後仍被視為等同 '../'（例如 '.../ ' 或某 Unicode 正規化後又變回 '..'）。成因是黑名單只列了 '../'，或
		在去除後沒有反覆反覆正規化，讓殘餘序列在下次解析時被視為穿越。修法是以實作層的路徑正規化（realpath）、允許
		根目錄字首驗證來決定容許值，而不是比對點點字面。`,
		problem: `# 不安全寫法：只移除 '../' 字樣，'...' 未被清掉可再解析成 '..'
def read(name):
    name = name.replace("../", "")          # '...' 不在黑名單
    return open(os.path.join(BASE, name)).read()`,
		fixed: `# 安全寫法：不靠字面黑名單，正規化後驗證仍限於根目錄
def read(name):
    p = os.path.realpath(os.path.join(BASE, name))
    if not p.startswith(os.path.realpath(BASE) + os.sep):
        raise ValueError("blocked")
    return open(p).read()`,
		patch: `@@
-    name = name.replace("../", "")
+    p = os.path.realpath(os.path.join(BASE, name))
+    if not p.startswith(os.path.realpath(BASE) + os.sep):
+        raise ValueError("blocked")
     return open(p).read()`,
		refs: ['CWE-32', 'OWASP-PathTraversal'],
		tags: ['path-traversal', 'triple-dot', 'bypass'],
	},
	{
		id: 'CWE-33',
		name: "Path Traversal: '....' (Multiple Dot)",
		lang: 'python',
		status: 'Complete',
		what: `路徑穿越變體：'....'。輸入加入多個點（四個或更多），再用來在正規化階段重新裝出 '../'：例如 '....//'、
		'..../' 在去除 '../' 的過濾後剩 '..'，進而被當作跳層序列。成因是過濾器做字面的、單次的移除，而非對路徑做
		反覆正規化，過濾與解析對同一串的解釋因此不一致。修法是對整條路徑以 realpath 正規化一次到位，再以「絕對路徑仍
		是允許根目錄之子」的檢驗取代黑名單。`,
		problem: `# 不安全寫法：單次 remove 多點串，殘餘的 .. 在下次解析變穿越
def read(name):
    name = name.replace("....", "")         # '....x' 處理後不再檢查
    return open(os.path.join(BASE, name)).read()`,
		fixed: `# 安全寫法：以正規化根目錄驗證取代字面過濾
def read(name):
    p = os.path.realpath(os.path.join(BASE, name))
    if not p.startswith(os.path.realpath(BASE) + os.sep):
        raise ValueError("blocked")
    return open(p).read()`,
		patch: `@@
-    name = name.replace("....", "")
+    p = os.path.realpath(os.path.join(BASE, name))
+    if not p.startswith(os.path.realpath(BASE) + os.sep):
+        raise ValueError("blocked")
     return open(p).read()`,
		refs: ['CWE-33', 'OWASP-PathTraversal'],
		tags: ['path-traversal', 'multi-dot', 'bypass'],
	},
	{
		id: 'CWE-34',
		name: "Path Traversal: '....//'",
		lang: 'python',
		status: 'Complete',
		what: `路徑穿越變體：'....//'（加倍點點斜線）。輸入使用 '....//' 或類似把兩個 '../' 併成 '....//' 的寫法，
		讓只移除單一 '../' 的過濾器處理後仍殘留 '..'（過濾掉一半留下一半），或讓只看字面數量的檢查誤判層數。
		成因是過濾器對疊合的序列只做單次、非循環的移除，過濾後的字串又回到解析管線。修法是對整段路徑做反覆正規化，
		用 realpath＋根目錄字首檢查決定可否放行，而不是數點／斜線出現幾次。`,
		problem: `# 不安全寫法：對 '../' 只 replace 一次，'....//' 殘留 '..' 仍可穿層
def read(name):
    name = name.replace("../", "")           # '....//x' → '..x' 未被再清
    return open(os.path.join(BASE, name)).read()`,
		fixed: `# 安全寫法：以解析後路徑與根目錄比較來放行
def read(name):
    p = os.path.realpath(os.path.join(BASE, name))
    if p != os.path.commonpath([p, BASE]):
        raise ValueError("blocked")
    return open(p).read()`,
		patch: `@@
-    name = name.replace("../", "")
+    p = os.path.realpath(os.path.join(BASE, name))
+    if p != os.path.commonpath([p, BASE]):
+        raise ValueError("blocked")
     return open(p).read()`,
		refs: ['CWE-34', 'OWASP-PathTraversal'],
		tags: ['path-traversal', 'doubled-slash', 'bypass'],
	},
	{
		id: 'CWE-35',
		name: "Path Traversal: '.../...//'",
		lang: 'python',
		status: 'Complete',
		what: `路徑穿越變體：'.../...//'。輸入把多個三點與混合的分隔組合在一起，如 '.../...//'，重疊的三點配上斜線，
		若過濾器做線性、單次的『去除』，重疊與再組會讓剩餘字元又被重組成 '../'。成因是黑名單式的單趟過濾不能窮舉
		變體。修法是回到原則面：對整條輸入做路徑正規化，再以「解析後絕對路徑仍為允許根目錄之子」作為唯一放行條件，
		並建議改用不依賴原始路徑的資料存取。`,
		problem: `# 不安全寫法：每種變體都手動列進黑名單，漏掉重疊組合即放行
def read(name):
    for bad in ["../", "....//", "..."]:
        name = name.replace(bad, "")
    return open(os.path.join(BASE, name)).read()`,
		fixed: `# 安全寫法：正規化後驗證仍限於允許根目錄
def read(name):
    p = os.path.realpath(os.path.join(BASE, name))
    if not p.startswith(os.path.realpath(BASE) + os.sep):
        raise ValueError("blocked")
    return open(p).read()`,
		patch: `@@
-    for bad in ["../", "....//", "..."]:
-        name = name.replace(bad, "")
+    p = os.path.realpath(os.path.join(BASE, name))
+    if not p.startswith(os.path.realpath(BASE) + os.sep):
+        raise ValueError("blocked")
     return open(p).read()`,
		refs: ['CWE-35', 'OWASP-PathTraversal'],
		tags: ['path-traversal', 'bypass', 'normalization'],
	},
	{
		id: 'CWE-37',
		name: "Path Traversal: '/absolute/pathname/here'",
		lang: 'python',
		status: 'Complete',
		what: `路徑穿越變體：斜線絕對路徑（'/absolute/pathname/here'）。程式接受以 '/' 開頭的絕對路徑輸入而未驗證，
		使用者就可直接指定系統上任何路徑（如 '/etc/passwd'），越過受限目錄。成因是應用把「相對到根目錄的檔名」與
		「同意提供的檔案」混在一起，對檔名做 join 時又因絕對路徑而忽略掉基底目錄。修法是拒絕絕對路徑、僅允許相對
		檔名，並在 join 後以 realpath 驗證仍落在允許根目錄；最穩妥是只取 basename。`,
		problem: `# 不安全寫法：接受以 / 開頭的絕對路徑，等於開放任意檔
def get(name):
    p = os.path.join(BASE, name)      # name='/etc/passwd' → 直接覆寫整個基底
    return open(p).read()`,
		fixed: `# 安全寫法：拒絕絕對路徑、化為純檔名並鎖進 BASEn
def get(name):
    leaf = os.path.basename(name)     # 去掉任何 / 與 ../
    p = os.path.join(BASE, leaf)
    if os.path.isabs(name): raise ValueError("abs not allowed")
    return open(p).read()`,
		patch: `@@
-    p = os.path.join(BASE, name)
-    return open(p).read()
+    if os.path.isabs(name): raise ValueError("abs not allowed")
+    leaf = os.path.basename(name)
+    p = os.path.join(BASE, leaf)
+    return open(p).read()`,
		refs: ['CWE-37', 'OWASP-PathTraversal'],
		tags: ['path-traversal', 'absolute-path', 'file'],
	},
	{
		id: 'CWE-38',
		name: "Path Traversal: '\\absolute\\pathname\\here'",
		lang: 'python',
		status: 'Complete',
		what: `路徑穿越變體：反斜線絕對路徑（'\\absolute\\pathname\\here'）。在 Windows 上以反斜線開頭的絕對路徑
		（如 '\\server\\share' 或磁碟根下的路徑）被程式接受而不驗證。若過濾器只擋 '/' 開頭，就會漏掉反斜線絕對
		路徑，讓使用者跳離受限目錄、指向任意位置。成因是路徑處理看待色為單一分隔形式而沒做平台正規化。修法是在
		Windows 語意下統一處理分隔，拒絕是絕對路徑的輸入，並以 realpath 驗證落在允許根目錄。`,
		problem: `# 不安全寫法：只擋正斜線絕對路徑，反斜線絕對路徑通過
def get(name):
    if name.startswith("/"): raise ValueError("no abs")
    return open(os.path.join(BASE, name)).read()   # '\\\\etc\\\\passwd' 通過`,
		fixed: `# 安全寫法：統一分隔後判絕對路徑並驗根目錄
def get(name):
    n = name.replace("\\\\", "/")
    if n.startswith("/"): raise ValueError("abs not allowed")
    p = os.path.realpath(os.path.join(BASE, n))
    if not p.startswith(os.path.realpath(BASE) + os.sep):
        raise ValueError("blocked")
    return open(p).read()`,
		patch: `@@
-    if name.startswith("/"): raise ValueError("no abs")
+    n = name.replace("\\\\", "/")
+    if n.startswith("/"): raise ValueError("abs not allowed")
+    p = os.path.realpath(os.path.join(BASE, n))
+    if not p.startswith(os.path.realpath(BASE) + os.sep):
+        raise ValueError("blocked")
     return open(p).read()`,
		refs: ['CWE-38', 'OWASP-PathTraversal'],
		tags: ['path-traversal', 'absolute-path', 'windows', 'file'],
	},
	{
		id: 'CWE-39',
		name: "Path Traversal: 'C:dirname'",
		lang: 'python',
		status: 'Complete',
		what: `路徑穿越變體：'C:dirname'（磁碟機代號）。輸入含 Windows 磁碟機或容量代號（'C:'）前綴，例如 'C:x'，
		而基底目錄假設名為 'D' 但實際指向使用者給的 'C:' 之下——明明要被限制在 'C:' 的受限目錄，成立基準卻被代號
		一字改變。成因是程式把「相對名」與「帶磁碟代號的相對名」混在一次 join，代號前的部分會重新定錨。修法是辨識並
		拒絕含有 ':'（代號或 alternative data stream）的輸入，正規化後再驗證落在允許根目錄。`,
		problem: `# 不安全寫法：接受含磁碟代號的相對路徑，基底被代號重新定錨
def get(name):
    return open(os.path.join("c:\\\\base", name)).read()   # name='c:x' → 跳離`,
		fixed: `# 安全寫法：拒絕含 ':' 的輸入，正規化後鎖進允許根目錄
def get(name):
    if ":" in name: raise ValueError("drive letter not allowed")
    root = os.path.realpath("c:\\\\base")
    p = os.path.realpath(os.path.join("c:\\\\base", name))
    if not p.startswith(root + os.sep):
        raise ValueError("blocked")
    return open(p).read()`,
		patch: `@@
-    return open(os.path.join("c:\\\\base", name)).read()
+    if ":" in name: raise ValueError("drive letter not allowed")
+    root = os.path.realpath("c:\\\\base")
+    p = os.path.realpath(os.path.join("c:\\\\base", name))
+    if not p.startswith(root + os.sep): raise ValueError("blocked")
+    return open(p).read()`,
		refs: ['CWE-39', 'OWASP-PathTraversal'],
		tags: ['path-traversal', 'drive-letter', 'windows'],
	},
	{
		id: 'CWE-40',
		name: "Path Traversal: '\\\\UNC\\\\share\\\\name\\\\'",
		lang: 'python',
		status: 'Complete',
		what: `路徑穿越變體：Windows UNC 共用（'\\\\UNC\\share\\name'）。輸入以寄出以 '\\\\' 開頭的 UNC 路徑，指向另一台
		主機上的共用資料夾。程式若把該輸入直接當本地路徑使用，使用者可把存取導向網路上的任意共用、繞過本地允許目錄，
		或讀寫他機的檔案。成因是本機路徑與「遠端 UNC 路徑」在同一 join／open 管線中未加區分。修法是拒絕以 '\\\\' 或
		'//' 開頭（UNC／網路路徑）的輸入，只接受本地相對檔名，並以 realpath 驗證著落地在允許根目錄。`,
		problem: `# 不安全寫法：接受 '\\\\server\\share' UNC 路徑，可直通遠端任意共用
def get(name):
    return open(os.path.join(BASE, name)).read()   # name='\\\\evil\\\\share\\\\f'`,
		fixed: `# 安全寫法：拒絕 UNC/網路路徑開頭，且只收純本地檔名
def get(name):
    if name.startswith("\\\\\\\\") or name.startswith("//"):
        raise ValueError("unc not allowed")
    leaf = os.path.basename(name)
    p = os.path.join(BASE, leaf)
    if p != os.path.commonpath([p, BASE]):
        raise ValueError("blocked")
    return open(p).read()`,
		patch: `@@
-    return open(os.path.join(BASE, name)).read()
+    if name.startswith("\\\\\\\\") or name.startswith("//"):
+        raise ValueError("unc not allowed")
+    leaf = os.path.basename(name)
+    p = os.path.join(BASE, leaf)
+    if p != os.path.commonpath([p, BASE]): raise ValueError("blocked")
+    return open(p).read()`,
		refs: ['CWE-40', 'OWASP-PathTraversal'],
		tags: ['path-traversal', 'unc', 'windows', 'file'],
	},
	{
		id: 'CWE-41',
		name: 'Improper Resolution of Path Equivalence',
		lang: 'javascript',
		status: 'Complete',
		what: `路徑等價性解析不當（Improper Resolution of Path Equivalence）。檔案系統允許「同一個物件」用多種名稱表示，
		例如檔名結尾的點、多個斜線、大小寫、短檔名（8.3）、捷徑與 symbolic link。程式若對兩個在 OS 層其實指同一個
		檔的名稱做了不同判斷，就可把一種名稱擋下、實際卻以另一種等價名稱存取目標，造成目錄檢查被繞過。成因是以「字面
		字串」而非「檔系統解析後的位元組」來做安全比較與允許範圍判定。後果是遮蔽列表繞過、存取範圍外檔案。修法是把輸入
		與允許範圍都正規化（resolve symlink、統一大小寫、擴展短名）在一致的表示下比較，或改用不碰路徑的物件層指標。`,
		problem: `// 不安全寫法：用原始字串判斷看向哪個檔，大小寫/尾點與磁碟實際解析不同
function open(name) {
  if (name.includes('secret')) throw new Error('blocked');
  return fs.realpathSync(name);      // 'SECRET.txt' 與 'secret.txt' 同一檔
}`,
		fixed: `// 安全寫法：以 realpath 正規化後的絕對路徑與允許根目錄比對
const path = require('path');
function open(name) {
  const root = fs.realpathSyncSync(RES_DIR);
  const p = fs.realpathSync(name);
  if (!p.startsWith(root + path.sep)) throw new Error('blocked');
  return p;
}`,
		patch: `@@
-  if (name.includes('secret')) throw new Error('blocked');
-  return fs.realpathSync(name);
+  const root = fs.realpathSyncSync(RES_DIR);
+  const p = fs.realpathSync(name);
+  if (!p.startsWith(root + path.sep)) throw new Error('blocked');
+  return p;`,
		refs: ['CWE-41', 'OWASP-PathTraversal'],
		tags: ['path-equivalence', 'canonicalization', 'bypass'],
	},
	{
		id: 'CWE-42',
		name: "Path Equivalence: 'filename.' (Trailing Dot)",
		lang: 'javascript',
		status: 'Complete',
		what: `路徑等價：結尾點（'filename.'）。Windows 檔案系統把 'file.' 與 'file' 視為同一個檔案（尾端點會被剝除），
		而在比對時若程式以未剝點的字串判定，就可能放行 'secret.' 而實際存取 'secret'，跳過來自 'secret' 的黑名單或
		目錄規則，使片段解析含糊。成因是驗證字串與檔案系統解析結果不一致。修法是先對輸入做檔系統一致的正規化（剝除尾點、
		正規化大小寫與反斜線），再以 realpath 與允許根目錄比較。`,
		problem: `// 不安全寫法：直接用原始檔名比較，尾點導致歧義解析被繞過
function open(name) {
  if (name === 'secret') throw new Error('blocked');
  return fs.createReadStream(name);   // 'secret.' 在同一判別下不等於 secret
}`,
		fixed: `// 安全寫法：剝尾點並以 realpath 正規化後才比較與存取
const path = require('path');
function open(name) {
  const norm = path.resolve(name).replace(/\\.$/, '');
  if (norm === path.resolve('secret')) throw new Error('blocked');
  return fs.createReadStream(norm);
}`,
		patch: `@@
-  if (name === 'secret') throw new Error('blocked');
-  return fs.createReadStream(name);
+  const norm = path.resolve(name).replace(/\\.$/, '');
+  if (norm === path.resolve('secret')) throw new Error('blocked');
+  return fs.createReadStream(norm);`,
		refs: ['CWE-42', 'CWE-41'],
		tags: ['path-equivalence', 'trailing-dot', 'bypass'],
	},
	{
		id: 'CWE-43',
		name: "Path Equivalence: 'filename....' (Multiple Trailing Dot)",
		lang: 'javascript',
		status: 'Complete',
		what: `路徑等價：多個尾點（'filename....'）。Windows 等多數檔案系統會把檔名結尾一串點剝除，使 'file....' 與
		'file' 指向同一目標。程式若以原始檔名字串（含一堆尾點）來做安全判定，驗證與實際解析對不上，可讓黑名單或目錄
		規則被繞過而存取到名字不同但物件相同的檔案。成因是驗證字串層與檔案系統解析層不一致。修法是將輸入剝除全部尾點、
		以 realpath 正規化到一致表示後，再進行安全與範圍判斷，驗證用與存取用同一表示。`,
		problem: `// 不安全寫法：比對用含多點的原名，存取指向解析後的不同檔
function open(name) {
  if (name === 'config') throw new Error('blocked');
  return fs.createReadStream(name);   // 'config....' 透過
}`,
		fixed: `// 安全寫法：剝除所有尾點再用同一正規化表示判斷與讀取
const path = require('path');
function open(name) {
  const norm = path.resolve(name).replace(/\\.+$/, '');
  if (norm === path.resolve('config')) throw new Error('blocked');
  return fs.createReadStream(norm);
}`,
		patch: `@@
-  if (name === 'config') throw new Error('blocked');
-  return fs.createReadStream(name);
+  const norm = path.resolve(name).replace(/\\.+$/, '');
+  if (norm === path.resolve('config')) throw new Error('blocked');
+  return fs.createReadStream(norm);`,
		refs: ['CWE-43', 'CWE-41'],
		tags: ['path-equivalence', 'trailing-dot', 'bypass'],
	},
	{
		id: "CWE-44",
		name: "Path Equivalence: 'file.name' (Internal Dot)",
		lang: 'javascript',
		status: 'Complete',
		what: `路徑等價：內含點（'file.name'）。檔名「內部」含點的字（例如把 'file' 寫成 'file..name' 或 'file.ext'
		part 利用點做區隔）在某些檔案系統與解析器下會被正規化成另一個名字，而程式以原始字串做安全判定時看不到等價關係。
		成因是驗證用的字面與檔案系統採用的正規化版本不一致，令黑名單或目錄檢查可被『多加一個點』繞過。修法是將檔名
		正規化到檔案系統實際解析的表示後統一比較，並以允許根目錄的 realpath 罩住存取。`,
		problem: `// 不安全寫法：用原始檔名判黑名單，檔名內部多個點可重新定錨
function open(name) {
  if (name.startsWith('.private')) throw new Error('blocked');
  return fs.createReadStream(name);   // '.p.rivate' 等價卻不命中
}`,
		fixed: `// 安全寫法：以 realpath 正規化的絕對路徑做範圍判定
function open(name) {
  const p = fs.realpathSyncSync(name);
  if (!p.startsWith(ROOT)) throw new Error('blocked');
  return fs.createReadStream(p);
}`,
		patch: `@@
-  if (name.startsWith('.private')) throw new Error('blocked');
-  return fs.createReadStream(name);
+  const p = fs.realpathSyncSync(name);
+  if (!p.startsWith(ROOT)) throw new Error('blocked');
+  return fs.createReadStream(p);`,
		refs: ['CWE-44', 'CWE-41'],
		tags: ['path-equivalence', 'internal-dot', 'bypass'],
	},
	{
		id: 'CWE-45',
		name: "Path Equivalence: 'file...name' (Multiple Internal Dot)",
		lang: 'javascript',
		status: 'Complete',
		what: `路徑等價：多個內部點（'file...name'）。檔名在名稱中間塞一串點（如 'file...name'），部分檔案系統或
		Windows 的 8.3 短檔名、或剝除連續點的行為會把它正規化成另一形式，而黑名單用原始字串比對時兩者不相等。
		成因是驗證與解析不一致，構成懸殊的「遮蔽列表」空隙。修法是將輸出一致正規化（去多餘連續點、擴展短名、
		統一大寫）後再以允許根目錄比較，避免『只比原始字面』的檢查。`,
		problem: `// 不安全寫法：黑名單字面比對，連續點的正規化形式逃過檢查
function open(name) {
  if (name.includes('private')) throw new Error('blocked');
  return fs.createReadStream(name);   // 'pri...vate' 正規化後即 private
}`,
		fixed: `// 安全寫法：以正規化後的解析結果為唯一決定基準
function open(name) {
  const norm = path.resolve(name).replace(/\\.{2,}/g, '.');
  const u = norm.toUpperCase();
  if (u.includes('PRIVATE')) throw new Error('blocked');
  return fs.createReadStream(norm);
}`,
		patch: `@@
-  if (name.includes('private')) throw new Error('blocked');
-  return fs.createReadStream(name);
+  const norm = path.resolve(name).replace(/\\.{2,}/g, '.');
+  if (norm.toUpperCase().includes('PRIVATE')) throw new Error('blocked');
+  return fs.createReadStream(norm);`,
		refs: ['CWE-45', 'CWE-41'],
		tags: ['path-equivalence', 'internal-dot', 'bypass'],
	},
	{
		id: 'CWE-46',
		name: "Path Equivalence: 'filename ' (Trailing Space)",
		lang: 'javascript',
		status: 'Complete',
		what: `路徑等價：尾隨空白（'filename '）。Windows 會在解析前剝除檔名結尾與開頭的一或多個空白，使 'file ' 與
		'file' 成為同一物件，而程式以含空白的原始字串做黑名單或目錄比較時，驗證與實際存取會對上不同名字。成因是
		未把字串『剝空白』到檔案系統的解析語意。修法是先將檔名 trim 到檔案系統實際接收的形式（去首尾空白與尾點），
		再用該正規化表示統一決定遮蔽與存取。`,
		problem: `// 不安全寫法：字面比對未剝尾隨空白，同一檔可被改名存取
function open(name) {
  if (name === '/etc/shadow') throw new Error('blocked');
  return fs.createReadStream(name);   // '/etc/shadow ' 逃過
}`,
		fixed: `// 安全寫法：剝除首尾空白後再用同一表示判定與讀取
const path = require('path');
function open(name) {
  const norm = path.resolve(name.trim());
  if (norm === path.resolve('/etc/shadow')) throw new Error('blocked');
  return fs.createReadStream(norm);
}`,
		patch: `@@
-  if (name === '/etc/shadow') throw new Error('blocked');
-  return fs.createReadStream(name);
+  const norm = path.resolve(name.trim());
+  if (norm === path.resolve('/etc/shadow')) throw new Error('blocked');
+  return fs.createReadStream(norm);`,
		refs: ['CWE-46', 'CWE-41'],
		tags: ['path-equivalence', 'trailing-space', 'bypass'],
	},
	{
		id: 'CWE-47',
		name: "Path Equivalence: ' filename' (Leading Space)",
		lang: 'javascript',
		status: 'Complete',
		what: `路徑等價：前導空白（' filename'）。Windows 與多數檔案系統會剝除檔名開頭的空白，因此 ' shadow' 與
		'shadow' 指同一檔案；若程式以含前導空格的字串做黑名單比較，會放行一個與受保護檔相同的物件。成因是比較字串
		未與檔案系統把前導空白剝除的語意對齊。修法是先對檔名做首尾 trim 與 other 正規化（去首尾空白與尾點），
		使其與檔案系統接收的一致，再以 realpath 罩住與比較允許範圍。`,
		problem: `// 不安全寫法：比對縮放時只擋不含空白的名字，前導空白可繞過
function open(name) {
  if (name === 'shadow') throw new Error('blocked');
  return fs.createReadStream(name);   // '  shadow' 逃過
}`,
		fixed: `// 安全寫法：先 trim 到檔案系統實際解析的形式再判斷與存取
function open(name) {
  const norm = path.resolve(name.trimStart());
  if (norm === path.resolve('shadow')) throw new Error('blocked');
  return fs.createReadStream(norm);
}`,
		patch: `@@
-  if (name === 'shadow') throw new Error('blocked');
-  return fs.createReadStream(name);
+  const norm = path.resolve(name.trimStart());
+  if (norm === path.resolve('shadow')) throw new Error('blocked');
+  return fs.createReadStream(norm);`,
		refs: ['CWE-47', 'CWE-41'],
		tags: ['path-equivalence', 'leading-space', 'bypass'],
	},
	{
		id: 'CWE-48',
		name: "Path Equivalence: 'file name' (Internal Whitespace)",
		lang: 'javascript',
		status: 'Complete',
		what: `路徑等價：內部空白（'file name'）。某些系統支援以特定字元替換空白或在多欄式檔案（如 tar、Windows 8.3）
		中把空白正規化，使 'file name' 可指向與無空白檔名相同的目標或相鄰目標，而黑名單以原始字串判定時看不出等價。
		成因是把『名字的字面』當成『一堆唯一的取值』，忽略正規化與別名的存在。修法是對輸入層的檔名做正規化、加上
		允許根目錄的 realpath 驗證與齊一的大小寫處理，若檔案由應用定義則建議以識別碼對照而不是直接拼檔案路徑。`,
		problem: `// 不安全寫法：直接以含空白的名字去比對／開檔，正規化結果可能相同
function open(name) {
  if (BANNED.has(name)) throw new Error('blocked');
  return fs.createReadStream(path.join(DIR, name));
}`,
		fixed: `// 安全寫法：以識別碼對照清單取得唯一路徑，不直接拼使用者名字
function open(key) {
  const p = MAP[key];
  if (!p || !p.startsWith(DIR)) throw new Error('blocked');
  return fs.createReadStream(p);
}`,
		patch: `@@
-  if (BANNED.has(name)) throw new Error('blocked');
-  return fs.createReadStream(path.join(DIR, name));
+  const p = MAP[key];
+  if (!p || !p.startsWith(DIR)) throw new Error('blocked');
+  return fs.createReadStream(p);`,
		refs: ['CWE-48', 'CWE-41'],
		tags: ['path-equivalence', 'whitespace', 'bypass'],
	},
	{
		id: 'CWE-49',
		name: "Path Equivalence: 'filename/' (Trailing Slash)",
		lang: 'javascript',
		status: 'Complete',
		what: `路徑等價：尾隨斜線（'filename/'）。程式判斷目標時若未剝除宣告尾斜線，'file/' 與 'file' 都指向同一
		目錄物件，黑名單比對或目錄檢查以『不含斜線的字面』判定就可能漏放。成因是驗證字串與檔案系統的斜線正規化
		不一致。實際案例常與目錄走查、符號連結結合，讓受限目錄的『檔案外洩到相鄰目錄』被斜線變體觸發。修法是對
		輸入與允許根目錄都以 path.resolve 剝斜線、解析為一致的絕對路徑後再比對。`,
		problem: `// 不安全寫法：用原始字串（含尾斜線與否）判定範圍，名字同 — 解析卻不同
function list(name) {
  if (name !== 'uploads') throw new Error('only uploads');
  return fs.readdirSync(path.join(DIR, name));   // 'uploads/' 也成立
}`,
		fixed: `// 安全寫法：剝掉尾斜線後再以解析路徑為準
const path = require('path');
function list(name) {
  const norm = path.resolve(name).replace(/\\/$|\\\\$/, '');
  if (norm !== path.resolve('uploads')) throw new Error('blocked');
  return fs.readdirSync(path.join(DIR, norm));
}`,
		patch: `@@
-  if (name !== 'uploads') throw new Error('only uploads');
-  return fs.readdirSync(path.join(DIR, name));
+  const norm = path.resolve(name).replace(/\\/$|\\\\$/, '');
+  if (norm !== path.resolve('uploads')) throw new Error('blocked');
+  return fs.readdirSync(path.join(DIR, norm));`,
		refs: ['CWE-49', 'CWE-41'],
		tags: ['path-equivalence', 'trailing-slash', 'bypass'],
	},
	{
		id: 'CWE-50',
		name: "Path Equivalence: '//multiple/leading/slash'",
		lang: 'javascript',
		status: 'Complete',
		what: `路徑等價：多個前導斜線（'//multiple/leading/slash'）。多個連續斜線 '//' 在很多系統會被正規化為單一
		斜線，'//etc/passwd' 便與 '/etc/passwd' 同等，而黑名單比對若只列出不含 // 的名字，就會漏放這個等價寫法。
		成因是驗證層沒有把連續斜線合併、或沒有與檔案系統的正規化行為對齊——尤其 '//' 開頭在部分平台還代表網路根
		（UNC 語意）。修法是以 path.normalize 將多斜線合一、以 realpath 取得唯一解析結果後再與允許根目錄比對。`,
		problem: `// 不安全寫法：只擋單一斜線絕對路徑，多重前導斜線放行
function open(name) {
  if (name.startsWith('/*')) throw new Error('no abs');
  return fs.createReadStream(path.join(DIR, name));   // '//etc/passwd'
}`,
		fixed: `// 安全寫法：normalize 進單一斜線後驗正規化路徑限於根目錄
function open(name) {
  const p = path.normalize(path.join(DIR, name));
  if (!p.startsWith(path.normalize(DIR))) throw new Error('blocked');
  return fs.createReadStream(p);
}`,
		patch: `@@
-  if (name.startsWith('/*')) throw new Error('no abs');
-  return fs.createReadStream(path.join(DIR, name));
+  const p = path.normalize(path.join(DIR, name));
+  if (!p.startsWith(path.normalize(DIR))) throw new Error('blocked');
+  return fs.createReadStream(p);`,
		refs: ['CWE-50', 'CWE-41'],
		tags: ['path-equivalence', 'leading-slash', 'bypass'],
	},
	{
		id: 'CWE-51',
		name: "Path Equivalence: '/multiple//internal/slash'",
		lang: 'javascript',
		status: 'Complete',
		what: `路徑等價：多個內部斜線（'/multiple//internal/slash'）。路徑中間允许多餘斜線（'a//b'）時，多數檔案系統
		將此正規化為 'a/b'，應用若以原始字面做驗證（如白人人只比 /dir/file）就會漏過 /dir//file 的等價寫法。
		成因是沒有把內部連續斜線壓縮到與檔案系統一致的表示。修法是對輸入以 path.normalize 收斂多斜線、以 realpath
		解析後，統一比較絕對路徑與允許根目錄，並對遮蔽清單一併以正規化代表儲存。`,
		problem: `// 不安全寫法：以排斥符號字面比對，/dir//file 等價寫法繞掉檢查
function open(name) {
  if (name.endsWith('/denied')) throw new Error('blocked');
  return fs.createReadStream(path.join(DIR, name));   // 'x//denied'
}`,
		fixed: `// 安全寫法：normalize 至單一斜線後用最終解析路徑判斷
function open(name) {
  const p = path.normalize(path.join(DIR, name));
  if (p.endsWith(path.normalize('/denied'))) throw new Error('blocked');
  return fs.createReadStream(p);
}`,
		patch: `@@
-  if (name.endsWith('/denied')) throw new Error('blocked');
-  return fs.createReadStream(path.join(DIR, name));
+  const p = path.normalize(path.join(DIR, name));
+  if (p.endsWith(path.normalize('/denied'))) throw new Error('blocked');
+  return fs.createReadStream(p);`,
		refs: ['CWE-51', 'CWE-41'],
		tags: ['path-equivalence', 'internal-slash', 'bypass'],
	},
	{
		id: 'CWE-52',
		name: "Path Equivalence: '/multiple/trailing/slash//'",
		lang: 'javascript',
		status: 'Complete',
		what: `路徑等價：多個尾隨斜線（'/multiple/trailing/slash//'）。檔名或目錄名結尾多個斜線（'dir//'）在正規化時
		被視為單一斜線、指向同一目錄，程式若比對『尾端斜線』的字面或數斜線個數，就會與檔案系統解析打架，讓受限目錄
		的存取以尾斜線變體被導到相鄰物件。成因是驗證字面層與 Normalize 層不一致。修法是削除並合併尾斜線、以
		realpath 正規化後統一與允許根目錄比較，避免依賴字面上的層數。`,
		problem: `// 不安全寫法：字面比對目錄路徑，尾端多斜線可改指別處
function list(name) {
  if (name !== 'uploads') throw new Error('only uploads');
  return fs.readdirSync(path.join(DIR, name));   // 'uploads//' 通過
}`,
		fixed: `// 安全寫法：併掉尾斜線再用解析後目錄判定
function list(name) {
  const p = path.join(DIR, name).replace(/(\\/|\\\\)*$/, '');
  const expect = path.join(DIR, 'uploads');
  if (p !== expect) throw new Error('blocked');
  return fs.readdirSync(expect);
}`,
		patch: `@@
-  if (name !== 'uploads') throw new Error('only uploads');
-  return fs.readdirSync(path.join(DIR, name));
+  const p = path.join(DIR, name).replace(/(\\/|\\\\)*$/, '');
+  if (p !== path.join(DIR, 'uploads')) throw new Error('blocked');
+  return fs.readdirSync(p);`,
		refs: ['CWE-52', 'CWE-41'],
		tags: ['path-equivalence', 'trailing-slash', 'bypass'],
	},
	{
		id: 'CWE-53',
		name: "Path Equivalence: '\\\\multiple\\\\\\ torn'",
		lang: 'javascript',
		status: 'Incomplete',
		what: `預留研究條目。`,
		problem: ``,
		fixed: ``,
		patch: ``,
		refs: ['CWE-53', 'CWE-41'],
		tags: ['path-equivalence', 'backslash', 'bypass'],
	},
	{
		id: 'CWE-54',
		name: "Path Equivalence: 'filedir\\\\' (Trailing Backslash)",
		lang: 'javascript',
		status: 'Complete',
		what: `路徑等價：尾隨反斜線（'filedir\\'）。Windows 會把檔名/目錄名結尾的反斜線視為目錄分隔、剝除後仍有相同
		目標，使 'filedir\\' 與 'filedir' 同名；程式若以含尾反斜線的字面做黑名單或目錄比較，驗證與實際解析不一，
		可繞過遮蔽。成因是只要驗證層未把反斜線視為可去除的分隔。修法是剝除尾反斜線、對輸入與允許根目錄都做
		path 正規化（在 Windows 語意下統一大小寫與分隔）後再比較，驗證與存取共用同一表示。`,
		problem: `// 不安全寫法：用原始檔名（可能含尾反斜線）比對遮蔽清單
function open(name) {
  if (BANNED.has(name)) throw new Error('blocked');
  return fs.createReadStream(path.join(DIR, name));   // 'secret\\\\'
}`,
		fixed: `// 安全寫法：剝尾反斜線並以正規化之後的名稱判定
function open(name) {
  const norm = name.replace(/\\\\+$/, '');
  if (BANNED.has(path.basename(norm))) throw new Error('blocked');
  return fs.createReadStream(path.join(DIR, norm));
}`,
		patch: `@@
-  if (BANNED.has(name)) throw new Error('blocked');
-  return fs.createReadStream(path.join(DIR, name));
+  const norm = name.replace(/\\\\+$/, '');
+  if (BANNED.has(path.basename(norm))) throw new Error('blocked');
+  return fs.createReadStream(path.join(DIR, norm));`,
		refs: ['CWE-54', 'CWE-41'],
		tags: ['path-equivalence', 'trailing-backslash', 'bypass'],
	},
	{
		id: 'CWE-55',
		name: "Path Equivalence: '/./' (Single Dot Directory)",
		lang: 'javascript',
		status: 'Complete',
		what: `路徑等價：單點目錄（'/./'）。在檔名或目錄中放進 '/./'（現行目錄）會被檔案系統當做無操作、直接剝去，
		例如 '/etc/./passwd' 就等於 '/etc/passwd'。程式若以原始字面（含 /./）做黑名單比較，就漏放這個等價寫法——
		名字不同卻指同一物件，是『遮蔽清單被繞過』的典型路徑等價。成因為正向含 '/./' 的正規化沒有落實。修法是
		path.normalize 把 '/./' 與重複分隔全部收斂後，用 final 絕對路徑與允許根目錄統一做存取與判定。`,
		problem: `// 不安全寫法：字面比對未處理 /./，等價寫法可繞過遮蔽
function open(name) {
  if (name.includes('/etc/passwd')) throw new Error('blocked');
  return fs.createReadStream(path.join(DIR, name));   // '/etc/./passwd'
}`,
		fixed: `// 安全寫法：normalize 縮合 '/'/./' 之後才決定
function open(name) {
  const p = path.normalize(path.join(DIR, name));
  if (p === path.normalize(path.join(DIR, '/etc/passwd')))
      throw new Error('blocked');
  return fs.createReadStream(p);
}`,
		patch: `@@
-  if (name.includes('/etc/passwd')) throw new Error('blocked');
-  return fs.createReadStream(path.join(DIR, name));
+  const p = path.normalize(path.join(DIR, name));
+  if (p === path.normalize(path.join(DIR, '/etc/passwd')))
+      throw new Error('blocked');
+  return fs.createReadStream(p);`,
		refs: ['CWE-55', 'CWE-41'],
		tags: ['path-equivalence', 'dot-directory', 'bypass'],
	},
	{
		id: 'CWE-56',
		name: "Path Equivalence: 'filedir*' (Wildcard)",
		lang: 'c',
		status: 'Complete',
		what: `路徑等價：萬用字元（'filedir*'）。檔名含有星號（'*'）等萬用字元時，執行檔的 shell、存取 API
		（如 Windows FindFirstFile 的自動擴充）或部分檔案系統會把它擴充成一組符合的名字，而黑名單以原始字面比對時
		看不到擴充結果、可能漏放並匹配到不應開放的目標。成因为把字面名当成唯一身份、又没停用万用展开。修法是先拒绝
		或停用萬用字元擴充，將檔名以無萬用字元的允許清單對應成檔案，並以 realpath 驗證最終路徑仍限於允許目錄。`,
		problem: `// 不安全寫法：直接 open 含萬用字元的檔名，API 自動展開匹配多檔
FILE *open_any(const char *pat) {
    if (strstr(pat, "secret")) return NULL;
    return glob_open(pat);   // 'secre*' 被展開而命中 secret
}`,
		fixed: `// 安全寫法：禁止萬用字元，檔名先對應到允許清單再開啟
FILE *open_safe(const char *key) {
    if (!is_alnum_only(key)) return NULL;                 // 無 * ? 
    const char *p = table_lookup(key, TABLE, N);        // 對照唯一檔案
    return p ? fopen(p, "rb") : NULL;
}`,
		patch: `@@
-    if (strstr(pat, "secret")) return NULL;
-    return glob_open(pat);
+    if (!is_alnum_only(key)) return NULL;
+    const char *p = table_lookup(key, TABLE, N);
+    return p ? fopen(p, "rb") : NULL;`,
		refs: ['CWE-56', 'CWE-41'],
		tags: ['path-equivalence', 'wildcard', 'file'],
	},
];
