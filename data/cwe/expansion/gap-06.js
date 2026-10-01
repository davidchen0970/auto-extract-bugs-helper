// CWE chunk — 類別:符號／邏輯／通道／例外與再入處理弱點（Symbol, Logic, Channel & Exception-Handling Weaknesses）
// 補齊官方 v4.20 中手冊原本缺漏的 Base/Variant 條目
export default [
	{
		id: 'CWE-386',
		name: 'Symbolic Name not Mapping to Correct Object',
		lang: 'c',
		status: 'Complete',
		what: `符號名稱對到不正確的物件。程式用某個符號名稱（常數、巨集、列舉、或命名的全域參考）來指稱「某個物件」，
		但該名稱在程式生命期中可以被重新定址、被換到另一個不同的物件上——例如一個全域指標符號被重新指派、或一個
		常數符號在不同檔案／分支被各自定義成不同值。於是在「命名當時」與「使用之時」符號指向的不再是同一個目標，
		後續操作便作用在錯誤的資料結構上，讀錯、寫錯、把無關物件的狀態一起改壞。成因是把「符號名稱」當成「永不改變的
		身分」來信任，忽略符號有可能在執行期間被重新綁定。修法是讓符號對到的物件在其使用期間保持不變、把符號綁定
		為 const／唯讀，或在使用前重新取得並驗證它確實對到預期的物件。`,
		problem: `// 不安全寫法:全域目標符號被另一段程式重新指派,主流程仍當它是原物件
#include <string.h>
static char g_logA[64];
static char *g_current = g_logA;   // 符號 g_current 最初指到 g_logA
static char backup_buf[64];
void redirect_log(void) { g_current = backup_buf; }  // 偷偷重新綁定符號
void write_log(const char *s) { strcpy(g_current, s); } // 實際寫到 backup_buf`,
		fixed: `// 安全寫法:把符號綁定成唯讀 const 常數,執行期間無法被重新指派
#include <string.h>
static char g_logA[64];
static char *const g_current = g_logA;   // const 指標:綁定後不可再指到別處
void write_log(const char *s) { strcpy(g_current, s); } // 永遠寫進 g_logA`,
		patch: `@@
- static char *g_current = g_logA;
+ static char *const g_current = g_logA;   // const: 綁定後不可再指到別處
  }
  void write_log(const char *s) { strcpy(g_current, s); }`,
		refs: ['CWE-386', 'OWASP'],
		tags: ['symbolic-name', 'object-binding', 'global-state'],
	},
	{
		id: 'CWE-393',
		name: 'Return of Wrong Status Code',
		lang: 'go',
		status: 'Complete',
		what: `回傳了錯誤的狀態碼。函式或操作完成後，回傳給呼叫端一個與「實際執行結果」不符的回傳值或狀態碼——例如
		明明失敗卻回報成功（Ok）、明明成功卻回報失敗、或用錯的代表成功常數。呼叫端依這個不真實的狀態碼去決定下一步，
		於是在錯誤的前提下繼續運作：把半完成的狀態當成已完成、把未寫入的資料當成已落盤、把失敗的驗證當成通過，
		一路走到錯誤的執行緒與控制流。成因多是把回傳值寫死、混用不同 API 的成功常數（把 0 與某 error code 用錯）、
		或在錯誤分支忘了更新回傳變數就 return。修法是讓每一條回傳路徑都「真的反映執行結果」：先想清楚成功／失敗的
		代表值，再有系統地設定並回傳正確的狀態碼。`,
		problem: `// 不安全寫法:就算下層失敗,這裡仍固定回 true(成功),呼叫端信以為真
func verify(token string, db *DB) bool {
	err := db.Lookup(token)          // 可能回 error
	if err != nil {
		db.LogFailure(token)         // 記錄失敗後……
	}
	return true                     // 錯:不管 err 都把結果回報成成功
}`,
		fixed: `// 安全寫法:每一條路徑的回傳值都反映真實結果
func verify(token string, db *DB) bool {
	if err := db.Lookup(token); err != nil {
		db.LogFailure(token)
		return false                // 失敗就回傳失敗狀態
	}
	return true                     // 只有真的通過才回傳成功
}`,
		patch: `@@
 	err := db.Lookup(token)
  	if err != nil {
  		db.LogFailure(token)
+		return false
  	}
  	return true`,
		refs: ['CWE-393', 'OWASP'],
		tags: ['status-code', 'return-value', 'error-handling'],
	},
	{
		id: 'CWE-395',
		name: 'Use of NullPointerException Catch to Detect NULL Pointer Dereference',
		lang: 'java',
		status: 'Complete',
		what: `用「捕捉 NullPointerException」來替代空值檢查。程式的做法是放任指針／參考去被解參考，等到 JVM 拋出
		NullPointerException（NPE）再 catch 起來當作「偵測到空值」的手段，而不是在解參考之前先用 if(ref == null)
		做程式化的檢查。問題在於 NPE 可以由很多來源同時觸發——不僅是「你預期的那個空參考」，也包括扣除錯、其它
		物件解體、或程式內部 bug——把「空值」與「其它意外」攪在一起，catch 到的異常往往不是原本想擋的空值，
		既會誤判根因，也掩蓋了真正的錯誤。此外依賴異常處理正常控制流效能差、可讀性差。修法是在使用參考前先
		顯式檢查 null，把「預期的空值」在異常系統之外處理掉。`,
		problem: `// 不安全寫法:允許空參考被解參考,再用 catch NullPointerException 當檢查
public static String readField(Map<String,String> m) {
    try {
        return m.get("key").toString();   // m.get 可能回 null,放任解參考
    } catch (NullPointerException e) {    // 把異常當空值檢查
        return null;
    }
}`,
		fixed: `// 安全寫法:在使用前用程式檢查,不靠異常偵測空值
public static String readField(Map<String,String> m) {
    String v = m.get("key");
    if (v == null) return null;           // 顯式空值檢查
    return v.toString();
}`,
		patch: `@@
-    try {
-        return m.get("key").toString();
-    } catch (NullPointerException e) {
-        return null;
-    }
+    String v = m.get("key");
+    if (v == null) return null;
+    return v.toString();`,
		refs: ['CWE-395', 'SEI CERT'],
		tags: ['null-dereference', 'npe', 'exception'],
	},
	{
		id: 'CWE-397',
		name: 'Declaration of Throws for Generic Exception',
		lang: 'java',
		status: 'Complete',
		what: `宣告拋出過於籠統的例外。方法以「寬到幾乎不具資訊量」的例外型別作為 throws——最典型的是直接 throws
		Exception、Throwable 或 RuntimeException——無論底下實際發生哪一種錯，通通上拋成同一個寬鬆型別。後果是把
		例外本身的細節（是哪個錯誤、低層拋出的是什麼）藏起來，呼叫端無法針對特定錯誤做精確的恢復或反應，只能全部
		當成同一種失敗處理，產生「對某些條件完全沒反應、對另一些條件反應錯誤」的不當行為。也會誘使呼叫端大段 try 全包。
		修法是逐一分類：只 throw 與實際失敗相符、夠具體的例外型別（如自訂業務例外、IOException 等），並在方法契約裡
		清楚宣告每一個可能被拋出的例外。`,
		problem: `// 不安全寫法:把真正特定的例外吞成籠統的 Exception 拋出,資訊全失
public String loadConfig() throws Exception {        // 過寬的例外宣告
    InputStream in = Files.newInputStream(Paths.get("cfg"));
    return new String(in.readAllBytes());            // IOException 被視為 Exception 上拋
}`,
		fixed: `// 安全寫法:宣告具體、與實際失敗相符的例外型別
public String loadConfig() throws IOException {
    InputStream in = Files.newInputStream(Paths.get("cfg"));
    return new String(in.readAllBytes());            // 只有 IOException 會冒出
}`,
		patch: `@@
- public String loadConfig() throws Exception {
+ public String loadConfig() throws IOException {
      InputStream in = Files.newInputStream(Paths.get("cfg"));`,
		refs: ['CWE-397', 'OWASP'],
		tags: ['exception', 'throws', 'error-handling'],
	},
	{
		id: 'CWE-403',
		name: "Exposure of File Descriptor to Unintended Control Sphere ('File Descriptor Leak')",
		lang: 'c',
		status: 'Complete',
		what: `檔案描述子外洩（File Descriptor Leak）。程式在 fork／exec 出子程式之前，沒有先關閉握有敏感資源的檔案
		描述子（fd），於是子程式繼承了這些 fd，得以在父程式預期之外的控制領域（control sphere）裡，對這些 fd 執行
		未經授權的輸入／輸出操作。典型是被 fork 出、執行外部指令的子程式，透過繼承的 fd 讀取或改寫父程式原本要保密的
		檔案、憑證或管道內容；若子程式還暴露給攻擊者控制，風險更大。成因是 fork 後忘了把不必要的 fd 關閉，或沒有為
		子程式設好只保留最少的 fd 集合。修法是 fork 前把不想繼承的 fd 關掉、用 close-on-exec（FD_CLOEXEC）旗標設定，
		並讓每次 exec 的子程式只繼承最少、已授權的 fd。`,
		problem: `// 不安全寫法:開啟含機密的檔案後直接 fork+exec 外部指令,子程式繼承了大量 fd
#include <fcntl.h>
#include <unistd.h>
int fd = open("/etc/secrets.dat", O_RDONLY);   // 敏感 fd
if (fork() == 0) {
    char *args[] = {"/usr/bin/some_tool", NULL};
    execv(args[0], args);                      // 子程式繼承 fd,可讀取機密
}
close(fd);`,
		fixed: `// 安全寫法:開啟的剄標 FD_CLOEXEC,exec 時自動關閉,子程式拿不到
#include <fcntl.h>
#include <unistd.h>
int fd = open("/etc/secrets.dat", O_RDONLY | O_CLOEXEC);  // close-on-exec
if (fork() == 0) {
    char *args[] = {"/usr/bin/some_tool", NULL};
    execv(args[0], args);                      // fd 因 CLOEXEC 在 exec 時自動關閉
}
close(fd);`,
		patch: `@@
- int fd = open("/etc/secrets.dat", O_RDONLY);
+ int fd = open("/etc/secrets.dat", O_RDONLY | O_CLOEXEC);`,
		refs: ['CWE-403', 'OWASP'],
		tags: ['fd-leak', 'file-descriptor', 'child-process'],
	},
	{
		id: 'CWE-419',
		name: 'Unprotected Primary Channel',
		lang: 'go',
		status: 'Complete',
		what: `主通道（primary channel）缺乏保護。程式以某個主要通道來提供管理或受限制的功能——通常是控制面、管理介面、
		內部服務——但沒有用與功能風險相符的保護（如認證、授權、加密）。由於通道就是拿來做高權限／管理操作的，一旦裸放
		在可觸達處，任何能連上的人都能未授權地驅使這些受限功能，等同把管理端無防護地敞開。成因是「內部或管理通道」被
		認為不需要特別防護，或預設所有人都可直連。修法是對主通道加上與其風險等級相稱的保護：身份驗證、權限檢查，以及
		需要時使用安全傳輸（TLS），並只在有授權的網路範圍內暴露。`,
		problem: `// 不安全寫法:管理通道(raw TCP)不認證也不加密,誰連上都可下管理指令
func main() {
    ln, _ := net.Listen("tcp", ":9443")       // 管理埠裸放
    for {
        conn, _ := ln.Accept()
        go handleAdmin(conn)                  // 無認證/無 TLS 的管理處理
    }
}`,
		fixed: `// 安全寫法:管理通道先要求認證,並透過 TLS 保護
func main() {
    ln, _ := tls.Listen("tcp", ":9443", tlsConfig)  // 加密通道
    for {
        conn, _ := ln.Accept()
        go func(c net.Conn) {
            if !authenticate(c) { return }          // 先認證再授權管理功能
            handleAdmin(c)
        }(conn)
    }
}`,
		patch: `@@
-    ln, _ := net.Listen("tcp", ":9443")
+    ln, _ := tls.Listen("tcp", ":9443", tlsConfig)
      for {
          conn, _ := ln.Accept()
-        go handleAdmin(conn)
+        go func(c net.Conn) {
+            if !authenticate(c) { return }
+            handleAdmin(c)
+        }(conn)
      }`,
		refs: ['CWE-419', 'OWASP'],
		tags: ['primary-channel', 'admin-channel', 'authentication'],
	},
	{
		id: 'CWE-420',
		name: 'Unprotected Alternate Channel',
		lang: 'go',
		status: 'Complete',
		what: `備用通道（alternate channel）缺乏保護。程式對「主通道」提供了某種保護（認證、加密），卻沒有用相同等級的保護
		去罩住另一個同樣能觸及相同資料或功能的備用通道——例如主站走 HTTPS+登入，但備援的後端埠、管理 socket、或代用
		介面仍以明文、免認證方式對外。攻擊者若找到那條沒被保護的備用通道，就能繞過主通道的防護，用同等權限存取原本該
		受保護的資料與功能，之前在主通道上的投資形同被旁路。成因是一次只保護「看得見的主通道」、忘了所有其它到達同一
		能力的路徑。修法是盤點每個能到達受限資料／功能的通道，並對每一條套用一致的認證、授權與傳輸加密保護。`,
		problem: `// 不安全寫法:主通道有 TLS+認證,但另一條備用 socket 是明文免認證
func main() {
    go serveSecureTLS(tlsConfig)          // 主通道:有保護
    ln, _ := net.Listen("tcp", ":8081")   // 備用通道:明文裸放
    for { c, _ := ln.Accept(); go handleAdmin(c) } // 同等受限功能,無認證
}`,
		fixed: `// 安全寫法:備用通道套用與主通道相同的認證與加密
func main() {
    go serveSecureTLS(tlsConfig)
    ln, _ := tls.Listen("tcp", ":8081", tlsConfig)   // 備用通道同樣 TLS
    for {
        c, _ := ln.Accept()
        if !authenticate(c) { c.Close(); continue }   // 同樣先認證
        handleAdmin(c)
    }
}`,
		patch: `@@
-    ln, _ := net.Listen("tcp", ":8081")
-    for { c, _ := ln.Accept(); go handleAdmin(c) }
+    ln, _ := tls.Listen("tcp", ":8081", tlsConfig)
+    for {
+        c, _ := ln.Accept()
+        if !authenticate(c) { c.Close(); continue }
+        handleAdmin(c)
+    }`,
		refs: ['CWE-420', 'OWASP'],
		tags: ['alternate-channel', 'bypass', 'authentication'],
	},
	{
		id: 'CWE-421',
		name: 'Race Condition During Access to Alternate Channel',
		lang: 'go',
		status: 'Complete',
		what: `在開啟備用通道期間的競態。程式為某個已授權的使用者建立一條備用通道來通訊，但在建立到真正「綁定／送出授權給
		這名使用者」之間存在空窗；建立通道當下它還沒有被嚴格關聯到該使用者的身份，這段時間裡其它行為者也可能連上或猜到
		這條還未歸屬的通道。若備用通道在授權資訊就緒前就可被存取，競爭的第三方即可攔截或偽裝進同一條通道，竊聽或冒名
		與受限功能互動。成因是把「建立通道」與「綁定身份／驗證」拆成兩段且沒讓兩者不可分割。修法是把「建立＋鑑別＋綁定」
		收進單一原子步驟，通道在通過身份確認之前不可被使用，並讓通道資源只可被已驗證的該使用者觸及。`,
		problem: `// 不安全寫法:先開啟備用通道德.Get(),之後才驗證 uid,空窗期人人可連
func openAlt(userID string) *Conn {
    ch := dialect.GetAltChannel()          // 先建立還未綁定身份的通道
    authorize(ch, userID)                  // 之後才綁定;中間可能有別人已連上
    return ch
}`,
		fixed: `// 安全寫法:取得通道時就綁定身份,驗證通過才開始接受使用
func openAlt(userID string) *Conn {
    ch, err := dialect.GetAltChannelFor(userID)   // 建立時即綁定該使用者
    if err != nil || !verify(ch, userID) {
        ch.Close()
        return nil
    }
    return ch                                     // 只有本人可用
}`,
		patch: `@@
-    ch := dialect.GetAltChannel()
-    authorize(ch, userID)
-    return ch
+    ch, err := dialect.GetAltChannelFor(userID)
+    if err != nil || !verify(ch, userID) {
+        ch.Close()
+        return nil
+    }
+    return ch`,
		refs: ['CWE-421', 'OWASP'],
		tags: ['alternate-channel', 'race-condition', 'authorization'],
	},
	{
		id: 'CWE-422',
		name: "Unprotected Windows Messaging Channel ('Shatter')",
		lang: 'c',
		status: 'Complete',
		what: `未受保護的 Windows 訊息通道（Shatter 攻擊）。程式以較高權限（如服務、提權管理員）執行時，透過 Windows 訊息
		系統與其它視窗溝通，卻沒有驗證送進來的消息（message）的來源是否為可信的寄件者。任何進程都可以用 PostMessage 等
		向高權限視窗送入 WM_COMMAND、WM_COPYDATA 或自訂訊息，等於創造了一條「備用通道」（alternate channel），讓
		攻擊者直接把自己的訊息餵給仍在提權狀態下的程式，誘使它去執行本不該執行的動作——這就是經典的 Shatter 提權、
		權限提升的手法。成因是信任了「訊息來自未知進程」而未核對。修法是不再以系統廣播訊息作為跨進程的命令通道，改用
		有身份鑑別的安全 IPC，或至少查證寄出訊息的進程身份與權限後才受理。`,
		problem: `// 不安全寫法:提權視窗不查訊號來源就處理自訂訊息 => 任一進程都能注入指令
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    if (msg == WM_APP_RUNCMD) {                // 自訂命令訊息
        // 沒有驗證 l 指向的進程/來源身份,直接執行敏感動作
        run_privileged_command((const char*)l);
        return 0;
    }
    return DefWindowProc(hwnd, msg, w, l);
}`,
		fixed: `// 安全寫法:改用帶身份鑑別的命名管道等安全 IPC,訊息只接受已驗證的呼叫端
HANDLE handle_client(void) {
    HANDLE hPipe = CreateNamedPipeA("\\\\.\\pipe\\trusted_admin",
        PIPE_ACCESS_DUPLEX, PIPE_WAIT, 1, 0, 0, 0, NULL);
    if (ConnectNamedPipe(hPipe, NULL) == 0) return NULL;
    if (!CallNamedPipeA("\\\\.\\pipe\\trusted_admin", auth, authLen, NULL, 0, &n, 0)
        || !is_trusted(hPipe)) {               // 只有通過來源鑑別的呼叫端才處理
        CloseHandle(hPipe osx);
        return NULL;
    }
    return hPipe;
}`,
		patch: `@@
- LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
-    if (msg == WM_APP_RUNCMD) {
-        run_privileged_command((const char*)l);
-        return 0;
-    }
-    return DefWindowProc(hwnd, msg, w, l);
- }
+ HANDLE handle_client(void) {
+    HANDLE hPipe = CreateNamedPipeA("\\\\.\\pipe\\trusted_admin",
+        PIPE_ACCESS_DUPLEX, PIPE_WAIT, 1, 0, 0, 0, NULL);
+    if (ConnectNamedPipe(hPipe, NULL) == 0) return NULL;
+    if (!CallNamedPipeA("\\\\.\\pipe\\trusted_admin", auth, authLen, NULL, 0, &n, 0)
+        || !is_trusted(hPipe)) { CloseHandle(hPipe osx); return NULL; }
+    return hPipe;
+ }`,
		refs: ['CWE-422', 'OWASP'],
		tags: ['shatter', 'windows-message', 'message-spoofing', 'privilege'],
	},
	{
		id: 'CWE-423',
		name: 'DEPRECATED: Proxied Trusted Channel',
		lang: '-',
		status: 'Deprecated',
		what: `本條目已被官方標記廢棄（DEPRECATED）：它原本是指「信任被代理的通道」這類弱點，但內容與 CWE-441 重複，
		現在官方已把全部內容遷移到 CWE-441。請改用 CWE-441（"Unintended Proxy or Intermediary ('Confused Deputy')"）來
		標記這類「把信任的通道當作代理來源、誤信送件者身份」的問題。保留此條只是為了讓依 id 查詢不致中斷，實務上
		應以 CWE-441 為準。`,
		problem: `// 已廢棄 -> 請參照 CWE-441 "Unintended Proxy or Intermediary (Confused Deputy)"`,
		fixed: `// 已廢棄 -> 用 CWE-441 標記與修繕「混淆代理」式信任來源問題`,
		patch: `@@
  // This entry is deprecated; all content moved to CWE-441.`,
		refs: ['CWE-423', 'CWE-441'],
		tags: ['deprecated', 'proxy', 'trusted-channel'],
	},
	{
		id: 'CWE-425',
		name: "Direct Request ('Forced Browsing')",
		lang: 'python',
		status: 'Complete',
		what: `直接請求／強制瀏覽（Forced Browsing）。Web 應用沒有在全部受限制的 URL、指令稿或檔案上確實執行授權檢查，
		只靠「不提供連結」當作唯一的防護。攻擊者無需靠連結，只要直接鍵入／導向那些隱藏的管理 URL、備份檔路徑或
		管理指令稿（例如 /admin、/config.inc.bak、/user?id=1 直接改 id），程式便直接回應或執行，因為它從未核對
		「這個使用者有沒有權限存取這條資源」。後果是未授權的使用者可存取管理功能、繞過權限階層竊取資料或執行作業。
		修法是對每個受限制的 URL、指令稿或檔案都套用一致的伺服器端授權檢查，不依賴「隱藏」或「少提供連結」當防護，
		一律在處理前先驗證身分與權限。`,
		problem: `// 不安全寫法:管理頁面只有「沒擺連結」,處理前完全不檢查權限
from flask import Flask, request
app = Flask(__name__)
@app.route('/admin/delete-all')
def delete_all():
    # 沒有檢查登入/角色 => 直接強制瀏覽就能觸發
    return wipe_everything()
@app.route('/admin')
def admin():
    # 即使知道網址也直接給頁面,不做授權
    return render_admin_panel()`,
		fixed: `// 安全寫法:每個受限路由處理前都檢查授權,否則拒絕
from flask import Flask, request, abort
app = Flask(__name__)
def admin_required():
    if not current_user.is_admin:
        abort(403)
@app.route('/admin/delete-all')
def delete_all():
    admin_required()              # 授權檢查在處理之前
    return wipe_everything()
@app.route('/admin')
def admin():
    admin_required()
    return render_admin_panel()`,
		patch: `@@
  @app.route('/admin/delete-all')
  def delete_all():
-    return wipe_everything()
+    admin_required()
+    return wipe_everything()
  @app.route('/admin')
  def admin():
-    return render_admin_panel()
+    admin_required()
+    return render_admin_panel()`,
		refs: ['CWE-425', 'OWASP'],
		tags: ['forced-browsing', 'direct-request', 'authorization', 'access-control'],
	},
	{
		id: 'CWE-431',
		name: 'Missing Handler',
		lang: 'node',
		status: 'Complete',
		what: `缺少處理常式。程式在某個會被觸發的事件、訊號、回呼或錯誤路徑上，沒有提供（或沒有實作）對應的 handler，
		於是當那個事件真的發生時，就沒有程式碼承接它——可能是未處理的例外直接讓行程崩潰、未處理的 Promise rejection
		把錯誤吞掉、硬體／訊號的處理常式空缺，或某個 REST 路由沒有註冊 handler 而對請求沒有回應。後果是該收回的錯誤
		沒有被收、該釋放的資源沒有釋放、行程意外終止或行為未定義。成因是在設計時漏列出了事件清單，或 mock 掉還沒做的
		handler。修法是為每一個可被觸發的事件／錯誤／訊號明確註冊 handler，並讓 handler 處理完該走的清理與回應路徑，
		對尚未實作的 handler 至少給一個顯式的空實作或不支援回應。`,
		problem: `// 不安全寫法:同步讀取拋出的例外沒有對應 handler,事件無人承接=>行程崩潰
import { readFileSync } from 'fs';
const data = readFileSync(process.argv[2]);   // 檔不存在就 throw
console.log(data.toString());
// 沒有 try/catch、沒有任何 rejected/uncaughtException handler`,
		fixed: `// 安全寫法:為可能觸發的事件加明確 handler,錯誤有承接、資源有清理
import { readFileSync } from 'fs';
try {
  const data = readFileSync(process.argv[2]);
  console.log(data.toString());
} catch (err) {
  console.error("read failed:", err.message);
  process.exit(1);                  // 明確處理,不留未收例外
}`,
		patch: `@@
  const data = readFileSync(process.argv[2]);
- console.log(data.toString());
+ try {
+   console.log(data.toString());
+ } catch (err) {
+   console.error("read failed:", err.message);
+   process.exit(1);
+ }`,
		refs: ['CWE-431', 'OWASP'],
		tags: ['missing-handler', 'unhandled', 'crash'],
	},
	{
		id: 'CWE-432',
		name: 'Dangerous Signal Handler not Disabled During Sensitive Operations',
		lang: 'c',
		status: 'Complete',
		what: `在敏感期間未停用危險的訊號處理常式。程式在某段必須不可被中斷的敏感操作進行中（例如正在處理共享全域、正持著
		鎖、正編寫關鍵狀態），其 signal handler 仍然維持「隨時可被呼叫」的狀態；handler 會與主流程共享狀態，但仍沒被
		mask／阻擋，於是同一個（或另一個）handler 可能在第一個還未跑完時又被觸發，造成 handler 重入、狀態被插入到
		敏感操作的中間，破壞主流程仍在依賴的不變式。後果是共享狀態被改到半途、資料損毀、甚至再次進入訊號處裡自身造成
		循環。修法是在進入敏感區之前先用 sigprocmask／pthread_sigmask 把相關訊號 block 起來、離開再還原，並讓 handler
		只處理 async-signal-safe 的最小動作。`,
		problem: `// 不安全寫法:敏感臨界區進行中沒 block 訊號,handler 可能在中間闖入並改全域
#include <signal.h>
#include <string.h>
static volatile sig_atomic_t g_step;
static char g_buf[64];
void handler(int sig) { (void)sig; g_step++; strcpy(g_buf, "alt"); }
void do_critical(void) {
    g_step = 0;                 // 敏感操作開始
    strcpy(g_buf, "real");      // 期待一口氣完成
    // 沒有 block 訊號 => 若此刻收到 SIGUSR1,handler 在寫 g_buf 的中間插入
    g_step++;                   // 回到這裡時 g_buf 已被 handler 改過
}`,
		fixed: `// 安全寫法:敏感期間先 block 訊號,離開再還原,保證不被闖入
#include <signal.h>
#include <string.h>
#include <stdatomic.h>
static volatile sig_atomic_t g_step;
static _Atomic char g_buf[64];
void do_critical(void) {
    sigset_t old; sigset_t set;
    sigemptyset(&set); sigaddset(&set, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &set, &old);   // 先把 handler 擋在外面
    g_step = 0;
    atomic_store64(g_buf, "real");            // 敏感操作不再被插入
    g_step++;
    pthread_sigmask(SIG_SETMASK, &old, NULL); // 離開還原
}`,
		patch: `@@
  void do_critical(void) {
+    sigset_t old; sigset_t set;
+    sigemptyset(&set); sigaddset(&set, SIGUSR1);
+    pthread_sigmask(SIG_BLOCK, &set, &old);
      g_step = 0;
      strcpy(g_buf, "real");
      g_step++;
+    pthread_sigmask(SIG_SETMASK, &old, NULL);
  }`,
		refs: ['CWE-432', 'SEI CERT'],
		tags: ['signal-handler', 'mask', 'reentrancy', 'critical-section'],
	},
	{
		id: 'CWE-433',
		name: 'Unparsed Raw Web Content Delivery',
		lang: 'php',
		status: 'Complete',
		what: `未解析的原始 Web 內容傳送。程式把「原始的內容或支援性程式碼」直接放在 web 文件根目錄之下，而且副檔名是
		伺服器不會特別處理的那種。例如把 PHP 原始碼另存成 .bak、.inc、.txt 或 .orig 的備份檔，放在可以透過瀏覽器
		直連的目錄下；Web 伺服器對這名字走「靜態檔案伺服」路徑，直接按文字傳送內容，而不會先丟給 PHP／其它解釋器執行。
		後果是本來在伺服器端執行的邏輯、資料庫帳密、演算法等原始碼與敏感設定被整包吐給任何下載的人，等同原始碼外洩。
		成因是「執行前要先解析」的檔案被錯放在可直連位置且用了伺服器不認得的副檔名。修法是永遠不要把原始碼／備份放在
		web 文件根之下，或用會被伺服器阻擋的副檔名、放進執行器外的目錄，並在伺服器端擋掉這些備份檔擴展名。`,
		problem: `// 不安全寫法:把 index.php 的備份 index.php.bak 放進 web 根目錄,伺服器當靜態檔送出
<!-- document root: /var/www/site -->
index.php            // 被執行
index.php.bak        // 伺服器不認得 .bak => 直接把原始 PHP 原始碼送回瀏覽器
db.php.orig          // 同樣,內含資料庫連線密碼的原始碼可被下載`,
		fixed: `// 安全寫法:原始碼/備份全部移出 web 根目錄,伺服器端另外阻擋備份擴名
<!-- 原始檔移到 web 根之外,或副檔名改為被伺服器拒絕 -->
/var/www/site/index.php            // 才執行
/var/repo/backups/index.php.bak    // 在 document root 之下永遠看不到
# 且組態一律對 .bak/.orig/.inc/~ 回 403:
#  Apache: <FilesMatch "\\.(bak|orig|inc|~)$"> Require all denied </FilesMatch>`,
		patch: `@@
- index.php.bak        # 靜態送出原始碼
+ # 全部移到 docroot 之外 + 伺服器端阻擋擴名
+ <FilesMatch "\\.(bak|orig|inc|~)$"> Require all denied </FilesMatch>`,
		refs: ['CWE-433', 'OWASP'],
		tags: ['source-disclosure', 'static-content', 'backup-file', 'information-exposure'],
	},
	{
		id: 'CWE-437',
		name: 'Incomplete Model of Endpoint Features',
		lang: 'python',
		status: 'Complete',
		what: `對端點功能特性的模型不完整。程式在兩個或以上的端點之間充當仲介／監看者（proxy、middleware、攔截器），但它對
		任一端點「真實具備的功能、行為或狀態」沒有建立完整模型——例如假設對面只有 GET／POST、只有單一內容型別、或只會
		發出固定語法的請求。當真實端點送來它沒學過的額外特性（額外標頭、另一種 HTTP 方法、非預期的編碼、分塊傳輸），
		仲介會基於「錯誤的假設」做出錯誤的動作：放行不該放的、改寫不該改的、或漏掉該做的檢查。後果是由於模型與真實
		端點不符，安全檢查被繞過或發生錯誤路由。修法是讓仲介對端點的特性、行為與狀態有完整而保守的建模，凡是無法理解的
		特性一律走「最安全」的處理或直接拒絕，而不是默認忽略。`,
		problem: `// 不安全寫法:proxy 只假設 body 是 UTF-8 文字、只認 Content-Length,其它一概忽略
def parse_request(r):
    body = r.data.decode("utf-8")          # 假設永遠 UTF-8 單一格式
    length = int(r.headers["Content-Length"])
    # unknown headers / non-raw body / extra methods 全被漠視
    return sanitize(body[:length])
def on_request(r):
    if r.method not in ("GET", "POST"):    # 只學過兩種方法
        return allow(r)                    # 其它方法直接放行 => 檢查被繞過
    return parse_request(r)`,
		fixed: `// 安全寫法:無法完整理解的特性一律保守拒絕,不默認忽略
def on_request(r):
    known = {"GET", "POST", "HEAD", "OPTIONS"}
    if r.method not in known:
        return reject(r, 405)              # 不認得的特性就拒絕
    if not valid_encoding(r):
        return reject(r, 400)              # 未能驗證的 body/編碼不放行
    return sanitize_then_forward(r)`,
		patch: `@@
-    if r.method not in ("GET", "POST"):
-        return allow(r)
-    return parse_request(r)
+    known = {"GET", "POST", "HEAD", "OPTIONS"}
+    if r.method not in known:
+        return reject(r, 405)
+    if not valid_encoding(r):
+        return reject(r, 400)
+    return sanitize_then_forward(r)`,
		refs: ['CWE-437', 'OWASP'],
		tags: ['proxy', 'endpoint-model', 'middleware', 'bypass'],
	},
	{
		id: 'CWE-439',
		name: 'Behavioral Change in New Version or Environment',
		lang: 'node',
		status: 'Complete',
		what: `在新版本或新環境中行為改變。元件 A 在某個新版本、或換了某個執行環境之後，行為或功能改變了，而依賴它的元件 B
		對這次改變毫不知情、也不足以管理它。例如 B 呼叫 A 的方法時假設「回傳一個陣列」，新版本 A 改回傳 Promise／物件／或
		在空集合時回傳 null；或 B 依賴的時區／字元編碼／亂數種子在部署環境不同後行為有變。於是在 B 無法預測的前提下，原本
		依賴的語義被安靜破壞，B 繼續用舊假設去處理 A 的新行為，產生錯誤結果或資安弱化。成因是 B 對其依賴的版本行為簽了
		隱式的契約，卻沒在升級／換環境時重新校驗。修法是對依賴的對外行為做明確版本測定的契約測試、在部署後跑回歸驗證、
		並讓 B 對 A 行為的假設可管理（版本鎖定、feature 偵測、相容層）。`,
		problem: `// 不安全寫法:B 深寫死 A 的回傳型/語義,沒做行為相容偵測,新版 A 一變就壞
import { parseUser } from "legacy-parser"    // 依賴元件,回傳假設如下
function renderRow(user) {
    // 假設 parseUser 一定回傳 user/name,不抓 null 或 async 變更
    return table.rows.add("<tr><td>" + user.name + "</td></tr>");
}`,
		fixed: `// 安全寫法:先抓取/偵測依賴的行為再使用,寫出可管理的相容層
import { parseUser } from "legacy-parser"
async function loadUser(id) {
    const raw = await parseUser(id);         // 兼容可能轉 async 的新版
    const user = (raw && raw.name) ? raw : { name: String(raw) };  // 防 null/型別變
    return user;
}
function renderRow(user) {
    return table.rows.add("<tr><td>" + user.name + "</td></tr>");
}`,
		patch: `@@
-    return table.rows.add('<tr><td>' + user.name + '</td></tr>');
+    const user = await loadUser(id);        // 對新版行為做相容處理
+    return table.rows.add('<tr><td>' + user.name + '</td></tr>');`,
		refs: ['CWE-439', 'OWASP'],
		tags: ['behavioral-change', 'dependency', 'version', 'compatibility'],
	},
	{
		id: 'CWE-443',
		name: 'DEPRECATED: HTTP response splitting',
		lang: '-',
		status: 'Deprecated',
		what: `本條目已被官方標記廢棄（DEPRECATED）：它原名「HTTP 回應切割（HTTP response splitting）」，但該弱點內容
		已整併到 CWE-113（"Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting')"）。
		現在的建議是改用 CWE-113 來標記「未正確中和 HTTP 標頭中的 CRLF 序列」這類問題——即攻擊者把 \r\n\r\n 注入回應產出，
		讓單一回應被切割成兩個、把使用者導到注入的額外回應。保留此條僅保持 id 連續，實務請以 CWE-113 為準。`,
		problem: `// 已廢棄 -> 請參照 CWE-113 (HTTP Request/Response Splitting / CRLF injection)`,
		fixed: `// 已廢棄 -> 依 CWE-113 修法:過濾所有進到回應標頭與 Location 的 CR/LF 序列`,
		patch: `@@
  // This entry is deprecated; see CWE-113 for HTTP response splitting.`,
		refs: ['CWE-443', 'CWE-113'],
		tags: ['deprecated', 'http-splitting', 'crlf'],
	},
	{
		id: 'CWE-447',
		name: 'Unimplemented or Unsupported Feature in UI',
		lang: 'javascript',
		status: 'Complete',
		what: `UI 中未實作或未支援的功能。某個安全功能的 UI 選項看起來被支援了——顯示著可點選的開關、有輸入框、按下後也有
		反應（例如顯示「已啟用」）——但底層那個功能其實根本沒有被實作。成因是在介面上先做程序原理／表單，而真實的安全邏輯
		漏做了，或留了空實作接點只是回傳成功。後果是使用者以為啟用了憑證驗證、雙重認證、欄位加密、登出等保護，實際卻從未
		生效，產生一種虛假的「已保護」狀態，攻擊者可放心繞過。修法是讓 UI 真的串到已實作的功能：未實現就該隱藏或標示
		disabled，且 UI 的「啟用」狀態必須來自真實後端功能的實際狀態，二者一致。`,
		problem: `// 不安全寫法:設定頁的「啟用 MFA」切換框**看起來**有效,其實後端動作是空實作
const toggle = document.getElementById('enable-mfa');
toggle.addEventListener('change', () => {
    // 尜後端沒有真的開 MFA:只是把 UI 狀態設成 on,給使用者「已啟用」的假象
    settings.mfaEnabled = toggle.checked;
    showToast('MFA 已啟用');
});`,
		fixed: `// 安全寫法:與後端實際功能同步,未實作就標示 disabled,不造假象
const toggle = document.getElementById('enable-mfa');
toggle.addEventListener('change', async () => {
    const ok = await api.setMfa(toggle.checked);   // 真的呼叫已實作後端
    if (!ok) { toggle.checked = !toggle.checked; showError('後端不支援'); return; }
    settings.mfaEnabled = await api.getMfa();       // UI 狀態來自有實際功能的後端
    showToast(settings.mfaEnabled ? 'MFA 已啟用' : '未啟用');
});`,
		patch: `@@
  toggle.addEventListener('change', () => {
-    settings.mfaEnabled = toggle.checked;
-    showToast('MFA 已啟用');
+    const ok = await api.setMfa(toggle.checked);
+    if (!ok) { toggle.checked = !toggle.checked; showError('後端不支援'); return; }
+    settings.mfaEnabled = await api.getMfa();
+    showToast(settings.mfaEnabled ? 'MFA 已啟用' : '未啟用');
  });`,
		refs: ['CWE-447', 'OWASP'],
		tags: ['ui', 'unimplemented-feature', 'false-protection'],
	},
	{
		id: 'CWE-448',
		name: 'Obsolete Feature in UI',
		lang: 'javascript',
		status: 'Complete',
		what: `UI 中的過時功能。使用者介面上仍顯示著某個功能，但這個功能（或其背後的作法）已經過時、不再適用，而程式沒有
		向使用者宣告它是 obsolete。常見如仍顯示已被舊的通訊協定取代的選項、已不安全的密碼演算法選項、或已被棄用的 API
		入口。問題在於使用者不知道這個選項已不該再用，會繼續選它、依賴一個可能已被底層變更或缺乏維護的路徑；若該過時功能
		剛好已不安全（如 SSLv3、MD5 雜湊），使用者就蒙在鼓裡用了有風險的設定。修法是對過時功能在 UI 上明確標示為
		deprecated／移除，並把使用者導向現行的替代方案。`,
		problem: `// 不安全寫法:下拉列選出已過時/不安全的加密選項,使用者無從得知它已被淘汰
<select id="cipher">
  <option value="RC4">RC4</option>      <!-- 已過時且不安全,沒任何提示 -->
  <option value="TLS_RSA">TLS_RSA</option><!-- 舊套件,仍默默可選 -->
</select>
// 程式沒偵測、也沒在選項旁標示 obsolete`,
		fixed: `// 安全寫法:過時選項必須標示 deprecated 或直接移除,並提供替代
<select id="cipher">
  <optgroup label="建議">
    <option value="TLS_AES_256_GCM" selected>TLS_AES_256_GCM</option>
  </optgroup>
  <optgroup label="已淘汰（不建議）">
    <option value="RC4" disabled>RC4（obsolete）</option>
    <option value="TLS_RSA" disabled>TLS_RSA（obsolete）</option>
  </optgroup>
</select>
// disabled + obsolete 標籤讓使用者不可能默默選用`,
		patch: `@@
  <option value="RC4">RC4</option>
- <option value="TLS_RSA">TLS_RSA</option>
+ <option value="RC4" disabled>RC4（obsolete）</option>
+ <option value="TLS_AES_256_GCM" selected>TLS_AES_256_GCM</option>`,
		refs: ['CWE-448', 'OWASP'],
		tags: ['obsolete', 'ui', 'deprecated', 'crypto-option'],
	},
	{
		id: 'CWE-449',
		name: 'The UI Performs the Wrong Action',
		lang: 'javascript',
		status: 'Complete',
		what: `UI 執行了錯誤的動作。介面在用者提出某個要求後，執行的是「不符合該要求」的另一個動作——典型是把「刪除」送成
		「停用」、把「加到白名單」送成「加到黑名單」、或把「允許」與「拒絕」的規則寫反。成因常是前後端事件的 handler 綁錯、
		用詞相近的兩個動作被複製貼上成同一支、或將「正向」與「反向」旗標在建構時顛倒了。後果是使用者以為做的是安全的動作，
		實際系統卻執行了一個相反或無關的動作：把該拒絕的放行、把該保留的刪除，讓權限、規則或狀態與使用者意圖相反。修法是
		讓 UI 動作與其對應的後端操作嚴格一對一，檢查 event 發送與 handler 的綁定，並對高風險動作加上二次確認及清楚的反向
		標示（例如把「刪除」與「停用」分開的按鈕與獨立 handler）。`,
		problem: `// 不安全寫法:點「停用使用者」卻呼叫到 ban 之外的白名單操作,動作綁錯
document.getElementById('deactivate-btn').addEventListener('click', () => {
    api.performAction(user.id, "ADD_TO_ACL");   // 錯:按停用,卻執行「加入白名單」
    // 使用者被告知「已停用」，實際用戶反而被加入准許清單
    showSuccess('使用者已停用');
});`,
		fixed: `// 安全寫法:UI 動作與後端操作一對一,高風險動作要確認,不張冠李戴
document.getElementById('deactivate-btn').addEventListener('click', async () => {
    const ok = await window.confirm('確定要永久停用此使用者嗎？');
    if (ok) {
        const res = await api.performAction(user.id, "DEACTIVATE");  // 動作正確
        showSuccess(res.message);
    }
});
document.getElementById('whitelist-btn').addEventListener('click', () => {
    api.performAction(user.id, "ADD_TO_ACL");   // 白名單有自己獨立的按鈕
});`,
		patch: `@@
  document.getElementById('deactivate-btn').addEventListener('click', () => {
-    api.performAction(user.id, "ADD_TO_ACL");
-    showSuccess('使用者已停用');
+    const ok = await window.confirm('確定要永久停用此使用者嗎？');
+    if (ok) { const res = await api.performAction(user.id, "DEACTIVATE");
+              showSuccess(res.message); }
  });`,
		refs: ['CWE-449', 'OWASP'],
		tags: ['ui', 'wrong-action', 'misbinding'],
	},
	{
		id: 'CWE-450',
		name: 'Multiple Interpretations of UI Input',
		lang: 'javascript',
		status: 'Complete',
		what: `UI 輸入有多種解讀方式。使用者給的輸入可以被 UI 以不止一種語義解讀，而程式在幾種解讀之間自行選了「比較不
		安全」的那一種，卻沒有回過頭來向使用者確認。例如逗號分隔值在「清單成員」與「單一指令引數」間歧義、空白或 & 的
		字元在「欄位值」與「規則語法」間歧義——程式選取較寬鬆、風險較高的詮釋，使用者以為輸入會照自己直覺的較受限方式
		被看待。後果是輸入被以比使用者預期更廣、更不安全的方式擴充或執行，牽扯到存取規則、命令建構或權限邊界時就可能
		出漏洞。修法是遇歧義一律提示使用者選擇明確的詮釋，並預設採用「受限、安全」的解讀，不明確就拒絕而非代為猜測。`,
		problem: `// 不安全寫法:輸入 , 分隔被當單一字串餵進 exec,歧義處直接選了不安全的解讀
function runFilters(input) {
    // 是把 "a,b" 當清單由 a 與 b 兩項?還是把整串送給 shell?這裡選了後者
    const cmd = "apply-filter " + input;   // input 含 ; rm -rf 會被長驅直入
    shell.exec(cmd);                       // 沒有向使用者確認或選安全詮釋
}`,
		fixed: `// 安全寫法:明確界定語義,歧義時用陣列一項項執行並避開 shell 詮釋
function runFilters(input) {
    const items = input.split(",").map(s => s.trim());  // 明確:以清單解析
    if (items.some(containsSpecial)) {
        return reject("輸入含非法字元，不允許執行");
    }
    items.forEach(item => apply(item));     // 逐項執行,不送進 shell 解讀
}`,
		patch: `@@
- function runFilters(input) {
-    const cmd = "apply-filter " + input;
-    shell.exec(cmd);
- }
+ function runFilters(input) {
+    const items = input.split(",").map(s => s.trim());
+    if (items.some(containsSpecial)) return reject("輸入含非法字元");
+    items.forEach(item => apply(item));
+ }`,
		refs: ['CWE-450', 'OWASP'],
		tags: ['ambiguous-input', 'ui', 'parsing'],
	},
	{
		id: 'CWE-454',
		name: 'External Initialization of Trusted Variables or Data Stores',
		lang: 'go',
		status: 'Complete',
		what: `用外部輸入初始化受信任的變數或資料儲存。程式在初始化某些關鍵的內部變數或資料儲存（例如判斷身分的旗標、
		管理員清單、權限位元、信任的網域表）時，直接採用「可被未受信任的參與者修改」的輸入。例如把某個使用者可改的
		環境變數、Cookie、請求標頭、或全域設定當成受信任的安全狀態的種子。後果是攻擊者只要控制那項輸入，就可以把受信任
		資料初始化成「對自己有利」的值——把自己標成管理員、把自己納入信任清單、或關閉某項安全旗標，繞過後續依賴該狀態
		的所有檢查。成因是低估了「被用來初始化受信任值」的輸入，把它當成不變的內部事實。修法是受信任變數／資料儲存的
		初始值必須來自受控的、不可被攻擊者改動的來源；外部輸入只能在通過明確驗證後，才被允許影響那類資料。`,
		problem: `// 不安全寫法:用使用者可控的標頭當「是否管理員」的真值來源
func isAdmin(r *http.Request) bool {
    // X-Admin 標頭由使用者自行送出,卻被拿來初始化受信任的管理員旗標
    return r.Header.Get("X-Admin") == "yes"
}`,
		fixed: `// 安全寫法:受信任旗標只可能來自伺服器端可驗證的權威,外部輸入不可影響
func isAdmin(r *http.Request) bool {
    sess, err := sessions.Get(r, "auth")
    if err != nil { return false }
    return sess.Claims.Admin == true   // 由伺服器端簽發的身分判定,非使用者可控
}`,
		patch: `@@
  func isAdmin(r *http.Request) bool {
-    return r.Header.Get("X-Admin") == "yes"
+    sess, err := sessions.Get(r, "auth")
+    if err != nil { return false }
+    return sess.Claims.Admin == true
  }`,
		refs: ['CWE-454', 'OWASP'],
		tags: ['trusted-variable', 'initialization', 'request-header', 'privilege'],
	},
	{
		id: 'CWE-458',
		name: 'DEPRECATED: Incorrect Initialization',
		lang: '-',
		status: 'Deprecated',
		what: `本條目已被官方標記廢棄（DEPRECATED）。它的名稱與描述原本並不相符：描述部分重複了 CWE-454（外部輸入初始化
		受信任變數），而名稱又暗示一個更抽象、與初始化相關的普遍問題。由於兩者碰撞造成歧義，官方已將本條廢棄。若你在處理
		的是「外部輸入初始化受信任資料」請用 CWE-454；若你在處理的是更普遍的初始化錯誤，請改參照 CWE-665（"Improper
		Initialization"）這類更抽象的初始化「Complete／上層」標記問題。保留此條僅維持 id 連續。`,
		problem: `// 已廢棄 -> 初始化相關問題請依情境改用 CWE-454 或 CWE-665`,
		fixed: `// 已廢棄 -> 外部受信任資料初始化用 CWE-454;一般初始化錯誤用 CWE-665`,
		patch: `@@
  // This entry is deprecated; refer to CWE-454 or CWE-665 for initialization issues.`,
		refs: ['CWE-458', 'CWE-454', 'CWE-665'],
		tags: ['deprecated', 'initialization'],
	},
	{
		id: 'CWE-460',
		name: 'Improper Cleanup on Thrown Exception',
		lang: 'python',
		status: 'Complete',
		what: `拋出例外時清理不當。程式在某個操作中已改動了狀態或佔用了資源（開啟檔案、持鎖、更新全域、修改交易），接著
		卻拋出了例外；而在例外路徑上，程式沒有做清理、或做了錯誤的清理——該釋放的鎖沒釋、該回滾的變更沒回滾、已經
		半讀半寫的狀態就那樣留在原處。後果是程式在例外的中斷點上留下「不一致的狀態與控制流」：資源繼續被佔用、全域或
		資料庫處在半套更新、後續所有走過這裡的程式心裡對「應該一致的狀態」做出錯誤假設，產生錯執行序甚至崩潰／死結。
		修法是讓清理動作對每條路徑（正常＋每一種退出方式）都保證執行：用 finally／defer／with / RAII 把「釋放與回滾」
		放進保證被呼叫的地方，讓例外留下整潔狀態。`,
		problem: `// 不安全寫法:拋例外前已改動全域狀態,卻沒回滾,例外後狀態壞掉
state = {"committed": False}
def do_payment(amount):
    state["committed"] = True      # 先改全域狀態
    if amount < 0:
        raise ValueError("bad amount")   # 拋例外:state 已被標成 committed
    return finalize(amount)        # 之後程式以為 committed=True 但其實沒送`,
		fixed: `// 安全寫法:只在「準備好」後才提交全域狀態,例外前先清理還原
def do_payment(amount):
    if amount < 0:
        raise ValueError("bad amount")   # 失敗先擋,不碰全域
    state["committed"] = False
    try:
        rc = finalize(amount)            # 實際處理
    except Exception:
        state["committed"] = False       # 例外路徑回滾,不留半套狀態
        raise
    finally:
        release_locks()                  # 保證每條路徑都釋放資源
    state["committed"] = True`,
		patch: `@@
-    state["committed"] = True
-    if amount < 0:
-        raise ValueError("bad amount")
-    return finalize(amount)
+    if amount < 0:
+        raise ValueError("bad amount")
+    state["committed"] = False
+    try:
+        rc = finalize(amount)
+    except Exception:
+        state["committed"] = False
+        raise
+    finally:
+        release_locks()
+    state["committed"] = True`,
		refs: ['CWE-460', 'OWASP'],
		tags: ['cleanup', 'exception', 'resource-release', 'state'],
	},
	{
		id: 'CWE-462',
		name: 'Duplicate Key in Associative List (Alist)',
		lang: 'python',
		status: 'Complete',
		what: `關聯清單（associative list / alist）中有重複的鍵。關聯清單是以成對 (key, value) 串成的清單式關聯結構，
		與字典不同，它允許同一個鍵出現多次；當程式以「以鍵查值」的慣用查找（通常回傳第一個相符者）運作時，重複鍵就會
		被「非唯一」的鍵弄混——查到的值可能不是最新、也不一定是預期的值，讓呼叫端誤把這條記錄當成唯一定義。後果是不同寫入
		位置對同鍵各自加了一筆，後續讀取互相打架，產生意料之外的覆蓋或誤判。成因是注入／收集資料時沒有先檢查鍵是否已存在
		就直接 push 一筆新的。修法是在往關聯清單插入鍵之前先查該鍵是否已存在，存在的話以「新增失敗或更新既有項」取代
		「多塞一份」；或直接改用可保證鍵唯一的字典／map 結構。`,
		problem: `// 不安全寫法:把鍵為"weight"的項目連塞兩次,alist 有重複鍵,查值抓錯/抓到舊值
# alist 是 (key, value) 成對的清單
alist = []
def set_alist(k, v):
    alist.append((k, v))        # 不查是否已存在,直接多塞一筆
set_alist("weight", 10)
set_alist("weight", 99)         # 現在有兩個 weight,沒有唯一性
def get(k):
    for a, b in alist:
        if a == k:
            return b            # 回傳第一個:還是 10,不是最新 99`,
		fixed: `// 安全寫法:新增前先查鍵,已存在就更新既有項,不產生重複鍵
def set_alist(alist, k, v):
    for i, (a, b) in enumerate(alist):
        if a == k:
            alist[i] = (k, v)   # 已存在 => 更新,不新增
            return
    alist.append((k, v))        # 不存在才新增
def get(alist, k):
    for a, b in alist:
        if a == k:
            return b
    return None`,
		patch: `@@
  def set_alist(k, v):
-    alist.append((k, v))
+    for i, (a, b) in enumerate(alist):
+        if a == k:
+            alist[i] = (k, v)
+            return
+    alist.append((k, v))`,
		refs: ['CWE-462', 'OWASP'],
		tags: ['duplicate-key', 'alist', 'associative-list'],
	},
	{
		id: 'CWE-463',
		name: 'Deletion of Data Structure Sentinel',
		lang: 'c',
		status: 'Complete',
		what: `誤刪資料結構的哨兵節點（sentinel）。許多資料結構——尤其是鏈結串列、循環緩衝——在邊界放一個「哨兵」節點
		（head/tail 或 dummy）來作為巡訪的錨點與迴圈終止條件，程式邏輯依賴它「永遠存在」。若某一支移除／清除邏輯在處理時
		把這個哨兵節點也當成一般節點刪掉，結構就會失去終止或定界的依據：之後的遍歷可能越界走進隨機記憶體、迴圈無法收尾、
		或對懸空的頭指標操作。後果是嚴重的邏輯錯亂——無限迴圈、記憶體損毀、甚至崩潰。成因是移除程式沒先判別「這個節點
		是哨兵」就動手。修法是在任何刪除動作前檢查目標是否為結構指定的哨兵，永遠不把哨兵當成資料節點來解自入鏈，讀寫
		與清空都以「保留哨兵」為前提。`,
		problem: `// 不安全寫法:移除節點時沒判斷是否為哨兵,把 head 哨兵也設成 NULL 丟掉
#include <stdlib.h>
typedef struct node { int v; struct node *next; } Node;
Node *g_head;                  // 哨兵(永不變,只能有它當錨)
void remove_node(Node *target) {
    for (Node **p = &g_head; *p; p = &(*p)->next) {
        if (*p == target) {
            *p = target->next;   // 若 target==g_head,等於搞壞哨兵
            free(target);
            return;
        }
    }
}`,
		fixed: `// 安全寫法:明定哨兵不可刪,移除只準清除資料節點
void remove_node_safe(Node **head, Node *target) {
    if (target == *head) return;         // 絕不允許刪哨兵節點
    for (Node **p = &(*head)->next; *p; p = &(*p)->next) {
        if (*p == target) {
            *p = target->next;
            free(target);                // 只刪資料節點,哨兵始終保留
            return;
        }
    }
}`,
		patch: `@@
  void remove_node(Node *target) {
+    if (target == g_head) return;        // 不允許刪哨兵
      for (Node **p = &g_head; *p; p = &(*p)->next) {
          if (*p == target) {
              *p = target->next;
              free(target);`,
		refs: ['CWE-463', 'OWASP'],
		tags: ['sentinel', 'linked-list', 'data-structure'],
	},
	{
		id: 'CWE-464',
		name: 'Addition of Data Structure Sentinel',
		lang: 'c',
		status: 'Complete',
		what: `意外加入資料結構的哨兵節點。資料結構在正常資料之外誤「多加一個哨兵」——例如把一個本当作「指示邊界／終止」
		的特殊值（0、-1、標示尾端的標記）當成一般資料元素一起插入，或用戶提供的資料含了與哨兵相同的值卻被直接存進去。
		於是後續邏輯在遇到「以為是邊界」時，因為真正的資料裡混進了一顆假哨兵而提早停住或誤判終止：在該停的地方沒停、
		在不該停的地方停了，遍歷被中斷在一個「其實是資料」的節點上。成因是沒有對輸入做與哨兵值的隔離／編碼。修法是
		確實隔離哨兵與資料：以「獨特的哨兵位址或旗標」而非「與資料撞車的數值」作為邊界，或在存入前檢查／編碼掉所有與
		哨兵相同的值。`,
		problem: `// 不安全寫法:使用 0 當哨兵,卻允許 0 當一般資料混進結構,遍歷被假哨兵截斷
int *arr; int n = 0;
void push(int v) {
    if (v == 0) return;               // 0 是哨兵,被當一般資料存進去 => 假哨兵
    arr[n++] = v difficulty;           // 之後的迴圈以 0 判斷結尾會被資料截斷
}`,
		fixed: `// 安全寫法:用獨立長度欄記錄實際元素數,不以值當終止哨兵,或先編碼哨兵
int *arr; size_t len = 0, cap = 0;
void push_sentinel_aware(int v) {
    if (len + 1 > cap) resize(&cap);
    if (v == 0) { arr[len++] = ENCODED_ZERO; }   // 把與哨兵撞車的值編碼,不當一般值
    else { arr[len++] = v; }
}
// 遍歷以 len 為界,不再靠「值==0」判斷結尾,假哨兵不再搞斷流程`,
		patch: `@@
- void push(int v) {
-    if (v == 0) return;
-    arr[n++] = v;
- }
+ void push_sentinel_aware(int v) {
+    if (v == 0) arr[len++] = ENCODED_ZERO;
+    else arr[len++] = v;
+ }`,
		refs: ['CWE-464', 'OWASP'],
		tags: ['sentinel', 'data-structure', 'terminator'],
	},
	{
		id: 'CWE-466',
		name: 'Return of Pointer Value Outside of Expected Range',
		lang: 'c',
		status: 'Complete',
		what: `回傳了預期範圍之外的指標值。函式回傳一個指標，而該指標所指的記憶體落在「呼叫端預期該指標會指的緩衝區」之外。
		可能因為回傳的是內建緩衝被重新配置後的新位址、算出來的位置推進逾位、或回傳了會指向緩衝前後位置的指標。呼叫端接著
		以這個「外號範圍」的指標去讀寫，便會超過原本該操作的緩衝邊界：讀到相鄰記憶體洩漏資料、寫入覆蓋無關區域，甚至觸發
		segfault。成因是函式沒能保證回傳的指標落在對應的記憶體物件的合法範圍內。修法是回傳指標前先驗證它指向的位址落在
		預期的緩衝範圍內（起點…起點+可用長度），並明確界定「函式慝該回傳的位址範圍」，超過就回報錯誤。`,
		problem: `// 不安全寫法:依 k 回傳陣列內「任一位址」,k 可被外部送超界,回傳超出緩衝的指標
#include <stddef.h>
static int g_buf[100];
static size_t g_len = 92;
int *element_at(int k) {
    return &g_buf[k];           // k>=len || k<0 => 回傳值落在預期範圍外
}`,
		fixed: `// 安全寫法:回傳前驗證位址落在 [g_buf, g_buf+g_len) 內,否則回傳 NULL
#include <stddef.h>
static int g_buf[100];
static size_t g_len = 92;
int *element_at(int k) {
    int *p = &g_buf[k];
    if (p < g_buf || p >= g_buf + g_len) return NULL;  // 檢查回傳範圍
    return p;
}`,
		patch: `@@
  int *element_at(int k) {
-    return &g_buf[k];
+    int *p = &g_buf[k];
+    if (p < g_buf || p >= g_buf + g_len) return NULL;
+    return p;
  }`,
		refs: ['CWE-466', 'OWASP'],
		tags: ['pointer', 'range', 'out-of-bounds'],
	},
	{
		id: 'CWE-467',
		name: 'Use of sizeof() on a Pointer Type',
		lang: 'c',
		status: 'Complete',
		what: `對指標型別使用 sizeof()。程式呼叫 sizeof() 卻傳給它一個「指標型別（或通道為陣列參數而衰變成指標的變數）」，
		而不是指標所指的資料。get 的是「指標本身的位元組數」（在常見 64 位元平台上通常是 8），而程式如果您打算算的是
		「被指到的資料要佔幾格」，就會得到一個比真實小得多的值。常見如對函式參數 int a[]（其實是 int *a）做 sizeof(a)，
		得到的不是陣列大小而是 8；拿這個值去傳給 memcpy 的長度或配置大小，便整個錯誤計算，造成記憶體配置太小、拷貝半截或
		越界。修法是整個佈長度由「實際配置時知道的大小」另行帶上，或用 sizeof(array) 於定義點取真的陣列 size，別對已衰變
		指標做 sizeof。`,
		problem: `// 不安全寫法:sizeof(a) 用到已衰變成指標的函式參數,拿到的是指標大小(如 8)
#include <string.h>
void copy_buf(int a[]) {          // a 實為 int *a, sizeof(a) 是 8
    int tmp[100];
    memcpy(tmp, a, sizeof(a));    // 只拷 8 個位元組,不是整個陣列
}`,
		fixed: `// 安全寫法:明確以參數帶入元素個數,不用 sizeof 算已衰變指標
#include <string.h>
void copy_buf(const int *a, size_t count) {   // count 由呼叫端真正知道
    int tmp[100];
    if (count > 100) return;
    memcpy(tmp, a, count * sizeof(int));      // 用元素數 * sizeof(int)
}`,
		patch: `@@
- void copy_buf(int a[]) {
-    int tmp[100];
-    memcpy(tmp, a, sizeof(a));
- }
+ void copy_buf(const int *a, size_t count) {
+    int tmp[100];
+    if (count > 100) return;
+    memcpy(tmp, a, count * sizeof(int));
+ }`,
		refs: ['CWE-467', 'OWASP'],
		tags: ['sizeof', 'pointer', 'array-decay'],
	},
	{
		id: 'CWE-468',
		name: 'Incorrect Pointer Scaling',
		lang: 'c',
		status: 'Complete',
		what: `指標縮放（pointer scaling）不正確。在 C/C++ 中，對指標做數學運算（+、-）時，位移量會被「隱式地以被指型別大小
		縮放」——即 &a[1] 實質上是往後跳 sizeof(elem) 個位元組。程式常在兩種情境出錯：把「位元組偏移」當成「元素偏移」
		去加其實要乘上元素大小；或相反，把「元素數」直接拿來當位元組偏移使用。於是指針就跳到了「根本不是目標元素」的
		記憶體位置，往錯格子讀寫，得到越界或讀到相鄰的資料。修法是在腦中明確區分「元素數」與「位元組數」：算位元組就先
		轉成位元組型別或乘元素大小，算元素就只是 +i，並讓指標運算的單位一致。`,
		problem: `// 不安全寫法:誤把位元組偏移當元素偏移,跳的格子與預期不符
#include <wchar.h>
wchar_t wstr[64];
void set_pos(wchar_t *base, long byte_off) {
    wchar_t *p = base + byte_off;   // byte_off 乘上 sizeof(wchar_t),不是指到預期字元
    *p = 0;
}`,
		fixed: `// 安全寫法:明確以元素索引運算,或先轉位元組指標再換算
#include <wchar.h>
wchar_t wstr[64];
void set_char_at(wchar_t *base, size_t index) {   // 以元素索引運算
    if (index >= 64) return;
    wchar_t *p = base + index;      // +的是元素數,恰好一個 wchar_t
    *p = 0;
}`,
		patch: `@@
- void set_pos(wchar_t *base, long byte_off) {
-    wchar_t *p = base + byte_off;
-    *p = 0;
- }
+ void set_char_at(wchar_t *base, size_t index) {
+    if (index >= 64) return;
+    wchar_t *p = base + index;
+    *p = 0;
+ }`,
		refs: ['CWE-468', 'OWASP'],
		tags: ['pointer-scaling', 'arithmetic', 'wchar'],
	},
	{
		id: 'CWE-469',
		name: 'Use of Pointer Subtraction to Determine Size',
		lang: 'c',
		status: 'Complete',
		what: `用指標相減來推得大小。程式用「一個指標減另一個指標」所得到的結果當作資料的大小，但這個演算法只有在兩個指標
		都指向「同一塊記憶體區塊」（同一個配置／陣列）內部時才是定義好、正確的。當兩個指標來自不同的記憶體區塊（不同一次的
		malloc、不同陣列、或混了位元組與元素指標）時，相減本身是未定義行為，得到的「大小」數值也完全不可信。拿這個錯的
		大小去當 memcpy 長度、迴圈界或配置量，就會讀寫到別的地方、溢出或洩漏。修法是不要靠「指標相減」跨區塊推尺寸：大小
		要在建立該區塊時就另外載上並帶到使用處，若必須相減，先確認兩指標落在同一個可定義的區塊內。`,
		problem: `// 不安全寫法:拿存放不同調節的兩個指標相減算長度,結果未定義
#include <string.h>
static char bufA[256];
static char bufB[512];
void leak_diff(void) {
    char *e = bufA + sizeof(bufA);
    size_t n = (size_t)(e - bufB);   // bufA 與 bufB 不同區塊,相減未定義
    memcpy(bufB, bufA, n);           // n 不可信 => 越界拷
}`,
		fixed: `// 安全寫法:長度由配置當下另外記載,不靠跨指標相減推得
#include <string.h>
static char bufA[256];
void copy_known(const char *src, size_t n) {
    if (n > sizeof(bufA)) return;    // 大小由呼叫端/容量欄位明確提供
    memcpy(bufA, src, n);
}`,
		patch: `@@
-    size_t n = (size_t)(e - bufB);
-    memcpy(bufB, bufA, n);
+    if (n > sizeof(bufA)) return;
+    memcpy(bufA, src, n);`,
		refs: ['CWE-469', 'OWASP'],
		tags: ['pointer-subtraction', 'size', 'undefined-behavior'],
	},
	{
		id: 'CWE-473',
		name: 'PHP External Variable Modification',
		lang: 'php',
		status: 'Complete',
		what: `PHP 外部變數修改。PHP 應用沒有妥善保護其變數免受外部來源（查詢參數、Cookie、HTTP 標頭、甚至環境變數）
		的篡改，其中最危險的是舊式 register_globals 行為——把外部輸入自動展開成同名的全域變數。一旦啟用這類機制或寫法，
		攻擊者就能直接用 ?admin=1 把原本應由伺服器內部設定的 $admin 蓋成自己給的值。於是程式內部那些「看似受信任、由
		程式自己設定的變數」被外部資料靜默覆寫，衍生出權限提升、繞過驗證、SQL／命令注入等一大堆本來不會存在的弱點。成因是
		「變數值」與「外部輸入」的名稱空間沒有隔離。修法是關閉 register_globals、一律經由 $_GET／$_POST／$_COOKIE
		顯式取得並驗證輸入，且不把未驗證的外部值直接覆寫進內部狀態變數。`,
		problem: `// 不安全寫法:依賴 register_globals,外部 ?admin=1 直接把內部 $admin 蓋掉
// php.ini: register_globals = On  (舊式危險設定)
if ($admin) {            // $admin 來自 ?admin=1,不是程式自己的判斷
    grant_admin_access();
} slog
// 攻擊者: GET /page.php?admin=1 => admin 權限直接被開啟`,
		fixed: `// 安全寫法:輸入一律顯式取用並驗證,內部狀態變數不許外部直接覆寫
$adminMode = false;
if (isset($_SESSION['role']) && $_SESSION['role'] === 'admin') {
    $adminMode = true;               // 權限只來自可驗證的工作階段，非 query 參數
}
if ($adminMode) {
    grant_admin_access();
}`,
		patch: `@@
- if ($admin) { grant_admin_access(); }
+ $adminMode = (isset($_SESSION['role']) && $_SESSION['role'] === 'admin');
+ if ($adminMode) { grant_admin_access(); }`,
		refs: ['CWE-473', 'OWASP'],
		tags: ['register-globals', 'external-input', 'variable-injection', 'php'],
	},
	{
		id: 'CWE-475',
		name: 'Undefined Behavior for Input to API',
		lang: 'c',
		status: 'Complete',
		what: `給 API 的輸入造成未定義行為。某個函式（尤其 C 標準庫或底層 API）的行為只有在「控制參數被設為特定值」時才有
		定義；給它「未指定／不合法」的控制參數，就落進未定義行為——手段例如依賴某個會隨實作而不同的邊界值、把範圍外的值傳給
		API 當長度／模式／旗標。未定義行為不會有「可預測的安全失敗」：從回傳垃圾值、編譯器自由優化把程式改得千奇百怪、
		到記憶體越界都可能發生，甚至在某些平台上可利用。修法是只用文件明確保證受支援的控制參數值，或在呼叫前先驗證輸入落在
		該 API 定義的範圍內，不依賴「碰巧能動」的值。`,
		problem: `// 不安全寫法:把範圍外長度直接丟給 API,行為未定義
#include <string.h>
void tail_copy(const char *src, size_t extra) {
    size_t off = strlen(src) - extra;      // extra 比 strlen(src) 大 => 下溢未定義
    char *p = (char *)memchr(src, 'x', off);
    if (p) write(1, p, off);               // off 已不可信
}`,
		fixed: `// 安全寫法:呼叫前把控制參數收斂到 API 定義的合法範圍
#include <string.h>
void tail_copy(const char *src, size_t extra) {
    size_t n = strlen(src);
    if (extra > n) extra = n;              // 先守住合法範圍才進 API
    char *p = (char *)memchr(src, 'x', n - extra);   // 定義好的呼叫
    if (p) write(1, p, n - extra);
}`,
		patch: `@@
-    size_t off = strlen(src) - extra;
-    char *p = (char *)memchr(src, 'x', off);
+    size_t n = strlen(src);
+    if (extra > n) extra = n;
+    char *p = (char *)memchr(src, 'x', n - extra);`,
		refs: ['CWE-475', 'OWASP'],
		tags: ['undefined-behavior', 'api', 'control-parameter'],
	},
	{
		id: 'CWE-479',
		name: 'Signal Handler Use of a Non-reentrant Function',
		lang: 'c',
		status: 'Complete',
		what: `訊號處理常式呼叫了不可重入（non-reentrant）的函式。訊號可分在任何時刻中斷主流程，可能正值主程式正跑到
		某個非同步安全不可的函式內部；此時若 signal handler 卻去呼叫非 reentrant ／非 async-signal-safe 的函式
		（printf、malloc、strtok、gettimeofday 或自家共享狀態的函式），就會中斷掉原本函式的內部狀態、或兩者同時改動
		同一份共享資料，造成狀態被交錯破壞。後果是資料損毀、記憶體被覆寫、死結，甚至又是第二次訊號重入。修法是讓訊號
		handler 只呼叫 async-signal-safe 的函式（write、sig_atomic_t 操作、signal-safe 家族），並避免在裏頭存取共享
		非 atomic 狀態，把重活留回由 volatile sig_atomic_t 旗標通知主流程處理。`,
		problem: `// 不安全寫法:handler 內呼叫 non-reentrant 的 printf/malloc
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
void handler(int sig) {
    printf("got %d\\n", sig);      // printf 非 async-signal-safe
    char *p = (char *)malloc(16);  // malloc 同樣 non-reentrant => 狀態損毀風險
    free(p);
}
int main(void) {
    signal(SIGUSR1, handler);
    while (1) { printf("hi %d\\n", 0); }   // 主流程 printf 被打斷時 handler 也在 printf
}`,
		fixed: `// 安全寫法:handler 只設 volatile sig_atomic_t 旗標,再回主流程安全呼叫
#include <signal.h>
static volatile sig_atomic_t got_signal = 0;
void handler(int sig) { (void)sig; got_signal = 1; }   // async-signal-safe 最小動作
int main(void) {
    signal(SIGUSR1, handler);
    while (1) {
        if (got_signal) { got_signal = 0;
            printf("handled\\n"); }      // 真正的輸出在主流程做
    }
}`,
		patch: `@@
- void handler(int sig) {
-    printf("got %d\\n", sig);
-    char *p = (char *)malloc(16); free(p);
- }
+ static volatile sig_atomic_t got_signal = 0;
+ void handler(int sig) { (void)sig; got_signal = 1; }
  int main(void) {
      signal(SIGUSR1, handler);
-    while (1) { printf("hi %d\\n", 0); }
+    while (1) { if (got_signal) { got_signal = 0; printf("handled\\n"); } }
  }`,
		refs: ['CWE-479', 'SEI CERT'],
		tags: ['signal-handler', 'non-reentrant', 'async-signal-safe'],
	},
	{
		id: 'CWE-480',
		name: 'Use of Incorrect Operator',
		lang: 'c',
		status: 'Complete',
		what: `使用了錯誤的運算子。程式不小心選用與意圖相反的運算子（== 與 =、&& 與 &、> 與 >=、! 與 != 等），使邏輯在
		與安全相關的地方被悄悄改動。許多這類錯誤在 C 語言的「assignment 當條件」時尤其陰險：「if (x = y)」不是比對此較 x==y
		而是先指派再判斷真偽，遇到 y 為 0 就整個判定錯。後果是條件與真實意圖相反——該通過沒通過、該擋的沒擋——把權限、驗證
		或重要旗標的判斷導向錯誤的分支，形成可利用的安全缺陷。修法是刻意區分「指派」與「比較」：比較一律用 ==，對可能誤打
		的指派當條件用編譯器／靜態檢查，並對「只允許常數在左」的比較撰寫式（如 y == x）搭配 -Wall 讓誤寫被編譯器攔下。`,
		problem: `// 不安全寫法:比較誤打成指派,flag 被塞 0 時整個驗證被判定為失敗/被繞過
#include <string.h>
int verify(const char *user) {
    int flag = is_allowed(user);
    if (flag = 0) return 0;     // 錯:把 0 指派給 flag,條件永遠為假
    return 1;                   // 永遠回傳允許 => 驗證被繞過
}`,
		fixed: `// 安全寫法:比較用 ==,並把常數放左側讓誤寫被編譯器抓到
#include <string.h>
int verify(const char *user) {
    int flag = is_allowed(user);
    if (flag == 0) return 0;    // 正確比較
    return 1;
}`,
		patch: `@@
-    if (flag = 0) return 0;
+    if (flag == 0) return 0;`,
		refs: ['CWE-480', 'SEI CERT'],
		tags: ['incorrect-operator', 'comparison', 'assignment'],
	},
	{
		id: 'CWE-481',
		name: 'Assigning instead of Comparing',
		lang: 'c',
		status: 'Complete',
		what: `想比較卻用了指派。程式在「本想比較兩值」的地方誤用了賦值運算子 =，把右邊的值指派給左邊變數，再以「指派結果
		的非零／零」當成條件的真偽。這是 C 族語言最著名的筆誤：「if (pin = stored_pin)」其實先蓋掉了 pin 再把 stored_pin
		的數值當條件判斷。若右邊是可被攻擊者塞成 0 或非 0 的值，判斷結果就和「本來要比對是否相等」完全無關，驗證可能
		永遠過或永遠不過，權限邊界直接失效。修法是把比較換成 ==；最佳防線是寫成「常數在左」（例如 if (stored_pin == pin)）
		讓「把常數當目標指派」必然出錯，並開 -Wall！使編譯器回報「使用指派當條件」的提示。`,
		problem: `// 不安全寫法:if(pin = stored_pin) 誤把比較變成指派
#include <string.h>
int check_pin(const char *pin) {
    const char *stored = "1234";
    if (pin = stored)            // 錯:把 stored 指派給 pin,再以非空指標判斷
        return 1;                // 指標非空 => 永遠通過
    return 0;
}`,
		fixed: `// 安全寫法:比較換用 ==,常數放左側讓編譯器攔誤寫
#include <string.h>
int check_pin(const char *pin) {
    const char *stored = "1234";
    if (stored == pin)           // 常數在左的 == :誤寫成 = 必被編譯器攔下
        return 1;
    return 0;
}`,
		patch: `@@
-    if (pin = stored)
+    if (stored == pin)`,
		refs: ['CWE-481', 'SEI CERT'],
		tags: ['assignment', 'comparison', '=='],
	},
	{
		id: 'CWE-482',
		name: 'Comparing instead of Assigning',
		lang: 'java',
		status: 'Complete',
		what: `想指派卻用了比較。程式在「本想把值指派給變數」的地方誤用比較運算子 ==，比較結果是一介 boolean，並不會改變
		左邊變數的值。典型是初始化或更新變數時用了 == 而不是 =，於是該被設定的變數根本沒被設定，維持原預設或上一次殘留的
		值；而比較本身又可能因為型別不同而「有意義地」回傳 false。後果是安全關鍵狀態沒有被真正設定——該開啟的防護沒開、
		該更新的旗標沒更新，程式仍把它當成預期值，因而在錯誤的前提下做出允許／拒絕決定。修法是確認每個打算寫入的動作真的
		使用指派 =；若左邊是物件而想設定欄位或物件，用恰當的 setter，並仰賴型別檢查與靜態策略避免 == 誤用在「要指派」處。`,
		problem: `// 不安全寫法:把 boolean 比較結果放進變數,想指派卻用了 ==,旗標沒被更新
public boolean updateGuard(boolean enforce) {
    boolean enforceEnabled = false;
    enforceEnabled == enforce;      // 錯:只是比較,enforceEnabled 永遠是 false
    return enforceEnabled;          // 使用者想開啟防護,程式卻沒設定它
}`,
		fixed: `// 安全寫法:把值指派進變數用 =,讓旗標真的被更新
public boolean updateGuard(boolean enforce) {
    boolean enforceEnabled;
    enforceEnabled = enforce;       // 正確指派:旗標被設為想要的值
    return enforceEnabled;
}`,
		patch: `@@
-    enforceEnabled == enforce;
+    enforceEnabled = enforce;`,
		refs: ['CWE-482', 'SEI CERT'],
		tags: ['comparison', 'assignment', '=='],
	},
	{
		id: 'CWE-483',
		name: 'Incorrect Block Delimitation',
		lang: 'c',
		status: 'Complete',
		what: `區塊邊界定界不正確。程式「想要涵蓋 2 行以上」的一段程式碼，沒有用花括號等明確的定界把它圍成單一區塊，只靠
		縮排或物件語言規則把「多行」誤當成在一個區塊內；而在以「單一語句為區塊單元」的語言（如 C 的 if/for/while 不加大括號）
		裡，只有緊接的第一行屬於該區塊，後續幾行其實在區塊之外。最典型是
		「if (cond) action1(); action2();」中只有 action1 受到 if 管，action2 無論條件都會執行。後果是安全判斷的「生效範圍」
		與程式員所想的狹窄了整整幾行，該受保護的動作仍在外頭照跑，形成邏輯與權限漏洞。修法是任何需要包 2 行以上的 if／迴圈
		都確實加上花括號 {}，並以縮排與之對齊。`,
		problem: `// 不安全寫法:if 沒加大括號,只有第一行進到條件,第二行任何情況都會執行
void perform_admin(const char *cmd, int trusted) {
    if (trusted)
        execute(createProc(cmd));     // 只有這行受 if 保護
        log_access(cmd);              // 自以為也是; 其實任何情況都執行
}`,
		fixed: `// 安全寫法:用花括號把整個區塊明確圍起來,每一行都受條件保護
void perform_admin(const char *cmd, int trusted) {
    if (trusted) {
        execute(createProc(cmd));
        log_access(cmd);              // 現在兩行都在 if 區塊內
    }
}`,
		patch: `@@
-    if (trusted)
-        execute(createProc(cmd));
-        log_access(cmd);
+    if (trusted) {
+        execute(createProc(cmd));
+        log_access(cmd);
+    }`,
		refs: ['CWE-483', 'SEI CERT'],
		tags: ['block-delimitation', 'braces', 'improper-block'],
	},
];
