// CWE chunk — 類別:低階功能、記憶體與資源管理、輸入過濾與並行安全
// code 內避免 `${` 以免汙染反引號字串。
export default [
	{
		id: 'CWE-695',
		name: 'Use of Low-Level Functionality',
		lang: 'python',
		status: 'Complete',
		what: `使用規範／框架明令禁止的低階功能。產品運作時本該待在某個框架或平台提供的抽象層內、遵守其定義的規範，卻為了省事或追求
效能直接呼叫了規範明確禁止的低階能力（例如手工寫機器碼、直接呼叫裸 syscall、繞過框架的型別檢查去碰底層記憶體）。成因是開發者
認為「這樣更快更彈性」，卻沒意識到這些低階路徑同時把框架當成安全邊界、輸送管線或審計點的保護一起繞過了。後果是安全措施形同虛設、
程式可移植性崩壞，且任何驗證、授權或結構不變式在低階層都被略過。建議只在非常明確的小範圍內使用低階功能並以文件與註解記錄理由，
其餘一律透過框架提供的正常 API 完成，並在 code review／build 階段用規則擋住這類呼叫。`,
		problem: `# 不安全寫法：繞過框架的審計與型別檢查,直接呼叫低階 syscall
import ctypes, os

# 框架要求所有檔案寫入必須經過稽核層,這裡卻用 libc 直接寫
libc = ctypes.CDLL("libc.so.6")
fd = libc.open(b"/var/run/db.bin", os.O_RDWR)
libc.write(fd, b"gamble", 6)   # 繞過框架的 access log`,
		fixed: `# 安全寫法：一律走框架提供的 API,讓其負責稽核與權限
from framework import store

store.write("/var/run/db.bin", b"gamble")   # 經過框架的稽核與授權`,
		patch: `@@
-import ctypes, os
-
-# 框架要求所有檔案寫入必須經過稽核層,這裡卻用 libc 直接寫
-libc = ctypes.CDLL("libc.so.6")
-fd = libc.open(b"/var/run/db.bin", os.O_RDWR)
-libc.write(fd, b"gamble", 6)
+from framework import store
+
+store.write("/var/run/db.bin", b"gamble")`,
		refs: ['CWE-695', 'OWASP'],
		tags: ['low-level', 'framework-bypass', 'abstraction'],
	},
	{
		id: 'CWE-698',
		name: 'Execution After Redirect (EAR)',
		lang: 'python',
		status: 'Complete',
		what: `重導向後仍繼續執行的 EAR 弱點。web 應用程式決定把使用者送回另一處（登入頁、錯誤頁、外部站台）時以 redirect 結尾，但
函式並未 return／exit，底下的程式碼照樣跑。常見成因是把 redirect 與後續處理寫在同一函式裡、少了明確的 return，或把需要「驗證成
功才做」的工作放在 redirect 之後。後果是身分未被驗證的請求也可能通過 redirect 這段、繼續執行後續的敏感動作（寫資料、建立權限），
把「先驗證再處理」的安全順序徹底 bypass。建議把 redirect 設計成流程的最後一步，若需要提前離場務必 return／exit，或把所有後續
處理移到獨立的驗證衛兵之後，若驗證失敗就直接 return 而非僅回 302。`,
		problem: `# 不安全寫法：未驗證就執行的動作與 redirect 並存,且 redirect 後不回傳
def cancel(acct, confirm):
    if not confirm:
        redirect("/confirm")       # 只是送出 302,函式繼續往下跑
    account.cancel(acct)          # 未確認也照樣取消帳戶 => EAR`,
		fixed: `# 安全寫法：redirect 後立刻 return,確認未過就不執行任何變更
def cancel(acct, confirm):
    if not confirm:
        return redirect("/confirm")
    account.cancel(acct)`,
		patch: `@@
 def cancel(acct, confirm):
     if not confirm:
-        redirect("/confirm")
+        return redirect("/confirm")
     account.cancel(acct)`,
		refs: ['CWE-698', 'OWASP'],
		tags: ['ear', 'redirect', 'validation-bypass'],
	},
	{
		id: 'CWE-708',
		name: 'Incorrect Ownership Assignment',
		lang: 'python',
		status: 'Complete',
		what: `資源歸屬（owner）指派錯誤。程式會把一個資源的「主人」指定成某個物件、程式或帳號，但這個主人落在原本預期的控制範疇之外，
也就是說它把資源的控制權交給了不被信任的一方。成因常是把存取權與「擁有權」混為一談——只檢查了現在誰能存取，卻沒確認權限最好要綁在誰
身上，或採用了預設／寬鬆的 owner。後果是持有該資源的對象擁有刪除、覆寫或重新指派的能力，即使它照理不該擁有這個權力，可能直接被拿去
竄改或刪除重要資料。建議在建立資源或指派權限的當下，明確地把 owner 設為真正需要控制它的實體，並對任何「換手」都做嚴格的驗證與授權，
拒絕把資源交給控制範疬之外的對象。`,
		problem: `# 不安全寫法：把資源的控制權交給「目前能連到的來源」而非真正的主人
def assign(doc, requester):
    doc.owner = requester            # 任何能呼叫的人都能成為 owner
    db.save(doc)`,
		fixed: `# 安全寫法：owner 必須是合法登記的帳號,並經授權後才轉移
def assign(doc, requester, token):
    if not admin_can_reassign(doc, requester, token):
        raise Forbidden("cannot change owner")
    doc.owner = requester
    db.save(doc)`,
		patch: `@@
 def assign(doc, requester):
-    doc.owner = requester
+    if not admin_can_reassign(doc, requester, token):
+        raise Forbidden("cannot change owner")
+    doc.owner = requester
     db.save(doc)`,
		refs: ['CWE-708', 'OWASP'],
		tags: ['ownership', 'authorization', 'access-control'],
	},
	{
		id: 'CWE-756',
		name: 'Missing Custom Error Page',
		lang: 'python',
		status: 'Complete',
		what: `缺少自訂錯誤頁面。使用者在操作失敗、輸入非法請求或找不到資源時，伺服器沒有送出自訂的錯誤頁，而是把框架預設的錯誤輸出或完整的
堆疊追蹤回傳給使用者。成因是開發者沒為各種錯誤型別設定錯誤處理頁、環境變數沒關掉 debug，或錯誤 handler 直接轉傳例外與 traceback。後果是
回應內容可能夾帶內部檔案路徑、資料庫結構、原始碼片段與堆疊資訊，等於把偵錯用的內部資訊白送給任何一個能隨意觸發錯誤的攻擊者，成為資訊洩漏
的跳板。建議為所有預期錯誤建立收斂的自訂錯誤頁，記錄完整細節進伺服器端日誌，對外在對漂亮、通用的錯誤訊息，並在正式環境徹底關閉 debug／
traceback 輸出。`,
		problem: `# 不安全寫法：沒設自訂錯誤頁,例外一拋就把內部細節回傳
from flask import Flask

app = Flask(__name__)

@app.errorhandler(500)
def oops(e):
    return traceback.format_exc(), 500   # 把檔案路徑/堆疊洩給使用者`,
		fixed: `# 安全寫法：細節進日誌,對外只回通用訊息
import logging
from flask import Flask, jsonify

app = Flask(__name__)
log = logging.getLogger("app")

@app.errorhandler(500)
def oops(e):
    log.error("failed request", exc_info=True)   # 細節留在伺服器端
    return jsonify(error="something went wrong"), 500`,
		patch: `@@
 @app.errorhandler(500)
 def oops(e):
-    return traceback.format_exc(), 500
+    log.error("failed request", exc_info=True)
+    return jsonify(error="something went wrong"), 500`,
		refs: ['CWE-756', 'OWASP'],
		tags: ['error-page', 'information-disclosure', 'logging'],
	},
	{
		id: 'CWE-760',
		name: 'Use of a One-Way Hash with a Predictable Salt',
		lang: 'python',
		status: 'Complete',
		what: `對不可逆輸入使用了帶可預測 salt 的單向雜湊。像密碼這種不該被還原的祕密，正確作法是「一組隨機且足夠長的 salt 加上慢速雜湊」
（如 bcrypt、argon2），但程式用了一個可預測的 salt——同一個寫死的常數、時間戳、序號或很短的值——就直接與密碼拼接後做 SHA 這類快速單向
雜湊。成因是誤以為只要加 salt 就安全，卻忽略「可預測、固定、過短」的 salt 等於沒加。後果是雜湊表外洩時，攻擊者可把字典或 rainbow table
對每個固定 salt 套用，直接離線暴力比對還原密碼，多個帳戶共用同 salt 更會一起淪陷。建議用密碼專用 KDF（bcrypt/argon2/scrypt）讓它自己
產生隨機 salt、自動帶進驗證流程，並配合作業系統層的次數與記憶體成本參數。`,
		problem: `# 不安全寫法：固定、可預測的 salt,配上快速 SHA,等同沒加 salt
import hashlib

SALT = "myapp"                          # 對所有使用者一樣且可預測

def store_password(hashstore, name, pw):
    d = hashlib.sha256((SALT + pw).encode()).hexdigest()
    hashstore[name] = d`,
		fixed: `# 安全寫法：用密碼專用 KDF,隨機 salt,驗證時獨立比對
from werkzeug.security import generate_password_hash, check_password_hash

def store_password(hashstore, name, pw):
    hashstore[name] = generate_password_hash(pw)  # bcrypt,內含隨機 salt

def ok(name, pw):
    return check_password_hash(hashstore[name], pw)`,
		patch: `@@
-import hashlib
-
-SALT = "myapp"
+from werkzeug.security import generate_password_hash, check_password_hash
 
 def store_password(hashstore, name, pw):
-    d = hashlib.sha256((SALT + pw).encode()).hexdigest()
-    hashstore[name] = d
+    hashstore[name] = generate_password_hash(pw)`,
		refs: ['CWE-760', 'OWASP'],
		tags: ['password-hashing', 'predictable-salt', 'kdf'],
	},
	{
		id: 'CWE-761',
		name: 'Free of Pointer not at Start of Buffer',
		lang: 'c',
		status: 'Complete',
		what: `對不在緩衝區起頭的指標呼叫 free。C 語言只允許 free 一個由堆積配置（malloc/calloc/realloc）直接回傳的指標，程式卻把指標前移一段
（例如為了跳過標頭、或想縮小 payload）之後才釋放。成因常是想釋放「中間或尾端的一部分」、把算數後的位址錯當成原配置的基準。後果是 free 收到
的不是配置紀錄的起點，觸發未定義行為：輕則 heap 管理結構被誤釋、狀態錯亂，重則當場崩潰或被利用做堆積攻擊。建議永遠保留配置回傳的原始指標
並只 free 這個指標，若要「跳過一段」就用另一支臨時移動指標用的變數，釋放時仍以最原始的位址為準。`,
		problem: `// 不安全寫法：把指標往前跳過 4 位元組的標頭後才 free
#include <stdlib.h>

void kill(char *p, size_t cap) {
    char *body = p + 4;      // 指向緩衝區中段
    // ...使用 body...
    free(body);               // 不是配置的起點 => undefined behavior
}`,
		fixed: `// 安全寫法：保留原始指標,只用額外變數做位移,釋放仍指到起點
#include <stdlib.h>

void kill(char *p, size_t cap) {
    char *body = p + 4;
    // ...使用 body...
    free(p);                 // 釋放配置的原點
}`,
		patch: `@@
 void kill(char *p, size_t cap) {
     char *body = p + 4;
     // ...使用 body...
-    free(body);
+    free(p);
 }`,
		refs: ['CWE-761'],
		tags: ['free', 'pointer', 'heap-violation'],
	},
	{
		id: 'CWE-765',
		name: 'Multiple Unlocks of a Critical Resource',
		lang: 'c',
		status: 'Complete',
		what: `對重要資源做了多次解鎖。一個由鎖／旗號保護的關鍵資源，應該維持「每次加鎖恰好配一次解鎖」的平衡，程式卻在單次取得後釋放了
多於所需次數。常見成因是錯誤處理路徑與正常路徑各自都會 unlock、卻沒有統一旗標，或把解鎖放進會重疊跳過的迴圈／分支。後果是把鎖「過度釋放」：
其他執行緒或處理程序可能在同個臨界區重入、看到半完成的狀態，破壞互斥的假設，演變成資料競爭、狀態錯亂甚至死鎖。建議把加鎖、解鎖做成嚴格的
配對結構——理想上利用 RAII／defer／with 語意讓解鎖只能發生一次，替換到任何 return 分支都不能重複釋放，並用工具檢查 lock/unlock 的成對性。`,
		problem: `// 不安全寫法：正常與錯誤路徑各自 unlock,失敗時同一把鎖被釋放兩次
pthread_mutex_lock(&mtx);
struct node *n = list->head;
if (!n) {
    pthread_mutex_unlock(&mtx);     // 錯誤路徑先解了一次
    return NULL;
}
// ...處理 n...
pthread_mutex_unlock(&mtx);         // 若上方 return 掉,這裡會同鎖再解一次`,
		fixed: `// 安全寫法：單一出口解鎖,確保加鎖/解鎖嚴格成對
pthread_mutex_lock(&mtx);
struct node *n = list->head;
if (n) {
    // ...處理 n...
}
pthread_mutex_unlock(&mtx);         // 所有分支只在此釋放一次
int rc = n ? 0 : -1;
return rc;
return rc;`,
		patch: `@@
 pthread_mutex_lock(&mtx);
 struct node *n = list->head;
-if (!n) {
-    pthread_mutex_unlock(&mtx);
-    return NULL;
-}
-// ...處理 n...
-pthread_mutex_unlock(&mtx);
+if (n) {
+    // ...處理 n...
+}
+int rc = n ? 0 : -1;
+pthread_mutex_unlock(&mtx);
+return rc;`,
		refs: ['CWE-765', 'OWASP'],
		tags: ['double-unlock', 'lock', 'concurrency'],
	},
	{
		id: 'CWE-766',
		name: 'Critical Data Element Declared Public',
		lang: 'java',
		status: 'Complete',
		what: `把關鍵資料元素宣告成 public。安全政策要求某個關鍵變數、欄位或成員只能被擁有它的類別（或其受信任子系統）存取時，程式卻把它宣告為
公開可觸及的。成因常是圖方便、或為了讓其他類別直接讀寫而放棄封裝。後果是任何程式碼、甚至來自外部輸入的物件都能直接讀到或竄改這份關鍵資料，
繞過類別內所有協定、不變式與驗證邏輯，讓密鑰、旗標、餘額等敏感值暴露並可被任意覆寫。建議把這類成員宣告為 private（必要時 protected）、只留
受控的存取子（getter/setter）去做驗證，不變的量選 final；用 static analysis 持續檢查「安全敏感欄位不得 public」。`,
		problem: `// 不安全寫法：關鍵旗標與密鑰直接 public,任何物件都能改
public class Guard {
    public boolean authorized;      // 外部可直接設為 true 越權
    public byte[] masterKey;       // 敏感資料完全外露
}`,
		fixed: `// 安全寫法：private + 受控存取子,變更要走驗證路徑
public class Guard {
    private boolean authorized;
    private byte[] masterKey;

    public boolean isAuthorized() { return authorized; }
    public void grant() { checkPolicy(); authorized = true; }   // 經過驗證
}`,
		patch: `@@
 public class Guard {
-    public boolean authorized;
-    public byte[] masterKey;
+    private boolean authorized;
+    private byte[] masterKey;
+
+    public boolean isAuthorized() { return authorized; }
+    public void grant() { checkPolicy(); authorized = true; }
 }`,
		refs: ['CWE-766', 'OWASP'],
		tags: ['public-field', 'encapsulation', 'abstraction-error'],
	},
	{
		id: 'CWE-767',
		name: 'Access to Critical Private Variable via Public Method',
		lang: 'java',
		status: 'Complete',
		what: `透過公開方法存取關鍵的私有變數。變數本身宣告成 private，但類別卻提供了一個 public 方法可以直接呼叫者讀取或修改它，且此方法沒做任何
額外檢查或受限上下文驗證。常見成因是為了測試／除錯開了「直接讀寫原始欄位」的 setter/getter，或公開方法幾乎就是把欄位拋回去。後果是 private
宣告形同虛設——任何能呼叫該方法的人都被當成「原本就在掌控內」，取得或改動敏感的內部狀態，繞過所有由私有變數維繫的單元不變式與授權邏輯。
建議公開方法只回傳／接受「必要的視圖」而非原始欄位，能唯讀就別給寫，需要修改時在方法內完成驗證、授權再改，敏感值永遠不回傳整個原始物件。`,
		problem: `// 不安全寫法：public 方法直接把內部機密拋給任何呼叫者
public class Vault {
    private byte[] secret;

    public byte[] getSecret() { return secret; }   // 誰都能拿整個祕密
    public boolean verifyPin(String pin) { ... }
}`,
		fixed: `// 安全寫法：公開介面只給受控視圖 / 布林結果,不透出原始欄位
public class Vault {
    private byte[] secret;

    public boolean matches(String candidate) {        // 只在內部比較後回傳布林
        return MessageDigest.isEqual(secret, hash(candidate));
    }
    public int strength() { return secret.length; }  // 摘要式視圖
}`,
		patch: `@@
 public class Vault {
     private byte[] secret;
 
-    public byte[] getSecret() { return secret; }
+    public boolean matches(String candidate) {
+        return MessageDigest.isEqual(secret, hash(candidate));
+    }
+    public int strength() { return secret.length; }
 }`,
		refs: ['CWE-767', 'OWASP'],
		tags: ['private-leak', 'public-method', 'encapsulation'],
	},
	{
		id: 'CWE-768',
		name: 'Incorrect Short Circuit Evaluation',
		lang: 'c',
		status: 'Complete',
		what: `誤用的短路求值。條件敘述中用了多個邏輯運算式，其中某個「非領頭」的運算式會產生副作用，但這個運算式是否執行完全取決於前面的
結果。在 C 語言裡 &&／|| 是「短路」的：若左側已決定結局，右側根本不評估。常見成因是開發者把「必須靠呼叫帶副作用才更新狀態」的函式塞進
條件式中間，誤以為它每次都會跑到。後果是程式狀態飄忽不定——同一個條件在第一次與之後的執行看起來一致但實際副作用被跳過，導致資源沒釋放、
旗標沒設、計數沒增，狀態進入未預期的局面。建議把有副作用的呼叫提出條件式、先在別行執行並把結果存進變數，條件式只比較純值，並時刻記住
短路語意會跳過右側。`,
		problem: `// 不安全寫法：把執行中釋放資源的呼叫塞進條件式右側,短路時根本不會跑
int close_handle(int fd);

if (fd >= 0 && close_handle(fd)) {   // fd<0 時右側不執行,fd 遺漏釋放
    log("closed");
}`,
		fixed: `// 安全寫法：副作用呼叫與條件式分離,先執行再比較
if (fd >= 0) {
    if (close_handle(fd)) {
        log("closed");
    }
}`,
		patch: `@@
-if (fd >= 0 && close_handle(fd)) {   // fd<0 時右側不執行
-    log("closed");
+if (fd >= 0) {
+    if (close_handle(fd)) {
+        log("closed");
+    }
 }`,
		refs: ['CWE-768'],
		tags: ['short-circuit', 'side-effect', 'logic-error'],
	},
	{
		id: 'CWE-769',
		name: 'DEPRECATED: Uncontrolled File Descriptor Consumption',
		lang: '-',
		status: 'Deprecated',
		what: `棄用的條目「無控制式檔案描述符耗用」。本條曾被用來涵蓋「程式無止境地配置檔案描述符或 handle，卻不加以限制，最終耗盡系統資源」這類
問題，但審查後認定它與 CWE-774（配置檔案描述符或 handle 而未設限制或節流）重覆，因此內容已全數移轉到 CWE-774，本條自此棄用。實務上要處理
的仍是同一個成因：對每個能開啟資源的動作缺少上限與節流。若要檢視或對映這類弱點，應改用 CWE-774 並把 fd／handle 的掌管原則落實在每一處
配置點。`,
		problem: `# 本條已棄用;經典的壞寫法仍是——對每個情況都新開 fd,量再多也不管
def leak(tar):
    for i in range(1_000_000):
        f = open(tar, "r")     # fd 從不關閉,會耗盡資源`,
		fixed: `# 改用 CWE-774 的角度修：限制數量並以 with 保證釋放
MAX = 128

def bounded(tar, n):
    if n > MAX:
        return
    with open(tar, "r") as f:   # 用完即釋放,且總量受限
        return f.read()`,
		patch: `@@
-… 見 CWE-774,此條內容已全數移轉 …`,
		refs: ['CWE-769', 'CWE-774'],
		tags: ['deprecated', 'fd-consumption', 'resource-management'],
	},
	{
		id: 'CWE-773',
		name: 'Missing Reference to Active File Descriptor or Handle',
		lang: 'c',
		status: 'Complete',
		what: `缺少對「仍在使用中的檔案描述符或 handle」的參照。物件不再需要時應關閉、回收其底層資源，但程式對一個仍要保持開啟的 fd／handle
沒保留任何可對它執行的參照，於是這份資源既關不掉、也用不到，永遠占著黑客的名字。常見成因是 fd 被存在太小的暫存、被複寫、或放在離開範疇就
消失的變數裡。後果是 fd 數量持續攀高：系統把描述符預留給這份「失聯」資源，其他合法的開啟／連線動作開始失敗，最後資源耗盡、服務退化或當機。
建議把每個 fd／handle 的權屬明確化：開在哪就到同一個管理結構關在哪，明確持有參照直到釋放完成，並嘗試先用有界的資源池或 RAII 歸還機制，讓
一路上的例外路徑也能正確關閉。`,
		problem: `// 不安全寫法：fd 只存在臨時變數,真的要用來釋放時早已不見蹤影
#include <unistd.h>
#include <fcntl.h>

int open_anything(const char *path) {
    int fd = open(path, O_RDWR);   // 唯一參照只有區域變數
    int err = do_work(fd);         // ...之後再也沒有地方記住 fd
    return err;                    // fd 就此失聯,關不掉也釋放不掉
}`,
		fixed: `// 安全寫法：把 fd 記進有所有權的結構,統一在清理路徑關閉
struct session { int fd; };

void open_session(struct session *s, const char *path) {
    s->fd = open(path, O_RDWR);    // 權屬被明確記住
}

void close_session(struct session *s) {
    if (s->fd >= 0) close(s->fd);  // 有參照才能正確回收
    s->fd = -1;
}`,
		patch: `@@
-int open_anything(const char *path) {
-    int fd = open(path, O_RDWR);
-    int err = do_work(fd);
-    return err;
+void open_session(struct session *s, const char *path) {
+    s->fd = open(path, O_RDWR);
+}
+
+void close_session(struct session *s) {
+    if (s->fd >= 0) close(s->fd);
+    s->fd = -1;
 }`,
		refs: ['CWE-773'],
		tags: ['file-descriptor', 'resource-leak', 'handle'],
	},
	{
		id: 'CWE-774',
		name: 'Allocation of File Descriptors or Handles Without Limits or Throttling',
		lang: 'c',
		status: 'Complete',
		what: `無限制、無節流地配置檔案描述符或 handle。程式替某個「角色／請求」分配 fd 或 handle 時，不設任何數量上限，也不做節流，完全不管這個
角色到底能合法持有多少。常見成因是 server 對每個連線都 open 一堆檔案、每個請求都新開 socket，卻沒有配額或關閉策略。後果是單一攻擊者只要不斷
觸發開啟，就能佔滿系統的 fd／socket／執行緒資源，吃掉這類資源供給其他所有請求也一起失敗，變成典型且容易濫用的 DoS。建議為每個角色設定明確的
fd/handle 配額，超過就拒絕或繼續此外，並加上節流與逾時回收，用有界資源池統一掌管配置與歸還，確保常見的逼近上限路徑能被偵測並記錄。`,
		problem: `// 不安全寫法：每個請求都無條件開 socket,沒有配額也沒有節流
#include <sys/socket.h>

int handle_request(int req) {
    int s = socket(AF_INET, SOCK_STREAM, 0);   // 數量完全不設限
    do_work(req, s);                            // 請求爆量 => socket 耗盡
    close(s);
}`,
		fixed: `// 安全寫法：先量配額,超限即拒絕,再開資源
int handle_request(int req) {
    if (active_sockets() >= MAX_PER_CLIENT) {
        return ERR_TOO_MANY;                    // 節流,保護整體資源
    }
    int s = socket(AF_INET, SOCK_STREAM, 0);
    do_work(req, s);
    close(s);
}`,
		patch: `@@
 int handle_request(int req) {
+    if (active_sockets() >= MAX_PER_CLIENT) {
+        return ERR_TOO_MANY;
+    }
     int s = socket(AF_INET, SOCK_STREAM, 0);
     do_work(req, s);
     close(s);
 }`,
		refs: ['CWE-774'],
		tags: ['fd-exhaustion', 'resource-limit', 'denial-of-service'],
	},
	{
		id: 'CWE-777',
		name: 'Regular Expression without Anchors',
		lang: 'python',
		status: 'Complete',
		what: `缺少錨點的規則運算式。程式用正規表示式做資料淨化（neutralization 過濾，例如把危險字元替掉），但這個 regex 沒有錨點，並未要求整段
輸入都要符合，於是「部分相符」也會被放行。常見成因是只寫了要過濾或允許的模式卻忘了加 ^…$ 或 \\A…\\Z，或誤用 search 而非 fullmatch。後果是惡意或
格式不正確的資料能從沒比對到的縫隙溜過去：例如想「以英數開頭」的錨沒釘死開頭，前面的空白或注入字元未被視作需要淨化的部分，造成過濾被 bypass。
建議在淨化用的 regex 明確使用完整配對錨點（anchors）或 fullmatch 類 API、確認「輸出不只含允許集合中的字元」，並用測試覆蓋前綴／後綴被塞髒資料的
情形。`,
		problem: `# 不安全寫法：想允許純英數,卻沒釘死整段,注入字元從兩側溜過
import re

def sanitize(text):
    # 沒錨點,「a1; DROP」也被當成可接受
    return re.sub(r"[^A-Za-z0-9]*", "", text, count=1) or text`,
		fixed: `# 安全寫法：用完整配對錨定整段,非允許集合一律拒絕
import re

ALLOWED = re.compile(r"^[A-Za-z0-9]+$")

def sanitize(text):
    if not ALLOWED.match(text):
        raise Invalid("not allowed")
    return text`,
		patch: `@@
 def sanitize(text):
-    return re.sub(r"[^A-Za-z0-9]*", "", text, count=1) or text
+    if not ALLOWED.match(text):
+        raise Invalid("not allowed")
+    return text`,
		refs: ['CWE-777', 'OWASP'],
		tags: ['regex-anchor', 'filter-bypass', 'neutralization'],
	},
	{
		id: 'CWE-779',
		name: 'Logging of Excessive Data',
		lang: 'python',
		status: 'Complete',
		what: `記錄了過多不必要的資料。程式把大量資料塞進日誌——把整個請求本體、回傳內容、擴充套件的偵錯輸出、甚至連密碼與 token 都逐筆寫下。
成因常是為了「以後好查」把開發期的極度瑣碎紀錄直接帶上線、logger 層級設定過低、或把敏感欄位完整拷進日誌。後果是日誌檔膨脹到難以處理、過濾
與搜尋成本暴增；同時把使用者個資或死活記在明文中，攻擊後要做的鑑識／復原（forensics)反而被海量噪音干擾，更可能成為資料洩漏的另一條出口。建議
只記錄「事件性質、時序、足以歸責的最小欄位」，敏感值一律遮蔽或雜湊，日誌層級在正式環境拉高門檻並做輪替、保留與權限控管，確保駭侵後查得到有用
線索而不是一坨垃圾。`,
		problem: `# 不安全寫法：整個請求體連密碼一起 log,日誌多到難處理
def login(req):
    log.info("request=%s", req.body)     # 含 password + 整個 payload
    return do_login(req)`,
		fixed: `# 安全寫法：只記最小欄位,敏感值遮蔽
def login(req):
    log.info("login user=%s ok=%s", req.user, masked(req.body.get("password")))
    return do_login(req)`,
		patch: `@@
 def login(req):
-    log.info("request=%s", req.body)
+    log.info("login user=%s ok=%s", req.user, masked(req.body.get("password")))
     return do_login(req)`,
		refs: ['CWE-779', 'OWASP'],
		tags: ['log-flood', 'information-disclosure', 'forensics'],
	},
	{
		id: 'CWE-780',
		name: 'Use of RSA Algorithm without OAEP',
		lang: 'python',
		status: 'Complete',
		what: `使用 RSA 卻沒採用 OAEP 填充。用 RSA 加密時要靠填充（padding）把明文撐開、注入隨機性，OAEP（最佳非對稱加密填充，RSA-OAEP）是針對
這需求設計的安全方案；程式卻直接做裸 RSA（NoPadding 或只有 1 的 PKCS#1 v1.5 級別）就把明文套上去。成因常是呼叫加密 API 時省略 padding 參數、
或想省事直接用「教科書式」RSA。後果是在某些數件下可被預測或破解：若明文小、無隨機性，相同的明文塊得到相同密文，方便字典比對；配合低指數或
選擇密文攻擊，可能洩漏明文甚至遭竄改，整體大幅削弱加密強度。建議一律使用 PKCS#1 OAEP（或 RSAES-OAEP），讓 API 提供隨機 salt 並啟用，且對每筆
資料解密方要能驗證完整性。`,
		problem: `# 不安全寫法：裸 RSA,沒有 OAEP,可預測且弱
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def enc(pub, plain):
    return pub.encrypt(plain, padding.PKCS1v15())   # 弱填充,不是 OAEP`,
		fixed: `# 安全寫法：一律使用 OAEP,注入隨機填充並驗證完整性
from cryptography.hazmat.primitives.asymmetric import rsa, padding

SHA = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                  algorithm=hashes.SHA256(), label=None)

def enc(pub, plain):
    return pub.encrypt(plain, SHA)                   # RSA-OAEP`,
		patch: `@@
 def enc(pub, plain):
-    return pub.encrypt(plain, padding.PKCS1v15())
+    return pub.encrypt(plain, SHA)`,
		refs: ['CWE-780', 'OWASP'],
		tags: ['rsa', 'oaep', 'padding', 'crypto'],
	},
	{
		id: 'CWE-781',
		name: 'Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code',
		lang: 'c',
		status: 'Complete',
		what: `METHOD_NEITHER 的 IOCTL 位址驗證不當。驅動程式定義了一個 I/O control code，其 I/O 方式為 METHOD_NEITHER；這種方式下核心不會
自動對使用者傳來的緩衝區位址做檢查或攔截，完全由驅動自己負責。程式卻沒驗證、或錯誤驗證了呼叫端提供的位址。常見成因是誤信 METHOD_NEITHER
「反正自己要處理」就把使用者指標直接拆解，或只驗一部分而漏掉另一方向。後果是驅動可能對任意使用者位址（包含核心位址空間或不存在的記憶體）做
讀寫，把相對快速的核心面送入可被利用的任意寫，或是用核心位址當成緩衝造成資訊洩漏或當機。建議對 METHOD_NEITHER 的位址明確呼叫 ProbeForRead/
ProbeForWrite 這類安全驗證、確認其與處理的 acceptable 方向相符，並用 MAKELONG／METHOD 把 I/O 類型釘在能由核心副揆的程序。`,
		problem: `// 不安全寫法：METHOD_NEITHER 的 IOCTL 直接把使用者位址當緩衝,沒做探測
NTSTATUS OnDeviceIoControl(PDEVICE_OBJECT d, PIRP irp) {
    PIO_STACK_LOCATION sl = IoGetCurrentIrpStackLocation(irp);
    PVOID buf = sl->Parameters.DeviceIoControl.Type3InputBuffer;  // 使用者給的
    // 直接對 buf 讀寫,核心不會代為檢查位址 => 可能打到任意位址
    RtlCopyBufferToUser((PUCHAR)buf, kernel_secret, n);
}`,
		fixed: `// 安全寫法：先用 ProbeForWrite 驗證使用者位址方向與長度,再進行存取
NTSTATUS OnDeviceIoControl(PDEVICE_OBJECT d, PIRP irp) {
    PIO_STACK_LOCATION sl = IoGetCurrentIrpStackLocation(irp);
    PVOID buf = sl->Parameters.DeviceIoControl.Type3InputBuffer;
    if (buf != NULL) {
        ProbeForWrite(buf, n, PAGE_SIZE);      // 確認是使用者可寫區間
    }
    __try {
        RtlCopyBufferToUser((PUCHAR)buf, kernel_secret, n);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_INVALID_PARAMETER;
    }
}`,
		patch: `@@
 NTSTATUS OnDeviceIoControl(PDEVICE_OBJECT d, PIRP irp) {
     PIO_STACK_LOCATION sl = IoGetCurrentIrpStackLocation(irp);
     PVOID buf = sl->Parameters.DeviceIoControl.Type3InputBuffer;
-    RtlCopyBufferToUser((PUCHAR)buf, kernel_secret, n);
+    if (buf != NULL) {
+        ProbeForWrite(buf, n, PAGE_SIZE);
+    }
+    __try {
+        RtlCopyBufferToUser((PUCHAR)buf, kernel_secret, n);
+    } __except(EXCEPTION_EXECUTE_HANDLER) {
+        return STATUS_INVALID_PARAMETER;
+    }
 }`,
		refs: ['CWE-781'],
		tags: ['ioctl', 'method-neither', 'kernel', 'address-validation'],
	},
	{
		id: 'CWE-782',
		name: 'Exposed IOCTL with Insufficient Access Control',
		lang: 'c',
		status: 'Complete',
		what: `暴露了存取控制不足的 IOCTL。程式（通常是核心驅動或系統服務）實作了一個 IOCTL，其功能本該受限給受信任的呼叫者，但它沒有正確地
執行存取控制就把這個 handler 大門打開。常見成因是只檢查了「能開啟裝置」卻沒檢查「能執行這個命令」、把 IOCTL 編號塞給任何傳入的 process、
或根深蒂固地依賴文件權限而忽略 MSR／BUFFER 層面的身分。後果是低權限的使用者只要開到裝置就能觸發原本保留給特權者的功能——切換模式、改硬體暫存器、
讀取核心記憶體，直接變成權限提升或系統當掉的管道。建議為每個 IOCTL 綁定明確的角色／權限檢查，而不只信賴對裝置的開啟權限，僅把受控命令暴露在
受信任的 namespace，並在進入真正處理前攔住每一個未授權的呼叫者。`,
		problem: `// 不安全寫法：只允許開啟裝置,卻放任任何 process 送這個「核心指令」IOCTL
NTSTATUS My_Ioctl(PDEVICE_OBJECT d, ULONG ioctl) {
    if (ioctl == IOCTL_RAW_KERNEL_WRITE) {      // 危險手段,沒檢查呼叫者身分
        return DoRawWrite(GetUserAddr(irp));    // 任何能 open 的人都能觸發
    }
    return STATUS_INVALID_DEVICE_REQUEST;
}`,
		fixed: `// 安全寫法：進入處理前先用權杖/身分檢查,非授權一律拒絕
NTSTATUS My_Ioctl(PDEVICE_OBJECT d, ULONG ioctl) {
    if (ioctl == IOCTL_RAW_KERNEL_WRITE) {
        if (!HasPrivilege(SeLoadDriverPrivilege)) {
            return STATUS_ACCESS_DENIED;         // 只授權受信任身分
        }
        return DoRawWrite(GetUserAddr(irp));
    }
    return STATUS_INVALID_DEVICE_REQUEST;
}`,
		patch: `@@
 NTSTATUS My_Ioctl(PDEVICE_OBJECT d, ULONG ioctl) {
     if (ioctl == IOCTL_RAW_KERNEL_WRITE) {
+        if (!HasPrivilege(SeLoadDriverPrivilege)) {
+            return STATUS_ACCESS_DENIED;
+        }
         return DoRawWrite(GetUserAddr(irp));
     }
     return STATUS_INVALID_DEVICE_REQUEST;
 }`,
		refs: ['CWE-782'],
		tags: ['ioctl', 'access-control', 'privilege-escalation'],
	},
	{
		id: 'CWE-783',
		name: 'Operator Precedence Logic Error',
		lang: 'c',
		status: 'Complete',
		what: `運算子優先順序造成的邏輯錯誤。程式裡的運算式因為運算子優先權與組合規則，實際算出的意義跟作者腦中想的不一樣。典型例子是拿
「位元與、比較、賦值」混在一起用：如 a & mask == 0 會被解讀成 a & (mask == 0)，或 (x = read()) > 0 被寫成 x = read() > 0。
常見成因是過度依賴記憶、省略括號、沒留意位元運算的優先權。後果是條件判定的分支完全走錯方向：安全檢查被悄悄 bypass（該拒絕的沒拒絕）、迴圈或邊界
判斷出錯，卻在 code review 時因為「看起來對」而漏過。建議對任何混合位元、比較、邏輯與賦值的運算式一律用括號把意圖釘死，並在 CI 用編譯器警告
（如 -Wparentheses）與 linter 抓出這類歧義。`,
		problem: `// 不安全寫法：== 優先權高於 &,整式被算成 a & (mask == 0)
int allowed(int a, int mask) {
    return a & mask == 0;   // 真正想的是 (a & mask) == 0,但結果相反
}`,
		fixed: `// 安全寫法：用括號明確釘住「先遮罩再比較」的意圖
int allowed(int a, int mask) {
    return (a & mask) == 0;
}`,
		patch: `@@
 int allowed(int a, int mask) {
-    return a & mask == 0;
+    return (a & mask) == 0;
 }`,
		refs: ['CWE-783'],
		tags: ['operator-precedence', 'logic-error', 'parentheses'],
	},
	{
		id: 'CWE-784',
		name: 'Reliance on Cookies without Validation and Integrity Checking in a Security Decision',
		lang: 'python',
		status: 'Complete',
		what: `在安全決策上只依賴未經驗證與未做完整性檢查的 cookie。程式用 cookie 的「存在」或「值」作為身分判斷的依據，卻沒有確認這個 cookie
真的是伺服器發給、無法被使用者竄改的。常見成因是直接用 is_admin、role 這種明文的 cookie 判權限，卻沒用簽章、HMAC 或 httponly 保護它。後果是
攻擊者只要自己改 cookie 的值——把 admin:false 改成 admin:true——就可能把身分或權限提升到不屬於自己的等級，接管他人帳號或取得管理權。建議永遠不要
用「可被用戶端修改」的明文 cookie 做安全決策：改用伺服器端 session，或用帶金鑰的簽名／HMAC 綁住使用者 id 與完整性，並在每次決策前重新驗證簽章與
到期時間。`,
		problem: `# 不安全寫法：直接相信 cookie 的明文值來決定權限
def is_admin(req):
    return req.cookies.get("is_admin") == "true"   # 使用者自己就能改`,
		fixed: `# 安全寫法：權限放進伺服器端 session,由簽章的 session id 決定
def is_admin(req):
    # session 內容存在伺服器端, cookie 只是簽名的索引
    return session_is_admin(req.session_id)`,
		patch: `@@
 def is_admin(req):
-    return req.cookies.get("is_admin") == "true"
+    return session_is_admin(req.session_id)`,
		refs: ['CWE-784', 'OWASP'],
		tags: ['cookie', 'session', 'integrity-check', 'access-control'],
	},
	{
		id: 'CWE-786',
		name: 'Access of Memory Location Before Start of Buffer',
		lang: 'c',
		status: 'Complete',
		what: `讀寫了緩衝區起點之前的記憶體。程式用一個索引或指標算出「要碰的位置」，這個位置卻在緩衝區的開頭之前；與常見的「越過結尾」不同，
這回是往負方向越界。常見成因是索引遞減迴圈沒設下界、指標以為往前跳一格其實跳到頭之前、或把考慮 1-based 的邏輯誤裝在 0-based 的語言上。後果是把
相鄰位於緩衝前的前置物件、物件頭或會計資料讀到／寫壞：往前一讀洩漏前一個物件的內容，往後一寫還可能覆寫配置標頭釀成崩潰或可用來做堆積破壞。
建議所有指標／索引運算都對上下兩個界做檢查，遞減迴圈用 ≥0 一併檢查，並讓負索引在型別或測試層就被擋掉。`,
		problem: `// 不安全寫法：遞減迴圈衝過 0,索引在 -1 時讀到緩衝原點之前
struct elem { int v; };
extern struct elem table[N];

int sum_prefix(void) {
    int i = N - 1, s = 0;
    while (i >= 0) {
        s += table[i].v;    // i=-1 時讀到 table 之前的記憶體
        i--;
    }
    return s;
}`,
		fixed: `// 安全寫法：下界也一起檢查,確保絕不讀到起點之前
struct elem { int v; };
extern struct elem table[N];

int sum_prefix(void) {
    int i = N - 1, s = 0;
    while (i > 0) {          // 只讀實際存在的元素(索引 0..N-1)
        s += table[--i].v;   // 先遞減,永遠停在 >= 0
    }
    return s;
}`,
		patch: `@@
 int sum_prefix(void) {
     int i = N - 1, s = 0;
-    while (i >= 0) {
-        s += table[i].v;    // i=-1 越界
-        i--;
+    while (i > 0) {
+        s += table[--i].v;
     }
     return s;
 }`,
		refs: ['CWE-786'],
		tags: ['before-buffer', 'out-of-bounds', 'negative-index'],
	},
	{
		id: 'CWE-791',
		name: 'Incomplete Filtering of Special Elements',
		lang: 'python',
		status: 'Complete',
		what: `對特殊元素的過濾不完整。程式從上游元件接收資料，要把其中的「特殊元素」（如 SQL 注入用的引號、HTML 的 <、路徑跳脫的 . 與 ..）
過濾掉再往下游送，但只遮掉一部分、剩下的漏放。常見成因是只靠瑣碎的補充進黑名單，卻忘了與時俱進（編碼、替代字元、Unicode 正規化），或只做一次
replace 沒考慮多種型式。後果是原本要擋的注入資料能繞過過濾抵達下游解析器，觸發 SQL injection、XSS 或路徑穿越，而程式自己卻以為「已過濾過」。
建議不要用「黑名單加一道」的方式逐字元過濾，最好超前導把資料結構化（參數化查詢、安全執行環境），特殊字元只在該當被當資料的地方、以白名單或
單一正確的編碼處理，並處理嵌套編碼。`,
		problem: `# 不安全寫法：只過濾單引號,雙引號與反斜線直接放行
def sanitize(s):
    return s.replace("'", "").replace(";", "   ")   # " ... 與 "\\" 沒擋`,
		fixed: `# 安全寫法：透過參數化介面傳資料,不靠手工過濾特殊字元
def query(name):
    # 特殊字元被當參數值處理,永不被當語法
    return conn.execute("SELECT * FROM users WHERE name = ?", (name,))`,
		patch: `@@
 def sanitize(s):
-    return s.replace("'", "").replace(";", "   ")
+    return conn.execute("SELECT * FROM users WHERE name = ?", (name,))`,
		refs: ['CWE-791', 'OWASP'],
		tags: ['special-elements', 'filter-bypass', 'injection'],
	},
	{
		id: 'CWE-792',
		name: 'Incomplete Filtering of One or More Instances of Special Elements',
		lang: 'python',
		status: 'Complete',
		what: `對一個或多個特殊元素實例的過濾不完整。上游資料進入與下游之間，程式想「清掉某個特殊元素」，卻漏掉它的若干個實例。與只擋一種
的差別是：這裡「已經知道要擋哪幾個字元」、但數量上沒清乾淨——例如只浪費第一個或前面的幾個。常見成因是把過濾做成「只處理一次 occurrence」的
呼叫、或迴圈的計數與資料內實際出現數不符。後果是遺漏的那幾處保留原字元送往下游，只要攻擊者塞多份就能讓其中一份完整存活而 bypass 注入防護。
建議過濾必須「處理所有實例」——用使命的全局 replace、迴圈直到不再出現、或更根本地不靠過濾改用參數化/結構化傳遞，並檢查處理後的輸出確實不含
任何殘留的特殊元素。`,
		problem: `# 不安全寫法：只把每種特殊字元清掉「一次」,多餘的實例存活
def sanitize(s):
    for ch in ("<", ">", "&"):
        s = s.replace(ch, "", 1)     # count=1 => 只清第一個實例
    return s`,
		fixed: `# 安全寫法：清掉所有實例,或直接輸出的結構化方式
import html

def sanitize(s):
    return html.escape(s).replace("&#x27;", "'")   # 全部實例都被轉義`,
		patch: `@@
 def sanitize(s):
-    for ch in ("<", ">", "&"):
-        s = s.replace(ch, "", 1)
-    return s
+    return html.escape(s).replace("&#x27;", "'")`,
		refs: ['CWE-792', 'OWASP'],
		tags: ['special-elements', 'partial-filter', 'injection'],
	},
	{
		id: 'CWE-793',
		name: 'Only Filtering One Instance of a Special Element',
		lang: 'python',
		status: 'Complete',
		what: `只過濾特殊元素的「單一」實例。程式在把資料送向下游前，會清掉特殊元素，但對每一種特殊字元都只處理「一次」，明知道可能有多個
卻不再檢查第二次。常見成因是把 replace 預設成只取代第一處、迴圈只跑一輪、或寫得太快只 cover 到單一注入情境。後果是攻擊者只要連續塞好幾個同樣
的特殊字元或多段注入，未被處理的那幾處就會原封不動到達下游並被解讀成語法，繞過看似做過的淨化。建議用能一次處理全部實例的機制（全局 replace、
翻譯表、正規化的 escape），實測過含多個相同字元的輸入，並配合「輸出後再檢查仍不含特殊元素」的強化。`,
		problem: `# 不安全寫法：每種字元只清一次,「' OR '1'='1' OR ''='」只剩中間被擋
def sanitize(s):
    return s.replace("'", "", 1)   # 多個單引號只抹掉一個`,
		fixed: `# 安全寫法：全部實例都清/轉義,不留下半個單引號
def sanitize(s):
    return s.replace("'", "")       # 預設全欄,所有實例都移除`,
		patch: `@@
 def sanitize(s):
-    return s.replace("'", "", 1)
+    return s.replace("'", "")`,
		refs: ['CWE-793', 'OWASP'],
		tags: ['special-elements', 'single-filter', 'injection'],
	},
	{
		id: 'CWE-794',
		name: 'Incomplete Filtering of Multiple Instances of Special Elements',
		lang: 'python',
		status: 'Complete',
		what: `對多個特殊元素實例的過濾不完整。程式想清理某個特殊元素，雖有心要處理「多個」實例，卻沒把「所有」實例都處理完——漏掉一部分
而殘留其餘。常見成因是過濾邏輯裡有 break、取最前面若干個、或對編碼後的第二輪型式沒迭代處理，導致清一次後還有變化型漏網。後果是殘存的特殊元素
仍在下游被解讀成可執行語法，攻擊者多製造幾份編碼即可讓至少一份完整抵達而達成注入。建議過濾必須對「每一種」與「每一輪」型式都覆蓋，最好改用
參數化／結構化傳遞而非清理輸入，並在送出前對輸出做驗證式檢查：比對是否仍含任何被視為特殊字元的序列。`,
		problem: `# 不安全寫法：刪了前兩個實例就停,剩下的編碼實例原樣送出
def sanitize(s):
    for _ in range(2):                 # 只處理 2 個,第 3 個以後不管
        s = s.replace('<', '', 1)
    return s`,
		fixed: `# 安全寫法：直到乾淨為止迴圈清除,保障全數實例被轉義
def sanitize(s):
    while '<' in s:
        s = s.replace('<', '')
    return s`,
		patch: `@@
 def sanitize(s):
-    for _ in range(2):
-        s = s.replace('<', '', 1)
-    return s
+    while '<' in s:
+        s = s.replace('<', '')
+    return s`,
		refs: ['CWE-794', 'OWASP'],
		tags: ['special-elements', 'multi-filter', 'injection'],
	},
	{
		id: 'CWE-795',
		name: 'Only Filtering Special Elements at a Specified Location',
		lang: 'python',
		status: 'Complete',
		what: `只在「指定位置」過濾特殊元素。程式知道要擋掉特殊元素，卻只在某個固定位置——例如輸入字串的開頭或結尾——做處理，其他位置出現的同類
字元全部放行。常見成因是假設攻擊者只會把注入塞在最顯眼的一端，於是把過濾寫成 strip 或只檢查第一個字元。後果是只要特殊元素出現在其他位置（例如
字串中間夾帶的 <、文字中間的引號），就會原封保留並被下游解讀成語法，淨化因此形同虛設。建議過濾應掃描整段輸入而不假設位置，明確把整個外部邊界
內的任一字元都當作可能含特殊元素來處理，依場合採用全域轉義、參數化存取並對輸出做完整性檢查。`,
		problem: `# 不安全寫法：只檢查頭尾,字串中間塞的引號與標籤全部免責
def sanitize(s):
    return s.replace(s[0], s[0], 1) if s and s[0] == '<' else s   # 只顧開頭`,
		fixed: `# 安全寫法：對整個輸入做轉義,不限定任何位置
import html

def sanitize(s):
    return html.escape(s)   # 每個特殊字元(無論位置)都被轉義`,
		patch: `@@
 def sanitize(s):
-    return s.replace(s[0], s[0], 1) if s and s[0] == '<' else s
+    return html.escape(s)`,
		refs: ['CWE-795', 'OWASP'],
		tags: ['special-elements', 'position-filter', 'injection'],
	},
	{
		id: 'CWE-796',
		name: 'Only Filtering Special Elements Relative to a Marker',
		lang: 'python',
		status: 'Complete',
		what: `只過濾「相對某個標記位置」的特殊元素。程式在清理資料時，只針對「與某標記的相對位置」做處理——例如只清字串開頭或結尾附近的、只處理
第一個參數之後，或只處理緊隨等號後的值——而把其他位置出現的特殊元素視為不需處理。常見成因是認定惡意內容只會從特定「地方」（前面、後面、某參數）
進來，處過那一帶就收手。後果是同一種特殊元素只要不在那個相對位置，就能完整逃逸至下游並被解讀成語法，非但沒淨化還給人「已處理」的錯覺。建議過濾或
編碼要涵蓋整份資料、不讓「標記位置」以外的字元享有豁免，改用可對全部來源做輸出的轉義/參數化方式，並在送出前驗證輸出不含未清的特殊元素。`,
		problem: `# 不安全寫法：只對「=」之後第一個值在意,位置以外的引號全放行
def sanitize(s):
    eq = s.find('=')
    return s if eq < 0 else s[:eq+1] + s[eq+1:].replace("'", "", 1)  # 只看等號後第一段`,
		fixed: `# 安全寫法：不再看位置,整段輸入一致轉義
import html

def sanitize(s):
    return html.escape(s)   # 哪裡的特殊字元都被處理,與標記無關`,
		patch: `@@
 def sanitize(s):
-    eq = s.find('=')
-    return s if eq < 0 else s[:eq+1] + s[eq+1:].replace("'", "", 1)
+    return html.escape(s)`,
		refs: ['CWE-796', 'OWASP'],
		tags: ['special-elements', 'marker-filter', 'injection'],
	},
	{
		id: 'CWE-797',
		name: 'Only Filtering Special Elements at an Absolute Position',
		lang: 'python',
		status: 'Complete',
		what: `只在「絕對位置」過濾特殊元素。程式清理資料時，只針對存在於某個固定坐標上的特殊元素做處理——例如「第 10 個 byte」「第 0 個字元」——
而其他位置出現的同類元素一律不管。常見成因是拿「塞一個固定偏移」的方式處理注入，誤以為位置是把惡意資料吸附的地方，因而只淨化那一格。後果是特殊元素只要
出現在任何其他絕對位置就會留存並被下游當成語法，攻擊者可把注入放在別處就輕鬆繞過。建議不要以「坐標」決定要不要過濾，任何輸入內部的特殊元素都應被涵蓋：
採用涵蓋全輸入的轉義、參數化傳遞或白名單比對，並對最終輸出做「不再包含特殊元素」的檢查，而非只檢查跳過的那一標。`,
		problem: `# 不安全寫法：只檢查與清理「固定第 10 格」,其他位置的 < 直接放行
def sanitize(s, idx=10):
    if len(s) > idx and s[idx] == '<':
        s = s[:idx] + s[idx+1:]
    return s   # 位置不在第 10 格的 < 全部保留`,
		fixed: `# 安全寫法：不依賴位置,全數輸入一致轉義
import html

def sanitize(s):
    return html.escape(s)   # 每個 < 無論在哪一 bit 都被處理`,
		patch: `@@
 def sanitize(s, idx=10):
-    if len(s) > idx and s[idx] == '<':
-        s = s[:idx] + s[idx+1:]
-    return s
+    return html.escape(s)`,
		refs: ['CWE-797', 'OWASP'],
		tags: ['special-elements', 'absolute-position', 'injection'],
	},
	{
		id: 'CWE-804',
		name: 'Guessable CAPTCHA',
		lang: 'python',
		status: 'Complete',
		what: `可被猜出的 CAPTCHA。程式用 CAPTCHA 挑戰想證明「不是機器人」，但這張挑戰可以被非真人直接猜中或自動辨識。常見成因是答案集太小、
使用固定的挑戰與答案配對、字數太少、或只用基本的變形沒有對抗 OCR／機器學習，甚至把答案以弱式藏在輸入或 cookie 裡。後果是 CAPTCHA 淪為擺設，自動化
程式可以快速正確作答，任意的註冊、留言、票券搶購、登入暴破就直接碾過原本想要的「人機門檻」。建議用強挑戰設計（亂選文字、扭曲、隨機背景雜訊、指令碼阻擋
伺服器端驗證答案不落地），增加猜測與自動辨識的成本，並限制嘗試次數與加上時間窗，讓「過關次數」也被節流。`,
		problem: `# 不安全寫法：答案集固定幾種、且明顯可猜
import random

CHOICES = ["1234", "abcd", "zzzz"]       # 可猜的答案池很小

def challenge():
    ans = random.choice(CHOICES)          # 猜中機率高,OCR 一下就破
    return ans, img(ans)`,
		fixed: `# 安全寫法：挑戰由伺服器生成、答案存 session,再配合嘗試次數上限
import secrets

def challenge():
    ans = secrets.token_hex(4)           # 高熵、亂數挑戰
    return stamp(ans), ans

def verify(ans, given):
    return hmac.compare_digest(ans, given) and attempts_ok()   # 節流`,
		patch: `@@
-CHOICES = ["1234", "abcd", "zzzz"]
-
 def challenge():
-    ans = random.choice(CHOICES)
-    return ans, img(ans)
+    ans = secrets.token_hex(4)
+    return stamp(ans), ans`,
		refs: ['CWE-804', 'OWASP'],
		tags: ['captcha', 'guessable', 'automation'],
	},
	{
		id: 'CWE-806',
		name: 'Buffer Access Using Size of Source Buffer',
		lang: 'c',
		status: 'Complete',
		what: `用「來源緩衝區的大小」來存取目的緩衝區。程式在讀寫時，採用的長度是來源緩衝區的容量，而不是目的緩衝區實際可用的空間。「來源大、
目的小」時，複製／填入就會越過目的邊界。常見成因是把 sizeof(src) 或 src 的長度直接丟進 memcpy(dst)、或是用配置來源時那個數字來決定
“放進多少到 dst”。後果是寫入超過 dst 的容量，覆寫相鄰記憶體釀成緩衝區溢位、崩潰甚至任意碼執行。建議長度永遠相對「要寫的那一邊（目的地）」
來計算與校驗，複製前確認 n 不超過目的容量，使用帶上限的函式（如 memcpy_s／snprintf）並對目的容量使錯即停。`,
		problem: `// 不安全寫法：把來源的長度當作要寫入目的的量,dst 可能比 src 小
void cp(char *dst, size_t dcap, const char *src, size_t scap) {
    memcpy(dst, src, scap);   // 用 src 大小 => 若 scap > dcap 就越界寫
}`,
		fixed: `// 安全寫法：長度以目的緩衝容量為準,過長就截斷
void cp(char *dst, size_t dcap, const char *src, size_t scap) {
    size_t n = (scap > dcap) ? dcap : scap;   // 以 dst 容量當上限
    memcpy(dst, src, n);
}`,
		patch: `@@
 void cp(char *dst, size_t dcap, const char *src, size_t scap) {
-    memcpy(dst, src, scap);
+    size_t n = (scap > dcap) ? dcap : scap;
+    memcpy(dst, src, n);
 }`,
		refs: ['CWE-806'],
		tags: ['source-size', 'out-of-bounds', 'buffer-overflow'],
	},
	{
		id: 'CWE-821',
		name: 'Incorrect Synchronization',
		lang: 'c',
		status: 'Complete',
		what: `對共享資源的同步不正確。程式以並行方式使用某個共享資源，但沒有正確地同步對它的存取——可能要同步沒同步、或用了錯的鎖在同一個
資料上不一致地加鎖。常見成因是忘掉提 lock、在多處對同一變數有的鎖有的沒鎖、或把鎖縮得太小導致臨界區不完整。後果是兩個執行緒可同時讀寫同一份
資料，產生資料競爭（data race）：看到半更新狀態、計數失準、記憶體撕裂，甚至造成崩潰或被利用來破壞內部不變式。建議為每個共享變數明確定義它由哪
把鎖保護、加鎖與存取永遠成對、避免把保護範圍縮在資料本身的更新之外，並配合互斥鎖／原子操作讓所有讀寫路徑走同一把鎖。`,
		problem: `// 不安全寫法：一個執行緒更新的變數,另一個沒上鎖就讀
static int counter = 0;   // 由 g_lock 保護

void writer() {
    pthread_mutex_lock(&g_lock);
    counter++;              // 有鎖
    pthread_mutex_unlock(&g_lock);
}

int reader() {
    return counter;         // 沒鎖 => 與 writer 產生 data race
}`,
		fixed: `// 安全寫法：讀寫都要同一把鎖,避免資料競爭
int reader() {
    pthread_mutex_lock(&g_lock);
    int v = counter;
    pthread_mutex_unlock(&g_lock);
    return v;
}`,
		patch: `@@
 int reader() {
+    pthread_mutex_lock(&g_lock);
-    return counter;
+    int v = counter;
+    pthread_mutex_unlock(&g_lock);
+    return v;
 }`,
		refs: ['CWE-821', 'OWASP'],
		tags: ['data-race', 'synchronization', 'concurrency'],
	},
	{
		id: 'CWE-825',
		name: 'Expired Pointer Dereference',
		lang: 'c',
		status: 'Complete',
		what: `解參考過期（失效）指標。程式解靠一個指標，它指向的記憶體「以前有效、現在已無效」——這份記憶體可能已經被 free、被釋放回堆積或被換內容。
常見成因是釋放後還留著舊指標（dangling pointer）沒清掉、緩衝區重新配置後仍用舊址、或長存結構中存放的指針在某狀態變更後沒同步更新。後果是把使用
已回收記憶體、或解到已被重新配置成別的物件的位置稱之為「下類未定義」：可能讀到被篡改的內容、寫壞別人正在用的資料、雙重釋放或直接當機，也是常見的
可利用記憶體破壞。建議指標被釋放後立刻歸零，監測所有保存指標的更動（可有 slot 記錄），對常規的生命週期把「誰負責釋放、誰在釋放後還引用」列清楚，
再用 UAF 偵測器／sanitizer 在開發期就抓到。`,
		problem: `// 不安全寫法：釋放後仍留著指標,稍後又解參照
#include <stdlib.h>

char *p = malloc(64);
// ...使用 p...
free(p);            // 記憶體已回收
use(p);             // 解到已失效的 p => use-after-free`,
		fixed: `// 安全寫法：釋放後立即歸零,禁止再使用
char *p = malloc(64);
// ...使用 p...
free(p);
p = NULL;           // 之後任何 use(p) 都能被檢查擋下
if (p != NULL) use(p);`,
		patch: `@@
 free(p);
+p = NULL;
 use(p);`,
		refs: ['CWE-825'],
		tags: ['dangling-pointer', 'use-after-free', 'uaf'],
	},
	{
		id: 'CWE-826',
		name: 'Premature Release of Resource During Expected Lifetime',
		lang: 'c',
		status: 'Complete',
		what: `在資源仍在預期生命週期內就把它過早釋放。某份資源在其預期生命週期「還沒結束」時就被釋放，而它自身或另一個角色原本還要用。常見情形與
double-free、UAF 是一路親戚：callback、另執行緒、多個 owner 之間都由自己執行釋放，卻沒協調好——第一個用完就 free，其它還想用時已經沒了。常見成因是
「用完就釋」的欄位混著「別人也許還在用」的欄位共用同一介面、或沒有明確的命中期權。後果是另一位仍擁有指標的呼叫者解到已釋放的資源，讀到垃圾、
把釋放的指標當可寫緩衝，竄寫別人記憶體而當機或出錯。建議每個資源都定義明確的「最後一個 owner」執行釋放，使用引用計數／RAII 讓真正最後用到之人
才 free，且不要在同一函式裡既釋放又保留給後續呼叫。`,
		problem: `// 不安全寫法：自己用完先 free,但如早他付出的另外還在用同指標
void notify(struct buf *b) {
    // ...
}

void run(struct buf *b) {
    process(b);            // process 內部可能 async 還保留 b
    free(b);               // listener 之後用 b => premature release
    dispatch(b);           // 再碰已 free 的 b
}`,
		fixed: `// 安全寫法：引用計數,最後一個持有者才釋放
void run(struct buf *b) {
    acquire(b);            // 增加引用
    process(b);
    release(b);            // 遞減引用
    dispatch_owned(b);     // 由唯一 owner 於生命周期結束時釋放
}`,
		patch: `@@
 void run(struct buf *b) {
-    process(b);
-    free(b);
-    dispatch(b);
+    acquire(b);
+    process(b);
+    release(b);
+    dispatch_owned(b);
 }`,
		refs: ['CWE-826'],
		tags: ['premature-free', 'resource-lifetime', 'refcount'],
	},
	{
		id: 'CWE-827',
		name: 'Improper Control of Document Type Definition',
		lang: 'python',
		status: 'Complete',
		what: `對 Document Type Definition（DTD）參考的控制不當。程式解析 XML 時不限制 DTD 的參照範圍，攻擊者可透過 xml 內容注一指任意 DTD
來觸發 XXE（XML External Entity）。常見成因是直接拿未處理的解析器去 load 使用者提供的 XML、沒關閉 DT 與外部實體、或 load DTD 的網址不加白名單。
後果是這條參考能讓解析器去讀本機檔案（如 /etc/passwd）、展開巨量實體耗盡記憶體（billion laughs）當機、或代表攻擊者把伺服器當跳板發起任意 HTTP
請求，等於一次釋出讀檔、DoS 與 SSRF。建議一律使用防預設的 XML parser（如 Python 的 defusedxml、Java 關閉 external DTD），顯式禁用 DT 與外部
實體，或採非 XML 且不支援 DTD 的輕量格式。`,
		problem: `# 不安全寫法：直接解析使用者 XML,ET 預設可載入外部實體/DTD
import xml.etree.ElementTree as ET

def parse(blob):
    return ET.fromstring(blob)   # 能觸發 XXE:<!DOCTYPE ... SYSTEM "file:///etc/passwd">`,
		fixed: `# 安全寫法：用防 XXE 的解析器,禁用外部實體與 DTD
from defusedxml import ElementTree

def parse(blob):
    return ElementTree.fromstring(blob)   # 拒絕外部實體,不讀任意 DTD`,
		patch: `@@
-import xml.etree.ElementTree as ET
+from defusedxml import ElementTree

 def parse(blob):
     return ElementTree.fromstring(blob)`,
		refs: ['CWE-827', 'OWASP'],
		tags: ['xxe', 'dtd', 'xml', 'external-entity'],
	},
	{
		id: 'CWE-828',
		name: 'Signal Handler with Functionality that is not Asynchronous-Safe',
		lang: 'c',
		status: 'Complete',
		what: `訊號處理程式含有不具非同步安全性的功能。訊號 handler 內部的程式序列不是 async-signal-safe——它不可重入，也可能在執行中被同樣訊號中斷。
原因常是開發者在 handler 裡呼叫了 free()、printf()、malloc() 或複製等非 async-signal-safe 的函式，也沒有理解 spec 對 handler 的限定。後果是訊號抵達的那瞬間中斷主程式的任意執行點，handler 若碰非安全函式會破壞執行中不會被打斷的資料結構（如 heap、stdio 緩衝），造成死鎖、當機或其它未定義行為，
讓多數「收到訊號就處理」的設計變成不穩定。建議 handler 只做最低限度的 async-signal-safe 動作（寫 signal-safe fd、設 volatile sig_atomic_t 旗標），
把真正工作丟回主迴圈（透過 self-pipe 或 sigwait 的執行緒）執行；任何配置、釋放、I/O 輸出都不准在 handler 內做。`,
		problem: `// 不安全寫法：訊號 handler 裡面呼叫非 async-signal-safe 的 printf/free
#include <csignal>

void on_int(int sig) {
    printf("ctrl-c\\n");   // 非 async-signal-safe,可能死鎖/崩潰
    free(some_ptr);        // 絕不可在訊號上下文釋放記憶體
}

int main() { signal(SIGINT, on_int); /* ... */ }`,
		fixed: `// 安全寫法：handler 只設旗標,實際工作留到主迴圈
#include <csignal>
#include <atomic>

std::atomic<bool> g_interrupted{false};

void on_int(int sig) {
    g_interrupted.store(true, std::memory_order_relaxed);  // async-safe
}

int main() {
    signal(SIGINT, on_int);
    while (!g_interrupted.load(std::memory_order_relaxed)) {
        // ...正常主迴圈工作...
    }
}`,
		patch: `@@
 void on_int(int sig) {
-    printf("ctrl-c\\n");
-    free(some_ptr);
+    g_interrupted.store(true, std::memory_order_relaxed);
 }`,
		refs: ['CWE-828'],
		tags: ['signal-handler', 'async-signal-safe', 'reentrancy'],
	},
	{
		id: 'CWE-830',
		name: 'Inclusion of Web Functionality from an Untrusted Source',
		lang: 'javascript',
		status: 'Complete',
		what: `包含來自不可信來源的 web 功能。產品把別的網域上的 web 功能（如第三方 widget、script、嵌入的 iframe）直接塞進自己的頁面，導致那段外來
程式在「產品網域」的力量下執行。常見成因是想省事直接以 script 標籤載入別站的 widget.js、或嵌入別站的 widget 而沒審核其行為。後果是
外站腳本在你的網域下等同「原網域程式碼」運行：它可讀取你網域的 cookie、localStorage、攫取 CSRF token、改 DOM、發送 session，也就是把自家網域的整盤
控制與存取交到那不可信來源手上，等於種下 XSS／帳號接管。建議不要載入不可信的第三方功能；若要載，把第三方腳本換成受審核的子資源完整性（SRI, integrity
attributve）、把執行範圍隔離在 sandboxed iframe，或用 CSP 把可載入的外部來源白名單化並禁 script。`,
		problem: `<!-- 不安全寫法：從未受信網域直接帶程式,等同把我的網域控制權讓出去 -->
<script src="https://untrusted.example/tracker.js"></script>
<iframe src="https://untrusted.example/widget" ></iframe>`,
		fixed: `<!-- 安全寫法：載入受審核的來源 + 子資源完整性,外部內容隔離在 sandbox -->
<script src="/vendor/widget.built.js" integrity="sha384-XXXX" crossorigin="anonymous"></script>
<iframe sandbox="allow-scripts" src="/local-proxy-widget" ></iframe>`,
		patch: `@@
-<script src="https://untrusted.example/tracker.js"></script>
-<iframe src="https://untrusted.example/widget" ></iframe>
+<script src="/vendor/widget.built.js" integrity="sha384-XXXX" crossorigin="anonymous"></script>
+<iframe sandbox="allow-scripts" src="/local-proxy-widget" ></iframe>`,
		refs: ['CWE-830', 'OWASP'],
		tags: ['third-party-widget', 'untrusted-dom', 'xss', 'sri'],
	},
	{
		id: 'CWE-831',
		name: 'Signal Handler Function Associated with Multiple Signals',
		lang: 'c',
		status: 'Complete',
		what: `把同一個函式同時掛給多個訊號當 handler。一個函式被「一個以上」訊號註冊為處理者，於是它在不可控的時刻、也被多種訊號觸發。常見成因是為了
省行程式把 SIGINT／SIGTERM／SIGHUP 全指到同個縮寫 handler，卻沒考慮不同訊號代表不同意圖、也沒有把「訊號來自誰」區分清楚。後果是處理者可能在它
「正在被一個訊號執行」的途中另被第二個訊號重入中斷，若 handler 有共享狀態或碰非 async-safe 的動作就會資料錯亂、死鎖，甚至把不同訊號的「停機／重新載
入／刷新」語意攪在一起、執行了不該做的動作。建議若共用 handler 至少要能分辨是哪個訊號（接收 sig 參數並分別 vacation），對每個訊號配置獨立、async-safe、
可重入的最小 handler，或把機制改用 sigwait 交給專屬執行緒統一處理。`,
		problem: `// 不安全寫法：一個函式同時掛給多個訊號,無法分辨語意也易重入
#include <csignal>

void on_any(int sig) {
    // 分不出是 SIGINT 還是 SIGHUP => 停機與重載姿勢搞混
    stop_everything();
    reload_config();
}

int main() {
    signal(SIGINT, on_any);
    signal(SIGHUP, on_any);   // 兩訊號共用同一不可區分 handler
}`,
		fixed: `// 安全寫法：依訊號分流,各自做最小、async-safe 的動作
#include <csignal>
#include <atomic>

std::atomic<bool> g_reload{false};
std::atomic<bool> g_stop{false};

void on_any(int sig) {
    if (sig == SIGHUP) g_reload.store(true, std::memory_order_relaxed);
    else g_stop.store(true, std::memory_order_relaxed);
}

int main() {
    signal(SIGINT, on_any);
    signal(SIGHUP, on_any);
    signal(SIGTERM, on_any);
}`,
		patch: `@@
 void on_any(int sig) {
-    stop_everything();
-    reload_config();
+    if (sig == SIGHUP) g_reload.store(true, std::memory_order_relaxed);
+    else g_stop.store(true, std::memory_order_relaxed);
 }`,
		refs: ['CWE-831'],
		tags: ['signal-handler', 'multi-signal', 'reentrancy'],
	},
	{
		id: 'CWE-832',
		name: 'Unlock of a Resource that is not Locked',
		lang: 'c',
		status: 'Complete',
		what: `對「根本沒上鎖」的資源解鎖。程式對一個本來就沒上鎖、或早已解鎖的資源再次呼叫 unlock，破壞了加鎖／解鎖的配對保證。常見成因是錯誤
路徑與正常路徑都叫 unlock 卻沒人負責要加鎖、鎖在不同物件上傳參或用錯 id、或重複的清理邏輯對同一資源解了兩次。後果是解一個沒鎖的鎖是未定義行為：
可能把同一個鎖「多算一次釋放」讓別人的上鎖也失效、混亂計數器與等待佇列，造成多個執行緒同時進入臨界區、資料競爭或死鎖。建議嚴格維持「每次 unlock
都對應到一次確實發生的 lock」，確保同一份 lock 識別來源一致、所有分支都成對，最好使用 RAII／scope guard 讓「只在真的持有時才釋放」被型別系統強制。`,
		problem: `// 不安全寫法：keep 邏輯在同一路徑先沒上鎖又想解鎖
void contended(struct node *n) {
    if (prepare(n)) {            // 內部沒上鎖
        pthread_mutex_unlock(&g_lock);   // 解一把根本沒上的鎖
        return;
    }
    pthread_mutex_unlock(&g_lock);       // 正常路徑又解一次
}`,
		fixed: `// 安全寫法：加鎖/解鎖嚴格成對,只在確實持有時才 unlock
void contended(struct node *n) {
    if (!trylock(&g_lock)) return;        // 失敗就不會有 unlock
    if (prepare(n)) {
        pthread_mutex_unlock(&g_lock);    // 配對 trylock 的解鎖
        return;
    }
    pthread_mutex_unlock(&g_lock);        // 配對的同一次解鎖
}`,
		patch: `@@
 void contended(struct node *n) {
-    if (prepare(n)) {
-        pthread_mutex_unlock(&g_lock);
-        return;
-    }
+    if (!trylock(&g_lock)) return;
+    if (prepare(n)) {
+        pthread_mutex_unlock(&g_lock);
+        return;
+    }
     pthread_mutex_unlock(&g_lock);
 }`,
		refs: ['CWE-832'],
		tags: ['unlock-without-lock', 'mutex', 'concurrency'],
	},
];
