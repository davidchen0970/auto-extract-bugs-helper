// CWE chunk — category: Error Handling.
// One chunk = one category, <= 5 entries. Every entry:
//   what    : 簡短、繁中、白話+技術描述（(#) 弱點是什麼)
//   problem : 「壞的寫法」程式片段（(#) 問題長怎樣)
//   fixed   : 「修好的寫法」程式片段（(#) 解完會長怎樣)
//   patch   : problem → fixed 的統一 diff 文字（(#) 範例 patch)
//   lang    : 此條範例主力語言，依 CWE 類別選擇
//   status  : Complete | Incomplete | Deprecated
//   refs    : 參考（MITRE / SEI CERT 等）
//   tags    : 英文搜尋標籤
export default [
	{
		id: 'CWE-248',
		name: 'Uncaught Exception',
		lang: 'java',
		status: 'Complete',
		what: `未捕捉的例外。程式會 throw 出例外，但呼叫端沒有一處 catch，例外就一路爆到最上層把執行緒／請求
直接炸掉；單一惡意或意外輸入就能讓服務回應崩潰，反覆發生就成了 DoS。常見於把「必然可能失敗」的 I/O、解析、網路操作
寫進沒有 try/catch 的區塊，且也不在邊界統一攔截。建議做法是：凡會失敗的呼叫都用精確的 try/catch 包起來、把失敗轉成
符合當下錯誤模型的受控例外，並在 app 最外層留一個兜底 handler，確保任何未預期例外也「被處理」而不是讓程序死掉。`,
		problem: `// 不安全寫法：parse 會拋 NumberFormatException 卻沒人接,輸入一爛整個請求就爆
public int readId(String raw) {
    return Integer.parseInt(raw);   // raw 不是數字 => 例外未捕捉,一路拋到最上層
}`,
		fixed: `// 安全寫法：捕捉可預期例外,轉成受控制的結果 + 診斷日誌
public int readId(String raw) {
    try {
        return Integer.parseInt(raw);
    } catch (NumberFormatException e) {
        log.error("bad id input", e);
        throw new BadRequest("invalid id");
    }
}`,
		patch: `@@
 public int readId(String raw) {
-    return Integer.parseInt(raw);
+    try {
+        return Integer.parseInt(raw);
+    } catch (NumberFormatException e) {
+        log.error("bad id input", e);
+        throw new BadRequest("invalid id");
+    }
 }`,
		refs: ['CWE-248', 'SEI CERT'],
		tags: ['uncaught-exception', 'error-handling'],
	},
	{
		id: 'CWE-388',
		name: '7PK - Errors',
		lang: 'python',
		status: 'Deprecated',
		what: `七大致命王國分類裡的「Errors」好壞（7PK - Errors）。這個 Category 曾用來統整「應用程式沒能正確處理處理過程
中發生的錯誤」這一大類，典型就是這兩個方向：不是「錯誤處理得不好或根本沒處理」，就是「產生的錯誤給人太多資訊、或難被妥善處理」。
這兩個方向下又有更精確的成員，如未檢查的錯誤（CWE-391）、未回報錯誤（CWE-392）、catch 泛型例外（CWE-396）等等。MITRE 已把這類
組織性的 Category 標記為 Deprecated，且自 2019 起不再建議拿它在實際漏洞做對映。審查錯誤路徑時保持心法不變：每條「可能失敗」的呼叫
都得有人負起「偵測、處理、回報」的責任，回報時不把內部細節外洩。`,
		problem: `# 不安全寫法:偵測到失敗卻不回報也不處理 => 錯誤被靜默吞掉
def upload(f, store):
    try:
        store.save(f)
    except OSError:
        pass           # 錯誤既沒回報也沒處理,呼叫端以為成功`,
		fixed: `# 安全寫法:錯誤被明確轉成受控例外並回報 => 錯誤處理三要素齊備
def upload(f, store):
    try:
        store.save(f)
    except OSError as e:
        raise StoreError(f"save failed for {f.name}") from e`,
		patch: `@@
 def upload(f, store):
     try:
         store.save(f)
     except OSError:
-        pass
+        raise StoreError(f"save failed for {f.name}") from e`,
		refs: ['CWE-388', 'CWE-391'],
		tags: ['7pk-errors', 'deprecated', 'error-handling'],
	},
	{
		id: 'CWE-390',
		name: 'Detection of Error Condition Without Action',
		lang: 'python',
		status: 'Complete',
		what: `偵測到錯誤卻沒有任何實際行動。程式不是沒有發現問題，而是發現之後就沒真正處理：
只 print 一段訊息、把 fallback 值記下來、甚至直接 pass 當作沒這回事，然後繼續帶著「假設成功」的狀態往下跑。
這種「吞掉錯誤」的寫法最難查，因為症狀多半出現在幾步之後的邏輯壞掉，跟真正的原因完全看不出關聯。
正確做法是偵測到錯誤時就要採取能改變控制流的行動，例如中止、回退、或明確改用備援來源。`,
		problem: `# 不安全寫法：偵測到開啟失敗卻只 print + pass，接著拿未初始化的 f 繼續讀
def load_config(path):
    try:
        f = open(path, "r")
    except OSError as e:
        print(f"cannot open {path}: {e}")   # 只印出來，什麼都不做
        pass                                 # 錯誤被吞掉
    data = f.read().upper()                  # 檔案沒開成 => 後續邏輯直接壞掉
    f.close()
    return data`,
		fixed: `# 安全寫法：偵測到錯誤就採取行動——這裡直接中止並說明原因
def load_config(path):
    try:
        with open(path, "r") as f:
            return f.read().upper()          # 資源由 with 管理
    except OSError as e:
        raise ConfigError(f"cannot load config from {path}") from e   # 有行動：中止 + 鏈結原因`,
		patch: `@@
 def load_config(path):
     try:
-        f = open(path, "r")
+        with open(path, "r") as f:
+            return f.read().upper()
     except OSError as e:
-        print(f"cannot open {path}: {e}")
-        pass
-    data = f.read().upper()
-    f.close()
-    return data
+        raise ConfigError(f"cannot load config from {path}") from e`,
		refs: ['CWE-390', 'OWASP-BrokenHandling'],
		tags: ['error-handling', 'swallowed-error', 'detection-without-action'],
	},
	{
		id: 'CWE-391',
		name: 'Unchecked Error Condition',
		lang: 'c',
		status: 'Complete',
		what: `未檢查的錯誤條件。函式會用回傳碼／errno 告訴你失敗（如 open 回 -1、malloc 回 NULL、
	int snprintf 回負數），呼叫端卻忽略這個回傳值，直接假設「一定成功」就繼續拿結果用下去。malloc 回 NULL 當作
	成功去寫就崩潰、open 失敗還去寫就寫進錯的地方、recv 回 <=0 還當收到資料就誤解析。修法是在每一支「有回傳值表示成敗」
	的呼叫後檢查那個回傳值，失敗就走錯誤分支，永遠別把失敗結果當成成功來消費。`,
		problem: `// 不安全寫法:忽略 malloc / open 的回傳錯誤 => 拿失敗結果繼續用
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int load(const char *path) {
    int fd = open(path, O_RDONLY);   // 沒檢查 open 是否 -1
    char buf[24] = {0};
    read(fd, buf, sizeof buf - 1);   // fd 是 -1 => 讀取失敗仍被當成功
    char *tmp = (char *)malloc(1024); // 沒檢查 NULL => 有可能拿 NULL 用
    strcpy(tmp, buf);                  // NULL 寫入即崩潰 (以及 fd 錯誤導致的緩衝)
    free(tmp);
    close(fd);
    return 0;
}`,
		fixed: `// 安全寫法:每一支會失敗的呼叫都檢查回傳值,失敗走錯誤分支
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int load(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;                // 檢查 open
    char tmp[1024];
    ssize_t n = read(fd, tmp, sizeof tmp - 1);
    if (n < 0) { close(fd); return -1; } // 檢查 read
    tmp[n] = '\0';
    close(fd);
    return 0;
}`,
		patch: `@@
 #include <string.h>
 
 int load(const char *path) {
-    int fd = open(path, O_RDONLY);
-    char buf[24] = {0};
-    read(fd, buf, sizeof buf - 1);
-    char *tmp = (char *)malloc(1024);
-    strcpy(tmp, buf);
-    free(tmp);
-    close(fd);
-    return 0;
+    int fd = open(path, O_RDONLY);
+    if (fd < 0) return -1;
+    char tmp[1024];
+    ssize_t n = read(fd, tmp, sizeof tmp - 1);
+    if (n < 0) { close(fd); return -1; }
+    tmp[n] = '\\0';
+    close(fd);
+    return 0;
 }`,
		refs: ['CWE-391', 'SEI CERT'],
		tags: ['unchecked-error', 'return-value', 'error-handling'],
	},
	{
		id: 'CWE-392',
		name: 'Missing Report of Error Condition',
		lang: 'java',
		status: 'Complete',
		what: `錯誤條件的回報遺失。程式偵測到並處理了錯誤，但「外面該知道這回事的人」卻完全不知道：吞掉例外不
	往上提、不記日誌、不設定失敗回傳碼、也不更新任何導致呼叫端注意到失敗的狀態。結果是上層繼續抱持「一切正常」的幻想去做
	依賴該資源的決定——把救不回來的快取當命中、把壞掉的備援當正常、把失敗的下單當成功。修法是讓「失敗」沿著合約的管道被
	傳出去：拋出受控例外／回傳失敗碼、加上有意義的錯誤訊息､並日誌化，確保任何人看了呼叫結果都能得知發生過問題。`,
		problem: `// 不安全寫法:快取讀取失敗就默默回「快取命中」=> 上層永遠不知情,當作有資料
public String getFromCache(String k) {
    try {
        return cache.get(k);
    } catch (CacheDown e) {
        return null;      // 錯誤既沒拋出、沒記日誌,呼叫端還以為「miss 正常」
    }
}`,
		fixed: `// 安全寫法:基礎設施錯誤要回報(加上日誌),不能把「快取壞了」偽裝成 「沒有值」
public String getFromCache(String k) {
    try {
        return cache.get(k);
    } catch (CacheDown e) {
        log.error("cache unreachable", e);
        throw new StorageUnavailable("cache down", e);  // 明確回報錯誤
    }
}`,
		patch: `@@
 public String getFromCache(String k) {
     try {
-        return cache.get(k);
+        return cache.get(k);
     } catch (CacheDown e) {
-        return null;
+        log.error("cache unreachable", e);
+        throw new StorageUnavailable("cache down", e);
     }
 }`,
		refs: ['CWE-392', 'SEI CERT'],
		tags: ['error-reporting', 'swallowed-error', 'log', 'error-handling'],
	},
	{
		id: 'CWE-394',
		name: 'Unexpected Status Code or Return Value',
		lang: 'python',
		status: 'Complete',
		what: `未預期的狀態碼或回傳值。程式對某個呼叫的回傳做了「等我期望的那個值」的假設，卻沒有處理「它還會
回其它值」的情況：例如把任何非零回傳碼一律當成成功、把 HTTP 404 當成成功、或只處理了 return 0 而漏掉 return -1、
halt 等其它表示「另一種發生的情況」的值。常見在吃外部 API 的小組件：只認得 200 就不再確認 body，或只比對了一個
錯誤值。修法是完整列舉所有可能的回傳／狀態，對「非預期」的值走明確的錯誤或中斷邏輯，而不是靠單一值的假設。`,
		problem: `# 不安全寫法:只比對 "ok" 一種回傳,其它回傳值全被當成成功
def push(worker, job):
    rc = worker.run(job)
    if rc == -1:          # 只處理 -1
        raise WorkerError("worker failed")
    return True           # rc==-2、"busy"、"404" 等其它值也被當成成功 => 誤判`,
		fixed: `# 安全寫法:白名單成功值,任何其它回傳都視為失敗
def push(worker, job):
    rc = worker.run(job)
    if rc != "ok":        # 只認得明確的成功值,其它通通失敗
        raise WorkerError(f"unexpected status: {rc!r}")
    return True`,
		patch: `@@
 def push(worker, job):
     rc = worker.run(job)
-    if rc == -1:
-        raise WorkerError("worker failed")
-    return True
+    if rc != "ok":
+        raise WorkerError(f"unexpected status: {rc!r}")
+    return True`,
		refs: ['CWE-394', 'SEI CERT'],
		tags: ['status-code', 'return-value', 'error-handling'],
	},
	{
		id: 'CWE-396',
		name: 'Declaration of Catch for Generic Exception',
		lang: 'java',
		status: 'Complete',
		what: `對「泛型例外」宣告 catch。用 catch (Exception e)、catch (Throwable t) 這種括到底的寫法，
等於把格式錯誤、空指標、型別轉換失誤甚至記憶體不足全部打成一類「反正失敗」。
後果是衛生錯誤被隱藏、判斷控制流混在一起、修正用的診斷資訊也消失，
問題往往要等真正出事才浮現。正確做法是只捕捉你確實能處理的最小例外類型（NumberFormatException、IOException 等），
其餘讓它自然往上拋給真正會處理它的地方。`,
		problem: `// 不安全寫法：catch(Exception) 把所有錯誤一概吞掉，連嚴重的問題也被當成「格式錯誤」
public int parse(String raw) {
    try {
        return Integer.parseInt(raw);
    } catch (Exception e) {       // 連 NPE/ClassCastException 都被當成格式錯誤
        return -1;
    }
}`,
		fixed: `// 安全寫法：只捕捉可期的最小例外類型，其餘讓它正常往上拋
public int parse(String raw) {
    try {
        return Integer.parseInt(raw);
    } catch (NumberFormatException e) {          // 精準
        throw new IllegalArgumentException("not a number: " + raw, e);
    }
}`,
		patch: `@@
     try {
         return Integer.parseInt(raw);
-    } catch (Exception e) {
-        return -1;
+    } catch (NumberFormatException e) {
+        throw new IllegalArgumentException("not a number: " + raw, e);
     }
 }`,
		refs: ['CWE-396'],
		tags: ['catch-generic', 'exception', 'error-handling'],
	},
	{
		id: 'CWE-398',
		name: '7PK - Code Quality',
		lang: 'python',
		status: 'Deprecated',
		what: `七大致命王國分類裡的「Code Quality」好壞（7PK - Code Quality）。這個 Category 統整那些「不直接造成漏洞、卻表示
該產品沒有被用心開發與維護」的弱點——未初始化的變數、永遠的 dead code、過時的 API、不良的註解等等。作者提醒：單純程式品質差本身
常不會直接被打，但它帶來「不可預測的行為」，對攻擊者而言正是「在預期外的方面去逼系統出錯」的機會。MITRE 已將這個組織性分類標記為
Deprecated，也不建議直接拿它映射實際漏洞，應往下映射到具體的成員（如未初始化變數 CWE-457、過時函式 CWE-477）。務實守則：開
啟編譯/靜態分析的最高警告層級、刪除死碼與沒用的變數、把註解換成可測的程式碼。`,
		problem: `# 不安全寫法:未用到的變數 + 永遠死路徑,讓行為不可預測又難維護
def auth(user):
    secret = compute_secret()      # 沒用到的變數(dead)
    if userrole == "admin":      # 永遠不成立的判斷(dead path)
        return "grant_all"
    if user.role == "admin":
        return "admin"
    return "user"`,
		fixed: `# 安全寫法:移除死碼,判斷條件真實可控 => 行為可預測
def auth(user):
    if user.role == "admin":
        return "admin"
    return "user"`,
		patch: `@@
 def auth(user):
-    secret = compute_secret()
-    if userrole == "admin":
-        return "grant_all"
     if user.role == "admin":
         return "admin"
     return "user"`,
		refs: ['CWE-398', 'CWE-561'],
		tags: ['7pk-code-quality', 'dead-code', 'deprecated'],
	},
	{
		id: 'CWE-404',
		name: 'Improper Resource Shutdown or Release',
		lang: 'c',
		status: 'Complete',
		what: `資源關閉／釋放不當。開啟的檔案描述符（fd）、鎖、socket 或 heap 區塊，
在某些錯誤路徑直接 return，沒有被釋放就丟棄最後一個參照。反覆發生會把 fd 與記憶體耗盡，
長期執行下效用便會退化，甚至把相關資源佔著不放。
正確做法是採用單一出口（unified exit／goto cleanup／RAII），保證每一條成功或失敗的路徑都確實關閉、釋放資源。`,
		problem: `// 不安全寫法：flock 失敗路徑直接 return，印象開著的 FILE *f 從此沒人關
#include <stdio.h>
#include <sys/file.h>
#include <unistd.h>

int lock_and_read(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return -1;
    if (flock(fileno(f), LOCK_EX) != 0) {
        return -2;                  // 忘了 fclose(f) => CWE-404
    }
    char c = fgetc(f);
    fclose(f);
    return (int)c;
}`,
		fixed: `// 安全寫法：單一出口，每一條路徑都保證釋放
#include <stdio.h>
#include <sys/file.h>
#include <unistd.h>

int lock_and_read(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return -1;
    int rc = 0;
    if (flock(fileno(f), LOCK_EX) != 0) {
        rc = -2;
        goto out;                   // 統一出口，這裡釋放
    }
    rc = fgetc(f);
out:
    fclose(f);                       // 一定關閉 FILE
    return rc;
}`,
		patch: `@@
 int lock_and_read(const char *path) {
     FILE *f = fopen(path, "rb");
     if (f == NULL) return -1;
+    int rc = 0;
     if (flock(fileno(f), LOCK_EX) != 0) {
-        return -2;
+        rc = -2;
+        goto out;                  // 統一出口，這裡釋放
     }
-    char c = fgetc(f);
+    rc = fgetc(f);
+ out:
     fclose(f);
-    return (int)c;
+    return rc;
 }`,
		refs: ['CWE-404', 'SEI CERT'],
		tags: ['resource-leak', 'file-descriptor', 'shutdown'],
	},
	{
		id: 'CWE-477',
		name: 'Use of Obsolete Function',
		lang: 'python',
		status: 'Complete',
		what: `使用過時（obsolete）的函式。程式呼叫了已被官方標記過時、刪除、或已知不安全的 API——例如 Python 的
	cgi、md5、random（非密碼用）用於安全目的、C 的 gets、strcpy，或一家框架裡列為 deprecated 的方法。過時函式往往
	保有當年的設計缺陷（安全或不安全），或已不適配現行環境、行為不保證。靠版本更新後可能直接消失、或偷偷變語意，讓程式壞在哪都不
	知道。修法是查官方文件改用建議的現代替換（hashlib 取代 md5、secrets 取代 random、getpass 處理密碼），並讓 linter
	在出現 deprecated 欄位時就出警告。`,
		problem: `# 不安全寫法:用過時的 random 模組產生關鍵 token,token 可被預測/碰撞
import random

def make_token():
    return str(random.randrange(10**15))   # random 非密碼安全,產生器可被預測`,
		fixed: `# 安全寫法:改用密碼學安全來源 secrets => token 不可預測
import secrets

def make_token():
    return secrets.token_hex(16)           # 保密學安全,不可預測`,
		patch: `@@
-import random
-
 def make_token():
-    return str(random.randrange(10**15))
+    return secrets.token_hex(16)`,
		refs: ['CWE-477', 'OWASP'],
		tags: ['obsolete-api', 'random', 'deprecated', 'crypto'],
	},
	{
		id: 'CWE-478',
		name: 'Missing Default Case in Multiple Condition Expression',
		lang: 'c',
		status: 'Complete',
		what: `多條件表示式缺少 default case。用來把「多種可能值」分派到不同動作的 switch ／對應語法，只覆蓋了
	一部分已知情況，漏掉其它可能到達的值；凡是遇到「不在清單上」的輸入，程式就沒有明確的動作——可能悄悄落到錯誤的分支、維持
	上一個狀態、或根本沒有回傳，最後行為未定義或錯誤地進入預設處理。少一個 bucket 是典型的「看起來每個 case 都覆蓋了」的常見漏洞形態。
	修法是為任何多條件的分派明確留下 default／else：對接到的未知值要麼指定成行的行為、要麼明確拒絕，而絕不默不作聲地漏掉。`,
		problem: `// 不安全寫法:switch 只處理 GET/POST,其它方法落不到任何 case => 未定義行為
#include <string.h>

const char *method_action(const char *m) {
    if (strcmp(m, "GET") == 0) return "read";
    if (strcmp(m, "POST") == 0) return "create";
    // 沒 else:PUT/DELETE/其它字串進來時沒有定義,回傳值未確定
    return unused_placeholder;   // 會被誤用/未定義
}`,
		fixed: `// 安全寫法:補上 else,未知方法明確拒絕 => 所有輸入都有定義
#include <string.h>

const char *method_action(const char *m) {
    if (strcmp(m, "GET") == 0)  return "read";
    if (strcmp(m, "POST") == 0) return "create";
    if (strcmp(m, "DELETE") == 0) return "remove";
    return "unknown";  // 明確的 default:其它方法有明確動作/拒絕
}`,
		patch: `@@
 const char *method_action(const char *m) {
     if (strcmp(m, "GET") == 0) return "read";
     if (strcmp(m, "POST") == 0) return "create";
-    return unused_placeholder;
+    if (strcmp(m, "DELETE") == 0) return "remove";
+    return "unknown";
 }`,
		refs: ['CWE-478', 'SEI CERT'],
		tags: ['default-case', 'switch', 'multicondition', 'error-handling'],
	},
	{
		id: 'CWE-546',
		name: 'Suspicious Comment',
		lang: 'python',
		status: 'Complete',
		what: `有問題的註解（Suspicious Comment）。原始碼裡留有明顯「不該出現在正式版」的記號——例如把安全檢查註解
	起來、FIXME/HACK/XXX// TODO: uncomment this、或故意留著一串「別讓人改」的說明。這種註解常是理解漏洞的線索：
	被註解掉的驗證、被繞道的檢查、暫時停用卻永久遺留的安全控制，全都直接關掉了一層防護，正式交付時仍在。它本身未必是漏洞，
	但「該強制的檢查被留言封鎖」常常就是那隻洞。建議做法是在收尾前搜出並移除這些 marker，把臨時停用的檢查改回正式啟用，
	並把註解換成說明「為什麼這裡這樣寫」。`,
		problem: `# 不安全寫法:把授權檢查整段註解起來,FIXME 遺留在正式碼 => 防護被悄悄拿掉
def delete(uid):
    # FIXME: validation disabled for now, re-enable before release
    # if not is_owner(uid): raise Forbidden
    db.delete(uid)      # 檢查被註解 => 人人可刪`,
		fixed: `# 安全寫法:註解說明原因並保留真正生效的檢查 => 防護不再被留言關閉
def delete(uid):
    if not is_owner(uid):      # 正式啟用的授權檢查
        raise Forbidden
    db.delete(uid)`,
		patch: `@@
 def delete(uid):
-    # FIXME: validation disabled for now, re-enable before release
-    # if not is_owner(uid): raise Forbidden
+    if not is_owner(uid):
+        raise Forbidden
     db.delete(uid)`,
		refs: ['CWE-546'],
		tags: ['suspicious-comment', 'fixme', 'commented-out', 'code-quality'],
	},
	{
		id: 'CWE-561',
		name: 'Dead Code',
		lang: 'c',
		status: 'Complete',
		what: `死碼（Dead Code）。原始碼中存在「永遠不會被執行到」的區塊：無條件 return 後的行、永遠為假的 if 分支
	裡的程式、沒人呼叫的函式、或 if(0){...}。死碼不執行所以「看起來無害」，但它非常危險：它常是上一次修改留下來的殘骸，
	帶著舊邏輯或舊權限判斷；不知情的人看到還以為那層防護「有生效」，刻意留著當備而實際完全沒運作——這正是「安全控制形同虛設」
	的經典來源。且死碼阻礙閱讀與維護、養出更多誤判。修法是刪除任何不可達的路徑，用涵蓋率工具確認每段碼真的有在跑，讓註釋
	「這段在做什麼」對應真實的執行。`,
		problem: `// 不安全寫法:return 之後還有 "清理與檢查",那行永遠不執行 => 檢查形同虛設
#include <string.h>

int check(const char *s) {
    return 0;            // 先 return => 下面全是 dead code
    if (!strcmp(s, "admin")) {   // 永不執行 => 授權檢查根本沒生效
        return 1;
    }
}`,
		fixed: `// 安全寫法:真要在意就把檢查移到 return 之前 => 撤掉死人路徑,邏輯回歸執行
#include <string.h>

int check(const char *s) {
    if (strcmp(s, "admin") == 0) {  // 真正會被執行到的判斷
        return 1;
    }
    return 0;
}`,
		patch: `@@
 int check(const char *s) {
-    return 0;
-    if (!strcmp(s, "admin")) {
+    if (strcmp(s, "admin") == 0) {
         return 1;
     }
+    return 0;
 }`,
		refs: ['CWE-561', 'SEI CERT'],
		tags: ['dead-code', 'unreachable', 'code-quality'],
	},
	{
		id: 'CWE-563',
		name: 'Assignment to Variable without Use (Unused Variable)',
		lang: 'python',
		status: 'Complete',
		what: `指派之後從未使用的變數（未使用變數）。判斷／賦值把值寫進某個變數，但這個值在後續任何地方都沒被讀用
	——它既沒進判斷、沒進回傳、也沒作為參數傳出。對安全而言這是「有檢查、網路／算出的結果卻完全沒有作用」的徵兆：例如算出 hasPermission
	卻拿去 return hasAccess；設定機密旗標卻沒人檢查；多算一個變數蓋過該用的值。真正想做的檢查因此被架空。修法是確保每個賦值都被使用
	（消除未用指派，或把它的值真正接進後續邏輯），讓 lint 對「assigned-and-unused」出警告後立即處理。`,
		problem: `# 不安全寫法:算出 is_allowed 卻回傳另一個未檢查的結果 => 檢查形同被架空
def delete(record, user):
    can_delete = authorize(user, record)   # 指派後沒使用
    if record.owner == user.id:          # 走的是這條,沒有 authorize 保護
        db.delete(record)
        return "ok"
    return "denied"`,
		fixed: `# 安全寫法:被指派的檢查值真正接進決策 => 授權結果確實生效
def delete(record, user):
    can_delete = authorize(user, record)
    if can_delete:                      # 使用該指派 => authorize 真正決定結果
        db.delete(record)
        return "ok"
    return "denied"`,
		patch: `@@
 def delete(record, user):
     can_delete = authorize(user, record)
-    if record.owner == user.id:
+    if can_delete:
         db.delete(record)
         return "ok"
     return "denied"`,
		refs: ['CWE-563'],
		tags: ['unused-variable', 'dead-assignment', 'code-quality'],
	},
	{
		id: 'CWE-570',
		name: 'Expression is Always False',
		lang: 'c',
		status: 'Complete',
		what: `表示式永遠為假（Expression is Always False）。某個條件在程式控制流程中「永遠不成立」——例如拿
	已驗證不可能的值去比大小、比較方向寫反（檢查 max 卻寫 < 某極小值）、或把「永不為該值的欄位」當分支條件。分支永遠不會被
	選中，意味著那條該走的邏輯／該做的檢查根本走不到：想擋下「過大值」的分支因為條件永遠 false 而從不觸發、該允許的合法路徑
	被斷掉等形式都有。修法是讓條件與實際資料可能值對得上，用測試／覆蓋率證明每個分支至少走得到，別讓一個「平行世界」的分支永遠死著。`,
		problem: `// 不安全寫法:想擋超大值,條件方向卻寫反 => 永遠為 false,保護從不觸發
#include <stdint.h>

uint8_t pack(uint16_t v) {
    // 本該擋下超過 255 的值,卻多寫了一個不可能的條件 => 整個判斷永遠不成立
    if (v > 255 && v < 0) {   // v<0 永遠 false => 整條檢查永不成立
        return 0xFF;            // 永不執行
    }
    return (uint8_t)v;        // 大於 255 的值照被截斷 => 資料損壞
}`,
		fixed: `// 安全寫法:條件寫對(>255 一個條件即可) => 超過就明確拒絕
#include <stdint.h>

uint8_t pack(uint16_t v) {
    if (v > 255) {            // 只要有餘一個"真正會成立"的條件
        return 0xFF;          // 現在能觸發 => 保護生效
    }
    return (uint8_t)v;
}`,
		patch: `@@
 uint8_t pack(uint16_t v) {
-    if (v > 255 && v < 0) {
+    if (v > 255) {
         return 0xFF;
     }
     return (uint8_t)v;
 }`,
		refs: ['CWE-570'],
		tags: ['always-false', 'logic-error', 'condition', 'code-quality'],
	},
	{
		id: 'CWE-617',
		name: 'Reachable Assertion',
		lang: 'python',
		status: 'Complete',
		what: `可觸及的斷言（Reachable Assertion）。依靠 assert 來把關「不該發生」的前提——例如用 assert 檢查權限、
	檢查輸入範圍、檢查解密成功。斷言通常在正式的 production build 被剝掉（Python 用 -O 就丟掉 assert），而且一旦把「防護邏輯」
	交給 assert，攻擊者觸發那條前提前，程式就直接以 AssertionError 崩掉那張請求，這也成了可診斷並利用的 DoS。用斷言當「安全
	檢查」是把它用在錯誤的地方：安全相關的前提必須用真正的 if＋明確拒絕來強制，斷言只留給開發期「證明我的假設」的非安全恆真式。`,
		problem: `# 不安全寫法:用 assert 當授權檢查 => -O 下若被剝離,檢查直接消失
def download(user, doc):
    assert user.is_member, "must be member"   # 授權交給 assert => 會被移除
    return docs[doc]                          # 斷言失敗也會直接崩request`,
		fixed: `# 安全寫法:授權用真實的 if+明確拒絕 => 檢查在任何 build 都有效,且不喊崩
def download(user, doc):
    if not user.is_member:                     # 明確的授權檢查
        raise Forbidden("not a member")
    return docs[doc]`,
		patch: `@@
 def download(user, doc):
-    assert user.is_member, "must be member"
+    if not user.is_member:
+        raise Forbidden("not a member")
     return docs[doc]`,
		refs: ['CWE-617', 'SEI CERT'],
		tags: ['assertion', 'reachable-assert', 'auth-check', 'panic'],
	},
	{
		id: 'CWE-684',
		name: 'Incorrect Provision of Specified Functionality',
		lang: 'javascript',
		status: 'Complete',
		what: `提供功能的規格錯誤（Incorrect Provision of Specified Functionality）。程式「對表面宣稱／由其說明文件所
	保證的功能」其實沒提供，或提供的是另一套行為：宣告要加密卻只做 base64、宣稱要驗籤卻只用比大小代替、
	「距離排序」結果根本沒排序。問題是呼叫端跟依賴它做判斷的邏輯全都相信「這函式真的做到那份功能」，於是把「該保護的資料」交給
	一群沒在守住承諾的函式。修法是讓每個模組的實作真正滿足它的 API 契約、針對每項宣稱功能補上驗證性測試，把「說了有做」變成
	「做了且測了」。`,
		problem: `// 不安全寫法:宣告是加密,實作是 base64 => 看似加密實則可被解密
function protect(secret) {
  // 名字叫 encrypt,其實只是編碼 => 戳掉"加密"這項功能
  return Buffer.from(secret).toString('base64');
}`,
		fixed: `// 安全寫法:實作真的提供宣稱的加密 => 功能與契約一致
const crypto = require('crypto');

function protect(secret, key) {
  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  return Buffer.concat([c.update(secret), c.final()]);  // 真正加密
}`,
		patch: `@@
 function protect(secret) {
-  return Buffer.from(secret).toString('base64');
+  const iv = crypto.randomBytes(16);
+  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
+  return Buffer.concat([c.update(secret), c.final()]);
 }`,
		refs: ['CWE-684'],
		tags: ['functionality', 'fake-encryption', 'contract', 'code-quality'],
	},
	{
		id: 'CWE-699',
		name: 'Software Development',
		lang: 'python',
		status: 'Deprecated',
		what: `軟體開發（Software Development）。這曾是 CWE 的 View（Software Development）層面的「總括分類」，用來把
	CWE 依「開發視角」切出分散在不同概念的弱點，方便開發流程（需求、設計、實作、測試）裡被引用。它本身不是一個具體弱點，而是
	組織整理的容器——依用途 MITRE 現在把這類 View 標記為 Deprecated，不建議直接用它在單一漏洞做映射。做 REVIEW 時它提醒的角度
	仍然有用：看一個弱點該由「設計（D）」還是「實作（I）」或「處理（O）」層負責，從那一個階層去補強最有效。實務上仍應映射到
	具體的基層/變異層弱點，而不是掛這個開發層容器。`,
		problem: `# 代表性壞例:CWE-699 是 "可見防線",底下常見的實作漏是在 O/I 層錯手
def serve(handler, conn):
    # 這整塊是"實作階段"的位置:可見該在哪一層補強
    do_dangerous(conn)      # 沒有在處理層放任何檢查 => 開發視角層面漏蓋`,
		fixed: `# 代表性好例:按 設計(O)/實作(I)/運維 分層各自補強,而不是靠一個容器分類
def serve(handler, conn):
    if not validate_request(conn):   # 實作層:進入前驗證
        return
    audit(conn)                    # 運維層:留稽核
    do_dangerous(conn)`,
		patch: `@@
 def serve(handler, conn):
-    do_dangerous(conn)
+    if not validate_request(conn):
+        return
+    audit(conn)
+    do_dangerous(conn)`,
		refs: ['CWE-699', 'CWE-1008'],
		tags: ['software-development', 'view', 'deprecated'],
	},
	{
		id: 'CWE-703',
		name: 'Improper Check or Handling of Exceptional Conditions',
		lang: 'go',
		status: 'Complete',
		what: `例外狀況的檢查或處理不當（Improper Check or Handling of Exceptional Conditions）。遇到錯誤、極端值、
	壞輸入這類「非常態狀況」時，程式沒有以符合安全模型的方式來檢查／處理——常見組合是「要嘛完全沒檢查、要嘛檢查了卻處理錯」。
	例如某條件該回到失敗路徑卻回到成功路徑、該中止卻繼續往下用壞資料、該回 sanitize 卻原樣輸出。這種「處理了但處理得讓系統更糟」與
	「該檢查卻不檢查」兩面都算。這是錯誤處理的上層抽象：具體上需要對每種狀況定義「正確結果」並用唯一出口強制。修法是建立統一的
	錯誤模型：每個失敗的呼叫都要有成交檢查＋把失敗轉成安全語意＋在最外層兜底，讓例外狀況絕不會被「誤當作成功」走下去。`,
		problem: `// 不安全寫法:遇到解析錯誤仍回成功 => 例外狀況被當作正常往下走
package main

func lookup(db map[string]string, k string) string {
	// 沒檢查 key 是否存在,直接回零值 => 例外(不存在)被當成"有值"
	v, _ := db[k]       // k 不存在 => v=="",呼叫端以為有值
	return v
}`,
		fixed: `// 安全寫法:用 ok 明確檢查例外,並回報 => 例外狀況不會被當成成功
package main

import "errors"

var ErrMissing = errors.New("missing key")

func lookup(db map[string]string, k string) (string, error) {
	v, ok := db[k]
	if !ok {
		return "", ErrMissing   // 例外被明確回報,不是假裝有值
	}
	return v, nil
}`,
		patch: `@@
-func lookup(db map[string]string, k string) string {
-	v, _ := db[k]
-	return v
+func lookup(db map[string]string, k string) (string, error) {
+	v, ok := db[k]
+	if !ok {
+		return "", ErrMissing
+	}
+	return v, nil
 }`,
		refs: ['CWE-703', 'CWE-755'],
		tags: ['exceptional-condition', 'error-handling', 'edge-case'],
	},
	{
		id: 'CWE-755',
		name: 'Improper Handling of Exceptional Conditions',
		lang: 'python',
		status: 'Complete',
		what: `例外狀況處理不當（Improper Handling of Exceptional Conditions）。程式遇到預期外的例外（例外被 throw、回傳
	碼表示異常、極端值）時，處理方式不當：吞掉後繼續用壞狀態、把例外訊息整個外洩給呼叫端、或靠「反正不會發生」的心態完全不處理
	，結果某個小異常一路擴大成狀態錯亂甚至崩潰。成因常是「只在正常路徑上驗證」，沒為失敗路徑設計等價的處理。修法是對每一支會失敗
	的呼叫明確定義失敗行為：攔截並轉成安全語義、記錄日誌、走安全預設或中止，讓任何例外狀況都有明確且安全的歸屬，而不是靠運氣。`,
		problem: `# 不安全寫法:捕捉後把內部細節拋給呼叫端,且繼續返回低品質預設 => 例外處理不當
def ticket(app, id):
    try:
        return db.get(id)["title"]
    except Exception as e:
        return {"error from db": str(e)}   # 內部細節外洩給外部,還掛了汙染`,
		fixed: `# 安全寫法:記錄細節,對外回通用安全結果 => 例外處理收斂且安全
def ticket(app, id):
    try:
        return db.get(id)["title"]
    except Exception as e:
        logger.exception("ticket lookup failed")   # 細節留在日誌
        raise NotFound("ticket not available")     # 對外安全、且明確中止`,
		patch: `@@
 def ticket(app, id):
     try:
         return db.get(id)["title"]
     except Exception as e:
-        return {"error from db": str(e)}
+        logger.exception("ticket lookup failed")
+        raise NotFound("ticket not available")`,
		refs: ['CWE-755', 'CWE-248'],
		tags: ['exceptional-handling', 'error-disclosure', 'error-handling'],
	},
	{
		id: 'CWE-1018',
		name: 'Manage User Sessions',
		lang: 'python',
		status: 'Deprecated',
		what: `管理使用者工作階段（Manage User Sessions）。這是架構概念分類（Architectural Concepts）裡組織「工作階段
	(session) 設計」相關弱點的容器：session-ID 的長度與隨機性、session 過期、session 綁定錯誤資料、Session Fixation、以及在多請求
	之間如何保存與切換使用者的存取權限。它是設計層的容器而非具體弱點，因此 MITRE 現在標記為 Deprecated 並不建議拿它直接映射實際
	漏洞；要標記時請往下映射到成員，如 Session Fixation（CWE-384）、session 過期不足（CWE-613）、資料被錯誤綁到別人的 session
	（CWE-488）等。設計面守則不變：每次請求都要正確鑑別身份、SESSION 要夠長夠隨機、對權益變更即時撤銷。`,
		problem: `# 代表性壞例:session 只在建立時檢查,權限變更也不主動撤銷 => session 管理鬆散
def api(request):
    sid = request.cookies["SID"]
    sess = store.get(sid)                 # 沒檢查 sid 是否失效/過期
    return serve_with(sess)               # 會話權益異動後仍照舊放行`,
		fixed: `# 代表性好例:每個請求重新鑑別身份並檢查過期 => session 生命週期受管
def api(request):
    sid = request.cookies["SID"]
    sess = store.validate(sid)            # 重新驗證 session(過期/撤銷都擋)
    if sess is None:
        raise Unauthorized
    return serve_with(sess)`,
		patch: `@@
 def api(request):
     sid = request.cookies["SID"]
-    sess = store.get(sid)
+    sess = store.validate(sid)
+    if sess is None:
+        raise Unauthorized
     return serve_with(sess)`,
		refs: ['CWE-1018', 'CWE-384'],
		tags: ['session', 'manage-user-sessions', 'deprecated'],
	},
	{
		id: 'CWE-1184',
		name: 'SEI CERT Perl Coding Standard - Guidelines 06. Object-Oriented Programming (OOP)',
		lang: 'perl',
		status: 'Deprecated',
		what: `SEI CERT Perl 編碼規範第 06 節：物件導向程式設計（OOP）。這是把「SEI CERT Perl Coding Standard」的
	OOP 章節對應到 CWE 的一組分類，涵蓋如「透過 public method 存取到關鍵 private 變數」（CWE-767）等由該規範引用的規約。它
	是規範對映所用的 Category，不是一個可對映的具體漏洞，因此 MITRE 已標記為 Deprecated。用那組分類審視 Perl OOP 實務時要抓的
	還是「封裝是否被外洩、共享物件的內部狀態是否被人繞過顧及就讀寫」，這些在更精確的弱點（如不安全的直接存取、Taint）能找到對應。
	務實守則：用物件封裝限制外部對內部狀態的寫入，別讓公開 method 因為側效應改動關鍵 private 欄位，除非有個可說明的授權用途。`,
		problem: `# 代表性壞例:public 方法直接暴露/改動關鍵 private 欄位 => OOP 規約所慮的狀態外洩
package Widget;
sub new { my ($c,$x)=@_; bless { _secret => $x }, $c }
sub change_bg { my ($s,$v)=@_; $s->{_secret}=$v; return $v }  # 公開法直接碰關鍵欄位`,
		fixed: `# 代表性好例:關鍵欄位只由封閉的存取器、並伴隨檢查更新 => OOP 規約內的狀態受顧
package Widget;
sub new { my ($c,$x)=@_; bless { _secret => $x }, $c }
sub get_secret { return $_[0]->{_secret} }
sub change_bg {
    my ($s,$v)=@_;
    die "no" unless positive($v);   # 關鍵欄位由受控方法改動
    $s->{_secret}=$v;
    return $s->{_secret};
}`,
		patch: `@@
 sub new { my ($c,$x)=@_; bless { _secret => $x }, $c }
-sub change_bg { my ($s,$v)=@_; $s->{_secret}=$v; return $v }
+sub get_secret { return $_[0]->{_secret} }
+sub change_bg {
+    my ($s,$v)=@_;
+    die "no" unless positive($v);
+    $s->{_secret}=$v;
+    return $s->{_secret};
+}`,
		refs: ['CWE-1184', 'SEI CERT'],
		tags: ['perl', 'oop', 'cert-perl', 'deprecated'],
	},
	{
		id: 'CWE-1335',
		name: 'Incorrect Bitwise Shift of Integer',
		lang: 'c',
		status: 'Complete',
		what: `整數位元搬移（shift）錯誤。對整數做左移／右移時，搬移量是負數、或大於等於該整數的位元數
	——C 語言裡這是未定義行為，各架構的實作截然不同（例如把負搬移量取 2 補數後遮成低 6 bit 會得到完全不同的數）、
	其它語言則可能給出錯誤結果或例外。結果是算了錯的 bit-mask、寫到錯誤的同伴、入侵任狀態被設錯，進而越界存取或當機。
	成因常是搬移量來自外部數值或算出來的差，沒檢查範圍。修法是在 shift 前確認量 >0 且 < 型別的位元數,越界就走錯誤
	分支，絕不讓未定義的搬移發生。`,
		problem: `// 不安全寫法:搬移量由外部差值決定,可為負值或超標 => 未定義行為
#include <stdbool.h>

// bit_number 可從外部算出負的值或超過 31 => 搬移未定義
unsigned int set_bit(unsigned int reg, int bit_number) {
    return reg | (1u << bit_number);   // 負數/>=位元數 => 未定義搬移=>錯的 bit
}

bool test_bit(unsigned int r, int n) {
    return (r >> n) & 1u;           // 同樣,未檢查就右移
}`,
		fixed: `// 安全寫法:搬移前確認範圍,越界回錯 => 行為有定義
#include <stdbool.h>

int set_bit(unsigned int *reg, int bit_number) {
    if (bit_number < 0 || bit_number >= 32) {
        return -1;                    // 越界明確拒絕,不做未定義搬移
    }
    *reg |= (1u << bit_number);
    return 0;
}`,
		patch: `@@
-unsigned int set_bit(unsigned int reg, int bit_number) {
-    return reg | (1u << bit_number);
-}
-
-bool test_bit(unsigned int r, int n) {
-    return (r >> n) & 1u;
+int set_bit(unsigned int *reg, int bit_number) {
+    if (bit_number < 0 || bit_number >= 32) {
+        return -1;
+    }
+    *reg |= (1u << bit_number);
+    return 0;
 }`,
		refs: ['CWE-1335', 'CWE-682'],
		tags: ['bit-shift', 'shift-overflow', 'undefined-behavior', 'integer'],
	},
];
