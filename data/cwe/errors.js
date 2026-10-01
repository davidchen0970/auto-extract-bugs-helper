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

		what: `未捕捉的例外。當程式在執行時丟出例外卻沒有任何能夠接住它的處理器，
例如從服務端點或執行緒邊界一路往外爆開、或是 catch 寫得太窄，
程式就會以未定義狀態中止。這類隨機當機不但讓請求莫名失敗，
壞路徑上已開啟的連線與檔案也可能計算不到就流失。
正確做法是讓每條可能失敗的路徑都有明確的 catch，把例外記錄下來並轉成受控、可理解的失敗回應。`,

		problem: `// 不安全寫法：寫設定檔時沒捕捉例外，FileWriter 一丟 IOException 就直接爆出去
public void persist(String content) {
    FileWriter w = new FileWriter(path);   // 可能丟出 IOException
    w.write(content);
    w.close();
}`,

		fixed: `// 安全寫法：用 try-with-resources 明確捕捉例外，記錄原因並轉成受控錯誤
public void persist(String content) {
    try (FileWriter w = new FileWriter(path)) {
        w.write(content);                  // 資源自動關閉
    } catch (IOException e) {
        log.error("persist failed", e);    // 留下可診斷的線索
        throw new PersistException("unable to write profile", e);  // 受控例外
    }
}`,

		patch: `@@
 public void persist(String content) {
-    FileWriter w = new FileWriter(path);   // 可能丟出 IOException
-    w.write(content);
-    w.close();
+    try (FileWriter w = new FileWriter(path)) {
+        w.write(content);
+    } catch (IOException e) {
+        log.error("persist failed", e);
+        throw new PersistException("unable to write profile", e);
+    }
 }`,

		refs: ['CWE-248', 'SEI CERT'],
		tags: ['uncaught-exception', 'error-handling'],
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
+     int rc = 0;
      if (flock(fileno(f), LOCK_EX) != 0) {
-         return -2;
+         rc = -2;
+         goto out;                  // 統一出口，這裡釋放
      }
-     char c = fgetc(f);
+     rc = fgetc(f);
+ out:
      fclose(f);
-     return (int)c;
+     return rc;
  }`,

		refs: ['CWE-404', 'SEI CERT'],
		tags: ['resource-leak', 'file-descriptor', 'shutdown'],
	},
];
