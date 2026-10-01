// CWE chunk — category: Concurrency / Race Conditions (Go / C).
// One chunk = one category, <= 5 entries. Every entry:
//   what    : 簡短、繁中、白話+技術描述（(#) 弱點是什麼)
//   problem : 「壞的寫法」程式片段（(#) 問題長怎樣)
//   fixed   : 「修好的寫法」程式片段（(#) 解完會長怎樣)
//   patch   : problem → fixed 的統一 diff 文字（(#) 範例 patch)
//   lang    : 此條範例主力語言，依 CWE 類別選擇
//   status  : Complete | Incomplete | Deprecated
//   refs    : 參考（OWASP / MITRE / SEI CERT 等）
//   tags    : 英文搜尋標籤
export default [
	{
		id: 'CWE-362',
		name: 'Concurrent Execution using Shared Resource with Improper Synchronization',
		lang: 'go',
		status: 'Complete',
		what: `多執行緒／多 goroutine 同時讀寫同一份共享資源，卻沒有做同步（鎖、原子操作）。
這些並行的操作互相交錯執行，最後結果取決於「誰先誰後」的執行序，行為變成不確定。
典型症狀是計數器漏數、餘額錯誤、或 slice／map 在並行寫入時直接崩潰。Go 的 -race
檢測器可抓出這種 data race。建議做法是以互斥鎖（sync.Mutex）保護臨界區，或改用原子操作，
保證「讀-改-寫」這個序列在共享資源上是不可分割的。`,
		problem: `// 不安全寫法：多 goroutine 同時對 balance 做 ++，沒有鎖 => data race
package main

import "sync"

var balance int

// 每個 goroutine 各 +1000，總數該是 N*1000，但無鎖時經常漏數
func deposit(wg *sync.WaitGroup) {
	defer wg.Done()
	for i := 0; i < 1000; i++ {
		balance++   // 讀-改-寫並非原子，交錯執行會互相覆蓋
	}
}

func main() {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go deposit(&wg)
	}
	wg.Wait()
	_ = balance // 執行完不保證是 8000
}`,
		fixed: `// 安全寫法：用 sync.Mutex 鎖住臨界區，balance 的讀改寫變成不可分割
package main

import "sync"

var (
	balance int
	mu      sync.Mutex // 保護 balance 的互斥鎖
)

func deposit(wg *sync.WaitGroup) {
	defer wg.Done()
	for i := 0; i < 1000; i++ {
		mu.Lock()   // 進入臨界區前上鎖
		balance++
		mu.Unlock() // 離開臨界區後解鎖
	}
}

func main() {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go deposit(&wg)
	}
	wg.Wait()
	if balance != 8000 { // 有鎖保證結果確定
		panic("wrong balance")
	}
}`,
		patch: `@@
- var balance int
+ var (
+     balance int
+     mu      sync.Mutex // 保護 balance 的互斥鎖
+ )
@@
-        balance++
+        mu.Lock()   // 進入臨界區前上鎖
+        balance++
+        mu.Unlock() // 離開臨界區後解鎖
@@
-    _ = balance
+    if balance != 8000 {
+        panic("wrong balance")
+    }`,
		refs: ['CWE-362', 'Go Race Detector'],
		tags: ['data-race', 'mutex', 'race-condition', 'concurrency'],
	},
	{
		id: 'CWE-364',
		name: 'Signal Handler Race Condition',
		lang: 'c',
		status: 'Complete',
		what: `訊號處理器（signal handler）本身的競態。訊號可能在程式執行到任何一點時隨時中斷進來，
handler 內呼叫的函式會與主流程或另一個 handler 交錯執行。若 handler 用了非 async-signal-safe
的函式（malloc、free、strcpy、printf、甚至自家函式），或在 handler 內沒有以 volatile sig_atomic_t
（或以 lock 保護）就共用全域狀態，就會造成記憶體損毀或再次觸發同型 bug。
建議做法是 handler 只做「標記旗標／傳遞訊號給其他執行緒」這種最小動作，把重活留到主流程處理，
且共享旗標宣告為 volatile sig_atomic_t。`,
		problem: `// 不安全寫法：handler 呼叫非 async-signal-safe 的 malloc/free/strcpy => 競態
#include <signal.h>
#include <stdlib.h>
#include <string.h>

static char g_context[64];

void on_sigusr1(int sig) {
    (void)sig;
    char *tmp = (char *)malloc(64);   // malloc 非 async-signal-safe，可與主流程 malloc 交錯
    strcpy(tmp, g_context);           // 讀取共享全域，主流程可能同時在寫它
    // ... 處理 ...
    free(tmp);                        // free 同樣不安全
}

int main(void) {
    signal(SIGUSR1, on_sigusr1);
    while (1) {
        strcpy(g_context, "working"); // 主流程同時寫全域，與 handler 競態
    }
}`,
		fixed: `// 安全寫法：handler 只設 volatile sig_atomic_t 旗標，重活移到主流程
#include <signal.h>

static volatile sig_atomic_t g_pending = 0; // 唯一在 handler 內碰的共享變數

void on_sigusr1(int sig) { (void)sig; g_pending = 1; }

int main(void) {
    struct sigaction sa = { .sa_handler = on_sigusr1 };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);
    while (1) {
        if (g_pending) {       // 主流程在安全點才處理訊號
            g_pending = 0;
            // 在這裡做實際工作（可安全使用 malloc / 改寫全域）
        }
    }
}`,
		patch: `@@
- static char g_context[64];
-
- void on_sigusr1(int sig) {
-     (void)sig;
-     char *tmp = (char *)malloc(64);
-     strcpy(tmp, g_context);
-     // ... 處理 ...
-     free(tmp);
+ static volatile sig_atomic_t g_pending = 0;
+
+ void on_sigusr1(int sig) { (void)sig; g_pending = 1; }
@@
-     signal(SIGUSR1, on_sigusr1);
+     struct sigaction sa = { .sa_handler = on_sigusr1 };
+     sigemptyset(&sa.sa_mask);
+     sigaction(SIGUSR1, &sa, NULL);
      while (1) {
-         strcpy(g_context, "working");
+         if (g_pending) {
+             g_pending = 0;
+             // 實際工作在安全點處理
+         }
      }`,
		refs: ['CWE-364', 'SEI CERT'],
		tags: ['signal-handler', 'async-signal-safe', 'race-condition'],
	},
	{
		id: 'CWE-366',
		name: 'Race Condition within a Critical Section',
		lang: 'go',
		status: 'Complete',
		what: `臨界區內的競態。程式雖然在某操作的前後上了鎖，但鎖顆粒度太粗或太細——
例如把「檢查＋動作」(check-then-act) 這組必須不可分割的步驟拆到鎖的外面，
或是用兩個不同的鎖各自保護同一個臨界區。結果是「看似有同步」，其實在鎖的間隙
仍可被另一個執行緒插進來改動共享狀態，讓判斷與使用之間的前提不一致。
修法是確保整個「讀取─判斷─寫回」序列都落在同一把鎖的保護範圍內。`,
		problem: `// 不安全寫法：先解鎖才執行動作，檢查與寫回之間留出空窗 => 臨界區內競態
package main

import "sync"

var seats = 10 // 剩餘座位
var mu sync.Mutex

// check-then-act 被拆開：Lock 後立刻 Unlock，別人在中間搶走座位
func bookBuy(uid int) bool {
	mu.Lock()
	ok := seats > 0
	mu.Unlock()           // 空窗：這裡插一個 goroutine 就能改變 seats
	if ok {
		// ... 執行付款、開票（耗時）...
		mu.Lock()
		seats--            // 等到這裡座位可能早已是 0，變成超賣
		mu.Unlock()
		return true
	}
	return false
}`,
		fixed: `// 安全寫法：檢查與扣減都在同一次上鎖的臨界區內完成 => 不可分割
package main

import "sync"

var seats = 10
var mu sync.Mutex

func bookBuy(uid int) bool {
	mu.Lock()
	defer mu.Unlock()      // 一把鎖涵蓋整個臨界區，中途絕不解鎖
	if seats <= 0 {
		return false        // 無座位直接拒絕
	}
	seats--                // 檢查與扣減連續完成，不會超賣
	return true
}`,
		patch: `@@
 		mu.Lock()
 		ok := seats > 0
-		mu.Unlock()
+		defer mu.Unlock()
 		if ok {
-			// ... 執行付款、開票（耗時）...
-			mu.Lock()
-			seats--
-			mu.Unlock()
+			// 付款、開票若耗時，可在確認庫存後選在外部進行
 			return true
 		}
 		return false`,
		refs: ['CWE-366', 'Go Race Detector'],
		tags: ['critical-section', 'check-then-act', 'race-condition', 'mutex'],
	},
	{
		id: 'CWE-367',
		name: 'Time-of-check Time-of-use (TOCTOU) Race Condition',
		lang: 'go',
		status: 'Complete',
		what: `時間差競態（TOCTOU）。程式先對某個資源做「檢查」（time-of-check），
過一段時間才用它的結果去操作（time-of-use）；檢查與使用之間有空窗，
攻擊者可趁機替換、刪除或改寫該資源。最經典的是「先檢查檔案是否存在／權限許可
再開啟」——兩個呼叫間檔案已被換成攻擊者控制的路徑（symlink 交換）。
修法是盡量用單一、原子、一次完成的系統呼叫（如 O_NOFOLLOW、openat），
或直接把「檢查」交給核心（使用者權限檢查）而不在自己程式中分開做。`,
		problem: `// 不安全寫法：先 os.Stat 檢查權限，之後才 os.Open 使用 => 中間可被換檔
package main

import (
	"os"
	"path/filepath"
)

// 攻擊者在 Stat 與 Open 之間把 cfg 換成指向敏感檔的 symlink
func readConfig(path string) ([]byte, error) {
	info, err := os.Stat(path)          // time-of-check：看是不是一般檔
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, os.ErrPermission     // 檢查動作與使用動作分開 => TOCTOU 空窗
	}
	data, err := os.ReadFile(path)     // time-of-use：此時 path 可能已被替換
	return data, err
}

func main() {
	c, _ := readConfig(filepath.Join(os.TempDir(), "cfg"))
	_ = c
}`,
		fixed: `// 安全寫法：用 O_NOFOLLOW + 單一 open 一次性完成「檢查＋開啟」
package main

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// 只開不追隨 symlink，且檢查與開啟在同一個 open 呼叫開啟、
再對回來的 fd 做單一型別判斷，檢查與使用之間沒有重新解析路徑的空窗。
func readConfig(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()              // 對已開啟的 fd 判斷，與開啟用的是同一份檔案
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, os.ErrPermission
	}
	return io.ReadAll(f) // 直接從已開啟的 fd 讀，不再按路徑重新解析 => 無空窗
}

func main() {
	c, _ := readConfig(filepath.Join(os.TempDir(), "cfg"))
	_ = c
}`,
		patch: `@@
-	info, err := os.Stat(path)
-	if err != nil {
-		return nil, err
-	}
-	if !info.Mode().IsRegular() {
-		return nil, os.ErrPermission
-	}
-	data, err := os.ReadFile(path)
-	return data, err
+	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
+	if err != nil {
+		return nil, err
+	}
+	defer f.Close()
+	info, err := f.Stat()
+	if err != nil {
+		return nil, err
+	}
+	if !info.Mode().IsRegular() {
+		return nil, os.ErrPermission
+	}
+	return io.ReadAll(f) // 直接從已開啟的 fd 讀，不再按路徑重新解析 => 無空窗`,
		refs: ['CWE-367', 'OWASP-API'],
		tags: ['toctou', 'symlink', 'race-condition', 'check-then-use'],
	},
	{
		id: 'CWE-662',
		name: 'Improper Synchronization',
		lang: 'c',
		status: 'Complete',
		what: `同步機制使用不當。程式明明「有做同步」，卻用錯方式：用兩把不同的鎖保護同一個
共享資源（第二執行緒持另一把鎖照樣闖入臨界區）、把非 async-signal-safe 的呼叫放進
handler、或是最糟的「明知自己已持有鎖又再要同一個非遞迴鎖」導致死鎖（deadlock）。
同步做不對，比完全不做更危險，因為它給人「已受保護」的錯覺而實際狀態仍可能被
同時破壞。修法是讓「每個共享資源只由一把、並且唯一一把鎖」管轄，並嚴格遵守
「先鎖、再碰共享狀態、離開前解鎖」的配對規則，避免重複上鎖。`,
		problem: `// 不安全寫法：同一份 shared_data 被兩把不同的鎖保護 => 形同沒鎖
#include <pthread.h>
#include <stdio.h>

static int shared_data = 0;
static pthread_mutex_t lock_a = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t lock_b = PTHREAD_MUTEX_INITIALIZER;

void *writer(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&lock_a);   // writer 用 lock_a
        shared_data++;
        pthread_mutex_unlock(&lock_a);
    }
}

void *reader(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&lock_b);   // reader 用不同的 lock_b => 未同步
        if (shared_data % 10 == 0) printf("%d\\n", shared_data);
        pthread_mutex_unlock(&lock_b);
    }
}`,
		fixed: `// 安全寫法：writer 與 reader 使用同一把 lock，共享資源單一管制
#include <pthread.h>
#include <stdio.h>

static int shared_data = 0;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER; // 唯一一把鎖

void *writer(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&lock);     // 與 reader 用同一把鎖
        shared_data++;
        pthread_mutex_unlock(&lock);
    }
}

void *reader(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&lock);     // writer 與 reader 互斥 => 真正同步
        if (shared_data % 10 == 0) printf("%d\\n", shared_data);
        pthread_mutex_unlock(&lock);
    }
}`,
		patch: `@@
-static pthread_mutex_t lock_a = PTHREAD_MUTEX_INITIALIZER;
-static pthread_mutex_t lock_b = PTHREAD_MUTEX_INITIALIZER;
+static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER; // 唯一一把鎖
@@
-        pthread_mutex_lock(&lock_a);
+        pthread_mutex_lock(&lock);
         shared_data++;
-        pthread_mutex_unlock(&lock_a);
+        pthread_mutex_unlock(&lock);
@@
-        pthread_mutex_lock(&lock_b);
+        pthread_mutex_lock(&lock);     // writer 與 reader 互斥 => 真正同步
         if (shared_data % 10 == 0) printf("%d\\n", shared_data);
-        pthread_mutex_unlock(&lock_b);
+        pthread_mutex_unlock(&lock);`,
		refs: ['CWE-662', 'SEI CERT'],
		tags: ['synchronization', 'mutex', 'deadlock', 'concurrency'],
	},
];
