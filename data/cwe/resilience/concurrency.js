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
+	return io.ReadAll(f)
 	return data, err
 }`,
		refs: ['CWE-367', 'SEI CERT'],
		tags: ['toctou', 'check-then-act', 'symlink', 'race-condition'],
	},
	{
		id: 'CWE-368',
		name: 'Context Switching Race Condition',
		lang: 'go',
		status: 'Complete',
		what: `上下文切換競態（Context Switching Race Condition）。多執行緒／多 goroutine 共享某個狀態，程式誤以為
「執行是連續不被打斷的」，把「讀─改─寫」當成單一動作，卻在兩個步驟之間會發生排程器把 CPU 切給另一個執行緒——也就是
在被搶佔的點上，別人都可以進來改同一份資料。經典如「非原子的 ++」、check-then-act、或拿局部快取決定全域動作；結果是計數漏、
超額、狀態被改到一半。修法與一般 data race 一致：把「必須不可分割」的序列包進互斥鎖或原子操作，並清楚知道「哪一行到尾行
之間的點都會被切換」，不要在切換敏感的位置讀寫共享狀態。`,
		problem: `// 不安全寫法：mapper 誤以為 Read/Add 連續執行,切換點之間可被別的 goroutine 插手
package main

import "sync"

// 找不到就放進 map 的 prune:兩個步驟間 CPU 可能被切走 => 次數漏算
var hits = map[string]int{}
var wg sync.WaitGroup

func record(key string) {
	// 讀取 + 檢查之間就是切換點
	if _, ok := hits[key]; !ok {   // check
		hits[key] = 1              // act(這裡與上面之間可被切走重複跑)
	} else {
		hits[key]++
	}
}`,
		fixed: `// 安全寫法：把檢查與更新都放進同一把鎖 => 切換點不再要命
package main

import "sync"

var (
	hits = map[string]int{}
	mu   sync.Mutex
)

func record(key string) {
	mu.Lock()               // 上鎖後整段不會被打斷
	if _, ok := hits[key]; !ok {
		hits[key] = 1
	} else {
		hits[key]++
	}
	mu.Unlock()
}`,
		patch: `@@
-var hits = map[string]int{}
+var (
+	hits = map[string]int{}
+	mu   sync.Mutex
+)
@@
 func record(key string) {
-	if _, ok := hits[key]; !ok {
+	mu.Lock()
+	if _, ok := hits[key]; !ok {
 		hits[key] = 1
 	} else {
 		hits[key]++
 	}
+	mu.Unlock()
 }`,
		refs: ['CWE-368', 'Go Race Detector'],
		tags: ['context-switch', 'race-condition', 'preemption', 'data-race'],
	},
	{
		id: 'CWE-567',
		name: 'Unsynchronized Access to Shared Data in Multithreaded Context',
		lang: 'c',
		status: 'Complete',
		what: `多執行緒環境下對共享資料的未同步存取。同一份變數或結構被多條執行緒當 shared 使用，卻沒有任何同步機制
	（沒有鎖、沒用原子、沒用 thread-local），每條執行緒都直接讀寫它。交錯執行時彼此看到的取值互相殘破：讀到半寫入的狀態、
	計數漏數、指標被寫到一半而被別執行緒拿來用。這比「有鎖但鎖錯」更原始——根本沒鎖。即便是「只在啟動寫、之後唯讀」或
	「緊接著就讀」都要明確同步才能保證可視性。修法是讓所有共享變數都被一顆鎖管著取用，或用 stdatomic 的原子操作與正確的
	memory order，從根子上把「未同步存取」消掉。`,
		problem: `// 不安全寫法:全域 shared 直接在各執行緒讀寫,沒有任何同步 => 交錯讀寫
#include <pthread.h>
#include <stdint.h>

static uint32_t counter = 0;      // 各執行緒直接 counter++,無鎖/無原子

void *worker(void *arg) {
    (void)arg;
    for (int i = 0; i < 100000; i++) {
        counter++;                 // 未同步的讀-改-寫 => 交錯會漏數
    }
    return NULL;
}`,
		fixed: `// 安全寫法:改用 atomic 讀寫 => 對共享資料的取用是有同步的
#include <pthread.h>
#include <stdatomic.h>

static _Atomic uint32_t counter = 0;   // 原子計數 => 讀寫不會交錯撕裂

void *worker(void *arg) {
    (void)arg;
    for (int i = 0; i < 100000; i++) {
        atomic_fetch_add(&counter, 1);
    }
    return NULL;
}`,
		patch: `@@
-#include <stdint.h>
-
-static uint32_t counter = 0;      // 各執行緒直接 counter++,無鎖/無原子
+#include <stdatomic.h>
+
+static _Atomic uint32_t counter = 0;
@@
-        counter++;
+        atomic_fetch_add(&counter, 1);`,
		refs: ['CWE-567', 'SEI CERT'],
		tags: ['unsynchronized-access', 'shared-data', 'atomic', 'race-condition'],
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
- static pthread_mutex_t lock_a = PTHREAD_MUTEX_INITIALIZER;
- static pthread_mutex_t lock_b = PTHREAD_MUTEX_INITIALIZER;
+ static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER; // 唯一一把鎖
@@
-         pthread_mutex_lock(&lock_a);
+         pthread_mutex_lock(&lock);
         shared_data++;
-         pthread_mutex_unlock(&lock_a);
+         pthread_mutex_unlock(&lock);
@@
-         pthread_mutex_lock(&lock_b);
+         pthread_mutex_lock(&lock);
         if (shared_data % 10 == 0) printf("%d\\n", shared_data);
-         pthread_mutex_unlock(&lock_b);
+         pthread_mutex_unlock(&lock);`,
		refs: ['CWE-662', 'SEI CERT'],
		tags: ['synchronization', 'mutex', 'deadlock', 'concurrency'],
	},
	{
		id: 'CWE-664',
		name: 'Improper Control of a Resource Through its Lifetime',
		lang: 'go',
		status: 'Complete',
		what: `對資源生命周期的控制不當。程式把某個資源的生命周期交給「不是真正擁有者」的地方、或對它做了過早／過晚
	的處理——例如把內部 map、slice 或結構的參考直接洩給呼叫端／其它執行緒，別人就能在擁有者還要用時把元素移除或改掉；
	或是在物件仍被引用時就解鎖、close、free。於是在「資源客效力期間之外」仍有人對它操作，落到 use-after-free、過早釋放、
	狀態被半開狀態摸走等一組問題，本質是把「誰擁有、何時有效、何時失效」的邊界錯放了。修法是嚴格定義每個資源的 owner，
	存取一律透過受控的介面，分享出去盡量給（含拷貝／immutable）副本而非裸參考，並用 RAII／defer 讓釋放與擁有者對齊。`,
		problem: `// 不安全寫法:把內部 mutable 參考直接傳出去 + 提前解鎖 => 生命周期邊界失控
package main

import "sync"

var (
	cache = map[string]*Item{}
	mu    sync.Mutex
)

func TakeLocked(key string) *Item {
	mu.Lock()
	defer mu.Unlock()        // 一 return 就解鎖,但內部 *Item 仍然漏出去
	it := cache[key]        // 外部拿到後在無鎖下繼續改/删 => 生命周期錯放
	return it
}`,
		fixed: `// 安全寫法:交出去之前解引用成副本,並延後釋放點與擁有者對齊 => 邊界清楚
package main

import "sync"

var (
	cache  = map[string]*Item{}
	mu     sync.Mutex
)

func Get(key string) (Item, bool) {
	mu.Lock()
	defer mu.Unlock()
	if it, ok := cache[key]; ok {
		return *it, true    // 回傳的是拷貝,外部改不到內部共享物件
	}
	return Item{}, false
}`,
		patch: `@@
-func TakeLocked(key string) *Item {
-	mu.Lock()
-	defer mu.Unlock()
-	it := cache[key]
-	return it
+func Get(key string) (Item, bool) {
+	mu.Lock()
+	defer mu.Unlock()
+	if it, ok := cache[key]; ok {
+		return *it, true
+	}
+	return Item{}, false
 }`,
		refs: ['CWE-664', 'CWE-416'],
		tags: ['resource-lifetime', 'ownership', 'use-after-free', 'escape'],
	},
	{
		id: 'CWE-667',
		name: 'Improper Locking',
		lang: 'c',
		status: 'Complete',
		what: `鎖定（locking）不當。涉及「先取得某權利再執行動作」的序列沒有用鎖（或沒用在點上）保護：程式把「權限/slot/
	唯一性」這類可被並行爭奪的權利當成「只要讀到就可以動手」，卻沒有在上鎖後才重新確認。鎖的時機錯了——先動作、鎖等在那，
	或被取走後沒有照著鎖的約束——就會有多個執行緒同時進入「只該有一個」的動作（同時用同一個 slot、同時 refill 一次、同時
	授出同一張票）。修法是讓「檢查可不可做」與「做」都發生在持鎖區間內，保證每個並行請求都排隊宅重確認，權利在被使用的
	那一刻仍然有效。`,
		problem: `// 不安全寫法:lock 在 commit 前一刻才拿,期間多執行緒都認為 slot 可用 => 鎖拿得太慢
#include <pthread.h>

static int slots[8];
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

// "檢查哪個 slot 空" 沒有鎖保護,別人同時也找到同一個空 slot
int reserve(int id) {
    for (int i = 0; i < 8; i++) {
        if (slots[i] == 0) {        // 檢查"沒被鎖"包著 => 可並行整個
            pthread_mutex_lock(&mtx);
            slots[i] = id;           // 到這裡別人也選中了同樣的 i
            pthread_mutex_unlock(&mtx);
            return i;
        }
    }
    return -1;
}`,
		fixed: `// 安全寫法:檢查與標記都在同一把鎖內完成 => 每個 slot 只會被發一次
#include <pthread.h>

static int slots[8];
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

int reserve(int id) {
    pthread_mutex_lock(&mtx);
    for (int i = 0; i < 8; i++) {
        if (slots[i] == 0) {
            slots[i] = id;          // 檢查與標記在持鎖區間 => 不可並行
            pthread_mutex_unlock(&mtx);
            return i;
        }
    }
    pthread_mutex_unlock(&mtx);
    return -1;
}`,
		patch: `@@
 int reserve(int id) {
+    pthread_mutex_lock(&mtx);
     for (int i = 0; i < 8; i++) {
-        if (slots[i] == 0) {
-            pthread_mutex_lock(&mtx);
-            slots[i] = id;
-            pthread_mutex_unlock(&mtx);
+        if (slots[i] == 0) {
+            slots[i] = id;
+            pthread_mutex_unlock(&mtx);
             return i;
         }
     }
+    pthread_mutex_unlock(&mtx);
     return -1;
 }`,
		refs: ['CWE-667', 'SEI CERT'],
		tags: ['improper-locking', 'check-then-act', 'critical-section'],
	},
	{
		id: 'CWE-764',
		name: 'Multiple Locks of a Critical Resource',
		lang: 'go',
		status: 'Complete',
		what: `對同一臨界資源重複上鎖。同一個執行緒（或不同執行緒蓄意地）把「同一把不可重入的鎖」上了兩層——在已經
	持鎖／同一份資源被鎖住的狀況下又嘗試再取同一把：遞迴（非 reentrant 鎖內再 lock）會直接把自己等死成 deadlock；由不同
	執行緒同時都想鎖「都已先鎖住另一把」的交叉鎖則一起僵死（互相等）。即使「以為不同鎖」實際卻指向同一把，也會造成同一針極。
	修法是維持「鎖是排他占用、不可堆疊」的事實：用可 reentrant 的鎖或在進鎖前確認還未持有，並對「多執行緒各拿一把資源鎖」
	的組合統一排序，讓取鎖順序一致以避免互相等待。`,
		problem: `// 不安全寫法:非 reentrant 鎖在同一個 goroutine 內被連續拿兩層 => 自己把自己鎖死
package main

import "sync"

var mu sync.Mutex

func inner() {
	mu.Lock()          // 第二層 lock(非 reentrant)=> 死鎖:在等外層自己
	defer mu.Unlock()
}

func outer() {
	mu.Lock()          // 第一層 lock
	inner()          // 這裡又去 lock 同一把 => deadlock
	defer mu.Unlock()
}`,
		fixed: `// 安全寫法:改以 sync.Mutex 的單次持有 + 需要遞迴處拆解成不重疊的臨界區
package main

import "sync"

var mu sync.Mutex

func innerLocked() {      // 只在已持鎖的函式內處理,不再自己再 lock
	// inner 的工作假設呼叫者已持鎖
}

func outer() {
	mu.Lock()
	defer mu.Unlock()
	innerLocked()        // 不再重複上鎖 => 不會 deadlock
}`,
		patch: `@@
-func inner() {
-	mu.Lock()
-	defer mu.Unlock()
-}
-
 func outer() {
 	mu.Lock()
-	inner()
 	defer mu.Unlock()
+	innerLocked()
 }`,
		refs: ['CWE-764', 'CWE-833'],
		tags: ['multiple-locks', 'deadlock', 'reentrant', 'locking'],
	},
	{
		id: 'CWE-820',
		name: 'Missing Synchronization on Function or Variable',
		lang: 'go',
		status: 'Complete',
		what: `對「函式或變數」的同步機制缺失。一段函式／一個共用變數「理當要被同步保護」——它在並行執行的情境下被讀寫、
	或夾帶「檢查─動作」的不可分割序列——但程式沒給它任何同步（沒有鎖、沒有原子、沒有 once 保證）。結果是函式可能在奇怪的時點
	被同時進入、變數在交錯下看到半新舊值，最後落在未定義行為或錯狀態。常發在「啟動後再也不會變」所以「順手沒鎖」的變數，
	這種「只啟動寫、之後閱讀」依然需要正確的同步才保證可見性。修法是對每個共享變數決定它該用的同步機制（mutex、atomic、sync.Once、
	Happens-before),把該鎖的臨界區真的用 lock 圍起來。`,
		problem: `// 不安全寫法:共享的設定變數沒有同步 => concurrent 上下文錯半的讀寫
package main

import (
	"fmt"
	"sync"
)

var factor int          // 共享變數,既沒有 lock 也沒有原子

func scale(x int) int {
	return x * factor   // 另一 goroutine 同時在寫 factor => 讀到半狀態
}

func main() {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); factor = 3 }()
	fmt.Println(scale(10))
	wg.Wait()
}`,
		fixed: `// 安全寫法:用 atomic 存取共享變數 => 讀寫都同步,可見性有保證
package main

import (
	"fmt"
	"sync"
	"sync/atomic"
)

var factor int64              // atomic => 讀寫原子且可見

func scale(x int64) int64 {
	return x * atomic.LoadInt64(&factor)
}

func main() {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); atomic.StoreInt64(&factor, 3) }()
	fmt.Println(scale(10))
	wg.Wait()
}`,
		patch: `@@
 import (
 	"fmt"
 	"sync"
+	"sync/atomic"
 )
 
-var factor int
+var factor int64
 
-func scale(x int) int {
-	return x * factor
+func scale(x int64) int64 {
+	return x * atomic.LoadInt64(&factor)
 }
@@
-	go func() { defer wg.Done(); factor = 3 }()
+	go func() { defer wg.Done(); atomic.StoreInt64(&factor, 3) }()`,
		refs: ['CWE-820', 'Go Race Detector'],
		tags: ['missing-synchronization', 'data-race', 'atomic'],
	},
	{
		id: 'CWE-833',
		name: 'Deadlock',
		lang: 'go',
		status: 'Complete',
		what: `死鎖（deadlock）。兩個或以上的執行緒互相等一個由對方持有、且都不會再還出來的鎖或資源，於是一群人永遠停轉
	等下去，誰也動不了。常見的成因：非 reentrant 鎖在同線疊兩層；多執行緒以「不一致的順序」去取同一組多把鎖（A 等 B、B 等 A）；
	鎖在某條出錯路徑忘了還。死鎖會把部分功能永久凍結，若狀態保持在「半更新」狀態更危險。修法是：只在必要處取鎖且取鎖順序全隊統一、
	用 try-lock 或帶逾時的取鎖避免無限等、保證每一條路徑（含錯誤／panic）都在離開前還鎖（defer Unlock/RAII），並用單一鎖或
	較小的臨界區縮小互相等的機會。`,
		problem: `// 不安全寫法:兩 goroutine 以相反順序取 a 與 b => A 拿 a 等 b、B 拿 b 等 a => deadlock
package main

import "sync"

var (
	a sync.Mutex
	b sync.Mutex
)

func left() { a.Lock(); b.Lock(); a.Unlock(); b.Unlock() }
func right() { b.Lock(); a.Lock(); b.Unlock(); a.Unlock() } // 取鎖順序相反

func main() {
	go left()
	go right()   // 兩個一起 => 等到天荒地老
}`,
		fixed: `// 安全寫法:所有 goroutine 都用同一個取鎖順序(a 再 b)=> 不可能互等
package main

import "sync"

var (
	a sync.Mutex
	b sync.Mutex
)

func left()  { a.Lock(); b.Lock(); a.Unlock(); b.Unlock() }
func right() { a.Lock(); b.Lock(); a.Unlock(); b.Unlock() } // 順序統一

func main() {
	go left()
	go right()
}`,
		patch: `@@
 func left()  { a.Lock(); b.Lock(); a.Unlock(); b.Unlock() }
-func right() { b.Lock(); a.Lock(); b.Unlock(); a.Unlock() }
+func right() { a.Lock(); b.Lock(); a.Unlock(); b.Unlock() }`,
		refs: ['CWE-833', 'CWE-667'],
		tags: ['deadlock', 'lock-ordering', 'circular-wait', 'mutex'],
	},
	{
		id: 'CWE-1265',
		name: 'Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls',
		lang: 'c',
		status: 'Complete',
		what: `經由巢狀呼叫而意外重入非 reentrant 的程式碼。A 正在執行未設計成可重入（reentrant）的函式時，因為某個
	巢狀呼叫——偶發的事件 handler、callback、coerce 到的使用者程式、解構式——又把它再叫進去一次；第二次進場會改動第一次仍在用的
	non-local 狀態（全變、同一份資料、同一個 counter）。等第一次恢復回來，它依賴的狀態早被第二次改掉，於是撞到 use-after-free、
	計數錯、或把一方的憑證誤配到另一方。修法是要么把函式做成真正 reentrant（不用共享全域、不呼叫其他非 reentrant 程式），要麼用
	旗標／串行化讓「同一份程式在同一執行緒只允許一進」：在事件處理上用 async 排程而非同步重入。`,
		problem: `// 不安全寫法:handler 內的巢狀呼叫又去改同一份全域背景 => 兩層重用同一狀態
#include <stdio.h>
#include <string.h>

static char *g_current;    // non-reentrant:全層共用一份背景

void run(const char *script) {
    g_current = (char *)script;   // 第一層設定背景
    eval_script(script);          // 內層又觸發 handler
    // 歸來時 g_current 早被巢狀呼叫蓋掉 => 用到另一份的狀態
}

void on_event(void) {
    run("inner");                 // 在 run 展開期間被重入 => g_current 被覆寫
}`,
		fixed: `// 安全寫法:背景以區域變數傳遞(不再用非 reentrant 的全域) => 重入不互相改動
#include <string.h>

void run(const char *script, char *bg) {
    strcpy(bg, script);         // 背景改用"由呼叫者給"的區域緩衝
    eval_with(script, bg);      // 巢狀重入時用的是內層自己的 bg
}

void on_event(void) {
    char mybg[128];
    run("inner", mybg);         // 與外層的 bg 分開 => 不會覆蓋
}`,
		patch: `@@
-char *g_current;    // non-reentrant:全層共用一份背景
-
-void run(const char *script) {
-    g_current = (char *)script;
-    eval_script(script);
+void run(const char *script, char *bg) {
+    strcpy(bg, script);
+    eval_with(script, bg);
 }
 
 void on_event(void) {
-    run("inner");
+    char mybg[128];
+    run("inner", mybg);
 }`,
		refs: ['CWE-1265', 'CWE-663'],
		tags: ['reentrancy', 'reentrant', 'nested-call', 'race-condition'],
	},
];
