// CWE chunk — category: Resource Consumption / DoS (Go / Node / C).
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
		id: 'CWE-369',
		name: 'Divide By Zero',
		lang: 'c',
		status: 'Complete',
		what: `除以零（Divide By Zero）。程式直接拿「未經驗證的數值」當除數或取模的除數，例如使用者
	輸入的數量、從協定封包解出來的長度欄位、或某個可能為 0 的計算結果。在 C 這種語言裡除以零是未定義行為，
	整數除法甚至可以直接把程序炸掉（SIGFPE），浮點數則可能產生無窮或 NaN 並一路污染後續計算；在其它語言則常以
	例外或崩潰的形式結束。最典型的成因是把「二進位可控制值」當分母卻沒有檢查是否非零。修法是在每一次除法、
	取模前明確檢查除數不等於零，不合法就直接回錯或走安全分支，絕對不讓零進入除法運算元。`,
		problem: `// 不安全寫法：用外部輸入當除數，等於零時直接除爆
#include <stdint.h>
#include <stdlib.h>

// len 來自解析的協定封包，攻擊者可設為 0 => 除以零
uint32_t avg_per_byte(uint32_t total, uint32_t len) {
    return total / len;   // len==0 => 未定義行為,整數除零崩潰(SIGFPE)
}`,
		fixed: `// 安全寫法：除法前先檢查除數非零，為 0 就走錯誤分支
#include <stdint.h>

int32_t avg_per_byte(uint32_t total, uint32_t len, uint32_t *out) {
    if (len == 0) {
        return -1;       // 除數為 0,明確拒絕而非除爆
    }
    *out = total / len;
    return 0;
}`,
		patch: `@@
-#include <stdlib.h>
-
-// len 來自解析的協定封包，攻擊者可設為 0 => 除以零
-uint32_t avg_per_byte(uint32_t total, uint32_t len) {
-    return total / len;   // len==0 => 未定義行為,整數除零崩潰(SIGFPE)
+int32_t avg_per_byte(uint32_t total, uint32_t len, uint32_t *out) {
+    if (len == 0) {
+        return -1;
+    }
+    *out = total / len;
+    return 0;
 }`,
		refs: ['CWE-369', 'SEI CERT'],
		tags: ['divide-by-zero', 'division', 'crash', 'integer'],
	},
	{
		id: 'CWE-399',
		name: 'Resource Management Errors',
		lang: 'c',
		status: 'Deprecated',
		what: `資源管理錯誤（Resource Management Errors）。這曾是 CWE 的一個大類別，用來統稱與「系統資源
	管理不當」有關的所有弱點：記憶體、檔案描述符（fd）、socket、鎖、連線等等該釋放沒釋放、該有上限沒上限、
	或使用方式錯誤，最後都往資源耗盡或資源洩漏收斂。MITRE 在後續版本把這類組織性的 Category 淘汰（標記為
	Deprecated，2019 起不再用於弱點對映），把較具體的成因拆散成更精確的後代弱點，例如無界資源消耗（CWE-400）、
	資源該釋放卻沒釋放（CWE-404）、無限配置資源（CWE-770）等。撰寫或審查程式時，遇到任何拿取資源的呼叫都要自問
	「生命周期誰負責、拿不到上限在哪」；若今天要對映實際漏洞，改映射到底層那幾個具體的資源管理弱點，而不是用這個已被
	停用的類別。`,
		problem: `// 不安全寫法：每條路徑都說要管理資源,但錯誤路徑上 fd 與 chunk 都漏掉釋放
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int read_token(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    char *buf = (char *)malloc(256);
    ssize_t n = read(fd, buf, 255);
    if (n < 0) return -2;   // 這個提早回傳同時漏了 close(fd) 與 free(buf)
    int v = (int)strtoul(buf, NULL, 10);
    free(buf);
    close(fd);
    return v;
}`,
		fixed: `// 安全寫法：單一出口統一釋放,並記錄回傳碼,兩條路徑資源都不漏
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int read_token(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    char *buf = (char *)malloc(256);
    if (buf == NULL) { close(fd); return -1; }
    ssize_t n = read(fd, buf, 255);
    int rc = (n <= 0) ? -2 : (int)strtoul(buf, NULL, 10);
    free(buf);
    close(fd);
    return rc;   // 所有路徑都落在同一出口後才釋放
}`,
		patch: `@@
     if (fd < 0) return -1;
     char *buf = (char *)malloc(256);
+    if (buf == NULL) { close(fd); return -1; }
     ssize_t n = read(fd, buf, 255);
-    if (n < 0) return -2;   // 這個提早回傳同時漏了 close(fd) 與 free(buf)
-    int v = (int)strtoul(buf, NULL, 10);
+    int rc = (n <= 0) ? -2 : (int)strtoul(buf, NULL, 10);
     free(buf);
     close(fd);
-    return v;
+    return rc;
 }`,
		refs: ['CWE-399', 'CWE-400', 'CWE-770'],
		tags: ['resource-management', 'deprecated', 'resource-leak'],
	},
	{
		id: 'CWE-405',
		name: 'Asymmetric Resource Consumption (Amplification)',
		lang: 'node',
		status: 'Complete',
		what: `非對稱的資源消耗（放大攻擊）。伺服器回應某個請求時，所花費的成本遠大於攻擊者送來請求本身
	的成本——攻擊者用極少量的輸入、換到伺服器極大量CPU／記憶體／頻寬支出，這就叫「放大」（amplification）。若把這種
	耗資源的操作公開給未認證的大量呼叫使用，任何人只要連敲幾十個極小的請求就能把整台機器拖垮，是典型的 DoS 起手式。
	常見在花式的重算、無上限的聚合／排序、範本展開、對外重查詢等動作上。修法是替這類「成本>>輸入大小」的計算設定
	明確的上限（輸入長度、呼叫頻率、運算量），或是把它們搬到非同步佇列裡節流，確保單一請求絕不可能吃掉與輸入不成
	比例的資源。`,
		problem: `// 不安全寫法：對外部輸入做多層展開 + 昂貴正則,輸入 100 byte 能燒掉數秒 CPU
const express = require('express');
const app = express();

app.post('/render', (req, res) => {
  const tpl = req.body.template;            // 小輸入
  let out = tpl;
  for (let i = 0; i < 1000; i++) {     // 對輸入做 1000 次 O(n) 拼接 => 成本 x1000
    out = out.replace(/\{\{(\w+)\}\}/g, 'A$1B');
  }
  res.send(out);                            // 輸入小、成本超大 => 放大攻擊
});`,
		fixed: `// 安全寫法：限制展開次數與模板大小,並對呼叫做速率限制使成本與輸入成比例
const express = require('express');
const app = express();

const MAX_ITER = 20;                       // 展開次數寫死,不隨輸入成長

app.post('/render', (req, res) => {
  const tpl = req.body.template;
  if (!tpl || tpl.length > 4096) {
    return res.status(413).send('template too big');
  }
  let out = tpl;
  for (let i = 0; i < Math.min(MAX_ITER, tpl.length); i++) {
    out = out.replace(/RE_/g, 'A');
  }
  res.send(out);
});`,
		patch: `@@
 app.post('/render', (req, res) => {
   const tpl = req.body.template;            // 小輸入
+  if (!tpl || tpl.length > 4096) {
+    return res.status(413).send('template too big');
+  }
   let out = tpl;
-  for (let i = 0; i < 1000; i++) {
-    out = out.replace(/\\{\\{(\\w+)\\}\\}/g, 'A$1B');
+  for (let i = 0; i < Math.min(MAX_ITER, tpl.length); i++) {
+    out = out.replace(/RE_/g, 'A');
   }
   res.send(out);
 });`,
		refs: ['CWE-405', 'OWASP-DoS'],
		tags: ['amplification', 'asymmetric-resource', 'dos', 'cost'],
	},
	{
		id: 'CWE-406',
		name: 'Insufficient Control of Network Message Volume (Network Amplification)',
		lang: 'go',
		status: 'Complete',
		what: `對網路訊息量的控制不足（網路放大）。網路規模的 DoS 最常靠「放大」達成：攻擊者送出一個
	很小的請求（例如帶偽造來源位址的 UDP probe），伺服器卻回送一個大得多的回應，讓流量被乘以放大倍數狠狠地灌到
	受害者身上。成因是服務對「來源端送出的請求」與「回應產生的位元組」之間不成比例的量沒有限制：不檢查來源可信度、
	不回覆的請求沒限額、回應體積可被隨意放大。修法是限縮回應大小、限制每個來源的單位時間請求量（rate limit）、
	對無狀態大封包介面做來源驗證與頻寬節流，使任何單一小請求都不可能膨脹成超大回應來幫攻擊者放大別人。`,
		problem: `// 不安全寫法：對每個 UDP 請求都回一整包大資料,不回覆量/大小限制 => 放大攻擊
package main

import (
	"net"
	"strings"
)

func handle(c *net.UDPConn) {
	buf := make([]byte, 32)
	for {
		n, addr, _ := c.ReadFromUDP(buf)
		// 把小 request 回應成一個 60 KB 大全資料,沒有來源驗證也沒限額
		reply := strings.Repeat("A", 60*1024)
		c.WriteToUDP([]byte(reply), addr) // 放大倍率數千倍,可反射打爆受害者
		_ = n
	}
}`,
		fixed: `// 安全寫法：限制回應大小並對來源做粗略節流,讓放大倍率收斂
package main

import (
	"net"
)

var perAddr = make(map[string]int)

func handle(c *net.UDPConn) {
	buf := make([]byte, 32)
	for {
		n, addr, _ := c.ReadFromUDP(buf)
		// 每個來源每秒最多放行一次,且回應也有固定小上限
		perAddr[addr.String()]++
		if perAddr[addr.String()] > 1 {
			continue        // 超額直接丟棄,不再放大
		}
		c.WriteToUDP(make([]byte, 64), addr) // 回應與請求同數量級
		_ = n
	}
}`,
		patch: `@@
  func handle(c *net.UDPConn) {
  	buf := make([]byte, 32)
  	for {
  		n, addr, _ := c.ReadFromUDP(buf)
-		// 把小 request 回應成一個 60 KB 大全資料,沒有來源驗證也沒限額
-		reply := strings.Repeat("A", 60*1024)
-		c.WriteToUDP([]byte(reply), addr) // 放大倍率數千倍,可反射打爆受害者
+		perAddr[addr.String()]++
+		if perAddr[addr.String()] > 1 {
+			continue
+		}
+		c.WriteToUDP(make([]byte, 64), addr) // 回應與請求同數量級
  		_ = n
  	}
  }`,
		refs: ['CWE-406', 'MITRE'],
		tags: ['network-amplification', 'udp', 'reflection', 'dos'],
	},
	{
		id: 'CWE-407',
		name: 'Inefficient Algorithmic Complexity',
		lang: 'python',
		status: 'Complete',
		what: `低效率的演算法複雜度。程式對「可用輸入長度觸發」的資料採用了昂貴或退化型的演算法——
	例如在迴圈裡對 list 做 O(n) 的 in／del 導致整體 O(n²)、未排序資料上做二次方迴圈、可被負面輸入逼成
	最壞情形的搜尋或雜湊（字串 key 全撞在同一 bucket）。在輸入正常的量下面看起來沒問題，一旦攻擊者構造剛好打在最壞
	情形的輸入，執行時間就隨輸入長度大幅增，變成 CPU 型 DoS。修法是優先選用與輸入成比例、最好能對抗負面輸入的
	演算法與資料結構（hash table 用亂序、迴圈避開 o(n) 查找），並限制可存取輸入的長度，讓最壞情形成本也可控。`,
		problem: `# 不安全寫法:對每個字元做一次 O(n) 的 in 檢查,整體變 O(n²),長字串就癱掉
def validate(chars):
    seen = []                 # list 用 in 每次 O(n)
    for ch in chars:          # n 個字元
        if ch in seen:        # 每次 O(n) => 總 O(n²)
            return False
        seen.append(ch)
    return True`,
		fixed: `# 安全寫法:改用 set,包含性檢查變 O(1),整體回到 O(n)
def validate(chars):
    seen = set()             # set 查詢攤銷 O(1)
    for ch in chars:
        if ch in seen:
            return False
        seen.add(ch)
    return True`,
		patch: `@@
-    seen = []                 # list 用 in 每次 O(n)
+    seen = set()             # set 查詢攤銷 O(1)
     for ch in chars:
         if ch in seen:
             return False
-        seen.append(ch)
+        seen.add(ch)
     return True`,
		refs: ['CWE-407', 'CWE-1333'],
		tags: ['algorithmic-complexity', 'complexity', 'cpu-dos', 'quadratic'],
	},
	{
		id: 'CWE-409',
		name: 'Improper Handling of Highly Compressed Data (Zip/Decompression Bomb)',
		lang: 'go',
		status: 'Complete',
		what: `不當處理高度壓縮的資料（zip／解壓縮炸彈）。攻擊者送來一份體積極小、但解壓後可膨脹
上百上千倍的壓縮檔（壓縮比可達數百萬比一）。程式若盲目地把每個 entry 整份解壓到記憶體或磁碟，
也不看解壓前後的最大體積、entry 總數、單檔大小限制，就會在解壓途中把 RAM 與磁碟瞬間吃光，
拖垮同一台機器上的所有程序。建議做法是在解壓前與解壓中都設定硬上限：限定最大 entry 總數、
每個 entry 的最大尺寸（以解壓後位元組計），一旦超過就立刻中止並回報錯誤，讓「解壓可控」。
長痛不如短痛，把限制寫在迴圈起點而非事後。`,
		problem: `// 不安全寫法：解壓時不檢查 entry 大小與總數，zip bomb 可無限膨脹吃爆記憶體
package main

import (
	"archive/zip"
	"io"
	"log"
	"strings"
)

func extract(r *zip.ReadCloser) {
	for _, f := range r.File {           // 不限制 entry 總數,也不看每個尺寸
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(rc)      // 一個數 GB 的解壓後內容直接全讀進 RAM
		if err != nil {
			continue
		}
		use(data)                        // 無限累積 => 記憶體耗盡,整個程序被砍
		rc.Close()
	}
}

func main() {
	r, err := zip.OpenReader("evil.zip")
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()
	extract(r)
}

func use([]byte)   {}
var _ = strings.TrimSpace`,
		fixed: `// 安全寫法：限制 entry 總數與單檔解壓上限,超過立刻中止 => 解壓有界
package main

import (
	"archive/zip"
	"errors"
	"io"
	"log"
)

const (
	MaxEntries = 1024      // 最多解壓 1024 個 entry
	MaxBytes   = 64 << 20  // 單檔最大 64 MB(解壓後)
)

var ErrTooLarge = errors.New("zip entry too large")

func extract(r *zip.ReadCloser) error {
	if len(r.File) > MaxEntries {
		return ErrTooLarge // 先擋下大量 entry 的炸彈
	}
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, MaxBytes+1))
		rc.Close()
		if err != nil {
			return err
		}
		if len(data) > MaxBytes {
			return ErrTooLarge // 超過 64 MB 立刻中止,不再累積
		}
		use(data)
	}
	return nil
}

func main() {
	r, err := zip.OpenReader("evil.zip")
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()
	if err := extract(r); err != nil {
		log.Fatal(err)
	}
}

func use([]byte) {}`,
		patch: `@@
 func extract(r *zip.ReadCloser) {
+	if len(r.File) > MaxEntries {
+		return ErrTooLarge
+	}
 	for _, f := range r.File {
 		rc, err := f.Open()
 		if err != nil {
 			continue
 		}
-		data, err := io.ReadAll(rc)
+		data, err := io.ReadAll(io.LimitReader(rc, MaxBytes+1))
 		if err != nil {
 			continue
 		}
+		if len(data) > MaxBytes {
+			return ErrTooLarge
+		}
 		use(data)`,
		refs: ['CWE-409', 'OWASP-DoS'],
		tags: ['zip-bomb', 'decompression', 'dos', 'resource-consumption'],
	},
	{
		id: 'CWE-674',
		name: 'Uncontrolled Recursion',
		lang: 'c',
		status: 'Complete',
		what: `不受控制的遞迴。函式會遞迴呼叫自己（或一組互相呼叫的函式），但遞迴深度受「外部可控」的值
	或沒有邊界檢查的資料結構決定，而且沒有深度上限。遞迴每下一層就要吃掉一塊 call stack；當層數因為輸入變成幾十萬幾百萬
	時，堆疊馬上爆掉（stack overflow），程式以崩潰收場，成為 DoS。常見在解析巢狀協定、處理任意的巢狀 JSON／XML、
	或樹狀結構走訪時。修法是為遞迴設定明確的深度上限（depth==MAX 就回錯），把明顯遞迴的巢狀結構轉成迭代式（stack）
	實作，並隨時檢查引數是否單調遞減保證能終止。`,
		problem: `// 不安全寫法：解析巢狀資料不設深度上限,極深的輸入讓堆疊爆掉
#include <stdio.h>
#include <string.h>

// depth 由輸入的巢狀層數決定,沒有上限 => 極深輸入會 stack overflow
int parse_nested(const char **p) {
    if (**p == '(') {
        (*p)++;
        int inner = parse_nested(p);   // 無限往下遞迴,不檢查深度
        if (**p == ')') (*p)++;
        return inner + 1;
    }
    return 0;
}`,
		fixed: `// 安全寫法：帶 depth 參數並限制最大深度,超過就中止
#include <stdio.h>

#define MAX_DEPTH 256

// depth 每層 +1;超過 MAX_DEPTH 立刻回錯,不容許無限加深
int parse_nested(const char **p, int depth) {
    if (depth > MAX_DEPTH) return -1;
    if (**p == '(') {
        (*p)++;
        int inner = parse_nested(p, depth + 1);
        if (inner < 0 || **p != ')') return -1;
        (*p)++;
        return inner + 1;
    }
    return 0;
}`,
		patch: `@@
 int parse_nested(const char **p) {
+// depth 每層 +1;超過 MAX_DEPTH 立刻回錯,不容許無限加深
+int parse_nested(const char **p, int depth) {
+    if (depth > MAX_DEPTH) return -1;
     if (**p == '(') {
         (*p)++;
-        int inner = parse_nested(p);   // 無限往下遞迴,不檢查深度
-        if (**p == ')') (*p)++;
-        return inner + 1;
+        int inner = parse_nested(p, depth + 1);
+        if (inner < 0 || **p != ')') return -1;
+        (*p)++;
+        return inner + 1;
     }
     return 0;
 }`,
		refs: ['CWE-674', 'SEI CERT'],
		tags: ['recursion', 'stack-overflow', 'unbounded-depth', 'dos'],
	},
	{
		id: 'CWE-770',
		name: 'Allocation of Resources Without Limits or Throttling',
		lang: 'go',
		status: 'Complete',
		what: `在沒有上限或節流（throttling）的情況下配置資源。程式把外部送入的資料不斷塞進
可無限成長的容器——如無界的 slice、map、queue、goroutine 或工作佇列——卻完全不設總數或
總容量上限。每個進來的專案就 append 或 enqueue 一次，量一多，記憶體與任務堆疊就被無止盡
吃光，等同把資源管理的控制權交給攻擊者。建議做法是為任何會累積的地方設定明確上限：容量
用預分配＋檢查、溢滿就拒絕；工作佇列用有界佇列並設定 worker 數量，backpressure 讓生產與
消費互相牽制；讓「可累積的資源」永遠有界，而非默默地一路長大。`,
		problem: `// 不安全寫法：工作佇列無界,每個請求都 go 一個 goroutine 一直 append => 記憶體無止盡成長
package main

import (
	"fmt"
	"time"
)

type job struct{ payload []byte }

var queue []job // 全域無界佇列,每人一進就 append,永遠不縮

func enqueue(payload []byte) {
	queue = append(queue, job{payload: payload}) // 無任何上限,持續累積
	go process()                                  // 每個任務一個 goroutine,人一多就失控
}

func process() {
	// 處理失敗的任務也不會從 queue 移除 => queue 只增不減
}

func main() {
	for {
		var p []byte
		fmt.Scanln(&p)   // 外部任意餵入
		enqueue(p)
		time.Sleep(time.Millisecond)
	}
}`,
		fixed: `// 安全寫法：有界佇列 + 固定 worker 數,佇列滿了就拒絕(reject)讓資源有界
package main

import "fmt"

type job struct{ payload []byte }

const MaxQueue = 1024 // 佇列最多 1024 筆,超過就 DROP,不讓它無界成長
const Workers = 8     // 固定 worker 數,並行度也被節流

var queue = make(chan job, MaxQueue) // 有界 channel 就是天然的 backpressure

func enqueue(payload []byte) error {
	select {
	case queue <- job{payload: payload}:
		return nil     // 空間夠,塞進去
	default:
		return ErrFull // 佇列滿了,立刻拒絕而非默默吞下更多記憶體
	}
}

func worker() {
	for j := range queue {
		_ = j            // 固定 worker 消費佇列,生產與消費互為節流
	}
}

var ErrFull = fmt.Errorf("queue full")

func main() {
	for i := 0; i < Workers; i++ {
		go worker()
	}
	enqueue([]byte("work"))
}`,
		patch: `@@
-var queue []job // 全域無界佇列,每人一進就 append,永遠不縮
-
-func enqueue(payload []byte) {
-	queue = append(queue, job{payload: payload})
-	go process()
-}
-
-func process() {
-}
+var queue = make(chan job, MaxQueue)
+
+func enqueue(payload []byte) error {
+	select {
+	case queue <- job{payload: payload}:
+		return nil
+	default:
+		return ErrFull
+	}
+}
+
+func worker() {
+	for j := range queue {
+		_ = j
+	}
+} `,
		refs: ['CWE-770', 'SEI CERT'],
		tags: ['resource-allocation', 'unbounded', 'queue', 'backpressure', 'dos'],
	},
	{
		id: 'CWE-776',
		name: "Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')",
		lang: 'python',
		status: 'Complete',
		what: `不當限制 DTD 中的遞迴實體參照（XML Entity Expansion，又稱 Billion Laughs 或 XML bomb）。
	XML 的 DTD 可以宣告實體；若把「一個實體內容引用另一個實體」層層嵌套下去，例如 &A; 展開成兩個字元、&B; 再展開
	成兩個 &A;，每層就翻倍。解析器若放任這種遞迴實體無上限地完整展開，一份只有幾百 bit 的 XML 就能展開成數 GB 的
	文字，把記憶體與 CPU 瞬間吃光，是標準的 DoS。修法是停用外部／自訂 DTD 實體展開，或用能設定實體展開深度與大小
	上限的 parser（例如 Python 的 defusedxml），把任何可能指數成長的展開都限制成有界。`,
		problem: `# 不安全寫法:XML parser 預設會展開 DTD 遞迴實體 => 極小輸入膨脹成 GB 級資料
from xml.etree import ElementTree
from io import StringIO

def parse_user_xml(data):
    # ElementTree 預設處理 internal DTD,billion laughs 會把 data 指數展開
    root = ElementTree.fromstring(data)
    return root.text`,
		fixed: `# 安全寫法:改用 defusedxml,它會封鎖遞迴實體展開 => 展開有界
from defusedxml import ElementTree

def parse_user_xml(data):
    # defusedxml 拒絕 DTD/billion-laughs 等實體展開攻擊
    root = ElementTree.fromstring(data)  # 超深/超大展開直接拋錯
    return root.text`,
		patch: `@@
-from xml.etree import ElementTree
-from io import StringIO
+from defusedxml import ElementTree
 
 def parse_user_xml(data):
-    # ElementTree 預設處理 internal DTD,billion laughs 會把 data 指數展開
-    root = ElementTree.fromstring(data)
+    # defusedxml 拒絕 DTD/billion-laughs 等實體展開攻擊
+    root = ElementTree.fromstring(data)  # 超深/超大展開直接拋錯
     return root.text`,
		refs: ['CWE-776', 'OWASP-XEE'],
		tags: ['xee', 'xml-bomb', 'billion-laughs', 'dos', 'xxe'],
	},
	{
		id: 'CWE-789',
		name: 'Uncontrolled Memory Allocation',
		lang: 'c',
		status: 'Complete',
		what: `不受控制的記憶體配置。程式用「來自外部、可以很大」的正數當大小去配置記憶體，卻沒有先檢查它是否
	在合理範圍內：例如直接拿 request 的 Content-Length、封包長度欄位去 malloc，或讀到多大就要多大。攻擊者只要報一個
	超大長度，程式就會嘗試配置數 GB 的 heap；配置若「假成功」再寫入就變成越界寫，若失敗則可能崩潰或觸發 OOM，兩者
	都是 DoS。修法是在配置前先對外部長度做硬上限與一致性檢查（>0、<=上限、不超過剩余資料），配置後也確認回傳非 NULL，
	讓任何配置的 size 都受控且有界。`,
		problem: `// 不安全寫法:直接拿封包長度欄位當 malloc 大小,超大值觸發 OOM/配置爆炸
#include <stdlib.h>
#include <stdint.h>

// len 由攻擊者的封包控制,未設上限就 malloc => 可申請數 GB
uint8_t *recv_payload(uint32_t len) {
    uint8_t *buf = (uint8_t *)malloc(len); // len 極大 => 配置失控 / OOM
    return buf;                              // 回傳 NULL 也沒檢查就被使用
}`,
		fixed: `// 安全寫法:配置前先檢查長度上限,並檢查回傳,失敗就回錯
#include <stdlib.h>
#include <stdint.h>

#define MAX_PAYLOAD (1u << 20) // 1 MB 硬上限

uint8_t *recv_payload(uint32_t len, size_t actual) {
    if (len > MAX_PAYLOAD || len > actual) {
        return NULL;               // 超過上限或超過剩余資料 => 拒絕配置
    }
    uint8_t *buf = (uint8_t *)malloc(len);
    if (buf == NULL) return NULL;  // 配置失敗要有檢查
    return buf;
}`,
		patch: `@@
-uint8_t *recv_payload(uint32_t len) {
-    uint8_t *buf = (uint8_t *)malloc(len);
-    return buf;
+uint8_t *recv_payload(uint32_t len, size_t actual) {
+    if (len > MAX_PAYLOAD || len > actual) {
+        return NULL;
+    }
+    uint8_t *buf = (uint8_t *)malloc(len);
+    if (buf == NULL) return NULL;
+    return buf;
 }`,
		refs: ['CWE-789', 'SEI CERT'],
		tags: ['memory-allocation', 'malloc', 'oom', 'dos'],
	},
	{
		id: 'CWE-799',
		name: 'Improper Control of Interaction Frequency (Missing Rate Limiting)',
		lang: 'node',
		status: 'Complete',
		what: `沒有正確控制互動頻率（缺乏速率限制）。API 只做「收到請求→執行→回傳」的動作，
對同一個 IP、帳號或 token 在單位時間內可以呼叫多少次完全不加管制；於是攻擊者可以超高速
連敲同一支昂貴或破壞性介面（大量查詢、開帳號、寄信、下單），把後端的 CPU／資料庫／外送
服務打到耗盡，或反覆觸發副作用。建議做法是在進入 handler 前套用 per-key 的計數器（以 IP
或 token 為鍵），並用 token bucket 這類演算法決定「限額內放行、超過立即回 429 Too Many
Requests」，讓請求頻率永遠被節流,而不把成本轉給後端。`,
		problem: `// 不安全寫法：完全沒有速率限制,多高頻率都不攔,後端成本可被快速打爆
const express = require('express');
const app = express();

// 昂貴操作:每個請求都打一次資料庫 + 發一封信
app.post('/api/transfer', (req, res) => {
  // 不做任何頻率計算,每個請求直接進業務邏輯
  const ok = transfer(req.body.from, req.body.to, req.body.amount);
  sendReceipt(req.body.to);              // 同一個使用者可每秒敲上百次
  res.json({ ok });
});`,
		fixed: `// 安全寫法：用 token bucket 對每個使用者限額,超限立即 429
const express = require('express');
const app = express();

const buckets = new Map();             // key -> 剩餘 token

function rateLimit(key, max = 10, windowMs = 60000) {
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || now - b.ts >= windowMs) b = { tokens: max, ts: now };
  b.tokens -= 1;                        // 每取用一個請求就扣一個 token
  buckets.set(key, b);
  return b.tokens >= 0;                 // 還有額度放行,否則阻擋
}

app.post('/api/transfer', (req, res) => {
  if (!rateLimit(req.body.from)) {      // 同一個使用者超限
    return res.status(429).json({ error: 'rate limited' });
  }
  const ok = transfer(req.body.from, req.body.to, req.body.amount);
  sendReceipt(req.body.to);
  res.json({ ok });
});`,
		patch: `@@
-// 昂貴操作:每個請求都打一次資料庫 + 發一封信
 app.post('/api/transfer', (req, res) => {
-  // 不做任何頻率計算,每個請求直接進業務邏輯
+  if (!rateLimit(req.body.from)) {
+    return res.status(429).json({ error: 'rate limited' });
+  }
   const ok = transfer(req.body.from, req.body.to, req.body.amount);
   sendReceipt(req.body.to);              // 同一個使用者可每秒敲上百次
   res.json({ ok });
 });`,
		refs: ['CWE-799', 'OWASP-API'],
		tags: ['rate-limit', 'interaction-frequency', 'dos', 'api'],
	},
	{
		id: 'CWE-834',
		name: 'Excessive Iteration (Unbounded Loop over Input)',
		lang: 'c',
		status: 'Complete',
		what: `過度迭代。迴圈的次數由「外部可控制的值」取決,而且完全沒有上限或邊界檢查：
	例如解析協定時用來回圈的「剩餘長度」來自攻擊者送的封包，或 len 取自未驗證的輸入。
	當這個值被改成極大數時,迴圈就會癱著停不下來,CPU 被單一請求綁死,變成 CPU 型 DoS。
	典型像是「以長度欄位當迴圈次數卻不檢查它小於真的緩衝區大小」造成越界或無止盡的空轉。
	建議做法是:所有以外部值當次數的迴圈都先做界線檢查,把所有「查一筆─遞增─再查」的迴圈
	次數上限寫死或與真實容量比較,超過就中斷,讓執行成本與輸入可控地有界。`,
		problem: `// 不安全寫法：以攻擊者可控的 len 當迴圈次數,沒有上限,可能無止盡空轉鎖死 CPU
#include <string.h>
#include <stdint.h>

// header 的長度欄位由外部資料控制,未驗證就直接拿去當迴圈次數
void parse_packet(const uint8_t *buf, uint32_t len) {
    uint32_t i;
    for (i = 0; i < len; i++) {   // len 極大時此迴圈幾乎停不下來
        if (buf[i] == 0xFF) {     // 且 len 可大於真實 buffer 大小 => 越界讀
            break;
        }
        // 每個元素做昂貴處理,CPU 被綁死在這裡
    }
}`,
		fixed: `// 安全寫法：迴圈次數先與真實容量比對並設上限,超過即中斷 => 迭代有界
#include <stdint.h>

// actual 是 buffer 的真實大小,len 是外部宣告的長度,取較小者當上限
void parse_packet(const uint8_t *buf, uint32_t actual, uint32_t len) {
    uint32_t limit = (len < actual) ? len : actual; // 永遠不超過真實容量
    uint32_t i;
    for (i = 0; i < limit; i++) {   // 次數受限於 actual,不可能無限空轉
        if (buf[i] == 0xFF) {
            break;
        }
    }
}`,
		patch: `@@
-void parse_packet(const uint8_t *buf, uint32_t len) {
-    uint32_t i;
-    for (i = 0; i < len; i++) {
-        if (buf[i] == 0xFF) {
-            break;
-        }
-    }
+void parse_packet(const uint8_t *buf, uint32_t actual, uint32_t len) {
+    uint32_t limit = (len < actual) ? len : actual;
+    uint32_t i;
+    for (i = 0; i < limit; i++) {
+        if (buf[i] == 0xFF) {
+            break;
+        }
+    }`,
		refs: ['CWE-834', 'SEI CERT'],
		tags: ['excessive-iteration', 'unbounded-loop', 'cpu-dos', 'bounds'],
	},
	{
		id: 'CWE-835',
		name: "Loop with Unreachable Exit Condition ('Infinite Loop')",
		lang: 'javascript',
		status: 'Complete',
		what: `迴圈有無法觸及的結束條件（無窮迴圈）。迴圈的終止條件取決於一個「永遠不會成立」的判斷——例如
	增量步驟被誤寫成條件、比較的方向寫反（i<0 而 i 不斷遞增）、在迴圈內把終止用的變數重置回初始值、或對某個永遠為
	真的條件迴圈。一旦迴圈停不下來，CPU 就被這個迴圈占死，單一執行緒從此不再回應其它工作，變成 CPU 型 DoS。常見成因是
	複雜的 while 條件或終止條件與狀態更新的順序寫錯。修法是確認迴圈的終止條件可到達、更新步進與條件方向一致、並為任何
	「外部條件迴圈」加上最大次數或權杖的逃脫閥，保證一定能在有界步數內跳出。`,
		problem: `// 不安全寫法:終止條件與遞增方向相反(應是 i<MAX),條件永遠成立 => CPU 卡死不退
function consume(q) {
  // i 一直增加,條件卻寫 i > max => 永遠進入迴圈,CPU 被占死
  for (let i = 0; i > q.length; i++) {
    handle(q[i]);   // 迴圈無法結束 => 無窮迴圈 DoS
  }
}`,
		fixed: `// 安全寫法:條件方向與遞增一致,並加保險的次數上限,保證有界跳出
function consume(q) {
  // 對外部長度再乘以 2 當保險上限,條件正確讓迴圈必然結束
  const limit = Math.min(q.length, 1e6);
  for (let i = 0; i < limit; i++) {
    handle(q[i]);
  }
}`,
		patch: `@@
-  for (let i = 0; i > q.length; i++) {
-    handle(q[i]);   // 迴圈無法結束 => 無窮迴圈 DoS
+  const limit = Math.min(q.length, 1e6);
+  for (let i = 0; i < limit; i++) {
+    handle(q[i]);
   }`,
		refs: ['CWE-835', 'SEI CERT'],
		tags: ['infinite-loop', 'unreachable-exit', 'cpu-dos'],
	},
	{
		id: 'CWE-911',
		name: 'Improper Update of Reference Count',
		lang: 'c',
		status: 'Complete',
		what: `參考計數（reference count）更新不當。用 reference counting 管理生命周期的物件，每次取得指標、每次釋放參照
	都必須把計數拿捏得剛剛好：加多了（拿去使用卻沒 +1）會讓物件被提前釋放，別處還在用就是 use-after-free；加少了（同一份參照被
	+1 兩次）會讓計數永遠降不到零，物件永不釋放變成記憶體／資源洩漏。錯拿計數的常見原因是非對稱的加減、外部呼叫者漏了 Retain、
	或錯誤路徑上少了一次 Release。修法是讓「每份參照」的增減嚴格配對：同一份 +1 在每條成功／失敗路徑都有對應的 -1，
	並用 RAII／scope 綁定釋放讓配對不會漏。`,
		problem: `// 不安全寫法:拿到參照但沒 +1,用完又 -1 => 第一次釋放提前把還在使用中的物件清掉
#include <stdlib.h>

typedef struct Obj { int refs; } Obj;
#define RETAIN(o)   ((o)->refs++)
#define RELEASE(o)   (--(o)->refs == 0 ? free(o) : 0)

Obj *borrow_obj(void);
void use(Obj *o);

void demo(void) {
    Obj *o = borrow_obj();     // 回傳的參照沒 RETAIN,計數沒增加
    use(o);                   // 使用中...
    RELEASE(o);              // 這一下很可能就把 refs 歸零 => 提前 free => UAF
}`,
		fixed: `// 安全寫法:借用前先 RETAIN,用完後 RELEASE,加減嚴格配對
#include <stdlib.h>

typedef struct Obj { int refs; } Obj;
#define RETAIN(o)   ((o)->refs++)
#define RELEASE(o)   (--(o)->refs == 0 ? free(o) : 0)

Obj *borrow_obj(void);
void use(Obj *o);

void demo(void) {
    Obj *o = borrow_obj();
    if (o == NULL) return;
    RETAIN(o);           // 這份參照 +1,確保使用期間不會被釋放
    use(o);
    RELEASE(o);          // 對應的 -1,配對平衡 => 生命周期正確
}`,
		patch: `@@
 void demo(void) {
     Obj *o = borrow_obj();     // 回傳的參照沒 RETAIN,計數沒增加
+    if (o == NULL) return;
+    RETAIN(o);
     use(o);                   // 使用中...
     RELEASE(o);`,
		refs: ['CWE-911', 'CWE-415', 'CWE-401'],
		tags: ['refcount', 'use-after-free', 'retain-release', 'memory'],
	},
	{
		id: 'CWE-1333',
		name: 'Inefficient Regular Expression Complexity',
		lang: 'javascript',
		status: 'Complete',
		what: `低效率的正規表示式複雜度（ReDoS）。電子式引擎（backtracking）的 regex 遇到巢狀的量詞——例如
	(a+)+、(\\w+\\s?)* 這類——在最壞情況下要做的回溯次數會隨輸入長度指數成長。只要把「會失敗又很長」的輸入送進來，
	匹配就要測遍天文數字的組合，單一請求就能把 CPU 占死好幾秒甚至更久，變成 CPU 型 DoS。常見成因是寫 regex 時只顧「能對上」
	卻沒考慮「對不上」時的最壞成本，又直接用於未驗證的外部輸入。修法是避免巢狀量詞、用原子／lookahead 技巧消除回溯、限制一個請求
	可被 regex 處理的輸入長度，並對正則本身與執行時間設限。`,
		problem: `// 不安全寫法:巢狀量詞 (\\w+\\s?)* 對「失敗又長」的輸入回溯量指數成長 => ReDoS
function looksLikeSentence(s) {
  // ^(\\w+\\s?)*$ 遇上不含空白/字母的怪字串時,回溯量爆炸
  return /^(\\w+\\s?)*$/i.test(s);
}`,
		fixed: `// 安全寫法:用 lookahead + 反向參照把回溯去掉,複雜度回到線性逼近
function looksLikeSentence(s) {
  // ^((?=(\\w+))\\2\\s?)*$ 沒有巢狀回溯,大量輸入也不會爆
  return /^((?=(\\w+))\\2\\s?)*$/i.test(s);
}`,
		patch: `@@
-  // ^(\\w+\\s?)*$ 遇上不含空白/字母的怪字串時,回溯量爆炸
-  return /^(\\w+\\s?)*$/i.test(s);
+  // ^((?=(\\w+))\\2\\s?)*$ 沒有巢狀回溯,大量輸入也不會爆
+  return /^((?=(\\w+))\\2\\s?)*$/i.test(s);`,
		refs: ['CWE-1333', 'OWASP-ReDoS'],
		tags: ['redos', 'regex', 'catastrophic-backtracking', 'cpu-dos'],
	},
];
