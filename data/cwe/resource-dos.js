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
+ 	if len(r.File) > MaxEntries {
+ 		return ErrTooLarge
+ 	}
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
-app.post('/api/transfer', (req, res) => {
-  const ok = transfer(req.body.from, req.body.to, req.body.amount);
-  sendReceipt(req.body.to);
-  res.json({ ok });
-});
+app.post('/api/transfer', (req, res) => {
+  if (!rateLimit(req.body.from)) {
+    return res.status(429).json({ error: 'rate limited' });
+  }
+  const ok = transfer(req.body.from, req.body.to, req.body.amount);
+  sendReceipt(req.body.to);
+  res.json({ ok });
+});`,
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
];
