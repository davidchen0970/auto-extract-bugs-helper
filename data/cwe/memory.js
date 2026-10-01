// CWE chunk — category: memory / buffer integrity (C / C++).
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
		id: 'CWE-119',
		name: 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
		lang: 'c',
		status: 'Complete',

		what: `記憶體緩衝區操作缺少邊界限制。CWE-119 是記憶體安全相關弱點的上位分類，
表示程式在讀取、寫入或複製資料時，未確認操作範圍是否位於已配置的緩衝區內。
常見情況包括 strcpy、memcpy 複製過多資料，或指標運算超出有效範圍，
可能造成越界讀取、越界寫入、程式崩潰，甚至衍生其他安全風險。
建議在操作緩衝區時一併管理其容量，並在讀寫前檢查資料長度，
確保所有操作都不會超出緩衝區邊界。`,

		problem: `// 不安全寫法：未檢查來源字串長度，直接複製到固定容量的緩衝區
#include &lt;string.h&gt;
<br><br>
void cp(char *dst, size_t cap, const char *src) {
    // 若 src 的長度加上結尾 NUL 大於 cap，將造成 dst 越界寫入
    memcpy(dst, src, strlen(src) + 1);
}`,

		fixed: `// 安全寫法：依目的緩衝區容量限制複製長度，並確保字串以 NUL 結尾
#include &lt;string.h&gt;
<br><br>
void cp(char *dst, size_t cap, const char *src) {
    if (cap == 0) {
        return;                               // 目的緩衝區沒有可用空間
    }

    size_t n = strlen(src);

    if (n &gt; cap - 1) {
        n = cap - 1;                         // 預留一個位元組存放結尾 NUL
    }

    memcpy(dst, src, n);                     // 僅複製容量允許的資料
    dst[n] = '\\0';                          // 確保輸出為有效的 C 字串
}`,

		patch: `@@
 void cp(char *dst, size_t cap, const char *src) {
-    memcpy(dst, src, strlen(src) + 1);
+    if (cap == 0) {
+        return;                               // 目的緩衝區沒有可用空間
+    }
+
+    size_t n = strlen(src);
+
+    if (n &gt; cap - 1) {
+        n = cap - 1;                         // 預留一個位元組存放結尾 NUL
+    }
+
+    memcpy(dst, src, n);                     // 僅複製容量允許的資料
+    dst[n] = '\\0';                          // 確保輸出為有效的 C 字串
 }`,

		refs: ['CWE-119'],
		tags: ['memory-buffer', 'bounds'],
	},
	{
		id: 'CWE-120',
		name: "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
		lang: 'c',
		status: 'Complete',
		what: `經典緩衝區溢位（緩衝區複製）。strcpy 這類函式不檢查來源長度，
就把整段內容拷進固定大小的目的緩衝。來源比目的緩衝大時，會改寫目的之外的記憶體，
在堆疊上可順帶覆寫返回位址（stack BOF）。建議改用有上限的 snprintf／strncpy，
並保證目的緩衝一定以 NUL 結尾。`,
		problem: `// 不安全寫法：strcpy 不檢查來源長度，直接把整個 src 拷進固定大小 buf
#include <stdio.h>
#include <string.h>

void copy_name(const char *src) {
    char buf[64];
    strcpy(buf, src);              // src 超過 63 字元 => 寫到 buf 外(stack overflow)
    printf("name=%s\\n", buf);
}`,
		fixed: `// 安全寫法：snprintf 限額寫入(至多 sizeof(buf)-1)，超過直接截斷
#include <stdio.h>

void copy_name(const char *src) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", src);   // 保證不溢位、一定結尾 NUL
    printf("name=%s\\n", buf);
}`,
		patch: `@@
-    char buf[64];
-    strcpy(buf, src);              // src 超過 63 字元 => 寫到 buf 外
+    char buf[64];
+    snprintf(buf, sizeof(buf), "%s", src);   // 保證不溢位、一定結尾 NUL
     printf("name=%s\\n", buf);`,
		refs: ['CWE-120', 'SEI CERT'],
		tags: ['buffer-overflow', 'copy', 'bounds'],
	},
	{
		id: 'CWE-122',
		name: 'Heap-based Buffer Overflow',
		lang: 'c',
		status: 'Complete',
		what: `堆積型緩衝區溢位。malloc 配置的緩衝太小，卻用 strcpy／memcpy 將更大的
來源整段寫入，改寫堆積上相鄰的 meta data 或資料。建議做法是先算出真正需要的
大小（含結尾 NUL），配置後不要使用會整段覆蓋、又不檢查大小的函式。`,
		problem: `// 不安全寫法：緩衝配一個固定太小的大小，strcpy 卻寫滿整個來源 => heap 溢位
#include <stdlib.h>
#include <string.h>

void dup_fixed(const char *src) {
    char *p = (char *)malloc(16);       // 來源 > 15 就寫破配置區
    strcpy(p, src);                      // heap-based buffer overflow
    free(p);
}`,
		fixed: `// 安全寫法：以 strlen+1 做為配置大小，再用 memcpy 只拷需要的位元組
#include <stdlib.h>
#include <string.h>

void dup_fixed(const char *src) {
    size_t n = strlen(src) + 1;          // +1 留給結尾 NUL
    char *p = (char *)malloc(n);
    if (p == NULL) return;
    memcpy(p, src, n);                   // 拷出的緩衝容量與來源相符
    free(p);
}`,
		patch: `@@
-    char *p = (char *)malloc(16);
-    strcpy(p, src);
+    size_t n = strlen(src) + 1;          // +1 留給結尾 NUL
+    char *p = (char *)malloc(n);
+    if (p == NULL) return;
+    memcpy(p, src, n);
     free(p);`,
		refs: ['CWE-122', 'SEI CERT'],
		tags: ['heap', 'buffer-overflow'],
	},
	{
		id: 'CWE-125',
		name: 'Out-of-bounds Read',
		lang: 'c',
		status: 'Complete',
		what: `越界讀取。以迴圈或索引讀取陣列時上界差 1，或對長度未受檢驗的緩衝進行存取，
程式便會讀到緩衝之外的記憶體，洩漏相鄰資料，甚至包含核心在內的其他記憶體內容。建議嚴格以半開區間
[0, len) 作為迴圈範圍，且在存取前先檢查索引。`,
		problem: `// 不安全寫法：迴圈上界多 1(<=)，i == len 時讀到陣列外一個元素
#include <stddef.h>
#include <stdio.h>

int sum(const int *a, size_t len) {
    int total = 0;
    for (size_t i = 0; i <= len; ++i)      // 應為 i < len
        total += a[i];                       // a[len] 越界讀取
    return total;
}`,
		fixed: `// 安全寫法：只讀 [0, len) 的合法範圍，上界用 < 而不是 <=
#include <stddef.h>

int sum(const int *a, size_t len) {
    int total = 0;
    for (size_t i = 0; i < len; ++i)       // 只觸碰 [0, len) 的元素
        total += a[i];
    return total;
}`,
		patch: `@@
-    for (size_t i = 0; i <= len; ++i)
-        total += a[i];                       // a[len] 越界讀取
+    for (size_t i = 0; i < len; ++i)
+        total += a[i];`,
		refs: ['CWE-125'],
		tags: ['out-of-bounds-read', 'bounds'],
	},
	{
		id: 'CWE-129',
		name: 'Improper Validation of Array Index',
		lang: 'c',
		status: 'Complete',
		what: `陣列索引未校驗。索引來自外部輸入或未受信任的計算，直接用來讀寫陣列；
負數或超過上限的值會造成越界存取。建議做法是存取前先檢查索引落在合法範圍
[0, n)，不在範圍內就拒絕存取。`,
		problem: `// 不安全寫法：idx 由外部(net)輸入，未校驗就當作索引用 arr[idx]
#include <stddef.h>

int value_at(const int *arr, size_t n, int idx) {
    return arr[idx];                 // idx<0 或 idx>=n => 越界讀取
}`,
		fixed: `// 安全寫法：先檢查負數與上限，合法才取用 arr[idx]
#include <stddef.h>

int value_at(const int *arr, size_t n, int idx) {
    if (idx < 0 || (size_t)idx >= n) return -1;   // 越界一律拒絕
    return arr[idx];
}`,
		patch: `@@
 int value_at(const int *arr, size_t n, int idx) {
-    return arr[idx];
+    if (idx < 0 || (size_t)idx >= n) return -1;   // 越界一律拒絕
+    return arr[idx];
 }`,
		refs: ['CWE-129', 'SEI CERT'],
		tags: ['array-index', 'bounds'],
	},
	{
		id: 'CWE-131',
		name: 'Incorrect Calculation of Buffer Size',
		lang: 'c',
		status: 'Complete',
		what: `緩衝大小計算錯誤。配置時把元素大小、元素個數，或要附帶的 NUL 尾格算錯，
導致配出太小（或少一格）的緩衝。建議明確寫成 count * sizeof(element)，
需要當字串使用時再多加 +1 並補上 NUL。`,
		problem: `// 不安全寫法：malloc 只配 n 位元組，卻要放 n 個 int(每個需 sizeof(int))
#include <stdlib.h>
#include <string.h>

int *make(int n, const int *src) {
    int *p = (int *)malloc(n);             // 應為 n * sizeof(int)
    if (p == NULL) return NULL;
    memcpy(p, src, n * sizeof(int));       // 寫到配出的緩衝外 => 堆積溢位
    return p;
}`,
		fixed: `// 安全寫法：用 n * sizeof(int) 正確算位元組數，再 memcpy 同樣長度
#include <stdlib.h>
#include <string.h>

int *make(int n, const int *src) {
    int *p = (int *)malloc(n * sizeof(int));   // 每個元素 sizeof(int)
    if (p == NULL) return NULL;
    memcpy(p, src, n * sizeof(int));
    return p;
}`,
		patch: `@@
-    int *p = (int *)malloc(n);
+    int *p = (int *)malloc(n * sizeof(int));   // 每個元素 sizeof(int)
     if (p == NULL) return NULL;
     memcpy(p, src, n * sizeof(int));`,
		refs: ['CWE-131'],
		tags: ['buffer-size', 'bounds'],
	},
	{
		id: 'CWE-134',
		name: 'Use of Externally-Controlled Format String',
		lang: 'c',
		status: 'Complete',
		what: `外部控制的格式字串。直接把使用者輸入當成 printf 的 fmt 引數；fmt 是格式化
字串，攻擊者可用 %s、%n 等讀寫堆疊，釀成資訊洩漏甚至任意位址寫入。
建議做法是 fmt 永遠是字面常數，使用者資料只能放進「參數」位置。`,
		problem: `// 不安全寫法：把使用者輸入直接當格式字串 -> 便宜的格式字串攻擊
#include <stdio.h>
#include <string.h>

void log_msg(const char *user) {
    char buf[256];
    snprintf(buf, sizeof(buf), user);      // user 含 %n/%s 可讀寫記憶體
    printf("%s\\n", buf);
}`,
		fixed: `// 安全寫法：fmt 是文字常數 "%s"，user 只是對應的字串參數
#include <stdio.h>
#include <string.h>

void log_msg(const char *user) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", user);   // user 永遠是資料，不是格式
    printf("%s\\n", buf);
}`,
		patch: `@@
-    snprintf(buf, sizeof(buf), user);
+    snprintf(buf, sizeof(buf), "%s", user);   // user 永遠是資料，不是格式
     printf("%s\\n", buf);`,
		refs: ['CWE-134', 'SEI CERT'],
		tags: ['format-string', 'printf'],
	},
	{
		id: 'CWE-170',
		name: 'Improper Null Termination',
		lang: 'c',
		status: 'Complete',
		what: `緩衝未以 NUL(0) 正確結尾。拷貝後沒有補上結尾字元，之後的字串函式會一直
讀到 NUL 才停下，一路越界讀出配置範圍。建議配置時多預留 1 格，拷完後在第 n 格寫入
結尾 NUL，即 dst[n]=0，確保任何長度下都正確結尾。`,
		problem: `// 不安全寫法：memcpy 拷 n 位元組，沒留 NUL,字串函式讀越界
#include <string.h>

void store(char *dst, const char *src) {
    size_t n = strlen(src);
    memcpy(dst, src, n);        // 沒拷結尾 NUL, dst 未終止
    if (strlen(dst) > 0) {}     // strlen 讀到 dst 配置之外才會停
}`,
		fixed: `// 安全寫法：拷完補 dst[n]=0, 下一次字串運算保證在緩衝內結束
#include <string.h>

void store(char *dst, const char *src) {
    size_t n = strlen(src);
    memcpy(dst, src, n);          // 拷 src 的 n 個字元
    dst[n] = 0;                    // 顯式 NUL 結尾
}`,
		patch: `@@
     size_t n = strlen(src);
     memcpy(dst, src, n);
-    if (strlen(dst) > 0) {}
+    dst[n] = 0;                    // 顯式 NUL 結尾
 }`,
		refs: ['CWE-170', 'SEI CERT'],
		tags: ['null-termination', 'string'],
	},
	{
		id: 'CWE-190',
		name: 'Integer Overflow or Wraparound',
		lang: 'c',
		status: 'Complete',
		what: `整數溢位／繞回。無號整數溢位不會報錯而是繞回成很小甚至 0 的值，
若拿溢位後的數當緩衝大小，malloc 會配太小，後續照原大小寫入造成溢位。
建議做法是先做範圍檢查（例如 len == SIZE_MAX）再 +1，且用夠寬的型別。`,
		problem: `// 不安全寫法：len+1 未先檢查，len 接近 SIZE_MAX 時繞回 0 => 配到過小緩衝
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

char *dup(const char *src, size_t len) {
    char *p = (char *)malloc(len + 1);       // len==SIZE_MAX 時 +1 溢位
    if (p == NULL) return NULL;
    memcpy(p, src, len);                      // 緩衝不足仍照 len 寫 => 堆積溢位
    p[len] = 0;
    return p;
}`,
		fixed: `// 安全寫法：先檢查 len 是 SIZE_MAX（溢位前）再 +1，且以 size_t 兜住
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

char *dup(const char *src, size_t len) {
    if (len == SIZE_MAX) return NULL;          // 溢位前擋掉最極端值
    char *p = (char *)malloc(len + 1);
    if (p == NULL) return NULL;
    memcpy(p, src, len);
    p[len] = 0;
    return p;
}`,
		patch: `@@
 char *dup(const char *src, size_t len) {
+    if (len == SIZE_MAX) return NULL;          // 溢位前擋掉最極端值
     char *p = (char *)malloc(len + 1);
     if (p == NULL) return NULL;`,
		refs: ['CWE-190', 'SEI CERT'],
		tags: ['integer-overflow', 'wraparound'],
	},
	{
		id: 'CWE-191',
		name: 'Integer Underflow (Wrap or Wraparound)',
		lang: 'c',
		status: 'Complete',
		what: `整數下溢／繞回。size_t（無號）迴圈往 0 以下遞減時，當 i 為 0 再執行 i--，
i 不會變小而是直接繞回 SIZE_MAX，造成無限迴圈與越界存取。建議以 i > 0 作為條件，
先 --i 再使用索引，讓它落在合法範圍且絕不超過上限。`,
		problem: `// 不安全寫法：size_t 迴圈用 i >= 0 往下走，i==0 再 --i 就繞回 SIZE_MAX
#include <stddef.h>
#include <stdio.h>

void walk_back(const unsigned char *buf, size_t len) {
    for (size_t i = len; i >= 0; --i)      // i 從 0 變成 SIZE_MAX，下溢 => 停不下來
        printf("%u\\n", buf[i]);              // 讀到緩衝之外
}`,
		fixed: `// 安全寫法：以 i > 0 當條件、迴圈內先 --i，保證從 len 一路合法走到 0
#include <stddef.h>
#include <stdio.h>

void walk_back(const unsigned char *buf, size_t len) {
    for (size_t i = len; i > 0; ) {
        --i;                                 // 先減再取，索引不會繞到下溢
        printf("%u\\n", buf[i]);
    }
}`,
		patch: `@@
-    for (size_t i = len; i >= 0; --i)
-        printf("%u\\n", buf[i]);
+    for (size_t i = len; i > 0; ) {
+        --i;                                 // 先減再取，索引不會繞到下溢
+        printf("%u\\n", buf[i]);
+    }`,
		refs: ['CWE-191'],
		tags: ['integer-underflow', 'wrap'],
	},
	{
		id: 'CWE-193',
		name: 'Off-by-one Error',
		lang: 'c',
		status: 'Complete',
		what: `差一錯誤。迴圈上界多 1（<= 該用 <）或少配置 1 位元組（萬一要放結尾 NUL），
都在邊界處恰好寫出／讀破一整格。這類錯誤常跟配置大小與索引型別綁在一起。
建議做法是謹守「n 個元素有效索引是 [0, n)」並統一迴圈寫法。`,
		problem: `// 不安全寫法：陣列只有 n 格，迴圈卻跑 0..n 共 n+1 次 => 最後一次越界
#include <stddef.h>

void zero_all(short *buf, size_t n) {
    for (size_t i = 0; i <= n; ++i)      // 上界多 1，i==n 已寫到一格之外
        buf[i] = 0;
}`,
		fixed: `// 安全寫法：索引只走到 n-1，迴圈恰好 n 次、停在緩衝內
#include <stddef.h>

void zero_all(short *buf, size_t n) {
    for (size_t i = 0; i < n; ++i)        // 合法索引範圍是 [0, n)
        buf[i] = 0;
}`,
		patch: `@@
-    for (size_t i = 0; i <= n; ++i)      // 上界多 1
+    for (size_t i = 0; i < n; ++i)        // 合法索引範圍是 [0, n)
        buf[i] = 0;`,
		refs: ['CWE-193'],
		tags: ['off-by-one', 'bounds'],
	},
	{
		id: 'CWE-242',
		name: 'Use of Inherently Dangerous Function',
		lang: 'c',
		status: 'Complete',
		what: `使用本質就危險的函式。C 的 gets() 不檢查緩衝大小、對整段輸入照單全收，
它就像一道完全不校驗的越界寫入大門；同屬本質危險的 system()，其風險則在於會叫出系統 shell，兩者都應避開。
建議改用 fgets()／getline() 這類支援上限的讀取，或乾脆完全不碰 gets()。`,
		problem: `// 不安全寫法：gets 不回長度也不校驗 => 輸入超過 buf 就爆 stack
#include <stdio.h>

void read_line(void) {
    char buf[128];
    gets(buf);                   // CWE-242: gets 本質危險、無上限
    printf("got=%s\\n", buf);
}`,
		fixed: `// 安全寫法：fgets 明確給大小上限 sizeof(buf)，多餘輸入直接截斷
#include <stdio.h>

void read_line(void) {
    char buf[128];
    if (fgets(buf, sizeof(buf), stdin) != NULL)   // 有上限、回傳值也校驗
        printf("got=%s\\n", buf);
}`,
		patch: `@@
 void read_line(void) {
     char buf[128];
-    gets(buf);
-    printf("got=%s\\n", buf);
+    if (fgets(buf, sizeof(buf), stdin) != NULL)   // 有上限的讀取
+        printf("got=%s\\n", buf);
 }`,
		refs: ['CWE-242', 'SEI CERT'],
		tags: ['gets', 'dangerous-function'],
	},
	{
		id: 'CWE-252',
		name: 'Unchecked Return Value',
		lang: 'c',
		status: 'Complete',
		what: `返回值未檢查。malloc/fopen/setuid 這類可能失敗的函式會回傳錯誤訊號，呼叫端
卻加以忽略，例如把 malloc 回傳的 NULL 當成有效位址接著寫入，或檔案開啟失敗後仍繼續使用。
建議對每個關鍵回傳值都做 if 判斷，失敗就先處理（return／釋放完再往下走）。`,
		problem: `// 不安全寫法：malloc 失敗回 NULL 被忽略，直接當陣列寫 => 崩潰/危險
#include <stdlib.h>
#include <string.h>

void fill(int n) {
    int *p = (int *)malloc(n * sizeof(int));
    for (int i = 0; i < n; ++i) p[i] = i;   // p 可能是 NULL => 寫空指標
    free(p);
}`,
		fixed: `// 安全寫法：malloc 之後立刻 if(p==NULL) 處理，NULL 絕不往下寫
#include <stdlib.h>
#include <string.h>

void fill(int n) {
    int *p = (int *)malloc(n * sizeof(int));
    if (p == NULL) return;                     // 失敗路徑先離開
    for (int i = 0; i < n; ++i) p[i] = i;
    free(p);
}`,
		patch: `@@
     int *p = (int *)malloc(n * sizeof(int));
+    if (p == NULL) return;                     // 失敗路徑先離開
     for (int i = 0; i < n; ++i) p[i] = i;
     free(p);`,
		refs: ['CWE-252', 'SEI CERT'],
		tags: ['return-value', 'malloc'],
	},
	{
		id: 'CWE-401',
		name: "Improper Release of Memory Before Removing Last Reference ('Memory Leak')",
		lang: 'c',
		status: 'Complete',
		what: `記憶體洩漏。配置後在某些分支直接 return、沒釋放就先丟掉最後引用，
該塊記憶體永遠無法歸還，長時間反覆發生會把可用記憶體耗盡。建議做法是集中管理清理：
用單一出口(unified)如 goto cleanup，或確保每一條路徑都 free。`,
		problem: `// 不安全寫法：錯誤路徑直接 return，malloc 的 buf 沒釋放 => memory leak
#include <stdlib.h>
#include <string.h>

static int check(const char *s) { (void)s; return 0; }
static void commit(char *s) { (void)s; }

int save(const char *data) {
    char *buf = (char *)malloc(strlen(data) + 1);
    if (buf == NULL) return -1;
    if (check(data) != 0) {
        return -2;                   // buf 沒 free => CWE-401
    }
    commit(buf);
    free(buf);
    return 0;
}`,
		fixed: `// 安全寫法：goto 統一出清理點，任何路徑都會 free => 無洩漏
#include <stdlib.h>
#include <string.h>

static int check(const char *s) { (void)s; return 0; }
static void commit(char *s) { (void)s; }

int save(const char *data) {
    char *buf = (char *)malloc(strlen(data) + 1);
    int rc = 0;
    if (buf == NULL) return -1;
    if (check(data) != 0) {
        rc = -2;
        goto out;                    // 統一出口，這裡保證釋放
    }
    commit(buf);
out:
    free(buf);
    return rc;
}`,
		patch: `@@
 int save(const char *data) {
     char *buf = (char *)malloc(strlen(data) + 1);
+    int rc = 0;
     if (buf == NULL) return -1;
     if (check(data) != 0) {
-        return -2;
+        rc = -2;
+        goto out;                    // 統一出口，這裡保證釋放
     }
     commit(buf);
+out:
     free(buf);
-    return 0;
+    return rc;
 }`,
		refs: ['CWE-401'],
		tags: ['memory-leak', 'free'],
	},
	{
		id: 'CWE-415',
		name: 'Double Free',
		lang: 'c',
		status: 'Complete',
		what: `雙重釋放。同一塊 heap 記憶體被 free() 兩次；第二次 free 會碰到已被歸還
並可能重新配置給別人的區塊，改寫管理結構或造成 use-after-free。建議做法是 free 之後
立即 p = NULL，之後只對非 NULL 才 free。`,
		problem: `// 不安全寫法：同一指標在兩個分支各自 free，有一條路徑連 free 兩次
#include <stdlib.h>

void work(char *p, int flag) {
    free(p);                        // 這裡已經還給 heap
    if (flag) free(p);              // flag 為真 => 對已 free 的 p 再 free
}`,
		fixed: `// 安全寫法：free 後立刻置 NULL，再次釋放前檢查 != NULL => 不會雙釋
#include <stdlib.h>

void work(char *p, int flag) {
    free(p);
    p = NULL;                      // 之後任何 free(p) 都是安全 no-op
    if (flag) {
        if (p != NULL) free(p);    // p 已是 NULL，不會進入
    }
}`,
		patch: `@@
 void work(char *p, int flag) {
     free(p);
-    if (flag) free(p);
+    p = NULL;                      // free 後置 NULL
+    if (flag) {
+        if (p != NULL) free(p);
+    }
 }`,
		refs: ['CWE-415'],
		tags: ['double-free', 'free'],
	},
	{
		id: 'CWE-416',
		name: 'Use After Free',
		lang: 'c',
		status: 'Complete',
		what: `釋放後使用。free(p) 之後還在解參考 p；p 成懸空指標，讀或寫它都是未定義
行為，且堆積常被重建、內容隨時間改變。建議做法是確保 free 是最後一次碰該指標，
free 後把指標設成 NULL，之後一見 NULL 就跳過。`,
		problem: `// 不安全寫法：free 之後又用同一個指標 strlen(name) => use-after-free
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cleanup(char *name) {
    printf("length=%zu\\n", strlen(name));   // 用(讀)name
    free(name);
    strlen(name);                            // name 已被 free，解參考懸空指標
}`,
		fixed: `// 安全寫法：所有資料使用都發生在 free 之前，free 後置 NULL
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cleanup(char *name) {
    size_t n = strlen(name);                 // 讀取都先做完
    printf("length=%zu\\n", n);
    free(name);                             // free 是最後一個使用 name 的動作
    name = NULL;                            // 之後一見 NULL 就不會再碰
}`,
		patch: `@@
 void cleanup(char *name) {
-    printf("length=%zu\\n", strlen(name));
+    size_t n = strlen(name);                 // 讀取都先做完
+    printf("length=%zu\\n", n);
     free(name);
-    strlen(name);
+    name = NULL;                            // free 後置 NULL，避免再碰
 }`,
		refs: ['CWE-416', 'SEI CERT'],
		tags: ['use-after-free', 'lifetime'],
	},
	{
		id: 'CWE-457',
		name: 'Use of Uninitialized Variable',
		lang: 'c',
		status: 'Complete',
		what: `使用未初始化變數。區域變數宣告後沒給初始值就進入使用路徑，其值是堆疊上
殘留的垃圾；讀到它行為未定義，也可能當成敏感資料外洩。建議做法是宣告時立即給預設值，例如
int v = 0，保證即使某分支沒賦值也用得到安全值。`,
		problem: `// 不安全寫法：int v 宣告後未初始化，條件不成立就直接拿 *out 用 => 讀垃圾
int pick(int *out, int use_default) {
    int v;                              // 未初始化
    if (use_default) v = 42;
    *out = v;                           // use_default 為假 => v 是未定義值
    return 0;
}`,
		fixed: `// 安全寫法：宣告當下就給預設值，避免任何路徑讀到未初始化變數
int pick(int *out, int use_default) {
    int v = 0;                          // 有確定的初始值
    if (use_default) v = 42;
    *out = v;                           // 一定來自已初始化的 v
    return 0;
}`,
		patch: `@@
-    int v;                              // 未初始化
+    int v = 0;                          // 有確定的初始值
     if (use_default) v = 42;
     *out = v;`,
		refs: ['CWE-457'],
		tags: ['uninitialized', 'read'],
	},
	{
		id: 'CWE-476',
		name: 'NULL Pointer Dereference',
		lang: 'c',
		status: 'Complete',
		what: `空指標解參考。函式收到 NULL 指標就直接解參考或塞給不允許 NULL 的標準函式，
立刻崩潰（segfault）；在多執行緒環境更難以診斷。建議做法是拿指標來用之前先 if(p != NULL)──
或反過來先處理 NULL 分支，再進行正常操作。`,
		problem: `// 不安全寫法：s 可能是 NULL，卻直接丟給 strlen 解參考 => 崩潰
#include <string.h>

size_t length_of(const char *s) {
    return strlen(s);                    // s==NULL 時 NULL pointer dereference
}`,
		fixed: `// 安全寫法：先檢查 NULL、回傳安全值，只有非空才算長度
#include <string.h>

size_t length_of(const char *s) {
    if (s == NULL) return 0;           // 先把 NULL 檔掉
    return strlen(s);
}`,
		patch: `@@
 size_t length_of(const char *s) {
+    if (s == NULL) return 0;           // 先把 NULL 檔掉
     return strlen(s);
 }`,
		refs: ['CWE-476'],
		tags: ['null-dereference'],
	},
	{
		id: 'CWE-590',
		name: 'Free of Memory not on the Heap',
		lang: 'c',
		status: 'Complete',

		what: `釋放非堆積區配置的記憶體。free() 只能用來釋放 malloc、calloc 或 realloc
	所配置的記憶體。若對區域陣列、靜態陣列、字串常值，或其他非動態配置的位址呼叫
	free()，將造成未定義行為，可能導致程式崩潰或記憶體管理狀態損毀。
	建議明確管理每個指標所指向記憶體的來源與擁有權，並只對動態配置且尚未釋放的
	記憶體呼叫 free()。區域陣列與靜態陣列不需要，也不應手動釋放。`,

		problem: `// 不安全寫法：對區域陣列呼叫 free()，但該記憶體並非由 malloc 配置
	#include &lt;stdlib.h&gt;
	<br><br>
	void f(void) {
		char buf[128];                        // 區域陣列，由系統自動管理
		/* ... 使用 buf ... */

		free(buf);                            // 錯誤：buf 不在堆積區，行為未定義
	}`,

		fixed: `// 安全寫法：區域陣列不需要呼叫 free()，函式結束時會自動失效
	void f(void) {
		char buf[128];                        // 區域陣列，由系統自動管理
		/* ... 使用 buf ... */

		// 不呼叫 free()；離開函式後，buf 的儲存空間會自動回收
	}`,

		patch: `@@
	void f(void) {
		char buf[128];
		/* ... 使用 buf ... */
	-
	-    free(buf);                            // 錯誤：buf 不在堆積區，行為未定義
	+    // 不呼叫 free()；區域陣列會在函式結束時自動失效
	}`,

		refs: ['CWE-590'],
		tags: ['free', 'stack', 'heap'],
	},
	{
		id: 'CWE-676',
		name: 'Use of Potentially Dangerous Function',
		lang: 'c',
		status: 'Complete',
		what: `使用潛在危險函式。strcpy/strcat/gets 這類函式「本身可被安全使用」，
但若呼叫端不自行校驗長度就容易出錯，等於放棄了邊界檢查。建議做法是換成支援上限的
strcpy_s/strncpy 配「+1」上限、或改用 snprintf。`,
		problem: `// 不安全寫法：strcat 直接把 src 銜在 dst 後面，不檢查 dst 剩餘容量
#include <string.h>

void append(char *dst, const char *src) {
    strcat(dst, src);               // CWE-676: strcat 無上限 => dst 溢位
}`,
		fixed: `// 安全寫法：改用 strncat 給上限(dst 剩餘大小)，超過即截斷
#include <string.h>

void append(char *dst, size_t cap, const char *src) {
    size_t used = strlen(dst);
    if (used + 1 < cap)                      // 至少留一格給 NUL
        strncat(dst, src, cap - used - 1);
}`,
		patch: `@@
-void append(char *dst, const char *src) {
-    strcat(dst, src);
+void append(char *dst, size_t cap, const char *src) {
+    size_t used = strlen(dst);
+    if (used + 1 < cap)                      // 至少留一格給 NUL
+        strncat(dst, src, cap - used - 1);
 }`,
		refs: ['CWE-676', 'SEI CERT'],
		tags: ['dangerous-function', 'strcat'],
	},
	{
		id: 'CWE-682',
		name: 'Incorrect Calculation',
		lang: 'c',
		status: 'Complete',
		what: `不正確的計算。整數運算在過窄／混合型別間進行，先溢位或被截斷才塞進寬型別，
結果遠小於實際所需，常讓配置緩衝太小。建議做法是先在較寬的型別做加／乘，例如
(uint64_t)count * page_size，或使用 checked arithmetic。`,
		problem: `// 不安全寫法：32 位元的 count 與 page_size 相乘，超出 range => 中間就溢位
#include <stdint.h>
#include <stdlib.h>

void *alloc_pages(uint32_t count, uint32_t page_size) {
    uint64_t bytes = count * page_size;       // 乘發生在 uint32，先溢位才存 uint64
    return malloc((size_t)bytes);             // 拿錯誤(過小)的總量去配置
}`,
		fixed: `// 安全寫法：先把一項型別提昇成 uint64 再相乘 => 計算正確
#include <stdint.h>
#include <stdlib.h>

void *alloc_pages(uint32_t count, uint32_t page_size) {
    uint64_t bytes = (uint64_t)count * page_size;   // 寬型別裡相乘，不會溢位
    return malloc((size_t)bytes);
}`,
		patch: `@@
-    uint64_t bytes = count * page_size;       // 在 uint32 上溢位
+    uint64_t bytes = (uint64_t)count * page_size;   // 在 uint64 上相乘
     return malloc((size_t)bytes);`,
		refs: ['CWE-682', 'SEI CERT'],
		tags: ['incorrect-calculation', 'integer'],
	},
	{
		id: 'CWE-754',
		name: 'Improper Check for Unusual or Exceptional Conditions',
		lang: 'c',
		status: 'Complete',
		what: `未適當檢查例外／異常條件。程式的「正常路徑」該先排除異常狀態（除零、載入
位元組數不為 0、未知操作）才往下走；沒先把這些邊緣情況擋掉，照正常邏輯處理
就會引進負值長度、除以零等錯誤。建議做法是在入口把異常情境先 if 分支解決掉。`,
		problem: `// 不安全寫法：len 可能為 0，卻直接拿當部分母做比例運算 => 除零
#include <stddef.h>

int ratio(const int *a, size_t len) {
    int sum = 0;
    for (size_t i = 0; i < len; ++i) sum += a[i];
    return sum / (int)len;              // len==0 => division by zero
}`,
		fixed: `// 安全寫法：先處理 len==0 這種例外情境，再進行正常運算
#include <stddef.h>

int ratio(const int *a, size_t len) {
    if (len == 0) return 0;            // 空陣列的例外先擋掉
    int sum = 0;
    for (size_t i = 0; i < len; ++i) sum += a[i];
    return sum / (int)len;             // len>0，除法安全
}`,
		patch: `@@
 int ratio(const int *a, size_t len) {
+    if (len == 0) return 0;            // 空陣列的例外先擋掉
     int sum = 0;
     for (size_t i = 0; i < len; ++i) sum += a[i];
     return sum / (int)len;`,
		refs: ['CWE-754'],
		tags: ['exceptional-condition', 'division-by-zero'],
	},
	{
		id: 'CWE-787',
		name: 'Out-of-bounds Write',
		lang: 'c',
		status: 'Complete',
		what: `越界寫入。逐字元填入或拷貝時沒檢查目的容量，位元組一路寫出緩衝尾端，
同時腐化堆積／堆疊上相鄰資料，是最常被利用以達成 RCE 的弱點之一。建議每次寫入前
都先驗證「還剩多少空間」並預留一格給 NUL。`,
		problem: `// 不安全寫法：一邊 copy 一邊 push，來源沒耗盡就一路寫過 dst 尾端
#include <string.h>

void append(char *dst, const char *src) {
    size_t len = strlen(dst);
    while (*src) dst[len++] = *src++;   // 完全沒檢查剩餘容量 => OOB write
    dst[len] = 0;
}`,
		fixed: `// 安全寫法：傳入容量 cap，條件需留下最後一格給 NUL 才續寫
#include <string.h>

void append(char *dst, size_t cap, const char *src) {
    size_t len = strlen(dst);
    while (*src && len + 1 < cap)       // len+1 要 <= cap，預留 NUL 位置
        dst[len++] = *src++;
    dst[len] = 0;
}`,
		patch: `@@
-void append(char *dst, const char *src) {
+void append(char *dst, size_t cap, const char *src) {
     size_t len = strlen(dst);
-    while (*src) dst[len++] = *src++;
+    while (*src && len + 1 < cap)       // len+1 要 <= cap，預留 NUL 位置
+        dst[len++] = *src++;
     dst[len] = 0;
 }`,
		refs: ['CWE-787', 'SEI CERT'],
		tags: ['out-of-bounds-write', 'bounds'],
	},
	{
		id: 'CWE-788',
		name: 'Access of Memory Location After End of Buffer',
		lang: 'c',
		status: 'Complete',
		what: `存取緩衝尾端之後的位置。指標運算常產生 one-past-the-end，它是「位置」不是
「元素」；對 b[n]（n 是元素個數）解參考就是在讀／寫緩衝結束之後的那格。
建議做法是知道合法範圍是 [0, n)，最後一個元素是 b[n-1]，存取前先檢查 n 是否為 0。`,
		problem: `// 不安全寫法：把「緩衝尾端之後的位置」當成元素直接解參考
unsigned char read_last(const unsigned char *b, size_t n) {
    return b[n];              // b[n] 是 one-past-the-end，在緩衝結束之後
}`,
		fixed: `// 安全寫法：先處理空緩衝，最後一個元素是 b[n-1]，不會碰尾端之後的位置
unsigned char read_last(const unsigned char *b, size_t n) {
    if (n == 0) return 0;              // 空緩衝直接給安全值
    return b[n - 1];                   // 最後一個元素
}`,
		patch: `@@
 unsigned char read_last(const unsigned char *b, size_t n) {
-    return b[n];
+    if (n == 0) return 0;              // 空緩衝直接給安全值
+    return b[n - 1];                   // 最後一個元素
 }`,
		refs: ['CWE-788'],
		tags: ['past-end', 'bounds'],
	},
];
