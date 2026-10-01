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
		id: 'CWE-118',
		name: "Incorrect Access of Indexable Resource ('Range Error')",
		lang: 'c',
		status: 'Complete',
		what: `範圍錯誤（對「可索引資源」的錯誤存取）。程式的可索引資源不一定是單純的線性陣列，可能是陣列構成的陣列、
階層式結構、檔案或其它用索引／指標存取的載體；本質是程式沒有限制、或錯誤地限制對該資源的存取。常見成因是用
與資源真實邊界不符的步進或維度去算索引，尤其把「元素數」與「位元組數」混用，或把需要一個一格的偏移誤當成
一整格來掃多層結構；於是即使步進「看似在範圍內」，也會指到資源內錯誤的一格或直接越出資源。後果可能讀到、寫到
相鄰的其它變數、資料結構或內部狀態，洩漏敏感資訊或損毀記憶體。建議只以一個清楚的維度（元素索引）去定址、讓迴圈
步進與資源真實結構一致、避免混用位元組數與元素數，並在每次用索引／指標存取前先確認它確實落在界內。`,
		problem: `// 不安全寫法：把「元素數」與「位元組數」搞混，用位元組步進去掃整數陣列
#include <stddef.h>

static int resources[8];
size_t used = 0;

void clear_all(void) {
    // used 是元素數，這裡卻以 sizeof(int) 為步進、範圍也乘上 sizeof(int)
    for (size_t off = 0; off < used * sizeof(int); off += sizeof(int))
        resources[off] = 0;                 // 把位元組步進當成陣列索引 => range error
}`,
		fixed: `// 安全寫法：直接用元素數當索引，步進一格 = 一個元素，位置永遠一致
#include <stddef.h>

static int resources[8];
size_t used = 0;

void clear_all(void) {
    for (size_t i = 0; i < used; ++i)      // 每步一個元素，範圍就是元素數
        resources[i] = 0;
}`,
		patch: `@@
-    for (size_t off = 0; off < used * sizeof(int); off += sizeof(int))
-        resources[off] = 0;
+    for (size_t i = 0; i < used; ++i)
+        resources[i] = 0;`,
		refs: ['CWE-118'],
		tags: ['range-error', 'indexable', 'index'],
	},
	{
		id: 'CWE-119',
		name: 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
		lang: 'c',
		status: 'Complete',

		what: `記憶體緩衝區操作缺少邊界限制（在緩衝區界外做讀寫）。CWE-119 是記憶體安全相關弱點的上位分類，本質是程式對
一個記憶體緩衝做讀取、寫入或複製等操作時，讀到或寫到該緩衝「預期邊界」之外的記憶體位置，因而碰觸到本不該碰觸的
記憶體：這些位置可能連著其它變數、資料結構或程式內部資料。常見成因是 strcpy、memcpy 這類複製在呼叫時不攜帶容量，
或長度未校驗、索引越界、指標運算把存取引到緩衝之外。界外讀取可能洩漏相鄰的敏感內容；界外寫入則會損毀相鄰記憶體，
釀成程式崩潰甚至衍生可被利用的安全風險。建議在操作緩衝時一併管理其容量，於讀寫或複製前先檢查資料長度與剩餘空間，
確保每一次存取都不越過已配置的邊界。`,

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
		what: `經典緩衝區溢位（緩衝區複製）。本質是程式把來源緩衝複製到目的緩衝時，沒有先驗證來源的大小小於目的的大小；
當來源比目的緩衝大，就會連同資料一起寫到目的之外，覆寫相鄰記憶體。成因幾乎都是少了一道「來源長度 < 目的容量」的
檢查，或計算容量時忘了替結尾 NUL 留格。在堆疊上可順帶覆寫返回位址（stack BOF）把控制流導向攻擊者，是最典型、
也最常被拿來執行任意程式碼的緩衝區弱點之一。建議改用有上限的 snprintf／strncpy，把複製數量限制在目的緩衝大小以內，
並保證目的緩衝一定以 NUL 結尾，複製後再檢查結果是否遭到截斷。`,
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
		id: 'CWE-121',
		name: 'Stack-based Buffer Overflow',
		lang: 'c',
		status: 'Complete',
		what: `堆疊型緩衝區溢位。被覆寫的緩衝配置在堆疊上——即函式的區域變數，或少數情況下是傳入的參數。程式在這些區域
陣列上複製或寫入超出其大小的資料，就會連帶改寫堆疊上緊鄰的內容，尤其是函式返回位址與呼叫者的區域變數，是歷史最經典、
也最常被用來奪取程式控制流的弱點。成因幾乎都是對來源長度沒有任何檢查，或計算容量時忘了替結尾 NUL 留格，一經溢寫便可覆寫
返回位址、把控制流向導向攻擊者的程式碼。建議明確以 cap 限制寫入長度、先檢查來源長度再處理，並讓目的緩衝一定以 NUL 結尾。`,
		problem: `// 不安全寫法：區域陣列 buf 在堆疊上，strcpy 卻可寫滿整個來源
#include <stdio.h>
#include <string.h>

void greet(const char *who) {
    char buf[64];                 // stack buffer
    strcpy(buf, who);             // who 超過 63 字元 => 改寫返回位址 (stack smashing)
    printf("hi %s\\n", buf);
}`,
		fixed: `// 安全寫法：snprintf 限額寫入、保證 NUL 結尾，超過直接截斷
#include <stdio.h>

void greet(const char *who) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", who);   // 寫入上限 = 緩衝大小，不會爆堆疊
    printf("hi %s\\n", buf);
}`,
		patch: `@@
-    char buf[64];
-    strcpy(buf, who);
+    char buf[64];
+    snprintf(buf, sizeof(buf), "%s", who);
     printf("hi %s\\n", buf);`,
		refs: ['CWE-121'],
		tags: ['stack', 'buffer-overflow'],
	},
	{
		id: 'CWE-122',
		name: 'Heap-based Buffer Overflow',
		lang: 'c',
		status: 'Complete',
		what: `堆積型緩衝區溢位。被覆寫的緩衝配置在堆積（heap）區塊，也就是用 malloc() 這類配置函式取得的小塊記憶體。
若配出的緩衝太小，卻用 strcpy／memcpy 將更大的來源整段寫入，多出來的資料就會覆寫堆積上緊鄰的資料與配置管理用的
meta data，破壞堆積的結構完整性；被改寫過的資料與控制結構之後的 free 甚至可能被誘導，把漏洞升級成任意程式碼執行。
成因多是沒算出真正需要的容量、或忘替結尾 NUL 留格。建議做法是先算出真正需要的大小（含結尾 NUL）再配置，配置後不要用
會整段覆蓋、又不檢查大小的函式，並確認配置成功後才寫入。`,
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
		id: 'CWE-123',
		name: 'Write-what-where Condition',
		lang: 'c',
		status: 'Complete',
		what: `任意寫（寫入內容與寫入位置都可被攻擊者控制）。只要攻擊者有能力把「任意值」寫到「任意位置」都歸此類，通常由
緩衝溢位造成。典型是目的位址由未受信任的長度或索引推算、內容也來自輸入；攻擊者可藉指定負偏移或超大長度，把一段受控資料
寫到任意位址，覆寫返回位址、函式指標或其它關鍵狀態，進而接管程式執行。成因常是「參與算出位址」的長度或索引未受校驗。
建議把目的位址固定在受管理的緩衝內，並先校驗任何參與算出位址的長度或索引都在合法範圍，讓 where（寫到哪）不可受控；
同時把 what（寫什麼）限制在通過檢驗的資料，兩端一併收斂到內部受管理的結構裡。`,
		problem: `// 不安全寫法：目的位址由 len 推算、內容是使用者字串，兩者都可控
#include <string.h>

static char heap_log[256];

void store(const char *s, size_t len) {
    // where = heap_log + len (len 可代任意值)
    // what  = s (內容供攻擊者填)
    strcpy(heap_log + len, s);            // write-what-where
}`,
		fixed: `// 安全寫法：位址固定在緩衝開頭、先用剩餘容量收斂長度，兩邊都受檢驗
#include <stdio.h>

static char heap_log[256];

void store(const char *s, size_t len) {
    if (len >= sizeof(heap_log)) return;  // 長度越界先擋，where 固定為 heap_log
    snprintf(heap_log + len, sizeof(heap_log) - len, "%s", s);
}`,
		patch: `@@
  void store(const char *s, size_t len) {
-    strcpy(heap_log + len, s);
+    if (len >= sizeof(heap_log)) return;
+    snprintf(heap_log + len, sizeof(heap_log) - len, "%s", s);
  }`,
		refs: ['CWE-123'],
		tags: ['write-what-where', 'arbitrary-write'],
	},
	{
		id: 'CWE-124',
		name: "Buffer Underwrite ('Buffer Underflow')",
		lang: 'c',
		status: 'Complete',
		what: `緩衝區下寫（下溢寫）。寫入位置落在緩衝「開頭之前」，通常是帶號索引為負值、或指標往回推過了頭，也可能是指標
算術讓目的位址跑到緩衝起點之前。越界方向向左一樣會覆寫前方相鄰的記憶體、瓦解堆疊或堆積結構，進而損壞其它變數甚或
控制資料，與上溢寫同樣危險。成因多是拿外部帶號值直接當索引或偏移、沒先擋掉負值的隱含轉型。建議在寫入前同時檢查下界
與上界，尤其是把外部帶號值當索引或偏移時，一律先攔掉所有負值；並確認指標算術或長度計算不會把位址推到緩衝起點之前。`,
		problem: `// 不安全寫法：i 是帶號型別、由外部控制，負值時 buf[i] 寫到陣列開頭之前
#include <stdint.h>

int store(int *buf, size_t n, int32_t i, int v) {
    buf[i] = v;                  // i < 0 => 寫到 buf[0] 之前 => buffer underwrite
    return 0;
}`,
		fixed: `// 安全寫法：先檢查下界(>=0)與上界(< n)，負值與越界一律拒絕
#include <stdint.h>

int store(int *buf, size_t n, int32_t i, int v) {
    if (i < 0 || (size_t)i >= n) return -1;   // 同時守住兩端
    buf[i] = v;
    return 0;
}`,
		patch: `@@
  int store(int *buf, size_t n, int32_t i, int v) {
+    if (i < 0 || (size_t)i >= n) return -1;
     buf[i] = v;
     return 0;
  }`,
		refs: ['CWE-124'],
		tags: ['buffer-underflow', 'underwrite', 'bounds'],
	},
	{
		id: 'CWE-125',
		name: 'Out-of-bounds Read',
		lang: 'c',
		status: 'Complete',
		what: `越界讀取。本質是程式讀取資料時越過目標緩衝的尾端或開頭，可能因迴圈或索引上界差 1、對長度未受檢驗的緩衝做
存取、或錯信字串結尾的哨兵（NUL）確實存在。界外的記憶體位置可能包含密鑰、個資、位址等秘密值，洩漏出去可做進一步的
攻擊，還可能用於繞過 ASLR 等保護機制；當程式依賴某個哨兵決定「讀到哪停」、而資料又缺尾時，也會讀過頭而觸發
segfault 崩潰。建議嚴格以半開區間 [0, len) 作迴圈範圍、在每次存取前先檢查索引，並對任何長度參數、緩衝大小計算
與偏移先做正確校驗，不要依賴未受信任輸入裡的哨兵來判斷界線。`,
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
		id: 'CWE-126',
		name: "Buffer Over-read ('Buffer Overrun')",
		lang: 'c',
		status: 'Complete',
		what: `緩衝區上讀（越界上讀）。讀取使用的索引或指標指向了目標緩衝「之後」的記憶體位置。常見成因是讓指標或索引一直
進到超出緩衝的位置才讀取：以大步進掃描、或在尾端讀固定大小的區塊時，最後一段資料不足所需的組大小仍照完整大小讀取，
便跨過緩衝尾端多讀幾格。後果是越界讀把相鄰的敏感資料（包括密鑰、堆積內容）洩漏給呼叫端，或對未映射位址觸發
崩潰。建議每一筆都用「確實存在的長度」來判定範圍，而不是只憑「起始位置 + 寫死的步進」當作界線；在試圖讀一整組資料前，
先確認整組都仍落在可用範圍內。`,
		problem: `// 不安全寫法：步進 8、只檢查起點，最後一組不完整仍照整組 8 位元組讀
int parse(const unsigned char *p, size_t avail) {
    int sum = 0;
    for (size_t i = 0; i < avail; i += 8)        // avail 不是 8 的整數時
        sum += p[i] + p[i + 2] + p[i + 4] + p[i + 6];  // i+6 可能 >= avail => over-read
    return sum;
}`,
		fixed: `// 安全寫法：以「一整組都還在範圍內」為繼續條件，不足整組就不讀
int parse(const unsigned char *p, size_t avail) {
    int sum = 0;
    for (size_t i = 0; i + 7 < avail; i += 8)   // 一整組 8 位元組都在 [i, i+7] 內
        sum += p[i] + p[i + 2] + p[i + 4] + p[i + 6];
    return sum;
}`,
		patch: `@@
-    for (size_t i = 0; i < avail; i += 8)
-        sum += p[i] + p[i + 2] + p[i + 4] + p[i + 6];
+    for (size_t i = 0; i + 7 < avail; i += 8)
+        sum += p[i] + p[i + 2] + p[i + 4] + p[i + 6];`,
		refs: ['CWE-126'],
		tags: ['buffer-overread', 'overrun', 'bounds'],
	},
	{
		id: 'CWE-128',
		name: 'Wrap-around Error',
		lang: 'c',
		status: 'Complete',
		what: `無號數值的繞回錯誤。無號型別在「最大值 + 1」時繞回 0、或減到 0 以下時下溢回最大值，得到一個很小、負值或
未定義的數。成因常在增量／減量迴圈、或用加減號去推算大小時沒留意型別上限，例如算「n - 1」時正好碰上 n 為 0。
若拿繞回後的值去算長度、索引或容量，會得到與真實值差很多的量，接著又依原本的大值去讀寫，就會出越界——緩衝配得太小、
索引錯得離譜多半由此而起。建議在運算前先判定「值已接近型別極限」再進行加／減，或改用更寬的型別與 checked arithmetic，
在尺寸或長度被拿來使用前先捕捉到可能的溢位／下溢。`,
		problem: `// 不安全寫法:n==0 時 n-1 下溢成 SIZE_MAX,再拿它當偏移讀取
#include <stdint.h>
#include <string.h>

void decode(const unsigned char *in, unsigned char *out, size_t n) {
    size_t off = n - 1;                    // n==0 => 下溢成 SIZE_MAX (wrap-around)
    memcpy(out, in + off, 1);             // 從錯得離譜的位置讀取 => 越界
}`,
		fixed: `// 安全寫法:運算前先擋掉會觸發繞回的極端值
#include <stdint.h>
#include <string.h>

void decode(const unsigned char *in, unsigned char *out, size_t n) {
    if (n == 0) return;                    // 先處理空緩衝,避免 n-1 下溢
    size_t off = n - 1;                    // 此時保證不繞回
    memcpy(out, in + off, 1);
}`,
		patch: `@@
  void decode(const unsigned char *in, unsigned char *out, size_t n) {
+    if (n == 0) return;
      size_t off = n - 1;
      memcpy(out, in + off, 1);
  }`,
		refs: ['CWE-128', 'CWE-191'],
		tags: ['wrap-around', 'underflow', 'bounds'],
	},
	{
		id: 'CWE-129',
		name: 'Improper Validation of Array Index',
		lang: 'c',
		status: 'Complete',
		what: `陣列索引未確實校驗。本質是程式用未受信任的輸入來計算或使用陣列索引，卻沒有校驗（或校驗方式錯誤）就確保
該索引指向陣列內的合法位置。常見成因是把迴圈索引、函式回傳值或計算結果直接當索引，只檢查上界而漏了下界（甚至完全不
檢查），負數或超過長度的值便被送進陣列存取。越界索引接著觸發界外讀寫：可能洩漏或修改敏感資料、存取到錯誤的物件，
若索引能被精準控制，甚至可觸發任意程式碼執行。建議存取前檢查索引落在合法 [0, n) 半開區間，把「負值」與「等於 n 以上」
一併視為越界拒絕，形成同時守住上下界的嚴謹校驗。`,
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
		id: 'CWE-130',
		name: 'Improper Handling of Length Parameter Inconsistency',
		lang: 'c',
		status: 'Complete',
		what: `長度參數與真實資料不一致。本質是程式解析具格式化的訊息或結構，卻沒有（或不正確地）處理與實際資料長度不符的
長度欄位，例如協定欄位的 len 與緩衝實際大小、真實剩餘位元組不一致，程式卻完全照 len 去 memcpy 或讀取。攻擊者可
操控長度參數使其與輸入實際長度分歧，動機之一是塞入任意大的輸入：len 比實際大就溢位（寫）或多讀（洩漏）、比實際小則
處理不足或解析錯位，都可能把應用帶進非預期、甚至具惡意的狀態，這些弱點常演成緩衝溢位或任意程式碼執行。建議把 len
同時對「已宣告的容量」與「緩衝內真實剩餘的長度」做交叉校驗，任一方不足就中止處理。`,
		problem: `// 不安全寫法:m->len 可能超過 out 的容量,仍照它整段拷
#include <string.h>

void unwrap(struct msg *m) {
    char out[64];
    memcpy(out, m->data, m->len);   // m->len > 64 => 拷超過 out => 溢位
    out[m->len] = 0;
}`,
		fixed: `// 安全寫法:len 對目的容量先做校驗,不符長度或不夠存就拒絕
#include <string.h>

void unwrap(struct msg *m) {
    char out[64];
    if (m->len >= sizeof(out)) return;      // len 與真實容量不一致時中止
    memcpy(out, m->data, m->len);
    out[m->len] = 0;
}`,
		patch: `@@
  void unwrap(struct msg *m) {
      char out[64];
+    if (m->len >= sizeof(out)) return;
      memcpy(out, m->data, m->len);
      out[m->len] = 0;
  }`,
		refs: ['CWE-130'],
		tags: ['length-parameter', 'inconsistent', 'bounds'],
	},
	{
		id: 'CWE-131',
		name: 'Incorrect Calculation of Buffer Size',
		lang: 'c',
		status: 'Complete',
		what: `緩衝大小計算錯誤。要配置一個緩衝時，沒有正確算出所需的大小，因而配出太小（或少一格）的緩衝，隨後照較大的
實際需求寫入便越過配置尾端、釀成緩衝溢位。常見成因是把元素大小與元素個數搞錯、漏算結構體的 padding，或忘了替結尾
NUL 多留一格——例如只用 count 而沒乘 sizeof(element)。後果是覆寫相鄰記憶體、程式崩潰，甚至被利用執行任意程式碼。
建議明確以 count * sizeof(element) 計算位元組數，需要當字串使用時再多加 +1 並寫入結尾 NUL，配置後再拿使用的
拷貝或讀寫長度與之相互核對。`,
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
		what: `外部控制的格式字串。程式把源自外部、可被使用者控制的字串，直接當成接收格式字串的函式（如 printf、snprintf）
的 fmt 引數來用。本質是混淆了「格式」與「資料」：fmt 是格式化字串而非資料，攻擊者可在其中埋入 %s、%p、%n 等
格式指示字，藉 %s／%p 從堆疊讀取資料（資訊洩漏），或用 %n 把已輸出的字元數寫到任意指定位址（任意寫），進而覆寫
控制資料、接管執行。建議做法是 fmt 永遠是字面常數，使用者輸入只能放在對應的「參數」位置，讓輸出內容永不具有格式控制能力。`,
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
		what: `字串／陣列未以 NUL（0）或等義終止符正確結尾。複製或組裝後沒有補上結尾字元、或終止方式有誤，之後
strlen、printf 這類字串函式會不斷前讀直到遇見 NUL 才停下，一路越界讀出配置範圍，洩漏相鄰記憶體或對未映射位址
崩潰。NUL 終止錯誤常以兩種方式產生：差一錯誤把 NUL 寫到界外，反而成了越界寫入；或錯用 strncpy() 等函式，讓
結尾 NUL 根本沒有被加上。建議配置時多預留 1 格、拷完後在第 n 格顯式寫入 dst[n] = 0，或改用以 NUL 結尾為
保證的函式，並用「長度 + 1」計算容量，確保任何長度下字串都正確終止。`,
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
		id: 'CWE-189',
		name: 'Numeric Errors',
		lang: 'c',
		status: 'Complete',
		what: `數值錯誤的上位分類，涵蓋整數溢位、下溢、繞回、符號轉換、截斷及型別換算
(CWE-190/191/195/197…) 等雜類錯誤。共同點是拿「算出錯的數」去當長度、容量或索引，
最後導向越界讀寫或錯誤的記憶體操作。建議把任何會變成「長度、索引、容量」的計算當成安全邊界：
用寬型別、checked arithmetic，並在使用前做範圍校驗。`,
		problem: `// 不安全寫法:store 的 capacity 與 element_count 皆為 32 位元,相乘先溢位
#include <stdint.h>
#include <stdlib.h>

void *alloc(uint32_t count, uint32_t elem) {
    return malloc(count * elem);         // 32 位元相乘溢位 => 配太小 => numeric error
}`,
		fixed: `// 安全寫法:運算在寬型別(64 位元)進行並檢查溢位,避免繞回
#include <stdint.h>
#include <stdlib.h>

void *alloc(uint32_t count, uint32_t elem) {
    uint64_t total = (uint64_t)count * elem;   // 寬型別相乘
    if (total > SIZE_MAX) return NULL;           // 仍會溢位就回報失敗
    return malloc((size_t)total);
}`,
		patch: `@@
-    return malloc(count * elem);
+    uint64_t total = (uint64_t)count * elem;
+    if (total > SIZE_MAX) return NULL;
+    return malloc((size_t)total);`,
		refs: ['CWE-189'],
		tags: ['numeric-error', 'integer', 'arithmetic'],
	},
	{
		id: 'CWE-190',
		name: 'Integer Overflow or Wraparound',
		lang: 'c',
		status: 'Complete',
		what: `整數溢位／繞回。本質是程式所做的運算會產生整數溢位或繞回，卻假設「結果必然比原值大」；當整數被增量到超過
其表示型別所能存的最大值，值會繞回成很小的數甚至負數。無號溢位不會報錯，而是安靜地繞回；對帶號溢位則屬未定義行為。
若拿溢位後的值當緩衝大小，malloc 會配出太小的緩衝，後續仍照原大小寫入就造成溢位；若拿它當索引或長度，也會得到
錯得離譜的數量。建議在運算發生前就先做溢位前檢查（例如判定 len == SIZE_MAX 再 +1），並用夠寬的型別或 checked
arithmetic，確保尺寸／長度計算不會悄悄繞回。`,
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
		what: `整數下溢／繞回。程式做減法時，結果小於該整數型別的最小可表示值，於是繞回、或得到一個不等於正確結果的值，
帶號與無號都會發生。典型是 size_t（無號）迴圈往 0 以下遞減：當 i 為 0 再執行 i--，i 不會變負而是直接繞回
SIZE_MAX，造成無限迴圈與越界存取。用下溢後的值去算長度或偏移，常把緩衝大小算大、索引算錯，接著照超大值去讀寫就
崩潰或洩漏。建議以 i > 0 作迴圈條件、先 --i 再取用索引讓它落在合法範圍；對任何會減到 0 以下的減法，先擋掉觸發
下溢的條件或改用寬型別處理。`,
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
		what: `差一錯誤。計算或使用的最大值／最小值比正確值多 1 或少 1。典型是迴圈上界多用 <= 而該用 <，或少配置 1
位元組（例如忘了放結尾 NUL），便都在邊界處恰好寫出／讀破一整格。這類錯誤常跟配置大小與索引型別綁在一起：傳給函式的
大小少了 1，該函式便少了最後一個元素或結尾字元的空間；索引推過一格便碰上一格界外。建議謹守「n 個元素的有效索引是
[0, n)」並統一迴圈寫法，配置字串緩衝時記得 +1 給終止符，讓上下界與容量都與元素個數精準對齊；任何增減單位的調整，
都要把「元素個數」與「需要的牆尾字元」一併納入，避免多一格或少一格。`,
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
		id: 'CWE-195',
		name: 'Signed to Unsigned Conversion Error',
		lang: 'c',
		status: 'Complete',
		what: `帶號轉無號錯誤。程式把帶號原始型別轉成無號型別；若原本的值無法以無號表示（例如負數），結果會變成一個
非預期的極大數（SIZE_MAX、UINT_MAX…），違反程式的假設。函式常以負值（如 -1）表示失敗，若把回傳值直接當索引或
長度參數使用，負的尺寸被隱式轉成極大的無號數——讓迴圈條件或 memcpy 的長度錯得離譜，甚至演成可利用的緩衝溢位或
下溢。依賴隱式轉型很危險。建議在檢查階段先把負值在帶號域攔掉，確認數值方向與大小都符合預期後，才進行無號轉型與
後續使用。`,
		problem: `// 不安全寫法:帶號 slen 為負卻直接轉 size_t,變成極大無號再當長度拷
#include <string.h>

void copy_len(char *dst, long slen, const char *src) {
    memcpy(dst, src, (size_t)slen);   // slen<0 => 轉成超大長度 => 越界寫
}`,
		fixed: `// 安全寫法:先攔掉負值、再做上界校驗,才轉型與複製
#include <string.h>

void copy_len(char *dst, size_t dcap, long slen, const char *src) {
    if (slen < 0) return;                       // 負值先拒絕
    if ((size_t)slen > dcap) return;            // 再對容量做上界檢查
    memcpy(dst, src, (size_t)slen);
}`,
		patch: `@@
-  void copy_len(char *dst, long slen, const char *src) {
-      memcpy(dst, src, (size_t)slen);
+  void copy_len(char *dst, size_t dcap, long slen, const char *src) {
+      if (slen < 0) return;
+      if ((size_t)slen > dcap) return;
+      memcpy(dst, src, (size_t)slen);
    }`,
		refs: ['CWE-195'],
		tags: ['signed-unsigned', 'cast', 'sign'],
	},
	{
		id: 'CWE-197',
		name: 'Numeric Truncation Error',
		lang: 'c',
		status: 'Complete',
		what: `數值截斷。寬型別（如 32 位元）的值被塞進窄型別（uint16/uint8）時，較高的位元在轉換中丟失，放進去的是與
原值不相等、被截短的值。這個被截短的數值可能被當成陣列索引、迴圈計數或必要的長度狀態：例如 32 位元的 len 截成
16 位元後，超過 65535 的高位全被砍掉，拿它當複製長度就與真實資料長度不一致，可能溢位或處理不足。由於值已不可信，
系統會進入未定義狀態；截斷雖偶爾被刻意用來取低位，但多數代表實作錯誤。建議全程以完整寬度處理長度／索引，需要窄值前
先驗證源值可被完整表示，避免窄型別在中間把高位截掉。`,
		problem: `// 不安全寫法:32 位元 len 截成 16 位元,超過 65535 的高位全被砍
#include <stdint.h>
#include <string.h>

static char g[65536];
void store(const char *data, uint32_t len) {
    uint16_t short_len = (uint16_t)len;   // len > 65535 時高位被截掉
    memcpy(g, data, short_len);             // 複製長度與 len 不一致
}`,
		fixed: `// 安全寫法:不截斷,以完整寬度校驗並限長後直接使用
#include <stdint.h>
#include <string.h>

static char g[65536];
void store(const char *data, uint32_t len) {
    if (len > sizeof(g)) len = sizeof(g);   // 用完整型別做上限檢查
    memcpy(g, data, len);                    // 長度與容量一致
}`,
		patch: `@@
  void store(const char *data, uint32_t len) {
-    uint16_t short_len = (uint16_t)len;
-    memcpy(g, data, short_len);
+    if (len > sizeof(g)) len = sizeof(g);
+    memcpy(g, data, len);
  }`,
		refs: ['CWE-197'],
		tags: ['truncation', 'narrowing', 'numeric'],
	},
	{
		id: 'CWE-242',
		name: 'Use of Inherently Dangerous Function',
		lang: 'c',
		status: 'Complete',
		what: `使用本質就危險的函式。某些函式無論怎麼用都無法保證安全——它們在設計時常常沒有把安全性納入考量，例如
C 的 gets() 完全不對輸入做邊界檢查，就把任意大小的輸入讀進目的緩衝，等同於一道完全不加校驗的越界寫入大門；本質危險的
system() 則因會叫出系統 shell 而高風險，兩者都應避開。成因是把「本質上無法安全使用」的 API 當成一般函式來呼叫，
風險全看輸入長度而不受呼叫端把關。建議徹底改用 fgets()／getline() 這類支援上限的讀取，明確提供大小並檢查回傳值，
或乾脆完全不碰這類本質危險的函式，直接用安全的替代函式替換。`,
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
		what: `函式回傳值未檢查。本質是程式呼叫某個可能失敗的方法或函式，卻忽略其回傳值，因而無法偵測非預期狀態與異常
條件。兩種常見的錯誤假設是「這個呼叫不可能失敗」與「失敗也無妨」；一旦攻擊者迫使函式失敗或回傳非預期的值，後續邏輯
便建立在錯誤的狀態上。例如 malloc／fopen 回傳 NULL 被忽略，接著把 NULL 當有效位址寫入或繼續使用已失敗的檔案；呼叫
setuid 降權卻沒檢查回傳，程式仍以較高權限執行的後果尤其嚴重。建議對每個關鍵回傳值都做 if 判斷，失敗先處理（return／
釋放完再往下走），在造成損害前把失敗路徑攔下。`,
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
		what: `記憶體洩漏。程式沒有充分追蹤並釋放已使用過的記憶體，使它無法被重新配置與再利用。典型是配置後在某個分支
直接 return、沒釋放就先丟掉最後引用，該塊記憶體永遠無法歸還；若反覆發生，長時間累積會把可用記憶體耗盡，釀成資源
耗竭、效能下降甚至服務中斷。建議集中管理清理：用單一出口（goto cleanup）統一路徑釋放，或確保每一條 return 之前都把
已配置且不再需要的記憶體 free 掉，並讓每個動態資源都有明確的擁有者與生命週期，避免引用被覆寫而失去追蹤。`,
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
		what: `雙重釋放。程式對同一個記憶體位址呼叫兩次 free()。本質是第二次釋放時，該記憶體已歸還給配置器、很可能又
被重新分配給別的區塊；再次 free 便會破壞配置管理結構、觸發崩潰，或造成 use-after-free 等更嚴重的後果，甚至可能被利用。
成因常是同一指標在多個分支各自釋放、或有共用所有權卻沒協調清楚。建議設計明確的單一擁有者；free 之後立即把指標設成
NULL，之後僅對非 NULL 的指標才執行 free，讓同一塊記憶體只會被釋放一次。`,
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
		what: `釋放後使用。記憶體被 free() 之後，程式仍重複使用或參考該指針（use-after-free）。本質是該區塊隨後可能
被重新分配、並存進另一個指針，原指針則指向新配置內的某處；所有透過「舊指針」進行的讀寫都引向本屬於別人的記憶體，
不再有定義。讀取可能是垃圾或敏感資料，寫入則會損毀新物件的狀態，常釀成崩潰或可被利用的安全缺陷。建議確保 free 是
對該指針的最後一個使用動作，free 後立即把指針設成 NULL，之後一見 NULL 便跳過，並以明確的擁有權與生命週期管理物件。`,
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
		what: `使用未初始化變數。程式使用了尚未被初始化的變數，導致不可預測或不預期的結果。在 C/C++ 中堆疊變數預設不
會初始化，通常帶著函式被呼叫前殘留在堆疊上的垃圾資料，攻擊者有時能控制或讀取這些內容；某些情況下，未顯式初始化的變數
會被給一個可能有安全含義的預設值（例如決定是否已認證的旗標）。未初始化也常暗示程式中的筆誤或缺漏。建議宣告當下就給
明確的初值（如 int v = 0），確保任何路徑第一次讀到它時，都是這個確定且安全的值。`,
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
		what: `空指標解參考。程式解參考一個它「預期有效」、但實際上是 NULL 或 0 的指標。常見成因是少了空值檢查：
malloc 家族回傳的 NULL 被略過、輸入給的字串指標可能為空就直接丟給標準函式、或指標根本沒設過值就落進解參考。
解參考 NULL 通常是未定義行為，一般立刻 segfault 崩潰，在多執行緒或複雜環境更難以診斷；若 NULL 落在可寫路徑，還可能
演成更嚴重的損害。建議拿指標來用之前先檢查 if(p != NULL)、或先處理 NULL 分支再進行正常操作，讓空指標在撞上解參考前
就被擋下。`,
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
		what: `使用潛在危險函式。本質是程式呼叫了「若誤用就可能引進弱點、但正確使用仍可安全」的函式，例如 strcpy、strcat、
gets、sprintf 等。這些函式本身不考慮邊界，安全性完全取決於呼叫端是否自行校驗長度；呼叫端一旦漏掉，就等於交出了邊界
把關，容易釀成緩衝溢位。與 CWE-242（本質就危險）不同，這類函式其實可以被安全使用。建議換成支援上限的變體——strncpy
配上「+1」上限、strncat 給剩餘容量、sprintf 改用 snprintf——並在呼叫點確實核對長度與剩餘空間。`,
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
		id: 'CWE-680',
		name: 'Integer Overflow to Buffer Overflow',
		lang: 'c',
		status: 'Complete',
		what: `整數溢位演變成緩衝區溢位。本質是程式為了決定要配置多少記憶體而計算容量，但運算過程中發生整數溢位，
使得配出的記憶體少於預期，接著便以較大的邏輯長度對它寫入，越過緩衝尾端。成因是「元素數 × 元素大小」這類乘法或
加法在窄型別上溢位、繞回成小值，malloc 依此配出過小緩衝，後續 memcpy 卻依未溢位的原始量整段複製，就跨過配置區
尾端。建議在乘法或加法發生前先做溢位前驗算（如 nb != 0 && nb > SIZE_MAX / sz 即回報失敗），並讓配置使用的總量與
複製使用的長度相互對齊。`,
		problem: `// 不安全寫法:nb*sz 溢位成小值 → 緩衝配太小 → memcpy 按原長度寫爆
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

char *make(size_t nb, size_t sz, const char *data) {
    char *dst = (char *)malloc(nb * sz);   // nb*sz 溢位 => 配太小
    memcpy(dst, data, nb * sz);            // 仍以原始量寫 => heap 溢位
    return dst;
}`,
		fixed: `// 安全寫法:配置前先做溢位前檢查,兩邊使用同一已驗算的總量
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

char *make(size_t nb, size_t sz, const char *data) {
    if (nb != 0 && nb > SIZE_MAX / sz) return NULL;   // 溢位前擋掉
    size_t total = nb * sz;                            // 已證明不溢位
    char *dst = (char *)malloc(total);
    if (dst == NULL) return NULL;
    memcpy(dst, data, total);
    return dst;
}`,
		patch: `@@
  char *make(size_t nb, size_t sz, const char *data) {
-    char *dst = (char *)malloc(nb * sz);
-    memcpy(dst, data, nb * sz);
+    if (nb != 0 && nb > SIZE_MAX / sz) return NULL;
+    size_t total = nb * sz;
+    char *dst = (char *)malloc(total);
+    if (dst == NULL) return NULL;
+    memcpy(dst, data, total);
      return dst;
  }`,
		refs: ['CWE-680', 'CWE-190'],
		tags: ['integer-overflow', 'buffer-overflow'],
	},
	{
		id: 'CWE-681',
		name: 'Incorrect Conversion between Numeric Types',
		lang: 'c',
		status: 'Complete',
		what: `型別的換算方式錯誤。從一種資料型別轉到另一種（如 long 轉 int）時，資料可能被捨棄、或以會產生非預期值的
方式重新解讀——例如負數與無號互轉、寬值截斷、檢查與轉型的次序顛倒。若換算後的值用在對安全性敏感的情境（當索引、
長度、配置大小），就會產生危險行為。常見是帶號值在比較或下標時被隱含轉成無號：本應在帶號域攔掉的負數，轉成極大
無號數後繞過範圍檢查，當索引便一次越界。建議做範圍判定時先在原始型別擋掉負值，再於同一型別內比較與定址，避免次序
顛倒讓換錯的數溜進敏感的操作。`,
		problem: `// 不安全寫法:只檢查上界,負數在當索引時被轉成無號而讀到陣列之前
#include <stddef.h>

uint8_t pick(const uint8_t *m, size_t n, int i) {
    if (i <= (int)n) return m[i];   // i 負時被當成無號索引 => 讀 m 之前
    return 0;
}`,
		fixed: `// 安全寫法:先擋負值,再以無號同型別校驗上界,才可做索引
#include <stddef.h>

uint8_t pick(const uint8_t *m, size_t n, int i) {
    if (i < 0 || (size_t)i >= n) return 0;   // 負與越界一併拒絕
    return m[i];
}`,
		patch: `@@
  uint8_t pick(const uint8_t *m, size_t n, int i) {
-    if (i <= (int)n) return m[i];
+    if (i < 0 || (size_t)i >= n) return 0;
      return m[i];
  }`,
		refs: ['CWE-681'],
		tags: ['numeric-conversion', 'cast', 'index'],
	},
	{
		id: 'CWE-682',
		name: 'Incorrect Calculation',
		lang: 'c',
		status: 'Complete',
		what: `不正確的計算。程式執行的運算產生錯誤或不符合用途的結果，而這個結果又被用於安全性關鍵的決策或資源管理。
常見成因是整數運算在過窄／混合型別間進行，先溢位或被截斷才塞進寬型別，求得的值遠小於實際所需，使配置緩衝太小，
或引致權限指派錯誤、比較失敗；被截斷值可能連帶使保護機制失效，甚至在極端案例演成任意程式碼執行。建議先在較寬的型別
做加／乘（如 (uint64_t)count * page_size），並在運算前先檢查可能溢位，或使用 checked arithmetic，確保算出的量與
實際使用一致。`,
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
		what: `未適當檢查異常／例外條件。本質是程式沒有、或不正確地檢查日常運行中不常發生的異常狀況，例如記憶體不足、
因權限不足而無法取得資源、行為失常的客戶端或元件。程式師常假設「這些事不會發生」，攻擊者卻會刻意觸發這些異常、違反
該假設，因而引進不穩定、錯誤行為或弱點。注意此條不專指例外（exception）機制的使用。建議在入口就把除零、載入位元組數
為 0、未知操作等異常情境先以 if 分支排除，確認「正常路徑」只在全無異常狀態時前進，並妥善處理每個可能失敗點的回報。`,
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
		id: 'CWE-762',
		name: 'Mismatched Memory Management Routines',
		lang: 'cpp',
		status: 'Complete',
		what: `記憶體管理例程配錯對。本質是程式要把記憶體資源還給系統時，呼叫的釋放函式與原本配置它的函式不相容。典型是
用 new 配的記憶體卻用 free()、用 malloc() 配的卻用 delete、甚至 new[] 配的用錯誤的釋放例程；廣義也包括配置於堆疊卻
用 free()。每個分配器管理自己的標頭與釋放方式，混用會把堆積管理結構寫壞、造成記憶體損毀或程式崩潰，後果嚴重時甚至
可被利用執行任意程式碼。建議讓配置與釋放成對：new→delete、new[]→delete[]、malloc/calloc/realloc→free，絕不交錯使用
不同來源的例程。`,
		problem: `// 不安全寫法:new[] 配的陣列用 malloc 家族的 free() 釋放 => 釋放方式不符
#include <cstdlib>

void run(size_t n) {
    int *p = new int[n];          // C++ new[]
    /* ... 使用 ... */
    free(p);                      // 應為 delete[] p => mismatched routine
}`,
		fixed: `// 安全寫法:成對使用 new[] / delete[]（或乾脆統一用 malloc/free）
#include <cstdlib>

void run(size_t n) {
    int *p = new int[n];
    /* ... 使用 ... */
    delete[] p;                   // 與 new[] 成對
}`,
		patch: `@@
     int *p = new int[n];
     /* ... 使用 ... */
-    free(p);
+    delete[] p;`,
		refs: ['CWE-762'],
		tags: ['mismatched-memory', 'free-delete'],
	},
	{
		id: 'CWE-763',
		name: 'Release of Invalid Pointer or Reference',
		lang: 'c',
		status: 'Complete',
		what: `對無效指標、或不正確的釋放方式做釋放。本質是程式要把記憶體還給系統，卻呼叫了錯誤的釋放函式、或正確的
函式被用得不得當。幾種形式：用一種方式（顯式或隱式）配置、卻用不相容的另一個函式釋放（見 CWE-762）；函式或例程
本身挑得對但用法錯誤，例如對指向配置「中間」的指標、早已釋放的指標、或根本不是動態記憶體的位址呼叫 free()。釋放器只
認得它發出去的區塊起點，傳錯就破壞管理結構、崩潰甚至被利用。建議永遠保存原始配置回傳的指標、只對它釋放一次，並以成對
的配置／釋放例程為準。`,
		problem: `// 不安全寫法:把指向配置「中間」的指標 free,而非配置開頭
#include <stdlib.h>

void write_msg(char *base, const char *body) {
    char *payload = base + 4;        // 指向 base 區塊的內部
    /* 使用 payload ... */
    free(payload);                    // 不是配置起點 => release of invalid pointer
}`,
		fixed: `// 安全寫法:只 free 原始配置回傳的起點(整個區塊)
#include <stdlib.h>

void write_msg(char *base, const char *body) {
    /* 使用 base、base+4 ... */
    free(base);                      // 釋放時回到配置開頭
}`,
		patch: `@@
  void write_msg(char *base, const char *body) {
      char *payload = base + 4;
      /* 使用 payload ... */
-    free(payload);
+    free(base);
  }`,
		refs: ['CWE-763'],
		tags: ['invalid-pointer', 'free'],
	},
	{
		id: 'CWE-785',
		name: 'Use of Path Manipulation Function without Maximum-sized Buffer',
		lang: 'c',
		status: 'Complete',
		what: `路徑處理函式的輸出緩衝過小。本質是程式呼叫正規化路徑／檔名的函式（如 realpath()、readlink()、PathAppend()
）時，提供的輸出緩衝小於可能的最大尺寸（例如 PATH_MAX）。如果組出路徑用 strcpy/strcat 去填一個固定大小陣列，目錄與
檔名多層串起後很容易超過陣列或路徑上限而溢位改寫相鄰記憶體。建議直接以函式要求的最大容量（通常是 PATH_MAX）配置輸出
緩衝、改用帶容量上限的 snprintf，並檢查回傳值確認路徑沒有被截斷、結果完整有效後再使用。`,
		problem: `// 不安全寫法:用 strcpy/strcat 逐步組路徑,全程沒有大小上限
#include <string.h>

void build_path(char *out, const char *dir, const char *file) {
    strcpy(out, dir);     // out 是多大的緩衝無人知道
    strcat(out, "/");
    strcat(out, file);    // 路徑超過 => 溢位
}`,
		fixed: `// 安全寫法:snprintf 帶上限且含結尾 NUL,回傳值判定是否被截斷
#include <stdio.h>

void build_path(char *out, size_t cap, const char *dir, const char *file) {
    int n = snprintf(out, cap, "%s/%s", dir, file);
    if (n < 0 || (size_t)n >= cap) return;   // 截斷視為失敗直接返回
}`,
		patch: `@@
-  void build_path(char *out, const char *dir, const char *file) {
-      strcpy(out, dir);
-      strcat(out, "/");
-      strcat(out, file);
+  void build_path(char *out, size_t cap, const char *dir, const char *file) {
+      int n = snprintf(out, cap, "%s/%s", dir, file);
+      if (n < 0 || (size_t)n >= cap) return;
    }`,
		refs: ['CWE-785'],
		tags: ['path', 'strcat', 'bounds'],
	},
	{
		id: 'CWE-787',
		name: 'Out-of-bounds Write',
		lang: 'c',
		status: 'Complete',
		what: `越界寫入。本質是程式把資料寫到目標緩衝的尾端之後、或開頭之前。逐字元填入、迴圈複製或用指標算術計算索引
與偏移時，沒有確認還有剩餘落在緩衝內，位元組便一路寫出緩衝範圍，同時覆寫堆積／堆疊上相鄰的資料。寫操作會造成記憶體
損毀：可改寫返回位址等控制資料以執行非預期程式碼，或造成程式崩潰，是最常被利用以達成 RCE（遠端程式碼執行）與其它
記憶體損毀後果的弱點之一。建議每次寫入前都先驗證「還剩多少空間」、檢查迴圈是否會寫破邊界、並預留一格給結尾 NUL；
對字串用帶長度的 strncpy 等並留意它對 NUL 結尾的行為。`,
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
		what: `存取緩衝尾端之後的位置。本質是程式用指向緩衝「結束之後」的指標或索引進行讀寫。常發生在把指標或它的索引
推進緩衝尾端之後、或指標算術結果落在緩衝之後時——例如對長度為 n 的緩衝去存取 b[n]（one-past-the-end），那只是
「位置」不是「元素」。對該位置解參考就是在緩衝結束後那一格讀寫，輕則誤讀洩漏，重則覆寫相鄰記憶體而崩潰或損毀其保護
資料。建議掌握合法範圍是 [0, n)、最後一個元素是 b[n-1]，存取前先檢查 n 是否為 0，並確保索引／偏移不會把位址推到
緩衝之後。`,
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
	{
		id: 'CWE-805',
		name: 'Buffer Access with Incorrect Length Value',
		lang: 'c',
		status: 'Complete',
		what: `位址正確但長度值給錯。本質是程式用循序操作（如 memcpy、read）讀寫緩衝時，使用了錯誤的長度值，使存取落到
緩衝邊界之外。常見是長度引數大於目的實際容量（或大於來源已用的長度）、來自未受信任的輸入、或帶號值轉成無號後暴漲
（例如 -1 變成超大值）；當長度超過目的容量就寫過緩衝尾端造成溢位。與 CWE-119 不同，這裡問題就出在「長度」本身的
數值與真實容量不一致。建議在每個複製／讀寫點把長度與真實容量同步校驗，先確認長度不超過容量並讓兩者對齊，再執行操作。`,
		problem: `// 不安全寫法:dst 位址正確,但 n 是呼叫端給的,可能大於 cap
#include <string.h>

void store(char *dst, size_t cap, const char *src, size_t n) {
    memcpy(dst, src, n);        // n > cap => 寫到 dst 之後 => OOB write
}`,
		fixed: `// 安全寫法:先把長度收斂到容量內,長度與真實空間一致後才複製
#include <string.h>

void store(char *dst, size_t cap, const char *src, size_t n) {
    if (n > cap) n = cap;      // length 對齊真實容量
    memcpy(dst, src, n);
}`,
		patch: `@@
  void store(char *dst, size_t cap, const char *src, size_t n) {
-    memcpy(dst, src, n);
+    if (n > cap) n = cap;
+    memcpy(dst, src, n);
  }`,
		refs: ['CWE-805'],
		tags: ['incorrect-length', 'bounds', 'memcpy'],
	},
	{
		id: 'CWE-823',
		name: 'Use of Out-of-range Pointer Offset',
		lang: 'c',
		status: 'Complete',
		what: `指標偏移超出有效範圍。本質是程式對一個合法指標做指標算術，卻用了會把結果移出合法記憶體範圍的偏移。
雖然指標理論上能指到任意位址，程式通常只期望它在有限範圍（如逐個陣列元素或結構欄位）內存取；偏移可能來自未受信任的
來源、不正確的計算或其它錯誤。若攻擊者能控制或影響偏移，使它越出結構或陣列邊界，就能讀寫產品其它地方使用的記憶體，因而
改變程式狀態、造成崩潰或不穩定，甚至導致程式碼執行。建議在做指標算術前先確認 offset 落在 [0, n) 之內，並以「帶界限
檢查的索引」取代裸指標算術。`,
		problem: `// 不安全寫法:off 由外部給,未校驗就直接以 *(a + off) 解參考
#include <stddef.h>

int read_at(const int *a, size_t n, long off) {
    return *(a + off);          // off 為負或 >= n => 指到陣列外再解參考
}`,
		fixed: `// 安全寫法:解參考前先校驗 off 的上下界(等同再轉成索引)
#include <stddef.h>

int read_at(const int *a, size_t n, long off) {
    if (off < 0 || (size_t)off >= n) return -1;   // 範圍外直接拒絕
    return a[off];                                  // 以索引代替裸指標偏移
}`,
		patch: `@@
  int read_at(const int *a, size_t n, long off) {
-    return *(a + off);
+    if (off < 0 || (size_t)off >= n) return -1;
+    return a[off];
  }`,
		refs: ['CWE-823'],
		tags: ['pointer-offset', 'out-of-range', 'bounds'],
	},
	{
		id: 'CWE-839',
		name: 'Numeric Range Comparison Without Minimum Check',
		lang: 'c',
		status: 'Complete',
		what: `範圍檢查只做上限、漏掉最小（下界）檢查。本質是程式確認某值小於或等於某上限，卻沒同時驗證它大於等於最小值。
有些程式用帶號整數或浮點，即使其值本應非負（≥ 0），輸入校驗又只檢查上限；例如拿帶號值當索引時只寫 i <= 上限，負數
也照樣通過，接著以負索引越界存取。負值若被用於配置大小、陣列與緩衝存取，最終可能釀成緩衝溢位或其它記憶體損毀；也可
用於其它資源（如使購物車算出負價）。建議上下界「同時」校驗：先擋負值再驗上界，兩者缺一都算範圍校驗不完整。`,
		problem: `// 不安全寫法:只檢查上界(i <= max),負數仍會通過且成為負索引
uint8_t fetch(const uint8_t *tbl, size_t n, int i) {
    if (i <= (int)n)             // 負數也 <= 上限 => 放行
        return tbl[i];            // i<0 => 讀到 tbl 之前
    return 0;
}`,
		fixed: `// 安全寫法:下限(i>=0)與上限(i<n)一起檢查才算完整
uint8_t fetch(const uint8_t *tbl, size_t n, int i) {
    if (i < 0 || (size_t)i >= n) return 0;   // 上下界都守住
    return tbl[i];
}`,
		patch: `@@
  uint8_t fetch(const uint8_t *tbl, size_t n, int i) {
-    if (i <= (int)n)
-        return tbl[i];
+    if (i < 0 || (size_t)i >= n) return 0;
+    return tbl[i];
  }`,
		refs: ['CWE-839'],
		tags: ['range-check', 'bounds', 'negative-index'],
	},
	{
		id: 'CWE-1285',
		name: 'Improper Validation of Specified Index in Product',
		lang: 'c',
		status: 'Complete',
		what: `對指定索引／位置／偏移的校驗不嚴謹。本質是程式接收預期指明「可索引資源」（如緩衝或檔案）中某個索引、位置或
偏移的輸入，卻沒有（或不正確地）驗證該索引具有所需的性質。常見是允許「正好等於陣列長度」的特例，讓 one-past-the-end
的索引溜過去，因而讀寫到緩衝結尾之後那一格。當未受信任的輸入未經妥善校驗就被當成索引，攻擊者可存取資源的未授權部分，
觸發緩衝溢位、過度配置或非預期的失敗。建議校驗採用嚴格的半開區間 [0, len)，把「等於 len」與「大於 len」一併視為
越界拒絕，並對位置／偏移同樣施加合法的上下界。`,
		problem: `// 不安全寫法:允許 i == MAX 的特例,而 MAX 正是元素個數 => one-past-the-end
#define MAX 16
static int slots[MAX];

int get_slot(unsigned i) {
    if (i <= MAX) return slots[i];   // i==MAX 時讀的是陣列結尾之後
    return -1;
}`,
		fixed: `// 安全寫法:用嚴格的 [0, MAX),等於 MAX 一律視為越界
#define MAX 16
static int slots[MAX];

int get_slot(unsigned i) {
    if (i >= MAX) return -1;        // 只允許 [0,16)
    return slots[i];
}`,
		patch: `@@
  int get_slot(unsigned i) {
-    if (i <= MAX) return slots[i];
+    if (i >= MAX) return -1;
      return slots[i];
  }`,
		refs: ['CWE-1285'],
		tags: ['index-validation', 'one-past-end', 'bounds'],
	},
];
