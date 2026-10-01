// CWE chunk — category: Uninitialized / Null & Pointer Safety (C / C++).
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
		id: 'CWE-171',
		name: 'Cleansing, Canonicalization, and Comparison Errors',
		lang: 'c',
		status: 'Complete',
		what: `資料在可比對之前沒有經過一致的清洗(canonicalization)就逕行比較。
若進入系統的資料可以有大小寫、空白、不同路徑寫法等多種形式，而程式直接拿「原始」輸入
去對白名單或黑名單做比對，攻擊者只要換一種形式（例如多打一個空格、改大小寫）
就能騙過檢查，讓非法輸入進入系統內部才被發現。建議做法是先將輸入標準化到單一形式
（去空白、轉小寫、正規化路徑），再拿這份清洗過的值來比較，確保檢查與使用的是同一份資料。`,
		problem: `// 不安全寫法：直接拿原始輸入比較，沒先清大小寫/空白 => 檢查可被繞過
#include <string.h>

static int is_admin(const char *user) {
    // "Admin"、"admin "、"ADMIN" 都騙得過這個 == 比較 => CWE-171
    return strcmp(user, "admin") == 0;
}`,
		fixed: `// 安全寫法：先清洗(去掉空白、轉小寫)成單一形式，再拿它做比較
#include <ctype.h>
#include <string.h>

static int is_admin(const char *user) {
    char canon[32] = {0};
    size_t j = 0;
    for (size_t i = 0; user[i] && j < sizeof(canon) - 1; ++i) {
        if (isspace((unsigned char)user[i])) continue; // 清掉任何空白
        canon[j++] = (char)tolower((unsigned char)user[i]); // 統一小寫
    }
    canon[j] = '\\0';
    return strcmp(canon, "admin") == 0;   // 用清洗過的值做比較
}`,
		patch: `@@
- static int is_admin(const char *user) {
-     return strcmp(user, "admin") == 0;
+ static int is_admin(const char *user) {
+     char canon[32] = {0};
+     size_t j = 0;
+     for (size_t i = 0; user[i] && j < sizeof(canon) - 1; ++i) {
+         if (isspace((unsigned char)user[i])) continue;
+         canon[j++] = (char)tolower((unsigned char)user[i]);
+     }
+     canon[j] = '\\0';
+     return strcmp(canon, "admin") == 0;
  }`,
		refs: ['CWE-171', 'OWASP'],
		tags: ['canonicalization', 'comparison', 'cleansing', 'bypass'],
	},
	{
		id: 'CWE-253',
		name: 'Incorrect Check of Function Return Value',
		lang: 'c',
		status: 'Complete',
		what: `檢查了回傳值，但檢查的條件不對——判斷的方式與函式合約不符。若把失敗訊號(例如 -1、負值)
誤當成成功，就會照常往下用沒填好的資料。read 成功但耗盡回 0、失敗回 -1；若用 if(n) 判斷「有資料」，
-1 也會當成有大量資料而拿去當長度。建議以函式文件規定的回傳語義為準，分「失敗、耗盡、有資料」
三路判斷。`,
		problem: `// 不安全寫法:if(n) 判斷「有資料」,但 read 錯誤時回 -1(非 0) 也會成立
#include <unistd.h>

ssize_t drain(int fd) {
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n) emit(buf, (size_t)n);   // n==-1(錯誤)被當巨量資料 => 越界讀
    return n;
}`,
		fixed: `// 安全寫法:明確三路判斷:失敗(<0)、耗盡(==0)、有資料(>0)
#include <unistd.h>

ssize_t drain(int fd) {
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n < 0) return n;            // 錯誤:直接離開
    if (n > 0) emit(buf, (size_t)n); // 只有真的讀到資料才處理
    return n;
}`,
		patch: `@@
     char buf[64];
     ssize_t n = read(fd, buf, sizeof(buf));
-    if (n) emit(buf, (size_t)n);
+    if (n < 0) return n;
+    if (n > 0) emit(buf, (size_t)n);
      return n;`,
		refs: ['CWE-253'],
		tags: ['return-check', 'read', 'error-handling'],
	},
	{
		id: 'CWE-453',
		name: 'Insecure Default Variable Initialization',
		lang: 'c',
		status: 'Complete',
		what: `變數或旗標的預設值對安全不利。初始化的安全原則是「預設封閉、明確開啟」；
若把功能預設成開啟(例如敏感輸出、除錯權限為真)，而真正設定它的初始化路徑又沒被執行，
程式就以不安全預設狀態運作，洩漏敏感資料或放行越權操作。建議讓任何敏感開關的預設值是關閉的。`,
		problem: `// 不安全寫法:旗標預設「開」,初始化若漏執行就整段敏感資料漏出
static int sensitive_dump = 1;          // 預設就允許輸出敏感資訊

void init(void) { /* ..沒執行或漏蓋掉 sensitive_dump.. */ }

void maybe_dump(void) {
    if (sensitive_dump) dump_all();     // 用上不安全預設 => 洩漏
}`,
		fixed: `// 安全寫法:預設「關」,唯有初始化顯式開啟才允許輸出
static int sensitive_dump = 0;          // 預設封閉

void init(void) {
    if (authorized) sensitive_dump = 1; // 明確且受控下才開啟
}

void maybe_dump(void) {
    if (sensitive_dump) dump_all();
}`,
		patch: `@@
-    static int sensitive_dump = 1;
+    static int sensitive_dump = 0;
      void maybe_dump(void) {
          if (sensitive_dump) dump_all();`,
		refs: ['CWE-453'],
		tags: ['insecure-default', 'initialization', 'default'],
	},
	{
		id: 'CWE-455',
		name: 'Non-exit on Failed Initialization',
		lang: 'c',
		status: 'Complete',
		what: `初始化失敗後沒有離開(return/exit)，仍繼續用「只初始化到一半」的狀態。例如全域緩衝配置
失敗回傳錯誤，呼叫端卻忽略該回傳，繼續對可能還未預備好的全域指標寫入，演成空指標解參考或未初始化
使用。原則：初始化失敗的分支必須立即中斷，不要往下使用尚未完成的資源。`,
		problem: `// 不安全寫法:init 回 -1(失敗)卻不 return,仍對可能為 NULL 的全域快取寫入
#include <stdlib.h>
#include <string.h>

static char *g_cache;
int init_cache(void) {
    g_cache = (char *)malloc(1024);
    return g_cache ? 0 : -1;
}
void use_cache(const char *s) {
    if (init_cache() != 0) { /* 漏寫 return,繼續往下 */ }
    strcpy(g_cache, s);          // g_cache==NULL => 空指標解參考
}`,
		fixed: `// 安全寫法:失敗即離開,不碰尚未初始化的 g_cache
#include <stdlib.h>
#include <string.h>

static char *g_cache;
int init_cache(void) {
    g_cache = (char *)malloc(1024);
    return g_cache ? 0 : -1;
}
void use_cache(const char *s) {
    if (init_cache() != 0) return;   // 失敗分支立即中斷
    strcpy(g_cache, s);
}`,
		patch: `@@
  void use_cache(const char *s) {
-    if (init_cache() != 0) { /* 漏寫 return,繼續往下 */ }
+    if (init_cache() != 0) return;
      strcpy(g_cache, s);
  }`,
		refs: ['CWE-455'],
		tags: ['failed-init', 'initialization', 'null'],
	},
	{
		id: 'CWE-456',
		name: 'Missing Initialization of a Variable',
		lang: 'c',
		status: 'Complete',
		what: `變數在第一次讀取之前根本沒有被賦予初始值。區域變數在堆疊上留下的是一段
隨機的殘留資料，若某條路徑沒有先「設定」就直接「使用」，程式讀到的就是這份垃圾值——
可能拿未初始化的累加器去加、拿未初始化的指標去解參考、或用它做分支判斷，導致結果
不可預期、行為未定義。建議做法是宣告的當下就給明確的初值（如 int n = 0），
確保任何路徑第一次使用它時，讀到的都是這個確定的安全值。`,
		problem: `// 不安全寫法：sum 未初始化就直接 +=，第一次讀時拿到的是堆疊殘留的垃圾
int total(const int *a, size_t len) {
    int sum;                          // 未初始化
    for (size_t i = 0; i < len; ++i)
        sum += a[i];                  // 第一次讀 sum 是未定義值 => CWE-456
    return sum;
}`,
		fixed: `// 安全寫法：宣告當下就 sum = 0，保證每次 += 讀到的都是已初始化的值
int total(const int *a, size_t len) {
    int sum = 0;                      // 明確初值 0
    for (size_t i = 0; i < len; ++i)
        sum += a[i];
    return sum;
}`,
		patch: `@@
-     int sum;                          // 未初始化
+     int sum = 0;                      // 明確初值 0
      for (size_t i = 0; i < len; ++i)
          sum += a[i];
      return sum;`,
		refs: ['CWE-456', 'SEI CERT'],
		tags: ['missing-init', 'uninitialized', 'stack'],
	},
	{
		id: 'CWE-459',
		name: 'Incomplete Cleanup',
		lang: 'c',
		status: 'Complete',
		what: `清理不夠完整：釋放或關閉了部分資源，但在每一條錯誤路徑上漏掉了其中一項。例如開了檔案、
又配了緩衝，卻在某個失敗分支直接返回而兩者皆未釋放。建議用單一出口(goto cleanup 或統一函式)、
對「每個已取得的資源」逐一釋放，確保所有路徑都完整清理。`,
		problem: `// 不安全寫法:parse 失敗分支直接 return,準備好的 f 與 buf 都沒還
#include <stdio.h>
#include <stdlib.h>

int proc(const char *name) {
    FILE *f = fopen(name, "r");
    char *buf = (char *)malloc(64);
    if (parse(f, buf) != 0) return -1;   // 漏掉 fclose/free => incomplete cleanup
    fclose(f);
    free(buf);
    return 0;
}`,
		fixed: `// 安全寫法:統一收尾,任何路徑都把 f 與 buf 一起釋放
#include <stdio.h>
#include <stdlib.h>

int proc(const char *name) {
    FILE *f = fopen(name, "r");
    char *buf = (char *)malloc(64);
    int rc = (parse(f, buf) == 0) ? 0 : -1;
cleanup:
    if (f) fclose(f);
    free(buf);
    return rc;
}`,
		patch: `@@
  int proc(const char *name) {
      FILE *f = fopen(name, "r");
      char *buf = (char *)malloc(64);
-    if (parse(f, buf) != 0) return -1;
-    fclose(f);
-    free(buf);
-    return 0;
+    int rc = (parse(f, buf) == 0) ? 0 : -1;
+cleanup:
+    if (f) fclose(f);
+    free(buf);
+    return rc;
  }`,
		refs: ['CWE-459'],
		tags: ['incomplete-cleanup', 'resource'],
	},
	{
		id: 'CWE-465',
		name: 'Pointer Issues',
		lang: 'c',
		status: 'Complete',
		what: `指標問題的上位分類，泛指種種指標誤用——型別混淆、懸空指標、釋放後使用、未初始化指標、
空指標解參考等(CWE-415/416/476/824/843…)。共同特徵是拿狀態不符的指標去解參考，結果常是崩潰、
記憶體損毀或資訊洩漏。統一的防線：指標宣告即初始化(或 NULL)、解參考前檢查 NULL，並嚴格管理每個
指標的擁有權與生命週期。`,
		problem: `// 不安全寫法:指標既可能為 NULL 也可能未初始化,卻直接解參考
void use(int *p) {
    *p = 1;      // p 可能為 NULL 或未指向有效物件 => 崩潰
}`,
		fixed: `// 安全寫法:解參考前確認指標非空且已指向有效物件
void use(int *p) {
    if (p != NULL) *p = 1;   // 確認有效才解參考
}`,
		patch: `@@
  void use(int *p) {
-    *p = 1;
+    if (p != NULL) *p = 1;
  }`,
		refs: ['CWE-465'],
		tags: ['pointer-issue', 'dangling', 'null'],
	},
	{
		id: 'CWE-562',
		name: 'Return of Stack Variable Address',
		lang: 'c',
		status: 'Complete',
		what: `把區域(堆疊)變數的位址傳回給呼叫端。函式一結束，它的棧框就被回收，呼叫端再拿那個位址
去存取或修改，拿到的是不穩定、隨時會被覆寫的記憶體(懸空指標)。建議改為配置於堆積並交還所有權，
或直接以傳值回傳內容。`,
		problem: `// 不安全寫法:回傳 &x,而 x 是區域變數,函式返回後棧框已失效
int *make(int v) {
    int x = v;
    return &x;              // return of stack variable address => dangling
}`,
		fixed: `// 安全寫法:改用堆積配置、交還所有者責任(caller 用畢 free),或改成傳值
#include <stdlib.h>

int *make(int v) {
    int *p = (int *)malloc(sizeof(int));   // 生命週期延伸到函式之外
    if (p) *p = v;
    return p;
}`,
		patch: `@@
  int *make(int v) {
-    int x = v;
-    return &x;
+    int *p = (int *)malloc(sizeof(int));
+    if (p) *p = v;
+    return p;
  }`,
		refs: ['CWE-562'],
		tags: ['return-stack-address', 'dangling', 'lifetime'],
	},
	{
		id: 'CWE-587',
		name: 'Assignment of a Fixed Address to a Pointer',
		lang: 'c',
		status: 'Complete',
		what: `把硬編碼的固定位址直接指派給指標，例如 (char*)0x1000 或假的系統位址。真實程式的可用位址
由配置器(OS/執行期)決定，固定位址大多不在合法映射區，一解參考就崩潰或寫亂記憶體。
建議由 malloc/mmap 這類配置器取得有效位址，不要自己拼位址。`,
		problem: `// 不安全寫法:把直譯出來的固定位址當成有效緩衝直接用
#include <stdlib.h>

void poke(void) {
    char *p = (char *)0x10000;   // 猜某區段就在這
    *p = 'A';                     // 一解參考即崩潰或毀損
}`,
		fixed: `// 安全寫法:向配置器要有效位址,並檢查成功後才使用
#include <stdlib.h>

void poke(void) {
    char *p = (char *)malloc(4096);
    if (p != NULL) *p = 'A';     // 位址由系統配發,已受檢驗且已映射
    free(p);
}`,
		patch: `@@
  void poke(void) {
-    char *p = (char *)0x10000;
-    *p = 'A';
+    char *p = (char *)malloc(4096);
+    if (p != NULL) *p = 'A';
+    free(p);
  }`,
		refs: ['CWE-587'],
		tags: ['fixed-address', 'pointer', 'hardcoded'],
	},
	{
		id: 'CWE-588',
		name: 'Attempt to Access Child of a Non-structure Pointer',
		lang: 'c',
		status: 'Complete',
		what: `把不是結構體的指標強制轉型成結構指標，再用 -> 去讀它的成員(child)。最常見是硬把
int 或整數位址轉成 struct*，或把太小／型別不合的緩衝轉成 struct* 後直接解參考；
程式假設「這個位址後面就接著一整套的 struct 欄位」，但實際配置根本不是那麼大或不是
那個型別，於是讀到有效範圍外的資料或垃圾，觸發越界讀取或未定義行為。
建議做法是用正確型別的指標、或改為 memcpy 到完整的 struct，並先確認來源大小至少
等於 struct 的 sizeof。`,
		problem: `// 不安全寫法：把 int 位址硬轉成 struct* 再解參考成員 => 型別違規
#include <stdio.h>

struct Point { int x; int y; };

void print_x(int v) {
    struct Point *fake = (struct Point *)&v; // v 只有 4 位元組，卻當成 struct
    printf("%d\\n", fake->x);                 // 讀 v 本身還沒事，但
    printf("%d\\n", fake->y);                 // fake->y 已越過 v 的有效範圍
}`,
		fixed: `// 安全寫法：改用型別正確的 int 本體，不再偽裝成 struct
#include <stdio.h>

void print_x(int v) {
    printf("%d\\n", v);              // 直接讀正確型別的值
}`,
		patch: `@@
- struct Point { int x; int y; };
-
- void print_x(int v) {
-     struct Point *fake = (struct Point *)&v;
-     printf("%d\\n", fake->x);
-     printf("%d\\n", fake->y);
+ void print_x(int v) {
+     printf("%d\\n", v);              // 直接讀正確型別的值
  }`,
		refs: ['CWE-588', 'SEI CERT'],
		tags: ['struct-cast', 'type-punning', 'non-structure-pointer'],
	},
	{
		id: 'CWE-665',
		name: 'Improper Initialization',
		lang: 'c',
		status: 'Complete',
		what: `物件或結構沒有被「完整」初始化就使用。不同於變數漏初始(456)，這裡是初始化不完全的狀態——
例如結構只填了幾個欄位，其餘是殘留資料或 0，之後讀到未填欄位就是未定義或錯誤行為。
建議一律「全欄位明確設定」或先 memset 再個別填，確保結構任何欄位都有定義。`,
		problem: `// 不安全寫法:cfg 只設 size,name 欄位未初始化就被帶走使用
struct cfg { int size; char *name; };

struct cfg make(void) {
    struct cfg c;         // 未初始化
    c.size = 1024;       // 只填一個欄位
    return c;            // name 是垃圾值 => improper initialization
}`,
		fixed: `// 安全寫法:先整體歸零({0})再依需要填值,所有欄位都有定義
struct cfg { int size; char *name; };

struct cfg make(void) {
    struct cfg c = {0};       // 所有欄位先有確定的初值
    c.size = 1024;            // 再設定要用的欄位
    return c;
}`,
		patch: `@@
  struct cfg make(void) {
-    struct cfg c;
+    struct cfg c = {0};       // 所有欄位先有確定的初值
      c.size = 1024;
      return c;
  }`,
		refs: ['CWE-665'],
		tags: ['improper-init', 'initialization', 'struct'],
	},
	{
		id: 'CWE-672',
		name: 'Operation on a Resource after Release or Expiration',
		lang: 'c',
		status: 'Complete',
		what: `資源在釋放或到期之後還被操作。與 use-after-free 同源，但針對廣義的資源(檔案、socket、
互斥鎖)，尤其釋放後其 id 可能被系統重用，繼續對已到期的資源操作是去動到不相干的新資源。建議用封裝
持有資源的容器，並在校驗其有效性(state)之後才操作，不要各自握一個號碼。`,
		problem: `// 不安全寫法:fd 在一個分支中 close,另一個分支又對它 read => 資源已到期仍操作
#include <unistd.h>

int step(int fd, int close_it) {
    if (close_it) close(fd);      // fd 已釋放
    char buf[16];
    return (int)read(fd, buf, sizeof(buf));   // 到期後仍讀,可能誤用重用的號碼
}`,
		fixed: `// 安全寫法:釋放時把狀態標成無效,操作前先檢查資源仍有效
#include <unistd.h>

int step(int fd, int *active, int close_it) {
    if (close_it) { close(fd); *active = 0; }
    if (!*active) return -1;      // resource 已到期 => 拒絕操作
    char buf[16];
    return (int)read(fd, buf, sizeof(buf));
}`,
		patch: `@@
-  int step(int fd, int close_it) {
-      if (close_it) close(fd);
+  int step(int fd, int *active, int close_it) {
+      if (close_it) { close(fd); *active = 0; }
+      if (!*active) return -1;
        char buf[16];
        return (int)read(fd, buf, sizeof(buf));
    }`,
		refs: ['CWE-672'],
		tags: ['expired-resource', 'lifetime', 'use-after'],
	},
	{
		id: 'CWE-690',
		name: 'Unchecked Return Value to NULL Pointer Dereference',
		lang: 'c',
		status: 'Complete',
		what: `malloc、strdup、fopen 這一類「可能失敗」的函式，失敗時會回傳 NULL，程式卻沒有
先檢查就立刻解參考它。例如 strdup 失敗回傳 NULL 後直接丟給 strlen、或 fopen 失敗回傳 NULL
後直接對它做 fread／fprintf，便會在該行就空指標解參考而崩潰(segfault)。
建議做法是把回傳值先存進一個暫存變數，先判斷 p != NULL（或 == NULL 就先處理錯誤路徑），
只有確認有效才接著解參考，把失敗路徑在撞上空指標前就攔截掉。`,
		problem: `// 不安全寫法：strdup 失敗回 NULL 沒檢查，立刻解參考算長度 => 崩潰
#include <stdio.h>
#include <string.h>

void report(const char *msg) {
    char *copy = strdup(msg);         // 記憶體不足時 copy == NULL
    printf("len=%zu\\n", strlen(copy)); // 直接對可能的 NULL 解參考 => CWE-690
    free(copy);
}`,
		fixed: `// 安全寫法：先檢查 NULL，失敗就先處理再往下走
#include <stdio.h>
#include <string.h>

void report(const char *msg) {
    char *copy = strdup(msg);
    if (copy == NULL) {               // 失敗路徑先在這裡攔截
        printf("no memory\\n");
        return;
    }
    printf("len=%zu\\n", strlen(copy)); // 此時 copy 保證有效
    free(copy);
}`,
		patch: `@@
  void report(const char *msg) {
      char *copy = strdup(msg);
-     printf("len=%zu\\n", strlen(copy));
+     if (copy == NULL) {
+         printf("no memory\\n");
+         return;
+     }
+     printf("len=%zu\\n", strlen(copy));
      free(copy);
  }`,
		refs: ['CWE-690', 'CWE-252', 'SEI CERT'],
		tags: ['unchecked-return', 'null-dereference', 'malloc', 'strdup'],
	},
	{
		id: 'CWE-704',
		name: 'Incorrect Type Conversion or Cast',
		lang: 'c',
		status: 'Complete',
		what: `型別轉換(cast)不當，把一段記憶體以「不是它真正的型別」來解讀。例如把 int* 硬轉成大的結構
指標、或把一個型別的物件 reinterpret 成另一種，之後照錯誤型別讀寫就是型別混淆與越界。建議使用正確
型別；需要跨型別傳輸時，用 memcpy 進入對齊的正確型別物件，避免強制轉型後直接解參考。`,
		problem: `// 不安全寫法:把 int* 硬轉成 struct head* 再解參考成員 => 型別不齊
struct head { int tag; long next; };

int get_tag(int v) {
    struct head *h = (struct head *)&v;   // v 只有 4 位元組,head 較大
    return h->tag;                         // 後續欄位越界 => incorrect cast
}`,
		fixed: `// 安全寫法:不要偽裝型別,直接用真正的型別取值
struct head { int tag; long next; };

int get_tag(int v) {
    return v;            // 直接以 int 讀取,不做型別混淆
}`,
		patch: `@@
  int get_tag(int v) {
-    struct head *h = (struct head *)&v;
-    return h->tag;
+    return v;
  }`,
		refs: ['CWE-704'],
		tags: ['type-conversion', 'cast', 'type-confusion'],
	},
	{
		id: 'CWE-733',
		name: 'Compiler Optimization Removal or Modification of Security-critical Code',
		lang: 'c',
		status: 'Complete',
		what: `編譯器最佳化把安全關鍵的檢查刪掉或改掉。若程式依賴「未定義行為」(如帶號溢位)，最佳化器
就有權假設它不會發生，而把整段檢查視為恆真或恆假移除。建議用無號運算(無號溢位有定義)、或明確
檢查極限值，讓最佳化不會把檢查整段刪掉。`,
		problem: `// 不安全寫法:依賴帶號溢位的判定當邊界檢查,最佳化視為 UB 而可能把檢查移除
#include <limits.h>

int safe_add(int *out, int a, int b) {
    int r = a + b;                   // 溢位 => UB
    if (r < a) return 0;            // 若 a,b 皆正,溢位分支被當「恆不成立」而刪除
    *out = r;
    return 1;
}`,
		fixed: `// 安全寫法:用不會溢位的型別與大小,或先做溢位前檢查
#include <limits.h>

int safe_add(int *out, int a, int b) {
    if (b > 0 && a > INT_MAX - b) return 0;    // 正溢位前檢查
    if (b < 0 && a < INT_MIN - b) return 0;    // 負溢位前檢查
    *out = a + b;                                // 已證明不溢位
    return 1;
}`,
		patch: `@@
  int safe_add(int *out, int a, int b) {
-    int r = a + b;
-    if (r < a) return 0;
-    *out = r;
+    if (b > 0 && a > INT_MAX - b) return 0;
+    if (b < 0 && a < INT_MIN - b) return 0;
+    *out = a + b;
      return 1;
  }`,
		refs: ['CWE-733'],
		tags: ['compiler-optimization', 'ub', 'check-removed'],
	},
	{
		id: 'CWE-758',
		name: 'Reliance on Undefined, Unspecified, or Implementation-Defined Behavior',
		lang: 'c',
		status: 'Complete',
		what: `程式依賴標準不保證的行為，像是「同一運算式未定序地讀寫同一變數」、左移寬度位元數、
或二元運算的取值順序。結果隨編譯器與最佳化而異，換個平台或版本的輸出就不同。建議把運算拆成
明確定序的陳述，或用有定義的無號行為來寫，不要仰賴副作用次序。`,
		problem: `// 不安全寫法:同一陳式中讀 i 又 ++i,取值順序未定義
int f(int i) {
    return i + i++;       // i 被讀又被改,順序未定 => 行為不定
}`,
		fixed: `// 安全寫法:拆開成明確定序的兩步
int f(int i) {
    int a = i;      // 先取原值
    i++;            // 再遞增
    return a + i;
}`,
		patch: `@@
  int f(int i) {
-    return i + i++;
+    int a = i;
+    i++;
+    return a + i;
  }`,
		refs: ['CWE-758'],
		tags: ['undefined-behavior', 'unspecified', 'order'],
	},
	{
		id: 'CWE-771',
		name: 'Missing Reference to Active Allocated Resource',
		lang: 'c',
		status: 'Complete',
		what: `已配置且仍使用中的資源，卻沒被任何可追蹤的 reference 握住。若把唯一指向它的指標覆蓋掉，
該資源既無法釋放也無法審查，既洩漏又失去對記憶體的控制。建議讓每個動態資源都有固定的 tracking slot，
替換或重複用同一變數時，先把舊引用釋放或接管到其它 slot。`,
		problem: `// 不安全寫法:一直 malloc 卻只用同一個指標,上一塊的引用直接丟棄
#include <stdlib.h>

int add_item(void) {
    char *p = (char *)malloc(64);      // 配了一塊
    /* ... 使用 p ... */
    p = (char *)malloc(32);            // 上一塊從此無任何引用 => missing reference
    return 0;
}`,
		fixed: `// 安全寫法:每塊都放進固定 slot,可逐一追蹤與釋放
#include <stdlib.h>

static char *slots[4];
int add_item(int i) {
    if (i < 0 || i >= 4) return -1;
    if (slots[i] != NULL) free(slots[i]);    // 先釋放舊引用再給新的
    slots[i] = (char *)malloc(64);
    return slots[i] ? 0 : -1;
}`,
		patch: `@@
  int add_item(void) {
-    char *p = (char *)malloc(64);
-    p = (char *)malloc(32);
-    return 0;
+    if (slots[i] != NULL) free(slots[i]);
+    slots[i] = (char *)malloc(64);
+    return slots[i] ? 0 : -1;
  }`,
		refs: ['CWE-771'],
		tags: ['missing-reference', 'resource', 'tracking'],
	},
	{
		id: 'CWE-772',
		name: 'Missing Release of Resource after Effective Lifetime',
		lang: 'c',
		status: 'Complete',
		what: `資源在有效生命期過後沒被釋放。廣義資源(檔案、socket、鎖、記憶體)取用後不需再用時應該歸還；
遺漏釋放長期累積會耗盡可用資源。與 401(memory leak)相對，772 泛指所有資源。建議以統一清理路徑在
生命期結束點釋放資源，並確保釋放在每一條出口都被執行。`,
		problem: `// 不安全寫法:fopen 開了檔案,可用到的例外分支或正常結束都沒 fclose
#include <stdio.h>

int copy_file(const char *src, const char *dst) {
    FILE *in = fopen(src, "r");
    FILE *out = fopen(dst, "w");
    if (!in || !out) return -1;       // 已開的沒關 => 洩漏
    /* 複製內容 ... */
    return 0;                         // in/out 從未 fclose => resource leak
}`,
		fixed: `// 安全寫法:每個資源在配置失敗與正常結束的出口都釋放
#include <stdio.h>

int copy_file(const char *src, const char *dst) {
    FILE *in = fopen(src, "r");
    FILE *out = fopen(dst, "w");
    if (!in || !out) {
        if (in) fclose(in);
        if (out) fclose(out);
        return -1;
    }
    /* 複製內容 ... */
    fclose(in);                        // 正常結束也釋放
    fclose(out);
    return 0;
}`,
		patch: `@@
      FILE *in = fopen(src, "r");
      FILE *out = fopen(dst, "w");
-    if (!in || !out) return -1;
+    if (!in || !out) {
+        if (in) fclose(in);
+        if (out) fclose(out);
+        return -1;
+    }
      /* ... */
-    return 0;
+    fclose(in);
+    fclose(out);
+    return 0;`,
		refs: ['CWE-772'],
		tags: ['resource-leak', 'close', 'release'],
	},
	{
		id: 'CWE-775',
		name: 'Missing Release of File Descriptor or Handle after Effective Lifetime',
		lang: 'c',
		status: 'Complete',
		what: `檔案描述符(或 handle)在不再需要後沒有關閉。每開一個 fd 就佔一份系統列表配額，長期打開
不關會把 fd 配額用光，之後 open/socket 全部失敗。與 772 相比更聚焦在「fd/handle」。建議每次 open
後確保所有出口都 close(fd)，並把 fd >= 0 視為取得成功的必要檢查。`,
		problem: `// 不安全寫法:open 回傳的 fd 用完沒有 close
#include <fcntl.h>
#include <unistd.h>

int read_size(void) {
    int fd = open("/dev/data", O_RDONLY);   // 若不檢查,可能 fd<0 也照用
    char buf[16];
    ssize_t n = read(fd, buf, sizeof(buf));
    return (int)n;                           // 每呼叫一次洩漏一個 fd
}`,
		fixed: `// 安全寫法:先檢查 fd 有效,且每一條路徑都 close
#include <fcntl.h>
#include <unistd.h>

int read_size(void) {
    int fd = open("/dev/data", O_RDONLY);
    if (fd < 0) return -1;                 // 開啟失敗先處理
    char buf[16];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);                             // 用畢立即歸還 fd
    return (int)n;
}`,
		patch: `@@
      int fd = open("/dev/data", O_RDONLY);
+    if (fd < 0) return -1;
      char buf[16];
      ssize_t n = read(fd, buf, sizeof(buf));
+    close(fd);
      return (int)n;`,
		refs: ['CWE-775'],
		tags: ['fd-leak', 'close', 'resource'],
	},
	{
		id: 'CWE-822',
		name: 'Untrusted Pointer Dereference',
		lang: 'c',
		status: 'Complete',
		what: `解參考一個未受信的指標。指標的值(位址)直接來自外部輸入或可被攻擊者控制，解參考前完全沒有
驗證，等於讓攻擊者指定「讀哪、寫哪」。建議不接受外部提供的原始指標，改以「索引 + 已校驗的自行陣列」
來選址，讓解參考的範圍固定在自有資料結構內。`,
		problem: `// 不安全寫法:封包直接拿來當指標解參考,跳過一切驗證
#include <string.h>

struct node { int tag; int next; };

void push(const unsigned char *pkt) {
    struct node *t;
    memcpy(&t, pkt, sizeof(t));   // 外部提供位址 => untrusted pointer
    t->tag = 1;                    // deref 任意位址 => crash / 任意寫
}`,
		fixed: `// 安全寫法:只在校驗範圍內,選自有陣列的指標來用
#include <string.h>

struct node { int tag; int next; };
struct node pool[128];

void push(const unsigned char *pkt) {
    int i;
    memcpy(&i, pkt, sizeof(i));
    if (i < 0 || i >= 128) return;      // index 受控 => 不會選到陣列外
    pool[i].tag = 1;                     // deref 只在自有 pool 內
}`,
		patch: `@@
  void push(const unsigned char *pkt) {
-    struct node *t;
-    memcpy(&t, pkt, sizeof(t));
-    t->tag = 1;
+    int i;
+    if (i < 0 || i >= 128) return;
+    pool[i].tag = 1;
  }`,
		refs: ['CWE-822'],
		tags: ['untrusted-pointer', 'dereference', 'arbitrary'],
	},
	{
		id: 'CWE-824',
		name: 'Access of Uninitialized Pointer',
		lang: 'c',
		status: 'Complete',
		what: `解參考一個從未初始化、沒設過值的指標。區域指標若在指派前就被當來源或目的使用，它拿到的是
堆疊殘留的位址，接著讀寫就是訪問一個垃圾位址。建議宣告即設初值(NULL 或指向真實物件)，並在解參考前
檢查它不為 NULL。`,
		problem: `// 不安全寫法:src 宣告後沒指派,直接用來當複製來源
#include <string.h>

void copy_to(char *dst, size_t n) {
    char *src;                    // 未初始化
    memcpy(dst, src, n);         // 從垃圾位址複製 => 崩潰/洩漏
}`,
		fixed: `// 安全寫法:宣告時就把來源指派好,解參考前皆為已知位址
#include <string.h>

void copy_to(char *dst, const char *real, size_t n) {
    char *src = real;             // 明確指向有效來源
    memcpy(dst, src, n);
}`,
		patch: `@@
-  void copy_to(char *dst, size_t n) {
-      char *src;
+  void copy_to(char *dst, const char *real, size_t n) {
+      char *src = real;
        memcpy(dst, src, n);
    }`,
		refs: ['CWE-824'],
		tags: ['uninitialized-pointer', 'dereference'],
	},
	{
		id: 'CWE-843',
		name: "Access of Resource Using Incompatible Type ('Type Confusion')",
		lang: 'c',
		status: 'Complete',
		what: `型別混淆：把同一份記憶體資源用不相容的型別去解讀或存取。常以 cast 或 union 把小型緩衝當成
大結構、或把整數當指標。程式以此型別取欄位時，取的可能是尚未定義範圍的資料，造成越界讀或誤判。
建議複製到「大小正確的型別物件」再存取，並先核對來源大小至少等於目標 struct 的 sizeof。`,
		problem: `// 不安全寫法:直接把小緩衝當成更大的 struct 解參考
#include <string.h>

struct meta { unsigned long id; unsigned long len; };

int parse(const unsigned char *data) {
    struct meta *m = (struct meta *)data;   // data 可能比 meta 小 => 越界讀
    return (int)m->len;                     // type confusion(不相容型別存取)
}`,
		fixed: `// 安全寫法:先確認來源夠大,再 memcpy 進正確型別物件
#include <string.h>

struct meta { unsigned long id; unsigned long len; };

int parse(const unsigned char *data, size_t sz) {
    if (sz < sizeof(struct meta)) return -1;   // 來源太小先拒絕
    struct meta m;
    memcpy(&m, data, sizeof(m));              // 以正確型別正視資料
    return (int)m.len;
}`,
		patch: `@@
-  int parse(const unsigned char *data) {
-      struct meta *m = (struct meta *)data;
-      return (int)m->len;
+  int parse(const unsigned char *data, size_t sz) {
+      if (sz < sizeof(struct meta)) return -1;
+      struct meta m;
+      memcpy(&m, data, sizeof(m));
+      return (int)m.len;
    }`,
		refs: ['CWE-843'],
		tags: ['type-confusion', 'incompatible-type', 'cast'],
	},
	{
		id: 'CWE-908',
		name: 'Use of Uninitialized Resource',
		lang: 'c',
		status: 'Complete',
		what: `使用未初始化的資源物件。與純量變數(456)不同，這裡是用到未初始化的結構、socket 位址、緩衝等。
例如把未 memset 的 sockaddr 丟給 connect，棧框殘留決定了連到哪、或讀取未填的陣列內容。
建議在把資源交給 API 前，先用 memset 或 {0} 把整個結構初始化。`,
		problem: `// 不安全寫法:sockaddr_in 未初始化就交給 connect
#include <sys/socket.h>
#include <netinet/in.h>

int go(int s) {
    struct sockaddr_in sa;                       // 未初始化
    return connect(s, (struct sockaddr *)&sa, sizeof(sa));  // 讀到殘留值
}`,
		fixed: `// 安全寫法:使用前把結構先歸零、再逐欄位設定
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

int go(int s) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));                // 整個結構有確定初值
    sa.sin_family = AF_INET;
    return connect(s, (struct sockaddr *)&sa, sizeof(sa));
}`,
		patch: `@@
      int go(int s) {
          struct sockaddr_in sa;
+        memset(&sa, 0, sizeof(sa));
+        sa.sin_family = AF_INET;
          return connect(s, (struct sockaddr *)&sa, sizeof(sa));
      }`,
		refs: ['CWE-908'],
		tags: ['uninitialized-resource', 'init'],
	},
	{
		id: 'CWE-909',
		name: 'Missing Initialization of a Resource',
		lang: 'c',
		status: 'Complete',
		what: `資源在入口就完全沒被初始化便開始使用。例如互斥鎖、檔案號、句柄在初始化前就被操作或關閉。
缺少初始化步驟時，資源內部狀態無效，一用就出問題或崩潰。建議在資源「第一次使用」之前完成初始化
(建構或 init 呼叫)，未初始化前不要取用該資源。`,
		problem: `// 不安全寫法:互斥鎖從未 pthread_mutex_init 就被加鎖
#include <pthread.h>

static pthread_mutex_t mtx;      // 全域,但沒 init

void add_to(int *p) {
    pthread_mutex_lock(&mtx);    // 使用未初始化的鎖 => 未定義行為
    *p += 1;
    pthread_mutex_unlock(&mtx);
}`,
		fixed: `// 安全寫法:先初始化資源,之後才操作
#include <pthread.h>

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;   // 初始化完成

void add_to(int *p) {
    pthread_mutex_lock(&mtx);
    *p += 1;
    pthread_mutex_unlock(&mtx);
}`,
		patch: `@@
-    static pthread_mutex_t mtx;
+    static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
     void add_to(int *p) {
         pthread_mutex_lock(&mtx);`,
		refs: ['CWE-909'],
		tags: ['missing-init', 'resource', 'mutex'],
	},
	{
		id: 'CWE-910',
		name: 'Use of Expired File Descriptor',
		lang: 'c',
		status: 'Complete',
		what: `使用已到期的檔案描述符。fd 在 close 後其號碼已失效，系統很可能把它重新配發給後來新開的
檔案或 socket；若程式還拿舊 fd 去 read/write，就誤操作到不相關的新資源。建議在 fd 到期(close)後
把它設為 -1(或其它無效記號)，操作前一律檢查 fd 是否仍有效。`,
		problem: `// 不安全寫法:close(logfd) 之後又用 logfd 寫入 => 使用已到期的 fd
#include <unistd.h>

int log_step(int logfd) {
    if (logfd >= 0) {
        char m[] = "go\\n";
        write(logfd, m, sizeof(m));
        close(logfd);                      // fd 到期
    }
    char m2[] = "done\\n";
    write(logfd, m2, sizeof(m2));         // 用已過期 fd => 可能引到新資源
    return 0;
}`,
		fixed: `// 安全寫法:close 後立刻把 fd 標成無效(-1),使用處檢查後才下手
#include <unistd.h>

int log_step(int *logfd) {
    int fd = *logfd;
    if (fd >= 0) {
        char m[] = "go\\n";
        write(fd, m, sizeof(m));
        close(fd);
        *logfd = -1;                      // 到期後無效化
    }
    /* 之後都要先檢查 *logfd 是否有效 */
    return 0;
}`,
		patch: `@@
-  int log_step(int logfd) {
-      if (logfd >= 0) {
-          char m[] = "go\\n";
-          write(logfd, m, sizeof(m));
-          close(logfd);
-      }
-      write(logfd, m2, sizeof(m2));
+  int log_step(int *logfd) {
+      int fd = *logfd;
+      if (fd >= 0) {
+          char m[] = "go\\n";
+          write(fd, m, sizeof(m));
+          close(fd);
+          *logfd = -1;
+      }
        return 0;
    }`,
		refs: ['CWE-910'],
		tags: ['expired-fd', 'file-descriptor', 'lifetime'],
	},
];
