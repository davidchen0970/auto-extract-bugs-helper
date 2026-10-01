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
		what: `回傳值檢查方式錯誤。本質是程式對函式的回傳值做了檢查，但檢查的條件不對，判斷方式與函式合約不符，因而偵測
不到錯誤或例外狀態。重要的函式通常會回傳表示成功與否的值，提醒程式是否要處理因它而起的錯誤。若把失敗訊號（例如 -1、
負值）誤當成功，就會照常往下用尚未填好的資料：read 成功但耗盡回 0、失敗回 -1，用 if(n) 判斷「有資料」會把 -1 也
當成大量資料拿去當長度，引致越界讀。建議以函式文件規定的回傳語義為準，明確分成「失敗、耗盡、有資料」三路判斷，逐一
處理後才繼續。`,
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
		what: `預設值對安全不利的變數初始化。本質是程式預設把自己範疇的內部變數的初始值設成「可以做到、卻較不安全」的
值。初始化的安全原則是「預設封閉、明確開啟」：若某個功能／權限預設為開啟（例如敏感輸出、除錯權限為真），而真正設定
它的初始化路徑又沒被執行，程式便以不安全預設狀態運作，洩漏敏感資料或放行越權操作。建議讓任何敏感開關的預設值是關閉的、
是較不具權限的值，唯有在受控且經過檢驗的初始化流程中才把它明確開啟；並在初始化處記下「預設是否曾被安全設定」，防止程式
靜默地沿用這個較不安全的初值。`,
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
		what: `初始化失敗後沒有中止。本質是初始化發生與安全相關的錯誤時（例如設定檔格式錯誤、硬體安全模組 HSM 無法啟動），
程式沒有退出或調整其運作，仍繼續以「只初始化到一半」的狀態執行，結果以比管理者預期更不安全的方式運行。例如全域緩衝
配置失敗回傳錯誤，呼叫端卻忽略該回傳，繼續對可能還沒預備好的全域指標寫入，演成空指標解參考或未初始化使用。原則：
初始化失敗的分支必須立即 return／exit，不要繼續使用尚未完成的資源，並對失敗的安全機制採取明確的降級或中止策略。`,
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
		what: `關鍵變數缺失初始化。本質是程式沒有初始化關鍵變數，使執行環境用到非預期的值。C 語言的區域變數預設不
初始化，堆疊上留下的是呼叫前殘留的隨機垃圾資料；若某條路徑先「使用」後「設定」，程式讀到的就是這份垃圾值，可能拿它當
累加器、指標去解參考或做分支判斷，導致結果不可預期、行為未定義，甚至洩漏堆疊殘留的敏感內容。若該變數是決定安全性的
值（如是否已認證的旗標），其未初始化結果便有安全含義。建議宣告當下就給明確的初值（如 int n = 0），確保任何路徑第一次
使用它時，讀到的都是這個確定且安全的值。`,
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
		what: `清理不夠完整。本質是程式沒有妥善「清尾」並移除用過的暫存或輔助資源。釋放或關閉了部分資源，但在每一條
錯誤路徑上漏掉其中一項：例如開了檔案又配了緩衝，卻在某個失敗分支直接返回而兩者皆未釋放，或在例外途中遺留了暫存檔。
遺漏的資源可能被鎖住、外洩敏感資料或耗盡配額。建議用單一出口（goto cleanup 或統一清理函式）、對「每個已取得的資源」
逐一釋放，並確保所有路徑——含每一條錯誤返回——都執行同一套完整的清理；清理也應涵蓋暫時建立、會遺留在盤上的檔案與連結
等副作用，而不只釋放記憶體。`,
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
		what: `把區域（堆疊）變數的位址傳回給呼叫端。本質是一個函式回傳了它內部區域變數的位址。區域變數配置在堆疊上，
回傳其指標就是回傳一個堆疊位址；後續的函式呼叫很可能重用同一堆疊位址、覆寫指標所指的內容，而函式返回後其棧框已失效，
該位址不再對應原變數。最樂觀是指標的值非預期地改變，多數情形下再次解參考這個懸空位址會造成程式崩潰，或讀到已被覆寫、
需要特別防範的資料。建議修法是改為把資料配置於堆積並交還所有權（caller 用畢 free），或以傳值方式直接回傳內容，不要
回傳自動儲存區物件的位址。`,
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
		what: `把固定位址指派給指標。本質是程式把一個不是 NULL／0 的特定位址直接設給指標，例如 (char*)0x1000 或其它
硬編碼、假造的系統位址。用固定位址不具可攜性，因為該位址在別種環境或平台上多半不是有效位址；真實程式的可用位址是由
配置器（OS／執行期）決定的，硬拼的位址大多不在合法對映區，一解參考就崩潰或寫亂記憶體。建議一律由 malloc／mmap 這類
配置函式取得有效位址，驗證取得成功後再使用（檢查回傳是否非空、是否有效），而不要自己拼湊或猜測位址。`,
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
		what: `初始化不完全。本質是程式沒有初始化、或不正確地初始化一個資源，使它後在被存取、使用時處於非預期狀態。
相較於變數完全沒初始化（456），這裡是初始化到不完備——例如結構只填幾個欄位，其餘是殘留資料或 0，之後讀到未填欄位便是
未定義或錯誤行為。若該資源被期望有特定性質或值（例如決定使用者是否已通過認證的變數），未正確初始化便有安全後果。建議一律
「全欄位明確設定」、或用 {0}／memset 先整體歸零再依需要填寫個別欄位，確保任何欄位在讀取前都有定義。`,
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
		what: `資源到期或釋放後仍被操作。本質是程式對已到期、已釋放或已撤銷的資源仍做使用、存取等操作。與 use-after-free
同源，但針對廣義的資源（檔案、socket、互斥鎖、權杖等）：資源釋放後其 id／代號可能被系統重用，繼續對已到期的資源操作，
實際碰到的是毫不相干的「新」資源。例如 fd 釋放後又被拿來 read／write，可能誤動到系統重新配發給別人的檔案或裝置。
建議用封裝持有資源的容器，釋放時把有效性狀態標成無效，並在每次操作前核對其有效性狀態後才動用，不要各自握著一個號碼
就直接使用。`,
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
		what: `不正確的型別轉換或強制轉型。本質是程式把一個物件、資源或結構轉成另一種型別時沒有做對，最常見是用 cast 把
一段記憶體以「不是它真正的型別」來解讀，例如把 int* 硬轉成大的結構指標、把小型緩衝當成更大的結構、或把整數當指標。
之後照著錯誤型別去讀寫，就是型別混淆與越界：讀到有效範圍外的資料、覆寫不相干的記憶體，或讓程式對物件的屬性做出錯誤
假設。建議使用型別正確的指標；需要跨型別傳輸時，先確認來源大小至少等於目標型別的 sizeof，再用 memcpy 進入對齊的正確
型別物件，而不要強制轉型後直接解參考。`,
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
		what: `編譯器最佳化刪掉或更改安全關鍵碼。本質是開發者把安全關鍵的保護機制寫進程式，但編譯器在最佳化時把該機制
移除或修改，讓保護失效。當程式依賴未定義行為（如帶號溢位）時，最佳化器有權假設它不會發生，把相關的檢查視為恆真或
恆假而整段移除——例如「a + b 之後比較是否溢位」的檢查，在溢位屬未定義行為下會被當成不必要而刪掉。建議以「溢位有
定義」的方式寫（用無號運算），或在運算發生前明確檢查極限值（如 a > INT_MAX - b），讓最佳化器沒有理由把安全檢查
當成恆不成立而刪除。`,
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
		what: `依賴未定義、未指定或實作定義的行為。本質是程式以一種依賴「該實體並不保證成立」的性質來使用 API 函式、
資料結構或其它實體，例如同一運算式對同一變數未定序地先讀後寫、左移所用寬度等於型別位元數、或依憑二元運算的取值
順序。這類行為取決於編譯器與最佳化，輸出隨平台或版本而異；被依賴的性質一旦改變（如移植到別的平台、或發生互動錯誤 /
CWE-435），便衍生結果性弱點：檢查被最佳化推翻、結果不可重現、行為不可預期。建議把運算拆成明確定序的獨立陳述，使用
語言有定義的行為（如無號運算）來寫，不依賴副作用次序。`,
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
		what: `已配置資源缺少保留的引用。本質是程式沒有妥善保持一個已配置資源的引用，使資源永遠無法被回收。若把唯一
指向它的指標覆蓋掉或弄丟，這塊資源既無法釋放也無法審查，既洩漏又失去對它的控制；常見是重複 malloc 卻只用同一個
變數，舊那一塊的引用直接被丟棄。此條不一定適用於自動垃圾回收的語言／框架——那些環境裡「移除全部引用」正是資源可被回收
的訊號；但對手動管理的 C/C++ 而言，遺失引用就是洩漏。建議讓每個動態資源都有固定的追蹤槽位，替換或重複使用同一變數時，
先把舊引用釋放或接管到其它槽位。`,
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
		what: `有效生命期結束後未釋放資源。本質是資源在不再需要、有效生命期結束之後仍沒有被釋放。廣義資源（檔案、socket、
鎖、記憶體）取用後應該歸還，遺漏釋放會長期累積，把可用資源耗盡——檔案數、連線數、記憶體用光，使後續請求失敗或服務
中斷。相對 CWE-401（專指記憶體洩漏），772 泛指所有類型的資源，並把重點放在「生命期已結束」卻未釋放。建議以統一清理
路徑在生命期結束點釋放資源、確保釋放在每一條出口（含錯誤分支）都被執行；在取用資源當下便記錄它必須被歸還，讓釋放與
配置成對、不因早退的分支漏掉。`,
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
		what: `檔案描述符（或 handle）未在生命期結束後關閉。本質是程式不再需要某個檔案描述符或句柄時沒有釋放它（通常指
沒有顯式 close）。每開一個 fd 就佔走一份系統可用的描述符配額，長時間開啟不關會把配額耗盡：攻擊者可藉此消耗掉所有可用
的描述符／句柄，讓其它行程再也拿不到自己的 fd，形成阻斷服務。與 CWE-772 相比更聚焦在「fd／handle」。建議每次 open
都檢查 fd >= 0 代表取得成功，並確保所有出口（含錯誤路徑）都 close(fd)，用完立即歸還。`,
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
		what: `解參考未受信的指標。本質是程式從未受信任的來源取得一個值、把該值轉成指標、並解參考這個指標。指標的值
（位址）直接來自外部輸入或可被攻擊者控制，解參考前完全沒有驗證，等於讓攻擊者指定「讀哪、寫哪」。若用於寫，可修改
關鍵狀態變數、觸發崩潰或執行任意程式碼；若用於讀，可取到敏感資料、崩潰或讓變數得到非預期的值。常見型變包括把外部值
直接當函式呼叫、經由系統呼叫／API 進入內核、或原本單機的程式被移植到網路環境。建議不接受外部提供的原始指標，改以
「索引 + 已校驗的自有陣列」來選址，把解參考範圍固定在自己的資料結構內。`,
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
		what: `解參考未初始化的指標。本質是程式存取或使用一個尚未被初始化的指標。若指標內含未初始化的值，它多半不指向
有效的記憶體位置，程式就會從非預期的記憶體讀寫，造成阻斷服務；若未初始化的指標被當成函式呼叫，便是叫了任意函式。依
記憶體布局、相關管理行為與程式運作而定，攻擊者可能影響包在指標裡的未初始化內容，進而精細地控制要去存取的位址、把弱點
升級成程式碼執行或其它攻擊。建議宣告當下就賦明確的初值（指向真實物件或設成 NULL，指向真實物件通常是首選），並在解參考前
核實指標確已被正確設定。`,
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
		what: `型別混淆。本質是程式用一種型別配置或初始化一個資源（指標、物件、變數），之後卻用與原始型別不相容的型別
存取它。以不相容型別存取時，因為資源沒有預期的屬性，會觸發邏輯錯誤；在 C/C++ 這類不具記憶體安全（memory safety）的
語言，型別混淆常造成越界記憶體存取。成因常是把同一份記憶體以多種方式解讀——用 cast 或 union 把小型緩衝當成大結構、
把整數當指標。建議複製到「大小正確的型別物件」再存取，並先核對來源大小至少等於目標型別的 sizeof，避免以錯誤型別直接
解參考記憶體。`,
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
		what: `使用未初始化的資源。本質是程式使用或存取尚未初始化的資源——結構、socket 位址、緩衝等物件，而非純量的
變數。資源沒被妥善初始化，程式便可能出現非預期行為：崩潰或無效記憶體存取都可能發生，後果依資源類型與使用方式而異。
例如把未 memset 的 sockaddr 丟給 connect，棧框殘留的值決定了連到哪，或讀取尚未填寫的陣列內容。建議在把資源交給
API 之前，先用 memset 或 {0} 把整個物件歸零、再個別填寫欄位，確保任何欄位在使用前都有確定的初值。`,
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
		what: `資源缺失初始化。本質是程式在資源可用之前，沒有初始化一個「關鍵」的資源。許多資源必須先初始化才能被正確
使用；若沒有初始化，它可能含不可預測、已到期、或被設成無效預設值的資料，而當該資源被期望有特定性質或值（例如決定
權限的旗標、硬體句柄）時，便有安全後果。與 CWE-908（資源用了但沒初始化）相比，909 更強調「根本沒做初始化的動作」。
例如互斥鎖在 pthread_mutex_init 之前就被加鎖而有未定義行為。建議在資源「第一次使用」之前完成初始化（建構或 init 呼叫），
未初始化完成前不要取用該資源。`,
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
		what: `使用已到期的檔案描述符。本質是程式在 fd 被 close 之後仍去使用或存取它。某個檔案／裝置的描述符被釋放後，
其號碼可以被系統重用：程式若仍拿舊 fd 去寫，寫的便可能不是原本那個檔案，而是現正重用該號碼的另一個檔案或裝置——不只
失效，還可能誤操作到不相關的新資源、洩漏或損壞別人的資料。建議在 fd 到期（close）後立即把它標成無效（如設為 -1），
並在每次 read／write 之前檢查 fd 仍有效，用明確的生命週期管理確保到期（expire）後不再動用。`,
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
