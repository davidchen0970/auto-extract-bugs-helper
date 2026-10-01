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
];
