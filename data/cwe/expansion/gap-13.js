// CWE chunk — 類別:程式碼品質、文件後設與硬體設計弱點清單
// 涵蓋:可攜性/寫碼壞習慣(1101-1109)、文件不完整(1110-1118)、複雜度(1119-1127)、
//      驗證框架(1173/1174)、已棄用重複(1187)、SoC/開機信任與硬體暫存器(1189-1193、
//      1209、1220、1221)以及弱 IV(1204)。
export default [
	{
		id: 'CWE-1101',
		name: 'Reliance on Runtime Component in Generated Code',
		lang: 'c',
		status: 'Complete',
		what: `依賴「執行時期元件」的自動產生碼。產品使用某種 code generator(IDL、資料模型、序列化框架)
	產生的程式碼,而這份產生碼必須靠特定版本的 runtime 函式庫或公用程式支援才能跑;一旦這份 runtime
	元件缺失、版本不符、或平台不提供,整段產生碼就無法執行。成因是把產生碼當成「一批獨立的靜態原始碼」
	看待,卻沒意識到它其實是 runtime 引擎的一塊重要拼圖,驗證環境只編譯了自己產出的檔,拿上目標機卻組
	不起來。具體後果是部署時崩潰、找不到符號、或行為不一致,往上要追邏輯又因產生器版本不同而難以重現。
	修法是以鎖定的版本把 runtime 與產生碼一起納管、在 build 階段做 ABI/契約檢查、並把所需的最小相容
	版本寫進產生碼的前言。`,
		problem: `// 不安全寫法:產生碼呼叫 runtime 專屬 API,卻不檢查/不固定 runtime 版本
#include "gen_proto.h"
struct Msg m;
#include "gen_runtime.h"   // 產生碼仰賴它,但未鎖版本、也不偵測缺失

void handle(void) {
    gen_init();            // 目標機缺 runtime => 連結/執行直接失敗
    gen_decode(&m, buf, len);
}`,
		fixed: `// 安全寫法:用 ABI/版本查核先驗證 runtime 相容,並鎖定產生器與 runtime 配套版本
#include "gen_runtime.h"
#ifndef GEN_RUNTIME_VERSION_HDR
#error "generated code requires gen runtime 2.x"
#endif

void handle(void) {
    if (gen_abi_check(GEN_ABI_VER) != 0) return;  // 明載所需 ABI,不符即拒
    gen_init();
    gen_decode(&m, buf, len);
}`,
		patch: `@@
  #include "gen_proto.h"
  struct Msg m;
  #include "gen_runtime.h"
+ #ifndef GEN_RUNTIME_VERSION_HDR
+ #error "generated code requires gen runtime 2.x"
+ #endif
  void handle(void) {
+     if (gen_abi_check(GEN_ABI_VER) != 0) return;  // 檢查 runtime 相容
      gen_init();
      gen_decode(&m, buf, len);
  }`,
		refs: ['CWE-1101', 'OWASP'],
		tags: ['generated-code', 'runtime', 'codegen', 'portability'],
	},
	{
		id: 'CWE-1102',
		name: 'Reliance on Machine-Dependent Data Representation',
		lang: 'c',
		status: 'Complete',
		what: `依賴「機器相依」的資料表示法。程式用到的資料型別或結構其實隨硬體與平台而變:直接假設 int
	就是 32 位元、直接假設小端序、用 size_t 給出的寬度硬切 buffer、或把 float 的 IEEE layout 當成可嵌
	的整數位元。成因是不想花心思訂資料協定,直接把「我這個機器記憶體裡的版面」當成「對外格式」。具體
	後果是同樣一份資料在不同機器產生不同結果、跨機器交換的資料被拆錯位元、或依平台寬度算出的緩衝大小
	過小造成溢位。修法是只用有明確定義大小的型別(uint32_t 等)構成對外格式、自訂帶 endian 標記的序列化
	/反序列化,並以 sizeof 而非猜測為準。`,
		problem: `// 不安全寫法:假設 int=32bit 且小端,直接把結構的「原生長相」當成對外送出的位元組流
struct rec { int id; long val; };              // int/long 寬度未定,隨平台而異
unsigned char swap_id(unsigned char raw[4]) {
    return (unsigned char)(raw[0] | (raw[3] << 24)); // 假設小端;大端機上全部錯位
}`,
		fixed: `// 安全寫法:以固定寬度型別 + 明確 endian 轉換構成對外格式,與機器表示脫鉤
#include <stdint.h>
struct rec_wire { uint32_t id; uint64_t val; };   // 固定寬度,不隨平台變
static uint32_t le32(const uint8_t b[4]) {
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}`,
		patch: `@@
- struct rec { int id; long val; };              /* 平台相依寬度 */
- unsigned char swap_id(unsigned char raw[4]) {
-     return (unsigned char)(raw[0] | (raw[3] << 24)); /* 假設小端 */
- }
+ #include <stdint.h>
+ struct rec_wire { uint32_t id; uint64_t val; }; /* 固定寬度 */
+ static uint32_t le32(const uint8_t b[4]) {
+     return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
+            ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
+ }`,
		refs: ['CWE-1102', 'OWASP'],
		tags: ['data-representation', 'endianness', 'portability', 'fixed-width'],
	},
	{
		id: 'CWE-1103',
		name: 'Use of Platform-Dependent Third Party Components',
		lang: 'c',
		status: 'Complete',
		what: `使用「平台相依」的第三方元件。挑的第三方函式庫、SDK 或中介軟體只在某些平台有對等功能,
	其餘平台上行為缺損或根本不存在,卻仍宣稱產品在所有目標平台都能一致運作。成因是選型只看「首選平台
	可用」,沒在支援矩陣上逐一核對該元件在每個目標 OS、CPU、架構的等價支援,也沒做行為對照。具體後果是
	在某些平台功能悄悄失效、權限誤判、或產生不一致的資料,而且把「平台範圍」不當擴張成一個難以察覺的
	默默錯誤分支。修法是選用官方支援涵蓋全部目標平台的元件、替缺失能力做明示的退化路徑,並在 CI 對每個
	支援平台跑同一組憑證測試以驗證等價行為。`,
		problem: `// 不安全寫法:直接呼叫只存在於部分平台的第三方 API,選型時沒篩平台等價
#include <vendor_io.h>            // 只在特定 OS 的樣板提供
int read_temperature(void) {
    // 架構 B 上 vendor_io 不存在 => 在那平台連結失敗
    return vendor_io_get(TEMP_SENSOR);
}`,
		fixed: `// 安全寫法:以抽象層收斂平台相依呼叫,缺失平台走明示的等價/退化實作
int read_temperature(void) {
#ifdef USE_VENDOR_IO            // 只在元件確有等價功能的平台啟用
    return vendor_io_get(TEMP_SENSOR);
#else
    return EMULATED_TEMP;       // 其他平台有對等實作或明確定義的退化
#endif
}`,
		patch: `@@
  int read_temperature(void) {
-     return vendor_io_get(TEMP_SENSOR);   /* 部分平台不存在 */
+ #ifdef USE_VENDOR_IO                  /* 啟用僅限有等價支援者 */
+     return vendor_io_get(TEMP_SENSOR);
+ #else
+     return EMULATED_TEMP;              /* 等價退化路徑 */
+ #endif
  }`,
		refs: ['CWE-1103', 'OWASP'],
		tags: ['third-party', 'platform', 'sdk', 'portability', 'vendor'],
	},
	{
		id: 'CWE-1104',
		name: 'Use of Unmaintained Third Party Components',
		lang: 'node',
		status: 'Complete',
		what: `使用「無人維護」的第三方元件。產品依賴某個第三方套件或函式庫,而其原始作者或可信代理已
	不再更新、不再回應弱點通告、也不修 bug;軟體卻持續把它編進發行。成因是選型只看「當下能用」,沒評估
	維護訊號——最後提交時間、issue 回覆、釋出頻率、有無活躍主要支撐。具體後果是元件裡已知或日後被揭露的
	弱點永遠不會有人補上修補,一旦它觸及的位置被攻擊者利用,產品就長期暴露而無更新可裝。修法是改用維護
	中有弱點回報與固定釋出的元件、追蹤上游弱點公告、把無人維護的元件拆分重寫或遷移到受維護替代品,並在
	套件登錄上以 lock 檔與版本上限收斂。`,
		problem: `// 不安全寫法:使用已 3 年未更新、上游已停擺的套件,不查維護狀態
const parse = require('legacy-config-parser'); // 原作已停擺,已知 RCE 無人修
module.exports = function load(cfgText) {
  return parse(cfgText);   // 把漏洞套件一路帶進發行
};`,
		fixed: `// 安全寫法:選用有維護與弱點回報程序的依賴,鎖版本並追蹤上游公告
const parse = require('maintained-config-parser'); // 活躍開發、定期釋出
module.exports = function load(cfgText) {
  return parse(cfgText);   // 依賴本身維護中,弱點可即時更新
};`,
		patch: `@@
- const parse = require('legacy-config-parser'); // 已停維護,漏洞無人修
+ const parse = require('maintained-config-parser'); // 有弱點回報與釋出
  module.exports = function load(cfgText) {
    return parse(cfgText);
  };`,
		refs: ['CWE-1104', 'OWASP'],
		tags: ['dependency', 'abandoned', 'supply-chain', 'maintained', 'npm'],
	},
	{
		id: 'CWE-1105',
		name: 'Insufficient Encapsulation of Machine-Dependent Functionality',
		lang: 'c',
		status: 'Complete',
		what: `「機器相依功能」封裝不足。程式用不同平台特有做法(系統呼叫、登錄檔、裝置 API)達成同一
	件事,卻把這些做法分散寫在業務邏輯各處,沒有收斂成可被替換的抽象層。成因是開發時圖快、就地插入
	平台分支,於是平台判斷散布在十幾個檔案。具體後果是移植到新平台時要一個一個找出並改正所有平台片段,
	容易漏改造成行為錯亂;程式也更難測試,因為每個分支都要不同環境才跑得到;安全上也讓平台差異「露」
	進演算法,重則造成錯誤的平台選擇。修法是把所有機器相依操作收進單一組件、統一介面,其餘程式只呼叫
	抽象 API,各平台實作各自封包。`,
		problem: `// 不安全寫法:平台特有做法直接散在業務邏輯,沒有抽象層可替換
int get_mono_ms(void) {
#ifdef _WIN32
    DWORD t = GetTickCount64();       // Windows 特有呼叫埋在核心邏輯
    return (int)t;
#else
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
#endif
}`,
		fixed: `// 安全寫法:抽象為單一平台介面,業務處只呼叫 mono_ms();各平台實作各自封包
// time_platform.h
int mono_ms(void);
// linux_time.c
#include <time.h>
int mono_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
// app.c
total = start + mono_ms();   // 業務邏輯只依賴抽象,不感知平台`,
		patch: `@@
- int get_mono_ms(void) {
- #ifdef _WIN32
-     DWORD t = GetTickCount64();     /* Windows 埋在邏輯 */
-     return (int)t;
- #else
-     struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
-     return (int)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
- #endif
- }
+ /* time_platform.h: int mono_ms(void); */
+ /* linux_time.c */
+ int mono_ms(void) {
+     struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
+     return (int)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
+ }
+ /* app.c: total = start + mono_ms(); 只碰抽象 */`,
		refs: ['CWE-1105', 'OWASP'],
		tags: ['encapsulation', 'portability', 'platform', 'abstraction'],
	},
	{
		id: 'CWE-1106',
		name: 'Insufficient Use of Symbolic Constants',
		lang: 'java',
		status: 'Complete',
		what: `符號常數使用不足。原始碼把「會被改動或演進」的值直接寫成字面常數(magic number、字串),
	而不是取名給它。出現 1048576、86400、/api/v1 這類會被時間、專案尺寸、協定版本左右的值時,成因是想
	省一行定義。具體後果是這些值像複製品一樣散布到幾十個地方,改動時漏改一處,不同點的同一原則(同一
	timeout、同一上限)就長出不同值、行為不一致;而字面值極難搜出全部語意相同的「實例」,也無法讓編譯器
	在型別上把關。修法是對一切非絕不會變的常數,以具有意義的具名常數收斂定義,改動只需動一處。`,
		problem: `// 不安全寫法:把會演進的「上限」與「時長」寫成裸字面值,複製到各處
public class Config {
    public boolean isValid(String key) {
        // 字面值 256 / 5000,語意不明,日後改上限得搜「所有 256」
        return key.length() >= 1 && key.length() <= 256 && wait() <= 5000;
    }
    private long wait() { return 5000; }  // 與上面的 5000 其實是同一個極限,卻各寫各的
}`,
		fixed: `// 安全寫法:具名符號常數集中定義,語意與改動都有依據
public final class Limits {
    public static final int MIN_KEY = 1;
    public static final int MAX_KEY = 256;
    public static final long MAX_WAIT_MS = 5000L;
}
// 使用處一律引用 Limits.MAX_KEY / Limits.MAX_WAIT_MS`,
		patch: `@@
  public class Config {
+    private static final int MAX_KEY = 256;
+    private static final long MAX_WAIT_MS = 5000L;
      public boolean isValid(String key) {
-        return key.length() >= 1 && key.length() <= 256 && wait() <= 5000;
+        return key.length() >= 1 && key.length() <= MAX_KEY && wait() <= MAX_WAIT_MS;
      }
    }`,
		refs: ['CWE-1106', 'OWASP'],
		tags: ['magic-number', 'constant', 'symbolic', 'maintainability'],
	},
	{
		id: 'CWE-1107',
		name: 'Insufficient Isolation of Symbolic Constant Definitions',
		lang: 'java',
		status: 'Complete',
		what: `符號常數「定義位置」隔離不足。程式明明用了具名常數,卻把定義散在許多檔案或類別裡,沒有
	收攏進單一、集中的位置(共用常數 module 或 interface)。成因是各組件各自定義自己那幾個常數,同一組
	語意的常數在不同檔案出現兩份同名、同值卻不相通。具體後果是改動一個檔案的常數、以為改了全部,另一處
	卻還是舊值,於是在檔案邊界上產生不一致的行為;而且這種不一致無法靠編譯器抓出來——它是各自為政的
	平行定義而非重複宣告。低落的可維護性更讓某一份未來被改成不同值,製造隱性偏差。修法是把全專案共用
	常數集中到單一定義檔,讓需要者單向引用。`,
		problem: `// 不安全寫法:同一語意常數在兩個類別各自宣告,各自獨立、易不同步
class HttpA { static final int MAX_BODY = 1048576; }   // 一份定義
class HttpB { static final int MAX_BODY = 2097152; }   // 另一份:不同步仍編得過
// HttpA.MAX_BODY 與 HttpB.MAX_BODY 都說「體積上限」卻不同值`,
		fixed: `// 安全寫法:集中到單一檔案,各處只引用同一來源
public final class Limits {
    public static final int MAX_BODY = 1048576;   // 唯一定義處,改動只有一處生效
}
// HttpA 與 HttpB 一律使用 Limits.MAX_BODY,不再各自復刻`,
		patch: `@@
- class HttpA { static final int MAX_BODY = 1048576; }
- class HttpB { static final int MAX_BODY = 2097152; }   /* 兩處不同步 */
+ public final class Limits {
+     public static final int MAX_BODY = 1048576;         /* 單一定義 */
+ }
+ /* HttpA: Limits.MAX_BODY;  HttpB: Limits.MAX_BODY */`,
		refs: ['CWE-1107', 'OWASP'],
		tags: ['constant', 'single-source', 'isolation', 'maintainability'],
	},
	{
		id: 'CWE-1108',
		name: 'Excessive Reliance on Global Variables',
		lang: 'python',
		status: 'Complete',
		what: `過度依賴全域變數。程式把與單一運算綁定的「狀態」放在模組層級全域變數,讓各處在高與設定
	它之間流竄,而不是在更窄、更本地的脈絡裡保存。成因是傳參數麻煩,圖省事就把 current、config、token
	掛在全域。具體後果是:同時處理多個請求或多執行緹的環境會互相污染,A 設的值被 B 覆寫而產生錯誤結果——
	全域「單一份」本質上就承不住並行;而且「誰在何時改了它」難以追蹤,測試要重設全域、注入也困難,行為
	隨呼叫順序而變。修法是讓狀態隨呼叫流走:以參數傳入、用回傳值帶出、或藏進明確的 instance。`,
		problem: `# 不安全寫法:進度/身分存在模組級全域,高併發下互相覆寫
current_user = None

def begin(user):
    global current_user
    current_user = user            # 執行緹 A 設定後,B 又覆寫它

def validate():
    global current_user
    return permit(current_user)    # 讀到的可能是「別人的」使用者`,
		fixed: `# 安全寫法:狀態隨呼叫流走,以參數傳入,執行緹彼此隔離
def begin(user):
    return user                  # 回傳並往下傳,不存全域

def validate(uid):
    return permit(uid)          # 只有傳入的那個呼叫,上下文唯一`,
		patch: `@@
- current_user = None
  def begin(user):
-     global current_user
-     current_user = user
+     return user           # 以回傳/參數傳遞,不進全域
  def validate():
-     global current_user
-     return permit(current_user)
+     return permit(user)` ,
		refs: ['CWE-1108', 'OWASP'],
		tags: ['global-variable', 'shared-state', 'concurrency', 'state'],
	},
	{
		id: 'CWE-1109',
		name: 'Use of Same Variable for Multiple Purposes',
		lang: 'c',
		status: 'Complete',
		what: `同一變數被拿去「多用途」。同一段可呼叫程式、區塊或迴圈裡,一個變數被用來控制一件以上的
	工作,或存放一份以上的不同資料。成因常是省變數或偷懒重用暫存區。具體後果是:只要某個用途留下殘值,
	另一個用途就拿到「看起來很像卻不全對」的資料;同一變數在多用途間切換讓程式意圖模糊,容易在某條路徑
	漏設或錯設,型別上也無法分辨「現在它是什麼」;日後要加新目的時又得小心翼翼不破壞舊的。修法是每個用途
	給各自專屬、語意明確的變數,用更窄的作用域與更明確的型別分開。`,
		problem: `// 不安全寫法:暫存變數一下放長度、一下放定界字,兩用途互相污染
int send_pkt(int fd, const char *data, size_t len) {
    int tmp = (int)len;            // 用途一:長度
    if (tmp > 255) return -1;
    if (write(fd, data, tmp) != tmp) return -1;
    tmp = 0x7b;                  // 用途二:起使定界字(複用同一變數)
    if (write(fd, &tmp, 1) != 1) return -1;
    return 0;
}`,
		fixed: `// 安全寫法:各用途專屬變數,意圖清楚、互相不污染
int send_pkt(int fd, const char *data, size_t len) {
    if (len > 255u) return -1;
    unsigned long w = write(fd, data, len);
    if (w != len) return -1;
    unsigned char delim = 0x7b;    // 專屬變數
    if (write(fd, &delim, 1) != 1) return -1;
    return 0;
}`,
		patch: `@@
  int send_pkt(int fd, const char *data, size_t len) {
-     int tmp = (int)len;
-     if (tmp > 255) return -1;
-     if (write(fd, data, tmp) != tmp) return -1;
-     tmp = 0x7b;
-     if (write(fd, &tmp, 1) != 1) return -1;
+     if (len > 255u) return -1;
+     if (write(fd, data, len) != len) return -1;
+     unsigned char delim = 0x7b;   /* 各用途專屬變數 */
+     if (write(fd, &delim, 1) != 1) return -1;
      return 0;
  }`,
		refs: ['CWE-1109', 'OWASP'],
		tags: ['variable-reuse', 'naming', 'legibility', 'state'],
	},
	{
		id: 'CWE-1110',
		name: 'Incomplete Design Documentation',
		lang: 'text',
		status: 'Complete',
		what: `「設計文件」不完整。產品的設計文件沒有充分描述控制流、資料流、系統初始化、工作之間的關係、
	元件之間的關聯、設計理由(rationale) 等關鍵面向;或這些只有片段存在。成因是文件被當成「事後才補」,
	只畫了架構圖而缺少感性決策與結構理由。具體後果是後續開發與維護者無從得知「為什麼是這樣設計」,於是在
	更動時用了錯誤假設、破壞原設計邊界;新成員或稽核無法僅憑文件重建系統行為,對初始化順序、權限邊界的
	安全審查缺乏依據,誤解設計很可能正是日後弱點的來源。修法是在設計期就把控制流、資料流、初始化與各工作間
	互動及決策理由一起寫下,並隨變更持續更新。`,
		problem: `# 不安全寫法:設計文件只有一張架構圖與方塊名,缺控制流/資料流/初始化順序
## 系統設計(C)
- 客戶端模組:驗證請求
- 認證服務:發 token
> 沒有:信任邊界、初始化次序、請求如何流經、為什麼這樣分割`,
		fixed: `# 安全寫法:設計文件補充信任邊界、資料流、初始化順序與理由
## 系統設計(C)
1. 信任邊界:未驗證輸入不得進入核心
2. 初始化順序:config -> logger -> auth -> listen
3. 資料流:request -> sanitize -> authn -> authz -> handler
4. 設計理由:先初始化 auth,避免未授權的受理 window
> 每次更改同步更新對應章節`,
		patch: `@@
  ## 系統設計
  - 客戶端模組:驗證請求
  - 認證服務:發 token
+ 1. 信任邊界:未驗證輸入不得進入核心
+ 2. 初始化順序:config -> logger -> auth -> listen
+ 3. 資料流:request -> sanitize -> authn -> authz -> handler
+ 4. 設計理由:先初始化 auth,避免未授權 window`,
		refs: ['CWE-1110', 'OWASP'],
		tags: ['docs', 'design', 'data-flow', 'init', 'rationale'],
	},
	{
		id: 'CWE-1111',
		name: 'Incomplete I/O Documentation',
		lang: 'text',
		status: 'Complete',
		what: `「輸入／輸出」文件不完整。產品的文件沒有正確定義它對外提供的介面:輸入來源、輸出目的、
	格式、允許範圍、錯誤時的回應;也常漏掉「系統／軟體介面」的契約。成因是開發時介面由程式碼隱晦形成,
	文件沒跟上。具體後果是呼叫端(內部模組或外部整合者)只能猜測參數語意與邊界,送出超出定義的值,而程式
	可能沒針對該範圍驗證,造成格式混淆、溢位或非預期的資料外洩;對安全而言,沒把輸入契約寫清楚等於沒聲明
	「哪些是有效的」,驗證與測試就沒有基準。修法是把每個入口/出口的型別、允許值、長度、編碼與錯誤行為
	一一寫進介面文件。`,
		problem: `# 不安全寫法:API 文件只寫「arg:string」,沒定義範圍、格式與錯誤
# POST /case
# 參數: 文本(text:string)
# 缺乏: 長度上限、許可字元集、回傳碼語意`,
		fixed: `# 安全寫法:定義每個輸入/輸出的契約(型別、範圍、編碼、錯誤)
# POST /case
# 參數: text(string, UTF-8, 1..4096 字元, 禁 control chars)
# 輸出: 200 + hash;400 超長/非法字元;413 payload 過大
# 介面契約: 只接受純文字,不含控制字元`,
		patch: `@@
  # POST /case
- # 參數: 文本(text:string)
+ # 參數: text(string, UTF-8, 1..4096, 禁 control chars)
+ # 輸出: 200 + hash;400 超長/非法;413 過大
+ # 契約: 只接受純文字`,
		refs: ['CWE-1111', 'OWASP'],
		tags: ['io-docs', 'interface', 'contract', 'validation'],
	},
	{
		id: 'CWE-1112',
		name: 'Incomplete Documentation of Program Execution',
		lang: 'text',
		status: 'Complete',
		what: `「程式執行機制」文件不完整。文件沒有完整描述所有會控制或影響產品如何執行其程式的機制:命令列
	參數、環境變數、設定檔、排程觸發、信號處理、各種開關與它們的組合效果。成因是文件只寫「如何安裝、如何
	開啟」,執行層面的選項與預設沒交代。具體後果是操作者或自動化只能靠猜驅動程式——漏設某個必須的環境
	變數會造成設定誤載,或在不知情下開啟某個安全攸關的旗標(如停用驗證);稽核也看不出該以哪些參數執行
	才算安全組態。修法是完整列出每個可執行入口及其參數、環境變數,並註明它們對安全行為的影響。`,
		problem: `# 不安全寫法:文件只有「執行 ./server」一句,使用者不知必帶旗標
## 執行方式
$ ./server
# 參數、環境變數、與它們影響的安全設定皆未記載`,
		fixed: `# 安全寫法:完整列出入口、旗標、環境變數與安全影響
## 執行方式
$ ./server --listen 0.0.0.0:8443 --tls-only
環境變數(影響行為):
  SERVER_ADMIN_PASSWORD : 必設,否則拒絕啟動
  ENABLE_INSECURE_HTTP : 預設 OFF,開啟會降級為明文
安全旗標: --tls-only 不可在產線關閉`,
		patch: `@@
  ## 執行方式
- $ ./server
+ $ ./server --listen 0.0.0.0:8443 --tls-only
+ 環境變數: SERVER_ADMIN_PASSWORD 必須設;ENABLE_INSECURE_HTTP 預設 OFF
+ 安全旗標: --tls-only 產線不得關閉`,
		refs: ['CWE-1112', 'OWASP'],
		tags: ['execution', 'envar', 'flags', 'docs', 'run'],
	},
	{
		id: 'CWE-1113',
		name: 'Inappropriate Comment Style',
		lang: 'c',
		status: 'Complete',
		what: `「註解風格」不適當。原始碼使用的註解寫法或格式不一致,或不符專案訂下的標準(混用 /* */ 與
	//、註解語法忽高忽低、有的用 Doxygen 有的裸寫、行尾註解擠成一排)。成因是沒訂一致的註解規範、或沒用
	linter 強制。具體後果是自動文件工具誤判而漏抓或錯放註解、醜陋的排列讓事實難以對應到意圖;對安全而
	言更糟的是「看起來像註解其實是程式」的誤會、或風格造成的事實遮蔽使漏洞不被當成問題;retool 也難用同一種
	註解 pattern 一次搜到。修法是訂定一致註解準則,並以 linter 在建構時強制執行。`,
		problem: `// 不安全寫法:同專案混用多種註解語法與風格,難以一致解讀
/* 舊式 C 註解(還跨多行) */
int a;  // 行尾註解又另一種
/**** 花俏分隔線框架 ****/
int b;  //
// 有的用 Doxygen、有的裸寫,自動文件抓不全`,
		fixed: `// 安全寫法:統一註解風格與標記,Doxygen 標籤齊整
/** 初始化事件處理器。
 * @return 0 成功;負值為錯誤碼。
 */
int init_event(void);
int a;                /* 行內註解採同一基準 */
int b;                /* 同上 */`,
		patch: `@@
- /* 舊式 C 註解 */
- int a;  // 行尾註解
- /**** 花俏分隔線 ****/
+ /** 初始化事件處理器。 @return 0 成功,負值錯誤。 */
+ int init_event(void);
+ int a;              /* 統一風格 */
+ int b;              /* 統一風格 */`,
		refs: ['CWE-1113', 'OWASP'],
		tags: ['comments', 'style', 'lint', 'consistency'],
	},
	{
		id: 'CWE-1114',
		name: 'Inappropriate Whitespace Style',
		lang: 'python',
		status: 'Complete',
		what: `「空白字元」風格不當。原始碼的縮排、空白、分行規則在全程式內不一致或不符合專案標準(混用
	tab/space、縮排寬度隨檔而變、多餘尾端空白)。成因是沒有共同的編輯器設定與 linter 強制。對版式語言的
	Python 尤其危險:縮排本身承載區塊結構,一旦混用 tab 與空格,同一個「看起來一樣」的位置在不同編輯器會被
	解讀成不同的巢狀深度,於是一行程式可能被靜靜歸進或移出它本不屬於的流程、繞過原本的條件,造成邏輯
	漏洞卻難查;其他語言則製造 diff 噪音、遮蔽真實變更。修法是統一縮排規則、以 formatter 自動套用,並在
	CI 檢查。`,
		problem: `# 不安全寫法:tab 與空格混用,「是否在 if 內」一檔兩讀
def check(user):
\tif user.role == "admin":
\t\treturn True
        return False     # 這列是 if 外還是 if 內?混用縮排造成歧義
# 縮排錯一層會讓 return False 誤進/移出條件 => 授權誤判`,
		fixed: `# 安全寫法:全檔統一 4 空格縮排,區塊歸屬一目了然
def check(user):
    if user.role == "admin":
        return True
    return False        # 明確的 if 外層,語意不隨編輯器而歧義`,
		patch: `@@
  def check(user):
-\tif user.role == "admin":
-\t\treturn True
-        return False
+    if user.role == "admin":
+        return True
+    return False       # 統一縮排,歸屬無歧義`,
		refs: ['CWE-1114', 'OWASP'],
		tags: ['whitespace', 'indent', 'format', 'python'],
	},
	{
		id: 'CWE-1115',
		name: 'Source Code Element without Standard Prologue',
		lang: 'c',
		status: 'Complete',
		what: `「標準前言(prologue)」缺失。原始檔等元素未一致提供專案訂下的序文/檔頭(版權、作者、
	檔名用途、修改歷史欄位)。成因是各檔自己寫開頭、或沒有產生檔頭的工具統一加上。直接後果是版權/授權無法
	審計、出處不明,維護者在不知道這份碼源自哪個版本、被改過幾次的情況下更動;標準前言常註記「本檔的意圖
	／不變式」——缺少它,繼承者不清楚這份碼在哪被建立、該守哪些安全界;大專案的掃描與稽核也缺了主權與許可
	資訊。修法是定義單一 prologue 範本,以產生器/檢查器確保每個原始檔都帶。`,
		problem: `// 不安全寫法:原始檔直接裸露程式,沒有檔頭說明出處/用途/授權
int decode(const unsigned char *buf, size_t len) {
    // 是哪一支產品的?誰改過?授權為何?完全無從得知
    return inner_decode(buf, len);
}`,
		fixed: `// 安全寫法:每個檔帶標準 prologue,載明授權、用途、修改歷史
/*
 * funcs.c - 認證金鑰解碼
 * Copyright 2024 Acme Corp, Apache-2.0
 * Rev 1.0 | 2024-01-02 | alice | initial
 */
int decode(const unsigned char *buf, size_t len) {
    return inner_decode(buf, len);
}`,
		patch: `@@
+ /*
+  * funcs.c - 認證金鑰解碼
+  * Copyright 2024 Acme Corp, Apache-2.0
+  * Rev 1.0 | 2024-01-02 | alice | initial
+  */
  int decode(const unsigned char *buf, size_t len) {
      return inner_decode(buf, len);
  }`,
		refs: ['CWE-1115', 'OWASP'],
		tags: ['prologue', 'header', 'license', 'metadata'],
	},
	{
		id: 'CWE-1116',
		name: 'Inaccurate Source Code Comments',
		lang: 'c',
		status: 'Complete',
		what: `「不精確的註解」。原始碼內的註解沒有正確描述它所附著段落的行為:註解說「這裡過濾輸入」其實
	沒有、參數意思與事實相反、或描述的行為在重構後早已變掉。成因是改碼時忘了同步改註解、或以猜測名義寫
	註。具體後果是維護者「信任註解」來推理——註解只要錯一句,就可能讓繼承者以為某段做了驗證/處理某邊界而
	跳過,漏洞就在這層信任下被維持下去;最常見的誤導像是「這份資料已清洗過」讓程式不再檢查。修法是讓註解
	描述「此刻的真實行為」、每次修改時連帶更新,並對安全攸關的註解對應的行為補測試驗證。`,
		problem: `// 不安全寫法:註解宣稱已過濾輸入,實則沒有(信任落空)
// 這裡已移除所有可執行字元,直接安全
void store(const char *s) {   // 並未做任何清理
    write_log(s);             // 註解說安全,實際把原始字串寫入 => 注入風險
}`,
		fixed: `// 安全寫法:註解描述實際做過的事,與行為一致
void store(const char *s) {
    char *clean = sanitize(s);   // 真實的過濾步驟
    write_log(clean);            // 註解與實際行為一致
}`,
		patch: `@@
  void store(const char *s) {
-     write_log(s);              /* 註解稱已過濾,實際沒有 */
+     char *clean = sanitize(s); /* 註解對應真實步驟 */
+     write_log(clean);
  }`,
		refs: ['CWE-1116', 'OWASP'],
		tags: ['comment', 'misleading', 'trust', 'accuracy'],
	},
	{
		id: 'CWE-1117',
		name: 'Callable with Insufficient Behavioral Summary',
		lang: 'c',
		status: 'Complete',
		what: `「行為說明不足」的可呼叫單元。某函數/方法的簽名與內嵌文件未能充分說明它的輸入、輸出、副作用、
	前置假設與回傳碼。成因是只寫一行名字就把實作塞進去,把「呼叫者必須先做某事」「會覆寫傳入指標」「負值是
	錯誤」這些契約藏在看不出來的地方。具體後果是呼叫端誤用:誤把回傳碼當布林(0 其實是成功)、沒注意引數會被
	改寫、沒在乎前置條件——只要一個落了空就可能繞過檢查或存取到錯誤資源,而多半不在呼叫者預期內,成為日後安全
	缺陷。修法是把每個 public callable 的 precondition、postcondition、副作用與回傳碼意涵寫進介面文件。`,
		problem: `// 不安全寫法:簽名看不出語意,沒寫前置條件與回傳碼
int hurt(char *buf, size_t cap) {
    // 沒說明:呼叫者是否須緩衝歸誰、buf 是否被改、0 表示成功
    fill(buf, cap);   // 負值/0/正值代表什麼完全看不出
}`,
		fixed: `// 安全寫法:註明文檔化前置條件、副作用與回傳碼
/** 讀出金鑰到 caller 提供的緩衝。
 * @pre buf 指向至少 cap 位元組的可寫空間。
 * @param[out] buf 會被覆寫。
 * @return 0 成功;負值為錯誤碼。
 */
int load_key(unsigned char *buf, size_t cap) {
    if (!buf || cap < 16) return -1;
    return hw_key(buf, cap);
}`,
		patch: `@@
- int hurt(char *buf, size_t cap) {
-     fill(buf, cap);   /* 無前置/回傳說明 */
- }
+ /** @pre buf 至少 cap 位元組可寫;buf 會被覆寫;0=成功,負值=錯誤。 */
+ int load_key(unsigned char *buf, size_t cap) {
+     if (!buf || cap < 16) return -1;
+     return hw_key(buf, cap);
+ }`,
		refs: ['CWE-1117', 'OWASP'],
		tags: ['docs', 'contract', 'precondition', 'callable'],
	},
	{
		id: 'CWE-1118',
		name: 'Insufficient Documentation of Error Handling Techniques',
		lang: 'java',
		status: 'Complete',
		what: `「錯誤處理方法」文件不完備。文件未充分說明產品使用哪些錯誤處理技巧:例外策略、哪些失敗可復原、
	哪些必須中止、error code 的收斂規則、狀態如何復位。成因是只寫成功路徑、把錯誤路徑當「不會發生」省略。
	具體後果是錯誤發生時維護者不知道該回傳什麼、是否該重試、是否要做狀態回滾,於是以不一致甚至不安全的姿態
	收拾殘局——該中止的地方繼續執行、把部分寫入的資料當成完整交易,或把敏感錯誤訊息暴露給使用者;缺少復原
	契約也使 fail-open／fail-closed 的決策沒有依據。修法是在文件定義錯誤分類、每類的處理(重試/降級/中止)
	與狀態回復規則。`,
		problem: `// 不安全寫法:錯誤路徑完全未說明,維護者只能用猜的
public void transact(String id) {
    // 沒寫:會丟什麼例外?丟了要不要重試?狀態是否已回滾?
    step1(id);          // 例如 step1 已寫、step2 失敗 => 半完成狀態無人接
    step2(id);
}`,
		fixed: `// 安全寫法:文件定義錯誤分類與每類處置,程式照契約收尾
/** 交易:任一階段失敗丟 BizException;呼叫端應回滾並可單次重試。
 * @throws BizException 資料未變動,可安全重試
 * @throws FatalException CPU/IO 損傷,呼叫端不應重試、應中止 */
public void transact(String id) throws BizException, FatalException {
    try { step1(id); step2(id); }
    catch (IOFailure e) { rollback(id); throw new BizException(e); }
    catch (HardFail e)  { throw new FatalException(e); }
}`,
		patch: `@@
- public void transact(String id) {
-     step1(id);
-     step2(id);
- }
+ public void transact(String id) throws BizException, FatalException {
+     try { step1(id); step2(id); }
+     catch (IOFailure e) { rollback(id); throw new BizException(e); } /* 可重試 */
+     catch (HardFail e)  { throw new FatalException(e); }           /* 應中止 */
+ }`,
		refs: ['CWE-1118', 'OWASP'],
		tags: ['error-handling', 'exception', 'recovery', 'docs'],
	},
	{
		id: 'CWE-1119',
		name: 'Excessive Use of Unconditional Branching',
		lang: 'c',
		status: 'Complete',
		what: `過度使用無條件分支(goto)。程式用過多 goto 來跳來跳去控制流程,執行之路像一碗麵線。少量受
	控的 goto 可用,過量就成了問題。成因是想在錯誤路徑共用清理碼而一路 goto error。具體後果是程式遮蔽真正
	流程,容易在某條跳轉漏掉初始化或清理,尤其是跳過變數初始化、或跨越資源取得就直接跳到使用點,在未設定的
	狀態下使用資源;而且「這條路徑在哪些值下執行」無法單純從閱讀推出,混淆安全審計對收斂/分歧點的掌握。
	修法是限制 goto 只往檔尾的單一錯誤清理處跳,採 RAII 或明確的回傳錯誤結構,並以 lint 設跳轉上限。`,
		problem: `// 不安全寫法:goto 到處跳、還往後往回跳,一條路徑繞一大圈
void proc(void) {
    FILE *f = NULL;
    do { goto retry; } while (0);       // 無條件跳,流程難讀
    goto done;
retry:
    f = fopen("x", "r");
    goto done;
    if (!f) goto fail;                  // 跳越,初始化與檢查順序錯亂
    /* ... */
done:
fail:
    if (f) fclose(f);
}`,
		fixed: `// 安全寫法:單一「只往檔尾統一清理」的 goto,流程可讀、資源必配清理
void proc(void) {
    FILE *f = fopen("x", "r");
    if (!f) goto cleanup;              // 僅此一跳,且跳向統一清理
    int rc = read_file(f);
    if (rc != 0) goto cleanup;
cleanup:
    if (f) fclose(f);
}`,
		patch: `@@
  void proc(void) {
-     do { goto retry; } while (0);
-     goto done;
- retry:
-     f = fopen("x", "r");
-     goto done;
-     ...
- done:
- fail:
+     FILE *f = fopen("x", "r");
+     if (!f) goto cleanup;
+     if (read_file(f) != 0) goto cleanup;
+     cleanup:
      if (f) fclose(f);
  }`,
		refs: ['CWE-1119', 'OWASP'],
		tags: ['goto', 'branch', 'flow', 'spaghetti'],
	},
	{
		id: 'CWE-1121',
		name: 'Excessive McCabe Cyclomatic Complexity',
		lang: 'java',
		status: 'Complete',
		what: `「McCabe 迴圈複雜度」過高。程式某一函數的 cyclomatic complexity 超過理想上限——它由 if、
	for、while、case、&&、||、catch 等決策點多寡決定。成因是把一大包業務全塞進單一方法。具體後果是高
	複雜度代表成功/失敗路徑太多,測試難以窮舉到所有分支、審計也難逐一驗證每個決策點的授權前提;路徑多自然
	隱藏「只在特定組合下才成立」的死角,這類死角正是繞過權限或觸發異常的地方。複雜度又常隨時間只增不降,
	成為弱點溫床。修法是把函數拆小、每個函數只做單一決策層,抽出子函式或用多型/查找表降低決策點,並以
	複雜度上限配合 CI 強制。`,
		problem: `// 不安全寫法:單一方法塞滿決策點,V(G) 遠超上限
int authorize(String u, String r, boolean sso, int age) {
    if (u == null) return -1;
    String[] g = groups(u);
    for (int i = 0; i < g.length; i++) {
        if (g[i].equals("audit") && r.equals("read") && sso && age > 0) return 1;
        if (g[i].equals("audit") && r.equals("write") && !sso) return 0;
    }
    return -1;    // 決策點一堆,路徑組合多到無法驗證
}`,
		fixed: `// 安全寫法:拆成單決策層的小函數、以查找表收斂,每處一層判斷
int ruleFor(String r, boolean sso, int age) {
    if (!isAudit(u)) return -1;
    return DECISION_TABLE.lookup(r, sso, age);   // 決策表取代大片巢狀 if
}`,
		patch: `@@
- int authorize(...) {  /* 大片決策點 */
-     ...
- }
+ int ruleFor(String r, boolean sso, int age) {
+     if (!isAudit(u)) return -1;
+     return DECISION_TABLE.lookup(r, sso, age); /* 決策表收斂 */
+ }`,
		refs: ['CWE-1121', 'OWASP'],
		tags: ['complexity', 'mccabe', 'cyclomatic', 'refactor'],
	},
	{
		id: 'CWE-1122',
		name: 'Excessive Halstead Complexity',
		lang: 'c',
		status: 'Complete',
		what: `「Halstead 複雜度」過高。程式的 Halstead 度量(由運算子、運算元的獨特總數與總數推導)超過
	理想上限。成因與單一函數的 V(G) 不同,是「語言構成上的冗餘」——變數、函數、運算子被重複使用、名稱過近
	相像、同一概念用太多不同 token 表達。具體後果是理解成本高:維護要記憶大量互異 token 及其關聯,容易把一個
	運算元看成另一個,漏網的比較或誤用的資料就在 Token 字典越來越擠時產生;審計也因要追太多「看起來很像實則
	不同」的符號而漏網。修法是收斂 token:化簡變數與運算子數、統一命名,使 token 字典最小化並與語意穩定
	對應。`,
		problem: `// 不安全寫法:一堆近似撞名的變數與運算子,Token 字典很臃腫
int calc(int a, int b) {
    int aa = a + 1;        // aa / ab / ba 長得幾乎一樣
    int ab = b * 2;
    int ba = aa + ab;
    return ba - a - b;     // 讀者難辨識,一失神就把 a 當成 aa
}`,
		fixed: `// 安全寫法:總 token 收斂、命名彼此清楚可區分
int calcThen(int base, int step) {
    int a1 = base + 1;           // 語意清楚、可區分的命名
    int b2 = step * 2;
    return (a1 + b2) - (base + step);
}`,
		patch: `@@
  int calc(int a, int b) {
-     int aa = a + 1;
-     int ab = b * 2;
-     int ba = aa + ab;
-     return ba - a - b;
+     int a1 = base + 1;            /* 名稱可區分 */
+     int b2 = step * 2;
+     return (a1 + b2) - (base + step);
  }`,
		refs: ['CWE-1122', 'OWASP'],
		tags: ['halstead', 'complexity', 'metrics', 'naming'],
	},
	{
		id: 'CWE-1123',
		name: 'Excessive Use of Self-Modifying Code',
		lang: 'c',
		status: 'Complete',
		what: `過度使用「自行修改程式碼」。程式在執行期把自己的指令或資料位置寫掉——改寫後續要執行的機器
	碼、或把「唯讀」的程式區當工作區。成因常是執行期打補丁或刻意做變形。具體後果極危險:第一,自我修改
	常建立在「指令長度固定、內容可寫」的機器相依假設上,換平台即錯;第二,它破壞 W^X 防禦——被寫入的
	程式區帶執行權限,成為可被注碼的執行空間,或自改成攻擊者控制的路徑;第三是難以靜態審計,稽核看見的碼與
	執行完跑的碼不同,惡意版本構造全被藏在背後。修法是避免執行期改寫程式區,改用資料驅動分派、跳表或把「會
	變的」做成資料與組態。`,
		problem: `// 不安全寫法:執行期改寫程式碼緩衝(把該執行處當 WRITE 目標)
void fn(void) {
    unsigned char *p = (unsigned char*)&stub[0]; // 指向會執行的程式碼
    *p = 0x90;                  // 執行期改碼 => 可寫程式域,繞過 W^X
    ((void(*)(void))stub)();     // 從可寫緩衝呼叫 => 可執行的注入點
}`,
		fixed: `// 安全寫法:改成資料驅動的分派表,程式碼不自我改寫、執行影印不可寫
typedef int (*op)(int);
static const op TABLE[] = { opA, opB, opC };   // 唯讀資料表,不執行期變形
int apply(int n, int i) { return TABLE[i](n); }  // 資料決定行為,碼本身不變`,
		patch: `@@
- unsigned char *p = (unsigned char*)&stub[0];
- *p = 0x90;              /* 執行期改自己 */
- ((void(*)(void))stub)();
+ static const op TABLE[] = { opA, opB, opC };  /* 資料驅動 */
+ int apply(int n, int i) { return TABLE[i](n); }`,
		refs: ['CWE-1123', 'OWASP'],
		tags: ['self-modifying', 'writable-text', 'w-x', 'exec'],
	},
	{
		id: 'CWE-1124',
		name: 'Excessively Deep Nesting',
		lang: 'c',
		status: 'Complete',
		what: `「巢狀過深」。某可呼叫單元或程式群組裡,判斷或迴圈的巢狀深度超過理想上限(常見門檻四層)。
	成因是把層層條件逐一疊進、或邊寫邊把檢查一層層塞進既有的 if 內。具體後果是:每層縮排都是「唯有前面
	條件都真才進入」的隱含限制,深巢把這些限制黏在一起,讓「何時執行到此」難以還原,審計者極易漏看內層那
	個 if 而下錯授權/清理決策;深巢也容易因縮排失誤把某行誤移到錯誤層級(與 CWE-1114 共振)造成邏輯
	偏差。修法是早退(guard clause)、把內層抽成小函數、或用查表取代條件,把最大深度壓到一眼可看穿。`,
		problem: `// 不安全寫法:if 只在 if 內,五層以上難讀難審
int go(int a, int b) {
    if (a > 0) {
        if (b > 0) {
            if (a + b > 10) {
                if (b % 2 == 0) {
                    if (a % 2 == 0) {
                        return a * b;   // 有多少層縮排才到得了?看不出
                    } } } } } }
    return 0;
}`,
		fixed: `// 安全寫法:以 guard clause 早退,平鋪條件一眼可讀
int go(int a, int b) {
    if (a <= 0) return 0;         // 早退,不再往內疊
    if (b <= 0) return 0;
    if (a + b <= 10) return 0;
    if (b % 2 != 0) return 0;
    if (a % 2 != 0) return 0;
    return a * b;                  // 平鋪條件,執行條件一目了然
}`,
		patch: `@@
  int go(int a, int b) {
-     if (a>0) { if (b>0) { if (a+b>10) { if (ok) return a*b; } } }
-     return 0;
+     if (a <= 0) return 0;       /* guard clause 平鋪 */
+     if (b <= 0) return 0;
+     if (a+b <= 10) return 0;
+     if (b % 2 != 0) return 0;
+     if (a % 2 != 0) return 0;
+     return a*b;
  }`,
		refs: ['CWE-1124', 'OWASP'],
		tags: ['nesting', 'guard-clause', 'depth', 'readability'],
	},
	{
		id: 'CWE-1125',
		name: 'Excessive Attack Surface',
		lang: 'node',
		status: 'Complete',
		what: `「攻擊面」過大。產品的攻擊面定量量測超過理想上限——暴露給未授權方的入口、通訊埠、協定、
	介面太多。成因是功能豐富卻沒收斂:每個額外監聽埠預設開啟、範例與管理路由都掛在正式服務、冗餘關口對外
	開放。具體後果是讓攻擊者有越多下手點:每個暴露入口都是需要防守的一條線,越多越容易碰到「某支沒人維護的
	範例或管理 handler」正好可觸發弱點;過廣表面也讓修補覆蓋不到全部,稽核與加固成本升高。修法是採最小
	化:只開放業務真正需要的界面、預設關閉其他能力、管理面綁 loopback/內網,並定期量測與縮減暴露面。`,
		problem: `// 不安全寫法:綁在全部位址、把管理/debug 路由直接對外裸露
const http = require('http');
http.createServer((req, res) => {
  const p = req.url;
  if (p === '/admin') adminHandler(req, res);      // 管理面直接對外
  if (p === '/debug') debugHandler(req, res);      // debug 路由未關
  res.end('ok');
}).listen(8080, '0.0.0.0');   // 綁全部位址,管理/debug 通通裸露`,
		fixed: `// 安全寫法:只綁內網/loopback、把非必要路由下線,縮減可觸及表面
const http = require('http');
const ADMIN_NETS = ['127.0.0.1'];              // 管理面只在 loopback
http.createServer((req, res) => {
  const p = req.url;
  if (p.startsWith('/debug')) { res.statusCode = 404; return res.end(); }
  if (p === '/admin') {
    if (!ADMIN_NETS.includes(req.socket.remoteAddress)) { res.statusCode = 403; return res.end(); }
    return adminHandler(req, res);
  }
  res.end('ok');
}).listen(8080, '127.0.0.1');  // 不綁 0.0.0.0,只暴露最小表面`,
		patch: `@@
- }).listen(8080, '0.0.0.0');   /* 全位址 + 管理/debug 全暴露 */
+ }).listen(8080, '127.0.0.1');  /* 只綁 loopback */
+   if (p.startsWith('/debug')) { res.statusCode = 404; return res.end(); }
+   if (p === '/admin' && !ADMIN_NETS.includes(req.socket.remoteAddress))
+       { res.statusCode = 403; return res.end(); }`,
		refs: ['CWE-1125', 'OWASP'],
		tags: ['attack-surface', 'exposure', 'hardening', 'listening'],
	},
	{
		id: 'CWE-1126',
		name: 'Declaration of Variable with Unnecessarily Wide Scope',
		lang: 'c',
		status: 'Complete',
		what: `「變數宣告範圍過寬」。原始碼把變數宣告在很外層的 scope(函數頂或更廣),而它其實只在裡面的
	窄小區塊被用到。成因圖省事把變數一次拉到外面好「想用就用」。具體後果是過寬作用域讓變數的存活期與可見
	範圍超出所需:其他內層程式可能誤用或改寫它、讀者無法確定它是否被旁支動過;在並行或迴圈期間,過長存活
	也增加共用/衝突的機率(race 造成不一致);編譯器與靜態分析也難收縮到它真正承載的目的。它常與 CWE-1109
	(多用途)共同出現。修法是僅在最小需要區塊內宣告、能 const 就 const、能更內層就內層。`,
		problem: `// 不安全寫法:i 與 tmp 一路拉在函數頂,即使只在一個小迴圈用
void work(int *arr, size_t n) {
    int i, tmp;             // 只有底下一小迴圈用,卻整個函數可見可改
    /* ... 中間數十行邏輯都可能誤改 tmp ... */
    for (i = 0; i < (int)n; i++) { tmp = arr[i] * 2; arr[i] = tmp; }
}`,
		fixed: `// 安全寫法:在最小使用範圍(該迴圈)內宣告,旁支碰不到、生命週期最短
void work(int *arr, size_t n) {
    /* 前面邏輯無 tmp 可誤用 */
    for (int i = 0; i < (int)n; i++) {
        const int tmp = arr[i] * 2;   /* const + 局部,窄 scope */
        arr[i] = tmp;
    }
}`,
		patch: `@@
  void work(int *arr, size_t n) {
-     int i, tmp;                 /* 過寬,全函數可見 */
+     /* ... 中間邏輯不再能誤改 tmp ... */
      ...
-     for (i = 0; i < n; i++) { tmp = arr[i] * 2; arr[i] = tmp; }
+     for (int i = 0; i < (int)n; i++) {
+         const int tmp = arr[i] * 2;   /* 局部+const */
+         arr[i] = tmp;
+     }
  }`,
		refs: ['CWE-1126', 'OWASP'],
		tags: ['scope', 'variable', 'lifetime', 'locality'],
	},
	{
		id: 'CWE-1127',
		name: 'Compilation with Insufficient Warnings or Errors',
		lang: 'c',
		status: 'Complete',
		what: `「編譯警示／錯誤不足」的建構。程式在編譯時沒有開啟足夠的 warning/error 旗標,使一批本可被
	編譯器攔下的微妙 bug 或品質問題默默進入產品。成因是只開預設、或為了壓掉警告用 -Wno-*、甚至 -fpermissive
	放行。具體後果是:未初始化變數、型別降級轉換、&& 與 & 打錯、函數未宣告 prototype 回傳 int 造成截斷、
	buffer 大小不符的格式化——這些靜態即可補捉的安全弱點,到了執行期難以追查,還可能只在特定輸入才爆。修法是開
	-Wall -Wextra -Werror、啟用 format/conversion 相關警訊,把警告視為錯誤,逼工程師修對而不是關掉。`,
		problem: `// 不安全寫法:幾乎關掉/忽略警訊,一堆可靜態抓的 bug 進包
// Makefile 沒開 -Wall -Wextra,且 -Wno-conversion 把轉換警訊關掉
void f(const char *user) {
    char c = 300;                 // 轉換警訊被關,截斷無聲
    char buf[8]; sprintf(buf, "%s", user);  // 格式/長度警訊也被吞
}`,
		fixed: `# 安全寫法:全開警示並視為錯誤,違反即刻拉紅
$ gcc -Wall -Wextra -Wformat=2 -Wconversion -Werror app.c -o app
# 上述 sprintf 與轉換在建構當下即報錯,迫使修對而不是帶進`,
		patch: `@@
- gcc -fpermissive -Wno-conversion app.c -o app
+ gcc -Wall -Wextra -Wformat=2 -Wconversion -Werror app.c -o app`,
		refs: ['CWE-1127', 'OWASP'],
		tags: ['compiler', 'warnings', 'werror', 'build'],
	},
	{
		id: 'CWE-1173',
		name: 'Improper Use of Validation Framework',
		lang: 'java',
		status: 'Complete',
		what: `「驗證框架」使用不當。產品沒有使用、或不正確使用由來源語言或獨立函式庫提供的輸入驗證框架
	(如 Jakarta Bean Validation)。成因是整套驗證是自造臨時的、或框架開了但忘了在入口觸發、或只用 annotation
	驗了部分欄位。具體後果是產生「驗證形同虛設」的假信任:看起來有 @NotBlank 保護的欄位其實從不被執行、驗證
	只查「存在」不查「邊界」、未完清化的輸入照進核心——這是 XSS、注入、溢位的門口。修法是一致的在處理前強制
	觸發框架、以框架宣告規則蓋滿所有輸入欄位、用框架的錯誤回饋接收不符者並拒絕。`,
		problem: `// 不安全寫法:有驗證框架可用,卻沒把入口觸發、也沒覆蓋所有欄位
public void create(User u) {        // u 含 bio 欄,但沒標任何驗證
    String bio = u.getBio();       // bio 從未套用 @Size/@Length 規則
    repo.save(u);                 // 超長/含控制字元的 bio 照存 => 儲存後 XSS 來源
}`,
		fixed: `// 安全寫法:用框架宣告全部欄位規則,並在資料進核心前強制驗證、以框架拒絕不符者
public class User {
    @NotBlank @Size(max=64)  String name;
    @Size(max=2000)          String bio;   // bio 也被框架蓋到
}
public void create(@Valid User u) {        // @Valid 觸發框架驗證
    repo.save(u);                         // 不符者由框架擋下
}`,
		patch: `@@
- public void create(User u) {
-     String bio = u.getBio();
-     repo.save(u);
- }
+ public class User {
+     @NotBlank @Size(max=64) String name;
+     @Size(max=2000)        String bio;
+ }
+ public void create(@Valid User u) {   /* 框架強制觸發驗證 */
+     repo.save(u);
+ }`,
		refs: ['CWE-1173', 'OWASP'],
		tags: ['validation', 'framework', 'bean-validation', 'input'],
	},
	{
		id: 'CWE-1174',
		name: 'ASP.NET Misconfiguration: Improper Model Validation',
		lang: 'csharp',
		status: 'Complete',
		what: `ASP.NET 組態不當:「模型驗證」使用不當。ASP.NET 應用沒有或不正確地使用它的 model validation
	框架——例如某些 action 沒讓 [ApiController] 的自動驗證生效、忘了檢查 ModelState.IsValid、或只驗部分屬性。
	成因是資料綁定預設放行、沒在每個 API 統一掛驗證。具體後果是:不具 [Required]/[Range] 或標了但仍被
	忽略的欄位乖乖綁進模型,之後以「已驗證」的名義寫進 DB 或拿去決定權限;ModelState 沒檢查時框架照樣執行
	handler,把非法輸入帶進敏感商務邏輯,引發注入、越權或驗證錯誤導致的當機。修法是讓模型屬性以
	DataAnnotations 宣告規則、進入 action 前檢查 ModelState.IsValid、不合法即回 400,並用框架產生一致的錯誤
	回應。`,
		problem: `// 不安全寫法:controller 沒檢查 ModelState / 沒驗證標記,非法輸入直接過
[ApiController]
public class UserApi : ControllerBase {
  [HttpPost]
  public IActionResult Create(string name, int age) {   // 無驗證、無 ModelState 檢查
      db.Users.Add(new User { Name = name, Age = age }); // age=-5、name="" 照存
      return Ok();
  }
}`,
		fixed: `// 安全寫法:用 DataAnnotations + 檢查 ModelState,不合法回 400
public class UserCreate {
  [Required][StringLength(64)] public string Name { get; set; }
  [Range(1, 120)]            public int Age { get; set; }
}
[ApiController]
public class UserApi : ControllerBase {
  [HttpPost]
  public IActionResult Create([FromBody] UserCreate m) {
      if (!ModelState.IsValid) return BadRequest(ModelState);   // 非法即 400
      db.Users.Add(...);
      return Ok();
  }
}`,
		patch: `@@
- public IActionResult Create(string name, int age) {
-     db.Users.Add(new User { Name = name, Age = age });
-     return Ok();
+ public class UserCreate {
+   [Required][StringLength(64)] public string Name { get; set; }
+   [Range(1,120)]             public int Age { get; set; }
+ }
+ public IActionResult Create([FromBody] UserCreate m) {
+   if (!ModelState.IsValid) return BadRequest(ModelState);   /* 非法即 400 */
+     db.Users.Add(...);
+     return Ok();
  }`,
		refs: ['CWE-1174', 'OWASP'],
		tags: ['aspnet', 'modelstate', 'validation', 'datannotation'],
	},
	{
		id: 'CWE-1187',
		name: 'DEPRECATED: Use of Uninitialized Resource',
		lang: 'text',
		status: 'Deprecated',
		what: `本條目已棄用(Deprecated)。原因:它是 CWE-908(Use of Uninitialized Resource) 的重複條目,
	所有內容皆已移往 CWE-908,本條目不再維護,實務裁判時請勿引用。凡是「未初始化資源」的命題——讀取尚未
	賦值就使用的變數、放任的指標或描述子、依賴殘值——一律查閱並套用 CWE-908。此條保留僅為相容舊文件與
	已發布的證言,因此標記 status:'Deprecated',不再把「使用未初始化資源」歸類到此條。`,
		problem: `// (棄用)本條目不作為裁判;未初始化資源請參考並使用 CWE-908
int boom(void) {
    int v;                 // 未初始化即使用,全屬 CWE-908 範疇
    return v + 1;
}`,
		fixed: `// 修法也屬 CWE-908:使用前先賦值,不依賴未定型的值
int safe(void) {
    int v = 0;            // 使用前初始化 => 以 CWE-908 解析
    return v + 1;
}`,
		patch: `@@
  int boom(void) {
-     int v;
+     int v = 0;            /* 使用前初始化 */
      return v + 1;
  }`,
		refs: ['CWE-1187', 'CWE-908'],
		tags: ['deprecated', 'uninitialized', 'duplicate', 'cwe-908'],
	},
	{
		id: 'CWE-1189',
		name: 'Improper Isolation of Shared Resources on System-on-a-Chip (SoC)',
		lang: 'verilog',
		status: 'Complete',
		what: `SoC「共享資源隔離不當」。System-on-Chip 沒有在受信任與不受信任的代理(agent)之間正確隔離共享
	資源——例如內建 SRAM、記憶體控制器、回寫快取或中斷被設計成所有 master 直接可用,權限低的不可信 master
	因此得以讀寫到安全域(secure world、安全 CPU、特權韌體)的資料。成因是預設「反正人人可存取」視為無害、
	或為了省效能省掉隔離閘與分區伺服器。具體後果是:一個僅「不可信任的對外 core」只要照常發匯流排交易,就
	能讀到金鑰或上下文、或改寫安全狀態,繞過所有軟體層保護——信任邊界名存實亡。修法是依 agent 信任等級做
	硬體隔離:把記憶體保護與互連規則與 master 身分綁定,不可信端拿不到不該拿的銀行空間。`,
		problem: `// 不安全做法:共享 SRAM 不對 master 做權限判斷,不可信 core 與安全 core 同權
module soc_bus(input clk, input avalid, input [31:0] addr,
              input wr, input [31:0] wdata, input [3:0] masterid);
  sram u_sram(.addr(addr), .wr(wr), .wdata(wdata), .q(q));
  // 沒有依 masterid 查權:A0 的不可信 core 可直接踩安全銀行的位址
endmodule`,
		fixed: `// 安全做法:依 masterid 查核每個 master 的銀行權限,無權即拒絕(硬體隔離共享資源)
module soc_bus(input clk, input avalid, input [31:0] addr, input wr,
              input [31:0] wdata, input [3:0] masterid, output [31:0] q);
  wire acc = (bank_of_w(addr) == SEC_BANK) ? (masterid == SEC_MASTER) : 1'b1;
  // 不可信 master 對安全銀行讀寫被 acc 擋下,無權讀回無效值
endmodule`,
		patch: `@@
- module soc_bus(... masterid);
-   sram u_sram(.addr(addr), .wr(wr), .wdata(wdata), .q(q));
- endmodule
+ module soc_bus(input clk, input avalid, input [31:0] addr, input wr,
+               input [31:0] wdata, input [3:0] masterid, output [31:0] q);
+   wire acc = (bank_of_w(addr)==SEC_BANK) ? (masterid==SEC_MASTER) : 1'b1;
+ endmodule`,
		refs: ['CWE-1189', 'OWASP'],
		tags: ['soc', 'isolation', 'shared-resource', 'secure-world', 'ram'],
	},
	{
		id: 'CWE-1190',
		name: 'DMA Device Enabled Too Early in Boot Phase',
		lang: 'c',
		status: 'Complete',
		what: `DMA 裝置在開機階段「過早」啟用。在安全組態尚未建立之前,產品就把具直接記憶體存取(DMA)
	能力的裝置打開——例如讓 DMA 控制器在 MMU/SMMU、分頁表或記憶體存取控制尚未設定時就能發匯流排主存取。
	成因是 boot loader 想早點讓儲存/網路加速起來,在信任基礎準備好前就寫了啟動位元。具體後果是攻擊者能在
	「安全組態未設」的開窗內,驅動 DMA 從尚未整備的實體記憶體讀金鑰、韌體鏡像,或直接寫入取得執行權並
	持續提權——DMA 可自由掃實體 RAM,等於繞過全部軟體權限。修法是嚴格把 DMA 裝置啟用延後到 I/O 認證、
	記憶體保護域、韌體驗證就緒之後,並以硬體門鎖確保該開機段不可提前開啟。`,
		problem: `// 不安全做法:boot 極早期就把 DMA enable,此時 MMU/記憶體保護未建置
enable_dma_clock();
write_hw(DMA_CTRL, DMA_EN);   // 先開 DMA
init_mmu_and_security();         // 安全組態後到 => 開窗期 DMA 可任登實體記憶體
load_kernel();`,
		fixed: `// 安全做法:先完成 MMU、I/O 認證與記憶體保護域,最後才允許 DMA
init_mmu_and_security();        // 先把信任基礎建好
config_smmu_domains();        // 為 DMA 限身家:只能掃受限域
enable_dma_clock();
write_hw(DMA_CTRL, DMA_EN);  // 安全組態就緒後才許開`,
		patch: `@@
- enable_dma_clock();
- write_hw(DMA_CTRL, DMA_EN);        /* 過早:安全組態未建 */
- init_mmu_and_security();
- load_kernel();
+ init_mmu_and_security();              /* 信任基礎先就緒 */
+ config_smmu_domains();
+ enable_dma_clock();
+ write_hw(DMA_CTRL, DMA_EN);`,
		refs: ['CWE-1190', 'OWASP'],
		tags: ['dma', 'boot', 'smmu', 'memory-protection', 'hardware'],
	},
	{
		id: 'CWE-1191',
		name: 'On-Chip Debug and Test Interface With Improper Access Control',
		lang: 'verilog',
		status: 'Complete',
		what: `晶片「除錯／測試介面」的存取控管不當。晶片沒有實作或沒有正確執行存取控管,去驗證誰透過
	實體 Debug/Test 介面(如 JTAG TAP、掃描鏈、trace port)被授權讀取內部暫存器與測試模式。成因是量產前
	把 debug 全開方便驗證,量產後忘了以 security fuse/授權碼關掉或鎖定。具體後果是:任何拿到實體接近權人都
	能透過該介面停止 CPU、讀寫任何內部暫存器與金鑰、掃描鏈還可切進測試模式改寫權限位元——等同晶片上的硬體
	後門,幾乎解除整套安全機制。修法是製造前以 security fuse 關閉未授權 TAP、要求授權碼/公鑰驗證才能入
	test mode,並以 lock pin 禁止 scan chain 外洩。`,
		problem: `// 不安全做法:JTAG TAP 完全開放,任何實體接線者都能進 test mode 讀寫讀內部暫存器
module tap_soc(input tck, input tms, input tdi, output tdo);
  always @(posedge tck)
     scan_shift_en = 1'b1;          // 沒有身分/授權檢查,test mode 全開
endmodule`,
		fixed: `// 安全做法:未通過授權驗證前 debug 存取被 gate,量產以 fuse 鎖死
module tap_soc(input tck, input tms, input tdi, output tdo,
              input security_lock);
  wire authorized = security_lock ? 1'b0 : tap_auth_ok(tms, tdc);
  assign tdo = (authorized) ? tap_shift_out(/*...*/) : 1'bz;
  // security_lock(fuse)熔斷後,永遠拒絕 unauthenticated debug
endmodule`,
		patch: `@@
- module tap_soc(input tck, input tms, input tdi, output tdo);
-    always @(posedge tck) scan_shift_en = 1'b1;   /* 全開 no auth */
- endmodule
+ module tap_soc(..., input sec_lock);
+    wire authorized = sec_lock ? 1'b0 : tap_auth_ok(tms, tdc);
+    assign tdo = authorized ? tap_shift_out(...) : 1'bz; /* 授權才開 */
+ endmodule`,
		refs: ['CWE-1191', 'OWASP'],
		tags: ['jtag', 'debug', 'test-mode', 'fuse', 'hardware'],
	},
	{
		id: 'CWE-1192',
		name: 'Improper Identifier for IP Block used in System-On-Chip (SOC)',
		lang: 'verilog',
		status: 'Complete',
		what: `SoC 中「IP 區塊識別符不當」。SoC 沒有為各元件提供唯一、不可變的識別符(ID/rev/型號),或
	提供的是可由程式偽造的識別。成因是把識別做成韌體可寫的暫存器、或共用稀疏的 partition ID、或量產時沒
	固化 production ID。具體後果是:系統與外部無法可靠分辨硬體能力與版本,授權邏輯若依賴該 ID 就可能被假身分
	騙過(偽稱較低資安版本騙過更新門檻、或偽裝成不敏感組件繞過策略);資產盤點、供應鏈稽核與憑證綁定也
	失準。修法是給每顆 IP 用 OTP/保險絲熔斷的唯獨、全域唯一識別碼,任何運行期都不能被改寫或偽造。`,
		problem: `// 不安全做法:IP/版本識別是可寫暫存器,冒牌可改寫成「別顆」
module ip_id(input clk, input [7:0] setid, input wen);
  reg [7:0] id_reg;
  always @(posedge clk) if (wen) id_reg <= setid;  // 可被覆寫 => 身分可偽造
  assign cpu_id = id_reg;
endmodule`,
		fixed: `// 安全做法:生產後以唯讀/保險絲給獨一識別,運行期無法改寫
module ip_id(output [7:0] cpu_id);
  // OTP/保險絲固化:量產時唯一、永不可寫;無 wen 埠、無寫通道
  reg [7:0] id_reg; initial id_reg = 8'h2A;   // 實際以 OTP 產生
  assign cpu_id = id_reg;
endmodule`,
		patch: `@@
- module ip_id(input clk, input [7:0] setid, input wen);
-    reg [7:0] id_reg;
-    always @(posedge clk) if (wen) id_reg <= setid;  /* 可覆寫 */
-    assign cpu_id = id_reg;
+ module ip_id(output [7:0] cpu_id);
+    reg [7:0] id_reg; initial id_reg = 8'h2A;  /* OTP 固化,無寫通道 */
+    assign cpu_id = id_reg;
  endmodule`,
		refs: ['CWE-1192', 'OWASP'],
		tags: ['soc', 'id', 'otp', 'unforgeable', 'hardware'],
	},
	{
		id: 'CWE-1193',
		name: 'Power-On of Untrusted Execution Core Before Enabling Fabric Access Control',
		lang: 'c',
		status: 'Complete',
		what: `「不可信執行核心」在開機制(fabric)存取控管啟用前就先上電。產品把含不可信韌體的運算核心
	先啟動,直到它開始執行、可能已透過記憶體與 on-chip fabric 走過一輪,才啟用對這些資源的存取控管。成因是
	電源序列把使用者端 core 排在前、把 fabric access control host(SMMU、firewall、bus ownership)排在後。具體
	後果是:不可信 core 在防護未生效的空窗內自由讀寫記憶體與外設——能預先藏好資料、重寫某安全區、或竄改
	隨後要載入的組態,讓之後才啟用的控管建立在被污染的初始狀態上。修法是電源/信任化序列嚴格把 fabric access
	control 的初始化排在不可信 core 首次可用之前。`,
		problem: `// 不安全做法:先上電並跑不可信 core,再設存取控管(fabric 控管後到)
power_on_untrusted_core();      // 它一上路就能踩記憶體,控管還沒上
init_fabric_access_control();    // 太遲:不可信 core 早已進行可寫操作
jump_to_untrusted_code();`,
		fixed: `// 安全做法:fabric 存取控管、記憶體安全域先就緒,才上電不可信 core
init_fabric_access_control();    // 先設 firewall/SMMU 域與起始 policy
prime_safety_domains();
power_on_untrusted_core();     // 才讓不可信 core 有受控的資源面
jump_to_untrusted_code();`,
		patch: `@@
- power_on_untrusted_core();
- init_fabric_access_control();
- jump_to_untrusted_code();
+ init_fabric_access_control();   /* 控管先於不可信 core 可用 */
+ prime_safety_domains();
+ power_on_untrusted_core();
+ jump_to_untrusted_code();`,
		refs: ['CWE-1193', 'OWASP'],
		tags: ['power-on', 'fabric', 'smmu', 'firewall', 'boot'],
	},
	{
		id: 'CWE-1204',
		name: 'Generation of Weak Initialization Vector (IV)',
		lang: 'c',
		status: 'Complete',
		what: `產生「弱 IV」。產品用某個需要 IV 的密碼原語(CBC、CTR、GCM 等),但產生 IV 的方式不夠
	不可預測或不夠唯一,未達該原語的密碼學要求。成因是拿時間戳、計數器或固定零當 IV,或同一 IV 重用給
	非常多訊息。具體後果依模式而異:批量模式下 IV 可預測會啟動已知明文攻擊、讓 prefix 相同的密文洩漏輸入關係;
	CTR/GCM 重用 IV 直接讓金鑰串流重複,保密與完整性一起崩潰——密文被 XOR 出明文,認證標籤可偽造。修法
	是讓每個加密操作以密碼學安全亂數(CSPRNG)取精確長度 IV,並在協議層嚴格禁止重用。`,
		problem: `// 不安全寫法:以時間戳當 IV,可預測且同一秒內全重用
#include <time.h>
static uint8_t iv[16];
void ctr_enc(const uint8_t *key, const uint8_t *pt, size_t n, uint8_t *ct) {
    uint32_t t = (uint32_t)time(NULL);       // 可預測 IV
    memset(iv, 0, 16); memcpy(iv, &t, 4); // 同一秒內都同 IV => 串流重用
    aesctr(key, iv, pt, n, ct);
}`,
		fixed: `// 安全寫法:以 CSPRNG 每次取唯一 IV,每次加密都不可重復
#include <openssl/rand.h>
void ctr_enc(const uint8_t *key, const uint8_t *pt, size_t n, uint8_t *ct) {
    uint8_t iv[16];
    if (RAND_bytes(iv, sizeof iv) != 1) abort();  // 密碼學隨機,非計數器
    aesctr(key, iv, pt, n, ct);
}`,
		patch: `@@
-     uint32_t t = (uint32_t)time(NULL);
-     memset(iv, 0, 16); memcpy(iv, &t, 4);   /* 可預測/可重用 IV */
-     aesctr(key, iv, pt, n, ct);
+     if (RAND_bytes(iv, sizeof iv) != 1) abort(); /* CSPRNG 唯一 IV */
+     aesctr(key, iv, pt, n, ct);`,
		refs: ['CWE-1204', 'OWASP'],
		tags: ['iv', 'crypto', 'random', 'ctr', 'nonce-reuse'],
	},
	{
		id: 'CWE-1209',
		name: 'Failure to Disable Reserved Bits',
		lang: 'verilog',
		status: 'Complete',
		what: `「保留位元未禁能」就量產。硬體設計中的保留位元(reserved bits)在量產前沒有被關閉或禁用。
	保留位元本來留給未來功能用,設計上不該支撐任何功能性邏輯;但設計者有時為了在生產硬體上悄悄 debug 或
	開發新功能,暗地替這些位元接了功能。具體後果是:任何能寫到這些位元的資料都碰「表面是保留、實則有行為」
	的狀態——可用原本未定義的位元改寫硬體狀態、切進未公開模式、或當成後門控制安全相關暫存器;而稽核對保留
	位元的預期是讀寫無作用,所以偵測不到。修法是量產前把 reserved bits 一律打成無行為(硬接唯讀 0)、不接任何
	變更行為的邏輯、並以硬體檢查確認。`,
		problem: `// 不安全做法:某「保留位元」被偷接了會變更狀態的功能,量產時未禁能
reg  [31:0] cfg_reg;
reg  debug_on;
always @(posedge clk) if (wen) cfg_reg <= wdata;
assign debug_on = cfg_reg[31];     // 位元31給廠內調試用,卻連著功能邏輯
                                  // 未熔斷 => 攻擊者可用保留位元進調試模式`,
		fixed: `// 安全做法:reserved(31)量產熔斷拴死,不接任何功能邏輯,寫入無效
reg  [31:0] cfg_reg;
wire debug_locked = OTP_RESERVED_LOCK;    // 保險絲將保留位元禁能
assign debug_on_pc = debug_locked ? 1'b0 : cfg_reg[31]; // 保留位元無功能行為
always @(posedge clk) if (wen && !reserved_hw_block) cfg_reg <= wdata;`,
		patch: `@@
- assign debug_on = cfg_reg[31];      /* 保留位元已接功能 */
+ wire debug_locked = OTP_RESERVED_LOCK;    /* 量產熔斷 */
+ assign debug_on_pc = debug_locked ? 1'b0 : cfg_reg[31];
  always @(posedge clk)
-   if (wen) cfg_reg <= wdata;
+   if (wen && !reserved_hw_block) cfg_reg <= wdata;`,
		refs: ['CWE-1209', 'OWASP'],
		tags: ['reserved-bits', 'hardware', 'backdoor', 'fuse'],
	},
	{
		id: 'CWE-1220',
		name: 'Insufficient Granularity of Access Control',
		lang: 'c',
		status: 'Complete',
		what: `「存取控管的粒度不足」。產品用某個 policy/功能實作存取控管,本意是停用或不許不可信代理對
	系統內資產的讀寫;但粒度不足——too coarse——讓策略太寬,使未授權代理仍能對安全敏感資產做不該做的存取。
	成因常是只分「整顆硬體域開/關」、粒度只到 bank 不到單一暫存器、或只看 who 有權而漏了「這資料流的
	讀/寫差別」。具體後果是最終 policy 是一大把「都允許」,原本要擋的窄用途在「某域可寫」下全通過,最小
	權限原則失效;審計也無從表達「究竟誰能碰哪一格」。修法是讓控管細到每資產、每操作粒度:列每一 master 對
	每一 region 的 R/W 位元,以最小權限生成 policy。`,
		problem: `// 不安全做法:控管只到「整顆外設域」,不細分讀寫與暫存器
unsigned is_allowed(unsigned master) {
    return (master == A0);      // 只要 master==A0 就放行對整個 UART 域
}
// 但 A0 也因此有權寫 UART 的「模式/中斷控制」等敏感暫存器 -- 粒度過粗`,
		fixed: `// 安全做法:細到 master x 區域 x 讀/寫 位元,最小權限
#define U_CTRL (1u<<0)  /* 控制暫存器 */
#define U_DATA (1u<<1)
unsigned can_write(unsigned master, unsigned reg) {
    if (master == A0) return wmask[reg] & U_DATA;  // A0 只能寫 DATA,不能碰 CTRL
    return 0;
}`,
		patch: `@@
- unsigned is_allowed(unsigned master) {
-     return (master == A0);                 /* 域級粒度,過粗 */
- }
+ #define U_CTRL (1u<<0) /* 控制暫存器 */
+ #define U_DATA (1u<<1)
+ unsigned can_write(unsigned master, unsigned reg) {
+     if (master == A0) return wmask[reg] & U_DATA; /* 細到 暫存器 x R/W */
+     return 0;
+ }`,
		refs: ['CWE-1220', 'OWASP'],
		tags: ['access-control', 'granularity', 'least-privilege', 'policy'],
	},
	{
		id: 'CWE-1221',
		name: 'Incorrect Register Defaults or Module Parameters',
		lang: 'verilog',
		status: 'Complete',
		what: `「暫存器預設值／模組參數」錯誤設成不安全值。硬體描述語言(HDL)程式把暫存器預設值或 IP
	模組參數設成不安全的內容。成因是把某個對外部除錯友善的初值帶進量產預設——把「看門狗關閉」「安全鎖=0」
	「測試模式初開」設成 reset 後預設、或 parameter 給寬鬆的允許值。具體後果是系統一復位就處在不安全狀態:
	必要防護未啟動的開機視窗、或一開機所有 agent 都具特權的初始預設,直到(可能永遠)有韌體去改;若韌體
	假設「預設即安全」而省去設定,漏洞就維持整個生命週期。修法是讓 reset 預設值與模組參數一律採「最安全的
	初始值」:防護開啟、鎖上、測試模式關、寬度與允許值取最小,並在驗證中明列 reset 值。`,
		problem: `// 不安全做法:reset 後就把安全相關防護「關掉」(看門狗 off、鎖=0)
parameter WDT_DISABLE = 1'b1;        // 預設就讓看門狗停用
reg  secure_lock;
always @(posedge clk or posedge rst)
  if (rst) secure_lock <= 1'b0;       // reset 後安全鎖未上 => 啟動窗口無防護`,
		fixed: `// 安全做法:reset 預設/參數採最安全初始值:防護開、鎖上
parameter WDT_DISABLE = 1'b0;       // 預設看門狗在運行
always @(posedge clk or posedge rst)
  if (rst) secure_lock <= 1'b1;      // 復位即上鎖,直到韌體具授權才釋放
// factory/debug 參數在量產調校時切成鎖定值`,
		patch: `@@
- parameter WDT_DISABLE = 1'b1;          /* 預設關防護 */
- if (rst) secure_lock <= 1'b0;           /* 復位未上鎖 */
+ parameter WDT_DISABLE = 1'b0;          /* 預設看門狗在運行 */
+ if (rst) secure_lock <= 1'b1;           /* 復位即上鎖 */`,
		refs: ['CWE-1221', 'OWASP'],
		tags: ['hdl', 'register-default', 'parameter', 'safe-default', 'hardware'],
	},
];
