// CWE chunk — 類別:硬體設計安全性弱點與韌體/密碼健壯性（Hardware Security Design, Firmware & Crypto）
// 補齊官方 v4.20 中手冊原本缺漏的 Base/Variant 條目(硬體 lock/fuse、側信道、記憶體保護、韌體與密碼)
export default [
	{
		id: 'CWE-1222',
		name: 'Insufficient Granularity of Address Regions Protected by Register Locks',
		lang: 'c',
		status: 'Complete',
		what: `受暫存器鎖護衛的位址區間粒徑不足。硬體用同一個 register lock 控制位元把一整大塊位址區間一起鎖住,目的是防止開機後又被軟體改動。但這塊區間裡有些位址在正常執行期間本來就必須允許軟體寫入(例如睡眠/喚醒、動態參數),而安全要求又規定系統組態鎖位元必須在開機流程中就設好搶先鎖上,兩者互相衝突。開發者為了保住功能性往往得在開機後偷偷解鎖,或壓根不敢真正鎖上,令鎖杄保護形同虛設。成因是保護粒徑太粗,把「該鎖死的敏感暫存器」與「執行期需可寫的暫存器」綁在同一把鎖底下。修法是把每一條真正該在開機後保持不變的敏感暫存器用更細的保護區間與各自的 lock bit 管理,讓「開機鎖住」與「執行中可寫」兩種需求各得其所,互不衝突。`,
		problem: `// 不安全寫法:整塊位址區域共用同一個 lock bit,含執行期仍必須可寫的暫存器
#define CFG_BASE        0x40000000
#define REG_SLEEP       0x04   // 執行期必須可寫(睡眠/喚醒控制)
#define REG_OTP_KEY     0x10   // 開機後不該再被改
#define LOCK_CFG_ALL    (1u << 0)   // 一次鎖住整塊 CFG 區域

void cfg_init(void) {
    // 開機鎖整塊 => REG_SLEEP 從此也不能寫,許可了要解鎖或索性不鎖
    write_reg(CFG_BASE + 0xF0, LOCK_CFG_ALL);
}`,
		fixed: `// 安全寫法:細分保護區,同一把鎖只管真正敏感的位址,軟體用暫存器獨立可寫
#define LOCK_SENSITIVE  (1u << 0)   // 只鎖住敏感位址區(OTP_KEY/安全控制)
#define LOCK_CONTROL    (1u << 1)   // 控制區不受 LOCK_SENSITIVE 波及

void cfg_init(void) {
    // 只對敏感區下鎖;REG_SLEEP 位址不在受鎖範圍,執行期仍可寫
    write_reg(CFG_BASE + 0xF0, LOCK_SENSITIVE | LOCK_CONTROL);
}`,
		patch: `@@
 void cfg_init(void) {
-    write_reg(CFG_BASE + 0xF0, LOCK_CFG_ALL);   // 整塊全鎖,執行期可寫位址也被鎖死
+    write_reg(CFG_BASE + 0xF0, LOCK_SENSITIVE | LOCK_CONTROL); // 只鎖敏感區
 }`,
		refs: ['CWE-1222', 'OWASP'],
		tags: ['hardware-lock', 'register-lock', 'granularity', 'secure-config', 'platform'],
	},
	{
		id: 'CWE-1223',
		name: 'Race Condition for Write-Once Attributes',
		lang: 'c',
		status: 'Complete',
		what: `write-once(只可寫一次)屬性暫存器落入競態。硬體規定某些安全屬性或組態只能在開機初期設一次,之後就鎖定;但實作沒有保證「第一個寫入的」是可信的初始化程式碼。啟動時序若讓不可信任的軟體組件比可信開機碼更早執行,它就能搶先對這個 write-once 暫存器寫入,把安全狀態設錯或在可信碼還來不及設定之前就把它鎖進一個不安全的決策;輪到真正的可信程式要設定時已永久封死、無從挽回。成因是設定時序缺乏序列化與授權,把「唯一一次機會」留給任何先存取的人都行。修法是讓這類暫存器交由不可被他人先行觸碰的階段(整合區的 Boot ROM / 安全控制器)在可信碼開始執行的一瞬間程式化並鎖定,並在解鎖前以硬體拒絕一切未授權的寫入企圖。`,
		problem: `// 不安全寫法:write-once 暫存器任由先到達的 agent 搶先寫入,沒有來源與時序管制
// boot 序列不保證先寫的是可信碼 => 不可信組件可搶先鎖死成不安全狀態
void early_agent_touch(void) {
    if (probe_bus() == FROM_UNTRUSTED) {
        // 競態:在可信開機碼之前就把 secure state 寫成 DISABLED 並鎖死
        write_once_reg(SEC_STATE, STATE_DISABLED);   // 從此無法改回
    }
}`,
		fixed: `// 安全寫法:write-once 交由可信 Boot ROM 在序列化後的開機流程第一步就設定
// 硬體層:任何非可信來源對該暫存器的寫入都在解鎖前被忽略
void secure_boot_start(void) {
    // 單一執行者、無競態;率先程式化並鎖定安全狀態
    set_master(BOOT_ROM);
    write_once_reg(SEC_STATE, STATE_SECURE);   // 只有外部 reset 能重開此窗
    lock_write_once(SEC_STATE);
}`,
		patch: `@@
-void early_agent_touch(void) {
-    if (probe_bus() == FROM_UNTRUSTED) {
-        write_once_reg(SEC_STATE, STATE_DISABLED);
-    }
-}
+void secure_boot_start(void) {
+    set_master(BOOT_ROM);
+    write_once_reg(SEC_STATE, STATE_SECURE);
+    lock_write_once(SEC_STATE);   // 率先寫入並鎖死,免除競態
+}`,
		refs: ['CWE-1223', 'OWASP'],
		tags: ['write-once', 'race-condition', 'boot-order', 'hardware', 'one-time-programmable'],
	},
	{
		id: 'CWE-1224',
		name: 'Improper Restriction of Write-Once Bit Fields',
		lang: 'c',
		status: 'Complete',
		what: `write-once / sticky bit 欄位實作不當,仍可被軟體重新程式化。硬體原意用「黏住第一次值」的欄位鎖存只做一次的決策——例如組態鎖、除錯關閉、熔絲模擬——之後軟體不能再改。但若該欄位只是個一般可寫暫存器位元,軟體就能在任意時刻把它寫回未設定的初值,或藉清理路徑把它清掉;受它之前保障的一次性決策便會被軟體自行推翻。成因是把「write-once」做成了「隨時可寫」的一般暫存器,硬體沒有鎖存住設定後的值。修法是讓欄位具備真正的 sticky 語意:第一次寫入後,內部邏輯置位並鎖存,讀寫介面不再提供把它清除的路徑,軟體只能讀取、永遠無法還原到未設定狀態。`,
		problem: `// 不安全寫法:sticky bit 放在一般可寫暫存器,軟體可事後清除 => 一次性決策被推翻
#define CTRL_SECURE_LOCK  (1u << 3)   // 宣稱是 write-once 安全位元
// 但 CTRL 暫存器本身可任意寫回:
void bypass_lock(void) {
    write_reg(CTRL, read_reg(CTRL) & ~CTRL_SECURE_LOCK);   // 直接拆掉鎖 => 軟體翻盤
}`,
		fixed: `// 安全寫法:sticky 鎖存在硬體邏輯裡,寫回初始值也不會被清除
// RTL:lock bit 一旦 set,介面層只可讀,write 對該位元無效(write-ignore)
void program_lock(void) {
    // 嘗試清除 write_clear 對 sticky bit 沒有作用;僅有硬體 reset 能重設
    write_reg(CTRL, CTRL_SECURE_LOCK);          // 設定
    write_reg(CTRL, read_reg(CTRL) & ~CTRL_SECURE_LOCK); // 無效,值仍保留
}`,
		patch: `@@
-void bypass_lock(void) {
-    write_reg(CTRL, read_reg(CTRL) & ~CTRL_SECURE_LOCK);
-}
+void program_lock(void) {
+    write_reg(CTRL, CTRL_SECURE_LOCK);
+    // 後續 write-clear 對 sticky bit 無效,僅硬體 reset 能重設
+}`,
		refs: ['CWE-1224', 'CWE-1223'],
		tags: ['write-once', 'sticky-bit', 'lock', 'hardware', 'reprogram'],
	},
	{
		id: 'CWE-1230',
		name: 'Exposure of Sensitive Information Through Metadata',
		lang: 'node',
		status: 'Complete',
		what: `透過中繼資料(metadata)洩露敏感資訊。程式雖然擋住了對敏感資源的直接存取,卻沒有同等限制那些「由原始敏感資訊衍生」的 metadata——例如受保護檔的縮圖、搜尋索引的摘要、知道答覆的訊息(欄位存在、長度、型別)、或只切出一段預覽的端點。攻擊者只要重複查詢這些衍生表示,就能拼湊、還原出與原資料接近的內容,從而在不觸碰「禁止的路徑」下得到相同的價值,等於繞過了直接存取的防線。成因是只把授權檢查做在原始通道,沒對所有能導出內容的衍生表示一起上鎖。修法是建立統一的資源存取清單,凡能從機密導出內容的表示(縮圖/預覽/摘要/錯誤訊息)一律比照原始資源的權限檢查,並對敏感資料做最小化揭露(不回顯存在與否、長度、欄位結構)。`,
		problem: `// 不安全寫法:主資源檢查了權限,但「摘要/預覽」端點沒檢查就回傳衍生自機密的內容
const { readFileSync } = require('fs');

function preview(req, res) {
  const path = req.params.id;
  // 只有預覽端點做了權限檢查,卻把整段敏感內容當摘要回傳
  if (!allowed(currentUser, path)) return res.status(403).end();
  const body = readFileSync('/private/' + path, 'utf8');
  res.send(body.slice(0, 4000));   // 衍生 metadata 洩露出原敏感內容
}`,
		fixed: `// 安全寫法:凡能導出內容的表示都套同一份權限清單,且不洩露存在/長度
const { readFileSync } = require('fs');

function preview(req, res) {
  const path = req.params.id;
  const canRead = allowed(currentUser, path);
  if (!canRead) return res.status(404).end();      // 不洩露資源是否存在
  const body = readFileSync('/private/' + path, 'utf8');
  res.send(redact(body).slice(0, 200));            // 最小化 + 去識別化後才回
}`,
		patch: `@@
 function preview(req, res) {
   const path = req.params.id;
-  if (!allowed(currentUser, path)) return res.status(403).end();
+  const canRead = allowed(currentUser, path);
+  if (!canRead) return res.status(404).end();
   const body = readFileSync('/private/' + path, 'utf8');
-  res.send(body.slice(0, 4000));
+  res.send(redact(body).slice(0, 200));
 }`,
		refs: ['CWE-1230', 'OWASP'],
		tags: ['metadata', 'information-disclosure', 'preview', 'leak', 'access-control'],
	},
	{
		id: 'CWE-1231',
		name: 'Improper Prevention of Lock Bit Modification',
		lang: 'c',
		status: 'Complete',
		what: `沒有防止 lock bit 在設定後又被修改。硬體用一個可信的 lock bit 來限制對暫存器、位址區或其他資源的存取,卻沒有禁止軟體在鎖定之後再把這個 lock bit 的值寫成「未鎖」。只要鎖暫存器是普通可讀寫的,任何想更動受保護資源的程序都能順手把鎖清掉——開機時費力設進的安全狀態因此隨時可以被拆掉。成因是把鎖設計成一般的 read-write 暫存器,而不是單向的 one-way 機制。修法是讓 lock bit 帶 set-only 語意:一旦被設定,後續所有軟體寫入都不能把它清成 unlock,只有硬體週邊的 reset 能重置,使「鎖上」之後的狀態對軟體來說是不可逆的。`,
		problem: `// 不安全寫法:鎖暫存器可被軟體直接寫回 0 解鎖
#define LOCK_CTRL  0x50
#define LOCK_BIT   0x01

void unlock_regs(void) {
    // 鎖只是普通可寫位元,直接就能把狀態改回未鎖
    write_reg(LOCK_CTRL, read_reg(LOCK_CTRL) & ~LOCK_BIT);
}`,
		fixed: `// 安全寫法:lock bit 僅可被設定,軟體不能清除;唯有硬體 reset 能重設
// RTL:locked = 1 後 write 對該位元一律 write-ignore(除非 reset)
void lock_regs(void) {
    write_reg(LOCK_CTRL, LOCK_BIT);                 // 設定成功
    // 若此時再嘗試 write-clear,該位元不會變動(one-way / sticky)
    return;
}`,
		patch: `@@
-void unlock_regs(void) {
-    write_reg(LOCK_CTRL, read_reg(LOCK_CTRL) & ~LOCK_BIT);
-}
+void lock_regs(void) {
+    write_reg(LOCK_CTRL, LOCK_BIT);   // set-only,軟體清除無效
+}`,
		refs: ['CWE-1231', 'CWE-1224'],
		tags: ['lock-bit', 'one-way', 'hardware', 'sticky', 'register'],
	},
	{
		id: 'CWE-1232',
		name: 'Improper Lock Behavior After Power State Transition',
		lang: 'c',
		status: 'Complete',
		what: `電源狀態轉換之後鎖的行為不當。register lock 的保護只覆蓋「正常運作」區段,一旦平台進入低功耗睡眠模式再被喚醒(power state transition),部分受保護的暫存器或 lock bit 本身又變回可程式化,而系統沒有在喚醒的第一時間把它們重新鎖上。於是在喚醒後的一段視窗裡,軟體就能改動那些開機時本該鎖死的系統組態,開機建立的保護被省電路徑悄悄清掉了。成因是省電流程在保存/喚醒暫存器狀態時順帶繞過或沒有保存 lock,喚醒碼也未重鎖。修法是讓 lock 狀態跨電源狀態持續保留,或在喚醒後由可信流程於第一時間重鎖,並對「喚醒後仍可程式化」的視窗加上授權檢查,不讓低功耗變成開啟組態改寫的後門。`,
		problem: `// 不安全寫法:暫存器隨睡眠/喚醒被還原,但 lock 沒被重新設定
#define CFG_LOCK  0x20
#define LOCK_STATE_REG  0x24

void wake_from_sleep(void) {
    restore_saved_context();          // 暫存器被還原,但鎖狀態沒有被再次設定
    // 喚醒後 lock 失效 => 開機時建立的保護在省電後悄然消失
}`,
		fixed: `// 安全寫法:喚醒流程第一時間重新上鎖,鎖狀態也納入保存/還原
#define CFG_LOCK  0x20

void wake_from_sleep(void) {
    restore_saved_context();
    write_reg(CFG_LOCK, read_reg(CFG_LOCK) | LOCK_ALL);  // 喚醒立即重鎖
}`,
		patch: `@@
 void wake_from_sleep(void) {
     restore_saved_context();
+    write_reg(CFG_LOCK, read_reg(CFG_LOCK) | LOCK_ALL);   // 喚醒立即重鎖
 }`,
		refs: ['CWE-1232', 'CWE-1231'],
		tags: ['power-state', 'sleep', 'lock', 'hardware', 'wake'],
	},
	{
		id: 'CWE-1233',
		name: 'Security-Sensitive Hardware Controls with Missing Lock Bit Protection',
		lang: 'c',
		status: 'Complete',
		what: `安全敏感的硬體控制缺少 lock bit 保護。產品用了 register lock bit 保護機制,卻沒有確保這個鎖真的罩住所有會變更系統重要組態的暫存器與控制——例如某組暫存器上了鎖,但旁支的其它控制暫存器、或同模組內未被列入鎖範圍的關鍵位元仍然可寫。軟體鎖上之後,攻擊者(或錯誤韌體)仍可經由那些「沒被鎖」的開口改動組態,lock 的保護是選擇性、不完整的。成因是 lock bit 的防護範圍與「可變更敏感組態」的全部通路沒有完整對齊,缺少覆蓋度驗證。修法是先窮舉所有可更動重要硬體組態的控制,逐條確認受 lock 管轄,並在建構/測試階段做「lock 有效覆蓋率」檢查,施行任何未列入 lock 的可寫控制一律視為缺陷。`,
		problem: `// 不安全寫法:有 lock bit,但某些敏感控制不在鎖的覆蓋範圍
#define CTRL_LOCKED  0x10    // 上了鎖的核心控制
#define CTRL_UNLOCKED_EXTRA  0x18   // 卻漏鎖了另一個可變更組態的控制

void harden(void) {
    write_reg(CTRL_LOCKED, LOCK_ALL);     // 鎖下後,漏網的 CTRL_UNLOCKED_EXTRA 仍可寫
}`,
		fixed: `// 安全寫法:先讓所有敏感控制都納入鎖的防護範圍再上鎖
void harden(void) {
    // 覆蓋檢查:凡可變更重要組態的控制都必須受 lock 管轄
    assert(is_covered(CTRL_LOCKED));
    assert(is_covered(CTRL_UNLOCKED_EXTRA));   // 漏管的控制也一併納入
    write_reg(CTRL_LOCKED, LOCK_ALL);
    write_reg(CTRL_UNLOCKED_EXTRA, LOCK_SEC);  // 完整覆蓋後才鎖
}`,
		patch: `@@
 void harden(void) {
-    write_reg(CTRL_LOCKED, LOCK_ALL);
+    assert(is_covered(CTRL_LOCKED));
+    assert(is_covered(CTRL_UNLOCKED_EXTRA));
+    write_reg(CTRL_LOCKED, LOCK_ALL);
+    write_reg(CTRL_UNLOCKED_EXTRA, LOCK_SEC);   // 沒漏管的控制也入鎖
 }`,
		refs: ['CWE-1233', 'CWE-1231'],
		tags: ['lock-bit', 'hardware', 'coverage', 'security-control', 'register'],
	},
	{
		id: 'CWE-1234',
		name: 'Hardware Internal or Debug Modes Allow Override of Locks',
		lang: 'verilog',
		status: 'Complete',
		what: `硬體內部或除錯模式允許覆寫鎖。晶片為了測試與除錯提供內部/除錯模式,這些模式往往擁有更高的權限、可以直接改臨除錯介面與掃描等設施;如果除錯模式沒有與安全性互斥——即進入除錯時 lock bit 保護被直接 bypass——那麼拿到除錯入口的人就能繞過系統組態的鎖定:把受保護暫存器改回可寫、把安全狀態改回不安全,甚至把金鑰區域開啟。成因是除錯優先權被設計成「覆蓋一切安全」而沒有任何身份驗證或管制。修法是讓除錯模式不自動覆寫安全鎖:除錯必須經過授權(如 authentication/fuse-gated debug unlock),且在除錯執行時安全保護(記憶體/金鑰)仍然有效,或除錯前先銷毀機密,避免把鎖的保護當成可被測試開關移除的東西。`,
		problem: `// 不安全寫法:debug mode 直接把 security lock 遮罩掉,未經授權即可覆寫保護
// RTL
always @(posedge clk) begin
    if (debug_en) begin
        cfg_lock <= 1'b0;      // 除錯直接取消系統鎖,金鑰/組態全可寫
    end
end`,
		fixed: `// 安全寫法:除錯必須授權通過且不覆寫安全鎖
// RTL:只有 authenticated debug 且該位址非受保護區時才放行
always @(posedge clk) begin
    if (debug_en && debug_authenticated) begin
        cfg_lock <= cfg_lock;      // 鎖保持,不因除錯而解除
    end
end`,
		patch: `@@
  always @(posedge clk) begin
-    if (debug_en) begin
-        cfg_lock <= 1'b0;
+    if (debug_en && debug_authenticated) begin
+        cfg_lock <= cfg_lock;                   // 除錯不覆寫安全鎖
     end
  end`,
		refs: ['CWE-1234', 'CWE-1244'],
		tags: ['debug-mode', 'lock', 'bypass', 'hardware', 'authentication'],
	},
	{
		id: 'CWE-1235',
		name: 'Incorrect Use of Autoboxing and Unboxing for Performance Critical Operations',
		lang: 'java',
		status: 'Complete',
		what: `效能關鍵操作誤用封箱與拆箱。Java 程式在高效能、高頻的熱路徑裡使用 Integer、Long 這類封箱(object)型別,而不是 int/long 基本型別。每次 ++、比較、算術時,編譯器都必須當場拆箱(unbox)取值、運算完再裝箱(box)包成物件,網路迴圈裡反覆如此會產生大量中間物件與記憶體分配、加重 GC 負擔,熱點(如累加計數、雜湊、大量迴圈演算)被拖到明顯變慢。成因是把物件型別當一般數值直接用,忽略了每次隱含交換的開銷。修法是在效能關鍵的內層迴圈一律使用基本型別,只有需要存入泛型集合或跨越 API 邊界時才做一次轉換,讓熱路徑零裝箱、零臨時物件。`,
		problem: `// 不安全寫法:熱累加迴圈用封箱型別,反覆裝箱/拆箱並產生臨時物件
public long heavySum(int n) {
    Long total = 0L;                 // 封箱型別
    for (int i = 0; i < n; i++) {
        total += i;                  // 每次 = unbox + 加 + box + 新物件
    }
    return total;
}`,
		fixed: `// 安全寫法:迴圈內用基本型別 long,零裝箱開銷,最後才轉一次
public long heavySum(int n) {
    long total = 0L;                 // 基本型別
    for (int i = 0; i < n; i++) {
        total += i;                  // 原生算術,無裝箱/拆箱
    }
    return total;
}`,
		patch: `@@
 public long heavySum(int n) {
-    Long total = 0L;
+    long total = 0L;
     for (int i = 0; i < n; i++) {
-        total += i;
+        total += i;
     }
     return total;
 }`,
		refs: ['CWE-1235', 'OWASP'],
		tags: ['java', 'autoboxing', 'performance', 'primitive', 'hot-loop'],
	},
	{
		id: 'CWE-1239',
		name: 'Improper Zeroization of Hardware Register',
		lang: 'c',
		status: 'Complete',
		what: `硬體暫存器未在使用者交接時清除機密。硬體區塊被切給某個使用者/domain 使用,裡面的內建暫存器(暫存資料、加解密中間值、金鑰暫存)殘留上一手用過的敏感資訊;當硬體區塊的所有人變更(ownership change),例如安全世界中斷、虛擬化切換、或 DMA engine 被其他 agent 接管,沒有對暫存器進行清理(zeroize)。下一手使用者就能在原位讀到上一手的金鑰、資料或中間值,跨信任邊界的資訊洩漏因此發生。成因是缺少「資源釋放即清空」的硬體規範或流程。修法是每一位址相同屬性的暫存器在 ownership 移交、reset、release 時一律清空或依安全等級抹除,並在交還給不可信 agent 前對存放機密的暫存器執行 zeroize 與驗證。`,
		problem: `// 不安全寫法:硬體區塊釋放時不清暫存器,下一個使用者讀到舊機密
void release_hw_block(int owner) {
    release_to(owner);              // 把硬體區塊交接出去
    // 內部暫存器仍留有上一手加解密的中間值與金鑰片段
}`,
		fixed: `// 安全寫法:交接前對存放機密的暫存器執行 zeroize
void release_hw_block(int owner) {
    // 先抹除內建暫存器裡的機密再交接,並驗證確已清空
    zeroize_secure_regs(BLOCK_KEYS);
    zeroize_secure_regs(BLOCK_CONTEXT);
    if (verify_zeroized(BLOCK_KEYS) != 0) fail_security();
    release_to(owner);
}`,
		patch: `@@
 void release_hw_block(int owner) {
+    zeroize_secure_regs(BLOCK_KEYS);
+    zeroize_secure_regs(BLOCK_CONTEXT);
+    if (verify_zeroized(BLOCK_KEYS) != 0) fail_security();
     release_to(owner);
 }`,
		refs: ['CWE-1239', 'CWE-262'],
		tags: ['zeroize', 'hardware-register', 'ownership', 'cleanup', 'key-leak'],
	},
	{
		id: 'CWE-1240',
		name: 'Use of a Cryptographic Primitive with a Risky Implementation',
		lang: 'python',
		status: 'Complete',
		what: `採用高風險實作的密碼學原語。為了滿足加密需求的先前目的,產品用自己的方式實作一個演算法,但卻是「非標準、未經檢驗、或不符規範」的自製實現——例如自創的 XOR/旋轉、改良版的 RSA、homebrew 雜湊,或把某個公開演算法魔改成不安全的變體。這些實作大多缺乏正規的密碼分析,在金鑰管理、填充、邊界條件與側信道上常有致命缺陷,很容易被已知明文、暴力或選擇明文攻擊破解;更糟的是它營造「已加密」的假象,讓人忽視真實風險。成因是為了省依賴、害怕標準庫壓力或抄捷徑。修法是只使用通過長期公開審查的標準演算法與成熟實作(如 PyCryptodome、OpenSSL、Java JCE),由函式庫代辦金鑰協商、模式(如 AES-GCM)與填充細節,不自行拼裝。`,
		problem: `# 不安全寫法:自製的「加密」,未經審查且有規律性,易被破解
def secret_cipher(data, key):
    out = []
    for i, ch in enumerate(data):
        out.append(ch ^ key[i % len(key)])   # 重複金鑰的 XOR,統計分析即破
    return bytes(out)`,
		fixed: `# 安全寫法:使用標準、經審查的函式庫實作(AES-GCM)
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def secret_encrypt(data, key):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    return nonce + tag + ct   # 交給成熟實作處理模式與填充`,
		patch: `@@
-def secret_cipher(data, key):
-    out = []
-    for i, ch in enumerate(data):
-        out.append(ch ^ key[i % len(key)])
-    return bytes(out)
+def secret_encrypt(data, key):
+    nonce = get_random_bytes(12)
+    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
+    ct, tag = cipher.encrypt_and_digest(data)
+    return nonce + tag + ct`,
		refs: ['CWE-1240', 'OWASP'],
		tags: ['crypto', 'custom-crypto', 'homebrew', 'algorithm', 'weak-encryption'],
	},
	{
		id: 'CWE-1241',
		name: 'Use of Predictable Algorithm in Random Number Generator',
		lang: 'java',
		status: 'Complete',
		what: `隨機數產生器使用可預測的演算法。裝置或程式用種子決定、可被倒推的偽隨機演算法產生「隨機值」,例如以時間、計數器或其它可預知狀態當種子的線性同餘產生器,或直接改用非密碼安全的演算法流程。攻擊者只要取得少量樣本或猜中種子,就能完全重現之後的整個序列,於是被當作「隨機」的金鑰、nonce、token 與 challenge 全都被算出來,並未提供任何密碼學上的不可預測性。成因是把一般用途 PRNG 拿來兼任需要亂數的場合。修法是改用密碼學安全亂數產生器(CSPRNG),並以不可預測的熵打底、由作業系統的亂數源(或安全硬體的 TRNG)當種子:Java 用 SecureRandom 預設實作,不自己以時間當種子來推資料。`,
		problem: `// 不安全寫法:以使用者/攻擊者能預知的時間當種子的可預測 PRNG 產生重要 token
Random rng = new Random(System.currentTimeMillis());   // 時間可猜,序列可重現
String token = Integer.toString(rng.nextInt());        // 產生的 token 毫無機密性`,
		fixed: `// 安全寫法:使用密碼學安全亂數 SecureRandom,由作業系統熵源打底
SecureRandom rng = new SecureRandom();              // 由 OS 熵源提供不可預測性
byte[] token = new byte[32];
rng.nextBytes(token);                              // 產生的 token 不可被預測/重現`,
		patch: `@@
-Random rng = new Random(System.currentTimeMillis());
-String token = Integer.toString(rng.nextInt());
+SecureRandom rng = new SecureRandom();
+byte[] token = new byte[32];
+rng.nextBytes(token);`,
		refs: ['CWE-1241', 'CWE-338', 'OWASP'],
		tags: ['rng', 'predictable', 'csprng', 'random', 'secure-random'],
	},
	{
		id: 'CWE-1242',
		name: 'Inclusion of Undocumented Features or Chicken Bits',
		lang: 'verilog',
		status: 'Complete',
		what: `內建未記錄的功能或「chicken bit」。晶片裡藏了未公開、未文件化、只為除錯/測試/內部方便而設的控制與後門機制——例如可由某條序列命令或通訊通道觸發的高權限測試進入點、能一鍵跳過安全檢查的 bypass 位元。這些「chicken bit」一旦留在量產矽上,就成了未經授權行為者入侵系統的入口:攻擊者只要在公開規格之外猜到或探得這個位,就能關掉安全保護、取得特權或進入高權限模式,而且因為它沒有文件,平時不會有人檢查它的狀態。成因是為工程除錯/測試圖方便,把非生產功能留在出貨晶片上而未封閉。修法是徹底移除非必要後門;真正保留的除錯/測試功能必須經由授權機制(如 fuse-gated、需身分驗證)才可開啟,並限縮其能力,禁止任何未記錄、默認開啟的高權限通道存在。`,
		problem: `// 不安全寫法:一個未記錄的 bypass 位元,能把安全檢查整個關掉
// RTL
wire chicken_bypass;      // 未公開,可由序列測式命令寫入 => 攻擊者可觸發
assign secure_ok = (chicken_bypass) ? 1'b1 : real_check_result;`,
		fixed: `// 安全寫法:無未記錄後門;即使測式命令也無法繞過安全檢查
// RTL:bypass 不存在,secure_ok 只由真實檢查結果決定
assign secure_ok = real_check_result & debug_gated_ok;   // 無 bypass 位元`,
		patch: `@@
-wire chicken_bypass;
-assign secure_ok = (chicken_bypass) ? 1'b1 : real_check_result;
+assign secure_ok = real_check_result & debug_gated_ok;   // 移除未記錄後門`,
		refs: ['CWE-1242', 'CWE-1234'],
		tags: ['chicken-bit', 'backdoor', 'undocumented', 'hardware', 'bypass'],
	},
	{
		id: 'CWE-1243',
		name: 'Sensitive Non-Volatile Information Not Protected During Debug',
		lang: 'c',
		status: 'Complete',
		what: `存於非揮發性儲存(fuse)的機敏資訊在除錯時未受保護。裝置把金鑰、身分、機密組態燒進 one-time-programmable 的 fuse(如 eFuse)裡,正常狀態下軟體不能讀取;但一旦進入除錯(test/debug)模式,fuse 的內容被當作可讀的暫存器或掃描鏈直接外露。除錯介面的持有者(或經由掃描/實體探測)就能把整包機密金鑰整批讀走,安全性瞬間潰堤。成因是除錯/測試路徑沒有把 fuse 機密區列入排除白名單,或除錯功能開啟時原本的遮罩被繞過。修法是設計成「進入任何實體除錯/掃描流程之前,先遮罩或銷毀讀取 fuse 機密區的通道」,fuse 機密永遠不經由除錯介面可見,或對除錯進行強制身分驗證後才授予非機密檢視。`,
		problem: `// 不安全寫法:進入除錯模式後,保險絲機密區可被整包讀出
void enter_debug(void) {
    enable_scan();                 // 掃描鏈全開
    debug_read(EFUSE_KEY);         // 除錯介面未遮罩,金鑰全漏
}`,
		fixed: `// 安全寫法:除錯前先遮罩/銷毀 fuse 機密讀取通道
void enter_debug(void) {
    mask_secure_fuse(EFUSE_KEY);        // 除錯模式下 fuse 機密為不可讀
    zeroize_secure_regs(KEY_CACHE);
    enable_scan_only_public();          // 掃描只開放非機密區
}`,
		patch: `@@
 void enter_debug(void) {
+    mask_secure_fuse(EFUSE_KEY);
+    zeroize_secure_regs(KEY_CACHE);
     enable_scan();
-    debug_read(EFUSE_KEY);
+    enable_scan_only_public();
 }`,
		refs: ['CWE-1243', 'CWE-1258'],
		tags: ['fuse', 'debug', 'key-leak', 'hardware', 'non-volatile'],
	},
	{
		id: 'CWE-1244',
		name: 'Internal Asset Exposed to Unsafe Debug Access Level or State',
		lang: 'c',
		status: 'Complete',
		what: `內部資產暴露在不安全的除錯存取等級或狀態。產品使用支援多種存取等級的實體除錯/測試介面(full debug、secure debug、limited debug 等),每個等級應對應不同信任度的除錯代理;但如果某個內部資產——金鑰暫存器、保密 SRAM、安全狀態暫存器——被分派到過低、本不該碰到它的地址別名除錯等級,不可信任的除錯 agent 就能經由那個低階介面讀到原不該看到的東西。成因是資產的安全性分級與除錯存取等級沒有正確對應,或預設等級鬆。修法是為每個內部資產標記「最低允許存取等級」,除錯介面在核準時要求代理等級 ≥ 資產門檻,並將預設設為最低授權;不存在任何「公開等級可達機密資產」的組合。`,
		problem: `// 不安全寫法:秘密資產被預設指派到通用(低等級)除錯存取等級
// 密鑰暫存器被標成 gen_access,任一除錯代理都能讀
set_debug_attr(KEY_REG, DEBUG_LEVEL_GENERAL);   // 過低的存取等級 => 洩漏`,
		fixed: `// 安全寫法:機密資產標記最高門檻,除錯代理等級不足即拒絕
set_debug_attr(KEY_REG, DEBUG_LEVEL_SECURE);     // 只有受信任代理能讀
if (debug_agent.level < req_level(KEY_REG)) deny(KEY_REG); // 等級門檻檢查`,
		patch: `@@
- set_debug_attr(KEY_REG, DEBUG_LEVEL_GENERAL);
+ set_debug_attr(KEY_REG, DEBUG_LEVEL_SECURE);
+ if (debug_agent.level < req_level(KEY_REG)) deny(KEY_REG);`,
		refs: ['CWE-1244', 'CWE-1243'],
		tags: ['debug', 'access-level', 'hardware', 'asset', 'privilege'],
	},
	{
		id: 'CWE-1245',
		name: 'Improper Finite State Machines (FSMs) in Hardware Logic',
		lang: 'verilog',
		status: 'Complete',
		what: `硬體邏輯的有限狀態機(FSM)設計不當。若 FSM 缺少對未定義/保留狀態的處理、狀態轉移表有漏洞、或輸出在非法狀態沒有安全預設值,一旦被非預期輸入觸發,系統就會推進到未定義狀態:可能造成運算錯誤、卡死而阻斷服務(DoS),或被引入較高特權的狀態,讓攻擊者取得不應有的權限。硬體免疫力的核心在於「任何錯態都得有一個明確且安全的下一個狀態」。成因是 state 編碼沒寫全 case 的 next-state 與 default 輸出。修法是在組合式 next state / 輸出邏輯對所有非法與保留編碼提供明確回復目標(跳回 idle/reset),輸出由整組 case 決定(含 default)而非常態下降落,並以工具做完整狀態覆蓋與可達性驗證,證明不可抵達高權限狀態。`,
		problem: `// 不安全寫法:F/FSM 對非法狀態沒有 default,可卡死或誤輸出
// RTL
always @(posedge clk)
    case (state)
        S_IDLE: state <= cmd_valid ? S_BUSY : S_IDLE;
        S_BUSY: state <= done ? S_IDLE : S_BUSY;
        // 沒有 default:碰到錯位(如 2'b11)就停留在未定義狀態 => 卡死
    endcase`,
		fixed: `// 安全寫法:對所有未定義/保留狀態給出安全回復目標
always @(posedge clk)
    case (state)
        S_IDLE: state <= cmd_valid ? S_BUSY : S_IDLE;
        S_BUSY: state <= done ? S_IDLE : S_BUSY;
        default: state <= S_IDLE;      // 任何非法狀態都回復到安全狀態
    endcase`,
		patch: `@@
     case (state)
         S_IDLE: state <= cmd_valid ? S_BUSY : S_IDLE;
         S_BUSY: state <= done ? S_IDLE : S_BUSY;
+        default: state <= S_IDLE;      // 非法/保留狀態一律安全回復
     endcase`,
		refs: ['CWE-1245', 'OWASP'],
		tags: ['fsm', 'finite-state-machine', 'hardware', 'dos', 'undefined-state'],
	},
	{
		id: 'CWE-1246',
		name: 'Improper Write Handling in Limited-write Non-Volatile Memories',
		lang: 'c',
		status: 'Complete',
		what: `可寫次數有限的非揮發記憶體寫入處理不當。NVM(如 NOR/NAND flash)有抹寫次數上限與單元磨損的限制;若韌體反覆把資料(計數器、參數、日誌)寫在同一個邏輯位置,而沒有實作耗損平均(wear leveling),幾個固定位置會被快速寫穿,導致單元磨損、寫入失敗、提早老化,系統甚至無法再保存關鍵安全資料而失去可信度。成因是把 NVM 當「可無限寫的 DRAM」用,固定地址連續覆寫。修法是實作 wear leveling:把邏輯位址動態對映到實體空位、輪換寫入區塊、定期募集/合併被寫穿的區塊,並在抹寫次數接近上限時降級保護與回報,延長壽命並避免安全資料在前面寫壞。`,
		problem: `// 不安全寫法:把計數器老是寫在同一實體位址,快速磨損那幾個單元
void bump_counter(void) {
    uint32_t v;
    nvm_read(FIXED_CTR_ADDR, &v);          // 永遠同一地址
    nvm_erase(FIXED_CTR_ADDR);             //   反覆抹寫同一單元 => 過早耗損
    nvm_write(FIXED_CTR_ADDR, v + 1);
}`,
		fixed: `// 安全寫法:以耗損平均把邏輯位址對映到輪換的實體區塊
void bump_counter(void) {
    int slot = wear_slot_next();            // 依實體抹寫次數選取最低磨損區塊
    nvm_erase(slot);
    nvm_write(slot, cur_value + 1);
    update_mapping(LOGICAL_CTR, slot);     // 邏輯位址重新對映
}`,
		patch: `@@
 void bump_counter(void) {
-    uint32_t v;
-    nvm_read(FIXED_CTR_ADDR, &v);
-    nvm_erase(FIXED_CTR_ADDR);
-    nvm_write(FIXED_CTR_ADDR, v + 1);
+    int slot = wear_slot_next();
+    nvm_erase(slot);
+    nvm_write(slot, cur_value + 1);
+    update_mapping(LOGICAL_CTR, slot);
 }`,
		refs: ['CWE-1246', 'OWASP'],
		tags: ['nvm', 'wear-leveling', 'flash', 'embedded', 'durability'],
	},
	{
		id: 'CWE-1247',
		name: 'Improper Protection Against Voltage and Clock Glitches',
		lang: 'c',
		status: 'Complete',
		what: `對電壓與時脈毛刺(glitch)防護不足。設備沒有包含正確實作的感測器或電路來偵測並抵擋電壓毛刺與時脈毛刺,無法保護內部機密資料與軟體。攻擊者可對電源或時脈線注入精準的短暫毛刺,讓 CPU 於關鍵時刻走漏條件跳轉、跳過檢查(例如跳過密碼驗證、頻果檢查),導致安全決策被繞過而讀走敏感資料或讓保護失效。成因是硬體缺少 fault-injection 防護,軟體也只有單一弱檢查。修法是硬體側加入電壓/時脈感測器、延遲窗比較與毛刺偵測後自動 reset;軟體側對安全決策做控制流強制——重複驗證、循序執行偵測、關鍵檢查多點複檢——讓單一毛刺無法造成可重現的安全繞過。`,
		problem: `// 不安全寫法:安全決策只做「一次檢查」,電壓/時脈毛刺可跳過它
bool verify_auth(void) {
    if (check_token() != OK) return false;   // 單次檢查,毛刺一跳就過
    return true;
}`,
		fixed: `// 安全寫法:多次反覆檢驗 + 毛刺偵測後拒絕與回復
bool verify_auth(void) {
    // 關鍵流程重複檢驗,且在偵測到 glitch 時立即拒絕
    if (!check_token()) return false;
    if (glitch_detector_armed() && glitch_after_entry()) return false;
    if (!check_token()) return false;         // 重複第二遍,單一毛刺無法穩定跳過
    return true;
}`,
		patch: `@@
 bool verify_auth(void) {
-    if (check_token() != OK) return false;
+    if (!check_token()) return false;
+    if (glitch_detector_armed() && glitch_after_entry()) return false;
+    if (!check_token()) return false;
     return true;
 }`,
		refs: ['CWE-1247', 'OWASP'],
		tags: ['glitch', 'fault-injection', 'voltage', 'clock', 'secure-boot'],
	},
	{
		id: 'CWE-1248',
		name: 'Semiconductor Defects in Hardware Logic with Security-Sensitive Implications',
		lang: 'verilog',
		status: 'Complete',
		what: `安全敏感的硬體模組內含半導體缺陷。製程或封裝產生的缺陷(test escapes、缺陷佈局)使安全模組裡某些邏輯單元、暫存器或防護電路行為不正確——例如 fuse 讀錯、安全檢查位元黏在錯誤值、某顆查表記憶體壞位元——而這些缺陷在常規測試下沒被揪出。缺陷在運作時表現不一,可能讓加密結果錯誤、安全保護時好時壞,根本無法信賴。成因是常規(非安全導向)測試對安全相關邏輯的覆蓋率不足,缺陷被放行到量產。修法是對安全模組採取可測試性與可靠性設計:掃描鏈、內建自我測試/BIST、刪冗餘、奇偶與 ECC 保護,在製程測試與每顆開機時做失效偵測與隔離,並在偵得安全相關缺陷時將該單元標記為不可信而拒絕可疑操作。`,
		problem: `// 不安全寫法:安全邏輯沒有自測與冗餘,單一缺陷位元直接破壞安全決策
// RTL:安全檢查位元有壞位,但沒有 ECC / 冗餘與 BIST
assign ok = permission;      // 若 permission 單元有製程缺陷,安全決定就錯
// 無掃描/BIST 驗證 => defect 逃過測試直接出貨`,
		fixed: `// 安全寫法:安全決策用冗餘/ECC 保護,並以 BIST 偵測與隔離缺陷
// RTL:permission 以 triple-modular 冗餘並帶 parity,且開機跑 BIST
wire a = permission_tmr[0], b = permission_tmr[1], c = permission_tmr[2];
assign ok = (a & b) | (a & c) | (b & c);   // 多數決,容忍單一缺陷
// boot 時 BIST 檢查 security element,發現壞單元即拒絕可疑操作`,
		patch: `@@
-assign ok = permission;
+wire a = permission_tmr[0], b = permission_tmr[1], c = permission_tmr[2];
+assign ok = (a & b) | (a & c) | (b & c);
+// BIST 偵測缺陷,失敗即隔離並 reject`,
		refs: ['CWE-1248', 'CWE-1245'],
		tags: ['semiconductor', 'defect', 'hardware', 'bist', 'test-escape'],
	},
	{
		id: 'CWE-1249',
		name: 'Application-Level Admin Tool with Inconsistent View of Underlying Operating System',
		lang: 'node',
		status: 'Complete',
		what: `管理應用程式對底層作業系統的認識與實際狀態不一致。產品提供給管理員的工具會維護一份「它自以為的 OS 狀態」模型(使用者、服務、群組、權限、套件),但這個模型是內部快取或事先假設,並未與作業系統的真實現況同步。當 OS 被其它工具、腳本或使用者直接改動後,管理工具的視圖就失真:可能對「其實已不存在」的實體派予權限、漏掉真正存在的資源、或以過時的資訊去改系統,造成管控缺口或誤操作。成因是沒有以 OS 的權威來源即時重建模型。修法是每次動作前都向作業系統的權威介面(passwd、getent、系統 API)查詢實際狀態,以「真實清單」為準,不以快取模型做決策。`,
		problem: `// 不安全寫法:用內部快取模型做決策,與 OS 實際狀態不同步
const cached = loadCache('users');        // 可能是過時清單

function setAdmin(user) {
  // 模型以為該用戶存在,但 OS 已被其它工具刪除
  if (!cached.includes(user)) return;
  shadow.addToAdmin(user);   // 對「其實不存在」的帳號下權 => 或漏管真實資源
}`,
		fixed: `// 安全寫法:以作業系統權威來源即時查詢實際狀態
function setAdmin(user) {
  const live = queryOS('listUsers');      // 每動作查真實狀態(getent/passwd)
  if (!live.includes(user)) return;
  shadow.addToAdmin(user);
}`,
		patch: `@@
 function setAdmin(user) {
-  const cached = loadCache('users');
-  if (!cached.includes(user)) return;
+  const live = queryOS('listUsers');
+  if (!live.includes(user)) return;
   shadow.addToAdmin(user);
 }`,
		refs: ['CWE-1249', 'CWE-1250'],
		tags: ['admin-tool', 'inconsistency', 'os-state', 'cache', 'management'],
	},
	{
		id: 'CWE-1250',
		name: 'Improper Preservation of Consistency Between Independent Representations of Shared State',
		lang: 'go',
		status: 'Complete',
		what: `共享狀態的多份獨立表示之間未維持一致。系統由多個分散的組件或子系統組成,每個都必須自行維護一份共享資料(狀態、快取)的本地副本,但產品沒有保證所有副本彼此同步一致。某個節點更新了狀態,其它節點的舊副本沒有被更新或使失效,於是在不同組件眼中看到不同的「真相」;依賴這些表示的後續決策就可能基於舊資料,造成權限判斷錯誤、資料欺騙或流程錯亂。成因是共享狀態散布後缺少可靠的傳播、失效與交易機制。修法是讓共享狀態有單一權威來源,更新時以(序列化)事務發布給所有持有副本的組件並同步失效——快取改用 cache invalidation、版本號或一致性協調——確保任何讀取都拿到最新一致的副本。`,
		problem: `// 不安全寫法:多組件各自維護共享計數快取,沒有真正同步 => 不一致
var perNodeCache sync.Map   // 每節點留一份過時快取

func readCredits(node int) int {
    v, _ := perNodeCache.Load(node)     // 可能停在舊值,另一節點早已更新
    return v.(int)
}`,
		fixed: `// 安全寫法:共享狀態交由單一權威/協調器,統一發布才讀取一致副本
func readCredits(node int) int {
    // 統一由權威來源取值(或經一致性協調的失效快取),保證副本一致
    return coordinatorCurrent(node)      // 單一真相,同步追到底
}`,
		patch: `@@
 func readCredits(node int) int {
-    v, _ := perNodeCache.Load(node)
-    return v.(int)
+    return coordinatorCurrent(node)      // 單一權威來源,副本一致
 }`,
		refs: ['CWE-1250', 'CWE-1251'],
		tags: ['distribution', 'consistency', 'shared-state', 'cache-invalidation', 'transaction'],
	},
	{
		id: 'CWE-1251',
		name: 'Mirrored Regions with Different Values',
		lang: 'c',
		status: 'Complete',
		what: `鏡像(mirror)記憶體區段內容不一致。硬體架構把同一區域提供多個鏡像位址(window)以便存取,或作為冗餘;但若沒有保證所有鏡像隨時同步——例如某個鏡像被不同的 master 直接寫入、或鏡像更新路徑存在時間差——之後各鏡像就會持有不同的值。安全比對、加密運算或韌體驗證若讀到不同的鏡像,可能得到不一致甚至被利用的結果,攻擊者可以找到「還沒被同步」的那個鏡像來避開防護。成因是鏡像被當成「可獨立寫入的備份」而非唯讀別名。修法是讓鏡像只能做為同源唯讀視窗,所有寫入一律經由主要儲存與統一控制路徑,硬體確保任一鏡像讀到的都是同一份最新的值。`,
		problem: `// 不安全寫法:鏡像區可被不同 master 直接寫入,兩邊內容失去同步
#define MIR_A  0x80000000
#define MIR_B  0x90000000
// 安全檢查讀 MIR_A,data master 卻從 MIR_B 寫;檢查與用到的不是同一份值
secure_check(read_reg(MIR_A));      // 可能還是舊值,被 MIR_B 的新內容繞過`,
		fixed: `// 安全寫法:鏡像為唯讀別名,寫入一律走單一主儲存路徑
// RTL:MIR_A / MIR_B 都直接連結同一個 storage,寫入只允許到主儲存
secure_check(read_reg(MIR_A));      // MIR_A 與 MIR_B 永遠讀到同一份最新值`,
		patch: `@@
-// MIR_A / MIR_B 各自可寫 => 內容可不同步
-secure_check(read_reg(MIR_A));      // 讀舊值,被 MIR_B 繞過
+// MIR_A / MIR_B 為唯讀同源別名,寫入走主儲存
+secure_check(read_reg(MIR_A));      // 兩個鏡像永遠一致`,
		refs: ['CWE-1251', 'CWE-1257'],
		tags: ['mirror', 'alias', 'hardware', 'consistency', 'memory'],
	},
	{
		id: 'CWE-1252',
		name: 'CPU Hardware Not Configured to Support Exclusivity of Write and Execute Operations',
		lang: 'c',
		status: 'Complete',
		what: `CPU 硬體未配置成支援「寫」與「執行」互斥。現代 CPU 提供不執行(NX/XN)加上記憶體屬性組合,讓記憶體頁可以做「可寫不可執行、可執行不可寫」(W^X / DEP)。若平台沒有開啟這項能力,或開機時把記憶體一律標成可執行,資料與堆疊也能被當成程式碼執行;把 payload 寫進可寫記憶體就能直接執行,遠端程式碼執行、堆疊與 heap 注入都因此變得容易。成因是頁全部被賦予「可寫又可執行」,或平台預設未強制 NX。修法是在開機階段啟用 NX/DEP,把資料、堆疊、heap 標記為不可執行(NX),程式碼區保持可執行不可寫(W^X),達成寫與執行互斥。`,
		problem: `// 不安全寫法:分配可寫又可執行的記憶體,或平台未開啟 NX => 資料頁可被當程式碼執行
void *buf = alloc_pages(granularity, RWX);   // 可讀寫又可執行
// 攻擊者寫進 buf 的 shellcode 直接可執行,阻擋機制形同虛設`,
		fixed: `// 安全寫法:開機啟用 NX,資料與堆疊不可執行,達成 W^X 互斥
enable_nx_dep(boot_config());       // 開機強制 NX
void *buf = alloc_pages(granularity, RW);    // 資料頁不可執行
// 寫進 buf 的內容無法當程式碼執行,阻止注入型攻擊`,
		patch: `@@
-void *buf = alloc_pages(granularity, RWX);
+enable_nx_dep(boot_config());
+void *buf = alloc_pages(granularity, RW);
 // 寫進 buf 的 shellcode 無法直接執行`,
		refs: ['CWE-1252', 'OWASP'],
		tags: ['nx', 'wx', 'dep', 'memory-execute', 'exploit'],
	},
	{
		id: 'CWE-1253',
		name: 'Incorrect Selection of Fuse Values',
		lang: 'c',
		status: 'Complete',
		what: `依賴於「保險絲未燒斷」來設定安全態,選錯 fuse 邏輯位準。設定系統為安全狀態所使用的邏輯位準,建立在某個 fuse「未燒斷(unblown)」這個出廠預設上。大量生產時預設不燒,而安全要求的成立又要押在一次「可能被遺漏」的燒斷動作上;只要有哪顆保險絲沒被正確燒斷,系統就一直停在不安全的狀態——而且這常是多數出貨單元的真實情況。成因是選擇了與「預設需要安全」方向相反的 fuse 邏輯,把暴露當成本底、安全當特例。修法是採用出廠即安全的預設方向:讓需要特殊處理的能力由「燒斷後依然add權限」的正向邏輯代表,或讓安全態由燒斷後的實體位準決定,並在出貨測試中驗證安全態確實可達。`,
		problem: `// 不安全寫法:安全狀態依賴某顆 fuse「未燒斷」,漏燒就暴露,且是多數單元預設
// 預設(unblown)即 asunsecure;只有確實誤燒才安全
void init_secure_state(void) {
    if (!fuse_is_blown(SECURITY_FUSE)) {
        // 出廠預設未燒 => 保持在不安全/暴露狀態
        enter_insecure_mode();
    }
}`,
		fixed: `// 安全寫法:出廠預設即安全;需特殊權限才走向暴露,並驗證安全態可達
void init_secure_state(void) {
    if (!fuse_is_blown(SECURITY_FUSE)) {
        enter_secure_mode();        // 預設安全,暴露需額外熔絲設定
    }
}`,
		patch: `@@
 void init_secure_state(void) {
-    if (!fuse_is_blown(SECURITY_FUSE)) {
-        enter_insecure_mode();
-    }
+    enter_secure_mode();            // 出廠即安全,暴露才需特別設定
 }`,
		refs: ['CWE-1253', 'CWE-1269'],
		tags: ['fuse', 'secure-state', 'default', 'hardware', 'boot'],
	},
	{
		id: 'CWE-1254',
		name: 'Incorrect Comparison Logic Granularity',
		lang: 'c',
		status: 'Complete',
		what: `比較邏輯粒度不當。產品的比較邏輯是分成一連串步驟執行,而不是一次掃過整個字串;若其中某一步比較失敗就提早回傳,時間消耗便隨「比到第幾個字元才對不上」而變,成為可供側量推測的時序通道。攻擊者量測大量比較所需的時間——位元愈靠前對粗時間愈短、愈匹配愈長——就能逐字元把「參考值」(金鑰、token)指認出來,進而攔截程序為己用。成因是把安全比較拆成可提早退出的逐段/逐字比對。修法是使用固定時間(constant-time)比較:一次以固定長度掃完整個空間、只累積「是否都相等」的結果,中途不回傳也不短路,讓耗時與資料值徹底無關,防堵時序攻擊。`,
		problem: `// 不安全寫法:逐字比較,第一個不同就 `+`return,耗時隨比對程而變 => 時序泄漏
int bad_compare(const uint8_t *a, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return 0;   // 提早回傳:時間比例 = 命中的位元數
    }
    return 1;
}`,
		fixed: `// 安全寫法:常數時間比較,全程跑完長度,不因資料值而短路
int good_compare(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);   // 累積差異,不回傳、不中斷
    }
    return (diff == 0);
}`,
		patch: `@@
 int compare(const uint8_t *a, const uint8_t *b, size_t n) {
-    for (size_t i = 0; i < n; i++) {
-        if (a[i] != b[i]) return 0;   /* 提早回傳 => 時序漏出 */		
-    }
-    return 1;
+    uint8_t diff = 0;
+    for (size_t i = 0; i < n; i++) {
+        diff |= (uint8_t)(a[i] ^ b[i]);   /* 累積,不回傳 */
+    }
+    return (diff == 0);
 }`,
		refs: ['CWE-1254', 'CWE-1255'],
		tags: ['timing-attack', 'constant-time', 'compare', 'side-channel', 'token'],
	},
	{
		id: 'CWE-1255',
		name: 'Comparison Logic is Vulnerable to Power Side-Channel Attacks',
		lang: 'c',
		status: 'Complete',
		what: `比較邏輯易受功耗側信道攻擊。裝置在評估 security token(如 PIN、金鑰、晶片驗證碼)期間,即時功耗會被外部持續監測,而耗電量與被比對的參考值密切相關——執行的位元算數、暫存器切換次數、資料路徑取決於秘密的每一位。攻擊者用示波器/功耗探針記錄認證當下的功率軌跡,收集大量樣本後以統計分析(如 DPA/CPA)重建出參考 token 各比特的值,完全不需侵入晶片內部。成因是未遵行常數功耗原則,運算的功耗型態與機密度資料相關。修法是讓與秘密相關的操作在時間與功耗上都與資料「無關」:採用常數時間、隨機遮罩(masking)、盲化(blinding)、雙軌邏輯或恆定功耗設計,使任何一條功率軌跡都無法與 token 值建立關聯。`,
		problem: `// 不安全寫法:認證/比較運算的功耗隨秘密位元而變,可用功率軌跡推算 token
int compare_token(uint32_t *secret) {
    // 暫存器寫回多少由 secret 位元決定 => 功率波形與 token 值強相關
    for (int i = 0; i < 32; i++) {
        acc += (secret[i/32] >> (i%32)) & 1;    // 可被 DPA/CPA 統計還原
    }
    return acc == expected;
}`,
		fixed: `// 安全寫法:對秘密操作施加遮罩/盲化與恆時功耗,切斷功耗與 token 的關聯
int compare_token(uint32_t *secret) {
    uint32_t mask = csprng();            // 隨機遮罩
    // 先把 secret 與 mask 混合,運算的功耗不再直接反映秘密位元
    uint32_t mixed = *secret ^ mask;
    int eq = (mixed ^ expected_blinded(mask)) == 0;
    // 操作次數與暫存器寫回固定 => 軌跡不洩漏 token 值
    return eq;
}`,
		patch: `@@
 int compare_token(uint32_t *secret) {
-    for (int i = 0; i < 32; i++) {
-        acc += (secret[i/32] >> (i%32)) & 1;
-    }
-    return acc == expected;
+    uint32_t mask = csprng();
+    uint32_t mixed = *secret ^ mask;
+    int eq = (mixed ^ expected_blinded(mask)) == 0;
+    return eq;
 }`,
		refs: ['CWE-1255', 'CWE-1254'],
		tags: ['side-channel', 'power-analysis', 'dpa', 'token', 'masking'],
	},
	{
		id: 'CWE-1256',
		name: 'Improper Restriction of Software Interfaces to Hardware Features',
		lang: 'c',
		status: 'Complete',
		what: `對硬體功能的軟體介面限制不當。產品提供軟體可控的設備功能,涵蓋電源、時脈管理等效餛筆;但沒有妥善限制那些會導致「改動硬體記憶體或暫存器位元、或得以觀察物理側信道」的功能。於是不可信任的軟體(或透過這條介面的攻擊者)能改動硬體組態來讓系統進入不安全狀態、修改關鍵暫存器,或把功耗/電磁/時脈等物理訊號量測出來,進而洩漏機密。成因是這條 control path 缺少授權檢查與功能最小化。修法是為每種軟體可控的硬體功能設定最小授權與身分驗證,禁止不必要的寫入或觀察能力;硬體又在獨立途徑上再度檢查,限制任何一筆操作只能落在允許的位址與作業範圍內。`,
		problem: `// 不安全寫法:電力/時脈管理介面對任何軟體敞開,可改動硬體位元與量測側信道
// 任何 agent 都能控制 hardware controls,沒做資格/位址限制
void hw_ctrl_client(uint32_t req) {
    apply_power_clock(req);            // 直接改硬體 => 可把系統推入不安全態
}|`,
		fixed: `// 安全寫法:受控介面最小化 + 授權/位址檢查 + 硬體二次限制
void hw_ctrl_client(uint32_t req) {
    if (!authorized(current_agent)) return;       // 身分/權限檢查
    restrict_to_allowed(req);                     // 最小功能,禁止越界寫入
    // 硬體側再以 allowlist 檢查,攔下任何不到位的操作
}`,
		patch: `@@
 void hw_ctrl_client(uint32_t req) {
-    apply_power_clock(req);
+    if (!authorized(current_agent)) return;
+    restrict_to_allowed(req);
 }`,
		refs: ['CWE-1256', 'CWE-1262'],
		tags: ['hardware-interface', 'mmio', 'access-control', 'side-channel', 'firmware'],
	},
	{
		id: 'CWE-1257',
		name: 'Improper Access Control Applied to Mirrored or Aliased Memory Regions',
		lang: 'c',
		status: 'Complete',
		what: `對鏡像/別名記憶體區施行的存取控制不一致。硬體設計用多個互相鏡像或別名的位址指向同一塊實體記憶體,但每個別名的讀寫權限定義可能各自獨立、沒有完全一致。結果是:某個別名把不可信 agent 擋在外面,對應的另一個別名卻放它進去;攻擊者只要繞到權限較鬆的別名,就照樣碰到那塊記憶體,原本的存取控制被別名輕鬆繞過。成因是把別名當成互不相干的獨立視窗,權限矩陣沒有同步套到所有別名。修法是讓所有指向同一實體資源的別名共用同一組權限屬性,授權一律以「實體資源」為準而非以位址別名判定,硬體在解譯任一別名時都用同一套檢查,不允許同實體保有強弱不一的多套規則。`,
		problem: `// 不安全寫法:實體記憶體有強(A)與弱(B)兩組鏡像權限,弱別名放行不可信 agent
#define MEM_ALIAS_A  0x10000000   // 權限較嚴
#define MEM_ALIAS_B  0x20000000   // 權限較鬆的同實體視窗
// 未受信 agent 被 A 擋下,卻可經 B 存取同一塊記憶體
if (check_alias(addr) == ALIAS_A) { deny(); }   // 只擋 A => 從 B 繞過`,
		fixed: `// 安全寫法:權限以實體資源為中心,所有別名共用同一組屬性
// RTL:別名都以實體位址查同一份權限表,不管從 A 或 B 進來都同檢查
if (!permit(physical_of(addr), agent)) { deny(); }   // 以實體為準,別名無異`,
		patch: `@@
-// A 擋 B 鬆 => 可繞 B
-if (check_alias(addr) == ALIAS_A) { deny(); }
+// 一律以實體資源查同一份權限
+if (!permit(physical_of(addr), agent)) { deny(); }`,
		refs: ['CWE-1257', 'CWE-1260'],
		tags: ['mirror', 'alias', 'access-control', 'hardware', 'memory'],
	},
	{
		id: 'CWE-1258',
		name: 'Exposure of Sensitive System Information Due to Uncleared Debug Information',
		lang: 'c',
		status: 'Complete',
		what: `進入除錯模式時未清除安全敏感資訊。硬體切進除錯模式時,沒有把仍停留在暫存器與工作區的安全敏感值——金鑰、加解密的中間值、查表(狀態匣)內值、資料暫存器——完全清掉。這些機密殘骸留在除錯介面可見的矽片區域,除錯持有者或掃描工具可直接讀取,即便安全運作早就結束。成因是除錯入口不會自動 zeroize,原機密就地停留。修法是偵測到「進入除錯」的第一時間,先遮罩或清除所有夾帶機密的工作區與暫存器再開啟除錯;同時確認除錯介面能讀取的任何位置,都不再殘留任何一把金鑰或其衍生的中間值。`,
		problem: `// 不安全寫法:進入除錯模式沒有清掉仍在暫存器/狀態匣的金鑰與中間值
void enter_debug(void) {
    // 金鑰與 AES 中間值仍留在暫存器區,掃描/除錯介面直接可讀
    raise_debug_lines();
    debug_dump(saved_aes_context);     // 中間值外洩
}`,
		fixed: `// 安全寫法:進入除錯前先銷毀所有含機密的暫存器/狀態
void enter_debug(void) {
    zeroize(saved_aes_key);            // 先抹除金鑰與中間值
    zeroize(sbox_clear);      
    memset_secure(aes_ctx, 0, sizeof aes_ctx);
    raise_debug_lines();               // 抹完才開除錯,無殘骸可讀
}`,
		patch: `@@
 void enter_debug(void) {
+    zeroize(saved_aes_key);
+    zeroize(sbox_clear);
+    memset_secure(aes_ctx, 0, sizeof aes_ctx);
     raise_debug_lines();
-    debug_dump(saved_aes_context);
 }`,
		refs: ['CWE-1258', 'CWE-1243'],
		tags: ['debug', 'zeroize', 'key-leak', 'hardware', 'intermediate'],
	},
	{
		id: 'CWE-1259',
		name: 'Improper Restriction of Security Token Assignment',
		lang: 'c',
		status: 'Complete',
		what: `SoC 用之區分動作許可的 Security Token(安全權杖)機制保護不當。SoC 以 Security Token 來決定「來自某實體的交易能做哪些、被禁止哪些動作」;每筆交易的發源地會被貼上 token,權杖被當作授權的依據。但若 Security Token 本身可被偽造、被篡改、或由低特權實體任意指定——例如可經軟體填入、可被組合某條通道覆寫、或沒有加密/簽章綁定發源——不可信的高權限組件(如 DMA)或在信任邊界內的工具就能替自己蓋上高權限 token,騙過以 token 為準的檢查,執行本不允許的動作。成因是把授權決定整個押在一個未受保護、可變的欄位。修法是讓 token 由安全控制器在可信實體邊界內產生、以認證方式綁定發源(fabric 依實體主機與 token 一起驗證)、且不可由軟體任意覆寫,防止 token 升等。`,
		problem: `// 不安全寫法:Security Token 可由軟體寫入,誰都能替自己貼高權限 token
// transaction 的 security token 欄位由軟體可直接設定 => 偽造/升等
void issue_transfer(uint32_t raw_addr) {
    ht.probe token = SET_HIGH_PERM;    // 低特權就塞高權限 token
    fabric_issue(raw_addr, token);      // 以 token 為準的檢查被騙過
}`,
		fixed: `// 安全寫法:token 由 fabric/安全控制器依發源實體產生,軟體不可寫
void issue_transfer(uint32_t raw_addr) {
    // 由 fabric 依「實體主機」判定 token,軟體欄位不作為授權依據
    token_t t = fabric_token_of(current_master());
    fabric_issue(raw_addr, t);          // 別名無法升等權杖
}`,
		patch: `@@
 void issue_transfer(uint32_t raw_addr) {
-    ht.probe token = SET_HIGH_PERM;
-    fabric_issue(raw_addr, token);
+    token_t t = fabric_token_of(current_master());
+    fabric_issue(raw_addr, t);
 }`,
		refs: ['CWE-1259', 'CWE-1268'],
		tags: ['soc', 'security-token', 'fabric', 'privilege', 'transaction'],
	},
	{
		id: 'CWE-1260',
		name: 'Improper Handling of Overlap Between Protected Memory Ranges',
		lang: 'c',
		status: 'Complete',
		what: `受保護記憶體範圍重疊處置不當。產品允許位址範圍互相重疊;當記憶體保護以「位址範圍」為判斷單位時,攻擊者可以把同一塊實體記憶體同時放進一個「受保護」範圍和一個「不受保護/低權限」範圍。硬體依規則比對時,哪條規則先命中、或哪套較窄的規則較寬鬆,較低權限的那條就可能放行對這塊記憶體的存取,受保護區域形同沒設。成因是沒有拒絕重疊範圍,或重疊時保護屬性沒有套用嚴格的交集。修法是讓範圍配置在產生時即禁止重疊、或硬體對重疊區域一律以「最嚴格」的屬性結算並定義清楚的比對順序,確保任何實體位址不會同時落在互相矛盾的規則裡。`,
		problem: `// 不安全寫法:允許兩個範圍重疊,低權限規則先命中就放行 → 保護被繞過
// protected: 0x3000-0x4000 (高權限)
// literal: 0x3500-0x3800 (低權限),與 protected 重疊
if (is_in(low_range, addr)) grant_low();   // 重疊處先被低權限規則放行`,
		fixed: `// 安全寫法:禁止重疊,或以最嚴格屬性合併判定
// 產生 rule 時拒絕任何 range 重疊;重疊一律以較嚴格屬性求出交集
if (is_in(protected_range, addr)) grant_high();   // 最嚴者勝,不給低權限乘隙`,
		patch: `@@
-// 兩範圍重疊,低權限先命中 => 繞過
-if (is_in(low_range, addr)) grant_low();
+// 禁止重疊,重疊處以最嚴格屬性判斷
+if (is_in(protected_range, addr)) grant_high();`,
		refs: ['CWE-1260', 'CWE-1257'],
		tags: ['memory-range', 'overlap', 'protection', 'hardware', 'bypass'],
	},
	{
		id: 'CWE-1261',
		name: 'Improper Handling of Single Event Upsets',
		lang: 'verilog',
		status: 'Complete',
		what: `對單一事件翻轉(SEU/軟錯誤)的處理不當。硬體邏輯對記憶單元或暫存器受到單一高能粒子(或雜訊)造成位元翻轉(soft error)的情形沒有有效處置。若關鍵的安全旗標、特權位、金鑰快取或控制暫存器被一個 SEU 翻轉,可能把「檢查結果」從拒絕變允許、把特權位翻高、或讓加密運算出錯,安全與整體正確性同受影響,且這類錯誤無跡可查、難以重現。成因是對安全相強與跨區記憶體的可靠性保護(ECC/奇偶/冗餘)不足。修法是對載有安全狀態與資料的區採用 ECC、奇偶檢查或 triple-modular redundancy(TMR),偵測到單一翻轉即修正或安全重置,並且被翻轉的位元不會直接影響安全決策。`,
		problem: `// 不安全寫法:安全旗標無保護,單一粒子翻轉即翻轉安全決定
// RTL
reg secure_bit;                     // 無 ECC/冗餘的普通暫存器
always @(posedge clk) secure_bit <= some_secure_result;
// 一個 SEU 可把 secure_bit 翻成 1 => 權限誤判`,
		fixed: `// 安全寫法:以 TMR/ECC 保護安全暫存器並容錯單一翻轉
// RTL:voted = 三份冗餘多數決,容忍單一位元翻轉
wire v = (r[0] & r[1]) | (r[0] & r[2]) | (r[1] & r[2]);
assign secure_result = v;          // 單一 SEU 不影響安全決策`,
		patch: `@@
-reg secure_bit;
-always @(posedge clk) secure_bit <= some_secure_result;
+wire v = (r[0] & r[1]) | (r[0] & r[2]) | (r[1] & r[2]);
+assign secure_result = v;         // TMR 容忍單一 SEU`,
		refs: ['CWE-1261', 'CWE-1248'],
		tags: ['seu', 'soft-error', 'tmr', 'hardware', 'reliability'],
	},
	{
		id: 'CWE-1262',
		name: 'Improper Access Control for Register Interface',
		lang: 'c',
		status: 'Complete',
		what: `對記憶體對應 I/O(MMIO)暫存器介面的存取控制不當。產品使用 MMIO 暫存器當作軟體操控硬體功能的介面,但對「誰能對哪些暫存器做讀寫」沒有恰當的存取控制——例如所有暫存器對所有 agent 都可寫、或沒有按特權/領域區分讀寫權。未授權的軟體或硬體組件就能改動敏感的暫存器(安全機制開關、時脈、除錯控制),直接把系統推進不安全狀態、關閉保護或竊取機密。成因是對暫存器空間沒有做 per-register 的粒授權。修法是為 MMIO 介面加上按 agent 特權/領域評判的存取控制,敏感暫存器只允許受信任代理寫入,其它寫入由硬體忽略(write-ignore),並統計與阻擋異常的改動。`,
		problem: `// 不安全寫法:MMIO 暫存器空間對任何 agent 一視同仁,敏感暫存器人人可寫
// 不檢查來源特權 => 未受信軟體可直接改關鍵暫存器
reg w_reg = mmio_read(KEY_LOCK);    // 無存取階層檢查
mmio_write(SECURE_CTRL, DISABLE_SECURITY);   // 人人可寫 => 關掉安全`,
		fixed: `// 安全寫法:按 agent 特權/領域對每筆 MMIO 存取做檢查
void hw_access(agent_t a, uint32_t reg) {
    if (!allow_write(a, reg)) return;       // 以 agent 特權決定敏感暫存器誰可寫
    if (reg && is_secure_ctrl(reg) && !a.privileged) return;
    mmio_apply_write(reg);
}`,
		refs: ['CWE-1262', 'CWE-1256'],
		patch: `@@
-reg w_reg = mmio_read(KEY_LOCK);
-mmio_write(SECURE_CTRL, DISABLE_SECURITY);
+void hw_access(agent_t a, uint32_t reg) {
+    if (!allow_write(a, reg)) return;
+    if (reg && is_secure_ctrl(reg) && !a.privileged) return;
+    mmio_apply_write(reg);
+}`,
		refs: ['CWE-1262', 'CWE-1256'],
		tags: ['mmio', 'register', 'access-control', 'hardware', 'privilege'],
	},
	{
		id: 'CWE-1264',
		name: 'Hardware Logic with Insecure De-Synchronization between Control and Data Channels',
		lang: 'verilog',
		status: 'Complete',
		what: `控制與資料通道之間不安全的失同步造成硬體邏輯漏洞。硬體的錯誤處理與安全檢查邏輯,本應在「確認資料無誤、檢查通過」之後才把資料向後送出;但若資料轉發與安全檢查兩條通道各行其是、失同步——資料在安全檢查尚未完成前就先 forward——未通過檢查的資料(例如錯誤資料、越界內容、帶不可信標記的封包)就已進入後續邏輯。防護就像沒裝,錯誤資料可能被利用以提升權限或造成洩漏。成因是資料 valid/ready 與檢查完成的 valid 沒有用同一個握手互鎖。修法是讓資料轉發的 valid 訊號,嚴格以「安全檢查完成且通過」為成集門檻——資料 valid 只有在 check_ok 拉起後才拉起,兩個通道經同一握手協議,確保資料必定晚於檢查完成到達下游。`,
		problem: `// 不安全寫法:資料在安全檢查完成前就先被 forward(兩通道不同步)
// RTL
always @(posedge clk) begin
    if (data_valid) begin
        out_data <= in_data;        // 資料先送
    end
    if (sec_check_ok) begin
        out_ok <= 1;                // 檢查完成的通知晚於資料到達
    end
end`,
		fixed: `// 安全寫法:資料轉發以「安全檢查完成且通過」為門檻,檢查完成才送資料
always @(posedge clk) begin
    if (data_valid && sec_check_ok) begin   // 檢查通過才 forward
        out_data <= in_data;
    end
end`,
		patch: `@@
  always @(posedge clk) begin
-    if (data_valid) begin
-        out_data <= in_data;
-    end
-    if (sec_check_ok) begin
-        out_ok <= 1;
-    end
+    if (data_valid && sec_check_ok) begin   // 檢查完成才送資料
+        out_data <= in_data;
+    end
  end`,
		refs: ['CWE-1264', 'CWE-1251'],
		tags: ['de-synchronization', 'control-channel', 'hardware', 'data-forward', 'validation'],
	},
	{
		id: 'CWE-1266',
		name: 'Improper Scrubbing of Sensitive Data from Decommissioned Device',
		lang: 'c',
		status: 'Complete',
		what: `裝置退役時未妥善清除機密資料。產品沒有提供管理員在報廢/退役時移除敏感資料的能力,或該污染防治功能不當——例如缺失、不完整、或不正確:沒有 secure erase 指令、沒銷毀金鑰、只刪除部分、或用了可被還原的方式。退役裝置流入他人之手後,磁碟與 NVM 上殘留的金鑰、使用者資料與組態就被直接讀出。成因是把「刪除」當成「可還原的遮蔽」,或根本漏做。修法是提供一等公民的資料滅除路徑:廠商認證的 sanitize / secure erase(依如 NIST SP 800-88 標準),並對金鑰做金鑰滅除(crypto erase)後驗證其實已被破壞或覆寫,確保退役後機密無法回復。`,
		problem: `// 不安全寫法:所謂的「清洗」只是覆寫檔頭,或根本沒有滅除能力
void decommission(void) {
    printf_ack('cleaned');
    // 只清空索引,實際資料/金鑰仍留在媒體上供讀取
}`,
		fixed: `// 安全寫法:提供真正的 secure erase / sanitize,並驗證支援也不留
void decommission(void) {
    secure_erase(nvm, FULL_MEDIA);       // 依標準做整批滅除(如 NIST SP 800-88)
    crypto_erase(keys);                   // 密鑰滅除,破壞後才結束
    if (!verify_erased()) fail_decommission();
}`,
		patch: `@@
 void decommission(void) {
-    printf_ack('cleaned');
+    secure_erase(nvm, FULL_MEDIA);
+    crypto_erase(keys);
+    if (!verify_erased()) fail_decommission();
 }`,
		refs: ['CWE-1266', 'OWASP'],
		tags: ['decommission', 'sanitize', 'secure-erase', 'data-removal', 'key-eraser'],
	},
	{
		id: 'CWE-1267',
		name: 'Policy Uses Obsolete Encoding',
		lang: 'python',
		status: 'Complete',
		what: `安全策略使用過時的編碼機制。產品用某種過時或不當的編碼來表達存取控制策略(權限、屬性、身分),而這種編碼已不被現行標準支援、具備已知的解析歧義、或被新機制取代。環境/語言在解譯這種舊編碼時行為可能不一致或不再受保障,規則被錯誤解析、排序錯或乾脆被忽略,該攔的沒攔,基於它的存取控制形同虛設。成因是把老舊的組態/編碼直接沿用給安全判定,沒有改寫並驗證。修法是將策略改用現行、被實作與監管區明確認定義的編碼/格式,以權威解析器解析,並在匯入後驗證每一條規則確實在執行路徑上生效。`,
		problem: `# 不安全寫法:把過時的存取清單編碼直接當成判權規則,解析/語意一致率差
POLICY = "rw u:alice g:staff *:---"   # 自訂/過時編碼,可解析歧義
def authorize(actor, res):
    return naive_parse(POLICY).has(actor, res)   # 語意不嚴謹,規則可能被忽略`,
		fixed: `# 安全寫法:改用現行、語意清楚的標準編碼,並以權威解析器驗證實際生效
# 以結構化且受稽核的規則(如 JSON-based ACL / 標準權限語法)取代過時編碼
DEF = {"rules": [{"subject": "alice", "effect": "allow", "object": "res"}]}
def authorize(actor, res):
    r = validate_and_eval(DEF, actor, res)   # 權威解析 + 只認定義清楚的規則
    return r`,
		patch: `@@
-POLICY = "rw u:alice g:staff *:---"
-def authorize(actor, res):
-    return naive_parse(POLICY).has(actor, res)
+DEF = {"rules": [{"subject": "alice", "effect": "allow", "object": "res"}]}
+def authorize(actor, res):
+    return validate_and_eval(DEF, actor, res)`,
		refs: ['CWE-1267', 'CWE-16'],
		tags: ['policy', 'encoding', 'access-control', 'legacy', 'parsing'],
	},
	{
		id: 'CWE-1268',
		name: 'Policy Privileges are not Assigned Consistently Between Control and Data Agents',
		lang: 'c',
		status: 'Complete',
		what: `控制與資料兩種通路之間的特權指派不一致。硬體施加於某資源的存取控制,對「控制(control)」與「寫入(write)」兩類策略的特權差異沒有被一致衡量。攻擊者若可以經控制通路改變資源的存取權或安全屬性、或利用控制操作蓋掉資料，而資料寫入策略與它的判定沒有同一套權威，就能用較弱的授權取得比單一側檢查容許的更高權限，從中繞過另一側的防線。成因是 control 與 write 兩份策略各自獨立查核、沒有對齊到同一權威特權模型。修法是讓對任一資源的「控制 vs 資料」策略共用同一份權威特權模型;凡是能變更資源狀態的操作，都套用同一套授權判定，不允許某個較多的通路成為特權旁門。`,
		problem: `// 不安全寫法:control 與 write 用兩套不一致的策略,較弱的 write 通路可繞過檢查
// control: 只授權 owner 可改資源屬性
// write:   任何 agent 都可以直接透過較鬆的 write 設定該資源
if (is_ctrl_op) { return owner_only(actor); }
else           { return any_agent(actor); }   // write 較鬆 => 特權不一致`,
		fixed: `// 安全寫法:control 與 write 共用同一套權威特權模型
int authorize(actor_t actor, op_t op) {
    return common_policy(actor, op);   // 單一權威模型,控制與寫入同標準
}`,
		patch: `@@
-// control 授權、write 全放行 => 特權不一致
-if (is_ctrl_op) { return owner_only(actor); }
-else           { return any_agent(actor); }
+int authorize(actor_t actor, op_t op) {
+    return common_policy(actor, op);   // 統一權威模型
+}`,
		refs: ['CWE-1268', 'CWE-1259'],
		tags: ['control', 'write', 'policy', 'privilege', 'hardware'],
	},
	{
		id: 'CWE-1269',
		name: 'Product Released in Non-Release Configuration',
		lang: 'c',
		status: 'Complete',
		what: `產品以非正式發行組態出貨。拿上市場的產品其實是預產(pre-production)或製造(manufacturing)組態——例如保留除錯/測試韌體、寫死在開發者帳號與預設密碼、未關閉 debug/日誌通道、以較弱的預設安全值、或捲進測試用後門與開發金鑰。收貨方因此拿到一台「還能進一步被利用」的機:出場韌體允許未授權存取、除錯介面仍開著、或內含未撤換的開發憑證。成因是把製造/預產 build 當成正式發行送出,缺少「僅發行組態」的強制與驗證。修法是建立產品「release 組態」並強制施行:在建置與出貨檢測中驗證處於 release 狀態(除錯關閉、預設密碼清除、ROM 正確、後門移除),發現非 release 組態即拒絕出貨。`,
		problem: `// 不安全寫法:把開發/製造組態(debug 開、預設帳號密碼)直接打包出貨
debug_enable(0x1);            // 出貨仍開除錯,介面可被未授權存取
default_cred("admin", "admin");   // 內建開發者帳密未撤
// 進入市場的仍是預產組態 => 攻擊者可直接動手`,
		fixed: `// 安全寫法:出貨符合 release 組態,並於出貨檢測驗證
assert_release_config();       // 檢查除錯關閉、預設密碼已清、後門移除
default_cred("admin", regenerate_once());   // 撤開發密,強制設新憑證
manufacturing_test_verify_release();        // 非 release 組態一律不出貨`,
		patch: `@@
-debug_enable(0x1);
-default_cred("admin", "admin");
+assert_release_config();
+default_cred("admin", regenerate_once());
+manufacturing_test_verify_release();`,
		refs: ['CWE-1269', 'CWE-1242'],
		tags: ['release', 'manufacturing', 'debug', 'default-credential', 'shipping'],
	},
];
