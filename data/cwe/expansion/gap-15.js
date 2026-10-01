// CWE chunk — 類別:硬體/SoC 晶片安全與輸入驗證（Hardware / SoC & Input Validation）
// 補齊官方 v4.20 中手冊原本缺漏的 Base/Variant 條目
export default [
	{
		id: 'CWE-1270',
		name: 'Generation of Incorrect Security Tokens',
		lang: 'c',
		status: 'Complete',
		what: `安全憑證（Security Token）機制產生的憑證不正確。產品實作一套 security token 機制，用以區分某一筆
		交易源自某個實體時「哪些動作被允許、哪些被禁止」；但系統產生的 token 內容是錯的——可能是隨機源不好、
		被共同的種子初始化、或在生成過程中被擾動，導致該 token 沒有「真正身分證明」該有的獨特與不可預測。一旦
		token 可被猜中、或被不同身分重現，攻擊者就能偽造他人身分，在原本該被拒絕的權限下送出交易，越過以該
		token 建立的屬性與存取界限。成因是對 token 的生成缺乏高熵亂數、entropy 來源或 ID 唯一性的保證。修法是
		確保 token 由高熵、不可預測的來源生成，驗證其在整個生命周期的獨特性，並把「生成、驗證」與「身分→權限」
		的對照設計成一致的閉環，讓任何錯誤 token 一出現就被拒絕，不因生成失誤而偷偷放行。`,
		problem: `// 不安全寫法：用可預測、可逆的來源產生 security token => 可被偽造
uint32_t make_token(uint32_t uid) {
    return uid * 0x9E3779B1u;   // 由 uid 直接換算,可逆、可猜 => 可重現他人身分
}`,
		fixed: `// 安全寫法：以高熵亂數源產生 token,並確保唯一性與一次性
uint32_t make_token(void) {
    for (;;) {
        uint32_t t = hw_get_random();   // 硬體高熵亂數源,不可預測
        if (token_is_unique(t)) return t; // 確保全生命週期不重複
    }
}`,
		patch: `@@
-uint32_t make_token(uint32_t uid) {
-    return uid * 0x9E3779B1u;   // 可逆、可猜
+uint32_t make_token(void) {
+    for (;;) {
+        uint32_t t = hw_get_random();   // 高熵不可預測
+        if (token_is_unique(t)) return t;
+    }
 }`,
		refs: ['CWE-1270', 'OWASP'],
		tags: ['security-token', 'authentication', 'randomness', 'spoofing', 'entropy'],
	},
	{
		id: 'CWE-1271',
		name: 'Uninitialized Value on Reset for Registers Holding Security Settings',
		lang: 'verilog',
		status: 'Complete',
		what: `重位（reset）後，存放安全設定的暫存器沒有被設成已知值。安全關鍵邏輯（如存取控制設定、中斷遮罩、
		信任根旗標）依賴某個暫存器，但該暫存器在 reset 時沒有被重置到明確的安全預設值，而是維持不明的
		uninitialized／隨機／hold 狀態。於是上電或系統 reset 後，安全邏輯可能在前幾拍就以前置值運作——存取控制
		暫存器若是任意值就可能把不該開的門打開、遮罩暫存器可能沒遮上；倘若該值又恰好落在「允許／開啟」的狀態，
		不安全軟體就能在系統一開始就越界。成因是把安全設定暫存器當一般暫存器，沒有把它納入 reset 對應重置的範圍。
		修法是在 reset 常式（或安全復位路徑）中，把安全關鍵暫存器明確初始化成「最不具權限者」的已知值，並確認
		其復位值永遠落在安全的側，而非任由它跑到人無法預期的值。`,
		problem: `// 不安全寫法：安全設定暫存器未在 reset 清除 => 復位後值不確定
reg [7:0] sec_cfg;
always @(posedge clk) begin
    if (rst_n) sec_cfg <= 8'hFF;   // 右側值不明,復位後可能是任意/允許態
    else if (wr) sec_cfg <= wdata;
end`,
		fixed: `// 安全寫法：reset 時把安全設定暫存器清成已知、最保守的安全值
reg [7:0] sec_cfg;
always @(posedge clk or negedge rst_n) begin
    if (!rst_n) sec_cfg <= 8'h00;   // 復位 => 最保守安全預設,值已知
    else if (wr) sec_cfg <= wdata;
end`,
		patch: `@@
-  reg [7:0] sec_cfg;
-  always @(posedge clk) begin
-      if (rst_n) sec_cfg <= 8'hFF;   // 不明
+  reg [7:0] sec_cfg;
+  always @(posedge clk or negedge rst_n) begin
+      if (!rst_n) sec_cfg <= 8'h00;   // 復位清成安全預設
       else if (wr) sec_cfg <= wdata;
   end`,
		refs: ['CWE-1271', 'CWE-456'],
		tags: ['reset', 'register', 'security-settings', 'initialization'],
	},
	{
		id: 'CWE-1272',
		name: 'Sensitive Information Uncleared Before Debug/Power State Transition',
		lang: 'c',
		status: 'Complete',
		what: `在進入 power state 或 debug state 轉換前，沒有把敏感資訊清除。產品會進行電源或偵錯狀態的轉換
		（進入較低耗電模式、deep sleep，或把 CPU 交由 debug／low-power 域處理），而這段期間資訊的存取限制會改變——
		例如偵錯引擎或較弱的電源域能讀到記憶體／暫存器的內容。若在轉換前沒有「清掉那些依新的存取限制已不再該被
		讀到」的機密（金鑰、明文資料、使用者資料），殘留在記憶體的部分就會在限制鬆綁後被低權限或偵錯途徑讀走。
		成因是把電源／偵錯狀態管理只當省電或可維護性問題，忽略了它同時改變了資訊存取的邊界。修法是在任何會「鬆綁
		存取」的 power／debug 轉換之前，顯式清除涉及機密的緩衝區、暫存器與記憶體，並確認較低電源域的保留內容中不
		殘留任何明文機密，讓狀態切換真正收緊而非洩漏資訊。`,
		problem: `// 不安全寫法：進入 deep-sleep 前沒清除含機密的緩衝區 => 低電源域可讀到殘留
static uint8_t keybuf[32];

void enter_deep_sleep(void) {
    // keybuf 裡的機密仍留在 RAM,debug/low-power 域接著可讀走
    enter_sleep_mode();
}`,
		fixed: `// 安全寫法：狀態轉換前先清除機密,再進入低電源域
static uint8_t keybuf[32];

void enter_deep_sleep(void) {
    secure_memset(keybuf, 0, sizeof keybuf);   // 轉換前抹淨機密
    wfi();                                     // 之後才改變電源/偵錯存取
}`,
		patch: `@@
  void enter_deep_sleep(void) {
+    secure_memset(keybuf, 0, sizeof keybuf);   // 進入前清除機密
      enter_sleep_mode();
  }`,
		refs: ['CWE-1272', 'CWE-212'],
		tags: ['sensitive-data', 'power-state', 'debug', 'clearing', 'remanence'],
	},
	{
		id: 'CWE-1273',
		name: 'Device Unlock Credential Sharing',
		lang: 'c',
		status: 'Complete',
		what: `解鎖裝置所需的憑證在多個參與方之間共用。產品的「解鎖」（unlock）由一把或幾把憑證（金鑰、密碼、
		pin）構成，而這些解鎖憑證被設計成多方共享——例如同一把解鎖碼散給多家 OEM、多個維修點、或多個供應商通用。
		當解鎖能力分屬多方管轄時，就無法界定單一可信主體：任何人手上的那一份薄弱憑證都足以解鎖，而任何一方外洩、
		遺失或被內鬼複製，都會把他人共享的解鎖能力直接暴露出來，張力由大家共同承擔。成因是忽略「憑證一旦分散越多、
		受攻擊面越大」的關係，以為一個共享碼就夠。修法是讓解鎖能力拆分並依附信頼鏈：每一解鎖實體取得唯一、可撤銷的
		憑證（可獨立吊銷），解密到裝置端再與身分綁定，使任一方的洩漏只作廢它自己那一份、不影響其他參與方，把「一方
		失守全盤皆輸」降成「單點可隔離」。`,
		problem: `// 不安全寫法：同一把解鎖金鑰散給多個參與方,任一方外洩全盤失守
static const uint8_t unlock_key[] = "SHARED_UNLOCK_KEY";   // 多方複製同一份

int try_unlock(const uint8_t *given, size_t n) {
    return n == sizeof unlock_key && memcmp(given, unlock_key, n) == 0;
}`,
		fixed: `// 安全寫法：每方持唯一、可撤銷憑證,解鎖還檢查身分與撤銷狀態
int try_unlock(const uint8_t *key, const char *party, size_t n) {
    if (key_is_revoked(party)) return 0;          // 該參與方已被吊銷
    return check_party_key(party, key, n);         // 每一方僅驗自己的唯一憑證
}`,
		patch: `@@
-  static const uint8_t unlock_key[] = "SHARED_UNLOCK_KEY";
-  int try_unlock(const uint8_t *given, size_t n) {
-      return n == sizeof unlock_key && memcmp(given, unlock_key, n) == 0;
+  int try_unlock(const uint8_t *key, const char *party, size_t n) {
+      if (key_is_revoked(party)) return 0;          // 逐方吊銷
+      return check_party_key(party, key, n);         // 唯一憑證,單方失守可隔離
   }`,
		refs: ['CWE-1273', 'CWE-522'],
		tags: ['unlock', 'credential', 'sharing', 'key-management', 'revocation'],
	},
	{
		id: 'CWE-1274',
		name: 'Improper Access Control for Volatile Memory Containing Boot Code',
		lang: 'verilog',
		status: 'Complete',
		what: `承載 boot code 的揮發性記憶體（VM）缺乏充分的存取控制。產品進行 secure-boot：從非揮發性記憶體
		（NVM）把 bootloader 程式碼傳到揮發性記憶體（VM）再執行；但對這個 VM 沒有做足夠的存取控制或保護。boot
		code 在 VM 內執行或暫存時，若任何能碰這塊 RAM 的 agent（偵錯口、弱權 core、DMA、未信任主使用者）都能
		讀／改，就能在開機進行中篡改或竊取信任根，把安全開機變成「已開機」的假象。成因是只對 NVM／OTP 這種
		「看起來該鎖」的地方做存取控制，而忽略 boot code 被搬進 RAM 之後的那一段。修法是把 VM 中的 boot code 區域
		納入與 NVM 同等的保護：設為只讀／僅可執行、限制能寫入它的 agent、禁止未授權偵錯存取，並在搬移與執行期間
		全程維持存取邊界，確保 boot code 一旦進入 VM 仍與它在 NVM 時一樣被隔離保護。`,
		problem: `// 不安全寫法：boot code 搬進 RAM 後無寫入保護,任何 agent 可改
always @(posedge clk) begin
    if (dma_req) boot_ram[dma_addr] <= dma_wdata;   // DMA/未授權 agent 能覆寫 boot code
end`,
		fixed: `// 安全寫法：boot 期間對 boot RAM 上寫禁止,只授權的來源可寫
wire boot_wen = secure_boot_done_wr ? 1'b1 : 1'b0;   // 開機鎖定後只可執行
always @(posedge clk)
    if (boot_wen) boot_ram[addr] <= wdata;               // 未鎖前只允許受信區寫入`,
		patch: `@@
-  always @(posedge clk) begin
-      if (dma_req) boot_ram[dma_addr] <= dma_wdata;
-  end
+  wire boot_wen = secure_boot_done_wr ? 1'b1 : 1'b0;
+  always @(posedge clk)
+      if (boot_wen) boot_ram[addr] <= wdata;   // 未授權來源不得寫 boot RAM`,
		refs: ['CWE-1274', 'CWE-281'],
		tags: ['secure-boot', 'volatile-memory', 'access-control', 'boot-code'],
	},
	{
		id: 'CWE-1275',
		name: 'Sensitive Cookie with Improper SameSite Attribute',
		lang: 'node',
		status: 'Complete',
		what: `敏感 cookie 未設定 SameSite 屬性，或使用了不安全的設定值。SameSite 屬性告訴瀏覽器這個 cookie 是否
		該在「跨站」請求時一起送出。若敏感 cookie（含 session、認證 token）沒設 SameSite=Strict／Lax，或明確設成
		None（通常還得搭配 Secure），它就會被隨同跨站請求送出；配合 CSRF 或跨站側通道，攻擊者可誘使受害者瀏覽器在
		另一個站台發出的請求中帶上這個敏感 cookie，藉此偽造一個「已受認證」的動作。成因是開發時只在意 HttpOnly／
		Secure，漏看了 SameSite 如何在首方／第三方語境送出認證。修法是對每個敏感 cookie 明確設定 SameSite=Strict（或
		至少 Lax），並確保真的需要 None 時必有 Secure 且有明確意圖，把「跨站請求會帶出認證 cookie」這個行為關掉，
		讓敏感 cookie 只在真正訪問自己站台時送出。`,
		problem: `// 不安全寫法：session cookie 沒設 SameSite => 依瀏覽器預設,可被跨站請求帶出
const cookie = serialize('session', token, {
  httpOnly: true,
  secure: true,
  // SameSite 未設定 => 預設 Lax 之前/部分瀏覽器,或受跨站 CSRF 影響
});`,
		fixed: `// 安全寫法：明確 SameSite=Strict,跨站請求不帶認證
const cookie = serialize('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'Strict',   // 只有首方請求才送出敏感 cookie
});`,
		patch: `@@
   const cookie = serialize('session', token, {
     httpOnly: true,
     secure: true,
+    sameSite: 'Strict',   // 明確限制跨站不帶出
   });`,
		refs: ['CWE-1275', 'CWE-352'],
		tags: ['cookie', 'samesite', 'csrf', 'session', 'sensitive'],
	},
	{
		id: 'CWE-1276',
		name: 'Hardware Child Block Incorrectly Connected to Parent System',
		lang: 'verilog',
		status: 'Complete',
		what: `硬體子模組（child block）與父系統（parent/SoC）之間的信號接線錯誤，導致安全風險。子模組的輸入／輸出
		信號之信任屬性與訂定不符——例如把該接在「可信控制器」的授權、reset、interrupt 或 access-enable，接到不受信、
		會被一般軟體控制的來源；或未把 parent 必須送到的授權信號連好，使子模組在沒有授權下也能動作。這類「接線錯誤」
		多發生在系統整合（system integration）階段，靜態驗證不容易抓到，卻可能讓安全功能被未授權路徑驅動或繞過。成因是
		整合時以「接得通就行」而非「信任屬性一致」為準。修法是在整合階段對 child block 每個 security-relevant 輸入（授權、
		reset、mode）建立明確的連線來源矩陣並逐一審查，用形式化連線／存取檢查保證這些信號只由可信片上來源驅動，並對
		與訂定不符的接線在驗證階段直接擋下來。`,
		problem: `// 不安全寫法：安全使能接錯來源 => 一般軟體可關掉保護
assign child.secure_en = user_ctrl[7];     // 一般軟體可控 => 可關掉 secure 使能
assign child.reset_n   = test_reset_n;      // reset 還接錯測試來源`,
		fixed: `// 安全寫法：安全相關輸入只接可信來源
assign child.secure_en = soc_sec_ctrl.secure_en;   // 僅受信安全控制器驅動
assign child.reset_n   = soc_reset_n;`,
		patch: `@@
-  assign child.secure_en = user_ctrl[7];
-  assign child.reset_n   = test_reset_n;
+  assign child.secure_en = soc_sec_ctrl.secure_en;   // 受信來源
+  assign child.reset_n   = soc_reset_n;`,
		refs: ['CWE-1276', 'CWE-284'],
		tags: ['integration', 'signal-connection', 'security', 'ip-block'],
	},
	{
		id: 'CWE-1277',
		name: 'Firmware Not Updateable',
		lang: 'c',
		status: 'Complete',
		what: `產品不提供使用者更新／修補 firmware 的能力。若 firmware 已是「烙死／不可更新」——沒有 update path、
		沒有驗簽的更新 bootloader、或更新介面被關閉——一旦發現韌體弱點，使用者沒有任何方法把它修掉，漏洞只能一直存在。
		對需要長期暴露在網路的裝置尤其致命：新發現的 CVE 沒有現場補丁可打，戰損會一直卡在那裡。成因是為了省成本或
		簡化，把「可更新」視為非必要，或只留給 OTA 而未預留簽章與驗證機制。修法是設計一條可信的韌體更新路徑：提供
		具簽章驗證的更新（含 recovery）流程、可回滾／可驗證的版本檢查，並保證「更新能力」本身是啟動後永不關閉的資安
		功能，讓設備在任何時候發現漏洞時都真的能把修補映像打上去，而不是只能眼睜睜承受已知弱點。`,
		problem: `// 不安全寫法：firmware 沒有更新機制,發現 CVE 也無從修補
static const uint8_t fw[] = { /* 烙定,無任何 update code path */ };

void firmware_main(void) {
    run(fw);   // 只能跑這一份,永遠無法載入新的版本
}`,
		fixed: `// 安全寫法：預留簽章驗證的更新路徑與版本/回滾檢查
int bootloader_try_update(void) {
    const fw_image_t *img = fetch_update_candidate();
    if (!img || !verify_signature(img)) return BOOT_EXISTING;   // 驗簽才接受
    if (img->version < current_version()) return BOOT_EXISTING;    // 版本/回滾控制
    return apply_update(img);
}`,
		patch: `@@
-  static const uint8_t fw[] = { /* 烙定 */
-  void firmware_main(void) { run(fw); }
+  int bootloader_try_update(void) {
+      const fw_image_t *img = fetch_update_candidate();
+      if (!img || !verify_signature(img)) return BOOT_EXISTING;
+      if (img->version < current_version()) return BOOT_EXISTING;
+      return apply_update(img);
+  }`,
		refs: ['CWE-1277', 'OWASP'],
		tags: ['firmware', 'update', 'patching', 'signed-firmware', 'recovery'],
	},
	{
		id: 'CWE-1278',
		name: 'Missing Protection Against Hardware Reverse Engineering Using Integrated Circuit (IC) Imaging Techniques',
		lang: 'c',
		status: 'Complete',
		what: `對「以積體電路（IC）影像技術進行的硬體逆向工程」缺乏防護。硬體中儲存的資訊，夠能力的攻擊者可以用
		掃描式電子顯微鏡等手段，從矽片的物理影像把安全金鑰、密碼、mask ROM 內容、熔絲狀態等逐層還原出來。若這些
		機密以「直接可量測／可見」的形式躺在 top metal、poly 或離散元件上，攻擊者下封（decap）後成像分析，就能把佈局
		一層層萃取並讀回裡面的位元。成因是設計時把「硬體碰不到」當假設，而未對抗敵意製程末端的物理分析。修法是對
		關鍵機密做抗物理分析的工程：採用混淆／加密儲存、金鑰只放在硬體專用結構（如安全 NVM／HSM）內、在元件層打散
		訊號密度、並加入防拆與感測機制（物理衝擊／上蓋被移除時自毀或清除），把機密的可成像性壓到無法被 SEM 直接辨識，
		讓逆向即使拿到晶片也還原不出真相。`,
		problem: `// 不安全寫法：機密以明文位元型式存在,可被解封成像直接比對
fuse[31:0] <= af_key_value;      // 每個 bit 對應一條可見熔絲/金屬結構 => SEM 可讀出`,
		fixed: `// 安全寫法：機密不以明文位元儲存,以混淆/加密打散並加防拆
store_with_obfuscation(af_key_value);   // 訊號打散、金属遮蔽,影像讀不到原值`,
		patch: `@@
-  fuse[31:0] <= af_key_value;   // 可見結構,成像可讀
+  store_with_obfuscation(af_key_value);   // 混淆 + 防拆,不可成像還原`,
		refs: ['CWE-1278', 'CWE-311'],
		tags: ['hardware-re', 'ic-imaging', 'obfuscation', 'reverse-engineering', 'secret'],
	},
	{
		id: 'CWE-1279',
		name: 'Cryptographic Operations are run Before Supporting Units are Ready',
		lang: 'c',
		status: 'Complete',
		what: `加密運算在支援單元尚未就緒之前就被執行。密碼運算通常需要依賴支援輸入「就緒」才有效：需要隨機種子
		（entropy／TRNG）已同步、時脈／PLL 穩定、或亂數源已歸位。若在這些支援單元尚未驗證就緒時就啟動加密，密碼運算
		吃到的是未初始化或可預測的種子／輸入，產生的結果（金鑰、nonce、簽章）便會失去真正的機密性／不可預測性——
		nonce 重複、金鑰低熵，接著就可被破解或重放。成因是開機順序把加密初始化放在其相依單元的 ready 檢查之前，或忘了把
		ready 當成必要條件。修法是讓加密路徑在「執行」之前同步確保支援單元（尤其 entropy／安全時脈）就緒並通過自檢，未就緒
		就不算；也絕不在可預測狀態下產生金鑰，讓加密所需的隨機輸入永遠來自有保障的來源。`,
		problem: `// 不安全寫法：TRNG 尚未 ready 就用它填 key => 種子低熵/可預測
void boot(void) {
    uint8_t key[32];
    trng_fill(key);            // TRNG 可能沒歸定 => key 低熵且可猜
    init_crypto(key);
}`,
		fixed: `// 安全寫法：先等待並檢查支援單元就緒才啟動加密
void boot(void) {
    uint8_t key[32];
    if (!wait_ready(TRNG_READY)) fault();   // 先確認 entropy 就緒
    trng_fill(key);                          // 就緒後才取有效輸入
    init_crypto(key);
}`,
		patch: `@@
  void boot(void) {
      uint8_t key[32];
+     if (!wait_ready(TRNG_READY)) fault();   // 就緒檢查
      trng_fill(key);
      init_crypto(key);
  }`,
		refs: ['CWE-1279', 'CWE-330'],
		tags: ['crypto', 'trng', 'readiness', 'entropy', 'key'],
	},
	{
		id: 'CWE-1280',
		name: 'Access Control Check Implemented After Asset is Accessed',
		lang: 'verilog',
		status: 'Complete',
		what: `硬體的存取控制檢查在資源已被存取之後才執行。理想的存取控制要發生在「資源被讀／寫之前」就把它擋下；
		若檢查是在資產已解到、且值已放出之後才跑，結果往往為時已晚——資料早已流出，或副作用（寫入、使能）已經發生，
		即使檢查判定不妥也不可挽回。成因是把檢查與資源存取接成不當的順序（check 放得太晚），或在 pipeline 中把授權判定
		延後。後果是安全屬性只像「事後哨站」：受保護資產被未授權 requester 先行取走，檢查形同虛設。修法是讓「授權判定
		→資源門控」組合成單一、前置的決策點：在解出資料之前，以授權信號閘住 read／write enable，命中授權才放行對資產的
		存取；未授權的根本不解資料、不回填內容，確保任何未授權存取在資產被碰觸之前就被擋下。`,
		problem: `// 不安全寫法：先把資產讀出,才做檢查 => 資料已被送出
always @(posedge clk) begin
    rdata <= mem[raddr];              // 資產先被讀出
    if (!auth_ok) rdata <= 32'h0;    // 檢查太晚,資料早已洩出
end`,
		fixed: `// 安全寫法：授權檢查在前,命中才放行對記憶體的讀取
wire re_gate = auth_ok;                        // 先做授權判定
always @(posedge clk)
    if (re_gate) rdata <= mem[raddr];         // 未授權則不解資產
    else          rdata <= 32'hDEADBEEF;       // 只回掩碼`,
		patch: `@@
-  always @(posedge clk) begin
-      rdata <= mem[raddr];
-      if (!auth_ok) rdata <= 32'h0;
-  end
+  wire re_gate = auth_ok;
+  always @(posedge clk)
+      if (re_gate) rdata <= mem[raddr];
+      else          rdata <= 32'hDEADBEEF;`,
		refs: ['CWE-1280', 'CWE-697'],
		tags: ['access-control', 'ordering', 'authorization', 'hardware'],
	},
	{
		id: 'CWE-1281',
		name: 'Sequence of Processor Instructions Leads to Unexpected Behavior',
		lang: 'c',
		status: 'Complete',
		what: `特定組合的處理器指令序列導致非預期行為。某些處理器上的指令或其組合（特定編碼、被禁止組合、邊緣記憶體
		屬性）會觸發非預期行為——例如把處理器鎖住，直到需 hard reset 才恢復。一個看似合理卻踩到白化／未定義行為的指令序列，
		可以把執行緒帶進未知路徑、觸發 watchdog 風暴或把 CPU 卡死；若攻擊者能操控輸入以製造出這種具確定性的序列，這就等同
		間接的阻斷服務，或在「卡死」前留下不一致的系統狀態。成因是程式碼在不常見、未定義的指令組合上依賴未言明的行為，或未對
		特定處理器行為做驗證。修法是避開未定義／未建模的指令組合，用受支援的指令集完成工作，並對實際硬體做廣覆蓋的指令序列
		測試，把會觸發異常行為的序列在開發階段就攔下來，而不是留到生產現場才等著當機。`,
		problem: `// 不安全寫法：依賴特定核心對某個編碼組合的既有行為
uint32_t r;
__asm__ volatile("mull %0, %1, %1" : "=r"(r) : "r"(a));   // 特定 stepping 下可鎖片`,
		fixed: `// 安全寫法：改用受支援、定義清楚的運算,由編譯器選合法指令
uint64_t r = (uint64_t)a * (uint64_t)a;   // 受支援的乘法,不依賴未定義編碼`,
		patch: `@@
-  uint32_t r;
-  __asm__ volatile("mull %0, %1, %1" : "=r"(r) : "r"(a));
+  uint64_t r = (uint64_t)a * (uint64_t)a;   // 受支援指令`,
		refs: ['CWE-1281', 'CWE-1208'],
		tags: ['processor', 'instruction', 'undefined-behavior', 'lockup', 'cpu'],
	},
	{
		id: 'CWE-1282',
		name: 'Assumed-Immutable Data is Stored in Writable Memory',
		lang: 'c',
		status: 'Complete',
		what: `被假定「不可變」的資料卻存放在可寫記憶體裡。不可變資料——第一階段 bootloader、裝置識別符、
		write-once 設定——被放在可以被現場重新程式／更新的可寫記憶體（如一般 flash、無保護 RAM、可重編寫的 NVM）。既然它
		們是可寫的，一旦被改寫（透過韌體 bug、未授權更新、或檢測漏洞），這些被假裝「不變」的信任根就被篡改：bootloader 被
		換成惡意的、device ID 被改掉、安全設定被重錘。成因是誤把「我設計時不想改」當成「它物理上不能被改」。修法是讓真正的
		不可變編碼進不可現場更動的儲存（OTP／ mask ROM／受寫保護的 fuse），或至少為其設定嚴格的寫保護與驗簽，確保這類資料
		的寫入不是「可重新程式」的普通路徑，而是一條被硬件鎖死、只能在受控階段觸發的受保護通道。`,
		problem: `// 不安全寫法：first-stage bootloader/裝置 ID 放在一般可寫 flash => 可被覆寫
const uint8_t boot0[] __attribute__((section(".app_flash"))) = { 0xEB, 0x01 };
// device_id 也在同一棵可重編寫 NVM 中`,
		fixed: `// 安全寫法：不可變資料進 OTP/受寫保護區,且硬體阻擋其寫入
PLACE_IN_SECURE_OTP(boot0);   // 一次性/受寫保護,現場不可重程式`,
		patch: `@@
-  const uint8_t boot0[] __attribute__((section(".app_flash"))) = { 0xEB, 0x01 };
+  PLACE_IN_SECURE_OTP(boot0);   // OTP/受寫保護,不可現場改`,
		refs: ['CWE-1282', 'CWE-123'],
		tags: ['immutable', 'writable', 'flash', 'tamper', 'boot'],
	},
	{
		id: 'CWE-1286',
		name: 'Improper Validation of Syntactic Correctness of Input',
		lang: 'node',
		status: 'Complete',
		what: `對輸入的「語法正確性」驗證不當。產品收取的輸入被預期要「well-formed」——要符合某種語法（syntax）——
		但產品沒有驗證、或不正確地驗證該輸入是否符合語法。例如一個要能安全解析的欄位（長度、字元集合、欄位結構）沒有被
		檢查；後續若假設它已是合法語法而去 parse，就會在解析上走進非預期路徑：過長欄位觸發緩衝溢出、意外字元觸發解析錯誤、
		或把半壞的結構吞進邏輯而產生錯狀態。這個弱點驗的是輸入的「形態」而非「性質」：先確認結構乖方才去解釋它。修法是對每個
		「預期 well-formed」的輸入，在進入任何依賴其結構的邏輯之前，明確檢查並通過語法驗證——長度、允許的字元集合、必要的欄位
		與分隔符，任何一項不符合即拒絕，不讓半壞輸入有機會以「合法語法」的地位流進後續處理。`,
		problem: `// 不安全寫法：沒先驗證語法,假設一定找得到分隔符才 parse
function parseLine(buf) {
  const idx = buf.indexOf('\n');                // 假設一定有分隔符
  const line = buf.toString('utf8', 0, idx);  // idx=-1 時 slice 行為非預期
  return JSON.parse(line);                     // 半壞輸入直接進 parse
}`,
		fixed: `// 安全寫法：先行語法驗證(分隔符、非空、結構完整),不符即拒
function parseLine(buf) {
  const idx = buf.indexOf('\n');
  if (idx < 1) throw new Error('malformed');     // 需有分隔符且非空
  const line = buf.toString('utf8', 0, idx);
  const obj = JSON.parse(line);                   // 形態已完整才 parse
  if (!isWellFormed(obj)) throw new Error('bad syntax');
  return obj;
}`,
		patch: `@@
  function parseLine(buf) {
+    const idx = buf.indexOf('\n');
+    if (idx < 1) throw new Error('malformed');
-    const idx = buf.indexOf('\n');
      const line = buf.toString('utf8', 0, idx);
-    return JSON.parse(line);
+    const obj = JSON.parse(line);
+    if (!isWellFormed(obj)) throw new Error('bad syntax');
+    return obj;
  }`,
		refs: ['CWE-1286', 'CWE-20'],
		tags: ['input-validation', 'syntax', 'malformed-input', 'parsing'],
	},
	{
		id: 'CWE-1288',
		name: 'Improper Validation of Consistency within Input',
		lang: 'node',
		status: 'Complete',
		what: `對輸入內各欄位間「一致性」的驗證不當。輸入包含多個元素／欄位，它們彼此必須一致；但產品沒有驗證、或
		不正確地驗證欄位之間的一致性。例如請求同時宣告「傳輸長度」與「實際資料長度」、檔名的副檔名與內容型別、起訖欄位、
		或上下界，這些彼此必須吻合；若沒有跨欄位檢查，這些互有矛盾的欄位會被當成可信資料來用，造成資料結構被解釋成不一致的
		狀態——緩衝區讀寫越界、解析錯位、或把明顯矛盾的授權意圖照單全收。成因是把每個欄位「各自」獨立驗證而忽略了「跨欄位」
		的約束。修法是明確列出所有欄位之間必須成立的不變式（invariant），在處理容器內容之前驗證這些不變式彼此一致；只要有一個
		矛盾就整份拒絕，不讓內部自成矛盾但「單欄位看似合法」的輸入通過。`,
		problem: `// 不安全寫法：只信任 header 宣告長度,未驗證與實際 body 一致
function unpack(hdr, body) {
  const n = hdr.len;                              // 假定 hdr.len 與 body 相符
  return parse(body.slice(0, n));                 // 沒驗證 hdr.len 等於 body.length
}`,
		fixed: `// 安全寫法：先驗證欄位間一致性(宣告長度 = 實際長度)
function unpack(hdr, body) {
  if (hdr.len !== body.length) throw new Error('inconsistent length');  // 跨欄位不變式
  return parse(body);
}`,
		patch: `@@
  function unpack(hdr, body) {
-    const n = hdr.len;
-    return parse(body.slice(0, n));
+    if (hdr.len !== body.length) throw new Error('inconsistent length');
+    return parse(body);
  }`,
		refs: ['CWE-1288', 'CWE-20'],
		tags: ['input-validation', 'consistency', 'invariant', 'cross-field'],
	},
	{
		id: 'CWE-1289',
		name: 'Improper Validation of Unsafe Equivalence in Input',
		lang: 'node',
		status: 'Complete',
		what: `對輸入中「不安全的等價」驗證不當。產品收到的輸入值被當成資源識別符或其他型別的參考（路徑、URL、檔名、
		組態 key），卻沒有驗證該輸入是否「等價」於某個可能不安全的值。輸入可以化簡／正規化後等於某個危險目標——例如「..」、
		已存在的受保護資源、".env"、管理員路徑——而產品只以「原樣」與白名單比，就讓這個形狀看起來不同、實際指向同一目標的
		輸入被當成無誤放行。成因是直接拿原始輸入當鍵，沒做「等價於危險目標」的化簡與比對。修法是先把輸入正規化到唯一定義的
		key／參考形式，再與保守的「不安全值」集合做等價比對；任何命中（包括經過化簡後命中）都一律拒絕，而不是拿未化簡的原樣與
		allowlist 相比，讓化簡路徑能繞過白名單。`,
		problem: `// 不安全寫法：未正規化、未做等價比對, raw 變體能繞過白名單
function resolveKey(raw) {
  if (ALLOW.has(raw)) return readResource(raw);   // 'dir/..' 或 './.env' 這類變體被放行
  throw new Error('denied');
}`,
		fixed: `// 安全寫法：正規化到唯一定義形式,再對不安全目標做等價比對
function resolveKey(raw) {
  const norm = path.normalize(raw);              // 化簡成唯一形式
  if (norm === '..' || UNSAFE.has(norm)) throw new Error('unsafe');   // 等價比對
  return readResource(norm);
}`,
		patch: `@@
  function resolveKey(raw) {
-    if (ALLOW.has(raw)) return readResource(raw);
+    const norm = path.normalize(raw);
+    if (norm === '..' || UNSAFE.has(norm)) throw new Error('unsafe');
-    throw new Error('denied');
+    return readResource(norm);
  }`,
		refs: ['CWE-1289', 'CWE-22'],
		tags: ['input-validation', 'unsafe-equivalence', 'path', 'canonicalization'],
	},
	{
		id: 'CWE-1290',
		name: 'Incorrect Decoding of Security Identifiers',
		lang: 'verilog',
		status: 'Complete',
		what: `把 bus-transaction 訊號解碼成 security identifier（安全識別符）時實作錯誤。產品實作一段解碼機制，要把
		某些匯流排交易訊號解碼成對應的安全識別符；解碼若寫錯，不被信賴的 agent（未授權 master／component）就可能被解成「受信／
		較高權限」的身分，進而取得本不該有的存取權。例如 AXI prot/user 位元被錯解，或某些 agent 身分位元沒納入解碼，就會把
		多個來歷無差別地當成同一個（甚至最高權限）身分；所有下游以該識別符判斷的存取控制全部被架空。成因是解碼邏輯與身分定義
		不符，缺少「未知組合→最低權限」的工程習慣。修法是讓解碼對任何「未能以白名單身分解出的組合」一律 fallback 成最低權限並
		拒絶，並在 build 階段對解碼對照表做形式化驗證，確保 untrusted 訊號永遠解不出 trusted 身分。`,
		problem: `// 不安全寫法：default 把未定義組合解成最高權限 => 未授權被架空
function automatic [1:0] decode_id(input [2:0] prot);
    case (prot)
        3'b000: return ID_S;
        3'b001: return ID_U;
        default: return ID_SECURE_MASTER;   // 未知=最高權限,風險
    endcase
endfunction`,
		fixed: `// 安全寫法：未定義組合一律導到最低權限
function automatic [1:0] decode_id(input [2:0] prot);
    case (prot)
        3'b000: return ID_S;
        3'b001: return ID_U;
        default: return ID_UNTRUSTED_LOWEST;   // 未知組合落最低權限
    endcase
endfunction`,
		patch: `@@
         3'b000: return ID_S;
         3'b001: return ID_U;
-        default: return ID_SECURE_MASTER;
+        default: return ID_UNTRUSTED_LOWEST;   // 未知一律最低`,
        refs: ['CWE-1290', 'CWE-863'],
        tags: ['security-identifier', 'decode', 'access-control', 'untrusted'],
	},
	{
		id: 'CWE-1291',
		name: 'Public Key Re-Use for Signing both Debug and Production Code',
		lang: 'c',
		status: 'Complete',
		what: `同一把公鑰同時被用來簽署並驗證除錯碼（debug code）與生產碼（production code）。若 debug 與 production
		程式碼共用同一把簽章私鑰／對應公鑰，這把金鑰就被同時用於防護兩類影像。除錯碼通常權限大、防護鬆、且會分布到更多
		人手上；一旦 debug 域的私鑰洩漏（或 debug 影像被抽出、反向），攻擊者就能拿同一把剩簽 production image，把要部署到終端的
		生產韌體污染成卻帶後門的版本。成因是把金鑰管理過度簡化，把安全位準不同的兩類影像合用一把金鑰。修法是依資安等級分離
		金鑰：debug code 用獨立、且最好是權限較低或可吊銷的金鑰，production code 用僅存在受控安全環境的 production key；任一路
		洩漏都不應危及另一路，並在開機驗證時也區分影像類別，讓 debug 與 production 的信任邊界彼此獨立。`,
		problem: `// 不安全寫法：debug 與 production 共用同一把簽章 key
bool validate_prod_img(const img_t *img) {
    return rsa_verify(img, shared_pubkey);   // debug 也用它簽 => 洩漏互炸
}`,
		fixed: `// 安全寫法：依影像類別用分離、信任位不同的 key
bool validate_img(const img_t *img) {
    const key_t *kp = (img->type == IMG_PRODUCTION) ? prod_pubkey : debug_pubkey;
    return rsa_verify(img, kp);   // 分離金鑰,洩漏彼此不互蝕
}`,
		patch: `@@
-  bool validate_prod_img(const img_t *img) {
-      return rsa_verify(img, shared_pubkey);
+  bool validate_img(const img_t *img) {
+      const key_t *kp = (img->type == IMG_PRODUCTION) ? prod_pubkey : debug_pubkey;
+      return rsa_verify(img, kp);   // 分離金鑰
   }`,
		refs: ['CWE-1291', 'CWE-327'],
		tags: ['key-reuse', 'debug', 'signing', 'production', 'trust'],
	},
	{
		id: 'CWE-1292',
		name: 'Incorrect Conversion of Security Identifiers',
		lang: 'verilog',
		status: 'Complete',
		what: `把 bus-transaction 訊號轉換（conversion）到 security identifier 時實作錯誤。產品實作一段轉換機制，要把
		匯流排交易訊號透過轉換函式對應到安全識別符；轉換若實作錯，不被信賴的 agent 可被轉成較高權限／受信的身分，獲得未授權
		的資產存取。它與「錯誤解碼」（CWE-1290）相似，差別在於這裡強調從一個域／形式的識別符「轉換」到另一種表示時的對照表或
		換算錯誤——例如多對一、或在換算時遺失最低權限位元，使不同 agent 被併到同一個身分。成因是轉換映射與安全設計不符、缺少
		驗證。修法是讓轉換對所有輸入組合維持「依權限方向正確、未知落最低權限」的映射：對未知／未列組合一律導到最低權限，並以形式化
		方法證明 untrusted 訊號無法被轉換成 trusted 身分，避免身份經由映射被意外抬高。`,
		problem: `// 不安全寫法：換算時遺失最低權限位元,多個 agent 併成同一 secure id
function automatic [1:0] conv_id(input [3:0] sid);
    return sid[3:2];   // 低權限資訊丟失 => 不同 agent 都被頂成高權身分
endfunction`,
		fixed: `// 安全寫法：明確映射,未知組合一律最低權限
function automatic [1:0] conv_id(input [3:0] sid);
    case (sid)
        4'b1000, 4'b0100: return ID_S;
        4'b0010, 4'b0001: return ID_U;
        default:            return ID_UNTRUSTED_LOWEST;   // 未知一律最低
    endcase
endfunction`,
		patch: `@@
-  function automatic [1:0] conv_id(input [3:0] sid);
-      return sid[3:2];
-  endfunction
+  function automatic [1:0] conv_id(input [3:0] sid);
+      case (sid)
+          4'b1000, 4'b0100: return ID_S;
+          4'b0010, 4'b0001: return ID_U;
+          default:            return ID_UNTRUSTED_LOWEST;
+      endcase
+  endfunction`,
		refs: ['CWE-1292', 'CWE-863'],
		tags: ['security-identifier', 'conversion', 'mapping', 'untrusted'],
	},
	{
		id: 'CWE-1293',
		name: 'Missing Source Correlation of Multiple Independent Data',
		lang: 'node',
		status: 'Complete',
		what: `缺少對多個獨立資料來源的交叉比對。產品只依賴單一來源的資料來做決定，因此當該資料來源被敵方攻破或篡改時，
		沒有任何第二個獨立來源可用來揭露異常。感測值、設備狀態、交易唯一性、身分判斷取自單一通道；若該通道的讀取被玩家控制，產品就
		完全被瞞在鼓裡——一個感測器被餵假資料，但沒有任何同位指標可以看穿。成因是把信頼收斂到「單點」，以為「只要這個來源真，
		決定就真」，卻忽略了來源本身是可控的。修法是讓決定性的資訊來自多個獨立、可交叉比對的來源：當各來源內容不一致時視為異常並拒絶，
		用多源驗證的一致取代對單一來源的盲信，逼敵方必須同時攻破多個點才能矇騙系統，把單點失守放大成多點同時被掌控的難度。`,
		problem: `// 不安全寫法：只信單一 sensor 來源,被餵假也照單受理
function overVoltage(s1) {
  return s1.raw > THRESHOLD;   // 單一通道,可被假資料矇騙
}`,
		fixed: `// 安全寫法：多個獨立來源一致才採信,不一致視為異常
function overVoltage(s1, s2, s3) {
  const v = [s1.raw, s2.raw, s3.raw];
  if (Math.abs(v[0] - v[1]) > TOL || Math.abs(v[1] - v[2]) > TOL)
    throw new Error('discordant sources');
  return median(v) > THRESHOLD;   // 多源一致才下判斷
}`,
		patch: `@@
-  function overVoltage(s1) {
-    return s1.raw > THRESHOLD;
-  }
+  function overVoltage(s1, s2, s3) {
+    const v = [s1.raw, s2.raw, s3.raw];
+    if (Math.abs(v[0] - v[1]) > TOL || Math.abs(v[1] - v[2]) > TOL)
+      throw new Error('discordant sources');
+    return median(v) > THRESHOLD;
+  }`,
		refs: ['CWE-1293', 'CWE-353'],
		tags: ['source-correlation', 'redundancy', 'multi-source', 'integrity'],
	},
	{
		id: 'CWE-1295',
		name: 'Debug Messages Revealing Unnecessary Information',
		lang: 'c',
		status: 'Complete',
		what: `除錯訊息洩漏了不必要、甚至敏感的資訊。產品沒有妥善防止除錯訊息把不必要且可能敏感的系統資訊洩漏出去。
		除錯日誌、error message、assert、printf／SWD 後門常內嵌金鑰片段、組態、記憶體地址、內部結構細節或使用者資料；這些訊息
		很多時候預設開啟、或在 release 只是「被關」而非「被移除」，被攻擊者從 console、日誌檔案或開放的偵錯介面讀到後，就成為開啟
		更深入攻擊的資訊源。成因是只考量「對開發有用」而忽略這些字串在部署後的暴露面。修法是對除錯輸出做嚴格的資安審查：release build
		不編譯進敏感字串，只記錄非敏感的 event／類別與唯一事件 ID，並把寫進日誌的敏感資料降到最小，確保訊息內容不足以推導內部機密，
		機密細節即便要診斷也只進受控、不會出現於一般輸出。`,
		problem: `// 不安全寫法：除錯訊息直接印出金鑰/地址等敏感資料,且 release 仍開啟
fprintf(stderr, "aes key=%s reg=%p tok=%s\n", aes_key, (void *)reg, auth_token);`,
		fixed: `// 安全寫法：release 只印非敏感的事件類別與 ID
log_event(EVT_AUTH_ERR);   // 不印任何機密,細節停在受控診斷端`,
		patch: `@@
-  fprintf(stderr, "aes key=%s reg=%p tok=%s\n", aes_key, (void *)reg, auth_token);
+  log_event(EVT_AUTH_ERR);   // 非敏感,不帶機密`,
		refs: ['CWE-1295', 'CWE-532'],
		tags: ['logging', 'debug-message', 'information-leak', 'sanitization'],
	},
	{
		id: 'CWE-1296',
		name: 'Incorrect Chaining or Granularity of Debug Components',
		lang: 'c',
		status: 'Complete',
		what: `除錯元件（debug component）的 chaining（串接）或 granularity（粒徑）不正確。晶片除錯機能常由多個如 TAP／JTAG、
		trace、程式結點組成一條 chain，各元件負責收集／轉送除錯資訊。若把多個安全位準不同的功能串在同一條 chain，或在錯誤的粒徑層把不
		相干的區塊一起暴露，攻擊者就能從鏈中某一個薄弱處順藤到其他不相干、但安全敏感的除錯點；或在該粒徑下的權限判定，把本不該一起
		放出的除錯內容一起送出。成因是除錯拓樸設計沒顧慮資安：該分開的沒分開、該只在封鎖期存在的在開放期也可登入。修法是按資安位準
		切割除錯鏈並控制各 chain 的啟用時機與粒徑：只把同一授權層的元件串在一起，越權的除錯功能成熟封裝後就鎖／關閉；未授權的讀取的
		粒徑不會放行任何除錯資料，讓鏈的組成與暴露範圍都落在昂控的授權內。`,
		problem: `// 不安全寫法：把安全關鍵回調與一般除錯串同一條 JTAG chain,粒徑過粗
chain_add(DEBUG_FUNC_ALL);   // 連帶暴露 SECURE registers 的粒徑`,
		fixed: `// 安全寫法：不同資安位準分鏈,交集只在受授權 router
chain_add(DEBUG_FUNC_PUBLIC);          // 公開功能一條鏈
chain_secure_add(DEBUG_FUNC_SECURE);   // 安全級分開,需專用授權`,
		patch: `@@
-  chain_add(DEBUG_FUNC_ALL);
+  chain_add(DEBUG_FUNC_PUBLIC);
+  chain_secure_add(DEBUG_FUNC_SECURE);   // 分鏈 + 粒度受授權`,
		refs: ['CWE-1296', 'CWE-200'],
		tags: ['debug', 'chain', 'granularity', 'jtag'],
	},
	{
		id: 'CWE-1297',
		name: 'Unprotected Confidential Information on Device is Accessible by OSAT Vendors',
		lang: 'c',
		status: 'Complete',
		what: `裝置上的機密資訊沒有受護，使得外包封裝／測試廠（OSAT）可以取得。製造流程裡，晶圓會送到 OSAT
		（Outsourced Semiconductor Assembly And Test）做切割、封裝、測試；若把機密（測試金鑰、程式碼、設定、使用者資料）以明文或受護
		不住的形式送過 OSAT 端設備，或存在待測試區域，OSAT 的既有作業與工具就能讀到它。即使 OSAT 個別可信，把不必要地大量的機密暴露
		給「工程鏈的中间人」仍違反最小洩露原則：一旦 OSAT 那一端失守，全部機密就同步失守。成因是為了工序方便而讓非受控執行面碰到機密。
		修法是只把 OSAT 完成工作所需的內容交付給它，並把機密加密／混淆，或做成一次性（one-time）／受限形式，確保 OSAT 摸到的盡量是
		不敏感的或因一次性而解不開的形態，並可在測試完成後作廢，把暴露面收到最小。`,
		problem: `// 不安全寫法：把測試金鑰以明文送過 OSAT 端設備處理
deploy_to_osat(test_key_plaintext, img);   // OSAT 工具直接讀到明文機密`,
		fixed: `// 安全寫法：只交付 OSAT 必需、且加密/一次性形式的內容
deploy_to_osat(encrypt_for_osat(img, osat_derived_key), digest);   // 解不開或一次性`,
		patch: `@@
-  deploy_to_osat(test_key_plaintext, img);
+  deploy_to_osat(encrypt_for_osat(img, osat_derived_key), digest);   // 一次性加密`,
		refs: ['CWE-1297', 'OWASP'],
		tags: ['osat', 'supply-chain', 'confidential', 'encryption', 'least-privilege'],
	},
	{
		id: 'CWE-1298',
		name: 'Hardware Logic Contains Race Conditions',
		lang: 'verilog',
		status: 'Complete',
		what: `硬體邏輯存在競態（race condition），破壞系統的安全保證。同一個暫存器／訊號被多個來源同時且不同步地更新、
		combo 路徑與時脈產生不確定值、或安全閘（secure gate）與一般資料路徑不同步，使得一個開關就能在「狀態未確定」的窗口中被看見
		或被改變；安全屬性（存取閘、授權標記、FIFO 邊界）在這種競態窗口中失真。攻擊者若能構造時序／輸入把這扇競態窗敲開，就能在閘
		沒有真正閉上時讓資料通過或篡改，資安保證在那一瞬失效。成因是電路裡「互相獨立更新的事件」如何確序沒有時脈約束或同步。修法是讓所有
		安全相關狀態都以單一時脈域、用明確的握手／同步器達到單一更新來源更新，並以形式化時序檢查確保更新事件被正確確序，讓授權閘的決定不
		受時序不確定影響，把競態窗從電路上根除掉。`,
		problem: `// 不安全寫法：同一個授權標記被兩組 independent logic 更新 => 競態
always @(posedge clkA) grant <= g1;   // 來源 A
always @(posedge clkB) grant <= g2;    // 來源 B 未同步 => grant 值不確定`,
		fixed: `// 安全寫法：授權狀態由單一時脈域 + 同步握手更新
always @(posedge clk) begin
    if (grant_req && synced_valid) grant_q <= g;   // 單時脈域、單來源、有同步
end`,
		patch: `@@
-  always @(posedge clkA) grant <= g1;
-  always @(posedge clkB) grant <= g2;
+  always @(posedge clk)
+      if (grant_req && synced_valid) grant_q <= g;   // 同步、單源`,
		refs: ['CWE-1298', 'CWE-362'],
		tags: ['race-condition', 'hardware', 'synchronizer', 'access-control'],
	},
	{
		id: 'CWE-1299',
		name: 'Missing Protection Mechanism for Alternate Hardware Interface',
		lang: 'verilog',
		status: 'Complete',
		what: `對「替代硬體介面（alternate hardware interface）」缺乏保護機制。有受控資產透過主路徑有存取控制保護，但硬體
		還有其他「替代路徑」也通得到該資產——未受保護的 shadow 暫存器、額外的 bus master、sideband 介面、多的 debug／測試口、或 fabric
		中另一個未含閘的對接——這些旁路的問題是沒有套用與主路徑相同的保護。攻擊者只要不走「受保護的主路徑」而是選一條未上鎖的替代路徑，
		就能把現有對資產的存取控制整個繞過。成因是只對「主要的地址／介面」做 gate，忽略其他也能解到同一資源的物理或邏輯路徑。修法是為每個
		資產識別並列出其「所有可達路徑」，在 fabric 的入口與每一條路徑上都一致地施加存取過濾，讓替代介面與主介面共用同一道授權控制，確保
		沒有一條未受保護的旁路可以獨立解到受保護資源。`,
		problem: `// 不安全寫法：主介面有 gating,替代 shadow 介面未上保護
assign main_rw_en = auth_ok & req_valid;   // 主路徑有 check
assign sh_rw_en   = shadow_valid;           // 旁路無閘 => 繞過保護`,
		fixed: `// 安全寫法：替代介面共用同一道授權判定
assign sh_rw_en = auth_ok & shadow_valid;   // 與主路徑同 gate`,
		patch: `@@
-  assign sh_rw_en = shadow_valid;
+  assign sh_rw_en = auth_ok & shadow_valid;   // 共用同閘`,
		refs: ['CWE-1299', 'CWE-284'],
		tags: ['alternate-interface', 'shadow-register', 'bypass', 'access-control'],
	},
	{
		id: 'CWE-1300',
		name: 'Improper Protection of Physical Side Channels',
		lang: 'c',
		status: 'Complete',
		what: `對物理側通道（physical side channel）的保護不足。裝置沒有充足的保護機制，防止物理側通道把敏感資訊洩漏出去。
		側通道是指透過可察覺的物理現象洩漏機密：功耗起伏、電磁發射（EME）、聲波、時間，這些都會受資料或金鑰影響而起伏。密碼運算（尤其對
		資料或分支有依賴的實作）在這些通道上往往透露操作數或分支資訊；電路每次運算的功耗／EM 波形都帶有金鑰位元的影子，經 FFT／統計分析
		（如 SPA／DPA／EDA）就可逐步還原金鑰。成因是只顧邏輯保安而未對「物理可量測的高了部分」做掩蔽。修法是做對抗側通道的工程：constant-time、
		隨機化（掩碼、blinding）、功耗域加噪音、佈局上把 EM 混動與遮蔽、對敏感運算做 equalized，並以 SPA／DPA／EM 測試驗證隨掃，把機密在
		任一物理通道上的洩漏壓到無法利用。`,
		problem: `// 不安全寫法：分支依賴金鑰 bit => power/EM 洩密
bigint_t mul_or_nop(const bigint_t *a, int key_bit) {
    if (key_bit) return bigint_mul(a, base);   // 分支造成可測量的功耗差異
    return a[0];
}`,
		fixed: `// 安全寫法：constant-time + 掩碼,分支與功率與 key 無關
c = bigint_mul(a, base_sel);              // 一律執行乘法,不依 key bit 分支
r = bigint_unmask(c, mask_factor);         // 運算式先掩碼,結果再解掩`,
		patch: `@@
-  bigint_t mul_or_nop(const bigint_t *a, int key_bit) {
-      if (key_bit) return bigint_mul(a, base);
-      return a[0];
-  }
+  c = bigint_mul(a, base_sel);      // constant-time
+  r = bigint_unmask(c, mask_factor);  // 掩碼打散側通道`,
		refs: ['CWE-1300', 'CWE-203'],
		tags: ['side-channel', 'dpa', 'em-emission', 'power-analysis', 'constant-time'],
	},
	{
		id: 'CWE-1301',
		name: 'Insufficient or Incomplete Data Removal within Hardware Component',
		lang: 'c',
		status: 'Complete',
		what: `硬體元件內的資料移除過程不徹底，沒有把資料完全刪除乾淨。產品的資料移除流程沒有把硬體元件中的資料及其中可能
		敏感的資訊清乾淨。「清除」往往只是邏輯刪除或一次不確定的寫入，只清掉主區的位元而留下殘留（remanence 在 RAM、flash、電容、暫存器、
		cache 的殘值），仍可被復原。當殘留對應的是金鑰、明文、快取的使用者資料，落到下一手或二手轉讓時就可被完整還原。成因是清除未經驗證、
		或只做「邏輯删除」而非物理抹淨。修法是實施並驗證物理性清除：多次寫入／淡化、對 NVM 做 block erase 後回讀驗證、涵蓋所有儲存載體
		（主存、flash、cache、暫存器），確定不留任何可復原殘值，並在釋出／轉讓硬體前確實執行此抹淨流程，用回讀比對保證真的清乾淨了。`,
		problem: `// 不安全寫法：清除只用 memset,未必寫穿且無回讀驗證
void wipe(uint8_t *buf, size_t n) {
    memset(buf, 0, n);   // 優化器可能跳過;也無驗證值是否真的寫穿
}`,
		fixed: `// 安全寫法：volatile 抹淨不會被優化,並回讀驗證清空
void wipe(uint8_t *buf, size_t n) {
    size_t orig = n;
    volatile uint8_t *p = buf;
    while (n--) *p++ = 0x00;          // volatile => 不會被優化掉
    verify_zeroed(buf, orig);            // 回讀比對確認殘值清淨
}`,
		patch: `@@
  void wipe(uint8_t *buf, size_t n) {
-      memset(buf, 0, n);
+      volatile uint8_t *p = buf;
+      while (n--) *p++ = 0x00;   // 不優化、寫穿
+      verify_zeroed(buf, orig_n);     // 回讀驗證
  }`,
		refs: ['CWE-1301', 'CWE-212'],
		tags: ['data-removal', 'erasure', 'remanence', 'wipe', 'sanitization'],
	},
	{
		id: 'CWE-1302',
		name: 'Missing Source Identifier in Entity Transactions on a System-On-Chip (SOC)',
		lang: 'verilog',
		status: 'Complete',
		what: `SOC 上、來自某原本（entity）的交易缺少 source identifier（來源識別符）。產品實作一套 security identifier 機制，
		用以區分交易源自哪個實體、判定哪些動作被允許；但某筆交易送出時沒有帶上來源安全識別符。於是下游以該識別符做判斷的存取控制，面對這筆
		「無身分標籤」的交易無法分辨它的權限，容易把它視為「無限制／預設允許」或「無從判斷」而放行，來自低信任實體的請求就可能以不明身分越界
		到受保護的資產。成因是把某些 master／路徑落在身分標記設計之外、沒被賦予識別符。修法是保證「任何實體發出的任何交易」都帶有被定義的
		source security identifier；對缺少／未妥當標記的交易一律以最低權限或拒絶處理，並在 fabric 入口對「缺失身分」的交易做失敗關閉，讓
		沒有身分的交易根本走不到受保護資源。`,
		problem: `// 不安全寫法：某個 master 的交易沒帶 source id => 下游視為無識別/可通行
assign src_id = (master == ALIEN_MASTER) ? NO_ID : id_lut[master];   // NO_ID 被當無限制`,
		fixed: `// 安全寫法：缺身分一律導到最低權限
assign src_id = (master == ALIEN_MASTER) ? ID_UNTRUSTED_LOWEST : id_lut[master];`,
		patch: `@@
-  assign src_id = (master == ALIEN_MASTER) ? NO_ID : id_lut[master];
+  assign src_id = (master == ALIEN_MASTER) ? ID_UNTRUSTED_LOWEST : id_lut[master];`,
		refs: ['CWE-1302', 'CWE-863'],
		tags: ['soc', 'source-id', 'security-identifier', 'fabric'],
	},
	{
		id: 'CWE-1304',
		name: 'Improperly Preserved Integrity of Hardware Configuration State During a Power Save/Restore Operation',
		lang: 'c',
		status: 'Complete',
		what: `電源省電／還原（power save／restore）操作之間，硬體設定狀態的完整性沒有被維持或驗證。產品進行 power
		save／restore，但在操作起訖之間並未確保設定狀態的完整性被維持、或被驗證。低電址域（sub-power domain）的暫存器在省電時被關電、
		restore 時又載回；若 save／restore 的內容（設定暫存器、安全設定、NVM 快取）沒被完整保存與比對，或 restore 路徑不驗證寫回值，
		可能丟失部分設定、或載回被篡改的值而不自知——安全相關設定因此被改掉而系統仍照常啟動，攻擊者可透過電源操控誘使系統掉回不安全的設定。
		成因是 save／restore 沒有與安全設定連動、缺復現驗證。修法是對硬體安全設定維持「省電期間遭改即失效」的保護，並在 restore 時對寫回值做
		完整性檢查（CRC／ECC／回讀比對）；任何不一致都觸發安全失效並回到已知的安全設定，不把可能被篡改或喪失的狀態當作可用的組態。`,
		problem: `// 不安全寫法：power save/restore 直接載回,不驗證完整性
void restore_cfg(void) {
    memcpy(cfg, saved_cfg, sizeof *cfg);   // 不查是否被篡改/失落/斷電
}`,
		fixed: `// 安全寫法：restore 前後做完整性驗證,敗時回安全預設
void restore_cfg(void) {
    if (crc32(saved_cfg, sizeof *saved_cfg) != saved_crc)   // 完整性檢查
        return reset_to_secure_defaults();                       // 不一致 => 安全失效
    memcpy(cfg, saved_cfg, sizeof *cfg);
}`,
		patch: `@@
  void restore_cfg(void) {
+    if (crc32(saved_cfg, sizeof *saved_cfg) != saved_crc)
+        return reset_to_secure_defaults();
      memcpy(cfg, saved_cfg, sizeof *cfg);
  }`,
		refs: ['CWE-1304', 'CWE-353'],
		tags: ['power-save', 'integrity', 'configuration', 'restore'],
	},
	{
		id: 'CWE-1310',
		name: 'Missing Ability to Patch ROM Code',
		lang: 'c',
		status: 'Complete',
		what: `缺少修補 ROM 程式碼的能力。系統／SoC 少了「打 patch ROM 代碼」的機制，讓它留在受漏洞影響的狀態。ROM
		code（常是 boot ROM）在矽片製定後就固定無法更改；若在其中發現弱點，又沒有提供「以 NVM／可信影像在開機時修飾 ROM 行為」的能力
		（patch table、overlay、indirect jump remap），就只能讓每個韌體版本都繞著它打轉，甚至在該處根本無解、只能整批回收。當弱點落在 boot
		ROM 這種信任最前端，後續的韌體更新也無法根除，攻擊者總能回到那個固定的弱 ROM。成因是設計時沒預想 ROM 也可能有 bug，故沒預留修飾入口。
		修法是為 ROM 設計一條受信任的 patch 路徑：ROM 開機時查核並接受「只針對已知問題」的修飾資料（覆寫可改行為、重導間接呼叫），而 patch
		影像本身要驗簽、且可受韌體更新控制，如此 ROM 弱點能被現場修掉而不必換晶片。`,
		problem: `// 不安全寫法：ROM 程式碼被直接執行,無任何 patch/overlay 機制
void boot_from_rom(void) {
    rom_main();   // bug 發現後仍只能跑壞的 ROM
}`,
		fixed: `// 安全寫法：開機時查受驗證的 patch table 再重導
void boot_from_rom(void) {
    const patch_tbl_t *pt = get_verified_patch();     // 受信任、驗證的 patch 表
    if (patch_required(pt->rom_rev, BUG_ID)) goto_apply(pt);   // 重導受影響段
    else rom_main();
}`,
		patch: `@@
  void boot_from_rom(void) {
-      rom_main();
+      const patch_tbl_t *pt = get_verified_patch();
+      if (patch_required(pt->rom_rev, BUG_ID)) goto_apply(pt);
+      else rom_main();
  }`,
		refs: ['CWE-1310', 'CWE-1188'],
		tags: ['rom', 'patch', 'boot', 'firmware'],
	},
	{
		id: 'CWE-1311',
		name: 'Improper Translation of Security Attributes by Fabric Bridge',
		lang: 'verilog',
		status: 'Complete',
		what: `fabric 橋（bridge）在把交易從某種傳輸協定轉到另一協定時，錯誤地轉譯其安全屬性。bridge 負責跨 fabric
		protocol 轉換，同時要把安全屬性（trusted／untrusted、權限位準、secure 標記）一起翻譯；若把它從「trusted 譯成 untrusted」或
		「untrusted 譯成 trusted」，就會把低信任資料貼上高信任標籤（下游誤以為該筆已通過安全檢查而放行未授權內容），或反過來把本該受保護的
		標籤吹高。trusted／untrusted 平衡一旦壞掉，存取控制判斷就整個謊報，攻擊者可以借橋讓未授權交易以「已授權」的身分穿越。成因是 bridge
		的屬性對照／換算未與兩端安全語域校準，或有些屬性位元在轉換時遺失。修法是讓 bridge 對安全屬性做單一、正向的對照並保留／標記繼承，
		對「無法映射」的屬性一律落到最低權限，並用 fabric 驗證屬性在每筆跨界交易上的傳播一致。`,
		problem: `// 不安全寫法：bridge 錯換,把 untrusted 譯成 trusted => 屬性被抬升
function automatic [1:0] xlate(input [1:0] attr);
    return (attr == 2'b01) ? 2'b11 : attr;   // untrusted 被頂成 trusted
endfunction`,
		fixed: `// 安全寫法：明確映射,未知/未列一律最低權限
function automatic [1:0] xlate(input [1:0] attr);
    case (attr)
        2'b11: return 2'b11;   // trusted => trusted
        2'b01: return 2'b01;   // untrusted 保持 untrusted
        default: return 2'b00;  // 未知一律最低權限
    endcase
endfunction`,
		patch: `@@
-  function automatic [1:0] xlate(input [1:0] attr);
-      return (attr == 2'b01) ? 2'b11 : attr;
-  endfunction
+  function automatic [1:0] xlate(input [1:0] attr);
+      case (attr)
+          2'b11: return 2'b11;
+          2'b01: return 2'b01;
+          default: return 2'b00;
+      endcase
+  endfunction`,
		refs: ['CWE-1311', 'CWE-863'],
		tags: ['fabric', 'bridge', 'security-attribute', 'translation'],
	},
	{
		id: 'CWE-1312',
		name: 'Missing Protection for Mirrored Regions in On-Chip Fabric Firewall',
		lang: 'verilog',
		status: 'Complete',
		what: `on-chip fabric 防火牆對其鏡像（mirrored）區域缺保護。fabric 防火牆保護主要定址的區域，但沒有保護任何鏡像的
		記憶體或 MMIO 區域。當同一段實體資源能透過「多個地址別名」（mirroring／aliasing，因解碼寬度或未完全解碼而有多個映射）到達時，
		firewall 通常只對它的主地址設 gate；同一資源的別名地址卻未被過濾。攻擊者避開主門，從沒有 gate 的鏡像地址就能讀寫到同一的受保護
		資源，把主區域的保護整個繞過。成因是防火牆規則以「地址」而非以「實際資源」做驅動，漏掉了別名映射。修法是對所有 mirror／alias 映射建立
		完整的地址表，讓同一受保護資源的「每一條鏡像地址」都受同一道 firewall rule 管轄，或乾脆禁掉不必要的 alias，確保沒有任何未過濾的可達替名
		能繞過主門。`,
		problem: `// 不安全寫法：firewall 只對主解碼地址設規則,鏡像位址不過濾
assign in_prot = (addr >= LO) && (addr <= HI);          // 只查主區域
assign grant  = in_prot ? fw_access_ok : 1'b1;      // 鏡像別名不在表內 => 放行`,
		fixed: `// 安全寫法：把主區域與所有 mirror 地址都納入同一規則
assign in_prot = (addr >= LO && addr <= HI) || (addr >= M_LO && addr <= M_HI);   // 含鏡像
assign grant  = in_prot ? fw_access_ok : 1'b1;`,
		patch: `@@
-  assign in_prot = (addr >= LO) && (addr <= HI);
+  assign in_prot = (addr >= LO && addr <= HI) || (addr >= M_LO && addr <= M_HI);   // 含鏡像`,
		refs: ['CWE-1312', 'CWE-284'],
		tags: ['fabric', 'firewall', 'mirror-region', 'alias', 'bypass'],
	},
	{
		id: 'CWE-1313',
		name: 'Hardware Allows Activation of Test or Debug Logic at Runtime',
		lang: 'verilog',
		status: 'Complete',
		what: `硬體在執行期間（runtime）允許啟動測試／除錯邏輯。這些 test／debug 功能通常只該在開發或封裝驗證時用，例如
		scan-chain、debug port、test mode 開關；若它們在正常執行期間可由一般軟體或外部介面觸發，敵方就能動用該功能「改變硬體狀態」——強制寫
		入安全暫存器、旁路 secure reset、打開 debug 讀寫，進而改變系統目的行為、或洩漏／篡改敏感資料。成因是 test／debug 的啟用時序與權限
		沒有和「進入正常運行」分開管控。修法是讓所有 test／debug 入口只能在受嚴格管控的階段（安全開機前、且經專用授權與身分驗證）才能開，進入
		一般運行後就把它們鎖死／去能（scan 與 debug 全關），對「已進入 runtime 卻仍能開 debug」的一切路徑都拒絶，使這些高權限功能在敵方可及
		的運行時間不存在。`,
		problem: `// 不安全寫法：test/debug 入口在 runtime 仍可由外部信號直接開啟
assign debug_enable = test_pin | dbg_sw[0];   // 一般執行期間也能開`,
		fixed: `// 安全寫法：進入運行即關,僅在授權階段可開
assign debug_enable = (state == SECURE_BOOTING) ? allow_dbg : 1'b0;   // runtime 鎖死`,
		patch: `@@
-  assign debug_enable = test_pin | dbg_sw[0];
+  assign debug_enable = (state == SECURE_BOOTING) ? allow_dbg : 1'b0;   // runtime 關`,
		refs: ['CWE-1313', 'CWE-693'],
		tags: ['debug', 'test-mode', 'runtime', 'scan', 'hardware'],
	},
	{
		id: 'CWE-1314',
		name: 'Missing Write Protection for Parametric Data Values',
		lang: 'c',
		status: 'Complete',
		what: `對感測器的參數資料值缺少寫保護。裝置沒有對「縮放感測器值」的參數資料（如增益、偏移、校準常數）做
		write-protect，讓不受信軟體在執行期間去改這些值。這些參數會把量測值縮放；被改動後，元件的溫度／電壓／電流讀數就會被調成整你想要
		的值——過熱被報成安全、故障被隱藏、甚至讓驅動與真實量測脫鉤，進而可能損壞硬體或造成運作失效。成因是校準資料對普通／不受信主軟體
		可寫，未把它的權限與保護降到最低。修法是將參數資料區置於寫保護（一次性或受授權寫、加上權限門控與完整性保護），校準值只能由受信／安全
		路徑更新；一般使用者軟體對它只可讀不可寫，確保縮放參數不被通用軟體就地竄改。`,
		problem: `// 不安全寫法：校準/縮放參數是一般全域,任何軟體皆可改
static int scale_gain = 100;
long read_temp(void) { return raw * scale_gain / 100; }   // 改 gain 就動了量測`,
		fixed: `// 安全寫法：縮放參數置於寫保護,只由受信校準路徑更新
const int READONLY scale_gain;   // 硬體寫保護
void calibrate(int g) { if (perm(secure_only)) write_otp_params(g); }   // 受信路徑`,
		patch: `@@
-  static int scale_gain = 100;
-  long read_temp(void) { return raw * scale_gain / 100; }
+  const int READONLY scale_gain;   // 寫保護
+  long read_temp(void) { return raw * scale_gain / 100; }
+  void calibrate(int g) { if (perm(secure_only)) write_otp_params(g); }`,
		refs: ['CWE-1314', 'CWE-471'],
		tags: ['write-protect', 'sensor', 'calibration', 'tamper'],
	},
	{
		id: 'CWE-1315',
		name: 'Improper Setting of Bus Controlling Capability in Fabric End-point',
		lang: 'verilog',
		status: 'Complete',
		what: `fabric 端點（end-point）的匯流排控制能力設定不當。匯流排控制器在 fabric 端點啟用的位元，讓回覆端
		（responder）可以控制 fabric 上的交易。通常只有受信的 master／bus controller 才有權在 fabric 上發起或控制交易；若端點本不該具備此控制
		能力，卻把 controlling capability 的 bit 開給它（例如除錯口或弱權的 responder 也能 enumer／arbitrate／fence 交易），低信任端就能操控
		fabric 的仲裁與交易的傳送順序，插入自己帶有篡改屬性的交易，或在錯誤時點抑止／插入，影響存取控制判定與資料完整性。成因是端點能力暫存器
		以不需授權即可寫、或預設就開。修法是讓 fabric 端點的 controlling capability 預設關閉，只在受信配置審核後、透過受授權流程開啟，並把端點
		能控制的交易範圍縮到它該有的權限以內，避免任何低信任端意外取得匯流排控制權。`,
		problem: `// 不安全寫法：responder 的 bus-controlling bit 落入一般可寫 => 低信任可自啟
assign endp_ctrl_en = endp_reg[7];   // 一般軟體可寫,弱權端也能自啟控制能力`,
		fixed: `// 安全寫法：control capability 僅受信配置時開啟,預設關
assign endp_ctrl_en = secure_cfg && busctrl_perm;   // 預設 0,僅受信授權後為 1`,
		patch: `@@
-  assign endp_ctrl_en = endp_reg[7];
+  assign endp_ctrl_en = secure_cfg && busctrl_perm;   // 預設關`,
		refs: ['CWE-1315', 'CWE-269'],
		tags: ['fabric', 'endpoint', 'bus-control', 'privilege'],
	},
	{
		id: 'CWE-1316',
		name: 'Fabric-Address Map Allows Programming of Unwarranted Overlaps of Protected and Unprotected Ranges',
		lang: 'verilog',
		status: 'Complete',
		what: `fabric 的地址映射允許把受保護與未受保護的範圍規劃得互相重疊。on-chip fabric 的地址圖（address map）如果允許
		「protected 區域」與「unprotected 區域」重疊，就會產生這種重疊：受保護與不受保護區各自 map 到同一段實體地址。firewall 以「地址範圍」
		過濾；若同一物理資源同時居住在受保護（會被 gate）的地址與不受保護（不會被 gate）的地址，攻擊者經由不受保護的那條重疊映射，就能把那段資源
		取到手，對重疊部分的受保護區域繞過存取控制。成因是 address map 容許軟體／配置把自己與受保護區規劃到未審查的重疊。修法是讓 fabric 拒絶
		「受保護與未受保護範圍重疊」的映射：規劃時對整個 address map 做不可重疊的完整性檢查，禁止把同一資源既掛受保護又掛未受保護映射，確定每一筆
		可達交易都落在被一致管制且不重疊的規則內，重疊就在規劃階段被卡下。`,
		problem: `// 不安全寫法：addr-region 規則可把 protected 與 unprotected 規劃重疊
reg [31:0] prot_lo, prot_hi, unprot_lo, unprot_hi;   // 未檢查即接受 => 可重疊`,
		fixed: `// 安全寫法：規劃時檢查映射不可重疊,發現重疊即拒
wire overlap = (prot_lo <= unprot_hi) && (unprot_lo <= prot_hi);
always @(posedge clk) if (overlap) assert_error(CONFIG_OVERLAP);   // 重疊被拒`,
		patch: `@@
-  reg [31:0] prot_lo, prot_hi, unprot_lo, unprot_hi;
+  wire overlap = (prot_lo <= unprot_hi) && (unprot_lo <= prot_hi);
+  always @(posedge clk) if (overlap) assert_error(CONFIG_OVERLAP);   // 拒重疊`,
		refs: ['CWE-1316', 'CWE-284'],
		tags: ['fabric', 'address-map', 'overlap', 'access-control', 'bypass'],
	},
	{
		id: 'CWE-1317',
		name: 'Improper Access Control in Fabric Bridge',
		lang: 'verilog',
		status: 'Complete',
		what: `fabric 橋（bridge）在兩個 IP 區塊之間轉送交易時存取控制不當。產品以 fabric bridge 傳送兩個 IP block 間的
		交易，但該 bridge 沒有把預期的 privilege、identity 或其他存取控制檢查在兩 IP 之間正確執行。bridge 應作為權限／身分／存取的強制點；若它
		在轉送時跳過、弱化或直接 pass-through 這些 check，一個本無權取另一側資源的 IP 就能讓交易穿橋直達受保護資產，意即「橋」變成受保護區之間
		的安全後門。成因是只把 bridge 當 bus conversion（bus 轉換）而忘了「跨橋即跨信頼域」，安全屬性就在跨界處退化。修法是讓 fabric bridge 成為
		真正的 enforcement point：轉送前後一致地檢查並維持 privilege／identity／access 屬性，依兩端的信頼域規則放行；正確的存取檢查在每一筆跨界交易
		上都執行，不因「只是換協定」就省略授權判定。`,
		problem: `// 不安全寫法：bridge 對兩 IP 間交易直接轉送,不執行權限檢查
always @(posedge clk) fifo <= in_pkt;   // IP-A 請求直送 IP-B,無身份/權限驗證`,
		fixed: `// 安全寫法：bridge 以 privilege/identity 檢查後才轉送
assign fwd_ok = req_valid & identity_check(req_src, req_dst) & perm_check(req_dst);
always @(posedge clk) if (fwd_ok) fifo <= in_pkt;   // 跨界檢查才放行`,
		patch: `@@
-  always @(posedge clk) fifo <= in_pkt;
+  assign fwd_ok = req_valid & identity_check(req_src, req_dst) & perm_check(req_dst);
+  always @(posedge clk) if (fwd_ok) fifo <= in_pkt;`,
		refs: ['CWE-1317', 'CWE-284'],
		tags: ['fabric', 'bridge', 'access-control', 'crossing'],
	},
	{
		id: 'CWE-1318',
		name: 'Missing Support for Security Features in On-chip Fabrics or Buses',
		lang: 'c',
		status: 'Complete',
		what: `on-chip fabric 或 bus 缺少安全功能支援。on-chip fabric／bus 要麼支持不了、要麼沒有被配置成支持 privilege
		separation 或其他安全功能（例如存取控制）。若 fabric 沒有 protocol 層級的 privilege／security 標記、沒有可掛 firewall 的 hook、或規則根本沒
		配置，就等於一條裸 bus——每一筆交易都以同一預設權限即可通行，受保護內容只能靠各自經它傳送的 IP 自行處理。因為隔離與存取控制要 fabric
		配合，缺了它，SoC 上「只要不高地址就安全」的想像就不成立，弱權 master 可隨意到達高權內容。成因是只把 fabric 當互聯，而非當安全基礎架構。
		修法是讓 fabric 提供並啟用 security／protocol 功能：為交易攜帶 privilege／security 屬性、在每個入口掛一致的 firewall／存取規則，並以配置預設
		「最低權限」，確保安全功能是被固定且被驗證的存在，而不是關掉或根本不支援的選項。`,
		problem: `// 不安全寫法：fabric 無 privilege 分離,規則為空,任何 master 可走任何地址
fabric_configure(FABRIC_DEFAULTS_without_acl);   // 無 protocol 安全標記/規則`,
		fixed: `// 安全寫法：每個入口配置 ACL + 攜帶 privilege 標記,預設最小權限
fabric_set_protocol(FABRIC_PROT_SEC, privilege_tag_on);   // 交易帶安全屬性
each_iface_acl(DEFAULT_DENY_ACL);                      // 預設拒絕,只開允許`,
		patch: `@@
-  fabric_configure(FABRIC_DEFAULTS_without_acl);
+  fabric_set_protocol(FABRIC_PROT_SEC, privilege_tag_on);
+  each_iface_acl(DEFAULT_DENY_ACL);   // 預設拒絶`,
		refs: ['CWE-1318', 'CWE-250'],
		tags: ['fabric', 'bus', 'privilege-separation', 'access-control'],
	},
];
