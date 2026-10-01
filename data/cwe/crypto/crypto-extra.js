// CWE chunk — category: Cryptographic Issues (sources, secrets handling, origin validation / randomness).
//   what    : 簡短、繁中、白話+技術描述（(#) 弱點是什麼)
//   problem : 「壞的寫法」程式片段（(#) 問題長怎樣)
//   fixed   : 「修好的寫法」程式片段（(#) 解完會長怎樣)
//   patch   : problem → fixed 的統一 diff 文字（(#) 範例 patch)
//   lang    : 此條範例主力語言，依 CWE 類別選擇
//   status  : Complete | Incomplete | Deprecated
//   refs    : 參考（OWASP / MITRE 等）
//   tags    : 英文搜尋標籤
export default [
	{
		id: 'CWE-14',
		name: 'Compiler Removal of Code to Clear Buffers',
		lang: 'c',
		status: 'Complete',
		what: `編譯器移除清除緩衝區的程式碼。開發者想用 memset() 抹除含機密的緩衝區，
但編譯器最佳化認為該次寫入「結果從未被讀取」，便把整段 memset 判定為無效
程式碼（dead code）刪除，使得機密在記憶體原封不動。問題根源是依賴標準庫
對已知大小、未使用的 buffer 做清除，編譯器合法地「優化」掉它。有效的清除
必須對編譯器「隱形」。建議做法是改用保證不被最佳化移除的函式：
explicit_bzero（glibc）、SecureZeroMemory（Windows）或 volatile 指針迴圈，
並把清除動作集中在最終使用點、避免在不清除的情況下 return 或釋出。`,
		problem: `char secret[64];
... fill_secret(secret, sizeof(secret));
memset(secret, 0, sizeof(secret));   // -O2 下 "write 後無讀取"，這行可能被整段刪掉
/* 實際上機密還完好留在記憶體 */`,
		fixed: `char secret[64];
... fill_secret(secret, sizeof(secret));
explicit_bzero(secret, sizeof(secret));  // 被標準明確保證的清除，最佳化無法刪除`,
		patch: `@@
-  memset(secret, 0, sizeof(secret));   // -O2 下可能被當 dead code 整段刪掉
+  explicit_bzero(secret, sizeof(secret));  // 保證不可被最佳化移除`,
		refs: ['SEI CERT', 'CWE-14'],
		tags: ['buffer-clear', 'compiler-optimization', 'memset', 'explicit_bzero'],
	},
	{
		id: 'CWE-212',
		name: 'Improper Removal of Sensitive Information Before Storage or Transfer',
		lang: 'c',
		status: 'Complete',
		what: `存放或傳輸前未移除敏感資訊。資料結構裡含有 session token、密碼、內部 ID
或個資這類機密欄位，在執行序列化、寫入 DB、記錄 log、或呼叫外部 API 送出
之前，沒有將其排除或遮蔽，導致機密跟著被存到不相干的地方。任何能讀 log、
dump 或攔截輸出的人，就拿到本不該外流的內容。常見成因是「整個物件一口氣
輸出」。建議做法是在輸出的臨界點刻意只選取必要欄位（allowlist／DTO 對映），
機密欄位一律排除或遮蔽，並覆寫 toString／序列化把機密欄位標記排除。`,
		problem: `// 不安全寫法：把整塊含密碼的 struct 直接寫入 log/trace，機密欄位一起落盤
struct user { char name[32]; char password[64]; };
void log_user(struct user *u) {
    write_log(u, sizeof(*u));   // password 欄位未被剝離，跟著 log 長期留存在磁碟
}`,
		fixed: `// 安全寫法：輸出臨界點只選取允許欄位，機密不進入 log
struct user { char name[32]; char password[64]; };
void log_user(struct user *u) {
    char line[96];
    snprintf(line, sizeof(line), "name=%s", u->name);  // 只輸出 name
    write_log(line);                                    // password 完全不到 log
}`,
		patch: `@@
  void log_user(struct user *u) {
-     write_log(u, sizeof(*u));   // password 跟著 log 出去
+     char line[96];
+     snprintf(line, sizeof(line), "name=%s", u->name);  // allowlist：只要 name
+     write_log(line);
  }`,
		refs: ['OWASP-Secrets', 'CWE-212'],
		tags: ['redaction', 'sensitive-data', 'logging', 'allowlist'],
	},
	{
		id: 'CWE-222',
		name: 'Truncation of Security-relevant Information',
		lang: 'node',
		status: 'Complete',
		what: `截斷與安全相關的資訊。記錄、顯示或處理安全事件時，把對鑑識有用的資訊截斷
——例如 log 事件欄位被固定長度截掉，位在後段的來源 IP、使用者或完整參數被
切掉，只留下殘缺片段。如此攻擊的來源與手法被部分遮蔽，入侵後無法完整重建
事件全貌，難以找出真正的攻擊者或受影響範圍，也容易讓維運人員誤判嚴重度。
常見成因是把多個重要欄位拼成一行再切長度。建議做法是對安全事件以結構化
方式完整記錄時間、來源 IP、使用者、動作與完整參數，長內容拆分多筆或多行，
切勿無心地截斷關鍵欄位。`,
		problem: `// 不安全寫法：只留存取 record 的前 80 字元，來源 IP 位在後段常被截掉
function audit(user, ip, action, detail) {
  const entry = \`\${user}@\${ip} :: \${action} \${JSON.stringify(detail)}\`;
  logger.info(entry.slice(0, 80));   // IP 與參數常在洩漏前先被切掉
}`,
		fixed: `// 安全寫法：結構化完整記錄安全欄位，長內容分開輸出、不截斷
function audit(user, ip, action, detail) {
  logger.info({ user, ip, action, detail });          // 欄位各自獨立，不截斷
  logger.info(\`-- begin detail --\\n\${JSON.stringify(detail)}\`); // 長內容整段輸出
}`,
		patch: `@@
  function audit(user, ip, action, detail) {
-    const entry = \`\${user}@\${ip} :: \${action} \${JSON.stringify(detail)}\`;
-    logger.info(entry.slice(0, 80));
+    logger.info({ user, ip, action, detail });
+    logger.info(\`-- begin detail --\\n\${JSON.stringify(detail)}\`);
  }`,
		refs: ['CWE-222'],
		tags: ['audit', 'log-truncation', 'forensics', 'security-events'],
	},
	{
		id: 'CWE-226',
		name: 'Sensitive Information in Resource Not Removed Before Reuse',
		lang: 'c',
		status: 'Complete',
		what: `資源重用前未清除敏感資訊。把含機密的緩衝區、socket、分頁或磁碟區塊釋回
可重用資源池時，沒有先抹除其中的敏感資料。後續的分配者（或拿到同塊記憶體
的惡意程序）重複使用時，就能從殘留內容翻出上一個使用者留下的金鑰、密碼或
token；用 realloc() 清洗也危險，它可能回傳不同位址，留下舊區塊的明文副本。
建議做法是在釋放／重用前的「最終使用點」主動把記憶體覆寫清除
（explicit_bzero／SecureZeroMemory），需要擴充時先拷貝到新區塊再清除舊區塊，
並妥善計畫讓 freed 記憶體確實被覆寫而不是只讓指標失效。`,
		problem: `char *b = malloc(128);
read_secret(b);            // b 裝入金鑰
b = realloc(b, 256);      // 可能搬去新位址，舊區塊更不可控地殘留明文
use(b);
free(b);                  // 未先清除：明文留在可被重複分配的記憶體裡`,
		fixed: `char *b = malloc(128);
read_secret(b);
char *nb = malloc(256);   // 不用 realloc 搬移
memcpy(nb, b, 128);
explicit_bzero(b, 128);   // 釋回前先抹除舊緩衝區，避免殘留明文
free(b);
b = nb;                   // 再使用擴充後的區塊`,
		patch: `@@
-  b = realloc(b, 256);      // 可能搬址，舊區塊殘留明文
-  use(b);
-  free(b);                  // 沒清除就釋回
+  char *nb = malloc(256);
+  memcpy(nb, b, 128);
+  explicit_bzero(b, 128);   // 釋回前先抹除舊緩衝區
+  free(b);
+  b = nb;
   use(b);`,
		refs: ['SEI CERT', 'CWE-226'],
		tags: ['realloc', 'memory-reuse', 'buffer-scrub', 'sensitive-data'],
	},
	{
		id: 'CWE-297',
		name: 'Improper Validation of Certificate with Host Mismatch',
		lang: 'node',
		status: 'Complete',
		what: `憑證主機名驗證不符。程式有驗證 TLS 憑證，但只檢查憑證鏈／簽章，沒檢查
憑證是否對應連線目標的主機名（hostname），或用了自訂的 verify／
checkServerIdentity 回呼直接把主機名比對關掉，結果替某網域簽發與目標
毫不相干的憑證也能通過。攻擊者只要拿到一張合法但主機名不同的憑證，就仍能
站到中間冒充伺服器。核心是把「簽章有效」與「這張憑證要給這台主機」兩件事
混為一談。建議做法是保留內建的主機名比對（checkServerIdentity、依賴系統 CA 的
SSLContext 預設行為），不要手動關閉或覆寫成恆真。`,
		problem: `// 不安全寫法：自訂 checkServerIdentity 永遠不過就主機名比對，形同關閉
const https = require('https');
const req = https.request(
  {
    host: 'api.example.com',
    rejectUnauthorized: true,
    checkServerIdentity: () => undefined,   // 回 undefined＝不報錯，比對被完全繞過
  },
  () => {}
);`,
		fixed: `// 安全寫法：沿用預設的主機名比對，憑證 SAN/DN 必須與 api.example.com 相符
const https = require('https');
const req = https.request({ host: 'api.example.com' }, () => {});
// 預設 checkServerIdentity 會比對憑證與目標主機名，這是不可關的必要一步`,
		patch: `@@
  const req = https.request(
   {
     host: 'api.example.com',
-    rejectUnauthorized: true,
-    checkServerIdentity: () => undefined,   // 主機名比對被繞過
   },
   () => {}
- );`,
		refs: ['OWASP-Transport', 'CWE-297'],
		tags: ['hostname-mismatch', 'certificate', 'tls', 'mitm'],
	},
	{
		id: 'CWE-300',
		name: 'Channel Accessible by Non-Endpoint',
		lang: 'python',
		status: 'Complete',
		what: `通訊通道可被非端點使用（中間人）。連線雙方之間允許非預期者在通訊路徑上
讀寫資料，例如自訂 socket 協定既無加密也未驗證對端身份、TLS 憑證驗證被關
掉，攻擊者就能站到兩端中間攔截並改寫訊息，而雙方都毫無察覺。防護重心放在
「兩端互相認證」與「通道完整性」：建議做法是啟用 TLS 並驗證對端憑證與主機名、
使用帶 forward secrecy 的金鑰交換（ECDHE／TLS1.3）、對可信固定伺服器做公鑰
pinning，並在應用層以 MAC／簽章確保即使身處中間也無法竄改內容而不被發現。`,
		problem: `# 不安全寫法：明文 socket 無身份驗證，任何人可站到中間假冒任一端
import socket
s = socket.socket()
s.bind(('0.0.0.0', 9000)); s.listen(1)
c, _ = s.accept()
tok = c.recv(64).decode()      # 中間人可以截走真 token，並代送假 token`,
		fixed: `# 安全寫法：TLS + 驗證對端憑證，非端點無法混進兩端之間
import ssl
ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ctx.load_cert_chain('/etc/tls/server.pem', '/etc/tls/server.key')
ctx.load_verify_locations('/etc/tls/peers')   # 只信任已知端點
c, _ = sock.accept()
try:
    tls = ctx.wrap_socket(c, server_side=True)
except ssl.SSLCertVerificationError:
    return None                # 對端憑證無法驗證→直接拒絕`,
		patch: `@@
+  import ssl
+  ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
+  ctx.load_cert_chain('/etc/tls/server.pem', '/etc/tls/server.key')
+  ctx.load_verify_locations('/etc/tls/peers')
   c, _ = sock.accept()
-  tok = c.recv(64).decode()      # 中間可截走
+  try:
+      tls = ctx.wrap_socket(c, server_side=True)
+  except ssl.SSLCertVerificationError:
+      return None`,
		refs: ['OWASP-Transport', 'CWE-300'],
		tags: ['mitm', 'endpoint-auth', 'tlC-protected', 'non-endpoint'],
	},
	{
		id: 'CWE-321',
		name: 'Use of Hard-coded Cryptographic Key',
		lang: 'python',
		status: 'Complete',
		what: `使用硬編碼的密碼學金鑰。把 AES 金鑰、HMAC 密鑰或簽章私鑰直接寫死在
原始碼或設定檔裡，這種金鑰是「固定不變」的，一旦被抽出就等於永久外洩——
任何人拿到 git 歷史、原始碼或可反組譯的二進位都能把金鑰取出，進而解密、
偽造或竄改受保護的資料。官方指出：只要用了硬編碼金鑰，幾乎可以斷言他
終究會利用到受影響的帳號或機制而把保護繞過，受保護的加密資料被還原的
機率大幅上升；其影響涵蓋繞過防護機制、取得或冒充他人身分、讀取應用資料，
在 OT／工業產品中更曾被大量用於關鍵功能而釀成安全事故。建議做法是金鑰由
KMS／vault 產生並集中管理，以環境變數或祕密管理服務注入，讓金鑰可以隨時
輪換而不需改程式碼，並確保同一把金鑰不會被複用於多個部署或跟著預設值
一起散佈到各處。`,
		problem: `# 不安全寫法：AES-256 金鑰直接寫死在原始碼，一推上 repo 金鑰就外洩
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY = b"\\x8a\\x5f\\x72\\x1c\\x...\\x3d"      # <-- 硬編碼金鑰烙在 code 裡

def encrypt_secret(plain: bytes) -> bytes:
    nonce = os.urandom(12)                    # nonce 有隨機，但金鑰是壞的
    return nonce + AESGCM(KEY).encrypt(nonce, plain, None)`,
		fixed: `# 安全寫法：金鑰從 secret manager 注入，可輪換、不進版本庫
import os, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY = base64.b64decode(os.environ["AES_KEY_B64"])   # 部署平台注入，非寫死
if len(KEY) != 32:
    raise RuntimeError("AES_KEY_B64 must be 32 bytes")

def encrypt_secret(plain: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(KEY).encrypt(nonce, plain, None)`,
		patch: `@@
-  KEY = b"\\x8a\\x5f\\x72\\x1c\\x...\\x3d"
+  KEY = base64.b64decode(os.environ["AES_KEY_B64"])
+  if len(KEY) != 32:
+      raise RuntimeError("AES_KEY_B64 must be 32 bytes")
   def encrypt_secret(plain: bytes) -> bytes:
       nonce = os.urandom(12)
       return nonce + AESGCM(KEY).encrypt(nonce, plain, None)`,
		refs: ['OWASP-Secrets', 'CWE-321'],
		tags: ['hardcoded-key', 'key-management', 'secrets'],
	},
	{
		id: 'CWE-330',
		name: 'Use of Insufficiently Random Values',
		lang: 'python',
		status: 'Complete',
		what: `使用不夠隨機的亂數值。在依賴不可預測數值的資安情境（session id、產生
金鑰時的種子、nonce、重設碼）用了隨機度不足的值：以時間、PID 為種子
的統計型 PRNG，或取值空間太小、可被推導的數值都算。問題在於電腦本是
確定性機器，統計型 PRNG 的輸出高度可預測、極易重現同一串數值，拿它
產生受保護資源的 id 或種子，攻擊者就能猜出別人的 session／金鑰，進而
繞過身分判定、越權讀取他人資源。常見成因是貪圖省事沿用 non-crypto 的
random 模組、種子空間太小或種子可被觀察序列回推。建議做法是資安場景
一律改用密碼學安全亂數（secrets／os.urandom／SecureRandom），採用被公認
夠強、實作受驗證的演算法與足夠長度的種子（256-bit 起跳），並讓產生器
在需要時以高品質熵源自行重新播種，確保種子無法由任何可觀察值反推。`,
		problem: `# 不安全寫法：用 random（Mersenne Twister、種子與時間相關）產生重置金鑰
import random, string

reset_code = "".join(
    random.choice(string.ascii_letters + string.digits) for _ in range(20)
)   # random 初始可被觀察序列後預測，20 字元形同虛設`,
		fixed: `# 安全寫法：改用 secrets 模組，密碼學安全亂數、種子不可推導
import secrets, string

reset_code = "".join(
    secrets.choice(string.ascii_letters + string.digits) for _ in range(32)
)   # 256-bit 且種子無法由觀察結果回推`,
		patch: `@@
-  import random, string
+  import secrets, string
   reset_code = "".join(
-      random.choice(string.ascii_letters + string.digits) for _ in range(20)
-  )   # random 初始可被觀察序列後預測，20 字元形同虛設
+      secrets.choice(string.ascii_letters + string.digits) for _ in range(32)
+  )   # 256-bit 且種子無法由觀察結果回推`,
		refs: ['OWASP-Crypto', 'CWE-330'],
		tags: ['randomness', 'predictable', 'token'],
	},
	{
		id: 'CWE-331',
		name: 'Insufficient Entropy',
		lang: 'python',
		status: 'Complete',
		what: `熵不足。產生金鑰、nonce、session id 或驗證碼時，用了熵太少、再生能力差的
亂數來源——例如以固定種子、時間、PID 或低熵硬體取得的值來「偽裝」隨機。
熵不足讓「隨機」值落在很小的取值空間或實際可被預測，攻擊者可窮舉或回推出
其他人的金鑰／token；密碼學強度根本上依賴亂數的不可預測性，所以這是
「看似加密、實際可猜」的經典例子。建議做法是直接採用作業系統的密碼學安全
亂數（os.urandom／secrets／SecureRandom），確保位元長度足夠，並在熵池初始化
失敗時拒絕啟動，而不是默默退回可預測的種子。`,
		problem: `# 不安全寫法：以秒級時間為種子再以偽隨機補位，可被窮舉的空間極小
import random, time
random.seed(int(time.time()))                 # 種子只有"現在這秒"可言
key = bytes(random.getrandbits(8) for _ in range(32))
# 攻擊者只要比對前後幾秒的種子就能重現整把 32-byte "金鑰"`,
		fixed: `# 安全寫法：os.urandom 直接取自 OS 熵池，種子不可由時間推測、長度完整
import os
key = os.urandom(32)   # 256-bit，種子來自 OS 密碼學安全熵池`,
		patch: `@@
-  import random, time
-  random.seed(int(time.time()))
-  key = bytes(random.getrandbits(8) for _ in range(32))
+  import os
+  key = os.urandom(32)   # 256-bit，來自 OS 熵池`,
		refs: ['OWASP-Crypto', 'CWE-331'],
		tags: ['entropy', 'seed', 'random', 'key-gen'],
	},
	{
		id: 'CWE-338',
		name: 'Use of Cryptographically Weak Pseudo-Random Number Generator',
		lang: 'java',
		status: 'Complete',
		what: `使用密碼學上偏弱的擬亂數產生器。在密碼學情境裡用了一個演算法本身
不具備密碼學強度的 PRNG，例如 java.util.Random 這類線性同餘產生器
（LCG）、或 C 的 rand()。這類產生器多是為省運算、不消耗系統有限熵源
而設計的統計型 PRNG；但正是這些「省資源」的特性會被攻擊者反過來利用——
輸出序列可以從少數觀察值完整回推，拿它產生 IV、金鑰、session id 或
salt，即可預測後續數值，讓依賴它的保護機制整組失守：認證、授權、
身分判定都能被猜測繞過。建議做法是密碼學場景一律改用密碼學安全、最好
直接由硬體／作業系統熵源供值的產生器（java.security.SecureRandom、
Windows CryptGenRandom、Linux hw_rand），確保輸出不可推導，而不是拿表面上
「很快」的統計型 PRNG 充數。`,
		problem: `// 不安全寫法：用 java.util.Random 產生 AES 的 IV，LCG 可被回推
import java.util.Random;

byte[] iv = new byte[16];
new Random().nextBytes(iv);   // LCG 序列可預測，IV 重複即砸掉 AES 安全性`,
		fixed: `// 安全寫法：改用 SecureRandom，種子來自 OS 熵池，不可推導
import java.security.SecureRandom;

byte[] iv = new byte[16];
new SecureRandom().nextBytes(iv);   // CSPRNG，IV 隨機且不可預測`,
		patch: `@@
-  import java.util.Random;
+  import java.security.SecureRandom;
   byte[] iv = new byte[16];
-  new Random().nextBytes(iv);   // LCG 序列可預測，IV 重複即砸掉 AES 安全性
+  new SecureRandom().nextBytes(iv);   // CSPRNG，IV 隨機且不可預測`,
		refs: ['OWASP-Crypto', 'CWE-338'],
		tags: ['prng', 'secure-random', 'java'],
	},
	{
		id: 'CWE-346',
		name: 'Origin Validation Error',
		lang: 'node',
		status: 'Complete',
		what: `來源（origin）驗證錯誤。在 WebSocket、跨視窗 postMessage、CORS 等跨來源機制
中，程式用可被偽造的欄位或根本不看來源欄位來判斷身分——例如只檢查可被帶假
值的 Referer、對任何 * 來源都放行、或從不讀 event.origin。一旦來源驗證不嚴，
惡意網域發來的訊息或連線會被當作自家系統處理，可能導致資料竊取、CSRF 或
任意執行。建議做法是以明確的字串白名單比對 Origin／Sec-WebSocket-Origin／
postMessage 的 event.origin，逐個精確比較後才放行；不要用可被繞過的片段式正則
或寬鬆字串包含來判斷。`,
		problem: `// 不安全寫法：postMessage 完全不檢查 event.origin，任何網域都能驅使可執行操作
window.addEventListener('message', (ev) => {
  eval(ev.data.script);   // 不明來源送來的程式碼也被執行
});`,
		fixed: `// 安全寫法：以白名單逐字元比對 event.origin，來源不符直接忽略
const ALLOWED = new Set(['https://app.example.com']);
window.addEventListener('message', (ev) => {
  if (!ALLOWED.has(ev.origin)) return;   // 非名單內來源一律丟棄
  consume(ev.data);
});`,
		patch: `@@
+  const ALLOWED = new Set(['https://app.example.com']);
  window.addEventListener('message', (ev) => {
-    eval(ev.data.script);   // 不明來源也執行
+    if (!ALLOWED.has(ev.origin)) return;   // 白名單比對
+    consume(ev.data);
  });`,
		refs: ['OWASP-Top10', 'CWE-346'],
		tags: ['origin-validation', 'postMessage', 'websocket', 'csrf'],
	},
	{
		id: 'CWE-349',
		name: 'Acceptance of Extraneous Untrusted Data With a Trusted Data Source',
		lang: 'java',
		status: 'Complete',
		what: `信任的來源夾帶了多餘的不可信資料。程式從受信任的通道讀取資料，卻把同一份
資料連帶所有欄位不加以區分地全部採信——例如反序列化時讓請求能直設內部欄位
（mass assignment）、或允許攻擊者在認可欄位外再塞入覆寫用的參數。也就是說，
資料來源是受信任的，但裡面混進來不可信的欄位卻被當成同一個來源的一部分。
建議做法是採用 allowlist 白名單：反序列化前先規定且驗證允許的欄位集合，未知
或額外欄位一律拒絕；並避免把整個請求物件直接 bind 到持久化實體或擁有權限欄位
的類別。`,
		problem: `// 不安全寫法：把整個可控制物件的所有欄位（含 isAdmin 權限旗標）一併落地
@PostMapping("/profile")
User update(User payload) {          // isAdmin、role 等欄位也隨 payload 被寫入
    return repo.save(payload);       // mass assignment：使用者可自設 isAdmin=true
}`,
		fixed: `// 安全寫法：只接收並落地白名單欄位，權限欄位完全不來自請求
@PostMapping("/profile")
User update(@RequestBody UpdateProfile body) {
    User u = repo.findById(currentUserId()).get();
    u.setNickname(body.nickname());          // 只允許 nickname
    return repo.save(u);                    // isAdmin/role 不會被請求覆寫
}`,
		patch: `@@
  @PostMapping("/profile")
- User update(User payload) {
-     return repo.save(payload);       // 人人可自設 isAdmin=true
- }
+ User update(@RequestBody UpdateProfile body) {
+     User u = repo.findById(currentUserId()).get();
+     u.setNickname(body.nickname());         // allowlist 欄位
+     return repo.save(u);
+ }`,
		refs: ['OWASP-MassAssignment', 'CWE-349'],
		tags: ['mass-assignment', 'allowlist', 'deserialization', 'extra-fields'],
	},
	{
		id: 'CWE-522',
		name: 'Insufficiently Protected Credentials',
		lang: 'python',
		status: 'Complete',
		what: `憑證保護不足。密碼、私鑰、API token 等憑證被以能輕易取得或可逆的形式儲存
或傳輸：明文、只做可解碼的編碼（base64／ROT）、或用不含成本因子的快速雜湊。
即使只是「看似加密」，只要防護能被人輕鬆反推就都屬於此類。它與「明文儲存」
的差別在於：資料有加一層保護，但那層保護強度不足才出問題。建議做法是密碼存
強化式、內含成本因子與單獨鹽的雜湊（bcrypt／argon2id）；密鑰放 KMS 或硬體
保管庫；token 採短生命週期並繫結宿主，避免把可被反推的編碼當作加密來用。`,
		problem: `# 不安全寫法：拿 base64「編碼」當保護，可逆、等同明文外洩
import base64
DB.persist(user, base64.b64encode(pw.encode()))   # 任何人可解碼回明文`,
		fixed: `# 安全寫法：密碼改存含成本因子與每條獨立鹽的 bcrypt 雜湊
import bcrypt
h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12))  # 不可逆、含成本
DB.persist(user, h)`,
		patch: `@@
-  import base64
-  DB.persist(user, base64.b64encode(pw.encode()))
+  import bcrypt
+  h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12))
+  DB.persist(user, h)`,
		refs: ['OWASP-Crypto', 'CWE-522'],
		tags: ['credentials', 'base64', 'bcrypt', 'weak-protection'],
	},
	{
		id: 'CWE-524',
		name: 'Use of Cache Containing Sensitive Information',
		lang: 'java',
		status: 'Complete',
		what: `使用含敏感資訊的快取。應用程式或瀏覽器把含機密的回應或資料存入快取，卻沒有
適當的私密性控制（Cache-Control: no-store），使共用電腦上的下一位使用者、或任何
能碰快取的人，從快取讀出走他的個人資料。常見成因是敏感 API 的回應沒帶禁止快取
的標頭、快取鍵與使用者不分、或 token 放進 URL 而被歷史／prefetch 快取。建議
做法是對含個資或機密的回應一律設 Cache-Control: no-store, no-cache（或 private
而非 public），快取鍵區分使用者與授權上下文，並避免把 token 放進網址而被快取。`,
		problem: `// 不安全寫法：回傳個人資料卻沒禁用快取，共用瀏覽器會留下給下一位
@GetMapping("/user/{id}/profile")
User profile(@PathVariable String id) {   // 沒有 Cache-Control 標頭
    return repo.find(id);                // 個資被快取，共用者可讀走
}`,
		fixed: `// 安全寫法：機密回應明確標記 no-store，驅離所有層級的快取
@GetMapping("/user/{id}/profile")
ResponseEntity<User> profile(@PathVariable String id) {
    return ResponseEntity.ok()
        .cacheControl(CacheControl.noStore())   // 禁止任何快取
        .header("Pragma", "no-cache")
        .body(repo.find(id));
}`,
		patch: `@@
  @GetMapping("/user/{id}/profile")
- User profile(@PathVariable String id) {
-     return repo.find(id);                // 無 Cache-Control
- }
+ ResponseEntity<User> profile(@PathVariable String id) {
+     return ResponseEntity.ok()
+         .cacheControl(CacheControl.noStore())
+         .header("Pragma", "no-cache")
+         .body(repo.find(id));
+ }`,
		refs: ['OWASP-Privacy', 'CWE-524'],
		tags: ['cache', 'no-store', 'sensitive-data', 'shared-browser'],
	},
	{
		id: 'CWE-598',
		name: 'Use of GET Request Method With Sensitive Query Strings',
		lang: 'node',
		status: 'Complete',
		what: `用 HTTP 請求且把敏感資料放進 query string。網頁應用在處理請求時，把
session id、密碼、存取 token、API 金鑰、電子郵件甚至個資等敏感資訊拼到
query string 裡——最常見是 GET，但 POST／PUT／DELETE 同樣可能帶 query string。
URL 會被寫進瀏覽器歷史、透過 Referer 傳給第三方網站、被記到 web log 或
其它日誌來源，任一方只要看到該 URL 就等同取得機密。攻擊者可藉此冒充合法
使用者、竊取專有資料或執行非開發者預期的操作，而這些洩漏出的資訊還會
被用來升級攻擊手法。常見成因是直接把敏感參數塞進查詢字串圖方便。建議
做法是傳送敏感資訊時只放在請求 body 或 header 中，而非 query string，
必要時乾脆避免 GET 方法。`,
		problem: `// 不安全寫法：把帳密塞進 GET query string，會烙進 log 歷史與 Referer
const res = await fetch(
  \`https://api.example.com/login?user=\${user}&password=\${pass}\`
);   // URL 會被記到 log、代理、瀏覽器歷史`,
		fixed: `// 安全寫法：改用 POST + body（或 Authorization Header），機密不進 URL
const res = await fetch("https://api.example.com/login", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ user, password: pass }),   // 機密在 body，不進 log
});`,
		patch: `@@
-  const res = await fetch(
-    \`https://api.example.com/login?user=\${user}&password=\${pass}\`
-  );   // URL 會被記到 log、代理、瀏覽器歷史
+  const res = await fetch("https://api.example.com/login", {
+    method: "POST",
+    headers: { "Content-Type": "application/json" },
+    body: JSON.stringify({ user, password: pass }),   // 機密在 body，不進 log
+  });`,
		refs: ['OWASP-Transport', 'CWE-598'],
		tags: ['get-request', 'query-string', 'sensitive-data'],
	},
	{
		id: 'CWE-916',
		name: 'Use of Password Hash With Insufficient Computational Effort',
		lang: 'python',
		status: 'Complete',
		what: `使用運算成本不足的密碼雜湊。用 MD5／SHA−1／SHA−256 這類極快的
通用雜湊存密碼，即使各自加鹽，攻擊者仍能用 GPU／ASIC 在離線以
每秒數十億次的速度暴力試，使得雜湊幾乎等於明文外洩。
建議做法是改用內建成本因子（cost／memory）的專用密碼 KDF——
argon2id、scrypt 或 bcrypt——故意把每次驗證拖慢到數十毫秒以上，
讓離線暴力破解成本高到不可能。`,
		problem: `# 不安全寫法：用極快的 MD5 存密碼，單顆 GPU 每秒可試數十億次
import hashlib

def store_password(raw: str) -> str:
    return hashlib.md5(raw.encode()).hexdigest()   # 快＝可離線暴力破解`,
		fixed: `# 安全寫法：用 argon2id 帶成本參數，故意拖慢 + 內建鹽
from argon2 import PasswordHasher

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

def store_password(raw: str) -> str:
    return ph.hash(raw)   # 每次生成/驗證數十毫秒，暴力成本高不可行`,
		patch: `@@
-  import hashlib
+  from argon2 import PasswordHasher
+
+  ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
   def store_password(raw: str) -> str:
-      return hashlib.md5(raw.encode()).hexdigest()   # 快＝可離線暴力破解
+      return ph.hash(raw)   # 每次生成/驗證數十毫秒，暴力成本高不可行`,
		refs: ['OWASP-Crypto', 'CWE-916'],
		tags: ['password-hashing', 'argon2', 'kdf', 'slow-hash'],
	},
	{
		id: 'CWE-1283',
		name: 'Mutable Attestation or Measurement Reporting Data',
		lang: 'c',
		status: 'Complete',
		what: `可被變造的證明／量測資料。作證式開機（secure/measured boot）會把載入的程式碼
做單向雜湊並「延伸」到 PCR／量測暫存器，最後的雜湊作為量測結果用來證明系統
狀態。但若量測暫存器位於可被 CPU 軟體直接覆寫的普通記憶體、或回溯時沒有
一次性（extend-only）保護與硬體根端簽章，惡意韌體就能在回報前竄改量測值，
讓駭客的程式看起來像是受信任的。建議做法是把 PCR／量測暫存器做成硬體層一次性
唯延伸（只可 extend、不可覆寫）的暫存器，並在對外提供或證明時，把量測摘要用
硬體持有的私鑰簽名綁定，任何竄改都會讓證明驗證直接失敗。`,
		problem: `// 不安全寫法：量測值放在可被任意軟體直接覆寫的一般記憶體
uint32_t pcr_values[24];            // 與普通資料同在可寫 RAM
void report(void) {
    attest(pcr_values);             // 回報前內容可能早已被竄改
}`,
		fixed: `// 安全寫法：量測以"只能延伸"方式塞進 TPM PCR，並以硬體私鑰簽名後回報
while (to_measure(cnt)) {
    TPM2_PCR_Extend(TPM_ALG_SHA256, idx, digest);  // 只可 extend，不可覆寫
}
// 回報前以 TPM 私鑰簽名綁定量測摘要：改過任何位元→簽名/證明即失效`,
		patch: `@@
-  uint32_t pcr_values[24];            // 可被軟體覆寫
-  void report(void) {
-      attest(pcr_values);
-  }
+  while (to_measure(cnt)) {
+      TPM2_PCR_Extend(TPM_ALG_SHA256, idx, digest);  // extend-only
+  }
+  attest(TPM2_Quote(kek));   // 以硬體私鑰簽名量測，無法竄改`,
		refs: ['CWE-1283'],
		tags: ['attestation', 'measured-boot', 'tpm', 'pcr'],
	},
];
