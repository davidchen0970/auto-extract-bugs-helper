// CWE chunk — category: Cryptographic Issues (encryption at rest / in transit / weak crypto).
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
		id: 'CWE-310',
		name: 'Cryptographic Issues',
		lang: 'python',
		status: 'Complete',
		what: `密碼學議題總類（class）。CWE-310 是 MITRE 對所有與密碼學實作
相關弱點的父類別（pillar），本身不指向單一缺陷，而是涵蓋金鑰管理、
加密演算法選用、亂數來源、簽章驗證與密碼儲存等一整族問題。之所以
危險，是因為開發者在任一個環節偷工——用弱演算法、硬編碼金鑰、可預測
亂數或明文存機密——都會讓原本旨在保護資料的加密形同虛設。修法上應先做
風險盤點，確認哪些資料需要機密性／完整性，再逐環節套用對應的子類 CWE
解法：選用經審核的認證加密、以 KMS 管理金鑰、用 CSPRNG 產生隨機值、
並以專用 KDF 存密碼。`,
		problem: `# 不安全寫法：多處密碼學偷工——弱演算法＋硬編碼金鑰＋可預測亂數
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
KEY = b"\x6e\x2f\x91..."           # <-- 金鑰寫死在程式裡
def seal(secret):
    enc = Cipher(algorithms.AES(KEY), modes.ECB()).encryptor()   # ECB＋帶金鑰
    return enc.update(secret)          # 同一明文永遠同密文，且整袋金鑰外洩`,
		fixed: `# 安全寫法：認證加密 AES-GCM＋KMS 供鑰＋os.urandom 產 nonce，一次補足
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
KEY = load_master_key()               # 從 KMS/vault 取得，不寫死、可輪換
def seal(secret: bytes) -> bytes:
    nonce = os.urandom(12)          # CSPRNG 產 nonce
    return nonce + AESGCM(KEY).encrypt(nonce, secret, None)   # 機密性+完整性`,
		patch: `@@
-  from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
-  KEY = b"\x6e\x2f\x91..."
-  def seal(secret):
-      enc = Cipher(algorithms.AES(KEY), modes.ECB()).encryptor()
-      return enc.update(secret)
+  import os
+  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
+  KEY = load_master_key()
+  def seal(secret: bytes) -> bytes:
+      nonce = os.urandom(12)
+      return nonce + AESGCM(KEY).encrypt(nonce, secret, None)`,
		refs: ['OWASP-Crypto', 'CWE-310'],
		tags: ['cryptography', 'class', 'crypto-misuse'],
	},
	{
		id: 'CWE-311',
		name: 'Missing Encryption of Sensitive Data',
		lang: 'python',
		status: 'Complete',
		what: `敏感資料缺少加密保護。產品的儲存或傳輸前沒有把敏感或關鍵資訊加密：
token、信用卡號、個資等欄位直接以明文寫進資料庫、檔案或送上網路。未用
安全通道時，能取得網路流量的攻擊者可竊聽封包讀走資料；再極端一點，在
任何網路上傳輸資料的系統一旦省略加密，就等同把每一筆資料同時交到收送兩端
各自區域網路上的使用者手上，更糟的是攻擊者還能趁勢把假資料注入兩方之間的
通訊流，受害者無從分辨真假。常見成因是架構設計漏掉這一步、只求好用而跳過
昂貴但必要的密碼學步驟。建議做法是明確盤點哪些資料值得保護，採用經審核、
現今仍夠強的演算法（如 AES-GCM）並妥善管理主金鑰，解密只在真正需要時進行；
切勿自製演算法，且要定期確認所用密碼學未因算力進步而淪為可破（MD4、MD5、
SHA1、DES 皆曾屬此列）。`,
		problem: `# 不安全寫法：token 以明文寫進資料庫，備份外洩即等於資料外洩
import sqlite3
conn = sqlite3.connect('app.db')
conn.execute(
    "INSERT INTO sessions (token, user) VALUES (?, ?)",
    (request.form['token'], user_id),
)
conn.commit()`,
		fixed: `# 安全寫法：用 AES-GCM 認證加密後才寫入，解密僅在真正需要使用時進行
import os, sqlite3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = load_master_key()                       # 從 KMS／vault 安全取得，不寫死
nonce = os.urandom(12)
ct = AESGCM(key).encrypt(nonce, request.form['token'].encode(), None)
conn.execute(
    "INSERT INTO sessions (token, user) VALUES (?, ?)",
    (nonce + ct, user_id),
)`,
		patch: `@@
+import os
+from cryptography.hazmat.primitives.ciphers.aead import AESGCM
+
+key = load_master_key()
+nonce = os.urandom(12)
+ct = AESGCM(key).encrypt(nonce, request.form['token'].encode(), None)
 conn.execute(
-    "INSERT INTO sessions (token, user) VALUES (?, ?)",
-    (request.form['token'], user_id),
+    "INSERT INTO sessions (token, user) VALUES (?, ?)",
+    (nonce + ct, user_id),
 )`,
		refs: ['OWASP-Crypto', 'CWE-311'],
		tags: ['data-at-rest', 'encryption', 'sensitive-data'],
	},
	{
		id: 'CWE-312',
		name: 'Cleartext Storage of Sensitive Information',
		lang: 'python',
		status: 'Complete',
		what: `以明文儲存敏感資訊。產品把密碼、密鑰、session token 這類機密當作一般
資料，明文寫進檔案、設定檔、DB 欄位、cookie 或 log 等可能被其它控制域
存取的資源。即使內容經過 base64 這類編碼、看起來不像人可讀，本質仍屬
「明文」——有能力的人一旦辨識出編碼方式就能解回，幾乎等同直接暴露。任何
能碰到該資源的人（拿到備份、磁碟映像、設定檔或檔案系統權限）即可讀走機密；
在雲端這類資源位在網路上，更易被遠端起手存取。常見成因是把機密當普通欄位
一起序列化或落盤。建議做法是密碼等機密改存強化式雜湊（bcrypt），密鑰／
token 放入密碼保管庫（keyring／vault），並善用儲存服務的靜態加密；避免將
可解碼的明文存放在本機、網頁根目錄或公開路徑。`,
		problem: `# 不安全寫法：把使用者密碼明文寫進設定檔，任何人讀檔即得密碼
with open('users.txt', 'a') as f:
    f.write(f"{user}:{request.form['password']}\n")`,
		fixed: `# 安全寫法：絕不存明文，只存 bcrypt 強化雜湊（含自動 salt）
import bcrypt
hashpw = bcrypt.hashpw(request.form['password'].encode(), bcrypt.gensalt())
store_credential(user, hashpw)   # 資料庫／保管庫只存雜湊`,
		patch: `@@
+import bcrypt
+hashpw = bcrypt.hashpw(request.form['password'].encode(), bcrypt.gensalt())
+store_credential(user, hashpw)
+
-with open('users.txt', 'a') as f:
-    f.write(f"{user}:{request.form['password']}\n")`,
		refs: ['OWASP-Crypto', 'CWE-312'],
		tags: ['secrets', 'cleartext', 'password-storage'],
	},
	{
		id: 'CWE-316',
		name: 'Cleartext Storage of Sensitive Information in Memory',
		lang: 'c',
		status: 'Complete',
		what: `在記憶體中以明文儲存敏感資訊。把密碼、密鑰或解密後的明文資料
放進一般的 heap/stack 緩衝區，用完不加以覆寫清除，機密就停留在記憶體中，
直到被 GC、遭 swap 換到磁碟、被 core dump 或被除錯器／同機惡意程序讀走。
常見成因是開發者以為「用完就不管」即可，甚至緩衝區在執行緒間被複製
多份。建議做法是以 volatile 直頁＋不可被最佳化移除的函式
（explicit_bzero／SecureZeroMemory／volatile 指針迴圈）在最後使用點立刻抹除，
並避免用不可控實作的不可變（String）型別長期保管機密。`,
		problem: `// 不安全寫法：密碼拷進共用 stack buffer，用完不清除，祕密留在記憶體
char buf[64];
strncpy(buf, getenv("DB_PASS"), sizeof(buf) - 1);
connect_db(buf);               // 連線完畢，buf 仍燒著旅行
/* 沒有任何清除動作：明文停留在可用還堆疊區 */`,
		fixed: `// 安全寫法：用完立刻以不可被最佳化掉的方式抹除緩衝區
char buf[64];
size_t n = strnlen(getenv("DB_PASS"), sizeof(buf) - 1);
memcpy(buf, getenv("DB_PASS"), n);
buf[n] = '\\0';
int fd = connect_db(buf);           // 正常使用
explicit_bzero(buf, sizeof(buf));   // glibc 2.25+：編譯器無法刪除，
                                   // 卻不會被 -O2 最佳化拿掉`,
		patch: `@@
   char buf[64];
   strncpy(buf, getenv("DB_PASS"), sizeof(buf) - 1);
-  connect_db(buf);
-  /* 沒有任何清除動作：明文停留在可用還堆疊區 */
+  size_t n = strnlen(getenv("DB_PASS"), sizeof(buf) - 1);
+  memcpy(buf, getenv("DB_PASS"), n);
+  buf[n] = '\\0';
+  int fd = connect_db(buf);
+  explicit_bzero(buf, sizeof(buf));   // 用完立刻、不可最佳化清除`,
		refs: ['OWASP-Crypto', 'CWE-316'],
		tags: ['memory-cleartext', 'buffer-scrub', 'secrets-in-memory'],
	},
	{
		id: 'CWE-319',
		name: 'Cleartext Transmission of Sensitive Information',
		lang: 'python',
		status: 'Complete',
		what: `明文傳輸敏感資料。產品在可被未授權者竊聽的通訊通道上用明文傳送敏感或
安全關鍵資料：用未加密的 TCP、HTTP 或自訂協定把帳密、憑證、token 送網。
封包從來源到目的要經過網際網路、內網、雲端等許多中間節點，有權限存取
任一段鏈路或網路介面（如路由器）的攻擊者就可竊聽；即使內容只是「不容易
讀」的編碼，也能被辨識後解回。有時連整段通訊都會被錄成 packet dump，
攻擊者可事後取得 dump，再從紀錄中翻出明文。常見成因是架構漏掉傳輸加密。
建議做法是傳輸前先用可靠、保護機密的密碼學協定加密；Web 應讓 SSL／TLS
從登入到登出全程啟用、不可只保登入頁，並驗證對端憑證以避免中間人，
伺服器端一律設定使用加密通道。`,
		problem: `# 不安全寫法：透過明文 TCP socket 送憑證，鏈路上可直接被竊聽
import socket
s = socket.create_connection(('svc.example.com', 9999))
s.sendall(f"LOGIN {user} {pwd}\\r\\n".encode())`,
		fixed: `# 安全寫法：包 TLS 並校驗對端憑證，明文不再裸奔於網路上
import socket, ssl
ctx = ssl.create_default_context()          # 信任系統 CA，驗證主機名
raw = socket.create_connection(('svc.example.com', 9443))
ss = ctx.wrap_socket(raw, server_hostname='svc.example.com')
ss.sendall(f"LOGIN {user} {pwd}\\r\\n".encode())`,
		patch: `@@
+import ssl
+ctx = ssl.create_default_context()
 raw = socket.create_connection(...)
+ss = ctx.wrap_socket(raw, server_hostname='svc.example.com')
-ss.sendall(f"LOGIN {user} {pwd}\\r\\n".encode())`,
		refs: ['OWASP-Transport', 'CWE-319'],
		tags: ['tls', 'cleartext', 'data-in-transit'],
	},
	{
		id: 'CWE-325',
		name: 'Missing Required Cryptographic Step',
		lang: 'python',
		status: 'Complete',
		what: `缺少必需的密碼學步驟。資料流程要求「加密＋簽章或 MAC」一同保證機密性、
完整性與來源，但程式只在某些分支做了其中一部：在某些路徑算 MAC、
在另一條路徑直接回傳密文，或只在 happy path 加密而在錯誤路徑把機密外洩，
或簽章只在某些角色身上才驗。只要任何一環被跳過就留下實作缺口——
少了 MAC 無法偵測竄改，少了加密洩漏內容，少了簽章無法判斷來源。
建議做法是讓密碼學動作在單一、無條件執行的集中路徑完成，並直接用同時
保證機密性＋完整性的認證加密（AES-GCM／ChaCha20-Poly1305）消除「少做一步」
的可能。`,
		problem: `# 不安全寫法：MAC 只在特定分支計算，Exit 分支少了 MAC 就把密文交出去
def seal(secret, authed):
    enc = AESGCM(KEY).encrypt(nonce, secret, None)   # 只先加密
    if authed:
        return enc + hmac(enc)           # <-- 只有這分支有 MAC
    return enc                            # <-- 另一分支少了完整性步驟，
                                         #     攻擊者可竄改密文而不被察覺`,
		fixed: `# 安全寫法：任何路徑都完整做認證加密，一個操作同時處理加密與 MAC
def seal(secret: bytes) -> bytes:
    # 單一集中路徑，無簡 - - 分支：認證加密內建 MAC，缺失步驟不存在
    return nonce + AESGCM(KEY).encrypt(nonce, secret, None)`,
		patch: `@@
-  def seal(secret, authed):
-      enc = AESGCM(KEY).encrypt(nonce, secret, None)   # 只先加密
-      if authed:
-          return enc + hmac(enc)
-      return enc
+  def seal(secret: bytes) -> bytes:
+      # 單一集中路徑，認證加密內建 MAC，缺失步驟不存在
+      return nonce + AESGCM(KEY).encrypt(nonce, secret, None)`,
		refs: ['OWASP-Crypto', 'CWE-325'],
		tags: ['missing-mac', 'aead', 'incomplete-crypto'],
	},
	{
		id: 'CWE-326',
		name: 'Inadequate Encryption Strength',
		lang: 'php',
		status: 'Complete',
		what: `加密強度不足。產品用某個「理論上沒毛病」、但不足以支撐所需防護等級的
加密方案來儲存或傳輸敏感資料：金鑰過短（DES 56-bit、過短的 AES 金鑰）、
已過時且現今可被暴力破解的演算法、或工作因子過低。因為演算本身尚屬健全、
不是「已破損」，常被誤認為安全；然而在現行攻擊手法與算力下，這類弱加密
極有機會被暴力嘗試直接還原明文——攻擊者可突破保護、讀取資料。常見成因是
圖省事沿用舊演算法、只求「有加密」而沒有隨安全標準推進更新強度。建議做法
是採用現今業界公認夠強的方案，並驗證金鑰長度確實符合演算法要求（AES-256
金鑰必須是 32 bytes），同時定期隨算力成長重新評估所選強度是否仍足夠。`,
		problem: `// 不安全寫法：用 56-bit 的 DES，金鑰太短且演算法已可被暴力破解
$key = '7Bk2pL';                    // < 8 bytes，DES-ECB 只吃 56-bit
$ct = openssl_encrypt($secret, 'des-ecb', $key);`,
		fixed: `// 安全寫法：AES-256，並以 strlen 校驗確保金鑰為 32 bytes
$key = random_bytes(32);            // 256-bit
if (strlen($key) !== 32) throw new Exception('key too short');
$iv  = random_bytes(openssl_cipher_iv_length('aes-256-cbc'));
$ct  = openssl_encrypt($secret, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);`,
		patch: `@@
-  $key = '7Bk2pL';
-  $ct  = openssl_encrypt($secret, 'des-ecb', $key);
+  $key = random_bytes(32);
+  if (strlen($key) !== 32) throw new Exception('key too short');
+  $iv  = random_bytes(openssl_cipher_iv_length('aes-256-cbc'));
+  $ct  = openssl_encrypt($secret, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);`,
		refs: ['OWASP-Crypto', 'CWE-326'],
		tags: ['key-length', 'weak-cipher', 'encryption-strength'],
	},
	{
		id: 'CWE-327',
		name: 'Use of a Broken or Risky Cryptographic Algorithm',
		lang: 'php',
		status: 'Complete',
		what: `使用已破損或有風險的密碼學演算法／協定。密碼學演算法是把資料攪亂以防
未授權讀寫的手段，而得用於生產的其實只有少數經多年審視、被大量研究的演算法；
拿非標準、已被破解或存有風險的演算法（MD4、MD5、SHA1、DES 等）保護資料，
堅決的攻擊者能破解演算、連帶拖垮它所保護的一切。密碼學進展極快，演算法
即使以前被視為強，也會因新攻擊被發現、算力大增而一夜之間淪為「不安全」。
後果包含洩漏機密；若用在數位簽章這類標定來源的場合，還無法證明資料源頭、
破壞不可否認性。常見成因是沿用舊演算法、圖成本自製或誤用近義函式。建議
做法是選用業界公認夠強、實作受驗證且原始碼可檢視的演算法（FIPS 140-2
認證；密碼存 bcrypt／argon2，一般資料用 AES-256-GCM），不自行發明，並定期
確認未過時；硬體端因難以事後修補，更須在設計階段就選對。`,
		problem: `// 不安全寫法：用 MD5 存密碼，演算法既快又有碰撞，可進行離線暴力破解
$hash = md5($password . $salt);    // 別自炊 salt+md5 當密碼雜湊
if ($hash === $stored) { /* login ok */ }`,
		fixed: `// 安全寫法：用 password_hash() 走 bcrypt，內建鹽與工作因子
$hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
if (password_verify($password, $stored)) { /* login ok */ }`,
		patch: `@@
-  $hash = md5($password . $salt);
-  if ($hash === $stored) { /* login ok */ }
+  $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
+  if (password_verify($password, $stored)) { /* login ok */ }`,
		refs: ['OWASP-Crypto', 'CWE-327'],
		tags: ['md5', 'sha1', 'broken-algorithm', 'password-hashing'],
	},
	{
		id: 'CWE-328',
		name: 'Reversible One-Way Hash',
		lang: 'node',
		status: 'Complete',
		what: `使用弱雜湊。產品用一個「輸出摘要無法滿足安全性期待」的演算法充當雜湊函式，
例如 MD5、SHA1 這類先天有碰撞缺憾、又刻意打造得極快的通用雜湊。健全的
密碼學雜湊必須不可逆、同樣輸入必得同樣輸出，且攻擊者無法從摘要回推原始
輸入（預影像攻擊）、找不到另一組會得同摘要的輸入（次預影像）、也湊不出多
對數值撞出同一摘要（生日攻擊）；用不達標的雜湊，這些條件就存在被打破的
可能。即使對每筆密碼各自加鹽，仍可被離線用 GPU／ASIC 高速暴力破解、
甚至彩虹表還原，形同把單向雜湊變成可反推。建議做法是改用成本可調的調適
型雜湊（scrypt／argon2／bcrypt／PBKDF2），靠提高迭代與記憶體需求調整式地
拖慢暴力破解，算力增快時還可再調高成本而無需換演算法；惟此類函式較耗
資源，取值需權衡以免反倒招致拒絕服務。`,
		problem: `// 不安全寫法：SHA1 + 每條各自加鹽，雖加了鹽但仍快得可離線爆破（形同可逆）
const crypto = require('crypto');
function stashPw(pw, salt) {
  return crypto.createHash('sha1').update(salt + pw).digest('hex');
} // 用 ASIC/GPU 仍可在合理時間內把明文試出來`,
		fixed: `// 安全寫法：crypto.scrypt 帶 cost，故意拖慢、幾乎不可逆
const crypto = require('crypto');
function stashPw(pw, salt) {
  const opts = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
  return crypto.scryptSync(pw, salt, 32, opts).toString('hex');
}`,
		patch: `@@
-  return crypto.createHash('sha1').update(salt + pw).digest('hex');
+  const opts = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
+  return crypto.scryptSync(pw, salt, 32, opts).toString('hex');`,
		refs: ['OWASP-Crypto', 'CWE-328'],
		tags: ['one-way-hash', 'scrypt', 'brute-force', 'password-hashing'],
	},
	{
		id: 'CWE-345',
		name: 'Insufficient Verification of Data Authenticity',
		lang: 'node',
		status: 'Complete',
		what: `對資料真實性（authenticity）驗證不足。程式消費從外部（網路、佇列、
請求）來的資料，卻只信任來源位址或某個可被偽造的標頭，沒有驗證資料
本身是否出自預期來源、也無法確認中途未被竄改。攻擊者偽裝來源或竄改
內容時，程式就把假資料當真處理，造成欺騙、授權繞過或注格式轉譯。
建議做法是對影響決策的資料加上 MAC／簽章，並在消費之前用持有鑰匙真正
驗證完整性與簽署者，而不是只信呼叫端位址或自報的欄位。`,
		problem: `// 不安全寫法：只檢查可被偽造的 Header 欄位，body 完全採信、無 MAC 無簽章
function processOrder(req) {
  if (req.headers['x-internal'] === 'yes') return applyOrder(req.body);
}
// 攻擊者自行加上 x-internal:yes 即視同內部呼叫，內容可隨意竄改`,
		fixed: `// 安全寫法：以 HMAC 綁住 body 並驗證，來源不實即拒收
const crypto = require('crypto');
function processOrder(req) {
  const body = JSON.stringify(req.body);
  const mac  = crypto.createHmac('sha256', AUTH_KEY).update(body).digest('base64');
  const got  = req.headers['x-integrity'] || '';
  const ok   = crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(got));
  if (!ok) throw new Error('origin/integrity not verified');
  return applyOrder(req.body);
}`,
		patch: `@@
+  const crypto = require('crypto');
  function processOrder(req) {
-    if (req.headers['x-internal'] === 'yes') return applyOrder(req.body);
+    const body = JSON.stringify(req.body);
+    const mac  = crypto.createHmac('sha256', AUTH_KEY).update(body).digest('base64');
+    const got  = req.headers['x-integrity'] || '';
+    const ok   = crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(got));
+    if (!ok) throw new Error('origin/integrity not verified');
+    return applyOrder(req.body);
  }`,
		refs: ['OWASP-Crypto', 'CWE-345'],
		tags: ['authenticity', 'hmac', 'integrity', 'origin'],
	},
	{
		id: 'CWE-353',
		name: 'Missing Support for Integrity Check',
		lang: 'python',
		status: 'Complete',
		what: `缺少完整性檢查的支援。加密或傳輸所設計的格式裡沒有計算訊息鑑別碼（MAC）、
HMAC 或簽章欄位，或採用了不提供任何完整性保證的分組模式（CBC／ECB），
使得密文可在完全不解密的情況下被攻擊者翻轉位元、重排區塊或移花接木，
而接收端沒有任何機制能發現。輕則格式解譯錯亂，重則引發編碼層注入或
Padding 攻擊。建議做法是改用內建認證的 AEAD 模式（AES-GCM、
ChaCha20-Poly1305），在單一操作內同時獲得機密性與完整性，或在加密之外
明確地對密文加算並驗證獨立的 MAC。`,
		problem: `# 不安全寫法：AES-CBC 只有加密沒有 MAC，任何人可翻轉密文位元而不被察覺
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
def enc(plain: bytes) -> bytes:
    c = Cipher(algorithms.AES(KEK), modes.CBC(iv)).encryptor()   # 無 tag
    return c.update(pad(plain)) + c.finalize()                    # 完整性全靠信任`,
		fixed: `# 安全寫法：改用 AES-GCM，單一操作=加密+認證，竄改一律驗測失敗
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def enc(plain: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(KEK).encrypt(nonce, pad(plain), None)   # AEAD 內建完整性`,
		patch: `@@
-  from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
-  def enc(plain: bytes) -> bytes:
-      c = Cipher(algorithms.AES(KEK), modes.CBC(iv)).encryptor()
-      return c.update(pad(plain)) + c.finalize()
+  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
+  def enc(plain: bytes) -> bytes:
+      nonce = os.urandom(12)
+      return nonce + AESGCM(KEK).encrypt(nonce, pad(plain), None)`,
		refs: ['OWASP-Crypto', 'CWE-353'],
		tags: ['mac', 'integrity-check', 'aead', 'cbc'],
	},
	{
		id: 'CWE-354',
		name: 'Improper Validation of Integrity Check Value',
		lang: 'python',
		status: 'Complete',
		what: `完整性檢查值驗證不當。程式有計算 MAC／雜湊，但驗證細節抄錯：用一般
字串「==」比較而非恆定時間比較、MAC 只涵蓋部分資料而把可被竄改的欄位
漏掉、或驗證失敗時只記一條 warning 卻照樣採用資料。只要比較時序能被
旁路觀察、涵蓋範圍不完整、或失敗不被當成嚴重錯誤，就不足以叫完整性保證。
建議做法是驗證範圍要涵蓋密文與所有相關 context（身份、階段、時間戳），
全部以恆定時間函式（hmac.compare_digest／timingSafeEqual）比較，且驗證失敗
一律視作致命錯誤，直接拋例外拒絕與丟棄資料。`,
		problem: `# 不安全寫法：用普通「==」串比對 MAC（時序依長度/前綴外洩），失敗也不攔下來
def check(ct, mac):
    if hmac_new(mac) == ct_tag:    # 非恆定時間：時序洩漏、可逐步擬測
        log.warning("tag mismatch")  # 只記 warning，資料照樣被繼續用
    return ct                       # <-- 沒傳回的檢查結果，破壞了驗證`,
		fixed: `# 安全寫法：恆定時間比較，失敗即拋例外，驗證範圍涵蓋 context
import hmac
def check(ct, expected, ctx):
    tag = hmac.new(KEY, ctx + ct, hashlib.sha256).digest()  # 涵蓋密文+context
    if not hmac.compare_digest(tag, expected):                  # 恆定時間比較
        raise IntegrityError("tag mismatch")                      # 失敗=致命
    return ct`,
		patch: `@@
-  import hmac
-  def check(ct, mac):
-      if hmac_new(mac) == ct_tag:    # 非恆定時間、時序外洩
-          log.warning("tag mismatch")
-      return ct
+  import hmac
+  def check(ct, expected, ctx):
+      tag = hmac.new(KEY, ctx + ct, hashlib.sha256).digest()  # 涵蓋密文+context
+      if not hmac.compare_digest(tag, expected):                  # 恆定時間比較
+          raise IntegrityError("tag mismatch")                      # 失敗=致命
+      return ct`,
		refs: ['OWASP-Crypto', 'CWE-354'],
		tags: ['mac-validation', 'constant-time', 'timing-safe'],
	},
	{
		id: 'CWE-757',
		name: 'Selection of Less-Secure Algorithm During Negotiation',
		lang: 'python',
		status: 'Complete',
		what: `交涉時選用了較不安全的演算法。當通訊或協定採用「交涉」方式挑選演算法，
程式若允許且採用對方提議中最弱的那一組——未設強演算法白名單、接受含 RC4／
無 forward secrecy 的 cipher、或對端提議的哈希／簽章一律放行——整個通道的
強度就墮落到最弱連結，攻擊者可主動誘降（downgrade）到可破解的選項。
建議做法是只在一方「都允許」的強演算法交集中協商，拒絕所有弱或過時的
候選，協商完成後再檢查所挑選的組合確實在允許清單內，若不成立就直接終止
連線而非妥協降級。`,
		problem: `# 不安全寫法：直接採納對方提供的第一個 cipher 套件，連 NULL/RC4 也照收
def negotiate(offered):
    return offered[0]   # 若對端先提 'TLS_PSK_WITH_NULL_SHA'，也照單全收`,
		fixed: `# 安全寫法：只在強演算法白名單中挑，沒有強選項就終止而非降級
STRONG = frozenset({'ECDHE_AES_256_GCM', 'ECDHE_CHACHA20_POLY1305'})
def negotiate(offered):
    picked = STRONG & set(offered)
    if not picked:
        raise Disallow('no strong suite offered')   # 不降級到弱選項
    return pick_highest_priority(picked)`,
		patch: `@@
-  def negotiate(offered):
-      return offered[0]   # 對端可能塞 NULL/RC4
+  STRONG = frozenset({'ECDHE_AES_256_GCM', 'ECDHE_CHACHA20_POLY1305'})
+  def negotiate(offered):
+      picked = STRONG & set(offered)
+      if not picked:
+          raise Disallow('no strong suite offered')
+      return pick_highest_priority(picked)`,
		refs: ['OWASP-Transport', 'CWE-757'],
		tags: ['downgrade', 'cipher-negotiation', 'weak-algorithm'],
	},
	{
		id: 'CWE-922',
		name: 'Insecure Storage of Sensitive Information',
		lang: 'python',
		status: 'Complete',
		what: `以不安全的方式儲存敏感資訊。機密被放進權限過大的位置——例如 /tmp、
人人可讀的設定檔、Web 根目錄（document root）下的靜態檔，或無意中被推
進版本庫——即使資料本身沒外洩，位置一不合理就等於公開。本條和「明文
儲存」（CWE-312）互補，強調的是儲存位置與存取控制的失當：任何人可讀的
地方放再怎麼加密的機密也形同無防護。建議做法是把祕密集中在最小權限的
目錄或祕密保管庫，設定正確的檔案權限（0600／禁用 world-readable），並把
含機密或使用者專屬 token 的文件完整排除在版本庫與公開路徑之外。`,
		problem: `# 不安全寫法：把 API token 寫進 HTTP server 直接伺服的文件根目錄，權限還全開
with open('/srv/www/tokens/config.json', 'w') as f:   # 位於網頁根目錄
    json.dump({'api_token': tok}, f)
os.chmod('/srv/www/tokens/config.json', 0o666)        # 任何人皆可讀`,
		fixed: `# 安全寫法：token 改存專屬祕密檔案並設最小權限，不落入公開路徑
keyring.set_password('myapp', 'api', tok)   # 優先走 secret manager/keyring
with open('/etc/myapp/api_token', 'w') as f:   # 若必須落盤則在 /etc 下
    os.write(f.fileno(), tok.encode())
os.chmod('/etc/myapp/api_token', 0o600)      # 檔主可讀寫，其它人均拒絕`,
		patch: `@@
-  with open('/srv/www/tokens/config.json', 'w') as f:   # 在網頁根目錄
-      json.dump({'api_token': tok}, f)
-  os.chmod('/srv/www/tokens/config.json', 0o666)
+  keyring.set_password('myapp', 'api', tok)
+  with open('/etc/myapp/api_token', 'w') as f:
+      os.write(f.fileno(), tok.encode())
+  os.chmod('/etc/myapp/api_token', 0o600)`,
		refs: ['OWASP-Secrets', 'CWE-922'],
		tags: ['secret-storage', 'permissions', 'secrets', '0600'],
	},
];
