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
		id: 'CWE-311',
		name: 'Missing Encryption of Sensitive Data',
		lang: 'python',
		status: 'Complete',
		what: `敏感資料缺少加密保護。把 token、信用卡號、個資等敏感欄位
直接以明文寫進資料庫或檔案，導致靜態儲存（at rest）保護不足，
任何拿到 DB 備份、磁碟映像或檔案系統權限的人都能直接讀。
建議先妥善取得並管理主金鑰，再用認證加密演算法（如 AES-GCM）加密後才落庫，
解密只在真正需要時進行。`,
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
		what: `以明文儲存敏感資訊。把密碼、密鑰、session token 這類
機密當作一般資料明文寫進檔案、設定檔、DB 欄位或 log，
資料一旦外洩，內容便直接暴露。建議做法是密碼等機密改存強化式雜湊（bcrypt），
密鑰／token 進密碼保管庫（keyring/vault），避免以明文儲存在本機。`,
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
-    f.write(f"{user}:{request.form['password']}\\n")`,
		refs: ['OWASP-Crypto', 'CWE-312'],
		tags: ['secrets', 'cleartext', 'password-storage'],
	},
	{
		id: 'CWE-319',
		name: 'Cleartext Transmission of Sensitive Information',
		lang: 'python',
		status: 'Complete',
		what: `明文傳輸敏感資料。用未加密的 TCP、HTTP 或自訂協定把帳密、
憑證、token 送上網路，中間網路可被竊聽（sniff），
明文在傳輸鏈路上可能遭未授權讀取。建議做法是把傳輸包進 TLS（ssl socket／HTTPS），
並驗證伺服器憑證避免攔截（MITM）。`,
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
		id: 'CWE-326',
		name: 'Inadequate Encryption Strength',
		lang: 'php',
		status: 'Complete',
		what: `加密強度不足。用了過短的金鑰（如 DES 56-bit 金鑰、過短的 AES 金鑰）、
過時、現今已可被暴力破解的演算法或過低的工作因子，
使加密在合理的運算資源下即可被攻破。建議做法是採用長度足夠的金鑰
（AES-256）並驗證金鑰長度符合演算法要求。`,
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
		what: `使用已破損或有風險的密碼學演算法。把 MD5／SHA1 系列的快速雜湊
拿來存密碼，或把 DES／3DES 這類已可被破解的區塊加密用來保護資料，
攻擊者可進行離線暴力破解或直接還原明文。建議做法是密碼用 bcrypt／argon2，
一般資料改用 AES-256-GCM 這類經審核的演算法。`,
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
		what: `「單向」雜湊變成可反推。用 MD5／SHA1 這類又快又弱的雜湊存密碼，
即使對每條資料各自加鹽，攻擊者仍可離線使用 GPU 以極高速度
暴力嘗試，形同把單向雜湊變成可被反推。建議做法是改用具成本參數的
慢雜湊（scrypt／argon2／bcrypt），故意拖慢暴力破解速度。`,
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
];
