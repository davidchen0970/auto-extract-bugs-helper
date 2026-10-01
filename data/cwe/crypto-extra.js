// CWE chunk — category: Cryptographic Issues (extra coverage for key handling / randomness / transport).
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
		id: 'CWE-321',
		name: 'Use of Hard-coded Cryptographic Key',
		lang: 'python',
		status: 'Complete',
		what: `使用硬編碼的密碼學金鑰。把 AES 金鑰、HMAC 密鑰或簽章私鑰
直接寫死在原始碼或設定檔裡，進到版本庫就等於外洩，
任何人拿到 git 歷史、原始碼或可反組譯的二進位都能抽出金鑰，
進而解密、偽造或竄改受保護的資料。建議做法是金鑰由 KMS／vault 產生並管理，
以環境變數或祕密管理服務注入，讓金鑰可以隨時輪換而不需要改程式碼。`,
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
		what: `使用不夠隨機的亂數值。用可預測的亂數來源（例如以時間為種子的
random 模組）產生 token、session id、nonce 或重設碼，
序列很短或可被推導，攻擊者可預測下一個「隨機」值，
進而猜中別人的 session/重設 token。建議做法是改用密碼學安全亂數
secrets／os.urandom，產生 length 足夠且種子不可推導的值。`,
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
		id: 'CWE-338',
		name: 'Use of Cryptographically Weak Pseudo-Random Number Generator',
		lang: 'java',
		status: 'Complete',
		what: `使用密碼學上偏弱的擬亂數產生器。java.util.Random 這類線性同餘
產生器（LCG）雖快，但輸出序列可以從少數觀察值完整回推，
若拿它產生 IV、key、session id 或 salt，攻擊者可預測後續數值。
建議做法是密碼學場景一律改用 java.security.SecureRandom，
它在作業系統層收集真正的熵，輸出不可推導。`,
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
		id: 'CWE-598',
		name: 'Use of GET Request Method With Sensitive Query Strings',
		lang: 'node',
		status: 'Complete',
		what: `用 GET 方法且把敏感資料放進 query string。密碼、token、session id
等機密若拼進 URL，會完整出現在存取 log、瀏覽器歷史、代理與
Referer Header，任一方看到 URL 即等於外洩機密。建議做法是把敏感欄位
改放 HTTP body（POST）或 Authorization Header，query string 只放無機密性的參數。`,
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
];
