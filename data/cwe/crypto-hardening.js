// CWE chunk — category: Cryptographic Issues (TLS / signature / hashing hardening).
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
		id: 'CWE-295',
		name: 'Improper Certificate Validation',
		lang: 'node',
		status: 'Complete',
		what: `憑證驗證不當。將 TLS 伺服器憑證的驗證整個關閉（rejectUnauthorized:
false、自訂 context 設定 checkHostname/CA 為 false 等），或未正確驗證
憑證鏈、過期時間與主機名稱是否相符，等於放棄了 TLS 最基本的身份保證，
中間人（MITM）可以用自己簽發的憑證冒充伺服器攔截、解密甚至竄改名義上
受 TLS 保護的通訊內容。建議做法是保留系統 CA 的驗證與主機名比對，
只在必要場景針對固定公鑰做 pinning，絕不無條件信任所有憑證。`,
		problem: `// 不安全寫法：關掉憑證驗證以「省麻煩」，實則對 MITM 全面敞開大門
const https = require('https');

const req = https.request(
  {
    host: 'api.example.com',
    path: '/login',
    method: 'POST',
    rejectUnauthorized: false,   // <-- 不做任何憑證驗證，任何假憑證都通過
  },
  (res) => { /* ... */ }
);
req.write(JSON.stringify({ user, password }));`,
		fixed: `// 安全寫法：保留預設的 CA 驗證與主機名比對，或針對固定公鑰做 pinning
const https = require('https');
const tls = require('tls');

// 信任系統 CA 並強制驗證主機名（預設行為，勿關閉）
const req = https.request(
  { host: 'api.example.com', path: '/login', method: 'POST' },
  (res) => { /* ... */ }
);

// 需要 pin 時，再額外校驗對端憑證指紋，而不是關閉所有驗證
req.on('socket', (socket) => {
  const peerCert = tls.getPeerCertificate.call(socket, true);
  if (!peerCert || peerCert.fingerprint256 !== EXPECTED_PIN) {
    req.destroy(new Error('untrusted server certificate'));
  }
});`,
		patch: `@@
    method: 'POST',
-    rejectUnauthorized: false,   // <-- 不做任何憑證驗證，任何假憑證都通過
   },
   (res) => { /* ... */ }
  );
+ // 預設會以系統 CA 驗證並比對主機名；需要時再額外對固定公鑰做 pinning
+ req.on('socket', (socket) => {
+   const peerCert = tls.getPeerCertificate.call(socket, true);
+   if (!peerCert || peerCert.fingerprint256 !== EXPECTED_PIN) {
+     req.destroy(new Error('untrusted server certificate'));
+   }
+ });`,
		refs: ['OWASP-Transport', 'CWE-295'],
		tags: ['certificate-validation', 'tls', 'mitm', 'rejectUnauthorized'],
	},
	{
		id: 'CWE-322',
		name: 'Key Exchange without Entropy of Peer',
		lang: 'python',
		status: 'Complete',
		what: `金鑰交換時未利用對端（peer）的熵。在 ECDH／DH／ECDHE 等金鑰交換
協定中，若其中一方把自己的私鑰、隨機亂數或 nonce 寫死成常數或全零值，
或以可預測的種子產生，握手產生的共享祕密就沒有真正的不確定性，
任何人若知道該固定值，即可推導出整個工作階段的會話金鑰並解密通訊。
建議做法是私鑰一律來自密碼學安全亂數，處理 ECDH 使用
secrets／os.urandom 產生每根連線獨立、不可預測的私鑰，不複用、不寫死。`,
		problem: `# 不安全寫法：把 ECDH 私鑰寫死成常數，共享金鑰完全可被推導
import os
from cryptography.hazmat.primitives.asymmetric import ec

# <-- 私鑰寫死，等同沒有熵；任何人知道它就能推出共享祕密
static_private = ec.derive_private_key(1, ec.SECP256R1())

def handshake(peer_pub):
    shared = static_private.exchange(ec.ECDH(), peer_pub)  # 每條連線同一把金鑰
    return shared`,
		fixed: `# 安全寫法：用 os.urandom 產生真正隨機的私鑰，每條連線各自獨立、不可預測
import os
from cryptography.hazmat.primitives.asymmetric import ec

def handshake(peer_pub):
    # 私鑰由 OS 熵池隨機產生，不寫死、不複用，共享金鑰無法被預測
    ephem = ec.generate_private_key(ec.SECP256R1())
    shared = ephem.exchange(ec.ECDH(), peer_pub)[:32]
    return shared, ephem.public_key()   # 記錄公鑰供雙方確認、簽名綁定`,
		patch: `@@
-  import os
-  from cryptography.hazmat.primitives.asymmetric import ec
-
-  # <-- 私鑰寫死，等同沒有熵；任何人知道它就能推出共享祕密
-  static_private = ec.derive_private_key(1, ec.SECP256R1())
-
-  def handshake(peer_pub):
-      shared = static_private.exchange(ec.ECDH(), peer_pub)  # 每條連線同一把金鑰
-      return shared
+  import os
+  from cryptography.hazmat.primitives.asymmetric import ec
+
+  def handshake(peer_pub):
+      # 私鑰由 OS 熵池隨機產生，不寫死、不複用，共享金鑰無法被預測
+      ephem = ec.generate_private_key(ec.SECP256R1())
+      shared = ephem.exchange(ec.ECDH(), peer_pub)[:32]
+      return shared, ephem.public_key()   # 記錄公鑰供雙方確認、簽名綁定`,
		refs: ['OWASP-Crypto', 'CWE-322'],
		tags: ['key-exchange', 'ecdhe', 'entropy', 'nonce', 'predictable'],
	},
	{
		id: 'CWE-347',
		name: 'Improper Verification of Cryptographic Signature',
		lang: 'node',
		status: 'Complete',
		what: `密碼學簽章未正確驗證。對 JWT、簽名後的 payload 或受簽章保護的資料，
只做了 base64 解碼、解析或僅取出內容，卻從未用公鑰真正呼叫
驗證（jwt.verify / crypto.verify）的函式，或用了不具驗證效果的
decode-only 路徑讀取內容。這樣等於完全沒有把關資料的真實性與完整性，
任何人都可以自簽偽造的 JWT 或竄改 payload 而照樣被接受為有效。
建議做法是驗證前一律用可信公鑰（含英放者、演算法白名單與有效期）呼叫
驗證 API，成功後才可信任其中的欄位。`,
		problem: `// 不安全寫法：只 decode 不驗證簽章，偽造的 JWT 照樣被當作有效內容讀取
const jwt = require('jsonwebtoken');

function authorize(req) {
  const token = req.headers.authorization.replace(/^Bearer /, '');
  const payload = jwt.decode(token);          // <-- 只解碼，完全沒驗簽章
  if (payload && payload.isAdmin) {           // 攻擊者自簽 payload 即可化身 admin
    /* 放行管理行為 */
  }
}`,
		fixed: `// 安全寫法：用可信公鑰 + 演算法白名單真正驗證簽章，驗不過就拒收
const jwt = require('jsonwebtoken');
const { readFileSync } = require('fs');

const PUBLIC_KEY = readFileSync('public.pem');   // 可信簽發者公鑰，非寫死來源

function authorize(req) {
  const token = req.headers.authorization.replace(/^Bearer /, '');
  const payload = jwt.verify(
    token,
    PUBLIC_KEY,
    { algorithms: ['RS256'], issuer: 'auth.example.com', maxAge: '1h' },
  );  // 演算法白名單 + issuer/到期檢查，驗不過直接拋例外
  if (payload.isAdmin) { /* 放行管理行為 */ }
}`,
		patch: `@@
   const token = req.headers.authorization.replace(/^Bearer /, '');
-  const payload = jwt.decode(token);          // <-- 只解碼，完全沒驗簽章
-  if (payload && payload.isAdmin) {           // 攻擊者自簽 payload 即可化身 admin
-    /* 放行管理行為 */
-  }
+  const payload = jwt.verify(
+    token,
+    PUBLIC_KEY,
+    { algorithms: ['RS256'], issuer: 'auth.example.com', maxAge: '1h' },
+  );  // 演算法白名單 + issuer/到期檢查，驗不過直接拋例外
+  if (payload.isAdmin) { /* 放行管理行為 */ }`,
		refs: ['OWASP-JWT', 'CWE-347'],
		tags: ['jwt', 'signature-verification', 'decode-only', 'integrity'],
	},
	{
		id: 'CWE-759',
		name: 'Use of a One-Way Hash without a Salt',
		lang: 'python',
		status: 'Complete',
		what: `使用沒有加鹽的單向雜湊。直接用 SHA-1／MD5 這類快速雜湊對密碼做
一次雜湊、不帶任何每使用者獨立的鹽（salt），相同密碼一定會產生
完全相同的雜湊值。這讓攻擊者可以離線用彩虹表（rainbow table）或預先
計算好的字典一次反查整批雜湊，也可以拿同一雜湊直接進行字典型攻擊並觀察
重複，等同於把所有密碼攤在公開的破解表上。建議做法是使用自動包含
每條資料獨立、隨機鹽與成本因子的專用密碼 KDF（bcrypt／argon2id／scrypt）。`,
		problem: `# 不安全寫法：SHA-1 不帶 salt，相同密碼雜湊相同，可整批用彩虹表反查
import hashlib

def store_password(raw: str) -> str:
    return hashlib.sha1(raw.encode()).hexdigest()   # 無鹽、又快，2 位使用者同碼即重複`,
		fixed: `# 安全寫法：每條資料帶獨立隨機鹽的成本型 KDF，彩虹表完全失效
from argon2 import PasswordHasher

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

def store_password(raw: str) -> str:
    return ph.hash(raw)   # 內建每條獨立隨機鹽 + 成本參數，同密碼結果也不重複`,
		patch: `@@
-  import hashlib
-
-  def store_password(raw: str) -> str:
-      return hashlib.sha1(raw.encode()).hexdigest()   # 無鹽、又快，2 位使用者同碼即重複
+  from argon2 import PasswordHasher
+
+  ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
+
+  def store_password(raw: str) -> str:
+      return ph.hash(raw)   # 內建每條獨立隨機鹽 + 成本參數，同密碼結果也不重複`,
		refs: ['OWASP-Crypto', 'CWE-759'],
		tags: ['password-hashing', 'salt', 'rainbow-table', 'sha1', 'md5'],
	},
];
