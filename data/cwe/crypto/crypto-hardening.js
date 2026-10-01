// CWE chunk — category: Cryptographic Issues (side channels, channel integrity / behavioral discrepancy hardening).
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
		id: 'CWE-203',
		name: 'Observable Discrepancy',
		lang: 'python',
		status: 'Complete',
		what: `可觀察的差異。這是一族「旁路 oracle」的父類弱點：程式處理機密或隱私判斷時，
對不同輸入或不同布林真相，在回應時間、行為、錯誤訊息、輸出大小等可觀察面向
表現出差異，攻擊者就能把這種差異當作探針（oracle），逐一猜出帳號、推翻密碼
或以反覆觀察推回內部狀態。它統領較專業的子女類別：計時差異（CWE-208）、
行為差異（CWE-205）與隱蔽計時通道（CWE-385）。建議做法是讓敏感路徑的計算量、
輸出內容與分支行為都與秘密無關——統一工作量、恆定時間比較、對所有失敗給一致的
回應，並以 dummy 運算抹平數量與內容的差異。`,
		problem: `# 不安全寫法：比較一遇不同或長度不符就提早 return，回應與耗時都洩漏真相
def matches(stored, given):
    if len(given) != len(stored):
        return False                       # 長度錯就秒回，量時間即知長度
    for a, b in zip(stored, given):
        if a != b:
            return False                  # 越早錯越早回，時序洩漏逐位
    return True`,
		fixed: `# 安全寫法：恆定時間比較，一律等時不等億回，不分誰長誰短
import hmac
def matches(stored, given):
    return hmac.compare_digest(stored.encode(), given.encode())  # 不提早終止`,
		patch: `@@
-  def matches(stored, given):
-      if len(given) != len(stored):
-          return False
-      for a, b in zip(stored, given):
-          if a != b:
-              return False
-      return True
+  import hmac
+  def matches(stored, given):
+      return hmac.compare_digest(stored.encode(), given.encode())`,
		refs: ['OWASP-Crypto', 'CWE-203'],
		tags: ['side-channel', 'oracle', 'constant-time', 'timing'],
	},
	{
		id: 'CWE-205',
		name: 'Observable Behavioral Discrepancy',
		lang: 'python',
		status: 'Complete',
		what: `可觀察的行為差異（帳號列舉 oracle）。此類弱點出現於程式在內部失敗呈現
不同型態時給出「外型不一致」的回應——例如帳號不存在回「沒有這個帳號」而密碼
錯誤回「密碼錯誤」、權限不足與找不到資源回傳不同狀態碼、或對存在與否採取不同
動作。攻擊者就能逐一列舉合法帳號、資源或測試憑證，大幅縮小暴力破解範圍。安全
訊息設計的原則是「對攻擊者而言各種失敗不可分辨」：建議做法是讓所有失敗都回同一個
泛用且等價的回應（如一律「登入失敗」而不是揭露「帳號不存在」），並讓處理這些
分支的計算與延遲也一致，杜絕從錯誤碼、欄位或行為上推斷內部布林真相。`,
		problem: `# 不安全寫法：給不同的失敗系統別的訊息，等於把"帳號是否存在"標示出來
def login(user, pw):
    if not user_exists(user):
        return "沒有這個帳號"       # 攻擊者可枚舉合法帳號
    if not check_pw(user, pw):
        return "密碼錯誤"
    return issue_session(user)`,
		fixed: `# 安全寫法：不管哪種失敗都回相同結果，帳號是否存在不可分辨
def login(user, pw):
    ok = user_exists(user) and check_pw(user, pw)   # 兩者都跑，行為一致
    if not ok:
        return "帳號或密碼錯誤"     # 同一訊息，無法分辨差別
    return issue_session(user)`,
		patch: `@@
  def login(user, pw):
-     if not user_exists(user):
-         return "沒有這個帳號"
-     if not check_pw(user, pw):
-         return "密碼錯誤"
-     return issue_session(user)
+     ok = user_exists(user) and check_pw(user, pw)
+     if not ok:
+         return "帳號或密碼錯誤"
+     return issue_session(user)`,
		refs: ['OWASP-Auth', 'CWE-205'],
		tags: ['login-oracle', 'user-enumeration', 'behavioral-discrepancy'],
	},
	{
		id: 'CWE-208',
		name: 'Observable Timing Discrepancy',
		lang: 'python',
		status: 'Complete',
		what: `可觀察的計時差異。程式的執行時間依賴於秘密或高敏感比較的結果：密碼比較在
遇第一個錯誤字元就提前回傳、只有「帳號存在」才跑成本較高的 KDF、或對
不同長度的輸入花費不同時間。攻擊者只要大量量測並統計回應時間，就能逐步回復秘密，
就算做不到完全還原也可大幅縮小空間。計時是公認最難防的旁路之一，因為它不是
內容外洩而是「花多久」外洩。建議做法是讓敏感比較用恆定時間函式
（hmac.compare_digest／MessageDigest.isEqual）、移除依賴祕密的提前終止分支，
並讓運算成本與輸入無關，或對帳號存在與否跑完全等量的作業再統一回答。`,
		problem: `# 不安全寫法：逐字元比較且遇到第一個差異就早退，計時洩漏每位資訊
def matches(secret, guess):
    for i in range(min(len(secret), len(guess))):
        if secret[i] != guess[i]:
            return False     # 越前面的位元對不上越快回傳 → 可量時間推出字首
    return len(secret) == len(guess)`,
		fixed: `# 安全寫法：恆定時間比較，執行時間與秘密內容完全無關
import hmac
def matches(secret, guess):
    return hmac.compare_digest(secret.encode(), guess.encode())   # 不提前終止`,
		patch: `@@
-  def matches(secret, guess):
-      for i in range(min(len(secret), len(guess))):
-          if secret[i] != guess[i]:
-              return False
-      return len(secret) == len(guess)
+  import hmac
+  def matches(secret, guess):
+      return hmac.compare_digest(secret.encode(), guess.encode())`,
		refs: ['OWASP-Crypto', 'CWE-208'],
		tags: ['timing-attack', 'constant-time', 'hmac', 'compare'],
	},
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
		id: 'CWE-385',
		name: 'Covert Timing Channel',
		lang: 'python',
		status: 'Complete',
		what: `隱蔽計時通道。把受保護資料的內容，透過「花多久才做完」這條旁路洩露出去：
例如不同秘密值讓程式走成本高低不同的分支（條件式壓縮、KDF 或解壓），或某種
忙線迴圈的長度隨秘密內容而變。旁觀者只要量測耗時，就能把「資料是多少」解讀
出來，比計時差異更清楚地把耗時當成一條真正的資訊通道。它躲過內容型檢查的監看。
建議做法是敏感轉換一律使用與秘密無關的常時間計算：避免分支與運算步伐依賴秘密、
統一開銷，必要時以固定延遲或 dummy 運算把可分辨的差異完全填平，讓耗時再也無法
攜帶資料。`,
		problem: `# 不安全寫法：是否為管理者走不同的壓縮路徑，耗時與權限綁在一起
def send(user_data, is_admin):
    if is_admin:
        payload = compress(user_data)     # 較耗時路徑，量時間就看得出 is_admin
    else:
        payload = user_data
    write(socket, payload)`,
		fixed: `# 安全寫法：所有使用者都走同一計算路徑、同一成本，耗時與秘密無關
def send(user_data, is_admin):
    payload = compress(user_data)       # 統一壓縮→加密，所有人都一樣
    write(socket, enc(payload))`,
		patch: `@@
  def send(user_data, is_admin):
-     if is_admin:
-         payload = compress(user_data)     # 較耗時路徑洩漏權限
-     else:
-         payload = user_data
-     write(socket, payload)
+     payload = compress(user_data)       # 統一成本
+     write(socket, enc(payload))`,
		refs: ['OWASP-Crypto', 'CWE-385'],
		tags: ['timing-channel', 'side-channel', 'covert'],
	},
	{
		id: 'CWE-514',
		name: 'Covert Channel',
		lang: 'java',
		status: 'Complete',
		what: `隱蔽通道。攻擊者可藉由程式的某種共享資源或可觀察行為，在不受正常安全控制
攔截的情況下竊取或傳出機密資料：例如把一個位元的真相編碼進迴圈的忙線長度、
某個全局計數器的數值、物件的存在與否，或迴應的快慢，於是訊號透過一條「本來與
傳送機密無關」的管道流出去。之所以棘手，是因為內容檢查或網路層過濾看不到這條通道。
CWE-385（計時）只是它的一種特例。建議做法是先盤點程式「可對外觀察」的輸出與
共享資源，對不受信任的輸入不留下任何可被利用的輸出通道，敏感程序以 sandbox 隔離，
並且只允許透過受控且經 allowlist 的管道對外輸出資料。`,
		problem: `// 不安全寫法：拿忙線迴圈的執行時間把內部機密一位一位編碼「發送」出去
public void emit(boolean secret) {
    long since = System.nanoTime();
    while (System.nanoTime() - since < (secret ? 50_000_000L : 1_000_000L)) {
    }   // 旁觀者量測這次呼叫的耗時即得到 secret
}`,
		fixed: `// 安全寫法：對外耗時與內部機密完全解耦，只允許受控制的輸出通道
public void emit(boolean secret) {
    // secret 不影響任何耗時或可觀察行為，只能經由受控管道寫出
    controlledChannel.write(allowlistedTransform(secret));
}`,
		patch: `@@
  public void emit(boolean secret) {
-     long since = System.nanoTime();
-     while (System.nanoTime() - since < (secret ? 50_000_000L : 1_000_000L)) {
-     }   // 耗時即外洩 secret
+     // 耗時不再隨 secret 變化；只用受控通道輸出
+     controlledChannel.write(allowlistedTransform(secret));
  }`,
		refs: ['CWE-514'],
		tags: ['covert-channel', 'side-channel', 'exfiltration'],
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
-      return hashlib.sha1(raw.encode()).hexdigest()   # 無鹽、又快，同碼即重複
+  from argon2 import PasswordHasher
+
+  ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
+
+  def store_password(raw: str) -> str:
+      return ph.hash(raw)   # 內建獨立隨機鹽 + 成本參數`,
		refs: ['OWASP-Crypto', 'CWE-759'],
		tags: ['password-hashing', 'salt', 'rainbow-table', 'sha1', 'md5'],
	},
	{
		id: 'CWE-923',
		name: 'Improper Restriction of Communication Channel to Intended Endpoints',
		lang: 'python',
		status: 'Complete',
		what: `通訊通道未限制到預期的端點。伺服器或用戶端建立的通訊沒有把對端限制在
「原本想要通訊的對象」：例如伺服器對任何來源都開放控制指令、用戶端連線時不
驗證對方憑證也就不受限制連到哪個假冒端點。如此非預期的端點（別台主機、偽裝
的伺服器、未知的參與者）也能進入通道，機密被冒名者收走或控制指令被任意來源觸發
。它與「可被非端點存取」（CWE-300）相近，這裡特別強調通道本應限制在被告知的
端點集合。建議做法是連線兩端互相認證（mTLS），伺服器只信任已知端點的憑證，
用戶端驗證對端主機名並可對固定公鑰 pin，讓非預期端點在握手時就被拒絕。`,
		problem: `# 不安全寫法：控制用的伺服器對任何能連到 port 的來源都開放
import socket
s = socket.socket(); s.bind(('0.0.0.0', 9443)); s.listen(10)
while True:
    c, _ = s.accept()          # 沒驗證來源，誰來都收
    cmd = c.recv(1024)
    do_privileged(cmd)         # 任何主機都能下控制指令`,
		fixed: `# 安全寫法：以 mTLS 只信任已知端點，非預期端點握手即失敗
import socket, ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('/etc/certs/srv.pem', '/etc/certs/srv.key')
ctx.load_verify_locations('/etc/certs/allowed-clients')   # 只認已知端點
ctx.verify_mode = ssl.CERT_REQUIRED                     # 客戶端也必須出示憑證
while True:
    c, _ = s.accept()
    with ctx.wrap_socket(c, server_side=True) as tls:   # 未知端點會拋例外
        do_privileged(tls.recv(1024))`,
		patch: `@@
+  import socket, ssl
+  ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
+  ctx.load_cert_chain('/etc/certs/srv.pem', '/etc/certs/srv.key')
+  ctx.load_verify_locations('/etc/certs/allowed-clients')
+  ctx.verify_mode = ssl.CERT_REQUIRED
   while True:
       c, _ = s.accept()
-      cmd = c.recv(1024); do_privileged(cmd)
+      with ctx.wrap_socket(c, server_side=True) as tls:
+          do_privileged(tls.recv(1024))`,
		refs: ['OWASP-Transport', 'CWE-923'],
		tags: ['mtls', 'endpoint-restriction', 'channel', 'peer-auth'],
	},
	{
		id: 'CWE-924',
		name: 'Improper Enforcement of Message Integrity During Transmission in a Communication Channel',
		lang: 'python',
		status: 'Complete',
		what: `傳輸過程的訊息完整性未被確實執行。程式在傳輸資料時沒有替訊息加任何能偵測
竄改的完整性標記，或加了卻不在接收端執行驗證：例如把控制指令或配置直接送出去、
對消息資料加算未涵蓋全文的 MAC、或驗證失敗仍照常處理。中間人就可在訊息戰報
中改寫內容而不被察覺，導致接收端依竄改後的資料動作。它與「缺少完整性檢查
支援」（CWE-353）相近，但重點落在「在一條通訊通道上傳輸」時要確實執行
完整性把關。建議做法是對每則消息以雙方共用的金鑰計算並附加 HMAC／簽章，接收
端一律以恆定時間驗證其涵蓋全部欄位（含對談與序號等 context），驗不過就直接
拋棄、拒絕處理。`,
		problem: `# 不安全寫法：把遙控指令直接直播出去，中間可欄改而不被發覺
import socket, json
s = socket.create_connection(('ctrl.example.com', 9999))
s.sendall(json.dumps({'cmd': 'apply', 'cfg': cfg}).encode())   # 無 HMAC、有數據`,
		fixed: `# 安全寫法：以 HMAC 綁住整個 payload 並附上，對端驗不過就拒收
import socket, json, hmac, hashlib
payload = json.dumps({'cmd': 'apply', 'cfg': cfg}).encode()
mac = hmac.new(CTRL_KEY, payload, hashlib.sha256).digest()   # 涵蓋全文
s.sendall(mac + payload)          # 中間改任何 bit → MAC 對不上 → 對端拒收`,
		patch: `@@
+  import hmac, hashlib
   payload = json.dumps({'cmd': 'apply', 'cfg': cfg}).encode()
-  s.sendall(payload)               # 可被肆意竄改
+  mac = hmac.new(CTRL_KEY, payload, hashlib.sha256).digest()
+  s.sendall(mac + payload)        # 綁全文，竄改即被識破`,
		refs: ['OWASP-Transport', 'CWE-924'],
		tags: ['message-integrity', 'hmac', 'transmission', 'tamper'],
	},
	{
		id: 'CWE-1303',
		name: 'Non-Transparent Sharing of Microarchitectural Resources',
		lang: 'c',
		status: 'Complete',
		what: `微架構資源的非透明共用。CPU 中的快取、分支預測器、TLB 等資源在不同執行
上下文之間共用而未做隔離，攻擊程序便能用「走快取需花多少時間」這類腳印，
推測受害者正在處理的機密——Spectre／Meltdown 這類暫態執行側通道都隸屬此類。
秘密一旦當作記憶體位址（陣列索引、間接分支目標）使用，會留下可量測的足跡。
緩解分成多層：系統層使用處理器與作業系統的隔離／緩解開關，軟體層則要求機敏
路徑「與存取位址及分支無關」——不讓機密參與陣列索引或流程分支，改用常時間
累加、遮罩或迴廊遍歷，確保無論機密值多少，執行的記憶體足跡都完全相同。`,
		problem: `// 不安全寫法：以機密當作陣列索引，快取的足跡向外洩漏機密內容
uint8_t SBOX[256];
volatile uint8_t v = SBOX[secret];   // 秘密進入存取位址：共用快取可被量測`,
		fixed: `// 安全寫法：以遮罩累加遍歷整個查表，存取足跡與機密完全無關
uint8_t SBOX[256];
uint8_t r = 0;
for (int i = 0; i < 256; i++) {
    uint8_t m = ((int8_t)((i ^ secret) - 1)) >> 7;   // i==secret 才全 1
    r |= SBOX[i] & m;                                     // 位址固定遍歷，不洩漏
}`,
		patch: `@@
-  uint8_t SBOX[256];
-  volatile uint8_t v = SBOX[secret];   // 索引依賴機密，快取腳印外洩
+  uint8_t SBOX[256];
+  uint8_t r = 0;
+  for (int i = 0; i < 256; i++) {
+      uint8_t m = ((int8_t)((i ^ secret) - 1)) >> 7;
+      r |= SBOX[i] & m;
+  }`,
		refs: ['CWE-1303'],
		tags: ['side-channel', 'cache', 'speculative-execution', 'constant-time'],
	},
];
