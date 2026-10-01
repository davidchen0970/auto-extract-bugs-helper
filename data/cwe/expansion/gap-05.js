// CWE chunk — 類別:認證機制、明文儲存與密碼學／隨機數弱點補遺（Auth, Sensitive-Data Storage & Crypto/PRNG）
// 補齊官方 v4.20 中手冊原本缺漏的 Base/Variant 條目（CWE-301..CWE-383,含狀態與競態、UI 警示與 J2EE 誤用）
export default [
	{
		id: 'CWE-301',
		name: 'Reflection Attack in an Authentication Protocol',
		lang: 'python',
		status: 'Complete',
		what: `認證協議中的反射攻擊（Reflection Attack）。簡單的 challenge–response 協議若把「收到的挑戰值」原樣當回應回傳、
			，或對所有通訊方都套用同一個回應函式、不區分訊息的方向與參與者身分，攻擊者就能利用「目標主機」當成反射器：
			他把受信機器對自己提出的挑戰轉送給目標主機，再攔下目標主機的回應回丟給受信機器，藉此通過驗證、冒充受信任使用者。
			成因是回應計算沒綁定「這則訊息由誰發、往哪個方向發」，使一個合法的回應可被跨方重播。後果是未經授權的冒充登入
			與身分欺騙。修法是讓雙方使用不同的回應函式（f 與 f0、f1），並把通訊參與者的身分與方向資訊一起綁進挑戰內容後才計算回應。`,
		problem: `# 壞寫法：回應函式「原樣回傳」挑戰值，未綁定發送方與方向，可被反射重播
import hmac
def respond(challenge):
    return challenge          # 原樣回傳，跨參與者重播也能成立`,
		fixed: `# 好寫法：把方向/身分位元與挑戰值一起簽入回應，方向不同回應就不同
def respond(challenge, direction):
    mac = hmac.new(SECRET, direction + b':' + challenge, sha256)
    return mac.digest()`,
		patch: `@@
-    return challenge
+    mac = hmac.new(SECRET, direction + b':' + challenge, sha256)
+    return mac.digest()`,
		refs: ['CWE-301', 'OWASP-Auth'],
		tags: ['reflection', 'authentication', 'challenge-response'],
	},
	{
		id: 'CWE-303',
		name: 'Incorrect Implementation of Authentication Algorithm',
		lang: 'python',
		status: 'Complete',
		what: `認證演算法實作錯誤。需求明確定採用某種公認、經審核的認證演算法（HMAC、PBKDF2、Argon2、帶保護的比較……），
			但實作的人卻自製了等價函式或把演算法改錯：用普通字串比對而非常數時間比較、自寫有缺陷的金鑰衍生、把加密隨意
			當作認證、或把誠認證與 MAC 混用，得到的保護與原演算法不符。成因為「不信任被審核的實作、自己重造」，而自製版本
			幾乎都會引入常數時間、長度與填補等細微錯誤。後果是驗證可被側通道、暴力或長度洩漏繞過。修法是直接使用各語言
			標準函式庫中被審核的演算法，金鑰經由正規 KDF 取得，任何比較都用常數時間 API。`,
		problem: `# 壞寫法：自幹「Hash(金鑰+資料)」充當認證，且用普通 == 比較，有常數時間差異
def verify_mac(data, tag):
    derived = hashlib.sha1(KEY + data).digest()   # 自製 MAC,非 HMAC,可被長度延伸攻擊
    return derived == tag                            # 非結構時間比較`,
		fixed: `# 好寫法：直接使用正規 HMAC 演算法與常數時間比較
import hmac, hashlib
def verify_mac(data, tag):
    expected = hmac.new(KEY, data, hashlib.sha256).digest()
    return hmac.compare_digest(expected, tag)`,
		patch: `@@
-    derived = hashlib.sha1(KEY + data).digest()
-    return derived == tag
+    expected = hmac.new(KEY, data, hashlib.sha256).digest()
+    return hmac.compare_digest(expected, tag)`,
		refs: ['CWE-303', 'OWASP-Auth'],
		tags: ['authentication', 'hmac', 'timing', 'constant-time'],
	},
	{
		id: 'CWE-304',
		name: 'Missing Critical Step in Authentication',
		lang: 'java',
		status: 'Complete',
		what: `認證時遺漏了關鍵步驟。產品實作了某種認證技術，卻在流程中跳過一個原本應該存在的環節，使技術提供的保護被削弱：
			例如跳過「變更權限前的再次驗證」、跳過「登入失敗次數的鎖定計數」、把「已登入」與「已通過評估」混作一談、或
			完成初次憑證檢查後就永久放行而不在敏感性操作前回頭再驗證。成因為開發者認為某步驟可省略或假設先前檢查足以涵蓋後續。
			後果是攻擊者可倚靠被跳過的環節取得不該有的授權。修法是補齊每個安全性攸關步驟：身分或權限變更前重新確認目前使用者、
			併入失敗計帳與鎖定、並在多個階段各自做對應的驗證而不能只做一次。`,
		problem: `// 壞寫法：變更角色時漏掉「再次輸入密碼」這一步，憑已過期的登入就直接提權
void promoteSession(Session s, String role) {
    s.setRole(role);            // 沒有 re-authentication,任何人借到 session 即可提權
}`,
		fixed: `// 好寫法：提權前強制再次驗證目前使用者身分
void promoteSession(Session s, String role, String cred) {
    if (!verifyAuth(s.getUser(), cred)) {         // 關鍵的再次驗證步驟
        throw new AccessDenied("re-auth required");
    }
    s.setRole(role);
}`,
		patch: `@@
  void promoteSession(Session s, String role) {
-     s.setRole(role);
+     s.setRole(role);
+     if (!verifyAuth(s.getUser(), cred)) {
+         throw new AccessDenied("re-auth required");
+     }
+     s.setRole(role);
  }`,
		refs: ['CWE-304', 'OWASP-Auth'],
		tags: ['authentication', 'missing-step', 'privilege-elevation'],
	},
	{
		id: 'CWE-308',
		name: 'Use of Single-factor Authentication',
		lang: 'javascript',
		status: 'Complete',
		what: `使用單一因子的認證。產品在「理應需要多重因子」的安全性攸關情境（高權限主機登入、資金轉帳、遠端管理）卻只用單一因子（如密碼）。
			密碼一旦被竊取、釣魚或被暴力破解，就等於攻擊者拿到完整的身分，沒有任何第二層可依賴。成因為怕麻煩而省略 OTP／硬體金鑰／生物
			指紋等第二因子。後果是憑單一洩漏點即達成提權或冒充。修法是依風險評估在敏感操作與特權帳號上強制多重因子（MFA/2FA）：搭配
			TOTP、WebAuthn 或一次性碼，讓單一因子外洩不足以通過認證，並為高風險交易額外加一層動態驗證。`,
		problem: `// 壞寫法：只檢查密碼就放行,即使目標是高權限管理帳號
function login(user, password) {
  if (verifyPassword(user, password)) {
    return issueSession(user);
  }
}`,
		fixed: `// 好寫法：高權限著陸一律要求第二因子(TOTP),單一因子竄竊不足以登入
function login(user, password, otp) {
  if (verifyPassword(user, password) && verifyTOTP(user, otp)) {
    return issueSession(user);
  }
  return null;
}`,
		patch: `@@
  function login(user, password) {
-   if (verifyPassword(user, password)) {
+   if (verifyPassword(user, password) && verifyTOTP(user, otp)) {
      return issueSession(user);
    }
  }`,
		refs: ['CWE-308', 'OWASP-Authentication'],
		tags: ['single-factor', 'mfa', 'authentication'],
	},
	{
		id: 'CWE-309',
		name: 'Use of Password System for Primary Authentication',
		lang: 'javascript',
		status: 'Complete',
		what: `以密碼系統作為主要認證手段。把密碼當成唯一或主要的認證方式,會受一連串先天缺陷拖累而削弱其效力:密碼強弱由使用者決定
			、容易重複使用與洩漏、可被釣魚與暴力破解、又被儲存在伺服器端成為單點竊取目標。若同時缺少強健的儲存(未加鹽雜湊、普通雜湊、
			甚至明文)、缺少失敗鎖定與速率限制、或允許弱密碼,整個機制任何一環被攻破就等同身分被竊。修法是把儲存改成慢速加鹽的專用
			KDF(PBKDF2/Argon2/bcrypt)、強制密碼政策與多因子、對登入做速率限制與鎖定,並以 WebAuthn/憑證作為更強的主力取代純密碼。`,
		problem: `// 壞寫法:以明文/純雜湊存放密碼,且採暴力可破的偏弱雜湊與無鎖定
async function verify(user, input) {
  const row = await db.get('SELECT pw FROM users WHERE name=?', [user]);
  return md5(row.pw) === input;      // 無加鹽、無鎖定、可字典攻擊
}`,
		fixed: `// 好寫法:以 bcrypt 加鹽慢雜湊驗證,並對失敗進行速率限制/鎖定
const bcrypt = require('bcrypt');
async function verify(user, input) {
  await enforceLockout(user);                    // 失敗鎖定
  const row = await db.get('SELECT hash FROM users WHERE name=?', [user]);
  return bcrypt.compare(input, row.hash);        // 加鹽慢 KDF
}`,
		patch: `@@
  async function verify(user, input) {
    const row = await db.get('SELECT pw FROM users WHERE name=?', [user]);
-   return md5(row.pw) === input;
+   await enforceLockout(user);
+   const row2 = await db.get('SELECT hash FROM users WHERE name=?', [user]);
+   return bcrypt.compare(input, row2.hash);
  }`,
		refs: ['CWE-309', 'OWASP-Authentication'],
		tags: ['password', 'authentication', 'kdf', 'lockout'],
	},
	{
		id: 'CWE-314',
		name: 'Cleartext Storage in the Registry',
		lang: 'csharp',
		status: 'Complete',
		what: `在登錄檔(Registry)中明文儲存機密。程式把密碼、token、連線字串或卡號等敏感資料以明文直接寫進 Windows 登錄檔的值項,
			任何能讀取登錄的本機使用者或惡意軟體(包括 Network Service、登入的使用者)都能直接把這些值讀走,不需要解密。登錄檔是
			常被掃描的低垂果實,攻擊者往往在提權的第一步就去翻 ILM/Software 下的機密。成因為把「內部機制」當成不會被讀取的地點、
			又沒做任何保護。修法是機密不要落地進登錄:需要時從作業系統金鑰储存或 DPAPI\/憑證庫讀取,必要寫入時用 DPAPI 的
			ProtectedData.Protect 以目前使用者範圍加密後再寫入。`,
		problem: `// 壞寫法:把金鑰明文寫進登錄檔,任何本機使用者都能讀走
using Microsoft.Win32;
Registry.CurrentUser.OpenSubKey(@"Software\\MyApp", true)
  .SetValue("ApiKey", apiKey);            // 明文 token 烙進登錄`,
		fixed: `// 好寫法:敏感值以 DPAPI 加密後才存,或根本不放登錄而經由系統金鑰儲存
using System.Security.Cryptography;
var cipher = ProtectedData.Protect(
    Encoding.UTF8.GetBytes(apiKey), null, DataProtectionScope.CurrentUser);
Registry.CurrentUser.OpenSubKey(@"Software\\MyApp", true)
  .SetValue("ApiKey", cipher);`,
		patch: `@@
 -  .SetValue("ApiKey", apiKey);
+  var cipher = ProtectedData.Protect(
+      Encoding.UTF8.GetBytes(apiKey), null, DataProtectionScope.CurrentUser);
+  .SetValue("ApiKey", cipher);`,
		refs: ['CWE-314', 'OWASP'],
		tags: ['registry', 'cleartext', 'secrets'],
	},
	{
		id: 'CWE-315',
		name: 'Cleartext Storage of Sensitive Information in a Cookie',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `把敏感資訊明文存進 Cookie。程式直接將密碼、token、卡號或身分標識寫進瀏覽器 Cookie 且未加保護:沒設 Secure(可被 HTTP 竊聽)、
			沒設 HttpOnly(任何 XSS 都能取走)、也常以明文存放。Cookie 位在使用者的瀏覽器端,會被快取、被其他登入的惡意瀏覽器擴充或 XSS
			觸及、也無法被伺服器加密在傳輸完成後再利用,等同把機密送到最不受信的位置。成因為把「之後要再取的東西」塞進單一可回傳的 cookie,
			而忽略其暴露面。修法是 Cookie 只放不敏感的隨機會話識別碼,真正的資料留在伺服器端;任何寫入的 Cookie 都要同時設 Secure、HttpOnly、SameSite,
			並對內容做認證加密後才下放。`,
		problem: `// 壞寫法:把卡號與權杖明文寫進 cookie,且未設保護旗標
function loginOK(res, user) {
  res.setHeader('Set-Cookie',
    'auth=' + user.cardNumber + '; Path=/');   // 明文 + 無 Secure/HttpOnly
}`,
		fixed: `// 好寫法:只用隨機不敏感 session id,加 Secure/HttpOnly/SameSite,資料留在伺服器
function loginOK(res, user) {
  const sid = crypto.randomBytes(32).toString('hex');
  sessions.set(sid, user);        // 資料留伺服器端
  res.setHeader('Set-Cookie',
    'sid=' + sid + '; HttpOnly; Secure; SameSite=Lax; Path=/');
}`,
		patch: `@@
-   res.setHeader('Set-Cookie',
-     'auth=' + user.cardNumber + '; Path=/');
+   const sid = crypto.randomBytes(32).toString('hex');
+   sessions.set(sid, user);
+   res.setHeader('Set-Cookie',
+     'sid=' + sid + '; HttpOnly; Secure; SameSite=Lax; Path=/');`,
		refs: ['CWE-315', 'OWASP'],
		tags: ['cookie', 'cleartext', 'httponly'],
	},
	{
		id: 'CWE-317',
		name: 'Cleartext Storage of Sensitive Information in GUI',
		lang: 'javascript',
		status: 'Complete',
		what: `在 GUI 中以明文呈現／存留敏感資訊。程式把密碼、金鑰或認證資料以可讀的明文回填進使用者介面欄位、或用可被讀取的 DOM 保存,
			而沒有做遮蔽;例如密碼輸入框開啟了瀏覽器自動完成、把密碼值直接 assign 回輸入欄位、或用 plain text 元素顯示金鑰。GUI 上的明文
			會被螢幕分享、肩窺、瀏覽器「記住密碼」與開發者工具輕易取走。成因為把「給人看的輸入框」直接當成資料容器,而不做遮蔽或停留限制。
			修法是用 password 型別輸入框、關閉 autocomplete、避免把機密寫進 DOM,且送出後立即清空並以專用密碼管理儲存保管。`,
		problem: `// 壞寫法:把使用者密碼明文assign回密碼輸入框,且開啟自動完成,瀏覽器會儲存
passwordInput.type = 'password';        // 看似遮蔽
passwordInput.value = savedPassword;    // 明文回填,autocomplete 預設開啟會記住
passwordInput.autocomplete = 'on';`,
		fixed: `// 好寫法:不留存密碼值於 DOM,並關閉自動完成與表單記憶
passwordInput.type = 'password';
passwordInput.autocomplete = 'off';
passwordInput.value = '';              // 不把機密寫進 UI 欄位`,
		patch: `@@
- passwordInput.value = savedPassword;
+ passwordInput.autocomplete = 'off';
+ passwordInput.value = '';`,
		refs: ['CWE-317', 'OWASP'],
		tags: ['gui', 'cleartext', 'password-field'],
	},
	{
		id: 'CWE-318',
		name: 'Cleartext Storage of Sensitive Information in Executable',
		lang: 'cpp',
		status: 'Complete',
		what: `在可執行檔中明文儲存敏感資訊。程式把密碼、API 金鑰、加密金輪或憑證直接以可讀字串寫死在執行檔內——字面常數、字串表、或僅以
			XOR\/Base64 這種「假遮蔽」藏起來。任何拿到 binary(下載、反向工程、strings 掃描)的人都能直接翻出這些機密;因複雜度極高也幾乎無法在
			外洩後更換,等同永久授權。成因為把「不在眼前就行」的帳密寫死以求方便。修法是凡機密一律不在原始碼、執行檔或設定檔中落地:由受保護的
			密鑰儲存、KMS、作業系統金鑰鏈在執行期注入,並對 binary 做符號與字串剔除、使用混淆層也不等於安全。`,
		problem: `// 壞寫法:把資料庫密碼寫成字面常數,strings 掃一下 binary 就外洩
const char *kDbPass = "CorrectHorseBatteryStaple";   // 明文躺在 .rodata
int main() { db_connect("db.internal", "app", kDbPass); }`,
		fixed: `// 好寫法:執行期由作業系統金鑰鏈注入,不在 binary 留下任何機密字串
char *pass = NULL;
errcObtainSecret("app/db-pass", &pass);   // macOS Keychain / Windows 憑證庫
db_connect("db.internal", "app", pass ? pass : abort_fail());`,
		patch: `@@
- const char *kDbPass = "CorrectHorseBatteryStaple";
- int main() { db_connect("db.internal", "app", kDbPass); }
+ char *pass = NULL;
+ errcObtainSecret("app/db-pass", &pass);
+ db_connect("db.internal", "app", pass ? pass : abort_fail());`,
		refs: ['CWE-318', 'OWASP'],
		tags: ['cleartext', 'hardcoded', 'binary', 'secrets'],
	},
	{
		id: 'CWE-323',
		name: 'Reusing a Nonce, Key Pair in Encryption',
		lang: 'python',
		status: 'Complete',
		what: `加密時重用 Nonce／金鑰組合。Nonce（或初始化向量 IV）的本意是「只給當次且只用一次」,用來保證同一金鑰底下每次密文不同;
			一旦同一組 nonce 與金鑰被重複使用,認證加密的可選隨機性就消失:同明文會產出同密文、nonce 重用更可能讓攻擊者直接導出 XOR 密文
			、偽造標籤或解密任意內容(尤其 AEAD 如 AES-GCM 重用 nonce 是災難性的)。成因為常將 nonce 當成固定常數、或在多處共用同一個值。
			修法是每次加密都由 CSPRNG(secrets.token_bytes)新產一個唯一的 nonce∘IV,並把該值與密文一同儲存∘傳遞,絕不重用。`,
		problem: `# 壞寫法:同一支 nonce 被固定重用,同明文→同密文,可被分析甚至偽造
NONCE = b"0123456789ab"        # 重用同一個 nonce
def encrypt(data):
    return aesgcm.encrypt(NONCE, data, None)   # GCM nonce 重用極危險`,
		fixed: `# 好寫法:每次加密由 CSPRNG 新產 unique nonce,再與密文一起存留
import secrets
def encrypt(data):
    nonce = secrets.token_bytes(12)                    # 每次唯一
    ct = aesgcm.encrypt(nonce, data, None)
    return nonce + ct                                  # 隨密文保存供解密`,
		patch: `@@
-NONCE = b"0123456789ab"
 def encrypt(data):
-    return aesgcm.encrypt(NONCE, data, None)
+    nonce = secrets.token_bytes(12)
+    ct = aesgcm.encrypt(nonce, data, None)
+    return nonce + ct`,
		refs: ['CWE-323', 'OWASP-Crypto'],
		tags: ['nonce', 'reuse', 'aead', 'gcm'],
	},
	{
		id: 'CWE-324',
		name: 'Use of a Key Past its Expiration Date',
		lang: 'java',
		status: 'Complete',
		what: `使用已超過效期的金鑰或密碼。產品在密鑰（或密碼）到達其規定的到期／輪換時限後仍繼續使用、從不檢查或從不輪換。密鑰期間越長,
			暴露給暴力破解與「長期收集後才攻破」攻擊的時間窗就越大;而且長期不輪換的金鑰一旦在某次事件中洩漏,影響面會一路延伸,無法靠
			撤銷來止血。成因為把輪換當成可選、或缺少到期檢查與提醒機制。修法是為每一個金鑰定義明確的生命週期:在使用時檢查其 notAfter／
			到期欄位、到期前就產生新金鑰並搬移資料、支撐平滑的密鑰輪換與撤銷,並將舊密鑰單獨標記為失效後停用。`,
		problem: `// 壞寫法:遇到過期金鑰仍照常信任,不做到期檢查也不輪換
boolean keyOK(X509Certificate cert) {
    return signature.verifiedBy(cert);     // 不看 cert.getNotAfter(),過期照用
}`,
		fixed: `// 好寫法:使用前檢查到期,並在到期前安排輪換
boolean keyOK(X509Certificate cert, Date now) {
    if (cert.getNotAfter().before(now) || cert.getNotBefore().after(now)) {
        return false;                      // 過期/未生效一律拒絕
    }
    if (rotationDue(cert)) { rotateKeys(cert); }   // 事前輪換
    return signature.verifiedBy(cert);
}`,
		patch: `@@
 boolean keyOK(X509Certificate cert) {
+     if (cert.getNotAfter().before(now) || cert.getNotBefore().after(now)) {
+         return false;
+     }
+     if (rotationDue(cert)) { rotateKeys(cert); }
      return signature.verifiedBy(cert);
 }`,
		refs: ['CWE-324', 'OWASP-Crypto'],
		tags: ['expiry', 'rotation', 'key-lifecycle'],
	},
	{
		id: 'CWE-329',
		name: 'Generation of Predictable IV with CBC Mode',
		lang: 'python',
		status: 'Complete',
		what: `以可預測的 IV 搭配 CBC 模式。程式為 Cipher Block Chaining(CBC)產生並使用可預測的初始化向量(固定 IV、以時間或計數器衍生)。CBC 的
			IV 作用是把每個訊息的相同明文歧異化;若 IV 可被預測,在多個訊息共用同一金鑰時,相同的明文前綴會產生相同的密文前綴(留下「水印」),
			攻擊者可據此做字典攻擊、確認已猜測的明文值,或重建已知明文的正確性——「CBC oracle」一類的攻擊也通常由此趁虛而入。成因為把 IV 當成
			可重複的計數器或常數。修法是 CBC（及任何需要隨機 IV 的模式)的 IV 一律由 CSPRNG 每次新產、且為完整區塊長度不可預測,再與密文一起存放。`,
		problem: `# 壞寫法:以固定/可預測的 IV 搭配 AES-CBC,同明文留下相同密文前綴
IV = b"\x00" * 16        # 每次都一樣(或可預測)
def enc_cbc(key, plaintext):
    return AES.new(key, AES.MODE_CBC, IV).encrypt(pad(plaintext))`,
		fixed: `# 好寫法:每次由 CSPRNG 隨機產生不可預測的完整區塊 IV
import os
def enc_cbc(key, plaintext):
    iv = os.urandom(AES.block_size)        # 每次隨機、不可預測
    c = AES.new(key, AES.MODE_CBC, iv)
    return iv + c.encrypt(pad(plaintext)) # iv 與密文一起保存`,
		patch: `@@
-IV = b"\x00" * 16
 def enc_cbc(key, plaintext):
-    return AES.new(key, AES.MODE_CBC, IV).encrypt(pad(plaintext))
+    iv = os.urandom(AES.block_size)
+    c = AES.new(key, AES.MODE_CBC, iv)
+    return iv + c.encrypt(pad(plaintext))`,
		refs: ['CWE-329', 'OWASP-Crypto'],
		tags: ['cbc', 'iv', 'predictable', 'watermark'],
	},
	{
		id: 'CWE-332',
		name: 'Insufficient Entropy in PRNG',
		lang: 'cpp',
		status: 'Complete',
		what: `偽隨機產生器能獲取／使用的熵不足。Pseudo-Random Number Generator(PRNG)若只從一小撮、低品質或可猜測的來源取種(系統時間、pid、
			未指派緩衝區、過度採樣同一熵池),產出的序列即使看起來隨機,其真正的可能性空間也極小。對密碼早已不足或不穩定的攻擊者只要窮舉種子即可
			重構整個序列;對要求不可預測性的密碼情境(金鑰、nonce、session id)等於完全失效。成因是以非加密用途的 rand()/PRNG 充當 CSPRNG,且輸入熵
			不足。修法是密碼睦關的地方一律改用系統級的加密安全隨機源(getrandom、BcryptGenRandom、RAND_bytes),並在取隨機值前確認熵池已就緒、輸出的
			位元組量符合所需的安全強度。`,
		problem: `// 壞寫法:以 libc rand() 當密碼源,種子熵極低,序列可被窮舉重現
srand(clock());                  // 種子只有計時器那點熵
uint8_t key[32];
for (int i = 0; i < 32; i++) key[i] = (uint8_t)(rand() & 0xff); // 可預測`,
		fixed: `// 好寫法:改用作業系統 CSPRNG,熵充分且輸出不可預測
#include <sys/random.h>
uint8_t key[32];
if (getrandom(key, sizeof key, 0) != 32) abort();   // 系統級高熵`,
		patch: `@@
-srand(clock());
-uint8_t key[32];
-for (int i = 0; i < 32; i++) key[i] = (uint8_t)(rand() & 0xff);
+uint8_t key[32];
+if (getrandom(key, sizeof key, 0) != 32) abort();`,
		refs: ['CWE-332', 'OWASP-Crypto'],
		tags: ['prng', 'entropy', 'cryptographic-random'],
	},
	{
		id: 'CWE-333',
		name: 'Improper Handling of Insufficient Entropy in TRNG',
		lang: 'cpp',
		status: 'Complete',
		what: `真隨機產生器(TRNG)熵不足以供處理不當。硬體的 True Random Number Generator 天生只有有限且可能枯竭的熵來源,當它撈不到足夠熵時
			會失敗或阻塞;若程式無視回傳碼、把失敗或熵不足的輸出照樣當成「已經準備好」的有效隨機值拿去做金鑰或 nonce,就等於在零比特的隨機
			性上建立安全。成因為跑了 RAND_bytes 就假定必然成功、不檢查 RAND_status,也不考慮阻塞期。後果是緊要時刻產出低熵值,密碼可被預測、
			若同時忽略錯誤還可能致 DoS。修法是取隨機值前先確認熵池處於就緒狀態、檢查每個失敗回傳並採取「等熵到位或中止安全的操作」的安全失效
			路徑,不在熵不夠時硬幹。`,
		problem: `// 壞寫法:不檢查 RAND_status 即取隨機,TRNG 熵枯竭時拿到低熵值照用
unsigned char key[32];
RAND_bytes(key, 32);        // 回傳失敗或阻塞期照單全收,不做任何檢查`,
		fixed: `// 好寫法:先確保熵池就緒,每個回傳都檢查,失敗就中止安全操作
if (RAND_status() != 1) { wait_for_entropy(); }   // 等熵到位
if (RAND_bytes(key, 32) != 1) { abort_secure(); } // 失敗永不使用結果`,
		patch: `@@
-unsigned char key[32];
-RAND_bytes(key, 32);
+if (RAND_status() != 1) { wait_for_entropy(); }
+if (RAND_bytes(key, 32) != 1) { abort_secure(); }`,
		refs: ['CWE-333', 'OWASP-Crypto'],
		tags: ['trng', 'entropy', 'rand_bytes'],
	},
	{
		id: 'CWE-334',
		name: 'Small Space of Random Values',
		lang: 'java',
		status: 'Complete',
		what: `隨機值的可取範圍過小。產生器雖然用了隨機數,但可產生的值個數遠小於產品安全所需要的量(把 token 做 0..999、用 4 位數 OTP「當很久」、
			隨機值是做了但總可能性只有幾百幾萬),讓暴力窮舉在現實時間內即可掃完整個空間。成因為用小整數範圍或切短隨機值的位元數,又把這
			「小空間」拿去守護安全攸關的資料。後果是 token、session 或驗證碼可被窮舉猜中,防衛形同虛設。修法是讓隨機值的空間至少對應所需的
			安全強度:疑似 128-bit 以上的 CSPRNG 輸出(例如 16 byte token),把長度視為安全參數,而不是用一個小 range 濫竽充數。`,
		problem: `// 壞寫法:以很小的整數空間當金鑰,暴力可在瞬間窮舉
Random r = new Random();
int resetToken = 1000 + r.nextInt(9000);   // 只約 9000 種可能,可窮舉`,
		fixed: `// 好寫法:以 CSPRNG 產出足夠位元的隨機 token,空間大到無法暴力
byte[] token = new byte[16];
new SecureRandom().nextBytes(token);        // 128-bit 空間
String resetToken = Base64.urlEncode(token);`,
		patch: `@@
-Random r = new Random();
-int resetToken = 1000 + r.nextInt(9000);
+byte[] token = new byte[16];
+new SecureRandom().nextBytes(token);
+String resetToken = Base64.urlEncode(token);`,
		refs: ['CWE-334', 'OWASP-Crypto'],
		tags: ['random', 'brute-force', 'key-space'],
	},
	{
		id: 'CWE-335',
		name: 'Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)',
		lang: 'java',
		status: 'Complete',
		what: `偽隨機產生器(PHG)播種使用不當。程式的確播了種,但播種時機、次數或方式不對以致「隨機」失效:以固定種子初始化普通 PRNG、在產生過程中
			重新 setSeed 打斷熵流使之後的輸出可被倒退重建、或把種子重複拿來 re-seed 同一個實例。PRNG 的種子是整個序列熵的唯一來源,一旦種子管理
			錯誤,序列就不再具備不可預測性。成因不了解 PRNG 內部狀態與 setSeed 的語意、把演算法的重送能力與密碼安全混為一談。修法是密碼目的一律
			用 CSPRNG 並讓其自行安全播種(reseed 由系統熵自動進行),不要手動 setSeed、不要為可預測性而復用同一種子、也勿把同源種子灌給多個實例。`,
		problem: `// 壞寫法:產生中途手動 setSeed 重新播種,推 wipe 熵流使輸出落入可重建的狀態
Random r = new Random(System.currentTimeMillis());
r.setSeed(fixedSeed);              // 中途重置種子,之後輸出由已知種子決定`,
		fixed: `// 好寫法:用 CSPRNG 並讓它自行安全播種,不手動 setSeed
SecureRandom sr = new SecureRandom();       // 作業系統熵自動播種與 reseed
String tok = Long.toHexString(sr.nextLong());`,
		patch: `@@
-Random r = new Random(System.currentTimeMillis());
-r.setSeed(fixedSeed);
+SecureRandom sr = new SecureRandom();
+String tok = Long.toHexString(sr.nextLong());`,
		refs: ['CWE-335', 'OWASP-Crypto'],
		tags: ['prng', 'seed', 'reseed'],
	},
	{
		id: 'CWE-336',
		name: 'Same Seed in Pseudo-Random Number Generator (PRNG)',
		lang: 'java',
		status: 'Complete',
		what: `偽隨機產生器每次都使用相同的種子。每次程式初始化都餵進同一顆種子(文件常數、金鑰檔、固定字串),於是每一次執行產出的「隨機」序列完全
			相同。知道或推測出種子的人只要跑一次同種子的 PRNG 就能精確重造今後所有值;在不同部署之間也必然彼此一致,使任何依賴此隨機性的
			session、token 或金鑰都可被預測。成因為複製範例的固定種子又從不換。修法是不要在程式碼中出現固定的種子常數——密碼用途改用 CSPRNG、
			由其自身從系統熵安全取材;若真的需要可重現序列的非密碼用途,也要刻意標記為非密碼使用,並嚴禁與密碼混用。`,
		problem: `// 壞寫法:固定種子 42,每次開機都產出同一條「隨機」序列
Random r = new Random(42);
long cookie = r.nextLong();      // 每次都一樣,可被預測`,
		fixed: `// 好寫法:交由 CSPRNG 自行從系統熵播種,絕無固定種子
SecureRandom sr = new SecureRandom();   // 每次執行種子不同
long cookie = sr.nextLong();`,
		patch: `@@
-Random r = new Random(42);
-long cookie = r.nextLong();
+SecureRandom sr = new SecureRandom();
+long cookie = sr.nextLong();`,
		refs: ['CWE-336', 'OWASP-Crypto'],
		tags: ['prng', 'fixed-seed', 'predictable'],
	},
	{
		id: 'CWE-337',
		name: 'Predictable Seed in Pseudo-Random Number Generator (PRNG)',
		lang: 'cpp',
		status: 'Complete',
		what: `偽隨機產生器以可預測的種子初始化。種子取自攻擊者可觀察或推測的來源——系統時間(秒級)、process ID、固定地址、使用者提供的數值——使
			PRNG 序列可以被低成本重現。因為種子空間與已知性直接決定了序列可被窮舉的程度,取 time(NULL) 或 getpid() 當種子,攻擊者只要推測當下
			時間戳/ pid 就能重算整條值。成因為用方便取得的「觀察值」當熵。修法是密碼用途不走種子型 PRNG:直接用系統級 CSPRNG(getrandom／
			RAND_bytes／SecureRandom)在作業系統熵池充足的前提下取得值,而不是先 seed 一個可預測的 rand()。`,
		problem: `// 壞寫法:以目前系統時間秒數當種子,時間可被預測,整串輸出可被重現
srand(time(NULL));          // 種子 = 可預測的系統時間
int token = rand();`,
		fixed: `// 好寫法:直接使用作業系統加密安全隨機,沒有可預測種子這回事
unsigned int token;
if (getrandom(&token, sizeof token, 0) != sizeof token) abort();`,
		patch: `@@
-   srand(time(NULL));
-   int token = rand();
+   unsigned int token;
+   if (getrandom(&token, sizeof token, 0) != sizeof token) abort();`,
		refs: ['CWE-337', 'OWASP-Crypto'],
		tags: ['prng', 'predictable-seed', 'time-seed'],
	},
	{
		id: 'CWE-339',
		name: 'Small Seed Space in PRNG',
		lang: 'java',
		status: 'Complete',
		what: `偽隨機產生器使用的種子空間過小。種子雖然每次不同,但可能的種子總數非常小(例如用 process ID、短計數器、或把秒級時間取模到幾萬),
			等於整鐵規則地限定輸出序列只有少數幾百萬甚至幾千種。攻擊者不必知道確切序列,只要暴力迭代「所有可能的種子」重算輸出即可命中——種子
			空間就是暴力面的上界。成因為拿「夠在樣本看到不同」的種子卻沒考慮其總空間必須大於攻擊者的窮舉成本。修法是讓密碼用途的隨機性不再依賴
			人工種子:採用系統 CSPRNG(其種子與熵空間以億兆計),而非把時間或 pid 這類幾個 byte 的值當種子。`,
		problem: `// 壞寫法:以 process ID(通常 < 32768)當種子,種子空間小到可暴力窮舉
Random r = new Random(ProcessHandle.current().pid());
long token = r.nextLong();    // 窮舉幾萬個 pid 即可重現`,
		fixed: `// 好寫法:CSPRNG 由系統熵自動播種,種子空間遠超過窮舉能力
SecureRandom sr = new SecureRandom();
long token = sr.nextLong();   // 種子熵 256-bit 以上`,
		patch: `@@
-Random r = new Random(ProcessHandle.current().pid());
+SecureRandom sr = new SecureRandom();
 long token = r.nextLong();`,
		refs: ['CWE-339', 'OWASP-Crypto'],
		tags: ['prng', 'seed-space', 'brute-force'],
	},
	{
		id: 'CWE-341',
		name: 'Predictable from Observable State',
		lang: 'python',
		status: 'Complete',
		what: `可由可觀察的系統狀態預測。用來做安全決定的數值或識別碼,其來源是攻擊者多少能觀察到的系統或網路狀態——目前時間、process ID、連線序號、
			記憶體位置、計數器等。即使對這些狀態做了某種「運算」,可觀察的一方只要估得回輸入範圍就能重算輸出,尤其當來源是粗粒度的 time() 或
			自增值。成因為把「看似隨機的衍生物」建立在低熵可觀察量上。修法是密碼攸關的隨機值一律由 CSPRNG/secrets 產生且與任何可觀察量無關;
			需要不可猜測的身份時採用真正隨機的 token,而不是函式把時間/pid 轉字串來湊。`,
		problem: `# 壞寫法:以系統時間當隨機來源,攻擊者觀察到當下秒能直推 token
import time
def make_token():
    return str(int(time.time()))   # 可觀察的狀態 → 可預測的值`,
		fixed: `# 好寫法:由 secrets(CSPRNG)產生,與系統狀態無關
import secrets
def make_token():
    return secrets.token_urlsafe(16)   # 不可從時間/pid 推測`,
		patch: `@@
 import time
 def make_token():
-    return str(int(time.time()))
+    return secrets.token_urlsafe(16)
+    # 移除 time 依賴,改用 secrets`,
		refs: ['CWE-341', 'OWASP-Crypto'],
		tags: ['predictable', 'observable-state', 'time'],
	},
	{
		id: 'CWE-342',
		name: 'Predictable Exact Value from Previous Values',
		lang: 'python',
		status: 'Complete',
		what: `可由先前值精確預測下一個數值。產品的隨機數由某種內部狀態可被重建的產生器驅動(Mersenne Twister,低度線性回饋位移暫存器,或對於
			使用者可觀察到大量輸出的 PRNG)。攻擊者連續觀察(往往只需 624 個 32-bit 輸出就能完整重建 MT 的內部狀態)之後,就能「精確」算出下一次
			的完整數值。成因為把設計上可重放、內建狀態有限的演算法用在需要不可預測性的地方。修法是密碼情境改用 never 依賴 MT/自建 PRNG 的 CSPRNG:
			Python 用 secrets(random 喖列的 MT 不適於安全),C/Java 用 getrandom/SecureRandom,並避免把產生器輸出過量暴露給攻擊者。`,
		problem: `# 壞寫法:以 Mersenne Twister(random 模組)產 token,可從前 624 個輸出重建內部狀態
import random
tok = random.getrandbits(32)     # 觀察足夠多輸出後,下一值可精確算出`,
		fixed: `# 好寫法:改用 secrets(CSPRNG),內部狀態不可從輸出一路重建
import secrets
tok = secrets.randbits(32)       # 不可預測的加密安全值`,
		patch: `@@
-import random
-tok = random.getrandbits(32)
+import secrets
+tok = secrets.randbits(32)`,
		refs: ['CWE-342', 'OWASP-Crypto'],
		tags: ['mt19937', 'predictable', 'state-recovery'],
	},
	{
		id: 'CWE-343',
		name: 'Predictable Value Range from Previous Values',
		lang: 'python',
		status: 'Complete',
		what: `可由先前值收窄下一個值的可能範圍。產品的隨機值經過觀察後,可以推斷出下一次輸出僅來自「相對很小的可能範圍」;這不是精確預測,但夠讓
			攻擊者把需要窮舉的空間縮到實務可掃完的規模。常見於以線性或低度非線性演算法、或以狀態派生的 PRNG 做非密碼用途時;時間戳與計數器
			谷雜的輸出尤其如此。成因為把低熵或不沿隨機性的產生器當作安全隨機來源。修法是讓產生的值擁有完整的安全強度——由 CSPRNG/secrets 提供、
			每個位元都不可由先前輸出縮窄;若某個值本質就很小(如 4 位 OTP),就要以失效次數與時間窗等其他防禦補強,而不是期望它不可猜。`,
		problem: `# 壞寫法:以計數器/時間谷雜出「範圍可被先前觀察收窄」的 slot
def next_slot(prev):
    return (prev * 2654435761 + 123) % (1 << 20)   # 線性 LCG,範圍可推`,
		fixed: `# 好寫法:由 CSPRNG 取完整隨機值,先前輸出無法縮小下一個的範圍
import secrets
def next_slot():
    return secrets.randbelow(1 << 20)     # 每 출력均分佈,不可由前置值推`,
		patch: `@@
 def next_slot(prev):
-    return (prev * 2654435761 + 123) % (1 << 20)
+    return secrets.randbelow(1 << 20)`,
		refs: ['CWE-343', 'OWASP-Crypto'],
		tags: ['random', 'range-guess', 'lcg'],
	},
	{
		id: 'CWE-344',
		name: 'Use of Invariant Value in Dynamically Changing Context',
		lang: 'javascript',
		status: 'Complete',
		what: `在動態變化的情境中使用了固定不變的值。程式採用某個「常數、名稱或引用」,但這個值在不同環境、租戶、部署或請求之間本應有所差別(預設共同
			帳密、只一套金鑰「全包」、死寫一個 shared secret 或固定主機)。當上下文實際各不相同時仍共用同一個不變值,等於把多個隔離面打成一層:一個
			請求的資訊洩漏或猜中,就能橫向套用到所有環境。成因為把「先寫死能動就好」當成最終狀態、缺乏依環境切換的設定與名稱隔離。修法是讓任何
			本應相異的值都依其上下文派生或從組態注入:依 tenant/environment 選擇金鑰與帳號、以 per-context 的識別碼區隔資料,並提供明確的設定機制
			而不是烙死一個全應用共用的常數。`,
		problem: `// 壞寫法:所有租戶共用同一金鑰與內部主機,甲租戶遷漏即感染全部租戶
const API_BASE = 'https://admin.internal.example.com';   // 死寫,所有環境一樣
const SHARED_SECRET = 'default-secret';                // 全應用共用同一密鑰`,
		fixed: `// 好寫法:依環境與租戶由組態注入,各自使用獨立隔離的金鑰
const API_BASE = process.env.API_BASE;                // 依環境提供
const secret = keyring.tenantSecret(tenantId);          // 每個租戶一個獨立密鑰`,
		patch: `@@
-const API_BASE = 'https://admin.internal.example.com';
-const SHARED_SECRET = 'default-secret';
+const API_BASE = process.env.API_BASE;
+const secret = keyring.tenantSecret(tenantId);`,
		refs: ['CWE-344', 'OWASP'],
		tags: ['hardcoded', 'tenant-isolation', 'configuration'],
	},
	{
		id: 'CWE-348',
		name: 'Use of Less Trusted Source',
		lang: 'javascript',
		status: 'Complete',
		what: `使用了較不受信的來源。系統對同一份資料／資訊存在兩個可能的來源——一個源自可直接驗證、難被偽造(連線 socket 對端位址、伺服器內建資料),
			一個源自不可驗證、可被攻擊者控制(HTTP 標頭、請求參數、客戶端送來的值)——卻選用較不可信的那個。例如用可被偽造的 X-Forwarded-For 決定
			信任與否、以客戶端給的 role 覆寫伺服器查得的 role。成因為便利性優先、拿「能取得」當「該採信」,而不知道二者信任等級不同。修法是安全攸關
			的決定永遠用「較可信、較能驗證」的來源:原始連線資訊取自身通訊,身份與權限以伺服器端會話資料為準,客戶端輸入只用於不涉權威的用途,
			並在每處使用前標注其信賴等級。`,
		problem: `// 壞寫法:以可偽造的 X-Forwarded-For 標頭決定信任,忽略連線本身的對端位址
function isTrusted(req) {
  const ip = req.headers['X-Forwarded-For'];   // 攻擊者可自設
  return trustedIpSet.has(ip);
}`,
		fixed: `// 好寫法:以連線本身的對端位址為準,不可偽造的較可信來源
function isTrusted(req) {
  const ip = req.socket.remoteAddress;   // 由實際 TCP 連線取得,無法由請求偽造
  return trustedIpSet.has(ip);
}`,
		patch: `@@
 function isTrusted(req) {
-  const ip = req.headers['X-Forwarded-For'];
+  const ip = req.socket.remoteAddress;
   return trustedIpSet.has(ip);
 }`,
		refs: ['CWE-348', 'OWASP'],
		tags: ['trust', 'x-forwarded-for', 'data-source'],
	},
	{
		id: 'CWE-350',
		name: 'Reliance on Reverse DNS Resolution for a Security-Critical Action',
		lang: 'python',
		status: 'Complete',
		what: `將安全攸關動作建立在反向 DNS 解析上。程式對 IP 做反向查詢取得 hostname,並用這個 hostname 來做安全決定(是否放行、是否視為可信網域)。
			反向 DNS 的可信度極低:它由不可控的 DNS 伺服器回傳,攻擊者對相應 PTR 記錄具有控制權時能隨意指向可信名稱,而正向查證又常被省略,
			因此「IP 真的與該 hostname 綁定」並未受到保證。成因為把「解析出來的文字」誤當成身份憑證。修法是不要用 rDNS 作為信任依據:改用經簽發
			與驗證的 TLS 憑證主題、或得過清晰驗的生命週期對映、可信配置的白名單;若一定用主機名,也要正向解析回 IP 並與原始 IP 雙向核對,再壓上
			其它可驗證因子。`,
		problem: `# 壞寫法:把反向查得的 hostname 直接決定信任,不核對 IP 真實對應
import socket
def allow(ip):
    host, _, _ = socket.gethostbyaddr(ip)       # 由外部 DNS 回傳
    return host.endswith('.trusted.example.com')   # PTR 可被偽造`,
		fixed: `# 好寫法:改用已驗證的對映(或 TLS 憑證),不信任可偽造的 rDNS
def allow(ip):
    if ip not in VERIFIED_MAPPING: return False     # 手上的固定白名單對映
    return VERIFIED_MAPPING[ip].is_trusted`,
		patch: `@@
 def allow(ip):
-    host, _, _ = socket.gethostbyaddr(ip)
-    return host.endswith('.trusted.example.com')
+    if ip not in VERIFIED_MAPPING: return False
+    return VERIFIED_MAPPING[ip].is_trusted`,
		refs: ['CWE-350', 'OWASP'],
		tags: ['reverse-dns', 'ptr', 'spoofing'],
	},
	{
		id: 'CWE-351',
		name: 'Insufficient Type Distinction',
		lang: 'javascript',
		status: 'Complete',
		what: `對不同型別區分不足。程式沒有妥善分辨本應不同的元素型別,把型別差異混為一談而引出不安全行為:把某字串「型別標記」直接拿來當實際的能力決策
			、把一種節點／物件型別當成另一種處理、或以 == 把預期型別的近義物也放行。型別之別一旦被抹平,屬於受限種類的值就會被當作特權種類對待
			,導致存取到不屬於它的能力。成因為信任型別名稱/標記字串而非做明確的型別檢查。修法是對每個值得區分的型別做顯式的驗證(instanceof、
			判別欄位、白名單映射),未通過即拒絕,確保只有正確型別的值能觸及對應行為。`,
		problem: `// 壞寫法:取 client 給的角色字串直接當權限鍵,任意字串都能撞出特權行為
function canAdmin(claim) {
  const key = claim.role;                   // 未驗證型別/來源
  return key === 'admin' || permissions.has(key);
}`,
		fixed: `// 好寫法:以明確型別檢查與已知角色白名單對照,未知一律拒絕
function canAdmin(claim) {
  if (typeof claim.role !== 'string') return false;       // 型別檢查
  const realRole = roleFromSession(claim.sessionId);       // 以伺服器端查得為準
  return realRole === 'admin';                            // 不接受 claim 自行聲稱
}`,
		patch: `@@
 function canAdmin(claim) {
-  const key = claim.role;
-  return key === 'admin' || permissions.has(key);
+  if (typeof claim.role !== 'string') return false;
+  const realRole = roleFromSession(claim.sessionId);
+  return realRole === 'admin';
 }`,
		refs: ['CWE-351', 'OWASP'],
		tags: ['type-confusion', 'distinction', 'access-control'],
	},
	{
		id: 'CWE-356',
		name: 'Product UI does not Warn User of Unsafe Actions',
		lang: 'javascript',
		status: 'Complete',
		what: `產品 UI 在進行危險動作前不警告使用者。介面代替使用者執行了某項不安全或不可回復的操作(整批刪除、覆蓋檔案、送出機密、執行高風險指令),
			但在按下按鈕當下沒有任何確認或警示。使用者可能因誤觸、按太快或被釣魚頁誘導,在不知情下就造成了損害。成因為把可回復性當成理所當然、
			或為了「流暢 UX」省略確認。修法是對「不可回復、破壞性或高權限」動作用戶介面,以不易誤觸的方式先行確認(模態確認框、要求輸入檔名或二次
			render),並把危險操作與一般按鈕從視覺與互動上區隔開來,必要時加上不可勾略過的確認步驟。`,
		problem: `// 壞寫法:單一按鈕靜默執行整批刪除,沒有確認警示
function onClickDeleteAll() {
  api.bulkDeleteAll();        // 使用者誤觸即永久刪除全部資料,無任何警告
}`,
		fixed: `// 好寫法:執行前以阻擋式確認,並要求明確鍵入才能繼續
function onClickDeleteAll() {
  const ok = showModal({ type: 'danger',
    text: '即將刪除所有資料,此動作無法復原', confirmPhrase: 'DELETE' });
  if (!ok) return;
  api.bulkDeleteAll();
}`,
		patch: `@@
 function onClickDeleteAll() {
+  const ok = showModal({ type: 'danger',
+    text: '即將刪除所有資料,此動作無法復原', confirmPhrase: 'DELETE' });
+  if (!ok) return;
   api.bulkDeleteAll();
 }`,
		refs: ['CWE-356', 'OWASP'],
		tags: ['ui', 'user-warning', 'misleading-ux'],
	},
	{
		id: 'CWE-357',
		name: 'Insufficient UI Warning of Dangerous Operations',
		lang: 'javascript',
		status: 'Complete',
		what: `對危險動作的 UI 警示不足。介面「有」警告,但這警告不夠醒目到足以引起使用者的注意:藏在角落的小字、瞬間自動消失的 toast、用與內容同色的低反差
			文字、或被放在「確定」按鈕旁被順手按掉。使用者在注意力放別處時便可能無視這個警示而繼續危險動作,防護形同虛設、反而給人「有提醒過」的假象。
			成因為以「存在性」代替「有效性」,沒有把警告當成安全控制來設計。修法是要讓警示真正攔得住使用者:用模態且要求明確動作才能繼續、高對比度＋阻擋
			式互動、避免自動消失或可被秒關,並給出不可回復操作的強後果說明與延遲,使意外的「是」不能一刻間就發生。`,
		problem: `// 壞寫法:警告以小字/自動消失的方式呈現,幾乎不會被注意到
function launchDanger() {
  showToast('注意:此操作可能造成資料遺失');   // 2 秒自動消失,不阻撓
  api.danger();
}`,
		fixed: `// 好寫法:以高強調的阻擋式模態確認,未明確確認不下去
function launchDanger() {
  const ok = showBlockingDialog({
    title: '資料遺失風險',
    primaryLabel: '繼續',
    detail: '此操作無法復原',
  });
  if (!ok) return;          // 不自動消失,不容忽略
  api.danger();
}`,
		patch: `@@
 function launchDanger() {
-  showToast('注意:此操作可能造成資料遺失');
+  const ok = showBlockingDialog({ title: '資料遺失風險', primaryLabel: '繼續',
+    detail: '此操作無法復原' });
+  if (!ok) return;
   api.danger();
 }`,
		refs: ['CWE-357', 'OWASP'],
		tags: ['ui', 'warning', 'confirmation'],
	},
	{
		id: 'CWE-360',
		name: 'Trust of System Event Data',
		lang: 'cpp',
		status: 'Complete',
		what: `信任系統事件資料。把安全決定建立在「事件發生位置／來源裝置」之上,而這些事件位置是可被偽造的:例如透過 /dev/input 的輸入事件(觸控、鍵盤、
			滑鼠)及其裝置節點來判斷是不是真人操作或可信來源。事件節點與輸入資料都能被使用者空間程式偽造或注入,監控事件來源的「設備節點不存在性檢查」
			也不足以代表對端使用者真實;依照事件位置所做的敏感控管因此可被繞過。成因為把「來自某某事件源」錯誤當成「來自某某可信人」。修法是任何安全
			攸關的授權都要綁定能驗證的受信實體(登入會話、已驗證的身份、簽署的動作),事件資料只能用於 UX 等非關鍵用途,絕不作為存取控制的唯一依據。`,
		problem: `// 壞寫法:以輸入事件的來源裝置作身份證明,可被注入裝置偽造
if (readEvent() && device_is_touch) {
    grant_privileged_action();   // 事件來源本身可偽造,不足以授權`,
		fixed: `// 好寫法:以已驗證的使用者身份做授權,事件僅供介面參考
if (current_user && session_authenticated(current_user)) {
    grant_action(current_user);   // 綁定可驗證的身份,而非事件來源`,
		patch: `@@
-if (readEvent() && device_is_touch) {
-    grant_privileged_action();
+if (current_user && session_authenticated(current_user)) {
+    grant_action(current_user);`,
		refs: ['CWE-360', 'OWASP'],
		tags: ['input-event', 'spoofing', 'device-trust'],
	},
	{
		id: 'CWE-363',
		name: 'Race Condition Enabling Link Following',
		lang: 'cpp',
		status: 'Complete',
		what: `符號連結追隨的競態(TOCTOU)。程式在「先檢查檔案狀態(lstat／access)」與「後存取該檔案(open／write)」之間假定對象不變;攻擊者在這空窗內
			把該路徑換成符號連結,指向我不應觸及的檔案,於是檢查的對象與實際存取的對象不同,造成對敏感檔的覆寫或讀寫。這是典型的 Time-Of-Check-Time-Of-Use
			競態。成因為把檢查與使用拆成兩個非原子的步驟又重複引用同一路徑字串。修法是採用原子操作讓「檢查＋開啟」一次完成:以 open(O_NOFOLLOW｜O_CLOEXEC)、
			openat 搭配 dirfd、fstat 於開啟後核對與 lstat 一致再動手,使連結替換的空窗無縫可入。`,
		problem: `// 壞寫法:先檢查為普通檔再開啟;中間注入能被換成 symlink 指向他人檔案
if (lstat(path, &st) == 0 && !S_ISLNK(st.st_mode)) {
    int fd = open(path, O_WRONLY);   // 空窗內 path 已被換成 symlink
    write(fd, payload, n);
}`,
		fixed: `// 好寫法:用 O_NOFOLLOW 原子開啟,不信任檢查後的同一路徑
int fd = open(path, O_WRONLY | O_NOFOLLOW);   // 拒絕符號連結,單一原子步驟
if (fd >= 0) { write(fd, payload, n); }`,
		patch: `@@
-if (lstat(path, &st) == 0 && !S_ISLNK(st.st_mode)) {
-    int fd = open(path, O_WRONLY);
+int fd = open(path, O_WRONLY | O_NOFOLLOW);
+if (fd >= 0) {
     write(fd, payload, n);
 }`,
		refs: ['CWE-363', 'OWASP'],
		tags: ['race', 'toctou', 'symlink'],
	},
	{
		id: 'CWE-365',
		name: 'DEPRECATED: Race Condition in Switch',
		lang: 'cpp',
		status: 'Deprecated',
		what: `(已停用)Switch 中的競態。這筆條目已被 MITRE 標記為 Deprecated:文獻與實務中「switch 的控制運算式會被重複求值」這種情況不成立——switch 的
			control expression 實際上只會計算一次,因此不存在所設想的對時競爭;其概念與更通則的競態(CWE-362、CWE-361)重疊,不構成獨立弱點。此處僅為
			完整保留歷史記錄與命名,不應再以本 ID 映射新漏洞;處理真實的檢查–使用或雙重求值型問題時,請直接對應 CWE-362( Race Condition)等既有類別。`,
		problem: `// 歷史疑慮:誤以為 switch 控制運算式會被重複求值而有競態(實為 False)
switch (shared_value) {        // control expression 僅求值一次
  case 1: workA(); break;
  case 2: workB(); break;
}`,
		fixed: `// 正確認識:control expression 只評估一次,不需也不存在針對 switch 的競態修法
int v = snapshot(shared_value);   // 需要快照時先取一次再判斷
switch (v) { case 1: workA(); break; default: workB(); }`,
		patch: `@@
-   switch (shared_value) {
+   int v = snapshot(shared_value);   // 明確取一次快照
+   switch (v) {`,
		refs: ['CWE-365'],
		tags: ['deprecated', 'switch', 'race'],
	},
	{
		id: 'CWE-370',
		name: 'Missing Check for Certificate Revocation after Initial Check',
		lang: 'java',
		status: 'Complete',
		what: `只在初次檢查後就不再檢查憑證撤銷狀態。程式剛連線時做了一次撤銷(CRL／OCSP)檢查,之後在同一個保留的憑證或長連線上便一直使用、再也不會回頭
			驗證撤銷狀態。憑證可能在初次檢查後才被撤銷(遺失金鑰、身分變更、憑證機構犯錯),但程式仍把它當有效憑證,甚至用它執行特權動作、簽章驗證或
			保密連線。成因為把「一次的、某個時點」的結果當成「永久有效」。修法是對每個可被使用者控制／影響存續長時間的憑證,在使用與授權前重新執行撤銷檢查
			(OCSP stapling／CRL 快取定期刷新),對撤銷的憑證立即失效並重新驗證,尤其在高風險操作前務必按「當下」狀態確認。`,
		problem: `// 壞寫法:只在建立連線初檢查一次撤銷,之後沿用並信任同一憑證
X509Certificate cert = firstHandshake().getPeerCertificate();
boolean revokedOnce = checkRevocation(cert);     // 只檢查一次
TLSSocket s = openTLS(cert);
if (revokedOnce) { s.trust(); }               // 之後永不重查,撤銷晚於初查也照用`,
		fixed: `// 好寫法:每次使用/授權前重新確認撤銷狀態,撤銷立即停用
for (Request req : requests) {
    if (isRevokedNow(cert)) {                 // 每次動作用前重查
        renegotiateOrReject(req); continue;
    }
    grantUsing(certInput(cert), req);
}`,
		patch: `@@
-  boolean revokedOnce = checkRevocation(cert);
-  TLSSocket s = openTLS(cert);
-  if (revokedOnce) { s.trust(); }
+  for (Request req : requests) {
+      if (isRevokedNow(cert)) { renegotiateOrReject(req); continue; }
+      grantUsing(certInput(cert), req);
+  }`,
		refs: ['CWE-370', 'OWASP'],
		tags: ['certificate', 'revocation', 'crl', 'ocsp'],
	},
	{
		id: 'CWE-372',
		name: 'Incomplete Internal State Distinction',
		lang: 'java',
		status: 'Complete',
		what: `對內部狀態區分不完整。程式未能正確辨識自己當下到底位在哪一個狀態:狀態機只覆蓋了部分狀態、把幾個互斥的狀態併成一個、或在轉移處理中漏掉了某支
			,於是它誤以為自己在狀態 X 而實際處於狀態 Y,對應的動作便以錯誤的前提被執行。在安全攸關處(驗證、初始化、交易、權限切換)這會拿錯的狀態當基礎
			做決定。成因為用布林/旗標拼狀態機、漏 case、或假定某些轉移不會發生。修法是以窮盡的列舉型別管理狀態,每個轉移都被明確處理、default 分支把
			不可達到或未知狀態導向安全拒絕,並在關鍵動作前對「實際狀態」做顯式斷言而非依賴隱含假設。`,
		problem: `// 壞寫法:以雜亂旗標假設狀態,漏掉某個互斥組合而不自知
boolean authed = false, initialized = false;
public void run() {
    if (authed) doSensitive();      // initialized 為假時也照做,誤判自己已就緒
}`,
		fixed: `// 好寫法:以窮盡 enum 狀態管理,只允許明確且正確的狀態執行敏感動作
enum State { INIT, AUTHED, ERROR }
State st = State.INIT;
public void run() {
    switch (st) {
      case AUTHED:  doSensitive(); break;      // 只在此態動作正確
      case INIT:
      case ERROR:    throw new IllegalStateException("wrong state");
    }
}`,
		patch: `@@
-   boolean authed = false, initialized = false;
-   public void run() {
-       if (authed) doSensitive();
-   }
+   enum State { INIT, AUTHED, ERROR }
+   State st = State.INIT;
+   public void run() {
+       switch (st) {
+         case AUTHED:  doSensitive(); break;
+         case INIT:
+         case ERROR:    throw new IllegalStateException("wrong state");
+       }
+   }`,
		refs: ['CWE-372', 'OWASP'],
		tags: ['state-machine', 'state', 'logic-error'],
	},
	{
		id: 'CWE-373',
		name: 'DEPRECATED: State Synchronization Error',
		lang: 'java',
		status: 'Deprecated',
		what: `(已停用)狀態同步錯誤。這筆條目已被 MITRE 標記為 Deprecated,因為它與更具體的競態(CWE-362, Race Condition)與不當同步(CWE-662)概念重疊,不再
			構成一筆獨立、可明確映射的弱點。它原先描述的「狀態在不同執行緒／組件間不同步」類問題,實質成因是缺乏同步或存在檢查–使用競爭。此處保留僅為
			完整沿用官方索引與歷史脈絡;辨識實際缺陷時請改對應 CWE-662(Improper Synchronization)或 CWE-362(Race Condition),並以正確的鎖定、原子變數與
			不可交錯的臨界區段解決,而不該再把本 ID 投入新弱點映射。`,
		problem: `// 歷史示範:跨執行緒共用計數器未同步,讀與寫交錯造成狀態不一致
int prepared = 0;
volatile boolean ready = false;              // 讀寫未同步,狀態可能不一致`,
		fixed: `// 正確做法:以不可交錯的同步(如 atomic/lock)保護狀態,保持一致性
AtomicInteger prepared = new AtomicInteger();
public void safeInc() { prepared.incrementAndGet(); }   // 具原子意義,無 race`,
		patch: `@@
-  int prepared = 0;
-  volatile boolean ready = false;
+  AtomicInteger prepared = new AtomicInteger();
+  public void safeInc() { prepared.incrementAndGet(); }`,
		refs: ['CWE-373'],
		tags: ['deprecated', 'synchronization', 'race'],
	},
	{
		id: 'CWE-375',
		name: 'Returning a Mutable Object to an Untrusted Caller',
		lang: 'java',
		status: 'Complete',
		what: `把可變物件直接回傳給不受信任的呼叫者。敏感物件(權限清單、Group 列表、金鑰清單)在被 getter 回傳時沒有先做防禦性複製,而把內部真正的
			mutable 引用交了出去;呼叫端(甚至跨信任邊界的程式入)拿到的是同一個實體,可直接改寫或刪除其內容,因而破壞了本該由擁有者維持的不變量——權限、
			組態、快取一夕間可被竄改。成因為奠基「呼叫者只讀不動」的可信假設。修法是回傳前做一份副本(Collections.unmodifiableList／List.copyOf／clone),
			對內部清單與陣列逐層複製,並提供唯讀視圖;需要變更時由內部管理方法進行而非放任外部取得。`,
		problem: `// 壞寫法:把可變清單的本體直接回傳,呼叫方能竄改權限
public List<String> getGrantedRoles() {
    return this.grantedRoles;         // 呼叫端可直接在回傳值上 remove/add
}`,
		fixed: `// 好寫法:回傳不可變副本,保有內部不變量與安全
public List<String> getGrantedRoles() {
    return List.copyOf(this.grantedRoles);   // 唯讀副本,外部改不動內部
}`,
		patch: `@@
 public List<String> getGrantedRoles() {
-    return this.grantedRoles;
+    return List.copyOf(this.grantedRoles);
 }`,
		refs: ['CWE-375', 'OWASP'],
		tags: ['mutable', 'defensive-copy', 'exposure'],
	},
	{
		id: 'CWE-379',
		name: 'Creation of Temporary File in Directory with Insecure Permissions',
		lang: 'cpp',
		status: 'Complete',
		what: `在權限不安全的目錄中建立暫存檔。程式把暫存檔建立在世界可讀寫的目錄(如 /tmp、不相干的共享目錄)且未以專屬、最小權限建立;其他使用者能藉由
			猜測檔名、先佔用同名檔或檢視存在與否,讀出、竄改或刪除這些暫存檔。成因為「暫存不長命」的輕率假設、用固定或可預測的暫存檔名與預設 0666
			權限。後果是機密外洩、權限提升與任意檔覆寫。修法是使用 mkstemp/mkostemp 產生不可猜測的唯一檔名並 fchmod 為 0600、將權限鎖成僅屬自己一個
			owned 目錄、用完即關即刪,並避免把信任放在 /tmp 這類世界可寫空間。`,
		problem: `// 壞寫法:在共享目錄以可預測檔名、寬鬆權限建立暫存檔
int fd = open("/tmp/app.tmp", O_CREAT|O_TRUNC|O_WRONLY, 0666);   // 可預測且可讀寫
fprintf(fd, "%s", secret);`,   // 其它使用者可讀走或覆寫`,
		fixed: `// 好寫法:以 mkstemp 產生唯一檔名並立刻 chmod 0600,用完即刪
int fd = mkstemp("/tmp/app-XXXXXX");
fchmod(fd, 0600);                       // 最小權限,僅屬建立者
write(fd, secret, len);
unlink("/tmp/app-XXXXXX");               // 用完即清`,
		patch: `@@
-  int fd = open("/tmp/app.tmp", O_CREAT|O_TRUNC|O_WRONLY, 0666);
-  fprintf(fd, "%s", secret);
+  int fd = mkstemp("/tmp/app-XXXXXX");
+  fchmod(fd, 0600);
+  write(fd, secret, len);
+  unlink("/tmp/app-XXXXXX");`,
		refs: ['CWE-379', 'OWASP'],
		tags: ['temp-file', 'permissions', 'symlink'],
	},
	{
		id: 'CWE-382',
		name: 'J2EE Bad Practices: Use of System.exit()',
		lang: 'java',
		status: 'Complete',
		what: `J2EE 反模式:System.exit() 的使用。J2EE 應用在執行於容器(Application Server)內,呼叫 System.exit() 不只結束應用本身,還會把整個容器／JVM 一起關閉,
			使同機的所有應用與連線同時崩潰,形成每個請求級使用者都能觸發的拒絕服務。成因為把「桌面程式中止」的習慣誤用在受管的伺服器環境,又未受管理者許可。
			後果是整個容器停擺、未處理的工作流失、可用性被單一請求抹平。修法是從不自訂程式碼呼叫 System.exit():遇到致命錯誤記錄錯誤並交給容器的例外機制、
			ServletContextListener 或應用框架自行清理與重啟單一應用;確實需要結束時,由管理面以容器的受管停止程序辦理。`,
		problem: `// 壞寫法:伺服器程式內直接 System.exit(),結束整個容器
public void doGet(HttpServletRequest req, HttpServletResponse resp) {
    if (fatal()) { System.exit(1); }    // 連同必伴的全容器一起關掉
}`,
		fixed: `// 好寫法:交由容器與錯誤處理機制接管,不自行終止 JVM
public void doGet(HttpServletRequest req, HttpServletResponse resp) {
    if (fatal()) throw new FatalAppException("fatal");   // 交容器清理單一應用
}`,
		patch: `@@
     if (fatal()) {
-        System.exit(1);
+        throw new FatalAppException("fatal");
     }
 }`,
		refs: ['CWE-382', 'OWASP'],
		tags: ['j2ee', 'system-exit', 'availability'],
	},
	{
		id: 'CWE-383',
		name: 'J2EE Bad Practices: Direct Use of Threads',
		lang: 'java',
		status: 'Complete',
		what: `J2EE 反模式:直接使用執行緒。Web 應用直接對需求 new Thread()／建構 Runnable 來自己管理執行緒,而非交給容器管理的執行緒池與工作執行管理器。在某些規格
			環境下此法甚至被禁止,又始終極度容易出錯:並未受容器的執行緒池管理、沒有統一的生命週期、資源與攔截器,執行緒就算用完也常不被回收,甚至在不同請求
			間洩漏安全上下文,處理請求的執行緒數一多就資源耗盡並失去監管。成因為「需要就 new 一支」的桌面思維。修法是改用受管執行緒池／Executor、
			J2EE 應用的非同步執行(Servlet 3.1 Async、EJB @Asynchronous、JMS),讓容器控制並發量與執行緒生命,並把需要的執行緒安全上下文於提交時顯式攜帶。`,
		problem: `// 壞寫法:Servlet 直接 new Thread,自行管理執行緒,偏離容器控制
class Job extends Thread { public void run() { heavyWork(); } }
new Job().start();                  // 不受容器管理,可能洩漏執行緒與安全上下文`,
		fixed: `// 好寫法:提交到容器的受管執行緒池執行,執行緒生命與並發受控
ExecutorService pool = (ExecutorService) envLoopup("java:comp/env/executor");
pool.submit(() -> heavyWork());     // 全程由容器管理執行緒資源`,
		patch: `@@
-class Job extends Thread { public void run() { heavyWork(); } }
-new Job().start();
+ExecutorService pool = (ExecutorService) envLoopup("java:comp/env/executor");
+pool.submit(() -> heavyWork());`,
		refs: ['CWE-383', 'OWASP'],
		tags: ['j2ee', 'threads', 'executor'],
	},
];
