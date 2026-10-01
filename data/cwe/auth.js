// CWE chunk — category: Authentication & Authorization.
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
		id: 'CWE-287',
		name: 'Improper Authentication',
		lang: 'python',
		status: 'Complete',
		what: `身分驗證不當。驗證「來的是誰」的機制有漏洞，攻擊者可繞過登入流程或冒充他人身分。
最典型的是伺服器把驗證結果放在使用者可控的地方（例如表單欄位、明文 Cookie），
然後逕自信任它當作「已登入／是管理員」的依據，實際上並未驗證密碼，也未妥善管理伺服器端工作階段。`,
		problem: `# 不安全寫法：逕自信任表單欄位 is_admin，使用者只要送出 1，就可能取得管理員權限
from flask import Flask, request

app = Flask(__name__)

@app.post('/login')
def login():
    user = request.form.get('user')
    # 沒有查資料庫、沒有比對密碼，只把前端送來的旗標作為判斷依據
    is_admin = request.form.get('is_admin') == '1'
    resp = make_response({'ok': True})
    resp.set_cookie('admin', str(is_admin).lower())  # Cookie 明文、且由使用者控制
    return resp`,
		fixed: `# 安全寫法：密碼先做安全比對，會話標記只存在伺服器端 Flask session
from flask import Flask, request, session, make_response
import secrets, hmac, hashlib

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)   # 由部署環境注入，不寫死

@app.post('/login')
def login():
    user = request.form.get('user')
    pwd  = request.form.get('password')
    rec = db.get_user(user)               # 從資料庫取回使用者記錄
    if rec is None or not hmac.compare_digest(
            hashlib.sha256(rec['salt'] + pwd.encode()).hexdigest(),
            rec['hash']):
        return make_response('bad creds', 401)
    session.clear()
    session['uid'], session['admin'] = rec['id'], rec['is_admin']  # 伺服器端保存
    return make_response({'ok': True})`,
		patch: `@@
-    user = request.form.get('user')
-    # 沒有查資料庫、沒有比對密碼，只把前端送來的旗標作為判斷依據
-    is_admin = request.form.get('is_admin') == '1'
-    resp = make_response({'ok': True})
-    resp.set_cookie('admin', str(is_admin).lower())
-    return resp
+    user = request.form.get('user')
+    pwd  = request.form.get('password')
+    rec = db.get_user(user)
+    if rec is None or not hmac.compare_digest(
+            hashlib.sha256(rec['salt'] + pwd.encode()).hexdigest(),
+            rec['hash']):
+        return make_response('bad creds', 401)
+    session.clear()
+    session['uid'], session['admin'] = rec['id'], rec['is_admin']
+    return make_response({'ok': True})`,
		refs: ['OWASP-Auth', 'CWE-287'],
		tags: ['authentication', 'auth-bypass', 'session'],
	},
	{
		id: 'CWE-306',
		name: 'Missing Authentication for Critical Function',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `關鍵功能缺少身分驗證。像是刪除帳號、刷新憑證、管理後台這類高敏感操作，
對外開了路由卻沒套任何驗證中介層（middleware），匿名或未登入者可以直接呼叫。
建議做法是在這些「臨界功能」前面一律掛上 requireAuth 中介層，先驗證再處理。`,
		problem: `// 不安全寫法：管理類操作路由沒有掛驗證中介層，任何人 POST 就能刪帳號
const express = require('express');
const app = express();

app.delete('/api/account/:id', (req, res) => {   // 沒有 requireAuth！
  db.accounts.deleteOne({ _id: req.params.id }, (err) => {
    res.sendStatus(200);
  });
});`,
		fixed: `// 安全寫法：先掛身分驗證中介層，未登入直接 401，驗過才進到處理函式
const express = require('express');
const app = express();

function requireAuth(req, res, next) {
  if (!req.session || !req.session.uid) return res.sendStatus(401);
  next();
}
// 驗證掛在路由之前，任何未登入者都進不來
app.delete('/api/account/:id', requireAuth, (req, res) => {
  if (String(req.params.id) !== String(req.session.uid)) return res.sendStatus(403);
  db.accounts.deleteOne({ _id: req.params.id }, () => res.sendStatus(200));
});`,
		patch: `@@
-  app.delete('/api/account/:id', (req, res) => {
+  function requireAuth(req, res, next) {
+    if (!req.session || !req.session.uid) return res.sendStatus(401);
+    next();
+  }
+  app.delete('/api/account/:id', requireAuth, (req, res) => {
+    if (String(req.params.id) !== String(req.session.uid)) return res.sendStatus(403);
     db.accounts.deleteOne({ _id: req.params.id }, (err) => {
       res.sendStatus(200);
     });`,
		refs: ['OWASP-CriticalFunction', 'CWE-306'],
		tags: ['authentication', 'missing-auth', 'critical-function'],
	},
	{
		id: 'CWE-307',
		name: 'Improper Restriction of Excessive Authentication Attempts',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `未限制過多的驗證嘗試次數。登入介面沒有針對每個 IP／帳號做嘗試計數與鎖定，
攻擊者就能無限暴力猜密碼（brute force）。建議做法是統計失敗次數、做速率限制（rate limit），
超過上限就鎖定一段時間或加入漸進式延遲。`,
		problem: `// 不安全寫法：登入迴圈無限重試，每次只比對密碼對不對，不計次數、不延遲
const login = (user, pwd) => db.getUser(user).then(r => {
  if (!r || r.pwd != pwd) {                    // 密碼比對，還用明文
    return { error: 'bad creds' };             // 同 IP 可以無限試
  }
  return { uid: r.id };
});`,
		fixed: `// 安全寫法：失敗計數、限制速率、超過上限即鎖定一段時間
const attempt = {};                            // in-memory 計數，正式用 Redis

const login = async (user, pwd) => {
  const key = user + '@' + req.ip;
  const n = (attempt[key] = (attempt[key] || 0) + 1);
  if (n > 5) {                                // 超過 5 次就鎖 15 分鐘
    attempt[key] = -1;
    setTimeout(() => delete attempt[key], 15 * 60 * 1000);
    return { error: 'too many attempts' };
  }
  if (await bcrypt.compare(pwd, (await db.getUser(user))?.hash)) {
    delete attempt[key];
    return { uid: (await db.getUser(user)).id };
  }
  return { error: 'bad creds' };               // 鎖定前憑證錯誤的泛化回應
};`,
		patch: `@@
-const login = (user, pwd) => db.getUser(user).then(r => {
-  if (!r || r.pwd != pwd) {
-    return { error: 'bad creds' };
-  }
-  return { uid: r.id };
-});
+const attempt = {};
+const login = async (user, pwd) => {
+  const key = user + '@' + req.ip;
+  const n = (attempt[key] = (attempt[key] || 0) + 1);
+  if (n > 5) {
+    attempt[key] = -1;
+    setTimeout(() => delete attempt[key], 15 * 60 * 1000);
+    return { error: 'too many attempts' };
+  }
+  if (await bcrypt.compare(pwd, (await db.getUser(user))?.hash)) {
+    delete attempt[key];
+    return { uid: (await db.getUser(user)).id };
+  }
+  return { error: 'bad creds' };
+};`,
		refs: ['OWASP-Brute-force', 'CWE-307'],
		tags: ['brute-force', 'rate-limit', 'authentication'],
	},
	{
		id: 'CWE-521',
		name: 'Weak Password Requirements',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `密碼需求過弱。註冊或改密碼時只要「非空字串」就收，沒有最小長度、複雜度或禁用常見弱密碼清單，
使用者很容易設成 123 / password 這種極易破解的密碼。建議做法是明訂強度規則（長度下限、字元種類），
並搭配 zxcvbn-ts 這類「弱密碼預測」來拒絕常見密碼。`,
		problem: `// 不安全寫法：密碼只要 exists 就收，強度完全沒把關
async function register(req, res) {
  const { user, password } = req.body;
  if (!password) return res.status(400).json({ error: 'password required' });
  // 沒查長度、沒查複雜度，"1" 也會過
  const hash = await bcrypt.hash(password, 10);
  await db.users.insertOne({ user, hash });
  res.status(201).json({ ok: true });
}`,
		fixed: `// 安全寫法：長度 + 字元種類下限，加上字典檢查拒絕常見弱密碼
import { zxcvbn } from 'zxcvbn-ts';

async function register(req, res) {
  const { user, password } = req.body;
  const lenOk = password.length >= 12;
  const clsOk = /[a-z]/.test(password) && /[A-Z]/.test(password)
              && /\\d/.test(password) && /[^A-Za-z0-9]/.test(password);
  const weak = zxcvbn(password).score < 3;            // 字典/常用弱密碼直接擋
  if (!lenOk || !clsOk || weak) {
    return res.status(400).json({ error: 'password too weak' });
  }
  const hash = await bcrypt.hash(password, 12);
  await db.users.insertOne({ user, hash });
  res.status(201).json({ ok: true });
}`,
		patch: `@@
-  if (!password) return res.status(400).json({ error: 'password required' });
-  // 沒查長度、沒查複雜度，"1" 也會過
-  const hash = await bcrypt.hash(password, 10);
+  const lenOk = password.length >= 12;
+  const clsOk = /[a-z]/.test(password) && /[A-Z]/.test(password)
+              && /\\d/.test(password) && /[^A-Za-z0-9]/.test(password);
+  const weak = zxcvbn(password).score < 3;
+  if (!lenOk || !clsOk || weak) {
+    return res.status(400).json({ error: 'password too weak' });
+  }
+  const hash = await bcrypt.hash(password, 12);
   await db.users.insertOne({ user, hash });`,
		refs: ['OWASP-Password', 'CWE-521'],
		tags: ['password', 'weak', 'policy'],
	},
	{
		id: 'CWE-640',
		name: 'Weak Password Recovery Mechanism for Forgotten Password',
		lang: 'php',
		status: 'Complete',
		what: `密碼遺忘的重設機制太弱。例如用可被猜測的亂數（mt_rand）當重設 token、
把新密碼直接寄回信箱、或 token 沒有發行時間與一次性失效。攻擊者可重設別人的帳號。
建議做法是產生夠強的 crypto 隨機 token、到期即失效、只存雜湊、且整個流程可以提早失效。`,
		problem: `<?php // 不安全寫法：mt_rand() 產生可預測的 token，而且直接寄「明文」重設碼
$token = mt_rand(100000, 999999);            // 僅 90 萬種可能值，可被暴力窮舉掃過
$link  = "https://example.com/reset?uid={$uid}&token={$token}";
mail($email, 'Reset', "Click: $link");       // 重設機制的關鍵以明文經 email 傳送
$db->query("UPDATE users SET reset_token='$token' WHERE id=$uid");`,
		fixed: `<?php // 安全寫法：random_bytes 產生強隨機 token、以雜湊存庫、帶有效期限且一次性
$token = bin2hex(random_bytes(32));                     // 256-bit，掃不到
$hash  = password_hash($token, PASSWORD_BCRYPT);       // 庫裡只存雜湊
$exp   = time() + 15 * 60;                            // 15 分鐘內有效
$db->prepare('UPDATE users SET reset_hash=?, reset_exp=? WHERE id=?')
   ->execute([$hash, $exp, $uid]);
mail($email, 'Reset', "https://example.com/reset?token=$token"); // 給的是臨時 token`,
		patch: `@@
-      $token = mt_rand(100000, 999999);
-      $link  = "https://example.com/reset?uid={$uid}&token={$token}";
-      mail($email, 'Reset', "Click: $link");       # 以明文經 email 轉送
-      $db->query("UPDATE users SET reset_token='$token' WHERE id=$uid");
+      $token = bin2hex(random_bytes(32));
+      $hash  = password_hash($token, PASSWORD_BCRYPT);
+      $exp   = time() + 15 * 60;
+      $db->prepare('UPDATE users SET reset_hash=?, reset_exp=? WHERE id=?')
+         ->execute([$hash, $exp, $uid]);
+      mail($email, 'Reset', "https://example.com/reset?token=$token");`,
		refs: ['OWASP-ForgotPassword', 'CWE-640'],
		tags: ['password-recovery', 'token', 'forgot-password'],
	},
	{
		id: 'CWE-798',
		name: 'Use of Hard-coded Credentials',
		lang: 'python',
		status: 'Complete',
		what: `使用硬編碼憑證。把資料庫密碼、API Key、連線字串直接寫死在程式碼裡，
進到版本庫就等於外流，也無法輪換（每次都得改程式碼並重新部署）。建議做法是憑證從環境變數、
config server 或 secret manager 注入，程式碼裡完全不出現秘密。`,
		problem: `# 不安全寫法：密碼寫死在原始碼，一推上 repo 秘密就外洩
DB_URL = "postgres://app:SuperS3cret@db.internal:5432/app"

def connect():
    return psycopg2.connect(DB_URL)          # 密碼烙在 code 與 git 歷史裡`,
		fixed: `# 安全寫法：從環境變數 / secret manager 讀，code 裡零秘密
import os
DB_URL = os.getenv("DB_URL")                 # 由部署工具注入，可輪換
if not DB_URL:
    raise RuntimeError("DB_URL not configured")

def connect():
    return psycopg2.connect(DB_URL)`,
		patch: `@@
-      DB_URL = "postgres://app:SuperS3cret@db.internal:5432/app"
-      def connect():
-          return psycopg2.connect(DB_URL)          # 密碼烙在 code 與 git 歷史裡
+      DB_URL = os.getenv("DB_URL")                 # 由部署工具注入，可輪換
+      if not DB_URL:
+          raise RuntimeError("DB_URL not configured")
+      def connect():
+          return psycopg2.connect(DB_URL)`,
		refs: ['OWASP-Secrets', 'CWE-798'],
		tags: ['hardcoded', 'credentials', 'secrets'],
	},
	{
		id: 'CWE-862',
		name: 'Missing Authorization',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `缺少授權檢查。只驗證「有登入」（authenticated），卻沒檢查「這個人有沒有權限做這件事」。
於是一般使用者只要直接呼叫路由，就能打管理功能或存取別人的資源。
修法是在每個敏感路由都掛上以「角色／擁有權」為依據的授權中介層（authorization/middleware）。`,
		problem: `// 不安全寫法：只確認 req.session.uid 存在（有登入）就放行，沒檢查是不是管理員
app.get('/api/admin/export', (req, res) => {
  if (!req.session.uid) return res.sendStatus(401);   // 已登入就放行 ???
  db.exportAll(req.session.uid, (err, blob) => res.send(blob));  // 任何登入者都能拿資料
});`,
		fixed: `// 安全寫法：掛 requireAdmin 授權中介層，用伺服器端角色資料決定准不准
function requireAdmin(req, res, next) {
  if (!req.session.uid) return res.sendStatus(401);
  db.users.findById(req.session.uid, (e, rec) => {
    if (e || !rec || rec.role !== 'admin') return res.sendStatus(403);  // 403 拒絕
    next();
  });
}
app.get('/api/admin/export', requireAdmin, (req, res) => {
  db.exportAll(null, (err, blob) => {
    if (err) return res.sendStatus(500);
    res.send(blob);
  });
});`,
		patch: `@@
-  app.get('/api/admin/export', (req, res) => {
-    if (!req.session.uid) return res.sendStatus(401);   # 已登入就放行 ????
-    db.exportAll(req.session.uid, (err, blob) => res.send(blob));
-  });
+  function requireAdmin(req, res, next) {
+    if (!req.session.uid) return res.sendStatus(401);
+    db.users.findById(req.session.uid, (e, rec) => {
+      if (e || !rec || rec.role !== 'admin') return res.sendStatus(403);
+      next();
+    });
+  }
+  app.get('/api/admin/export', requireAdmin, (req, res) => {
+    db.exportAll(null, (err, blob) => {
+      if (err) return res.sendStatus(500);
+      res.send(blob);
+    });
+  });`,
		refs: ['OWASP-Auth', 'CWE-862'],
		tags: ['authorization', 'broken-access-control', 'role'],
	},
	{
		id: 'CWE-863',
		name: 'Incorrect Authorization',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `授權檢查做錯。授權決策使用了錯誤的依據，例如拿 request body／query 送來的 role 或 url 字串當真、
檢查順序寫反、或比對使用者 id 時取錯來源，讓本該沒權限的人被放行。
建議做法是授權一律以伺服器端資料（session + DB 記錄）為唯一依據，並確認檢查順序。`,
		problem: `// 不安全寫法：決策拿使用者可控的 body 當依據，自己送 role:"admin" 就被當管理員
app.delete('/api/order/:id', (req, res) => {
  const granted = req.body.role === 'admin';            // role 是使用者自己填的！
  if (!granted) return res.sendStatus(403);
  db.orders.deleteOne({ _id: req.params.id }, () => res.sendStatus(200));
});`,
		fixed: `// 安全寫法：只信任伺服器端 session + DB 的角色與資源擁有權
async function canModifyOrder(uid, orderId) {
  const [u, o] = await Promise.all([db.users.findById(uid), db.orders.findById(orderId)]);
  if (!u || !o) return '404';
  if (u.role === 'admin') return 'ok';                 // 以 DB 角色+擁有權判定
  return String(u._id) === String(o.owner) ? 'ok' : '403';
}
app.delete('/api/order/:id', async (req, res) => {
  const verdict = await canModifyOrder(req.session.uid, req.params.id);   // 非 req.body
  if (verdict !== 'ok') return res.sendStatus(Number(verdict));
  await db.orders.deleteOne({ _id: req.params.id });
  res.sendStatus(200);
});`,
		patch: `@@
-  app.delete('/api/order/:id', (req, res) => {
-    const granted = req.body.role === 'admin';            # role 是使用者自己填的！
-    if (!granted) return res.sendStatus(403);
-    db.orders.deleteOne({ _id: req.params.id }, () => res.sendStatus(200));
-  });
+  async function canModifyOrder(uid, orderId) {
+    const [u, o] = await Promise.all([db.users.findById(uid), db.orders.findById(orderId)]);
+    if (!u || !o) return '404';
+    if (u.role === 'admin') return 'ok';
+    return String(u._id) === String(o.owner) ? 'ok' : '403';
+  }
+  app.delete('/api/order/:id', async (req, res) => {
+    const verdict = await canModifyOrder(req.session.uid, req.params.id);
+    if (verdict !== 'ok') return res.sendStatus(Number(verdict));
+    await db.orders.deleteOne({ _id: req.params.id });
+    res.sendStatus(200);
+  });`,
		refs: ['OWASP-AccessControl', 'CWE-863'],
		tags: ['authorization', 'broken-access-control', 'ownership'],
	},
];
