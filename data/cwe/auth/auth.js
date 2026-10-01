// CWE chunk — category: Authentication & Authorization.
//   what    : 簡短、繁中、白話+技術描述（(#) 弱點是什麼)
//   problem : 「壞的寫法」程式片段（(#) 問題長怎樣）
//   fixed   : 「修好的寫法」程式片段（(#) 解完會長怎樣）
//   patch   : problem → fixed 的統一 diff 文字（(#) 範例 patch)
//   lang    : 此條範例主力語言，依 CWE 類別選擇
//   status  : Complete | Incomplete | Deprecated
//   refs    : 參考（OWASP / MITRE 等）
//   tags    : 英文搜尋標籤
export default [
	{
		id: 'CWE-201',
		name: 'Insertion of Sensitive Information Into Sent Data',
		lang: 'python',
		status: 'Complete',
		what: `插入敏感資訊至送出的資料中（Insertion of Sensitive Information Into Sent Data）。程式把不該外流的敏感資料——
	作業系統種類與版本、內部 IP、明文憑證、使用者個人資料——連同正常回應一次次傳給不受信任的接收端。最常見的來源是除錯能力
	本身：例如把完整 stack trace、資料庫連線字串、或系統路徑寫進錯誤回應的 body、HTTP 標頭或錯誤頁。攻擊者只要觸發一次
	錯誤、或觀察回應裡的欄位，就能收集到規劃進下一步攻擊所需的資訊。正確做法是對送出的每項資料都做「最小化」：回應只暴露
	最低必要資訊，敏感欄位一律遮罩或拔掉，把詳細細節改寫入「受保護的伺服器端日誌」而非回給使用者。`,
		problem: `# 不安全寫法：錯誤處理把整份 exception 與內部路徑直接吐回頁面 / 回應
from flask import Flask, jsonify
app = Flask(__name__)

@app.errorhandler(Exception)
def on_err(exc):
    # 把內部堆疊與設定字串整個送給使用者
    return jsonify(detail=str(exc), stack=traceback.format_exc(),
                  dsn=app.config['DSN'], host=os.uname().nodename), 500`,
		fixed: `# 安全寫法：回應只回泛化訊息，細節全部改寫入伺服器端日誌
from flask import Flask, jsonify
import logging
app = Flask(__name__)
log = logging.getLogger('api')

@app.errorhandler(Exception)
def on_err(exc):
    log.exception('unhandled error')          # 明細只進 server-side 日誌
    return jsonify(detail='internal error'), 500  # 客戶端拿不到堆疊／路徑／設定`,
		patch: `@@
  @app.errorhandler(Exception)
  def on_err(exc):
-     return jsonify(detail=str(exc), stack=traceback.format_exc(),
-                   dsn=app.config['DSN'], host=os.uname().nodename), 500
+     log.exception('unhandled error')
+     return jsonify(detail='internal error'), 500`,
		refs: ['OWASP-Leak', 'CWE-201'],
		tags: ['sensitive-data', 'info-exposure', 'stack-trace'],
	},
	{
		id: 'CWE-202',
		name: 'Exposure of Sensitive Data Through Data Queries',
		lang: 'python',
		status: 'Complete',
		what: `經由資料庫查詢洩漏敏感資料（Exposure of Sensitive Data Through Data Queries）。在把查詢結果回傳、或把 ORM
	物件序列化時，連同資料庫內部結構、欄位名，甚至不相關的「後端私有欄位」一起交出去。最典型的是 SELECT * 回傳整列、或
	直接序列化整個 model 物件，把 password_hash、internal_token、is_deleted、created_by 這種後端專用欄位也一起帶給客戶端；在
	除錯時把整份含敏感參數的查詢字串寫進回應或日誌同樣如此。被拖出的欄位若含金鑰、雜湊或內部管理員旗標，等於把攻防面
	直接奉送。正確做法是「白名單式」地挑選需要回傳的欄位，任何後端內部性質在序列化時一律排除。`,
		problem: `# 不安全寫法：把 model 物件整個序列化回給前端，private 欄位一併外流
from flask import Flask, jsonify
@app.get('/api/user/<int:uid>')
def get_user(uid):
    row = db.sess.query(User).get(uid)          # User 含 password_hash、api_token 等欄位
    return jsonify(row.__dict__)                # SELECT * 全吐：雜湊跟 token 都出去了`,
		fixed: `# 安全寫法：白名單式挑欄位，只回前端真正需要的公開欄目
from flask import Flask, jsonify
@app.get('/api/user/<int:uid>')
def get_user(uid):
    row = db.sess.query(User).get(uid)
    if row is None:
        return jsonify(error='not found'), 404
    return jsonify(id=row.id, name=row.name, avatar=row.avatar)  # 明列允許的欄位集`,
		patch: `@@
  @app.get('/api/user/<int:uid>')
  def get_user(uid):
      row = db.sess.query(User).get(uid)
-     return jsonify(row.__dict__)
+     if row is None:
+         return jsonify(error='not found'), 404
+     return jsonify(id=row.id, name=row.name, avatar=row.avatar)`,
		refs: ['OWASP-Leak', 'CWE-202'],
		tags: ['sensitive-data', 'orm-serialization', 'select-star'],
	},
	{
		id: 'CWE-254',
		name: 'Security Features',
		lang: 'nodejavascript',
		status: 'Deprecated',
		what: `安全功能（Security Features）——這是 MITRE 已停用（Deprecated）的里程碑性質（Landmark）條目，僅在此保留說明
	與歷史脈絡。它泛指身分驗證、授權、權限管理、工作階段管理、密碼政策這整群「安全功能」，屬於涵蓋範圍極廣的聚合概念，幾乎
	等於每個角色體制各自條目化的總和，過於籠統，MITRE 已不再建議用它來映射真實弱點。實務上應改以它旗下的具體子條目來
	對症下藥——CWE-287 不當身分驗證、CWE-284 不當存取控制、CWE-269 不當權限管理、CWE-613 工作階段不足過期等等。
	本條保留範例用意，只在示範「安全功能被分散地、各處自行實作以致規則不一」這種概括性缺失的樣貌，不應視為獨立弱點。`,
		problem: `// 示範樣態：「驗證／授權」被散落各 handler 自行重蓋一遍，行為彼此不一致
app.get('/api/a', (req, res) => {
  if (!req.cookies.is_admin) return res.sendStatus(401);   // v1 自己寫的檢查
  sendA(res);
});
app.get('/api/b', (req, res) => {
  sendB(res);                                           // v2 甚至連檢查都沒有
});`,
		fixed: `// 示範樣態：把所有安全功能收斂為一套共用且統一的伺服器端中介層
app.use(centralAuth);                      // 統一的身分驗證
app.get('/api/a', requireRole(['admin']), (req, res) => sendA(res));
app.get('/api/b', requireRole(['user', 'admin']), (req, res) => sendB(res));`,
		patch: `@@
-  app.get('/api/a', (req, res) => {
-    if (!req.cookies.is_admin) return res.sendStatus(401);
-    sendA(res);
-  });
-  app.get('/api/b', (req, res) => {
-    sendB(res);
-  });
+  app.use(centralAuth);
+  app.get('/api/a', requireRole(['admin']), (req, res) => sendA(res));
+  app.get('/api/b', requireRole(['user', 'admin']), (req, res) => sendB(res));`,
		refs: ['OWASP-Auth', 'CWE-287'],
		tags: ['security-features', 'landmark', 'deprecated'],
	},
	{
		id: 'CWE-287',
		name: 'Improper Authentication',
		lang: 'python',
		status: 'Complete',
		what: `不當身分驗證（Improper Authentication）。當一個角色聲稱自己具有某個身分時，系統沒有證明、
	或只做了不充分的證明，就採信了這個聲明。常見成因是把驗證結果放在使用者可控的地方——表單欄位、
	明文 Cookie、可自填的旗標——然後逕自信任它當「已登入／是管理員」的依據，根本沒去比對密碼，
	或沒妥善管理伺服器端工作階段。攻擊者只需把可控制的旗標改成過關的值，就能繞過整段登入流程、
	冒充他人身分。輕則外流敏感資料，重則取得更高權限、甚至以受害者身分執行未授權動作。
	修法是不要自行拼湊弱驗證，改用它人驗證過的身分驗證框架／函式庫（例如 OWASP ESAPI 的
	驗證功能），並讓身分判定完全落在伺服器端受保護的憑證與工作階段上。`,
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
-    resp.set_cookie('admin', str(is_admin).lower())  # Cookie 明文、且由使用者控制
-    return resp
+    user = request.form.get('user')
+    pwd  = request.form.get('password')
+    rec = db.get_user(user)               # 從資料庫取回使用者記錄
+    if rec is None or not hmac.compare_digest(
+            hashlib.sha256(rec['salt'] + pwd.encode()).hexdigest(),
+            rec['hash']):
+        return make_response('bad creds', 401)
+    session.clear()
+    session['uid'], session['admin'] = rec['id'], rec['is_admin']  # 伺服器端保存
+    return make_response({'ok': True})`,
		refs: ['OWASP-Auth', 'CWE-287'],
		tags: ['authentication', 'auth-bypass', 'session'],
	},
	{
		id: 'CWE-306',
		name: 'Missing Authentication for Critical Function',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `關鍵功能缺少身分驗證（Missing Authentication for Critical Function）。凡是需要「可被證明的使用者身分」、
	或會耗用大量資源的功能，系統卻完全不驗證就執行——像是刪除帳號、刷新憑證、管理後台、列印機密報表這些
	高敏感操作，對外開了路由卻沒套任何驗證中介層。常見成因是開發者在主要通道做了驗證，卻另開一條「以為是
	私密」的次要通道或介面不加防護（登入佔某個埠、驗證後又開第二個埠假設只有已登入者連得到）。攻擊者只要
	直接走沒上鎖的入口，就能以該功能本身的權限做事——讀改敏感資料、碰管理功能，甚至執行任意程式碼。修法是
	把系統劃分為匿名／一般／特權／管理區，明確標出哪些區需要已驗證身分並用集中式驗證把關，而且所有可能
	的通訊通道（包括被誤當私密的那條）都要一一確認受保護；前端做的檢查也務必在伺服器端重複一次。`,
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
		what: `未適當限制過多的驗證失敗次數（Improper Restriction of Excessive Authentication Attempts）。
	登入介面沒有在短時間內防住多次失敗嘗試的手段——不計次數、不鎖定、也不限制速率，同一個 IP／帳號
	可以無窮無盡地試密碼。常見做法是每次呼叫驗證函式就換一個密碼重試，只要盲猜（brute force）的樣本夠大，
	總能猜中目標帳號的密碼而取得存取權。只有 time 之後再 sleep 而沒有限制並行連線數，也算沒限住。修法是
	在短時間內連續失敗即採取多層保護：失敗幾次就中斷連線、實施逾時或鎖定目標帳號一段時間、或要求使用者
	先完成一道運算題（captcha 類），並搭配經審核的驗證函式庫一次到位。`,
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
		id: 'CWE-359',
		name: 'Exposure of Private Personal Information',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `私人個人資訊（PII）外洩（Exposure of Private Personal Information）。系統收集或處理身分、電話、信箱、地址、
	健康、財務、定位這類可識別個人（PII）的資訊，卻在介面回應、檔案權限或授權流程的某些點把它暴露出來。常見成因是把所有
	欄位一口氣序列化回傳、把敏感欄位塞進 URL 查詢字串或日誌、或預設就把完整資料同步到次要系統。攻擊者得到這些資料即可
	拿來做個資販售、釣魚、帳號竊取或身分盜用，也使系統因違反個資法（GDPR 等）面臨重罰。正確做法是對 PII 一律加密
	儲存與遮罩（mask）顯示、最小化收集範圍、序列化時採白名單回傳，並把對 PII 的每一次存取寫入不可竄改的稽核日誌。`,
		problem: `// 不安全寫法：完整個資欄位含敏感號碼全量回給排序／列表端，還印進 log 查
app.get('/api/people', async (req, res) => {
  const rows = await db.people.find();      // 含 email、phone、doc_no 完整個資
  rows.forEach((r) => logger.info(JSON.stringify(r)));   // 隱私資料進日誌
  res.json(rows);                        // 前端明明只需要 id 跟 name，卻附上全套 PII
});`,
		fixed: `// 安全寫法：列表只回白名單欄位；PII 顯示時遮罩，日誌也一律不含裸個資
app.get('/api/people', async (req, res) => {
  const rows = await db.people.pick('id', 'name');      // 只取需要的欄
  res.json(rows.map((r) => ({
    id: r.id, name: r.name,
    phone: maskPhone(r.phone),           // 只露尾 3 碼
  })));                                // email / doc_no 根本不下行
});`,
		patch: `@@
  app.get('/api/people', async (req, res) => {
-   const rows = await db.people.find();
-   rows.forEach((r) => logger.info(JSON.stringify(r)));
-   res.json(rows);
+   const rows = await db.people.pick('id', 'name');
+   res.json(rows.map((r) => ({
+     id: r.id, name: r.name,
+     phone: maskPhone(r.phone),
+   })));
  });`,
		refs: ['OWASP-Pii', 'CWE-359'],
		tags: ['pii', 'privacy', 'personal-data'],
	},
	{
		id: 'CWE-521',
		name: 'Weak Password Requirements',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `密碼需求過弱（Weak Password Requirements）。系統沒有要求好的、夠強的密碼，註冊或改密碼時
	只要「非空字串」就收，沒有長度下限、不擋常見弱密碼、也不限定字元組合與禁止重複使用，容易讓使用者
	設成 123 / password 這類極易猜中的值。功能繁簡可因受保護的系統而異，靠傳統的「定期逼改」收效也有限。
	後果是攻擊者可輕鬆猜出使用者密碼、取得他人帳號。修法是明訂並落實符合情境的密碼政策：強制最小與最大長度、
	禁止重複使用舊密碼、禁止用常見密碼、禁止把使用者名稱等已知字串放進密碼；再視需要加入字元組合或較大的
	最小長度（引導用密碼詞組），並搭配 zxcvbn 這類弱密碼預測在落地端拒收。`,
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
async function register(req, res) {
  const { user, password } = req.body;
  const ok = password && password.length >= 12 &&
    zxcvbn(password).score >= 3 && !COMMON_PW.has(password);
  if (!ok) return res.status(400).json({ error: 'weak password' });
  const hash = await bcrypt.hash(password, 12);
  await db.users.insertOne({ user, hash });
  res.status(201).json({ ok: true });
}`,
		patch: `@@
   const { user, password } = req.body;
-  if (!password) return res.status(400).json({ error: 'password required' });
+  const ok = password && password.length >= 12 &&
+    zxcvbn(password).score >= 3 && !COMMON_PW.has(password);
+  if (!ok) return res.status(400).json({ error: 'weak password' });
+  const hash = await bcrypt.hash(password, 12);
-  const hash = await bcrypt.hash(password, 10);
   await db.users.insertOne({ user, hash });`,
		refs: ['OWASP-Password', 'CWE-521'],
		tags: ['password', 'weak', 'policy'],
	},
	{
		id: 'CWE-640',
		name: 'Weak Password Recovery Mechanism for Forgotten Password',
		lang: 'php',
		status: 'Complete',
		what: `弱密碼遺忘的重置／還原機制太弱（Weak Password Recovery Mechanism for Forgotten Password）。
	系統提供「不須知道原密碼就可恢復或更換密碼」的機制，但這套機制本身不牢靠：有的保密問答太好猜、或答案
	可從社群媒體打聽到；有的在認證前就把新密碼寄到非本人信箱；有的重設次數完全不限流，攻擊者用他人帳號連番
	觸發重設就能把合法使用者擋在門外（DoS）；還有的直接把「原密碼」原封寄回而非派發一次性新密碼。因為這條路
	本來就是設計來「無需舊密碼」的旁路，一旦失守，會把再強的密碼驗證也從根上打穿。修法是徹底過濾驗證重設
	流程的所有輸入、用數題且不可猜的問答、對錯答次數設定節流並達上限就停用、寄新密碼到最首約根地登記的
	信箱且不給使用者改收件位址、並改派一次性新密碼而不是洩露原密碼。`,
		problem: `<?php // 不安全寫法：mt_rand() 產生可預測的 token，而且直接寄「明文」重設碼
$token = mt_rand(100000, 999999);            // 僅 90 萬種可能值，可被暴力窮舉掃過
$link  = "https://example.com/reset?uid={$uid}&token={$token}";
mail($email, 'Reset', "Click: $link");       // 重設機制的關鍵以明文經 email 傳送
$db->query("UPDATE users SET reset_token='$token' WHERE id=$uid");`,
		fixed: `<?php // 安全寫法：random_bytes 產生強隨機 token、以雜湊存庫、帶有效期限且一次性
$token = bin2hex(random_bytes(32));                     // 256-bit，掃不到
$hash  = password_hash($token, PASSWORD_BCRYPT);       // 庫裡只存雜湊
$exp   = time() + 15 * 60;                        // 15 分鐘內有效
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
		what: `使用硬編碼憑證（Use of Hard-coded Credentials）。產品內建寫死的密碼或加密金鑰，分兩種樣態：
	「內向式」是驗證機制拿寫死的一組憑證檢查輸入——例如預設管理員帳號配一組每個安裝都一樣、而且不手動改程式
	就打不掉也不能停用的密碼，管理者還很難察覺；「外向式」是產品要連另一套系統、把連它所需的後端密鑰直接寫死在
	前端程式。只要有人反組譯出或從程式與 git 歷史挖到這組值，任何知情者都能登入，甚至因所有安裝共用同個密碼、
	不同組織都通用，更容易被擴散成大規模攻擊（例如蠕蟲）。修法是把憑證移出程式碼：由環境變數、設定伺服器或
	secret manager 注入並可輪換；必須保留內建值的話，限制能碰到該功能的實體並對外存身分做存取控制、密碼存強
	單向雜湊加隨機 salt，前後端之間則用須定時變動且受限的憑證。`,
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
		what: `缺少授權檢查（Missing Authorization）。當一個角色試圖存取資源或執行動作時，系統完全沒有做
	「他到底有沒有資格做這件事」的授權判定——只驗證了「有登入」（authenticated），卻不管權限。
	常見成因是把單人其次用途的程式搬到多人環境卻沒補授權、或開發者誤以為標頭／Cookie 這類輸入沒人能改。
	於是一般使用者只要直接呼叫敏感路由，就能打管理功能、讀別人資源、甚至直接動到未加密保護的資料庫或特權功能，
	輕則外流、改寫資料，重則取得更高權限、或把資源耗盡造成服務阻斷。修法是依「舉例」把角色與資料、功能仔細
	對應並用 RBAC 在正確邊界把關，讓授權檢查對準每段業務邏輯，伺服器端每頁都要正確執行、別讓直連頁就能繞過。`,
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
		what: `授權檢查做錯（Incorrect Authorization）。角色嘗試存取資源或執行動作時，系統有做授權判定、卻做得不正確，
	沒有如實擋下該擋的人。常見肇因有：拿使用者可控的輸入當判斷依據（如 request body／query 送來的 role、
	可偽造的 Cookie、URL 字串）、授權排在解析與正規化之前、或比對擁有者時取錯來源，甚至被篡改的資料
	直接誤放行。於是本該沒權限的人能繞過原本的限制去讀改敏感資料、取得更高權限，甚或執行未授權的指令。
	修法是授權一律以伺服器端可靠資料（session＋DB、角色／擁有權）為唯一準據、先正規化再決定、檢查順序
	確實無誤，並用 RBAC 在正確邊界把關、每頁逐次在伺服器端重驗，配 default-deny 的 ACL。`,
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
		refs: ['OWASP-Auth', 'CWE-863'],
		tags: ['authorization', 'broken-access-control', 'ownership'],
	},
	{
		id: 'CWE-937',
		name: 'OWASP Top Ten 2013 Category A2 - Broken Authentication and Session Management',
		lang: 'nodejavascript',
		status: 'Deprecated',
		what: `OWASP Top Ten 2013 A2——身分驗證與工作階段管理破損（Broken Authentication and Session Management）。
	這是 MITRE 為對應 OWASP 2013 前十名 A2 項目而建立的支柱（Pillar）條目，屬已停用（Deprecated）類別，僅保留歷史
	對映用途，不建議用來做真實弱點的唯一標籤。它概括的是「驗證身分的機制」與「延續驗證狀態的工作階段」整體品質低落的一整
	群問題：包含可被猜測或硬編碼的憑證、缺乏逾時的乾糙裝置、未妥善存放的 token、以及缺少多因素與竊取防護。實際修復應改
	以它旗下的具體子條目對症下藥——CWE-287 不當身分驗證、CWE-522 弱憑證儲存、CWE-613 工作階段不足過期、CWE-640
	弱的密碼遺忘回收機制。`,
		problem: `// (支柱示例)：登入成功卻沿用舊 session、把密碼以明文存在資料庫裡——A2 的典型樣態
if (passwordMatches(user, inputPw)) {
  // 不重新產生 session id、密碼也以明文存(應以 bcrypt 雜湊)
  storePasswordPlaintext(user.id, user.password);
  session_fix(user.id);      // 沿用可被預設的舊 sid，讓固定／掠奪有機可乘
}`,
		fixed: `// (支柱示例修法)：散列密碼＋成功登入即換新 session，並設登出使失效
if (await bcrypt.compare(inputPw, user.hash)) {
  rotateSessionId(user.id);          // 登入成功立刻換新 sid，丟棄舊的
  setSessionTimeout(1800);          // 明文→雜湊；session 也會在時限內過期
  await db.sessions.expireOld(user.id);
}`,
		patch: `@@
  if (passwordMatches(user, inputPw)) {
-     storePasswordPlaintext(user.id, user.password);
-     session_fix(user.id);
+     rotateSessionId(user.id);
+     setSessionTimeout(1800);
+     await db.sessions.expireOld(user.id);
  }`,
		refs: ['OWASP-A2', 'CWE-937'],
		tags: ['broken-authn', 'session', 'owasp-2013', 'deprecated'],
	},
];
