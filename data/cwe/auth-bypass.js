// CWE chunk — category: Authentication Bypass & Alternative Path / Trust.
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
		id: 'CWE-288',
		name: 'Authentication Bypass Using an Alternate Path',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `使用另一條路徑繞過身分驗證。受保護的動作（例如 DELETE 訂單）明明掛了驗證中介層，
	不過同一個動作另有一條「旁門左道」的路由忘了套 verify——像是多了個未保護的 GET 對照端點、
	路徑大小寫歧義、或一個標記成 /internal 卻對外可見的入口。攻擊者只要改走這條替代路徑，
	就能完全繞過驗證存取關鍵資料。修法是讓受保護的動作只由唯一、且全程掛驗證的端點提供。`,
		problem: `// 不安全寫法：DELETE 有掛 requireAuth，卻是空包彈——真有動作的是沒上鎖的內建捷徑
async function requireAuth(req, res, next) {
  if (!req.session || !req.session.uid) return res.sendStatus(401);
  const rec = await db.users.findById(req.session.uid);
  if (!rec || rec.role !== 'admin') return res.sendStatus(403);
  next();
}

app.delete('/api/orders/:id', requireAuth, async (req, res) => {   // 有驗證，但…
  await db.orders.deleteOne({ _id: req.params.id });
  res.sendStatus(200);
});

// 旁門左道：內部用 GET 暫時頂著用的捷徑，忘了換成有 requireAuth 的版本
app.get('/api/orders/:id', async (req, res) => {                  // 完全沒驗證，匿名叫了就跑
  await db.orders.deleteOne({ _id: req.params.id });
  res.sendStatus(204);
});`,
		fixed: `// 安全寫法：真正會刪資料的動作只有「唯一」且掛驗證的端點；GET 只做唯讀查詢
async function requireAuth(req, res, next) {
  if (!req.session || !req.session.uid) return res.sendStatus(401);
  const rec = await db.users.findById(req.session.uid);
  if (!rec || rec.role !== 'admin') return res.sendStatus(403);
  next();
}

app.get('/api/orders/:id', async (req, res) => {                 // GET 只能唯讀
  const doc = await db.orders.findById(req.params.id);
  if (!doc) return res.sendStatus(404);
  res.json(doc);
});

app.delete('/api/orders/:id', requireAuth, async (req, res) => {  // 改刪除只走這唯一入口
  await db.orders.deleteOne({ _id: req.params.id });
  res.sendStatus(200);
});`,
		patch: `@@
-  app.delete('/api/orders/:id', requireAuth, async (req, res) => {
-    await db.orders.deleteOne({ _id: req.params.id });
-    res.sendStatus(200);
-  });
-  app.get('/api/orders/:id', async (req, res) => {
-    await db.orders.deleteOne({ _id: req.params.id });
-    res.sendStatus(204);
-  });
+  app.get('/api/orders/:id', async (req, res) => {
+    const doc = await db.orders.findById(req.params.id);
+    if (!doc) return res.sendStatus(404);
+    res.json(doc);
+  });
+  app.delete('/api/orders/:id', requireAuth, async (req, res) => {
+    await db.orders.deleteOne({ _id: req.params.id });
+    res.sendStatus(200);
+  });`,
		refs: ['OWASP-Auth', 'CWE-288'],
		tags: ['auth-bypass', 'alternate-path', 'missing-auth'],
	},
	{
		id: 'CWE-290',
		name: 'Authentication Bypass by Spoofing',
		lang: 'python',
		status: 'Complete',
		what: `靠偽造就繞過身分驗證。伺服器直接採信用戶可自行填寫的來源資訊——例如 X-Forwarded-For、
	X-Real-IP、X-Authenticated-User，或乾脆用來源 IP——來認定「來者何人、夠不夠格」。
	這種標頭／位址任誰都能在工作站端偽造，攻擊者插一筆假的 X-Real-IP 或來源位址，
	就足以冒充白名單主機身分。修法是信任鏈只由你可控制的一層（可信反向代理）設定，
	身份與權限一律以伺服器端 session＋DB 記錄為準。`,
		problem: `# 不安全寫法：直接吃前端可偽造的標頭當身分與權限：「來源是否受信任」
from flask import Flask, request

app = Flask(__name__)

@app.route('/admin/cmd')
def admin_cmd():
    ip = request.headers.get('X-Real-IP')            # 用戶自己就能帶的假標頭
    if ip not in TRUSTED_IPS:                       # 偽造成管理主機 IP 就放行
        return 'forbidden', 403
    return run(command)                              # 等同未經驗證的管理權`,
		fixed: `# 安全寫法：可信反向代理才允許拿標頭，且身分以伺服器端 session＋DB 記錄為準
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = os.environ['APP_SECRET']            # 由部署環境注入

def peer_ip():
    # 只信任自己架設的代理層轉來的標頭，杜絕用戶偽造直連
    return trust_proxy(request.remote_addr,
                    request.headers.get('X-Forwarded-For')) if BEHIND_PROXY \\
        else request.remote_addr

@app.route('/admin/cmd')
def admin_cmd():
    if not session.get('uid'):                       # 身份只認伺服器端 session
        return 'unauthorized', 401
    rec = db.get_system(session['uid'])
    if not rec or rec.role != 'admin':
        return 'forbidden', 403
    return run(command)`,
		patch: `@@
-  @app.route('/admin/cmd')
-  def admin_cmd():
-      ip = request.headers.get('X-Real-IP')
-      if ip not in TRUSTED_IPS:
-          return 'forbidden', 403
-      return run(command)
+  def peer_ip():
+      return trust_proxy(request.remote_addr,
+                      request.headers.get('X-Forwarded-For')) if BEHIND_PROXY \\
+          else request.remote_addr
+
+  @app.route('/admin/cmd')
+  def admin_cmd():
+      if not session.get('uid'):
+          return 'unauthorized', 401
+      rec = db.get_system(session['uid'])
+      if not rec or rec.role != 'admin':
+          return 'forbidden', 403
+      return run(command)`,
		refs: ['OWASP-ServerSideForgery', 'CWE-290'],
		tags: ['spoofing', 'trusted-header', 'ip-trust'],
	},
	{
		id: 'CWE-302',
		name: 'Authentication Bypass by Assumed-Immutable Data',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `把「不會被改」的客戶端資料當作權限依據，藉此繞過驗證。像「是否管理員」由一個
	Cookie 旗標、隱藏表單欄位或 URL 參數來決定——開發者假設一般人不會動手腳。偏偏這些資料
	完全存於用戶機器上、人人都改得了，攻擊者只要在自己瀏覽器動一行值（把 admin=0 改 1），
	就能冒充管理員。修法是資格認定一律回歸伺服器端受保護的資料（session／DB），
	任何客戶端能寫的地方都不得參與安全決策。`,
		problem: `// 不安全寫法：「是不是管理員」由客戶端可控的 Cookie 旗標決定
app.get('/api/config', (req, res) => {
  // zh-hant: 開發者預設這旗標「使用者不會改」，其實根本是可偽造的 plaintext value
  const isAdmin = (req.cookies.is_admin || '0') === '1';
  if (!isAdmin) return res.sendStatus(403);
  res.json(db.config.all());          // 用瀏覽器把 is_admin 改成 1 就能看配置
});`,
		fixed: `// 安全寫法：管理資格只來自伺服器端 session＋DB 的角色記錄
async function requireAdmin(req, res, next) {
  if (!req.session || !req.session.uid) return res.sendStatus(401);
  const rec = await db.users.findById(req.session.uid);     // 唯一可信的角色來源
  if (!rec || rec.role !== 'admin') return res.sendStatus(403);
  next();
}
app.get('/api/config', requireAdmin, (req, res) => {
  res.json(db.config.all());
});`,
		patch: `@@
-  app.get('/api/config', (req, res) => {
-    const isAdmin = (req.cookies.is_admin || '0') === '1';
-    if (!isAdmin) return res.sendStatus(403);
-    res.json(db.config.all());
-  });
+  async function requireAdmin(req, res, next) {
+    if (!req.session || !req.session.uid) return res.sendStatus(401);
+    const rec = await db.users.findById(req.session.uid);
+    if (!rec || rec.role !== 'admin') return res.sendStatus(403);
+    next();
+  }
+  app.get('/api/config', requireAdmin, (req, res) => {
+    res.json(db.config.all());
+  });`,
		refs: ['OWASP-DataValidation', 'CWE-302'],
		tags: ['assumed-immutable', 'client-state', 'privilege-flag'],
	},
	{
		id: 'CWE-602',
		name: 'Client-Side Enforcement of Server-Side Security',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `只在客戶端（瀏覽器）把關安全性，伺服器卻照單全收。把「能不能按、欄位要不要鎖、值合不合法」
	只靠一層 JavaScript 擋用戶——例如 disable 掉「管理員」按鈕、隱藏欄位、或前端先檢查權限——然後
	API 本身不做任何授權與驗證。攻擊者完全不必跑前端，直接 curl 呼叫 API 就能執行受保護動作或送出非法值。
	修法是每一支 API 都獨立做伺服器端驗證與授權，前端那些 UI 限制只是「體驗」，不是安全防線。`,
		problem: `// zh-hant: 不安全寫法——唯一防線只剩前端的 disabled，API 本身零驗證
const btn = document.getElementById('grant-admin');
if (!currentUser.admin) btn.disabled = true;   // 純前端擋，後端不管誰呼叫都放行

// server side（不安全）
app.post('/api/grant/:target', (req, res) => {   // 沒授權中介層、沒角色比對
  db.users.updateRole(req.params.target, 'admin');   // 任何人 curl 就能把自己升級成管理員
  res.sendStatus(200);
});`,
		fixed: `// 安全寫法：前端只做 UX，真正的安全判定完全在伺服器端中介層
const btn = document.getElementById('grant-admin');
btn.disabled = !currentUser.admin;            // 只是 UX，不是防線

// server side（安全）
async function requireAdmin(req, res, next) {
  if (!req.session || !req.session.uid) return res.sendStatus(401);
  const me = await db.users.findById(req.session.uid);
  if (!me || me.role !== 'admin') return res.sendStatus(403);   // 伺服器端才決定誰能做
  next();
}
app.post('/api/grant/:target', requireAdmin, async (req, res) => {
  await db.users.updateRole(req.params.target, 'admin');
  res.sendStatus(200);
});`,
		patch: `@@
-  const btn = document.getElementById('grant-admin');
-  if (!currentUser.admin) btn.disabled = true;
-  app.post('/api/grant/:target', (req, res) => {
-    db.users.updateRole(req.params.target, 'admin');
-    res.sendStatus(200);
-  });
+  const btn = document.getElementById('grant-admin');
+  btn.disabled = !currentUser.admin;
+  async function requireAdmin(req, res, next) {
+    if (!req.session || !req.session.uid) return res.sendStatus(401);
+    const me = await db.users.findById(req.session.uid);
+    if (!me || me.role !== 'admin') return res.sendStatus(403);
+    next();
+  }
+  app.post('/api/grant/:target', requireAdmin, async (req, res) => {
+    await db.users.updateRole(req.params.target, 'admin');
+    res.sendStatus(200);
+  });`,
		refs: ['OWASP-FrontEndSecurity', 'CWE-602'],
		tags: ['client-side-security', 'gui', 'server-side-enforcement'],
	},
];
