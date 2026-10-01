// CWE chunk — category: Broken Access Control.
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
		id: 'CWE-284',
		name: 'Improper Access Control',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `存取控制不當（Improper Access Control）。軟體在授權「誰能讀／寫哪個資源、執行哪個動作」時，
	沒有定義或沒有落實一套一致的檢查原則——可能直接跳過判斷、也可能把身分不足的人誤判為有權。
	相較於 CWE-862「漏了授權檢查」與 CWE-863「授權判錯」，這裡是更上層的通病：整個系統沒有
	一套統一、以伺服器端資料為唯一依據的存取規則，導致不同入口行為不一致，讓攻擊者有一條繞過之路。
	正確做法是把所有資源存取收斂到一個共同閘門（gate/middleware），規則單一而可審計。`,

		problem: `// 不安全寫法：每個 handler 各自為政，有的有檢查、有的沒有，規則無法一致
app.get('/api/file/:name', (req, res) => {
  // 這個 handler 乾脆沒做任何身分與權限檢查，任何人都能讀檔
  res.send(fs.readFileSync('/var/files/' + req.params.name));
});

app.get('/api/settings', (req, res) => {
  // 另一個入口反而檢查，行為不一致：同一個資源在不同路由竟然有不同的授權規則
  db.settings.findOne({ key: req.query.key }, (e, row) => {
    res.json(row);   // 沒檢查「這人可不可以看這個 key」
  });
});`,

		fixed: `// 安全寫法：所有資源存取都先通過同一個授權閘門，依伺服器端資料判別權限
function requireAccess(resource) {
  return (req, res, next) => {
    if (!req.session.uid) return res.sendStatus(401);            // 先驗身分
    const rec = db.userRoles.findOne({ uid: req.session.uid });  // 以 DB 決策
    if (!rec || !rec.can[resource]) return res.sendStatus(403);  // 再驗權限
    next();
  };
}

// 每個資源路由都掛上相同的 requireAccess，規則單一、行為一致
app.get('/api/file/:name', requireAccess('file:read'), (req, res) => {
  res.send(fs.readFileSync('/var/files/' + req.params.name));
});
app.get('/api/settings', requireAccess('settings:read'), (req, res) => {
  db.settings.findOne({ key: req.query.key }, (e, row) => res.json(row));
});`,

		patch: `@@
-  app.get('/api/file/:name', (req, res) => {
-    // 這個 handler 乾脆沒做任何身分與權限檢查，任何人都能讀檔
-    res.send(fs.readFileSync('/var/files/' + req.params.name));
-  });
-  app.get('/api/settings', (req, res) => {
-    db.settings.findOne({ key: req.query.key }, (e, row) => {
-      res.json(row);   // 沒檢查 $的人可不可以看這個 key
-    });
-  });
+  function requireAccess(resource) {
+    return (req, res, next) => {
+      if (!req.session.uid) return res.sendStatus(401);
+      const rec = db.userRoles.findOne({ uid: req.session.uid });
+      if (!rec || !rec.can[resource]) return res.sendStatus(403);
+      next();
+    };
+  }
+  app.get('/api/file/:name', requireAccess('file:read'), (req, res) => {
+    res.send(fs.readFileSync('/var/files/' + req.params.name));
+  });
+  app.get('/api/settings', requireAccess('settings:read'), (req, res) => {
+    db.settings.findOne({ key: req.query.key }, (e, row) => res.json(row));
+  });`,
		refs: ['OWASP-BrokenAccessControl', 'CWE-284'],
		tags: ['broken-access-control', 'authorization', 'access-control'],
	},
	{
		id: 'CWE-639',
		name: 'Authorization Bypass Through User-Controlled Key',
		lang: 'python',
		status: 'Complete',
		what: `經由「使用者可控的金鑰」繞過授權，也就是所謂的 Insecure Direct Object Reference（IDOR）。
	程式直接拿使用者在 URL／表單裡填的物件識別碼（id、order_id、user_id、file 名稱…）去取資料，
	卻沒先確認這筆記錄屬於「目前登入的人」。攻擊者只要把 id+1、換成別人的帳號編號，
	就能越權讀取或修改別人的資源。修法是：先用伺服器端 session 取得操作者身分，再以該身分
	驗證物件「所有權或範圍」是否相符，不相符就回 403，而不是照單全收地索引資料。`,

		problem: `# 不安全寫法：直接把 query 的 uid 當索引去撈資料，沒有檢查「是不是自己」
@app.get('/api/orders')
def list_orders():
    uid = request.args.get('uid')            # uid 來自使用者輸入，可隨意改
    rows = db.execute(
        'SELECT * FROM orders WHERE user_id = ?', (uid,)
    ).fetchall()
    return jsonify(rows)                    # 把 ?uid=2 就會拿到別人的訂單`,
		fixed: `# 安全寫法：操作者身分一律取自伺服器端 session，永不接受 query 送來的 uid
@app.get('/api/orders')
def list_orders():
    uid = session['uid']                    # 身分只在伺服器端，使用者無法改
    rows = db.execute(
        'SELECT * FROM orders WHERE user_id = ?', (uid,)
    ).fetchall()
    # 只回自己 uid 的資料，別人如何竄改參數也算不到他頭上
    return jsonify(rows)`,
		patch: `@@
-      uid = request.args.get('uid')            # uid 來自使用者輸入，可隨意改
+      uid = session['uid']                    # 身分只在伺服器端，使用者無法改
       rows = db.execute(
           'SELECT * FROM orders WHERE user_id = ?', (uid,)
       ).fetchall()`,
		refs: ['OWASP-ObjectLevelAuth', 'CWE-639'],
		tags: ['idor', 'object-reference', 'user-controlled-key', 'access-control'],
	},
	{
		id: 'CWE-706',
		name: 'Use of Incorrectly-Resolved Name or Reference',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `使用了「被錯誤解析」的名稱或參照（Use of Incorrectly-Resolved Name or Reference）。
	程式拿使用者提供的名稱到某個命名空間去找「它想做的那個東西」，但因為名稱對映的規則不清楚、
	或檢查用的是名稱本身而存取用的是真實物件，最後解析出來的資源／函式不是原本意圖的那一個。
	典型是目錄穿越若解析符號連結、或「先檢查檔名後讀內容」時名稱先在別處被重新詮釋；
	這裡聚焦在名稱→資源的對映會指向錯誤目標。修法是讓名稱與授權決策綁定同一個、由伺服器端
	正規化並解析過的代表，且解析結果必須落在預期的範圍內。`,

		problem: `// 不安全寫法：依使用者送的檔案名去 fs 解析，卻讓符號連結與 ‥ 改變真實目標
const fs = require('fs');
const path = require('path');
const ROOT = '/var/archive';

app.get('/api/read/:name', (req, res) => {
  // root 只驗了「開頭字串」，name = '../../etc/shadow' 或 symlink 都能溜出去
  const target = path.join(ROOT, req.params.name);
  if (!target.startsWith(ROOT)) return res.sendStatus(403);
  res.send(fs.readFileSync(target));   // 解析出來的可能是 ROOT 之外的檔案
});`,

		fixed: `// 安全寫法：先用 realpath 徹底正規化目標，再以「絕對位置」做包含檢查與授權
const fs = require('fs');
const path = require('path');
const ROOT = fs.realpathSync('/var/archive');

app.get('/api/read/:name', (req, res) => {
  const allow = path.join(ROOT, req.params.name).slice(0, ROOT.length);
  const target = fs.realpathSync(allow);          // 解析 symlink、消去 ..
  if (!target.startsWith(ROOT)) return res.sendStatus(403);   // 以真實位置驗證
  res.send(fs.readFileSync(target));
});`,
		patch: `@@
-  const target = path.join(ROOT, req.params.name);
-  if (!target.startsWith(ROOT)) return res.sendStatus(403);
-  res.send(fs.readFileSync(target));   // 解析出來的可能是 ROOT 之外的檔案
+  const allow = path.join(ROOT, req.params.name).slice(0, ROOT.length);
+  const target = fs.realpathSync(allow);          // 解析 symlink、消去 ..
+  if (!target.startsWith(ROOT)) return res.sendStatus(403);   // 以真實位置驗證
+  res.send(fs.readFileSync(target));`,
		refs: ['OWASP-PathTraversal', 'CWE-706'],
		tags: ['path-traversal', 'symlink', 'name-resolution', 'access-control'],
	},
	{
		id: 'CWE-1188',
		name: 'Insecure Default Initialization of Resource',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `資源預設值不安全（Insecure Default Initialization of Resource）。套件、設備或程式在「開箱即用」時，
	就把關鍵資源初始化成可被預測或不安全的狀態——最典型是奉送一組「出廠預設密碼／掃描不到的卻人人
	知道的管理帳號」，或預設把管理介面/共享資源對外開啟而不設任何一把鎖。使用者只要不去改，
	攻擊者用公開的預設值就能登入或存取。修法是：首次啟動就強制要求使用者設定自己的秘密、
	或產生隨機密碼並只顯示一次，且不安全功能預設關閉。`,

		problem: `// 不安全寫法：初次開跑就給一組公開的固定帳密，人人皆知、改了才會安全
if (!db.hasAdmin()) {
  // "admin"/"admin" 這組預設值列在說明書裡，成千上萬台都同一把鑰匙
  db.createAdmin({
    user: 'admin',
    hash: bcrypt.hashSync('admin', 10),      // 固定的出廠密碼
  });
}`,

		fixed: `// 安全寫法：沒有管理員時不偷給預設值，而是強制設定或派發一次性隨機密碼
const crypto = require('crypto');

async function bootstrapAdmin() {
  if (db.hasAdmin()) return;
  if (process.env.ADMIN_FIRST_SETUP) {
    // 首次啟動就導到「自行設定密碼」流程，拒絕固定預設值
    return redirect('/setup/choose-password');
  }
  const temp = crypto.randomBytes(9).toString('base64'); // 一次性隨機，只印在開機日誌
  db.createAdmin({ user: 'admin', hash: bcrypt.hashSync(temp, 10) });
  console.log('temporary admin password (regenerate on login):', temp);
}`,
		patch: `@@
-  db.createAdmin({
-    user: 'admin',
-    hash: bcrypt.hashSync('admin', 10),      // 固定的出廠密碼
-  });
+  const temp = crypto.randomBytes(9).toString('base64'); // 一次性隨機，只印在開機日誌
+  db.createAdmin({ user: 'admin', hash: bcrypt.hashSync(temp, 10) });
+  console.log('temporary admin password (regenerate on login):', temp);`,
		refs: ['OWASP-DefaultCreds', 'CWE-1188'],
		tags: ['default-credentials', 'default-configuration', 'weak-defaults'],
	},
];
