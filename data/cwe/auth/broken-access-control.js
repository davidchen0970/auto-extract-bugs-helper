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
		id: 'CWE-285',
		name: 'Improper Authorization',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `不當授權。授予或拒絕資源／動作存取權的決策是錯的——可能是「該擋的被放行」，也可能是授權邏輯根本沒被
	呼叫、或寫疑時漏掉條件。它與 CWE-862「整個漏了授權檢查」、CWE-863「授權判錯」屬同一家族，這裡泛指這類
	決策偏誤的總體。典型例子是某個管理動作只在路由上臨頭判斷、忘了納入細顆粒權限、或以不完整的條件就放行。被不當
	授權的結果就是越權存取資料、執行特權動作。正確做法是把授權決策當成一等公民：集中而一致的閘門、以伺服器端身分＋
	角色＋擁有權為依據，並確保每個敏感動作都確實經過它。`,
		problem: `// 不安全寫法：授權判斷只在一個動作上做，其它「同級」動作卻漏網；且條件只認 role 字串
app.put('/api/order/:id/status', (req, res) => {
  if (req.session.role !== 'admin') return res.sendStatus(403);  // 只管這一個
  db.orders.updateStatus(req.params.id, req.body.status);
});
// 同理可改訂單的地方堆在一起：取消就完全沒檢查，供路人也能喊停別人的單
app.delete('/api/order/:id', (req, res) => db.orders.cancel(req.params.id));`,
		fixed: `// 安全寫法：授權邏輯收斂成共用中介層，並以伺服器端身分＋擁有權共同決定
function requireOrderOwnerOrAdmin(req, res, next) {
  if (!req.session || !req.session.uid) return res.sendStatus(401);
  db.orders.findById(req.params.id, (e, o) => {
    const isAdmin = db.users.isAdmin(req.session.uid);         // 角色來自 DB
    if (e || !o || (!isAdmin && String(o.ownerUid) !== String(req.session.uid)))
      return res.sendStatus(403);                             // owner 或 admin 才准
    next();
  });
}
app.put('/api/order/:id/status', requireOrderOwnerOrAdmin, (req, res) =>
  db.orders.updateStatus(req.params.id, req.body.status));
app.delete('/api/order/:id', requireOrderOwnerOrAdmin, (req, res) =>
  db.orders.cancel(req.params.id));`,
		patch: `@@
-  app.put('/api/order/:id/status', (req, res) => {
-    if (req.session.role !== 'admin') return res.sendStatus(403);
-    db.orders.updateStatus(req.params.id, req.body.status);
-  });
-  app.delete('/api/order/:id', (req, res) => db.orders.cancel(req.params.id));
+  function requireOrderOwnerOrAdmin(req, res, next) {
+    if (!req.session || !req.session.uid) return res.sendStatus(401);
+    db.orders.findById(req.params.id, (e, o) => {
+      const isAdmin = db.users.isAdmin(req.session.uid);
+      if (e || !o || (!isAdmin && String(o.ownerUid) !== String(req.session.uid)))
+        return res.sendStatus(403);
+      next();
+    });
+  }
+  app.put('/api/order/:id/status', requireOrderOwnerOrAdmin, (req, res) =>
+    db.orders.updateStatus(req.params.id, req.body.status));
+  app.delete('/api/order/:id', requireOrderOwnerOrAdmin, (req, res) =>
+    db.orders.cancel(req.params.id));`,
		refs: ['OWASP-Auth', 'CWE-285'],
		tags: ['authorization', 'broken-access-control', 'role'],
	},
	{
		id: 'CWE-358',
		name: 'Improperly Implemented Security Check for Standard',
		lang: 'nodejavascript',
		status: 'Deprecated',
		what: `對「標準」的安全檢查實作不當（Improperly Implemented Security Check for Standard）。這是 MITRE 已停用
	（Deprecated）的支柱（Pillar）條目。它泛指某個安全標準／規範要求的檢查「有實作卻做錯」的概括性缺陷——例如對某
	法規或組織規範做了表面檢查，卻漏掉真正攸關的條件，或照規範該驗證的動作實際被驗證的是別的項目。由於涵蓋對象太雜、
	幾乎是所有「檢查做偏」的集合，MITRE 不再建議用它映射單一真實弱點，而應往下對應到具體子條目（例如 CWE-863 不當
	授權、CWE-287 不當身分驗證）逐一處理。本條保留範例在示範「照規範應驗證，實作卻指向別處」這類錯位的樣貌。`,
		problem: `// 示範：專案規範規定「任何寫入前都必須先驗證角色」，實作卻驗成了「登入與否」
app.put('/api/doc/:id', (req, res) => {
  if (!req.session || !req.session.uid) return res.sendStatus(401); // 只驗了「有登入」
  db.docs.save(req.params.id, req.body);   // 該做的角色檢查(from policy)被寫成純登入檢查
});`,
		fixed: `// 示範：把規範要求的檢查實作到位——登入之外，再加上角色的審核
function requireWriteRole(req, res, next) {
  if (!req.session || !req.session.uid) return res.sendStatus(401);
  if (!db.users.isEditor(req.session.uid)) return res.sendStatus(403);  // 規範要求的角色驗證
  next();
}
app.put('/api/doc/:id', requireWriteRole, (req, res) => db.docs.save(req.params.id, req.body));`,
		patch: `@@
    app.put('/api/doc/:id', (req, res) => {
-     if (!req.session || !req.session.uid) return res.sendStatus(401);
-     db.docs.save(req.params.id, req.body);
-   });
+     if (!req.session || !req.session.uid) return res.sendStatus(401);
+     if (!db.users.isEditor(req.session.uid)) return res.sendStatus(403);
+     db.docs.save(req.params.id, req.body);
+   });`,
		refs: ['OWASP-BrokenAccessControl', 'CWE-358'],
		tags: ['security-check', 'standard', 'deprecated'],
	},
	{
		id: 'CWE-402',
		name: "Transmission of Private Resources into a New Sphere ('Resource Leak')",
		lang: 'python',
		status: 'Complete',
		what: `把私有資源傳送到新的範疇（資源外洩，Resource Leak）。產品把「原本只該在自己控制範疇內被存取」的資源，
	漏到不受信任的一方——例如把內物件的參考（reference）、檔案描述子、記憶體區域、資料庫連線或權杖，帶到能由外部觸及的
	介面上交付。這與 CWE-668「把資源暴露到錯誤的範疇」相近，這裡更強調「跨越信任邊界的格叠傳遞造成外洩」。一旦私有
	資源落入錯誤範疇，持有者就能越過應有的存取檢查撥弄它。正確做法是嚴格定義信任範疇的邊界，私有資源只在自己的範疇內
	傳遞，跨範疇從不直接交付原始參考，而是提供一個受限的「觀點（view）」或副本。`,
		problem: `# 不安全寫法：把內部的敏感物件參考直球交到外掛（不受信任程式碼）手上
def expose(document_id, plugin):
    doc = store.open_private(document_id)     # 私有文件物件（含修正權杖、內部欄位）
    plugin.render(doc)                      # plugin 是不受信任程式碼，卻拿到活體可變物件`,
		fixed: `# 安全寫法：交給外掛的只是「受限的觀點」，不含內部狀態與寫入能力
def expose(document_id, plugin):
    doc = store.open_private(document_id)
    view = PublicView(title=doc.title, body=doc.body)   # 只挑公開欄目，丟掉權杖
    plugin.render(view)                                  # 外掛只能讀 view，碰不到內部物件`,
		patch: `@@
  def expose(document_id, plugin):
      doc = store.open_private(document_id)
-     plugin.render(doc)                     # 活體可變物件
+     view = PublicView(title=doc.title, body=doc.body)
+     plugin.render(view)`,
		refs: ['OWASP-BrokenAccessControl', 'CWE-668'],
		tags: ['resource-leak', 'sphere', 'trust-boundary'],
	},
	{
		id: 'CWE-636',
		name: "Not Failing Securely ('Failing Open')",
		lang: 'nodejavascript',
		status: 'Complete',
		what: `不以安全的方式失敗（Failing Open）。程式遇到錯誤或失敗時，依設計退回「比其它可用方案更不安全」的狀態——
	例如授權查詢拋例外時預設「允許」、加密找不到最強演算法時改用最弱的、權限讀取失敗時以最全開的權限繼續處理。
	攻擊者只要能誘發錯誤狀態（送壞輸入、讓權限查詢拋出、製造時序問題），就直接走進「失敗即放行」的通道，於是
	「成功才放行」的約束形同虛設。正確做法是失敗預設為「拒絕並記錄」，把所有錯誤分支都導向保守、可審計的路徑，
	而授權、加密這類安全決策的例外一律視同不安全而關閉。`,
		problem: `// 不安全寫法：權限查詢拋出例外時，catch 直接把請求放行（最壞的 fallback = 允許）
app.get('/api/order/:id', async (req, res) => {
  try {
    const can = await checkCan(req.session.uid, req.params.id);
    if (!can) return res.sendStatus(403);
    res.json(await db.orders.findById(req.params.id));
  } catch (err) {
    res.sendStatus(200);            // 任何錯誤(含 checkCan 崩)都回 200，等同無權也看得到
  }
});`,
		fixed: `// 安全寫法：安全決策的例外一律當成「拒絕」——失敗即關閉，並留下可稽核的記錄
app.get('/api/order/:id', async (req, res) => {
  try {
    const can = await checkCan(req.session.uid, req.params.id);
    if (!can) return res.sendStatus(403);      // 連 false 都拒絕
    res.json(await db.orders.findById(req.params.id));
  } catch (err) {
    logger.error('authorization check failed, denying', err);  // 例外 → 拒絕
    res.sendStatus(403);
  }
});`,
		patch: `@@
    try {
      const can = await checkCan(req.session.uid, req.params.id);
      if (!can) return res.sendStatus(403);
      res.json(await db.orders.findById(req.params.id));
    } catch (err) {
-     res.sendStatus(200);
+     logger.error('authorization check failed, denying', err);
+     res.sendStatus(403);
    }`,
		refs: ['OWASP-FailSecure', 'CWE-636'],
		tags: ['fail-open', 'fail-secure', 'default-allow'],
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
		id: 'CWE-668',
		name: 'Exposure of Resource to Wrong Sphere',
		lang: 'python',
		status: 'Complete',
		what: `把資源暴露到錯誤的範疇（Exposure of Resource to Wrong Sphere）。系統在設計或實作時，把「某個資源」放到
	不該碰觸它、但位於系統其它部分／控制範疇的位置。例如把記憶體區域映射進含可執行區、把唯讀資料的緩衝區以可寫權限
	交出、或把內部的資料庫連線暴露給只負責顯示的部件。因為資源落在錯誤主體可觸及的範疇，即使在自己範疇內的存取控制
	「是正確的」，仍攔不住這條跨範疇的洩出。正確做法是先畫出信任範疇與資源的支配圖，任何資源（記憶、檔案、連線、
	物件參考）都傳到它該待的、受約束的範疇，並在界限處再次套用最窄的暴露。`,
		problem: `# 不安全寫法：把資料庫連線物件（含寫入權）直接貼在 request 上交給只做顯示的模板
def handle(req, conn):
    req.conn = conn                   # conn 是活的 DB 連線，等下無論誰渲染 req 都能用它
    t = template.render(req)           # 若 req(含 conn)被傳給低信任的渲染器即可寫入資料庫`,
		fixed: `# 安全寫法：對外只給「唯讀觀點」，連線與寫入能力留在高信任範疇內
def handle(req, conn):
    view = make_read_only(req)         # 只保留渲染所需的欄位，沒有 conn
    t = template.render(view)         # 渲染端完全碰不到寫入資源`,
		patch: `@@
  def handle(req, conn):
-     req.conn = conn
-     t = template.render(req)
+     view = make_read_only(req)
+     t = template.render(view)`,
		refs: ['OWASP-BrokenAccessControl', 'CWE-668'],
		tags: ['wrong-sphere', 'resource-exposure', 'trust-boundary'],
	},
	{
		id: 'CWE-669',
		name: 'Incorrect Resource Transfer Between Spheres',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `範疇間資源轉移不當（Incorrect Resource Transfer Between Spheres）。產品把資源／行為「轉移」到另一個範疇、
	或「從另一個範疇匯入」時做法不當，因而給了外來者對該資源的意外控制權。典型是把擁有者的憑證、內部權柄在伺服器對
	伺服器、或伺服器對不可信外掛元件之間傳遞時，把過多能力一起帶過去；或從低信賴路徑匯入「控制權」而不追加校驗。
	被誤傳的資源通常攜帶控制權，接收方實際得到的控制範圍因此超出刻意賦予的。正確做法是在範疇界線處以「最小能力」介面
	交換資源，只交付接收方真正需要的觀點，並對任何跨範疇匯入的權重重新驗證。`,
		problem: `// 不安全寫法：把持有者自己的憑證整包轉交給副服務，副服務因此握有完整委派能力
async function handoff(orderId, downstream) {
  const token = await vault.ownerCredential(orderId);   // 都是完整憑證
  await downstream.fulfill(orderId, { token });        // downstream(untrusted) 取得 owner 能力
}`,
		fixed: `// 安全寫法：轉交給下游的只是「綁定單一動作的短期、限權委派」，能力最小
async function handoff(orderId, downstream) {
  const delegation = await iam.delegateToken({
    orderId,
    actions: ['ship:update'],          // 只授一項最小動作
    ttl: '15m',
  });
  await downstream.fulfill(orderId, { delegation });   // 下游頂多能 ship，拿不到 owner 全權
}`,
		patch: `@@
  async function handoff(orderId, downstream) {
-   const token = await vault.ownerCredential(orderId);
-   await downstream.fulfill(orderId, { token });
+   const delegation = await iam.delegateToken({
+     orderId,
+     actions: ['ship:update'],
+     ttl: '15m',
+   });
+   await downstream.fulfill(orderId, { delegation });
  }`,
		refs: ['OWASP-BrokenAccessControl', 'CWE-669'],
		tags: ['resource-transfer', 'sphere', 'least-privilege'],
	},
	{
		id: 'CWE-693',
		name: 'Protection Mechanism Failure',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `保護機制失敗（Protection Mechanism Failure）。產品「沒有使用」、或「用錯」了足以對抗定向攻擊的安全機制。
	它涵蓋三大類失守：完全沒有部署保護機制、實作了卻有利害缺陷而被繞過、或把機制用在不當位置、使它沒在該生效時生效。
	例如該做身分驗證的地方只做了身份識別、該加密的地方用明文、該在邊界做的輸入監理被拖到最內層才小修。因為這是一個
	支柱／類別的頂層描述，最有效的動作是往下落到底層的子條目（CWE-287、CWE-284、CWE-79 等）去定位確實的缺口。
	正確做法是確保每一個「升高信任」的動作，都在正確的邊界使用正確、完整、且持續更新的保護機制，並對機制做反繞過測試。`,
		problem: `// 不安全寫法：號稱有身分驗證，實際上只是前端藏按鈕，伺服器路由完全沒上保護機制
app.post('/api/delete-threads', (req, res) => {
  // 伺服器端連身分檢查都沒有；前端把按鈕 disable 就以為「受保護了」
  threadStore.bulkDelete(req.body.ids);
  res.sendStatus(200);
});`,
		fixed: `// 安全寫法：在信任邊界處使用正確的保護機制——先驗證身分，再授權動作
async function requireAuthForDelete(req, res, next) {
  if (!req.session || !req.session.uid) return res.sendStatus(401);
  const u = await db.users.findById(req.session.uid);
  if (!u || !u.can('thread:delete')) return res.sendStatus(403);
  next();
}
app.post('/api/delete-threads', requireAuthForDelete, (req, res) => {
  threadStore.bulkDelete(req.body.ids);
  res.sendStatus(200);
});`,
		patch: `@@
-  app.post('/api/delete-threads', (req, res) => {
-    threadStore.bulkDelete(req.body.ids);
-    res.sendStatus(200);
-  });
+  async function requireAuthForDelete(req, res, next) {
+    if (!req.session || !req.session.uid) return res.sendStatus(401);
+    const u = await db.users.findById(req.session.uid);
+    if (!u || !u.can('thread:delete')) return res.sendStatus(403);
+    next();
+  }
+  app.post('/api/delete-threads', requireAuthForDelete, (req, res) => {
+    threadStore.bulkDelete(req.body.ids);
+    res.sendStatus(200);
+  });`,
		refs: ['OWASP-BrokenAccessControl', 'CWE-693'],
		tags: ['protection-mechanism', 'missing-check', 'authz'],
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
		id: 'CWE-730',
		name: 'OWASP Top Ten 2004 Category A1 - Unvalidated Input',
		lang: 'nodejavascript',
		status: 'Deprecated',
		what: `OWASP Top Ten 2004 A1——未受驗證的輸入（Unvalidated Input）。這是 MITRE 為對應 OWASP 2004 前十名 A1
	而建立的支柱（Pillar）條目，屬已停用（Deprecated）類別，僅保留歷史對映用途，不建議用來做真實弱點的唯一標籤。它
	概括「來自客戶端的輸入沒有任何驗證就被使用」而衍生的整群攔截層弱點——SQL 注入、跨站腳本、命令注入、緩衝區溢位
	等等，範圍橫跨多個完全不同的技術根因。修復必須對症到具體的子條目，例如 CWE-89 SQL 注入、CWE-79 XSS、CWE-78
	命令注入。唯一普遍適用的原則是：把所有外部輸入都當成不受信任，在信任邊界做白名單式驗證，再以最小權限使用。`,
		problem: `// (支柱示例)：把 HTTP query 當成「不需要驗證」直接拼進 SQL，等於 A1 的典型後果
app.get('/api/user', (req, res) => {
  const q = "SELECT * FROM users WHERE name = '" + req.query.name + "'";  // 未驗證即拼入
  res.json(db.all(q));
});`,
		fixed: `// (支柱示例修法)：在邊界驗證＋參數化，杜絕「未驗證輸入」變成執行字串
app.get('/api/user', (req, res) => {
  const name = String(req.query.name || '').slice(0, 64);   // 邊界處先收斂／驗證
  if (!/^[\\w.@-]+$/.test(name)) return res.sendStatus(400);
  res.json(db.prepare('SELECT * FROM users WHERE name = ?').all(name)); // 參數化查詢
});`,
		patch: `@@
  app.get('/api/user', (req, res) => {
-   const q = "SELECT * FROM users WHERE name = '" + req.query.name + "'";
-   res.json(db.all(q));
+   const name = String(req.query.name || '').slice(0, 64);
+   if (!/^[\\w.@-]+$/.test(name)) return res.sendStatus(400);
+   res.json(db.prepare('SELECT * FROM users WHERE name = ?').all(name));
   });`,
		refs: ['OWASP-A1', 'CWE-730'],
		tags: ['unvalidated-input', 'owasp-2004', 'deprecated'],
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
