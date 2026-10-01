// CWE chunk — category: Authentication Bypass & Alternative Path / Trust.
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
		id: 'CWE-288',
		name: 'Authentication Bypass Using an Alternate Path',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `經由另一條路徑或通道繞過身分驗證（Authentication Bypass Using an Alternate Path or Channel）。
	受保護的動作（例如 DELETE 訂單）明明要求驗證，卻另有一條替代路徑或通道完全不驗證就放行——
	像是多了個未保護的 GET 對照端點、路徑大小寫歧義、被重導向到的別名 URL、或一個標記成
	/internal 卻對外可見的入口，甚至是前門程式之外可直接被呼叫的支援程式。攻擊者只要改走這條旁門左道，
	就能繞過保護機制、以等同受保護功能的權限取得關鍵資料。因為問題出在受保護入口之外還另開了後門，
	光在主端點補驗證無法治本。修法是讓所有存取都收攏到唯一漏斗（single choke point）通過，
	每筆請求在抵達資源前都要檢查呼叫者是否確有此權限，任何通道都不允許略過。`,
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
		id: 'CWE-289',
		name: 'Authentication Bypass by Alternate Name',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `以「替代名稱」繞過身分驗證（Authentication Bypass by Alternate Name）。驗證把「使用者名稱」一路當成身分的
	唯一錨點，卻只對其中一種名稱寫法做檢查，而實際查詢或比對身分時接受的又是另一種寫法。例如登入封鎖只比對
	「使用者名稱」欄位，但後端同時以 mail 或 user_alias 當可登入的別名；或對大小寫、尾隨空白、Unicode 正規化的變體
	處理前後不一致。於是攻擊者用同一帳號的「另一種名字」（別名、大小寫變體）送進授權邏輯，就繞過了以「名稱字串」為
	基準建立的封鎖。正確做法是指定單一、不可變、且已徹底正規化（大小寫、空白、編碼都統一）的身份識別子，所有驗證與
	實際查詢一致使用同一個來源名稱，不給第二種名字的旁路。`,
		problem: `// 不安全寫法：封鎖名單比對「username」，但唯一可以登入的起點卻又可吃 mail
const BANNED = ['mallory'];
function blocked(login) {
  return BANNED.some((b) => b === login);          // 只比對會傳給它的那一種寫法
}
app.post('/login', (req, res) => {
  const login = req.body.alias || req.body.username;     // 攻擊者改帶 name=mallory@x.com 就不同字串
  if (blocked(login)) return res.sendStatus(403);      // 但底下照樣靠任意 login 欄位去查
  const user = db.users.where({ username: login }).or({ email: login }).first(); // 兩支 alias 都能過
  ...issueSession(user);
});`,
		fixed: `// 安全寫法：鎖定單一被正規化的主識別子，驗證與查詢都用同一個來源、同一組規則
function canonical(login) {
  if (!login) return null;
  return String(login).trim().toLowerCase();             // 大小寫／空白先統一
}
async function principal(login, type) {
  if (type !== 'username') return null;                 // 只接受一種身份辨識方式
  return db.users.findByUsername(canonical(login));
}
app.post('/login', (req, res) => {
  const u = await principal(canonical(req.body.username), 'username');
  if (!u || BANNED.some((b) => canonical(b) === canonical(u.username)))
    return res.sendStatus(403);
  verifyPassword(u, req.body.password);
});`,
		patch: `@@
-  const BANNED = ['mallory'];
-  function blocked(login) {
-    return BANNED.some((b) => b === login);
-  }
-  app.post('/login', (req, res) => {
-    const login = req.body.alias || req.body.username;
-    if (blocked(login)) return res.sendStatus(403);
-    const user = db.users.where({ username: login }).or({ email: login }).first();
-    ...issueSession(user);
-  });
+  function canonical(login) {
+    if (!login) return null;
+    return String(login).trim().toLowerCase();
+  }
+  async function principal(login, type) {
+    if (type !== 'username') return null;
+    return db.users.findByUsername(canonical(login));
+  }
+  app.post('/login', async (req, res) => {
+    const u = await principal(canonical(req.body.username), 'username');
+    if (!u || BANNED.some((b) => canonical(b) === canonical(u.username)))
+      return res.sendStatus(403);
+    verifyPassword(u, req.body.password);
+  });`,
		refs: ['OWASP-Auth', 'CWE-289'],
		tags: ['auth-bypass', 'alternate-name', 'alias'],
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
		id: 'CWE-294',
		name: 'Authentication Bypass by Capture-replay',
		lang: 'python',
		status: 'Complete',
		what: `以擷取-重放（Capture-replay）繞過身分驗證。身分驗證依賴的憑證或協定消息本身可以被攻擊者離線攔截，之後
	原封不動地以假主體的身分重放一遍而照樣通過——通常是因為單次通行碼／挑戰沒有綁定會話與隨機性，或身分交換仰賴可被
	側錄的固定料（固定 PIN、被重播的 HMAC／憑證、未綁客戶端的通行碼）。攻擊者不必知道秘密內容，只要錄手一段成功交換便能
	重現。正確做法是在每一輪驗證導入「不可重用」的隨機挑戰（nonce）與時間戳，把回應跟當下的挑戰、時序、會話上下文綁在
	一起，並在驗證端記錄已用的 nonce、拒絕重複者，從根切斷重放。`,
		problem: `# 不安全寫法：挑戰值固定、回應不含亂數，攔截到就能原封重放換身分
def handshake(peer):
    # challenge 每次都一樣，回應也不綁當次隨機性
    token = digest(PEER_KEY)               # 可被側錄的固定 result
    result = peer.respond(token)
    return result == expect(PEER_KEY)      # 錄一次就能 replay`,
		fixed: `# 安全寫法：每輪都發新 random nonce，回應綁定 nonce 且驗證端記下並拒絕重複
import secrets, hmac
seen = set()
def handshake(peer):
    nonce = secrets.token_bytes(16)        # 每次新的不可重用挑戰
    if nonce in seen or has_expired(nonce):
        return False
    seen.add(nonce)                      # 用過的就拒絕再重放
    msg = nonce + b'|' + peer.id()
    mac = hmac.new(SEED, msg, 'sha256').digest()     # MAC 綁定當次 nonce
    return hmac.compare_digest(peer.respond(mac), mac)`,
		patch: `@@
  def handshake(peer):
-     token = digest(PEER_KEY)
-     result = peer.respond(token)
-     return result == expect(PEER_KEY)
+     nonce = secrets.token_bytes(16)
+     if nonce in seen or has_expired(nonce):
+         return False
+     seen.add(nonce)
+     msg = nonce + b'|' + peer.id()
+     mac = hmac.new(SEED, msg, 'sha256').digest()
+     return hmac.compare_digest(peer.respond(mac), mac)`,
		refs: ['OWASP-Replay', 'CWE-294'],
		tags: ['capture-replay', 'replay', 'nonce'],
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
		id: 'CWE-305',
		name: 'Authentication Bypass by Primary Weakness',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `因「主要機制本身存在弱點」而繞過身分驗證（Authentication Bypass by Primary Weakness）。系統本來設置了一套
	主要的身分驗證機制，卻因這套機制在根本處就脆弱，以致可整體繞過——例如伺服器對輸入只做「部分比對」（只查長度不查
	內容、只查結尾不查開頭）、把驗證身分的密碼與不該混淆的欄位攪在一起、或驗證流程前開了不該開的通道，使未驗證者仍能
	抵達已驗證資源。因為問題在主的驗證邏輯，靠外圍補丁無法根治。正確做法是主驗證機制整體重寫：採「完整比對＋白名單」，
	身分判定由伺服器端以密碼驗證與 session 共同完成，並確保不存在任何跳過主驗證即可觸及的受保護資源。`,
		problem: `// 不安全寫法：驗證只比「結尾」，且「已登入」旗標可由 query 決定，主要機制故有根本洞
app.get('/api/account', (req, res) => {
  const pw = req.query.pw || '';
  if (pw.endsWith('secret')) return serveAccount(req);      // 只查結尾，{x}secret 也算過
  if (req.query.logged_in === '1') return serveAccount(req); // 再者還可直接聲明已登入
  res.sendStatus(403);
});`,
		fixed: `// 安全寫法：主要驗證改為完整比對、以伺服器端 session 為憑，不存在旁路
app.post('/api/login', async (req, res) => {
  const u = await db.users.findByName(req.body.username);
  if (!u || !(await bcrypt.compare(req.body.password, u.hash)))
    return res.sendStatus(403);                       // 完整密碼比對(不是尾碼)
  req.session.uid = u.id;
  res.sendStatus(204);
});
app.get('/api/account', async (req, res) => {
  if (!req.session || !req.session.uid) return res.sendStatus(403); // 只看 session
  res.json(await db.users.profile(req.session.uid));
});`,
		patch: `@@
-  app.get('/api/account', (req, res) => {
-    const pw = req.query.pw || '';
-    if (pw.endsWith('secret')) return serveAccount(req);
-    if (req.query.logged_in === '1') return serveAccount(req);
-    res.sendStatus(403);
-  });
+  app.post('/api/login', async (req, res) => {
+    const u = await db.users.findByName(req.body.username);
+    if (!u || !(await bcrypt.compare(req.body.password, u.hash)))
+      return res.sendStatus(403);
+    req.session.uid = u.id;
+    res.sendStatus(204);
+  });
+  app.get('/api/account', async (req, res) => {
+    if (!req.session || !req.session.uid) return res.sendStatus(403);
+    res.json(await db.users.profile(req.session.uid));
+  });`,
		refs: ['OWASP-Auth', 'CWE-305'],
		tags: ['auth-bypass', 'primary-weakness', 'partial-compare'],
	},
	{
		id: 'CWE-374',
		name: 'Passing Mutable Objects to an Untrusted Method',
		lang: 'java',
		status: 'Complete',
		what: `把可變（mutable）物件交傳給不受信任的方法（Passing Mutable Objects to an Untrusted Method）。產品在把工作
	交給不受信任的程式碼（外掛、擴充、非同等的服務或外包元件）時，直接把令它仍然可被修改的內部物件引用交出去。由於物件
	可變，被交的一方可以反向改動呼叫者仍一直視為可信的內部狀態，或從該物件的巢狀欄位中竊走不該被看到的資料——即使本意
	只是要給對方「唯讀」或某一欄。正確做法是在信任邊界處「複製再交」：只把可變狀態複製成副本或序列化後的新實體交出去，
	或著窄化成唯讀介面／防禦性拷貝後才傳給不可信區域，別讓活生生的內部參照直接落進他人手中。`,
		problem: `// 不安全寫法：把帶有內部變異能力的 ArrayList 原樣交給第三方 plug-in
public void notifyAuditors(Plugin p) {
    // audits 同時也是內部審核清單；直接交出去，plug-in 就能 add/remove 篡改內部狀態
    p.onAudit(audits);
}
void onAudit(List<String> list) {
    list.clear();            // 第三方拿到的就是内部的可變引用，一 call 就清空内部清單
    list.addAll(fake);
}`,
		fixed: `// 安全寫法：交付前做防禦性拷貝，對方動的副本，動不到內部狀態
public void notifyAuditors(Plugin p) {
    List<String> immutableCopy = Collections.unmodifiableList(new ArrayList<>(audits));
    p.onAudit(immutableCopy);          // plug-in 只能唯讀看，連清空都拋 UnsupportedOperationException
}
void onAudit(List<String> list) {
    // list 已是快照且不可改：this.audits 完全不受影響
    summarize(list);
}`,
		patch: `@@
   public void notifyAuditors(Plugin p) {
-      p.onAudit(audits);
+      List<String> immutableCopy = Collections.unmodifiableList(new ArrayList<>(audits));
+      p.onAudit(immutableCopy);
   }
   void onAudit(List<String> list) {
-      list.clear();
-      list.addAll(fake);
+      summarize(list);
   }`,
		refs: ['OWASP-DataValidation', 'CWE-374'],
		tags: ['mutable-object', 'trusted-boundary', 'defensive-copy'],
	},
	{
		id: 'CWE-501',
		name: 'Trust Boundary Violation',
		lang: 'python',
		status: 'Complete',
		what: `信賴界限違反（Trust Boundary Violation）。程式把「可信」與「不可信」之間的界線畫錯，或處理資料時讓不可信的
	資料直接「升級」成可信區而被使用，卻沒任何過渡。信賴界限的用途就是讓資料安全地由不可信側跨到可信側——過程需要驗證、
	消毒與正常化。若界線畫在錯誤位置、或只靠一個不檢查的內建轉換（直接把未消毒輸入放行給敏感 API），等同讓攻擊者把注入料
	當成已經「受信任」的輸入用於決策與執行。正確做法是對每個資料標明其信賴來源，界定一個真實的檢查點（驗證＋消毒），
	任何跨越界線的資料都要先在該處正規化、捨弃非法內容，之後才准進入可信區。`,
		problem: `# 不安全寫法：界線畫錯位置——外部 query 直接當成「已受信任」輸入，沒有檢查點
def lookup(req):
    name = req.args['name']                       # 不可信側，直接進入可信執行區
    cmd = ["grep", name, "/var/db/index.txt"]   # 沒有驗證／消毒即拿去做決策與執行
    return subprocess.check_output(cmd)`,
		fixed: `# 安全寫法：在邊界設立檢查點，驗證＋黑名單/白名單消毒後才升為可信輸入
import re
def lookup(req):
    raw = req.args.get('name', '')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', raw):  # 邊界白名單驗證
        raise ValueError('untrusted name rejected at boundary')
    name = raw                                        # 才承認它是可信輸入
    return grep_subprocess(name, "/var/db/index.txt")   # 且以參數化方式使用`,
		patch: `@@
   def lookup(req):
-      name = req.args['name']
-      cmd = ["grep", name, "/var/db/index.txt"]
-      return subprocess.check_output(cmd)
+      raw = req.args.get('name', '')
+      if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', raw):
+          raise ValueError('untrusted name rejected at boundary')
+      name = raw
+      return grep_subprocess(name, "/var/db/index.txt")`,
		refs: ['OWASP-InputValidation', 'CWE-501'],
		tags: ['trust-boundary', 'untrusted-input', 'validation'],
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
		refs: ['OWASP-FrontEnd Security', 'CWE-602'],
		tags: ['client-side-security', 'gui', 'server-side-enforcement'],
	},
];
