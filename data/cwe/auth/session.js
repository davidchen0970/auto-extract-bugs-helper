// CWE chunk — category: Session Management.
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
		id: 'CWE-384',
		name: 'Session Fixation',
		lang: 'php',
		status: 'Complete',
		what: `工作階段固定（Session Fixation）。伺服器在登入前就接受使用者可控的 session id，
	而在登入成功後沒有重新產生全新 id。攻擊者可以先把自己的 session id 丟給受害者，
	等受害者用同一個 id 登入後，攻擊者再用同一個 id 就能偽裝成受害者。
	建議做法是登入前不採用客戶端提供的 session id，並在權限升級（登入／取得管理權）時
	一律呼叫 session_regenerate_id(true) 打掉舊 id。`,
		problem: `<?php // 不安全寫法：登入前直接採納用戶送的 PHPSESSID，登入後也不重新產生
session_id($_COOKIE['PHPSESSID'] ?? uniqid());   // 接受使用者可控的 session id
session_start();

if (password_verify($pwd, $row['hash'])) {
    // 沒呼叫 session_regenerate_id()，沿用同一個可被攻擊者先指派的 id
    $_SESSION['uid'] = $row['id'];
}`,
		fixed: `<?php // 安全寫法：不採用外部 session id，登入成功時強制產生全新 id
session_start();

if (password_verify($pwd, $row['hash'])) {
    // 打掉舊 id、丟棄舊 session 資料，讓攻擊者預設的 id 完全失效
    session_regenerate_id(true);
    $_SESSION['uid'] = $row['id'];
}`,
		patch: `@@
-  session_id($_COOKIE['PHPSESSID'] ?? uniqid());   // 接受使用者可控的 session id
-  session_start();
-
-  if (password_verify($pwd, $row['hash'])) {
-      // 沒呼叫 session_regenerate_id()，沿用同一個可被攻擊者先指派的 id
-      $_SESSION['uid'] = $row['id'];
-  }
+  session_start();
+
+  if (password_verify($pwd, $row['hash'])) {
+      // 打掉舊 id、丟棄舊 session 資料，讓攻擊者預設的 id 完全失效
+      session_regenerate_id(true);
+      $_SESSION['uid'] = $row['id'];
+  }`,
		refs: ['OWASP-SessionFixation', 'CWE-384'],
		tags: ['session-fixation', 'session', 'regenerate-id'],
	},
	{
		id: 'CWE-488',
		name: 'Exposure of Data Element to Wrong Session',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `把資料元素暴露給「錯誤的工作階段」（Exposure of Data Element to Wrong Session）。系統在建立或切換 session
	時，把原先屬於某個 session 專屬的資料元素放到了會被另一場 session 誤讀的位置——例如用一個程式全域變數存放「目前
	登入者」，於是同時開兩個瀏覽器／帳號時雙方互踩同一份資料；或私有的購物車、角色、胸章被寫進以「共用常數」當 key
	的全域 hash，讓所有 session 都能互相讀到。攻擊者只要在同一台裝置並存登入，或用共用的後端暫存（memcache/glob），
	就能把別人的資料誤接回自己身上，造成身分混淆與越權存取。正確做法是每筆 session 私有資料都嚴格以唯一、不衝突的
	session 識別為 key，由伺服器端的 session store 分隔保存，絕不把個別 session 的私有元素放進共用可互相讀取的區。`,
		problem: `// 不安全寫法：把「目前登入者」存成模組全域變數，並場 session一起跑就互竊資料
let currentUid = null;          // 全域！不是每個 session 專屬
let currentCart = null;
app.use((req, res, next) => {
  currentUid = req.query.debug_uid || null;      // 還被 query 直接控制
  currentCart = db.carts.get(currentUid);
  next();
});
app.post('/api/checkout', (req, res) => {
  // 讀到的 currentCart 可能是「別人最後一次設定」的那份
  charge(currentUid, currentCart);
});`,
		fixed: `// 安全寫法：session 私有資料一律放進伺服器端、以該 session 唯一識別為 key
app.use(session({ store: redisStore, secret, cookie: { httpOnly: true } }));
app.post('/api/checkout', (req, res) => {
  if (!req.session || !req.session.uid) return res.sendStatus(401);   // 身分來自 session，非 query
  const cart = db.carts.get(req.session.uid);          // 以 session 綁定的 uid 讀自己那份
  charge(req.session.uid, cart);
});`,
		patch: `@@
-  let currentUid = null;
-  let currentCart = null;
-  app.use((req, res, next) => {
-    currentUid = req.query.debug_uid || null;
-    currentCart = db.carts.get(currentUid);
-    next();
-  });
   app.post('/api/checkout', (req, res) => {
-    charge(currentUid, currentCart);
+    if (!req.session || !req.session.uid) return res.sendStatus(401);
+    const cart = db.carts.get(req.session.uid);
+    charge(req.session.uid, cart);
   });`,
		refs: ['OWASP-SessionManagement', 'CWE-488'],
		tags: ['session', 'wrong-session', 'shared-state'],
	},
	{
		id: 'CWE-613',
		name: 'Insufficient Session Expiration',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `工作階段不會（或不夠快地）過期。沒有設定 maxAge、設成一年、或沒有 idle timeout，
	等於使用者「永遠在線」，被偷走的 session id 也能無限重用。
	建議做法是設定夠短的有效期（absolute/absoluteTimeout），並加入不活動逾時與 rolling renewal，
	讓憑證與 session 都要在可接受時間內確實失效，敏感刪除時也要主動 session.destroy()。`,
		problem: `// 不安全寫法：cookie maxAge 長達一年，等同永不停期的 session，偷到的 sid 能狂用
const express = require('express');
const session = require('express-session');
const app = express();

app.use(session({
  secret: super_safe_secret,
  cookie: { maxAge: 365 * 24 * 3600 * 1000 },   // 一年！token 洩漏後可被重放一整年
}));
// 也沒有 idle inactive timeout，放著不管也永遠保持在線`,
		fixed: `// 安全寫法：短有效期 + 不活動逾時 + rolling，session 確實會到期
app.use(session({
  secret: super_safe_secret,
  cookie: {
    maxAge: 30 * 60 * 1000,        // 30 分鐘 absolute 上限
    httpOnly: true, secure: true,  // 並用 HttpOnly + Secure 減少洩漏面
  },
  rolling: true,                   // 每次請求延長（連帶更新過期時間，避免「永不活動」陷阱）
  name: 'sid',                    // 別用預設的 connect.sid 當公開名
}));

setInterval(() => db.sessions.deleteMany({ expires_at: { $lt: Date.now() } }), 60e3);`,
		patch: `@@
-  app.use(session({
-    secret: super_safe_secret,
-    cookie: { maxAge: 365 * 24 * 3600 * 1000 },   // 一年！token 洩漏後可被重放一整年
-  }));
-  // 也沒有 idle inactive timeout，放著不管也永遠保持在線
+  app.use(session({
+    secret: super_safe_secret,
+    cookie: {
+      maxAge: 30 * 60 * 1000,        // 30 分鐘 absolute 上限
+      httpOnly: true, secure: true,  // 並用 HttpOnly + Secure 減少洩漏面
+    },
+    rolling: true,                   // 每次請求延長（連帶更新過期時間，避免「永不活動」陷阱）
+    name: 'sid',                    // 別用預設的 connect.sid 當公開名
+  }));
+  setInterval(() => db.sessions.deleteMany({ expires_at: { $lt: Date.now() } }), 60e3);`,
		refs: ['OWASP-SessionManagement', 'CWE-613'],
		tags: ['session-expiration', 'timeout', 'idle-timeout'],
	},
	{
		id: 'CWE-642',
		name: 'External Control of Critical State Data',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `關鍵狀態資料被外部控制（External Control of Critical State Data）。系統把「跟安全高度相關的使用者狀態或
	系統自身狀態」放在未授權者可存取的位址——明文 Cookie、隱藏表單欄位、輸入參數、環境變數、資料庫紀錄、
	設定檔——並直接信任它。既有欄值決定安全決策（結帳金額、授權旗標、流程步驟、計費等級）。只要攻擊者
	能改動這個值，程式工程師又沒料到它會變，就會照單全收做出錯的安全決策：可借此繞過驗證、抬高權限、
	把本就敏感的狀態值洩漏給客戶端、或塞進違反預期的值把流程打到當機。修法是讓狀態與敏感資料「只放
	伺服器端」，由系統自己明確無歧義地追蹤本身與使用者的狀態狀態轉移，不許使用者繞過正當動作直接改；真要在
	客戶端暫存，就要加密並以 HMAC 這類訊息鑑別碼保證完整，不被竄改。`,
		problem: `// 不安全寫法：把「是否已付款」與「金額」存在前端可控的 cookie，改值就賴帳
const cart = JSON.parse(req.cookies.cart || '{}');   // 隱藏表單 / cookie 由用戶掌控
if (cart.paid === true) {                            // 攻擊者只需把 paid 設成 true
  shipOrder(req.body.orderId, cart.amount);          // 而且連金額都是 client 給的
  return res.sendStatus(200);
}`,
		fixed: `// 安全寫法：付款狀態與金額只存在伺服器端 DB，由付款閘道回呼來更新
db.orders.findById(req.body.orderId, (e, order) => {
  if (e || !order) return res.sendStatus(404);
  if (!order.paid) return res.status(402).json({ error: 'not paid' });   // 以 DB 為準
  shipOrder(order._id, order.amount);                // 金額取自已驗證的 DB 紀錄
  res.sendStatus(200);
});`,
		patch: `@@
-  const cart = JSON.parse(req.cookies.cart || '{}');   // 隱藏表單 / cookie 由用戶掌控
-  if (cart.paid === true) {                            // 攻擊者只需把 paid 設成 true
-    shipOrder(req.body.orderId, cart.amount);          // 而且連金額都是 client 給的
-    return res.sendStatus(200);
-  }
+  db.orders.findById(req.body.orderId, (e, order) => {
+    if (e || !order) return res.sendStatus(404);
+    if (!order.paid) return res.status(402).json({ error: 'not paid' });   // 以 DB 為準
+    shipOrder(order._id, order.amount);                // 金額取自已驗證的 DB 紀錄
+    res.sendStatus(200);
+  });`,
		refs: ['OWASP-SessionManagement', 'CWE-642'],
		tags: ['client-side-state', 'critical-state', 'hidden-field'],
	},
	{
		id: 'CWE-807',
		name: 'Reliance on Untrusted Inputs in a Security Decision',
		lang: 'python',
		status: 'Complete',
		what: `在安全決策上依賴不可信的輸入（Reliance on Untrusted Inputs in a Security Decision）。系統的安全性機制
	正是「建立在某一輸入的存在或其值上」——例如以 X-Forwarded-For 標頭、隱藏表單欄位、Cookie 旗標、來源 IP、
	或 query 參數來決定要不要放行、要不要限速、要信任誰。開發者常誤以為這類輸入「改不了」，其實攻擊者用自製客戶端或
	其他手法就能改，而且改了往往不被察覺。把驗證／授權這種安全決策建在它的值上，攻擊者就能繞過整個保護機制：
	偽造來源或送出過關的旗標即可冒充、抬高權限、外流或竄改敏感資料，甚至讓系統當機或執行任意程式碼。修法是
	狀態全部留在伺服器端、安全決策不依賴任何送進來的輸入，非存客戶端不可就加密＋HMAC 驗完整性。`,
		problem: `# 不安全寫法：用前端可隨意偽造的 X-Forwarded-For 當來源決定「要不要限速」
from flask import request

def get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0]

def rate_limit_key():
    ip = get_client_ip()
    if ip in TRUSTED_IPS:          # 安全決策：是否放行，但 ip 完全由請求端指定
        return 'trusted'           # curl 加個 -H "X-Forwarded-For: 10.0.0.1" 就繞過了
    return ip`,
		fixed: `# 安全寫法：真實來源只能由可信的反向代理設定，伺服器端不信任任意外部值
from flask import request

def client_ip():
    # 只在受信任反向代理之後才讀取 XFF，否則一律用 TCP socket 對端位址
    return request.remote_addr if not BEHIND_TRUSTED_PROXY \\
        else trust_proxy(request.headers.get('X-Forwarded-For'))

def rate_limit_key():
    ip = client_ip()
    # 決定限速與否只依伺服器端取得的 ip，外掛的任何標頭都不會影響決策
    return 'trusted' if ip in TRUSTED_IPS else ip`,
		patch: `@@
-  def get_client_ip():
-      return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0]
-
-  def rate_limit_key():
-      ip = get_client_ip()
-      if ip in TRUSTED_IPS:          # 安全決策：是否放行，但 ip 完全由請求端指定
-          return 'trusted'           # curl 加個 -H "X-Forwarded-For: 10.0.0.1" 就繞過了
-      return ip
+  def client_ip():
+      # 只在受信任反向代理之後才讀取 XFF，否則一律用 TCP socket 對端位址
+      return request.remote_addr if not BEHIND_TRUSTED_PROXY \\
+          else trust_proxy(request.headers.get('X-Forwarded-For'))
+
+  def rate_limit_key():
+      ip = client_ip()
+      # 決定限速與否只依伺服器端取得的 ip，外掛的任何標頭都不會影響決策
+      return 'trusted' if ip in TRUSTED_IPS else ip`,
		refs: ['OWASP-DataValidation', 'CWE-807'],
		tags: ['untrusted-input', 'security-decision', 'trust-boundary'],
	},
];
