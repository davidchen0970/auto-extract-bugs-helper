// CWE chunk — category: Session Management.
//   what    : 簡短、繁中、白話+技術描述（(#) 弱點是什麼)
//   problem : 「壞的寫法」程式片段（(#) 問題長怎樣)
//   fixed   : 「修好的寫法」程式片段（(#) 解完會長怎樣)
//   patch   : problem → fixed 的統一 diff 文字（(#) 範例 patch)
//   lang    : 此條範例主力語言，依 CWE 類別選擇
//   status  : Complete | Incomplete | Deprecated
//   refs    : 參考（OWASP / MITRE 等）
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
		what: `關鍵狀態資料被外部控制。把決定流程或安全的「狀態」（結帳金額、授權旗標、
流程步驟、計費等級）存在使用者可控的地方——明文 cookie、隱藏表單欄位、query——
並直接信任它。攻擊者改動這個狀態值（例：把結帳金額改成 1 元、把已完成付款指為 true），
伺服器便照單全收、做出錯誤的安全決策。建議做法是狀態一律留在伺服器端（session／DB）保管。`,
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
		what: `安全決策建立在不可信的輸入上。以用戶可以偽造或射入的資料——例如
X-Forwarded-For 標頭、隱藏表單欄位、車票欄位——直接當作「是否放行／要不要限速／
要信任誰」的依據。攻擊者送出偽造的來源或旗標，就能繞過速率限制、假裝來自白名單 IP。
建議做法是安全決策只用伺服器端蒐集並驗證過的資料，若要取真實 IP 就解析可信的代理層。`,
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
