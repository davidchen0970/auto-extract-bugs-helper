// CWE chunk — category: Security Misconfiguration & Defaults (Node / Python / shell).
// One chunk = one category, <= 5 entries. Every entry:
//   what    : 簡短、繁中、白話+技術描述（(#) 弱點是什麼)
//   problem : 「壞的寫法」程式片段（(#) 問題長怎樣)
//   fixed   : 「修好的寫法」程式片段（(#) 解完會長怎樣)
//   patch   : problem → fixed 的統一 diff 文字（(#) 範例 patch)
//   lang    : 此條範例主力語言，依 CWE 類別選擇
//   status  : Complete | Incomplete | Deprecated
//   refs    : 參考（MITRE / SEI CERT 等）
//   tags    : 英文搜尋標籤
export default [
	{
		id: 'CWE-15',
		name: 'External Control of System or Configuration Setting',
		lang: 'node',
		status: 'Complete',
		what: `「外部可控制系統或組態設定」。程式把一個會影響安全行為的組態開關——例如是否開啟
除錯模式、feature flag、除錯輸出、CORS 許可名單、或密碼重試次數——直接用外部輸入（query、body、
環境變數、request header）來覆寫，而沒有把「能改變安全設定的值」限制在可信來源。攻擊者只要把
這些開關改掉，就能關閉必須存在的保護（像是關掉驗證、打開詳細錯誤、或把自己加進許可名單），
讓原本的安全性設定形同虛設。修法是只用回條中受信賴的管理端設定來決定組態，並拒絕任何直接由
外部輸入帶進來的覆寫。`,
		problem: `// 不安全寫法：直接用 query 參數蓋掉組態開關,外部可任意關閉重要保護
const express = require('express');
const app = express();

app.get('/api/data', (req, res) => {
  // req.query.debug 由使用者控制:傳 ?debug=1 就輸出敏感詳細資料
  const debug = req.query.debug === '1' || config.debug;
  const data = fetchSensitive(req.user.id);
  if (debug) return res.json({ data, stack: data.stackTrace, secret: config.dbSecret });
  res.json(data);
});`,
		fixed: `// 安全寫法：所有組態一律來自啟動時載入、可受審核的設定檔,傳進來的限制在它
const express = require('express');
const app = express();

// config 於啟動時自環境/設定檔載入一次,之後完全由伺服器端控制
const { debug, data } = loadConfig(process.env.CONFIG_PATH);

app.get('/api/data', (req, res) => {
  const result = fetchSensitive(req.user.id);
  // 永遠不因外部 query 改變是否附帶機敏欄位
  if (debug) return res.json({ data: result, stack: result.stackTrace });
  res.json(result);
});`,
		patch: `@@
  app.get('/api/data', (req, res) => {
-  // req.query.debug 由使用者控制:傳 ?debug=1 就輸出敏感詳細資料
-  const debug = req.query.debug === '1' || config.debug;
+  const { debug, data } = loadConfig(process.env.CONFIG_PATH);
   const data = fetchSensitive(req.user.id);
-  if (debug) return res.json({ data, stack: data.stackTrace, secret: config.dbSecret });
+  if (debug) return res.json({ data: result, stack: result.stackTrace });
   res.json(data);
 });`,
		refs: ['CWE-15'],
		tags: ['config', 'misconfiguration', 'feature-flag', 'external-input'],
	},
	{
		id: 'CWE-16',
		name: 'Configuration', 
		lang: 'node',
		status: 'Complete',
		what: `部署了不安全的預設組態（Configuration / 預設值把保護長期關閉）。系統、框架或函式庫
被設定成「開箱即不安全」的預設值,例如把除錯模式、詳細錯誤訊息、CORS 全放行（*）、關閉登入驗證、
或帳號使用已知的預設 root 密碼就上線。因為這些開關一旦放上去很少有人去動,等於把保護「預設就關著」,
讓任何連得上的人都取得管理權或偵錯輸出。修法是以「安全」為出廠預設：除錯與詳細錯誤只在明確開啟時
存在、CORS 白名單要明確列出可信任的來源、管理帳號必須在上線時就強制修改預設密碼。`,
		problem: `// 不安全寫法：出廠就 CORS 全放行 + 開啟詳細錯誤 + 預設 root 密碼,預設值就是洞
const express = require('express');
const app = express();

const cors = require('cors');

// 預設全放行:任何來源都能跨域讀取 => 結合 cookie 授權就是帳號裸露
app.use(cors({ origin: true, credentials: true }));
app.use((err, req, res, next) => res.status(500).json(err.stack)); // 預設印出整條堆疊

// 帳戶出廠就用公開的預設密碼,登入永遠「通過」
const ADMIN = { user: 'root', pass: 'root' };
app.post('/login', (req, res) => {
  if (req.body.user === ADMIN.user && req.body.pass === ADMIN.pass) {
    res.send('admin ok'); // 預設密碼沒被要求修改
  }
});`,
		fixed: `// 安全寫法：預設漂閉鎖；CORS 白名單、錯誤不洩內部、登入後強制改預設密碼
const express = require('express');
const app = express();
const cors = require('cors');

// 只允許明確列出的信任來源,不允許 credentials+ 通配
app.use(cors({ origin: ['https://app.example.com'], credentials: true }));
app.use((err, req, res, next) => res.status(500).json({ error: 'internal error' }));

const bcrypt = require('bcrypt');
// 上線流程第一步就是設密碼;根本不存「預設 root 密碼」
const adminHash = process.env.ADMIN_HASH; // 由 init 流程導入的唯一密碼 hash
app.post('/login', async (req, res) => {
  const ok = await bcrypt.compare(req.body.pass, adminHash);
  res.send(ok ? 'admin ok' : 'forbidden');
});`,
		patch: `@@
-app.use(cors({ origin: true, credentials: true }));
-app.use((err, req, res, next) => res.status(500).json(err.stack)); // 預設印出整條堆疊
+app.use(cors({ origin: ['https://app.example.com'], credentials: true }));
+app.use((err, req, res, next) => res.status(500).json({ error: 'internal error' }));
-
-// 帳戶出廠就用公開的預設密碼,登入永遠「通過」
-const ADMIN = { user: 'root', pass: 'root' };
-app.post('/login', (req, res) => {
-  if (req.body.user === ADMIN.user && req.body.pass === ADMIN.pass) {
-    res.send('admin ok'); // 預設密碼沒被要求修改
-  }
-});
+const bcrypt = require('bcrypt');
+const adminHash = process.env.ADMIN_HASH;
+app.post('/login', async (req, res) => {
+  const ok = await bcrypt.compare(req.body.pass, adminHash);
+  res.send(ok ? 'admin ok' : 'forbidden');
+});`,
		refs: ['CWE-16'],
		tags: ['default-misconfiguration', 'insecure-defaults', 'cors', 'verbose-error'],
	},
	{
		id: 'CWE-313',
		name: 'Cleartext Storage of Sensitive Information in a File or on Disk',
		lang: 'python',
		status: 'Complete',
		what: `以明文把機敏感性資訊存進檔案或磁碟。程式拿到一筆 key、token、密碼或 .env 內容時,
直接以可讀的純文字寫進檔案,既不加密也不設定私有權限。落盤的明文只要檔案被其他人讀取（開到共用的
備份、被目錄列出、被網頁靜態與誤外洩、或是磁碟被偷走）就會整段裸漏,等於把機密持續性地留在磁碟上。
修法應把機密寫到專責的密鑰/密碼管理儲存並加密、在存檔時使用作業系統的私有權限（0600, 且放在使用者
專屬目錄）,並避免任何程式將機密以明文落到一般資料檔。`,
		problem: `# 不安全寫法：把呼叫 API 取得的 token 以明文 .env 落盤,也不設權限 => 整段裸漏
import os, requests

def refresh_token():
    r = requests.post('https://idp/oauth/token',
                      json={'grant_type': 'client_credentials',
                            'client_id': os.environ['CLIENT_ID'],
                            'client_secret': os.environ['CLIENT_SECRET']})
    token = r.json()['access_token']
    # 明文 + 預設權限(通常是 0644)直接寫到家目錄下的 .docker-token
    with open(os.path.expanduser('~/.docker-token'), 'w') as f:
        f.write(token)       # 磁碟上就是一段任何人都能讀的明文`,
		fixed: `# 安全寫法：機密不落明文;要留就用 0600 私有權限並限定於使用者專屬目錄
import hashlib, os
from pathlib import Path

def store_secret(token):
    # 放在使用者私有目錄, o600 只允許本人讀寫;內容以環境變數方式交由 runtime 注入
    p = Path(os.path.expanduser('~/.config/myapp/token'))
    p.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(p.parent, 0o700)
    p.touch(mode=0o600, exist_ok=True)
    p.write_text(token)
    os.chmod(p, 0o600)        # 明確私有權限;且不放進一般資料目錄`,
		patch: `@@
-    token = r.json()['access_token']
-    # 明文 + 預設權限(通常是 0644)直接寫到家目錄下的 .docker-token
-    with open(os.path.expanduser('~/.docker-token'), 'w') as f:
-        f.write(token)       # 磁碟上就是一段任何人都能讀的明文
+    p = Path(os.path.expanduser('~/.config/myapp/token'))
+    p.parent.mkdir(parents=True, exist_ok=True)
+    os.chmod(p.parent, 0o700)
+    p.touch(mode=0o600, exist_ok=True)
+    p.write_text(token)
+    os.chmod(p, 0o600)        # 明確私有權限;且不放進一般資料目錄`,
		refs: ['CWE-313', 'SEI CERT'],
		tags: ['cleartext-storage', 'token', 'secrets', 'chmod', 'plaintext'],
	},
	{
		id: 'CWE-656',
		name: 'Reliance on Security Through Obscurity',
		lang: 'python',
		status: 'Complete',
		what: `把「安全」建立在保密細節上（Security Through Obscurity）。開發者以為只要把關卡擺在「別人
不知道」的地方就算保護：例如管理後台藏在一串難猜的網址、把檢查邏輯刻意寫得晦澀難讀、用自己發明的
混淆/自訂編碼藏起密碼,或以為「錯綜複雜就難被繞過」。真正的攻擊者靠掃描、逆向、側錄就能找出這些
隱藏點,一旦那個「祕密點」被拆穿,整個機制便完全失效;而且混淆往往伴隨不該有的能力洩露（例如把
後台權限綁在只要猜對路徑就能登入,沒有真正的驗證）。修法是用真正的存取控管──認證、授權、
加密、APACL──當做唯一防線,而不是指望程式碼或資源「藏在哪裡」不被發現。`,
		problem: `# 不安全寫法：管理功能只靠「一打就中的神秘路徑」開啟,沒有真正的驗證 => 純靠保密
import os
from flask import Flask, request, session

app = Flask(__name__)

ADMIN_PATH = '/verysecret-9x7k/admin'   # 只要猜到這個網址,不需要憑證就能進後台

@app.get('/verysecret-9x7k/admin')
def admin():
    # 沒有任何登入;路徑本身被當成「通行令牌」,用「不知道的人找不到」當作防線
    return 'secret admin panel: {0}'.format(os.environ.get('DB_DSN'))`,
		fixed: `# 安全寫法：後台以真正的認證+授權當唯一防線,路徑只是入口、安全性不依賴它
import os
from flask import Flask, request, session, abort
from functools import wraps

app = Flask(__name__)

def require_admin(f):
    @wraps(f)
    def wrapped(*a, **k):
        if not session.get('uid'):
            return abort(401)            # 沒有登入一律拒絕
        if session.get('role') != 'admin':
            return abort(403)            # 角色不符也拒絕
        return f(*a, **k)
    return wrapped

@app.get('/admin')
@require_admin                 # 認證 + 授權是唯一的保護,不指望網址難猜
def admin():
    return 'admin panel: {0}'.format(os.environ.get('DB_DSN'))`,
		patch: `@@
-ADMIN_PATH = '/verysecret-9x7k/admin'   # 只要猜到這個網址,不需要憑證就能進後台
-
-@app.get('/verysecret-9x7k/admin')
-def admin():
-    # 沒有任何登入;路徑本身被當成「通行令牌」,用「不知道的人找不到」當作防線
-    return 'secret admin panel: {0}'.format(os.environ.get('DB_DSN'))
+def require_admin(f):
+    @wraps(f)
+    def wrapped(*a, **k):
+        if not session.get('uid'):
+            return abort(401)
+        if session.get('role') != 'admin':
+            return abort(403)
+        return f(*a, **k)
+    return wrapped
+
+@app.get('/admin')
+@require_admin                 # 認證 + 授權是唯一的保護,不指望網址難猜
+def admin():
+    return 'admin panel: {0}'.format(os.environ.get('DB_DSN'))`,
		refs: ['CWE-656', 'OWASP-STM'],
		tags: ['security-through-obscurity', 'obfuscation', 'obscure-url', 'authn-z'],
	},
];