// CWE chunk — category: Web / Misc sensitive & request handling.
// One chunk = one category, <= 6 entries. Every entry:
//   what    : 簡短、繁中、白話+技術描述（(#) 弱點是什麼)
//   problem : 「壞的寫法」程式片段（(#) 問題長怎樣)
//   fixed   : 「修好的寫法」程式片段（(#) 解完會長怎樣)
//   patch   : problem → fixed 的統一 diff 文字（(#) 範例 patch)
//   lang    : 此條範例主力語言（python / node / php）
//   status  : Complete | Incomplete | Deprecated
//   refs    : 參考（OWASP / MITRE 等）
//   tags    : 英文搜尋標籤
export default [
	{
		id: 'CWE-200',
		name: 'Exposure of Sensitive Information to an Unauthorized Actor',
		lang: 'node',
		status: 'Complete',
		what: `敏感資訊暴露。把資料庫整列（含密碼雜湊、API key、token 等）
	直接回傳給前端，未經授權的使用者就能取得無權存取的欄位。
	建議做法是只回傳允許清單欄位，敏感欄位留在後端，或是走最小欄位投影。`,
		problem: `// 不安全寫法：整列資料直接 res.json，password_hash / API key 一起外洩
app.get('/api/users/:id', async (req, res) => {
  const user = await db.one('SELECT * FROM users WHERE id = ?', [req.params.id]);
  res.json(user);   // 含 password_hash、API key 等敏感欄位
});`,
		fixed: `// 安全寫法：只回傳允許清單欄位，敏感欄位留在伺服器內
app.get('/api/users/:id', async (req, res) => {
  const user = await db.one('SELECT * FROM users WHERE id = ?', [req.params.id]);
  res.json({ id: user.id, name: user.name, email: user.email });
});`,
		patch: `@@
 app.get('/api/users/:id', async (req, res) => {
   const user = await db.one('SELECT * FROM users WHERE id = ?', [req.params.id]);
-  res.json(user);
+  res.json({ id: user.id, name: user.name, email: user.email });
 });`,
		refs: ['OWASP-SensitiveData', 'CWE-200'],
		tags: ['information-disclosure', 'sensitive-data', 'api'],
	},
	{
		id: 'CWE-209',
		name: 'Generation of Error Message Containing Sensitive Information',
		lang: 'python',
		status: 'Complete',
		what: `錯誤訊息含敏感資訊。把 exception 的原始訊息（含 SQL、查詢值、路徑、堆疊）
	直接回給使用者，等於把內部拓樸細節洩漏出來，使攻擊者更容易探查系統。
	建議做法是詳細資訊只寫入日誌，對外統一返回泛化的錯誤訊息。`,
		problem: `# 不安全寫法：把 str(e)（含資料庫查詢／內部路徑／堆疊）原封不動回給使用者
@app.get('/login')
def login(request):
    try:
        row = db.execute('SELECT * FROM users WHERE id = %s', [request['id']])
    except Exception as e:
        return f"Error: {e}", 500    # 洩漏 DB 內部細節`,
		fixed: `# 安全寫法：細節寫入日誌，對外一律泛化錯誤訊息
@app.get('/login')
def login(request):
    try:
        row = db.execute('SELECT * FROM users WHERE id = %s', [request['id']])
    except Exception as e:
        logger.exception('login lookup failed for id=%r', request['id'])  # 細節寫入日誌
        return 'Internal error', 500                                      # 對外泛化錯誤訊息`,
		patch: `@@
     try:
         row = db.execute('SELECT * FROM users WHERE id = %s', [request['id']])
     except Exception as e:
-        return f"Error: {e}", 500
+        logger.exception('login lookup failed for id=%r', request['id'])
+        return 'Internal error', 500`,
		refs: ['OWASP-ErrorHandling', 'CWE-209'],
		tags: ['error-handling', 'information-disclosure', 'log'],
	},
	{
		id: 'CWE-352',
		name: 'Cross-Site Request Forgery (CSRF)',
		lang: 'node',
		status: 'Complete',
		what: `跨站請求偽造（CSRF）。對狀態變更的 POST 請求沒有任何來源驗證，
	別的網站只要誘使受害者的瀏覽器送出一個表單／圖片，就能偽裝成受害者的
	身分要求伺服器執行操作。
	建議做法是 CSRF token + Double Submit：隨機 token 同時放 session 與表單 hidden 欄位，提交時比對。`,
		problem: `// 不安全寫法：轉帳/改密等狀態變更沒有 token 驗證，站外表單可直接觸發
app.post('/api/transfer', (req, res) => {
  transfer(req.session.userId, Number(req.body.amount));   // 來源無法驗證
});`,
		fixed: `// 安全寫法：render 時發 token，Double Submit 比對表單欄位與 session
const crypto = require('crypto');

app.get('/form', (req, res) => {
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(24).toString('hex');
  res.send('<form method="post" action="/api/transfer">'
         + '<input type="hidden" name="_csrf" value="' + req.session.csrf + '">'
         + '<input type="text" name="amount"></form>');
});

app.post('/api/transfer', (req, res) => {
  if (!req.session.csrf || req.body._csrf !== req.session.csrf) {
    return res.status(403).json({ error: 'CSRF token mismatch' });
  }
  transfer(req.session.userId, Number(req.body.amount));
});`,
		patch: `@@
 app.post('/api/transfer', (req, res) => {
+  if (!req.session.csrf || req.body._csrf !== req.session.csrf) {
+    return res.status(403).json({ error: 'CSRF token mismatch' });
+  }
   transfer(req.session.userId, Number(req.body.amount));
 });
+
+// + render 時產 token 塞 session，並放進表單 hidden 欄位供比對`,
		refs: ['OWASP-CSRF', 'CWE-352'],
		tags: ['csrf', 'token', 'double-submit'],
	},
	{
		id: 'CWE-434',
		name: 'Unrestricted Upload of File with Dangerous Type',
		lang: 'php',
		status: 'Complete',
		what: `危險型別上傳不受限。副檔名直接取自使用者上傳的檔名，.php/.phtml 被存入 Web 根目錄，
	攻擊者上傳 PHP shell 後再透過瀏覽器直接存取，就可能造成遠端程式碼執行（RCE）。
	建議做法是允許清單副檔名 + 用 finfo 檢查真實 MIME，並以隨機檔名存到 web root 之外。`,
		problem: `<?php
// 不安全寫法：副檔名來自使用者檔名，.php shell 直接進 web root
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);`,
		fixed: `<?php
// 安全寫法：允許清單副檔名 + finfo 檢查真實 MIME，隨機檔名存到 web root 外
$ALLOWED_EXT = ['jpg', 'jpeg', 'png', 'gif'];
$ALLOWED_MIME = ['image/jpeg', 'image/png', 'image/gif'];

$info = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($info, $_FILES['file']['tmp_name']);
if (!in_array($mime, $ALLOWED_MIME, true)) die('bad mime');

$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $ALLOWED_EXT)) die('bad extension');

$name = bin2hex(random_bytes(16)) . '.' . $ext;
move_uploaded_file($_FILES['file']['tmp_name'], '/srv/uploads/' . $name);   // web root 外`,
		patch: `@@
-<?php
-// 不安全寫法：副檔名來自使用者檔名，.php shell 直接進 web root
-$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
-move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);
+<?php
+$ALLOWED_EXT = ['jpg', 'jpeg', 'png', 'gif'];
+$ALLOWED_MIME = ['image/jpeg', 'image/png', 'image/gif'];
+$info = finfo_open(FILEINFO_MIME_TYPE);
+$mime = finfo_file($info, $_FILES['file']['tmp_name']);
+if (!in_array($mime, $ALLOWED_MIME, true)) die('bad mime');
+$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
+if (!in_array($ext, $ALLOWED_EXT)) die('bad extension');
+$name = bin2hex(random_bytes(16)) . '.' . $ext;
+move_uploaded_file($_FILES['file']['tmp_name'], '/srv/uploads/' . $name);`,
		refs: ['OWASP-FileUpload', 'CWE-434'],
		tags: ['file-upload', 'rce', 'mime'],
	},
	{
		id: 'CWE-502',
		name: 'Deserialization of Untrusted Data',
		lang: 'python',
		status: 'Complete',
		what: `反序列化不可信資料。把使用者可控的內容直接傳入 pickle.loads()，
	pickle 反序列化過程本就會執行物件程式碼，惡意建構的負載可直接 RCE。
	建議做法是「絕不反序列化使用者輸入」，改用純資料格式（JSON）+ 允許清單校驗。`,
		problem: `# 不安全寫法：直接反序列化使用者可控的 pickle，一進去就能執行任意程式碼
import pickle
payload = request.form['blob']
obj = pickle.loads(payload.encode('latin1'))   # 使用者可藉此塞入 RCE 負載`,
		fixed: `# 安全寫法：不反序列化不可信輸入，改用 JSON（純資料）+ 允許清單校驗
import json
try:
    data = json.loads(request.form['payload'])      # 純資料，不會執行程式碼
except json.JSONDecodeError:
    return 'invalid payload', 400
# 之後再依需要的欄位，從允許清單中取用並驗證型別`,
		patch: `@@
-import pickle
-payload = request.form['blob']
-obj = pickle.loads(payload.encode('latin1'))
+import json
+try:
+    data = json.loads(request.form['payload'])
+except json.JSONDecodeError:
+    return 'invalid payload', 400`,
		refs: ['OWASP-Deserialization', 'CWE-502'],
		tags: ['deserialization', 'pickle', 'rce'],
	},
	{
		id: 'CWE-601',
		name: "URL Redirection to Untrusted Site ('Open Redirect')",
		lang: 'node',
		status: 'Complete',
		what: `開放重導向（Open Redirect）。直接拿使用者提供的網址做 res.redirect()，
	next 可被填成 https://evil.com 或 //evil.com，將使用者導向釣魚網站。
	建議做法是只允許站內相對路徑，拒絕站外 URL 與 // 開頭的協定相對網址。`,
		problem: `// 不安全寫法：使用者給什麼就 redirect 到哪，可帶完整網址或 //evil.com
app.get('/login', (req, res) => {
  const next = req.query.next ? decodeURIComponent(String(req.query.next)) : '';
  res.redirect(next || '/');        // https://evil.com 或 //evil.com 都會被帶走
});`,
		fixed: `// 安全寫法：只接受站內相對路徑，擋掉站外 URL 與 // 開頭
app.get('/login', (req, res) => {
  const next = req.query.next ? decodeURIComponent(String(req.query.next)) : '';
  if (next && next.startsWith('//')) {
    return res.status(400).send('open redirect blocked');
  }
  if (next && !next.startsWith('/')) {
    return res.status(400).send('open redirect blocked');
  }
  res.redirect(next || '/');
});`,
		patch: `@@
 app.get('/login', (req, res) => {
   const next = req.query.next ? decodeURIComponent(String(req.query.next)) : '';
+  if (next && next.startsWith('//')) {
+    return res.status(400).send('open redirect blocked');
+  }
+  if (next && !next.startsWith('/')) {
+    return res.status(400).send('open redirect blocked');
+  }
   res.redirect(next || '/');
 });`,
		refs: ['OWASP-OpenRedirect', 'CWE-601'],
		tags: ['open-redirect', 'url', 'phishing'],
	},
];
