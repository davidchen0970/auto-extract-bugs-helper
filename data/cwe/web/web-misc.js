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
		what: `敏感資訊暴露給未授權者。程式把個資、存取權杖、密碼雜湊、金鑰、內部路徑或商業機密放在未授權者
	可觸及的地方——例如把資料庫整列（含 password_hash、API key、token）直接回傳給前端、寫進可公開讀取的錯誤頁或
	記錄，或放到過度開放的檔案／儲存桶。成因為「能存取」與「能被誰存取」沒有分開，輸出時未做最小洩漏，授權也
	未細到欄位層級。後果是帳號被接管、憑證被竊、橫向移動與聲譽／法令損失。修法是只回傳允許清單內的最小欄位
	集合、敏感欄位留在後端、做欄位層級的授權與最小權限存取，並逐一審查每個回應端點會外洩的內容。`,
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
		what: `錯誤訊息夾帶敏感資訊。程式把例外或剖析失敗的原始細節——資料庫查詢字串、連線字串、內部絕對路徑、
	堆疊追蹤、使用者名稱或金鑰——原封不動放進對使用者或客戶端的錯誤回應。成因為除錯期直接以 str(e)／getMessage()
	回傳給使用者，或統一錯誤處理把開發後門帶進正式環境。後果是洩漏內部拓樸、資料結構與驗證邏輯，大幅降低
	攻擊者探查系統與構築攻擊的成本，甚至直接流出機密。修法是將詳細技術資訊只寫入受限的伺服器日誌，對外一律回傳
	泛化的安全錯誤訊息，並在錯誤處理的統一入口過濾任何可能外洩的欄位。`,
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
		what: `跨站請求偽造（CSRF）。對改變狀態的請求（轉帳、改密、刪除、變更設定）只認 cookie 等自動攜帶的
	憑證，卻沒有驗證這筆狀態變更是否真的是使用者本人主動在該頁面發起；瀏覽器會背景自動帶上 cookie、Basic Auth 等
	憑證，別的網站就能用隱藏表單、圖片或指令誘使受害者的瀏覽器對目標送出看似合法的請求。成因為把「請求格式合法」
	（well-formed）誤當成「請求被使用者授權」，缺乏對請求來源與意圖的驗證。後果是冒充使用者執行任何其身份可做的
	狀態變更，屬身分信任層級的問題。修法是對每筆狀態變更採用 CSRF token（同步器／Double Submit）驗證意圖，
	並搭配 SameSite cookie 與檢查 Origin／Referer。`,
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
		what: `危險型別的檔案上傳不受限。程式接受附件上傳卻不驗證其真實型別，副檔名／MIME 又直接取自使用者
	提供的檔名：.php、.phtml、.jsp 等可被網頁伺服器當腳本執行的檔案一旦落入 web 根目錄，攻擊者上傳一個
	web shell 再用瀏覽器存取，就等同遠端任意程式碼執行（RCE）。成因為「只信檔名表頭」而非內容本身、又未把可
	執行檔隔離在靜態目錄之外。後果是 RCE、網頁竄改與伺服器內的橫向滲透。修法是使用允許清單副檔名並以內容
	偵測（finfo／magic bytes）驗證真實 MIME，以伺服器產生的隨機檔名存到 web 根目錄之外，並確保該目錄不被當作
	腳本執行路徑。`,
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
		what: `反序列化不可信資料。程式把使用者可控或未受信賴的位元組流直接交給反序列化機制（pickle.loads、
	ObjectInputStream、unserialize 等），卻未先驗證資料來源與結構。成因為這類格式在還原物件時常把「欄位內容」與
	「要產生的型別／行為」綁在同一包，攻擊者可構造序列化負載指明任意類別與參數，還原過程即觸發其建構式或魔術
	方法。後果是遠端任意程式碼執行（RCE）、拒絕服務與資料破壞，危害程度取決於可被還原的類別庫。修法是絕不反
	序列化不可信輸入，改用純資料格式（如 JSON）並以允許清單限定可還原的型別與欄位、驗證完整性或簽章，把可被
	還原的類別集合降到最小。`,
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
		what: `開放重導向（Open Redirect）。程式直接拿使用者提供的網址（如 next、redirect、return、callback 參數）
	呼叫 res.redirect()／Location 等重導行為，只檢查了「是不是字串」而沒檢驗目標；https://evil.com 甚至協定相對的
	//evil.com 都能逃過只擋 http／https 前綴的簡陋檢查。成因為重導參數掌握了目標的選擇權，卻沒把它限定在站內、
	也沒有伺服器端允許清單。後果主要是淪為釣魚跳板：以看似官方的登入或轉跳網址，把受騙者導向攻擊者站台竊取
	帳密與權杖。修法是只接受站內相對路徑、拒絕完整外部 URL 與 // 開頭的協定相對網址，若確實需要對外則用伺服器端
	允許清單逐一比對目標。`,
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
