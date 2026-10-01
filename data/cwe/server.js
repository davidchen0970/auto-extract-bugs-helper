// CWE chunk — category: Server / Request Robustness (Python / Go / Node).
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
		id: 'CWE-377',
		name: 'Insecure Temporary File',
		lang: 'python',
		status: 'Complete',
		what: `不安全的暫存檔。用 tempfile.mktemp() 這類呼叫時，它只「回傳一個檔名」而沒有真的
建檔，檔名又常以時間戳或 PID 這一類可預測的方式產生。程式接著才用 os.chmod、open 去修改或開啟
「那個路徑」。中間這段空窗就是 TOCTOU：攻擊者可先在同一個預測路徑塞入自已的連結（symlink）或檔案，
程式再去 open 便會寫到攻擊者控管的檔案上。建議直接改用 tempfile.NamedTemporaryFile 或 tempfile.mkstemp()，
它們會在核心層原子地建立「隨機、一般人無法預測、而且一建出來就如有正確權限」的暫存檔，把「建立」與「使用」
合併成單一動作，根絕這條競態路徑。`,
		problem: `# 不安全寫法：mktemp() 只回傳可預測檔名、沒建檔，之後才 open 寫入 => TOCTOU
import os, tempfile

def write_temp(msg):
    path = tempfile.mktemp()          # 檔名可預測（時間戳/PID），且此刻尚未建檔
    with open(path, 'w') as f:        # gap：攻擊者可先在此路徑擺 symlink
        f.write(msg)
    os.chmod(path, 0o600)             # 太晚; 權限設定在寫入之後才做`,
		fixed: `# 安全寫法：mkstemp() 在核心立即建出隨機、私有(0600)的暫存檔再寫入
import os, tempfile

def write_temp(msg):
    fd, path = tempfile.mkstemp()      # 建立與回傳路徑是同一個原子動作,權限已是 0600
    try:
        with os.fdopen(fd, 'w') as f:  # 直接對已建立的 fd 寫入,無空窗
            f.write(msg)
    finally:
        os.close(fd)`,
		patch: `@@
 def write_temp(msg):
-    path = tempfile.mktemp()          # 檔名可預測（時間戳/PID），且此刻尚未建檔
-    with open(path, 'w') as f:        # gap：攻擊者可先在此路徑擺 symlink
-        f.write(msg)
-    os.chmod(path, 0o600)             # 太晚; 權限設定在寫入之後才做
+    fd, path = tempfile.mkstemp()      # 建立與回傳路徑是同一個原子動作,權限已是 0600
+    try:
+        with os.fdopen(fd, 'w') as f:  # 直接對已建立的 fd 寫入,無空窗
+            f.write(msg)
+    finally:
+        os.close(fd)`,
		refs: ['CWE-377', 'SEI CERT'],
		tags: ['temp-file', 'toctou', 'symlink', 'tmp'],
	},
	{
		id: 'CWE-400',
		name: 'Uncontrolled Resource Consumption',
		lang: 'go',
		status: 'Complete',
		what: `不受控制的資源消耗（又稱無界資源消耗）。伺服器對外部請求提供的資料量或工作量沒有限額：
例如把整張 request body 一次讀滿、不限制 payload 大小，或用迴圈一直消費可被外部餵大的輸入，也不設上限。
攻擊者只要連續送幾個「大請求」或觸發停不下來的迴圈，就能讓記憶體、CPU、連線數被瞬間耗盡，
壓垮同一台機器上的所有使用者並拖垮整個服務。建議做法是：在進入處理前就檢查並限制 body 的上限
（http.MaxBytesReader、Content-Length 預檢），對任何迴圈也設定明確的次數或時間上限；把「資源有界」
寫成處理器的起手式而非事後補救。`,
		problem: `// 不安全寫法：不檢查外部 body 大小就整段讀入並處理，攻擊者可耗盡記憶體
package main

import (
	"io"
	"log"
	"net/http"
)

func upload(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(r.Body)        // 無大小上限,一個 GB 異常請求就吃滿 RAM
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	process(w, data)                      // 資料越大處理越久,CPU 也跟著失控
}

func main() {
	http.HandleFunc("/upload", upload)
	log.Fatal(http.ListenAndServe(":8080", nil))
}`,
		fixed: `// 安全寫法：用 http.MaxBytesReader 設 1 MB 硬上限,超過直接拒絕 => 資源有界
package main

import (
	"io"
	"log"
	"net/http"
)

const MaxBody = 1 << 20 // 1 MB

func upload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBody) // 超過上限立刻截斷/拒絕
	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "body too large or unreadable", 413) // 413 Request Entity Too Large
		return
	}
	process(w, data)
}

func main() {
	http.HandleFunc("/upload", upload)
	log.Fatal(http.ListenAndServe(":8080", nil))
}`,
		patch: `@@
 func upload(w http.ResponseWriter, r *http.Request) {
-	data, err := io.ReadAll(r.Body)        // 無大小上限,一個 GB 異常請求就吃滿 RAM
+	r.Body = http.MaxBytesReader(w, r.Body, MaxBody) // 超過上限立刻截斷/拒絕
+	data, err := io.ReadAll(r.Body)
 	if err != nil {
-		http.Error(w, err.Error(), 400)
+		http.Error(w, "body too large or unreadable", 413) // 413 Request Entity Too Large
 		return
 	}
 	process(w, data)`,
		refs: ['CWE-400'],
		tags: ['resource-consumption', 'dos', 'request-size', 'unbounded'],
	},
	{
		id: 'CWE-430',
		name: 'Deployment of Wrong Handler (e.g. HTTP Verb Tampering)',
		lang: 'node',
		status: 'Complete',
		what: `部署了錯誤的處理器（HTTP Verb Tampering）。伺服器把「不同 HTTP 方法」的請求通通導到同一個
不加以區分的處理函式，或錯誤地用 app.use 而不限 verb；於是本該只允許 GET（讀取）的路徑，攻擊者改用
POST、PUT 或 DELETE 去敲也可能照樣被處理，甚至動到不該碰的副作用。CWE-430 的涵意是「路由層比對失準、
真正被呼叫的那個 handler 並非精心想部署的那一個」。建議做法是在註冊路由時就用精確的方法＋路徑（app.get、
app.post、app.method('/path')），對不合法的 verb 一律回 405 Method Not Allowed，不讓任何方法滑進誤裝的處理器。`,
		problem: `// 不安全寫法：app.use 不限 HTTP verb,任何方法都會執行「換密碼」這個小心動作
const express = require('express');
const bcrypt = require('bcrypt');
const app = express();

app.use(express.json());

// app.use = 所有 verb(GET/POST/PUT/DELETE...) 都會進來,且無 "/change-password" 檢查
app.use((req, res) => {
  if (req.query.newpass) {
    const hash = bcrypt.hashSync(req.query.newpass, 10);
    saveCreds(req.user.id, hash);        // 用 GET 也能觸發改密碼 => verb tampering
  }
  res.sendStatus(200);
});`,
		fixed: `// 安全寫法：只註冊 POST /change-password,其它 verb 一律 405 Method Not Allowed
const express = require('express');
const bcrypt = require('bcrypt');
const app = express();

app.use(express.json());

app.post('/change-password', (req, res) => {   // 方法與路徑都精確指定
  const hash = bcrypt.hashSync(req.body.newpass, 12);
  saveCreds(req.user.id, hash);
  res.sendStatus(204);
});`,
		patch: `@@
-// app.use = 所有 verb(GET/POST/PUT/DELETE...) 都會進來,且無 "/change-password" 檢查
-app.use((req, res) => {
-  if (req.query.newpass) {
-    const hash = bcrypt.hashSync(req.query.newpass, 10);
-    saveCreds(req.user.id, hash);        // 用 GET 也能觸發改密碼 => verb tampering
-  }
-  res.sendStatus(200);
-});
+app.post('/change-password', (req, res) => {   // 方法與路徑都精確指定
+  const hash = bcrypt.hashSync(req.body.newpass, 12);
+  saveCreds(req.user.id, hash);
+  res.sendStatus(204);
+});`,
		refs: ['CWE-430'],
		tags: ['verb-tampering', 'http-method', 'routing', 'handler'],
	},
	{
		id: 'CWE-444',
		name: 'Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)',
		lang: 'node',
		status: 'Complete',
		what: `HTTP 請求解讀不一致（HTTP Request Smuggling、走私）。前端（反向代理、負載平衡器）與後端
伺服器各自用不同的規則來決定「一條請求解讀到哪裡結束」：例如後端依 Content-Length 數位元組，而前端優先看
Transfer-Encoding: chunked；當同一份請求兩種標頭並存且長度對不上時，兩邊切出來的邊界就不一致。攻擊者就能把
「第二條被夾帶的請求」塞進代理以為已經結束的連線，繞過 WAF、劫持連到同一個後端的其它使用者連線。
修法是：統一由同一個解析器測量與執行安全性策略、不允許同時信任這兩個衝突的長度標頭，並核對兩者之一與實際
body 一致,對標頭不一致的請求直接拒絕上線。`,
		problem: `// 不安全寫法：同時接受 Content-Length 與 Transfer-Encoding,長度兜不攏時仍照單收下
const http = require('http');

http.createServer((req, res) => {
  let raw = '';
  // 作法一(看 CL):req 長度照 Content-Length;
  // 作法二(看 TE):若 header 帶 Transfer-Encoding: chunked,就該照 chunked 解。
  // 此處不加裁定:只要兩個標頭並存就存在走私縫
  req.on('data', (c) => (raw += c));
  req.on('end', () => {
    handle(raw);        // 邊界錯位 => 被解進同一連線的下一段請求
    res.end('ok');
  });
}).listen(8080);`,
		fixed: `// 安全寫法：明確拒絕 Content-Length 與 Transfer-Encoding「並存」的請求,無法裁定就丟掉
const http = require('http');

http.createServer((req, res) => {
  const hasCL = req.headers['content-length'] !== undefined;
  const hasTE = req.headers['transfer-encoding'] !== undefined;
  if (hasCL && hasTE) {                // 衝突的長度標頭共存 => 走私武器,直接拒絕
    res.writeHead(400);
    return res.end('ambiguous framing');
  }
  let raw = '';
  req.on('data', (c) => (raw += c));
  req.on('end', () => {
    handle(raw);
    res.end('ok');
  });
}).listen(8080);`,
		patch: `@@
 http.createServer((req, res) => {
+  const hasCL = req.headers['content-length'] !== undefined;
+  const hasTE = req.headers['transfer-encoding'] !== undefined;
+  if (hasCL && hasTE) {                // 衝突的長度標頭共存 => 走私武器,直接拒絕
+    res.writeHead(400);
+    return res.end('ambiguous framing');
+  }
   let raw = '';
-  // 作法一(看 CL):req 長度照 Content-Length;
-  // 作法二(看 TE):若 header 帶 Transfer-Encoding: chunked,就該照 chunked 解。
-  // 此處不加裁定:只要兩個標頭並存就存在走私縫
   req.on('data', (c) => (raw += c));
   req.on('end', () => {
     handle(raw);        // 邊界錯位 => 被解進同一連線的下一段請求
     res.end('ok');
   });
 }).listen(8080);`,
		refs: ['CWE-444', 'OWASP-HTTP'],
		tags: ['http-request-smuggling', 'content-length', 'transfer-encoding', 'framing'],
	},
];
