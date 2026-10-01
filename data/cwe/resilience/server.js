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
		id: 'CWE-408',
		name: 'Incorrect Behavior Order: Early Amplification',
		lang: 'go',
		status: 'Complete',
		what: `行為順序錯誤：過早放大（Early Amplification）。程式在「驗證、節流、抽取最小必要資料」等
保護性的重活之前，就先對輸入做了把資源放大的動作——例如在檢查權限／驗證請求前就先解壓整個 body、先對每個
請求開出大量 goroutine／佔用連線、或先做昂貴的展開才發現這請求根本不該被處理。順序一錯，攻擊者不必通過檢查，
只要連敲介面就能讓「放大」先發生，資源在檢查有機會拒絕之前就被耗光。修法是「先做便宜的檢查與節流、再做貴的甚至
放大的處理」，把解密／解壓／大分配這些重動作搬到驗證與頻率限制之後。`,
		problem: `// 不安全寫法：先解壓整個 body 才檢查 token => 未通過驗證的請求也能先放大耗資源
package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	body, err := gzip.NewReader(r.Body)      // 先解壓:壓縮炸彈在此膨脹
	if err != nil {
		http.Error(w, "bad body", 400)
		return
	}
	data, _ := io.ReadAll(body)              // 放大先發生
	if r.Header.Get("X-Auth") != "secret" { // 驗證在放大"之後" => 過早放大
		http.Error(w, "unauthorized", 401)
		return
	}
	process(w, data)
}`,
		fixed: `// 安全寫法：先做便宜的權限檢查,驗證通過才解壓 => 未授權請求不會觸發放大
package main

import (
	"io"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Auth") != "secret" { // 便宜檢查在前
		http.Error(w, "unauthorized", 401)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 有限度讀進原始 body
	data, _ := io.ReadAll(r.Body)
	processed, _ := gunzip(data)                     // 驗證通過才解壓,放大成本受控
	process(w, processed)
}`,
		patch: `@@
  func handler(w http.ResponseWriter, r *http.Request) {
-	body, err := gzip.NewReader(r.Body)      // 先解壓:壓縮炸彈在此膨脹
-	if err != nil {
-		http.Error(w, "bad body", 400)
-		return
-	}
-	data, _ := io.ReadAll(body)              // 放大先發生
 	if r.Header.Get("X-Auth") != "secret" {
 		http.Error(w, "unauthorized", 401)
 		return
 	}
+	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
+	data, _ := io.ReadAll(r.Body)
+	processed, _ := gunzip(data)
-	process(w, data)
+	process(w, processed)
 }`,
		refs: ['CWE-408', 'CWE-405'],
		tags: ['early-amplification', 'behavior-order', 'before-validation', 'dos'],
	},
	{
		id: 'CWE-412',
		name: 'Unrestricted Externally Accessible Lock',
		lang: 'c',
		status: 'Complete',
		what: `外部可存取的鎖未加限制。程式用「外部可控制的資源」當鎖來協調互斥——例如把伺服器數據庫鎖檔放在
	使用者可寫入、可預測的路徑，或以可被別人取代的檔名當 lock file。攻擊者可以先把自己手腳放在那個 lock 位置：預先建立或鎖住、
	換成指向敏感檔的 symlink，程式再去拿「這把鎖」時要嘛鎖不到（其他執行緒也拿不到，服務卡死）、要嘛沿著路徑寫到攻擊者的檔案
	上；更糟的是靠檔名存在與否當旗標會被別人的檔案污染。修法是讓鎖不在外部可控空間——用專門的鎖服務、受保護目錄內唯一且不可預測的
	鎖檔、或 in-memory／核心層的鎖，而不是把 lock 的物體交給使用者能碰的地方。`,
		problem: `// 不安全寫法：把鎖建立在 /tmp 的可預測路徑 => 攻擊者可預佔或用 symlink 換走
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>

void lock_work(void) {
    // /tmp/work.lock 人人可寫且路徑可預測,攻擊者可先占住或換成 symlink
    int fd = open("/tmp/work.lock", O_CREAT | O_WRONLY, 0644);
    flock(fd, LOCK_EX);   // 這把「鎖」的外部狀態不受我們控制
}`,
		fixed: `// 安全寫法：改用受保護目錄內、只對本服務可寫的私有鎖狀態 => 外部碰不到
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>

void lock_work(void) {
    int fd = open("/var/run/myapp/work.lock",
                 O_CREAT | O_WRONLY, 0600); // root 專屬目錄 + 0600
    flock(fd, LOCK_EX);   // 鎖的物件在外部不可寫空間,不會被別人預佔/掉包
}`,
		patch: `@@
 void lock_work(void) {
-    int fd = open("/tmp/work.lock", O_CREAT | O_WRONLY, 0644);
+    int fd = open("/var/run/myapp/work.lock",
+                 O_CREAT | O_WRONLY, 0600);
     flock(fd, LOCK_EX);
 }`,
		refs: ['CWE-412', 'SEI CERT'],
		tags: ['external-lock', 'lock-file', 'symlink', 'tmp'],
	},
	{
		id: 'CWE-413',
		name: 'Improper Resource Locking',
		lang: 'c',
		status: 'Complete',
		what: `資源鎖定（locking）不當。共享資源明明「應該被鎖」，卻在某些路徑沒鎖、鎖錯資源、或鎖定的範圍
與真正存取範圍不一致：例如只鎖了「寫」沒鎖「讀」、鎖的是另一個物件（兩把不同的鎖保護同一份資料）、或 check 與 use
之間有一段落鎖的空窗。結果是「既有鎖也鎖不到點」——多執行緒仍能同時進入臨界區改動共享狀態，競態照樣發生。修法是讓
「每一份共享狀態只由唯一一把鎖保護」，並且鎖必須涵蓋完整的『讀取─判斷─寫回』範圍，所有存取者都用同一把鎖。`,
		problem: `// 不安全寫法：寫有上鎖、讀沒上鎖 => 鎖的範圍不一致,讀寫仍競態
#include <pthread.h>
#include <stdio.h>

static int state = 0;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

void write_state(int v) {
    pthread_mutex_lock(&mtx);
    state = v;              // 寫入有鎖
    pthread_mutex_unlock(&mtx);
}

int read_state(void) {
    return state;            // 讀取"沒上鎖",可與寫入交錯 => 鎖定範圍不一致
}`,
		fixed: `// 安全寫法：讀與寫都用同一把鎖 => 鎖定範圍一致,交換的兩個操作都被保護
#include <pthread.h>

static int state = 0;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

void write_state(int v) {
    pthread_mutex_lock(&mtx);
    state = v;
    pthread_mutex_unlock(&mtx);
}

int read_state(void) {
    int v;
    pthread_mutex_lock(&mtx);
    v = state;             // 讀取也上同一把鎖
    pthread_mutex_unlock(&mtx);
    return v;
}`,
		patch: `@@
 int read_state(void) {
-    return state;            // 讀取"沒上鎖",可與寫入交錯 => 鎖定範圍不一致
+    int v;
+    pthread_mutex_lock(&mtx);
+    v = state;
+    pthread_mutex_unlock(&mtx);
+    return v;
 }`,
		refs: ['CWE-413', 'SEI CERT'],
		tags: ['improper-locking', 'mutex', 'critical-section', 'locking'],
	},
	{
		id: 'CWE-414',
		name: 'Missing Lock Check',
		lang: 'c',
		status: 'Complete',
		what: `缺少鎖定檢查。程式在「先檢查、後動作」的流程裡，只在「動作」階段才想起要持鎖保護，而在那份必須
	不可分割的判斷（check）階段完全沒有鎖：例如先平白讀取共享狀態決定「還能不能做」，鎖是等到真的動手前一刻才拿。問題就在
	判斷與動手之間的空窗——別的執行緒可以插進來把狀態改掉，讓判斷結果失效，最後仍做出不該做的動作（超賣、超額扣款等）。
	修法是讓整個 check-then-act 落在同一把鎖保護的連續區段內：上鎖→判斷→動作→解鎖，一次完成，絕不在判斷與動作之間留縫。`,
		problem: `// 不安全寫法：先平白檢查剩餘額度,鎖只用在真正扣款那一下 => check 與 act 之間空窗
#include <pthread.h>

static int tickets = 1;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

int buy_one(void) {
    if (tickets > 0) {          // check:沒有上鎖,別人可同時通過檢查
        pthread_mutex_lock(&mtx);  // act 才上鎖 => 中間有空窗,多賣一張
        tickets--;
        pthread_mutex_unlock(&mtx);
        return 1;
    }
    return 0;
}`,
		fixed: `// 安全寫法：check 與 act 都在同一把鎖內 => 判斷與動作不可分割
#include <pthread.h>

static int tickets = 1;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

int buy_one(void) {
    int ok = 0;
    pthread_mutex_lock(&mtx);   // 先上鎖再判斷
    if (tickets > 0) {
        tickets--;              // 判斷與動作連續完成
        ok = 1;
    }
    pthread_mutex_unlock(&mtx);
    return ok;
}`,
		patch: `@@
 int buy_one(void) {
+    int ok = 0;
+    pthread_mutex_lock(&mtx);   // 先上鎖再判斷
     if (tickets > 0) {
-        pthread_mutex_lock(&mtx);
-        tickets--;
-        pthread_mutex_unlock(&mtx);
-        return 1;
+        tickets--;
+        ok = 1;
     }
+    pthread_mutex_unlock(&mtx);
-    return 0;
+    return ok;
 }`,
		refs: ['CWE-414', 'CWE-367'],
		tags: ['missing-lock-check', 'check-then-act', 'race-condition'],
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
		id: 'CWE-438',
		name: 'Behavioral Problems',
		lang: 'python',
		status: 'Complete',
		what: `行為問題（Behavioral Problems）。這是一個範疇類別，集合那些「程式輸出的行為與合理的、可預期的行為
	不一致」類型的弱點——像錯誤的操作順序、誤用運算子、迴圈有無窮的出口、工作流程能被跳步執行等等。這些往往不是單一一處錯誤，而是
	而是「哪裡該有的行為沒出現、不該出現的行為卻發生」，最終導致狀態錯亂、繞過檢查或 DoS。因為是分類用的 Category，MITRE
	不建議直接用它在實際漏洞做對映，而應往下映射到更精確的成員弱點（如 CWE-408 過早放大、CWE-835 無窮迴圈、CWE-841
	行為工作流程未強制）。寫程式的務實對策是把「驗證─動作」與「狀態更新─判斷是否退出」等行為順序寫成明確、可推斷的單一
	流程，並針對每個行為寫測試鎖住預期結果。`,
		problem: `# 不安全寫法:先執行動作、後才檢查權限 => 該被擋下的行為已經先執行
def delete_user(req, uid):
    # 動作先做:刪除行為已發生
    db.delete(uid)
    # 才檢查呼叫者是不是管理者 => 順序錯,未授權也可先刪
    if not is_admin(req.user):
        return "forbidden"   # 動作都做完了才說不行`,
		fixed: `# 安全寫法:先做便宜的權限檢查,通過才執行破壞性行為 => 行為順序正確
def delete_user(req, uid):
    if not is_admin(req.user):   # 檢查在前
        return "forbidden"
    db.delete(uid)             # 通過才動作
    return "ok"`,
		patch: `@@
 def delete_user(req, uid):
-    # 動作先做:刪除行為已發生
-    db.delete(uid)
-    if not is_admin(req.user):
-        return "forbidden"
+    if not is_admin(req.user):
+        return "forbidden"
+    db.delete(uid)
     return "ok"`,
		refs: ['CWE-438', 'CWE-408'],
		tags: ['behavioral-problems', 'behavior-order', 'logic'],
	},
	{
		id: 'CWE-440',
		name: 'Expected Behavior Violation',
		lang: 'python',
		status: 'Complete',
		what: `違反預期行為（Expected Behavior Violation）。程式在某種輸入下，行為與呼叫端／規範「合理預期的結果」
	相悖：例如對 PEM 字串回了「成功卻沒解密」、對重複的參數只處理最後一個、對空輸入做出非空結果，或把有定義語意的值
	擅自改成另一種語意。這類問題的特色是程式「沒當場崩掉」，而是回傳一個看似正常但其實不對的結果，錯誤要到很後面、甚至到了
	其它組件才爆發，最難追。成因常是呼叫了語意鬆散的 API、或邊界值／重複值沒被明確定義。修法是讓介面對每種輸入都有明確
	且符合文件的定義，把有歧義的輸入（重複參數、空值、越界）在進入處就規範與拒絕。`,
		problem: `# 不安全寫法:把空密鑰視為「有效」=> 呼叫端以為加密真被使用,實則裸存秘密
import base64

def derive_key(raw):
    if not raw:                       # 空輸入沒有被拒絕
        return None
    return base64.b64decode(raw)

def encrypt(secret, raw_key):
    key = derive_key(raw_key)
    if key is None:
        return ("plain", secret)       # 偷偷回 "沒加密",違反呼叫端預期
    return ("cipher", xor(secret, key))`,
		fixed: `# 安全寫法:空密鑰直接拋錯 => 行為與預期一致,不默默降級
import base64

def derive_key(raw):
    if not raw:
        raise ValueError("empty key")   # 明確拒絕,不容許靜默降級
    return base64.b64decode(raw)

def encrypt(secret, raw_key):
    key = derive_key(raw_key)
    return ("cipher", xor(secret, key))`,
		patch: `@@
 def derive_key(raw):
-    if not raw:                       # 空輸入沒有被拒絕
-        return None
+    if not raw:
+        raise ValueError("empty key")
     return base64.b64decode(raw)
 
 def encrypt(secret, raw_key):
     key = derive_key(raw_key)
-    if key is None:
-        return ("plain", secret)
     return ("cipher", xor(secret, key))`,
		refs: ['CWE-440', 'MITRE'],
		tags: ['expected-behavior', 'semantic', 'silent-degradation'],
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
	{
		id: 'CWE-628',
		name: 'Function Call with Incorrectly Specified Arguments',
		lang: 'c',
		status: 'Complete',
		what: `函式呼叫的引數指定錯誤。呼叫某個函式時，引數的「個數、順序、或型別」與函式的契約不符——例如
	C 語言裡 type 不匹配的實參、把長度與緩衝區傳反、或忘了傳第 4 個參數。編譯器若沒抓到就會悄悄產生錯誤行為：
	緩衝區大小算錯造成越界寫、權限旗標傳錯造成開錯權限、字串長度傳反導致解析到錯誤的資料。因為「看起來有傳、也有呼叫」
	，這種錯最容易被人工審查漏掉。修法是讓整份程式保持嚴格的型別（用 __builtin 檢查、啟用 -Wformat 等警告）、給函式
	有意義的具名結構／參數物件，並在呼叫處逐一核對引數合約，讓「該傳的是什麼」無法靠錯位蒙混。`,
		problem: `// 不安全寫法:snprintf 的 size 與 format 順序傳錯 => size 被當成 format 字串,嚴重錯位
#include <stdio.h>

int fmt(char *dst, size_t cap, const char *name) {
    // 正確是 snprintf(dst, cap, "%s", name);下面順序寫反
    return snprintf(dst, "%s", cap);  // cap(size_t) 被視為 format => 型別/順序錯誤
}`,
		fixed: `// 安全寫法:引數個數/型別/順序與宣告一致 => 行為正確
#include <stdio.h>

int fmt(char *dst, size_t cap, const char *name) {
    return snprintf(dst, cap, "%s", name); // size cap 在前,format "%s" 對應 name
}`,
		patch: `@@
 int fmt(char *dst, size_t cap, const char *name) {
-    return snprintf(dst, "%s", cap);  // cap(size_t) 被視為 format => 型別/順序錯誤
+    return snprintf(dst, cap, "%s", name);
 }`,
		refs: ['CWE-628', 'SEI CERT'],
		tags: ['wrong-argument', 'snprintf', 'argument-order', 'format-string'],
	},
	{
		id: 'CWE-840',
		name: 'Business Logic Errors',
		lang: 'python',
		status: 'Complete',
		what: `業務邏輯錯誤（Business Logic Errors）。程式的「規則」本身寫得不夠硬或定義有漏洞，讓攻擊者可以
	繞過業務流程的意圖：跳過付款也能下單、負數數量扣款、同一張券重複兌換、先把價格改成負數再撿便宜……這類問題不該
	歸到程式漏洞（memory、injection），而是「允許了不合理卻『合法』的輸入序列」。成因是信任了本該重新驗證的狀態：價格、
	庫存、狀態機轉移都沒有在關鍵動作再檢查一遍。修法是將業務規則集中成可驗證的檢查點（server-side 重新計算金額、狀態機只
	允許合法轉移、把「動作是否被當前狀態允許」寫成不輸入便否決），並對關鍵條件加唯一性／原子性約束以防止重複動作。`,
		problem: `# 不安全寫法:訂單金額直接吃用戶端送的數字,負數也能通過 => 業務規則被繞過
def create_order(user, item, qty, price_from_client):
    if qty <= 0:
        return "bad qty"
    # 金額完全信任用戶端,可送負數或 0 => 倒收錢/免費拿
    amount = qty * price_from_client
    charge(user, amount)
    ship(item, qty)`,
		fixed: `# 安全寫法:金額一律由伺服器端重新查價計算 => 用戶端價格不可信
def create_order(user, item, qty):
    if qty <= 0:
        return "bad qty"
    price = server_price(item)    # 重新查價,而不是吃用戶端送來的數字
    amount = qty * price       # 金額只能由伺服器端算
    charge(user, amount)
    ship(item, qty)`,
		patch: `@@
-def create_order(user, item, qty, price_from_client):
+def create_order(user, item, qty):
     if qty <= 0:
         return "bad qty"
-    amount = qty * price_from_client
+    price = server_price(item)
+    amount = qty * price
     charge(user, amount)
     ship(item, qty)`,
		refs: ['CWE-840', 'OWASP-BusinessLogic'],
		tags: ['business-logic', 'client-trust', 'logic-bypass', 'pricing'],
	},
	{
		id: 'CWE-841',
		name: 'Improper Enforcement of Behavioral Workflow',
		lang: 'python',
		status: 'Complete',
		what: `行為工作流程未正確強制（Improper Enforcement of Behavioral Workflow）。系統關係到「一連串狀態必須照著
	某種順序走」的流程，但伺服器沒有強制這個順序：例如購物必須先登入再付款再取貨，但介面允許攻擊者「跳過登入直接取貨」
	、重複執行「已完成的步驟」、或任意往回倒來重跑步驟。成因是每個端點各自為政，只驗證自己那一動，卻不知道整個會話進行到
	哪一步、以及「這一步在此狀態是否合法」。修法是維護伺服器端的流程狀態機：任何進到下一步的請求都要檢查「現在狀態可否到那一步」
	，不合法順序一律拒絕（例如以 token 的一次性、step 欄位、狀態轉移檢查來強制單調前進且不重複）。`,
		problem: `# 不安全寫法:每個步驟只檢查自己,不管它是否發生在對的階段 => 可跳步/重跑
def fulfill(app):
    step = app.get("step")
    if step == "ship":
        do_ship(app)          # 攻擊者可把 step 直接設 ship,跳過付款
        return
    if step == "pay":
        do_pay(app)
    # 完全沒檢查「是否已先登入、是否已付款、是否重複」(workflow 沒被強制)`,
		fixed: `# 安全寫法:伺服器端以狀態機強制流程,狀態不合法就直接拒絕
ALLOWED = {"auth": {"pay"}, "pay": {"ship"}}

def fulfill(server_state, requested):
    expected = ALLOWED.get(server_state, set())
    if requested not in expected:
        raise Forbidden(f"cannot move {server_state}->{requested}")
    if requested == "pay":
        do_pay()
    elif requested == "ship":
        require_authed()
        do_ship()
    server_state = requested   # 狀態只允許前進,且走過的不重複`,
		patch: `@@
-def fulfill(app):
-    step = app.get("step")
-    if step == "ship":
-        do_ship(app)
-        return
-    if step == "pay":
-        do_pay(app)
+def fulfill(server_state, requested):
+    expected = ALLOWED.get(server_state, set())
+    if requested not in expected:
+        raise Forbidden(f"cannot move {server_state}->{requested}")
+    if requested == "pay":
+        do_pay()
+    elif requested == "ship":
+        require_authed()
+        do_ship()
+    server_state = requested`,
		refs: ['CWE-841', 'CWE-1018'],
		tags: ['workflow', 'state-machine', 'step-ordering', 'business-logic'],
	},
	{
		id: 'CWE-895',
		name: 'SFP Primary Cluster: Information Leak',
		lang: 'python',
		status: 'Complete',
		what: `資訊洩漏分類（SFP Primary Cluster: Information Leak）。這是 Software Fault Patterns 階層裡用來統整「系統
	把該保有機密性的資料洩漏出去」這一大類的 Category，底下涵蓋了錯誤訊息外洩內部細節、暫存檔被曝光、session 管理不當、
	以及對未授權者揭露狀態等具體成員。它本身是組織用分類，MITRE 不建議直接用它在實際漏洞對映，應用更精確的洩漏型弱點
	（如 CWE-209 錯誤訊息洩漏內部資訊、CWE-377 暫存檔）來標記。實務守則：任何「回給呼叫端的輸出」都只含最小必要資訊，
	例外訊息不帶檔案路徑／堆疊／SQL，錯誤在 server 端記錄，回給使用者的是通用文案。`,
		problem: `# 不安全寫法:把資料庫例外細節原封不動回給使用者 => 洩漏內部結構
def get_user(uid):
    try:
        return db.fetch(uid)
    except Exception as e:
        # 把底層錯誤(表名/SQL/路徑)直接外洩給呼叫端
        return {"error": str(e)}`,
		fixed: `# 安全寫法:完整細節僅上 server 日誌,回給使用者的是通用文案 => 最小洩漏
def get_user(uid):
    try:
        return db.fetch(uid)
    except Exception as e:
        logger.exception("fetch user failed")      # 細節只留 server 端日誌
        return {"error": "request failed"}       # 對外回傳通用錯誤`,
		patch: `@@
     try:
         return db.fetch(uid)
     except Exception as e:
-        return {"error": str(e)}
+        logger.exception("fetch user failed")
+        return {"error": "request failed"}`,
		refs: ['CWE-895', 'CWE-209'],
		tags: ['information-leak', 'error-disclosure', 'cwe_cat', 'logging'],
	},
];
