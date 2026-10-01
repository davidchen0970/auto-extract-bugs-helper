// CWE chunk — category: Logging / Sensitive Information Disclosure.
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
		id: 'CWE-532',
		name: 'Insertion of Sensitive Information into Log File',
		lang: 'java',
		status: 'Complete',
		what: `把敏感資訊寫進日誌檔。程式直接把使用者敏感資料、完整路徑、系統資訊寫進 log，等於為攻擊者開了一條
防護較薄弱、更容易取得的獲取資訊管道。登入失敗、交易或例外處理時，開發者常順手把 request 的整個參數、
密碼明文、信用卡號、token 塞進 logger.info／printStackTrace，甚至連資料庫查詢字串也一併印出（會洩漏表名、
欄名，反而方便 SQL injection），接著這些資料就永久落在日誌檔案，對能讀到日誌的人——含下游彙整、備援、維運——
全部曝光。修法是先認真想清楚寫進日誌的資訊有多敏感，絕不把秘密寫進 log；部署到 production 前移除除錯 log、
把設定從 debug 狀態正確調回正式層級，並保護日誌檔防止未授權讀寫。平常只記可以識別但不敏感的欄位（例如訂單
編號、使用者 ID），密碼／金鑰／卡號一律遮蔽或完全不記錄。`,
		problem: `// 不安全寫法：例外時直接把整張 request、密碼一起寫進 log
@PostMapping("/register")
public void register(@RequestBody UserReq req) {
    try {
        UserService.create(req);          // 記錄: 含明文 password
        log.info("register ok, body=" + req.toString());
    } catch (Exception e) {
        log.error("failed body=" + req.toString(), e);   // password 落 log
    }
}`,
		fixed: `// 安全寫法：只log識別用的身分，密碼移除後再看要不要記
import java.util.Objects;

@PostMapping("/register")
public void register(@RequestBody UserReq req) {
    try {
        UserService.create(req);          // req 內不該攜帶 password 欄位
        log.info("register ok, user=" + mask(req.getUsername()));
    } catch (Exception e) {
        log.error("failed user=" + mask(req.getUsername()), e);  // 不打秘密
    }
}
private String mask(String s) {
    return s == null ? "" : s.substring(0, Math.min(3, s.length())) + "***";
}`,
		patch: `@@
     try {
-        UserService.create(req);          // 記錄: 含明文 password
-        log.info("register ok, body=" + req.toString());
+        UserService.create(req);          // req 內不該攜帶 password 欄位
+        log.info("register ok, user=" + mask(req.getUsername()));
     } catch (Exception e) {
-        log.error("failed body=" + req.toString(), e);   // password 落 log
+        log.error("failed user=" + mask(req.getUsername()), e);  // 不打秘密
     }
-}
+}
+private String mask(String s) {
+    return s == null ? "" : s.substring(0, Math.min(3, s.length())) + "***";
+}`,
		refs: ['OWASP-Logging', 'CWE-532'],
		tags: ['logging', 'log', 'sensitive-data'],
	},
	{
		id: 'CWE-534',
		name: 'Information Exposure Through Debug Log Files',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `除錯日誌洩漏資訊。開發時常用 console.log 把變數、主機資訊、內部設定甚至原始請求整包印出來；
一旦 production 忘了關掉或層級仍設在 debug，這些開發用日誌就會把內部結構、環境細節、可能的秘密
持續寫入日誌檔。建議做法是把除錯輸出限定在開發環境用 logger debug level，正式環境一律 INFO 起跳，
且不要把未地化的細節用 console.log 烙在程式碼裡。`,
		problem: `// 不安全寫法：production 也留著 console.log 把整個 request/機密一次印光
const express = require('express');
const app = express();
app.use(express.json());

app.post('/api/pay', (req, res) => {
  console.log('DEBUG raw body:', req.body);        // 卡號、CVV 全都在 log
  console.log('req headers:', req.headers);        // authorization token 外洩
  charge(req.body);
  res.sendStatus(200);
});`,
		fixed: `// 安全寫法：敏感主體用 log.enabled('debug') 才印，正式環境不會輸出
const express = require('express');
const createLogger = require('pino');
const log = createLogger();                    // 正式環境 level=info，debug 會過濾
const app = express();
app.use(express.json());

app.post('/api/pay', (req, res) => {
  if (log.levelVal) { ; }                     // (占位) 只在需要時進 debug
  const txn = { cardLast4: req.body.card?.slice(-4), amount: req.body.amount };
  log.debug({ txn }, 'charge request');        // debug level，且只記遮罩欄位
  charge(req.body);
  res.sendStatus(200);
});`,
		patch: `@@
 app.post('/api/pay', (req, res) => {
-  console.log('DEBUG raw body:', req.body);        // 卡號、CVV 全都在 log
-  console.log('req headers:', req.headers);        // authorization token 外洩
+  if (log.levelVal) { ; }                     // (占位) 只在需要時進 debug
+  const txn = { cardLast4: req.body.card?.slice(-4), amount: req.body.amount };
+  log.debug({ txn }, 'charge request');        // debug level，且只記遮罩欄位
   charge(req.body);
   res.sendStatus(200);
 });`,
		refs: ['OWASP-DebugLog', 'CWE-534'],
		tags: ['debug-log', 'logging', 'disclosure'],
	},
	{
		id: 'CWE-535',
		name: 'Exposure of Information Through Shell Error Message',
		lang: 'python',
		status: 'Complete',
		what: `把系統資訊透過 Shell（命令列）錯誤訊息外洩出去。命令列的錯誤訊息本身就揭示了後端應用程式碼裡存在
未處理（unhandled）的例外；很多情況下，攻擊者可以善用這些會觸發錯誤的條件，取得對系統的未授權存取。
呼叫 subprocess／os.system、或作業系統在命令執行失敗時，若直接把完整命令、絕對路徑、環境變數或整段底層例外
堆疊回傳／顯示出來，這些細節能協助攻擊者推敲部署結構、套件版本與內部目錄，進而設計後續侵入。修法是只對外
回傳泛化的錯誤訊息、明確告知「命令失敗」即可，把完整的診斷內容改寫進伺服器端日誌供維運查閱，絕不在回應
或使用者介面上顯示未處理例外與原始的 shell 輸出，阻斷這條不合法的資訊外洩管道。`,
		problem: `# 不安全寫法：命令失敗時把整段 traceback 與命令內容直接吐給使用者
import subprocess

def run_backup():
    try:
        subprocess.run(["rsync", "-av", "/srv/data", "/mnt/backup"], check=True)
    except subprocess.CalledProcessError as e:
        return f"備份失敗: {e.cmd} exit={e.returncode}\\n{e.stderr}"   # 路徑/命令全洩給前端`,
		fixed: `# 安全寫法：回應只給泛化訊息，詳細 stderr 寫進伺服器端日誌
import subprocess, logging

log = logging.getLogger("backup")

def run_backup():
    try:
        subprocess.run(["rsync", "-av", "/srv/data", "/mnt/backup"], check=True)
    except subprocess.CalledProcessError as e:
        log.error("backup failed: %r exit=%s stderr=%s", e.cmd, e.returncode, e.stderr)
        return "備份失敗，請聯絡維運"   # 前端只看得到泛化訊息`,
		patch: `@@
 def run_backup():
     try:
         subprocess.run(["rsync", "-av", "/srv/data", "/mnt/backup"], check=True)
     except subprocess.CalledProcessError as e:
-        return f"備份失敗: {e.cmd} exit={e.returncode}\\n{e.stderr}"   # 路徑/命令全洩給前端
+        log.error("backup failed: %r exit=%s stderr=%s", e.cmd, e.returncode, e.stderr)
+        return "備份失敗，請聯絡維運"   # 前端只看得到泛化訊息`,
		refs: ['CWE-535', 'OWASP-ErrorHandling'],
		tags: ['shell', 'error-message', 'information-disclosure'],
	},
	{
		id: 'CWE-615',
		name: 'Inclusion of Sensitive Information in Source Code Comments',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `在程式註解裡寫入敏感資訊。維護者為了方便，常把「真帳號密碼」「API 金鑰」「內網連線字串」
當成備註寫在註解旁，這種資訊會跟著原始碼進版本庫、內部分支、UAT——進出團隊與CI機器的人全都看得到。
CWE-615 強調註解也是程式內容，一旦版本庫外洩或被拉取，密碼就跟著外洩，也無法快速輪換。建議做法是註解只寫目的
與意圖，不在程式碼（含註解）中出現任何可用的秘密，並用 secret scanner 掃過歷次提交。`,
		problem: `// 不安全寫法：註解旁邊直接寫真密碼，秘密隨原始碼進版本庫
const jwt = require('jsonwebtoken');

// FIXME: 連正式資料庫都用這個密碼: P@ssw0rd-2024!
const DB_PASS = 'P@ssw0rd-2024!';

// 付款用的 HMAC 金鑰請勿更動，會壞掉:  kh7f00D3d!8JkP
function sign(data) {
  return jwt.sign(data, 'kh7f00D3d!8JkP', { expiresIn: '1h' });
}`,
		fixed: `// 安全寫法：註解只描述目的；秘密從環境變數讀入，並由 secret scanner 把關
const jwt = require('jsonwebtoken');

// 資料庫帳號密碼由部署平台注入環境變數，勿寫死在碼上
const DB_PASS = process.env.DB_PASS;

// 付款簽章金鑰從環境取得，缺失時直接啟動失敗而非用預設值
function sign(data) {
  const key = process.env.PAYMENT_HMAC_SECRET;
  if (!key) throw new Error('PAYMENT_HMAC_SECRET not configured');
  return jwt.sign(data, key, { expiresIn: '1h' });
}`,
		patch: `@@
-// FIXME: 連正式資料庫都用這個密碼: P@ssw0rd-2024!
-const DB_PASS = 'P@ssw0rd-2024!';
+// 資料庫帳號密碼由部署平台注入環境變數，勿寫死在碼上
+const DB_PASS = process.env.DB_PASS;
 
-// 付款用的 HMAC 金鑰請勿更動，會壞掉:  kh7f00D3d!8JkP
+// 付款簽章金鑰從環境取得，缺失時直接啟動失敗而非用預設值
 function sign(data) {
-  return jwt.sign(data, 'kh7f00D3d!8JkP', { expiresIn: '1h' });
+  const key = process.env.PAYMENT_HMAC_SECRET;
+  if (!key) throw new Error('PAYMENT_HMAC_SECRET not configured');
+  return jwt.sign(data, key, { expiresIn: '1h' });
 }`,
		refs: ['CWE-615', 'OWASP-Secrets'],
		tags: ['comments', 'secrets', 'hardcoded'],
	},
];
