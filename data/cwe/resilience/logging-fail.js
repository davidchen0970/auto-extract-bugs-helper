// CWE chunk — category: Log Injection / Overflow & Insufficient Monitoring.
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
		id: 'CWE-93',
		name: 'Improper Neutralization of CRLF Sequences',
		lang: 'python',
		status: 'Complete',
		what: `CRLF 字元（\\r\\n）未做中和的 log injection／log spoofing。把使用者輸入（如帳號、User-Agent、
請求標頭）未消毒就接進 logger 或 print 的訊息字串，攻擊者可以在輸入中夾帶 \\r\\n 造假一整段日誌行、
模仿登入成功或管理員操作的假紀錄，誤導維運與資安鑑識，甚至隱藏真實攻擊行為。建議做法是把輸入中的
\\r、\\n 或其他控制字元全部換成安全的跳脫表示（如 \\r → %0d），再送進日誌框架，確保每筆紀錄只有一行。`,
		problem: `# 不安全寫法：User-Agent 直接拼進 log，夾帶 \\r\\n 就能偽造一整行
import logging, os

log = logging.getLogger("web")

def audit_request(client_ip, user_agent, status=200):
    # user_agent 可能是: 'evil\\r\\n[INFO] admin login OK\\r\\n normal'
    log.info("req ip=%s ua=%s status=%s", client_ip, user_agent, status)`,
		fixed: `# 安全寫法：先把 \\r\\n 等控制字元跳脫，再進 log，一行只是一個事件
import logging, re

log = logging.getLogger("web")

_CTRL = re.compile(r"[\\r\\n\\x00-\\x1f\\x7f]")

def sanitize(field: str) -> str:
    # 換成可讀的跳脫表示，避免日誌行注入
    return _CTRL.sub(lambda m: "\\\\x%02x" % ord(m.group()), field)

def audit_request(client_ip, user_agent, status=200):
    log.info("req ip=%s ua=%s status=%s", sanitize(client_ip), sanitize(user_agent), status)`,
		patch: `@@
  def audit_request(client_ip, user_agent, status=200):
      # user_agent 可能是: 'evil\\r\\n[INFO] admin login OK\\r\\n normal'
-     log.info("req ip=%s ua=%s status=%s", client_ip, user_agent, status)
+     log.info("req ip=%s ua=%s status=%s", sanitize(client_ip), sanitize(user_agent), status)
+
+  def sanitize(field: str) -> str:
+      return _CTRL.sub(lambda m: "\\\\x%02x" % ord(m.group()), field)`,
		refs: ['OWASP-LogInjection', 'CWE-93'],
		tags: ['log-injection', 'crlf', 'log-spoofing', 'logging'],
	},
	{
		id: 'CWE-117',
		name: 'Improper Output Neutralization for Logs',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `日誌輸出的 Log Injection 靜態缺陷。把未經中和的使用者輸入直接寫入日誌，允許輸入內的換行
與控制字元（\\n、\\r、\\x1b 等）穿透進日誌內容，讓攻擊者可以把假造的日誌行注入、或覆蓋／竄改既有紀錄。
與 CWE-93 不同，CWE-117 泛指對日誌輸出給定內容缺乏消毒——只要使用者可控的字串進到 log 就成立，
與是否刻意造假一行無關。建議做法是所有動態內容進入 logging 之前先跑跳脫／換行的清洗函式，
限制每筆日誌為單一不可拆分行，並對非 ASCII 控制字元做編碼。`,
		problem: `// 不安全寫法：直接把回報者提供的字串塞進 log，夾帶換行即注入浮點假紀錄
const log = require('pino')();

function report(username, message) {
  // message = "請處理\\n[ERROR] pay failed amount=9999\\n" 會偽造一行假錯誤
  log.info('user ' + username + ' reported: ' + message);
}`,
		fixed: `// 安全寫法：把內容中的控制字元 UTF-8 跳脫後再記，保留單一「事件一行」語意
const log = require('pino')();

function escapeLine(s = '') {
  // 換 0x00-0x1F、0x7F 控制字元為 %XX，讓日誌框架不會把輸入當成另一行
  return s.replace(/[\\x00-\\x1f\\x7f]/g, (c) => '%' + c.charCodeAt(0).toString(16).padStart(2, '0'));
}

function report(username, message) {
  log.info({ user: escapeLine(username) }, 'user reported: ' + escapeLine(message));
}`,
		patch: `@@
  function report(username, message) {
    // message = "請處理\\n[ERROR] pay failed amount=9999\\n" 會偽造一行假錯誤
-   log.info('user ' + username + ' reported: ' + message);
+   log.info({ user: escapeLine(username) }, 'user reported: ' + escapeLine(message));
  }
+
+ function escapeLine(s = '') {
+   return s.replace(/[\\x00-\\x1f\\x7f]/g, (c) => '%' + c.charCodeAt(0).toString(16).padStart(2, '0'));
+ }`,
		refs: ['OWASP-LogInjection', 'CWE-117'],
		tags: ['log-injection', 'logging', 'neutralization', 'log-forging'],
	},
	{
		id: 'CWE-210',
		name: 'Self-generated Error Message Containing Sensitive Information',
		lang: 'java',
		status: 'Complete',
		what: `自己產生的錯誤訊息帶出敏感資訊。應用程式主動組裝錯誤訊息時，把內部例外 message、堆疊機跡
trace、SQL 語句、連線字串、使用者名資料庫欄位與使用者身分等一起回傳給呼叫端。攻擊者光靠觸發
不同輸入引發的錯誤回應，就能逐步拼出資料表結構、版本、內部路徑與業務規則。建議做法是
外層回應只回泛化錯誤碼與訊息，真正診斷內容（例外類別、堆疊、敏感欄位）寫進伺服器端日誌，
並再以白名單映射使用者可讀的錯誤。外部可讀訊息不得含任何欄位值或機跡。`,
		problem: `// 不安全寫法：錯誤回應內建堆疊機跡與 SQL，把內部結構直接外洩
@RestController
public class OrderController {
    @GetMapping("/order/{id}")
    public String getOrder(@PathVariable long id) {
        try {
            return orderRepo.findSql(id);            // 底層可能拋 RuntimeException
        } catch (Throwable t) {
            StringBuilder sb = new StringBuilder("查詢失敗: ");
            sb.append(t.getMessage());               // 堆疊、SQL、類別名全外洩
            for (StackTraceElement s : t.getStackTrace()) sb.append(s).append("\\n");
            return sb.toString();                    // 回給瀏覽器的完整堆疊
        }
    }
}`,
		fixed: `// 安全寫法：回應只給泛化錯誤，完整診斷寫進伺服器端日誌
@RestController
public class OrderController {
    private static final Logger LOG = LoggerFactory.getLogger(OrderController.class);

    @GetMapping("/order/{id}")
    public String getOrder(@PathVariable long id) {
        try {
            return orderRepo.findSql(id);
        } catch (Throwable t) {
            LOG.error("order lookup failed id={}", id, t);   // 診斷進日誌
            return "查詢失敗，請稍後重試";                     // 前端只有泛化訊息
        }
    }
}`,
		patch: `@@
      try {
          return orderRepo.findSql(id);            // 底層可能拋 RuntimeException
      } catch (Throwable t) {
-         StringBuilder sb = new StringBuilder("查詢失敗: ");
-         sb.append(t.getMessage());               // 堆疊、SQL、類別名全外洩
-         for (StackTraceElement s : t.getStackTrace()) sb.append(s).append("\\n");
-         return sb.toString();                    // 回給瀏覽器的完整堆疊
+         LOG.error("order lookup failed id={}", id, t);   // 診斷進日誌
+         return "查詢失敗，請稍後重試";                     // 前端只有泛化訊息
      }`,
		refs: ['CWE-210', 'OWASP-ErrorHandling'],
		tags: ['error-message', 'information-disclosure', 'stack-trace', 'logging'],
	},
	{
		id: 'CWE-778',
		name: 'Insufficient Logging',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `日誌記錄不足，導致安全事件無從稽核。登入失敗、授權遭拒、帳號鎖定、設定變更、權限升降或
金鑰輪換等攸關安全的動作沒有記任何日誌；即使有記，也沒帶上時間、使用者、來源 IP、結果與事件唯一
識別碼，讓稽核與事件回應完全失去裉據。攻擊者的探查、列舉或被拒嘗試都不留痕跡，事後也無法定案
是否真的被入侵。建議做法是為所有安全相關活動撰寫結構化稽核日誌（誰、什麼時間、做了什麼、從哪來、
成功與否），並設定集中彙整與告警，讓異常登入或授權拒絕能被即時偵測。`,
		problem: `// 不安全寫法：登入與授權失敗都不記 log，暴力破解與探測完全無跡可循
const express = require('express');
const app = express();

app.post('/api/login', (req, res) => {
  const ok = users.verify(req.body.user, req.body.pass);
  if (!ok) {
    res.status(401).json({ error: 'bad credentials' });   // 不留下任何紀錄
    return;
  }
  res.json({ token: issueToken(req.body.user) });
});

app.get('/api/admin', (req, res) => {
  if (!req.user?.role === 'admin') {
    return res.sendStatus(403);                            // 連 403 都沒記
  }
  res.send(adminPanel);
});`,
		fixed: `// 安全寫法：把失敗嘗試與敏感操作寫成結構化稽核日誌，供後續告警與事後鑑識
const express = require('express');
const pino = require('pino');
const audit = pino({ name: 'security-audit' });   // 集中到安全日誌/告警系統
const app = express();

app.post('/api/login', (req, res) => {
  const ok = users.verify(req.body.user, req.body.pass);
  if (!ok) {
    audit.warn({ user: req.body.user, ip: req.ip, event: 'login.failed' });
    res.status(401).json({ error: 'bad credentials' });
    return;
  }
  audit.info({ user: req.body.user, ip: req.ip, event: 'login.ok' });
  res.json({ token: issueToken(req.body.user) });
});

app.get('/api/admin', (req, res) => {
  if (req.user?.role !== 'admin') {
    audit.warn({ user: req.user?.sub, ip: req.ip, path: req.path, event: 'authz.denied' });
    return res.sendStatus(403);                    // 授權拒絕也留下稽核軌跡
  }
  res.send(adminPanel);
});`,
		patch: `@@
  app.post('/api/login', (req, res) => {
    const ok = users.verify(req.body.user, req.body.pass);
    if (!ok) {
+     audit.warn({ user: req.body.user, ip: req.ip, event: 'login.failed' });
      res.status(401).json({ error: 'bad credentials' });   // 不留下任何紀錄
      return;
    }
+   audit.info({ user: req.body.user, ip: req.ip, event: 'login.ok' });
    res.json({ token: issueToken(req.body.user) });
  });
 
  app.get('/api/admin', (req, res) => {
-   if (!req.user?.role === 'admin') {
+   if (req.user?.role !== 'admin') {
+     audit.warn({ user: req.user?.sub, ip: req.ip, path: req.path, event: 'authz.denied' });
      return res.sendStatus(403);                            // 連 403 都沒記
    }
    res.send(adminPanel);
  });`,
		refs: ['OWASP-Logging4', 'CWE-778'],
		tags: ['insufficient-logging', 'audit', 'monitoring', 'authz-denied'],
	},
];
