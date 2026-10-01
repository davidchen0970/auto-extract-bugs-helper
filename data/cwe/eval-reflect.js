// CWE chunk — category: Dynamic Code / Unsafe Reflection & NoSQL.
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
		id: 'CWE-95',
		name: 'Improper Neutralization of Directives in Dynamically Evaluated Code (e.g. Eval Injection)',
		lang: 'javascript',
		status: 'Complete',
		what: `動態程式碼求值注入（eval injection ／ 程式碼注入）。把使用者輸入用字串拼接後直接
丟給 eval()、Function() 建構子或字串形式的 setTimeout／setInterval，
使用者輸入便會被當成 JavaScript 程式碼執行，等於遠端任意程式碼執行（RCE）。
建議做法是徹底避免對使用者輸入求值，改用查表對照的允許清單加上正規 API。`,
		problem: `// 不安全寫法：把使用者輸入拼成字串直接丟給 eval()，輸入就是程式碼
function applyFilter(code) {
  // 輸入 e.g. "process.mainModule.require('child_process').exec('id')" 即 RCE
  return eval('(' + code + ')');
}
// 另一種：用字串版 setTimeout/setInterval，同樣會把輸入當程式碼執行
setTimeout("updateRow(" + userRowIndex + ")", 100);   // userRowIndex 可帶任意程式`,
		fixed: `// 安全寫法：不用 eval/Function/setTimeout(string)，以允許清單查表解釋操作
const OPS = new Set(['sum', 'avg', 'max', 'min']);
function applyOp(op, values) {
  if (!OPS.has(op)) throw new Error('unknown op');      // 只放行已知動作
  const fn = { sum: vs => vs.reduce((a, b) => a + b, 0),
               avg: vs => vs.reduce((a, b) => a + b, 0) / vs.length }[op];
  return fn(values);
}`,
		patch: `@@
-  return eval('(' + code + ')');
-  setTimeout("updateRow(" + userRowIndex + ")", 100);
+  const OPS = new Set(['sum', 'avg', 'max', 'min']);
+  function applyOp(op, values) {
+    if (!OPS.has(op)) throw new Error('unknown op');
+    const fn = { sum: vs => vs.reduce((a, b) => a + b, 0),
+                 avg: vs => vs.reduce((a, b) => a + b, 0) / vs.length }[op];
+    return fn(values);
+  }`,
		refs: ['OWASP-CodeInjection', 'CWE-95'],
		tags: ['eval', 'code-injection', 'rce', 'javascript'],
	},
	{
		id: 'CWE-470',
		name: 'Use of Externally-Controlled Input to Select Classes or Code (Unsafe Reflection)',
		lang: 'java',
		status: 'Complete',
		what: `不安全反射。用使用者輸入（類別名稱、方法名或命令字）直接決定要反射載入哪個類別、
	呼叫哪個方法，卻沒有比對允許清單。例如把 request 來的 className 直接交給
	Class.forName() 再 newInstance()，攻擊者就能載入任意含可利用建構式的類別達成 RCE。
	建議做法是反射前一定要對輸入做允許清單校驗，只放行預先白名單的類別／命令。`,
		problem: `// 不安全寫法：類別名稱由使用者輸入決定，直接反射並實例化，等於任意類別載入
String className = request.getParameter("className");  // e.g. "org.example.Evil"
Object instance = Class.forName(className)             // 載入後 new 出來
    .getDeclaredConstructor().newInstance();
// 也常見搭配命令字：switch 或直接 newInstance 都由外部參數選動作`,
		fixed: `// 安全寫法：只准從允許清單（白名單）挑類別，外部輸入不能直接選類別或方法
private static final Map<String, Class<?>> HANDLERS = Map.of(
    "invoice", InvoiceHandler.class,
    "order",   OrderHandler.class,
    "report",  ReportHandler.class);

final String choice = request.getParameter("handler");
Class<?> handler = HANDLERS.get(choice);              // 不在白名單即是 null
if (handler == null) throw new SecurityException("unknown handler");
Object instance = handler.getDeclaredConstructor().newInstance();`,
		patch: `@@
-  String className = request.getParameter("className");
-  Object instance = Class.forName(className)
-      .getDeclaredConstructor().newInstance();
+  final String choice = request.getParameter("handler");
+  Class<?> handler = HANDLERS.get(choice);
+  if (handler == null) throw new SecurityException("unknown handler");
+  Object instance = handler.getDeclaredConstructor().newInstance();`,
		refs: ['OWASP', 'CWE-470'],
		tags: ['reflection', 'class-loading', 'rce', 'java', 'whitelist'],
	},
	{
		id: 'CWE-749',
		name: 'Exposed Dangerous Method or Function',
		lang: 'javascript',
		status: 'Complete',
		what: `把危險的方法／功能直接暴露出去。把敏感、內部或足以造成危害的函式（如刪除檔案、
	執行 shell、重設密碼、內部管理操作）以開放的 API 路由、RPC 或 RMI 介面直接對外，
	且缺乏權限檢查。攻擊者只要呼叫這個公開端點就能觸發原本該受保護的行為。
	建議做是行為本身仍要權限控管，並把危險操作包在最小權限的服務端後端，不直接對外。`,
		problem: `// 不安全寫法：把內部危險函式直接綁到公開路由，任何人都可直接呼叫刪檔
const methods = {
  // loader.run(args) 內部方法，可能執行 shell / 變更系統狀態
  runServiceAction: (args) => svc.runServiceAction(args.action, args.target),
};
// 開放的字串導向 RPC：客戶端隨意指定要呼叫哪個方法，重未檢查權限
function rpcHandler(req, res) {
  methods[req.body.method](req.body.args);   // 傳 "runServiceAction" 就執行危險操作
  res.sendStatus(200);
}`,
		fixed: `// 安全寫法：對外只暴露受允許、包好的動作，危險方法絕不直接出現於公開介面
const PUBLIC_ACTIONS = new Map([
  ['getStatus',  () => svc.getStatus()],     // 只暴露無害的唯讀動作
  ['getLogTail', () => svc.getLogTail()],
]);

function rpcHandler(req, res) {
  const action = PUBLIC_ACTIONS.get(req.body.method);  // 危險方法根本不在其中
  if (!action) return res.status(400).json({ error: 'unknown action' });
  if (!isAuthorized(req.user, req.body.method))         // 且仍需權限檢查
    return res.status(403).json({ error: 'forbidden' });
  res.json(action());
}`,
		patch: `@@
-  methods[req.body.method](req.body.args);
-  res.sendStatus(200);
+  const action = PUBLIC_ACTIONS.get(req.body.method);
+  if (!action) return res.status(400).json({ error: 'unknown action' });
+  if (!isAuthorized(req.user, req.body.method))
+    return res.status(403).json({ error: 'forbidden' });
+  res.json(action());`,
		refs: ['OWASP-API', 'CWE-749'],
		tags: ['rpc', 'exposed-method', 'privilege', 'api'],
	},
	{
		id: 'CWE-943',
		name: 'Improper Neutralization of Special Elements in Data Query Logic (NoSQL Injection)',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `NoSQL 注入。把使用者輸入用字串拼接直接建 MongoDB 等 NoSQL 查詢，
	或讓使用者提供的欄位根本就是操作符物件（如 { [field]: { $gt: '' } }），
	攻擊者就能用 $ne、$gt、$where、/^admin.*$/ 正則改寫查詢邏輯，騙過驗證或列資料。
	建議做是用參數查詢 API 傳值，並用允許清單限制可被查詢的欄位，拒絕操作符物件。`,
		problem: `// 不安全寫法：把使用者輸入直接拼進字串查詢，或整包物件當 query 條件
const col = db.collection('users');
// 字串拼接：username 可帶 ' || true 改寫整個邏輯
col.find("username == '" + req.body.user + "'", { password: 1 }).toArray();
// 整包 $or 注入：送出 { $gt: '' } 讓條件永遠成立 → 列舉全部帳號
col.find({ $or: [{ user: req.body.user }, { admin: { $gt: '' } }] }).toArray();`,
		fixed: `// 安全寫法：用參數化查詢傳值（不拼接），並限制可查的欄位、擋掉操作符物件
const ALLOWED_FIELDS = new Set(['username', 'email']);

function safeFind(filters) {
  const parsed = {};
  for (const [k, v] of Object.entries(filters)) {
    if (!ALLOWED_FIELDS.has(k)) continue;         // 鍵白名單，外部鍵無法做操作符
    if (v && typeof v === 'object') throw new Error('operators not allowed'); // $gt/$ne…
    parsed[k] = v;                                // 純值由 driver 參數化處理
  }
  return db.collection('users').find(parsed, { password: 0 }).toArray();
}`,
		patch: `@@
-  col.find("username == '" + req.body.user + "'", { password: 1 });
-  col.find({ $or: [{ user: req.body.user }, { admin: { $gt: '' } }] });
+  const parsed = safeFind(req.body.filters);      // 欄位白名單 + 擋操作符物件
+  return db.collection('users').find(parsed, { password: 0 });`,
		refs: ['OWASP-NoSQLInjection', 'CWE-943'],
		tags: ['mongodb', 'nosql', 'injection', 'query'],
	},
];
