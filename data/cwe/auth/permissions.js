// CWE chunk — category: Permissions / Privilege Management.
// One chunk = one category, <= 5 entries. Every entry:
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
		id: 'CWE-250',
		name: 'Execution with Unnecessary Privileges',
		lang: 'python',
		status: 'Complete',

		what: `以不必要的權限執行。程式整體以過高的作業系統權限運行，例如把網頁伺服器、工作程式整個用 root
	或 SYSTEM 身分啟動，即使它根本不需要那些能力。一旦程式被漏洞或惡意輸入攻陷，攻擊者就能享受
	它身上多出來的所有權限，把單點弱點放大成系統級入侵。正確做法是只用實際需要的最小權限開跑，
	需要特權的初始化（綁特權連接埠、讀金鑰）完成後就立刻永久性地降權。`,

		problem: `# 不安全寫法：整個服務以 root 起跑，之後從不降權，程式全程帶超級使用者身分
import os
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        data = open('/etc/app/config.ini').read()   # 讀敏感的系統檔
        self.wfile.write(data.encode())

if __name__ == '__main__':
    # 被 systemd 以 User=root 拉起，內部完全沒有降權邏輯
    HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()`,

		fixed: `# 安全寫法：需要 root 的初始化（綁特權埠）一做完，就立刻永久降到專用 uid
import os, pwd
from http.server import HTTPServer, BaseHTTPRequestHandler

UNPRIVILEGED = pwd.getpwnam('webapp').pw_uid   # 專用低權限帳號

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            data = open('/etc/app/config.ini').read()
        except OSError:                          # 降權後只能讀它應讀的檔
            return self.send_error(403)
        self.wfile.write(data.encode())

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8080), Handler)   # 綁特權埠仍需要 root
    os.setuid(UNPRIVILEGED)                     # 之後永久丟掉 root，不再恢復
    server.serve_forever()`,

		patch: `@@
  import os
+ import pwd
  from http.server import HTTPServer, BaseHTTPRequestHandler
 
+ UNPRIVILEGED = pwd.getpwnam('webapp').pw_uid   # 專用低權限帳號
+
  class Handler(BaseHTTPRequestHandler):
      def do_GET(self):
-         data = open('/etc/app/config.ini').read()
+         try:
+             data = open('/etc/app/config.ini').read()
+         except OSError:
+             return self.send_error(403)
          self.wfile.write(data.encode())
 
  if __name__ == '__main__':
-     # 被 systemd 以 User=root 拉起，內部完全沒有降權邏輯
-     HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
+     server = HTTPServer(('0.0.0.0', 8080), Handler)
+     os.setuid(UNPRIVILEGED)                     # 綁完特權埠就永久降權
+     server.serve_forever()`,
		refs: ['OWASP-LeastPrivilege', 'CWE-250'],
		tags: ['privilege', 'least-privilege', 'setuid', 'privesc'],
	},
	{
		id: 'CWE-264',
		name: 'Permissions, Privileges, and Access Controls',
		lang: 'nodejavascript',
		status: 'Deprecated',

		what: `權限、特權與存取控制（Permissions, Privileges, and Access Controls）——這是 MITRE 已停用
	（Deprecated）的最高層支柱（Pillar）條目。它曾是一整棵「誰能對哪個資源做什麼」弱點樹的根，
	把不當身分驗證、不當授權、權限指派、最小權限原則與工作階段管理等全部攏括進來，過於抽象、
	幾乎無法映射到單一真實弱點，MITRE 現已不再建議使用此 ID 做為弱點標籤。實務上應對症到它的
	具體子條目，例如 CWE-269 不當權限管理、CWE-284 不當存取控制、CWE-285 不當授權。本條保留
	範例意在示範「存取規則沒有統一閘門、四散且可繞過」這種概括性缺陷的樣貌。`,
		problem: `// 概貌示範：權限判斷散落在各 handler，規則不統一，其中一個路由可被人繞過
app.get('/api/doc/:name', (req, res) => {
  // 沒有身分也放行：這個 handler 認「路徑開頭」就給讀
  if (req.path.startsWith('/api/doc/')) return send(fetch(req.params.name));
  res.sendStatus(403);
});

app.get('/api/secret', (req, res) => {   // 另一個入口卻又要求登入，行為不一致
  if (!req.session.uid) return res.sendStatus(403);
  res.send(loadSecret());
});`,
		fixed: `// 概貌修法：所有資源統一收斂到一只共用閘門，規則單一、以伺服器端決定權限
function requireAccess(kind, resource) {
  return (req, res, next) => {
    if (!req.session || !req.session.uid) return next(unauthorized());
    const role = db.userRoles.get(req.session.uid);          // 以 DB 為唯一依據
    if (!allow(role, kind, resource)) return next(forbidden());
    next();
  };
}
app.get('/api/doc/:name', requireAccess('read', 'doc'), (req, res) => res.send(fetch(req.params.name)));
app.get('/api/secret',  requireAccess('read', 'secret'), (req, res) => res.send(loadSecret()));`,
		patch: `@@
-  app.get('/api/doc/:name', (req, res) => {
-    // 沒有身分也放行：這個 handler 認「路徑開頭」就給讀
-    if (req.path.startsWith('/api/doc/')) return send(fetch(req.params.name));
-    res.sendStatus(403);
-  });
-  app.get('/api/secret', (req, res) => {
-    if (!req.session.uid) return res.sendStatus(403);
-    res.send(loadSecret());
-  });
+  function requireAccess(kind, resource) {
+    return (req, res, next) => {
+      if (!req.session || !req.session.uid) return next(unauthorized());
+      const role = db.userRoles.get(req.session.uid);
+      if (!allow(role, kind, resource)) return next(forbidden());
+      next();
+    };
+  }
+  app.get('/api/doc/:name', requireAccess('read', 'doc'), (req, res) => res.send(fetch(req.params.name)));
+  app.get('/api/secret',  requireAccess('read', 'secret'), (req, res) => res.send(loadSecret()));`,
		refs: ['OWASP-AccessControl', 'CWE-284'],
		tags: ['permissions', 'privilege', 'access-control', 'deprecated'],
	},
	{
		id: 'CWE-265',
		name: 'Privilege Issues',
		lang: 'nodejavascript',
		status: 'Complete',

		what: `權限議題（Privilege Issues）——這是 CWE 的一個彙整類別（Category）。它收納「權限的指派、管理與
	處理不當」所衍生的整群弱點。權限是賦予某個主體的特殊能力，使其能做原本不允許的動作，例如重啟主機、
	寫特定目錄、指派人；當這些權限被錯誤指派、被過度保留、或使用區域超出授權範圍時，問題就落入這個類別。
	因為這是聚合層級而非單一具體缺陷，MITRE 標示此 ID「不應用於真實弱點映射」。要真正修復，必須往下挑出
	具體的基礎／變異子條目——CWE-266 不當權限指派、CWE-271 降權錯誤、CWE-272 違反最小權限——
	逐一補洞，而不是停在「權限有問題」這種層次。`,
		problem: `// 概括示範：權限「給得大而無當」，一個角色被塞進大量不相干的能力一起授出
const ROLE_DB = {
  shipper: ['ship', 'download-report', 'delete-any-order', 'restart-worker'], // 能力過度併捆
};

function can(jwt, action) {
  const roles = ROLE_DB[jwt.role] || [];
  return roles.includes(action) || roles.includes('*');   // 還留了一扇萬用後門
}`,
		fixed: `// 概括修法：能力細粒度拆開，任何角色只授與任務實際需要的子集，絕不留 * 通配
const GRANTS = {
  shipper: ['ship'],
  report_viewer: ['download-report'],
  admin: ['ship', 'download-report', 'delete-any-order'],
};

function can(jwt, action) {
  if (!jwt || !jwt.role) return false;
  const allowed = GRANTS[jwt.role] || [];
  if (allowed.includes('*')) return false;         // 明確擋掉萬用通配
  return allowed.includes(action);
}`,
		patch: `@@
-  const ROLE_DB = {
-    shipper: ['ship', 'download-report', 'delete-any-order', 'restart-worker'],
-  };
-  function can(jwt, action) {
-    const roles = ROLE_DB[jwt.role] || [];
-    return roles.includes(action) || roles.includes('*');
-  }
+  const GRANTS = {
+    shipper: ['ship'],
+    report_viewer: ['download-report'],
+    admin: ['ship', 'download-report', 'delete-any-order'],
+  };
+  function can(jwt, action) {
+    if (!jwt || !jwt.role) return false;
+    const allowed = GRANTS[jwt.role] || [];
+    if (allowed.includes('*')) return false;
+    return allowed.includes(action);
+  }`,
		refs: ['OWASP-LeastPrivilege', 'CWE-264'],
		tags: ['privilege', 'permissions', 'roles'],
	},
	{
		id: 'CWE-266',
		name: 'Incorrect Privilege Assignment',
		lang: 'nodejavascript',
		status: 'Complete',

		what: `不當的權限指派（Incorrect Privilege Assignment）。系統把「多於所需」的特權授予某個主體，造就出超過
	預期的控制範圍——例如給一般使用者管理員角色、或把資料庫連線的整套 root 能力一起交付。常見肇因是對權限
	模型缺乏盤點，以「圖個方便」直接套最高權限角色，或把角色所能涵蓋的資源範圍定義過寬。被多給權限的一方
	一旦被攻陷，攻擊者就會完整繼承它身上多出來的那一整片控制面。正確做法是先最小化指派：為每一種任務建立
	精確的最小角色、只授與該任務實際上需要的權限，並定期稽核權限清單、主動收回不再必要的項目。`,
		problem: `// 不安全寫法：身分判定失敗就一律退讓成 admin，把最高權限當成萬用兜底
app.post('/api/ops/:cmd', async (req, res) => {
  const principal = await resolvePrincipal(req.session.uid);   // 可能解析失敗
  const role = principal?.role ?? 'admin';                  // 找不到就給 admin = 權限錯授
  if (role !== 'admin') return res.sendStatus(403);
  await execOp(req.params.cmd);
  res.sendStatus(204);
});`,
		fixed: `// 安全寫法：解析不出身分就明確拒絕，權限只授與「最小的必要既定角色」
app.post('/api/ops/:cmd', async (req, res) => {
  if (!req.session || !req.session.uid) return res.sendStatus(401);
  const principal = await resolvePrincipal(req.session.uid);
  if (!principal || !GLOBAL_ROLES[principal.role])          // 不存在＝沒這種角色
    return res.sendStatus(403);                            // 失敗即拒絕，絕不升高
  if (!HAS_OP(principal.role, req.params.cmd)) return res.sendStatus(403);
  await execOp(req.params.cmd);
  res.sendStatus(204);
});`,
		patch: `@@
    const principal = await resolvePrincipal(req.session.uid);
-   const role = principal?.role ?? 'admin';
+   if (!principal || !GLOBAL_ROLES[principal.role])
+     return res.sendStatus(403);
+   const role = principal.role;
     if (role !== 'admin') return res.sendStatus(403);
-   await execOp(req.params.cmd);
+   if (!HAS_OP(role, req.params.cmd)) return res.sendStatus(403);
+   await execOp(req.params.cmd);`,
		refs: ['OWASP-LeastPrivilege', 'CWE-266'],
		tags: ['privilege-assignment', 'roles', 'elevation'],
	},
	{
		id: 'CWE-267',
		name: 'Privilege Defined With Unsafe Actions',
		lang: 'nodejavascript',
		status: 'Complete',

		what: `權限被定義成可執行不安全動作（Privilege Defined With Unsafe Actions）。某個權限／角色／能力即使「指派給
	正確的人」，仍然被他拿去做當初從未設想過的危險動作。典型是設計時粒度太粗：例如一位「維護者」角色一次附帶
	了改設定、執行遠端命令、覆寫他人檔案等一大堆併在一起的能力，於是只要取得該權限，就同時握有多把關鍵鑰匙；
	甚至能力本身（如允許迭帶改權）就足以自我升級。補救方向是把細粒度的動作拆開，不要讓「危險」與「一般」動作
	綁在同一把權限上，並在設計階段就質問：賦予這個權限之後，其持有者還多出哪些本不該有的能力。`,
		problem: `// 不安全寫法：一個「deploy」權限同時挾帶改角色跟執行任意命令，等於設計了一顆隱形炸彈
const PERM = { deploy: ['run_pipeline', 'run_any_command', 'assign_role_owner'] };

app.post('/rpc', authorize(PERM), (req, res) => {
  // 持 deploy 者既能跑管線，也能 assign_role_owner 把別人抬成擁有者、再 run 任意命令
  rpc(req.body.action, req.body.args);
});`,
		fixed: `// 安全寫法：把危險能力拆到受隔離的最小權限，即使拿到 deploy 也升不了級
const PERM = {
  deploy: ['run_pipeline'],
  platform_admin: ['run_any_command', 'assign_role_owner'],  // 高風險能力單獨、審慎發放
};

app.post('/rpc', authorizeFor(req.session.uid), (req, res) => {
  if (!canAct(req.session.uid, req.body.action, req.body.target))
    return res.sendStatus(403);
  rpc(req.body.action, req.body.args);   // 先驗該動作是否落在授與的最小集合內
});`,
		patch: `@@
   const PERM = {
-    deploy: ['run_pipeline', 'run_any_command', 'assign_role_owner'],
+    deploy: ['run_pipeline'],
+    platform_admin: ['run_any_command', 'assign_role_owner'],
   };
   app.post('/rpc', authorize(PERM), (req, res) => {
+    if (!canAct(req.session.uid, req.body.action, req.body.target))
+      return res.sendStatus(403);
     rpc(req.body.action, req.body.args);
   });`,
		refs: ['OWASP-Authorization', 'CWE-267'],
		tags: ['privilege', 'unsafe-action', 'capability'],
	},
	{
		id: 'CWE-269',
		name: 'Improper Privilege Management',
		lang: 'nodejavascript',
		status: 'Complete',

		what: `權限管理不當。程序取得了某項作業系統特權卻沒有妥善控管其存續期間，例如資料庫、Web 工作行程
	以高權限帳號建連線後就把密碼跟能力一路帶著跑、或是一段分階段處理在不需要特權的階段仍保留 root／SYSTEM。
	與 CWE-250 單指「一開頭就給太多權限」不同，這裡問題在「已取得的權限沒有被適時降級或收回」，
	使授權特別高的話語權停留在攻擊者可操縱的介面上。正確做法是嚴格限定特權被使用的範圍與時間，
	用盡即收回，並在需要權限的極小臨界區之後立即降級。`,

		problem: `// 不安全寫法：整條請求處理都跑在有權讀密鑰的高權限上下文，權限從頭滯留到尾
const fs = require('fs');

app.post('/admin/run-job', (req, res) => {
  // 讀取金鑰與呼叫更換機都需要特權，但整個函式都帶著特權在跑
  const key = fs.readFileSync('/etc/secrets/signing.pem');   // 高權限讀取
  doSignedWorkflow(req.body);          // 純業務邏輯並不需要系統特權
});`,

		fixed: `// 安全寫法：只在極小的臨界區內取用特權，越過之後立刻把特權收回／釋放
const fs = require('fs/promises');

async function sign(token) {
  const key = await fs.readFile('/etc/secrets/signing.pem');  // 特權的取用縮到這一行
  clearCachedPrivilege();                                    // 用完立刻收回
  return signBytes(token, key);
}

app.post('/admin/run-job', async (req, res) => {
  const sig = await sign(req.body.token);                    // 特權只在 sign 內短暫存在
  await doSignedWorkflow(req.body, sig);                   // 之後全以低權限執行
});`,

		patch: `@@
-  app.post('/admin/run-job', (req, res) => {
-    // 讀取金鑰與呼叫更換機都需要特權，但整個函式都帶著特權在跑
-    const key = fs.readFileSync('/etc/secrets/signing.pem');
-    doSignedWorkflow(req.body);
-  });
+  async function sign(token) {
+    const key = await fs.readFile('/etc/secrets/signing.pem');   // 特權取用縮到這
+    clearCachedPrivilege();                                       // 用完立刻收回
+    return signBytes(token, key);
+  }
+  app.post('/admin/run-job', async (req, res) => {
+    const sig = await sign(req.body.token);
+    await doSignedWorkflow(req.body, sig);
+  });`,
		refs: ['OWASP-LeastPrivilege', 'CWE-269'],
		tags: ['privilege', 'drop-privileges', 'privilege-management'],
	},
	{
		id: 'CWE-270',
		name: 'Privilege Context Switching Error',
		lang: 'python',
		status: 'Complete',

		what: `權限上下文切換錯誤（Privilege Context Switching Error）。程式在「不同特權、不同控制範圍」的上下文之間
	切換（例如先以 root 啟動，之後要切去以低權限使用者的身分執行工作，或在一支以一般使用者的身分執行的執行緒
	中短暫升權處理）時，沒有正確保存或復原狀態：可能是降了權卻沒徹底捨棄既有的高權限 handle、可能切換後忘了復原、
	也可能並行時不同上下文互相覆蓋憑證與組態。於是低權限的段落仍然偷偷握有高權限的能力。正確做法是明確定義身分
	切換的界限：切換時丟棄舊上下文、與可供退回的高權限句柄徹底切斷，並在並行環境用不可重入的一次性切換作業。`,
		problem: `# 不安全寫法：升權做事之後沒有復原，失敗分支更直接保留在 higher-priv 身分繼續跑
def do_as_root(fn):
    os.seteuid(0)                 # 升成 root 執行動作
    result = fn()                  # 若是例外，euid 永遠停留在 0（最高權限）
    # 忘了 set back：正常路徑也未復原原身分，後面全以 root 在跑
    return result

def handler(path):                 # 之後這段照理該以低權限執行，卻還是 root
    open(path, 'w').write(...)`,

		fixed: `# 安全寫法：升權只包裹最小區塊，finally 一律復原原身分
class SwitchedContext:
    def __enter__(self):
        self.prev = os.geteuid()
        os.seteuid(0)            # 只在這個 with 區塊內升權
        return self
    def __exit__(self, *exc):
        os.seteuid(self.prev)     # 無論成功或例外，都恢復原 euid
        return False

def do_as_root(fn):
    with SwitchedContext():        # root 只存活於此 with 區塊
        return fn()

def handler(path):                # 出來之後回到原始低權限身分執行
    with open(path, 'w') as f:
        f.write(...)`,

		patch: `@@
-  def do_as_root(fn):
-      os.seteuid(0)
-      result = fn()
-      # 忘了 set back：正常路徑也未復原原身分
-      return result
-  def handler(path):
-      open(path, 'w').write(...)
+  class SwitchedContext:
+      def __enter__(self):
+          self.prev = os.geteuid()
+          os.seteuid(0)
+          return self
+      def __exit__(self, *exc):
+          os.seteuid(self.prev)
+          return False
+  def do_as_root(fn):
+      with SwitchedContext():
+          return fn()
+  def handler(path):
+      with open(path, 'w') as f:
+          f.write(...)`,
		refs: ['OWASP-LeastPrivilege', 'CWE-270'],
		tags: ['privilege', 'context-switch', 'seteuid'],
	},
	{
		id: 'CWE-271',
		name: 'Privilege Dropping / Lowering Errors',
		lang: 'python',
		status: 'Complete',

		what: `降權／丟權時出錯（Privilege Dropping / Lowering Errors）。程式在「必須把權限降到較低層級之後」才要交由
	某個主體操作的地方，卻漏了降、或降得不徹底——例如 setuid(原有的使用者) 之後沒有拿掉 supplementary groups、
	沒有清掉可被打回的 capabilities、或走了某條 return 分支就直接以 root 身分把資源交出去。高權限的能力於是悄悄地
	滲入本該由低權限主體操作的部分。正確做法是「先降權、後交控制權」：確定 euid、egid、groups、capabilities
	全部同步地、不可回復地把權降到目標層級，再交出資源，並對分派之後的路徑做最後一道權限驗證。`,
		problem: `# 不安全寫法：setuid 降了 euid，卻漏拿 supplementary groups，被降權者仍具組員的高權限
def send_file_as_app(fd, path):
    os.setuid(APP_UID)                 # 只降了 uid
    # groups / egid 沒處理，APP_UID 仍是原始組員（例如 ability 群）
    os.write(fd, open(path, 'rb').read())   # 高權限組的檔案照讀不誤`,
		fixed: `# 安全寫法：逐項永久降權（euid、egid、groups、capabilities），再送／交資源
def send_file_as_app(fd, path):
    os.setgroups([])                    # 先清空 supplementary groups
    os.setgid(APP_GID)                # 再設定 egid
    os.setuid(APP_UID)                # 最後才設 euid（依序 gid→uid 才不會被反收復）
    os.setresuid(APP_UID, APP_UID, APP_UID)   # 也固化 saved uid，防止 setuid(0) 打回
    try:
        os.write(fd, open(path, 'rb').read())
    except PermissionError:              # 降到最低權限後，越權就該失敗還不該偷偷成功
        os.write(fd, b'forbidden')`,
		patch: `@@
  def send_file_as_app(fd, path):
-     os.setuid(APP_UID)
+     os.setgroups([])
+     os.setgid(APP_GID)
+     os.setuid(APP_UID)
+     os.setresuid(APP_UID, APP_UID, APP_UID)
+     try:
          os.write(fd, open(path, 'rb').read())
+     except PermissionError:
+         os.write(fd, b'forbidden')`,
		refs: ['OWASP-LeastPrivilege', 'CWE-271'],
		tags: ['privilege', 'drop-privileges', 'setuid', 'groups'],
	},
	{
		id: 'CWE-272',
		name: 'Least Privilege Violation',
		lang: 'nodejavascript',
		status: 'Complete',

		what: `違反最小權限原則（Least Privilege Violation）。帳號或程序被指派、或執行時刻意地使用「超過任務實際所需」
	的權限——例如 Web 工作者全程以 root 執行、資料庫使用者一開場就被授與整套 dba、或一個只需讀某個目錄的任務
	卻一路帶著可寫全部檔案的權限。一旦含著過剩權限的程式被漏洞射穿，攻擊者就直接繼承多出來的全部能力，把單一
	瑕疵放大成系統級淪陷。正確做法是依照每個任務「真的需要的下限」來建立帳號與角色，特權只在最小臨界區出現並立即
	收回，並在部署與平日維護中逐項稽核實際持有的權限是否符合最小需求。`,
		problem: `// 不安全寫法：整個處理程序開跑就用 root，任何可寫 vs 可執行的資源全部開放
const fs = require('fs');
const { spawn } = require('perf_hooks');

// child process 全程帶著管理權，而它真正要做的只是把暫存檔搬到另一個目錄
const cp = spawn('/srv/uploadd/worker.sh', [], { uid: 0, gid: 0 });`,
		fixed: `// 安全寫法：子程序只以能完成「搬檔」所需的專用低權限帳號運行
const fs = require('fs');
const { spawn } = require('child_process');

const { uid, gid } = require('./runas');   // 專用 uploader 帳號：只擁 target 目錄寫入權
// 不再整段以 root 跑，僅以「剛好夠搬檔」的權限執行
const cp = spawn('/srv/uploadd/worker.sh', [], { uid, gid });`,
		patch: `@@
-  const cp = spawn('/srv/uploadd/worker.sh', [], { uid: 0, gid: 0 });
+  const { uid, gid } = require('./runas');
+  const cp = spawn('/srv/uploadd/worker.sh', [], { uid, gid });`,
		refs: ['OWASP-LeastPrivilege', 'CWE-272'],
		tags: ['least-privilege', 'privilege', 'principle-of-least-privilege'],
	},
	{
		id: 'CWE-274',
		name: 'Improper Handling of Insufficient Privileges',
		lang: 'python',
		status: 'Complete',

		what: `不當處理權限不足的情況（Improper Handling of Insufficient Privileges）。程式執行某項「需要特定權限才能成功」
	的操作，卻沒有檢查操作是否真的成功、或是沒有妥善對待「權限不足／身分不符」的失敗分支。例如呼叫一個會核對權限
	的函式後不理會回傳值、catch 到權限例外時反而退回更高特權的路徑、或是以「預設允許」的方式繼續往下走。結果輕則
	把系統留在不確定狀態，重則以錯誤的權限把資源或權杖送到不該到達的地方。正確做法是對任何「非有權限不可」的呼叫
	都檢查回傳值並妥善處理失敗，整體遵從「預設關閉、失敗即拒絕」的基準。`,
		problem: `# 不安全寫法：要寫入受保護檔只怕開檔拋例外而中斷，卻沒把「權限不足」當成重要失敗處理
def write_config(path, blob):
    try:
        f = open(path, 'w')             # 權限不夠時 open 會失敗
    except OSError:
        return False                     # 默默吞掉錯誤，呼叫端以為成功
    f.write(blob)
    f.close()
    return True                         # 但檔可能根本沒被寫成，或只寫到一半`,
		fixed: `# 安全寫法：權限不足視為明確的拒絕事件，記錄並拋出可稽核的錯誤，絕不靜默成功
import logging
def write_config(path, blob):
    try:
        if not os.access(path, os.W_OK):        # 先檢查可寫性
            raise PermissionError(path)
        with open(path, 'w') as f:
            f.write(blob)
    except OSError as exc:
        logging.warning("need elevated privilege to write %s: %s", path, exc)
        raise RuntimeError('config write denied')   # 失敗即拒絕，並留下trace
    return True`,
		patch: `@@
  def write_config(path, blob):
      try:
-         f = open(path, 'w')
+         if not os.access(path, os.W_OK):
+             raise PermissionError(path)
+         with open(path, 'w') as f:
+             f.write(blob)
      except OSError:
-         return False
-     f.write(blob)
-     f.close()
+         logging.warning("need elevated privilege to write %s", path)
+         raise RuntimeError('config write denied')
      return True`,
		refs: ['OWASP-ErrorHandling', 'CWE-274'],
		tags: ['insufficient-privileges', 'fail-closed', 'error-handling'],
	},
	{
		id: 'CWE-275',
		name: 'Permission Issues',
		lang: 'nodejavascript',
		status: 'Complete',

		what: `權限議題（Permission Issues）——一個彙整用的 CWE 類別（Category），涵蓋權限被「不當指派或不當處理」而
	衍生的整套弱點，主題大致集中在權限指派、權限保留與擁有權管理等方向。這是聚合層級，與 CWE-265（Privilege Issues）
	常被混為一談，MITRE 標示此 ID「不應用於真實弱點映射」。要落入實際修復，應往下選出具體的子條目——例如 CWE-280
	權限或特權不足處理不當、CWE-281 權限未妥善保留、CWE-282 擁有權管理不當——針對單一缺陷處理。普遍原則包含：
	以最小權限為預設、每個新物件成立當下就設定收緊的權限、複製／還原資源時保留原本權限，並驗證資源擁有權。`,
		problem: `// 列目示範：建立臨時檔幾乎都靠作業系統預設權限，且複製時直接覆寫目標，權限全鬆
const fs = require('fs');
fs.writeFileSync('/tmp/notes.bin', data);                    // 預設 0666
fs.copyFileSync('/tmp/notes.bin', '/var/app/cache/notes');  // 複製不保留來源權限`,
		fixed: `// 列目修法：明確指定最小且收緊的權限，複製後再以來源權限重放
const fs = require('fs');
const MODE = 0o600;
fs.writeFileSync('/tmp/notes.bin', data, { mode: MODE });
const stat = fs.statSync('/tmp/notes.bin');
fs.copyFileSync('/tmp/notes.bin', '/var/app/cache/notes');
fs.chmodSync('/var/app/cache/notes', stat.mode & 0o7777); // 複製後重放原權限`,
		patch: `@@
-  fs.writeFileSync('/tmp/notes.bin', data);
-  fs.copyFileSync('/tmp/notes.bin', '/var/app/cache/notes');
+  fs.writeFileSync('/tmp/notes.bin', data, { mode: 0o600 });
+  const stat = fs.statSync('/tmp/notes.bin');
+  fs.copyFileSync('/tmp/notes.bin', '/var/app/cache/notes');
+  fs.chmodSync('/var/app/cache/notes', stat.mode & 0o7777);`,
		refs: ['OWASP-FilePerms', 'CWE-275'],
		tags: ['permission', 'file-permissions', 'category'],
	},
	{
		id: 'CWE-276',
		name: 'Incorrect Default Permissions',
		lang: 'nodejavascript',
		status: 'Complete',

		what: `預設權限設定錯誤。程式在建立檔案或目錄時，用的預設模式比所需更開放，例如不指定 mode 就依賴
	作業系統預設、或是直接帶 0o777／0666 這種「誰都能讀寫」的八進位。UMask 又不保證存在時，
	其他本機使用者就可能讀到不該讀的設定檔或金鑰，竄改掉要執行的腳本。正確做法是建立每個資源時
	都明確指定收緊的八進位模式，例如目錄 0o700、一般檔 0o600，把「最小可用權限」直接寫進呼叫。`,

		problem: `// 不安全寫法：mkdir / writeFile 沒給 mode，實際權限取決於不明的 umask，可能全放開
const fs = require('fs');

// 某些環境 umask 是 000，recursive 建出來的目錄可能是 drwxrwxrwx
fs.mkdirSync('/var/app/data', { recursive: true });
// writeFile 預設 0666，任何人(包括非擁有者)都可讀
fs.writeFileSync('/var/app/data/config.ini', sensitiveJson);`,

		fixed: `// 安全寫法：建立資源時就明確指定收緊的八進位模式，不依賴 umask
const fs = require('fs');

// 目錄只給擁有者 rwx，其他人全擋掉
fs.mkdirSync('/var/app/data', { recursive: true, mode: 0o700 });
// 設定檔只給擁有者 rw，明確寫 0o600
fs.writeFileSync('/var/app/data/config.ini', sensitiveJson, { mode: 0o600 });`,

		patch: `@@
  const fs = require('fs');
 
- // 某些環境 umask 是 000，recursive 建出來的目錄可能是 drwxrwxrwx
- fs.mkdirSync('/var/app/data', { recursive: true });
- // writeFile 預設 0666，任何人(包括非擁有者)都可讀
- fs.writeFileSync('/var/app/data/config.ini', sensitiveJson);
+ // 目錄只給擁有者 rwx，其他人全擋掉
+ fs.mkdirSync('/var/app/data', { recursive: true, mode: 0o700 });
+ // 設定檔只給擁有者 rw，明確寫 0o600
+ fs.writeFileSync('/var/app/data/config.ini', sensitiveJson, { mode: 0o600 });`,
		refs: ['OWASP-FilePerms', 'CWE-276'],
		tags: ['default-permissions', 'chmod', 'world-readable'],
	},
	{
		id: 'CWE-280',
		name: 'Improper Handling of Insufficient Permissions or Privileges',
		lang: 'python',
		status: 'Complete',

		what: `對「權限或特權不足」處理不當（Improper Handling of Insufficient Permissions or Privileges）。產品在自己該有的
	權限下要存取某資源或功能，卻碰到「權限不够／特權不足」的情況，而它處理錯誤或根延本沒處理——例如不檢查檔案開啟
	是否成功、把權限被拒的結果當成成功、或對權限不足的反應走了一條預期之外的路徑以致停留在壞狀態。這會讓本應明確
	擋下的存取變成含混的成功或半成功，甚至衍生後續弱點。雖然高權限環境較少踩到，但在權限顆粒度細的模型（Linux
	capabilities、Windows 權限群組）裡很常見；正確做法是每次資源操作後都確認確實成功，失敗時一律走「拒絕並記錄」的
	安全路徑，避免留下隱含的全開狀態。`,
		problem: `# 不安全寫法：把「權限不足」跟「一般錯誤」混為一談，僅 print 之後當成成功往下走
def backup(src, dst):
    ok = subprocess.run(["cp", src, dst])
    if ok.returncode != 0:
        print("cp failed")               # 沒分檔：權限不足被當成普通失敗吞掉
    return True                        # 但仍回報成功、呼叫端照常往下執行`,
		fixed: `# 安全寫法：明確判別權限例外並以「拒絕」處理，成功才回報
def backup(src, dst):
    try:
        cp = subprocess.run(["cp", src, dst], capture_output=True, text=True, check=False)
    except OSError as exc:
        raise PermissionError(f"cannot exec backup: {exc}")
    if cp.returncode != 0:
        raise PermissionError(f"backup denied for {dst}")   # 失敗即拒絕
    return True`,
		patch: `@@
  def backup(src, dst):
-     ok = subprocess.run(["cp", src, dst])
-     if ok.returncode != 0:
-         print("cp failed")
-     return True
+     try:
+         cp = subprocess.run(["cp", src, dst], capture_output=True, text=True, check=False)
+     except OSError as exc:
+         raise PermissionError(f"cannot exec backup: {exc}")
+     if cp.returncode != 0:
+         raise PermissionError(f"backup denied for {dst}")
+     return True`,
		refs: ['OWASP-ErrorHandling', 'CWE-280'],
		tags: ['insufficient-permissions', 'fail-closed', 'permission-check'],
	},
	{
		id: 'CWE-281',
		name: 'Improper Preservation of Permissions',
		lang: 'nodejavascript',
		status: 'Complete',

		what: `權限未被妥善保留（Improper Preservation of Permissions）。在複製、還原或分享物件時，沒有保留（或錯誤保留）
	原本的權限，導致新物件比意圖的更加開放。典型包括：複製檔案時以目的地目錄預設的新權限取代原始檔的精確權限、
	從備份還原時捨弃 ACL、或把物件「分享／移動」到別處時一併鬆脫了鎖。這類問題使用者不易察覺，因為「看起來一樣」
	的物件實際已悄悄開放給他人。正確做法是在 copy／restore／move 操作中，顯式地把原本的權限位遮罩（連同 ACL）一路
	攜帶並重放，並在任何分享動作前重新評估、收斂到最小範圍。`,
		problem: `// 不安全寫法：備份還原時只複製內容，權限落回 accept 檔案的預設值(常見 0644，可能世界可讀)
const { execSync } = require('child_process');
restore(configPath) {
  execSync('cp /backups/app.conf ' + configPath);   // 沒重放來源權限
}`,
		fixed: `// 安全寫法：還原時把來源檔的 mode（及 ACL）一併重放到目標
const { execSync } = require('child_process');
const fs = require('fs');
restore(configPath) {
  execSync('cp /backups/app.conf ' + configPath);
  const src = fs.statSync('/backups/app.conf');   // 取來源既有 mode
  fs.chmodSync(configPath, src.mode & 0o7777); // 重放為原本的精確權限
}`,
		patch: `@@
   const { execSync } = require('child_process');
-  restore(configPath) { execSync('cp /backups/app.conf ' + configPath); }
+  const fs = require('fs');
+  restore(configPath) {
+    execSync('cp /backups/app.conf ' + configPath);
+    const src = fs.statSync('/backups/app.conf');
+    fs.chmodSync(configPath, src.mode & 0o7777);
+  }`,
		refs: ['OWASP-FilePerms', 'CWE-281'],
		tags: ['preserve-permissions', 'copy', 'acl'],
	},
	{
		id: 'CWE-282',
		name: 'Improper Ownership Management',
		lang: 'nodejavascript',
		status: 'Complete',

		what: `擁有權管理不當（Improper Ownership Management）。產品「指派了錯誤的擁有者」或「沒有正確驗證物件的擁有者」。
	擁有權往往決定了誰能調整權限、誰能查看或刪除資源，一旦把關鍵資源（設定檔、金鑰、資料夾）交付給錯誤的擁有者、
	或在授權時沒有確認請求者就是真實擁有者，就可能讓不具資格者獲得存取或控制。常見如把目錄 chown 給不該擁有它的
	角色、或在授權判斷時只按「名稱」比對而不檢查真實擁有權。正確做法是每個資源都由明確的持有者註冊，任何存取決策先由
	伺服器端解析並驗證真正的擁有權，擁有權的任何變動都要受控並記入稽核。`,
		problem: `// 不安全寫法：許可時只比對使用者「名字」，不改送亂給別人 owner；用戶改名即可接管他人資源
function canEdit(owner, req) {
  return req.body.ownerName === owner;      // 用可被偽造的 name 當擁有權證據
}
app.patch('/api/doc/:id', (req, res) => {
  if (!canEdit(doc.ownerName, req)) return res.sendStatus(403);
  doc.body = req.body.text;                 // 但 doc 的真正 owner uid 從未被驗證
});`,
		fixed: `// 安全寫法：以伺服器端持久化的 owner uid 驗證，姓名只是顯示用
async function canEditDoc(uid, docId) {
  const doc = await db.docs.findById(docId);
  return doc && String(doc.ownerUid) === String(uid);   // 真正的 owner uid 比對
}
app.patch('/api/doc/:id', async (req, res) => {
  const ok = await canEditDoc(req.session.uid, req.params.id);
  if (!ok) return res.sendStatus(403);
  await db.docs.updateOne({ _id: req.params.id }, { $set: { body: req.body.text } });
});`,
		patch: `@@
-  function canEdit(owner, req) {
-    return req.body.ownerName === owner;
-  }
   app.patch('/api/doc/:id', (req, res) => {
-    if (!canEdit(doc.ownerName, req)) return res.sendStatus(403);
-    doc.body = req.body.text;
-  });
+    if (!req.session || !req.session.uid) return res.sendStatus(401);
+    const doc = await db.docs.findById(req.params.id);
+    if (!doc || String(doc.ownerUid) !== String(req.session.uid))
+      return res.sendStatus(403);
+    await db.docs.updateOne({ _id: req.params.id }, { $set: { body: req.body.text } });
+  });`,
		refs: ['OWASP-AccessControl', 'CWE-282'],
		tags: ['ownership', 'owner', 'authorization'],
	},
	{
		id: 'CWE-732',
		name: 'Incorrect Permission Assignment for Critical Resource',
		lang: 'nodejavascript',
		status: 'Complete',

		what: `對「關鍵資源」設定了錯誤的權限。像是私密金鑰、資料庫連線設定、含機敏資訊的記錄檔這類
	影響安全性的資源，被安排成可被他人讀取、甚至寫入的權限，例如以 0o666 產生金鑰檔，或事後 chmod
	把組／他人也放進來。本機上其他使用者就能竊取金鑰、篡改信任根或讀走整池密碼。
	正確做法是對關鍵資源一律設定最窄的權限（金鑰 0o600，目錄 0o700），並於任何可能改變模式的
	路徑後側再次確認，確保擁有者以外的任何帳號都碰不到。`,

		problem: `// 不安全寫法：把私密金鑰寫成 0o666，系統上的任何使用者都可讀走私鑰
const fs = require('fs');
const { execSync } = require('child_process');

const blob = execSync('openssl genrsa 2048', { encoding: 'utf8' });
// 未指定 mode，node fs 預設 0666 = 擁有人、組、他人全部可讀寫，金鑰就此外洩
fs.writeFileSync('/etc/app/service.key', blob);`,

		fixed: `// 安全寫法：關鍵資源一產生就鎖成 0o600，再補一次 chmod 防任何預設值滲漏
const fs = require('fs');
const { execSync } = require('child_process');

const blob = execSync('openssl genrsa 2048', { encoding: 'utf8' });
// 產生時就直接指定只有擁有者可讀寫
fs.writeFileSync('/etc/app/service.key', blob, { mode: 0o600 });
// 防復元參數被忽略／預設值覆寫，事後再以明確 chmod 收緊一次
fs.chmodSync('/etc/app/service.key', 0o600);`,

		patch: `@@
  const { execSync } = require('child_process');
 
  const blob = execSync('openssl genrsa 2048', { encoding: 'utf8' });
- // 未指定 mode，node fs 預設 0666 = 擁有人、組、他人全部可讀寫
- fs.writeFileSync('/etc/app/service.key', blob);
+ // 產生時就直接指定只有擁有者可讀寫
+ fs.writeFileSync('/etc/app/service.key', blob, { mode: 0o600 });
+ // 防參數被忽略／預設值覆寫，事後以明確 chmod 收緊一次
+ fs.chmodSync('/etc/app/service.key', 0o600);`,
		refs: ['OWASP-FilePerms', 'CWE-732'],
		tags: ['critical-resource', 'file-permissions', 'world-readable'],
	},
];
