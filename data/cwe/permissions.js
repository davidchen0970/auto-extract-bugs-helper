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
  await doSignedWorkflow(req.body, sig);                     // 之後全以低權限執行
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
