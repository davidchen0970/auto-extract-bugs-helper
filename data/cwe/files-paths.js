// CWE chunk — category: Files / Search Path & Symlink (C / Node / Python / shell).
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
		id: 'CWE-59',
		name: "Improper Link Resolution Before File Access ('Link Following')",
		lang: 'c',
		status: 'Complete',
		what: `不當的「先解析連結、之後才開檔」做法（symlink 跟隨、link following）。程式常常
	先把路徑「檢查一遍」確認它不是符號連結、或確認它指向的是價得信賴的檔案，通過檢查之後
	才真正去 open 它。這兩次存取之間的空窗就是 TOCTOU：攻擊者可以在檢查通過後、open 之前，
	把原本的檔換成一條指向敏感檔案（如 /etc/passwd）的符號連結，於是最後 open 到的其實是
	「審核過的路徑」背後完全不同、由攻擊者控制的目標。建議做法是把「確認與開啟」合成單一
	不可分割的動作——例如用 open() 的 O_NOFOLLOW 旗標，或對已經 open 的目錄 fd 用 openat()
	一次完成，讓核心在建立 fd 的當下對絕對真實、無法中途置換的路徑做解析。`,
		problem: `// 不安全寫法：先 lstat 確認「不是 symlink」，才後補性 open(path) => 中空窗被置換
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int open_config(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return -1;
    if (S_ISLNK(st.st_mode)) return -1;   // 檢查的瞬間它是安全的一般檔案
    // gap：攻擊者在「檢查過」與「open」之間把 path 換成指向 /etc/passwd 的 symlink
    return open(path, O_WRONLY);          // TOCTOU => 開到的不是剛才檢查的那個檔案
}`,
		fixed: `// 安全寫法：對「已開啟的目錄 fd」用 openat + O_NOFOLLOW 一次完成,核心層保證不跟隨 symlink
#include <fcntl.h>
#include <unistd.h>

int open_config(int dirfd, const char *name) {
    // 同一個動作裡要求「不要跟隨連結」,沒有檢查與開啟之間的空窗
    return openat(dirfd, name, O_WRONLY | O_NOFOLLOW);
}`,
		patch: `@@
  int open_config(const char *path) {
  	struct stat st = ...;
  -    if (lstat(path, &st) != 0) return -1;
  -    if (S_ISLNK(st.st_mode)) return -1;   // 檢查與 open 分開 => TOCTOU 空窗
  -    return open(path, O_WRONLY);
  +    return openat(dirfd, name, O_WRONLY | O_NOFOLLOW); // 單一原子動作
  }`,
		refs: ['CWE-59', 'SEI CERT'],
		tags: ['symlink', 'toctou', 'link-following', 'openat', 'race'],
	},
	{
		id: 'CWE-426',
		name: 'Untrusted Search Path',
		lang: 'node',
		status: 'Complete',
		what: `使用不受信賴的搜尋路徑（Untrusted Search Path）。程式在要執行另一支程式、載入
	模組、或開啟動態函式庫時，不是用完整的絕對路徑，而是只給一個「名字」，交由作業系統依環境
	變數 PATH（或其他搜尋路徑）到處找。這條搜尋路徑往往由使用者或環境控制、可被放置不可信的
	目錄；攻擊者只要在自己可以寫入、且又排在前面被搜尋的目錄裡，放一支與程式要找的檔案同名、
	但其實是惡意的替身，系統就會找到這一支並執行，達到命令執行或身分替身的目標。建議做法是
	以絕對路徑指定要啟動的執行檔或載入的函式庫，不把自己的目錄塞進搜尋路徑，也不信任環境給的
	PATH。`,
		problem: `// 不安全寫法：只傳檔名就不要經過 shell 由 PATH 找,呼叫端可控制 PATH 放入惡意目錄
const { exec } = require('child_process');

function backup() {
  // "tar" 不是絕對路徑,由環境變數 PATH 決定;若 PATH 排入攻擊者可控目錄 =>
  // 會被導到攻擊者放的同名 tar 替身
  exec('tar -czf backup.tgz ./data', (err) => {
    if (err) console.error(err);
  });
}`,
		fixed: `// 安全寫法：用 execFile 直接給 /usr/bin/tar 絕對路徑,不經 shell、也不受 PATH 影響
const { execFile } = require('child_process');

function backup() {
  execFile('/usr/bin/tar', ['-czf', 'backup.tgz', './data'], (err) => {
    if (err) console.error(err);
  });
}`,
		patch: `@@
  function backup() {
  -    exec('tar -czf backup.tgz ./data', (err) => {
  +    execFile('/usr/bin/tar', ['-czf', 'backup.tgz', './data'], (err) => {
      	if (err) console.error(err);
      });
  }`,
		refs: ['CWE-426', 'SEI CERT'],
		tags: ['untrusted-search-path', 'path', 'exec', 'absolute-path'],
	},
	{
		id: 'CWE-427',
		name: 'Uncontrolled Search Path Element',
		lang: 'python',
		status: 'Complete',
		what: `不受控的搜尋路徑元素（Uncontrolled Search Path Element）。CWE-427 強調搜尋路徑
	本身「某些組成單元」由程式或使用者直接注入、但沒有被控制或清除：例如把自己的執行目錄、
	使用者可控的目錄、或相對路徑前置在 PATH 的最前面。因為搜尋是照順序從第 0 個元素開始找，
	只要這個不受控的元素排在前面，攻擊者就能在裡面放同名替身來攔截原本該執行的程式或載入的
	模組，藉此提升權限或在不同的執行者身分下埋入自己的程式。與 CWE-426 差別在於：426 泛指
	整條 PATH 不可信，427 則聚焦在「某一個被塞進來的路徑元素沒有任何控制／過濾」。修法是絕不
	把使用者可控目錄或目前工作目錄加入搜尋路徑，並用絕對路徑啟動程式。`,
		problem: `# 不安全寫法：把「目前工作目錄」直接前置進 PATH,搜尋時會被當成第一個元素 => 不受控
import os, subprocess

def run_tool(cmd):
    # os.getcwd() 是使用者可控目錄,被塞在 PATH 最前面;目錄內同名惡意執行檔會被優先找到
    os.environ['PATH'] = os.getcwd() + os.pathsep + os.environ['PATH']
    subprocess.call([cmd])      # cmd 只給檔名,由已污染的 PATH 首個元素決定載哪支`,
		fixed: `# 安全寫法：剔除工作目錄與使用者可控元素,只留系統目錄,並以絕對路徑執行
import os, subprocess

def run_tool():
    safe = [d for d in os.environ.get('PATH', '').split(os.pathsep)
            if d.startswith(('/', '/usr/'))]     # 過濾掉來路不明的元素
    os.environ['PATH'] = os.pathsep.join(safe)
    subprocess.call(['/usr/bin/tool'])           # 絕對路徑,搜尋路徑不再有控制權`,
		patch: `@@
  def run_tool(cmd):
  -    os.environ['PATH'] = os.getcwd() + os.pathsep + os.environ['PATH']
  -    subprocess.call([cmd])
  +    safe = [d for d in os.environ.get('PATH', '').split(os.pathsep)
  +            if d.startswith(('/', '/usr/'))]     # 過濾掉來路不明的元素
  +    os.environ['PATH'] = os.pathsep.join(safe)
  +    subprocess.call(['/usr/bin/tool'])           # 絕對路徑`,
		refs: ['CWE-427', 'SEI CERT'],
		tags: ['search-path', 'path-element', 'path-traversal', 'privilege-escalation'],
	},
	{
		id: 'CWE-428',
		name: 'Unquoted Search Path or Element',
		lang: 'c',
		status: 'Complete',
		what: `未加引號的搜尋路徑或路徑元素（Unquoted Search Path / Element,主要見於 Windows）。
	當要執行的程式路徑包含空格（例如 "C:\\\\Program Files\\\\My App\\\\app.exe"）卻沒有被雙引號包住時,
	作業系統的 CreateProcess／LoadLibrary 會被誘導用「拆斷後的片段」逐段去試著解析：先嘗試
	"C:\\\\Program.exe"，再 "C:\\\\Program Files\\\\My.exe"，最後才是完整的原本路徑。攻擊者只要在
	上述任一欄位放得下同名檔案，就能讓系統於解析中間某段時誤載自己的執行檔——例如在 Program
	目錄裡塞一支惡意檔案，等待正確的程式被啟動。修法是把整段含空格的路徑用雙引號完整包住，
	讓作業系統一次解析到真正的可執行目標。`,
		problem: `// 不安全寫法：binPath 可執行路徑含有空格卻未加引號 => Windows 會分段試著解析中間片段
// 攻擊者可在 C:\\Program Files\\ 放置惡意 "My.exe" 搶先被載入
sc create MyService binPath= C:\\Program Files\\My App\\app.exe start= auto`,
		fixed: `// 安全寫法：把整段含空格的可執行路徑用雙引號完整包住,作業系統一次解析到正確目標
sc create MyService binPath= "C:\\Program Files\\My App\\app.exe" start= auto`,
		patch: `@@
  sc create MyService binPath=
  -    C:\\Program Files\\My App\\app.exe start= auto
  +    "C:\\Program Files\\My App\\app.exe" start= auto`,
		refs: ['CWE-428', 'SEI CERT'],
		tags: ['unquoted-path', 'windows', 'quote', 'service', 'command-line'],
	},
];