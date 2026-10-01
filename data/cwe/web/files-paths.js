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
		id: 'CWE-61',
		name: 'UNIX Symbolic Link (Symlink) Following',
		lang: 'c',
		status: 'Complete',
		what: `UNIX 符號連結（symlink）跟隨攻擊。程式要開啟或寫入某個檔時，只憑「路徑名稱」就把
	open()／openat() 交出去，而不檢查這個路徑的某一層是不是以符號連結指向別處。攻擊者若能在該路徑的
	某一個目錄寫入（常見於共用的可寫暫存目錄，例如 /tmp），就能預先把這個「檔名」佈成一條指到受害者
	本無權讀寫的目標（如 /etc/shadow、其它使用者的設定檔）的連結；程式一 open，就照著連結把讀寫動作
	送到目標身上，造成任意檔被覆寫、讀取或建立，甚至配合 TOCTOU 在檢查與使用之間置換。CWE-61 與
	CWE-59 的差別在於 61 聚焦「UNIX symlink 本身被跟隨」，而 59 泛指一切 link-following 的 TOCTOU
	空窗。修法是使用 O_NOFOLLOW 拒絕跟隨最後一層、對已開啟的 fd 用 fstat 驗證目標身分，或把暫存
	檔放在程式專屬、不可被他人寫入的目錄裡。`,
		problem: `// 不安全寫法：在共享可寫目錄用預測得到的名字直接 open,最後一層可被擺成 symlink
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int save_pid(const char *tmpdir) {
    char path[512];
    snprintf(path, sizeof path, "%s/pid.txt", tmpdir);  // tmpdir 常見是 /tmp 這類共寫空間
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    dprintf(fd, "%d\\n", getpid());      // 若 path 被換成指向 /etc/shadow 的 symlink,就寫到那
    close(fd);
    return 0;
}`,
		fixed: `// 安全寫法：O_NOFOLLOW + O_EXCL 讓核心拒絕任何既存檔與符號連結,寫進「真正新開」的檔
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int save_pid(const char *tmpdir) {
    char path[512];
    snprintf(path, sizeof path, "%s/pid.txt", tmpdir);
    // O_EXCL: 已存在就失敗;O_NOFOLLOW: 對最後一層 symlink 直接 ELOOP 拒絕,不跟隨
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644);
    if (fd < 0) return -1;
    dprintf(fd, "%d\\n", getpid());
    close(fd);
    return 0;
}`,
		patch: `@@
-    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
+    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644);
     if (fd < 0) return -1;`,
		refs: ['CWE-61', 'CWE-59', 'SEI CERT'],
		tags: ['symlink', 'follow', 'O_NOFOLLOW', 'tmp', 'race', 'link'],
	},
	{
		id: 'CWE-65',
		name: 'Windows Hard Link',
		lang: 'c',
		status: 'Complete',
		what: `Windows 硬連結（Hard Link）攻擊。攻擊者若能在某目錄裡建立一個 hard link，可以把同一個
	檔以「另一個名字」同時出現在受控位置;程式若以使用者可控路徑直接 CreateFileW() 覆寫或刪除，就會
	透過硬連結作用到它本不打算碰的原始檔上。與 CWE-59／61 的符號連結不同，Windows 硬連結沒有
	reparse point，O_NOFOLLOW 這類「不跟隨連結」的旗標對它沒有作用，攔得住 symlink 的檢查往往
	攔不住 hard link。修法是針對「已開啟的檔案物件」做身分驗證：用 GetFileInformationByHandle()
	讀出檔案的 volume serial ＋ file index，確認它落在受控目錄且 nNumberOfLinks 為 1，任何一條檔有
	多個連結都拒絕操作，避免透過第二個名字誤傷原始檔。`,
		problem: `// 不安全寫法：接受使用者可控路徑直接 CreateFileW 覆寫,身分類檢查對 hard link 失效
#include <windows.h>

int overwrite(const wchar_t *userpath) {
    // 攻擊者可在寫得進的目錄建一個 hard link,把 "GameData.dat" 別名指到受害者的設定檔
    HANDLE h = CreateFileW(userpath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                          NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    DWORD n = 0;
    WriteFile(h, (BYTE*)"pwn", 3, &n, NULL);   // 覆寫到的可能是指向的原始檔
    CloseHandle(h);
    return 0;
}`,
		fixed: `// 安全寫法：開啟後用檔案物件身分檢查;有「多個硬連結」的檔一律拒絕操作
#include <windows.h>

int overwrite_safe(const wchar_t *full) {
    HANDLE h = CreateFileW(full, GENERIC_READ | GENERIC_WRITE, 0,
                          NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    BY_HANDLE_FILE_INFORMATION fi;
    if (!GetFileInformationByHandle(h, &fi)) { CloseHandle(h); return -1; }
    // nNumberOfLinks > 1 代表同一個檔另有多個名字(hard link),拒絕以免誤寫到非預期對象
    if (fi.nNumberOfLinks > 1) { CloseHandle(h); return -1; }
    DWORD n = 0;
    WriteFile(h, (BYTE*)"pwn", 3, &n, NULL);
    CloseHandle(h);
    return 0;
}`,
		patch: `@@
-    HANDLE h = CreateFileW(userpath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
-                          NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
-    if (h == INVALID_HANDLE_VALUE) return -1;
+    // #固定基底、僅純檔名;並在開啟後做身分檢查
+    HANDLE h = CreateFileW(full, GENERIC_READ | GENERIC_WRITE, 0,
+                          NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
+    BY_HANDLE_FILE_INFORMATION fi;
+    if (!GetFileInformationByHandle(h, &fi)) { CloseHandle(h); return -1; }
+    if (fi.nNumberOfLinks > 1) { CloseHandle(h); return -1; }   // 多硬連結 => 拒
     DWORD n = 0;
     WriteFile(h, (BYTE*)"pwn", 3, &n, NULL);`,
		refs: ['CWE-65', 'SEI CERT'],
		tags: ['hard-link', 'windows', 'link', 'file-identity', 'nNumberofLinks'],
	},
	{
		id: 'CWE-66',
		name: 'Improper Handling of File Names that Identify Virtual Resources',
		lang: 'c',
		status: 'Complete',
		what: `不當處理「指向虛擬資源」的檔名。有些檔名並不一定真的代表一棵檔案群裡的一般檔案，
	而會解析到作業系統的特殊虛擬資源：Windows 的保留裝置名稱（NUL、CON、AUX、COM1）、Alternate
	Data Stream（檔名含 :）、以及 Unix 的 /dev、/proc 等特殊檔。程式若只憑使用者給的「名稱」就一路
	照字面去建立、讀寫或刪除，攻擊者就能塞進這類名字，讓複製／刪除／下載動作作用在一個「不是真的
	普通檔」的裝置或資料流上——例如把內容「寫入」名為 NUL 的檔案其實是丟進黑洞、把程式誤導去讀取
	特殊裝置的核心記憶體。修法是在接受檔名之前，先拒絕保留裝置名稱（CON、NUL、AUX、COM1 等）、
	結尾的點與空格，以及任何含 : 的 alternate data stream 語法，只允許真正落在受控目錄的一般檔案。`,
		problem: `// 不安全寫法：直接採信使用者檔名建立/寫入,名稱打到保留裝置名就改到虛擬資源
#include <windows.h>

int save_note(const wchar_t *name, const wchar_t *text) {
    WCHAR path[MAX_PATH] = L"C:\\\\notes\\\\";
    wcscat_s(path, MAX_PATH, name);                  // name 可能是 L"nul" 或 "CON"
    HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                          CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    DWORD n = 0;
    WriteFile(h, (BYTE*)text, (DWORD)wcslen(text) * 2, &n, NULL);  // 寫到的是 NUL 裝置
    CloseHandle(h);
    return 0;
}`,
		fixed: `// 安全寫法：先過濾保留名稱、尾端點/空白與 :: 語法,只准一般檔名進受控目錄
#include <windows.h>

static int is_reserved_name(const wchar_t *name) {
    wchar_t bare[16];
    int i = 0;
    while (name[i] && name[i] != L'.' && i < 15) { bare[i] = name[i]; i++; }
    bare[i] = L'\\0';
    if (i == 0) return 1;                                   // 空白名稱
    if (_wcsicmp(bare, L"CON") == 0 ||
        _wcsicmp(bare, L"NUL") == 0 ||
        _wcsicmp(bare, L"AUX") == 0 ||
        _wcsicmp(bare, L"PRN") == 0 ||
        _wcsnicmp(bare, L"COM", 3) == 0 ||               // COM1..COM9
        _wcsnicmp(bare, L"LPT", 3) == 0) return 1;      // LPT1..LPT9
    size_t len = wcslen(name);
    return wcsrchr(name, L':') != NULL ||                    // :: 資料流語法
           (len && name[len - 1] == L' ') ||
           (len && name[len - 1] == L'.');
}

int save_note_safe(const wchar_t *name, const wchar_t *text) {
    if (is_reserved_name(name)) return -1;                    // 命中保留/虛擬資源 => 拒
    WCHAR path[MAX_PATH] = L"C:\\\\notes\\\\";
    wcscat_s(path, MAX_PATH, name);
    HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                          CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    DWORD n = 0;
    WriteFile(h, (BYTE*)text, (DWORD)wcslen(text) * 2, &n, NULL);
    CloseHandle(h);
    return 0;
}`,
		patch: `@@
 int save_note(const wchar_t *name, const wchar_t *text) {
+    if (is_reserved_name(name)) return -1;                    // 保留裝置/:: 資料流 => 拒
     WCHAR path[MAX_PATH] = L"C:\\\\notes\\\\";
     wcscat_s(path, MAX_PATH, name);
     HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
     if (h == INVALID_HANDLE_VALUE) return -1;`,
		refs: ['CWE-66', 'CWE-67', 'CWE-69'],
		tags: ['virtual-resource', 'device-name', 'alternate-data-stream', 'reserved-name', 'windows'],
	},
	{
		id: 'CWE-378',
		name: 'Creation of Temporary File With Insecure Permissions',
		lang: 'c',
		status: 'Complete',
		what: `以不安全的權限建立暫存檔。開發者常用 tmpnam()／mktemp() 這類只「產生一個檔名」的 API，
	再做一次獨立的 open 來建立檔案;這樣做出的暫存檔權限受 umask 支配（常常是 0644），機敏感性內容
	（token、金鑰、暫存密碼檔）便對本機其他使用者可讀，而且「取名字」與「建立」分開還會留下可被預置
	symlink／猜中名字的競態空窗。CWE-378 特別強調權限問題:暫存檔內容一旦以世界可讀的權限落盤，
	任何能列目錄的人就能整份讀走。修法是使用 mkstemp() 這類「單一原子 API」——它在建立當下就生成
	唯一的隨機檔名、設定成 0600 私有權限、並直接回傳已開啟的 fd,寫完即關閉,不把機密留給他人可讀
	的暫存檔，也讓猜檔名的 symlink 攻擊無從下手。`,
		problem: `// 不安全寫法：tmpnam() 只給名字,再用 fopen 以預設 umask(常 0644)建立 => 他人可讀
#include <stdio.h>
#include <stdlib.h>

int write_secret(const char *secret) {
    char tmp[L_tmpnam];
    tmpnam(tmp);                  // tmpnam 只「產生名字」,不保證安全建立 & 權限
    FILE *f = fopen(tmp, "w");   // 受 umask 影響常見 0644,且名字可猜、可被預置 symlink
    if (!f) return -1;
    fprintf(f, "%s", secret);     // 機密以世界可讀權限留板
    fclose(f);
    return 0;
}`,
		fixed: `// 安全寫法：mkstemp() 一次建立唯一檔名 + 私有 0600 權限並回傳 fd
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int write_secret(const char *secret) {
    char tmpl[] = "/tmp/app-XXXXXX";
    int fd = mkstemp(tmpl);      // 建立即 0600(僅本人),檔名隨機不可猜,無預置/symlink空窗
    if (fd < 0) return -1;
    dprintf(fd, "%s", secret);
    close(fd);
    return 0;
}`,
		patch: `@@
-    char tmp[L_tmpnam];
-    tmpnam(tmp);
-    FILE *f = fopen(tmp, "w");
-    if (!f) return -1;
-    fprintf(f, "%s", secret);
-    fclose(f);
+    char tmpl[] = "/tmp/app-XXXXXX";
+    int fd = mkstemp(tmpl);      // 建立即 0600 私有,名字隨機
+    if (fd < 0) return -1;
+    dprintf(fd, "%s", secret);
+    close(fd);
     return 0;
 }`,
		refs: ['CWE-378', 'CWE-377', 'SEI CERT'],
		tags: ['temp-file', 'mkstemp', 'permissions', 'tmpnam', 'world-readable'],
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
	{
		id: 'CWE-552',
		name: 'Files or Directories Accessible to External Parties',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `不該公開的檔案或目錄被外部看得到。網頁伺服器／檔案伺服器用「整棵目錄」當靜態根,或把
	　包含設定、備份、原始碼、.env、.git 的目錄也放進能透過網路存取的根,於是最重要但最容易被忽略的
	資訊就露在加密運輸後面任何人可下載。攻擊者只要猜檔名或走目錄列舉(Listing)就能讀到設定密碼、資料庫
	連線字串、原始程式碼,甚至把 .git 整包拉下來逆推出更多秘密。這與需要深入發掘的漏洞不同——暴露通常是
	「某個路徑沒被擋住」這種壓根沒設防的狀態。修法是只把「明確白名單」的公開assets放進可存取根,其他
	目錄一律不分派、設定檔/原始檔放在文件根之外,並對敏感副檔名與隱藏檔(.env、.git、backup)回傳404。`,
		problem: `// 不安全寫法：把整個工作目錄(含 .env, .git, src)都設成靜態根,全都可被下載
const express = require('express');
const app = express();

// 文件根直接指向專案根目錄 => 任何人都能 GET /.env、/.git/config、/src/index.js
app.use(express.static(process.cwd()));   // process.cwd() 就是整個專案,含機密設定
app.listen(8080);`,
		fixed: `// 安全寫法：只把建置後的白名單 public 目錄設為靜態根;隱藏檔與敏感副檔名一律 404
const express = require('express');
const path = require('path');
const app = express();

const PUBLIC_ROOT = path.resolve(__dirname, 'dist', 'public');   // 只有公開 assets
app.use(express.static(PUBLIC_ROOT));                            // 源碼/.env/.git 根本不在根下

// 額外保險:對明顯的敏感路徑一律重導給 404,不回應存在與否
app.use('/.env', (req, res) => res.status(404).end());
app.use('/.git', (req, res) => res.status(404).end());
app.listen(8080);`,
		patch: `@@
  const app = express();
- // 文件根直接指向專案根目錄 => 任何人都能 GET /.env、/.git/config、/src/index.js
- app.use(express.static(process.cwd()));   // process.cwd() 就是整個專案,含機密設定
+ const PUBLIC_ROOT = path.resolve(__dirname, 'dist', 'public');
+ app.use(express.static(PUBLIC_ROOT));      // 源碼/.env/.git 不在靜態根之下
+ app.use('/.env', (req, res) => res.status(404).end());
+ app.use('/.git', (req, res) => res.status(404).end());
  app.listen(8080);`,
		refs: ['CWE-552', 'OWASP'],
		tags: ['exposed-files', 'directory-listing', 'static-root', 'source-exposure', '.env'],
	},
];