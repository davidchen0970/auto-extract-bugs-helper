// CWE chunk — 類別:輸入處理、路徑等價與注入 (Path Equivalence / Neutralization / Struts)
// 補齊官方 v4.20 中手冊原本缺漏的 Base/Variant 條目
export default [
  {
    id: 'CWE-57',
    name: "Path Equivalence: 'fakedir/../realdir/filename'",
    lang: 'javascript',
    status: 'Complete',
    what: `路徑等價攻擊—「fakedir/../realdir/filename」寫法。產品包含一道保護機制，用來限制對
    「realdir/filename」的存取;但當程式用它收取的外部輸入來建構路徑名稱時，允許的路徑語法
    可以寫成「fakedir/../realdir/filename」這種並非字面上等於受保護路徑、實際上卻指向同一個
    檔案的形式，於是該路徑並未被保護機制攔下。成因是防護靠在「字面字串比對」或「與受保護路徑
    精確相等」的假定上，沒有先把路徑正規化(canonicalize)再比對。後果是攻擊者可藉助 ..、重複
    分隔符等「等義寫法」繞過存取控制，對原先受保護的檔案未經授權存取。修法是先以作業系統提供的
    正規化解法(realpath、canonicalize)把路徑展開與誤導消解，並對消解後的結果套用先前對字面
    路徑做的那一套授權判定;解開檔案之前避免直接拿原始字面值開檔。`,
    problem: `// 壞的寫法:只比對字面路徑,.. 寫法可繞過保護
const fs = require('fs');
const path = require('path');

const PROTECTED = path.resolve('/srv/private', 'realdir', 'filename');
const ROOT = '/srv/private';

function readFile(userInput) {
  // 攻擊者可傳 "fakedir/../realdir/filename",resolve 後仍是同一檔
  const p = path.resolve(ROOT, userInput);
  if (p === PROTECTED) {
    throw new Error('forbidden'); // 只擋字面相等的路徑 => 可被繞過
  }
  return fs.readFileSync(p, 'utf8');
}`,
    fixed: `// 好的寫法:先正規化,再用正規化結果做授權,並限定在受控根目錄內
const fs = require('fs');
const path = require('path');
const realpath = fs.realpathSync;

const ROOT = path.resolve('/srv/private');

function readFile(userInput) {
  const full = path.resolve(ROOT, userInput);
  const canon = realpath(full);              // 消解 ...,符號連結等多重表示
  if (canon.indexOf(ROOT + path.sep) !== 0 && canon !== ROOT) {
    throw new Error('outside root');         // 先落回受控根,再做其他授權
  }
  if (/private/i.test(canon)) throw new Error('forbidden');
  return fs.readFileSync(canon, 'utf8');
}`,
    patch: `@@
   const PROTECTED = path.resolve('/srv/private', 'realdir', 'filename');
   const ROOT = '/srv/private';
   function readFile(userInput) {
-    const p = path.resolve(ROOT, userInput);
-    if (p === PROTECTED) throw new Error('forbidden');
-    return fs.readFileSync(p, 'utf8');
+    const full = path.resolve(ROOT, userInput);
+    const canon = fs.realpathSync(full);
+    if (canon.indexOf(ROOT + path.sep) !== 0 && canon !== ROOT)
+      throw new Error('outside root');
+    if (/private/i.test(canon)) throw new Error('forbidden');
+    return fs.readFileSync(canon, 'utf8');
   }`,
    refs: ['CWE-57', 'CWE-41', 'CWE-59'],
    tags: ['path-equivalence', 'dot-dot', 'canonicalization', 'path-traversal'],
  },
  {
    id: 'CWE-58',
    name: 'Path Equivalence: Windows 8.3 Filename',
    lang: 'c',
    status: 'Complete',
    what: `路徑等價攻擊之「Windows 8.3 短檔名」。產品在 Windows 上包含一個限制存取的保護機制,
    通常是針對長的檔名(例如 "importantfile.aspx");但同一個實體檔案還存在等價的短「8.3」
    別名(例如 "IMPORT~1.ASP"),保護機制沒有同樣限制這個短名。成因是過濾或授權僅比對長檔名,
    忽略了 NTFS 為每個長名自動產生的 8.3 輔助名稱。後果是攻擊者可用短名繞過原本對長檔名的限制,
    讀取或操作受保護的檔案。修法是在做授權判定前先取作業系統的「cannonical / 實際路徑」並正規化,
    讓長名與短名都落到同一個唯一的檔案標識,並一併套用相同的存取控制;或乾脆用檔案 handle 而非
    「使用者給的名字」來後續操作,避免旁路名。`,
    problem: `// 壞的寫法:過濾清單只含長檔名,短 8.3 名可繞過
#include <windows.h>

wchar_t denylist[][8] = { L"important.aspx" };

int allow_file(const wchar_t *name) {
    for (int i = 0; denylist[i][0]; i++)
        if (wcsicmp(name, denylist[i]) == 0) return 0; // 只比長檔名
    return 1; // 攻擊者傳 "IMPORT~1.ASP" 就被放行
}`,
    fixed: `// 好的寫法:以磁碟上的實際檔識別(canonical)做判定,長短名各自正規化
#include <windows.h>

int allow_handle(HANDLE f) {
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(f, &info)) return 0;
    // 對 8.3 短名用相同識別(volume+index)就不會漏:同檔得同一結果
    return is_forbidden_index(info.nFileIndexLow, info.nFileIndexHigh);
}`,
    patch: `@@
   wchar_t denylist[][8] = { L"important.aspx" };
   int allow_file(const wchar_t *name) {
-    for (int i = 0; denylist[i][0]; i++)
-        if (wcsicmp(name, denylist[i]) == 0) return 0;
-    return 1;
+    return 1;
   }`,
    refs: ['CWE-58', 'CWE-57', 'CWE-73'],
    tags: ['8.3', 'short-filename', 'windows', 'path-equivalence', 'canonicalization'],
  },
  {
    id: 'CWE-62',
    name: 'UNIX Hard Link',
    lang: 'c',
    status: 'Complete',
    what: `UNIX 硬連結(hard link)處理不當。程式要開啟一個檔或目錄時,如果這個檔名其實是一個硬連結、
    指向目標權限範圍之外的檔,NULL 連結會讓所有「檔名」都指向同一份數據;程式「照字面」開檔時不知道這個
    名字背後還有一個別名連到不受控的地方。成因是只以「名字→inode」作一次解析,對運算單元在同一個 inode
    上掛了多個連結(硬連結)沒有控管。後果是攻擊者可在目錄內先建立另一條指向目標的硬連結,再讓程式根據受控制的
    檔名去開/寫,於是在「寫得進去」的地方改了「不該碰」的檔案。修法是結合「好檔案系統根」與「開啟後驗證
    inode 身分」:用 openat 對已開啟的目錄 fd 操作,並用 fstat + st_nlink / st_ino 確認目標落回受控樹、
    且沒有被接上額外連結;避免只依路徑字面值下判斷。`,
    problem: `// 壞的寫法:只依路徑字面開啟,不檢查硬連結與 inode 身分
#include <fcntl.h>
#include <unistd.h>

int overwrite_log(const char *path) {
    int fd = open(path, O_WRONLY | O_TRUNC); // 攻擊者可先 ln target path
    if (fd < 0) return -1;
    write(fd, "pwned", 5);                   // 寫進的其實是被硬連結到的目標
    close(fd);
    return 0;
}`,
    fixed: `// 好的寫法:開啟後用 fstat 驗證身分,確認是一般檔且在受控樹且僅 1 個連結
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int overwrite_log_safe(int dirfd, const char *name) {
    int fd = openat(dirfd, name, O_WRONLY | O_TRUNC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1) {
        close(fd); return -1;   // 多連結 => 可能是硬連結指向受控之外的檔
    }
    write(fd, "ok", 2); close(fd);
    return 0;
}`,
    patch: `@@
   int overwrite_log(const char *path) {
-    int fd = open(path, O_WRONLY | O_TRUNC);
-    if (fd < 0) return -1;
-    write(fd, "pwned", 5); close(fd); return 0;
+    int fd = openat(dirfd, name, O_WRONLY | O_TRUNC | O_NOFOLLOW);
+    if (fd < 0) return -1;
+    struct stat st;
+    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1) {
+        close(fd); return -1;
+    }
+    write(fd, "ok", 2); close(fd); return 0;
   }`,
    refs: ['CWE-62', 'CWE-59', 'SEI CERT'],
    tags: ['hard-link', 'inode', 'openat', 'st-nlink', 'file-identity'],
  },
  {
    id: 'CWE-64',
    name: 'Windows Shortcut Following (.LNK)',
    lang: 'c',
    status: 'Complete',
    what: `Windows 捷徑(.LNK)跟隨處理不當。程式要開啟一個檔或目錄時,如果開啟的其實是一個
    Windows 捷徑(.lnk 檔案),其「目標」位於預期的控制範圍之外,程式沒有充分處理這種情況。成因是
    把 .lnk 當成一般的檔案內容讀,或以為「讀檔名即讀取該檔案」,沒想過 .lnk 是一個「指向其他目標」
    的間接檔案。後果是攻擊者放一支目標指向系統機密檔料的 .lnk,程式依使用者可控的來源開啟,最後
    「開啟到」的是與名字毫不相干的、受控之外的檔案,造成未授權存取或竄改。修法是明確辨識 .lnk:
    用重分析點/捷徑剖析 API 讀出真正的目標,並對「解析出來的目標」在受控範圍內做完整的授權判定,
    同時避免在建置了捷徑解析的環境下,直接把外部檔案當作一般檔開。`,
    problem: `// 壞的寫法:直接依路徑開啟,捷徑目標未被解析與授權
#include <windows.h>

void render_icon(const wchar_t *userpath) {
    HANDLE f = CreateFileW(userpath, GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    // userpath 可能是指向 C:\\\\Windows\\\\system32\\\\config\\\\SAM 的 .lnk
    read_and_process(f, userpath);   // 直接當一般檔開啟,捷徑目標未被解析
}`,
    fixed: `// 好的寫法:用 Shell API 讀出捷徑實際目標,再對目標做授權
#include <windows.h>
#include <shlobj.h>

int safe_open_shortcut(const wchar_t *userpath) {
    if (wcslen(userpath) >= 4 && _wcsicmp(userpath + wcslen(userpath) - 4, L".lnk") == 0) {
        wchar_t target[MAX_PATH];
        if (SHResolveShellLink(userpath, target, MAX_PATH) != S_OK) return -1;
        if (is_blocked_path(target)) return -1;   // 對解析出的目標重新做授權
        userpath = target;                        // 之後以「解析後的目標」開啟
    }
    return 0;
}`,
    patch: `@@
   void render_icon(const wchar_t *userpath) {
-        HANDLE f = CreateFileW(userpath, GENERIC_READ, FILE_SHARE_READ,
-                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
-        read_and_process(f, userpath);
+        if (is_lnk(userpath)) {                    // 明辨 .lnk,先解析真正目標
+            wchar_t target[MAX_PATH];
+            if (resolve_lnk_target(userpath, target, MAX_PATH) != S_OK) return;
+            if (is_blocked_path(target)) return;      // 對目標重新做授權
+            userpath = target;
+        }
   }`,
    refs: ['CWE-64', 'CWE-59', 'OWASP'],
    tags: ['shortcut', 'lnk', 'link-following', 'windows', 'untrusted-target'],
  },
  {
    id: 'CWE-71',
    name: "DEPRECATED: Apple '.DS_Store'",
    lang: 'javascript',
    status: 'Deprecated',
    what: `本條目已廢棄。它代表的是「UNIX 硬連結(UNIX Hard Link,CWE-62)」下一個具體觀測到的實例,
    而不再自成一個弱點類型。parking 到現在,請改以 CWE-62 作為對應。若在你的環境中真正看到
    「.DS_Store」相關的競態,應依 CWE-62 的脈絡去修:開啟前不要只依路徑字面,開檔後驗證檔案身分,並限制在受控的根目錄內。`,
    problem: `// (已廢棄)只做字面展示,CWE-62 已取代
open(".DS_Store", O_WRONLY);`,
    fixed: `// 改依 CWE-62:開檔後驗證身分並限定在受控樹
int fd = openat(dirfd, name, O_NOFOLLOW);
struct stat st; if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) return -1;`,
    patch: `@@
- open(".DS_Store", O_WRONLY);
+ // 以 CWE-62 的方式開: openat + O_NOFOLLOW,開完 fstat 驗證身分`,
    refs: ['CWE-71', 'CWE-62'],
    tags: ['deprecated', 'DS_Store', 'link-following', 'hard-link'],
  },
  {
    id: 'CWE-72',
    name: 'Improper Handling of Apple HFS+ Alternate Data Stream Path',
    lang: 'c',
    status: 'Complete',
    what: `不當處理 Apple HFS+ 的「交替資料流路徑」。產品接受檔案路徑,但沒有正確處理那些可以用來
    指到 HFS+ 檔案系統上「資料叉(data fork)」或「資源叉(resource fork)」的特殊路徑語法
    (Typical 用 "file/..namedfork/rsrc" 或 ":rsrc" 等表示資源叉)。成因是只把路徑當「一個檔」,
    沒認出後綴是指向檔案旁資料流的特殊欄位;於是對「整條路徑」的一致性、授權與清理都落在主檔名上,
    而真正被讀/寫的可能是資源叉。後果是攻擊者可用這類路徑存取本不該給它的資料流(內容躲藏、讀到他無法讀的
    資源),或繞過針對一般檔的過濾/下載防護。修法是組路徑/解析前先正規化並拆出「資料流」後綴,對主檔
    與 stream 分別以相同的授權檢查,並防止拿使用者輸入直接拼出 "..namedfork/..." 的語法。`,
    problem: `// 壞的寫法:直接拼使用者輸入當一般檔開啟,不處理 ::namedfork 語法
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

void open_media(char *user) {
    char path[512];
    snprintf(path, sizeof path, "/Volumes/Share/%s", user);
    int fd = open(path, O_RDONLY);          // user 可為 a.mp4/..namedfork/rsrc
    if (fd >= 0) read_all(fd);               // 讀到的根本不是主檔內容
    if (fd >= 0) close(fd);
}`,
    fixed: `// 好的寫法:拒絕 ::namedfork / ..namedfork 等資料流後綴,只准一般 data fork
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

int is_fork_path(const char *p) {
    return strstr(p, "..namedfork") != NULL || strchr(p, '/') != 0 &&
           strstr(p, "/rsrc") != NULL;
}

void open_media(const char *user) {
    if (strchr(user, ':') || is_fork_path(user) || strstr(user, "..namedfork")) {
        return; // 字元的資料流路徑 => 直接拒絕
    }
    char path[512];
    snprintf(path, sizeof path, "/Volumes/Share/%s", user);
    char *canon = realpath(path, NULL);
    if (!canon) return;
    clean_open(canon); free(canon);
}`,
    patch: `@@
  void open_media(char *user) {
+    if (strchr(user, ':') || strstr(user, "..namedfork")) return;
      char path[512];
      snprintf(path, sizeof path, "/Volumes/Share/%s", user);
-    int fd = open(path, O_RDONLY);
+    clean_open(path);
   }`,
    refs: ['CWE-72', 'CWE-66', 'CWE-73'],
    tags: ['hfs+', 'alternate-data-stream', 'resource-fork', 'resource-fork', 'data-fork'],
  },
  {
    id: 'CWE-76',
    name: 'Improper Neutralization of Equivalent Special Elements',
    lang: 'php',
    status: 'Complete',
    what: `不當中和「等義的特殊字元」。產品能正確中和某一種特殊字元(例如只擋雙引號),但卻沒有中和與之
    等價、或在不同字元編碼/不同字序下具有相同語法意義的特殊字元(例如全形引號、HTML 實體、或者替換成
    大小寫變異)。成因是過濾只針對特定、已知的字面清單,沒把所有「能達成同一語意效果」的等價形式一起處理。
    後果是過濾看似安全,攻擊者仍可換一種「等義寫法」把原本要梘的字元送進去,造成 XSS、注入等;安全防線變成
    虛有其表。修法是不要只做黑名單字面替換,要對輸入做嚴格的編碼解碼與白名單/允許清單,把送到「有語意的
    環境(context)」之前的資料依 context 專屬的規則輸出跳脫,讓所有表示同一語意的形式統一歸一處理。`,
    problem: `// 壞的寫法:只取代一個引號樣式,等價寫法全漏過去
function render($name) {
  $name = str_replace('"', '&quot;', $name);   // 只中和雙引號
  return "<div data-n=\"$name\"></div>";       // 但 ' (單引號)還能閉合成屬性
}`,
    fixed: `// 好的寫法:對 context 用專屬輸出跳脫,所有等義寫法一致才會影響
function render($name) {
  // 依 context 決定編碼:屬性值用 htmlspecialchars,讓引號都變實體或切換
  $e = htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
  return "<div data-n=\"$e\"></div>";
}`,
    patch: `@@
  function render($name) {
-    $name = str_replace('"', '&quot;', $name);
-    return "<div data-n=\"$name\"></div>";
+    $e = htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
+    return "<div data-n=\"$e\"></div>";
  }`,
    refs: ['CWE-76', 'CWE-79', 'OWASP'],
    tags: ['equivalent-special-elements', 'xss', 'encoding', 'context-aware-escaping'],
  },
  {
    id: 'CWE-81',
    name: 'Improper Neutralization of Script in an Error Message Web Page',
    lang: 'php',
    status: 'Complete',
    what: `在「錯誤訊息網頁」中不對腳本做中和。產品從上游元件接收輸入,但把它送到錯誤頁(Error Page)時,
    沒有中和、或錯誤地中和了那些可能被解釋為 web-scripting 元素(如 <script>、事件屬性)的特殊字元。
    成因是錯誤頁常被當「程式內部的文字」相信而直接用 echo/回應輸出,忘了這裡輸入仍然是由使用者/上游可控,
    且處於 HTML 的語意環境。後果是攻擊者把腳本注入錯誤訊息,當使用者或管理員瀏覽該錯誤頁時執行惡意 JS,
    形成反射型/儲存型 XSS。修法是「輸出端編碼」準則:凡是要放到 HTML(尤其錯誤頁)的任何動態字串,
    一律以 htmlspecialchars/HtmlEncoder 等依 context 跳脫後才輸出,不直接插值。`,
    problem: `// 壞的寫法:直接把輸入內容寫進錯誤頁,初始腳本活著出去
<?php
$err = $_GET['err'];
echo "<html><body><h1>Error</h1><p>$err</p></body></html>"; // 可注入 <script>
?>`,
    fixed: `// 好的寫法:輸出前依 HTML context 跳脫
<?php
$err = $_GET['err'];
$e = htmlspecialchars($err, ENT_QUOTES, 'UTF-8');
echo "<html><body><h1>Error</h1><p>$e</p></body></html>";
?>`,
    patch: `@@
   $err = $_GET['err'];
-  echo "<html><body><h1>Error</h1><p>$err</p></body></html>";
+  $e = htmlspecialchars($err, ENT_QUOTES, 'UTF-8');
+  echo "<html><body><h1>Error</h1><p>$e</p></body></html>";
  ?>`,
    refs: ['CWE-81', 'CWE-79', 'OWASP'],
    tags: ['error-page', 'xss', 'output-encoding', 'html-injection'],
  },
  {
    id: 'CWE-82',
    name: 'Improper Neutralization of Script in Attributes of IMG Tags in a Web Page',
    lang: 'php',
    status: 'Complete',
    what: `不當中和網頁內 IMG 標籤屬性中的腳本。網頁應用程式沒有中和、或錯誤中和了 HTML <img> 標籤
    屬性(像是 src、onerror)內所夾帶的 scripting 元素。成因是把使用者輸入直接塞進 IMG 屬性的「值」,
    而屬性值是能執行程式的"語言環境"(尤其 onerror 等事件屬性,或可被瀏覽器當成 URL 的 src)。後果是
    攻擊者把樣式閉合屬性、注入事件處理器,讓任何瀏覽該頁的人執行 JS -> XSS。修法是不要拼 HTML,讓屬性值
    進入時先做正確的 encoding(value encoding,不只跳脫引號),並用白名單/框架建樹(DOMPurify 審核)、
    避免使用內聯事件屬性。`,
    problem: `// 壞的寫法:直接拼接 IMG 屬性值
<?php
$img = $_GET['src'];
echo "<img src=\"$img\">";  // 傳 "x\" onerror=\"alert(1)" 即注入
?>`,
    fixed: `// 好的寫法:屬性值以 context 的 encoding 輸出,避免直達事件屬性
<?php
$src = htmlspecialchars($_GET['src'], ENT_QUOTES | ENT_HTML5, 'UTF-8');
if (!preg_match('#^https?://#i', $src)) $src = '';   // 必要時白名單 scheme
echo "<img src=\"$src\" alt=\"\">";  // 不支援 onerror 等由我們動態拼的屬性
?>`,
    patch: `@@
  $img = $_GET['src'];
- echo "<img src=\"$img\">";
+ $src = htmlspecialchars($_GET['src'], ENT_QUOTES | ENT_HTML5, 'UTF-8');
+ echo "<img src=\"$src\">";
  ?>`,
    refs: ['CWE-82', 'CWE-79', 'OWASP'],
    tags: ['img-attribute', 'xss', 'onerror', 'html-encoding'],
  },
  {
    id: 'CWE-84',
    name: 'Improper Neutralization of Encoded URI Schemes in a Web Page',
    lang: 'php',
    status: 'Complete',
    what: `不當中和「已編碼的 URI scheme」。網頁應用程式對使用者可控的輸入、為了把可執行腳本偽裝起來,
    可能採用已編碼的 URI 表示(例如把 javascript: 編碼成 javascript&#58;、\\u006a 或百分號編碼),這類輸入沒有被
    適當中和。成因是過濾器用「字面找 javascript/script」的解字串,遇到編碼變異就被繞過,或者功能端反解時
    把已中和的字元解開還原。後果是攻擊者把可執行腳本透過多重編碼送進某個可續動的環境,如 href/src
    的值,在瀏覽器解碼後照樣執行 -> 偽裝成不相干的寫法的 XSS。修法是對「最終要套用語意的 context」輸出
    跳脫,並把輸入整個轉成可受控制的字面「純資料」,不要讓雙重編碼或解碼路徑存在;對合法 scheme 用白名單,
    全部先解碼回歸一,再驗證。`,
    problem: `// 壞的寫法:只擋字面的 javascript:,編碼變異全漏
<?php
function safeHref($u) {
    if (strpos($u, 'javascript:') !== false) return '#';   // 只找字面
    return $u; // "j\\\\u0061vascript:alert(1)" 或 "java&#115;cript:" 放行
}
echo "<a href=\\"" . safeHref($_GET['url']) . "\\">link</a>";
?>`,
    fixed: `// 好的寫法:解碼回歸一後用 scheme 白名單,並對 context 跳脫
<?php
function safeHref($u) {
    $plain = rawurldecode(html_entity_decode($u, ENT_QUOTES, 'UTF-8'));
    $plain = preg_replace('/\\\\\\\\u[0-9a-fA-F]{4}/', '', $plain); // 再把 unicode 轉義還原
    if (preg_match('#^([a-z][a-z0-9+.-]*):#i', $plain, $m) &&
        strtolower($m[1]) !== 'http' && strtolower($m[1]) !== 'https') {
        return '#';                     // 非白名單 scheme(含 javascript:) => 拒
    }
    return htmlspecialchars($u, ENT_QUOTES, 'UTF-8');
}
?>`,
    patch: `@@
  function safeHref($u) {
-    if (strpos($u, 'javascript:') !== false) return '#';
-    return $u;
+    $plain = rawurldecode(html_entity_decode($u, ENT_QUOTES, 'UTF-8'));
+    if (preg_match('#^([a-z][a-z0-9+.-]*):#i', $plain, $m) &&
+        strtolower($m[1]) !== 'http' && strtolower($m[1]) !== 'https') return '#';
+    return htmlspecialchars($u, ENT_QUOTES, 'UTF-8');
   }`,
    refs: ['CWE-84', 'CWE-79', 'OWASP'],
    tags: ['encoded-uri', 'scheme', 'xss', 'url-encoding', 'allowlist'],
  },
  {
    id: 'CWE-85',
    name: 'Doubled Character XSS Manipulations',
    lang: 'php',
    status: 'Complete',
    what: `「字元倍增」的 XSS 操弄。網頁應用程式沒有過濾掉、使用者可控的輸入用「倍增其構成字元」的方式
    偽裝成可執行腳本(例如把 '<script>' 以 '<scr<script>ipt>' 表示,或把字元重複送出)。成因是防護用
    「第一次出現的字面樣式」去移除配對的關鍵字,而攻擊者讓關鍵字的字元被「再包一層」或重複送出,反覆進行
    時,殘留的尾部又組回合法腳本標籤。後果是過濾看似把 '<script>' 達標移除,但殘字重新組合成可執行的
    '<script>',瀏覽器再執行 -> XSS。修法是避免對輸入做「半套」的字面字串置空的防護;應該用完整、可靠的
    編碼 / 白名單 / 語法樹,確保送出的 HTML 中不可能重組成標籤;常用做法是把輸入以 context 之 escaped
    處理,再把它視為純文字,消除任何殘餘重組空間。`,
    problem: `// 壞的寫法:只移除第一次比對到的 <script>,倍增可以把殘字浮出
<?php
function strip_script($html) {
    while (($p = strpos($html, '<script>')) !== false)
        $html = substr_replace($html, '', $p, strlen('<script>'));
    return $html; // "<scr<script>ipt>alert(1)</script>" 清除後變 "<script>alert(1)"
}
echo strip_script($_POST['html']);
?>`,
    fixed: `// 好的寫法:以白名單/語法樹處理,不做字面字串剝除
<?php
function render_user_html($raw) {
    // 用整段 HTML 清理函式(例 DOMPurify-like),而非字面剝除
    $clean = cleanup_user_html($raw); // 依 DOM 層面刪除 node 等級的腳本
    return $clean;
}
echo render_user_html($_POST['html']);
?>`,
    patch: `@@
  function strip_script($html) {
-    while (($p = strpos($html, '<script>')) !== false)
-        $html = substr_replace($html, '', $p, strlen('<script>'));
-    return $html;
+    return cleanup_user_html($html);   // DOM 層清理,非字面剝除
  }`,
    refs: ['CWE-85', 'CWE-79', 'OWASP'],
    tags: ['doubled-character', 'xss', 'sanitization', 'dom-sanitizer'],
  },
  {
    id: 'CWE-86',
    name: 'Improper Neutralization of Invalid Characters in Identifiers in Web Pages',
    lang: 'php',
    status: 'Complete',
    what: `不當中和網頁中「識別子的無效字元」。產物沒有中和、或不當中和了位在標籤名稱、URI scheme 以及
    其他識別子「中間」的無效字元或位元組序列。成因是過濾器只看「識別子的起頭」或「乾淨的應該字串」,
    忽略了識別子中間混進 null byte、控制字元、編碼殘尾等無效字元。後果是這些無效字元在瀏覽器/上游解析時
    會被忽略或解讀,識別子的「有效部分」殘留並被當成不同權限/不同標籤來詮釋,讓過濾失效;像是把非法的
    字元插入後標籤已不相等於受保護字面,卻又能在瀏覽器端被「寬容地」解回同一標籤。修法是把輸入先過濾
    合法字符集合(白名單),並在真正比對之前對識別子做字元集正規化/清除無效字符,確保「被比對的字面」
    與「瀏覽器將解釋的識別子」完全一致。`,
    problem: `// 壞的寫法:只檢查識別子起頭,中間的無效字元照放過去
<?php
$tag = $_GET['tag'];
if (strpos($tag, '<') !== 0) { /* 允許 */ }
echo "<$tag>content</$tag>";  // 中間加控制字元等無效字元可改變瀏覽器解讀
?>`,
    fixed: `// 好的寫法:以白名單允許的合法字元過濾識別子
<?php
$tag = $_GET['tag'];
if (!preg_match('/^[a-zA-Z][a-zA-Z0-9_:-]*$/', $tag)) { $tag = ''; } // 白名單
echo "<$tag>content</$tag>";
?>`,
    patch: `@@
  $tag = $_GET['tag'];
- if (strpos($tag, '<') !== 0) { }
- echo "<$tag>content</$tag>";
+ if (!preg_match('/^[a-zA-Z][a-zA-Z0-9_:-]*$/', $tag)) { $tag = ''; }
+ echo "<$tag>content</$tag>";
  ?>`,
    refs: ['CWE-86', 'CWE-79', 'OWASP'],
    tags: ['identifier', 'invalid-characters', 'tag-name', 'xss', 'allowlist'],
  },
  {
    id: 'CWE-92',
    name: 'DEPRECATED: Improper Sanitization of Custom Special Characters',
    lang: 'javascript',
    status: 'Deprecated',
    what: `本條目已廢棄。它原本來自 PLOVER,該來源有時為了滿足分類法上的「完備性」要求而定義「其他」、
    「雜項」這類類別;在 CWE 脈絡下,對映時較偏向使用更抽象的一支條目。CWE-75 是比較適當的對映
    (不當中和特殊字元)。所以此 ID 請不要再當作新分類使用,遇到相近問題時以 CWE-75 為準。`,
    problem: `// (已廢棄)原條目無具體樣式範例*/
// 以現今 CWE 為準,由 CWE-75 承擔特殊字元中和`,
    fixed: `// 對映到 CWE-75:對要進入帶語意 context 的輸入做正確的跳脫
function sanitize(v) { return String(v).replace(/</g, '&lt;'); } // 示意`,
    patch: `@@
- // 舊的"自訂特殊字元"分類已廢棄
+ // CWE-75: 依 context 輸出跳脫`,
    refs: ['CWE-92', 'CWE-75'],
    tags: ['deprecated', 'sanitization', 'special-characters'],
  },
  {
    id: 'CWE-96',
    name: "Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')",
    lang: 'php',
    status: 'Complete',
    what: `靜態儲存程式碼中的指令不被中和(「靜態注入」)。產物從上游元件接收輸入,但在把輸入插入某個
    「可執行的資源」之前,沒有中和、或不當中和了「程式碼語法」;這些可執行資源包括函式庫、設定檔、或模板。
    成因是想「把使用者內容拼進程式檔案」而不把其當成可能含語意的程式碼對待;一旦被拼進 .php/.py 這類會被
    載入執行的來源,輸入就成了真正的指令。後果是把「資料」無意間變成「可執行指令」:此時弱點名稱是「靜態
    注入」——寫檔後對方再執行該檔,達到程式碼執行。修法是絕對不要用腳本源語言去編譯產出可執行碼;資料要
    以「資料表示(序列化/可檢驗的資料字串)」存放,讀回時用安全的解析而非 eval/載入即執行;任何 requires 的內容
    都在已知、白名單的路徑。`,
    problem: `// 壞的寫法:把輸入當成 PHP 語法拼入保留的設定檔
<?php
$name = $_POST['name'];
file_put_contents('/srv/data/settings.php',
  "<?php\\n\$CFG['greeting'] = '$name';\\n"); // 傳 "'); system('cat /etc/passwd'); //" 即注入
?>`,
    fixed: `// 好的寫法:以純資料格式(JSON/serial)存放,讀回用資料層解析,不把資料變語法
<?php
$data = ['greeting' => $_POST['name']];
file_put_contents('/srv/data/settings.json', json_encode($data)); // 無語法
$parsed = json_decode(file_get_contents('/srv/data/settings.json'), true);
echo htmlspecialchars($parsed['greeting']);
?>`,
    patch: `@@
-  file_put_contents('/srv/data/settings.php', "<?php \\$CFG['greeting'] = '$name';");
+  file_put_contents('/srv/data/settings.json', json_encode(['greeting'=>$name]));
  ?>`,
    refs: ['CWE-96', 'CWE-94', 'CWE-95', 'OWASP'],
    tags: ['static-code-injection', 'eval', 'code-injection', 'serialization'],
  },
  {
    id: 'CWE-102',
    name: 'Struts: Duplicate Validation Forms',
    lang: 'java',
    status: 'Complete',
    what: `Struts 重複的驗證表單。產品使用多個「名稱相同」的驗證表單(validation form)。成因是設定檔裡以
    同一個 name 定義了多組 form 驗證,或原形與覆蓋表單重名。後果是 Struts Validator 會驗證到程式員
    並未預期的表單:無意中把驗證規定套到(或不套到)不該套的那份表單、驗證規則被重複套用或忽略,造成
    部分輸入沒有被正確接受/拒絕,間接引入不足的輸入驗證。修法是讓每個名稱只存在一份驗證表單定義,以
    XWork/Struts 的驗證規則集中且唯一管理,並在重構後用竹 mock 測 Assemble 驗證確實被套到正確 form。`,
    problem: `// 壞的寫法:兩個同名 form 的驗證,讓 Validator 套到錯的那份
// validator-rules / validation.xml
// <form name="loginForm">...</form>
// <form name="loginForm">  <- 重複同名
//   <field property="username"><arg0 key="Login.user"/></field>
// </form>`,
    fixed: `// 好的寫法:每個表單名稱唯一,驗證規則清楚對應到單一 form
// <form name="loginForm">
//   <field property="username" depends="required,mask">...</field>
//   <field property="password" depends="required">...</field>
// </form>`,
    patch: `@@
- // <form name="loginForm">...</form>
- // <form name="loginForm">... 重複</form>
+ // <form name="loginForm"> 單一、唯一</form>`,
    refs: ['CWE-102', 'CWE-20', 'OWASP'],
    tags: ['struts', 'duplicate-form', 'validation', 'input-validation'],
  },
  {
    id: 'CWE-103',
    name: 'Struts: Incomplete validate() Method Definition',
    lang: 'java',
    status: 'Complete',
    what: `Struts 不完整的 validate() 方法定義。產品的 validator form 不是「沒有定義 validate() 方法」,
    就是「有定義 validate() 卻沒有呼叫 super.validate()」。成因是程式員提供了自訂 validate() 打算做額外
    檢查,卻遺漏呼叫父類的 validate()(ValidatorForm/ValidatorActionForm),因而原本由 Validator 框架載入的
    驗證規則完全沒被執行。後果是本該被整體框架驗證的欄位一路跳過驗證,未知/不想要的輸入可進入 Action,
    形成不足的輸入驗證。修法是自訂 validate() 的第一行就呼叫 super.validate()(或選對父類的方法簽名與
    return 型別),確保框架驗證與自訂檢查同時生效;若無自訂需求就不要覆蓋 validate()。`,
    problem: `// 壞的寫法:覆寫 validate() 卻未呼叫 super.validate() => 框架驗證失效
public class LoginForm extends ValidatorForm {
    public ActionErrors validate(ActionMapping mapping, HttpServletRequest request) {
        ActionErrors errors = new ActionErrors();
        if (username = null || username.length() == 0) errors.add("user", new ActionMessage("err"));
        return errors;   // 少了 super.validate(),其餘欄位的驗證規則全沒跑
    }
}`,
    fixed: `// 好的寫法:先呼叫 super.validate(),框架規則才會與自訂檢查並行
public class LoginForm extends ValidatorForm {
    public ActionErrors validate(ActionMapping mapping, HttpServletRequest request) {
        ActionErrors errors = super.validate(mapping, request);  // 先跑框架驗證
        if (username = null || username.length() == 0) errors.add("user", new ActionMessage("err"));
        return errors;
    }
}`,
    patch: `@@
  public ActionErrors validate(ActionMapping m, HttpServletRequest r) {
-    ActionErrors errors = new ActionErrors();
+    ActionErrors errors = super.validate(m, r);   // 補上父類驗證
      if (username == null || username.length() == 0) errors.add("user", new ActionMessage("err"));
      return errors;
  }`,
    refs: ['CWE-103', 'CWE-20', 'OWASP'],
    tags: ['struts', 'validate', 'super.validate', 'input-validation'],
  },
  {
    id: 'CWE-104',
    name: 'Struts: Form Bean Does Not Extend Validation Class',
    lang: 'java',
    status: 'Complete',
    what: `Struts 表單 bean 沒有繼承驗證類別。產品中,表單 bean 若沒有繼承 Validator 框架的
    ActionForm 子類(例如 ValidatorForm / ValidatorActionForm),這個 form 就不會被 Validator 跑驗證規則,
    暴露在「輸入驗證不足」相關的其他弱點之下。成因是誤建了「純 ActionForm」的自訂 bean、或在
    struts-config 並未把表單 bean 掛進 validator 之上,系統因此沒有哪套驗證規則被載入。修法是讓表單 bean
    繼承 ValidatorForm(或對應 Validator 的子類),並確實對映 form-bean 到 validation.xml 的 name,
    確保框架會以該表單的規則做驗證。`,
    problem: `// 壞的寫法:bean 只 extends ActionForm => 不跑 Validator 規則
public class LoginForm extends ActionForm {
    private String username;
    private String password;
    // setters/getters
}`,
    fixed: `// 好的寫法:繼承 Validator 相關子類使規則載入
public class LoginForm extends ValidatorForm {
    private String username;
    private String password;
    // setters/getters;由 validation.xml 的 loginForm 規則驗證
}`,
    patch: `@@
- public class LoginForm extends ActionForm {
+ public class LoginForm extends ValidatorForm {
    private String username;`,
    refs: ['CWE-104', 'CWE-20', 'OWASP'],
    tags: ['struts', 'form-bean', 'validator-form', 'ActionForm'],
  },
  {
    id: 'CWE-105',
    name: 'Struts: Form Field Without Validator',
    lang: 'java',
    status: 'Complete',
    what: `Struts 表單欄位沒有對應的驗證器。產品有一個表單欄位,但沒有由對應的驗證表單/規則進行驗證。
    成因是設定檔的 field 沒有掛 depends="required" 等規則、或欄位根本進不了把規則載入的那張表單,於是某個
    欄位「完全裸拷」通過。後果是該欄位的輸入可以不滿足格式/必填/型別限制就進入 Action,形成不足的輸入
    驗證;再與下游組合可變成注入、路徑管理不當等。修法是確認 validation.xml 對每個會從請求收值的欄位都有
    對應的 <field> 規則(required、型別、範圍、正規表示式),並以工具掃描「表單 bean 屬性 ↔ validator
    field」的覆蓋覆蓋,不讓任何欄位留白。`,
    problem: `// 壞的寫法:username 有規則,但 password 欄位完全沒有對應的 <field>
// <form name="loginForm">
//   <field property="username" depends="required">...</field>
// </form>   password 無規則 => 通過不檢`,
    fixed: `// 好的寫法:該表單的每個欄位都有對應驗證
// <form name="loginForm">
//   <field property="username" depends="required">...</field>
//   <field property="password" depends="required,minlength">
//       <var><var-name>minlength</var-name><var-value>6</var-value></var></field>
// </form>`,
    patch: `@@
  //  <field property="username" depends="required">...</field>
  //</form>
+ //  <field property="password" depends="required,minlength">
+ //      <var><var-name>minlength</var-name><var-value>6</var-value></var></field>
+ //</form>`,
    refs: ['CWE-105', 'CWE-20', 'OWASP'],
    tags: ['struts', 'form-field', 'validator', 'unvalidated-field'],
  },
  {
    id: 'CWE-106',
    name: 'Struts: Plug-in Framework not in Use',
    lang: 'java',
    status: 'Complete',
    what: `Struts 未使用外掛式驗證框架。當應用程式不使用像 Struts Validator 這類輸入驗證框架時,
    更有可能引入「輸入驗證不足」相關的弱點。成因是選擇手寫、零散的檢查,而非集中、宣告式的框架驗證;
    這種做法容易漏掉多個欄位的 ground-common 規則,也沒有統一的框架來保證「每一欄都驗」。後果是驗證不
    完整、不可維持,安全性依賴恰好記得檢查的每個點,形成不足的輸入驗證。修法是採用 Struts Validator
    (declarative validation) 並以驗證框架的統一規則處理所有 Action 的表單輸入;這在 CWE-106 的脈絡下,
    是「較不劣」的輸入驗證策略。`,
    problem: `// 壞的寫法:每個 Action 自己互散地手寫 if 檢查,沒有框架
public class LoginAction extends Action {
    public ActionForward execute(...){
        // 只記得檢查了 username,password 忘了 => 依賴程式員留心
        if (req.getParameter("username").isEmpty()) return mapping.findForward("error");
        return mapping.findForward("success");
    }
}`,
    fixed: `// 好的寫法:啟用 Validator plugin,由框架統一載入驗證規則
// struts-config.xml:
//   <plug-in className="org.apache.struts.validator.ValidatorPlugIn">
//     <set-property property="pathnames" value="/WEB-INF/validator-rules.xml,/WEB-INF/validation.xml"/>
//   </plug-in>
// 各 ActionForm 繼承 ValidatorForm,規則集中宣告於 validation.xml`,
    patch: `@@
- // execute 內手寫片段
+ // struts-config.xml 加上 ValidatorPlugIn 與 validation.xml`,
    refs: ['CWE-106', 'CWE-20', 'OWASP'],
    tags: ['struts', 'validator-plugin', 'validation-framework', 'input-validation'],
  },
  {
    id: 'CWE-107',
    name: 'Struts: Unused Validation Form',
    lang: 'java',
    status: 'Complete',
    what: `Struts 未被使用到的驗證表單。存在「沒有被任何地方使用」的驗證表單,即 validation.xml(或表單
    設定)裡定義了某個 <form>,系統卻沒有參考它。成因是把規則留在歷史/死的設定,欄位改了、驗證規則卻
    停在舊狀態。後果是「未使用的驗證表單」表示驗證邏輯沒有跟上最新的欄位與程式碼,程式員容易誤以為某個
    可用表單在保護、其實那個 form 不被載入 => 驗證不足,或讓人不確定哪份規則是有效的。修法是在交付前刪除
    不再使用的驗證表單/規則,並以工具檢查「使用的表單 ↔ 宣告的表單」一致,對 active 的欄位只保留 active
    的規則。`,
    problem: `// 壞的寫法:宣告了從未套用的 loginForm_old
// <form name="loginForm_old">
//   <field property="username" depends="required"/>... -> 沒人綁定它
// </form>
// 真正在用的 form 是 loginForm,但規則殘留在舊表單`,
    fixed: `// 好的寫法:只保留被綁定使用的表單
// <form name="loginForm">
//   <field property="username" depends="required"/>...
// </form>`,
    patch: `@@
- // <form name="loginForm_old">...=> 未使用,移除</form>
+ // 僅保留 (name=loginForm) 且確有被使用`,
    refs: ['CWE-107', 'CWE-20', 'OWASP'],
    tags: ['struts', 'unused-form', 'validation', 'dead-config'],
  },
  {
    id: 'CWE-108',
    name: 'Struts: Unvalidated Action Form',
    lang: 'java',
    status: 'Complete',
    what: `Struts 未驗證的 Action Form。每一個 ActionForm 都必須有對應的驗證表單;這裡是 Action 使用了
    某個 form bean,卻沒有相對應的 validation form 規則。成因是宣告了 form-bean、跑了一些 validator 規則只在
    某些 Action、或新加的欄位沒補規則。後果是 form 中部分(或全部)欄位未受驗證,輸入可原樣流入業務邏輯,
    構成不足的輸入驗證,也會放大 XSS、SQL 注入、命令注入等下游弱點。修法是對「每一個被表單載入的欄位」
    都提供對應的 validation.xml 規則,並讓受保護的 Action 走到 validator 驗證(lookup, 不要只靠手寫部分
    檢查)。`,
    problem: `// 壞的寫法:Action 使用某 form,但沒有對應的 validation.xml 規則
public class LoginAction extends Action {
    public ActionForward execute(...){
        LoginForm f = (LoginForm) form;  // 已塞進 bean
        bean.save(f);                    // 沒跑任何 validator
        return mapping.findForward("success");
    }
}`,
    fixed: `// 好的寫法:該 ActionForm 有對應驗證並先通過 validator
// validation.xml:
// <form name="loginForm">
//   <field property="username" depends="required"/>...
// </form>
// 且 <action path="/login" name="loginForm" validate="true">`,
    patch: `@@
- // <action path="/login" name="loginForm" validate="false">
+ // <action path="/login" name="loginForm" validate="true">
+ // 並於 validation.xml 提供 loginForm 對應規則`,
    refs: ['CWE-108', 'CWE-20', 'OWASP'],
    tags: ['struts', 'actionform', 'unvalidated', 'validation'],
  },
  {
    id: 'CWE-109',
    name: 'Struts: Validator Turned Off',
    lang: 'java',
    status: 'Complete',
    what: `Struts 驗證被關閉。透過 Struts bean 的自動過濾(automatic filtering / bean-form 的
    validate)被關掉了,連同 Struts Validator 與自訂驗證邏輯都會停用,把應用暴露在「不足的輸入驗證」
    相關的其它弱點。成因是誤設 validate="false"、把整個 config 的 validation 開關關掉、或把 bean 改成不
    繼承 ValidatorForm 的類型。後果是全部(或該 action 的)輸入不再驗證,任何欄位都能以任意值進 Action,
    放大注入與檢查繞過。修法是把 validate="true" 並正確繼承 ValidatorForm/呼叫 super.validate(),不要整組
    關閉;至少要做到「每個收輸入的 request 都走同一套驗證」。`,
    problem: `// 壞的寫法:把 validate 關掉 => 連 Validator 也不跑
// struts-config.xml:
// <action path="/login" name="loginForm" validate="false">
//   <forward name="success" path="/welcome.jsp"/>
// </action>
// => Validator 完全默認關閉,自訂定義也失效`,
    fixed: `// 好的寫法:開回 validate="true" 讓框架驗證生效
// <action path="/login" name="loginForm" validate="true">
//   <forward name="success" path="/welcome.jsp"/>
// </action>`,
    patch: `@@
- // <action path="/login" name="loginForm" validate="false">
+ // <action path="/login" name="loginForm" validate="true">`,
    refs: ['CWE-109', 'CWE-20', 'OWASP'],
    tags: ['struts', 'validate-always', 'validator-off', 'input-validation'],
  },
  {
    id: 'CWE-110',
    name: 'Struts: Validator Without Form Field',
    lang: 'java',
    status: 'Complete',
    what: `Struts 驗證器沒有對應的表單欄位。存在某些「驗證欄位」實際上並不出現在與其關聯的表單中,
    表示該處驗證邏輯已過時(out of date)。成因是欄位被從 form bean/JSP 移除、改名,但 validation.xml 的
    <field> 與 form 屬性沒有同步更新。後果是驗證欄位明明在保護一個「不存在的欄位」,真實存在的欄位反而
    不受保護;或驗證錯誤報告指到不存在的欄位,讓使用者/程式員誤判。修法是定期用工具比對「validator
    <field property> ↔ form bean 的屬性 ↔ JSP 的欄位名」並同步,移除過時的 <field>,對 still 存在
    的欄位補回規則。`,
    problem: `// 壞的寫法:validation.xml 裡 field 指向已移除的欄位
// form bean 已移除 "confirmPassword" 屬性,但規則還在:
// <form name="loginForm">
//   <field property="confirmPassword" depends="required"/> // 欄位不存在 => 沒保護任何東西
// </form>`,
    fixed: `// 好的寫法:欄位存在且規則對上對應欄位
// <form name="loginForm">
//   <field property="password" depends="required,minlength">...</field>
// </form>`,
    patch: `@@
- //  <field property="confirmPassword" depends="required"/>
+ //  <field property="password" depends="required,minlength">...</field>`,
    refs: ['CWE-110', 'CWE-20', 'OWASP'],
    tags: ['struts', 'field-mismatch', 'stale-validation', 'validation'],
  },
  {
    id: 'CWE-111',
    name: 'Direct Use of Unsafe JNI',
    lang: 'java',
    status: 'Complete',
    what: `直接使用不安全的 JNI(Java Native Interface)。Java 應用程式以 JNI 呼叫以其他語言撰寫的程式碼
    (C/C++)時,會把應用暴露在該「其他語言程式碼」本身的弱點之下,即使那些弱點在 Java 本體不會發生。
    成因是把不受信任的輸入直接跨過 JNI 邊界送進 native 碼,而 native 碼缺少 Java 層的陣列邊界與記憶體
    安全性(例如會用不正確的長度、字串轉換或溢位)。後果是記憶體破壞、緩衝區溢位、double free 等,可被
    觸發成任意程式碼執行;雖然 Java 端「安全」,JNI 端卻未必。修法是最小化並隔離 JNI 的使用:讓 native
    碼只處理已知型別、先驗證長度與邊界,不把使用者直接控制的資料當原生指標;以 JNI 介面提供的
    GetArrayLength 等校驗、不擅自信任 Java 傳入的整數;若能,用 JNA/別的安全橋接或完全不用 native。`,
    problem: `// 壞的寫法:直接依 Java 傳來的長度索引原生陣列,未驗證 => 越界
JNIEXPORT void JNICALL Java_demo_NativeLib_fill(JNIEnv *env, jobject obj,
                                                 jbyteArray arr, jint len) {
    jbyte *buf = (*env)->GetByteArrayElements(env, arr, NULL);
    for (int i = 0; i < len; i++)  // len 是 Java 端傳入(untrusted)
        buf[i] ^= 0x5A;            // len 過大 => 越界寫,記憶體破壞
    (*env)->ReleaseByteArrayElements(env, arr, buf, 0);
}`,
    fixed: `// 好的寫法:以 JNI 得到的實際長度來限制
JNIEXPORT void JNICALL Java_demo_NativeLib_fill(JNIEnv *env, jobject obj,
                                                jbyteArray arr, jint len) {
    jsize alen = (*env)->GetArrayLength(env, arr); // 內建長度才是真
    if (len < 0 || len > alen) return;             // 先驗證傳入 len
    jbyte *buf = (*env)->GetByteArrayElements(env, arr, NULL);
    for (jsize i = 0; i < len; i++) buf[i] ^= 0x5A;   // 已驗 len,不越界
    (*env)->ReleaseByteArrayElements(env, arr, buf, 0);
}`,
    patch: `@@
  JNIEXPORT void JNICALL Java_demo_NativeLib_fill(JNIEnv *env, jobject obj,
                                                  jbyteArray arr, jint len) {
+    jsize alen = (*env)->GetArrayLength(env, arr);
+    if (len < 0 || len > alen) return;
      jbyte *buf = (*env)->GetByteArrayElements(env, arr, NULL);
-    for (int i = 0; i < len; i++) buf[i] ^= 0x5A;
+    for (jsize i = 0; i < len; i++) buf[i] ^= 0x5A;
      (*env)->ReleaseByteArrayElements(env, arr, buf, 0);
  }`,
    refs: ['CWE-111', 'CWE-787', 'SEI CERT'],
    tags: ['jni', 'native-code', 'buffer-overflow', 'memory-safety'],
  },
  {
    id: 'CWE-112',
    name: 'Missing XML Validation',
    lang: 'java',
    status: 'Complete',
    what: `缺少 XML 驗證。產品接受來自不可信來源的 XML,但沒有依正確的 schema 去驗證這份 XML。成因是
    直接把收到的 XML parse 並使用,沒有(或不正確地)套用 XSD/DTD 的 schema 檢查。後果是不可信的內容裡
    可能是格式正確但不合 schema 的資料(錯的結構、型別、數量),被當「有效」消費,造成邏輯錯誤、越界欄位、
    或配合其他弱點做成注入/篡改;此外解析器若允許外部實體還有 XXE 風險。修法是永遠以嚴格模式對照 XSD(DTD
    或等價)validateSource,SchemaFactory 設安全的 feature(禁用外部實體),先驗證再解析使用;不驗證就別接
    受外部 XML。`,
    problem: `// 壞的寫法:直接解析不可信 XML,沒有 schema 驗證
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setNamespaceAware(true);
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
Document doc = dbf.newDocumentBuilder().parse(input); // 直接 parse,未對照 XSD
process(doc);`,
    fixed: `// 好的寫法:先對照 XSD 驗證,才解析使用
SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
sf.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
Schema schema = sf.newSchema(new File("config.xsd"));
Validator v = schema.newValidator();
v.validate(new StreamSource(input));       // 驗證通過才往下
Document doc = dbf.newDocumentBuilder().parse(input);
process(doc);`,
    patch: `@@
      DocumentBuilderFactory dbf = ...
-     Document doc = dbf.newDocumentBuilder().parse(input);
-     process(doc);
+     Schema schema = sf.newSchema(new File("config.xsd"));
+     schema.newValidator().validate(new StreamSource(input));
+     Document doc = dbf.newDocumentBuilder().parse(input);
+     process(doc);`,
    refs: ['CWE-112', 'CWE-611', 'OWASP'],
    tags: ['xml-validation', 'xsd', 'schema', 'xxe', 'xml'],
  },
  {
    id: 'CWE-115',
    name: 'Misinterpretation of Input',
    lang: 'c',
    status: 'Complete',
    what: `對輸入的誤解。產品以某種「與輸入產生者(是攻擊者或其他產品)實際傳達的不同」的、且具安全
    重要性的方式來解讀輸入。成因是假定輸入是「表面的字面」而非實質,例如把二進位識別子當字串比較、忽略
    null 字元的截尾語意、把某種編碼的字元當另一種看待、或拿「字串」表示傳遞「數值」。後果是程式對輸入的
    理解與對方不同,驗證就驗不到真實會發生的行為,發生驗證繞過;若再配合之間的回傳,可變成信任邊界錯置。
    修法是對輸入的「每種語意」都明確處理:以位元組字面與長度處理資料、對編碼由「發送端的語意」精確跳轉、
    不靠抽檢的字面判斷、在可能誤解的點以型別化/正規化消除歧義。`,
    problem: `// 壞的寫法:把二進位/含空位元的輸入當 C 字串處理,首個 null 後的中段被忽略
char *parse(const unsigned char *raw, size_t n) {
    char buf[64];
    size_t used = strnlen((const char*)raw, n); // 遇到 null 就停,後半忽略
    memcpy(buf, raw, used);                      // "allow\\0EVIL指令" 只看前半 => 誤解
    return enforce(buf);
}`,
    fixed: `// 好的寫法:以長度明確處理,不因 null 截斷而漏掉語意
int parse(const unsigned char *raw, size_t n) {
    // 明確抓出所有控制字元/null,不當「結尾」
    for (size_t i = 0; i < n; i++) {
        if (raw[i] == '\\0' || raw[i] < 0x20) return -1;   // 把 null 當字元判
    }
    return enforce(raw, n);   // 帶長度判斷,不再用 strnlen 截斷
}`,
    patch: `@@
  char *parse(const unsigned char *raw, size_t n) {
-    size_t used = strnlen((const char*)raw, n);
-    memcpy(buf, raw, used);
-    return enforce(buf);
+    for (size_t i = 0; i < n; i++)
+        if (raw[i] == '\\0' || raw[i] < 0x20) return -1;
+    return enforce(raw, n);
  }`,
    refs: ['CWE-115', 'CWE-170', 'SEI CERT'],
    tags: ['input-misinterpretation', 'null-byte', 'encoding', 'truncation'],
  },
  {
    id: 'CWE-127',
    name: 'Buffer Under-read',
    lang: 'c',
    status: 'Complete',
    what: `緩衝區「下溢讀」(Buffer Under-read,Back underread)。產品使用索引或指標等緩衝區存取機制去
    讀取資料,但讀到的位置指向「目標緩衝區之前」的記憶體。成因是程式員誤以「另一塊資料之前的鄰記憶體」為
    有效、或以負索引/-1 的位置、或計較「長度-1」後把下界算錯。後果是讀到緩衝範圍外的記憶體:合法的前一段
    資料(雜湊、密鑰、相鄰物件)被洩漏,或讀到未初始化記憶體造成未定義行為、當機;攻擊者可藉此探查堆/堆疊
    佈局。修法是存取前嚴謹檢驗上下界與空緩衝區長度;索引與長度都使用無號型別並於計算時避免下溢(例如
    p - N 應在 p >= base+N 才進行),並對外部輸入進來的長度做上限與下限檢查。`,
    problem: `// 壞的寫法:長度-1 後把下界計算成負,造成緩衝區前讀
char *style_last(const char *text, size_t len) {
    if (len < 2) return (char*)text - len;  // len=1 => text-1,讀到前面
    char *out = calloc(len, 1);
    memcpy(out, text + len - 1, 1);        // 正常點,但上方仍留可達 text- 的旁路
    return (char*)text - 1;                 // 別例:直接把負位移當回傳
}`,
    fixed: `// 好的寫法:每次都先確認「位移不會掉出 base 之前」
char *lastn(const char *text, size_t len, size_t n) {
    if (n == 0 || len < n) return NULL;       // 下界含空緩衝全擋
    return (char*)(text + (len - n));         // text+(len-n) >= text
}`,
    patch: `@@
  char *style_last(const char *text, size_t len) {
-    if (len < 2) return (char*)text - len;
-    ... memcpy(out, text + len - 1, 1);
-    return (char*)text - 1;
+    if (n == 0 || len < n) return NULL;
+    return (char*)(text + (len - n));   // 恆 >= base, 無 under-read
  }`,
    refs: ['CWE-127', 'CWE-786', 'CWE-125'],
    tags: ['buffer-underread', 'out-of-bounds', 'underflow', 'memory-read'],
  },
  {
    id: 'CWE-132',
    name: 'DEPRECATED: Miscalculated Null Termination',
    lang: 'c',
    status: 'Deprecated',
    what: `本條目已廢棄。它原本是「錯誤計算 null 終止」的個別條目,但內容與 CWE-170 重複;所有內容
    已轉移到 CWE-170(與 null termination 相關的錯誤運算)。因此請改用 CWE-170 處理「字串長度/空間算錯、
    null 終止符位置錯誤」之類的問題。`,
    problem: `// (已廢棄)原內容移轉至 CWE-170
char buf[8]; strncpy(buf, longdata, 8); // CWE-170:可能缺 null 終止`,
    fixed: `// 以 CWE-170 角度:保留空間給 null 並確保終止
char buf[9]; buf[8] = '\\0'; strncpy(buf, longdata, 8);`,
    patch: `@@
- char buf[8]; strncpy(buf, longdata, 8);
+ char buf[9]; buf[8] = '\\0'; strncpy(buf, longdata, 8); // 確保 null 終止`,
    refs: ['CWE-132', 'CWE-170'],
    tags: ['deprecated', 'null-termination', 'strncpy'],
  },
  {
    id: 'CWE-135',
    name: 'Incorrect Calculation of Multi-Byte String Length',
    lang: 'c',
    status: 'Complete',
    what: `不正確計算「多位元組字串」的長度。產品沒有正確計算可能包含寬字元或多位元組字元的字串長度。
    成因是「字元數」與「位元組數」被混淆:對 UTF-8、GBK 這種變動長度編碼,strlen/MB char 的計算是「位元組」
    而不是「字元」;寬(wide)字串則指標運算單位不同。後果是把「以位元組為單位的長度」與「緩衝區以字元為單位」
    交配,導致緩衝區長度估小(截斷、溢位)或溢過大(越界讀),並讓含有內嵌 null 或 lead byte 的長度算錯;
    攻擊者可送特定的多字元序列使長度估算失準以繞過檢查。修法對多位元組字串一律用正確的
    mbsrtowcs/wcrtomb、mbstowcs 並依目的編碼;對 UTF-8 用 utf8_next/合法驗證,取「字元數」時用
    專屬函式而非常規 strlen,並以位元組*wchar 寬度精確配置。`,
    problem: `// 壞的寫法:拿 strlen(位元組數) 當「字元數」並依此截半 => 可能切斷一字元
size_t half(const char *u8, size_t nbytes) {
    size_t half_n = nbytes / 2;               // 位元組折半,未必在字元界
    if ((u8[half_n] & 0xC0) == 0x80) half_n--; // (未完整處理 lead/cont)
    char *out = malloc(half_n + 1);
    memcpy(out, u8, half_n); out[half_n] = 0;   // 未處理 lead/continuation 字元界
    return half_n;
}`,
    fixed: `// 好的寫法:用正確轉換函式換算位元組/字元,再配置
size_t half_utf8(const char *u8, size_t nbytes) {
    mbstate_t st = {0};
    wchar_t *wcs = malloc((nbytes + 1) * sizeof(wchar_t));
    size_t nw = mbsrtowcs(wcs, &u8, nbytes + 1, &st);
    if (nw == (size_t)-1) { free(wcs); return 0; }
    size_t c = nw / 2;                       // 字元層折半=> 合法界
    wcs[c] = 0;
    size_t out = wcstombs(NULL, wcs, 0) + 1;
    char *outb = malloc(out);
    wcstombs(outb, wcs, out);
    free(wcs); return out;
}`,
    patch: `@@
  size_t half(const char *u8, size_t nbytes) {
-    size_t half_n = nbytes / 2;
-    ... memcpy(out, u8, half_n);
+    // 以 .cs 轉成 wchar 在字元界折半再轉回(示意)
+    size_t nw = mbsrtowcs(wcs, &u8, nbytes + 1, &st);
+    wcs[nw/2] = 0; ... wcstombs(outb, wcs, out);
  }`,
    refs: ['CWE-135', 'CWE-122', 'SEI CERT'],
    tags: ['multi-byte', 'utf-8', 'length-calculation', 'string-length'],
  },
  {
    id: 'CWE-140',
    name: 'Improper Neutralization of Delimiters',
    lang: 'javascript',
    status: 'Complete',
    what: `不當中和「分隔符」(delimiter)。產物沒有中和、或不當中和「分隔符」。分隔符是把資料切成一列的
    語法字元(換行、逗號、分號、冒號、空白等);在中和的抽象階層高(core CWE)的同時,它是後續專用層級
    (如 record/value/line/section/expression delimiter)的泛化。若輸入內含的分隔符被原樣流入下游的 data
    表示式,下游會把「一份資料」誤拆成多列/多欄,或注入控制的分隔。修法是對輸送到「以某個分隔符當語意
    的介面」的所有輸入,都把欄位內的分隔符以該介面專屬的規序轉義/跳脫,讓單一資料無法自成分隔;對下游採用
    帶長度的協定/序列化,而不要相信分隔符是獨一無二的。`,
    problem: `// 壞的寫法:把使用者可控的內容直接接進 CSV/換行分隔輸出
function buildCsv(rows) {
  return rows.map(r => r.join(','))
            .join('\\n');        // row 內的逗號/換行原樣 => 欄位被拆分
}
// 註:一行含 "a,b\\nc" 會把一欄拆兩欄兩列`,
    fixed: `// 好的寫法:對寫入分隔介面的欄位做轉義(內部引號與分隔符)
function esc(field){
  return '"' + String(field).replace(/,/g, '\\,').replace(/"/g, '""') + '"';
}
function buildCsv(rows){ return rows.map(r => r.map(esc).join(',')).join('\\r\\n'); }`,
    patch: `@@
  function buildCsv(rows) {
-    return rows.map(r => r.join(',')).join('\\n');
+    return rows
+      .map(r => r.map(esc).join(','))   // esc() 把欄位內分隔符與引號轉義
+      .join('\\r\\n');
  }`,
    refs: ['CWE-140', 'CWE-93', 'OWASP'],
    tags: ['delimiter', 'csv-injection', 'neutralization', 'data-parse'],
  },
  {
    id: 'CWE-142',
    name: 'Improper Neutralization of Value Delimiters',
    lang: 'javascript',
    status: 'Complete',
    what: `不當中和「值分隔符」。產物從上游元件接收輸入,但把它送往下游元件時,沒有中和、或不當中和那些
    可能被解釋為「值分隔符(value delimiter)」的特殊元素。值分隔符是把一個「資料值」與另一個值切開的語法
    (例如 K=V 配對裡的逗號/空白/分號)。成因是輸入裡的值分隔符原樣進入下游,下游(例如 HTTP header 多值、
    Cookie、設定檔的 key 配對、query 字串的 & )會因此把單一值拆成多個值或誤建欄位對應。後果是把注入值
    展開成多值，破壞既有值或塞進不被期望的新配對，造成輸出/邏輯錯亂。修法是對所有值分隔的介面，將分隔符在
    值內先轉義(或依其 context 做輸出跳脫),讓單一值的內容不會變成多個值的語法。`,
    problem: `// 壞的寫法:把使用者值直接塞進 cookie 多值語法(以分號/逗號分)
function setCookie(name, value) {
  document.cookie = name + '=' + value;   // value 含 ";" 或"," => 拆出額外 cookie
}`,
    fixed: `// 好的寫法:對 value 做編碼,分隔符不再代表語意
function setCookie(name, value) {
  const enc = encodeURIComponent(value).replace(/,/g, '%2C').replace(/;/g, '%3B');
  document.cookie = name + '=' + enc;   // 分隔符被編碼後不會被當分界
}`,
    patch: `@@
  function setCookie(name, value) {
-    document.cookie = name + '=' + value;
+    const enc = encodeURIComponent(value)
+                 .replace(/,/g, '%2C').replace(/;/g, '%3B');
+    document.cookie = name + '=' + enc;
  }`,
    refs: ['CWE-142', 'CWE-140', 'OWASP'],
    tags: ['value-delimiter', 'cookie', 'header', 'encoding'],
  },
  {
    id: 'CWE-143',
    name: 'Improper Neutralization of Record Delimiters',
    lang: 'javascript',
    status: 'Complete',
    what: `不當中和「紀錄分隔符」。產物從上游接收輸入,送往下游時沒有中和、或不當中和可能被判讀為
    「紀錄分隔符(record delimiter)」的特殊元素。紀錄分隔符把一「列/一筆紀錄」與下一筆分開(例如資料檔裡
    的換行、CSV 的列、一行一筆的清單)。成因是輸入內的紀錄分隔符(通常是換行)原樣進到「一行一筆」的下游；
    下游把單筆「輸入的紀錄」切成多筆。後果是把一份資料擴張成多筆假紀錄、或用注入的換行把額外紀錄塞進日誌/
    設定/白名單,造成邏輯/權限錯置。修法是對「每行一筆」的下游,先消除或轉義欄位內的換行與 CR,以長度或
    狀態明確切分紀錄,不讓使用者內容新增換行。`,
    problem: `// 壞的寫法:把使用者輸入直接寫進每行一筆的 log/allowlist
function appendAllow(user) {
  // user = "admin\\n127.0.0.1" => 直接新增第二筆紀錄
  fs.appendFileSync('/etc/app/allowlist', user + '\\n');
}`,
    fixed: `// 好的寫法:消除輸入內的換行/CR,避免製造額外紀錄
function appendAllow(user) {
  const clean = String(user).replace(/[\\r\\n]/g, ''); // 不容輸入挾帶分列
  if (!clean) return;
  fs.appendFileSync('/etc/app/allowlist', clean + '\\n');
}`,
    patch: `@@
  function appendAllow(user) {
-    fs.appendFileSync('/etc/app/allowlist', user + '\\n');
+    const clean = String(user).replace(/[\\r\\n]/g, '');
+    if (!clean) return;
+    fs.appendFileSync('/etc/app/allowlist', clean + '\\n');
  }`,
    refs: ['CWE-143', 'CWE-140', 'OWASP'],
    tags: ['record-delimiter', 'newline', 'log-injection', 'allowlist'],
  },
  {
    id: 'CWE-144',
    name: 'Improper Neutralization of Line Delimiters',
    lang: 'javascript',
    status: 'Complete',
    what: `不當中和「行分隔符」。產物從上游元件接收輸入,送往下游時沒有中和、或不當中和可能被判讀為
    「行分隔符(line delimiter)」的特殊元素。行分隔符是以換行(與可選的回車)切開一行的語法。成因是輸入中的換行
    (LF/CRLF)原樣流出,下游以「行」為單位解析時,會製造額外的行。後果是攻擊者以注入的換行插入假的行內容:
    偽造登入/設定、塞入設定檔的新行、改寫一行就變ㄧ意義,形成像 CRLF/LF injection 一般的影響。修法是對
    「以行為單位」的下游一律先移除或轉義輸入內的 \r 與 \n,確保一行就是一份值。`,
    problem: `// 壞的寫法:直接把 header/訊息值輸出,含換行就能拆出多行
function addHeader(res, name, value) {
  // value 可為 "ok\\r\\nSet-Cookie: admin=1" => 拆成另一行 header
  res.setHeader(name, value);
}`,
    fixed: `// 好的寫法:輸出 header 前移除換行字元
function addHeader(res, name, value) {
  const clean = String(value).replace(/[\\r\\n]/g, '');
  res.setHeader(name, clean.valueOf());   // 不再能注入新行
}`,
    patch: `@@
  function addHeader(res, name, value) {
-    res.setHeader(name, value);
+    res.setHeader(name, String(value).replace(/[\\r\\n]/g, ''));
  }`,
    refs: ['CWE-144', 'CWE-113', 'CWE-93'],
    tags: ['line-delimiter', 'crlf', 'header-injection', 'newline'],
  },
  {
    id: 'CWE-145',
    name: 'Improper Neutralization of Section Delimiters',
    lang: 'javascript',
    status: 'Complete',
    what: `不當中和「區段分隔符」。產物從上游元件接收輸入,送往下游時沒有中和、或不當中和可能被判讀為
    「區段分隔符(section delimiter)」的特殊元素。區段分隔符是切開 so-called「一大塊內容」與另一塊的語法
    (例如 INI 的 [section]、email 的 MIME boundary、JSON 的物件對、HTML 的註記區)。成因是輸入內的區段
    開關語法原樣流入,下游會據此把資料切進不同區段。後果是把「值」誤升成「區段結構」,或注入一個假的區段
    來覆蓋/覆寫既有設定區,造成設定錯置、白名單被換、或結構注入。修法是對「區段為基礎」的下游,先轉義/移除
    輸入裡的區段開關字元(如 [ ]、boundary 字串、結構標籤),或改用不會被內容擴張結構的序列化格式。`,
    problem: `// 壞的寫法:把使用者值寫進 INI-like 設定,值內的 [ 可開啟新區段
function setKey(cfg, key, value) {
  cfg.push(key + '=' + value);   // value = "x\\n[admin]\\npriv=1" 新增 [admin] 區
}`,
    fixed: `// 好的寫法:值內移除或移除區段開關字元,無法擴張結構
function setKey(cfg, key, value) {
  const v = String(value).replace(/[[\\]\\r\\n]/g, ''); // 不容 [ ] 或換行
  cfg.push(key + '=' + v);
}`,
    patch: `@@
  function setKey(cfg, key, value) {
-    cfg.push(key + '=' + value);
+    const v = String(value).replace(/[[\\]\\r\\n]/g, '');
+    cfg.push(key + '=' + v);   // 無法再注入 [section]
  }`,
    refs: ['CWE-145', 'CWE-140', 'OWASP'],
    tags: ['section-delimiter', 'ini-injection', 'config', 'structure'],
  },
  {
    id: 'CWE-146',
    name: 'Improper Neutralization of Expression/Command Delimiters',
    lang: 'javascript',
    status: 'Complete',
    what: `不當中和「表達式/指令 分隔符」。產物從上游接收輸入,送往下游時沒有中和、或不當中和可能被
    判讀為表達式或指令分隔符的特殊元素。這類分隔符(例如 shell 的 ;、&&、|,或 SQL 的語句間隔)能讓一個
    值變成「多個指令」。成因是把使用者可控的值直接拼進會分號分隔指令的介面(命令列、SQL、設定中的執行列表)。
    後果是攻擊者在「一個值」之後以分隔符接上自己的指令,演變成指令注入(OS command injection、SQL injection)。
    修法是不要以字串拼接組出可執行指令:命令/查詢一律用參數化或陣列引數傳遞,能把「值」與「指令語法」徹底
    分開;若無法,對分隔符(; & | 換行)依 context 轉義與白名單。`,
    problem: `// 壞的寫法:把使用者值拼進 shell 命令,值內的分隔符可啟動第二指令
const { exec } = require('child_process');
function backup(dir) {
  exec('tar -c "backup" ' + dir);   // dir = "/; rm -rf /" => 第二指令執行
}`,
    fixed: `// 好的寫法:用陣列引數,值不再具有指令語法
const { execFile } = require('child_process');
function backup(dir) {
  execFile('/usr/bin/tar', ['-c', '-f', 'backup.tar', dir]); // dir 只是參數
}`,
    patch: `@@
  function backup(dir) {
-    exec('tar -c "backup" ' + dir);
+    execFile('/usr/bin/tar', ['-c', '-f', 'backup.tar', dir]);
  }`,
    refs: ['CWE-146', 'CWE-78', 'CWE-77'],
    tags: ['command-injection', 'os-command', 'delimiter', 'parameterized'],
  },
  {
    id: 'CWE-148',
    name: 'Improper Neutralization of Input Leaders',
    lang: 'javascript',
    status: 'Complete',
    what: `不當「領頭字元/序列(leader)」的處理。產物沒有正確處理「領頭字元或序列缺失、格式錯誤,或
    當只允許一個時出現多個領頭」的情況。Leader 是指標識「這一筆資料是什麼/從哪裡開始」的前綴記號(像是
    註記符號、協定前綴、行首標記)。成因是程式假定「每筆輸入都會有、且只有一個正確的 leader」,碰到 leader
    缺失/重複/畸形時不驗或處理錯誤。後果是沒有 leader 或漏掉 leader 的輸入被當成「有 leader」來解析,
    或重複的 leader 造成 skip 過頭,使後續資料被誤判語意,讓過濾/解析的假定失效(例如把「不是指令的
    一行」當成指令、或漏掉前綴檢查）。修法是對每個 leader 位元組/序列都做「有/無/唯一」的明確驗證與
    處理;在真正可以存在多個時,逐一驗證每個的合法性,並只允許預期的單一 leader。`,
    problem: `// 壞的寫法:假定必有一個 '#' leader,改用 indexOf 找到就往前跳一個
function parseLine(line) {
  if (line.indexOf('#C') === 1) return null;   // 只在 index 1 檢查,其它位置漏
  return line.split('#')[1];                    // "#CC" 多 leader 或無 leader 都被可想做
}`,
    fixed: `// 好的寫法:leader 存在與唯一都明確驗證
function parseLine(line) {
  if (line[0] !== '#') return 'missing leader';
  const rest = line.slice(1);
  if (rest.includes('#')) return 'extra leader'; // 只准一個
  return unescape(rest);
}`,
    patch: `@@
  function parseLine(line) {
-    if (line.indexOf('#C') === 1) return null;
-    return line.split('#')[1];
+    if (line[0] !== '#') return 'missing leader';
+    if (line.slice(1).includes('#')) return 'extra leader';
+    return unescape(line.slice(1));
  }`,
    refs: ['CWE-148', 'CWE-20', 'OWASP'],
    tags: ['leader', 'prefix', 'parsing', 'input-validation'],
  },
  {
    id: 'CWE-149',
    name: 'Improper Neutralization of Quoting Syntax',
    lang: 'javascript',
    status: 'Complete',
    what: `不當處理「引號語法」。注入(或缺失、重複、畸形)的引號可用來危害系統:當資料被解析時,「被
    注入/被砍掉/重複/畸形」的引號可能使程序做出非預期的動作。成因是把使用者輸入直接放進以引號界定字串的
    語法(C 字串、shell 引號、SQL 字串、HTML 屬性、CSV 的引號欄),卻沒有正確轉義/配對引號。後果是
    多一個引號可以提前關閉字串後接語法、少一個引號會讓其餘都變成字串趣味,打破語法界線,促成指令注入、
    屬性注入等。修法是對「以引號為語意」的介面,依其 context 正規轉義引號(如 shell 用 sh 參數 + 引號、
    SQL 用參數化、HTML 屬性用編碼);引號一律由「程式框架」負責配對,不把未處理的引號交給字串拼接。`,
    problem: `// 壞的寫法:直接把使用者輸入放進單引號 shell 片段,引號可提前閉合
const { exec } = require('child_process');
function run(name) {
  exec("echo '" + name + "'");   // name = "x'; rm -rf /; echo '" => 斷語法
}`,
    fixed: `// 好的寫法:以陣列引數 + 由 shell 自行處理(或 shell-quote),不需手排引號
const { execFile } = require('child_process');
function run(name) {
  execFile('/bin/echo', [name]);   // 引號語法由程式庫/參數機制處理,值不會斷語法
}`,
    patch: `@@
  function run(name) {
-    exec("echo '" + name + "'");
+    execFile('/bin/echo', [name]);
  }`,
    refs: ['CWE-149', 'CWE-78', 'CWE-88'],
    tags: ['quotes', 'quoting', 'command-injection', 'shell-quote'],
  },
  {
    id: 'CWE-151',
    name: 'Improper Neutralization of Comment Delimiters',
    lang: 'javascript',
    status: 'Complete',
    what: `不當中和「註記分隔符」。產物從上游元件接收輸入,送往下游時沒有中和、或不當中和可能被判讀為
    「註記分隔符(comment delimiter)」的特殊元素。註記分隔符(如 SQL 的 --、/* */,HTML 的 <!-- -->,
    shell 的 # 與程式語言的 //)界定「不會被執行的一段」。成因是輸入內含註記開頭語法卻原樣流入會解析註記的
    介面;攻擊者可「註記掉」後續重要的語法。後果是可把原本要檢查/執行的程式段變成註解,關閉檢查、或讓
    資料混進註記中以繞過 filter,造成邏輯繞過與注入協助。修法是對「有註記語法」的介面,先把輸入內的註記
    開關字元依 context 移除或轉義(例如 SQL 不讓含 -- 與 /* 的值流入字串之外);最佳是以參數化避免進入
    可被註記的語境。`,
    problem: `// 壞的寫法:把使用者值拼進 SQL 字串,值內的 -- 可把查詢後半註解掉
function get(db, name) {
  return db.query("SELECT * FROM u WHERE name='" + name + "'");
  // name = "x' -- " => 把 WHERE 後段註解,繞過條件
}`,
    fixed: `// 好的寫法:參數化查詢,值不再有註記語法
function get(db, name) {
  return db.query('SELECT * FROM u WHERE name = ?', [name]); // 參數化
}`,
    patch: `@@
  function get(db, name) {
-    return db.query("SELECT * FROM u WHERE name='" + name + "'");
+    return db.query('SELECT * FROM u WHERE name = ?', [name]);
  }`,
    refs: ['CWE-151', 'CWE-89', 'CWE-93'],
    tags: ['comment-delimiter', 'sql', 'injection', 'parameterized'],
  },
];
