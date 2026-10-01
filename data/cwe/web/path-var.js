// CWE chunk — category: Path Traversal Variants & File Name Control (C / Node / Python).
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
		id: 'CWE-23',
		name: 'Relative Path Traversal',
		lang: 'python',
		status: 'Complete',
		what: `相對路徑穿越（Relative Path Traversal）。當程式接受使用者輸入的檔名並把它「直接」加在
	一個基礎目錄後面拼出路徑、卻沒有先把解析（resolve／realpath）後的結果拉回基礎目錄之下檢查，
	攻擊者就能送來一串 ./ 或 ../ 段，例如 ../../../../etc/passwd。因為相對路徑是照字面往上爬，
	每多一層 ../ 就往上退一層目錄，最後 open 到的位置完全脫離原本限制的沙箱、落在攻擊者指定的
	系統檔。與 CWE-22 的不同在於本條專注在「相對 ./../ 攀升」這個單一向量於 join 後未正規化的
	情境。修法是把 final 路徑用 realpath() 正規化後，用 commonpath() 嚴格要求它仍在根目錄之下。`,
		problem: `# 不安全寫法：basename 作為基礎目錄,直接把輸入 join 上去,未正規化也無 contain 檢查
import os

BASE = "/srv/uploads"

def read_note(name):
    # name = "../../../../etc/passwd => join 之後照字面一路往上爬,完全離開 BASE
    target = os.path.join(BASE, name)
    with open(target) as f:      # 讀到的是 /etc/passwd 而非 uploads 內檔案
        return f.read()`,
		fixed: `# 安全寫法：join 之後 realpath 正規化,再用 commonpath 強制落在 BASE(及其子目錄)內
import os

BASE = os.path.realpath("/srv/uploads")

def read_note(name):
    target = os.path.realpath(os.path.join(BASE, name))
    # realpath 已把 ../../ 攤平;若攤平後不在 BASE 底下 => 拒絕,不讓 any../.. 爬出沙箱
    if os.path.commonpath([target, BASE]) != BASE:
        raise PermissionError("path escapes restricted dir")
    with open(target) as f:
        return f.read()`,
		patch: `@@
   def read_note(name):
-    target = os.path.join(BASE, name)
+    target = os.path.realpath(os.path.join(BASE, name))
+    if os.path.commonpath([target, BASE]) != BASE:
+        raise PermissionError("path escapes restricted dir")
    with open(target) as f:
        return f.read()`,
		refs: ['CWE-23', 'SEI CERT'],
		tags: ['relative-path', 'traversal', 'realpath', 'commonpath', 'dotdot'],
	},
	{
		id: 'CWE-25',
		name: "Path Traversal: '/../filedir'",
		lang: 'node',
		status: 'Complete',
		what: `只過濾一種寫法而漏掉其他分離符的相對路徑穿越（Forward Slash bypass）。很多程式對
	「../../」有戒心、會把輸入中的 ../ 字串直接刪掉或拒絕,以為這樣就擋住穿越。但作業系統同時
	接受正斜線與反斜線、也接受以 / 、Drive（）開頭的絕對路徑;如果只用單一規則、只比賽者已知的
	那一種編碼,攻擊者改用別的分離符就繞過了——例如只擋 ../ 但送 /etc/passwd（絕對路徑直接
	開放）,或送 ..\\\\etc\\\\passwd（用 Windows 反斜線版本）,肉眼同樣爬到根目錄。修法不是做
	「黑名單窮舉」,而是統一剖析為正規化絕對路徑後,再用 root 包含性檢查把 final 路徑限制在受控
	根目錄之內才允許開啟。`,
		problem: `// 不安全寫法：只把字面上的 ../ 替換掉,搜尋不到時就去 fopen,可被 / 絕對路徑或 \\\\ 繞過
const path = require('path');
const fs = require('fs');

function openProfile(name) {
  // 只對正斜線../做字串層replace,但:
  //   輸入 "/etc/passwd"   => 不含 ../,../ 規則不會擋,變成絕對路徑直接開放
  //   輸入 "..\\etc\\passwd" => 反斜線沒被清洗,Windows 上等同 ..
  const cleaned = name.replace(/\.\.\//g, '');
  const full = path.join(__dirname, 'users', cleaned);
  return fs.readFileSync(full, 'utf8');
}`,
		fixed: `// 安全寫法:不同的分離符都當同名危害,統一正規化後做包含性檢查而非逐種吐黑名單
const path = require('path');
const fs = require('fs');

function openProfile(name) {
  const base = path.resolve(__dirname, 'users');
  const full = path.resolve(base, name);            // 承認 / 與 \\ 都是分離符
  // 正規化後若在任何一種分離符編碼下爬出 base => 一律拒絕,不追求列出每一種繞法
  if (full !== base && !full.startsWith(base + path.sep)) {
    throw new Error('invalid profile name');
  }
  return fs.readFileSync(full, 'utf8');
}`,
		patch: `@@
   function openProfile(name) {
-    const cleaned = name.replace(/\\.\\.\\//g, '');
-    const full = path.join(__dirname, 'users', cleaned);
+    const base = path.resolve(__dirname, 'users');
+    const full = path.resolve(base, name);
+    if (full !== base && !full.startsWith(base + path.sep)) {
+      throw new Error('invalid profile name');
+    }
     return fs.readFileSync(full, 'utf8');
   }`,
		refs: ['CWE-25', 'SEI CERT'],
		tags: ['separator', 'bypass', 'escape', 'canonicalization', 'path-traversal'],
	},
	{
		id: 'CWE-29',
		name: "Path Traversal: '\\..\\filename'",
		lang: 'python',
		status: 'Complete',
		what: `「反斜線編碼」的相對路徑穿越（Windows 風格的 \\..\\）。CWE-29 是 CWE-23 在
	Windows 分離符下的特例：作業系統同時把 / 與 \\ 都當成路徑分離符，但很多防禦只針對「正斜線版
	的 ../」做替換或黑名單，於是攻擊者改用反斜線寫成 ..\\..\\..\\etc\\passwd 就能原封不動穿越，
	因為清洗規則根本沒遇到自己認識的字串。這類繞過的字眼在於「只擋一種編碼」：只要分離符、編碼、
	或大小寫任一種沒被列進黑名單，爬出根目錄的行為照樣成立。修法不是把每一種 \\ 與 / 的排列窮舉
	掉，而是先把輸入與基底目錄 join 後用 realpath 正規化，再用 commonpath 嚴格確認最終路徑仍在受控
	根目錄之下，任何一種分離符編碼都爬不出去。`,
		problem: `# 不安全寫法：只對正斜線的 ../ 做字串清洗,Windows 反斜線版 ..\\ 完全沒被擋
import os

def load_local(win_name):
    # 只處理字面上的 '../';送 "..\\\\..\\\\..\\\\etc\\\\passwd" 因不含'../'而通過
    cleaned = win_name.replace('../', '')
    target = os.path.join('C:\\\\srv\\\\public', cleaned)  # 反斜線照樣當分離符一路往上爬
    with open(target, 'rb') as f:      # 開到的是 C:\\\\etc\\\\passwd,不在 public 內
        return f.read()`,
		fixed: `# 安全寫法：不挑編碼區別 / 與 \\,join 後正規化再做包含性檢查
import os

BASE = os.path.realpath('C:\\\\srv\\\\public')

def load_local(win_name):
    target = os.path.realpath(os.path.join(BASE, win_name))  # 攤平 ..\\、../、./ 所有編碼
    if os.path.commonpath([target, BASE]) != BASE:            # 反正規化後爬出 BASE => 拒絕
        raise PermissionError("path escapes restricted dir")
    with open(target, 'rb') as f:
        return f.read()`,
		patch: `@@
   def load_local(win_name):
-    cleaned = win_name.replace('../', '')
-    target = os.path.join('C:\\\\srv\\\\public', cleaned)
+    target = os.path.realpath(os.path.join(BASE, win_name))
+    if os.path.commonpath([target, BASE]) != BASE:
+        raise PermissionError("path escapes restricted dir")
     with open(target, 'rb') as f:
         return f.read()`,
		refs: ['CWE-29', 'CWE-23', 'SEI CERT'],
		tags: ['backslash', 'windows', 'path-traversal', 'separator-bypass', 'realpath'],
	},
	{
		id: 'CWE-36',
		name: 'Absolute Path Traversal',
		lang: 'c',
		status: 'Complete',
		what: `絕對路徑穿越（Absolute Path Traversal）。程式預期使用者只給一個檔名、由自己把它與
	固定目錄拼接來開啟,結果它直接接受了「完全獨立、以 / 開頭的絕對路徑」並原封不動交給
	fopen()／open()。這樣防護目錄的假設整個作廢:使用者傳 /etc/passwd 時,程式不是去開
	<sandbox>/etc/passwd,而是直接用那條以斜線開頭的路徑去開系統檔,根本沒有 base 這回事。
	與相對穿越（23/25）差在 23 需要靠 ../ 步進、36 則完全不管你 base,給什麼絕對路徑就開什麼。
	修法是把「基底目錄」與「檔名」分開對待,只允許來自受控目錄的實體檔,或直接把輸入限制成純
	檔名形不再接受斜線。`,
		problem: `// 不安全寫法：把使用者傳入的路徑直接當成最終路徑傳給 fopen,絕對路徑可直指任何系統檔
#include <stdio.h>

FILE *open_report(const char *userpath) {
    // userpath 可以是 "/etc/passwd" 這類絕對路徑;這裡沒做任何「限制在指定目錄」的處理
    return fopen(userpath, "r");   // 直接開放,沙箱假設失效
}`,
		fixed: `// 安全寫法：只接受純檔名,並永遠接在受控基底目錄之後,不接受以 / 開頭的任何內容
#include <stdio.h>
#include <string.h>

FILE *open_report(const char *name) {
    // 絕對路徑(以 / 開頭)直接被拒;其餘內容確保不含 / 再才拼進受控目錄
    if (strchr(name, '/') != NULL) return NULL;
    static const char base[] = "/srv/reports/";
    char full[512];
    snprintf(full, sizeof full, "%s%s", base, name);
    return fopen(full, "r");
}`,
		patch: `@@
   FILE *open_report(const char *userpath) {
-    return fopen(userpath, "r");
+    if (strchr(userpath, '/') != NULL) return NULL;
+    char full[512];
+    snprintf(full, sizeof full, "/srv/reports/%s", userpath);
+    return fopen(full, "r");
   }`,
		refs: ['CWE-36', 'SEI CERT'],
		tags: ['absolute-path', 'traversal', 'fopen', 'restricted-dir', 'directory'],
	},
	{
		id: 'CWE-73',
		name: 'External Control of File Name or Path for File Operation',
		lang: 'node',
		status: 'Complete',
		what: `外部控制的檔案名稱或路徑被用於檔案操作（External Control of File Name or Path）。
	與單純的../穿越不同,這個弱點不限於 dot-dot:,只要檔案操作的「目標名稱或路徑」由使用者輸入
	直接決定（讀、寫、刪、搬移),即使輸入是一段正常、沒有../的檔名,也可能指向任何目錄中的
	任意檔——例如刪除刪到別人的設定檔、覆寫寫到系統檔,或讓 targetFile 藉由絕對路徑指到沙箱
	以外。正確修法是把「使用者輸入」與「所在根目錄」徹底分開:先用 basename 只保留真正檔名、
	把結果固定在一個 confined root 下,再用 realpath 解析後以包含性檢查確認最終真實路徑確實落在
	這棵根目錄內,才算真正把檔案操作鎖在受控範圍。`,
		problem: `// 不安全寫法：檔案操作(rename/remove)直接拿使用者提供的 path 下手,輸入可指到任何地方
const fs = require('fs');
const path = require('path');

function removeFile(req) {
  // req.body.path 可為 "/etc/app.yaml" 或 "../../../srv/tmp/app.yaml":不經任何根目錄限制
  fs.unlinkSync(req.body.path);       // 想刪的其實不是應用程式管的檔,但被外部輸入決定
}`,
		fixed: `// 安全寫法：把輸入限定為純檔名、固定在 confined root 內,並用 realpath 做包含性檢查後才刪
const fs = require('fs');
const path = require('path');

const ROOT = fs.realpathSync('/srv/app/data');

function removeFile(req) {
  const name = path.basename(req.body.path);      // 只取末尾真正的檔名,去掉 ..與分離符
  const candidate = path.join(ROOT, name);
  const resolved = fs.realpathSync(candidate);    // 解析 symlink,取得「真實」路徑
  const rel = path.relative(ROOT, resolved);       // 相對 ROOT 的位移
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error('outside managed root');
  }
  fs.unlinkSync(resolved);
}`,
		patch: `@@
   function removeFile(req) {
-    fs.unlinkSync(req.body.path);
+    const name = path.basename(req.body.path);
+    const candidate = path.join(ROOT, name);
+    const resolved = fs.realpathSync(candidate);
+    const rel = path.relative(ROOT, resolved);
+    if (rel.startsWith('..') || path.isAbsolute(rel)) {
+      throw new Error('outside managed root');
+    }
+    fs.unlinkSync(resolved);
   }`,
		refs: ['CWE-73', 'SEI CERT'],
		tags: ['file-operation', 'filename', 'realpath', 'containment', 'basename'],
	},
];
