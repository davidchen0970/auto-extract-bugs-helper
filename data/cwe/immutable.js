// CWE chunk — Assumed-Immutable Data / Supply-chain Integrity.
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
		id: 'CWE-471',
		name: 'Modification of Assumed-Immutable Data (MAID)',
		lang: 'java',
		status: 'Complete',
		what: `假設不可變資料被竄改（Assumed-Immutable Data，MAID）。程式在信任邊界內部假定某些「狀態資料」永遠不會變，
		例如「前端渲染出來的結帳金額」「購物車總價」「低層邏輯的流程旗標」，於是直接把它當成決策依據或寫回伺服器端，
		卻把這些資料放在使用者可控的位置（隱藏表單欄位、cookie、可改寫的快取）。攻擊者改掉這個「本該不可變」的值，
		伺服器由於假定它不變而完全照單全收，做出錯誤的金額或授權決策。建議做法是任何會影響安全或價值的資料都只存在
		伺服器端並由伺服器端重新計算、綁定驗證碼（HMAC），永不直接信任從客戶端飄過來的「現成狀態值」。`,
		problem: `// 不安全寫法：把「目前結帳總金額」放進隱藏欄位，伺服器假設它從不變動
<form action="/checkout" method="post">
  <input type="hidden" name="amount" value="#{cart.amount}" /> <!-- 使用者可控 -->
  <input type="hidden" name="shipping" value="#{shippingCost}" />
  <button type="submit">結帳</button>
</form>

Total due = request.getParameter("amount");   // 直接信任前端寫回的金額（#）攻擊者可改成 1`,
		fixed: `// 安全寫法：金額與運費絕不來自客戶端，由伺服器端重算並綁定一次性憑證
String token = issueCheckoutToken(orderId);   // 伺服器端簽發並保存當次購物車內容
%>
<input type="hidden" name="token" value="<%= token %>" />
<form onsubmit="document.getElementById('ship').value='<%= shippingCost %>'"></form>

OrderTotals totals = orderCalculator.compute(orderId); // 以 DB 裡的商品與費率重算
if (!verifyCheckoutToken(request.getParameter("token"))) { throw new BadRequest(); }
charge(orderId, totals.getGrandTotal());      // 金額一律當場算，不接受客戶端數值`,
		patch: `@@
-<input type="hidden" name="amount" value="#{cart.amount}" />
-<input type="hidden" name="shipping" value="#{shippingCost}" />
-<button type="submit">結帳</button>
-</form>
-
-Total due = request.getParameter("amount");   // 直接信任前端寫回的金額（#）攻擊者可改成 1
+String token = issueCheckoutToken(orderId);   // 伺服器端簽發並保存當次購物車內容
+%>
+<input type="hidden" name="token" value="<%= token %>" />
+
+OrderTotals totals = orderCalculator.compute(orderId); // 以 DB 裡的商品與費率重算
+if (!verifyCheckoutToken(request.getParameter("token"))) { throw new BadRequest(); }
+charge(orderId, totals.getGrandTotal());`,
		refs: ['OWASP-HiddenField', 'CWE-471'],
		tags: ['maid', 'hidden-field', 'price-tampering', 'immutable-data'],
	},
	{
		id: 'CWE-472',
		name: 'External Control of Assumed-Immutable Web Parameter',
		lang: 'python',
		status: 'Complete',
		what: `假設不可變的網頁參數被外部控制。伺服端在寫處理流程時，主觀認定某個網頁參數（例如隱藏欄位、URL query、
		分頁導覽帶進來的 step 編號、登入來源旗標）「永遠只會是伺服端自己填的那個值」，因此毫不設防地直接拿它當
		流程決策或寫進狀態。可是 HTTP 請求的每個參數都由使用者與惡意工具隨時可改，攻擊者把 ?step 改成任何數字、
		或把 is_paid=1 偷塞進去，伺服器照單全收便跳過該保護步驟、做出越權決策。建議做法是把這類「附帶值」只當成
		顯示用的提示，真正的流程、步驟與授權狀態一律由伺服端 session／儲存層決定，必要時還要驗證一次性 token。`,
		problem: `# 不安全寫法：把結帳流程的「已同意服務條款」藏在 query 參數，並假定它不可變
def checkout(request):
    step = request.args.get('step', '1')        # 攻擊者可任意帶 step=3 跳步驟
    agreed = request.args.get('agreed', 'no')   # 假設表單只會填 yes，但可被偽造
    if step == '3' and agreed == 'yes':         # 不經前面 1,2 步驟就直接放行
        finalize_order(request)
    return render_step(step)`,
		fixed: `# 安全寫法：所有步驟與同意與否都在伺服器端 session 裡，query 只當顯示提示
def checkout(request):
    token = request.args.get('token')           # 由伺服端簽發、綁定購物車內容的憑證
    if not validate_checkout_token(token):
        abort(400)
    progress = server_state.current_step(token) # 進度、授權狀態以伺服器端儲存為準
    if progress >= 3 and server_state.terms_accepted(token):
        finalize_order(token)
    return render_step(progress)`,
		patch: `@@
-    step = request.args.get('step', '1')        # 攻擊者可任意帶 step=3 跳步驟
-    agreed = request.args.get('agreed', 'no')   # 假設表單只會填 yes，但可被偽造
-    if step == '3' and agreed == 'yes':         # 不經前面 1,2 步驟就直接放行
-        finalize_order(request)
-    return render_step(step)
+    token = request.args.get('token')           # 由伺服端簽發、綁定購物車內容的憑證
+    if not validate_checkout_token(token):
+        abort(400)
+    progress = server_state.current_step(token) # 進度、授權狀態以伺服器端儲存為準
+    if progress >= 3 and server_state.terms_accepted(token):
+        finalize_order(token)
+    return render_step(progress)`,
		refs: ['OWASP-ParameterTampering', 'CWE-472'],
		tags: ['parameter-tampering', 'query', 'step-enumeration', 'fluent'],
	},
	{
		id: 'CWE-494',
		name: 'Download of Code Without Integrity Check',
		lang: 'shell',
		status: 'Complete',
		what: `下載程式碼時沒有做完整性驗證。應用程式在執行期從網路上取得腳本、可執行檔或更新套件，卻用不安全的管道
		（明文 HTTP）抓取，或抓完後不驗證雜湊／簽章就立刻執行或解壓引用。中間人只要攔下這份檔案換成惡意版本，
		程式便照樣載入執行，等同直接把整台機器或整個供應鏈交出去，這是 supply-chain attack 最典型又最容易踩的入口。
		建議做法是只從 HTTPS＋受信任、固定版本的來源下載，並強制比對 SHA-256 或驗證發布者的數位簽章，任何一項不符
		就要拒絕執行並記錄告警，永不「下載即信任」。`,
		problem: `#!/bin/sh
# 不安全寫法：明文 HTTP 下載，抓完就直接執行，完全沒有雜湊驗證
wget http://cdn1.packages.example/widget-installer.sh
chmod +x widget-installer.sh
./widget-installer.sh        # 途中被換成惡意腳本，照樣執行（#）中間人即可遠端植入`,
		fixed: `#!/bin/sh
# 安全寫法：HTTPS＋固定版本來源，下載後強制比對 SHA-256 才執行
EXPECTED="$(curl -fsSL https://packages.example/releases/2.4.0/widget-installer.sh.sha256)"
curl -fsSL -o /tmp/widget-installer.sh \\
     https://packages.example/releases/2.4.0/widget-installer.sh
echo "$EXPECTED /tmp/widget-installer.sh" | sha256sum -c -   # 不符則退出
[ $? -eq 0 ] && sh /tmp/widget-installer.sh`,
		patch: `@@
-wget http://cdn1.packages.example/widget-installer.sh
-chmod +x widget-installer.sh
-./widget-installer.sh        # 途中被換成惡意腳本，照樣執行（#）中間人即可遠端植入
+EXPECTED="$(curl -fsSL https://packages.example/releases/2.4.0/widget-installer.sh.sha256)"
+curl -fsSL -o /tmp/widget-installer.sh \\
+     https://packages.example/releases/2.4.0/widget-installer.sh
+echo "$EXPECTED /tmp/widget-installer.sh" | sha256sum -c -   # 不符則退出
+[ $? -eq 0 ] && sh /tmp/widget-installer.sh`,
		refs: ['OWASP-SupplyChain', 'CWE-494'],
		tags: ['download', 'integrity-check', 'sha256', 'supply-chain'],
	},
	{
		id: 'CWE-565',
		name: 'Reliance on Cookies without Validation and Integrity Checking',
		lang: 'nodejavascript',
		status: 'Complete',
		what: `直接依賴 cookie 卻不對其做驗證與完整性檢查。伺服器單憑前端送回、且可被隨意改動的 cookie 內容就做出身分
		或授權決策——例如 userRole=admin、isPremium=true、cart 含金額——卻沒有檢查 cookie 的簽名或 MAC，也沒有比對
		真實資料庫。瀏覽器與使用者都能改 cookie，攻擊者把自己的 cookie 設成 admin 就能偽裝成管理員、把旗標翻轉就能
		解鎖付費功能或改價。建議做法是任何身分／授權／狀態決策都讀伺服器端 session 對應的資料，若要使用 cookie 內的值
		也必須是 HMAC 簽章驗證通過、且以簽章承載不可否認的固定欄位，絕不直接信任裸 cookie 內容。`,
		problem: `// 不安全寫法：直接信任客戶端 cookie 內容來決定身分與授權，改 cookie 就升權
const express = require('express');
const app = express();

app.get('/admin', (req, res) => {
  const role = req.cookies.userRole;            // 瀏覽器想設成 admin 就能設
  if (role === 'admin') return renderAdmin(req); // cookie 沒驗證也沒簽名，直接採信
  res.sendStatus(403);
});`,
		fixed: `// 安全寫法：身分與角色一律讀伺服器端 session，cookie 只存隨機 session id
const sid = req.cookies.sid;
store.sessions.find(sid, (e, s) => {          // 依 session id 查伺服器端狀態
  if (e || !s || !s.role) return res.sendStatus(403);
  if (s.role !== 'admin') return res.sendStatus(403);  // 角色以 DB 為準
  renderAdmin(req, s.userId);
});`,
		patch: `@@
-  const role = req.cookies.userRole;            // 瀏覽器想設成 admin 就能設
-  if (role === 'admin') return renderAdmin(req); // cookie 沒驗證也沒簽名，直接採信
-  res.sendStatus(403);
+  const sid = req.cookies.sid;
+  store.sessions.find(sid, (e, s) => {          // 依 session id 查伺服器端狀態
+    if (e || !s || !s.role) return res.sendStatus(403);
+    if (s.role !== 'admin') return res.sendStatus(403);  // 角色以 DB 為準
+    renderAdmin(req, s.userId);
+  });`,
		refs: ['OWASP-CookieTampering', 'CWE-565'],
		tags: ['cookie', 'integrity', 'hmac', 'authorization'],
	},
];
