# AI 弱點手冊資料庫（CVSS + package 弱點解釋）

存放「帶 CVSS 分數、與某套件綁定」的 SCA 弱點解釋，架構與 `data/cwe/` 手冊相同，
前端以「CVE 編號 + 套件」組合金鑰（`CVE-2021-44228@log4j-core`）建檔與檢索。

## 新增一筆解釋

1. 在 `data/vuln/<類別>/` 下新增一個 `.js` 檔（可複製現有範例），內容為預設匯出的陣列：

   ```js
   export default [
     {
       key: "CVE-2021-44228@log4j-core",   // 組合金鑰，必須全樹唯一
       cat: "Remote Code Execution",            // 分類
       cve: "CVE-2021-44228",                // 弱點編號
       pkg: "log4j-core",                     // 套件名稱
       version: "2.15.0",                    // 受影響/已修復版本（選填）
       name: "Log4Shell",                    // 顯示名稱
       cvss: "10.0",                         // CVSS 分數（選填）
       cvssNote: "來源與 CVSS vector 細節",  // (選填)評分的額外註解，只在詳情頁顯示，清單的 CVSS 只顯示裸分數
       what: "此弱點的解釋說明…",             // 解釋文字
       recommendation: "該怎麼因應…",         // (建議填)可直接依循的因應建議
       refs: ["NVD:CVE-2021-44228"],        // 參考（選填）
       tags: ["log4shell","rce"],             // 供搜尋的標籤（選填）
     },
   ];
   ```

   `what` 是這個弱點的「研究/說明」，`recommendation` 是「因應建議」；
   前端缺陷詳情的「**AI 研究結果**」欄會把兩者一起顯示。這份內容就是
   預先跑好的 AI 研究輸出（AI 可在 remote 產出後存進這些條目），前端只做 `CVE@pkg` 比對與呈現。


## Markdown 支援

`what` 與 `recommendation`（以及缺陷詳情「AI 研究結果」欄）都支援 **Markdown**，
前端經 `marked` 轉 HTML 後再用 DOMPurify 消毒，可用的語法包括：**粗體**、`行內程式碼`、
程式碼區塊（```）、`-`/`1.` 清單、`###` 標題、`>` 引用、`---` 分隔線與
GFM 表格。例如：

```md
**風險等級：高**
- 根因：`BZ2_decompress` 因過多 selectors 導致越界寫（CWE-787）。
- 建議：升級至已修復版本並重啟相關服務。
| 面向 | 說明 |
| ---- | ---- |
| 可利用 | 未認證、遠端 |
```

2. 重新產生組合檔：

   ```sh
   node scripts/build-vuln-index.mjs
   ```

3. `data/vuln/index.js` 是自動產生的，請勿手動編輯。

同一個 CVE 在不同套件下若要不同的解釋，就開另一筆、換成對應的 `@套件` 金鑰即可
（例如 `CVE-2014-0160@openssl` 與 `CVE-2014-0160@openssl-server`）。
