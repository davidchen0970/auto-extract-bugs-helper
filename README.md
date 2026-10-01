# Bug Tarball Viewer（缺陷預覽工作台）

純前端單頁工具：在瀏覽器內解壓縮並解析 `tar / tar.gz / tgz`，逐一預覽其中的「缺陷」。

## 使用方式

因為現在是 **ES module**，必須透過 HTTP 開啟（`file://` 會被瀏覽器 module CORS 擋掉）：

```bash
cd auto-extract-bugs-helper
python3 -m http.server 8000     # 或：npm run serve
# 開啟 http://localhost:8000
```

把 tar 拖進視窗（或點「開啟 tar / tar.gz」選檔）。檔案只在你自己的瀏覽器內處理，不會上傳。

## 自動辨識的缺陷來源

| 來源 | 檔案樣式 | 內容 |
| --- | --- | --- |
| **Coverity** | `*_coverity_guidance.html` | 靜態分析程式缺陷（類型 / checker / CWE / 檔案行號 / 執行路徑事件）|
| **BlackDuck** | `*_guidance_details.csv` | 第三方元件 CVE 弱點（中文欄位表頭）（嚴重性 / CVSS / 修復狀態 / 官方解法）|
| **自定義缺陷來源** | 英文欄位的 SCA 匯出（如 Black Duck SCA `*.csv`，含 `Component name` / `Vulnerability id` / `Security Risk` / `Overall score` / `CWE Ids` 等）| 以表頭**動態對應**，保留**每一欄原始值**（`fields`），並提升語意欄位（元件 / 版本 / CVE / 嚴重性 / 修復狀態 / CWE / 說明 / URL…）至卡片、搜尋、匯出與比對使用 |
| 建置產物 | `.ima/.bin/...` | 僅列示大小 |

> 「自定義缺陷來源」特別用來接住表頭是英文、但專案內建中文 Black Duck 解析器對不上的 SCA CSV。此類檔案誤入 Black Duck 解析器時，所有欄位會空白重、嚴重性全被擱成 LOW；自定義解析器會優先在 *blackduck* 之前認領它，並完整保留全部欄位。

## 功能

- TAR 精確解析（`ustar` / GNU long name (`L`) / PAX (`x`) / 512-byte 對齊 / base-256 大小）
- gzip 直接解壓縮（`DecompressionStream`，需現代瀏覽器；純 `.tar` 不需）
- 每個缺陷可展開檢視完整說明、執行路徑、修復建議
- **每筆 Coverity 缺陷顯示帶行號的原始碼片段**（命中行／事件行高亮，內嵌路徑註記）
- 嚴重性分頁過濾、全文搜尋、分頁瀏覽（每頁 10 筆）
- 「匯出 JSON」下載目前來源的所有缺陷
- **比對兩份報表**（工具列「比對兩份報表」）：各選一份 tar／單檔報表，會把壓縮檔內**每一種報表類型（Coverity 與 BlackDuck）**都針對該類型分別比對，自動分辨**新增／移除／內容差異**的缺陷
- **亮/暗主題切換**（右上「切換主題」或按 `T`）
- **鍵盤快速鍵**：`S` 搜尋、`E` 匯出、`T` 主題、`←`/`→` 換頁、`H` 說明

## 測試

```bash
npm install   # 需先裝 devDependency（jsdom）
npm test      # node --test → test/core/*
```

- `tar` / `blackduck`：純邏輯，Node 原生測試，不需 DOM。
- `coverity`：行到 `DOMParser`，測試用 jsdom 注入 DOM globals。

## 注意

- 缺 `DecompressionStream` 的舊瀏覽器無法解 `.tar.gz`，請改用純 `.tar`。
- ES module：**不要**用 `file://` 直接開 `index.html`，請用伺服器。
