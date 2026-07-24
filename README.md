# Portwell Website Security Inspection & Scheduler

AI Portwell WordPress 站台自動化安全巡檢與郵件報告排程系統。

## 功能特點

- **5 大固定巡檢站台**：
  - 國際站 (`https://www.portwell.com.tw`)
  - 台灣站 (`https://www.portwell.tw`)
  - AI 站 (`https://www.portwell.ai`)
  - 智利站 (`https://www.portwell.cl`)
  - DC 站 (`https://download.portwell.tw`)
- **被動式檢測與安全邊界**：
  - 不執行任何侵入式測試、爆破或滲透。
  - 僅解析公開 HTTP Headers、Meta generator 及公開靜態資源。
- **標準 7 大區塊報告**：
  - 產出清晰 HTML 有框線表格報告 (`border="1"`, `cellpadding="6"`)。
  - 包含執行摘要、CVE/漏洞命中摘要、高風險總覽、逐站結果表、詳細發現、人工確認清單、修補待辦清單。
- **安全邊界限制郵件發送**：
  - 預設收件人固定鎖定為 `39620@portwell.com.tw`。
  - 根據是否發現漏洞/CVE 命中動態設定郵件主旨標籤 (如 `[CVE/漏洞警示]`)。

## 使用方式

### 直接執行巡檢

```bash
python main.py
```

### 設定 SMTP 憑證 (環境變數)

```bash
export SMTP_SERVER="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USER="your-email@example.com"
export SMTP_PASS="your-app-password"
```
