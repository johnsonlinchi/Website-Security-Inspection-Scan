import os

# 預設巡檢與盤點站台
SITES = [
    {"name": "國際站", "url": "https://www.portwell.com.tw"},
    {"name": "台灣站", "url": "https://www.portwell.tw"},
    {"name": "AI 站",  "url": "https://www.portwell.ai"},
    {"name": "智利站", "url": "https://www.portwell.cl"},
    {"name": "DC 站",  "url": "https://download.portwell.tw"},
    {"name": "中國站", "url": "https://www.portwell.com.cn"}
]

# 基準環境版本 (如 PHP 8.3.32)
BASELINE_PHP_VERSION = "8.3.32"

# 允許的固定收件者白名單 (邊界控制)
ALLOWED_RECIPIENTS = [
    "39620@portwell.com.tw",
    "johnson.lin@portwell.com.tw"
]

# 預設收件者
DEFAULT_RECIPIENT = os.getenv("SMTP_RECIPIENT", "39620@portwell.com.tw")

# OpenAI ChatGPT API 設定
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

# SMTP 發信設定 (可透過環境變數覆寫)
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER or "security-bot@portwell.com.tw")

# 請求與重試參數
REQUEST_TIMEOUT = 10  # 秒
REQUEST_RETRY = 2     # 重試次數
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PortwellAssetMonitor/1.0"

# Log 檔案路徑
LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "monitor.log")
