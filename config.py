import os

# 固定巡檢站台
SITES = [
    {"name": "國際站", "url": "https://www.portwell.com.tw"},
    {"name": "台灣站", "url": "https://www.portwell.tw"},
    {"name": "AI 站", "url": "https://www.portwell.ai"},
    {"name": "智利站", "url": "https://www.portwell.cl"},
    {"name": "DC 站", "url": "https://download.portwell.tw"}
]

# 允許的固定唯一收件者
ALLOWED_RECIPIENT = "39620@portwell.com.tw"

# SMTP 發信設定 (可透過環境變數覆寫)
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER or "security-bot@portwell.com.tw")
