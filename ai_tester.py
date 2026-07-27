import sys
import ssl
import json
import urllib.request
from config import OPENAI_API_KEY, OPENAI_MODEL

def test_openai_api_connection() -> tuple[bool, str]:
    """測試 OpenAI ChatGPT API 連線與 API Key 是否有效"""
    if not OPENAI_API_KEY:
        return False, "未檢測到 OPENAI_API_KEY (目前使用內建 AI 啟發式引擎)"

    try:
        url = "https://api.openai.com/v1/chat/completions"
        payload = json.dumps({
            "model": OPENAI_MODEL,
            "messages": [{"role": "user", "content": "Hi"}],
            "max_tokens": 5
        }).encode('utf-8')

        req = urllib.request.Request(url, data=payload, headers={
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json"
        })
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, timeout=5, context=context) as resp:
            if resp.status == 200:
                return True, f"ChatGPT API 連線成功！(模型: {OPENAI_MODEL}, 金鑰認證正常)"
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return False, "ChatGPT API 失敗: 401 Unauthorized (API Key 無效或已過期)"
        elif e.code == 429:
            return False, "ChatGPT API 失敗: 429 Too Many Requests (API 額度已用完或頻率受限)"
        else:
            return False, f"ChatGPT API HTTP 錯誤: {e.code} {e.reason}"
    except Exception as e:
        return False, f"ChatGPT API 連線異常: {str(e)}"

    return False, "ChatGPT API 未知回應"
