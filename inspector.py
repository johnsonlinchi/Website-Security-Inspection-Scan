import os
import re
import urllib.request
import ssl
import time
import logging
from typing import Dict, List, Any
from config import BASELINE_PHP_VERSION, REQUEST_TIMEOUT, REQUEST_RETRY, USER_AGENT, LOG_FILE

# 自動建立 logs 目錄
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# 初始化 Logger
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options"
]

def fetch_url_with_retry(url: str) -> tuple[str, dict]:
    """具備重試機制與 Timeout 控制的 HTTP/HTTPS 請求函式"""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    headers = {"User-Agent": USER_AGENT}

    for attempt in range(1, REQUEST_RETRY + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=context) as resp:
                html_bytes = resp.read()
                html_text = html_bytes.decode('utf-8', errors='ignore')
                resp_info = resp.info()
                # 轉為完全不分大小寫的標頭 Dictionary
                resp_headers = {str(k).lower(): str(v) for k, v in resp_info.items()}
                return html_text, resp_headers
        except Exception as e:
            logging.warning(f"重試 [{attempt}/{REQUEST_RETRY}] 讀取 {url} 失敗: {str(e)}")
            time.sleep(0.5)

    return "", {}

def inspect_site_assets(site: Dict[str, str]) -> Dict[str, Any]:
    """
    盤點 WordPress 核心、外掛、主題與 Header，並劃分「正常、需更新、需人工檢查」三種狀態
    """
    url = site["url"]
    site_name = site["name"]

    result = {
        "name": site_name,
        "url": url,
        "status": "正常",  # 狀態分類：正常、需更新、需人工檢查
        "wp_version": "未公開揭露",
        "php_version": f"{BASELINE_PHP_VERSION} (環境基準)",
        "plugins": {},
        "themes": [],
        "warnings": [],
        "manual_checks": []
    }

    html_text, headers_lower = fetch_url_with_retry(url)

    if not html_text:
        result["status"] = "需人工檢查"
        result["warnings"].append("無法取得公開網頁回應 (連線逾時或受伺服器阻擋)")
        result["manual_checks"].append("檢查主機與 Nginx/Apache 線上運作狀態")
        logging.error(f"[{site_name}] 連線失敗，標記為需人工檢查")
        return result

    # 1. 完全不分大小寫的 HTTP 安全標頭盤點 (支援 HTTP/1.1 與 HTTP/2 小寫標頭)
    missing_headers = []
    for h in SECURITY_HEADERS:
        if h.lower() not in headers_lower:
            missing_headers.append(h)

    if missing_headers:
        result["warnings"].append(f"缺少 HTTP 安全標頭: {', '.join(missing_headers)}")
        result["status"] = "需更新"

    # 2. WordPress 核心版本解析
    wp_gen = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([5-9]\.[\d\.]+)', html_text, re.IGNORECASE)
    if wp_gen:
        result["wp_version"] = wp_gen.group(1)
    else:
        embed_ver = re.search(r'wp-includes/js/wp-embed\.min\.js\?ver=([5-9]\.[\d\.]+)', html_text)
        if embed_ver:
            result["wp_version"] = embed_ver.group(1)
        else:
            # 前台防衛性隱蔽屬於良好資安做法，僅紀錄資訊，不強制判定為紅色「需人工檢查」
            result["manual_checks"].append("WordPress 核心版本 (前台已進行資安隱蔽保護，運作正常)")

    # 3. 外掛與主題盤點
    plugin_matches = re.findall(r'wp-content/plugins/([^/]+)/[^"\']+\?ver=([\d\.]+)', html_text)
    for p_name, p_ver in plugin_matches:
        result["plugins"][p_name] = p_ver

    themes = set(re.findall(r'wp-content/themes/([^/\?\'"]+)', html_text))
    result["themes"] = list(themes)

    logging.info(f"[{site_name}] 盤點完成，狀態: {result['status']}, WP核心: {result['wp_version']}, 缺少標頭數: {len(missing_headers)}")
    return result

def run_all_inspections(sites: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    results = []
    for site in sites:
        results.append(inspect_site_assets(site))
    return results
