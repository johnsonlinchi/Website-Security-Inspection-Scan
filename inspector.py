import re
import urllib.parse
import urllib.request
import ssl
import json
from typing import Dict, List, Any

# 安全頭標檢測項目
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

def check_site_security(site: Dict[str, str]) -> Dict[str, Any]:
    url = site["url"]
    site_name = site["name"]
    
    result = {
        "site_name": site_name,
        "url": url,
        "wp_version": "Unknown",
        "php_version": "Unknown",
        "sql_version": "Unknown",
        "plugins_themes": [],
        "security_headers": {},
        "https_status": "Unknown",
        "cve_hits": [],
        "risk_level": "Low",
        "evidence": [],
        "manual_checks": ["PHP 版本 (需伺服器/後台確認)", "MySQL/MariaDB 版本 (需後台確認)", "完整外掛/主題列表 (需後台確認)"]
    }
    
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PortwellSecurityBot/1.0"
    }

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10, context=context) as response:
            result["https_status"] = "HTTPS 正常" if url.startswith("https") else "HTTP (未啟用 HTTPS)"
            resp_headers = dict(response.info())
            
            # 檢查安全 Header
            missing_headers = []
            for h in SECURITY_HEADERS:
                val = resp_headers.get(h) or resp_headers.get(h.lower())
                if val:
                    result["security_headers"][h] = val
                else:
                    missing_headers.append(h)
            
            if missing_headers:
                result["evidence"].append(f"缺少安全標頭: {', '.join(missing_headers)}")
                if result["risk_level"] in ["Low"]:
                    result["risk_level"] = "Medium"

            # 檢查 Server 或 X-Powered-By
            server_header = resp_headers.get("Server") or resp_headers.get("server")
            x_powered = resp_headers.get("X-Powered-By") or resp_headers.get("x-powered-by")
            if server_header:
                result["evidence"].append(f"Server 標頭回應: {server_header}")
            if x_powered:
                result["evidence"].append(f"X-Powered-By 揭露: {x_powered}")
                if "PHP" in x_powered:
                    php_match = re.search(r'PHP/([\d\.]+)', x_powered)
                    if php_match:
                        result["php_version"] = php_match.group(1)

            # 讀取 HTML 內容嘗試解析 WP generator
            html_bytes = response.read()
            html_text = html_bytes.decode('utf-8', errors='ignore')
            
            # 解析 WP generator meta
            wp_gen_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d\.]+)["\']', html_text, re.IGNORECASE)
            if wp_gen_match:
                result["wp_version"] = wp_gen_match.group(1)
                result["evidence"].append(f"發現 WordPress 核心版本標示: {result['wp_version']}")

            # 解析 wp-content 外掛與主題標籤
            plugins_found = set(re.findall(r'wp-content/plugins/([^/\?\'"]+)', html_text))
            themes_found = set(re.findall(r'wp-content/themes/([^/\?\'"]+)', html_text))
            
            for p in plugins_found:
                result["plugins_themes"].append(f"Plugin: {p}")
            for t in themes_found:
                result["plugins_themes"].append(f"Theme: {t}")

    except Exception as e:
        result["risk_level"] = "Unknown"
        result["evidence"].append(f"無法透過公開網路存取連線: {str(e)}")
        result["https_status"] = "連線失敗"

    # 若未找到核心版本，進行標記
    if result["wp_version"] == "Unknown":
        result["manual_checks"].append("WordPress 核心版本 (公開被動掃描未顯式揭露)")

    return result

def run_all_inspections(sites: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    results = []
    for site in sites:
        results.append(check_site_security(site))
    return results
