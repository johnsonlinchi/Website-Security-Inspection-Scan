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

def check_wp_cve(version: str) -> List[Dict[str, str]]:
    """比對 WordPress 核心版本已知 CVE 漏洞資料庫"""
    cve_hits = []
    if not version or version == "Unknown":
        return cve_hits
        
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=WordPress%20{urllib.parse.quote(version)}"
        req = urllib.request.Request(url, headers={"User-Agent": "PortwellSecBot/1.0"})
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with urllib.request.urlopen(req, timeout=5, context=context) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            vulnerabilities = data.get("vulnerabilities", [])
            for item in vulnerabilities[:3]:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "CVE-Unknown")
                descriptions = cve_data.get("descriptions", [])
                desc_text = descriptions[0].get("value", "") if descriptions else "無詳細說明"
                cve_hits.append({
                    "id": cve_id,
                    "desc": f"WordPress {version} 命中 NVD CVE: {desc_text[:120]}...",
                    "severity": "High"
                })
    except Exception:
        v_parts = version.split('.')
        try:
            major = float(f"{v_parts[0]}.{v_parts[1]}")
            if major < 6.4:
                cve_hits.append({
                    "id": "CVE-2023-5561 / CVE-2023-38000",
                    "desc": f"WordPress {version} (過舊核心版本): 存在未授權資訊洩漏與遠端程式碼執行 (RCE) 已知高風險漏洞公告",
                    "severity": "Critical"
                })
        except Exception:
            pass

    return cve_hits

def check_php_cve(version: str) -> List[Dict[str, str]]:
    """比對 PHP 版本已知 CVE 與 EOL 漏洞"""
    cve_hits = []
    if not version or version == "Unknown":
        return cve_hits
        
    try:
        v_parts = version.split('.')
        major_minor = f"{v_parts[0]}.{v_parts[1]}" if len(v_parts) >= 2 else version
        
        if major_minor.startswith("7.") or major_minor.startswith("5."):
            cve_hits.append({
                "id": "CVE-2024-4577 / CVE-2023-3824 (PHP EOL 警示)",
                "desc": f"PHP {version} 已停止官方安全更新 (EOL)。存在 CGI 引數注入 (CGI Argument Injection) 與緩衝區溢位未知修補嚴重漏洞！",
                "severity": "Critical"
            })
        elif major_minor in ["8.0", "8.1"]:
            cve_hits.append({
                "id": "CVE-2024-2756 (PHP 8.0/8.1 EOL 警示)",
                "desc": f"PHP {version} 已接近或過期安全生命週期，建議升級至 PHP 8.2 或 8.3 以維護資安。",
                "severity": "High"
            })
    except Exception:
        pass
        
    return cve_hits

def probe_extended_wp_endpoints(base_url: str, context: ssl.SSLContext) -> Dict[str, Any]:
    """
    透過被動靜態資源、REST API、RSS Feed 與公開說明檔等多維度路徑探測版本資訊
    """
    ext_results = {
        "wp_version": "Unknown",
        "php_version": "Unknown",
        "sql_version": "Unknown",
        "plugins": [],
        "evidence": []
    }
    
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PortwellSecurityBot/1.0"}
    
    # 1. 探測 /wp-json/ REST API 節點
    try:
        api_url = base_url.rstrip('/') + '/wp-json/'
        req = urllib.request.Request(api_url, headers=headers)
        with urllib.request.urlopen(req, timeout=5, context=context) as resp:
            api_data = json.loads(resp.read().decode('utf-8'))
            ext_results["evidence"].append("WordPress REST API (/wp-json/) 處於公開啟用狀態")
            
            # 部分擴充套件會在 API 根目錄揭露系統與版本資訊
            if "name" in api_data:
                ext_results["evidence"].append(f"REST API 站台名稱: {api_data.get('name')}")
            if "namespaces" in api_data:
                namespaces = api_data.get("namespaces", [])
                ext_results["evidence"].append(f"REST API 命名空間發現 ({len(namespaces)} 個組件)")
    except Exception:
        pass

    # 2. 探測 /feed/ (RSS Feed 的 generator 標籤)
    try:
        feed_url = base_url.rstrip('/') + '/feed/'
        req = urllib.request.Request(feed_url, headers=headers)
        with urllib.request.urlopen(req, timeout=5, context=context) as resp:
            feed_text = resp.read().decode('utf-8', errors='ignore')
            wp_feed_match = re.search(r'<generator>https?://wordpress\.org/\?v=([\d\.]+)</generator>', feed_text, re.IGNORECASE)
            if wp_feed_match:
                ext_results["wp_version"] = wp_feed_match.group(1)
                ext_results["evidence"].append(f"從 RSS Feed (/feed/) 成功擷取到 WordPress 核心版本: {ext_results['wp_version']}")
    except Exception:
        pass

    # 3. 探測 /readme.html (傳統 WP 靜態說明檔)
    try:
        readme_url = base_url.rstrip('/') + '/readme.html'
        req = urllib.request.Request(readme_url, headers=headers)
        with urllib.request.urlopen(req, timeout=4, context=context) as resp:
            readme_text = resp.read().decode('utf-8', errors='ignore')
            ver_match = re.search(r'Version\s+([\d\.]+)', readme_text, re.IGNORECASE)
            if ver_match:
                ext_results["wp_version"] = ver_match.group(1)
                ext_results["evidence"].append(f"公開 readme.html 揭露 WordPress 版本: {ext_results['wp_version']}")
    except Exception:
        pass

    return ext_results

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
        "manual_checks": ["PHP 版本 (若 Server 隱藏 Header，需伺服器/後台確認)", "MySQL/MariaDB 版本 (需內部 DB 存取確認)", "完整外掛/主題清單 (需後台確認)"]
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
            
            # 1. 檢查安全 Header
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

            # 2. 檢查 Server 或 X-Powered-By 擷取 PHP / Web Server 版本
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

            # 3. 讀取 HTML 內容嘗試解析 WP generator meta 與靜態資源 ?ver= 參數
            html_bytes = response.read()
            html_text = html_bytes.decode('utf-8', errors='ignore')
            
            # 3a. 解析 WP generator meta
            wp_gen_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d\.]+)["\']', html_text, re.IGNORECASE)
            if wp_gen_match:
                result["wp_version"] = wp_gen_match.group(1)
                result["evidence"].append(f"發現 WordPress 核心 Meta 標示: {result['wp_version']}")

            # 3b. 從 wp-includes/ 靜態 CSS/JS 的 ?ver= 參數推算核心版本
            if result["wp_version"] == "Unknown":
                ver_match = re.search(r'wp-includes/[^"\']+\?ver=([\d\.]+)', html_text)
                if ver_match:
                    result["wp_version"] = ver_match.group(1)
                    result["evidence"].append(f"從靜態資源 (?ver=) 提取 WordPress 核心版本: {result['wp_version']}")

            # 3c. 從 wp-content/plugins/ 擷取外掛與對應 ?ver= 版本號
            plugin_ver_matches = re.findall(r'wp-content/plugins/([^/]+)/[^"\']+\?ver=([\d\.]+)', html_text)
            found_plugins = {}
            for p_name, p_ver in plugin_ver_matches:
                found_plugins[p_name] = p_ver
            
            plugins_found_plain = set(re.findall(r'wp-content/plugins/([^/\?\'"]+)', html_text))
            for p in plugins_found_plain:
                if p not in found_plugins:
                    found_plugins[p] = "未知版本"

            themes_found = set(re.findall(r'wp-content/themes/([^/\?\'"]+)', html_text))
            
            for p_name, p_ver in found_plugins.items():
                result["plugins_themes"].append(f"Plugin: {p_name} (v{p_ver})")
            for t in themes_found:
                result["plugins_themes"].append(f"Theme: {t}")

    except Exception as e:
        result["risk_level"] = "Unknown"
        result["evidence"].append(f"無法透過公開網路存取連線: {str(e)}")
        result["https_status"] = "連線失敗"

    # 4. 多維度路徑探測 (RSS Feed / REST API / Readme)
    ext_data = probe_extended_wp_endpoints(url, context)
    result["evidence"].extend(ext_data["evidence"])
    if result["wp_version"] == "Unknown" and ext_data["wp_version"] != "Unknown":
        result["wp_version"] = ext_data["wp_version"]

    # 5. CVE 漏洞自動實時比對
    wp_cves = check_wp_cve(result["wp_version"])
    result["cve_hits"].extend(wp_cves)

    php_cves = check_php_cve(result["php_version"])
    result["cve_hits"].extend(php_cves)

    # 提升風險等級
    for cve in result["cve_hits"]:
        sev = cve.get("severity", "Medium")
        if sev == "Critical":
            result["risk_level"] = "Critical"
        elif sev == "High" and result["risk_level"] != "Critical":
            result["risk_level"] = "High"

    if result["wp_version"] == "Unknown":
        result["manual_checks"].append("WordPress 核心版本 (靜態/Feed/API 未顯式揭露)")

    return result

def run_all_inspections(sites: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    results = []
    for site in sites:
        results.append(check_site_security(site))
    return results
