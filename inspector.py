import os
import re
import urllib.request
import urllib.parse
import ssl
import time
import json
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

# 常見已知第三方前端庫 (避免將 Swiper 8.4.5 或 FontAwesome 5.15 誤判為外掛版號)
THIRD_PARTY_ASSET_VERSIONS = ["8.4.5", "5.15.4", "3.7.1", "1.8.7", "2.7.2"]

# 第三方擴充外掛關聯字過濾 (防止把 Starter Templates 誤判給 Elementor 本體，或把 Mailchimp 誤判給 WooCommerce 本體)
ADDON_KEYWORDS = [
    "starter templates", "addons for", "addon for", "extension for", 
    "for woocommerce", "for elementor", "beaver builder", "mailchimp for"
]

def parse_version_tuple(ver_str: str) -> tuple:
    """將版本字串轉換為可進行大於/小於比對的數字 Tuple (例如 '4.2.0' -> (4, 2, 0))"""
    clean = re.sub(r'[^\d\.]', '', ver_str)
    parts = [int(p) for p in clean.split('.') if p.isdigit()]
    return tuple(parts)

def is_version_vulnerable(current_ver: str, cve_desc: str) -> bool:
    """
    解析 CVE 描述中的版本影響範圍，並進行精確的 SemVer 數字比對：
    如果當前版本 >= 修補版本 (e.g. 'before 4.2.0' 且當前為 '4.2.0')，則判定為已修補 (不發告警)
    """
    curr_tuple = parse_version_tuple(current_ver)
    if not curr_tuple:
        return True

    # 1. 匹配 "before X.X.X" 或 "prior to X.X.X" 或 "<= X.X.X"
    match_before = re.search(r'(?:before|prior to|<|up to|through)\s+v?([\d\.]+)', cve_desc, re.IGNORECASE)
    if match_before:
        fixed_ver_tuple = parse_version_tuple(match_before.group(1))
        if fixed_ver_tuple:
            # 如果當前版本 >= 漏洞修補版本，代表已安全修補！
            if curr_tuple >= fixed_ver_tuple:
                return False

    return True

def get_exact_plugin_version(base_url: str, plugin_slug: str) -> str:
    """從外掛公開之 readme.txt 精確讀取真實版號 (若失敗則回傳空)"""
    readme_url = f"{base_url.rstrip('/')}/wp-content/plugins/{plugin_slug}/readme.txt"
    try:
        req = urllib.request.Request(readme_url, headers={"User-Agent": USER_AGENT})
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=3, context=context) as resp:
            if resp.status == 200:
                text = resp.read().decode('utf-8', errors='ignore')
                m = re.search(r'Stable\s+tag:\s*([\d\.]+)', text, re.IGNORECASE)
                if m:
                    return m.group(1).strip()
    except Exception:
        pass
    return ""

def check_php_cve(version: str) -> List[Dict[str, str]]:
    """比對 PHP 版本已知 CVE 漏洞 (同步 Nessus Plugin ID 313114 & 324980)"""
    hits = []
    if not version or "環境基準" in version:
        clean_ver = BASELINE_PHP_VERSION
    else:
        clean_ver = version

    try:
        v_parts = clean_ver.split('.')
        if len(v_parts) >= 2:
            major = int(v_parts[0])
            minor = int(v_parts[1])
            patch = int(v_parts[2]) if len(v_parts) >= 3 else 0

            if major == 8 and minor == 3:
                if patch < 31:
                    hits.append({
                        "id": "CVE-2025-14179 / CVE-2026-6722",
                        "desc": f"PHP {clean_ver} (低於 8.3.31): 存在 Critical 記憶體溢位與遠端攻擊風險，建議升級至 PHP 8.3.32+",
                        "severity": "Critical"
                    })
                elif patch < 32:
                    hits.append({
                        "id": "CVE-2026-12184",
                        "desc": f"PHP {clean_ver} (低於 8.3.32): 存在安全修補缺陷，建議升級至 PHP 8.3.32+",
                        "severity": "Medium"
                    })
            elif major < 8 or (major == 8 and minor < 2):
                hits.append({
                    "id": "CVE-2024-4577 / PHP EOL 警示",
                    "desc": f"PHP {clean_ver} 已停止官方安全維護 (EOL)，存在嚴重 CGI 注入與已知遠端執行漏洞！",
                    "severity": "Critical"
                })
    except Exception:
        pass
    return hits

def check_plugin_cve(plugin_name: str, plugin_version: str) -> List[Dict[str, str]]:
    """連線 NIST NVD 比對外掛版號線上 CVE (包含名稱過濾 + 語意化版本 SemVer 數字區間比對)"""
    hits = []
    if not plugin_version or plugin_version in ["已知安裝", "Unknown"]:
        return hits

    # 過濾第三方腳本庫版本
    if plugin_version in THIRD_PARTY_ASSET_VERSIONS and plugin_name in ["woocommerce", "elementor"]:
        return hits

    try:
        query = f"wordpress plugin {plugin_name} {plugin_version}"
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(query)}"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=4, context=context) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            for item in data.get("vulnerabilities", [])[:2]:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "CVE-Unknown")
                desc = cve_data.get("descriptions", [{}])[0].get("value", "")
                desc_lower = desc.lower()
                
                # 1. 檢查是否屬於第三方 Addon 誤報
                is_addon_mismatch = any(addon_kw in desc_lower for addon_kw in ADDON_KEYWORDS)
                if is_addon_mismatch:
                    continue

                # 2. 嚴格驗證 CVE 說明必須包含該外掛名稱主體
                clean_plugin_name = plugin_name.replace('-', ' ').lower()
                if clean_plugin_name in desc_lower:
                    # 3. 語意化版本 (SemVer) 數字範圍比對：判斷當前版本是否真的在受受影響區間內
                    if is_version_vulnerable(plugin_version, desc):
                        hits.append({
                            "id": cve_id,
                            "desc": f"外掛 {plugin_name} (v{plugin_version}) 命中 CVE: {desc[:100]}...",
                            "severity": "High"
                        })
                    else:
                        logging.info(f"[{plugin_name} v{plugin_version}] 已高於或等於漏洞修補版本，忽略 CVE {cve_id}")
    except Exception:
        pass
    return hits

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
                resp_headers = {str(k).lower(): str(v) for k, v in resp_info.items()}
                return html_text, resp_headers
        except Exception as e:
            logging.warning(f"重試 [{attempt}/{REQUEST_RETRY}] 讀取 {url} 失敗: {str(e)}")
            time.sleep(0.5)

    return "", {}

def inspect_site_assets(site: Dict[str, str]) -> Dict[str, Any]:
    """
    盤點外掛、主題、PHP 環境與安全 Header，比對 CVE 漏洞自動標示告警 (加入 SemVer 數字版本比對)
    """
    url = site["url"]
    site_name = site["name"]

    result = {
        "name": site_name,
        "url": url,
        "status": "正常",  # 狀態分類：正常、需更新、需人工檢查
        "php_version": f"{BASELINE_PHP_VERSION} (環境基準)",
        "plugins": {},
        "themes": [],
        "cve_hits": [],
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

    # 1. 完全不分大小寫的 HTTP 安全標頭盤點
    missing_headers = []
    for h in SECURITY_HEADERS:
        if h.lower() not in headers_lower:
            missing_headers.append(h)

    if missing_headers:
        result["warnings"].append(f"缺少 HTTP 安全標頭: {', '.join(missing_headers)}")
        result["status"] = "需更新"

    # 2. 外掛與主題盤點 (優先從 readme.txt 精確抓取)
    plugin_matches = re.findall(r'wp-content/plugins/([^/]+)/[^"\']+\?ver=([\d\.]+)', html_text)
    discovered_slugs = set(p[0] for p in plugin_matches)

    for slug in discovered_slugs:
        exact_ver = get_exact_plugin_version(url, slug)
        if exact_ver:
            result["plugins"][slug] = exact_ver
        else:
            for p_name, p_ver in plugin_matches:
                if p_name == slug:
                    if p_ver not in THIRD_PARTY_ASSET_VERSIONS or slug not in result["plugins"]:
                        result["plugins"][slug] = p_ver

    themes = set(re.findall(r'wp-content/themes/([^/\?\'"]+)', html_text))
    result["themes"] = list(themes)

    # 3. 線上 CVE 漏洞比對 (名稱過濾 + SemVer 數字版本範圍比對)
    php_cves = check_php_cve(result["php_version"])
    result["cve_hits"].extend(php_cves)

    for p_name, p_ver in result["plugins"].items():
        p_cves = check_plugin_cve(p_name, p_ver)
        result["cve_hits"].extend(p_cves)

    # 若命中任何 CVE 漏洞，自動觸發「需更新」告警狀態
    if result["cve_hits"]:
        result["status"] = "需更新"
        for hit in result["cve_hits"]:
            result["warnings"].append(f"⚠️ [CVE告警] {hit['id']}: {hit['desc']}")
        logging.warning(f"[{site_name}] 命中 {len(result['cve_hits'])} 項 CVE 漏洞！標示為需更新告警")

    logging.info(f"[{site_name}] 盤點完成，狀態: {result['status']}, 外掛數: {len(result['plugins'])}, CVE命中數: {len(result['cve_hits'])}")
    return result

def run_all_inspections(sites: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    results = []
    for site in sites:
        results.append(inspect_site_assets(site))
    return results
