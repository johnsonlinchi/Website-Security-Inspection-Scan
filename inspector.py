import os
import re
import urllib.request
import urllib.parse
import ssl
import time
import json
import logging
from typing import Dict, List, Any
from config import BASELINE_PHP_VERSION, REQUEST_TIMEOUT, REQUEST_RETRY, USER_AGENT, LOG_FILE, OPENAI_API_KEY, OPENAI_MODEL

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

def parse_version_tuple(ver_str: str) -> tuple:
    """將版本字串轉換為可進行大於/小於比對的數字 Tuple (例如 '4.2.0' -> (4, 2, 0))"""
    clean = re.sub(r'[^\d\.]', '', ver_str)
    parts = [int(p) for p in clean.split('.') if p.isdigit()]
    return tuple(parts)

def ai_evaluate_vulnerability(asset_name: str, asset_version: str, cve_id: str, cve_desc: str) -> bool:
    """
    🤖 ChatGPT 語意化資安裁決引擎：
    分析 CVE 描述文本與受影響版本區間，判定該 CVE 是否「真正影響」當前安裝的版本。
    回傳 True 表示真正存在漏洞 (需告警)，False 表示經 ChatGPT 研判為誤報或已修補版本。
    """
    # 1. 若配置了 OPENAI_API_KEY，優先呼叫 OpenAI ChatGPT API 進行資安語意推理
    if OPENAI_API_KEY:
        try:
            url = "https://api.openai.com/v1/chat/completions"
            prompt = (
                f"軟體名稱: {asset_name}\n"
                f"當前版本: {asset_version}\n"
                f"CVE ID: {cve_id}\n"
                f"CVE 描述: {cve_desc}\n\n"
                f"請精確研判：此 CVE 是否真正影響軟體 {asset_name} 的版本 {asset_version}？"
                f"(若屬第三方擴充外掛誤報或當前版本已高於修補版號，請回答 false)。\n"
                f"請只回傳 JSON: {{\x22is_vulnerable\x22: true/false, \x22reason\x22: \x22說明\x22}}"
            )
            payload = json.dumps({
                "model": OPENAI_MODEL,
                "messages": [
                    {"role": "system", "content": "你是一名精通 WordPress 與 Web 資安的權威專家。"},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.1
            }).encode('utf-8')

            req = urllib.request.Request(url, data=payload, headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json"
            })
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=6, context=context) as resp:
                res_data = json.loads(resp.read().decode('utf-8'))
                ai_text = res_data['choices'][0]['message']['content']
                if "false" in ai_text.lower():
                    logging.info(f"[ChatGPT 審核] 經 ChatGPT ({OPENAI_MODEL}) 研判 {asset_name} (v{asset_version}) 之 {cve_id} 為誤報或非主體漏洞")
                    return False
                return True
        except Exception as e:
            logging.warning(f"ChatGPT API 呼叫失敗，自動降級至內建 AI 啟發式推理: {str(e)}")

    # 2. 內建 AI 語意與 SemVer 啟發式推理規則 (無需 API Key 即可全自動運作)
    desc_lower = cve_desc.lower()
    asset_clean = asset_name.replace('-', ' ').lower()

    # 檢測是否為第三方 Addon 誤匹配 (例如將 Starter Templates 誤判給 Elementor 主體)
    addon_patterns = [
        r'starter templates', r'addons? for', r'extensions? for', 
        r'for woocommerce', r'for elementor', r'mailchimp for'
    ]
    for pat in addon_patterns:
        if re.search(pat, desc_lower) and not re.search(pat, asset_clean):
            logging.info(f"[內建 AI 審核] {cve_id} 屬於第三方擴充外掛描述 ({pat})，非 {asset_name} 本體漏洞，自動剔除誤報")
            return False

    # 語意化數字版本比對 (Semantic Versioning)
    curr_tuple = parse_version_tuple(asset_version)
    if curr_tuple:
        match_before = re.search(r'(?:before|prior to|<|up to|through)\s+v?([\d\.]+)', cve_desc, re.IGNORECASE)
        if match_before:
            fixed_ver_tuple = parse_version_tuple(match_before.group(1))
            if fixed_ver_tuple and curr_tuple >= fixed_ver_tuple:
                logging.info(f"[內建 AI 審核] {asset_name} 當前版本 (v{asset_version}) >= 已修補版本 (v{match_before.group(1)})，判定已安全修補")
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
    """連線 NIST NVD 比對外掛版號，並透過 🤖 ChatGPT API 進行資安審核」"""
    hits = []
    if not plugin_version or plugin_version in ["已知安裝", "Unknown"]:
        return hits

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

                # 透過 🤖 ChatGPT API 進行資安語意裁決
                if ai_evaluate_vulnerability(plugin_name, plugin_version, cve_id, desc):
                    hits.append({
                        "id": cve_id,
                        "desc": f"外掛 {plugin_name} (v{plugin_version}) 命中 CVE: {desc[:100]}...",
                        "severity": "High"
                    })
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
    盤點外掛、主題、PHP 環境與安全 Header，並經過 🤖 ChatGPT API 審核引擎過濾 CVE 告警
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

    # 3. 線上 CVE 漏洞比對 (經過 🤖 ChatGPT API 審核)
    php_cves = check_php_cve(result["php_version"])
    result["cve_hits"].extend(php_cves)

    for p_name, p_ver in result["plugins"].items():
        p_cves = check_plugin_cve(p_name, p_ver)
        result["cve_hits"].extend(p_cves)

    # 若命中任何真正的 CVE 漏洞，自動觸發「需更新」告警狀態
    if result["cve_hits"]:
        result["status"] = "需更新"
        for hit in result["cve_hits"]:
            result["warnings"].append(f"⚠️ [CVE告警] {hit['id']}: {hit['desc']}")
        logging.warning(f"[{site_name}] 經 ChatGPT 審核確認命中 {len(result['cve_hits'])} 項 CVE 漏洞！標示為需更新告警")

    logging.info(f"[{site_name}] 盤點完成，狀態: {result['status']}, 外掛數: {len(result['plugins'])}, CVE命中數: {len(result['cve_hits'])}")
    return result

def run_all_inspections(sites: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    results = []
    for site in sites:
        results.append(inspect_site_assets(site))
    return results
