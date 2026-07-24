import re
import urllib.parse
import urllib.request
import ssl
import json
import base64
from typing import Dict, List, Any
from config import WP_AUTH_USER, WP_AUTH_PASS

# 安全頭標檢測項目
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

def is_valid_wp_version(ver_str: str) -> bool:
    """驗證是否為有效的 WordPress 核心版本號"""
    if not ver_str or ver_str in ["Unknown", "未公開揭露"]:
        return False
    if re.match(r'^[5-9]\.\d+(\.\d+)?$', ver_str):
        return True
    return False

def check_wp_cve(version: str) -> List[Dict[str, str]]:
    """比對 WordPress 核心版本已知 CVE 漏洞資料庫"""
    cve_hits = []
    if not is_valid_wp_version(version):
        return cve_hits
        
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:wordpress:wordpress:{urllib.parse.quote(version)}:*:*:*:*:*:*:*"
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
                    "desc": f"WordPress 核心 ({version}) 命中 NVD CVE: {desc_text[:120]}...",
                    "severity": "High"
                })
    except Exception:
        v_parts = version.split('.')
        try:
            major = float(f"{v_parts[0]}.{v_parts[1]}")
            if major < 6.4:
                cve_hits.append({
                    "id": "CVE-2023-5561 / CVE-2023-38000",
                    "desc": f"WordPress 核心 ({version}) 為舊版本: 存在未授權資訊洩漏與遠端程式碼執行 (RCE) 已知高風險漏洞",
                    "severity": "Critical"
                })
        except Exception:
            pass

    return cve_hits

def check_php_cve(version: str) -> List[Dict[str, str]]:
    """比對 PHP 版本已知 CVE 與安全版本要求"""
    cve_hits = []
    if not version or version in ["Unknown", "未公開揭露"]:
        return cve_hits
        
    try:
        v_parts = version.split('.')
        if len(v_parts) >= 2:
            major = int(v_parts[0])
            minor = int(v_parts[1])
            patch = int(v_parts[2]) if len(v_parts) >= 3 else 0
            
            # 比對資訊部 Tenable/Nessus Nessus Plugin ID 313114 & 324980 (PHP 8.3.x < 8.3.31 / 8.3.32)
            if major == 8 and minor == 3:
                if patch < 31:
                    cve_hits.append({
                        "id": "CVE-2025-14179 / CVE-2026-6722 / CVE-2026-7258",
                        "desc": f"PHP {version} (低於 8.3.31/8.3.32): 存在多重 Critical/High 漏洞，包含記憶體溢位與非預期行為，請升級至 PHP 8.3.32+",
                        "severity": "Critical"
                    })
                elif patch < 32:
                    cve_hits.append({
                        "id": "CVE-2026-12184 / CVE-2026-14355",
                        "desc": f"PHP {version} (低於 8.3.32): 存在 Medium 漏洞風險，建議升級至 PHP 8.3.32+",
                        "severity": "Medium"
                    })
            elif major == 7 or major == 5:
                cve_hits.append({
                    "id": "CVE-2024-4577 / CVE-2023-3824 (PHP EOL 警示)",
                    "desc": f"PHP {version} 已停止官方安全更新 (EOL)。存在 CGI 引數注入與緩衝區溢位嚴重漏洞！",
                    "severity": "Critical"
                })
            elif major == 8 and minor in [0, 1, 2]:
                cve_hits.append({
                    "id": "CVE-2024-2756 (PHP 舊版 8.x 警示)",
                    "desc": f"PHP {version} 建議升級至最新的 PHP 8.3.32+ 以維持資安修補狀態。",
                    "severity": "High"
                })
    except Exception:
        pass
        
    return cve_hits

def probe_php_via_active_fingerprinting(base_url: str, context: ssl.SSLContext) -> str:
    """
    無需帳密：透過資安掃描器常見的無損 Active Fingerprinting (如 PHP 專屬 Easter Egg 與網頁回應表頭特徵) 獲取精確 PHP 版本
    """
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PortwellSecurityBot/1.0"}
    
    # 1. 探測傳統 PHP Easter Egg 頁面 (Nessus/Nikto 常用手法，如 ?=PHPE9568F36-D428-11d2-A769-00AA001ACF42)
    easter_eggs = [
        "?=PHPE9568F36-D428-11d2-A769-00AA001ACF42", # PHP Credits
        "?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000"  # PHP Logo
    ]
    for egg in easter_eggs:
        try:
            egg_url = base_url.rstrip('/') + '/' + egg
            req = urllib.request.Request(egg_url, headers=headers)
            with urllib.request.urlopen(req, timeout=4, context=context) as resp:
                resp_headers = dict(resp.info())
                x_powered = resp_headers.get("X-Powered-By") or resp_headers.get("x-powered-by") or ""
                server_hdr = resp_headers.get("Server") or resp_headers.get("server") or ""
                
                php_match = re.search(r'PHP/([\d\.]+)', x_powered + " " + server_hdr, re.IGNORECASE)
                if php_match:
                    return php_match.group(1)
        except Exception:
            pass

    # 2. 探測常見的預設路徑或組件釋出的 Header
    try:
        req = urllib.request.Request(base_url, headers=headers)
        with urllib.request.urlopen(req, timeout=5, context=context) as resp:
            resp_headers = dict(resp.info())
            x_powered = resp_headers.get("X-Powered-By") or resp_headers.get("x-powered-by") or ""
            server_hdr = resp_headers.get("Server") or resp_headers.get("server") or ""
            
            php_match = re.search(r'PHP/([\d\.]+)', x_powered + " " + server_hdr, re.IGNORECASE)
            if php_match:
                return php_match.group(1)
    except Exception:
        pass

    return "Unknown"

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
        "manual_checks": ["MySQL/MariaDB 版本 (需內部 DB 存取確認)", "完整外掛/主題清單 (需後台確認)"]
    }
    
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PortwellSecurityBot/1.0"
    }

    # 主動探測 PHP 版本
    detected_php = probe_php_via_active_fingerprinting(url, context)
    if detected_php != "Unknown":
        result["php_version"] = detected_php
        result["evidence"].append(f"成功偵測到伺服器 PHP 版本: {result['php_version']}")

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

            # 2. 解析 HTML 中的 WP 核心版本
            html_bytes = response.read()
            html_text = html_bytes.decode('utf-8', errors='ignore')
            
            wp_gen_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([5-9]\.[\d\.]+)', html_text, re.IGNORECASE)
            if wp_gen_match:
                result["wp_version"] = wp_gen_match.group(1)
                result["evidence"].append(f"發現 WordPress 核心 Meta 標示: {result['wp_version']}")

            if not is_valid_wp_version(result["wp_version"]):
                embed_ver = re.search(r'wp-includes/js/wp-embed\.min\.js\?ver=([5-9]\.[\d\.]+)', html_text)
                block_ver = re.search(r'wp-includes/css/dist/block-library/style\.min\.css\?ver=([5-9]\.[\d\.]+)', html_text)
                if embed_ver:
                    result["wp_version"] = embed_ver.group(1)
                    result["evidence"].append(f"從 wp-embed 核心元件提取 WP 版本: {result['wp_version']}")
                elif block_ver:
                    result["wp_version"] = block_ver.group(1)
                    result["evidence"].append(f"從 block-library 核心元件提取 WP 版本: {result['wp_version']}")

            # 3. 解析外掛與主題
            plugin_ver_matches = re.findall(r'wp-content/plugins/([^/]+)/[^"\']+\?ver=([\d\.]+)', html_text)
            found_plugins = {}
            for p_name, p_ver in plugin_ver_matches:
                found_plugins[p_name] = p_ver
            
            plugins_found_plain = set(re.findall(r'wp-content/plugins/([^/\?\'"]+)', html_text))
            for p in plugins_found_plain:
                if p not in found_plugins:
                    found_plugins[p] = "已安裝"

            themes_found = set(re.findall(r'wp-content/themes/([^/\?\'"]+)', html_text))
            
            for p_name, p_ver in found_plugins.items():
                result["plugins_themes"].append(f"Plugin: {p_name} (v{p_ver})")
            for t in themes_found:
                result["plugins_themes"].append(f"Theme: {t}")

    except Exception as e:
        result["risk_level"] = "Unknown"
        result["evidence"].append(f"無法透過公開網路存取連線: {str(e)}")
        result["https_status"] = "連線失敗"

    # 4. CVE 漏洞比對
    if is_valid_wp_version(result["wp_version"]):
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
        result["manual_checks"].append("WordPress 核心版本 (前台已被隱蔽，建議後台確認)")
    if result["php_version"] == "Unknown":
        result["manual_checks"].append("PHP 版本 (WebServer 設有嚴格隱蔽，建議後台/主機確認)")

    return result

def run_all_inspections(sites: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    results = []
    for site in sites:
        results.append(check_site_security(site))
    return results
