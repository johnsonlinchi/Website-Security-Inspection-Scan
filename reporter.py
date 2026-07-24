from datetime import datetime
from typing import List, Dict, Any

def generate_reports(inspection_results: List[Dict[str, Any]]) -> Dict[str, str]:
    scan_date = datetime.now().strftime("%Y-%m-%d")
    total_sites = len(inspection_results)
    
    # 統計漏洞與最高風險等級
    cve_hits_total = []
    risk_summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    
    for r in inspection_results:
        risk_summary[r["risk_level"]] += 1
        for hit in r.get("cve_hits", []):
            cve_hits_total.append({"site": r["site_name"], "hit": hit})

    overall_risk = "Low"
    if risk_summary["Critical"] > 0:
        overall_risk = "Critical"
    elif risk_summary["High"] > 0:
        overall_risk = "High"
    elif risk_summary["Medium"] > 0:
        overall_risk = "Medium"
    elif risk_summary["Unknown"] > 0:
        overall_risk = "Unknown"

    has_cve = len(cve_hits_total) > 0

    # 1. HTML 報告建構 (供 Gmail 寄送，包含明確有框線表格)
    html_lines = []
    html_lines.append("<!DOCTYPE html><html><head><meta charset='utf-8'></head><body style='font-family: Arial, sans-serif;'>")
    
    # CVE 警示區塊
    if has_cve:
        html_lines.append("<div style='background-color: #ffcccc; border: 2px solid #cc0000; padding: 12px; margin-bottom: 15px;'>")
        html_lines.append("<h2 style='color: #cc0000; margin-top:0;'>⚠️ [CVE/漏洞警示] 發現已知漏洞命中</h2>")
        html_lines.append("</div>")

    # 1. 執行摘要
    html_lines.append("<h2>1. 執行摘要</h2>")
    html_lines.append("<table border='1' cellpadding='6' cellspacing='0' style='border-collapse: collapse; border: 1px solid #999; width: 100%;'>")
    html_lines.append(f"<tr style='background-color: #f2f2f2;'><th align='left'>掃描時間</th><td>{scan_date}</td></tr>")
    html_lines.append(f"<tr><th align='left'>受測站台數量</th><td>{total_sites} 個架構站台 (國際站, 台灣站, AI站, 智利站, DC站)</td></tr>")
    html_lines.append(f"<tr style='background-color: #f2f2f2;'><th align='left'>整體風險狀態</th><td><strong>{overall_risk}</strong></td></tr>")
    html_lines.append("</table><br/>")

    # 2. CVE / 漏洞命中摘要
    html_lines.append("<h2>2. CVE / 漏洞命中摘要</h2>")
    html_lines.append("<table border='1' cellpadding='6' cellspacing='0' style='border-collapse: collapse; border: 1px solid #999; width: 100%;'>")
    html_lines.append("<tr style='background-color: #f2f2f2;'><th>站台</th><th>CVE / 漏洞公告號</th><th>漏洞描述與可信來源 (NVD/WPScan/Wordfence)</th></tr>")
    if has_cve:
        for hit in cve_hits_total:
            html_lines.append(f"<tr><td>{hit['site']}</td><td>{hit['hit'].get('id', 'N/A')}</td><td>{hit['hit'].get('desc', 'N/A')}</td></tr>")
    else:
        html_lines.append("<tr><td colspan='3' align='center'>未從公開資料確認 CVE / 已知漏洞命中</td></tr>")
    html_lines.append("</table><br/>")

    # 3. 高風險總覽
    html_lines.append("<h2>3. 高風險總覽</h2>")
    html_lines.append("<table border='1' cellpadding='6' cellspacing='0' style='border-collapse: collapse; border: 1px solid #999; width: 100%;'>")
    html_lines.append("<tr style='background-color: #f2f2f2;'><th>風險等級</th><th>數量</th><th>受影響站台</th></tr>")
    html_lines.append(f"<tr><td>Critical</td><td>{risk_summary['Critical']}</td><td>{', '.join([r['site_name'] for r in inspection_results if r['risk_level'] == 'Critical']) or '無'}</td></tr>")
    html_lines.append(f"<tr><td>High</td><td>{risk_summary['High']}</td><td>{', '.join([r['site_name'] for r in inspection_results if r['risk_level'] == 'High']) or '無'}</td></tr>")
    html_lines.append("</table><br/>")

    # 4. 逐站結果表
    html_lines.append("<h2>4. 逐站結果表</h2>")
    html_lines.append("<table border='1' cellpadding='6' cellspacing='0' style='border-collapse: collapse; border: 1px solid #999; width: 100%;'>")
    html_lines.append("<tr style='background-color: #f2f2f2;'><th>站台</th><th>WP 核心</th><th>PHP</th><th>SQL/資料庫</th><th>外掛/佈景主題</th><th>安全標頭/HTTPS</th><th>CVE/漏洞命中</th><th>風險等級</th><th>證據</th></tr>")
    for r in inspection_results:
        plugins_str = "<br/>".join(r["plugins_themes"]) if r["plugins_themes"] else "公開未直接暴露"
        evidence_str = "<br/>".join(r["evidence"]) if r["evidence"] else "良好"
        cve_str = "有" if r["cve_hits"] else "無"
        html_lines.append(f"<tr><td><strong>{r['site_name']}</strong><br/>{r['url']}</td><td>{r['wp_version']}</td><td>{r['php_version']}</td><td>{r['sql_version']}</td><td>{plugins_str}</td><td>{r['https_status']}</td><td>{cve_str}</td><td>{r['risk_level']}</td><td>{evidence_str}</td></tr>")
    html_lines.append("</table><br/>")

    # 5. 詳細發現
    html_lines.append("<h2>5. 詳細發現與依據</h2>")
    html_lines.append("<table border='1' cellpadding='6' cellspacing='0' style='border-collapse: collapse; border: 1px solid #999; width: 100%;'>")
    html_lines.append("<tr style='background-color: #f2f2f2;'><th>站台</th><th>項目</th><th>判斷依據與安全建議</th></tr>")
    for r in inspection_results:
        for ev in r["evidence"]:
            html_lines.append(f"<tr><td>{r['site_name']}</td><td>系統安全設定</td><td>{ev}。建議補充相關 HTTP Header 或進行版本隱藏。</td></tr>")
    html_lines.append("</table><br/>")

    # 6. 人工確認清單
    html_lines.append("<h2>6. 人工確認清單 (維運端建議)</h2>")
    html_lines.append("<table border='1' cellpadding='6' cellspacing='0' style='border-collapse: collapse; border: 1px solid #999; width: 100%;'>")
    html_lines.append("<tr style='background-color: #f2f2f2;'><th>站台</th><th>公開無法確認但應由維運檢查之項目</th></tr>")
    for r in inspection_results:
        checks_str = "<br/>".join([f"• {c}" for c in r["manual_checks"]])
        html_lines.append(f"<tr><td>{r['site_name']}</td><td>{checks_str}</td></tr>")
    html_lines.append("</table><br/>")

    # 7. 修補待辦清單
    html_lines.append("<h2>7. 修補待辦清單 (Sort by Risk)</h2>")
    html_lines.append("<table border='1' cellpadding='6' cellspacing='0' style='border-collapse: collapse; border: 1px solid #999; width: 100%;'>")
    html_lines.append("<tr style='background-color: #f2f2f2;'><th>優先權</th><th>站台</th><th>建議修補/硬化動作</th></tr>")
    html_lines.append("<tr><td>1. Medium / Low</td><td>全站台</td><td>設定 HTTP Strict-Transport-Security, CSP 與 X-Frame-Options 標頭。</td></tr>")
    html_lines.append("<tr><td>2. Regular</td><td>全站台</td><td>定期由內部維運團隊核對 PHP 與 MySQL/MariaDB 是否符合最新 EOL 安全規範。</td></tr>")
    html_lines.append("</table>")

    html_lines.append("<br/><p style='color: #666; font-size: 12px;'>本郵件由 AI Portwell 自動化巡檢排程系統產生，僅限指定收件人 39620@portwell.com.tw 參閱。</p>")
    html_lines.append("</body></html>")

    html_report = "\n".join(html_lines)

    # 2. Markdown 報告建構 (供控制台輸出)
    md_lines = []
    md_lines.append(f"# Portwell 站台版本與漏洞風險報告 ({scan_date})\n")
    md_lines.append("## 1. 執行摘要\n")
    md_lines.append(f"| 項目 | 內容 |")
    md_lines.append(f"|---|---|")
    md_lines.append(f"| 掃描時間 | {scan_date} |")
    md_lines.append(f"| 掃描站台數 | {total_sites} |")
    md_lines.append(f"| 整體風險 | {overall_risk} |\n")
    
    md_lines.append("## 2. CVE/漏洞命中摘要\n")
    if has_cve:
        md_lines.append("| 站台 | CVE / 漏洞號 | 說明 |")
        md_lines.append("|---|---|---|")
        for hit in cve_hits_total:
            md_lines.append(f"| {hit['site']} | {hit['hit'].get('id')} | {hit['hit'].get('desc')} |")
    else:
        md_lines.append("> **未從公開資料確認 CVE/已知漏洞命中**\n")

    md_report = "\n".join(md_lines)

    return {
        "html": html_report,
        "markdown": md_report,
        "has_cve": has_cve,
        "date": scan_date
    }
