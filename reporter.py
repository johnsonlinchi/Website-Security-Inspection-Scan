from datetime import datetime
from typing import List, Dict, Any

def generate_reports(inspection_results: List[Dict[str, Any]]) -> Dict[str, str]:
    scan_date = datetime.now().strftime("%Y-%m-%d")
    total_sites = len(inspection_results)
    
    # 統計「正常、需更新、需人工檢查」三種狀態
    status_summary = {"正常": 0, "需更新": 0, "需人工檢查": 0}
    for r in inspection_results:
        st = r.get("status", "正常")
        if st in status_summary:
            status_summary[st] += 1

    # 1. HTML 報告建構 (包含邊框表格與三種狀態劃分)
    html_lines = []
    html_lines.append("<!DOCTYPE html><html><head><meta charset='utf-8'></head><body style='font-family: Arial, sans-serif;'>")
    
    html_lines.append("<h2>1. 執行摘要 (Date: " + scan_date + ")</h2>")
    html_lines.append("<table border='1' cellpadding='6' cellspacing='0' style='border-collapse: collapse; border: 1px solid #999; width: 100%;'>")
    html_lines.append(f"<tr style='background-color: #f2f2f2;'><th>總盤點站台數</th><th>正常</th><th>需更新 (標頭/版本)</th><th>需人工檢查</th></tr>")
    html_lines.append(f"<tr><td>{total_sites}</td><td style='color:green; font-weight:bold;'>{status_summary['正常']}</td><td style='color:orange; font-weight:bold;'>{status_summary['需更新']}</td><td style='color:red; font-weight:bold;'>{status_summary['需人工檢查']}</td></tr>")
    html_lines.append("</table><br/>")

    html_lines.append("<h2>2. 逐站資產與維運盤點結果表</h2>")
    html_lines.append("<table border='1' cellpadding='6' cellspacing='0' style='border-collapse: collapse; border: 1px solid #999; width: 100%;'>")
    html_lines.append("<tr style='background-color: #f2f2f2;'><th>站台</th><th>狀態分類</th><th>WP 核心</th><th>PHP 環境</th><th>主要外掛/主題</th><th>維運警告與人工確認事項</th></tr>")
    
    for r in inspection_results:
        st = r["status"]
        st_color = "green" if st == "正常" else ("orange" if st == "需更新" else "red")
        
        plugins_list = [f"• {p} (v{v})" for p, v in r["plugins"].items()]
        plugins_str = "<br/>".join(plugins_list) if plugins_list else "前台無顯式暴露版號"
        
        notes = r["warnings"] + r["manual_checks"]
        notes_str = "<br/>".join(notes) if notes else "良好"

        html_lines.append(f"<tr>")
        html_lines.append(f"<td><strong>{r['name']}</strong><br/>{r['url']}</td>")
        html_lines.append(f"<td style='color:{st_color}; font-weight:bold;'>{st}</td>")
        html_lines.append(f"<td>{r['wp_version']}</td>")
        html_lines.append(f"<td>{r['php_version']}</td>")
        html_lines.append(f"<td>{plugins_str}</td>")
        html_lines.append(f"<td>{notes_str}</td>")
        html_lines.append(f"</tr>")
        
    html_lines.append("</table>")
    html_lines.append("<br/><p style='color: #666; font-size: 12px;'>本郵件由 Portwell Python 自動化資產盤點與維運監控系統產出。</p>")
    html_lines.append("</body></html>")

    html_report = "\n".join(html_lines)

    # 2. Markdown 控制台輸出
    md_lines = []
    md_lines.append(f"# Portwell 站台資產與維運盤點報告 ({scan_date})\n")
    md_lines.append(f"| 總站台數 | 正常 | 需更新 | 需人工檢查 |")
    md_lines.append(f"|---|---|---|---|")
    md_lines.append(f"| {total_sites} | {status_summary['正常']} | {status_summary['需更新']} | {status_summary['需人工檢查']} |\n")

    md_report = "\n".join(md_lines)

    return {
        "html": html_report,
        "markdown": md_report,
        "date": scan_date,
        "status_summary": status_summary
    }
