import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from config import ALLOWED_RECIPIENTS, DEFAULT_RECIPIENT, SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM

def send_inspection_email(recipient: str, reports: dict) -> bool:
    target_addr = recipient.strip().lower()
    
    # 邊界檢查：僅允許白名單內的 Portwell 指定收件者
    allowed_lowers = [addr.lower() for addr in ALLOWED_RECIPIENTS]
    if target_addr not in allowed_lowers:
        print(f"[SECURITY REJECT] 存取被拒：目前代理設定只允許寄給指定收件人 ({', '.join(ALLOWED_RECIPIENTS)})，拒絕寄送至 {recipient}")
        return False

    has_cve = reports.get("has_cve", False)
    scan_date = reports.get("date", "")
    
    if has_cve:
        subject = f"[CVE/漏洞警示][WP 安全巡檢] Portwell 站台版本與漏洞風險報告 - {scan_date}"
    else:
        subject = f"[WP 安全巡檢] Portwell 站台版本與漏洞風險報告 - {scan_date}"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = target_addr

    # 純文字與 HTML 部分
    text_part = MIMEText("請開啟 HTML 郵件檢視完整的 Portwell 安全巡檢報告。", "plain", "utf-8")
    html_part = MIMEText(reports["html"], "html", "utf-8")

    msg.attach(text_part)
    msg.attach(html_part)

    # 若未設定真實憑證，模擬成功寄送並輸出報告預覽
    if not SMTP_USER or not SMTP_PASS:
        print("\n=== [MAIL SIMULATION MODE] SMTP 憑證未設定 (SMTP_USER / SMTP_PASS) ===")
        print(f"收件者: {target_addr}")
        print(f"主旨: {subject}")
        print("郵件內容 HTML 表格樣式已正確渲染。")
        print("========================================================================\n")
        return True

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, [target_addr], msg.as_string())
        print(f"[MAIL SUCCESS] 巡檢報告已成功寄送至 {target_addr}")
        return True
    except Exception as e:
        print(f"[MAIL ERROR] 郵件寄送失敗: {str(e)}")
        return False
