import sys
import time
from config import SITES, ALLOWED_RECIPIENT
from inspector import run_all_inspections
from reporter import generate_reports
from mailer import send_inspection_email

def run_routine_inspection(target_recipient: str = ALLOWED_RECIPIENT):
    print("=" * 60)
    print("[START] 啟動 Portwell WordPress 站台安全巡檢作業")
    print("固定巡檢 5 個目標站台:")
    for s in SITES:
        print(f" - {s['name']}: {s['url']}")
    print("=" * 60)

    # 1. 執行被動式安全檢測
    print("\n[1/3] 執行網址版本與安全標頭檢查中...")
    inspection_results = run_all_inspections(SITES)
    
    # 2. 產出報告
    print("[2/3] 產生巡檢報告 (7 大區塊 & HTML 有框線表格)...")
    reports = generate_reports(inspection_results)
    
    # 控制台輸出 Markdown 摘要
    print("\n" + reports["markdown"] + "\n")

    # 3. 寄送郵件 (帶入安全邊界檢查)
    print(f"[3/3] 準備發送報告郵件至 {target_recipient}...")
    success = send_inspection_email(target_recipient, reports)
    
    if success:
        print("[SUCCESS] 巡檢作業與郵件寄送流程完成！")
    else:
        print("[FAILED] 巡檢作業完成，但郵件寄送失敗或被攔截。")

if __name__ == "__main__":
    recipient_arg = sys.argv[1] if len(sys.argv) > 1 else ALLOWED_RECIPIENT
    run_routine_inspection(recipient_arg)
