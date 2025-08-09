import os
import sys
import json
from datetime import datetime

# Import scan functions from other scripts
from Xss import scan_xss
from Sqli import scan_sqli
from final2 import run_scan
from scanner_gui import scan_csrf_and_sensitive_data

def ensure_reports_folder():
    reports_dir = os.path.join(os.path.dirname(__file__), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    return reports_dir

def run_all_scans(url, password_dir=None):
    reports_dir = ensure_reports_folder()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    summary = []

    # XSS Scan
    try:
        print("\n[=] Running XSS scan...")
        xss_report_path = os.path.join(reports_dir, f"xss_report_{timestamp}.json")
        scan_xss(url)
        # Move/rename result file if exists
        if os.path.exists("xss_results.json"):
            os.replace("xss_results.json", xss_report_path)
            summary.append(("XSS", "Completed", xss_report_path))
        else:
            summary.append(("XSS", "No results file", "-"))
    except Exception as e:
        summary.append(("XSS", f"Error: {e}", "-"))

    # SQLi Scan
    try:
        print("\n[=] Running SQL Injection scan...")
        sqli_report_path = os.path.join(reports_dir, f"sqli_report_{timestamp}.json")
        scan_sqli(url)
        if os.path.exists("sqli_results.json"):
            os.replace("sqli_results.json", sqli_report_path)
            summary.append(("SQLi", "Completed", sqli_report_path))
        else:
            summary.append(("SQLi", "No results file", "-"))
    except Exception as e:
        summary.append(("SQLi", f"Error: {e}", "-"))

    # Auth/Session/IDOR Scan
    try:
        print("\n[=] Running Auth/Session/IDOR scan...")
        final2_report_path = os.path.join(reports_dir, f"final2_report_{timestamp}.txt")
        # run_scan prints to stdout, so capture output
        from io import StringIO
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        if password_dir:
            run_scan(url, password_directory=password_dir)
        else:
            run_scan(url)
        sys.stdout = old_stdout
        with open(final2_report_path, "w", encoding="utf-8") as f:
            f.write(mystdout.getvalue())
        summary.append(("Auth/Session/IDOR", "Completed", final2_report_path))
    except Exception as e:
        summary.append(("Auth/Session/IDOR", f"Error: {e}", "-"))

    # CSRF & Sensitive Data Scan
    try:
        print("\n[=] Running CSRF & Sensitive Data scan...")
        csrf_report_path = os.path.join(reports_dir, f"csrf_sensitive_report_{timestamp}.txt")
        report, _ = scan_csrf_and_sensitive_data(url)
        with open(csrf_report_path, "w", encoding="utf-8") as f:
            f.write(report)
        summary.append(("CSRF/Sensitive Data", "Completed", csrf_report_path))
    except Exception as e:
        summary.append(("CSRF/Sensitive Data", f"Error: {e}", "-"))

    # Print summary table
    print("\n=== Scan Summary ===")
    print(f"{'Scan':<25} {'Status':<20} {'Report File'}")
    print("-" * 70)
    for scan, status, path in summary:
        print(f"{scan:<25} {status:<20} {path}")
    print("-" * 70)
    print(f"All reports are saved in: {reports_dir}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Unified Web Vulnerability Scanner")
    parser.add_argument("--url", required=True, help="Target URL (e.g., http://testphp.vulnweb.com/listproducts.php?cat=1)")
    parser.add_argument("--password-dir", help="Directory for password payloads (for final2.py)")
    args = parser.parse_args()

    run_all_scans(args.url, password_dir=args.password_dir)
