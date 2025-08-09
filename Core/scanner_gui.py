import requests
from bs4 import BeautifulSoup
import gradio as gr
import re
import os
from datetime import datetime

def scan_csrf_and_sensitive_data(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")

        # --- CSRF Check ---
        forms = soup.find_all("form")
        forms_without_csrf = []
        for form in forms:
            if not form.find("input", {"name": "csrf"}) and not form.find("input", {"name": "__csrf"}):
                forms_without_csrf.append(str(form.get("action")))

        # --- Sensitive Data Exposure ---
        sensitive_items = []
        sensitive_keywords = ["password", "api_key", "token", "secret", "email"]
        for keyword in sensitive_keywords:
            found = re.findall(rf"{keyword}\s*=\s*['\"]?[a-zA-Z0-9_.@-]+['\"]?", response.text, re.IGNORECASE)
            sensitive_items.extend(found)

        # --- Vulnerability Summary ---
        vuln_summary = []
        if forms_without_csrf:
            vuln_summary.append("CSRF Token Missing")
        if sensitive_items:
            vuln_summary.append("Sensitive Data Exposed")
        if not vuln_summary:
            vuln_summary.append("No vulnerabilities detected")

        # --- Suggestions ---
        suggestions = []
        if forms_without_csrf:
            suggestions.append("Add CSRF token to all forms performing sensitive actions.")
        if sensitive_items:
            suggestions.append("Avoid exposing passwords, tokens, and email in HTML.")

        # --- Report ---
        report = f"--- Website Vulnerability Scan Report ---\nTarget URL: {url}\n\n"
        report += "[Vulnerability Summary]\n"
        report += "\n".join([f"  - {v}" for v in vuln_summary])
        report += "\n\n[+] CSRF Issues:\n"
        report += "\n".join([f"  - Form without CSRF token: {form}" for form in forms_without_csrf]) or "  - None found"
        report += "\n\n[+] Sensitive Data Exposed:\n"
        report += "\n".join([f"  - {item}" for item in sensitive_items]) or "  - None found"
        report += "\n\n[Suggestions]\n"
        report += "\n".join(suggestions) or "  - No issues found."
        report += f"\n\n[Scan Time]: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"

        # --- Save Report ---
        filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, "w") as f:
            f.write(report)

        return report, filename

    except Exception as e:
        return f"[ERROR] Failed to scan: {e}", None


def run_scanner(url):
    result, report_file = scan_csrf_and_sensitive_data(url)
    message = "✅ Scan completed." if report_file else "❌ Scan failed."
    download_link = f"Report saved to: {report_file}" if report_file else "No report file."
    return result + "\n\n" + message + "\n" + download_link


def main(url):
    result, report_file = scan_csrf_and_sensitive_data(url)
    print(result)
    if report_file:
        print(f"[+] Report saved to: {report_file}")
    else:
        print("[!] No report file generated.")


# --- Gradio UI ---
interface = gr.Interface(
    fn=run_scanner,
    inputs=gr.Textbox(label="Enter Website URL (e.g., http://testphp.vulnweb.com)"),
    outputs=gr.Textbox(label="Scan Result"),
    title="Website Vulnerability Scanner (CSRF & Sensitive Data)",
    description="Enter a website URL to scan for CSRF issues and sensitive data exposure. Generates a report with suggestions."
)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Website Vulnerability Scanner (CSRF & Sensitive Data)")
    parser.add_argument("--url", help="Target URL to scan (e.g., http://testphp.vulnweb.com)")
    parser.add_argument("--gui", action="store_true", help="Launch Gradio GUI")
    args = parser.parse_args()

    if args.gui:
        interface.launch()
    elif args.url:
        main(args.url)
    else:
        parser.print_help()
