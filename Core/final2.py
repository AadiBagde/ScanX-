import requests
from bs4 import BeautifulSoup
import os
from urllib.parse import urljoin
import json
import argparse

# Global variables
SESSION = requests.Session()
VULNERABILITIES = {
    "IDOR": [],
    "Broken_Authentication": [],
    "Session_Management": []
}


def load_password_files(directory):
    """
    Loads passwords from the 6 most relevant .txt files in the given directory.
    Returns a set of unique passwords.
    """
    relevant_files = [
        "500-worst-passwords.txt",
        "best1050.txt",
        "best110.txt",
        "common-passwords.txt",
        "common-passwords-win.txt",
        "2023-200_most_used_passwords.txt",
        "2020-200_most_used_passwords.txt"
    ]
    password_set = set()
    for filename in relevant_files:
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                    for line in file:
                        password = line.strip()
                        if password:
                            password_set.add(password)
            except Exception as e:
                print(f"Error reading file {filename}: {e}")
        else:
            print(f"[*] Skipping missing payload file: {filename}")
    return password_set


def test_broken_authentication(base_url, password_directory=None):
    """
    Tests for broken authentication using passwords from payload files.
    """
    print("\n[+] Testing for Broken Authentication...")

    if password_directory and os.path.isdir(password_directory):
        print(f"[*] Loading passwords from {password_directory}")
        test_passwords = load_password_files(password_directory)
    else:
        print("[*] Using default password list")
        test_passwords = {"password", "123456", "admin", "letmein", "admin123", "juiceshop"}

    register_url = urljoin(base_url, "/api/Users/")
    headers = {"Content-Type": "application/json"}

    for pwd in list(test_passwords)[:50]:  # Limit for demo/intermediate level
        print(f"[*] Testing password: {pwd}")
        data = {
            "email": f"test{pwd}@example.com",
            "password": pwd,
            "passwordRepeat": pwd,
            "securityQuestion": {
                "id": 2,
                "question": "Mother's maiden name?",
                "createdAt": "2023-01-01",
                "updatedAt": "2023-01-01"
            },
            "securityAnswer": "test"
        }
        try:
            response = SESSION.post(register_url, json=data, headers=headers, timeout=10)
            if response.status_code == 201:
                VULNERABILITIES["Broken_Authentication"].append(
                    f"Weak password '{pwd}' accepted during registration")
                print(f"[!] Weak password '{pwd}' was accepted during registration")
        except requests.exceptions.Timeout:
            print(f"[!] Timeout testing password '{pwd}'")
        except requests.exceptions.ConnectionError as e:
            print(f"[!] Connection error testing password '{pwd}': {str(e)}")
        except Exception as e:
            print(f"[!] Error testing password '{pwd}': {str(e)}")

    login_api_url = urljoin(base_url, "/rest/user/login")
    invalid_creds = [
        {"email": "admin@juice-sh.op", "password": "invalid"},
        {"email": "nonexistent@example.com", "password": "password"}
    ]

    for pwd in list(test_passwords)[:5]:
        invalid_creds.append({"email": "admin@juice-sh.op", "password": pwd})

    for creds in invalid_creds:
        try:
            response = SESSION.post(login_api_url, json=creds, timeout=10)
            if response.status_code == 200 and "authentication" in response.text:
                VULNERABILITIES["Broken_Authentication"].append(
                    f"Login allowed with invalid credentials: {creds['email']}/{creds['password']}")
                print(f"[!] Login allowed with invalid credentials: {creds['email']}/{creds['password']}")
        except requests.exceptions.Timeout:
            print(f"[!] Timeout testing credentials {creds['email']}")
        except requests.exceptions.ConnectionError as e:
            print(f"[!] Connection error testing credentials {creds['email']}: {str(e)}")
        except Exception as e:
            print(f"[!] Error testing credentials {creds['email']}: {str(e)}")


def test_idor(base_url):
    print("\n[+] Testing for IDOR vulnerabilities...")
    login_url = urljoin(base_url, "/rest/user/login")
    creds = {"email": "admin@juice-sh.op", "password": "admin123"}
    try:
        response = SESSION.post(login_url, json=creds, timeout=10)
    except requests.exceptions.Timeout:
        print("[!] Timeout during IDOR login")
        return
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection error during IDOR login: {str(e)}")
        return
    except Exception as e:
        print(f"[!] Error during IDOR login: {str(e)}")
        return
    if response.status_code != 200:
        print("[!] Failed to login for IDOR test")
        return
    token = None
    try:
        if response.headers.get('Content-Type', '').startswith('application/json'):
            token = response.json().get("authentication", {}).get("token")
    except Exception:
        token = None
    if not token:
        print("[!] No token received for IDOR test")
        return
    SESSION.headers.update({"Authorization": f"Bearer {token}"})
    base_id = 1
    for test_id in range(base_id, base_id + 5):
        url = urljoin(base_url, f"/api/User/{test_id}")
        try:
            resp = SESSION.get(url, timeout=10)
            if resp.status_code == 200 and test_id != base_id:
                VULNERABILITIES["IDOR"].append(f"Accessed Basket/{test_id} without authorization")
                print(f"[!] IDOR found: Accessed Basket/{test_id} without authorization")
        except requests.exceptions.Timeout:
            print(f"[!] Timeout accessing Basket/{test_id}")
        except requests.exceptions.ConnectionError as e:
            print(f"[!] Connection error accessing Basket/{test_id}: {str(e)}")
        except Exception as e:
            print(f"[!] Error accessing Basket/{test_id}: {e}")


def test_session_management(base_url):
    print("\n[+] Testing for Session Management issues...")

    login_url = urljoin(base_url, "/rest/user/login")
    creds = {"email": "admin@juice-sh.op", "password": "admin123"}
    try:
        response = SESSION.post(login_url, json=creds, timeout=10)
    except requests.exceptions.Timeout:
        print("[!] Timeout during session management login")
        return
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection error during session management login: {str(e)}")
        return
    except Exception as e:
        print(f"[!] Error during session management login: {str(e)}")
        return

    cookies = SESSION.cookies
    for cookie in cookies:
        if 'token' in cookie.name.lower():
            if not cookie.secure:
                VULNERABILITIES["Session_Management"].append(f"Cookie '{cookie.name}' not marked as Secure")
                print(f"[!] Cookie '{cookie.name}' not marked as Secure")
            if not cookie.has_nonstandard_attr('HttpOnly'):
                VULNERABILITIES["Session_Management"].append(f"Cookie '{cookie.name}' not marked as HttpOnly")
                print(f"[!] Cookie '{cookie.name}' not marked as HttpOnly")

    print("[*] Manual check needed for session timeout behavior")


def test_token_reuse_after_logout(base_url):
    print("\n[*] Testing session reuse after logout...")

    login_url = urljoin(base_url, "/rest/user/login")
    whoami_url = urljoin(base_url, "/rest/user/whoami")
    logout_url = urljoin(base_url, "/rest/user/logout")

    creds = {"email": "admin@juice-sh.op", "password": "admin123"}
    try:
        resp = SESSION.post(login_url, json=creds, timeout=10)
    except requests.exceptions.Timeout:
        print("[!] Timeout during session reuse login")
        return
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection error during session reuse login: {str(e)}")
        return
    except Exception as e:
        print(f"[!] Error during session reuse login: {str(e)}")
        return
    token = None
    try:
        if resp.headers.get('Content-Type', '').startswith('application/json'):
            token = resp.json().get("authentication", {}).get("token")
    except Exception:
        token = None
    if not token:
        print("[!] Failed to extract token for session test.")
        return
    SESSION.headers.update({"Authorization": f"Bearer {token}"})
    try:
        SESSION.get(logout_url, timeout=10)
        whoami_after = SESSION.get(whoami_url, timeout=10)
    except requests.exceptions.Timeout:
        print("[!] Timeout during session reuse check")
        return
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection error during session reuse check: {str(e)}")
        return
    except Exception as e:
        print(f"[!] Error during session reuse check: {str(e)}")
        return
    if whoami_after.status_code == 200:
        VULNERABILITIES["Session_Management"].append("Token still valid after logout")
        print("[!] Token still valid after logout")
    else:
        print("[+] Token invalidated correctly after logout")


def print_results():
    print("\n[+] Scan completed. Vulnerability summary:")
    for vuln_type, findings in VULNERABILITIES.items():
        print(f"\n--- {vuln_type} ---")
        if findings:
            for finding in findings:
                print(f" - {finding}")
        else:
            print("No vulnerabilities found")


def run_scan(base_url, password_directory=None):
    """
    Runs all vulnerability tests.
    """
    print(f"[*] Starting vulnerability scan for {base_url}")
    print("[>] Running test_broken_authentication...")
    try:
        test_broken_authentication(base_url, password_directory)
    except Exception as e:
        print(f"[!] Exception in test_broken_authentication: {str(e)}")
    print("[>] Running test_session_management...")
    try:
        test_session_management(base_url)
    except Exception as e:
        print(f"[!] Exception in test_session_management: {str(e)}")
    print("[>] Running test_token_reuse_after_logout...")
    try:
        test_token_reuse_after_logout(base_url)
    except Exception as e:
        print(f"[!] Exception in test_token_reuse_after_logout: {str(e)}")
    print("[>] Running test_idor...")
    try:
        test_idor(base_url)
    except Exception as e:
        print(f"[!] Exception in test_idor: {str(e)}")
    print_results()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HexaScan Auth/Session/IDOR Scanner")
    parser.add_argument(
        "--url",
        required=True,
        help="Base URL of the target application (e.g. https://juice-shop.herokuapp.com)"
    )
    parser.add_argument(
        "--password-dir",
        default=os.path.join("..", "Payloads", "Broken_Auth"),
        help="Directory containing password payload files"
    )
    args = parser.parse_args()

    password_dir = args.password_dir
    base_url = args.url
    if not base_url:
        print("[!] You must specify a --url argument.")
        parser.print_help()
        exit(1)
    if os.path.isdir(password_dir):
        run_scan(base_url, password_directory=password_dir)
    else:
        print(f"[!] Password directory '{password_dir}' not found, using default passwords")
        run_scan(base_url)
