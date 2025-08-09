# HexaScan

HexaScan is a unified web vulnerability scanner that automates the detection of common web application security issues, including:

- Cross-Site Scripting (XSS)
- SQL Injection (SQLi)
- Broken Authentication
- Session Management
- Insecure Direct Object References (IDOR)
- CSRF & Sensitive Data Exposure

## Features
- Modular scanning: Each vulnerability type is handled by a dedicated module.
- Password brute-force using common password lists.
- Generates detailed reports for each scan in the `reports` directory.
- Command-line interface for easy automation.

## Requirements
- Python 3.8+
- Install dependencies:
  ```bash
  pip install -r requirements.txt
  ```
  (Typical dependencies: `requests`, `beautifulsoup4`, `gradio`)

## Usage

From the `Core` directory, run:

```bash
python main_scanner.py --url <target_url> [--password-dir <password_payload_dir>]
```

- `--url` (required): The target URL to scan (e.g., `http://testphp.vulnweb.com/listproducts.php?cat=1`)
- `--password-dir` (optional): Directory containing password `.txt` files for brute-force (default: `/Payloads/Broken_Auth`)

### Example
```bash
python main_scanner.py --url http://testphp.vulnweb.com/listproducts.php?cat=1 --password-dir ../Payloads/Broken_Auth
```

## Output
- All scan reports are saved in the `Core/reports/` directory.
- Each scan module generates its own report file (JSON or TXT).
- A summary table is printed at the end of each run.

## Project Structure
```
HexaScan/
  Core/
    main_scanner.py
    final2.py
    Sqli.py
    Xss.py
    scanner_gui.py
    reports/
  Payloads/
    Broken_Auth/
    Sql_payload/
    XSS_payload/
```

## Adding/Updating Payloads
- Place new password lists in `Payloads/Broken_Auth/`.
- Place new SQLi payloads in `Payloads/Sql_payload/`.
- Place new XSS payloads in `Payloads/XSS_payload/`.


