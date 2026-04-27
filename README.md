# Sentinel WebScanner

`Sentinel WebScanner` is a Python-based web application security assessment tool for **authorized penetration testing**.  
It crawls a target domain, detects attack surfaces (URLs and forms), and runs practical vulnerability checks for:

- Reflected XSS
- Error-based SQL injection indicators
- Open redirect flaws
- Missing security headers

The project is designed for beginner-to-intermediate security engineers and portfolio demonstration.

## Why This Project

This repository demonstrates:

- Modular pentesting architecture
- Payload-driven security testing
- Threaded scanning for better performance
- Production-style logging and error handling
- JSON reporting for pipeline integration

## Features

- Clean CLI with `argparse`
- Domain-scoped crawler (URL + form discovery)
- Multi-module scanner engine
- Colored console findings with severity levels
- JSON report export (`reports/scan_report.json` by default)
- Safe defaults and non-destructive checks
- Docker support

## Project Structure

```text
sentinel-webscanner/
├── main.py
├── modules/
│   ├── __init__.py
│   ├── crawler.py
│   ├── headers_scanner.py
│   ├── open_redirect_scanner.py
│   ├── sqli_scanner.py
│   └── xss_scanner.py
├── payloads/
│   ├── redirect_payloads.txt
│   ├── sqli_payloads.txt
│   └── xss_payloads.txt
├── utils/
│   ├── __init__.py
│   ├── http_client.py
│   ├── logger.py
│   ├── output.py
│   └── payload_loader.py
├── examples/
│   ├── basic_scan_command.txt
│   └── sample_report.json
├── screenshots/
│   └── README.md
├── Dockerfile
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation

```bash
git clone https://github.com/<your-username>/sentinel-webscanner.git
cd sentinel-webscanner
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows PowerShell
pip install -r requirements.txt
```

## Usage

### Basic scan

```bash
python main.py -t "https://testphp.vulnweb.com/listproducts.php?cat=1"
```

### Run selected modules only

```bash
python main.py -t "https://example.com" -m "xss,sqli"
```

### Tune performance and output

```bash
python main.py -t "https://example.com" --depth 2 --threads 12 --timeout 10 -o reports/custom_report.json
```

### Disable TLS verification (lab only)

```bash
python main.py -t "https://self-signed.local" --insecure
```

## Docker Usage

```bash
docker build -t sentinel-webscanner .
docker run --rm sentinel-webscanner -t "https://example.com" --depth 1 --threads 8
```

## Output

1. Console output: colored, severity-tagged findings.
2. JSON output: structured report with metadata, summary, and full findings list.

Example JSON is available in `examples/sample_report.json`.

## Vulnerability Modules

- `xss`: Injects payloads into query parameters and form fields, checks reflected output in HTML responses.
- `sqli`: Injects SQLi payloads and detects DB error signatures in responses.
- `redirect`: Tests redirect-related parameters for external `Location` header redirection.
- `headers`: Audits common security headers and reports missing protections.

## Screenshots

Placeholders:

- `screenshots/cli-output.png` -> terminal output with findings
- `screenshots/json-report.png` -> JSON report preview
- `screenshots/docker-run.png` -> Docker execution sample

## Ethical Use Disclaimer

This tool is provided for educational purposes and **authorized security testing only**.  
Do not scan systems without explicit written permission.  
The author and contributors are not responsible for misuse or damage caused by this project.

## GitHub Optimization

Suggested repository description:

`Python web pentesting scanner with crawling, payload-based XSS/SQLi/open-redirect checks, security header auditing, and JSON reporting.`

Suggested topics/tags:

- `cybersecurity`
- `penetration-testing`
- `web-security`
- `python`
- `bug-bounty`
- `vulnerability-scanner`
- `xss`
- `sqli`
- `open-redirect`
- `security-automation`

