import requests
import ssl
import socket
import time
from urllib.parse import urlparse
from http.cookies import SimpleCookie
from datetime import datetime

VULN_DB = {
    "X-Powered-By": "Leaking server technology info can aid attackers.",
    "Server": "Leaking server info can expose software versions and vulnerabilities.",
    "Access-Control-Allow-Origin:*": "Wildcard CORS header can expose APIs to all origins, leading to data theft.",
}

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Helps prevent XSS attacks by controlling resource loading.",
        "severity": "High",
        "fix": "Add Content-Security-Policy with strict directives."
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks by restricting framing.",
        "severity": "Medium",
        "fix": "Set X-Frame-Options: DENY or SAMEORIGIN."
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-sniffing attacks.",
        "severity": "High",
        "fix": "Set X-Content-Type-Options: nosniff."
    },
    "Strict-Transport-Security": {
        "description": "Forces HTTPS connections.",
        "severity": "High",
        "fix": "Set Strict-Transport-Security: max-age=31536000; includeSubDomains."
    },
    "Referrer-Policy": {
        "description": "Controls amount of referrer info sent.",
        "severity": "Medium",
        "fix": "Set Referrer-Policy: no-referrer."
    },
    "Permissions-Policy": {
        "description": "Restricts powerful browser features.",
        "severity": "Medium",
        "fix": "Set Permissions-Policy with restrictive values."
    },
    "Cache-Control": {
        "description": "Prevents caching of sensitive data.",
        "severity": "Low",
        "fix": "Set Cache-Control: no-store, no-cache, must-revalidate."
    },
    "Access-Control-Allow-Origin": {
        "description": "Controls CORS for cross-origin requests.",
        "severity": "Medium",
        "fix": "Configure Access-Control-Allow-Origin appropriately."
    }
}

def save_report(report_lines):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{timestamp}.txt"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            for line in report_lines:
                f.write(line + "\n")
        print(f"\n[+] Report saved to {filename}")
    except Exception as e:
        print(f"[!] Failed to save report: {e}")

def get_ssl_info(hostname):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    conn.settimeout(3)
    try:
        conn.connect((hostname, 443))
        cert = conn.getpeercert()
        tls_version = conn.version()
        conn.close()
        return cert, tls_version
    except Exception:
        return None, None

def analyze_cors(cors_value, credentials_allowed=False):
    if cors_value == "*":
        return True, "Wildcard '*' is dangerous: allows all origins."
    if credentials_allowed and cors_value == "*":
        return True, "Wildcard '*' cannot be used with Access-Control-Allow-Credentials: true."
    return False, ""

def check_cookies(response, report):
    cookies = response.headers.getlist('Set-Cookie') if hasattr(response.headers, 'getlist') else [response.headers.get('Set-Cookie')]
    if not cookies or cookies == [None]:
        report.append("[*] No Set-Cookie headers found.")
        return
    report.append("[*] Analyzing cookies:")
    for cookie_str in cookies:
        if not cookie_str:
            continue
        cookie = SimpleCookie()
        cookie.load(cookie_str)
        for key, morsel in cookie.items():
            flags = []
            if morsel['secure']:
                flags.append("Secure")
            else:
                report.append(f"  [!] Cookie '{key}' missing Secure flag.")
            if morsel['httponly']:
                flags.append("HttpOnly")
            else:
                report.append(f"  [!] Cookie '{key}' missing HttpOnly flag.")
            if morsel['samesite']:
                flags.append(f"SameSite={morsel['samesite']}")
            else:
                report.append(f"  [!] Cookie '{key}' missing SameSite attribute.")
            if flags:
                report.append(f"  [✔] Cookie '{key}' has flags: {', '.join(flags)}")

def check_headers(url, report):
    parsed = urlparse(url)
    hostname = parsed.hostname
    scheme = parsed.scheme
    report.append(f"\n[+] Scanning: {url}")

    try:
        start = time.time()
        response = requests.get(url, timeout=10)
        duration = int((time.time() - start) * 1000)  # in ms
    except Exception as e:
        report.append(f"[!] Request failed: {e}")
        return

    report.append(f"HTTP Status: {response.status_code}, Response Time: {duration} ms")

    # 1. Security Headers Check
    for header, info in SECURITY_HEADERS.items():
        val = response.headers.get(header)
        if val:
            # Special checks for some headers
            if header == "Access-Control-Allow-Origin":
                credentials = response.headers.get("Access-Control-Allow-Credentials", "false").lower() == "true"
                dangerous, warning = analyze_cors(val, credentials)
                if dangerous:
                    report.append(f"[⚠️] {header}: Present but DANGEROUS ({val})")
                    report.append(f"    ⚠️ Warning: {warning}")
                    continue
            report.append(f"[✔] {header}: Present ({val})")
        else:
            report.append(f"[✘] {header}: MISSING")
            report.append(f"    Description: {info['description']}")
            report.append(f"    Fix: {info['fix']}")
            report.append(f"    Severity: {info['severity']}")

    # 2. Vulnerability DB check for leaking headers
    for h in response.headers:
        vkey = h
        vval = response.headers[h].strip()
        # Check exact header
        if vkey in VULN_DB:
            report.append(f"[!] Vulnerability DB warning: Header '{vkey}' leaks info. {VULN_DB[vkey]}")
        # Check header + value combos
        if vkey == "Access-Control-Allow-Origin" and vval == "*":
            report.append(f"[!] Vulnerability DB warning: Wildcard CORS '*' exposes API to all origins.")

    # 3. SSL/TLS Checks if HTTPS
    if scheme == "https":
        cert, tls_version = get_ssl_info(hostname)
        if cert:
            report.append(f"TLS Version: {tls_version}")
            report.append(f"Issuer: {cert.get('issuer')}")
            report.append(f"Subject: {cert.get('subject')}")
            not_after = cert.get('notAfter')
            report.append(f"Certificate Expiry: {not_after}")
        else:
            report.append("[!] Could not retrieve SSL certificate info.")
    else:
        report.append("[*] Not HTTPS, SSL/TLS checks skipped.")

    # 4. Cookie security checks
    check_cookies(response, report)

def batch_scan(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]
            print(f"[+] Loaded {len(urls)} URLs from {file_path}")
            report = []
            for url in urls:
                if not url.startswith("http"):
                    url = "http://" + url
                check_headers(url, report)
            save_report(report)
    except FileNotFoundError:
        print(f"[!] File not found: {file_path}")

def main():
    print("Choose scan mode:")
    print("1. Basic headers check")
    print("2. Full scan (headers, SSL/TLS, cookies, CORS, vuln DB)")
    print("3. Batch scan from urls.txt (full scan)")
    choice = input("Enter 1, 2 or 3: ").strip()

    if choice == "1" or choice == "2":
        url = input("Enter target URL (with http/https): ").strip()
        report = []
        check_headers(url, report)
        # Print & save
        for line in report:
            print(line)
        save_report(report)

    elif choice == "3":
        batch_scan("urls.txt")

    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()
