# Automated Vulnerability Scanner

This is a Python-based **Automated Vulnerability Scanner** designed to help you scan websites or domains for common vulnerabilities such as:

- SQL Injection
- Cross-Site Scripting (XSS)
- Open Ports
- SSL/TLS Certificate Validation
- HTTP Security Headers
- Directory Traversal
- DNS Lookup
- CVE Information (via CVE API)

## Features

- **SQL Injection Detection**: Scans for SQL injection vulnerabilities by injecting common payloads into URL parameters.
- **XSS (Cross-Site Scripting)**: Scans for XSS vulnerabilities by injecting script tags into URL parameters.
- **Port Scanning**: Scans common ports like HTTP (80), HTTPS (443), MySQL (3306), and others.
- **SSL/TLS Validation**: Checks if the target domain has a valid SSL/TLS certificate.
- **HTTP Security Headers**: Checks the presence of important security headers like `Strict-Transport-Security`, `X-Content-Type-Options`, and more.
- **Directory Traversal**: Checks for potential directory traversal vulnerabilities on the server.
- **DNS Lookup**: Performs a DNS lookup to resolve the target domain to an IP address.
- **CVE Checking**: Fetches details for a given CVE ID using a public CVE API.

## Prerequisites

To run this scanner, you need Python 3.x and the following Python libraries:

- `requests`
- `beautifulsoup4`
- `socket`

You can install the required libraries using `pip`:

```bash
pip install requests beautifulsoup4
Usage
To run the scanner, use the following command structure:


python vuln_scanner.py --domain <target-domain> [options]
Options
-d, --domain <target-domain>: The target domain (without http:// or https://).
--xss: Enable Cross-Site Scripting (XSS) scan.
--sql: Enable SQL Injection scan.
--portscan: Enable port scanning.
--ssl: Check SSL/TLS certificate validity.
--headers: Check for HTTP security headers.
--dirtrav: Enable directory traversal vulnerability scan.
--dns: Perform DNS lookup.
--cve <CVE-ID>: Check a specific CVE ID (e.g., CVE-2021-12345).
Example Usage
Scan for XSS and SQL Injection vulnerabilities on a domain:


python vuln_scanner.py --domain example.com --xss --sql
Scan for open ports, SSL/TLS certificate, and check HTTP security headers:


python vuln_scanner.py --domain example.com --portscan --ssl --headers
Perform DNS lookup and directory traversal scan:


python vuln_scanner.py --domain example.com --dns --dirtrav
Check a specific CVE by ID:

python vuln_scanner.py --domain example.com --cve CVE-2021-12345

#####################################################
#                                                   #
#      Automated Vulnerability Scanner v1.0         #
#      Developed by Prakhar Verma                   #
#      Detect SQL Injection, XSS, CVE, Ports        #
#      Additional features coming soon!             #
#                                                   #
#####################################################
[+] Checking for XSS on: example.com
[!] Possible XSS vulnerability found with payload: <script>alert("XSS")</script>

[+] Checking for SQL Injection on: example.com
[!] Possible SQL Injection vulnerability found with payload: ' OR 1=1 --

[+] Scanning open ports for example.com
[+] Port 80 is open on example.com
[+] Port 443 is open on example.com
[!] Port 3306 is closed on example.com

[+] Checking SSL/TLS certificate for example.com
[+] SSL/TLS certificate is valid

[+] Checking HTTP security headers for example.com
[+] Strict-Transport-Security is present
[!] X-Content-Type-Options is missing
License
This tool is open-source and released under the MIT License.

Disclaimer
This tool is intended for educational purposes only. Always get permission from the owner of a domain or server before running any security scanning tools on it. Unauthorized access or scanning of systems without permission is illegal.

Developed by Prakhar Verma



This version merges all the information into one continuous section, making it easy to follow in a single read.
