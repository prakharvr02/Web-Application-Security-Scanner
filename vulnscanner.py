import argparse
import requests
import socket
import sys
from bs4 import BeautifulSoup
import time
import os
import re
from urllib.parse import urlparse

# Banner to display after running the script
def print_banner():
    banner = """
    #####################################################
    #                                                   #
    #      Automated Vulnerability Scanner v1.0         #
    #      Developed by Prakhar Verma                   #
    #      Detect SQL Injection, XSS, CVE, Ports        #
    #      Additional features coming soon!             #
    #                                                   #
    #####################################################
    """
    print(banner)

# Function to validate the URL
def validate_url(url):
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        url = "http://" + url
    if not url.endswith('/'):
        url += '/'
    return url

# Function for detecting SQL Injection
def check_sql_injection(url):
    payloads = ["' OR 1=1 --", '" OR "a"="a', "' OR 'x'='x", "'; DROP TABLE users; --", '1\' OR 1=1#']
    print(f"[+] Checking for SQL Injection on: {url}")
    for payload in payloads:
        try:
            response = requests.get(url + payload, timeout=5)
            if response.status_code == 200 and "error" in response.text.lower():
                print(f"[!] Potential SQL Injection vulnerability found with payload: {payload}")
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")

# Function for detecting XSS (Cross-site Scripting)
def check_xss(url):
    payloads = ['<script>alert("XSS")</script>', '<img src="x" onerror="alert(1)">', '<svg onload=alert(1)>']
    print(f"[+] Checking for XSS on: {url}")
    for payload in payloads:
        try:
            response = requests.get(url + payload, timeout=5)
            if payload in response.text:
                print(f"[!] Potential XSS vulnerability found with payload: {payload}")
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")

# Function for checking open ports
def check_ports(ip, ports):
    print(f"[+] Checking open ports on: {ip}")
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    if open_ports:
        print(f"[!] Open ports found: {', '.join(map(str, open_ports))}")
    else:
        print("[+] No open ports found.")

# Function to fetch CVE details using the CIRCL API
def check_cve(cve_id):
    print(f"[+] Checking CVE details for {cve_id}")
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if 'summary' in data:
                print(f"[!] CVE Details: {data['summary']}")
        else:
            print(f"[+] CVE {cve_id} not found.")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

# Function to detect directory traversal vulnerabilities
def check_directory_traversal(url):
    payloads = ['../../../../etc/passwd', '/etc/passwd', '/../../etc/passwd']
    print(f"[+] Checking for Directory Traversal on: {url}")
    for payload in payloads:
        try:
            response = requests.get(url + payload, timeout=5)
            if "root" in response.text or "passwd" in response.text:
                print(f"[!] Potential Directory Traversal vulnerability found with payload: {payload}")
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")

# Function for SSL/TLS certificate verification
def check_ssl_cert(ip):
    print(f"[+] Checking SSL/TLS certificate for {ip}")
    try:
        response = requests.get(f"https://{ip}", timeout=5, verify=False)
        cert = response.cert
        print(f"[!] SSL Certificate Details: {cert}")
    except requests.exceptions.RequestException as e:
        print(f"[+] SSL/TLS check failed for {ip}: {e}")

# Function to scan for weak passwords using a list of common passwords
def check_weak_password(url):
    passwords = ["123456", "password", "qwerty", "letmein", "12345678"]
    print(f"[+] Checking for weak passwords on: {url}")
    for password in passwords:
        try:
            response = requests.get(url, auth=('admin', password), timeout=5)
            if response.status_code == 200:
                print(f"[!] Weak password found: {password}")
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")

# Function to check for HTTP security headers
def check_security_headers(url):
    headers_to_check = ["Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"]
    print(f"[+] Checking security headers on: {url}")
    try:
        response = requests.get(url, timeout=5)
        for header in headers_to_check:
            if header not in response.headers:
                print(f"[!] Missing header: {header}")
            else:
                print(f"[+] Found header: {header}")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

# Function to detect open redirects
def check_open_redirect(url):
    payloads = ["http://evil.com", "javascript:alert(1)", "https://evil.com"]
    print(f"[+] Checking for Open Redirects on: {url}")
    for payload in payloads:
        try:
            response = requests.get(url + payload, timeout=5)
            if response.status_code == 301 or response.status_code == 302:
                print(f"[!] Potential Open Redirect vulnerability found with payload: {payload}")
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")

# Function to check for DNS Lookup
def check_dns_lookup(ip):
    print(f"[+] Checking DNS lookup for {ip}")
    try:
        response = socket.gethostbyaddr(ip)
        print(f"[+] DNS Lookup for {ip}: {response}")
    except socket.herror as e:
        print(f"[+] DNS Lookup failed for {ip}: {e}")

# Main function to handle command-line arguments
def main():
    parser = argparse.ArgumentParser(description="Automated Vulnerability Scanner")

    # Adding arguments for URL, IP, CVE, etc.
    parser.add_argument("-u", "--url", help="Target URL for scanning (e.g., http://example.com)")
    parser.add_argument("-p", "--ports", nargs='+', type=int, help="List of ports to scan (e.g., 80 443 8080)")
    parser.add_argument("-i", "--ip", help="IP address for port scanning (e.g., 192.168.1.1)")
    parser.add_argument("-c", "--cve", help="CVE ID to check (e.g., CVE-2021-12345)")
    
    # Flags for enabling specific types of scans
    parser.add_argument("--xss", action="store_true", help="Enable XSS scan")
    parser.add_argument("--sql", action="store_true", help="Enable SQL Injection scan")
    parser.add_argument("--portscan", action="store_true", help="Enable port scan")
    parser.add_argument("--cvecheck", action="store_true", help="Enable CVE check")
    parser.add_argument("--dirtrav", action="store_true", help="Enable directory traversal check")
    parser.add_argument("--ssl", action="store_true", help="Enable SSL/TLS certificate check")
    parser.add_argument("--weakpwd", action="store_true", help="Enable weak password check")
    parser.add_argument("--dns", action="store_true", help="Enable DNS Lookup")
    parser.add_argument("--headers", action="store_true", help="Enable HTTP security headers check")
    parser.add_argument("--redirect", action="store_true", help="Enable open redirect check")

    args = parser.parse_args()

    # Print banner
    print_banner()

    # Validate URL
    if args.url:
        url = validate_url(args.url)
        if args.sql:
            check_sql_injection(url)
        if args.xss:
            check_xss(url)
        if args.dirtrav:
            check_directory_traversal(url)
        if args.weakpwd:
            check_weak_password(url)
        if args.headers:
            check_security_headers(url)
        if args.redirect:
            check_open_redirect(url)

    # Validate IP for port scan, SSL checks, and DNS lookup
    if args.ip:
        if args.portscan:
            check_ports(args.ip, args.ports)
        if args.ssl:
            check_ssl_cert(args.ip)
        if args.dns:
            check_dns_lookup(args.ip)

    # CVE check
    if args.cve:
        check_cve(args.cve)

if __name__ == "__main__":
    main()
