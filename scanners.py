import requests
import socket
import ssl

def check_xss(domain):
    payloads = ['<script>alert("XSS")</script>', '<img src="x" onerror="alert(1)">']
    for payload in payloads:
        url = f"http://{domain}/{payload}"
        try:
            response = requests.get(url)
            if payload in response.text:
                print(f"[!] Possible XSS vulnerability found on {domain} with payload: {payload}")
        except requests.exceptions.RequestException:
            print(f"[-] Error checking XSS on {domain}")

def check_sql_injection(domain):
    payload = "' OR 1=1 --"
    url = f"http://{domain}/?id={payload}"
    try:
        response = requests.get(url)
        if "error" in response.text or "mysql" in response.text:
            print(f"[!] Possible SQL Injection vulnerability found on {domain} with payload: {payload}")
    except requests.exceptions.RequestException:
        print(f"[-] Error checking SQL Injection on {domain}")

def port_scan(domain):
    ports = [80, 443, 3306]
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((domain, port))
        if result == 0:
            print(f"[+] Port {port} is open on {domain}")
        else:
            print(f"[!] Port {port} is closed on {domain}")

def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        connection.connect((domain, 443))
        ssl_info = connection.getpeercert()
        print(f"[+] SSL/TLS certificate is valid for {domain}")
    except Exception as e:
        print(f"[!] SSL/TLS certificate validation failed for {domain}: {str(e)}")

def check_headers(domain):
    headers = ['Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options']
    try:
        response = requests.get(f"http://{domain}")
        for header in headers:
            if header in response.headers:
                print(f"[+] {header} is present on {domain}")
            else:
                print(f"[!] {header} is missing on {domain}")
    except requests.exceptions.RequestException:
        print(f"[-] Error checking headers on {domain}")

def check_directory_traversal(domain):
    payload = "../../../etc/passwd"
    url = f"http://{domain}/{payload}"
    try:
        response = requests.get(url)
        if "root:" in response.text:
            print(f"[!] Possible directory traversal vulnerability found on {domain}")
    except requests.exceptions.RequestException:
        print(f"[-] Error checking directory traversal on {domain}")

def perform_dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] DNS lookup successful for {domain}: {ip}")
    except socket.gaierror:
        print(f"[-] DNS lookup failed for {domain}")

def check_cve(domain, cve_id):
    print(f"[+] Checking CVE: {cve_id} for {domain}")
    # Here you can integrate with CVE databases or APIs to fetch relevant data.

