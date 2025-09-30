import socket
import threading
import re
import pyfiglet
import time

# -----------------------------
# Small local vulnerability "database"
# Each entry is a tuple (pattern, info_dict)
# pattern is a regex applied to banner or "service" string to detect known vulnerable versions
# info_dict contains: "name", "severity", "notes", "references"
# NOTE: This is a small local DB for quick checks. For production use integrate with NVD/CVE feeds or vulnerability scanners.
# -----------------------------
VULN_DB = [
    (r"OpenSSH[_\- ]?([0-9]+\.[0-9]+)", {"name": "OpenSSH older version", "severity": "medium", "notes": "Older OpenSSH versions may be vulnerable to various issues. Verify exact version and check CVE list.", "references": ["https://www.openssh.com/security.html"]}),
    (r"Apache/?([0-9]+\.[0-9]+\.[0-9]+)", {"name": "Apache HTTPD", "severity": "high", "notes": "Certain Apache versions have known vulnerabilities (mod_ssl/mod_status). Check CVEs for exact version.", "references": ["https://httpd.apache.org/security_report.html"]}),
    (r"nginx/?([0-9]+\.[0-9]+\.[0-9]+)", {"name": "nginx HTTPD", "severity": "high", "notes": "Known nginx vulnerabilities may affect some older releases.", "references": ["https://nginx.org/en/security_advisories.html"]}),
    (r"Microsoft-HTTPAPI/([0-9]+\.[0-9]+)", {"name": "Microsoft HTTPAPI", "severity": "high", "notes": "Windows HTTP API versions could indicate Windows IIS/HTTP.sys version which had serious CVEs.", "references": ["https://msrc.microsoft.com/"]}),
    (r"MSSQLServer|Microsoft SQL Server", {"name": "MSSQL Server", "severity": "high", "notes": "Check MS SQL Server version for remotely exploitable issues.", "references": ["https://msrc.microsoft.com/"]}),
    (r"vsFTPd ([0-9]+\.[0-9]+)", {"name": "vsFTPD", "severity": "medium", "notes": "Some vsFTPd releases had backdoor issues in the past.", "references": []}),
    (r"Exim \w*([0-9]+\.[0-9]+)", {"name": "Exim MTA", "severity": "high", "notes": "Exim historically had serious remote code execution vulnerabilities; check version-specific CVEs.", "references": []}),
    (r"ProFTPD ([0-9]+\.[0-9]+)", {"name": "ProFTPD", "severity": "medium", "notes": "ProFTPD sometimes had mod_copy or path traversal issues.", "references": []}),
    (r"OpenSSL ([0-9]+\.[0-9]+\.[0-9]+)", {"name": "OpenSSL", "severity": "high", "notes": "OpenSSL versions may contain critical CVEs. Verify exact patch level.", "references": ["https://www.openssl.org/news/vulnerabilities.html"]}),
    (r"Tomcat/?([0-9]+\.[0-9]+\.[0-9]+)", {"name": "Apache Tomcat", "severity": "high", "notes": "Tomcat had several CVEs — check exact version.", "references": []}),
]

# -----------------------------
# Dictionary of common ports and their typical services
# (kept from your original script)
# -----------------------------
PORT_SERVICES = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP (Mail)",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP (Web)",
    110: "POP3 (Mail)",
    123: "NTP",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS (SSL)",
    445: "Microsoft-DS/SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP (Mail Submission)",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1433: "MSSQL",
    1521: "Oracle DB",
    1723: "PPTP VPN",
    3306: "MySQL",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy/Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    11211: "Memcached"
}

# -----------------------------
# Helpers: validation functions (kept)
# -----------------------------

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def is_valid_port(port):
    return port.isdigit() and 1 <= int(port) <= 65535


def is_valid_port_range(port_range):
    if "-" in port_range:
        parts = port_range.split("-")
        if len(parts) == 2 and all(p.isdigit() for p in parts):
            start, end = int(parts[0]), int(parts[1])
            return 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end
    return False

# -----------------------------
# Function: Analyze banner and local DB for possible vulnerabilities
# -----------------------------

def identify_vulnerabilities(service, banner):
    findings = []
    text = (banner or "") + " " + (service or "")
    for pattern, info in VULN_DB:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            entry = info.copy()
            entry["match"] = m.group(0)
            # If version captured, include it
            if m.groups():
                entry["version"] = m.group(1)
            findings.append(entry)
    return findings

# -----------------------------
# Function: Send lightweight protocol probes to improve banners
# (safe, minimal probes: HTTP HEAD, SMTP EHLO, simple text for FTP etc.)
# -----------------------------

def protocol_probe(s, port, target):
    try:
        if port in (80, 8080, 8000, 8888):
            req = f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n"
            s.sendall(req.encode())
        elif port in (443, 8443):
            # TLS handshake would be necessary to get a proper banner; skip active TLS handshake here
            return None
        elif port in (25, 587, 465):
            # SMTP
            s.sendall(b"EHLO example.com\r\n")
        elif port in (21,):
            # FTP often sends banner immediately, but sending a newline may trigger response
            try:
                s.sendall(b"\r\n")
            except:
                pass
        elif port in (3306,):
            # MySQL sends handshake upon connect; no probe needed
            pass
        else:
            # Generic small payload to provoke a response for some services
            try:
                s.sendall(b"\r\n")
            except:
                pass
        time.sleep(0.2)
        try:
            data = s.recv(2048)
            return data.decode(errors="ignore").strip()
        except:
            return None
    except Exception:
        return None

# -----------------------------
# Function: Scan a single port (enhanced)
# -----------------------------

def scan_port(target, port, show_closed, save_results, results_list, vuln_check):
    service = PORT_SERVICES.get(port, "Unknown Service")

    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((target, port))

        # Try to read banner (some protocols send immediately)
        banner = ""
        try:
            # First try a non-blocking recv to get any immediate banner
            s.settimeout(1.0)
            chunk = s.recv(2048)
            banner = chunk.decode(errors='ignore').strip() if chunk else ""
        except:
            banner = ""

        # Try better probes for common protocols to get a more informative banner
        probe_banner = protocol_probe(s, port, target)
        if probe_banner:
            # If we got something from probe, append
            if banner:
                banner = banner + " | " + probe_banner
            else:
                banner = probe_banner

        result = f"[+] Port {port} ({service}) OPEN - Banner: {banner or 'No banner'}"
        print(result)

        # Vulnerability analysis
        vulns = []
        if vuln_check:
            vulns = identify_vulnerabilities(service, banner)
            if vulns:
                print("    -> Potential vulnerabilities found:")
                for v in vulns:
                    print(f"       - {v['name']} (severity: {v['severity']}) match: {v.get('match')} version: {v.get('version','unknown')}")
                    if v.get('notes'):
                        print(f"         notes: {v['notes']}")
                    if v.get('references'):
                        refs = ", ".join(v['references'])
                        if refs:
                            print(f"         refs: {refs}")

        # Save result if needed
        if save_results:
            entry = result
            if vulns:
                entry += "\n    Potential vulnerabilities:\n"
                for v in vulns:
                    entry += f"    - {v['name']} (severity: {v['severity']}), match: {v.get('match')}\n"
            results_list.append(entry)

        s.close()
    except Exception:
        if show_closed:
            result = f"[-] Port {port} ({service}) CLOSED or no response"
            print(result)
            if save_results:
                results_list.append(result)

# -----------------------------
# MAIN PROGRAM (interaction)
# -----------------------------

zam_text = pyfiglet.figlet_format("ZAMIN ALI")
print(zam_text)
print("===============================================")
print("\n* Copyright of Zamin Ali, 2024                              ")
print("* Github Link: https://github.com/zamin-codes                              ")
print("===============================================")

target = input("Enter the IP address or domain name: ")

if not is_valid_ip(target):
    try:
        resolved_ip = socket.gethostbyname(target)
        print(f"[INFO] Resolved domain '{target}' to IP: {resolved_ip}")
        target = resolved_ip
    except socket.gaierror:
        print("❌ Incorrect IP address or domain name")
        exit()

port_input = input("Enter port (single, e.g. 80) or range (e.g. 20-25): ")

ports = []
if is_valid_port(port_input):
    ports = [int(port_input)]
elif is_valid_port_range(port_input):
    start, end = map(int, port_input.split("-"))
    ports = list(range(start, end + 1))
else:
    print("❌ Incorrect port or port range")
    exit()

choice = input("Do you want to see closed ports too? (yes/no): ").strip().lower()
show_closed = choice in ["yes", "y"]

save_choice = input("Do you want to save results to a file? (yes/no): ").strip().lower()
save_results = save_choice in ["yes", "y"]

vuln_choice = input("Perform local vulnerability checks based on banners? (yes/no): ").strip().lower()
vuln_check = vuln_choice in ["yes", "y"]

results_list = []

print(f"\n[INFO] Starting scan on {target} for ports: {ports[0]} to {ports[-1]}")
print(f"[INFO] Displaying {'open + closed ports' if show_closed else 'only open ports'}")
if save_results:
    print("[INFO] Results will also be saved to 'scan_results.txt'\n")

threads = []
for port in ports:
    t = threading.Thread(target=scan_port, args=(target, port, show_closed, save_results, results_list, vuln_check))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

if save_results and results_list:
    with open("scan_results.txt", "w", encoding="utf-8") as f:
        for line in results_list:
            f.write(line + "\n")
    print("\n[INFO] Scan results saved to 'scan_results.txt'")

print("\n[INFO] Scan completed ✅")

# -----------------------------
# Usage notes & legal reminder (printed to console by user)
# -----------------------------
print('\n[NOTE] This tool performs basic banner-based checks only.\n       For accurate vulnerability detection integrate with services like NVD feeds, Vulners API, or use full scanners (e.g., nmap with scripts, OpenVAS, Nessus).')
print('[LEGAL] Only scan systems you own or have explicit permission to test. Unauthorized scanning may be illegal.')
