import socket
import threading
import pyfiglet

# -----------------------------
# Dictionary of common ports and their typical services
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
# Function: Validate if input is a valid IPv4 address
# -----------------------------
def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)  # raises error if not a valid IP
        return True
    except socket.error:
        return False

# -----------------------------
# Function: Validate a single port number
# -----------------------------
def is_valid_port(port):
    return port.isdigit() and 1 <= int(port) <= 65535

# -----------------------------
# Function: Validate a port range (e.g. "20-80")
# -----------------------------
def is_valid_port_range(port_range):
    if "-" in port_range:
        parts = port_range.split("-")
        if len(parts) == 2 and all(p.isdigit() for p in parts):
            start, end = int(parts[0]), int(parts[1])
            return 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end
    return False

# -----------------------------
# Function: Scan a single port
# -----------------------------
def scan_port(target, port, show_closed, save_results, results_list):
    # Determine the service name (if known, otherwise "Unknown")
    service = PORT_SERVICES.get(port, "Unknown Service")

    try:
        # Create socket
        s = socket.socket()
        s.settimeout(2)  # Timeout prevents hanging
        s.connect((target, port))  # Try connecting to target:port

        # Try grabbing banner
        try:
            banner = s.recv(1024).decode(errors="ignore").strip()
        except:
            banner = "No banner"

        result = f"[+] Port {port} ({service}) OPEN - Banner: {banner}"
        print(result)

        # Save result if needed
        if save_results:
            results_list.append(result)

        s.close()
    except:
        if show_closed:
            result = f"[-] Port {port} ({service}) CLOSED or no response"
            print(result)
            if save_results:
                results_list.append(result)

# -----------------------------
# MAIN PROGRAM
# -----------------------------

# Step 1: Ask for target IP/domain
zam_text = pyfiglet.figlet_format("ZAMIN ALI")
print(zam_text)
print("===============================================")
print("\n* Copyright of Zamin Ali, 2024                              ")
print("* Github Link: https://github.com/zamin-codes                              ")
print("===============================================")
target = input("Enter the IP address or domain name: ")

# If not a valid IP, try resolving domain
if not is_valid_ip(target):
    try:
        resolved_ip = socket.gethostbyname(target)
        print(f"[INFO] Resolved domain '{target}' to IP: {resolved_ip}")
        target = resolved_ip
    except socket.gaierror:
        print("❌ Incorrect IP address or domain name")
        exit()

# Step 2: Ask for port input
port_input = input("Enter port (single, e.g. 80) or range (e.g. 20-25): ")

# Validate input and create list of ports
ports = []
if is_valid_port(port_input):
    ports = [int(port_input)]
elif is_valid_port_range(port_input):
    start, end = map(int, port_input.split("-"))
    ports = list(range(start, end + 1))
else:
    print("❌ Incorrect port or port range")
    exit()

# Step 3: Ask whether to show closed ports
choice = input("Do you want to see closed ports too? (yes/no): ").strip().lower()
show_closed = choice in ["yes", "y"]

# Step 4: Ask whether to save results
save_choice = input("Do you want to save results to a file? (yes/no): ").strip().lower()
save_results = save_choice in ["yes", "y"]

results_list = []

print(f"\n[INFO] Starting scan on {target} for ports: {ports[0]} to {ports[-1]}")
print(f"[INFO] Displaying {'open + closed ports' if show_closed else 'only open ports'}")
if save_results:
    print("[INFO] Results will also be saved to 'scan_results.txt'\n")

# Step 5: Start scanning with multithreading
threads = []
for port in ports:
    t = threading.Thread(target=scan_port, args=(target, port, show_closed, save_results, results_list))
    threads.append(t)
    t.start()

# Step 6: Wait for all threads
for t in threads:
    t.join()

# Step 7: Save to file if needed
if save_results and results_list:
    with open("scan_results.txt", "w") as f:
        for line in results_list:
            f.write(line + "\n")
    print("\n[INFO] Scan results saved to 'scan_results.txt'")

print("\n[INFO] Scan completed ✅")
