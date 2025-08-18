# 🔎 Banner Grabbing & Port Scanner Tool

A fast **banner grabbing and port scanning tool** written in Python.  
This tool allows you to scan single ports or ranges, identify open/closed ports, grab service banners, and recognize common services (like HTTP, FTP, SSH, etc.).  

---

## ✨ Features
- ✅ Accepts both **IP addresses** and **domain names**
- ✅ Supports **single port** or **port ranges** (e.g. `80` or `20-100`)
- ✅ Option to display **only open ports** or **open + closed ports**
- ✅ Identifies **common port services** (e.g. `80 → HTTP`, `443 → HTTPS`)
- ✅ **Banner grabbing** to detect what service/software is running
- ✅ **Multithreaded scanning** for faster results
- ✅ Option to **save results to a file** (`scan_results.txt`)

---

## ⚡ Example Usage
Run the program:
```bash
python3 full_port_scanner.py
```

Example run:
```
===============================================
   Banner Grabbing & Port Scanner Tool
   Developed by Zamin Ali
   GitHub: https://github.com/zamin-codes
===============================================

Enter the IP address or domain name: google.com
[INFO] Resolved domain 'google.com' to IP: 142.250.190.78
Enter port (single, e.g. 80) or range (e.g. 20-25): 21-23
Do you want to see closed ports too? (yes/no): yes
Do you want to save results to a file? (yes/no): yes

[INFO] Starting scan on 142.250.190.78 for ports: 21 to 23
[INFO] Displaying open + closed ports
[INFO] Results will also be saved to 'scan_results.txt'

[-] Port 21 (FTP) CLOSED or no response
[-] Port 22 (SSH) CLOSED or no response
[-] Port 23 (Telnet) CLOSED or no response

[INFO] Scan results saved to 'scan_results.txt'
[INFO] Scan completed ✅
```

---

## 📂 Output
If saving is enabled, results will be stored in `scan_results.txt` in the same directory. Example:

```
[+] Port 80 (HTTP) OPEN - Banner: Apache/2.4.41 (Ubuntu)
[-] Port 21 (FTP) CLOSED or no response
```

---

## 🔧 Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/zamin-codes/Full_Port_Scanner.git
   cd banner-grabber
   ```

2. Run the program:
   ```bash
   python3 full_port_scanner.py
   ```

---

## 📖 Requirements
- Python 3.x  
- Standard libraries: `socket`, `threading` (already included in Python)  

No extra installation required 🎉

---

## ⚠️ Disclaimer
This tool is made for **educational and ethical security testing** only.  
Do not use it on targets you don’t have permission to scan. Unauthorized scanning may be illegal.

---

## 👨‍💻 Author
- **Zamin Ali**  
- GitHub: [zamin-codes](https://github.com/zamin-codes)
