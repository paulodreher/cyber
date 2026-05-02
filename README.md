# Pentest Tools

A collection of offensive security scripts written in Bash, Python, C, and PowerShell. Built for practice and learning across different programming languages.

> **For educational and authorized use only.** Only run these tools against systems you own or have explicit written permission to test.

---

## Structure

```
.
├── bashscript/     # Bash scripts and wordlists
├── c/              # C programs
├── python/         # Python scripts
└── powershell/     # PowerShell scripts
```

---

## Tools

### Reconnaissance

| Script | Language | Description |
|--------|----------|-------------|
| `bashscript/webrecon.sh` | Bash | Directory and file brute-forcer using curl |
| `python/webscrapping.py` | Python | Checks if a website returns HTTP 200 |
| `python/webserverinfo.py` | Python | Prints the `Server` header from a URL |
| `powershell/webscrapping.ps1` | PowerShell | Retrieves server headers, allowed HTTP methods, and links |
| `python/whois.py` | Python | WHOIS lookup via IANA (supports IPv6) |

### Port Scanning

| Script | Language | Description |
|--------|----------|-------------|
| `python/portscan.py` | Python | TCP port scanner, ports 1–65535 |
| `c/portscan.c` | C | TCP port scanner, ports 0–65535 |
| `powershell/portscan.ps1` | PowerShell | TCP port scanner using `Test-NetConnection`, ports 1–100 |

### DNS & Resolution

| Script | Language | Description |
|--------|----------|-------------|
| `python/resolver.py` | Python | Resolves a domain name to its IP address |
| `c/resolver.c` | C | Subdomain enumeration using a wordlist |

### Network

| Script | Language | Description |
|--------|----------|-------------|
| `python/bannergrabbing.py` | Python | Grabs a TCP service banner (prompts for IP and port) |
| `python/ftpconnect.py` | Python | Basic FTP connection and login test |
| `powershell/pingsweep.ps1` | PowerShell | Ping sweep across a /24 subnet |
| `c/socket.c` | C | Minimal TCP connection example |
| `c/dos.c` | C | TCP flood loop (educational demo only) |

---

## Usage

### `webrecon.sh` — Web directory brute-force
```bash
chmod +x bashscript/webrecon.sh
./bashscript/webrecon.sh bashscript/small.txt http://target.com php
```
Arguments: `<wordlist> <base_url> <file_extension>`

### `portscan.py` — Python port scanner
```bash
python3 python/portscan.py 192.168.1.1
```

### `portscan.c` — C port scanner
```bash
gcc c/portscan.c -o portscan
./portscan 192.168.1.1
```

### `resolver.c` — C subdomain brute-forcer
```bash
gcc c/resolver.c -o resolver
./resolver .target.com c/subdomains.txt
```

### `resolver.py` — Python DNS resolver
```bash
python3 python/resolver.py target.com
```

### `whois.py` — WHOIS lookup
```bash
python3 python/whois.py 8.8.8.8
```

### `webserverinfo.py` — Server header
```bash
python3 python/webserverinfo.py target.com
```

### `pingsweep.ps1` — PowerShell ping sweep
```powershell
.\powershell\pingsweep.ps1 192.168.0
```

### `portscan.ps1` — PowerShell port scanner
```powershell
.\powershell\portscan.ps1 192.168.1.1
```

---

## Requirements

**Python scripts**
- Python 3.x
- `requests` library: `pip install requests`

**C programs**
- GCC: `sudo apt install build-essential`

**Bash scripts**
- `curl`

**PowerShell scripts**
- PowerShell 5+ (Windows) or PowerShell Core (Linux/macOS)
