# 🔍 SiberRecon

A lightweight Python security reconnaissance tool for auditing system information and critical network services.

> ⚠️ **Disclaimer:** This tool is intended for educational purposes and authorized security auditing only. Do not use on systems you don't own or have explicit permission to test.

---

## ✨ Features

- 🖥️ **System Intelligence** — Gathers OS, architecture, hostname, and internal IP
- 🔌 **Port Scanner** — TCP connect scan on critical service ports (SSH, HTTP, HTTPS, MySQL)
- ⚡ **No dependencies** — Uses Python standard library only

## 📋 Requirements

- Python 3.6+

## 🚀 Usage

```bash
git clone https://github.com/ogulcantekines/SiberRecon
cd SiberRecon
python main.py
```

### Example Output

```text
==================== SiberRecon v1.0: Security Audit ====================

[+] Gathering System Intelligence...
    - Os Name: Linux
    - Os Release: 6.x.x
    - Architecture: x86_64
    - Hostname: mymachine
    - Internal Ip: 192.168.1.100

[+] Auditing Critical Network Services...
    - Port 22 (SSH): PASSED (Open)
    - Port 80 (HTTP): FAILED (Closed/Filtered)
    - Port 443 (HTTPS): FAILED (Closed/Filtered)
    - Port 3306 (MySQL): FAILED (Closed/Filtered)
```

## 🛣️ Roadmap

- [ ] CLI arguments (`-t` target, `-p` ports, `-o` output file)
- [ ] Parallel scanning with threading
- [ ] Colored terminal output
- [ ] Banner grabbing (service version detection)
- [ ] JSON/TXT report export

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
