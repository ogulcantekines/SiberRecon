import socket
import platform
import sys
import argparse
import threading
import json
from datetime import datetime

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

def get_system_metrics():
    """
    Retrieves core system information including OS details, 
    architecture, and network identifiers.
    """
    try:
        metrics = {
            "os_name": platform.system(),
            "os_release": platform.release(),
            "architecture": platform.machine(),
            "hostname": socket.gethostname(),
            "internal_ip": socket.gethostbyname(socket.gethostname()),
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        return metrics
    except Exception as e:
        return {"error": f"Failed to retrieve system metrics: {str(e)}"}

def check_port(target, port, timeout, results, lock):
    """
    Performs a TCP connect scan for a single port. Attempts to grab banner.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            connected = s.connect_ex((target, port)) == 0
            banner = None
            if connected:
                try:
                    # Simple probe to get a response (e.g., HTTP HEAD)
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    raw = s.recv(256).decode(errors="ignore").strip()
                    banner = raw.split("\n")[0] if raw else "Unknown Service"
                except Exception:
                    banner = "Service Detected"
            with lock:
                results[port] = {"open": connected, "banner": banner}
    except Exception:
        with lock:
            results[port] = {"open": False, "banner": None}

def save_report(data, output_path):
    """
    Saves the audit data to a file in JSON or plain text format.
    """
    ext = output_path.rsplit(".", 1)[-1].lower()
    if ext == "json":
        with open(output_path, "w") as f:
            json.dump(data, f, indent=4)
    else:
        with open(output_path, "w") as f:
            f.write(f"SiberRecon Report — {data['system']['scan_time']}\n")
            f.write("=" * 55 + "\n")
            f.write(f"Target: {data['system']['hostname']} ({data['system'].get('internal_ip', 'N/A')})\n\n")
            f.write("[Port Scan Results]\n")
            for port, info in data["ports"].items():
                status = "OPEN" if info["open"] else "CLOSED"
                banner = f" | {info['banner']}" if info.get('banner') else ""
                f.write(f"  Port {port}: {status}{banner}\n")
    print(green(f"\n[✔] Rapor başarıyla kaydedildi: {output_path}"))

# ─── Color Helpers ────────────────────────────────────────────────────────────

def green(text):
    return Fore.GREEN + text + Style.RESET_ALL if COLOR else text

def red(text):
    return Fore.RED + text + Style.RESET_ALL if COLOR else text

def cyan(text):
    return Fore.CYAN + text + Style.RESET_ALL if COLOR else text

def yellow(text):
    return Fore.YELLOW + text + Style.RESET_ALL if COLOR else text

def bold(text):
    return Style.BRIGHT + text + Style.RESET_ALL if COLOR else text

def run_recon_audit(args):
    """
    Main execution logic for the SiberRecon utility.
    """
    target_host = args.target
    timeout = args.timeout
    output = args.output

    print(bold(cyan(f"\n{'='*20} SiberRecon v1.6: Security Audit {'='*20}")))
    print(f"Target: {yellow(target_host)} | Timeout: {timeout}s")
    
    # System Information Gathering
    print(bold("\n[+] Gathering System Intelligence..."))
    system_data = get_system_metrics()
    for key, value in system_data.items():
        print(f"    {cyan('—')} {key.replace('_', ' ').title()}: {value}")
    
    # Critical Network Services Audit
    print(bold(f"\n[+] Auditing {yellow('18')} Common Services (Threaded)..."))
    ports_to_scan = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
        445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
    }
    
    scan_results = {}
    lock = threading.Lock()
    threads = []

    for port in ports_to_scan.keys():
        t = threading.Thread(target=check_port, args=(target_host, port, timeout, scan_results, lock))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Process results
    for port, service in sorted(ports_to_scan.items()):
        info = scan_results.get(port, {"open": False, "banner": None})
        is_open = bool(info.get("open", False))
        banner = info.get("banner")
        
        status = green("OPEN  ✔") if is_open else red("CLOSED ✘")
        banner_str = f" [{cyan(str(banner))}]" if banner else ""
        print(f"    - Port {port:5d} ({service:8s}): {status}{banner_str}")

    # Summary and Stats
    open_count = sum(1 for res in scan_results.values() if res.get("open"))
    total = len(ports_to_scan)
    print(bold(f"\n[+] Summary: {green(str(open_count))} open / {red(str(total - open_count))} closed out of {total} ports"))

    if output:
        report_data = {
            "system": system_data,
            "ports": scan_results
        }
        save_report(report_data, output)

    print(f"\n{'='*55}\n")

def parse_arguments():
    parser = argparse.ArgumentParser(description="SiberRecon: Security Recon Tool")
    parser.add_argument("-t", "--target", default="127.0.0.1", help="Target IP address (default: 127.0.0.1)")
    parser.add_argument("-o", "--output", help="Save results to a file (e.g. report.json or report.txt)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Scan timeout in seconds (default: 1.0)")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    run_recon_audit(args)