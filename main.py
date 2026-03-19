import socket
import platform
import sys
import os

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
            "internal_ip": socket.gethostbyname(socket.gethostname())
        }
        return metrics
        
    except Exception as e:
        return {"error": f"Failed to retrieve system metrics: {str(e)}"}

def check_service_status(target, port):
    """
    Performs a TCP connect scan to verify if a specific port is active.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.5)
        result = s.connect_ex((target, port))
        return result == 0

def run_recon_audit():
    """
    Main execution logic for the SiberRecon utility.
    """
    print(f"\n{'='*20} SiberRecon v1.0: Security Audit {'='*20}")
    
    # System Information Gathering
    print("\n[+] Gathering System Intelligence...")
    system_data = get_system_metrics()
    for key, value in system_data.items():
        print(f"    - {key.replace('_', ' ').title()}: {value}")
    
    # Critical Network Services Audit
    print("\n[+] Auditing Critical Network Services...")
    target_host = "[IP_ADDRESS]"
    critical_ports = {22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL"}

    for port, service in critical_ports.items():
        is_open = check_service_status(target_host, port)
        status = "PASSED (Open)" if is_open else "FAILED (Closed/Filtered)"
        print(f"    - Port {port} ({service}): {status}")

    print(f"\n{'='*55}\n")

if __name__ == "__main__":
    run_recon_audit()