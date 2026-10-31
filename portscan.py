"""
NetWatch - Port Scan Module
------------------------------
Checks a device for open TCP ports among a list of common,
well-known service ports, and labels each open port with the
service that typically runs there (SSH, HTTP, etc.).

This lets the app say more than "device is up" -- it can say
"this looks like a web server" or "SSH is open on this box",
which is much more useful for an IT/networking tool.

How it works:
    - socket.connect_ex() attempts a real TCP handshake against each
      port. A result of 0 means the connection succeeded (port open).
      Anything else means closed/filtered/refused.
    - Ports are checked concurrently (ThreadPoolExecutor), since
      checking ~17 ports one at a time with a timeout each would be slow.

Usage (standalone test):
    python portscan.py 10.139.6.213
"""

import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common ports worth checking, and the service typically found there.
# Deliberately a small, well-known set rather than a full 0-65535 scan --
# this is a "what's likely running here" check, not a security audit tool.
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5201: "iperf3",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


def check_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    """Try a real TCP connection to one port. Returns True if it succeeds."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        return result == 0
    except OSError:
        return False
    finally:
        sock.close()


def scan_ports(ip: str, ports: dict = None, max_workers: int = 20) -> list[dict]:
    """
    Check all `ports` (defaults to COMMON_PORTS) against `ip` concurrently.

    Returns a list of dicts, sorted by port number:
        [{"port": 22, "service": "SSH"}, {"port": 80, "service": "HTTP"}, ...]
    Only OPEN ports are included in the result.
    """
    ports = ports or COMMON_PORTS
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(check_port, ip, port): port for port in ports
        }
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            if future.result():
                open_ports.append(port)

    return [
        {"port": p, "service": ports.get(p, "Unknown")}
        for p in sorted(open_ports)
    ]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python portscan.py <ip>")
        sys.exit(1)

    target = sys.argv[1]
    print(f"Scanning {len(COMMON_PORTS)} common ports on {target} ...")
    found = scan_ports(target)

    if not found:
        print("No common ports found open.")
    else:
        for entry in found:
            print(f"  {entry['port']:<6} {entry['service']}")
