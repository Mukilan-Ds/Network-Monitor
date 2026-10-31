"""
NetWatch - Device Discovery Module
-----------------------------------
Scans a given subnet (CIDR) to find which IP addresses are currently
active/reachable. This is the foundation module: later, the GUI and
ping-latency modules will build on top of this.

Usage:
    python discovery.py 192.168.1.0/24

How it works:
    1. Expand the CIDR into individual host IPs.
    2. Ping each IP in parallel (using the OS 'ping' command via subprocess).
    3. Collect and print which ones responded.

Notes:
    - Uses subprocess + the system ping binary (cross-platform: Linux/macOS/Windows)
      instead of raw sockets, because raw ICMP sockets require root/admin
      privileges on most systems. This keeps it runnable without sudo.
    - Uses ThreadPoolExecutor to ping many hosts concurrently, since sequential
      pinging of a /24 (254 hosts) would take minutes otherwise.
"""

import ipaddress
import platform
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed


def ping_host(ip: str, timeout_ms: int = 1000) -> bool:
    """
    Ping a single IP once. Returns True if it responded, False otherwise.
    Cross-platform: builds the correct ping command for Windows vs Linux/macOS.
    """
    system = platform.system().lower()

    if system == "windows":
        # Windows: -n 1 (one echo request), -w <timeout in ms>
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        # Linux/macOS: -c 1 (one echo request), -W <timeout in seconds>
        timeout_sec = max(1, timeout_ms // 1000)
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=(timeout_ms / 1000) + 1,  # slightly longer than ping's own timeout
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        # TimeoutExpired: our own safety timeout fired (ping hung)
        # FileNotFoundError: 'ping' binary not found on this system
        return False


def scan_subnet(cidr: str, max_workers: int = 50) -> list[str]:
    """
    Given a CIDR string like '192.168.1.0/24', ping every host address
    in that range concurrently and return the list of IPs that responded.
    """
    network = ipaddress.ip_network(cidr, strict=False)

    # .hosts() excludes the network and broadcast addresses automatically
    all_ips = [str(ip) for ip in network.hosts()]

    print(f"Scanning {len(all_ips)} addresses in {cidr} ...")

    alive_hosts = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Map each future back to its IP so we know which result belongs to which host
        future_to_ip = {executor.submit(ping_host, ip): ip for ip in all_ips}

        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                is_alive = future.result()
            except Exception:
                is_alive = False

            if is_alive:
                alive_hosts.append(ip)
                print(f"  [UP]   {ip}")

    return sorted(alive_hosts, key=lambda ip: tuple(int(part) for part in ip.split(".")))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python discovery.py <CIDR>")
        print("Example: python discovery.py 192.168.1.0/24")
        sys.exit(1)

    cidr_arg = sys.argv[1]
    found = scan_subnet(cidr_arg)

    print("\n--- Scan complete ---")
    print(f"Devices found: {len(found)}")
    for ip in found:
        print(f"  - {ip}")
