"""
NetWatch - Ping Latency Module
--------------------------------
Builds on discovery.py: for each device found alive on the subnet,
send several pings and measure round-trip time (RTT) in milliseconds.

Usage:
    python latency.py 10.139.6.0/24

How it works:
    1. Reuse scan_subnet() from discovery.py to find live IPs.
    2. For each live IP, ping it a few times (not just once) and parse
       the RTT out of the ping command's own output.
    3. Report min/avg/max latency per device, and flag devices that
       had any dropped pings (packet loss) since that matters for a
       "network health" style tool.

Notes:
    - We reuse the OS ping binary again (not raw sockets) for the same
      reason as discovery.py: no admin/root privileges required.
    - Parsing ping output is done with simple string splitting rather than
      regex, since the output format is small and predictable per OS.
      This keeps the parsing easy to debug if a particular OS/locale
      formats its ping output differently than expected.
"""

import platform
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from discovery import scan_subnet


def _build_ping_command(ip: str, count: int, timeout_ms: int) -> list[str]:
    system = platform.system().lower()
    if system == "windows":
        return ["ping", "-n", str(count), "-w", str(timeout_ms), ip]
    else:
        timeout_sec = max(1, timeout_ms // 1000)
        return ["ping", "-c", str(count), "-W", str(timeout_sec), ip]


def _parse_rtts(output: str) -> list[float]:
    """
    Extract individual round-trip times (in ms) from raw ping output.
    Handles both Windows format ('time=12ms' or 'time<1ms') and
    Linux/macOS format ('time=12.3 ms').
    """
    rtts = []
    # Matches "time=12.3" / "time=12" / "time<1" (Windows sometimes uses '<')
    pattern = re.compile(r"time[=<]([\d.]+)\s*ms", re.IGNORECASE)
    for match in pattern.finditer(output):
        rtts.append(float(match.group(1)))
    return rtts


def measure_latency(ip: str, count: int = 4, timeout_ms: int = 1000) -> dict:
    """
    Ping a single IP `count` times and return latency stats.

    Returns a dict:
        {
            "ip": str,
            "sent": int,
            "received": int,
            "loss_pct": float,
            "min_ms": float | None,
            "avg_ms": float | None,
            "max_ms": float | None,
        }
    """
    cmd = _build_ping_command(ip, count, timeout_ms)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=((timeout_ms / 1000) * count) + 2,
        )
        output = result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        output = ""

    rtts = _parse_rtts(output)
    received = len(rtts)
    loss_pct = round(((count - received) / count) * 100, 1)

    return {
        "ip": ip,
        "sent": count,
        "received": received,
        "loss_pct": loss_pct,
        "min_ms": min(rtts) if rtts else None,
        "avg_ms": round(sum(rtts) / len(rtts), 1) if rtts else None,
        "max_ms": max(rtts) if rtts else None,
    }


def measure_all(ips: list[str], count: int = 4, max_workers: int = 20) -> list[dict]:
    """
    Measure latency for a list of IPs concurrently.
    Returns results sorted by IP for stable, readable output.
    """
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {
            executor.submit(measure_latency, ip, count): ip for ip in ips
        }
        for future in as_completed(future_to_ip):
            results.append(future.result())

    return sorted(results, key=lambda r: tuple(int(p) for p in r["ip"].split(".")))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python latency.py <CIDR>")
        print("Example: python latency.py 10.139.6.0/24")
        sys.exit(1)

    cidr_arg = sys.argv[1]

    print("Step 1: Discovering live devices...")
    live_ips = scan_subnet(cidr_arg)

    if not live_ips:
        print("No live devices found. Check your CIDR/subnet and try again.")
        sys.exit(0)

    print(f"\nStep 2: Measuring latency for {len(live_ips)} device(s)...\n")
    stats = measure_all(live_ips, count=4)

    print(f"{'IP':<16}{'Sent':<6}{'Recv':<6}{'Loss%':<8}{'Min':<8}{'Avg':<8}{'Max':<8}")
    for s in stats:
        min_s = f"{s['min_ms']}ms" if s['min_ms'] is not None else "-"
        avg_s = f"{s['avg_ms']}ms" if s['avg_ms'] is not None else "-"
        max_s = f"{s['max_ms']}ms" if s['max_ms'] is not None else "-"
        print(
            f"{s['ip']:<16}{s['sent']:<6}{s['received']:<6}"
            f"{s['loss_pct']:<8}{min_s:<8}{avg_s:<8}{max_s:<8}"
        )
