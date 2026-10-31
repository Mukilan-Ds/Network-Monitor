"""
NetWatch - Network Tools
-----------------------------
Small, dependency-free helpers used by the web server:

    * Wake-on-LAN   - build and broadcast a "magic packet"
    * ping_once()   - one ICMP echo via the system ping (so no admin rights needed)
    * traceroute()  - the system tracert / traceroute, parsed into hops
    * default_gateway() - the router's address, to give a MAC change on it extra weight

Every parser is its own function (taking the command's text output) so it can be
tested against real sample output from Windows, Linux and macOS.

Wake-on-LAN, in one paragraph: a sleeping PC's network card listens for a special
UDP broadcast containing 6 bytes of 0xFF followed by the card's MAC address 16 times.
There is no reply, so the sender can never know whether it worked; the device either
turns on (and shows up in the next scan) or it doesn't. It needs WoL enabled in the
device's BIOS/NIC settings and usually works only over Ethernet.
"""

import ipaddress
import math
import platform
import re
import shutil
import socket
import subprocess

from identify import normalize_mac

WOL_PORTS = (9, 7)

# ---------------------------------------------------------------------------
# Wake-on-LAN
# ---------------------------------------------------------------------------


def build_magic_packet(mac: str) -> bytes:
    """6 x 0xFF, then the target MAC repeated 16 times (102 bytes)."""
    clean = normalize_mac(mac)
    if clean is None:
        raise ValueError("Not a valid MAC address.")
    return b"\xff" * 6 + bytes.fromhex(clean.replace(":", "")) * 16


def broadcast_targets(cidr: str) -> list:
    """Where to send the packet: the monitored network's own broadcast address
    (which the OS routes out of the right network card) plus the generic
    255.255.255.255, each on the two conventional WoL ports."""
    addrs = []
    try:
        addrs.append(str(ipaddress.ip_network(cidr, strict=False).broadcast_address))
    except ValueError:
        pass
    addrs.append("255.255.255.255")
    return [(addr, port) for addr in addrs for port in WOL_PORTS]


def send_magic_packet(mac: str, targets, source_ip: str | None = None) -> dict:
    """
    Broadcast a magic packet to every (address, port) in `targets`.
    Binding to `source_ip` (this PC's address on the LAN) makes the OS use that
    network card even when the PC has several (VirtualBox adds extra ones).
    Returns {"sent": <number of successful sends>, "errors": [..]}.
    """
    packet = build_magic_packet(mac)
    sent, errors = 0, []
    for addr, port in targets:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            if source_ip and source_ip != "unknown":
                try:
                    sock.bind((source_ip, 0))
                except OSError:
                    pass  # fall back to the OS's default choice of interface
            sock.sendto(packet, (addr, port))
            sent += 1
        except OSError as e:
            errors.append(f"{addr}:{port} - {e.strerror or e}")
        finally:
            sock.close()
    return {"sent": sent, "errors": errors}


# ---------------------------------------------------------------------------
# Ping
# ---------------------------------------------------------------------------

# Language-neutral on purpose: Windows prints "time=" in English but "Zeit=",
# "tiempo=" ... in other locales. The number followed by "ms" is always there.
_PING_MS = re.compile(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", re.IGNORECASE)
_PING_TTL = re.compile(r"\bTTL\s*[=:]\s*(\d+)", re.IGNORECASE)


def parse_ping(output: str) -> dict:
    """Pull the round-trip time and TTL out of ping output."""
    ms = _PING_MS.search(output)
    ttl = _PING_TTL.search(output)
    return {
        "ok": ms is not None,
        "ms": float(ms.group(1).replace(",", ".")) if ms else None,
        "ttl": int(ttl.group(1)) if ttl else None,
    }


def ping_once(ip: str, timeout_ms: int = 1000) -> dict:
    """One ping. `ip` must already be a validated IPv4 address (it is passed
    as a separate argument, never through a shell)."""
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, math.ceil(timeout_ms / 1000))), ip]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_ms / 1000 + 3).stdout
    except FileNotFoundError:
        return {"ok": False, "ms": None, "ttl": None, "error": "The ping command isn't available on this system."}
    except subprocess.TimeoutExpired:
        return {"ok": False, "ms": None, "ttl": None}
    return parse_ping(out)


# ---------------------------------------------------------------------------
# Traceroute
# ---------------------------------------------------------------------------

_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_MS = re.compile(r"(<?\s*\d+(?:[.,]\d+)?)\s*ms", re.IGNORECASE)


def parse_traceroute(output: str, target: str | None = None) -> dict:
    """
    Parse tracert (Windows) or 'traceroute -n' (Linux/macOS) output into
    {"hops": [{"hop": 1, "ip": "10.0.0.1" | None, "ms": 0.5 | None}, ...], "reached": bool}.
    A hop with no reply (shown as * * *) has ip = None.
    """
    hops = []
    for line in output.splitlines():
        m = re.match(r"^\s*(\d{1,2})\s+(\S.*)$", line)
        if not m:
            continue
        rest = m.group(2)
        ips = _IPV4.findall(rest)
        times = []
        for t in _MS.findall(rest):
            t = t.replace(" ", "")
            times.append(0.5 if t.startswith("<") else float(t.replace(",", ".")))   # "<1 ms" -> 0.5
        hops.append({
            "hop": int(m.group(1)),
            "ip": ips[0] if ips else None,
            "ms": round(sum(times) / len(times), 1) if times else None,
        })
    reached = bool(target and hops and hops[-1]["ip"] == target)
    return {"hops": hops, "reached": reached}


def traceroute(ip: str, max_hops: int = 20, timeout: int = 90) -> dict:
    """Run the system traceroute against a validated IPv4 address."""
    if platform.system().lower() == "windows":
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "1000", ip]
    elif shutil.which("traceroute"):
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", "1", "-q", "1", ip]
    else:
        return {"hops": [], "reached": False,
                "error": "traceroute isn't installed. On Debian/Ubuntu: sudo apt install traceroute"}
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except FileNotFoundError:
        return {"hops": [], "reached": False, "error": "The traceroute command isn't available on this system."}
    except subprocess.TimeoutExpired:
        return {"hops": [], "reached": False, "error": "The traceroute took too long and was stopped."}
    result = parse_traceroute(out, ip)
    result["error"] = None
    return result


# ---------------------------------------------------------------------------
# Default gateway
# ---------------------------------------------------------------------------


def parse_gateway_windows(output: str) -> str | None:
    """From 'route print -4 0.0.0.0': rows are  dest  mask  gateway  interface  metric."""
    best = None
    for line in output.splitlines():
        m = re.match(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+(\d+)", line)
        if m:
            metric = int(m.group(2))
            if best is None or metric < best[0]:
                best = (metric, m.group(1))
    return best[1] if best else None


def parse_gateway_linux(output: str) -> str | None:
    """From 'ip route show default':  default via 192.168.1.1 dev eth0 ..."""
    m = re.search(r"^default\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})", output, re.MULTILINE)
    return m.group(1) if m else None


def parse_gateway_macos(output: str) -> str | None:
    """From 'route -n get default':   gateway: 192.168.1.1"""
    m = re.search(r"gateway:\s*(\d{1,3}(?:\.\d{1,3}){3})", output)
    return m.group(1) if m else None


def default_gateway() -> str | None:
    """This PC's default gateway (the router), or None if it can't be found."""
    system = platform.system().lower()
    if system == "windows":
        cmd, parse = ["route", "print", "-4", "0.0.0.0"], parse_gateway_windows
    elif system == "darwin":
        cmd, parse = ["route", "-n", "get", "default"], parse_gateway_macos
    else:
        cmd, parse = ["ip", "route", "show", "default"], parse_gateway_linux
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    return parse(out)
