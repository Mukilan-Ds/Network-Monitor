"""
NetWatch - Device Identification Module
------------------------------------------
Tries to figure out *what* a device is, not just that it responded to
a ping. Two independent techniques, since neither works 100% of the time:

    1. Reverse DNS / hostname lookup (socket.gethostbyaddr)
       - Works if the device broadcasts a name (Windows NetBIOS,
         mDNS/Avahi on some Linux distros). Often fails on a minimal
         Linux VM with no such service running.

    2. MAC address + vendor (OUI) lookup
       - Every MAC's first 3 bytes identify the manufacturer.
       - We read the MAC from the local ARP cache (populated
         automatically after you ping a device, which discovery.py
         and latency.py already do), so this needs no extra permissions.
       - Especially useful for a VM lab: VirtualBox, VMware, and
         Hyper-V virtual NICs all have distinct, well-known OUIs, so
         a VM will usually auto-identify as "VirtualBox Virtual NIC"
         even with zero configuration inside the guest OS.
       - MAC also survives DHCP reassigning the IP, unlike the IP itself.

Usage (standalone test):
    python identify.py 10.139.6.213
"""

import platform
import re
import socket
import subprocess
import sys

# A small offline table of common OUI prefixes (first 3 MAC bytes).
# Not exhaustive -- covers common virtualization platforms (most
# relevant for a VM lab) plus a handful of common real-hardware vendors.
# Format: "XX:XX:XX" (uppercase, colon-separated) -> vendor label
OUI_VENDORS = {
    "08:00:27": "VirtualBox Virtual NIC",
    "0A:00:27": "VirtualBox Virtual NIC (host-only)",
    "00:0C:29": "VMware Virtual NIC",
    "00:50:56": "VMware Virtual NIC",
    "00:05:69": "VMware Virtual NIC",
    "00:1C:14": "VMware Virtual NIC",
    "00:15:5D": "Microsoft Hyper-V Virtual NIC",
    "00:16:3E": "Xen Virtual NIC",
    "52:54:00": "QEMU/KVM Virtual NIC",
    "00:1A:4B": "Realtek",
    "00:E0:4C": "Realtek",
    "DC:A6:32": "Raspberry Pi Foundation",
    "B8:27:EB": "Raspberry Pi Foundation",
    "3C:5A:B4": "Google",
    "F4:F5:D8": "Google",
    "A4:83:E7": "Intel",
    "00:1B:21": "Intel",
    "FC:AA:14": "Apple",
    "AC:DE:48": "Apple",
    "B0:BE:76": "TP-Link",
    "50:C7:BF": "TP-Link",
    "C0:56:27": "Netgear",
}


def get_hostname(ip: str, timeout: float = 1.5) -> str | None:
    """
    Try a reverse DNS / NetBIOS name lookup. Returns the hostname
    (without domain suffix) if found, else None.
    """
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname.split(".")[0]  # strip domain suffix if present
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def get_mac(ip: str) -> str | None:
    """
    Look up the MAC address for an IP from the local ARP cache.
    Relies on the device having already been pinged recently (which
    discovery.py / latency.py already do), so the OS has a fresh
    ARP entry for it. Returns MAC as 'XX:XX:XX:XX:XX:XX' or None.
    """
    system = platform.system().lower()
    try:
        if system == "windows":
            output = subprocess.run(
                ["arp", "-a", ip], capture_output=True, text=True, timeout=3
            ).stdout
            # Windows format: "  10.139.6.213         08-00-27-ab-cd-ef     dynamic"
            match = re.search(r"([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}", output)
            if match:
                return match.group(0).replace("-", ":").upper()
        else:
            output = subprocess.run(
                ["ip", "neigh", "show", ip], capture_output=True, text=True, timeout=3
            ).stdout
            # Linux format: "10.139.6.213 dev eth0 lladdr 08:00:27:ab:cd:ef REACHABLE"
            match = re.search(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", output)
            if match:
                return match.group(0).upper()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def normalize_mac(text) -> str | None:
    """Return a MAC as 'AA:BB:CC:DD:EE:FF', or None if it isn't one.
    Accepts ':' '-' '.' separators or none (aa:bb.., aa-bb.., aabb.ccdd.eeff)."""
    compact = re.sub(r"[\s:.\-]", "", str(text))
    if re.fullmatch(r"[0-9a-fA-F]{12}", compact):
        return ":".join(compact[i:i + 2] for i in range(0, 12, 2)).upper()
    return None


_ARP_IP = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_ARP_MAC = re.compile(r"(?<![0-9a-fA-F:\-])((?:[0-9a-fA-F]{1,2}[:\-]){5}[0-9a-fA-F]{1,2})(?![0-9a-fA-F:\-])")


def parse_arp_table(text: str) -> dict:
    """
    Parse the output of 'arp -a' (Windows), 'arp -an' (macOS/Linux) or
    'ip neigh' (Linux) into {ip: MAC}. Skips incomplete entries, broadcast
    and multicast rows (Windows lists those as if they were devices).
    """
    table = {}
    for line in text.splitlines():
        if "incomplete" in line.lower() or "failed" in line.lower():
            continue
        ip_match, mac_match = _ARP_IP.search(line), _ARP_MAC.search(line)
        if not ip_match or not mac_match:
            continue
        ip = ip_match.group(1)
        octets = [int(o) for o in ip.split(".")]
        if any(o > 255 for o in octets) or octets[0] >= 224:      # multicast / broadcast / reserved
            continue
        parts = re.split(r"[:\-]", mac_match.group(1))
        mac = ":".join(p.zfill(2) for p in parts).upper()          # macOS prints '8:0:27:..'
        first_octet = int(parts[0], 16)
        if mac == "FF:FF:FF:FF:FF:FF" or first_octet & 1:           # broadcast / multicast MAC
            continue
        table[ip] = mac
    return table


def read_arp_table() -> dict:
    """The host's current ARP table as {ip: MAC}; {} if it can't be read.
    One call covers every device, so it is cheap enough to run every scan."""
    system = platform.system().lower()
    commands = [["arp", "-a"]] if system == "windows" else (
        [["arp", "-an"]] if system == "darwin" else [["ip", "neigh", "show"], ["arp", "-an"]])
    for cmd in commands:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
        except (OSError, subprocess.TimeoutExpired):
            continue
        table = parse_arp_table(out)
        if table:
            return table
    return {}


def get_vendor(mac: str | None) -> str | None:
    """Look up the vendor for a MAC address using the local OUI table."""
    if not mac:
        return None
    prefix = mac[:8]  # 'XX:XX:XX'
    return OUI_VENDORS.get(prefix.upper())


def get_ttl(ip: str, timeout: float = 1.0) -> int | None:
    """
    Send a single ping and extract the TTL value from the reply.
    Used for OS fingerprinting: different operating systems ship with
    different default TTLs, and that default survives (mostly intact)
    across a single local-network hop, so it's a decent hint about
    what kind of device answered -- with zero agent/software needed
    on the target.
    """
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 1
        )
        output = result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

    # Windows: "TTL=128"   Linux/macOS: "ttl=64"
    match = re.search(r"ttl[=:](\d+)", output, re.IGNORECASE)
    return int(match.group(1)) if match else None


def guess_os(ttl: int | None) -> str | None:
    """
    Map an observed TTL to a rough OS/device family guess.

    Most operating systems pick one of a few common starting TTLs
    (64, 128, 255) and decrement it by 1 per router hop. On the same
    local subnet there are usually 0-1 hops, so the observed value is
    normally within a few of the original -- hence the small buffer
    ranges below rather than requiring an exact match.
    """
    if ttl is None:
        return None
    if ttl > 200:
        return "Network device (router/switch) - TTL ~255"
    if ttl > 100:
        return "Windows - TTL ~128"
    if ttl > 30:
        return "Linux/Unix/macOS - TTL ~64"
    return "Unknown OS (unusual TTL)"


def identify(ip: str) -> dict:
    """
    Run all identification techniques for one IP and return a best-guess
    display name plus the raw evidence, so the GUI can show both.

    Returns:
        {
            "ip": str,
            "hostname": str | None,
            "mac": str | None,
            "vendor": str | None,
            "guessed_name": str,   # best available label, never None
        }
    """
    hostname = get_hostname(ip)
    mac = get_mac(ip)
    vendor = get_vendor(mac)
    ttl = get_ttl(ip)
    os_guess = guess_os(ttl)

    # Prefer a real hostname; fall back to vendor; fall back to "Unknown device"
    if hostname:
        guessed_name = hostname
    elif vendor:
        guessed_name = vendor
    else:
        guessed_name = "Unknown device"

    return {
        "ip": ip,
        "hostname": hostname,
        "mac": mac,
        "vendor": vendor,
        "ttl": ttl,
        "os_guess": os_guess,
        "guessed_name": guessed_name,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python identify.py <ip>")
        sys.exit(1)

    result = identify(sys.argv[1])
    print(f"IP:       {result['ip']}")
    print(f"Hostname: {result['hostname'] or '(none found)'}")
    print(f"MAC:      {result['mac'] or '(none found)'}")
    print(f"Vendor:   {result['vendor'] or '(unknown)'}")
    print(f"Guessed name: {result['guessed_name']}")
