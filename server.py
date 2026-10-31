#!/usr/bin/env python3
"""
NetWatch Web - local server
--------------------------------
Runs the real network scans (discovery.py, latency.py, identify.py,
portscan.py, bandwidth.py, health.py, database.py, filetransfer.py) and
serves the web frontend in the web/ folder, which talks to this server
through a small JSON API.

Usage:
    python server.py                      # auto-detects your network, opens the browser
    python server.py --cidr 10.139.6.0/24 # choose the network to monitor
    python server.py --port 9000 --no-browser

Why a backend at all? A web page can't run ping, read the ARP table, scan
ports or open raw sockets -- browsers deliberately forbid it. So this
script does the network work in Python and the page just displays it.

Security model (this server can scan networks and move files, so it is
locked down):
    * It listens on 127.0.0.1 only -- other machines on your LAN cannot
      reach it.
    * Requests whose Host header isn't localhost are refused (defeats DNS
      rebinding), and every POST must carry an X-NetWatch header and a
      matching Origin (defeats other websites in your browser poking it).
    * Only private-network targets are accepted for scans and transfers,
      and scan ranges are limited to /22 or smaller.
    * Static files are served only from the web/ folder.
"""

import argparse
import csv
import datetime
import io
import ipaddress
import json
import mimetypes
import os
import re
import shutil
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

import database
import filetransfer as ft
import nettools
from bandwidth import measure_bandwidth
from discovery import scan_subnet
from health import (LATENCY_CRIT_MS, LATENCY_WARN_MS, LOSS_CRIT_PCT, LOSS_WARN_PCT,
                    compute_health_score, health_label)
from identify import get_vendor, identify, normalize_mac, read_arp_table
from latency import measure_all
from portscan import scan_ports

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(SCRIPT_DIR, "web")
LABELS_FILE = os.path.join(SCRIPT_DIR, "labels.json")

REFRESH_SECONDS = 15
PING_COUNT = 4
NEW_DEVICE_HIGHLIGHT_SECONDS = 600
MAX_ALERTS = 200
MAX_TRANSFER_ROWS = 100
MAX_JSON_BODY = 64 * 1024
MAX_UPLOAD = ft.DEFAULT_MAX_SIZE

mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("image/svg+xml", ".svg")


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message, self.status = message, status


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def clean_text(value, limit: int = 80) -> str:
    """Strip control characters and cap length. Hostnames and file names
    come from other devices on the network, so they are untrusted."""
    return _CONTROL.sub("", str(value or "")).strip()[:limit]


def validate_cidr(text: str) -> str:
    try:
        net = ipaddress.ip_network(str(text).strip(), strict=False)
    except ValueError:
        raise ApiError("That isn't a valid network. Use CIDR form, for example 192.168.1.0/24.")
    if net.version != 4:
        raise ApiError("Only IPv4 networks are supported.")
    if not (22 <= net.prefixlen <= 30):
        raise ApiError("Use a /22 to /30 range (at most 1,022 addresses) so a scan stays quick.")
    if not (net.is_private or net.is_link_local):
        raise ApiError("Only private network ranges can be scanned "
                       "(10.x.x.x, 172.16-31.x.x, 192.168.x.x).")
    return str(net)


def validate_target(text: str) -> str:
    """Scan / transfer targets must be IPv4 addresses on a private or
    loopback network -- this tool must never become a way to probe the
    public internet."""
    try:
        ip = ipaddress.ip_address(str(text).strip())
    except ValueError:
        raise ApiError("Enter a valid IPv4 address.")
    if ip.version != 4:
        raise ApiError("Only IPv4 addresses are supported.")
    if not (ip.is_private or ip.is_loopback or ip.is_link_local):
        raise ApiError("Only devices on a private network can be targeted.")
    return str(ip)


_HOSTNAME = re.compile(r"[A-Za-z0-9_]([A-Za-z0-9_.-]{0,251}[A-Za-z0-9_])?")


def resolve_ping_target(text: str) -> tuple:
    """
    Targets for ping and traceroute may be private OR public (tracing the way
    out to the internet is the classic use), given as an IPv4 address or a
    host name. Whatever is typed, only the RESOLVED IPv4 address is ever passed
    to the command (as a separate argument, never through a shell), so input
    like "-f" or "1.1.1.1; reboot" can't become options or commands.
    Returns (ip_string, what_the_user_typed).
    """
    text = str(text or "").strip()
    if not text:
        raise ApiError("Enter an IP address or host name.")
    try:
        ip = ipaddress.ip_address(text)
        if ip.version != 4:
            raise ApiError("Only IPv4 addresses are supported.")
    except ValueError:
        if not _HOSTNAME.fullmatch(text):
            raise ApiError("That doesn't look like an IP address or host name.")
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(text))
        except (OSError, ValueError):
            raise ApiError(f"Couldn't find an address for '{text}'.")
    if ip.is_unspecified or ip.is_multicast or ip == ipaddress.ip_address("255.255.255.255"):
        raise ApiError("That address can't be pinged.")
    return str(ip), text


def require_mac(text: str) -> str:
    mac = normalize_mac(text)
    if mac is None:
        raise ApiError("Enter a valid MAC address, like 08:00:27:AB:CD:EF.")
    if int(mac[:2], 16) & 1:
        raise ApiError("That is a broadcast/multicast address, not a device.")
    return mac


def validate_port(value, low: int = 1, high: int = 65535) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ApiError("Port must be a number.")
    if not low <= port <= high:
        raise ApiError(f"Port must be between {low} and {high}.")
    return port


def detect_cidr() -> str:
    """Best guess at the local network: this machine's LAN address with a
    /24 mask. (A UDP connect() sends no packets; it only asks the OS which
    local address it would route from.) Can be changed in Settings."""
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("192.0.2.1", 9))
        ip = probe.getsockname()[0]
        probe.close()
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except (OSError, ValueError):
        return "192.168.1.0/24"


def local_ip_for(cidr: str) -> str:
    try:
        target = str(ipaddress.ip_network(cidr, strict=False).network_address + 1)
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect((target, 9))
        ip = probe.getsockname()[0]
        probe.close()
        return ip
    except (OSError, ValueError):
        return "unknown"


def ip_key(ip: str):
    return tuple(int(p) for p in ip.split("."))


def classify(avg_ms, loss_pct) -> str:
    if avg_ms is None:
        return "critical"
    if avg_ms > LATENCY_CRIT_MS or loss_pct >= LOSS_CRIT_PCT:
        return "critical"
    if avg_ms > LATENCY_WARN_MS or loss_pct >= LOSS_WARN_PCT:
        return "warning"
    return "normal"


def csv_safe(value) -> str:
    """Neutralise spreadsheet formula injection: a device could advertise a
    hostname like '=HYPERLINK(...)' that Excel would execute on open."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def load_labels() -> dict:
    try:
        with open(LABELS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {k: clean_text(v, 60) for k, v in data.items() if isinstance(v, str)}
    except (OSError, ValueError, AttributeError):
        return {}


def save_labels(labels: dict) -> None:
    tmp = LABELS_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(labels, f, indent=2)
        os.replace(tmp, LABELS_FILE)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Application state (shared by the scan thread and HTTP request threads)
# ---------------------------------------------------------------------------

class State:
    def __init__(self, cidr: str):
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.cidr = cidr
        self.detected_cidr = detect_cidr()
        self._local_ip_cache: dict = {}
        self.auto_refresh = True
        self.scanning = False
        self.scan_error = None
        self.last_scan = 0.0
        self.scan_count = 0
        self.session_start = time.time()

        self.labels = load_labels()
        self.identity: dict = {}
        self.identity_tries: dict = {}
        self.device_rows: list = []
        self.last_stats: list = []
        self.new_until: dict = {}
        self.prev_status: dict = {}
        self.prev_ips: set = set()
        self.baseline_checked = False
        self.baseline = False
        self.trusted: set = self._load_trusted()
        self.gateway_ip = None
        self._gateway_for_cidr = None
        self.dup_reported: set = set()
        self.trace_slots = threading.BoundedSemaphore(2)

        self.alerts: list = []
        self.alert_seq = 0

        self.transfers: list = []
        self.transfer_seq = 0
        self.receiver = None
        self.receiver_info: dict = {}
        self._recv_rows: dict = {}

    @staticmethod
    def _load_trusted() -> set:
        try:
            return database.trusted_macs()
        except sqlite3.Error:
            return set()

    def local_ip(self) -> str:
        with self.lock:
            if self.cidr not in self._local_ip_cache:
                self._local_ip_cache[self.cidr] = local_ip_for(self.cidr)
            return self._local_ip_cache[self.cidr]

    # ---------- alerts ----------

    def log_alert(self, kind: str, message: str):
        with self.lock:
            self.alert_seq += 1
            self.alerts.insert(0, {"id": self.alert_seq, "ts": time.time(),
                                   "kind": kind, "message": message})
            del self.alerts[MAX_ALERTS:]

    def clear_alerts(self):
        with self.lock:
            self.alerts.clear()

    # ---------- scanning ----------

    def display_name(self, ip: str) -> str:
        with self.lock:
            return (self.labels.get(ip)
                    or self.identity.get(ip, {}).get("guessed_name")
                    or "Unknown device")

    def _identify_missing(self, ips):
        """Identify devices we haven't (successfully) identified yet,
        concurrently -- DNS lookups can take a second or two each."""
        todo = []
        with self.lock:
            for ip in ips:
                ident = self.identity.get(ip)
                if ident is None or (not ident.get("mac") and self.identity_tries.get(ip, 0) < 3):
                    todo.append(ip)
        if not todo:
            return
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(identify, todo))
        with self.lock:
            for ip, ident in zip(todo, results):
                ident = dict(ident)
                ident["guessed_name"] = clean_text(ident.get("guessed_name"), 80) or "Unknown device"
                self.identity[ip] = ident
                self.identity_tries[ip] = self.identity_tries.get(ip, 0) + 1

    def run_scan(self) -> bool:
        with self.lock:
            if self.scanning:
                return False
            self.scanning = True
            self.scan_error = None
            cidr = self.cidr
        try:
            live = scan_subnet(cidr)
            stats = measure_all(live, count=PING_COUNT) if live else []
            stats = sorted(stats, key=lambda s: ip_key(s["ip"]))
            ips = [s["ip"] for s in stats]
            self._identify_missing(ips)
            self._refresh_macs(ips)
            self._refresh_gateway(cidr)

            if not self.baseline_checked:
                # Very first scan ever (empty database): everything is "new"
                # by definition, so alerting on all of it would be noise.
                self.baseline = database.known_device_count() == 0
                self.baseline_checked = True

            now = time.time()
            new_ips, rows = [], []
            for s in stats:
                ip = s["ip"]
                ident = self.identity.get(ip, {})
                key = ident.get("mac") or ip
                if not database.is_known_device(key) and not self.baseline:
                    new_ips.append(ip)
                database.mark_device_known(key)
                database.record_scan(ip, self.display_name(ip), s["avg_ms"], s["min_ms"],
                                     s["max_ms"], s["loss_pct"])
                rows.append({"ip": ip, "avg_ms": s["avg_ms"], "min_ms": s["min_ms"],
                             "max_ms": s["max_ms"], "loss_pct": s["loss_pct"],
                             "status": classify(s["avg_ms"], s["loss_pct"])})

            self._check_mac_changes(ips)
            database.bulk_update_inventory(
                [(self.identity[r["ip"]]["mac"], r["ip"], self.display_name(r["ip"]))
                 for r in rows if self.identity.get(r["ip"], {}).get("mac")])

            with self.lock:
                first_scan = self.scan_count == 0
                cur = set(ips)
                for ip in new_ips:
                    self.new_until[ip] = now + NEW_DEVICE_HIGHLIGHT_SECONDS
                    self.log_alert("new_device", f"New device detected: {self.display_name(ip)} ({ip})")
                if not first_scan:
                    for ip in sorted(self.prev_ips - cur, key=ip_key):
                        self.log_alert("offline", f"{self.display_name(ip)} ({ip}) stopped responding")
                    for ip in sorted(cur - self.prev_ips - set(new_ips), key=ip_key):
                        self.log_alert("info", f"{self.display_name(ip)} ({ip}) is back online")
                for r in rows:
                    was = self.prev_status.get(r["ip"])
                    if r["status"] == "critical" and was != "critical":
                        detail = ("is not answering pings" if r["avg_ms"] is None
                                  else f"is unhealthy (avg {r['avg_ms']} ms, {r['loss_pct']}% loss)")
                        self.log_alert("critical", f"{self.display_name(r['ip'])} ({r['ip']}) {detail}")
                    self.prev_status[r["ip"]] = r["status"]
                self.prev_ips = cur
                self.baseline = False  # only the very first scan is a baseline
                self.device_rows = rows
                self.last_stats = stats
                self.scan_count += 1
        except Exception as e:  # keep the server alive whatever the network does
            with self.lock:
                self.scan_error = str(e)
            self.log_alert("critical", f"Scan error: {e}")
        finally:
            with self.lock:
                self.scanning = False
                self.last_scan = time.time()
        return True

    def _refresh_macs(self, ips):
        """Re-read every device's MAC from the ARP table on EVERY scan. (The
        identity cache only learns a MAC once, which would hide a change.)"""
        arp = read_arp_table()
        if not arp:
            return
        with self.lock:
            for ip in ips:
                mac = arp.get(ip)
                if mac:
                    ident = self.identity.setdefault(ip, {})
                    if ident.get("mac") != mac:
                        ident["mac"] = mac
                        ident["vendor"] = get_vendor(mac)

    def _refresh_gateway(self, cidr):
        with self.lock:
            if self._gateway_for_cidr == cidr and (self.gateway_ip or self.scan_count % 10):
                return
        gateway = nettools.default_gateway()
        try:
            if gateway and ipaddress.ip_address(gateway) not in ipaddress.ip_network(cidr, strict=False):
                gateway = None
        except ValueError:
            gateway = None
        with self.lock:
            self.gateway_ip, self._gateway_for_cidr = gateway, cidr

    def _name_for_mac(self, mac: str, names: dict | None = None) -> str:
        with self.lock:
            for ip, ident in self.identity.items():
                if ident.get("mac") == mac:
                    return self.display_name(ip)
        if names is None:
            names = {r["mac"]: r["name"] for r in database.list_inventory()}
        return clean_text(names.get(mac), 60)

    def _check_mac_changes(self, ips):
        """
        Two signs that something is wrong at the address level:
          * an IP that used to answer with one MAC now answers with another
            (an address conflict, a replaced device -- or ARP spoofing);
          * one MAC answering for several IPs at once (a proxy-ARP router, a
            device with several addresses -- or an attacker claiming victims).
        Both can be innocent, so the alerts say so, and devices you've marked
        trusted are not reported. A changed MAC on the GATEWAY is flagged
        separately because it is the classic man-in-the-middle sign.
        """
        with self.lock:
            macs = {ip: self.identity.get(ip, {}).get("mac") for ip in ips}
            trusted, gateway = set(self.trusted), self.gateway_ip
        macs = {ip: m for ip, m in macs.items() if m}
        bindings = database.get_bindings()
        names = None

        def label(mac):
            nonlocal names
            if names is None:
                names = {r["mac"]: r["name"] for r in database.list_inventory()}
            name = self._name_for_mac(mac, names)
            return f"{name} ({mac})" if name else mac

        for ip in sorted(macs, key=ip_key):
            old, new = bindings.get(ip), macs[ip]
            if not old or old == new or (old in trusted and new in trusted):
                continue
            if ip == gateway:
                self.log_alert("gateway_change",
                               f"Your gateway {ip} now answers with a different MAC address: {label(old)} \u2192 {label(new)}. "
                               "If you didn't replace your router, someone may be intercepting traffic (ARP spoofing).")
            else:
                self.log_alert("mac_change",
                               f"{ip} now belongs to a different device: {label(old)} \u2192 {label(new)}. Normal after a DHCP "
                               "lease change; it can also mean an address conflict or ARP spoofing.")

        by_mac = {}
        for ip, mac in macs.items():
            by_mac.setdefault(mac, []).append(ip)
        for mac, group in by_mac.items():
            if len(group) < 2 or mac in trusted:
                continue
            group = sorted(group, key=ip_key)
            key = (mac, tuple(group))
            if key in self.dup_reported:
                continue
            self.dup_reported.add(key)
            shown = ", ".join(group[:5]) + (f" and {len(group) - 5} more" if len(group) > 5 else "")
            self.log_alert("duplicate_mac",
                           f"{mac} is answering for {len(group)} addresses ({shown}). A router with proxy ARP or a device "
                           "with several addresses does this legitimately; otherwise it can mean ARP spoofing.")
        database.set_bindings(macs)

    def scan_loop(self):
        self.run_scan()
        while not self.stop.wait(1):
            with self.lock:
                due = (self.auto_refresh and not self.scanning
                       and time.time() - self.last_scan >= REFRESH_SECONDS)
            if due:
                self.run_scan()

    def start_scan_async(self) -> bool:
        with self.lock:
            if self.scanning:
                return False
        threading.Thread(target=self.run_scan, daemon=True).start()
        return True

    # ---------- snapshots for the API ----------

    def devices_public(self) -> list:
        now = time.time()
        out = []
        for d in self.device_rows:
            ip = d["ip"]
            ident = self.identity.get(ip, {})
            out.append({
                "ip": ip,
                "name": self.display_name(ip),
                "custom": ip in self.labels,
                "os": ident.get("os_guess"),
                "mac": ident.get("mac"),
                "vendor": ident.get("vendor"),
                "trusted": bool(ident.get("mac")) and ident.get("mac") in self.trusted,
                "is_gateway": ip == self.gateway_ip,
                "is_self": ip == self.local_ip(),
                "avg": d["avg_ms"], "min": d["min_ms"], "max": d["max_ms"], "loss": d["loss_pct"],
                "status": d["status"],
                "is_new": self.new_until.get(ip, 0) > now,
            })
        return out

    def snapshot(self) -> dict:
        with self.lock:
            if self.scan_count:
                score = compute_health_score(self.last_stats)
                health = {"score": score, "label": health_label(score)}
            else:
                health = {"score": None, "label": "Waiting for the first scan"}
            return {
                "now": time.time(),
                "cidr": self.cidr,
                "detected_cidr": self.detected_cidr,
                "local_ip": self.local_ip(),
                "auto_refresh": self.auto_refresh,
                "scanning": self.scanning,
                "scan_error": self.scan_error,
                "scan_count": self.scan_count,
                "last_scan": self.last_scan or None,
                "session_start": self.session_start,
                "refresh_seconds": REFRESH_SECONDS,
                "health": health,
                "devices": self.devices_public(),
                "alerts": list(self.alerts[:100]),
                "thresholds": {"latency_warn": LATENCY_WARN_MS, "latency_crit": LATENCY_CRIT_MS,
                               "loss_warn": LOSS_WARN_PCT, "loss_crit": LOSS_CRIT_PCT},
            }

    def report_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["Name", "IP", "MAC", "OS guess", "Status", "Trusted", "Avg (ms)", "Min (ms)", "Max (ms)", "Loss %"])
        with self.lock:
            for d in self.devices_public():
                w.writerow([csv_safe(d["name"]), d["ip"], csv_safe(d["mac"]), csv_safe(d["os"]),
                            d["status"], "yes" if d["trusted"] else "no", d["avg"], d["min"], d["max"], d["loss"]])
        return buf.getvalue()

    # ---------- labels / settings ----------

    def set_label(self, ip: str, name: str):
        ip = validate_target(ip)
        name = clean_text(name, 60)
        with self.lock:
            if name:
                self.labels[ip] = name
            else:
                self.labels.pop(ip, None)
            save_labels(self.labels)

    def clear_labels(self):
        with self.lock:
            self.labels.clear()
            save_labels(self.labels)

    def apply_settings(self, body: dict):
        if "auto_refresh" in body:
            with self.lock:
                self.auto_refresh = bool(body["auto_refresh"])
        if "cidr" in body:
            cidr = validate_cidr(body["cidr"])
            with self.lock:
                changed = cidr != self.cidr
                self.cidr = cidr
                if changed:
                    # Devices from the old network no longer apply.
                    self.device_rows, self.last_stats = [], []
                    self.prev_ips, self.prev_status = set(), {}
                    self.scan_count = 0
                    self.baseline_checked, self.baseline = True, True
                    self.dup_reported.clear()
                    self._gateway_for_cidr = None
            if changed:
                self.log_alert("info", f"Monitored network changed to {cidr}")
            self.start_scan_async()

    # ---------- inventory, trust, Wake-on-LAN ----------

    def mac_from_body(self, body: dict) -> str:
        """Accept either {"mac": ...} or {"ip": ...} (looked up among known devices)."""
        if body.get("mac"):
            return require_mac(body["mac"])
        ip = validate_target(body.get("ip", ""))
        with self.lock:
            mac = self.identity.get(ip, {}).get("mac")
        if not mac:
            mac = next((r["mac"] for r in database.list_inventory() if r["last_ip"] == ip), None)
        if not mac:
            raise ApiError("NetWatch doesn't know that device's MAC address yet.", 404)
        return mac

    def inventory_public(self) -> list:
        rows = database.list_inventory()
        with self.lock:
            online = {self.identity.get(d["ip"], {}).get("mac") for d in self.device_rows}
            trusted = set(self.trusted)
        for r in rows:
            r["name"] = clean_text(r["name"], 60) or "Unknown device"
            r["online"] = r["mac"] in online
            r["trusted"] = r["mac"] in trusted
        return rows

    def set_trust(self, mac: str, trusted: bool):
        database.set_trusted([mac], trusted)
        with self.lock:
            (self.trusted.add if trusted else self.trusted.discard)(mac)

    def trust_all_current(self) -> int:
        with self.lock:
            me = self.local_ip()
            macs = sorted({self.identity.get(d["ip"], {}).get("mac") for d in self.device_rows
                           if d["ip"] != me and self.identity.get(d["ip"], {}).get("mac")})
        database.set_trusted(macs, True)
        with self.lock:
            self.trusted.update(macs)
        return len(macs)

    def forget_device(self, mac: str):
        database.forget_device(mac)
        with self.lock:
            self.trusted.discard(mac)

    def wake(self, mac: str) -> dict:
        result = nettools.send_magic_packet(mac, nettools.broadcast_targets(self.cidr), self.local_ip())
        if result["sent"] == 0:
            detail = result["errors"][0] if result["errors"] else "no network route"
            raise ApiError(f"Couldn't send the Wake-on-LAN packet: {detail}", 502)
        name = self._name_for_mac(mac)
        self.log_alert("info", f"Wake-on-LAN packet sent to {name or 'device'} ({mac})")
        return result

    # ---------- file transfer ----------

    def _new_transfer(self, direction, name, peer, status, kind="busy", progress=None) -> dict:
        with self.lock:
            self.transfer_seq += 1
            row = {"id": self.transfer_seq, "ts": time.time(), "direction": direction,
                   "file": name, "peer": peer, "status": status, "kind": kind, "progress": progress}
            self.transfers.insert(0, row)
            del self.transfers[MAX_TRANSFER_ROWS:]
            return row

    def on_receiver_event(self, ev: dict):
        kind, peer = ev["kind"], ev.get("peer", "?")
        name = clean_text(ev.get("name"), 120) or None
        key = (peer, name)
        with self.lock:
            if kind == "started":
                self._recv_rows[key] = self._new_transfer(
                    "Received", name, peer, f"Receiving {ft.format_size(ev['size'])}...", "busy", 0)
            elif kind == "progress":
                row = self._recv_rows.get(key)
                if row:
                    pct = int(100 * ev["received"] / ev["size"]) if ev["size"] else 100
                    row.update(status=f"Receiving... {pct}%", progress=pct)
            elif kind == "done":
                row = self._recv_rows.pop(key, None) or self._new_transfer("Received", name, peer, "", "ok")
                risky = bool(ev.get("risky"))
                row.update(status="Saved - executable file type, don't run it unless you trust the sender"
                           if risky else "Saved", kind="bad" if risky else "ok", progress=100)
                self.log_alert("info", f"File received from {peer}: {name} ({ft.format_size(ev['size'])})")
            elif kind in ("rejected", "error"):
                row = self._recv_rows.pop(key, None)
                msg = clean_text(ev.get("message"), 200)
                if row:
                    row.update(status=msg, kind="bad", progress=None)
                else:
                    self._new_transfer("Received", name or "-", peer, msg, "bad")
                self.log_alert("critical", f"File transfer from {peer} failed: {msg}")

    def start_receiver(self, pin: str, port: int, save_dir: str):
        with self.lock:
            if self.receiver is not None:
                raise ApiError("The receiver is already running.", 409)
            save_dir = os.path.abspath(os.path.expanduser(save_dir.strip() or "~/NetWatch_Received"))
            try:
                receiver = ft.FileReceiver(save_dir, pin, port, on_event=self.on_receiver_event)
            except ValueError as e:
                raise ApiError(str(e))
            try:
                receiver.start()
            except OSError as e:
                raise ApiError(f"Could not listen on port {port}: {e}. "
                               "Another program may already be using it.", 409)
            self.receiver = receiver
            self.receiver_info = {"port": port, "dir": save_dir}
        self.log_alert("info", f"File receiver started on port {port}")

    def stop_receiver(self):
        with self.lock:
            receiver, self.receiver = self.receiver, None
            self.receiver_info = {}
        if receiver:
            receiver.stop()
            self.log_alert("info", "File receiver stopped")

    def files_snapshot(self) -> dict:
        with self.lock:
            running = self.receiver is not None and self.receiver.running
            return {
                "receiver": {"running": running, **(self.receiver_info if running else {})},
                "local_ip": self.local_ip(),
                "default_dir": os.path.join(os.path.expanduser("~"), "NetWatch_Received"),
                "default_port": ft.DEFAULT_PORT,
                "max_size": MAX_UPLOAD,
                "min_pin": ft.MIN_PIN_LENGTH,
                "transfers": list(self.transfers),
            }

    def start_send(self, tmp_dir: str, path: str, name: str, target: str, pin: str, port: int):
        row = self._new_transfer("Sent", name, target, "Connecting...", "busy", 0)

        def on_progress(sent, total):
            pct = int(100 * sent / total) if total else 100
            with self.lock:
                row.update(status=f"Sending... {pct}%", progress=pct)

        def worker():
            try:
                result = ft.send_file(target, path, pin, port, on_progress=on_progress)
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            with self.lock:
                if result["ok"]:
                    row.update(status=f"Delivered (saved as {clean_text(result['message'], 120)})",
                               kind="ok", progress=100)
                else:
                    row.update(status=f"Failed: {clean_text(result['message'], 200)}", kind="bad", progress=None)
            if result["ok"]:
                self.log_alert("info", f"File sent to {target}: {name}")

        threading.Thread(target=worker, daemon=True).start()
        return row["id"]

    def clear_transfers(self):
        with self.lock:
            self.transfers[:] = [t for t in self.transfers if t["kind"] == "busy"]


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "NetWatch"
    sys_version = ""

    # -- plumbing ----------------------------------------------------------

    @property
    def state(self) -> State:
        return self.server.state

    def log_message(self, fmt, *args):  # keep the console readable
        if args and str(args[1]).startswith(("4", "5")):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _headers_common(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")

    def _send_json(self, obj, status: int = 200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._headers_common()
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, data: bytes, ctype: str, extra=None, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self._headers_common()
        self.end_headers()
        self.wfile.write(data)

    def _host_ok(self) -> bool:
        return (self.headers.get("Host") or "").lower() in self.server.allowed_hosts

    def _post_ok(self) -> bool:
        if self.headers.get("X-NetWatch") != "1":
            return False
        origin = self.headers.get("Origin")
        return origin is None or origin.lower() == f"http://{(self.headers.get('Host') or '').lower()}"

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ApiError("Bad Content-Length.")
        if length > MAX_JSON_BODY:
            raise ApiError("Request too large.", 413)
        if length == 0:
            return {}
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            raise ApiError("Request body must be JSON.")
        if not isinstance(data, dict):
            raise ApiError("Request body must be a JSON object.")
        return data

    # -- GET ---------------------------------------------------------------

    def do_GET(self):
        try:
            if not self._host_ok():
                return self._send_json({"error": "Forbidden host."}, 403)
            url = urlparse(self.path)
            path, query = url.path, parse_qs(url.query)
            if path == "/api/state":
                return self._send_json(self.state.snapshot())
            if path == "/api/files":
                return self._send_json(self.state.files_snapshot())
            if path == "/api/history":
                ip = validate_target((query.get("ip") or [""])[0])
                pts = [{"t": t, "v": v} for t, v in database.get_history(ip, 60)]
                return self._send_json({"ip": ip, "points": pts})
            if path == "/api/inventory":
                return self._send_json({"devices": self.state.inventory_public()})
            if path == "/api/report.csv":
                stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                return self._send_bytes(
                    self.state.report_csv().encode("utf-8-sig"), "text/csv; charset=utf-8",
                    {"Content-Disposition": f'attachment; filename="netwatch_{stamp}.csv"'})
            if path.startswith("/api/"):
                return self._send_json({"error": "Not found."}, 404)
            return self._static(path)
        except ApiError as e:
            self._send_json({"error": e.message}, e.status)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            sys.stderr.write(f"Unhandled error on GET {self.path}: {e!r}\n")
            self._send_json({"error": "Internal error."}, 500)

    def _static(self, path: str):
        rel = unquote(path).lstrip("/") or "index.html"
        if "\x00" in rel:
            return self._send_bytes(b"Not found", "text/plain; charset=utf-8", status=404)
        root = os.path.realpath(WEB_DIR)
        full = os.path.realpath(os.path.join(root, rel))
        if not (full == root or full.startswith(root + os.sep)) or not os.path.isfile(full):
            return self._send_bytes(b"Not found", "text/plain; charset=utf-8", status=404)
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("image/svg+xml", "application/json"):
            ctype += "; charset=utf-8"
        extra = {}
        if full.endswith(".html"):
            extra["Content-Security-Policy"] = (
                "default-src 'self'; img-src 'self' data:; base-uri 'none'; "
                "form-action 'self'; frame-ancestors 'none'")
        with open(full, "rb") as f:
            self._send_bytes(f.read(), ctype, extra)

    # -- POST --------------------------------------------------------------

    def do_POST(self):
        try:
            if not self._host_ok():
                return self._send_json({"error": "Forbidden host."}, 403)
            if not self._post_ok():
                return self._send_json({"error": "Forbidden."}, 403)
            path = urlparse(self.path).path
            st = self.state

            if path == "/api/files/send":
                return self._handle_send()

            body = self._read_json()
            if path == "/api/scan":
                return self._send_json({"started": st.start_scan_async()}, 202)
            if path == "/api/settings":
                st.apply_settings(body)
                return self._send_json({"ok": True})
            if path == "/api/label":
                st.set_label(body.get("ip", ""), body.get("name", ""))
                return self._send_json({"ok": True})
            if path == "/api/labels/clear":
                st.clear_labels()
                return self._send_json({"ok": True})
            if path == "/api/alerts/clear":
                st.clear_alerts()
                return self._send_json({"ok": True})
            if path == "/api/portscan":
                ip = validate_target(body.get("ip", ""))
                return self._send_json({"ip": ip, "open": scan_ports(ip)})
            if path == "/api/bandwidth":
                ip = validate_target(body.get("ip", ""))
                return self._send_json({"ip": ip, **measure_bandwidth(ip)})
            if path == "/api/trust":
                st.set_trust(st.mac_from_body(body), bool(body.get("trusted", True)))
                return self._send_json({"ok": True})
            if path == "/api/trust/all":
                return self._send_json({"ok": True, "trusted": st.trust_all_current()})
            if path == "/api/forget":
                st.forget_device(require_mac(body.get("mac", "")))
                return self._send_json({"ok": True})
            if path == "/api/wol":
                result = st.wake(st.mac_from_body(body))
                return self._send_json({"ok": True, "sent": result["sent"]})
            if path == "/api/ping":
                ip, typed = resolve_ping_target(body.get("target"))
                return self._send_json({"target": typed, "ip": ip, **nettools.ping_once(ip)})
            if path == "/api/traceroute":
                ip, typed = resolve_ping_target(body.get("target"))
                if not st.trace_slots.acquire(blocking=False):
                    raise ApiError("Two traceroutes are already running. Wait for one to finish.", 429)
                try:
                    return self._send_json({"target": typed, "ip": ip, **nettools.traceroute(ip)})
                finally:
                    st.trace_slots.release()
            if path == "/api/files/receive/start":
                pin = str(body.get("pin", ""))
                port = validate_port(body.get("port", ft.DEFAULT_PORT), 1024)
                st.start_receiver(pin, port, str(body.get("dir", "")))
                return self._send_json({"ok": True})
            if path == "/api/files/receive/stop":
                st.stop_receiver()
                return self._send_json({"ok": True})
            if path == "/api/files/clear":
                st.clear_transfers()
                return self._send_json({"ok": True})
            return self._send_json({"error": "Not found."}, 404)
        except ApiError as e:
            self._send_json({"error": e.message}, e.status)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            sys.stderr.write(f"Unhandled error on POST {self.path}: {e!r}\n")
            self._send_json({"error": "Internal error."}, 500)

    def _handle_send(self):
        """The browser uploads the chosen file here; the server (which can
        open the raw socket a browser can't) forwards it to the device."""
        target = validate_target(self.headers.get("X-Target", ""))
        port = validate_port(self.headers.get("X-Port", ft.DEFAULT_PORT), 1, 65535)
        pin = unquote(self.headers.get("X-Pin", ""))  # URL-encoded by the page (headers are ASCII-only)
        if len(pin) < ft.MIN_PIN_LENGTH:
            raise ApiError(f"PIN must be at least {ft.MIN_PIN_LENGTH} characters.")
        name = ft.sanitize_filename(unquote(self.headers.get("X-Filename", "")))
        if not name:
            raise ApiError("Unusable file name.")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            raise ApiError("Missing Content-Length.", 411)
        if length < 0 or length > MAX_UPLOAD:
            raise ApiError(f"File too large (limit {ft.format_size(MAX_UPLOAD)}).", 413)

        tmp_dir = tempfile.mkdtemp(prefix="netwatch_send_")
        path = os.path.join(tmp_dir, name)
        try:
            self.connection.settimeout(60)
            remaining = length
            with open(path, "wb") as out:
                while remaining > 0:
                    block = self.rfile.read(min(ft.CHUNK, remaining))
                    if not block:
                        raise ApiError("Upload was interrupted.")
                    out.write(block)
                    remaining -= len(block)
        except BaseException:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise
        job = self.state.start_send(tmp_dir, path, name, target, pin, port)
        self._send_json({"id": job}, 202)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(state: State, port: int) -> Server:
    httpd = Server(("127.0.0.1", port), Handler)
    httpd.state = state
    bound = httpd.server_address[1]
    httpd.allowed_hosts = {f"127.0.0.1:{bound}", f"localhost:{bound}"}
    return httpd


def main():
    ap = argparse.ArgumentParser(description="NetWatch web server")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--cidr", help="network to monitor, e.g. 192.168.1.0/24 (default: auto-detect)")
    ap.add_argument("--no-browser", action="store_true", help="don't open the browser automatically")
    args = ap.parse_args()

    try:
        cidr = validate_cidr(args.cidr) if args.cidr else detect_cidr()
    except ApiError as e:
        sys.exit(f"Invalid --cidr: {e.message}")
    if not os.path.isdir(WEB_DIR):
        sys.exit(f"Can't find the web folder at {WEB_DIR}. Keep server.py next to the web/ folder.")

    database.init_db()
    state = State(cidr)

    httpd, port = None, args.port
    for candidate in range(args.port, args.port + 10):
        try:
            httpd = make_server(state, candidate)
            port = candidate
            break
        except OSError:
            continue
    if httpd is None:
        sys.exit(f"Ports {args.port}-{args.port + 9} are all in use. Try --port <number>.")

    threading.Thread(target=state.scan_loop, daemon=True).start()
    url = f"http://127.0.0.1:{port}/"
    print(f"NetWatch is running at {url}")
    print(f"Monitoring {cidr}  (change it in Settings)   -   press Ctrl+C to stop")
    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        state.stop.set()
        state.stop_receiver()
        httpd.server_close()


if __name__ == "__main__":
    main()
