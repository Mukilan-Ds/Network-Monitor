"""
NetWatch - Database Module
------------------------------
Persists scan history to a local SQLite file so device trends survive
between app restarts, instead of resetting to empty every time the
app is closed and reopened.

Why SQLite specifically:
    - Built into Python's standard library (no extra install)
    - A single portable .db file, easy to inspect or back up
    - Handles concurrent-ish access fine for a single-user desktop app
    - Lets us query "last 30 readings for this IP" with a simple SQL
      query instead of hand-rolling file parsing

Usage:
    from database import init_db, record_scan, get_history
    init_db()
    record_scan("10.139.6.213", "My VM", avg_ms=12.3, min_ms=10.1, max_ms=15.0, loss_pct=0.0)
    history = get_history("10.139.6.213", limit=30)
"""

import datetime
import os
import sqlite3

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netwatch_history.db")


def init_db() -> None:
    """Create the scans table if it doesn't already exist. Safe to call
    every time the app starts -- CREATE TABLE IF NOT EXISTS is a no-op
    if the table is already there."""
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                device_name TEXT,
                timestamp TEXT NOT NULL,
                avg_ms REAL,
                min_ms REAL,
                max_ms REAL,
                loss_pct REAL
            )
            """
        )
        # Index speeds up "get history for this one IP" queries as the
        # table grows over many sessions.
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_ip ON scans(ip)")

        # Tracks every device identifier (MAC preferred, IP as fallback)
        # ever seen, so we can tell a brand-new device apart from one
        # that's simply reconnected. This is the basis for rogue/new
        # device alerts -- a lightweight intrusion-detection concept.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS known_devices (
                identifier TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL
            )
            """
        )

        # Every device ever seen, keyed by MAC address (a device's real
        # identity -- IPs change with DHCP). Powers the "offline devices"
        # list, Wake-on-LAN, and the trusted-devices feature.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS inventory (
                mac TEXT PRIMARY KEY,
                last_ip TEXT,
                name TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                trusted INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        # Which MAC last answered for each IP. A different MAC appearing for
        # the same IP is how address conflicts and ARP spoofing show up.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ip_bindings (
                ip TEXT PRIMARY KEY,
                mac TEXT NOT NULL,
                since TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def is_known_device(identifier: str) -> bool:
    """Returns True if this device identifier (MAC or IP) has been
    seen in any previous scan, ever."""
    conn = sqlite3.connect(DB_FILE)
    try:
        cursor = conn.execute(
            "SELECT 1 FROM known_devices WHERE identifier = ?", (identifier,)
        )
        return cursor.fetchone() is not None
    finally:
        conn.close()


def known_device_count() -> int:
    """How many distinct devices have ever been recorded. Zero means this
    is the very first run, so nothing yet counts as 'new' to alert about."""
    conn = sqlite3.connect(DB_FILE)
    try:
        return conn.execute("SELECT COUNT(*) FROM known_devices").fetchone()[0]
    finally:
        conn.close()


def mark_device_known(identifier: str) -> None:
    """Records a device identifier as seen. Safe to call repeatedly --
    INSERT OR IGNORE is a no-op if it's already recorded."""
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute(
            "INSERT OR IGNORE INTO known_devices (identifier, first_seen) VALUES (?, ?)",
            (identifier, datetime.datetime.now().isoformat(timespec="seconds")),
        )
        conn.commit()
    finally:
        conn.close()


def record_scan(ip: str, device_name: str, avg_ms, min_ms, max_ms, loss_pct: float) -> None:
    """Insert one scan result row for a device."""
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute(
            """
            INSERT INTO scans (ip, device_name, timestamp, avg_ms, min_ms, max_ms, loss_pct)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ip,
                device_name,
                datetime.datetime.now().isoformat(timespec="seconds"),
                avg_ms,
                min_ms,
                max_ms,
                loss_pct,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_history(ip: str, limit: int = 30) -> list[tuple[str, float]]:
    """
    Return the most recent `limit` (timestamp, avg_ms) readings for a
    device, oldest-first (so it's ready to feed straight into a graph).
    """
    conn = sqlite3.connect(DB_FILE)
    try:
        cursor = conn.execute(
            "SELECT timestamp, avg_ms FROM scans WHERE ip = ? ORDER BY id DESC LIMIT ?",
            (ip, limit),
        )
        rows = cursor.fetchall()
    finally:
        conn.close()

    return list(reversed(rows))  # DB gives newest-first; flip to chronological order


def prune_old_rows(days: int = 30) -> None:
    """
    Optional housekeeping: delete rows older than `days`, so the DB file
    doesn't grow forever if the app is left running for months. Not
    called automatically -- call it yourself if/when you want it.
    """
    cutoff = (datetime.datetime.now() - datetime.timedelta(days=days)).isoformat(timespec="seconds")
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute("DELETE FROM scans WHERE timestamp < ?", (cutoff,))
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Device inventory, trust and IP <-> MAC bindings
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


def _epoch(iso: str) -> float:
    try:
        return datetime.datetime.fromisoformat(iso).timestamp()
    except (TypeError, ValueError):
        return 0.0


def bulk_update_inventory(rows) -> None:
    """rows: iterable of (mac, ip, name). Inserts new devices and refreshes
    last_ip / name / last_seen for known ones, in one transaction."""
    now = _now()
    conn = sqlite3.connect(DB_FILE)
    try:
        for mac, ip, name in rows:
            conn.execute(
                "INSERT OR IGNORE INTO inventory (mac, last_ip, name, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
                (mac, ip, name, now, now),
            )
            conn.execute(
                "UPDATE inventory SET last_ip = ?, name = ?, last_seen = ? WHERE mac = ?",
                (ip, name, now, mac),
            )
        conn.commit()
    finally:
        conn.close()


def list_inventory() -> list[dict]:
    conn = sqlite3.connect(DB_FILE)
    try:
        cur = conn.execute(
            "SELECT mac, last_ip, name, first_seen, last_seen, trusted FROM inventory ORDER BY last_seen DESC"
        )
        return [
            {"mac": mac, "last_ip": ip, "name": name, "first_seen": _epoch(first),
             "last_seen": _epoch(last), "trusted": bool(trusted)}
            for mac, ip, name, first, last, trusted in cur.fetchall()
        ]
    finally:
        conn.close()


def trusted_macs() -> set:
    conn = sqlite3.connect(DB_FILE)
    try:
        return {r[0] for r in conn.execute("SELECT mac FROM inventory WHERE trusted = 1")}
    finally:
        conn.close()


def set_trusted(macs, trusted: bool) -> None:
    """Mark devices trusted/untrusted. A MAC not in the inventory yet is
    added (first/last seen = now) so trust can be granted before a rescan."""
    now = _now()
    conn = sqlite3.connect(DB_FILE)
    try:
        for mac in macs:
            conn.execute(
                "INSERT OR IGNORE INTO inventory (mac, last_ip, name, first_seen, last_seen) VALUES (?, NULL, NULL, ?, ?)",
                (mac, now, now),
            )
            conn.execute("UPDATE inventory SET trusted = ? WHERE mac = ?", (1 if trusted else 0, mac))
        conn.commit()
    finally:
        conn.close()


def forget_device(mac: str) -> None:
    """Remove a device entirely, so it counts as brand new if it returns."""
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute("DELETE FROM inventory WHERE mac = ?", (mac,))
        conn.execute("DELETE FROM ip_bindings WHERE mac = ?", (mac,))
        conn.execute("DELETE FROM known_devices WHERE identifier = ?", (mac,))
        conn.commit()
    finally:
        conn.close()


def get_bindings() -> dict:
    conn = sqlite3.connect(DB_FILE)
    try:
        return dict(conn.execute("SELECT ip, mac FROM ip_bindings").fetchall())
    finally:
        conn.close()


def set_bindings(bindings: dict) -> None:
    """bindings: {ip: mac}. Records who currently holds each IP."""
    now = _now()
    conn = sqlite3.connect(DB_FILE)
    try:
        for ip, mac in bindings.items():
            row = conn.execute("SELECT mac FROM ip_bindings WHERE ip = ?", (ip,)).fetchone()
            if row is None:
                conn.execute("INSERT INTO ip_bindings (ip, mac, since) VALUES (?, ?, ?)", (ip, mac, now))
            elif row[0] != mac:
                conn.execute("UPDATE ip_bindings SET mac = ?, since = ? WHERE ip = ?", (mac, now, ip))
        conn.commit()
    finally:
        conn.close()
