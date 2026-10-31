"""
NetWatch - File Transfer Module
------------------------------------
Send files to, and receive files from, other devices on your LAN.

Both sides need to run this code: NetWatch runs the receiver for you, and
this same file works standalone (no dependencies, Python 3.8+) so you can
copy it onto a Linux VM and run it there:

    On the receiving machine:   python3 filetransfer.py receive --pin 4821
    On the sending machine:     python3 filetransfer.py send 10.139.6.213 report.pdf --pin 4821

Protocol (one file per TCP connection):
    1. Receiver -> sender : "NWFT1 <random nonce>\\n"
    2. Sender -> receiver : one JSON header line: {name, size, sha256, auth}
       where auth = HMAC-SHA256(key=PIN, msg=nonce|name|size|sha256).
       The PIN itself is never sent, and the fresh nonce means a captured
       header can't be replayed against a later connection.
    3. Receiver -> sender : "READY\\n" (or "ERR <reason>\\n" and hangs up)
    4. Sender -> receiver : exactly <size> raw bytes
    5. Receiver verifies size + SHA-256, then replies "OK <saved name>\\n"

Security properties (and limits, honestly stated):
    + A PIN is mandatory; wrong/missing PIN is rejected before any data
      is accepted.
    + Filenames are sanitised to a bare name -- no path traversal, no
      writing outside the chosen folder; existing files are never
      overwritten (a " (1)" suffix is added instead).
    + A maximum file size is enforced, and data goes to a ".part" file
      that is only renamed after the SHA-256 checks out.
    - Contents are NOT encrypted. Fine for a home/lab LAN; don't use it
      across networks you don't trust.
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sys
import threading
import time

DEFAULT_PORT = 5005
DEFAULT_MAX_SIZE = 1024 * 1024 * 1024  # 1 GiB
MIN_PIN_LENGTH = 4
CHUNK = 64 * 1024
HEADER_LIMIT = 4096
IO_TIMEOUT = 15

RISKY_EXTENSIONS = {
    ".exe", ".msi", ".bat", ".cmd", ".com", ".scr", ".ps1", ".vbs", ".js",
    ".jar", ".sh", ".lnk", ".dll", ".reg",
}
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10)),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sanitize_filename(name: str) -> str:
    """Reduce an untrusted filename to a safe bare name. Returns '' if
    nothing usable is left."""
    name = str(name).replace("\\", "/").split("/")[-1]       # drop any directories
    name = re.sub(r"[\x00-\x1f<>:\"|?*]", "_", name).strip(" .")
    name = name[:120]
    if not name or name in (".", ".."):
        return ""
    stem = name.split(".")[0].upper()
    if stem in _WINDOWS_RESERVED:
        name = "_" + name
    return name


def unique_path(folder: str, name: str) -> str:
    """Return a path inside `folder` that doesn't exist yet."""
    base, ext = os.path.splitext(name)
    candidate = os.path.join(folder, name)
    n = 1
    while os.path.exists(candidate):
        candidate = os.path.join(folder, f"{base} ({n}){ext}")
        n += 1
    return candidate


def is_risky(name: str) -> bool:
    return os.path.splitext(name)[1].lower() in RISKY_EXTENSIONS


def _auth_tag(pin: str, nonce: str, name: str, size: int, sha256: str) -> str:
    msg = f"{nonce}|{name}|{size}|{sha256}".encode()
    return hmac.new(pin.encode(), msg, hashlib.sha256).hexdigest()


def _read_line(sock: socket.socket, limit: int = HEADER_LIMIT) -> bytes:
    """Read bytes up to a newline, refusing absurdly long lines."""
    buf = b""
    while len(buf) < limit:
        ch = sock.recv(1)
        if not ch:
            break
        if ch == b"\n":
            return buf
        buf += ch
    raise ValueError("header too long or connection closed")


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def format_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


# ---------------------------------------------------------------------------
# Sending
# ---------------------------------------------------------------------------

def send_file(host: str, path: str, pin: str, port: int = DEFAULT_PORT,
              on_progress=None, timeout: float = IO_TIMEOUT) -> dict:
    """
    Send one file. Returns {"ok": bool, "message": str, "name": str}.
    on_progress(sent_bytes, total_bytes) is called at most ~10x per second.
    """
    name = sanitize_filename(os.path.basename(path))
    if not os.path.isfile(path):
        return {"ok": False, "message": "File not found.", "name": name}
    if not name:
        return {"ok": False, "message": "Unusable file name.", "name": name}
    if len(pin) < MIN_PIN_LENGTH:
        return {"ok": False, "message": f"PIN must be at least {MIN_PIN_LENGTH} characters.", "name": name}

    size = os.path.getsize(path)
    try:
        digest = _file_sha256(path)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            greeting = _read_line(sock).decode(errors="replace").split()
            if len(greeting) != 2 or greeting[0] != "NWFT1":
                return {"ok": False, "message": "That port isn't a NetWatch receiver.", "name": name}
            nonce = greeting[1]

            header = {"name": name, "size": size, "sha256": digest,
                      "auth": _auth_tag(pin, nonce, name, size, digest)}
            sock.sendall((json.dumps(header) + "\n").encode())

            reply = _read_line(sock).decode(errors="replace")
            if reply != "READY":
                return {"ok": False, "message": reply.replace("ERR ", "", 1) or "Rejected.", "name": name}

            sent, last = 0, 0.0
            with open(path, "rb") as f:
                while True:
                    block = f.read(CHUNK)
                    if not block:
                        break
                    sock.sendall(block)
                    sent += len(block)
                    now = time.monotonic()
                    if on_progress and (now - last > 0.1 or sent == size):
                        on_progress(sent, size)
                        last = now

            final = _read_line(sock).decode(errors="replace")
            if final.startswith("OK"):
                return {"ok": True, "message": final[3:].strip() or name, "name": name}
            return {"ok": False, "message": final.replace("ERR ", "", 1), "name": name}
    except ConnectionRefusedError:
        return {"ok": False, "message": "Connection refused - is the receiver running on that device?", "name": name}
    except socket.timeout:
        return {"ok": False, "message": "Timed out talking to the device (firewall?).", "name": name}
    except (OSError, ValueError) as e:
        return {"ok": False, "message": f"Transfer failed: {e}", "name": name}


# ---------------------------------------------------------------------------
# Receiving
# ---------------------------------------------------------------------------

class FileReceiver:
    """
    Listens for incoming transfers in background threads.

    on_event(dict) is called from those threads, with dicts like:
        {"kind": "started",  "peer": ip, "name": ..., "size": ...}
        {"kind": "progress", "peer": ip, "name": ..., "received": n, "size": n}
        {"kind": "done",     "peer": ip, "name": ..., "size": ..., "path": ..., "risky": bool}
        {"kind": "rejected" | "error", "peer": ip, "message": ...}
    """

    def __init__(self, save_dir: str, pin: str, port: int = DEFAULT_PORT,
                 max_size: int = DEFAULT_MAX_SIZE, on_event=None):
        if len(pin) < MIN_PIN_LENGTH:
            raise ValueError(f"PIN must be at least {MIN_PIN_LENGTH} characters.")
        self.save_dir, self.pin, self.port = save_dir, pin, port
        self.max_size = max_size
        self.on_event = on_event or (lambda ev: None)
        self._server = None
        self._thread = None
        self._stop = threading.Event()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        os.makedirs(self.save_dir, exist_ok=True)
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("0.0.0.0", self.port))
        except OSError:
            server.close()
            raise
        server.listen(8)
        server.settimeout(0.5)
        self._server = server
        self._stop.clear()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        if self._server:
            self._server.close()
            self._server = None

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, addr[0]), daemon=True).start()

    def _emit(self, **ev):
        try:
            self.on_event(ev)
        except Exception:
            pass  # a faulty UI callback must never break a transfer

    def _reject(self, conn, peer, reason):
        try:
            conn.sendall(f"ERR {reason}\n".encode())
        except OSError:
            pass
        self._emit(kind="rejected", peer=peer, message=reason)

    def _handle(self, conn: socket.socket, peer: str):
        part_path = None
        try:
            conn.settimeout(IO_TIMEOUT)
            nonce = secrets.token_hex(16)
            conn.sendall(f"NWFT1 {nonce}\n".encode())

            try:
                header = json.loads(_read_line(conn))
                name, size, digest, auth = header["name"], header["size"], header["sha256"], header["auth"]
                if not (isinstance(name, str) and isinstance(size, int) and isinstance(digest, str)
                        and isinstance(auth, str)) or isinstance(size, bool):
                    raise ValueError
            except (ValueError, KeyError, TypeError):
                return self._reject(conn, peer, "Malformed request.")

            # Authenticate BEFORE trusting anything else in the header.
            expected = _auth_tag(self.pin, nonce, name, size, digest)
            if not hmac.compare_digest(expected, auth):
                return self._reject(conn, peer, "Wrong PIN.")

            safe_name = sanitize_filename(name)
            if not safe_name:
                return self._reject(conn, peer, "Unusable file name.")
            if size < 0 or size > self.max_size:
                return self._reject(conn, peer, f"File too large (limit {format_size(self.max_size)}).")
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                return self._reject(conn, peer, "Malformed checksum.")

            final_path = unique_path(self.save_dir, safe_name)
            part_path = final_path + ".part"
            conn.sendall(b"READY\n")
            self._emit(kind="started", peer=peer, name=safe_name, size=size)

            h, received, last = hashlib.sha256(), 0, 0.0
            with open(part_path, "wb") as out:
                while received < size:
                    block = conn.recv(min(CHUNK, size - received))
                    if not block:
                        raise ConnectionError("sender disconnected early")
                    out.write(block)
                    h.update(block)
                    received += len(block)
                    now = time.monotonic()
                    if now - last > 0.1 or received == size:
                        self._emit(kind="progress", peer=peer, name=safe_name, received=received, size=size)
                        last = now

            if h.hexdigest() != digest:
                os.remove(part_path)
                part_path = None
                conn.sendall(b"ERR Checksum mismatch - file corrupted in transit.\n")
                return self._emit(kind="error", peer=peer, name=safe_name,
                                  message="Checksum mismatch - file discarded.")

            os.replace(part_path, final_path)
            part_path = None
            conn.sendall(f"OK {os.path.basename(final_path)}\n".encode())
            self._emit(kind="done", peer=peer, name=os.path.basename(final_path), size=size,
                       path=final_path, risky=is_risky(safe_name))
        except (OSError, ConnectionError, socket.timeout) as e:
            self._emit(kind="error", peer=peer, message=f"Transfer interrupted: {e}")
        finally:
            if part_path and os.path.exists(part_path):
                try:
                    os.remove(part_path)
                except OSError:
                    pass
            try:
                conn.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Standalone command line
# ---------------------------------------------------------------------------

def _cli():
    ap = argparse.ArgumentParser(description="NetWatch LAN file transfer")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("receive", help="listen for incoming files")
    r.add_argument("--pin", required=True)
    r.add_argument("--dir", default=os.path.join(os.path.expanduser("~"), "NetWatch_Received"))
    r.add_argument("--port", type=int, default=DEFAULT_PORT)

    s = sub.add_parser("send", help="send a file to a receiver")
    s.add_argument("host")
    s.add_argument("file")
    s.add_argument("--pin", required=True)
    s.add_argument("--port", type=int, default=DEFAULT_PORT)

    args = ap.parse_args()

    if args.cmd == "send":
        def show(sent, total):
            print(f"\r  {format_size(sent)} / {format_size(total)}", end="", flush=True)
        res = send_file(args.host, args.file, args.pin, args.port, on_progress=show)
        print()
        print(("Sent: " if res["ok"] else "Failed: ") + res["message"])
        sys.exit(0 if res["ok"] else 1)

    def log(ev):
        k = ev["kind"]
        if k == "started":
            print(f"Receiving {ev['name']} ({format_size(ev['size'])}) from {ev['peer']} ...")
        elif k == "done":
            warn = "  [!] executable type - don't run it unless you trust the sender" if ev["risky"] else ""
            print(f"Saved {ev['path']}{warn}")
        elif k in ("rejected", "error"):
            print(f"{k.title()} ({ev['peer']}): {ev['message']}")

    try:
        rx = FileReceiver(args.dir, args.pin, args.port, on_event=log)
        rx.start()
    except (ValueError, OSError) as e:
        sys.exit(f"Could not start receiver: {e}")
    print(f"Listening on port {args.port}, saving to {args.dir}  (Ctrl+C to stop)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        rx.stop()


if __name__ == "__main__":
    _cli()
