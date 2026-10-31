"""
NetWatch - Bandwidth Module
------------------------------
Measures actual throughput (Mbps) to a device, as opposed to latency
(which only measures response time, not data-carrying capacity).

Requirement:
    - iperf3 must be available on THIS machine (the host) -- either on
      PATH, or its .exe placed directly in this script's own folder.
    - an iperf3 SERVER must be running on the target device:
        On the target (e.g. inside the Linux VM):  iperf3 -s
      This app only acts as the iperf3 CLIENT.

Usage (standalone test):
    python bandwidth.py 10.139.6.213
"""

import json
import os
import shutil
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOCAL_IPERF3 = os.path.join(SCRIPT_DIR, "iperf3.exe")


def find_iperf3() -> str | None:
    """
    Look for iperf3 in two places, in order:
      1. On the system PATH (normal case, if you added it there)
      2. Right next to this script (iperf3.exe in the same folder) --
         this avoids needing to edit PATH at all, just drop the .exe here.
    Returns the command to run (either "iperf3" or a full path), or None.
    """
    on_path = shutil.which("iperf3")
    if on_path:
        return on_path
    if os.path.exists(LOCAL_IPERF3):
        return LOCAL_IPERF3
    return None


def is_iperf3_available() -> bool:
    return find_iperf3() is not None


def measure_bandwidth(ip: str, duration: int = 3, port: int = 5201) -> dict:
    """
    Run an iperf3 client test against `ip` for `duration` seconds.

    Returns:
        {"success": True, "mbps": float}
        or
        {"success": False, "error": "<human-readable reason>"}
    """
    iperf3_cmd = find_iperf3()
    if not iperf3_cmd:
        return {
            "success": False,
            "error": "iperf3 not found. Either add it to your system PATH, "
                     "or drop iperf3.exe (and cygwin1.dll) directly in this "
                     f"app's folder ({SCRIPT_DIR}).",
        }

    cmd = [iperf3_cmd, "-c", ip, "-t", str(duration), "-p", str(port), "-J"]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=duration + 5
        )
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Timed out waiting for iperf3."}
    except FileNotFoundError:
        return {"success": False, "error": "iperf3 binary not found."}

    if result.returncode != 0:
        return {
            "success": False,
            "error": (result.stderr or "iperf3 client failed").strip()
            + " (is 'iperf3 -s' running on the target device?)",
        }

    try:
        data = json.loads(result.stdout)
        bits_per_second = data["end"]["sum_received"]["bits_per_second"]
        mbps = round(bits_per_second / 1_000_000, 2)
        return {"success": True, "mbps": mbps}
    except (json.JSONDecodeError, KeyError):
        return {"success": False, "error": "Could not parse iperf3 output."}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python bandwidth.py <ip>")
        sys.exit(1)

    outcome = measure_bandwidth(sys.argv[1])
    if outcome["success"]:
        print(f"Bandwidth: {outcome['mbps']} Mbps")
    else:
        print(f"Failed: {outcome['error']}")
