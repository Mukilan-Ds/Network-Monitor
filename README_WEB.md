# NetWatch Web

The NetWatch desktop app as a web app: an HTML/CSS/JavaScript frontend (`web/`) plus a small
Python server (`server.py`) that runs the real network scans.

## Run it
    python server.py

It opens http://127.0.0.1:8080 in your browser. Options:

    python server.py --cidr 10.139.6.0/24    # network to monitor (default: auto-detected /24)
    python server.py --port 9000             # different port
    python server.py --no-browser

Needs only Python 3.10+. No pip installs. Keep these files in one folder:
`server.py`, `web/`, `discovery.py`, `latency.py`, `identify.py`, `portscan.py`,
`bandwidth.py`, `health.py`, `database.py`, `filetransfer.py`, `nettools.py`.

## Trusted devices and address-change alerts
- On **Devices**, click a device's *Not trusted* chip to mark it **Trusted**, or use *Trust all* once
  you recognise everything. The dashboard shows how many devices you haven't reviewed yet.
- NetWatch re-reads every device's MAC address on each scan and alerts when:
  - an address now answers with a **different MAC** (a DHCP change, an address conflict, or ARP spoofing);
  - your **gateway's** MAC changes (the classic man-in-the-middle sign, so it gets its own louder alert);
  - **one MAC answers for several addresses** (a proxy-ARP router, or an attacker claiming other devices).
- These can all be innocent, so the alerts say so. A swap between two *trusted* devices is not reported.
- A device with no readable MAC (and the PC running NetWatch) can't be trusted or tracked this way.

## Wake-on-LAN
Devices NetWatch has seen before stay listed under **Offline devices** with a *Wake* button; you can also
type any MAC in **Network Tools**. There is no reply to a wake-up packet, so NetWatch rescans and tells you
when the device comes online (or that it didn't within 90 seconds). The target needs Wake-on-LAN enabled in
its BIOS and network adapter settings, and usually has to be wired.

## Ping and traceroute
**Network Tools** has a live ping graph (one ping a second, stops by itself after 10 minutes or when you
leave the page) and a traceroute. Unlike scans and file transfers, these may also target internet
addresses and host names. Linux needs the `traceroute` package (`sudo apt install traceroute`).

## Why a Python server?
Browsers can't run ping, read the ARP table, scan ports or open raw sockets, so the page
asks the server (which runs on your PC) to do that and just displays the results.

## Security
- Listens on 127.0.0.1 only, so other devices on your network cannot open it.
- Requests with a foreign Host header are refused (DNS rebinding), and every POST needs a
  custom header plus a matching Origin (other websites in your browser can't drive it).
- Scans, port checks, Wake-on-LAN and file transfers only accept private-network targets; scan ranges are
  /22 or smaller. Ping and traceroute may also reach the internet; only the resolved IP is ever passed to the
  command, never raw text.
- Device names and file names come from the network and are always rendered as plain text.
- File transfer needs a PIN (never sent over the network) but contents are NOT encrypted.
