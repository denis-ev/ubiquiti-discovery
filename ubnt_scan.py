#!/usr/bin/env python3
"""
ubnt_scan.py - Ubiquiti device discovery (airOS / airMAX / airFiber / EdgeSwitch /
EdgeRouter / UniFi) for a laptop on the local segment.

Pure standard library. No scapy, no Npcap, no root/admin required (except that
binding UDP/10001 may need elevation on some locked-down hosts - the script falls
back to an ephemeral port automatically).

Sends both discovery probes:
    v1  01 00 00 00   -> airOS / airMAX / airFiber / UniFi
    v2  02 08 00 00   -> EdgeSwitch, EdgeRouter, EdgeMAX, newer airOS 8.x

Usage:
    python3 ubnt_scan.py                       # broadcast discovery, all interfaces
    python3 ubnt_scan.py -t 10                 # longer listen window
    python3 ubnt_scan.py --watch               # keep scanning, report new/changed
    python3 ubnt_scan.py --sweep 192.168.1.0/24 # unicast probe a routed subnet
    python3 ubnt_scan.py --json devices.json   # machine-readable output
    python3 ubnt_scan.py --csv devices.csv
"""

import argparse
import csv
import ipaddress
import json
import os
import select
import socket
import struct
import sys
import tempfile
import time
from collections import namedtuple
from datetime import datetime

WINDOWS = os.name == "nt"

UBNT_PORT = 10001
UBNT_MCAST = "233.89.188.1"

PROBE_V1 = b"\x01\x00\x00\x00"
PROBE_V2 = b"\x02\x08\x00\x00"

# ---------------------------------------------------------------------------
# TLV field types seen in discovery replies
# ---------------------------------------------------------------------------
F_MAC = 0x01
F_MAC_IP = 0x02
F_FIRMWARE = 0x03
F_UPTIME = 0x0A
F_HOSTNAME = 0x0B
F_PLATFORM = 0x0C
F_ESSID = 0x0D
F_WMODE = 0x0E
F_MODEL_FULL = 0x14
F_MODEL_V2 = 0x15
F_FWVERSION_V2 = 0x16
F_MODEL_NAME_V2 = 0x1B

# Best-effort only: airOS wireless mode codes are not officially documented and
# differ between firmware trains. Unknown values are shown as "mode-N".
WMODES = {
    0: "Auto",
    1: "AdHoc",
    2: "Station",
    3: "AP",
    4: "Station WDS",
    5: "AP WDS",
    6: "Station Bridge",
    7: "AP Repeater",
    8: "AP PtP",
    9: "Station PtP",
}


def mac_str(raw):
    return ":".join("%02X" % b for b in raw)


def fmt_uptime(seconds):
    if seconds is None:
        return ""
    d, rem = divmod(int(seconds), 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return "%dd %dh" % (d, h)
    if h:
        return "%dh %dm" % (h, m)
    return "%dm" % m


def parse_reply(data, src_ip):
    """Parse a UBNT discovery reply into a dict, or return None if it isn't one."""
    if len(data) < 4:
        return None
    version, cmd = data[0], data[1]
    if version not in (1, 2):
        return None

    length = struct.unpack("!H", data[2:4])[0]
    body = data[4:4 + length] if length else data[4:]

    dev = {
        "ip": src_ip,
        "proto": "v%d" % version,
        "cmd": cmd,
        "mac": "",
        "addresses": [],
        "hostname": "",
        "platform": "",
        "model_full": "",
        "model_v2": "",
        "model_name_v2": "",
        "firmware": "",
        "fw_version": "",
        "essid": "",
        "wmode": "",
        "uptime_seconds": None,
        "unknown_fields": {},
    }

    i = 0
    while i + 3 <= len(body):
        ftype = body[i]
        flen = struct.unpack("!H", body[i + 1:i + 3])[0]
        i += 3
        val = body[i:i + flen]
        if len(val) < flen:      # truncated / malformed, stop cleanly
            break
        i += flen

        try:
            if ftype == F_MAC and flen >= 6:
                dev["mac"] = dev["mac"] or mac_str(val[:6])
            elif ftype == F_MAC_IP and flen >= 10:
                dev["mac"] = dev["mac"] or mac_str(val[:6])
                ip = socket.inet_ntoa(val[6:10])
                if ip not in dev["addresses"]:
                    dev["addresses"].append(ip)
            elif ftype == F_FIRMWARE:
                dev["firmware"] = val.decode("utf-8", "replace").strip("\x00")
            elif ftype == F_FWVERSION_V2:
                dev["fw_version"] = val.decode("utf-8", "replace").strip("\x00")
            elif ftype == F_UPTIME and flen >= 4:
                dev["uptime_seconds"] = struct.unpack("!I", val[:4])[0]
            elif ftype == F_HOSTNAME:
                dev["hostname"] = val.decode("utf-8", "replace").strip("\x00")
            elif ftype == F_PLATFORM:
                dev["platform"] = val.decode("utf-8", "replace").strip("\x00")
            elif ftype == F_ESSID:
                dev["essid"] = val.decode("utf-8", "replace").strip("\x00")
            elif ftype == F_WMODE and flen >= 1:
                dev["wmode"] = WMODES.get(val[0], "mode-%d" % val[0])
            elif ftype == F_MODEL_FULL:
                dev["model_full"] = val.decode("utf-8", "replace").strip("\x00")
            elif ftype == F_MODEL_V2:
                dev["model_v2"] = val.decode("utf-8", "replace").strip("\x00")
            elif ftype == F_MODEL_NAME_V2:
                dev["model_name_v2"] = val.decode("utf-8", "replace").strip("\x00")
            else:
                dev["unknown_fields"]["0x%02x" % ftype] = val.hex()
        except Exception:
            dev["unknown_fields"]["0x%02x" % ftype] = val.hex()

    dev["model"] = (dev["model_name_v2"] or dev["model_full"]
                    or dev["model_v2"] or dev["platform"] or "")
    dev["fw"] = dev["fw_version"] or dev["firmware"]
    if src_ip not in dev["addresses"]:
        dev["addresses"].insert(0, src_ip)
    return dev


# ---------------------------------------------------------------------------
# Interface handling
# ---------------------------------------------------------------------------
def local_ipv4s():
    """Return local IPv4 addresses. Uses netifaces/psutil if present, else falls
    back to hostname resolution plus the default-route address."""
    addrs = set()

    try:
        import netifaces
        for iface in netifaces.interfaces():
            for a in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
                if a.get("addr"):
                    addrs.add(a["addr"])
    except Exception:
        pass

    if not addrs:
        try:
            import psutil
            for _, snics in psutil.net_if_addrs().items():
                for snic in snics:
                    if snic.family == socket.AF_INET and snic.address:
                        addrs.add(snic.address)
        except Exception:
            pass

    if not addrs:
        try:
            _, _, ips = socket.gethostbyname_ex(socket.gethostname())
            addrs.update(ips)
        except Exception:
            pass
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # No packet is sent; connect() on UDP only asks the kernel
            # which source address it would use. 192.0.2.1 is TEST-NET-1.
            s.connect(("192.0.2.1", 53))
            addrs.add(s.getsockname()[0])
            s.close()
        except Exception:
            pass

    addrs = {a for a in addrs if not a.startswith("127.")}
    return sorted(addrs)


Sock = namedtuple("Sock", "ip port sock sender")


def _join_mcast(s, ip):
    try:
        mreq = struct.pack("=4s4s", socket.inet_aton(UBNT_MCAST),
                           socket.inet_aton(ip))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    except OSError:
        pass


def make_wildcard_socket(bind_ips, verbose=False):
    """Receive-only socket on 0.0.0.0:10001.

    Many airOS devices answer a discovery probe by *broadcasting* the reply to
    255.255.255.255:10001 instead of unicasting it back to our source port. A
    socket bound to a specific interface address never sees those, so we keep a
    wildcard listener running alongside the per-interface senders. Replies that
    arrive on both are merged by MAC in collect().
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        s.bind(("", UBNT_PORT))
    except OSError as exc:
        print("  ! cannot bind 0.0.0.0:%d (%s)" % (UBNT_PORT, exc),
              file=sys.stderr)
        print("    Devices that broadcast their reply will be missed. Close "
              "the Ubiquiti Discovery Tool / UISP agent and retry.",
              file=sys.stderr)
        s.close()
        return None
    for ip in bind_ips:
        _join_mcast(s, ip)
    # IP_PKTINFO tells us the receiving interface, so a reply heard on the
    # native LAN is not mis-attributed to the VLAN currently being probed.
    if hasattr(socket, "IP_PKTINFO"):
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_PKTINFO, 1)
        except OSError:
            pass
    s.setblocking(False)
    if verbose:
        print("  * listening on 0.0.0.0:%d (broadcast catcher)" % UBNT_PORT,
              file=sys.stderr)
    return Sock("0.0.0.0", UBNT_PORT, s, False)


def make_device_socket(device, verbose=False):
    """Sender bound to a named interface via SO_BINDTODEVICE (Linux only, needs
    root or CAP_NET_RAW).

    This is how you probe a VLAN sub-interface that has no usable IPv4 address:
    the probe still egresses the right interface. Devices that unicast their
    reply cannot answer a source of 0.0.0.0, so on an address-less interface
    you will only see devices that broadcast their reply - which the wildcard
    listener picks up. Give the interface an address in the target subnet to
    see the rest.
    """
    if not hasattr(socket, "SO_BINDTODEVICE"):
        print("  ! --device is Linux-only on this Python build; ignoring %s"
              % device, file=sys.stderr)
        return None
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                     device.encode() + b"\x00")
    except OSError as exc:
        print("  ! cannot bind to device %s (%s) - run as root?"
              % (device, exc), file=sys.stderr)
        s.close()
        return None
    try:
        s.bind(("", UBNT_PORT))
        port = UBNT_PORT
    except OSError:
        s.bind(("", 0))
        port = s.getsockname()[1]
    s.setblocking(False)
    if verbose:
        print("  * probing via device %s from port %d" % (device, port),
              file=sys.stderr)
    return Sock(device, port, s, True)


def make_sockets(bind_ips, verbose=False, wildcard=True, devices=()):
    """A receive-only wildcard socket, plus one sender per local IP (and per
    named device) so probes leave every interface."""
    socks = []
    if wildcard:
        wc = make_wildcard_socket(bind_ips, verbose=verbose)
        if wc:
            socks.append(wc)
    for device in devices:
        entry = make_device_socket(device, verbose=verbose)
        if entry:
            socks.append(entry)
    for ip in bind_ips:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            s.bind((ip, UBNT_PORT))
            port = UBNT_PORT
        except OSError:
            # Port busy. Unicast replies still land on the ephemeral port, and
            # the wildcard socket above covers broadcast replies.
            s.bind((ip, 0))
            port = s.getsockname()[1]
            if verbose:
                print("  ! %s: UDP/%d unavailable, sending from port %d"
                      % (ip, UBNT_PORT, port), file=sys.stderr)
        _join_mcast(s, ip)
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                         socket.inet_aton(ip))
        except OSError:
            pass
        s.setblocking(False)
        socks.append(Sock(ip, port, s, True))
        if verbose:
            print("  * probing from %s:%d" % (ip, port), file=sys.stderr)
    return socks


def send_probes(socks, targets, repeats=2, delay=0.15):
    for _ in range(repeats):
        for entry in socks:
            if not entry.sender:
                continue
            for dst in targets:
                for probe in (PROBE_V1, PROBE_V2):
                    try:
                        entry.sock.sendto(probe, (dst, UBNT_PORT))
                    except OSError:
                        pass
        time.sleep(delay)


def sweep_probes(socks, network, rate=400, should_stop=None):
    """Unicast probe every host in a CIDR - works across routed links.

    should_stop is an optional callable checked between hosts, so a long
    sweep can be cancelled instead of running to completion.
    """
    net = ipaddress.ip_network(network, strict=False)
    hosts = list(net.hosts()) if net.prefixlen < 31 else list(net)
    interval = 1.0 / rate
    sent = 0
    for host in hosts:
        if should_stop and should_stop():
            return sent
        sent += 1
        dst = str(host)
        for entry in socks:
            if not entry.sender:
                continue
            for probe in (PROBE_V1, PROBE_V2):
                try:
                    entry.sock.sendto(probe, (dst, UBNT_PORT))
                except OSError:
                    pass
        time.sleep(interval)
    return sent


PKTINFO_AVAILABLE = hasattr(socket, "IP_PKTINFO") and hasattr(socket.socket,
                                                              "recvmsg")


def _recv(sock, want_pktinfo):
    """recvfrom, plus the arrival interface name where the OS will tell us.

    recvmsg() does not exist on Windows, so the arrival interface is unknown
    there and per-interface filtering cannot work. Use --no-wildcard on
    Windows when results must be attributable to one interface.
    """
    if want_pktinfo and PKTINFO_AVAILABLE:
        try:
            data, ancdata, _flags, addr = sock.recvmsg(4096,
                                                       socket.CMSG_SPACE(64))
        except OSError:
            return None, None, None
        ifname = None
        for level, ctype, cdata in ancdata:
            if (level == socket.IPPROTO_IP and ctype == socket.IP_PKTINFO
                    and len(cdata) >= 4):
                idx = struct.unpack("i", cdata[:4])[0]
                try:
                    ifname = socket.if_indextoname(idx)
                except (OSError, ValueError):
                    ifname = str(idx)
        return data, addr, ifname
    try:
        data, addr = sock.recvfrom(4096)
    except OSError:
        return None, None, None
    return data, addr, None


def collect(socks, timeout, only_devices=None, should_stop=None,
            on_device=None):
    """Listen for replies until timeout, keyed by MAC (falling back to IP).

    only_devices restricts what the wildcard listener will accept to replies
    that actually arrived on those interfaces - needed for per-VLAN scanning,
    where the wildcard socket would otherwise also hear the native LAN.
    """
    found = {}
    deadline = time.time() + timeout
    by_fileno = {entry.sock.fileno(): entry for entry in socks}
    raw_socks = [entry.sock for entry in socks]
    local_ips = {entry.ip for entry in socks}
    while True:
        if should_stop and should_stop():
            break
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        # Capped at 0.25s so cancellation stays responsive during a long listen.
        ready, _, _ = select.select(raw_socks, [], [], min(remaining, 0.25))
        for s in ready:
            entry = by_fileno.get(s.fileno())
            is_wildcard = bool(entry) and not entry.sender
            data, addr, ifname = _recv(s, is_wildcard)
            if data is None:
                continue
            if (is_wildcard and only_devices and ifname
                    and ifname not in only_devices):
                continue          # arrived on some other interface, not ours
            if data in (PROBE_V1, PROBE_V2):
                continue          # our own probe, or someone else's, looped back
            if addr[0] in local_ips:
                continue          # anything we generated ourselves
            dev = parse_reply(data, addr[0])
            if not dev:
                continue
            dev["heard_via"] = "broadcast" if is_wildcard else "unicast"
            dev["heard_on"] = ifname or (entry.ip if entry else "")
            key = dev["mac"] or dev["ip"]
            if key in found:
                prev = found[key]
                for ip in dev["addresses"]:
                    if ip not in prev["addresses"]:
                        prev["addresses"].append(ip)
                for k, v in dev.items():
                    if v and not prev.get(k):
                        prev[k] = v
            else:
                dev["first_seen"] = datetime.now().isoformat(timespec="seconds")
                found[key] = dev
                if on_device:
                    on_device(dev)      # let a GUI show it the moment it lands
    return found


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
COLUMNS = [
    ("ip", "IP Address"),
    ("mac", "MAC"),
    ("hostname", "Hostname"),
    ("model", "Model"),
    ("fw", "Firmware"),
    ("uptime", "Uptime"),
    ("essid", "SSID / Mode"),
]


def row_for(dev):
    essid = dev.get("essid", "")
    wmode = dev.get("wmode", "")
    if essid and wmode:
        combined = "%s (%s)" % (essid, wmode)
    else:
        combined = essid or wmode
    return {
        "ip": dev["ip"],
        "mac": dev.get("mac", ""),
        "hostname": dev.get("hostname", ""),
        "model": dev.get("model", ""),
        "fw": dev.get("fw", ""),
        "uptime": fmt_uptime(dev.get("uptime_seconds")),
        "essid": combined,
    }


def format_table(devices):
    if not devices:
        return "\nNo Ubiquiti devices answered.\n"
    rows = [row_for(d) for d in devices]
    widths = {}
    for key, header in COLUMNS:
        widths[key] = max(len(header), max(len(r[key]) for r in rows))
    line = "  ".join(h.ljust(widths[k]) for k, h in COLUMNS)
    out = ["", line, "-" * len(line)]
    for r in sorted(rows, key=lambda x: tuple(
            int(p) for p in x["ip"].split(".")) if x["ip"].count(".") == 3 else (0,)):
        out.append("  ".join(r[k].ljust(widths[k]) for k, _ in COLUMNS))
    out.append("\n%d device(s).\n" % len(rows))
    return "\n".join(out)


def print_table(devices):
    print(format_table(devices))


def format_detail(devices):
    out = []
    for dev in devices:
        out.append("\n--- %s ---" % (dev.get("model") or "Unknown model"))
        out.append("  IP address   : %s" % dev["ip"])
        if len(dev["addresses"]) > 1:
            out.append("  All addresses: %s" % ", ".join(dev["addresses"]))
        out.append("  MAC address  : %s" % dev.get("mac", ""))
        out.append("  Hostname     : %s" % dev.get("hostname", ""))
        out.append("  Platform     : %s" % dev.get("platform", ""))
        out.append("  Firmware     : %s" % (dev.get("fw_version") or ""))
        out.append("  Firmware raw : %s" % (dev.get("firmware") or ""))
        out.append("  Uptime       : %s" % fmt_uptime(dev.get("uptime_seconds")))
        if dev.get("essid"):
            out.append("  SSID         : %s" % dev["essid"])
        if dev.get("wmode"):
            out.append("  Wireless mode: %s" % dev["wmode"])
        if dev.get("heard_on"):
            out.append("  Heard on     : %s" % dev["heard_on"])
        out.append("  Protocol     : %s (reply heard via %s)"
                   % (dev.get("proto", ""), dev.get("heard_via", "?")))
    out.append("")
    return "\n".join(out)


def print_detail(devices):
    print(format_detail(devices))


# ---------------------------------------------------------------------------
# Saved report - the results survive even if the console window closes
# ---------------------------------------------------------------------------
def _base_dir():
    """Directory of the exe when frozen, of the script otherwise."""
    try:
        if getattr(sys, "frozen", False):
            return os.path.dirname(os.path.abspath(sys.executable))
        return os.path.dirname(os.path.abspath(__file__))
    except Exception:
        return ""


def build_report(devices, scan_note=""):
    head = [
        "Ubiquiti discovery report",
        "Generated : %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Host      : %s" % socket.gethostname(),
    ]
    if scan_note:
        head.append("Scan      : %s" % scan_note)
    head.append("Devices   : %d" % len(devices))
    head.append("=" * 60)
    return "\n".join(head) + "\n" + format_table(devices) + format_detail(devices)


def write_report(devices, path=None, scan_note=""):
    """Write the report, falling back through candidate directories.

    Writing next to the exe is the intuitive place, but that can be a
    read-only share, a USB stick, or Program Files - so fall back to the
    working directory and finally the temp directory rather than losing
    the results.
    """
    body = build_report(devices, scan_note)
    if path:
        candidates = [path]
    else:
        name = "ubnt-scan-%s.txt" % datetime.now().strftime("%Y%m%d-%H%M%S")
        candidates = []
        for d in (_base_dir(), os.getcwd(), tempfile.gettempdir()):
            if d and os.path.join(d, name) not in candidates:
                candidates.append(os.path.join(d, name))
    last_error = None
    for candidate in candidates:
        try:
            with open(candidate, "w", encoding="utf-8") as fh:
                fh.write(body)
            return candidate
        except (OSError, UnicodeError) as exc:
            last_error = exc
    print("Could not write report: %s" % last_error, file=sys.stderr)
    return None


def write_json(path, devices):
    with open(path, "w") as fh:
        json.dump(devices, fh, indent=2)
    print("Wrote %s" % path)


def write_csv(path, devices):
    keys = [k for k, _ in COLUMNS] + ["platform", "proto", "addresses"]
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=keys)
        w.writeheader()
        for dev in devices:
            row = row_for(dev)
            row["platform"] = dev.get("platform", "")
            row["proto"] = dev.get("proto", "")
            row["addresses"] = " ".join(dev.get("addresses", []))
            w.writerow(row)
    print("Wrote %s" % path)


# ---------------------------------------------------------------------------
def launched_by_double_click():
    """Best-effort check for a console app started from Explorer.

    Under the classic conhost this is reliable: only our own process is
    attached to the console, so the count is 1. Under Windows Terminal (the
    default on Windows 11) the terminal host also attaches, giving 2 - which
    is indistinguishable from being run inside cmd.exe. So this is only ever
    one input into should_hold_window(), never the sole test.
    """
    if not WINDOWS:
        return False
    try:
        import ctypes
        buf = (ctypes.c_uint * 4)()
        count = ctypes.windll.kernel32.GetConsoleProcessList(buf, 4)
        return count <= 1
    except Exception:
        return False


def should_hold_window(argv, no_pause):
    """Whether to wait for a keypress before exiting.

    The dependable signal is that no arguments were passed: Explorer never
    supplies any. Someone running the exe from a terminal with no arguments
    also gets the prompt, which is harmless and beats the results vanishing.
    --no-pause always wins, for scheduled tasks and scripts.
    """
    if not WINDOWS or no_pause:
        return False
    return len(argv) <= 1 or launched_by_double_click()


def hold_window():
    """Wait for a keypress. input() first, msvcrt if stdin is unusable."""
    try:
        input("\nPress Enter to close...")
        return
    except (EOFError, KeyboardInterrupt):
        return
    except Exception:
        pass
    try:
        import msvcrt
        print("\nPress any key to close...")
        msvcrt.getch()
    except Exception:
        pass


def scan_once(socks, args):
    if args.sweep:
        count = sweep_probes(socks, args.sweep, rate=args.rate)
        if args.verbose:
            print("  probed %d hosts in %s" % (count, args.sweep), file=sys.stderr)
    else:
        send_probes(socks, args.targets, repeats=args.repeats)
    return collect(socks, args.timeout)


def main():
    ap = argparse.ArgumentParser(
        description="Discover Ubiquiti devices (airOS, EdgeSwitch, EdgeRouter, UniFi).")
    ap.add_argument("-t", "--timeout", type=float, default=5.0,
                    help="seconds to listen for replies (default 5)")
    ap.add_argument("-r", "--repeats", type=int, default=2,
                    help="how many times to send each probe (default 2)")
    ap.add_argument("-b", "--bcast", action="append", default=[],
                    help="extra broadcast address to probe, e.g. 192.168.1.255 "
                         "(repeatable)")
    ap.add_argument("-i", "--source", action="append", default=[],
                    help="only send from this local IP (repeatable)")
    ap.add_argument("-D", "--device", action="append", default=[],
                    metavar="IFACE",
                    help="send probes out this interface by name, e.g. "
                         "eth0.100 (Linux, needs root). Use for VLAN "
                         "sub-interfaces. Repeatable.")
    ap.add_argument("--sweep", metavar="CIDR",
                    help="unicast-probe every host in a CIDR instead of "
                         "broadcasting - reaches devices across routed links")
    ap.add_argument("--rate", type=int, default=400,
                    help="packets per second for --sweep (default 400)")
    ap.add_argument("--watch", action="store_true",
                    help="scan continuously and report devices as they appear")
    ap.add_argument("--interval", type=float, default=10.0,
                    help="seconds between scans in --watch mode (default 10)")
    ap.add_argument("--detail", action="store_true",
                    help="verbose per-device output instead of a table")
    ap.add_argument("--json", metavar="FILE", help="write results as JSON")
    ap.add_argument("--csv", metavar="FILE", help="write results as CSV")
    ap.add_argument("--no-wildcard", action="store_true",
                    help="do not open the catch-all listener. Results are then "
                         "guaranteed to belong to the chosen interface, at the "
                         "cost of missing devices that broadcast their reply. "
                         "Use on Windows when scanning one VLAN at a time.")
    ap.add_argument("--save", metavar="FILE", nargs="?", const="",
                    help="write a readable text report. With no filename, one "
                         "is auto-named next to the executable. This happens "
                         "automatically when the tool is double-clicked, so "
                         "results survive the window closing.")
    ap.add_argument("--no-save", action="store_true",
                    help="never write the automatic report")
    ap.add_argument("--no-pause", action="store_true",
                    help="do not wait for a keypress when the window would "
                         "otherwise close immediately (Windows)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="show interface and probe detail")
    args = ap.parse_args()

    if args.source:
        bind_ips = args.source
    elif args.device:
        bind_ips = []      # explicit interface given: do not probe the others
    else:
        bind_ips = local_ipv4s()
    if not bind_ips and not args.device:
        print("Could not determine any local IPv4 address. "
              "Use -i <ip> or -D <interface>.", file=sys.stderr)
        return 2

    targets = ["255.255.255.255", UBNT_MCAST] + args.bcast
    # Derive directed broadcasts assuming /24 where we have no netmask info.
    for ip in bind_ips:
        guess = ip.rsplit(".", 1)[0] + ".255"
        if guess not in targets:
            targets.append(guess)
    args.targets = targets

    if args.verbose:
        print("Source addresses: %s" % ", ".join(bind_ips), file=sys.stderr)
        if not args.sweep:
            print("Probe targets   : %s" % ", ".join(targets), file=sys.stderr)

    # Double-clicking gives no arguments, and that is also when the window is
    # most likely to vanish - so save a report in exactly that case.
    auto_save = (args.save is not None
                 or should_hold_window(sys.argv, args.no_pause))
    if args.no_save:
        auto_save = False
    save_path = args.save or None
    scan_note = ("unicast sweep of %s" % args.sweep) if args.sweep else "broadcast discovery"

    if args.device and not PKTINFO_AVAILABLE and not args.no_wildcard:
        print("  ! this OS cannot report a packet's arrival interface, so "
              "replies from other interfaces may be included. Add "
              "--no-wildcard for strict attribution.", file=sys.stderr)

    socks = make_sockets(bind_ips, verbose=args.verbose,
                         devices=args.device,
                         wildcard=not args.no_wildcard)
    if not any(e.sender for e in socks):
        print("No usable sending socket.", file=sys.stderr)
        return 2

    try:
        if args.watch:
            seen = {}
            watch_saved_note = False
            print("Watching (Ctrl-C to stop)...")
            while True:
                found = scan_once(socks, args)
                for key, dev in found.items():
                    if key not in seen:
                        seen[key] = dev
                        r = row_for(dev)
                        print("[%s] NEW  %-15s %-17s %-20s %s" % (
                            datetime.now().strftime("%H:%M:%S"), r["ip"],
                            r["mac"], r["hostname"], r["model"]))
                    elif seen[key]["ip"] != dev["ip"]:
                        print("[%s] MOVE %-17s %s -> %s" % (
                            datetime.now().strftime("%H:%M:%S"),
                            dev.get("mac", key),
                            seen[key]["ip"], dev["ip"]))
                        seen[key] = dev
                if auto_save and seen:
                    written = write_report(list(seen.values()), save_path,
                                           scan_note + " (watch mode)")
                    if written and not watch_saved_note:
                        print("  ...report updating at %s" % written)
                        watch_saved_note = True
                time.sleep(max(0.0, args.interval))
        else:
            print("Discovery in progress (%.0fs)..." % args.timeout)
            found = scan_once(socks, args)
            devices = list(found.values())
            if args.detail:
                print_detail(devices)
            else:
                print_table(devices)
            if args.json:
                write_json(args.json, devices)
            if args.csv:
                write_csv(args.csv, devices)
            if auto_save:
                written = write_report(devices, save_path, scan_note)
                if written:
                    print("Report saved to:\n  %s\n" % written)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        for entry in socks:
            entry.sock.close()
    return 0


if __name__ == "__main__":
    # The window-holding logic wraps everything, so a crash or a bad argument
    # stays on screen instead of closing instantly with the reason.
    _no_pause = "--no-pause" in sys.argv
    _hold = should_hold_window(sys.argv, _no_pause)
    _code = 1
    try:
        _code = main()
    except SystemExit as exc:                 # argparse --help or bad argument
        _code = exc.code if isinstance(exc.code, int) else 0
    except KeyboardInterrupt:
        print("\nStopped.")
        _code = 130
    except Exception:                         # noqa: BLE001 - must stay visible
        import traceback
        traceback.print_exc()
        print("\nThe scan failed. The traceback above is the detail.")
        _code = 1
    finally:
        if _hold:
            hold_window()
    sys.exit(_code)
