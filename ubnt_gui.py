#!/usr/bin/env python3
"""
ubnt_gui.py - simple window for ubnt_scan.

Wraps the scanner in a tkinter GUI so field techs don't need a command line.
tkinter ships with Python, so this adds no dependencies.

The scan runs on a worker thread and talks to the window through a queue,
because tkinter widgets may only be touched from the main thread. Results
appear as they arrive rather than at the end.

Three modes: broadcast the local segment, unicast-sweep a routed subnet, or
walk VLANs on a trunk port (Windows only, needs Administrator). The VLAN walk
is the same approach as vlan_scan.ps1 but driven in-process, so it needs no
separate script and no copy of ubnt_scan.exe beside it.

    python3 ubnt_gui.py
"""

import os
import queue
import sys
import threading
import traceback
import webbrowser
from datetime import datetime

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import ubnt_scan as U

try:
    import vlan_win as V
except Exception:                                    # pragma: no cover
    V = None


# ---------------------------------------------------------------------------
# A frozen --windowed build has no stdout, so a bare print() raises
# AttributeError and kills whatever thread it was on. Route it into the log
# pane instead of losing it.
# ---------------------------------------------------------------------------
class QueueWriter:
    def __init__(self, q):
        self.q = q
        self.buf = ""

    def write(self, text):
        self.buf += text
        while "\n" in self.buf:
            line, self.buf = self.buf.split("\n", 1)
            if line.strip():
                self.q.put(("log", line))
        return len(text)

    def flush(self):
        if self.buf.strip():
            self.q.put(("log", self.buf.strip()))
        self.buf = ""


COLUMNS = [
    ("vlan", "VLAN", 60),
    ("ip", "IP Address", 130),
    ("mac", "MAC", 150),
    ("hostname", "Hostname", 170),
    ("model", "Model", 180),
    ("fw", "Firmware", 150),
    ("uptime", "Uptime", 90),
    ("essid", "SSID / Mode", 190),
]

ADDRESS_MODE_LABELS = [
    ("DHCP - best coverage where DHCP exists", "dhcp"),
    ("Static - for factory-default gear", "static"),
    ("None - broadcast replies only, fastest", "none"),
]


def row_values(dev):
    """Table row for a device, with the VLAN column the scanner knows nothing of."""
    row = U.row_for(dev)
    row["vlan"] = str(dev.get("vlan", "") or "")
    return [row[key] for key, _, _ in COLUMNS]


class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.events = queue.Queue()
        self.devices = {}
        self.worker = None
        self.stop_flag = threading.Event()
        self.sort_state = {}
        self.caps = None            # last capability report, keyed by adapter
        self.walker = None          # live VlanWalker, so close can restore

        root.title("Ubiquiti Device Scanner")
        root.geometry("1180x660")
        root.minsize(900, 520)

        self._build_options(root)
        self._build_buttons(root)
        self._build_table(root)
        self._build_status(root)

        sys.stdout = QueueWriter(self.events)
        sys.stderr = QueueWriter(self.events)

        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(100, self.drain_events)

    # -- layout -------------------------------------------------------------
    def _build_options(self, root):
        frame = ttk.LabelFrame(root, text="Scan options", padding=8)
        frame.pack(fill="x", padx=8, pady=(8, 4))

        ttk.Label(frame, text="Interface:").grid(row=0, column=0, sticky="w")
        self.iface_var = tk.StringVar(value="All interfaces")
        choices = ["All interfaces"] + U.local_ipv4s()
        self.iface_box = ttk.Combobox(frame, textvariable=self.iface_var,
                                      values=choices, state="readonly", width=18)
        self.iface_box.grid(row=0, column=1, sticky="w", padx=(4, 16))

        ttk.Label(frame, text="Listen (s):").grid(row=0, column=2, sticky="w")
        self.timeout_var = tk.StringVar(value="5")
        ttk.Spinbox(frame, from_=1, to=120, width=5,
                    textvariable=self.timeout_var).grid(row=0, column=3,
                                                        sticky="w", padx=(4, 16))

        self.watch_var = tk.BooleanVar(value=False)
        self.watch_check = ttk.Checkbutton(frame, text="Keep scanning (watch)",
                                           variable=self.watch_var)
        self.watch_check.grid(row=0, column=4, sticky="w")

        ttk.Label(frame, text="Mode:").grid(row=1, column=0, sticky="w",
                                            pady=(8, 0))
        self.mode_var = tk.StringVar(value="broadcast")
        modes = ttk.Frame(frame)
        modes.grid(row=1, column=1, columnspan=4, sticky="w", pady=(8, 0))
        ttk.Radiobutton(modes, text="Broadcast (local segment)",
                        variable=self.mode_var, value="broadcast",
                        command=self._sync_mode).pack(side="left")
        ttk.Radiobutton(modes, text="Sweep subnet:", variable=self.mode_var,
                        value="sweep",
                        command=self._sync_mode).pack(side="left", padx=(16, 4))
        self.sweep_var = tk.StringVar(value="192.168.1.0/24")
        self.sweep_entry = ttk.Entry(modes, textvariable=self.sweep_var, width=20)
        self.sweep_entry.pack(side="left")
        self.vlan_radio = ttk.Radiobutton(modes, text="Walk VLANs",
                                          variable=self.mode_var, value="vlan",
                                          command=self._sync_mode)
        self.vlan_radio.pack(side="left", padx=(16, 0))

        ttk.Label(frame, text="Extra broadcast:").grid(row=2, column=0,
                                                       sticky="w", pady=(8, 0))
        self.bcast_var = tk.StringVar(value="")
        self.bcast_entry = ttk.Entry(frame, textvariable=self.bcast_var, width=20)
        self.bcast_entry.grid(row=2, column=1, sticky="w", padx=(4, 16),
                              pady=(8, 0))
        ttk.Label(frame, foreground="#666",
                  text="e.g. 10.0.0.255 - only needed if your subnet is not a /24"
                  ).grid(row=2, column=2, columnspan=3, sticky="w", pady=(8, 0))

        self._build_vlan_options(root)
        self._sync_mode()

    def _build_vlan_options(self, root):
        self.vlan_frame = ttk.LabelFrame(
            root, text="VLAN walk  -  trunk port only, needs Administrator",
            padding=8)
        self.vlan_frame.pack(fill="x", padx=8, pady=(0, 4))
        frame = self.vlan_frame

        ttk.Label(frame, text="Adapter:").grid(row=0, column=0, sticky="w")
        self.adapter_var = tk.StringVar(value="")
        self.adapter_box = ttk.Combobox(frame, textvariable=self.adapter_var,
                                        values=[], state="readonly", width=26)
        self.adapter_box.grid(row=0, column=1, sticky="w", padx=(4, 8))
        self.check_btn = ttk.Button(frame, text="Check adapter",
                                    command=self.check_adapter)
        self.check_btn.grid(row=0, column=2, sticky="w", padx=(0, 16))
        ttk.Label(frame, foreground="#666",
                  text="Reports what this NIC supports. Changes nothing."
                  ).grid(row=0, column=3, columnspan=2, sticky="w")

        ttk.Label(frame, text="VLAN IDs:").grid(row=1, column=0, sticky="w",
                                                pady=(8, 0))
        self.vlans_var = tk.StringVar(value="1-100")
        self.vlans_entry = ttk.Entry(frame, textvariable=self.vlans_var, width=26)
        self.vlans_entry.grid(row=1, column=1, sticky="w", padx=(4, 8),
                              pady=(8, 0))
        ttk.Label(frame, foreground="#666",
                  text="e.g. 1-100 or 10,20,99 - narrow this to your VLAN plan"
                  ).grid(row=1, column=2, columnspan=3, sticky="w", pady=(8, 0))

        ttk.Label(frame, text="Address:").grid(row=2, column=0, sticky="w",
                                               pady=(8, 0))
        self.addrmode_var = tk.StringVar(value=ADDRESS_MODE_LABELS[0][0])
        self.addrmode_box = ttk.Combobox(
            frame, textvariable=self.addrmode_var,
            values=[label for label, _ in ADDRESS_MODE_LABELS],
            state="readonly", width=38)
        self.addrmode_box.grid(row=2, column=1, columnspan=2, sticky="w",
                               padx=(4, 8), pady=(8, 0))
        self.addrmode_box.bind("<<ComboboxSelected>>",
                               lambda _e: self._sync_addrmode())

        ttk.Label(frame, text="Static IP:").grid(row=2, column=3, sticky="e",
                                                 pady=(8, 0))
        self.staticip_var = tk.StringVar(value="192.168.1.21")
        self.staticip_entry = ttk.Entry(frame, textvariable=self.staticip_var,
                                        width=16)
        self.staticip_entry.grid(row=2, column=4, sticky="w", padx=(4, 0),
                                 pady=(8, 0))

        self.vlan_note = ttk.Label(
            frame, foreground="#a33",
            text="Reconfigures the adapter and drops its connectivity while it runs. "
                 "Never pick the adapter carrying a remote session.")
        self.vlan_note.grid(row=3, column=0, columnspan=5, sticky="w", pady=(8, 0))

    def _build_buttons(self, root):
        bar = ttk.Frame(root)
        bar.pack(fill="x", padx=8, pady=4)
        self.scan_btn = ttk.Button(bar, text="Scan", command=self.start_scan)
        self.scan_btn.pack(side="left")
        self.stop_btn = ttk.Button(bar, text="Stop", command=self.stop_scan,
                                   state="disabled")
        self.stop_btn.pack(side="left", padx=4)
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Button(bar, text="Save report",
                   command=lambda: self.export("txt")).pack(side="left")
        ttk.Button(bar, text="Export CSV",
                   command=lambda: self.export("csv")).pack(side="left", padx=4)
        ttk.Button(bar, text="Export JSON",
                   command=lambda: self.export("json")).pack(side="left")
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Button(bar, text="Clear", command=self.clear).pack(side="left")

    def _build_table(self, root):
        wrap = ttk.Frame(root)
        wrap.pack(fill="both", expand=True, padx=8, pady=4)

        self.tree = ttk.Treeview(wrap, columns=[c[0] for c in COLUMNS],
                                 show="headings", selectmode="extended")
        for key, title, width in COLUMNS:
            self.tree.heading(key, text=title,
                              command=lambda k=key: self.sort_by(k))
            self.tree.column(key, width=width, anchor="w")
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.tree.bind("<Double-1>", self.open_in_browser)

        self.log = tk.Text(root, height=6, wrap="none", state="disabled",
                           background="#f6f6f6", relief="flat")
        self.log.pack(fill="x", padx=8, pady=(0, 4))

    def _build_status(self, root):
        bar = ttk.Frame(root)
        bar.pack(fill="x", padx=8, pady=(0, 8))
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(bar, textvariable=self.status_var).pack(side="left")
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=200)
        self.progress.pack(side="right")

    # -- mode plumbing ------------------------------------------------------
    def _sync_mode(self):
        mode = self.mode_var.get()
        self.sweep_entry.configure(
            state="normal" if mode == "sweep" else "disabled")

        vlan_state = "readonly" if mode == "vlan" else "disabled"
        entry_state = "normal" if mode == "vlan" else "disabled"
        self.adapter_box.configure(state=vlan_state)
        self.addrmode_box.configure(state=vlan_state)
        self.vlans_entry.configure(state=entry_state)
        self.check_btn.configure(state=entry_state)
        # A walk drives the interface itself, so these do not apply.
        self.iface_box.configure(
            state="disabled" if mode == "vlan" else "readonly")
        self.bcast_entry.configure(
            state="disabled" if mode == "vlan" else "normal")
        self.watch_check.configure(
            state="disabled" if mode == "vlan" else "normal")
        self._sync_addrmode()

        if mode == "vlan" and not self.adapter_box.cget("values"):
            self.load_adapters()

    def _sync_addrmode(self):
        static = (self.mode_var.get() == "vlan"
                  and self._address_mode() == "static")
        self.staticip_entry.configure(state="normal" if static else "disabled")

    def _address_mode(self):
        label = self.addrmode_var.get()
        for text, value in ADDRESS_MODE_LABELS:
            if text == label:
                return value
        return "dhcp"

    def _vlan_available(self):
        if V is None or not V.IS_WINDOWS:
            messagebox.showinfo(
                "Windows only",
                "VLAN walking tags a Windows network adapter, so it only runs "
                "on Windows.\n\nOn Linux use vlan_scan.sh, which creates a "
                "proper VLAN sub-interface per ID.")
            return False
        return True

    # -- adapter discovery --------------------------------------------------
    def load_adapters(self):
        if V is None or not V.IS_WINDOWS:
            return

        def work():
            try:
                adapters = V.list_adapters()
            except Exception as exc:
                self.events.put(("log", "Could not list adapters: %s" % exc))
                return
            self.events.put(("adapters", adapters))

        threading.Thread(target=work, daemon=True).start()

    def check_adapter(self):
        if not self._vlan_available():
            return
        adapter = self.adapter_var.get().strip()
        if not adapter:
            messagebox.showerror("No adapter", "Pick an adapter first.")
            return
        self.check_btn.configure(state="disabled")
        self.status_var.set("Checking %s..." % adapter)

        def work():
            try:
                caps = V.capabilities(adapter)
                lines = V.describe_capabilities(caps)
                try:
                    method = V.choose_method(caps)
                    lines.append("  Method that would be used: %s" % method)
                except V.VlanError as exc:
                    lines.append("  No usable method:")
                    lines.extend("    " + ln for ln in str(exc).splitlines())
                self.events.put(("caps", (adapter, caps, lines)))
            except Exception as exc:
                self.events.put(("log", "Capability check failed: %s" % exc))
            finally:
                self.events.put(("check_done", None))

        threading.Thread(target=work, daemon=True).start()

    # -- scanning -----------------------------------------------------------
    def start_scan(self):
        if self.worker and self.worker.is_alive():
            return
        if self.mode_var.get() == "vlan":
            self.start_vlan_walk()
            return

        try:
            timeout = float(self.timeout_var.get())
            if timeout <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid value",
                                 "Listen time must be a positive number.")
            return

        sweep = None
        if self.mode_var.get() == "sweep":
            sweep = self.sweep_var.get().strip()
            try:
                import ipaddress
                ipaddress.ip_network(sweep, strict=False)
            except ValueError:
                messagebox.showerror(
                    "Invalid subnet",
                    "%r is not a subnet in CIDR form.\n\nExample: 192.168.1.0/24"
                    % sweep)
                return

        source = None if self.iface_var.get() == "All interfaces" \
            else self.iface_var.get()
        bcast = [b.strip() for b in self.bcast_var.get().split(",") if b.strip()]

        self._begin_run("Scanning...", determinate=False)
        self.worker = threading.Thread(
            target=self.scan_thread,
            args=(timeout, sweep, source, bcast, self.watch_var.get()),
            daemon=True)
        self.worker.start()

    def scan_thread(self, timeout, sweep, source, bcast, watch):
        """Runs off the main thread. Touches no widget - only the queue."""
        socks = []
        try:
            bind_ips = [source] if source else U.local_ipv4s()
            if not bind_ips:
                self.events.put(("error", "No local IPv4 address found."))
                return

            targets = ["255.255.255.255", U.UBNT_MCAST] + bcast
            for ip in bind_ips:
                guess = ip.rsplit(".", 1)[0] + ".255"
                if guess not in targets:
                    targets.append(guess)

            socks = U.make_sockets(bind_ips, verbose=True)
            if not any(e.sender for e in socks):
                self.events.put(("error", "Could not open a sending socket."))
                return

            first = True
            while first or (watch and not self.stop_flag.is_set()):
                first = False
                if sweep:
                    self.events.put(("status", "Sweeping %s..." % sweep))
                    n = U.sweep_probes(socks, sweep, rate=400,
                                       should_stop=self.stop_flag.is_set)
                    self.events.put(("log", "Probed %d hosts in %s" % (n, sweep)))
                else:
                    U.send_probes(socks, targets, repeats=2)

                if self.stop_flag.is_set():
                    break
                self.events.put(("status", "Listening %gs..." % timeout))
                found = U.collect(socks, timeout,
                                  should_stop=self.stop_flag.is_set,
                                  on_device=lambda d: self.events.put(("device", d)))
                self.events.put(("cycle", len(found)))
        except Exception:
            self.events.put(("error", traceback.format_exc()))
        finally:
            for entry in socks:
                try:
                    entry.sock.close()
                except Exception:
                    pass
            self.events.put(("done", None))

    # -- VLAN walking -------------------------------------------------------
    def start_vlan_walk(self):
        if not self._vlan_available():
            return

        adapter = self.adapter_var.get().strip()
        if not adapter:
            messagebox.showerror("No adapter",
                                 "Pick the adapter plugged into the trunk port.")
            return
        try:
            vlans = V.parse_vlan_list(self.vlans_var.get())
        except ValueError as exc:
            messagebox.showerror("Invalid VLAN list", str(exc))
            return
        try:
            timeout = float(self.timeout_var.get())
            if timeout <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid value",
                                 "Listen time must be a positive number.")
            return

        if not V.is_admin():
            if not messagebox.askyesno(
                    "Administrator needed",
                    "Changing a VLAN tag needs Administrator rights.\n\n"
                    "Restart the scanner elevated now? Windows will ask you to "
                    "confirm, and this window will close and reopen.\n\n"
                    "Any results currently on screen will be lost."):
                return
            try:
                if V.relaunch_as_admin():
                    self.root.after(200, self.root.destroy)
                else:
                    messagebox.showwarning(
                        "Not elevated",
                        "The elevation prompt was dismissed, so nothing changed.\n\n"
                        "You can also close this window and start the scanner "
                        "with right-click > Run as administrator.")
            except Exception as exc:
                messagebox.showerror("Could not elevate", str(exc))
            return

        mode = self._address_mode()
        static_ip = self.staticip_var.get().strip()
        if mode == "static":
            try:
                import ipaddress
                ipaddress.ip_address(static_ip)
            except ValueError:
                messagebox.showerror(
                    "Invalid address",
                    "%r is not an IPv4 address.\n\nPick one you are certain is "
                    "free on every VLAN you are about to walk." % static_ip)
                return

        est = len(vlans) * (timeout + (2 if mode == "static" else 8))
        if not messagebox.askokcancel(
                "Start VLAN walk?",
                "About to walk %d VLAN(s) on '%s'.\n\n"
                "This reconfigures that adapter %d time(s) and it will lose "
                "normal connectivity until the walk finishes. Original settings "
                "are restored at the end, including if you press Stop.\n\n"
                "Disconnect Wi-Fi and other adapters first, or their devices "
                "may show up in the results.\n\n"
                "Rough estimate: %s."
                % (len(vlans), adapter, len(vlans), _fmt_duration(est))):
            return

        self._begin_run("Walking %d VLAN(s)..." % len(vlans),
                        determinate=True, maximum=len(vlans))
        self.worker = threading.Thread(
            target=self.vlan_thread,
            args=(adapter, vlans, timeout, mode, static_ip),
            daemon=True)
        self.worker.start()

    def vlan_thread(self, adapter, vlans, timeout, address_mode, static_ip):
        """Tag into each VLAN in turn and scan it. Off the main thread."""
        walker = None
        try:
            caps = self.caps if (self.caps and self.caps.get("adapter") == adapter) \
                else V.capabilities(adapter)
            if not caps.get("exists"):
                self.events.put(("error", "No adapter named %r." % adapter))
                return

            walker = V.VlanWalker(
                adapter, caps, address_mode=address_mode, static_ip=static_ip,
                log=lambda m: self.events.put(("log", m)))
            self.walker = walker
            self.events.put(("log", "Method: %s" % walker.method))

            targets = ["255.255.255.255", U.UBNT_MCAST]
            for index, vid in enumerate(vlans, start=1):
                if self.stop_flag.is_set():
                    break
                self.events.put(("status", "VLAN %d  (%d of %d)"
                                 % (vid, index, len(vlans))))
                self.events.put(("progress", index))
                try:
                    walker.set_vlan(vid)
                except V.VlanError as exc:
                    self.events.put(("log", "VLAN %d: could not set tag (%s)"
                                     % (vid, exc)))
                    continue

                ip = walker.address_for_vlan(should_stop=self.stop_flag.is_set)
                if self.stop_flag.is_set():
                    break
                if not ip:
                    self.events.put(("log", "VLAN %d: no address, skipped" % vid))
                    continue

                self._scan_one_vlan(vid, ip, timeout, targets)
            self.events.put(("walk_done", None))
        except Exception:
            self.events.put(("error", traceback.format_exc()))
        finally:
            if walker is not None:
                walker.restore()
            self.walker = None
            self.events.put(("done", None))

    def _scan_one_vlan(self, vid, ip, timeout, targets):
        """One VLAN's scan, bound to the address the adapter picked up."""
        socks = []
        try:
            per_vlan = list(targets)
            guess = ip.rsplit(".", 1)[0] + ".255"
            if guess not in per_vlan:
                per_vlan.append(guess)

            # wildcard=False is the --no-wildcard behaviour. Windows cannot
            # report which interface a packet arrived on, so the catch-all
            # listener would let other adapters contaminate this VLAN's
            # results. The cost is missing devices that broadcast their reply;
            # on Windows that trade is unavoidable.
            socks = U.make_sockets([ip], wildcard=False)
            if not any(e.sender for e in socks):
                self.events.put(("log", "VLAN %d: could not bind to %s" % (vid, ip)))
                return

            U.send_probes(socks, per_vlan, repeats=2)
            if self.stop_flag.is_set():
                return

            def on_device(dev, _vid=vid):
                dev["vlan"] = _vid
                self.events.put(("device", dev))

            found = U.collect(socks, timeout,
                              should_stop=self.stop_flag.is_set,
                              on_device=on_device)
            if found:
                self.events.put(("log", "VLAN %d (%s): %d device(s)"
                                 % (vid, ip, len(found))))
        finally:
            for entry in socks:
                try:
                    entry.sock.close()
                except Exception:
                    pass

    # -- run lifecycle ------------------------------------------------------
    def _begin_run(self, status, determinate=False, maximum=100):
        self.stop_flag.clear()
        self.scan_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.check_btn.configure(state="disabled")
        if determinate:
            self.progress.configure(mode="determinate", maximum=maximum, value=0)
        else:
            self.progress.configure(mode="indeterminate")
            self.progress.start(12)
        self.status_var.set(status)

    def stop_scan(self):
        self.stop_flag.set()
        if self.mode_var.get() == "vlan":
            self.status_var.set("Stopping - restoring the adapter...")
        else:
            self.status_var.set("Stopping...")

    # -- queue pump ---------------------------------------------------------
    def drain_events(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "device":
                    self.add_device(payload)
                elif kind == "status":
                    self.status_var.set(payload)
                elif kind == "log":
                    self.append_log(payload)
                elif kind == "progress":
                    self.progress.configure(value=payload)
                elif kind == "adapters":
                    self.fill_adapters(payload)
                elif kind == "caps":
                    self.show_caps(*payload)
                elif kind == "check_done":
                    if not (self.worker and self.worker.is_alive()):
                        self.check_btn.configure(state="normal")
                        self.status_var.set("Ready.")
                elif kind == "cycle":
                    self.status_var.set(
                        "%d device(s). Last scan %s."
                        % (len(self.devices), datetime.now().strftime("%H:%M:%S")))
                elif kind == "walk_done":
                    self.append_log("Walk finished.")
                elif kind == "error":
                    self.append_log(payload)
                    messagebox.showerror("Scan error", payload)
                elif kind == "done":
                    self.scan_finished()
        except queue.Empty:
            pass
        self.root.after(100, self.drain_events)

    def fill_adapters(self, adapters):
        names = [a["name"] for a in adapters]
        self.adapter_box.configure(values=names)
        for a in adapters:
            self.append_log("Adapter: %s  [%s]  %s  %s"
                            % (a["name"], a["status"], a["link_speed"],
                               a["description"]))
        if names and not self.adapter_var.get():
            # Prefer one that is actually plugged in.
            up = [a["name"] for a in adapters if a["status"].lower() == "up"]
            self.adapter_var.set(up[0] if up else names[0])
        if not names:
            self.append_log("No wired adapters found. A VLAN walk needs a "
                            "wired trunk port.")

    def show_caps(self, adapter, caps, lines):
        self.caps = caps
        for line in lines:
            self.append_log(line)
        # A Hyper-V check that could not run is not the same as no Hyper-V, and
        # the difference decides whether this machine can walk VLANs at all.
        # Offer to settle it rather than leaving a guess in the log.
        if (caps.get("hyperv_error") and not caps.get("elevated")
                and not caps.get("vlan_keyword")):
            if messagebox.askyesno(
                    "Check needs Administrator",
                    "This driver exposes no VLAN ID property, and the Hyper-V "
                    "check could not run without Administrator - so whether "
                    "this machine can walk VLANs is still unknown.\n\n"
                    "Restart the scanner elevated and check again? Windows "
                    "will ask you to confirm, and this window will close and "
                    "reopen.\n\nAny results currently on screen will be lost."):
                try:
                    if V.relaunch_as_admin():
                        self.root.after(200, self.root.destroy)
                    else:
                        self.append_log("Elevation prompt dismissed; "
                                        "Hyper-V state still unknown.")
                except Exception as exc:
                    messagebox.showerror("Could not elevate", str(exc))

    def add_device(self, dev):
        key = dev.get("mac") or dev["ip"]
        if dev.get("vlan"):
            # The same device can legitimately answer on more than one VLAN.
            key = "%s@vlan%s" % (key, dev["vlan"])
        self.devices[key] = dev
        values = row_values(dev)
        if self.tree.exists(key):
            self.tree.item(key, values=values)
        else:
            self.tree.insert("", "end", iid=key, values=values)
        self.status_var.set("%d device(s) found." % len(self.devices))

    def append_log(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", "%s  %s\n"
                        % (datetime.now().strftime("%H:%M:%S"), text))
        self.log.see("end")
        self.log.configure(state="disabled")

    def scan_finished(self):
        self.progress.stop()
        self.progress.configure(mode="indeterminate", value=0)
        self.scan_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        if self.mode_var.get() == "vlan":
            self.check_btn.configure(state="normal")
        if not self.devices:
            self.status_var.set("No Ubiquiti devices answered.")
        else:
            self.status_var.set("Finished. %d device(s)." % len(self.devices))

    # -- actions ------------------------------------------------------------
    def sort_by(self, key):
        reverse = self.sort_state.get(key, False)
        self.sort_state[key] = not reverse
        idx = [c[0] for c in COLUMNS].index(key)

        def sort_key(iid):
            val = self.tree.item(iid, "values")[idx]
            if key == "ip":
                try:
                    return tuple(int(p) for p in val.split("."))
                except ValueError:
                    return (0,)
            if key == "vlan":
                try:
                    return (0, int(val))
                except ValueError:
                    return (1, 0)
            return val.lower()

        for pos, iid in enumerate(sorted(self.tree.get_children(""),
                                         key=sort_key, reverse=reverse)):
            self.tree.move(iid, "", pos)

    def open_in_browser(self, _event):
        sel = self.tree.selection()
        if sel:
            idx = [c[0] for c in COLUMNS].index("ip")
            webbrowser.open("http://%s" % self.tree.item(sel[0], "values")[idx])

    def export(self, kind):
        if not self.devices:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        exts = {"csv": ".csv", "json": ".json", "txt": ".txt"}
        path = filedialog.asksaveasfilename(
            defaultextension=exts[kind],
            initialfile="ubnt-scan-%s%s"
                        % (datetime.now().strftime("%Y%m%d-%H%M%S"), exts[kind]),
            filetypes=[(kind.upper(), "*" + exts[kind]), ("All files", "*.*")])
        if not path:
            return
        devices = list(self.devices.values())
        try:
            if kind == "csv":
                self._write_csv(path, devices)
            elif kind == "json":
                U.write_json(path, devices)
            else:
                U.write_report(devices, path, self._scan_note())
            self.append_log("Saved %s" % path)
            messagebox.showinfo("Saved", "Written to:\n%s" % path)
        except Exception as exc:
            messagebox.showerror("Could not save", str(exc))

    def _write_csv(self, path, devices):
        """Like U.write_csv but with the VLAN column, which the scanner has no
        concept of. Empty for devices found by a plain scan."""
        import csv
        keys = ["vlan"] + [k for k, _ in U.COLUMNS] + ["platform", "proto",
                                                       "addresses"]
        with open(path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=keys)
            writer.writeheader()
            for dev in devices:
                row = U.row_for(dev)
                row["vlan"] = dev.get("vlan", "")
                row["platform"] = dev.get("platform", "")
                row["proto"] = dev.get("proto", "")
                row["addresses"] = " ".join(dev.get("addresses", []))
                writer.writerow(row)

    def _scan_note(self):
        vlans = sorted({d["vlan"] for d in self.devices.values() if d.get("vlan")})
        if vlans:
            return "GUI VLAN walk on %s, devices found on VLAN %s" % (
                self.adapter_var.get(),
                ", ".join(str(v) for v in vlans))
        if self.mode_var.get() == "sweep":
            return "GUI sweep of %s" % self.sweep_var.get()
        return "GUI scan"

    def clear(self):
        self.devices.clear()
        for iid in self.tree.get_children(""):
            self.tree.delete(iid)
        self.status_var.set("Cleared.")

    def on_close(self):
        self.stop_flag.set()
        walker = self.walker
        if self.worker and self.worker.is_alive():
            # Give the walk a chance to unwind and restore the adapter itself.
            self.worker.join(timeout=30.0 if walker else 2.0)
        if walker is not None:
            # Belt and braces: restore() is idempotent, so a walk that already
            # cleaned up costs nothing, and one that died mid-flight is caught.
            walker.restore()
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        self.root.destroy()


def _fmt_duration(seconds):
    seconds = int(seconds)
    if seconds < 90:
        return "%d seconds" % seconds
    if seconds < 5400:
        return "%d minutes" % round(seconds / 60.0)
    return "%.1f hours" % (seconds / 3600.0)


def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("vista" if os.name == "nt" else "clam")
    except tk.TclError:
        pass
    gui = ScannerGUI(root)
    if V is None or not V.IS_WINDOWS:
        gui.vlan_radio.configure(state="disabled")
        gui.vlan_frame.configure(text="VLAN walk  -  Windows only, "
                                      "use vlan_scan.sh on Linux")
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
