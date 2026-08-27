#!/usr/bin/env python3
"""
ubnt_gui.py - simple window for ubnt_scan.

Wraps the scanner in a tkinter GUI so field techs don't need a command line.
tkinter ships with Python, so this adds no dependencies.

The scan runs on a worker thread and talks to the window through a queue,
because tkinter widgets may only be touched from the main thread. Results
appear as they arrive rather than at the end.

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
    ("ip", "IP Address", 130),
    ("mac", "MAC", 150),
    ("hostname", "Hostname", 170),
    ("model", "Model", 180),
    ("fw", "Firmware", 150),
    ("uptime", "Uptime", 90),
    ("essid", "SSID / Mode", 190),
]


class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.events = queue.Queue()
        self.devices = {}
        self.worker = None
        self.stop_flag = threading.Event()
        self.sort_state = {}

        root.title("Ubiquiti Device Scanner")
        root.geometry("1080x620")
        root.minsize(820, 480)

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
        ttk.Checkbutton(frame, text="Keep scanning (watch)",
                        variable=self.watch_var).grid(row=0, column=4, sticky="w")

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

        ttk.Label(frame, text="Extra broadcast:").grid(row=2, column=0,
                                                       sticky="w", pady=(8, 0))
        self.bcast_var = tk.StringVar(value="")
        ttk.Entry(frame, textvariable=self.bcast_var, width=20).grid(
            row=2, column=1, sticky="w", padx=(4, 16), pady=(8, 0))
        ttk.Label(frame, foreground="#666",
                  text="e.g. 10.0.0.255 - only needed if your subnet is not a /24"
                  ).grid(row=2, column=2, columnspan=3, sticky="w", pady=(8, 0))

        self._sync_mode()

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

        self.log = tk.Text(root, height=5, wrap="none", state="disabled",
                           background="#f6f6f6", relief="flat")
        self.log.pack(fill="x", padx=8, pady=(0, 4))

    def _build_status(self, root):
        bar = ttk.Frame(root)
        bar.pack(fill="x", padx=8, pady=(0, 8))
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(bar, textvariable=self.status_var).pack(side="left")
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=160)
        self.progress.pack(side="right")

    def _sync_mode(self):
        state = "normal" if self.mode_var.get() == "sweep" else "disabled"
        self.sweep_entry.configure(state=state)

    # -- scanning -----------------------------------------------------------
    def start_scan(self):
        if self.worker and self.worker.is_alive():
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

        self.stop_flag.clear()
        self.scan_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.progress.start(12)
        self.status_var.set("Scanning...")

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

    def stop_scan(self):
        self.stop_flag.set()
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
                elif kind == "cycle":
                    self.status_var.set(
                        "%d device(s). Last scan %s."
                        % (len(self.devices), datetime.now().strftime("%H:%M:%S")))
                elif kind == "error":
                    self.append_log(payload)
                    messagebox.showerror("Scan error", payload)
                elif kind == "done":
                    self.scan_finished()
        except queue.Empty:
            pass
        self.root.after(100, self.drain_events)

    def add_device(self, dev):
        key = dev.get("mac") or dev["ip"]
        self.devices[key] = dev
        row = U.row_for(dev)
        values = [row[c[0]] for c in COLUMNS]
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
        self.scan_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
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
            return val.lower()

        for pos, iid in enumerate(sorted(self.tree.get_children(""),
                                         key=sort_key, reverse=reverse)):
            self.tree.move(iid, "", pos)

    def open_in_browser(self, _event):
        sel = self.tree.selection()
        if sel:
            webbrowser.open("http://%s" % self.tree.item(sel[0], "values")[0])

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
                U.write_csv(path, devices)
            elif kind == "json":
                U.write_json(path, devices)
            else:
                U.write_report(devices, path, "GUI scan")
            self.append_log("Saved %s" % path)
            messagebox.showinfo("Saved", "Written to:\n%s" % path)
        except Exception as exc:
            messagebox.showerror("Could not save", str(exc))

    def clear(self):
        self.devices.clear()
        for iid in self.tree.get_children(""):
            self.tree.delete(iid)
        self.status_var.set("Cleared.")

    def on_close(self):
        self.stop_flag.set()
        if self.worker and self.worker.is_alive():
            self.worker.join(timeout=2.0)
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        self.root.destroy()


def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("vista" if os.name == "nt" else "clam")
    except tk.TclError:
        pass
    ScannerGUI(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
