# ubnt_scan

A dependency-free Ubiquiti discovery tool for a laptop. Finds airOS / airMAX /
airFiber radios, EdgeSwitch, EdgeRouter and UniFi devices on the local segment
and prints their IP, MAC, hostname, model, firmware, uptime and SSID.

Standard library only. No scapy, no Npcap, no packet capture driver, and no
admin rights for the common case.

## Why

Most of the older scripts floating around send only the **v1** discovery probe
(`01 00 00 00`), which airOS answers but EdgeSwitch and EdgeRouter ignore. This
sends **both** the v1 and v2 (`02 08 00 00`) probes, so switches and routers
show up alongside radios.

It also catches devices that answer by *broadcasting* their reply to
`255.255.255.255:10001` rather than unicasting it back to the source port. A
socket bound to a specific interface address never receives those, so a
wildcard listener runs alongside the per-interface senders.

## GUI

`ubnt_gui.py` is a point-and-click window over the same scanner — for field
techs who should not be handed a command line. It uses tkinter, which ships
with Python, so it adds no dependencies.

```bash
python3 ubnt_gui.py
```

It exposes the options that matter: interface, listen time, broadcast vs
subnet sweep, an extra broadcast address, and watch mode. Results fill the
table as they arrive rather than at the end. Click a column heading to sort,
double-click a row to open that device's web interface, and export to text,
CSV or JSON. The **Stop** button cancels mid-scan, which matters because a
large subnet sweep would otherwise run for minutes.

Warnings that the command line prints — a port conflict with the Ubiquiti
Discovery Tool, for instance — appear in the log pane at the bottom instead of
being lost.

## Windows executable

There is no prebuilt exe in this repo, because a Windows binary must be built
on Windows — PyInstaller cannot cross-compile. Two ways to get one:

**On a Windows machine with Python installed**, double-click `build_exe.bat`.
It builds inside a throwaway virtualenv, installs nothing into your system
Python, and leaves two files behind:

- `dist\ubnt_scan_gui.exe` — the window. Hand this one to field techs.
- `dist\ubnt_scan.exe` — the command line version, for scripts and scheduled
  tasks.

Both are single files that run on any Windows machine, including ones with no
Python at all.

**With no Windows machine handy**, push this repo to GitHub. The included
workflow (`.github/workflows/build-windows.yml`) builds and smoke-tests the exe
on a Windows runner. Download it from the Actions run under Artifacts. Tagging
a commit `v1.0.0` also attaches the exe to a Release.

Running the GUI exe: just double-click it. Nothing else to know.

Running the command line exe:

- Double-clicking it runs a default scan and waits for a keypress before
  closing, so you can read the results. From a terminal it takes all the usual
  options: `ubnt_scan.exe -t 10 --csv devices.csv`.
- The keypress prompt appears whenever no arguments were passed, since
  Explorer never passes any. Running the exe from a terminal with no arguments
  therefore also prompts — harmless, and far more reliable than trying to
  detect Explorer. Pass `--no-pause` in scripts and scheduled tasks.
- If you make a desktop shortcut **with** arguments, Windows may close the
  window at the end, because arguments look like a terminal invocation. That
  no longer loses the results — see below.
- **A report is saved automatically when double-clicked.** A timestamped text
  file (`ubnt-scan-YYYYMMDD-HHMMSS.txt`) is written next to the exe containing
  the table and the full per-device detail. Even if the window closes for any
  reason, the results are on disk. If the exe sits somewhere unwritable — a
  read-only share, a USB stick, Program Files — it falls back to the working
  directory and then the temp directory, and prints where it landed.
  `--no-save` turns this off; `--save FILE` picks the location yourself.
- SmartScreen will warn about an unknown publisher the first time, because the
  exe is not code-signed. "More info" then "Run anyway". Code-signing needs a
  certificate; if you distribute this widely, sign it.
- Allow it through the Windows Firewall when prompted, or it cannot receive
  discovery replies.
- `--onefile` unpacks to `%TEMP%` at startup, which some endpoint protection
  blocks. If that bites, swap `--onefile` for `--onedir` in the build script
  and ship the resulting folder instead.
- `-D/--device` is Linux-only. The Windows VLAN walk uses `vlan_scan.ps1`
  instead, which drives this exe once per VLAN. See the VLAN section.

## Requirements

Python 3.6 or newer to run from source. Nothing else. The Windows exe bundles
its own interpreter and needs nothing installed.

If `netifaces` or `psutil` happen to be installed they are used to enumerate
interfaces more precisely, but neither is required — without them the script
falls back to hostname resolution and assumes a /24 when deriving directed
broadcast addresses. Use `-b` to state the broadcast address explicitly if
your subnet is not a /24.

## Usage

```bash
python3 ubnt_scan.py                        # scan every local interface
python3 ubnt_scan.py -t 10                  # listen longer
python3 ubnt_scan.py --detail               # full per-device dump
python3 ubnt_scan.py --csv devices.csv      # or --json
python3 ubnt_scan.py -b 10.0.0.255          # explicit broadcast address
python3 ubnt_scan.py --watch                # keep scanning, report changes
python3 ubnt_scan.py --sweep 192.168.1.0/24 # unicast probe a routed subnet
python3 ubnt_scan.py --save report.txt      # readable text report
```

In `--watch` mode the report is rewritten after every cycle, so stopping with
Ctrl-C never loses what was found.

Output:

```
IP Address     MAC                Hostname      Model               Firmware  Uptime   SSID / Mode
--------------------------------------------------------------------------------------------------
192.168.1.20   24:A4:3C:xx:xx:xx  radio-01      NanoStation M5      v6.3.11   100d 23h wireless-a (Station)
192.168.1.2    F0:9F:C2:xx:xx:xx  switch-01     EdgeSwitch 24 Lite  v1.9.7    14d 0h
```

### Options

| Option | Purpose |
| --- | --- |
| `-t, --timeout` | Seconds to listen per scan (default 5) |
| `-r, --repeats` | How many times to send each probe (default 2) |
| `-b, --bcast` | Extra broadcast address to probe. Repeatable |
| `-i, --source` | Only send from this local IP. Repeatable |
| `-D, --device` | Send out this interface by name. Linux, needs root. Repeatable |
| `--sweep CIDR` | Unicast-probe every host in a subnet instead of broadcasting |
| `--rate` | Packets per second for `--sweep` (default 400) |
| `--watch` | Scan continuously, print devices as they appear |
| `--interval` | Seconds between scans in watch mode (default 10) |
| `--detail` | Verbose per-device output instead of a table |
| `--json`, `--csv` | Write results to a file |
| `--save [FILE]` | Write a readable text report. No filename = auto-named next to the exe |
| `--no-save` | Never write the automatic report |
| `--no-wildcard` | Skip the catch-all listener; strict per-interface attribution |
| `--no-pause` | Do not wait for a keypress when double-clicked (Windows) |
| `-v, --verbose` | Show interface and probe detail |

## Scanning beyond the local segment

Discovery is a broadcast protocol, so a plain run only sees the segment the
laptop is plugged into. Two ways past that:

**Routed subnets** — `--sweep` unicasts a probe to every host in a CIDR.
Devices reply directly, so this works across routed links:

```bash
python3 ubnt_scan.py --sweep 10.0.0.0/24
```

Lower `--rate` when probing across a constrained wireless backhaul.

**Other VLANs on a trunk port** — see below.

## Scanning across VLANs

Yes, you can walk VLANs, but only if the switch port your laptop is plugged
into is a **trunk** (802.1Q tagged) carrying them. On an access port you will
only ever see the one untagged VLAN, and a plain run already covers that. No
amount of software makes tagged frames appear on an access port.

On **Linux**, `vlan_scan.sh` creates a VLAN sub-interface per ID, scans it,
tears it down, and moves on:

```bash
sudo ./vlan_scan.sh -n eth0 -r 1-100              # walk VLANs 1-100
sudo ./vlan_scan.sh -n eth0 -l 10,20,30,99        # only these
sudo ./vlan_scan.sh -n eth0 -r 1-4094 -a dhcp -o found.csv
```

Address mode matters more than it looks:

- `-a none` (default) leaves the interface without an IP. Probes still go out
  tagged, but a device that *unicasts* its reply has no address to send it to.
  You will only see devices that broadcast their reply. Fast, non-intrusive,
  and enough to answer "is anything alive on this VLAN".
- `-a dhcp` requests a lease per VLAN. Best coverage where DHCP exists.
- `-a static -c 192.168.1.21/24` puts a fixed address on every VLAN. Useful
  when hunting for factory-default gear, since airOS ships on 192.168.1.20.
  Pick an address you are certain is free.

Results are attributed per VLAN using `IP_PKTINFO`, so a reply that arrives on
the native LAN is not credited to whichever VLAN is under test.

Walking all 4094 VLANs at 3 seconds each takes roughly 3.5 hours. Narrow the
range to your actual VLAN plan.

On **macOS** the same approach works manually:

```bash
sudo ifconfig vlan0 create vlandev en0 vlan 100
sudo ipconfig set vlan0 DHCP
python3 ubnt_scan.py -i "$(ipconfig getifaddr vlan0)"
sudo ifconfig vlan0 destroy
```

On **Windows** there are no 802.1Q sub-interfaces, so you cannot have several
VLANs live at once. You can still walk them one at a time by tagging the
adapter itself. `vlan_scan.ps1` does that, using whichever of two methods your
hardware supports:

- **Adapter VLAN property** — sets the NIC's own "VLAN ID" advanced setting.
  Needs a driver that exposes it. Note that Intel removed VLAN support from
  PROSet on newer Windows 10/11 drivers, so this is absent on many modern
  laptops even with an Intel NIC.
- **Hyper-V** — sets the VLAN on an external vSwitch's management vNIC.
  Windows Pro/Enterprise only.

Run the capability check first. It reports what your machine supports and
changes nothing:

```powershell
.\vlan_scan.ps1 -Check -Adapter "Ethernet"
```

Then walk:

```powershell
.\vlan_scan.ps1 -Adapter "Ethernet" -Range 1-100
.\vlan_scan.ps1 -Adapter "Ethernet" -VlanIds 10,20,99 -AddressMode DHCP -OutFile found.csv
```

Read this before running it:

- It **reconfigures a live network adapter**, which loses normal connectivity
  for the duration. Never point it at the adapter carrying your RDP session.
  Original settings are restored on exit, including on Ctrl-C, but a crash
  mid-walk could leave a VLAN tag set — check the adapter's VLAN ID setting if
  anything looks wrong afterwards.
- Disconnect Wi-Fi and other adapters during the walk. Windows cannot report
  which interface a packet arrived on (`recvmsg` does not exist there), so the
  per-VLAN attribution that `vlan_scan.sh` relies on is unavailable. The
  script passes `--no-wildcard` to compensate, which keeps results tied to the
  adapter under test but misses devices that broadcast their replies. On
  Windows that trade is unavoidable.
- Requires Administrator.

If neither method is available, the remaining options are a Linux laptop or a
bridged Linux VM running `vlan_scan.sh`, or having the switch put the port into
each VLAN as an access port in turn and running a plain scan each time.

## Notes and gotchas

- **EdgeRouter** stays silent unless discovery is enabled:
  `set service ubnt-discover`. EdgeSwitch has it on by default.
- **Port conflict.** The official Ubiquiti Discovery Tool and UISP agents hold
  UDP 10001. If one is running, this script warns and you will miss devices
  that broadcast their replies. Close it first.
- **Host firewall.** Inbound UDP 10001 must be allowed. Windows Defender
  usually prompts on first run.
- **Wireless mode** labels are best-effort. The airOS mode codes are not
  documented and vary between firmware trains; unrecognised values show as
  `mode-N`.
- Unrecognised TLV fields are preserved as hex under `unknown_fields` in JSON
  output, which is handy for identifying a device the tool does not label.
- Probes from other machines on the segment, and the script's own probes, are
  filtered out by payload and by source address.

## Protocol

Discovery is UDP port 10001, sent to broadcast and to the multicast group
`233.89.188.1`. Replies are a 4-byte header (version, command, 16-bit length)
followed by type-length-value fields: 1-byte type, 2-byte big-endian length,
then the value. Recognised types include MAC (`0x01`), MAC+IP (`0x02`),
firmware (`0x03`), uptime (`0x0a`), hostname (`0x0b`), platform (`0x0c`),
SSID (`0x0d`), wireless mode (`0x0e`), model (`0x14`), and the v2 model and
firmware fields (`0x15`, `0x16`, `0x1b`).

## Security

Read-only. The tool sends discovery probes and parses replies. It does not
authenticate to devices, change configuration, or transmit anything off the
local network. No credentials are handled and nothing is phoned home.

Only run it on networks you are responsible for.

## Repository layout

```
ubnt_scan.py                        the scanner (also a CLI)
ubnt_gui.py                         point-and-click window
vlan_scan.sh                        VLAN walker (Linux)
vlan_scan.ps1                       VLAN walker (Windows)
build_exe.bat                       one-click Windows build
.github/workflows/build-windows.yml CI build of the Windows exe
README.md
```

## License

MIT. Add your own copyright line before publishing.
