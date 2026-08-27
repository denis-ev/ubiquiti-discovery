#!/usr/bin/env python3
"""
vlan_win.py - Windows 802.1Q VLAN walking, driven from Python.

Windows has no 802.1Q sub-interfaces the way Linux does, so a VLAN walk means
tagging the adapter itself into one VLAN at a time, scanning, and moving on.
This is the same approach vlan_scan.ps1 takes, reimplemented here so the GUI
can drive it directly instead of shelling out to a script that expects a
console and a copy of ubnt_scan.exe beside it.

Two methods, auto-detected:

    adapter - set the NIC's own "VLAN ID" advanced property. Needs a driver
              that exposes it. Intel removed VLAN support from PROSet on newer
              Windows 10/11 drivers, so this is absent on many modern laptops
              even with an Intel NIC.
    hyperv  - set the VLAN on a Hyper-V external switch's management vNIC.
              Windows Pro/Enterprise only.

Nothing here touches tkinter, so it can be exercised on its own.

IMPORTANT: a walk reconfigures a live adapter and drops its normal
connectivity for the duration. VlanWalker.restore() puts the original settings
back and must be called from a finally block.
"""

import json
import os
import re
import subprocess
import sys

IS_WINDOWS = os.name == "nt"

CREATE_NO_WINDOW = 0x08000000

# Registry keywords used for the VLAN ID property, in the order we try them.
# It differs between drivers, hence the list rather than one name.
VLAN_KEYWORDS = ("VlanID", "*VlanID", "VLANID", "VlanId")

ADDRESS_MODES = ("dhcp", "static", "none")


class VlanError(RuntimeError):
    """Anything that stops a walk from starting or continuing."""


# ---------------------------------------------------------------------------
# PowerShell plumbing
# ---------------------------------------------------------------------------
def _startupinfo():
    """Keep PowerShell from flashing a console window out of a --windowed exe."""
    if not IS_WINDOWS:
        return None
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0  # SW_HIDE
    return si


def run_ps(script, timeout=60):
    """Run a PowerShell snippet. Returns (returncode, stdout, stderr)."""
    if not IS_WINDOWS:
        raise VlanError("VLAN walking is Windows only.")
    cmd = ["powershell.exe", "-NoProfile", "-NonInteractive",
           "-ExecutionPolicy", "Bypass", "-Command", script]
    kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                  universal_newlines=True, startupinfo=_startupinfo())
    if IS_WINDOWS:
        kwargs["creationflags"] = CREATE_NO_WINDOW
    try:
        # Not capture_output=, which is 3.7+; this keeps the 3.6 promise.
        proc = subprocess.run(cmd, timeout=timeout, **kwargs)
    except subprocess.TimeoutExpired:
        raise VlanError("PowerShell timed out after %ss." % timeout)
    except OSError as exc:
        raise VlanError("Could not run PowerShell: %s" % exc)
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def ps_json(script, timeout=60):
    """Run a snippet whose last statement emits objects; return them as a list.

    ConvertTo-Json collapses a one-element array to a bare object on Windows
    PowerShell, and -AsArray is 7.0+, so normalise on this side instead.
    """
    wrapped = ("$ProgressPreference='SilentlyContinue';\n"
               "$out = @( %s );\n"
               "if ($out.Count -eq 0) { '[]' } "
               "else { $out | ConvertTo-Json -Compress -Depth 4 }" % script)
    rc, out, err = run_ps(wrapped, timeout=timeout)
    text = (out or "").strip()
    if not text:
        if rc != 0:
            raise VlanError((err or "PowerShell failed").strip())
        return []
    try:
        data = json.loads(text)
    except ValueError:
        raise VlanError("Unexpected PowerShell output: %s" % text[:200])
    if isinstance(data, dict):
        return [data]
    return list(data)


def _q(value):
    """Quote a string for a PowerShell single-quoted literal."""
    return "'%s'" % str(value).replace("'", "''")


# ---------------------------------------------------------------------------
# Elevation
# ---------------------------------------------------------------------------
def is_admin():
    """True if this process can reconfigure network adapters."""
    if not IS_WINDOWS:
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    """Re-run this program elevated via UAC.

    Returns True if a new elevated process was started, in which case the
    caller should exit. False means the user dismissed the UAC prompt.
    """
    if not IS_WINDOWS:
        raise VlanError("Elevation is Windows only.")
    import ctypes
    if getattr(sys, "frozen", False):
        exe = sys.executable
        argv = sys.argv[1:]
    else:
        exe = sys.executable
        argv = [os.path.abspath(sys.argv[0])] + sys.argv[1:]
    params = subprocess.list2cmdline(argv)
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", exe, params, None, 1)
    except Exception as exc:
        raise VlanError("Could not request elevation: %s" % exc)
    # ShellExecuteW returns >32 on success. 5 is ERROR_ACCESS_DENIED, which is
    # what a dismissed UAC prompt looks like.
    return int(rc) > 32


# ---------------------------------------------------------------------------
# Discovery of what this machine can do
# ---------------------------------------------------------------------------
def list_adapters():
    """Wired physical adapters, as a list of dicts."""
    rows = ps_json(
        "Get-NetAdapter -Physical -ErrorAction SilentlyContinue | "
        "Where-Object { $_.MediaType -ne 'Native 802.11' } | "
        "Select-Object Name, InterfaceDescription, Status, LinkSpeed")
    out = []
    for r in rows:
        out.append({
            "name": r.get("Name") or "",
            "description": r.get("InterfaceDescription") or "",
            "status": r.get("Status") or "",
            "link_speed": r.get("LinkSpeed") or "",
        })
    return [a for a in out if a["name"]]


_CAPS_SCRIPT = """
$name = %s
$out = [ordered]@{
    adapter = $name; exists = $false
    vlan_keyword = $null; vlan_display = $null; vlan_value = $null
    has_prio = $false; prio_value = $null
    hyperv = $false; hyperv_switch = $null
}
try { $null = Get-NetAdapter -Name $name -ErrorAction Stop; $out.exists = $true } catch { }
if ($out.exists) {
  try {
    $props = Get-NetAdapterAdvancedProperty -Name $name -ErrorAction Stop
    foreach ($kw in @(%s)) {
      $hit = $props | Where-Object { $_.RegistryKeyword -eq $kw } | Select-Object -First 1
      if ($hit) {
        $out.vlan_keyword = [string]$hit.RegistryKeyword
        $out.vlan_display = [string]$hit.DisplayName
        $out.vlan_value   = [string]($hit.RegistryValue | Select-Object -First 1)
        break
      }
    }
    if (-not $out.vlan_keyword) {
      $hit = $props | Where-Object {
          $_.DisplayName -match 'VLAN' -and $_.DisplayName -notmatch 'Priority'
      } | Select-Object -First 1
      if ($hit) {
        $out.vlan_keyword = [string]$hit.RegistryKeyword
        $out.vlan_display = [string]$hit.DisplayName
        $out.vlan_value   = [string]($hit.RegistryValue | Select-Object -First 1)
      }
    }
    $p = $props | Where-Object { $_.RegistryKeyword -eq '*PriorityVLANTag' } | Select-Object -First 1
    if ($p) {
      $out.has_prio   = $true
      $out.prio_value = [string]($p.RegistryValue | Select-Object -First 1)
    }
  } catch { }
}
if (Get-Command Get-VMSwitch -ErrorAction SilentlyContinue) {
  try {
    $sw = Get-VMSwitch -SwitchType External -ErrorAction Stop | Select-Object -First 1
    if ($sw) { $out.hyperv = $true; $out.hyperv_switch = [string]$sw.Name }
  } catch { }
}
[pscustomobject]$out
"""


def capabilities(adapter):
    """What VLAN methods this adapter supports. Changes nothing."""
    kw_list = ", ".join(_q(k) for k in VLAN_KEYWORDS)
    rows = ps_json(_CAPS_SCRIPT % (_q(adapter), kw_list))
    if not rows:
        raise VlanError("No capability information came back for %r." % adapter)
    caps = rows[0]
    return {
        "adapter": caps.get("adapter") or adapter,
        "exists": bool(caps.get("exists")),
        "vlan_keyword": caps.get("vlan_keyword") or None,
        "vlan_display": caps.get("vlan_display") or None,
        "vlan_value": caps.get("vlan_value"),
        "has_prio": bool(caps.get("has_prio")),
        "prio_value": caps.get("prio_value"),
        "hyperv": bool(caps.get("hyperv")),
        "hyperv_switch": caps.get("hyperv_switch") or None,
    }


def choose_method(caps, preferred="auto"):
    """Resolve 'auto' to 'adapter' or 'hyperv'. Raises if neither works."""
    preferred = (preferred or "auto").lower()
    if preferred == "adapter":
        if not caps.get("vlan_keyword"):
            raise VlanError("This driver does not expose a VLAN ID property.")
        return "adapter"
    if preferred == "hyperv":
        if not caps.get("hyperv"):
            raise VlanError("No Hyper-V external switch is available.")
        return "hyperv"
    if caps.get("vlan_keyword"):
        return "adapter"
    if caps.get("hyperv"):
        return "hyperv"
    raise VlanError(
        "Neither VLAN method is available on this machine.\n\n"
        "Remaining options:\n"
        "  - a NIC whose driver exposes a VLAN ID property\n"
        "  - enable Hyper-V (Pro/Enterprise) and create an external vSwitch\n"
        "  - run vlan_scan.sh from a Linux laptop or a bridged Linux VM\n"
        "  - have the switch put the port into each VLAN as an access port\n"
        "    in turn, and run a plain scan each time")


def describe_capabilities(caps):
    """Human-readable capability report, for the log pane."""
    lines = ["Capability report for '%s':" % caps["adapter"]]
    if not caps["exists"]:
        lines.append("  Adapter not found.")
        return lines
    if caps["vlan_keyword"]:
        lines.append("  Adapter VLAN tagging    : SUPPORTED (property '%s', keyword '%s')"
                     % (caps["vlan_display"], caps["vlan_keyword"]))
    else:
        lines.append("  Adapter VLAN tagging    : not exposed by this driver")
        lines.append("    Intel removed VLAN support from PROSet on newer Windows")
        lines.append("    10/11 drivers, so this is absent on many modern laptops")
        lines.append("    even with an Intel NIC. The check above is authoritative.")
    if caps["has_prio"]:
        lines.append("  Priority/VLAN tag       : present (current '%s')"
                     % caps["prio_value"])
    if caps["hyperv"]:
        lines.append("  Hyper-V external vSwitch: available ('%s')"
                     % caps["hyperv_switch"])
    else:
        lines.append("  Hyper-V external vSwitch: not available")
    return lines


# ---------------------------------------------------------------------------
# VLAN id parsing
# ---------------------------------------------------------------------------
def parse_vlan_list(text):
    """Turn '1-100', '10,20,99' or '1-10, 20 30' into a de-duplicated list."""
    ids = []
    for chunk in re.split(r"[,\s]+", (text or "").strip()):
        if not chunk:
            continue
        match = re.match(r"^(\d+)\s*-\s*(\d+)$", chunk)
        if match:
            low, high = int(match.group(1)), int(match.group(2))
            if low > high:
                low, high = high, low
            if high - low > 4093:
                raise ValueError("Range %s is wider than the VLAN space." % chunk)
            ids.extend(range(low, high + 1))
        elif chunk.isdigit():
            ids.append(int(chunk))
        else:
            raise ValueError("%r is not a VLAN id or range." % chunk)
    seen, out = set(), []
    for vid in ids:
        if 1 <= vid <= 4094 and vid not in seen:
            seen.add(vid)
            out.append(vid)
    if not out:
        raise ValueError("No VLAN ids in range 1-4094 found in %r." % text)
    return out


# ---------------------------------------------------------------------------
# The walker
# ---------------------------------------------------------------------------
class VlanWalker:
    """Tags one adapter into VLANs in turn, and puts it back afterwards.

    Usage:

        walker = VlanWalker(adapter, caps)
        try:
            for vid in vlans:
                walker.set_vlan(vid)
                ip = walker.wait_for_address()
                ...scan on ip...
        finally:
            walker.restore()

    restore() is idempotent and never raises, so it is safe in a finally block
    and safe to call again from a window-close handler.
    """

    def __init__(self, adapter, caps, method="auto", address_mode="dhcp",
                 static_ip="192.168.1.21", static_prefix=24, link_wait=12,
                 log=None):
        self.adapter = adapter
        self.caps = caps
        self.method = choose_method(caps, method)
        self.address_mode = (address_mode or "dhcp").lower()
        if self.address_mode not in ADDRESS_MODES:
            raise VlanError("Unknown address mode %r." % address_mode)
        self.static_ip = static_ip
        self.static_prefix = int(static_prefix)
        self.link_wait = int(link_wait)
        self._log = log or (lambda msg: None)

        self._touched = False       # have we changed anything yet
        self._static_added = False
        self._restored = False
        self._original_vlan = caps.get("vlan_value")
        self._original_prio = caps.get("prio_value")
        self._original_hyperv = None
        if self.method == "hyperv":
            self._original_hyperv = self._read_hyperv_vlan()

    # -- Hyper-V original state ---------------------------------------------
    def _read_hyperv_vlan(self):
        try:
            rows = ps_json(
                "Get-VMNetworkAdapterVlan -ManagementOS -ErrorAction SilentlyContinue | "
                "Select-Object -First 1 OperationMode, AccessVlanId")
        except VlanError:
            return None
        return rows[0] if rows else None

    # -- setting ------------------------------------------------------------
    def set_vlan(self, vid):
        """Tag the adapter into one VLAN. Raises VlanError on failure."""
        self._touched = True
        if self.method == "adapter":
            script = ""
            if self.caps.get("has_prio"):
                # 2 = VLAN enabled. Some drivers ignore the VLAN ID without it.
                script += ("Set-NetAdapterAdvancedProperty -Name %s "
                           "-RegistryKeyword '*PriorityVLANTag' -RegistryValue '2' "
                           "-NoRestart -ErrorAction SilentlyContinue;\n"
                           % _q(self.adapter))
            script += ("Set-NetAdapterAdvancedProperty -Name %s -RegistryKeyword %s "
                       "-RegistryValue %s -ErrorAction Stop"
                       % (_q(self.adapter), _q(self.caps["vlan_keyword"]), _q(vid)))
        else:
            script = ("Set-VMNetworkAdapterVlan -ManagementOS -Access -VlanId %d "
                      "-ErrorAction Stop" % int(vid))
        rc, _out, err = run_ps(script, timeout=60)
        if rc != 0:
            raise VlanError((err or "could not set VLAN %s" % vid).strip())

    def apply_static(self):
        """Put the fixed address on the adapter. Only for address_mode static."""
        self._static_added = True
        script = (
            "Remove-NetIPAddress -InterfaceAlias %s -IPAddress %s -Confirm:$false "
            "-ErrorAction SilentlyContinue;\n"
            "New-NetIPAddress -InterfaceAlias %s -IPAddress %s -PrefixLength %d "
            "-ErrorAction SilentlyContinue | Out-Null"
            % (_q(self.adapter), _q(self.static_ip),
               _q(self.adapter), _q(self.static_ip), self.static_prefix))
        run_ps(script, timeout=60)
        return self.static_ip

    def current_address(self):
        """First non-APIPA IPv4 on the adapter, else any IPv4, else None."""
        try:
            rows = ps_json(
                "Get-NetIPAddress -InterfaceAlias %s -AddressFamily IPv4 "
                "-ErrorAction SilentlyContinue | Select-Object IPAddress"
                % _q(self.adapter), timeout=30)
        except VlanError:
            return None
        addrs = [r.get("IPAddress") for r in rows if r.get("IPAddress")]
        for addr in addrs:
            if not addr.startswith("169.254."):
                return addr
        # APIPA is still worth scanning from: broadcast probes go out, and
        # devices that broadcast their reply are still heard.
        return addrs[0] if addrs else None

    def wait_for_address(self, should_stop=None):
        """Poll for an address after a VLAN change, up to link_wait seconds."""
        import time
        deadline = time.time() + self.link_wait
        while time.time() < deadline:
            if should_stop and should_stop():
                break
            addr = self.current_address()
            if addr and not addr.startswith("169.254."):
                return addr
            time.sleep(0.5)
        return self.current_address()

    def address_for_vlan(self, should_stop=None):
        """Get an address to scan from, honouring the address mode."""
        if self.address_mode == "static":
            return self.apply_static()
        if self.address_mode == "none":
            return self.current_address()
        return self.wait_for_address(should_stop=should_stop)

    # -- restoring ----------------------------------------------------------
    def restore(self):
        """Put the adapter back. Idempotent, and never raises."""
        if self._restored or not self._touched:
            self._restored = True
            return True
        self._restored = True
        self._log("Restoring original adapter settings...")
        ok = True
        try:
            if self.method == "adapter":
                script = ""
                if self._original_vlan is not None:
                    script += ("Set-NetAdapterAdvancedProperty -Name %s "
                               "-RegistryKeyword %s -RegistryValue %s "
                               "-NoRestart -ErrorAction SilentlyContinue;\n"
                               % (_q(self.adapter), _q(self.caps["vlan_keyword"]),
                                  _q(self._original_vlan)))
                if self._original_prio is not None and self.caps.get("has_prio"):
                    script += ("Set-NetAdapterAdvancedProperty -Name %s "
                               "-RegistryKeyword '*PriorityVLANTag' -RegistryValue %s "
                               "-NoRestart -ErrorAction SilentlyContinue;\n"
                               % (_q(self.adapter), _q(self._original_prio)))
                script += ("Restart-NetAdapter -Name %s -ErrorAction SilentlyContinue"
                           % _q(self.adapter))
            else:
                orig = self._original_hyperv or {}
                if orig.get("OperationMode") == "Access" and orig.get("AccessVlanId"):
                    script = ("Set-VMNetworkAdapterVlan -ManagementOS -Access "
                              "-VlanId %d -ErrorAction SilentlyContinue"
                              % int(orig["AccessVlanId"]))
                else:
                    script = ("Set-VMNetworkAdapterVlan -ManagementOS -Untagged "
                              "-ErrorAction SilentlyContinue")
            run_ps(script, timeout=120)

            if self._static_added:
                run_ps(
                    "Remove-NetIPAddress -InterfaceAlias %s -IPAddress %s "
                    "-Confirm:$false -ErrorAction SilentlyContinue;\n"
                    "Set-NetIPInterface -InterfaceAlias %s -Dhcp Enabled "
                    "-ErrorAction SilentlyContinue"
                    % (_q(self.adapter), _q(self.static_ip), _q(self.adapter)),
                    timeout=60)
            self._log("Adapter restored.")
        except Exception as exc:                       # never propagate
            ok = False
            self._log("Restore hit a problem: %s" % exc)
            self._log("Check the adapter's VLAN ID setting manually.")
        return ok
