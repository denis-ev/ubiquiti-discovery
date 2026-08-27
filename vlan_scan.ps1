<#
.SYNOPSIS
    Walk VLANs on a Windows laptop plugged into a trunk port and scan each one.

.DESCRIPTION
    Windows has no built-in 802.1Q sub-interfaces the way Linux does, so this
    tags the adapter itself into one VLAN at a time, scans, and moves on.

    Two methods, auto-detected:

      Adapter  - sets the NIC's own "VLAN ID" advanced property. Needs a driver
                 that exposes it (many Intel NICs do; most USB dongles and
                 Realtek chips do not).
      HyperV   - sets the VLAN on a Hyper-V external switch's management vNIC.
                 Needs Hyper-V, which is Windows Pro/Enterprise only.

    Run with -Check first. That reports what your hardware supports and changes
    nothing.

    IMPORTANT: this reconfigures a network adapter. The adapter loses its normal
    connectivity for the duration. Do not run it against the adapter carrying
    your RDP session. Original settings are restored on exit, including on
    Ctrl-C.

.EXAMPLE
    .\vlan_scan.ps1 -Check
.EXAMPLE
    .\vlan_scan.ps1 -Adapter "Ethernet" -Range 1-100
.EXAMPLE
    .\vlan_scan.ps1 -Adapter "Ethernet" -VlanIds 10,20,99 -AddressMode DHCP -OutFile found.csv
#>

[CmdletBinding()]
param(
    [string]$Adapter,
    [int[]]$VlanIds,
    [string]$Range,
    [ValidateSet('Adapter', 'HyperV', 'Auto')]
    [string]$Method = 'Auto',
    [ValidateSet('DHCP', 'Static', 'None')]
    [string]$AddressMode = 'DHCP',
    [string]$StaticIP = '192.168.1.21',
    [int]$StaticPrefix = 24,
    [int]$Timeout = 3,
    [int]$LinkWait = 12,
    [string]$Scanner = '.\ubnt_scan.exe',
    [string]$OutFile,
    [switch]$Check,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Write-Info  { param($m) Write-Host $m -ForegroundColor Cyan }
function Write-Warn  { param($m) Write-Host $m -ForegroundColor Yellow }
function Write-Bad   { param($m) Write-Host $m -ForegroundColor Red }
function Write-Good  { param($m) Write-Host $m -ForegroundColor Green }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-VlanProperty {
    <# The registry keyword differs between drivers, so match on several. #>
    param([string]$Name)
    try {
        $props = Get-NetAdapterAdvancedProperty -Name $Name -ErrorAction Stop
    } catch { return $null }
    foreach ($kw in @('VlanID', '*VlanID', 'VLANID', 'VlanId')) {
        $hit = $props | Where-Object { $_.RegistryKeyword -eq $kw }
        if ($hit) { return $hit }
    }
    $props | Where-Object { $_.DisplayName -match 'VLAN' -and
                            $_.DisplayName -notmatch 'Priority' } |
             Select-Object -First 1
}

function Get-Capabilities {
    param([string]$Name)
    $caps = [ordered]@{
        Adapter        = $Name
        VlanProperty   = $null
        PriorityVlan   = $null
        HyperV         = $false
        HyperVSwitch   = $null
    }
    $caps.VlanProperty = Get-VlanProperty -Name $Name
    try {
        $caps.PriorityVlan = Get-NetAdapterAdvancedProperty -Name $Name -ErrorAction Stop |
            Where-Object { $_.RegistryKeyword -eq '*PriorityVLANTag' }
    } catch {}
    if (Get-Command Get-VMSwitch -ErrorAction SilentlyContinue) {
        try {
            $sw = Get-VMSwitch -SwitchType External -ErrorAction Stop |
                  Select-Object -First 1
            if ($sw) { $caps.HyperV = $true; $caps.HyperVSwitch = $sw.Name }
        } catch {}
    }
    [pscustomobject]$caps
}

# ---------------------------------------------------------------------------
# Capability check
# ---------------------------------------------------------------------------
Write-Host ''
Write-Info '=== Windows VLAN scan ==='
Write-Host ''

if (-not (Test-Admin)) {
    Write-Bad 'Must be run as Administrator (right-click PowerShell > Run as administrator).'
    exit 1
}

if (-not $Adapter) {
    Write-Info 'Wired adapters on this machine:'
    Get-NetAdapter -Physical |
        Where-Object { $_.MediaType -ne 'Native 802.11' } |
        Format-Table Name, InterfaceDescription, Status, LinkSpeed -AutoSize
    Write-Warn 'Re-run with -Adapter "<Name>" from the Name column.'
    exit 0
}

try { $null = Get-NetAdapter -Name $Adapter -ErrorAction Stop }
catch { Write-Bad "No adapter named '$Adapter'."; exit 1 }

$caps = Get-Capabilities -Name $Adapter

Write-Info "Capability report for '$Adapter':"
if ($caps.VlanProperty) {
    Write-Good ("  Adapter VLAN tagging : SUPPORTED (property '{0}', keyword '{1}')" -f
                $caps.VlanProperty.DisplayName, $caps.VlanProperty.RegistryKeyword)
} else {
    Write-Warn  '  Adapter VLAN tagging : not exposed by this driver'
}
if ($caps.PriorityVlan) {
    Write-Host ("  Priority/VLAN tag    : present (current '{0}')" -f $caps.PriorityVlan.DisplayValue)
}
    Write-Warn  '  NOTE: Intel removed VLAN support from PROSet on newer'
    Write-Warn  '        Windows 10/11 drivers, so this can be absent even'
    Write-Warn  '        on an Intel NIC. The check above is authoritative.'
if ($caps.HyperV) {
    Write-Good ("  Hyper-V external vSwitch: available ('{0}')" -f $caps.HyperVSwitch)
} else {
    Write-Warn  '  Hyper-V external vSwitch: not available'
}
Write-Host ''

if ($Method -eq 'Auto') {
    if     ($caps.VlanProperty) { $Method = 'Adapter' }
    elseif ($caps.HyperV)       { $Method = 'HyperV'  }
    else {
        Write-Bad 'Neither method is available on this machine.'
        Write-Host ''
        Write-Host 'Remaining options:'
        Write-Host '  * Use a machine with an Intel NIC whose driver exposes VLAN ID.'
        Write-Host '  * Enable Hyper-V (Pro/Enterprise) and create an external vSwitch.'
        Write-Host '  * Run vlan_scan.sh from a Linux laptop or a bridged Linux VM.'
        Write-Host '  * Have the switch put the port into each VLAN as an access'
        Write-Host '    port in turn, and run a plain scan each time.'
        exit 1
    }
}
Write-Info "Method selected: $Method"

if ($Check) { Write-Host ''; Write-Good 'Check complete. Nothing was changed.'; exit 0 }

# ---------------------------------------------------------------------------
# Build the VLAN list
# ---------------------------------------------------------------------------
if ($Range) {
    if ($Range -notmatch '^\s*(\d+)\s*-\s*(\d+)\s*$') {
        Write-Bad "Range must look like 1-100."; exit 1
    }
    $VlanIds = ([int]$Matches[1])..([int]$Matches[2])
}
if (-not $VlanIds -or $VlanIds.Count -eq 0) {
    Write-Bad 'Give -VlanIds 10,20,30 or -Range 1-100.'; exit 1
}
$VlanIds = $VlanIds | Where-Object { $_ -ge 1 -and $_ -le 4094 }

if (-not (Test-Path $Scanner)) {
    Write-Bad "Scanner not found at '$Scanner'. Use -Scanner to point at ubnt_scan.exe."
    exit 1
}

Write-Host ''
Write-Warn "This will reconfigure '$Adapter' $($VlanIds.Count) time(s)."
Write-Warn 'It will lose normal connectivity during the walk. Do not run this'
Write-Warn 'against the adapter carrying your remote session.'
Write-Warn 'Other active adapters (Wi-Fi) should be disconnected, or their'
Write-Warn 'devices may appear in the results.'
if (-not $Force) {
    $answer = Read-Host 'Continue? (y/N)'
    if ($answer -notmatch '^[Yy]') { Write-Host 'Aborted.'; exit 0 }
}

# ---------------------------------------------------------------------------
# Save original state so it can be restored no matter how we exit
# ---------------------------------------------------------------------------
$original = @{
    VlanValue    = $null
    PriorityVal  = $null
    HyperVVlan   = $null
    StaticAdded  = $false
}
if ($Method -eq 'Adapter') {
    $original.VlanValue = $caps.VlanProperty.RegistryValue
    if ($caps.PriorityVlan) { $original.PriorityVal = $caps.PriorityVlan.RegistryValue }
} elseif ($Method -eq 'HyperV') {
    $original.HyperVVlan = Get-VMNetworkAdapterVlan -ManagementOS -ErrorAction SilentlyContinue |
                           Select-Object -First 1
}

function Set-Vlan {
    param([int]$Id)
    if ($Method -eq 'Adapter') {
        if ($caps.PriorityVlan) {
            # 2 = VLAN enabled. Without this some drivers ignore the VLAN ID.
            Set-NetAdapterAdvancedProperty -Name $Adapter `
                -RegistryKeyword '*PriorityVLANTag' -RegistryValue '2' `
                -NoRestart -ErrorAction SilentlyContinue
        }
        Set-NetAdapterAdvancedProperty -Name $Adapter `
            -RegistryKeyword $caps.VlanProperty.RegistryKeyword `
            -RegistryValue "$Id" -ErrorAction Stop
    } else {
        Set-VMNetworkAdapterVlan -ManagementOS -Access -VlanId $Id -ErrorAction Stop
    }
}

function Restore-Original {
    Write-Host ''
    Write-Info 'Restoring original adapter settings...'
    try {
        if ($Method -eq 'Adapter') {
            if ($null -ne $original.VlanValue) {
                Set-NetAdapterAdvancedProperty -Name $Adapter `
                    -RegistryKeyword $caps.VlanProperty.RegistryKeyword `
                    -RegistryValue $original.VlanValue `
                    -NoRestart -ErrorAction SilentlyContinue
            }
            if ($null -ne $original.PriorityVal -and $caps.PriorityVlan) {
                Set-NetAdapterAdvancedProperty -Name $Adapter `
                    -RegistryKeyword '*PriorityVLANTag' `
                    -RegistryValue $original.PriorityVal `
                    -NoRestart -ErrorAction SilentlyContinue
            }
            Restart-NetAdapter -Name $Adapter -ErrorAction SilentlyContinue
        } else {
            if ($original.HyperVVlan -and $original.HyperVVlan.OperationMode -eq 'Access') {
                Set-VMNetworkAdapterVlan -ManagementOS -Access `
                    -VlanId $original.HyperVVlan.AccessVlanId -ErrorAction SilentlyContinue
            } else {
                Set-VMNetworkAdapterVlan -ManagementOS -Untagged -ErrorAction SilentlyContinue
            }
        }
        if ($original.StaticAdded) {
            Remove-NetIPAddress -InterfaceAlias $Adapter -IPAddress $StaticIP `
                -Confirm:$false -ErrorAction SilentlyContinue
            Set-NetIPInterface -InterfaceAlias $Adapter -Dhcp Enabled `
                -ErrorAction SilentlyContinue
        }
        Write-Good 'Adapter restored.'
    } catch {
        Write-Bad "Restore hit a problem: $_"
        Write-Bad "Check the adapter's VLAN ID setting manually."
    }
}

function Wait-ForAddress {
    param([int]$Seconds)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        $ip = Get-NetIPAddress -InterfaceAlias $Adapter -AddressFamily IPv4 `
                -ErrorAction SilentlyContinue |
              Where-Object { $_.IPAddress -notlike '169.254.*' } |
              Select-Object -First 1
        if ($ip) { return $ip.IPAddress }
        Start-Sleep -Milliseconds 500
    }
    # Fall back to whatever is there, APIPA included: broadcast probes still
    # go out, and devices that broadcast their reply are still heard.
    $any = Get-NetIPAddress -InterfaceAlias $Adapter -AddressFamily IPv4 `
             -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($any) { return $any.IPAddress }
    return $null
}

# ---------------------------------------------------------------------------
$total = 0
try {
    foreach ($vid in $VlanIds) {
        Write-Host ("`rVLAN {0} ... setting tag        " -f $vid) -NoNewline
        try { Set-Vlan -Id $vid }
        catch { Write-Warn "`rVLAN $vid : could not set tag ($_)"; continue }

        if ($AddressMode -eq 'Static') {
            Remove-NetIPAddress -InterfaceAlias $Adapter -IPAddress $StaticIP `
                -Confirm:$false -ErrorAction SilentlyContinue
            New-NetIPAddress -InterfaceAlias $Adapter -IPAddress $StaticIP `
                -PrefixLength $StaticPrefix -ErrorAction SilentlyContinue | Out-Null
            $original.StaticAdded = $true
            $ip = $StaticIP
        } else {
            $ip = Wait-ForAddress -Seconds $LinkWait
        }

        if (-not $ip) { Write-Host ("`rVLAN {0} : no address, skipped   " -f $vid) -NoNewline; continue }

        $tmp = [System.IO.Path]::GetTempFileName()
        # --no-wildcard keeps results attributable: Windows cannot report a
        # packet's arrival interface, so the catch-all listener would let
        # other adapters contaminate this VLAN's results.
        & $Scanner -i $ip -t $Timeout --csv $tmp --no-wildcard --no-pause 2>&1 | Out-Null

        $rows = @()
        if (Test-Path $tmp) { $rows = @(Import-Csv $tmp -ErrorAction SilentlyContinue) }
        Remove-Item $tmp -ErrorAction SilentlyContinue

        if ($rows.Count -gt 0) {
            $total += $rows.Count
            Write-Host ''
            Write-Good ("VLAN {0} ({1}) -- {2} device(s):" -f $vid, $ip, $rows.Count)
            $rows | ForEach-Object {
                Write-Host ("    {0,-15} {1,-17} {2,-20} {3}" -f
                            $_.ip, $_.mac, $_.hostname, $_.model)
            }
            if ($OutFile) {
                $rows | Add-Member -NotePropertyName vlan -NotePropertyValue $vid -PassThru |
                    Export-Csv -Path $OutFile -NoTypeInformation -Append
            }
        } else {
            Write-Host ("`rVLAN {0} ({1}) : no response      " -f $vid, $ip) -NoNewline
        }
    }
} finally {
    Restore-Original
}

Write-Host ''
Write-Good "Done. $total device record(s) found."
if ($OutFile) { Write-Host "Written to $OutFile" }
