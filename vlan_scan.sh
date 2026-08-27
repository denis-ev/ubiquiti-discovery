#!/usr/bin/env bash
#
# vlan_scan.sh - loop through VLAN IDs on a trunk port and run ubnt_scan.py
#                on each one.
#
# Linux only. Needs root (creating VLAN interfaces and binding to them).
# Every interface it creates is removed again on exit, including on Ctrl-C.
#
#   sudo ./vlan_scan.sh -n eth0 -r 1-100
#   sudo ./vlan_scan.sh -n eth0 -l 10,20,30,99 -a dhcp
#   sudo ./vlan_scan.sh -n eth0 -r 1-4094 -t 2 -o found.csv
#
set -u

NIC=""
VLANS=""
ADDR_MODE="none"       # none | dhcp | static
STATIC_CIDR="192.168.1.21/24"
TIMEOUT=3
OUTFILE=""
SCAN="$(dirname "$0")/ubnt_scan.py"

usage() {
    cat <<'EOF'
Usage: sudo ./vlan_scan.sh -n <trunk-nic> [-r A-B | -l 1,2,3] [options]

  -n IFACE     physical interface plugged into the trunk port (required)
  -r A-B       VLAN ID range to walk, e.g. 1-100
  -l LIST      explicit comma-separated VLAN IDs, e.g. 10,20,99
  -a MODE      address mode on each VLAN interface:
                 none   (default) no IP; only catches devices that
                        broadcast their reply
                 dhcp   try a DHCP lease, fall back to none
                 static use -c CIDR on every VLAN
  -c CIDR      static address for -a static (default 192.168.1.21/24)
  -t SECONDS   listen time per VLAN (default 3)
  -o FILE      append all findings to a CSV
  -s PATH      path to ubnt_scan.py (default: alongside this script)
  -h           this help

Notes:
  * The switch port must be a TRUNK (802.1Q tagged) carrying the VLANs you
    want to see. On an access port you will only ever see one VLAN, and the
    untagged one is already covered by a plain ubnt_scan.py run.
  * With -a none the laptop has no address on the VLAN, so a device that
    unicasts its reply has nowhere to send it. You will still see devices
    that broadcast their reply. Use -a dhcp or -a static to catch the rest.
  * Walking all 4094 VLANs at 3s each takes about 3.5 hours. Narrow the
    range if you know your VLAN plan.
EOF
}

while getopts "n:r:l:a:c:t:o:s:h" opt; do
    case "$opt" in
        n) NIC="$OPTARG" ;;
        r) VLANS="$(echo "$OPTARG" | awk -F- '{for(i=$1;i<=$2;i++) print i}')" ;;
        l) VLANS="$(echo "$OPTARG" | tr ',' '\n')" ;;
        a) ADDR_MODE="$OPTARG" ;;
        c) STATIC_CIDR="$OPTARG" ;;
        t) TIMEOUT="$OPTARG" ;;
        o) OUTFILE="$OPTARG" ;;
        s) SCAN="$OPTARG" ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done

[ -z "$NIC" ] && { usage; exit 1; }
[ -z "$VLANS" ] && { echo "Give -r or -l"; exit 1; }
[ "$(id -u)" -ne 0 ] && { echo "Needs root."; exit 1; }
[ -f "$SCAN" ] || { echo "ubnt_scan.py not found at $SCAN (use -s)"; exit 1; }
ip link show "$NIC" >/dev/null 2>&1 || { echo "No such interface: $NIC"; exit 1; }

if ! lsmod 2>/dev/null | grep -q '^8021q' && ! modprobe 8021q 2>/dev/null; then
    echo "Warning: could not load the 8021q module; VLAN interfaces may fail."
fi

CURRENT_IF=""
cleanup() {
    if [ -n "$CURRENT_IF" ] && ip link show "$CURRENT_IF" >/dev/null 2>&1; then
        pkill -f "dhclient .*$CURRENT_IF" 2>/dev/null
        ip link delete "$CURRENT_IF" 2>/dev/null
    fi
    echo
    echo "Cleaned up. Interfaces created by this script are gone."
}
trap cleanup EXIT INT TERM

ip link set "$NIC" up

echo "Trunk NIC   : $NIC"
echo "Address mode: $ADDR_MODE"
echo "Per-VLAN    : ${TIMEOUT}s"
echo "VLAN count  : $(echo "$VLANS" | wc -l)"
echo

HITS=0
for VID in $VLANS; do
    case "$VID" in ''|*[!0-9]*) continue ;; esac
    [ "$VID" -lt 1 ] || [ "$VID" -gt 4094 ] && continue

    IFNAME="${NIC}.${VID}"
    ip link delete "$IFNAME" 2>/dev/null
    if ! ip link add link "$NIC" name "$IFNAME" type vlan id "$VID" 2>/dev/null; then
        echo "VLAN $VID: could not create interface, skipping"
        continue
    fi
    CURRENT_IF="$IFNAME"
    ip link set "$IFNAME" up

    case "$ADDR_MODE" in
        dhcp)
            timeout 6 dhclient -1 -nw "$IFNAME" 2>/dev/null
            sleep 3
            ;;
        static)
            ip addr add "$STATIC_CIDR" dev "$IFNAME" 2>/dev/null
            ;;
    esac

    HAVE_IP="$(ip -4 -o addr show dev "$IFNAME" | awk '{print $4}' | cut -d/ -f1 | head -1)"

    TMP="$(mktemp)"
    # -D is always passed: it confines the wildcard listener to this VLAN
    # interface, so a reply arriving on the native LAN is not credited to
    # whichever VLAN happens to be under test.
    if [ -n "$HAVE_IP" ]; then
        python3 "$SCAN" -D "$IFNAME" -i "$HAVE_IP" -t "$TIMEOUT" \
                --csv "$TMP" >/dev/null 2>&1
    else
        python3 "$SCAN" -D "$IFNAME" -t "$TIMEOUT" --csv "$TMP" >/dev/null 2>&1
    fi

    COUNT=$(($(wc -l < "$TMP") - 1))
    [ "$COUNT" -lt 0 ] && COUNT=0
    if [ "$COUNT" -gt 0 ]; then
        HITS=$((HITS + COUNT))
        echo "VLAN $VID ${HAVE_IP:+($HAVE_IP) }-- $COUNT device(s):"
        tail -n +2 "$TMP" | awk -F, '{printf "    %-15s %-17s %-20s %s\n",$1,$2,$3,$4}'
        if [ -n "$OUTFILE" ]; then
            [ -s "$OUTFILE" ] || head -1 "$TMP" | sed 's/^/vlan,/' > "$OUTFILE"
            tail -n +2 "$TMP" | sed "s/^/$VID,/" >> "$OUTFILE"
        fi
    else
        printf "VLAN %-5s no response\r" "$VID"
    fi
    rm -f "$TMP"

    pkill -f "dhclient .*$IFNAME" 2>/dev/null
    ip link delete "$IFNAME" 2>/dev/null
    CURRENT_IF=""
done

echo
echo "Done. $HITS device record(s) found."
[ -n "$OUTFILE" ] && echo "Written to $OUTFILE"
