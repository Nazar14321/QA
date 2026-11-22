#!/bin/sh

VERSION="1.0.0"

log_event() {
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" > /dev/console
}

if [ "${1:-}" = "--version" ]; then
    echo "Traffic Analyzer version: $VERSION"
    echo "Linux kernel: $(uname -r)"
    exit 0
fi

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 INTERFACE TFTP_SERVER_IP" >&2
    echo "Example: $0 br0 192.168.77.20" >&2
    exit 2
fi

IFACE=$1
SERVER=$2

if [ ! -d "/sys/class/net/$IFACE" ]; then
    echo "ERROR: interface '$IFACE' does not exist" >&2
    exit 2
fi

for tool in tcpdump tftp; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: $tool is not installed" >&2
        exit 2
    fi
done

if [ ! -w /dev/console ]; then
    echo "ERROR: /dev/console is not writable" >&2
    exit 2
fi

if ! ifconfig "$IFACE" up; then
    log_event "SNIFF_ERROR interface=$IFACE"
    exit 1
fi

FILE_NAME="traffic-$(date '+%Y%m%d-%H%M%S')-$$.pcap"
PCAP="/tmp/$FILE_NAME"

CAP_PID=

abort_capture() {
    trap - INT TERM HUP

    if [ -n "$CAP_PID" ] && kill -0 "$CAP_PID" 2>/dev/null; then
        kill -INT "$CAP_PID" 2>/dev/null
        wait "$CAP_PID" 2>/dev/null
    fi

    rm -f "$PCAP"
    log_event "SNIFF_INTERRUPTED interface=$IFACE"
    exit 130
}

trap 'abort_capture' INT TERM HUP

log_event "SNIFF_START interface=$IFACE duration=60s"

tcpdump -i "$IFACE" -s 0 -nn -w "$PCAP" \
    >/dev/null 2>/dev/console &

CAP_PID=$!

sleep 60

if kill -0 "$CAP_PID" 2>/dev/null; then
    kill -INT "$CAP_PID" 2>/dev/null
fi

wait "$CAP_PID"
CAP_RC=$?

CAP_PID=
trap - INT TERM HUP

if [ "$CAP_RC" -ne 0 ] || [ ! -s "$PCAP" ]; then
    log_event "SNIFF_ERROR rc=$CAP_RC file=$FILE_NAME"
    exit 1
fi

log_event "SNIFF_STOP file=$FILE_NAME"

if tftp -p -l "$PCAP" -r "$FILE_NAME" "$SERVER"; then
    log_event "TFTP_OK server=$SERVER file=$FILE_NAME"
else
    log_event "TFTP_ERROR server=$SERVER file=$FILE_NAME"
    exit 1
fi

exit 0