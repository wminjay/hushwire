#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <hushwire-binary>" >&2
    exit 2
fi

if [[ $(id -u) -ne 0 ]]; then
    echo "gateway_netns.sh must run as root" >&2
    exit 2
fi

for command_name in ip iptables iptables-save python3 realpath; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "missing required command: $command_name" >&2
        exit 2
    fi
done

binary_path=$(realpath "$1")
if [[ ! -x "$binary_path" ]]; then
    echo "HushWire binary is not executable: $binary_path" >&2
    exit 2
fi

test_directory=$(mktemp -d)
suffix=$$
client_namespace="hw-gw-client-${suffix}"
gateway_namespace="hw-gw-router-${suffix}"
server_namespace="hw-gw-server-${suffix}"
client_veth="hwgc${suffix}"
gateway_lan_veth="hwgl${suffix}"
gateway_tun_veth="hwgt${suffix}"
server_veth="hwgs${suffix}"
server_pid=""
gateway_applied=0

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    set +e

    if [[ -n "$server_pid" ]]; then
        kill -TERM "$server_pid" >/dev/null 2>&1
        wait "$server_pid" >/dev/null 2>&1
    fi
    if [[ $gateway_applied -eq 1 ]]; then
        ip netns exec "$gateway_namespace" \
            env HUSHWIRE_GATEWAY_STATE_DIR="$test_directory/state" \
            "$binary_path" gateway remove --config "$test_directory/gateway.toml" \
            >/dev/null 2>&1
    fi
    ip netns delete "$client_namespace" >/dev/null 2>&1
    ip netns delete "$gateway_namespace" >/dev/null 2>&1
    ip netns delete "$server_namespace" >/dev/null 2>&1
    rm -rf -- "$test_directory"
    exit "$status"
}
trap cleanup EXIT INT TERM

cat >"$test_directory/gateway.toml" <<'EOF'
[interface]
name = "stb0"
address = "10.77.99.2/30"
listen = "0.0.0.0:27779"
transport = "udp"
mtu = 1280
private_key = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="

[gateway]
lan_interface = "lan0"
tcp_mss = 1160
EOF

ip netns add "$client_namespace"
ip netns add "$gateway_namespace"
ip netns add "$server_namespace"

ip link add "$client_veth" type veth peer name "$gateway_lan_veth"
ip link add "$gateway_tun_veth" type veth peer name "$server_veth"
ip link set "$client_veth" netns "$client_namespace"
ip link set "$gateway_lan_veth" netns "$gateway_namespace"
ip link set "$gateway_tun_veth" netns "$gateway_namespace"
ip link set "$server_veth" netns "$server_namespace"

ip -n "$client_namespace" link set lo up
ip -n "$client_namespace" link set "$client_veth" name eth0
ip -n "$client_namespace" address add 10.20.0.2/24 dev eth0
ip -n "$client_namespace" link set eth0 mtu 1500 up
ip -n "$client_namespace" route add default via 10.20.0.1

ip -n "$gateway_namespace" link set lo up
ip -n "$gateway_namespace" link set "$gateway_lan_veth" name lan0
ip -n "$gateway_namespace" link set "$gateway_tun_veth" name stb0
ip -n "$gateway_namespace" address add 10.20.0.1/24 dev lan0
ip -n "$gateway_namespace" address add 192.0.2.1/24 dev stb0
ip -n "$gateway_namespace" link set lan0 mtu 1500 up
ip -n "$gateway_namespace" link set stb0 mtu 1280 up
ip netns exec "$gateway_namespace" iptables -P FORWARD DROP
ip netns exec "$gateway_namespace" sysctl -q -w net.ipv4.ip_forward=0

ip -n "$server_namespace" link set lo up
ip -n "$server_namespace" link set "$server_veth" name eth0
ip -n "$server_namespace" address add 192.0.2.2/24 dev eth0
ip -n "$server_namespace" link set eth0 mtu 1280 up
ip -n "$server_namespace" route add 10.20.0.0/24 via 192.0.2.1

gateway_command() {
    ip netns exec "$gateway_namespace" \
        env HUSHWIRE_GATEWAY_STATE_DIR="$test_directory/state" \
        "$binary_path" gateway "$@" --config "$test_directory/gateway.toml"
}

# Planning is deliberately non-mutating and can run before forwarding is enabled.
gateway_command plan >"$test_directory/plan.log"
grep -q "TCP MSS: 1160 (explicit)" "$test_directory/plan.log"
grep -q "No changes made by plan" "$test_directory/plan.log"
[[ $(ip netns exec "$gateway_namespace" sysctl -n net.ipv4.ip_forward) == 0 ]]
if ip netns exec "$gateway_namespace" iptables-save | grep -q "hushwire-gateway:"; then
    echo "gateway plan unexpectedly changed iptables" >&2
    exit 1
fi

# Applying twice must remain idempotent: five owned rules, not ten.
gateway_command apply
gateway_applied=1
gateway_command apply
gateway_command status >"$test_directory/status.log"
grep -q "OK tunnel MTU 1280" "$test_directory/status.log"
[[ $(ip netns exec "$gateway_namespace" sysctl -n net.ipv4.ip_forward) == 1 ]]
owned_rule_count=$(
    ip netns exec "$gateway_namespace" iptables-save |
        grep -c "hushwire-gateway:stb0"
)
if [[ $owned_rule_count -ne 5 ]]; then
    echo "expected 5 owned gateway rules, found $owned_rule_count" >&2
    exit 1
fi

# One TCP handshake must be clamped in both directions. TCP_MAXSEG is the
# effective payload ceiling after negotiated TCP options, so it may be a few
# bytes below the configured 1160 but must never exceed it.
ip netns exec "$server_namespace" python3 -c '
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("192.0.2.2", 24443))
s.listen(1)
c, _ = s.accept()
with open(sys.argv[1], "w", encoding="utf-8") as output:
    output.write(str(c.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)))
payload = c.recv(4096)
c.sendall(b"ok:" + str(len(payload)).encode())
time.sleep(0.2)
c.close()
s.close()
' "$test_directory/server-mss" &
server_pid=$!
sleep 0.25
ip netns exec "$client_namespace" python3 -c '
import socket, sys
s = socket.create_connection(("192.0.2.2", 24443), timeout=3)
with open(sys.argv[1], "w", encoding="utf-8") as output:
    output.write(str(s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)))
s.sendall(b"x" * 2000)
reply = s.recv(64)
assert reply.startswith(b"ok:"), reply
s.close()
' "$test_directory/client-mss"
wait "$server_pid"
server_pid=""

client_mss=$(<"$test_directory/client-mss")
server_mss=$(<"$test_directory/server-mss")
if ((client_mss < 536 || client_mss > 1160)); then
    echo "client effective MSS outside expected range: $client_mss" >&2
    exit 1
fi
if ((server_mss < 536 || server_mss > 1160)); then
    echo "server effective MSS outside expected range: $server_mss" >&2
    exit 1
fi

mangle_rules=$(ip netns exec "$gateway_namespace" iptables -t mangle -L FORWARD -n -v -x)
outbound_syns=$(awk '$3 == "TCPMSS" && $6 == "lan0" && $7 == "stb0" { print $1 }' <<<"$mangle_rules")
inbound_syns=$(awk '$3 == "TCPMSS" && $6 == "stb0" && $7 == "lan0" { print $1 }' <<<"$mangle_rules")
if [[ -z "$outbound_syns" || -z "$inbound_syns" || $outbound_syns -lt 1 || $inbound_syns -lt 1 ]]; then
    echo "bidirectional MSS rules did not both see the TCP handshake" >&2
    echo "$mangle_rules" >&2
    exit 1
fi

# MSS is TCP-specific; ordinary UDP forwarding and NAT must still work for a
# datagram that fits the 1280-byte tunnel MTU.
ip netns exec "$server_namespace" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("192.0.2.2", 24444))
data, peer = s.recvfrom(2048)
s.sendto(str(len(data)).encode(), peer)
s.close()
' &
server_pid=$!
sleep 0.25
ip netns exec "$client_namespace" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(b"u" * 1200, ("192.0.2.2", 24444))
reply, _ = s.recvfrom(64)
assert reply == b"1200", reply
s.close()
'
wait "$server_pid"
server_pid=""

# A policy update must replace, rather than stack on top of, the previous MSS
# rules. The tunnel interface name is the stable policy identity.
python3 - "$test_directory/gateway.toml" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
path.write_text(text.replace("tcp_mss = 1160", "tcp_mss = 1100"), encoding="utf-8")
PY
gateway_command apply >/dev/null
gateway_command status >"$test_directory/updated-status.log"
updated_rules=$(ip netns exec "$gateway_namespace" iptables-save)
if grep -q -- "--set-mss 1160" <<<"$updated_rules"; then
    echo "gateway policy update left the old MSS rule behind" >&2
    exit 1
fi
if [[ $(grep -c -- "--set-mss 1100" <<<"$updated_rules") -ne 2 ]]; then
    echo "gateway policy update did not install exactly two new MSS rules" >&2
    exit 1
fi
if [[ $(grep -c "hushwire-gateway:stb0" <<<"$updated_rules") -ne 5 ]]; then
    echo "gateway policy update left an unexpected owned rule count" >&2
    exit 1
fi

gateway_command remove
gateway_applied=0
[[ $(ip netns exec "$gateway_namespace" sysctl -n net.ipv4.ip_forward) == 0 ]]
if ip netns exec "$gateway_namespace" iptables-save | grep -q "hushwire-gateway:"; then
    echo "gateway remove left owned firewall rules behind" >&2
    exit 1
fi
if gateway_command status >/dev/null 2>&1; then
    echo "gateway status unexpectedly succeeded after remove" >&2
    exit 1
fi

# Removal is safe to retry, and a host whose forwarding was already enabled
# must keep that pre-existing setting after the managed policy is removed.
gateway_command remove >/dev/null
ip netns exec "$gateway_namespace" sysctl -q -w net.ipv4.ip_forward=1
gateway_command apply >/dev/null
gateway_applied=1
gateway_command remove >/dev/null
gateway_applied=0
[[ $(ip netns exec "$gateway_namespace" sysctl -n net.ipv4.ip_forward) == 1 ]]
ip netns exec "$gateway_namespace" sysctl -q -w net.ipv4.ip_forward=0

echo "isolated gateway test passed: plan was inert, apply was idempotent, TCP MSS was symmetric and reconcilable, UDP forwarded, and remove restored state"
