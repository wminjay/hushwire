#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <hushwire-binary>" >&2
    exit 2
fi

if [[ $(id -u) -ne 0 ]]; then
    echo "recovery_netns.sh must run as root" >&2
    exit 2
fi

for command_name in ip ping realpath; do
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
client_namespace="hw-client-${suffix}"
server_namespace="hw-server-${suffix}"
client_veth="hwc${suffix}"
server_veth="hws${suffix}"
client_pid=""
server_pid=""
server_generation=0

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    set +e

    if [[ $status -ne 0 ]]; then
        echo "--- client log ---" >&2
        tail -n 160 "$test_directory/client.log" >&2 2>/dev/null
        echo "--- restarted server log ---" >&2
        tail -n 160 "$test_directory/server-2.log" >&2 2>/dev/null
        echo "--- initial server log ---" >&2
        tail -n 80 "$test_directory/server-1.log" >&2 2>/dev/null
    fi

    if [[ -n "$client_pid" ]]; then
        kill -TERM "$client_pid" >/dev/null 2>&1
        wait "$client_pid" >/dev/null 2>&1
    fi
    if [[ -n "$server_pid" ]]; then
        kill -TERM "$server_pid" >/dev/null 2>&1
        wait "$server_pid" >/dev/null 2>&1
    fi

    ip netns delete "$client_namespace" >/dev/null 2>&1
    ip netns delete "$server_namespace" >/dev/null 2>&1
    rm -rf -- "$test_directory"
    exit "$status"
}
trap cleanup EXIT INT TERM

cat >"$test_directory/client.toml" <<'EOF'
[interface]
name = "hwtun-client"
address = "10.77.2.2/30"
listen = "0.0.0.0:0"
transport = "udp"
mtu = 1280
private_key = "CggT/efhwLvXYkiKz1n7ZrMaynmTKsVt3iQgCdQNtwk="

[[peer]]
name = "server"
endpoint = "192.0.2.1:27777"
allowed_ips = ["10.77.2.1/32"]
psk = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
public_key = "Xynrith/BOMMekRk30uyCjhasVMuXPj3cd00dBYujQg="
persistent_keepalive = 1
udp_rebind_after = 3
EOF

cat >"$test_directory/server.toml" <<'EOF'
[interface]
name = "hwtun-server"
address = "10.77.2.1/30"
listen = "0.0.0.0:27777"
transport = "udp"
mtu = 1280
private_key = "+BKKM7yvO+68uCpscwMqDBOhTzs5tc1c/B1TgR9hnsc="

[[peer]]
name = "client"
endpoint = "0.0.0.0:27777"
allowed_ips = ["10.77.2.2/32"]
psk = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
public_key = "fetuos8XUNQuWY6K3bw7D5Qz6Qn9wgqIqHUw5zPEMR0="
persistent_keepalive = 0
udp_rebind_after = 0
EOF

ip netns add "$client_namespace"
ip netns add "$server_namespace"
ip link add "$client_veth" type veth peer name "$server_veth"
ip link set "$client_veth" netns "$client_namespace"
ip link set "$server_veth" netns "$server_namespace"

ip -n "$client_namespace" link set lo up
ip -n "$client_namespace" link set "$client_veth" name eth0
ip -n "$client_namespace" address add 192.0.2.2/24 dev eth0
ip -n "$client_namespace" link set eth0 up

ip -n "$server_namespace" link set lo up
ip -n "$server_namespace" link set "$server_veth" name eth0
ip -n "$server_namespace" address add 192.0.2.1/24 dev eth0
ip -n "$server_namespace" link set eth0 up

start_server() {
    server_generation=$((server_generation + 1))
    ip netns exec "$server_namespace" env RUST_LOG=debug \
        "$binary_path" --log-format text up --config "$test_directory/server.toml" \
        >"$test_directory/server-${server_generation}.log" 2>&1 &
    server_pid=$!
}

wait_for_interface() {
    local namespace=$1
    local interface_name=$2
    local process_id=$3
    local log_path=$4

    for _ in $(seq 1 40); do
        if ! kill -0 "$process_id" >/dev/null 2>&1; then
            echo "HushWire exited while waiting for $interface_name" >&2
            tail -n 80 "$log_path" >&2
            return 1
        fi
        if ip -n "$namespace" link show "$interface_name" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done

    echo "timed out waiting for $interface_name" >&2
    tail -n 80 "$log_path" >&2
    return 1
}

wait_for_ping() {
    local namespace=$1
    local destination=$2

    for _ in $(seq 1 24); do
        if ip netns exec "$namespace" ping -n -c 1 -W 1 "$destination" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done

    echo "timed out waiting for ping to $destination" >&2
    return 1
}

start_server
wait_for_interface \
    "$server_namespace" hwtun-server "$server_pid" "$test_directory/server-1.log"

ip netns exec "$client_namespace" env RUST_LOG=debug \
    "$binary_path" --log-format text up --config "$test_directory/client.toml" \
    >"$test_directory/client.log" 2>&1 &
client_pid=$!
wait_for_interface \
    "$client_namespace" hwtun-client "$client_pid" "$test_directory/client.log"

wait_for_ping "$client_namespace" 10.77.2.1
sleep 2
kill -0 "$client_pid"

# Restart only the responder. The initiator must retain its process and detect
# that the old in-memory session no longer exists on the other side.
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=""
start_server
wait_for_interface \
    "$server_namespace" hwtun-server "$server_pid" "$test_directory/server-2.log"

wait_for_ping "$client_namespace" 10.77.2.1
kill -0 "$client_pid"

grep -q "peer liveness timeout invalidated the old session" "$test_directory/client.log"
grep -q "rebound UDP socket to recover the NAT path" "$test_directory/client.log"
if [[ $(grep -c "handshake completed (initiator)" "$test_directory/client.log") -lt 2 ]]; then
    echo "client did not complete a second initiator handshake" >&2
    exit 1
fi
grep -q "handshake completed (responder)" "$test_directory/server-2.log"

echo "isolated recovery test passed: server restarted, client PID $client_pid survived, ping recovered"
