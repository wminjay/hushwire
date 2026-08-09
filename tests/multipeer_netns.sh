#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <hushwire-binary> <udp|tcp>" >&2
    exit 2
fi

binary_path=$(realpath "$1")
transport=$2
case "$transport" in
    udp)
        client_recovery_config='udp_rebind_after = 3'
        ;;
    tcp)
        client_recovery_config=$'udp_rebind_after = 0\nsession_timeout = 3'
        ;;
    *)
        echo "unsupported transport: $transport" >&2
        exit 2
        ;;
esac

if [[ $(id -u) -ne 0 ]]; then
    echo "multipeer_netns.sh must run as root" >&2
    exit 2
fi

for command_name in ip ping realpath; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "missing required command: $command_name" >&2
        exit 2
    fi
done
if [[ ! -x "$binary_path" ]]; then
    echo "HushWire binary is not executable: $binary_path" >&2
    exit 2
fi

test_directory=$(mktemp -d)
suffix=$$
server_namespace="hw-multi-server-${suffix}"
client_a_namespace="hw-multi-a-${suffix}"
client_b_namespace="hw-multi-b-${suffix}"
server_a_veth="hwsa${suffix}"
client_a_veth="hwca${suffix}"
server_b_veth="hwsb${suffix}"
client_b_veth="hwcb${suffix}"
server_pid=""
client_a_pid=""
client_b_pid=""
server_generation=0

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    set +e

    if [[ $status -ne 0 ]]; then
        echo "--- client A log ---" >&2
        tail -n 120 "$test_directory/client-a.log" >&2 2>/dev/null
        echo "--- client B log ---" >&2
        tail -n 120 "$test_directory/client-b.log" >&2 2>/dev/null
        echo "--- current server log ---" >&2
        tail -n 180 "$test_directory/server-${server_generation}.log" >&2 2>/dev/null
    fi

    for process_id in "$client_a_pid" "$client_b_pid" "$server_pid"; do
        if [[ -n "$process_id" ]]; then
            kill -TERM "$process_id" >/dev/null 2>&1
            wait "$process_id" >/dev/null 2>&1
        fi
    done
    ip netns delete "$client_a_namespace" >/dev/null 2>&1
    ip netns delete "$client_b_namespace" >/dev/null 2>&1
    ip netns delete "$server_namespace" >/dev/null 2>&1
    rm -rf -- "$test_directory"
    exit "$status"
}
trap cleanup EXIT INT TERM

cat >"$test_directory/server.toml" <<EOF
[interface]
name = "hwmulti0"
address = "10.77.60.1/29"
listen = "0.0.0.0:27777"
transport = "$transport"
mtu = 1280
private_key = "+BKKM7yvO+68uCpscwMqDBOhTzs5tc1c/B1TgR9hnsc="

[[peer]]
name = "client-a"
endpoint = "0.0.0.0:0"
allowed_ips = ["10.77.60.2/32"]
psk = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
public_key = "fetuos8XUNQuWY6K3bw7D5Qz6Qn9wgqIqHUw5zPEMR0="
persistent_keepalive = 0

[[peer]]
name = "client-b"
endpoint = "0.0.0.0:0"
allowed_ips = ["10.77.60.3/32"]
psk = "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M="
public_key = "sIuZrGs5Jf2Js48E9Off+lxtawzyt+dOw7axs2If02E="
persistent_keepalive = 0
EOF

cat >"$test_directory/client-a.toml" <<EOF
[interface]
name = "hwmultia"
address = "10.77.60.2/29"
listen = "0.0.0.0:0"
transport = "$transport"
mtu = 1280
private_key = "CggT/efhwLvXYkiKz1n7ZrMaynmTKsVt3iQgCdQNtwk="

[[peer]]
name = "server"
endpoint = "192.0.2.1:27777"
allowed_ips = ["10.77.60.1/32"]
psk = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
public_key = "Xynrith/BOMMekRk30uyCjhasVMuXPj3cd00dBYujQg="
persistent_keepalive = 1
$client_recovery_config
EOF

cat >"$test_directory/client-b.toml" <<EOF
[interface]
name = "hwmultib"
address = "10.77.60.3/29"
listen = "0.0.0.0:0"
transport = "$transport"
mtu = 1280
private_key = "syBkDJG6pPalA2JOB6Z70dK4v/2Pcv9prjOtrXRaIkU="

[[peer]]
name = "server"
endpoint = "198.51.100.1:27777"
allowed_ips = ["10.77.60.1/32"]
psk = "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M="
public_key = "Xynrith/BOMMekRk30uyCjhasVMuXPj3cd00dBYujQg="
persistent_keepalive = 1
$client_recovery_config
EOF

ip netns add "$server_namespace"
ip netns add "$client_a_namespace"
ip netns add "$client_b_namespace"
ip link add "$server_a_veth" type veth peer name "$client_a_veth"
ip link add "$server_b_veth" type veth peer name "$client_b_veth"
ip link set "$server_a_veth" netns "$server_namespace"
ip link set "$server_b_veth" netns "$server_namespace"
ip link set "$client_a_veth" netns "$client_a_namespace"
ip link set "$client_b_veth" netns "$client_b_namespace"

ip -n "$server_namespace" link set lo up
ip -n "$server_namespace" link set "$server_a_veth" name eth-a
ip -n "$server_namespace" link set "$server_b_veth" name eth-b
ip -n "$server_namespace" address add 192.0.2.1/24 dev eth-a
ip -n "$server_namespace" address add 198.51.100.1/24 dev eth-b
ip -n "$server_namespace" link set eth-a up
ip -n "$server_namespace" link set eth-b up

ip -n "$client_a_namespace" link set lo up
ip -n "$client_a_namespace" link set "$client_a_veth" name eth0
ip -n "$client_a_namespace" address add 192.0.2.2/24 dev eth0
ip -n "$client_a_namespace" link set eth0 up

ip -n "$client_b_namespace" link set lo up
ip -n "$client_b_namespace" link set "$client_b_veth" name eth0
ip -n "$client_b_namespace" address add 198.51.100.2/24 dev eth0
ip -n "$client_b_namespace" link set eth0 up

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
    return 1
}

wait_for_ping() {
    local namespace=$1
    local destination=$2
    for _ in $(seq 1 28); do
        if ip netns exec "$namespace" ping -n -c 1 -W 1 "$destination" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    echo "timed out waiting for $namespace to ping $destination" >&2
    return 1
}

start_server
wait_for_interface "$server_namespace" hwmulti0 "$server_pid" "$test_directory/server-1.log"

ip netns exec "$client_a_namespace" env RUST_LOG=debug \
    "$binary_path" --log-format text up --config "$test_directory/client-a.toml" \
    >"$test_directory/client-a.log" 2>&1 &
client_a_pid=$!
ip netns exec "$client_b_namespace" env RUST_LOG=debug \
    "$binary_path" --log-format text up --config "$test_directory/client-b.toml" \
    >"$test_directory/client-b.log" 2>&1 &
client_b_pid=$!
wait_for_interface "$client_a_namespace" hwmultia "$client_a_pid" "$test_directory/client-a.log"
wait_for_interface "$client_b_namespace" hwmultib "$client_b_pid" "$test_directory/client-b.log"

wait_for_ping "$client_a_namespace" 10.77.60.1
wait_for_ping "$client_b_namespace" 10.77.60.1
wait_for_ping "$server_namespace" 10.77.60.2
wait_for_ping "$server_namespace" 10.77.60.3

# Restart only the one multi-peer server. Both original client processes must
# independently discard their stale session and reconnect to that one process.
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=""
start_server
wait_for_interface "$server_namespace" hwmulti0 "$server_pid" "$test_directory/server-2.log"

wait_for_ping "$client_a_namespace" 10.77.60.1
wait_for_ping "$client_b_namespace" 10.77.60.1
wait_for_ping "$server_namespace" 10.77.60.2
wait_for_ping "$server_namespace" 10.77.60.3
kill -0 "$client_a_pid"
kill -0 "$client_b_pid"

if [[ $(grep -c "handshake completed (responder)" "$test_directory/server-2.log") -lt 2 ]]; then
    echo "restarted server did not authenticate both clients" >&2
    exit 1
fi
if [[ $(grep -c "handshake completed (initiator)" "$test_directory/client-a.log") -lt 2 ]]; then
    echo "client A did not recover after the server restart" >&2
    exit 1
fi
if [[ $(grep -c "handshake completed (initiator)" "$test_directory/client-b.log") -lt 2 ]]; then
    echo "client B did not recover after the server restart" >&2
    exit 1
fi

echo "isolated $transport multi-peer test passed: one server process authenticated two clients; both client PIDs survived server restart"
