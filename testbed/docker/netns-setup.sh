#!/usr/bin/env bash
# CryptoLens - Linux Network Namespace Setup for Dual-Peer IPsec Testbed
# Creates isolated namespaces: peer_a (Moon) and peer_b (Sun)

set -euo pipefail

NS_A="peer_a"
NS_B="peer_b"
VETH_A="veth_a"
VETH_B="veth_b"

IP_A="10.10.0.1/24"
IP_B="10.10.0.2/24"

# Internal subnets for Tunnel Mode encapsulation
INNER_IP_A="192.168.1.1/24"
INNER_IP_B="192.168.2.1/24"
INNER_NET_A="192.168.1.0/24"
INNER_NET_B="192.168.2.0/24"

log() {
    echo -e "[netns-setup] $1"
}

setup_netns() {
    log "Tearing down any existing namespaces..."
    teardown_netns || true

    log "Creating namespaces: ${NS_A} and ${NS_B}..."
    ip netns add "${NS_A}"
    ip netns add "${NS_B}"

    log "Bringing up loopback interfaces..."
    ip netns exec "${NS_A}" ip link set lo up
    ip netns exec "${NS_B}" ip link set lo up

    log "Creating veth pair (${VETH_A} <-> ${VETH_B})..."
    ip link add "${VETH_A}" type veth peer name "${VETH_B}"

    log "Moving veth ends into respective namespaces..."
    ip link set "${VETH_A}" netns "${NS_A}"
    ip link set "${VETH_B}" netns "${NS_B}"

    log "Configuring WAN link interfaces..."
    ip netns exec "${NS_A}" ip addr add "${IP_A}" dev "${VETH_A}"
    ip netns exec "${NS_A}" ip link set "${VETH_A}" up

    ip netns exec "${NS_B}" ip addr add "${IP_B}" dev "${VETH_B}"
    ip netns exec "${NS_B}" ip link set "${VETH_B}" up

    log "Configuring internal dummy interfaces for Tunnel Mode..."
    # Dummy interface on Peer A
    ip netns exec "${NS_A}" ip link add dummy0 type dummy
    ip netns exec "${NS_A}" ip addr add "${INNER_IP_A}" dev dummy0
    ip netns exec "${NS_A}" ip link set dummy0 up
    ip netns exec "${NS_A}" ip route add "${INNER_NET_B}" via 10.10.0.2 dev "${VETH_A}"

    # Dummy interface on Peer B
    ip netns exec "${NS_B}" ip link add dummy0 type dummy
    ip netns exec "${NS_B}" ip addr add "${INNER_IP_B}" dev dummy0
    ip netns exec "${NS_B}" ip link set dummy0 up
    ip netns exec "${NS_B}" ip route add "${INNER_NET_A}" via 10.10.0.1 dev "${VETH_B}"

    log "Enabling IP forwarding and tuning sysctl..."
    ip netns exec "${NS_A}" sysctl -q -w net.ipv4.ip_forward=1
    ip netns exec "${NS_B}" sysctl -q -w net.ipv4.ip_forward=1

    # Disable rp_filter to prevent reverse path filtering issues on encrypted/tunneled packets
    ip netns exec "${NS_A}" sysctl -q -w net.ipv4.conf.all.rp_filter=0
    ip netns exec "${NS_A}" sysctl -q -w net.ipv4.conf.default.rp_filter=0
    ip netns exec "${NS_A}" sysctl -q -w net.ipv4.conf.${VETH_A}.rp_filter=0

    ip netns exec "${NS_B}" sysctl -q -w net.ipv4.conf.all.rp_filter=0
    ip netns exec "${NS_B}" sysctl -q -w net.ipv4.conf.default.rp_filter=0
    ip netns exec "${NS_B}" sysctl -q -w net.ipv4.conf.${VETH_B}.rp_filter=0

    log "Setting up isolated mount namespaces for per-peer /var/run..."
    mkdir -p /run/netns_mnt
    touch /run/netns_mnt/${NS_A} /run/netns_mnt/${NS_B}
    unshare --mount=/run/netns_mnt/${NS_A} bash -c 'mount -t tmpfs none /var/run'
    unshare --mount=/run/netns_mnt/${NS_B} bash -c 'mount -t tmpfs none /var/run'

    log "Namespace setup complete!"
}

teardown_netns() {
    log "Cleaning up namespaces ${NS_A} and ${NS_B}..."
    umount /run/netns_mnt/${NS_A} 2>/dev/null || true
    umount /run/netns_mnt/${NS_B} 2>/dev/null || true
    rm -rf /run/netns_mnt 2>/dev/null || true

    if ip netns list | grep -q "${NS_A}"; then
        ip netns del "${NS_A}" || true
    fi
    if ip netns list | grep -q "${NS_B}"; then
        ip netns del "${NS_B}" || true
    fi
    log "Cleanup complete."
}

check_connectivity() {
    log "Testing basic connectivity between namespaces..."
    if ip netns exec "${NS_A}" ping -c 2 -W 1 10.10.0.2 >/dev/null 2>&1; then
        log "SUCCESS: Ping from ${NS_A} to ${NS_B} (10.10.0.2) succeeded!"
    else
        log "ERROR: Ping from ${NS_A} to ${NS_B} (10.10.0.2) failed!"
        return 1
    fi
}

status_netns() {
    echo "=== Network Namespaces ==="
    ip netns list
    echo ""
    echo "=== ${NS_A} Interfaces ==="
    ip netns exec "${NS_A}" ip addr show
    echo ""
    echo "=== ${NS_B} Interfaces ==="
    ip netns exec "${NS_B}" ip addr show
}

case "${1:-setup}" in
    setup)
        setup_netns
        check_connectivity
        ;;
    teardown|cleanup)
        teardown_netns
        ;;
    check)
        check_connectivity
        ;;
    status)
        status_netns
        ;;
    *)
        echo "Usage: $0 {setup|teardown|check|status}"
        exit 1
        ;;
esac
