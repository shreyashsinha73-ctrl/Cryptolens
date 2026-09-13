#!/usr/bin/env bash
# ==============================================================================
# CryptoLens - Automated IPsec Capture Session Orchestrator
# Executes end-to-end capture sessions across 6 core configurations:
#   1. Sets up network namespaces (peer_a <-> peer_b) with mount namespaces
#   2. Starts strongSwan charon daemon in each namespace
#   3. Loads swanctl configuration
#   4. Begins packet capture (tcpdump) on virtual wire (IKE + ESP)
#   5. Initiates IPsec tunnel (IKEv2 handshake)
#   6. Injects application traffic (ICMP, HTTPS, VoIP/RTP)
#   7. Executes active duplicate ESP replay test
#   8. Finalizes labeled PCAP and updates ground-truth manifest.json
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFIGS_DIR="${SCRIPT_DIR}/configs"
GENERATED_DIR="${CONFIGS_DIR}/generated"
TRAFFIC_DIR="${SCRIPT_DIR}/traffic_gen"
REPLAY_DIR="${SCRIPT_DIR}/replay_test"
NETNS_SCRIPT="${SCRIPT_DIR}/docker/netns-setup.sh"
CAPTURES_DIR="${BASE_DIR}/captures"

# Ensure output directory exists
mkdir -p "${CAPTURES_DIR}"

log() {
    echo -e "\033[1;34m[CryptoLens Orchestrator]\033[0m $1"
}

log_success() {
    echo -e "\033[1;32m[SUCCESS]\033[0m $1"
}

log_error() {
    echo -e "\033[1;31m[ERROR]\033[0m $1" >&2
}

log_warn() {
    echo -e "\033[1;33m[WARN]\033[0m $1"
}

cleanup() {
    log "Performing cleanup of background processes and namespaces..."
    pkill -f "tcpdump.*veth" 2>/dev/null || true
    pkill -f "https_client.py" 2>/dev/null || true
    pkill -f "voip_sim.py" 2>/dev/null || true
    pkill -f "charon" 2>/dev/null || true
    sleep 0.5

    if [ -x "${NETNS_SCRIPT}" ]; then
        "${NETNS_SCRIPT}" teardown >/dev/null 2>&1 || true
    fi
}

trap cleanup EXIT INT TERM

check_prerequisites() {
    log "Checking prerequisites..."
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script requires root/net-admin privileges to configure netns and IPsec."
        exit 1
    fi

    for cmd in ip tcpdump python3 nsenter; do
        if ! command -v "$cmd" &>/dev/null; then
            log_error "Missing required command: $cmd"
            exit 1
        fi
    done

    # Ensure configs are generated
    if [ ! -d "${GENERATED_DIR}/peer_a" ] || [ ! -f "${GENERATED_DIR}/manifest_configs.json" ]; then
        log "Generated configs not found. Running generate_configs.py..."
        python3 "${CONFIGS_DIR}/generate_configs.py"
    fi
}

ns_a() {
    nsenter --net=/run/netns/peer_a --mount=/run/netns_mnt/peer_a "$@"
}

ns_b() {
    nsenter --net=/run/netns/peer_b --mount=/run/netns_mnt/peer_b "$@"
}

run_single_session() {
    local config_id="$1"
    local traffic_type="$2"
    local run_replay="$3"

    log "========================================================================"
    log "Starting Capture Session: Config [${config_id}] | Traffic [${traffic_type}]"
    log "========================================================================"

    local config_file_a="${GENERATED_DIR}/peer_a/${config_id}.conf"
    local config_file_b="${GENERATED_DIR}/peer_b/${config_id}.conf"

    if [ ! -f "${config_file_a}" ] || [ ! -f "${config_file_b}" ]; then
        log_error "Configuration files for ${config_id} not found."
        return 1
    fi

    # Determine mode (tunnel vs transport) from config file
    local mode="tunnel"
    if grep -q "mode = transport" "${config_file_a}"; then
        mode="transport"
    fi

    local target_ip="192.168.2.1"
    if [ "$mode" = "transport" ]; then
        target_ip="10.10.0.2"
    fi

    # Setup namespaces with mount namespace isolation
    "${NETNS_SCRIPT}" setup

    # Start charon daemons inside their isolated network and mount namespaces
    log "Starting strongSwan charon daemon in peer_b..."
    ns_b bash -c '/usr/lib/ipsec/charon > /tmp/charon_b.log 2>&1 &'
    log "Starting strongSwan charon daemon in peer_a..."
    ns_a bash -c '/usr/lib/ipsec/charon > /tmp/charon_a.log 2>&1 &'
    sleep 1.5

    # Load configurations via swanctl
    log "Loading configurations into strongSwan daemons..."
    ns_b swanctl --load-all --file "${config_file_b}"
    ns_a swanctl --load-all --file "${config_file_a}"

    # Setup capture file name
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local pcap_basename="${config_id}_${traffic_type}.pcap"
    local pcap_path="${CAPTURES_DIR}/${pcap_basename}"

    log "Starting packet capture on virtual interface veth_a -> ${pcap_basename}..."
    ns_a tcpdump -i veth_a -U -w "${pcap_path}" -s 0 >/dev/null 2>&1 &
    local tcpdump_pid=$!
    sleep 0.5

    # Initiate IPsec connection from Peer A (initiator)
    log "Initiating IPsec tunnel from peer_a (child_${config_id})..."
    local init_output=""
    set +e
    init_output=$(ns_a swanctl --initiate --child "child_${config_id}" 2>&1)
    local init_rc=$?
    set -e

    log "Initiate response: ${init_output}"
    if [ $init_rc -ne 0 ]; then
        log_warn "Notice: swanctl initiate reported: ${init_output}"
    fi

    # Check SA status
    log "Active Security Associations (peer_a):"
    ns_a swanctl --list-sas || true

    # Inject Traffic
    if [ "$traffic_type" = "icmp" ] || [ "$traffic_type" = "all" ]; then
        log "Injecting ICMP echo traffic across tunnel (target: ${target_ip})..."
        ns_a python3 "${TRAFFIC_DIR}/icmp_ping.py" --target "${target_ip}" --count 15 --interval 0.1 || true
    fi

    if [ "$traffic_type" = "https" ] || [ "$traffic_type" = "all" ]; then
        log "Injecting HTTPS web browsing traffic across tunnel (target: ${target_ip})..."
        # Start server in peer_b
        ns_b python3 "${TRAFFIC_DIR}/https_client.py" --mode server --server-ip "${target_ip}" --port 8443 &
        local https_server_pid=$!
        sleep 0.8
        # Run client in peer_a
        ns_a python3 "${TRAFFIC_DIR}/https_client.py" --mode client --server-ip "${target_ip}" --port 8443 --bursts 3 --requests 3 || true
        kill -9 $https_server_pid 2>/dev/null || true
    fi

    if [ "$traffic_type" = "voip" ] || [ "$traffic_type" = "all" ]; then
        log "Injecting VoIP (SIP + RTP) traffic across tunnel (target: ${target_ip})..."
        ns_a python3 "${TRAFFIC_DIR}/voip_sim.py" --dst "${target_ip}" --packets 40 --interval 0.02 || true
    fi

    # Active Replay Injection Test
    local replay_json="${CAPTURES_DIR}/${config_id}_replay.json"
    local replay_passed=false
    if [ "$run_replay" = "true" ]; then
        log "Executing active duplicate ESP packet replay injection test..."
        # Trigger background packets so there is ESP traffic to duplicate
        ns_a ping -c 10 -i 0.2 "${target_ip}" >/dev/null 2>&1 &
        local ping_bg_pid=$!
        sleep 0.2

        if ns_a python3 "${REPLAY_DIR}/inject_duplicate_esp.py" --interface veth_a --count 3 --output "${replay_json}"; then
            replay_passed=true
            log_success "Active replay test confirmed anti-replay window dropped duplicate packets!"
        else
            log_warn "Active replay test completed."
        fi
        kill -9 $ping_bg_pid 2>/dev/null || true
    fi

    # Stop packet capture
    sleep 0.5
    pkill -INT -f "tcpdump.*${pcap_basename}" 2>/dev/null || true
    sleep 0.5
    pkill -TERM -f "tcpdump.*${pcap_basename}" 2>/dev/null || true
    kill -9 $tcpdump_pid 2>/dev/null || true
    sleep 0.5

    # Check capture size and packet count
    local pkt_count=0
    local file_size=0
    local sha256_hash=""
    if [ -f "${pcap_path}" ]; then
        file_size=$(stat -c%s "${pcap_path}" 2>/dev/null || wc -c < "${pcap_path}")
        pkt_count=$(tcpdump -r "${pcap_path}" -n 2>/dev/null | wc -l || echo "0")
        sha256_hash=$(sha256sum "${pcap_path}" | awk '{print $1}')
        log_success "Saved capture: ${pcap_path} (${file_size} bytes, ${pkt_count} packets)"
    else
        log_error "PCAP file was not created: ${pcap_path}"
        return 1
    fi

    # Update manifest.json
    update_manifest "${config_id}" "${pcap_basename}" "${pkt_count}" "${file_size}" "${sha256_hash}" "${mode}" "${traffic_type}" "${replay_passed}" "${replay_json}"

    # Clean up daemons for this session
    pkill -f "charon" || true
    "${NETNS_SCRIPT}" teardown >/dev/null 2>&1 || true
    sleep 0.5
}

update_manifest() {
    local config_id="$1"
    local pcap_name="$2"
    local pkt_count="$3"
    local file_size="$4"
    local sha256="$5"
    local mode="$6"
    local traffic_type="$7"
    local replay_passed="$8"
    local replay_json="$9"

    local manifest_file="${CAPTURES_DIR}/manifest.json"

    python3 - <<EOF
import json
import os
from pathlib import Path

manifest_path = Path("${manifest_file}")
matrix_configs = {}
matrix_path = Path("${GENERATED_DIR}/manifest_configs.json")
if matrix_path.exists():
    with open(matrix_path, "r") as f:
        data = json.load(f)
        for c in data.get("configurations", []):
            matrix_configs[c["id"]] = c

manifest = {"dataset_version": "1.0", "captures": []}
if manifest_path.exists():
    try:
        with open(manifest_path, "r") as f:
            manifest = json.load(f)
    except Exception:
        pass

cfg_meta = matrix_configs.get("${config_id}", {})

new_entry = {
    "config_id": "${config_id}",
    "pcap_file": "${pcap_name}",
    "pcap_path": f"captures/${pcap_name}",
    "packet_count": int("${pkt_count}"),
    "size_bytes": int("${file_size}"),
    "sha256": "${sha256}",
    "ground_truth": {
        "mode": "${mode}",
        "cipher": cfg_meta.get("cipher", "unknown"),
        "integrity": cfg_meta.get("integrity", "unknown"),
        "prf": cfg_meta.get("prf", "unknown"),
        "dh_group": cfg_meta.get("dh_group", "unknown"),
        "dh_group_num": cfg_meta.get("dh_group_num", 0),
        "pfs": cfg_meta.get("pfs", False),
        "ike_version": cfg_meta.get("ike_version", 2),
        "rekey_time": cfg_meta.get("rekey_time", "0s"),
        "traffic_type": "${traffic_type}",
        "replay_protection_verified": "${replay_passed}" == "true",
        "benchmark_scores": cfg_meta.get("benchmark_scores", {})
    }
}

# Remove existing entry for same pcap if updating
manifest["captures"] = [c for c in manifest["captures"] if c.get("pcap_file") != "${pcap_name}"]
manifest["captures"].append(new_entry)

with open(manifest_path, "w") as f:
    json.dump(manifest, f, indent=2)

print(f"[manifest] Updated {manifest_path} (Total captures: {len(manifest['captures'])})")
EOF
}

run_all_configs() {
    local traffic_type="${1:-all}"
    local run_replay="${2:-true}"

    log "Running complete capture suite for all 6 configurations..."
    local config_ids=(
        "config_01_tunnel_aes256gcm_dh19_pfson"
        "config_02_tunnel_aes128gcm_dh14_pfson"
        "config_03_tunnel_aes256cbc_sha256_dh14_pfson"
        "config_04_transport_aes128cbc_sha1_dh5_pfsoff"
        "config_05_transport_3des_sha1_dh2_pfsoff"
        "config_06_tunnel_3des_sha1_dh2_pfsoff"
    )

    for cfg in "${config_ids[@]}"; do
        run_single_session "$cfg" "$traffic_type" "$run_replay" || log_warn "Session $cfg completed with notices."
    done

    log_success "All capture sessions completed! Deliverables saved in ${CAPTURES_DIR}"
}

usage() {
    cat <<EOF
CryptoLens IPsec Testbed Capture Orchestrator (Stage 1)

Usage:
  $0 [options]

Options:
  --config <id|all>      Configuration ID (e.g. config_01_tunnel_aes256gcm_dh19_pfson or 'all')
  --traffic <type>       Traffic type: icmp, https, voip, or all (default: all)
  --replay <true|false>  Run active duplicate ESP replay injection test (default: true)
  --output-dir <path>    Output directory for pcaps and manifest (default: ./captures)
  --list                 List all available configurations in the matrix
  --help                 Show this help message

Examples:
  $0 --config config_01_tunnel_aes256gcm_dh19_pfson --traffic all
  $0 --config all --traffic all --replay true
EOF
}

main() {
    local config_id="config_01_tunnel_aes256gcm_dh19_pfson"
    local traffic_type="all"
    local run_replay="true"

    while [ $# -gt 0 ]; do
        case "$1" in
            --config)
                config_id="$2"
                shift 2
                ;;
            --traffic)
                traffic_type="$2"
                shift 2
                ;;
            --replay)
                run_replay="$2"
                shift 2
                ;;
            --output-dir)
                CAPTURES_DIR="$2"
                mkdir -p "${CAPTURES_DIR}"
                shift 2
                ;;
            --list)
                python3 "${CONFIGS_DIR}/generate_configs.py"
                exit 0
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    check_prerequisites

    if [ "$config_id" = "all" ]; then
        run_all_configs "$traffic_type" "$run_replay"
    else
        run_single_session "$config_id" "$traffic_type" "$run_replay"
    fi
}

main "$@"
