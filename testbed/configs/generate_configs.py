#!/usr/bin/env python3
"""
CryptoLens - IPsec Configuration Generator
Renders strongSwan swanctl configuration files from config_matrix.yaml using template.swanctl.conf.j2.
Produces ready-to-load configurations for both Peer A and Peer B.
"""

import os
import sys
import json
import yaml
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent
CONFIG_MATRIX_PATH = SCRIPT_DIR / "config_matrix.yaml"
TEMPLATE_PATH = SCRIPT_DIR / "template.swanctl.conf.j2"
OUTPUT_DIR = SCRIPT_DIR / "generated"

def load_matrix(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Matrix file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def generate_configs(matrix: dict, out_dir: Path) -> dict:
    jinja_env = Environment(
        loader=FileSystemLoader(str(SCRIPT_DIR)),
        trim_blocks=True,
        lstrip_blocks=True
    )
    template = jinja_env.get_template(TEMPLATE_PATH.name)

    net = matrix.get("network", {})
    peer_a_net = net.get("peer_a", {})
    peer_b_net = net.get("peer_b", {})
    psk = net.get("psk", "CryptoLens_SIH2026_GroundTruthKey!")

    peer_a_dir = out_dir / "peer_a"
    peer_b_dir = out_dir / "peer_b"
    peer_a_dir.mkdir(parents=True, exist_ok=True)
    peer_b_dir.mkdir(parents=True, exist_ok=True)

    generated_manifest = {
        "version": matrix.get("schema_version", "1.0"),
        "total_configs": len(matrix.get("configurations", [])),
        "configurations": []
    }

    for cfg in matrix.get("configurations", []):
        cfg_id = cfg["id"]
        mode = cfg["mode"]
        rekey_time = cfg.get("rekey_time", "0s")

        # Traffic selectors based on mode
        if mode == "tunnel":
            a_local_ts = peer_a_net.get("inner_subnet", "192.168.1.0/24")
            a_remote_ts = peer_b_net.get("inner_subnet", "192.168.2.0/24")
            b_local_ts = peer_b_net.get("inner_subnet", "192.168.2.0/24")
            b_remote_ts = peer_a_net.get("inner_subnet", "192.168.1.0/24")
        else: # transport
            a_local_ts = f"{peer_a_net.get('wan_ip', '10.10.0.1')}/32"
            a_remote_ts = f"{peer_b_net.get('wan_ip', '10.10.0.2')}/32"
            b_local_ts = f"{peer_b_net.get('wan_ip', '10.10.0.2')}/32"
            b_remote_ts = f"{peer_a_net.get('wan_ip', '10.10.0.1')}/32"

        # Peer A context (Initiator)
        context_a = {
            "conn_name": cfg_id,
            "child_name": f"child_{cfg_id}",
            "local_ip": peer_a_net.get("wan_ip", "10.10.0.1"),
            "remote_ip": peer_b_net.get("wan_ip", "10.10.0.2"),
            "local_id": f"peer_a@{cfg_id}.cryptolens.local",
            "remote_id": f"peer_b@{cfg_id}.cryptolens.local",
            "mode": mode,
            "local_ts": a_local_ts,
            "remote_ts": a_remote_ts,
            "ike_version": cfg.get("ike_version", 2),
            "ike_proposals": cfg["ike_proposals"],
            "esp_proposals": cfg["esp_proposals"],
            "rekey_time": rekey_time,
            "psk": psk
        }

        # Peer B context (Responder)
        context_b = {
            "conn_name": cfg_id,
            "child_name": f"child_{cfg_id}",
            "local_ip": peer_b_net.get("wan_ip", "10.10.0.2"),
            "remote_ip": peer_a_net.get("wan_ip", "10.10.0.1"),
            "local_id": f"peer_b@{cfg_id}.cryptolens.local",
            "remote_id": f"peer_a@{cfg_id}.cryptolens.local",
            "mode": mode,
            "local_ts": b_local_ts,
            "remote_ts": b_remote_ts,
            "ike_version": cfg.get("ike_version", 2),
            "ike_proposals": cfg["ike_proposals"],
            "esp_proposals": cfg["esp_proposals"],
            "rekey_time": rekey_time,
            "psk": psk
        }

        file_a = peer_a_dir / f"{cfg_id}.conf"
        file_b = peer_b_dir / f"{cfg_id}.conf"

        with open(file_a, "w", encoding="utf-8") as f:
            f.write(template.render(context_a))
        with open(file_b, "w", encoding="utf-8") as f:
            f.write(template.render(context_b))

        cfg_entry = {
            "id": cfg_id,
            "name": cfg.get("name"),
            "mode": mode,
            "cipher": cfg.get("cipher"),
            "integrity": cfg.get("integrity"),
            "prf": cfg.get("prf"),
            "dh_group": cfg.get("dh_group"),
            "dh_group_num": cfg.get("dh_group_num"),
            "pfs": cfg.get("pfs"),
            "ike_version": cfg.get("ike_version", 2),
            "rekey_time": rekey_time,
            "config_file_peer_a": str(file_a.relative_to(SCRIPT_DIR)),
            "config_file_peer_b": str(file_b.relative_to(SCRIPT_DIR)),
            "benchmark_scores": cfg.get("benchmark_scores", {})
        }
        generated_manifest["configurations"].append(cfg_entry)

    manifest_file = out_dir / "manifest_configs.json"
    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(generated_manifest, f, indent=2)

    return generated_manifest

def main():
    print(f"[generate_configs] Loading configuration matrix from: {CONFIG_MATRIX_PATH}")
    matrix = load_matrix(CONFIG_MATRIX_PATH)
    print(f"[generate_configs] Generating swanctl configurations in: {OUTPUT_DIR}")
    manifest = generate_configs(matrix, OUTPUT_DIR)
    print(f"[generate_configs] Successfully generated {manifest['total_configs']} configurations!")
    for cfg in manifest["configurations"]:
        print(f"  - [{cfg['mode'].upper()}] {cfg['id']}: {cfg['name']}")

if __name__ == "__main__":
    main()
