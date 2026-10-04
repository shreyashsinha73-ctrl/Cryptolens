#!/usr/bin/env python3
"""
Pre-warm the AI Explainer cache for all six demo capture configurations.
Generates and caches deterministic standard-compliant explanations so that
demo audits execute with zero runtime HTTP calls.
"""

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.services.analyzer_provider import AnalyzerProvider
from backend.scoring.scoring_engine import ScoringEngine
from backend.remediation.remediation_engine import HardenedIPsecConfig
from backend.remediation.ai_explainer import (
    AICache,
    AIExplainer,
    generate_template_explanations,
    redact_findings_and_params,
)

CAPTURES_DIR = PROJECT_ROOT / "captures"

DEMO_PCAPS = [
    "config_01_tunnel_aes256gcm_dh19_pfson_all.pcap",
    "config_02_tunnel_aes128gcm_dh14_pfson_all.pcap",
    "config_03_tunnel_aes256cbc_sha256_dh14_pfson_all.pcap",
    "config_04_transport_aes128cbc_sha1_dh5_pfsoff_all.pcap",
    "config_05_transport_3des_sha1_dh2_pfsoff_all.pcap",
    "config_06_tunnel_3des_sha1_dh2_pfsoff_all.pcap",
]


def prewarm_cache():
    cache = AICache()
    provider = AnalyzerProvider(mode="real")
    scorer = ScoringEngine()

    print("[*] Pre-warming AI Explainer Cache for all 6 demo captures...")
    timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Hardened params baseline
    hardened_params = {
        "ike_version": 2,
        "encryption": "aes256gcm16",
        "integrity": "",
        "dh_group": "ecp384",
        "prf": "prfsha384",
        "pfs_enabled": True,
        "rekey_time": "3600s",
        "replay_window": 64,
    }

    providers_and_models = [
        ("gemini", "gemini-3.8-flash"),
        ("gemini", "gemini-2.5-flash"),
        ("openai_compat", "gpt-4o-mini"),
    ]

    total_cached = 0

    for pcap_name in DEMO_PCAPS:
        pcap_path = CAPTURES_DIR / pcap_name
        if not pcap_path.exists():
            print(f"[-] PCAP {pcap_name} not found, skipping...")
            continue

        analysis = provider.get_analysis(str(pcap_path))
        score_res = scorer.evaluate(analysis)
        findings = score_res.get("findings", [])

        redacted = redact_findings_and_params(findings, hardened_params)
        template_output = generate_template_explanations(
            redacted["redacted_findings"],
            redacted["hardened_params"],
        )

        output_dict = {
            "executive_summary": template_output.executive_summary,
            "findings_explanations": [f.model_dump() for f in template_output.findings],
            "cached_at": timestamp_str,
        }

        for prov, mod in providers_and_models:
            cache_key = cache.make_key(prov, mod, redacted)
            cache.set(cache_key, output_dict)
            total_cached += 1

        print(f"[+] Pre-warmed cache for: {pcap_name} ({len(findings)} findings)")

    print(f"[*] Successfully pre-warmed {total_cached} cache entries in {cache.cache_file}")


if __name__ == "__main__":
    prewarm_cache()
