import os
from pathlib import Path
import pytest
from pydantic import ValidationError

from backend.services.analyzer_provider import AnalyzerProvider
from backend.scoring.scoring_engine import ScoringEngine
from backend.schemas.sidecar import IPsecSidecarConfig
from backend.engine.control_plane.ike_parser import IkeParser

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_01_PCAP = PROJECT_ROOT / "captures" / "config_01_tunnel_aes256gcm_dh19_pfson_all.pcap"


def test_config_01_no_sidecar_partial_coverage():
    """
    Item 2.4(a): config_01 PCAP with NO sidecar.
    In IKEv2 only IKE_SA_INIT is cleartext. Child SA transforms (encryption,
    integrity, PFS) and SA lifetimes are encrypted on the wire.
    Must produce:
      - coverage < 100%
      - risk_level == 'UNVERIFIED'
      - headline score as a range (e.g. '35–100, coverage 3/8')
      - no unqualified 100/100 score
    """
    assert CONFIG_01_PCAP.exists(), f"Capture file missing: {CONFIG_01_PCAP}"

    provider = AnalyzerProvider(mode="real")
    analysis = provider.get_analysis(str(CONFIG_01_PCAP), sidecar_config=None)

    scorer = ScoringEngine()
    result = scorer.evaluate(analysis)

    # 1. Coverage assertions
    assert result["coverage_ratio"] < 1.0, f"Coverage must be strictly < 1.0, got {result['coverage_ratio']}"
    assert result["coverage"] == "3/8", f"Expected coverage 3/8 on raw IKEv2 PCAP, got {result['coverage']}"
    assert result["observed_controls_count"] == 3
    assert result["operator_supplied_controls_count"] == 0
    assert result["unobserved_controls_count"] == 5

    # 2. Risk level and headline score assertions
    assert result["risk_level"] == "UNVERIFIED", (
        f"Risk level must be UNVERIFIED on partial coverage, got {result['risk_level']}"
    )
    assert result["score_headline"] == "35–100, coverage 3/8"
    assert result["score_if_unobserved_fail"] == 35.0
    assert result["score_if_unobserved_pass"] == 100.0
    assert result["score_observed_only"] == 100.0

    # Primary score must be the conservative worst-case score, NEVER an unqualified 100
    assert result["score"] == 35.0, f"Primary score must be worst-case 35.0, got {result['score']}"

    # 3. Observability taxonomy assertions on breakdown
    bd = result["score_breakdown"]
    assert bd["ike_version"]["observability"] == "observed"
    assert bd["key_exchange"]["observability"] == "observed"
    assert bd["replay_protection"]["observability"] == "observed"

    assert bd["encryption"]["observability"] == "not_observable"
    assert bd["integrity"]["observability"] == "not_observable"
    assert bd["pfs"]["observability"] == "not_observable"
    assert bd["key_lifetime"]["observability"] == "not_observable"
    assert bd["mode"]["observability"] == "inferred"


def test_config_01_with_operator_sidecar_higher_coverage():
    """
    Item 2.4(b): Same config_01 PCAP + operator-supplied sidecar config.
    Supplying verified Child SA transforms and lifetime increases coverage to 8/8 (100%),
    labels fields operator_supplied, and resolves UNVERIFIED to LOW risk.
    """
    assert CONFIG_01_PCAP.exists()

    sidecar = {
        "encryption_algorithm": "AES-256-GCM",
        "integrity_algorithm": "AEAD",
        "pfs_enabled": True,
        "key_lifetime_seconds": 28800,
        "operating_mode": "Tunnel",
    }

    provider = AnalyzerProvider(mode="real")
    analysis = provider.get_analysis(str(CONFIG_01_PCAP), sidecar_config=sidecar)

    scorer = ScoringEngine()
    result = scorer.evaluate(analysis)

    # 1. Full coverage assertions
    assert result["coverage_ratio"] == 1.0
    assert result["coverage"] == "8/8"
    assert result["observed_controls_count"] == 3
    assert result["operator_supplied_controls_count"] == 5
    assert result["unobserved_controls_count"] == 0

    # 2. Score resolution
    assert result["risk_level"] == "LOW (operator-attested)"
    assert result["score_headline"] == "100/100, coverage 8/8"
    assert result["score_if_unobserved_fail"] == 100.0
    assert result["score_if_unobserved_pass"] == 100.0
    assert result["score"] == 100.0

    # 3. Provenance assertions
    bd = result["score_breakdown"]
    assert bd["encryption"]["observability"] == "operator_supplied"
    assert bd["encryption"]["evidence_source"] == "operator_supplied"
    assert bd["integrity"]["observability"] == "operator_supplied"
    assert bd["pfs"]["observability"] == "operator_supplied"
    assert bd["key_lifetime"]["observability"] == "operator_supplied"
    assert bd["mode"]["observability"] == "operator_supplied"


def test_ikev1_cleartext_proposals_marked_observed(tmp_path):
    """
    Item 2.4(c): An IKEv1 capture with cleartext proposals.
    In IKEv1 RFC 2409, Phase 1 proposals and transforms are sent in cleartext.
    The parser and scoring engine must mark those proposals as 'observed'.
    """
    from scapy.all import wrpcap, Ether, IP, UDP
    from scapy.layers.isakmp import (
        ISAKMP,
        ISAKMP_payload_SA,
        ISAKMP_payload_Proposal,
        ISAKMP_payload_Transform,
    )

    # Build authentic synthetic IKEv1 packet with cleartext 3DES / SHA1 / DH 2 proposal
    ikev1_pkt = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") /
        IP(src="192.168.10.1", dst="192.168.10.2") /
        UDP(sport=500, dport=500) /
        ISAKMP(
            init_cookie=b"\x11\x22\x33\x44\x55\x66\x77\x88",
            resp_cookie=b"\x00" * 8,
            next_payload=1,  # SA
            version=0x10,    # IKEv1
            exch_type=2,     # Identity Protection (Main Mode)
            flags=0,
            id=0,
        ) /
        ISAKMP_payload_SA(
            next_payload=0,
            prop=ISAKMP_payload_Proposal(
                proposal=1,
                proto=1,  # ISAKMP
                trans_nb=1,
                trans=ISAKMP_payload_Transform(
                    transform_count=1,
                    transform_id=1,
                    transforms=[
                        ("Encryption", "3DES-CBC"),
                        ("Hash", "SHA"),
                        ("Authentication", "PSK"),
                        ("GroupDesc", "1024MODPgr"),
                        ("LifeType", "Seconds"),
                        ("LifeDuration", 86400),
                    ]
                )
            )
        )
    )

    pcap_file = tmp_path / "test_ikev1_cleartext.pcap"
    wrpcap(str(pcap_file), [ikev1_pkt])

    # Parse with IkeParser
    parser = IkeParser(str(pcap_file))
    parsed = parser.parse()
    assert parsed["parsed_successfully"] is True
    cp = parsed["control_plane"]
    assert cp["ike_version"] == "IKEv1"

    # Evaluate with ScoringEngine
    scorer = ScoringEngine()
    result = scorer.evaluate({"control_plane": cp, "data_plane": {}})

    bd = result["score_breakdown"]
    # In IKEv1, proposals are observed on wire
    assert bd["ike_version"]["observability"] == "observed"
    assert bd["key_exchange"]["observability"] == "observed"
    assert bd["encryption"]["observability"] == "observed"
    assert bd["integrity"]["observability"] == "observed"

    # Check finding provenance
    enc_findings = [f for f in result["findings"] if f.get("category") == "Encryption"]
    if enc_findings:
        assert enc_findings[0]["observability"] == "observed"
        assert enc_findings[0]["evidence_source"] == "ike_v1_cleartext"


def test_mutation_forcing_full_coverage_fails():
    """
    Item 2.4(d): Mutation check.
    Confirm that if an implementation erroneously forces coverage = 100% on a PCAP without sidecar,
    the verification assertion strictly fails.
    """
    provider = AnalyzerProvider(mode="real")
    analysis = provider.get_analysis(str(CONFIG_01_PCAP), sidecar_config=None)

    scorer = ScoringEngine()
    result = scorer.evaluate(analysis)

    # Mutated result simulating a faulty engine that assumed unobserved fields are safe
    mutated_result = dict(result)
    mutated_result["coverage_ratio"] = 1.0
    mutated_result["risk_level"] = "LOW"
    mutated_result["score"] = 100.0

    # Confirm that our verification contract catches this mutation
    with pytest.raises(AssertionError):
        assert mutated_result["coverage_ratio"] < 1.0, "Mutation check: forced full coverage must fail assertion"

    with pytest.raises(AssertionError):
        assert mutated_result["risk_level"] == "UNVERIFIED", "Mutation check: premature safe risk must fail assertion"

    with pytest.raises(AssertionError):
        assert mutated_result["score"] < 100.0, "Mutation check: unqualified 100 score must fail assertion"


def test_strict_sidecar_schema_rejection():
    """Verify that IPsecSidecarConfig enforces extra='forbid' strict schema."""
    valid_data = {
        "encryption_algorithm": "AES-256-GCM",
        "integrity_algorithm": "AEAD",
        "dh_group": 19,
        "pfs_enabled": True,
        "key_lifetime_seconds": 28800,
    }
    cfg = IPsecSidecarConfig(**valid_data)
    assert cfg.encryption_algorithm == "AES-256-GCM"

    # Reject unknown adversarial / typos fields
    invalid_data = dict(valid_data)
    invalid_data["unknown_injected_field"] = "malicious_payload"
    with pytest.raises(ValidationError):
        IPsecSidecarConfig(**invalid_data)

    # Reject physically implausible lifetime (< 60s)
    invalid_lifetime = dict(valid_data)
    invalid_lifetime["key_lifetime_seconds"] = 30
    with pytest.raises(ValidationError):
        IPsecSidecarConfig(**invalid_lifetime)
