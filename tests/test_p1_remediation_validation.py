import json
from pathlib import Path
import pytest
from unittest.mock import patch, MagicMock

from backend.remediation.remediation_engine import (
    RemediationEngine,
    HardenedIPsecConfig,
    validate_swanctl_syntax,
    APPROVED_DH_GROUPS,
    AEAD_CIPHERS,
)


@pytest.mark.skip(reason="LLM config generation removed; explanation path covered in tests/test_ai_explainer.py")
def test_hostile_llm_cbc_without_hmac_rejected():
    """Verify that CBC mode ciphers without HMAC integrity are strictly rejected."""
    engine = RemediationEngine()

    hostile_output = {
        "response": json.dumps({
            "ike_version": 2,
            "encryption": "aes256",  # CBC
            "integrity": "",         # Missing HMAC!
            "dh_group": "ecp384",
            "prf": "prfsha384",
            "pfs_enabled": True,
            "rekey_time": "3600s",
            "replay_window": 64,
            "local_subnet": "192.168.1.0/24",
            "remote_subnet": "192.168.2.0/24",
            "local_id": "moon",
            "remote_id": "sun",
        })
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = hostile_output

    with patch("requests.post", return_value=mock_resp):
        res = engine.generate_remediation([], {})

    # Must reject and fallback to safe deterministic template
    assert res["engine_used"] == "deterministic_template"
    assert "CBC without HMAC is strictly prohibited" in res["fallback_reason"]
    assert res["validation_passed"] is True
    assert res["config"]["encryption"] == "aes256gcm16"  # Safe AEAD cipher


@pytest.mark.skip(reason="LLM config generation removed; explanation path covered in tests/test_ai_explainer.py")
def test_hostile_llm_weak_dh_group_rejected():
    """Verify that weak DH groups (e.g. DH 2 1024-bit) are rejected under NIST SP 800-77r1."""
    engine = RemediationEngine()

    hostile_output = {
        "response": json.dumps({
            "ike_version": 2,
            "encryption": "aes256gcm16",
            "integrity": "",
            "dh_group": "2",  # Insecure 1024-bit MODP!
            "prf": "prfsha384",
            "pfs_enabled": True,
            "rekey_time": "3600s",
            "replay_window": 64,
            "local_subnet": "192.168.1.0/24",
            "remote_subnet": "192.168.2.0/24",
            "local_id": "moon",
            "remote_id": "sun",
        })
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = hostile_output

    with patch("requests.post", return_value=mock_resp):
        res = engine.generate_remediation([], {})

    assert res["engine_used"] == "deterministic_template"
    assert "not permitted by NIST SP 800-77 Rev. 1" in res["fallback_reason"]


@pytest.mark.skip(reason="LLM config generation removed; explanation path covered in tests/test_ai_explainer.py")
def test_hostile_llm_injection_characters_rejected():
    """Verify that injection strings with newlines, braces, and shell metacharacters are rejected."""
    engine = RemediationEngine()

    # Injected config attempting to break out of swanctl braces
    hostile_output = {
        "response": json.dumps({
            "ike_version": 2,
            "encryption": "aes256gcm16",
            "integrity": "",
            "dh_group": "ecp384",
            "prf": "prfsha384",
            "pfs_enabled": True,
            "rekey_time": "3600s",
            "replay_window": 64,
            "local_subnet": "192.168.1.0/24\n  malicious_injected_block {\n    drop_firewall = yes\n  }",
            "remote_subnet": "192.168.2.0/24",
            "local_id": "moon; rm -rf /",
            "remote_id": "sun",
        })
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = hostile_output

    with patch("requests.post", return_value=mock_resp):
        res = engine.generate_remediation([], {})

    assert res["engine_used"] == "deterministic_template"
    assert "validation_error" in res["fallback_reason"]
    # Verify rendered output does not contain the injected payload
    assert "malicious_injected_block" not in res["swanctl_conf"]
    assert "rm -rf" not in res["swanctl_conf"]


def test_swanctl_syntax_validator():
    """Test AST-style swanctl syntax validator for balanced blocks and key-value correctness."""
    valid_conf = """
connections {
    hardened-tunnel {
        version = 2
        rekey_time = 3600s
        proposals = aes256gcm16-prfsha384-ecp384
        local {
            id = moon
        }
        remote {
            id = sun
        }
        children {
            secure-child {
                local_ts = 192.168.1.0/24
                remote_ts = 192.168.2.0/24
                esp_proposals = aes256gcm16-ecp384
                replay_window = 64
                mode = tunnel
                start_action = trap
            }
        }
    }
}
"""
    is_valid, err = validate_swanctl_syntax(valid_conf)
    assert is_valid is True
    assert err is None

    # Unbalanced braces
    bad_conf = valid_conf + "\n}"
    is_valid_bad, err_bad = validate_swanctl_syntax(bad_conf)
    assert is_valid_bad is False
    assert "unexpected closing brace" in err_bad

    # Malformed key-value statement
    broken_conf = valid_conf.replace("version = 2", "version")
    is_valid_broken, err_broken = validate_swanctl_syntax(broken_conf)
    assert is_valid_broken is False
    assert "unrecognized statement" in err_broken


def test_authoritative_target_and_reference_status():
    """Verify single authoritative target (swanctl_conf) and untested markers for others."""
    engine = RemediationEngine()
    res = engine.generate_remediation(
        findings=[],
        control_plane={"local_subnet": "10.0.0.0/24", "remote_subnet": "10.1.0.0/24"},
    )

    assert res["authoritative_target"] == "swanctl_conf"
    assert "swanctl_conf" in res
    assert res["ipsec_conf_status"] == "reference/untested"
    assert res["xfrm_script_status"] == "reference/untested"
    assert "10.0.0.0/24" in res["swanctl_conf"]
    assert "10.1.0.0/24" in res["swanctl_conf"]

    # Assert standard claim does NOT call classical P-384 "CNSA 2.0"
    assert "CNSA 2.0" not in res["swanctl_conf"]
    assert "CNSA 1.0 (Transitionary)" in res["swanctl_conf"]


@pytest.mark.asyncio
async def test_remediation_route_query_params():
    """Verify POST /api/v1/remediate/{job_id} accepts query parameters to override/supply subnets."""
    from backend.routes.remediation import generate_remediation
    from backend.services.result_store import ResultStore

    store = ResultStore()
    job_id = "test-job-remediation-p1"
    store.save(job_id, {
        "findings": [{"severity": "CRITICAL", "title": "Weak Cipher"}],
        "control_plane": {},  # Missing subnets in capture
    })

    data = await generate_remediation(
        job_id=job_id,
        local_subnet="172.16.10.0/24",
        remote_subnet="172.16.20.0/24",
        local_id="alpha-gateway",
        remote_id="beta-gateway",
    )

    assert "remediation" in data
    remediation = data["remediation"]
    assert remediation["authoritative_target"] == "swanctl_conf"
    assert "172.16.10.0/24" in remediation["swanctl_conf"]
    assert "172.16.20.0/24" in remediation["swanctl_conf"]
    assert "alpha-gateway" in remediation["swanctl_conf"]


def test_swanctl_load_execution(tmp_path):
    """
    Test real swanctl daemon configuration loading.
    If strongSwan charon daemon is active (/var/run/charon.vici exists), verifies that
    swanctl --load-all accepts the generated configuration.
    If charon is not active (non-root dev environment), documents requirement and verifies syntax.
    """
    import shutil
    import subprocess

    swanctl_bin = shutil.which("swanctl")
    if not swanctl_bin:
        pytest.skip("swanctl binary not installed on host")

    engine = RemediationEngine()
    res = engine.generate_remediation(
        findings=[],
        control_plane={"local_subnet": "10.0.0.0/24", "remote_subnet": "10.1.0.0/24"},
    )
    conf_path = tmp_path / "swanctl.conf"
    conf_path.write_text(res["swanctl_conf"], encoding="utf-8")

    # Check if charon daemon VICI socket exists
    vici_socket = Path("/var/run/charon.vici")
    if not vici_socket.exists():
        pytest.skip(
            "strongSwan charon daemon not running (/var/run/charon.vici missing). "
            "To test daemon loading manually: 'sudo systemctl start strongswan && pytest -k test_swanctl_load_execution'"
        )

    # charon daemon is active: run real swanctl --load-all
    proc = subprocess.run(
        [swanctl_bin, "--load-all", "--file", str(conf_path)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 0, f"swanctl --load-all failed: {proc.stderr}"


