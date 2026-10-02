import json
import pytest
from unittest.mock import patch, MagicMock
import requests

from backend.remediation.remediation_engine import RemediationEngine
from backend.engine.llm_client.client import GeminiClient, GeminiClientConfig
from backend.engine.data_plane.classifier import _classify_via_llm


@pytest.fixture
def sample_context():
    return {
        "findings": [{"severity": "HIGH", "title": "Weak 3DES Cipher"}],
        "control_plane": {
            "local_subnet": "10.0.0.0/24",
            "remote_subnet": "10.1.0.0/24",
            "local_id": "gw-alpha",
            "remote_id": "gw-beta",
        },
    }


def test_airgap_disabled_fallback_to_template(monkeypatch, sample_context):
    """When cloud LLM is disabled and Ollama is offline, fallback to deterministic template with reasons recorded."""
    monkeypatch.setenv("ENABLE_CLOUD_LLM", "false")
    monkeypatch.setenv("OLLAMA_URL", "http://localhost:11434")

    engine = RemediationEngine()

    with patch("requests.post", side_effect=requests.exceptions.ConnectionError("Connection refused")):
        res = engine.generate_remediation(sample_context["findings"], sample_context["control_plane"])

    assert res["engine_used"] == "deterministic_template"
    assert res["validation_level"] == "profile_compliant"
    assert res["validation_passed"] is True
    assert "ollama: ollama_offline" in res["fallback_reason"]
    assert "ENABLE_CLOUD_LLM=false" in res["fallback_reason"]
    assert "swanctl_conf" in res
    assert "10.0.0.0/24" in res["swanctl_conf"]


def test_ollama_success_no_fallback(monkeypatch, sample_context):
    """When Ollama succeeds with valid configuration, use Ollama without fallback."""
    monkeypatch.setenv("ENABLE_CLOUD_LLM", "false")
    engine = RemediationEngine()

    ollama_response = {
        "response": json.dumps({
            "ike_version": 2,
            "encryption": "aes256gcm16",
            "integrity": "",
            "dh_group": "ecp384",
            "prf": "prfsha384",
            "pfs_enabled": True,
            "rekey_time": "3600s",
            "replay_window": 64,
            "local_subnet": "10.0.0.0/24",
            "remote_subnet": "10.1.0.0/24",
            "local_id": "gw-alpha",
            "remote_id": "gw-beta",
        })
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = ollama_response

    with patch("requests.post", return_value=mock_resp):
        res = engine.generate_remediation(sample_context["findings"], sample_context["control_plane"])

    assert res["engine_used"] == "ollama"
    assert res["validation_level"] == "profile_compliant"
    assert res["fallback_reason"] is None
    assert res["config"]["encryption"] == "aes256gcm16"


def test_gemini_success_when_cloud_enabled(monkeypatch, sample_context):
    """When cloud LLM is enabled and Ollama fails, fallback to Gemini."""
    monkeypatch.setenv("ENABLE_CLOUD_LLM", "true")
    monkeypatch.setenv("GEMINI_API_KEY", "valid_key")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-2.5-flash")

    engine = RemediationEngine()

    gemini_json_payload = {
        "candidates": [{
            "content": {
                "parts": [{
                    "text": json.dumps({
                        "ike_version": 2,
                        "encryption": "aes256gcm16",
                        "integrity": "",
                        "dh_group": "ecp384",
                        "prf": "prfsha384",
                        "pfs_enabled": True,
                        "rekey_time": "3600s",
                        "replay_window": 64,
                        "local_subnet": "10.0.0.0/24",
                        "remote_subnet": "10.1.0.0/24",
                        "local_id": "gw-alpha",
                        "remote_id": "gw-beta",
                    })
                }]
            }
        }]
    }

    def fake_post(url, *args, **kwargs):
        if "11434" in url:
            raise requests.exceptions.ConnectionError("Ollama offline")
        mock = MagicMock()
        mock.status_code = 200
        mock.json.return_value = gemini_json_payload
        return mock

    with patch("requests.post", side_effect=fake_post):
        res = engine.generate_remediation(sample_context["findings"], sample_context["control_plane"])

    assert res["engine_used"] == "gemini"
    assert res["validation_level"] == "profile_compliant"
    assert "ollama_failed" in res["fallback_reason"]


def test_bad_api_key_fallback(monkeypatch, sample_context):
    """When Gemini returns 401/403, fallback to deterministic template with auth_error reason."""
    monkeypatch.setenv("ENABLE_CLOUD_LLM", "true")
    monkeypatch.setenv("GEMINI_API_KEY", "bad_key")

    engine = RemediationEngine()

    def fake_post(url, *args, **kwargs):
        if "11434" in url:
            raise requests.exceptions.ConnectionError("Ollama offline")
        mock = MagicMock()
        mock.status_code = 401
        return mock

    with patch("requests.post", side_effect=fake_post):
        res = engine.generate_remediation(sample_context["findings"], sample_context["control_plane"])

    assert res["engine_used"] == "deterministic_template"
    assert "auth_error" in res["fallback_reason"]


def test_timeout_fallback(monkeypatch, sample_context):
    """When LLM requests time out, fallback to deterministic template with timeout reason."""
    monkeypatch.setenv("ENABLE_CLOUD_LLM", "true")
    monkeypatch.setenv("GEMINI_API_KEY", "valid_key")

    engine = RemediationEngine()

    def fake_post(url, *args, **kwargs):
        raise requests.exceptions.Timeout("Request timed out")

    with patch("requests.post", side_effect=fake_post):
        res = engine.generate_remediation(sample_context["findings"], sample_context["control_plane"])

    assert res["engine_used"] == "deterministic_template"
    assert "timeout" in res["fallback_reason"]


def test_malformed_json_fallback(monkeypatch, sample_context):
    """When LLM returns malformed JSON, fallback to deterministic template with malformed_json reason."""
    monkeypatch.setenv("ENABLE_CLOUD_LLM", "false")
    engine = RemediationEngine()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": "Here is your config: {ike_version: INVALID_JSON"}

    with patch("requests.post", return_value=mock_resp):
        res = engine.generate_remediation(sample_context["findings"], sample_context["control_plane"])

    assert res["engine_used"] == "deterministic_template"
    assert "malformed_json" in res["fallback_reason"]


def test_gemini_client_airgap_policy(monkeypatch):
    """Verify GeminiClient refuses to execute when ENABLE_CLOUD_LLM=false."""
    monkeypatch.setenv("ENABLE_CLOUD_LLM", "false")
    monkeypatch.setenv("GEMINI_API_KEY", "some_key")

    config = GeminiClientConfig()
    assert config.validate() is False

    client = GeminiClient(config)
    result = client._call_gemini_api("test prompt")
    assert result is None


def test_classifier_llm_airgap_policy(monkeypatch):
    """Verify _classify_via_llm raises error when ENABLE_CLOUD_LLM=false."""
    monkeypatch.setenv("ENABLE_CLOUD_LLM", "false")
    with pytest.raises(RuntimeError, match="Cloud LLM disabled by policy"):
        _classify_via_llm({"lengths": [100, 200], "iats": [0.01, 0.02]})
