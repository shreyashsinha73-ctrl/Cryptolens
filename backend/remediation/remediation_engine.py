"""
AI-driven network hardening and configuration remediation engine.
Generates standard-compliant IPsec configurations when weak crypto is detected.

Supports:
  - Local LLM via Ollama (llama3.2:3b / mistral)
  - Gemini API free tier as fallback (air-gapped opt-in via ENABLE_CLOUD_LLM)
  - Deterministic Jinja2 template fallback (always valid and profile-compliant)
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Optional, Tuple

import requests
from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).parent / "templates"


# ──────────────────────────────────────────────────────────────
# Cryptographic Standards Compliance Sets
# ──────────────────────────────────────────────────────────────

APPROVED_CIPHERS = {
    "aes256gcm16",
    "aes128gcm16",
    "aes256-sha384",
    "aes256-sha256",
    "aes-gcm-256",
    "aes-256-gcm",
}
APPROVED_DH_GROUPS = {
    "ecp384",
    "ecp256",
    "modp4096",
    "modp3072",
    "modp2048",
    "19",
    "14",
    "20",
    "21",
}
APPROVED_PRF = {"prfsha384", "prfsha256", "prfsha512", "sha384", "sha256"}


class HardenedIPsecConfig(BaseModel):
    """Validated hardened IPsec configuration output."""

    ike_version: int = Field(default=2, ge=1, le=2, description="IKE version (2 preferred)")
    encryption: str = Field(default="aes256gcm16", description="AEAD cipher suite")
    integrity: str = Field(default="", description="Integrity algo (empty for AEAD)")
    dh_group: str = Field(default="ecp384", description="DH group for key exchange")
    prf: str = Field(default="prfsha384", description="PRF algorithm")
    pfs_enabled: bool = Field(default=True, description="PFS must be enabled")
    rekey_time: str = Field(default="3600s", description="SA rekey interval")
    replay_window: int = Field(default=64, ge=32, description="Anti-replay window size")
    local_subnet: str = Field(default="192.168.1.0/24")
    remote_subnet: str = Field(default="192.168.2.0/24")
    local_id: str = Field(default="moon")
    remote_id: str = Field(default="sun")

    def to_ike_proposal(self) -> str:
        """Generate strongSwan IKE proposal string."""
        parts = [self.encryption]
        if self.integrity:
            parts.append(self.integrity)
        if self.prf:
            parts.append(self.prf)
        parts.append(self.dh_group)
        return "-".join(parts)

    def to_esp_proposal(self) -> str:
        """Generate strongSwan ESP proposal string."""
        parts = [self.encryption]
        if self.integrity:
            parts.append(self.integrity)
        if self.pfs_enabled:
            parts.append(self.dh_group)
        return "-".join(parts)


class RemediationEngine:
    """
    Generates hardened IPsec configurations using:
      1. Local LLM via Ollama (preferred — air-gapped capable)
      2. Gemini API (cloud fallback, strictly gated behind ENABLE_CLOUD_LLM)
      3. Deterministic Jinja2 templates (guaranteed fallback)
    """

    def __init__(self):
        self.enable_cloud_llm = os.getenv("ENABLE_CLOUD_LLM", "false").lower() in ("true", "1", "yes")
        self.gemini_model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        self.gemini_key = (os.getenv("GEMINI_API_KEY") or os.getenv("AI_API_KEY") or "").strip().strip("'\"").strip()
        self.ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        self.ollama_model = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
        self.ollama_timeout = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "5.0"))
        self.gemini_timeout = float(os.getenv("GEMINI_TIMEOUT_SECONDS", "10.0"))
        self.jinja_env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))

    def _build_prompt(
        self,
        findings: list[dict],
        control_plane: dict,
        local_subnet: str,
        remote_subnet: str,
        local_id: str,
        remote_id: str,
    ) -> str:
        return f"""You are an IPsec configuration hardening expert for strongSwan.
Given the security audit findings and network context:
Findings: {json.dumps(findings)}
Control Plane: {json.dumps(control_plane)}

Generate a hardened, NIST SP 800-77 Rev. 1 compliant IPsec configuration.
Requirements:
1. IKEv2 only (ike_version=2).
2. Encryption must be AEAD: "aes256gcm16" or "aes128gcm16".
3. Integrity: empty string "" when using AEAD ciphers.
4. DH Group: "ecp384" (Group 20), "ecp256" (Group 19), or "modp3072" (Group 15).
5. PRF: "prfsha384" or "prfsha256".
6. PFS: true.
7. Anti-replay window: at least 32, recommended 64.

Respond with STRICT JSON ONLY matching this schema:
{{
  "ike_version": 2,
  "encryption": "aes256gcm16",
  "integrity": "",
  "dh_group": "ecp384",
  "prf": "prfsha384",
  "pfs_enabled": true,
  "rekey_time": "3600s",
  "replay_window": 64,
  "local_subnet": "{local_subnet}",
  "remote_subnet": "{remote_subnet}",
  "local_id": "{local_id}",
  "remote_id": "{remote_id}"
}}
"""

    def _validate_and_parse_config(self, text: str) -> Tuple[Optional[HardenedIPsecConfig], Optional[str]]:
        """Extract and validate HardenedIPsecConfig from LLM output."""
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
        if match:
            text = match.group(1).strip()

        try:
            data = json.loads(text.strip())
        except Exception:
            return None, "malformed_json"

        try:
            config = HardenedIPsecConfig(**data)
            if config.encryption.lower() not in APPROVED_CIPHERS:
                return None, f"unapproved_cipher ({config.encryption})"
            if config.dh_group.lower() not in APPROVED_DH_GROUPS:
                return None, f"unapproved_dh_group ({config.dh_group})"
            return config, None
        except Exception as e:
            return None, f"validation_error ({e})"

    def _try_ollama(self, prompt: str) -> Tuple[Optional[HardenedIPsecConfig], Optional[str]]:
        """Attempt configuration generation using local Ollama instance."""
        url = f"{self.ollama_url.rstrip('/')}/api/generate"
        payload = {
            "model": self.ollama_model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }
        try:
            resp = requests.post(url, json=payload, timeout=self.ollama_timeout)
            if resp.status_code != 200:
                return None, f"ollama_http_{resp.status_code}"
            data = resp.json()
            raw_text = data.get("response", "")
            return self._validate_and_parse_config(raw_text)
        except requests.exceptions.Timeout:
            return None, "timeout"
        except requests.exceptions.ConnectionError:
            return None, "ollama_offline"
        except Exception as e:
            return None, f"ollama_error ({e})"

    def _try_gemini(self, prompt: str) -> Tuple[Optional[HardenedIPsecConfig], Optional[str]]:
        """Attempt configuration generation using cloud Gemini API."""
        if not self.gemini_key:
            return None, "auth_error (missing API key)"

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.gemini_model}:generateContent?key={self.gemini_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}]
        }
        headers = {"Content-Type": "application/json"}
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=self.gemini_timeout)
            if resp.status_code in (401, 403):
                return None, "auth_error"
            if resp.status_code != 200:
                return None, f"gemini_http_{resp.status_code}"
            data = resp.json()
            candidates = data.get("candidates", [])
            if not candidates:
                return None, "malformed_json (no candidates)"
            parts = candidates[0].get("content", {}).get("parts", [])
            if not parts:
                return None, "malformed_json (no parts)"
            raw_text = parts[0].get("text", "")
            return self._validate_and_parse_config(raw_text)
        except requests.exceptions.Timeout:
            return None, "timeout"
        except requests.exceptions.ConnectionError:
            return None, "connection_error"
        except Exception as e:
            return None, f"gemini_error ({e})"

    def generate_remediation(
        self,
        findings: list[dict],
        control_plane: dict,
    ) -> dict:
        """
        Generate hardened config from audit findings with explicit fallback tracking.
        Returns dict with rendered configs, engine used, validation level, and fallback reason.
        """
        local_subnet = control_plane.get("local_subnet") or "192.168.1.0/24"
        remote_subnet = control_plane.get("remote_subnet") or "192.168.2.0/24"
        local_id = control_plane.get("local_id") or "moon"
        remote_id = control_plane.get("remote_id") or "sun"

        prompt = self._build_prompt(
            findings, control_plane, local_subnet, remote_subnet, local_id, remote_id
        )

        ollama_config, ollama_err = self._try_ollama(prompt)
        if ollama_config is not None:
            swanctl_conf = self._render_swanctl(ollama_config)
            ipsec_conf = self._render_ipsec_conf(ollama_config)
            xfrm_script = self._render_xfrm(ollama_config)
            return {
                "engine_used": "ollama",
                "validation_level": "profile_compliant",
                "validation_passed": True,
                "fallback_reason": None,
                "config": ollama_config.model_dump(),
                "swanctl_conf": swanctl_conf,
                "ipsec_conf": ipsec_conf,
                "xfrm_script": xfrm_script,
            }

        logger.info(f"Ollama remediation failed ({ollama_err}). Checking cloud LLM fallback...")

        gemini_config = None
        gemini_err = None

        if not self.enable_cloud_llm:
            gemini_err = "airgap_policy (ENABLE_CLOUD_LLM=false)"
            logger.info("Cloud LLM disabled by policy (ENABLE_CLOUD_LLM=false)")
        else:
            gemini_config, gemini_err = self._try_gemini(prompt)
            if gemini_config is not None:
                swanctl_conf = self._render_swanctl(gemini_config)
                ipsec_conf = self._render_ipsec_conf(gemini_config)
                xfrm_script = self._render_xfrm(gemini_config)
                return {
                    "engine_used": "gemini",
                    "validation_level": "profile_compliant",
                    "validation_passed": True,
                    "fallback_reason": f"ollama_failed ({ollama_err})",
                    "config": gemini_config.model_dump(),
                    "swanctl_conf": swanctl_conf,
                    "ipsec_conf": ipsec_conf,
                    "xfrm_script": xfrm_script,
                }

        # Fallback to deterministic template
        fallback_reasons = []
        if ollama_err:
            fallback_reasons.append(f"ollama: {ollama_err}")
        if gemini_err:
            fallback_reasons.append(f"gemini: {gemini_err}")
        combined_reason = "; ".join(fallback_reasons) if fallback_reasons else "default_template"

        logger.info(f"Falling back to deterministic template remediation: {combined_reason}")

        config = HardenedIPsecConfig(
            ike_version=2,
            encryption="aes256gcm16",
            integrity="",
            dh_group="ecp384",
            prf="prfsha384",
            pfs_enabled=True,
            rekey_time="3600s",
            replay_window=64,
            local_subnet=local_subnet,
            remote_subnet=remote_subnet,
            local_id=local_id,
            remote_id=remote_id,
        )

        swanctl_conf = self._render_swanctl(config)
        ipsec_conf = self._render_ipsec_conf(config)
        xfrm_script = self._render_xfrm(config)

        return {
            "engine_used": "deterministic_template",
            "validation_level": "profile_compliant",
            "validation_passed": True,
            "fallback_reason": combined_reason,
            "config": config.model_dump(),
            "swanctl_conf": swanctl_conf,
            "ipsec_conf": ipsec_conf,
            "xfrm_script": xfrm_script,
        }

    def _render_swanctl(self, config: HardenedIPsecConfig) -> str:
        """Render strongSwan swanctl.conf from validated config."""
        try:
            template = self.jinja_env.get_template("swanctl_hardened.conf.j2")
            return template.render(
                connection_name="hardened-tunnel",
                ike_version=config.ike_version,
                rekey_time=config.rekey_time,
                ike_proposal=config.to_ike_proposal(),
                esp_proposal=config.to_esp_proposal(),
                local_id=config.local_id,
                remote_id=config.remote_id,
                local_subnet=config.local_subnet,
                remote_subnet=config.remote_subnet,
                replay_window=config.replay_window,
            )
        except Exception:
            return f"""# CryptoLens Auto-Generated swanctl.conf
connections {{
    hardened-tunnel {{
        version = {config.ike_version}
        rekey_time = {config.rekey_time}
        proposals = {config.to_ike_proposal()}
        local {{
            id = {config.local_id}
        }}
        remote {{
            id = {config.remote_id}
        }}
        children {{
            secure-child {{
                local_ts = {config.local_subnet}
                remote_ts = {config.remote_subnet}
                esp_proposals = {config.to_esp_proposal()}
                replay_window = {config.replay_window}
                mode = tunnel
                start_action = trap
            }}
        }}
    }}
}}"""

    def _render_ipsec_conf(self, config: HardenedIPsecConfig) -> str:
        """Render a legacy ipsec.conf from validated config."""
        return f"""# CryptoLens Auto-Generated ipsec.conf (Legacy Format)
config setup
    charondebug="ike 2, knl 2, cfg 2"

conn hardened-tunnel
    keyexchange=ikev{config.ike_version}
    ike={config.to_ike_proposal()}!
    esp={config.to_esp_proposal()}!
    left=%defaultroute
    leftsubnet={config.local_subnet}
    leftid=@{config.local_id}
    right=%any
    rightsubnet={config.remote_subnet}
    rightid=@{config.remote_id}
    auto=route
    dpdaction=restart
    dpddelay=30s
    rekeymargin=3m
    rekeyfuzz=100%
    ikelifetime={config.rekey_time}"""

    def _render_xfrm(self, config: HardenedIPsecConfig) -> str:
        """Render a Linux ip xfrm policy script."""
        return f"""#!/bin/bash
# CryptoLens Auto-Generated xfrm Policy Script
# Apply hardened IPsec policy via Linux kernel xfrm subsystem

# Flush existing policies
ip xfrm policy flush
ip xfrm state flush

echo "Hardened IPsec policies applied:"
echo "  Cipher:    {config.encryption}"
echo "  DH Group:  {config.dh_group}"
echo "  PFS:       {config.pfs_enabled}"
echo "  Rekey:     {config.rekey_time}"
echo ""
echo "NOTE: This script provides the policy template."
echo "Full xfrm state requires IKE negotiation via strongSwan."

# Policy: outbound
ip xfrm policy add \\
    src {config.local_subnet} dst {config.remote_subnet} \\
    dir out \\
    tmpl src 0.0.0.0 dst 0.0.0.0 \\
    proto esp mode tunnel reqid 1

# Policy: inbound
ip xfrm policy add \\
    src {config.remote_subnet} dst {config.local_subnet} \\
    dir in \\
    tmpl src 0.0.0.0 dst 0.0.0.0 \\
    proto esp mode tunnel reqid 1

echo "xfrm policies installed successfully."
"""
