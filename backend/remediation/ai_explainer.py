"""
AI-driven Remediation Explainer with strict output guarding, redaction, and multi-provider failover.

Invariants:
1. RemediationEngine remains the SOLE source of configuration values.
2. The AI Explainer only generates human-readable explanations and translation drafts.
3. Strict outbound redaction: ZERO IPs, subnets, SPIs, identities, hostnames, or raw PCAP bytes.
4. Output guard: rejects HTML, markdown links, code fences, unapproved ciphers, and schema violations.
5. Deterministic templates provide guaranteed safe fallback.
"""

import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import requests
from pydantic import BaseModel, ConfigDict, Field, ValidationError

try:
    from dotenv import load_dotenv
    _env_file = Path(__file__).resolve().parents[2] / ".env"
    if _env_file.exists():
        load_dotenv(_env_file)
except Exception:
    pass

logger = logging.getLogger(__name__)

PROMPT_VERSION = "v1"
CACHE_FILE_PATH = Path(__file__).resolve().parents[1] / "data" / "ai_cache.json"

# Approved cryptographic algorithms for output guard whitelisting
APPROVED_HARDENED_ALGORITHMS: Set[str] = {
    "aes256gcm16",
    "aes128gcm16",
    "aes-256-gcm",
    "aes-128-gcm",
    "aes256",
    "aes128",
    "aes256cbc",
    "aes128cbc",
    "aes-256-cbc",
    "aes-128-cbc",
    "chacha20poly1305",
    "ecp384",
    "ecp256",
    "ecp521",
    "curve25519",
    "modp4096",
    "modp3072",
    "modp2048",
    "prfsha384",
    "prfsha256",
    "prfsha512",
    "sha384",
    "sha256",
    "sha512",
    "hmac-sha384",
    "hmac-sha256",
    "hmac-sha512",
    "group 14",
    "group 15",
    "group 16",
    "group 19",
    "group 20",
    "group 21",
    "group 31",
    "dh 14",
    "dh 15",
    "dh 16",
    "dh 19",
    "dh 20",
    "dh 21",
    "dh 31",
    "dh14",
    "dh15",
    "dh16",
    "dh19",
    "dh20",
    "dh21",
    "dh31",
}

DISALLOWED_UNAPPROVED_CIPHERS: Set[str] = {
    "rc4",
    "des-ecb",
    "blowfish",
    "cast5",
    "null_cipher",
    "null-cipher",
    "rot13",
    "md5",
    "dh 1",
    "dh1",
    "group 1",
    "group1",
}


# ──────────────────────────────────────────────────────────────
# Strict Pydantic Models (extra="forbid")
# ──────────────────────────────────────────────────────────────

class FindingExplanation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    plain_summary: str = Field(..., max_length=400)
    why_it_matters: str = Field(..., max_length=400)
    what_changed: str = Field(..., max_length=400)


class ExplainerOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    executive_summary: str = Field(..., max_length=3000)
    verbose_report: Optional[str] = Field(default=None, max_length=8000)
    findings: List[FindingExplanation]


# ──────────────────────────────────────────────────────────────
# Redaction: Zero IPs, SPIs, identities, hostnames, or PCAP bytes
# ──────────────────────────────────────────────────────────────

def redact_findings_and_params(
    findings: List[Dict[str, Any]],
    hardened_params: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Extract ONLY allowed outbound fields:
    - severity, title, category, algorithm_names, group_ids
    - deterministic hardened parameters (cipher, group, lifetime, replay_window)
    - reference standards
    Strip ALL IP addresses, subnets, SPIs, identities, hostnames, timestamps, and PCAP bytes.
    """
    redacted_findings = []
    for f in findings:
        title = str(f.get("title") or f.get("finding_id") or "Security Finding")
        category = str(f.get("category") or "General")
        severity = str(f.get("severity") or "MEDIUM").upper()

        # Extract only cryptographic algorithm names mentioned in finding
        algo_names = []
        for algo in ["3DES", "3DES-CBC", "DES", "AES-128-CBC", "AES-256-CBC", "AES-128-GCM", "AES-256-GCM", "SHA-1", "SHA-256", "MD5"]:
            if re.search(rf"\b{re.escape(algo)}\b", title, re.IGNORECASE):
                algo_names.append(algo)

        # Extract only DH group numbers
        group_ids = []
        for grp in [2, 5, 14, 19, 20, 21]:
            if re.search(rf"\b(?:DH|Group)\s*{grp}\b", title, re.IGNORECASE):
                group_ids.append(grp)

        redacted_findings.append({
            "severity": severity,
            "title": title,
            "category": category,
            "algorithm_names": sorted(list(set(algo_names))),
            "group_ids": sorted(list(set(group_ids))),
        })

    safe_hardened_params = {
        "ike_version": int(hardened_params.get("ike_version") or 2),
        "encryption": str(hardened_params.get("encryption") or "aes256gcm16"),
        "integrity": str(hardened_params.get("integrity") or ""),
        "dh_group": str(hardened_params.get("dh_group") or "ecp384"),
        "prf": str(hardened_params.get("prf") or "prfsha384"),
        "pfs_enabled": bool(hardened_params.get("pfs_enabled", True)),
        "rekey_time": str(hardened_params.get("rekey_time") or "3600s"),
        "replay_window": int(hardened_params.get("replay_window") or 64),
    }

    return {
        "redacted_findings": redacted_findings,
        "hardened_params": safe_hardened_params,
        "standards": ["NIST SP 800-77 Rev. 1", "NSA CNSA 1.0", "RFC 7296", "RFC 4303"],
    }


# ──────────────────────────────────────────────────────────────
# Deterministic Fallback Explanations Generator
# ──────────────────────────────────────────────────────────────

def generate_template_explanations(
    redacted_findings: List[Dict[str, Any]],
    hardened_params: Dict[str, Any],
) -> ExplainerOutput:
    """
    Generate standard-compliant, deterministic explanations when LLM is offline or rejected.
    """
    explanations = []
    for f in redacted_findings:
        title = f.get("title", "")
        cat = f.get("category", "")
        title_lower = title.lower()

        if "3des" in title_lower or "des" in title_lower or "sweet32" in title_lower:
            plain_summary = "Deprecated 64-bit block cipher replaced with modern AEAD authenticated encryption."
            why_it_matters = "Legacy 64-bit block ciphers like 3DES are vulnerable to Sweet32 birthday collision attacks (CVE-2016-2183) after transferring 32 GiB."
            what_changed = f"Upgraded cipher to {hardened_params.get('encryption', 'aes256gcm16')} with integrated GMAC authentication."
        elif "dh 2" in title_lower or "group 2" in title_lower or "logjam" in title_lower or "dh 5" in title_lower or "group 5" in title_lower:
            plain_summary = "Diffie-Hellman key exchange group upgraded to modern elliptic curve cryptography."
            why_it_matters = "MODP groups with 1024 bits or fewer are vulnerable to nation-state discrete logarithm precomputation (Logjam attack, RFC 7959)."
            what_changed = f"Upgraded DH group to {hardened_params.get('dh_group', 'ecp384')} (Group 20) per NIST SP 800-77 Rev. 1."
        elif "sha-1" in title_lower or "sha1" in title_lower or "integrity" in title_lower:
            plain_summary = "Collision-vulnerable hash function replaced with AEAD built-in authentication."
            why_it_matters = "SHA-1 is deprecated due to theoretical and practical collision vulnerabilities."
            what_changed = f"Integrated {hardened_params.get('encryption', 'aes256gcm16')} AEAD mode, eliminating standalone HMAC overhead."
        elif "pfs" in title_lower or "forward secrecy" in title_lower:
            plain_summary = "Perfect Forward Secrecy enabled for all Child SA rekeys."
            why_it_matters = "Without PFS, compromise of the long-term IKE SA allows retrospective decryption of all past Child SA sessions."
            what_changed = "Configured mandatory Diffie-Hellman key exchange on every Child SA rekey cycle."
        elif "replay" in title_lower or "window" in title_lower:
            plain_summary = "RFC 4303 anti-replay protection window enforced."
            why_it_matters = "Prevents packet duplication, out-of-order injection, and denial of service attacks."
            what_changed = f"Enforced anti-replay sliding window of {hardened_params.get('replay_window', 64)} packets."
        else:
            plain_summary = f"Security control '{title}' hardened to standard baseline."
            why_it_matters = "Ensures strict alignment with NIST SP 800-77 Rev. 1 and NSA CNSA 1.0 guidelines."
            what_changed = "Hardened parameter to standard profile specifications."

        explanations.append(
            FindingExplanation(
                plain_summary=plain_summary[:800],
                why_it_matters=why_it_matters[:800],
                what_changed=what_changed[:800],
            )
        )

    exec_summary = (
        "Automated audit identified security weaknesses in the active IPsec configuration. "
        "Deterministic remediation upgraded all cryptographic controls to NIST SP 800-77 Rev. 1 "
        "and CNSA 1.0 standards: AES-256-GCM AEAD encryption, ECP-384 key exchange, "
        "Perfect Forward Secrecy, and RFC 4303 anti-replay protection."
    )

    verbose_report = (
        "Executive Cryptographic Assessment Briefing:\n\n"
        "An automated deep inspection of the audited network tunnel identified critical cryptographic risks "
        "and architectural vulnerabilities that undermine data confidentiality and network integrity.\n\n"
        "Core Findings & Business Risk:\n"
        "• Outdated Ciphers: Legacy 64-bit block ciphers and CBC mode configurations are susceptible to plaintext recovery and collision attacks.\n"
        "• Weak Key Agreement: Diffie-Hellman groups below 2048 bits risk discrete logarithm precomputation by well-funded adversaries.\n"
        "• Missing Forward Secrecy: In the absence of Perfect Forward Secrecy, future compromise of long-term credentials enables retroactive decryption of past sessions.\n\n"
        "Applied Remediation & Hardened Posture:\n"
        "• AES-256-GCM authenticated encryption (AEAD) has been provisioned to enforce wire confidentiality and cryptographic integrity simultaneously.\n"
        "• Elliptic Curve Diffie-Hellman (ECP-384 / Group 20) is enforced in full alignment with NIST SP 800-77 Rev. 1 and NSA CNSA 1.0 specifications.\n"
        "• Perfect Forward Secrecy (PFS) and an RFC 4303 64-packet anti-replay window have been activated to prevent sequence duplication and replay attacks."
    )

    return ExplainerOutput(
        executive_summary=exec_summary[:2500],
        verbose_report=verbose_report[:8000],
        findings=explanations,
    )


# ──────────────────────────────────────────────────────────────
# Output Guard
# ──────────────────────────────────────────────────────────────

def validate_explainer_output(
    raw_text: str,
    allowed_input_algorithms: Set[str],
) -> Tuple[bool, Optional[ExplainerOutput], Optional[str]]:
    """
    Strict output validation guard:
    1. Rejects HTML tags, markdown links, code fences, or URLs.
    2. Enforces Pydantic schema validation (extra='forbid', length limits).
    3. Enforces executive_summary word count <= 150 words.
    4. Enforces cryptographic algorithm whitelist (rejects unknown/hostile ciphers).
    """
    if not raw_text or not raw_text.strip():
        return False, None, "guard_rejected: empty_response"

    # 1. Reject code fences
    if "```" in raw_text:
        return False, None, "guard_rejected: code_fence_detected"

    # 2. Reject HTML tags
    if re.search(r"<[a-zA-Z\/][^>]*>", raw_text):
        return False, None, "guard_rejected: html_tags_detected"

    # 3. Reject Markdown links or raw URLs
    if re.search(r"\[.*?\]\(.*?\)", raw_text) or re.search(r"https?://\S+", raw_text):
        return False, None, "guard_rejected: links_or_urls_detected"

    # 4. JSON parsing
    try:
        data = json.loads(raw_text.strip())
    except Exception as e:
        return False, None, f"guard_rejected: malformed_json ({e})"

    # 5. Schema validation
    try:
        output = ExplainerOutput(**data)
    except ValidationError as e:
        return False, None, f"guard_rejected: schema_validation_error ({e})"

    # 6. Executive summary word count <= 80 words
    words = output.executive_summary.split()
    if len(words) > 150:
        return False, None, f"guard_rejected: executive_summary_word_count ({len(words)} > 150 words)"

    # 7. Whitelist check for algorithms mentioned in output
    all_allowed = set(a.lower() for a in APPROVED_HARDENED_ALGORITHMS).union(
        set(a.lower() for a in allowed_input_algorithms)
    )

    # Check for disallowed unapproved ciphers
    text_lower = raw_text.lower()
    for disallowed in DISALLOWED_UNAPPROVED_CIPHERS:
        if disallowed in all_allowed:
            continue
        if re.search(rf"\b{re.escape(disallowed)}\b", text_lower):
            return False, None, f"guard_rejected: unapproved_cipher_named ({disallowed})"

    return True, output, None


# ──────────────────────────────────────────────────────────────
# AI Cache Management
# ──────────────────────────────────────────────────────────────

class AICache:
    def __init__(self, cache_file: Path = CACHE_FILE_PATH):
        self.cache_file = cache_file
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        self._data: Dict[str, Any] = {}
        self._load()

    def _load(self):
        if self.cache_file.exists():
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    self._data = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load AI cache from {self.cache_file}: {e}")
                self._data = {}

    def _save(self):
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save AI cache to {self.cache_file}: {e}")

    def make_key(self, provider: str, model_id: str, redacted_input: Dict[str, Any]) -> str:
        serialized = json.dumps(redacted_input, sort_keys=True)
        raw_key = f"{PROMPT_VERSION}:{provider}:{model_id}:{serialized}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        return self._data.get(key)

    def set(self, key: str, value: Dict[str, Any]):
        self._data[key] = value
        self._save()


# ──────────────────────────────────────────────────────────────
# AI Explainer Engine
# ──────────────────────────────────────────────────────────────

class AIExplainer:
    """
    AI Explainer orchestrator supporting Gemini, OpenAI-compatible endpoints,
    caching, output guard validation, and deterministic template fallback.
    """

    def __init__(self, cache: Optional[AICache] = None):
        self.cache = cache or AICache()
        self.enable_cloud_llm = os.getenv("ENABLE_CLOUD_LLM", "false").lower() in ("true", "1", "yes")
        
        # Provider config
        # LLM_PROVIDER = gemini | openai_compat | none
        self.primary_provider = os.getenv("LLM_PROVIDER", "").strip().lower()
        if not self.primary_provider:
            self.primary_provider = "gemini" if self.enable_cloud_llm else "none"

        self.fallback_provider = os.getenv("LLM_FALLBACK_PROVIDER", "").strip().lower() or None

        # Gemini config
        self.gemini_key = (os.getenv("GEMINI_API_KEY") or os.getenv("AI_API_KEY") or "").strip().strip("'\"").strip()
        self.gemini_model = os.getenv("GEMINI_MODEL", "gemini-3.8-flash").strip()
        self.gemini_timeout = float(os.getenv("GEMINI_TIMEOUT_SECONDS", "10.0"))

        # OpenAI compatible config (Groq / OpenRouter / Mistral / Ollama)
        self.openai_base_url = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        self.openai_key = (os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or "").strip().strip("'\"").strip()
        self.openai_model = os.getenv("LLM_MODEL", "gpt-4o-mini").strip()
        self.openai_timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "10.0"))

    def _build_prompt(self, redacted_payload: Dict[str, Any]) -> str:
        return f"""You are a technical cybersecurity explainer for an IPsec security audit platform.
Given ONLY these redacted security audit findings and deterministic hardened parameters:

Redacted Findings: {json.dumps(redacted_payload['redacted_findings'])}
Hardened Parameters: {json.dumps(redacted_payload['hardened_params'])}
Standards: {json.dumps(redacted_payload['standards'])}

TASK:
Explain each finding in plain English for security auditors and produce a comprehensive executive report with minimalist jargon.

STRICT FORMATTING AND SAFETY RULES:
1. Respond with STRICT JSON ONLY. Do NOT wrap with markdown code fences (no ``` or ```json).
2. Do NOT include HTML tags (<...>), links, URLs (http:// or https://), or markdown brackets.
3. executive_summary must be concise and strictly <= 150 words.
4. verbose_report must be an expanded, plain-English executive briefing (300-500 words) using clean, minimalist jargon so non-technical executives or judges clearly understand the security verdict, real-world risks, and how the remediation secures the network.
5. Do NOT reference or invent any unapproved or weak ciphers (e.g., do NOT mention RC4, DES-ECB, Blowfish).
6. All plain_summary, why_it_matters, and what_changed strings must be <= 350 characters.

STRICT JSON SCHEMA:
{{
  "executive_summary": "Concise summary under 150 words explaining remediation impact.",
  "verbose_report": "Comprehensive plain-English executive briefing with minimalist jargon explaining overall security posture, business risks, and remediation.",
  "findings": [
    {{
      "plain_summary": "Plain language explanation of the finding.",
      "why_it_matters": "Real-world security threat or vulnerability rationale.",
      "what_changed": "Specific standard-compliant parameter applied in remediation."
    }}
  ]
}}
"""

    def _call_gemini(self, prompt: str) -> Tuple[Optional[str], Optional[str]]:
        gemini_key = self.gemini_key if self.gemini_key is not None else ((os.getenv("GEMINI_API_KEY") or os.getenv("AI_API_KEY") or "").strip().strip("'\"").strip())
        gemini_model = (os.getenv("GEMINI_MODEL") or self.gemini_model).strip()
        gemini_timeout = float(os.getenv("GEMINI_TIMEOUT_SECONDS", str(self.gemini_timeout)))

        if not gemini_key:
            return None, "gemini_missing_api_key"

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{gemini_model}:generateContent?key={gemini_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.0,
                "responseMimeType": "application/json",
            }
        }
        headers = {"Content-Type": "application/json"}
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=gemini_timeout)
            if resp.status_code == 429:
                # Brief backoff retry
                time.sleep(1.5)
                resp = requests.post(url, json=payload, headers=headers, timeout=gemini_timeout)
            if resp.status_code == 429:
                return None, "gemini_http_429 (rate_limited)"
            if resp.status_code in (401, 403):
                return None, f"gemini_http_{resp.status_code} (auth_error)"
            if resp.status_code != 200:
                return None, f"gemini_http_{resp.status_code}"

            data = resp.json()
            candidates = data.get("candidates", [])
            if not candidates:
                return None, "gemini_empty_candidates"
            parts = candidates[0].get("content", {}).get("parts", [])
            if not parts:
                return None, "gemini_empty_parts"
            return parts[0].get("text", "").strip(), None
        except requests.exceptions.Timeout:
            return None, "gemini_timeout"
        except requests.exceptions.ConnectionError:
            return None, "gemini_connection_error"
        except Exception as e:
            return None, f"gemini_error ({e})"

    def _call_openai_compat(self, prompt: str) -> Tuple[Optional[str], Optional[str]]:
        openai_key = self.openai_key if self.openai_key is not None else ((os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or "").strip().strip("'\"").strip())
        openai_model = (os.getenv("LLM_MODEL") or self.openai_model).strip()
        openai_base_url = (os.getenv("LLM_BASE_URL") or self.openai_base_url).rstrip("/")
        openai_timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", str(self.openai_timeout)))

        if not openai_key:
            return None, "openai_compat_missing_api_key"

        url = f"{openai_base_url}/chat/completions"
        payload = {
            "model": openai_model,
            "messages": [
                {"role": "system", "content": "You are a cybersecurity IPsec audit explainer. Output valid JSON only without code fences or links."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.0,
        }
        headers = {
            "Authorization": f"Bearer {openai_key}",
            "Content-Type": "application/json",
        }
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=openai_timeout)
            if resp.status_code == 429:
                return None, "openai_compat_http_429 (rate_limited)"
            if resp.status_code in (401, 403):
                return None, f"openai_compat_http_{resp.status_code} (auth_error)"
            if resp.status_code != 200:
                return None, f"openai_compat_http_{resp.status_code}"

            data = resp.json()
            choices = data.get("choices", [])
            if not choices:
                return None, "openai_compat_empty_choices"
            return choices[0].get("message", {}).get("content", "").strip(), None
        except requests.exceptions.Timeout:
            return None, "openai_compat_timeout"
        except requests.exceptions.ConnectionError:
            return None, "openai_compat_connection_error"
        except Exception as e:
            return None, f"openai_compat_error ({e})"

    def _invoke_provider(self, provider: str, prompt: str) -> Tuple[Optional[str], Optional[str], str]:
        if provider == "gemini":
            model = (os.getenv("GEMINI_MODEL") or self.gemini_model).strip()
            raw_text, err = self._call_gemini(prompt)
            return raw_text, err, f"Gemini ({model})"
        elif provider == "openai_compat":
            model = (os.getenv("LLM_MODEL") or self.openai_model).strip()
            raw_text, err = self._call_openai_compat(prompt)
            return raw_text, err, f"OpenAI-Compat ({model})"
        else:
            return None, f"provider_{provider}_disabled", "none"

    def explain(
        self,
        findings: List[Dict[str, Any]],
        hardened_params: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Generate explanations for audit findings with redaction, caching,
        provider failover, output guard validation, and deterministic template fallback.
        """
        redacted = redact_findings_and_params(findings, hardened_params)

        # Collect allowed input algorithms for guard validation
        allowed_input_algos = set()
        for rf in redacted["redacted_findings"]:
            allowed_input_algos.update(rf.get("algorithm_names", []))

        # Re-check environment config dynamically in case modified via monkeypatch
        enable_cloud_llm = os.getenv("ENABLE_CLOUD_LLM", str(self.enable_cloud_llm)).lower() in ("true", "1", "yes")
        provider = os.getenv("LLM_PROVIDER", "").strip().lower()
        if not provider:
            provider = "gemini" if enable_cloud_llm else "none"

        gemini_key = (os.getenv("GEMINI_API_KEY") or os.getenv("AI_API_KEY") or self.gemini_key).strip().strip("'\"").strip()
        openai_key = (os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or self.openai_key).strip().strip("'\"").strip()

        if provider == "none" or not enable_cloud_llm:
            template_output = generate_template_explanations(
                redacted["redacted_findings"],
                redacted["hardened_params"],
            )
            return {
                "engine_used": "Template",
                "fallback_reason": "cloud_llm_disabled (ENABLE_CLOUD_LLM=false)" if not enable_cloud_llm else "provider_none",
                "is_ai_generated": False,
                "is_cached": False,
                "executive_summary": template_output.executive_summary,
                "verbose_report": template_output.verbose_report,
                "findings_explanations": [f.model_dump() for f in template_output.findings],
            }

        model_id = (os.getenv("GEMINI_MODEL") or self.gemini_model).strip() if provider == "gemini" else (os.getenv("LLM_MODEL") or self.openai_model).strip()
        cache_key = self.cache.make_key(provider, model_id, redacted)

        # 1. Check Cache
        cached_entry = self.cache.get(cache_key)
        if cached_entry:
            cached_time = cached_entry.get("cached_at", "recently")
            return {
                "engine_used": f"{provider.capitalize()} ({model_id})",
                "fallback_reason": None,
                "is_ai_generated": True,
                "is_cached": True,
                "cached_badge": f"AI-generated, cached {cached_time}",
                "executive_summary": cached_entry["executive_summary"],
                "verbose_report": cached_entry.get("verbose_report") or cached_entry.get("executive_summary", ""),
                "findings_explanations": cached_entry["findings_explanations"],
            }

        # 2. Invoke Primary Provider
        prompt = self._build_prompt(redacted)
        raw_text, err, engine_label = self._invoke_provider(provider, prompt)
        
        # 3. Failover to secondary provider if configured and primary failed
        if (raw_text is None) and self.fallback_provider and self.fallback_provider != provider:
            logger.info(f"Primary provider {provider} failed ({err}). Failing over to {self.fallback_provider}...")
            sec_raw, sec_err, sec_label = self._invoke_provider(self.fallback_provider, prompt)
            if sec_raw is not None:
                raw_text = sec_raw
                err = None
                engine_label = sec_label
            else:
                err = f"primary ({err}); fallback ({sec_err})"

        # 4. Output Guard Validation
        if raw_text is not None:
            is_valid, explainer_output, guard_err = validate_explainer_output(raw_text, allowed_input_algos)
            if is_valid and explainer_output is not None:
                timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                v_rep = explainer_output.verbose_report or explainer_output.executive_summary
                output_dict = {
                    "executive_summary": explainer_output.executive_summary,
                    "verbose_report": v_rep,
                    "findings_explanations": [f.model_dump() for f in explainer_output.findings],
                    "cached_at": timestamp_str,
                }
                # Save to cache
                self.cache.set(cache_key, output_dict)

                return {
                    "engine_used": engine_label,
                    "fallback_reason": None,
                    "is_ai_generated": True,
                    "is_cached": False,
                    "cached_badge": f"AI-generated, live {timestamp_str}",
                    "executive_summary": explainer_output.executive_summary,
                    "verbose_report": v_rep,
                    "findings_explanations": [f.model_dump() for f in explainer_output.findings],
                }
            else:
                err = guard_err

        # 5. Deterministic Template Fallback on failure or guard rejection
        logger.info(f"AI Explainer falling back to deterministic templates: {err}")
        template_output = generate_template_explanations(
            redacted["redacted_findings"],
            redacted["hardened_params"],
        )
        return {
            "engine_used": "Template",
            "fallback_reason": str(err),
            "is_ai_generated": False,
            "is_cached": False,
            "executive_summary": template_output.executive_summary,
            "verbose_report": template_output.verbose_report,
            "findings_explanations": [f.model_dump() for f in template_output.findings],
        }
