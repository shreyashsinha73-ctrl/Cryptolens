"""Plain-language hardening advice from findings only (no PCAP, no payload, no raw IPs)."""

import hashlib
import json
import logging
import os
import re
import threading
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError

logger = logging.getLogger(__name__)

TOTAL_TIMEOUT_SECONDS = 25.0
GEMINI_BUDGET_SECONDS = 20.0
MIN_POINTS, MAX_POINTS = 5, 8

_FINDING_FIELDS = ("finding_id", "severity", "category", "title", "observed_value", "observability", "evidence_source")
_CP_FIELDS = ("ike_version", "encryption_algorithm", "integrity", "dh_group", "pfs_enabled", "key_lifetime_seconds", "operating_mode")

_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b")
_HOST = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:[a-zA-Z]{2,})\b")


class AdvicePoint(BaseModel):
    model_config = ConfigDict(extra="forbid")
    priority: Literal["high", "medium", "low"]
    title: str = Field(min_length=1)
    problem: str = Field(min_length=1)
    why_it_matters: str = Field(min_length=1)
    how_to_fix: str = Field(min_length=1)


class HardeningAdvice(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(min_length=1)
    points: List[AdvicePoint] = Field(min_length=MIN_POINTS, max_length=MAX_POINTS)
    not_observable_note: str = ""


def redact(text: Any) -> Any:
    if not isinstance(text, str):
        return text
    text = _IPV4.sub("[ip]", text)
    text = _IPV6.sub("[ip]", text)
    return _HOST.sub("[host]", text)


def build_input(result: Dict[str, Any]) -> Dict[str, Any]:
    findings = []
    for f in result.get("threat_matrix") or result.get("findings") or []:
        findings.append({k: redact(f.get(k)) for k in _FINDING_FIELDS if k in f})
    cp = result.get("control_plane") or {}
    cp_out = {}
    for k in _CP_FIELDS:
        src = "integrity_algorithm" if k == "integrity" and k not in cp else k
        if src in cp:
            cp_out[k] = redact(cp[src])
    return {"threat_matrix": findings, "control_plane": cp_out}


def input_hash(data: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()


_BASELINE = [
    ("Use a strong authenticated cipher", "Baseline best practice (not from this capture)",
     "Older ciphers can be broken with enough effort, exposing what you send.",
     "Switch the tunnel to AES-GCM (AES-256-GCM if available) on both sides."),
    ("Turn on Perfect Forward Secrecy with a strong group", "Baseline best practice (not from this capture)",
     "Without it, one stolen key can unlock past and future traffic.",
     "Enable PFS and choose a modern Diffie-Hellman group (group 14 or higher, or an elliptic-curve group)."),
    ("Prefer IKEv2", "Baseline best practice (not from this capture)",
     "IKEv2 is simpler and has fewer known weaknesses than IKEv1.",
     "Configure both gateways to use IKEv2 only and turn IKEv1 off."),
    ("Keep replay protection on", "Baseline best practice (not from this capture)",
     "Replay protection stops an attacker from re-sending recorded packets.",
     "Make sure the anti-replay window is enabled on both ends."),
    ("Shorten key lifetimes", "Baseline best practice (not from this capture)",
     "Keys that live a long time give an attacker more data and more time to attack them.",
     "Rekey at least every few hours and well before large volumes of data are sent."),
    ("Review what the capture could not show", "Baseline best practice (not from this capture)",
     "Some settings are invisible in a capture, so they may still be weak.",
     "Check the gateway settings directly for anything marked not observable."),
    ("Plan for post-quantum readiness", "Baseline best practice (not from this capture)",
     "Future quantum computers may break today's key exchange.",
     "Follow your vendor's roadmap for post-quantum key exchange and update when available."),
    ("Keep gateway software updated", "Baseline best practice (not from this capture)",
     "Old software often has known, fixable security holes.",
     "Apply vendor security updates on a regular schedule."),
]


def _priority(sev: Any) -> str:
    s = str(sev or "").upper()
    if s in ("CRITICAL", "HIGH"):
        return "high"
    if s in ("MEDIUM", "MODERATE", "WARNING"):
        return "medium"
    return "low"


def rules_advice(data: Dict[str, Any]) -> Dict[str, Any]:
    points: List[Dict[str, str]] = []
    unobservable = []
    for f in data["threat_matrix"]:
        sev = str(f.get("severity") or "").upper()
        obs = str(f.get("observability") or "observed").lower()
        title = str(f.get("title") or f.get("finding_id") or "Finding")
        val = f.get("observed_value")
        if obs in ("unobserved", "unknown", "not_observable"):
            unobservable.append(title)
            continue
        if sev in ("INFO", "PASS", "") or len(points) >= MAX_POINTS:
            continue
        label = "seen on the wire" if obs == "observed" else f"reported as '{obs}', not seen directly on the wire"
        points.append({
            "priority": _priority(sev),
            "title": title,
            "problem": f"In this capture, '{title}' was found" + (f" (value: {val})" if val not in (None, "") else "")
                       + f" and is {label}.",
            "why_it_matters": "This setting weakens the protection of the tunnel and makes it easier to attack.",
            "how_to_fix": "Change this setting on both tunnel endpoints to a modern, recommended option, then capture again to confirm.",
        })
    order = {"high": 0, "medium": 1, "low": 2}
    points.sort(key=lambda p: order[p["priority"]])
    for t, prob, why, fix in _BASELINE:
        if len(points) >= MIN_POINTS:
            break
        points.append({"priority": "low", "title": t, "problem": prob, "why_it_matters": why, "how_to_fix": fix})
    n_real = sum(1 for p in points if not p["problem"].startswith("Baseline"))
    return {
        "summary": (f"We found {n_real} issue(s) in this capture based on handshake metadata only; nothing was decrypted. "
                    "Items marked as baseline are general good practice, not something seen in this capture."),
        "points": points,
        "not_observable_note": ("Could not be checked from the capture: " + "; ".join(unobservable[:8]) + ".")
        if unobservable else "Anything not shown in the handshake metadata could not be checked.",
    }


_PROMPT = """You are a network security advisor writing for a non-expert.
Using ONLY the findings below (metadata from an IPsec capture; nothing was decrypted), return JSON only, no markdown:
{{"summary":"2-3 plain sentences","points":[{{"priority":"high|medium|low","title":"short","problem":"what we saw in THIS capture, simple words","why_it_matters":"plain English, no jargon","how_to_fix":"concrete steps in simple words"}}],"not_observable_note":"what could not be checked"}}
Rules: between 5 and 8 points. Each point must be tied to a finding below, or be a baseline best practice whose problem field starts with "Baseline best practice". No vendor configuration snippets or code. Never claim anything was decrypted. Do not describe inferred or testbed_config values as wire-observed (respect each finding's observability and evidence_source). Be verbose but easy to understand.
INPUT:
{payload}
"""


def _strip_json(text: str) -> str:
    text = (text or "").strip()
    return re.sub(r"^```(?:json)?|```$", "", text, flags=re.M).strip()


def _gemini_advice(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    from backend.engine.llm_client.client import GeminiClient
    client = GeminiClient()
    if not client.config.validate():
        return None
    prompt = _PROMPT.format(payload=json.dumps(data))
    for _ in range(2):  # one retry on invalid output
        raw = client._call_gemini_api(prompt, budget_seconds=GEMINI_BUDGET_SECONDS)
        if not raw:
            return None
        try:
            return HardeningAdvice.model_validate(json.loads(_strip_json(raw))).model_dump()
        except (ValueError, ValidationError):
            logger.warning("Gemini advice invalid, retrying once")
    return None


_CACHE: Dict[str, Dict[str, Any]] = {}
_LOCK = threading.Lock()


def get_advice_sync(result: Dict[str, Any]) -> Dict[str, Any]:
    data = build_input(result)
    h = input_hash(data)
    cfg_model = os.getenv("GEMINI_MODEL", "").strip().strip("'\"") or "gemini-2.5-flash"
    with _LOCK:
        if h in _CACHE:
            return _CACHE[h]
    advice = None
    try:
        advice = _gemini_advice(data)
    except Exception as exc:  # never fail the feature
        logger.warning("Gemini advice failed: %s", type(exc).__name__)
    if advice:
        out = {"source": "gemini", "model": cfg_model, "advice": advice}
    else:
        out = {"source": "rules", "model": "rules-v1", "advice": rules_advice(data)}
    with _LOCK:
        _CACHE[h] = out
    return out
