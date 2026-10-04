import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
import hashlib
import threading
from typing import Optional, Dict, Any, List, Tuple
from .schema import (
    LLMInferenceResponse,
    ModeAndTrafficInferenceRequest,
    ModeInferenceResult,
    TrafficInferenceResult,
)

logger = logging.getLogger(__name__)


class GeminiClientConfig:
    def __init__(self):
        self.enable_cloud_llm = os.getenv("ENABLE_CLOUD_LLM", "false").lower() in ("true", "1", "yes")
        raw_key = os.getenv("GEMINI_API_KEY") or os.getenv("AI_API_KEY") or ""
        self.api_key = raw_key.strip().strip("'\"").strip()
        raw_model = os.getenv("GEMINI_MODEL") or "gemini-2.5-flash"
        self.model = raw_model.strip().strip("'\"").strip()
        self.timeout_seconds = float(os.getenv("GEMINI_TIMEOUT_SECONDS", "30.0"))
        
        # New requirements
        self.max_rpm = int(os.getenv("GEMINI_MAX_RPM", "5"))
        fallbacks_env = os.getenv("GEMINI_FALLBACK_MODELS", "")
        self.fallback_models = [m.strip().strip("'\"") for m in fallbacks_env.split(",") if m.strip()]

    def validate(self) -> bool:
        if not self.enable_cloud_llm:
            return False
        if not self.api_key:
            return False
        return True


class GeminiClient:
    """Central wrapper for Gemini API calls."""
    
    _lock = threading.Lock()
    _in_flight = False
    
    # Global state for rate limiting and circuit breaker
    _request_times: List[float] = []
    _model_cooldowns: Dict[str, float] = {}
    _quota_exhausted_until = 0.0
    _last_error_kind: Optional[str] = None
    
    _CACHE_FILE = "backend/data/ai_cache.json"

    @classmethod
    def _load_cache(cls) -> Dict[str, str]:
        if not os.path.exists("backend/data"):
            os.makedirs("backend/data", exist_ok=True)
        if not os.path.exists(cls._CACHE_FILE):
            return {}
        try:
            with open(cls._CACHE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    @classmethod
    def _save_cache(cls, cache: Dict[str, str]):
        try:
            # Simple bounded cache size
            if len(cache) > 1000:
                keys = list(cache.keys())
                for k in keys[:-500]:
                    del cache[k]
            with open(cls._CACHE_FILE, "w") as f:
                json.dump(cache, f)
        except Exception as e:
            logger.error(f"Error saving AI cache: {e}")

    @classmethod
    def get_status(cls) -> Dict[str, Any]:
        config = GeminiClientConfig()
        models = [config.model] + config.fallback_models if config.model else []
        models = list(dict.fromkeys([m for m in models if m]))
        
        now = time.time()
        cooldowns = {m: max(0, int(t - now)) for m, t in cls._model_cooldowns.items() if t > now}
        global_cooldown = max(0, int(cls._quota_exhausted_until - now))
        
        return {
            "enabled": config.enable_cloud_llm and bool(config.api_key),
            "cooling_down_until": global_cooldown if global_cooldown > 0 else cooldowns,
            "models": models,
            "last_error_kind": cls._last_error_kind
        }

    def _call_gemini_api(self, prompt: str, budget_seconds: float = 20.0) -> Optional[str]:
        config = GeminiClientConfig()
        if not config.validate():
            logger.info("Cloud LLM disabled by policy")
            return None

        # Cache check
        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        with self._lock:
            cache = self._load_cache()
            if prompt_hash in cache:
                return cache[prompt_hash]

        models_to_try = [config.model] + config.fallback_models
        models_to_try = list(dict.fromkeys([m for m in models_to_try if m]))

        with self._lock:
            if self._in_flight:
                logger.warning("Gemini request dropped: another request is in-flight.")
                return None
            self.__class__._in_flight = True

        try:
            result = self._execute_request(prompt, models_to_try, config.api_key, config.timeout_seconds, config.max_rpm)
            if result:
                with self._lock:
                    cache = self._load_cache()
                    cache[prompt_hash] = result
                    self._save_cache(cache)
            return result
        finally:
            with self._lock:
                self.__class__._in_flight = False

    def _execute_request(self, prompt: str, models: List[str], api_key: str, timeout: float, max_rpm: int) -> Optional[str]:
        now = time.time()
        if now < self._quota_exhausted_until:
            logger.warning("Gemini API is currently disabled due to quota exhaustion.")
            return None

        # RPM Check
        self.__class__._request_times = [t for t in self._request_times if now - t < 60]
        if len(self._request_times) >= max_rpm:
            logger.warning("Gemini max RPM reached.")
            return None

        request_body = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode("utf-8")

        for model in models:
            now = time.time()
            if now < self._model_cooldowns.get(model, 0):
                continue

            for attempt in range(2):
                now = time.time()
                self.__class__._request_times = [t for t in self._request_times if now - t < 60]
                if len(self._request_times) >= max_rpm:
                    logger.warning("Gemini max RPM reached mid-attempt.")
                    return None

                self.__class__._request_times.append(time.time())
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
                req = urllib.request.Request(
                    url,
                    data=request_body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )

                try:
                    with urllib.request.urlopen(req, timeout=timeout) as response:
                        body = response.read().decode("utf-8")
                        self.__class__._last_error_kind = None
                        return self._extract_response_text(body)
                except urllib.error.HTTPError as e:
                    body = ""
                    try:
                        body = e.read().decode("utf-8", errors="replace")
                    except Exception:
                        pass
                    
                    if e.code == 429 or e.code == 503:
                        retry_after = e.headers.get('Retry-After')
                        if "quota" in body.lower() or "exhausted" in body.lower() or "limit" in body.lower():
                            logger.error(f"Gemini quota exhausted; AI features using rules fallback until {time.strftime('%H:%M:%S', time.localtime(time.time() + 900))}")
                            self.__class__._quota_exhausted_until = time.time() + 900
                            self.__class__._last_error_kind = "quota_exhausted"
                            return None
                        
                        cooldown_secs = 60
                        if retry_after and retry_after.isdigit():
                            cooldown_secs = int(retry_after)
                            
                        self.__class__._last_error_kind = f"http_{e.code}"
                        
                        if attempt == 0:
                            # Instead of a long block, we just apply backoff or wait if small. 
                            # But instruction says: "honor Retry-After; per-model 60s cooldown after a 429"
                            # Fast fail beats waiting.
                            self.__class__._model_cooldowns[model] = time.time() + cooldown_secs
                            break # Skip to next model
                    
                    elif e.code == 404:
                        break # Skip to next model
                    
                    else:
                        self.__class__._last_error_kind = f"http_{e.code}"
                        return None
                        
                except Exception as e:
                    self.__class__._last_error_kind = "connection_error"
                    return None

        # If we got here, all models failed or are on cooldown
        logger.warning("All Gemini models exhausted or cooling down. API inference unavailable.")
        return None

    @staticmethod
    def _extract_response_text(api_response: str) -> Optional[str]:
        try:
            data = json.loads(api_response)
            candidates = data.get("candidates", [])
            if not candidates:
                return None
            return candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
        except json.JSONDecodeError:
            return None

    def infer_mode_and_traffic(self, request: ModeAndTrafficInferenceRequest) -> Optional[LLMInferenceResponse]:
        # Never used in live path anymore, but kept for compatibility if needed.
        return None
