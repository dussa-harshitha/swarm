"""LLM Router: watsonx.ai primary, Ollama local fallback, Mock for tests.
Tier: 'small' (plan/critique/synthesize) vs 'micro' (extract/summarize/match).
"""
from __future__ import annotations
import os, time, asyncio
import httpx

class LLMError(RuntimeError): ...

class MockLLM:
    """Deterministic canned responses keyed by role, for tests and offline dev."""
    def __init__(self, script: dict[str, list[str]] | None = None):
        self.script = script or {}
        self.calls: list[dict] = []
    async def chat(self, role: str, system: str, user: str, tier: str = "micro") -> tuple[str, int]:
        self.calls.append({"role": role, "tier": tier, "user": user[:200]})
        queue = self.script.get(role)
        if not queue:
            raise LLMError(f"MockLLM: no scripted response for role '{role}'")
        out = queue.pop(0) if len(queue) > 1 else queue[0]
        return out, max(1, len(out) // 4)

class OllamaLLM:
    def __init__(self, base: str = "http://localhost:11434",
                 small: str = "granite4:small", micro: str = "granite4:micro"):
        self.base, self.small, self.micro = base, small, micro
    async def chat(self, role: str, system: str, user: str, tier: str = "micro") -> tuple[str, int]:
        model = self.small if tier == "small" else self.micro
        async with httpx.AsyncClient(timeout=180) as c:
            r = await c.post(f"{self.base}/api/chat", json={
                "model": model, "stream": False,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
            r.raise_for_status()
            obj = r.json()
        text = obj.get("message", {}).get("content", "")
        tokens = obj.get("eval_count", len(text) // 4)
        return text, tokens

class WatsonxLLM:
    """watsonx.ai chat via REST. Requires env: WATSONX_APIKEY, WATSONX_PROJECT_ID, WATSONX_URL.
    Model ids configurable; verify availability in your region during the spike."""
    IAM = "https://iam.cloud.ibm.com/identity/token"
    def __init__(self,
                 small: str = os.getenv("WATSONX_MODEL_SMALL", "ibm/granite-4-h-small"),
                 micro: str = os.getenv("WATSONX_MODEL_MICRO", "ibm/granite-4-h-micro")):
        self.apikey = os.getenv("WATSONX_APIKEY")
        self.project = os.getenv("WATSONX_PROJECT_ID")
        self.url = os.getenv("WATSONX_URL", "https://us-south.ml.cloud.ibm.com")
        self.small, self.micro = small, micro
        self._token, self._exp = None, 0.0
        if not (self.apikey and self.project):
            raise LLMError("watsonx credentials missing: set WATSONX_APIKEY and WATSONX_PROJECT_ID")
    async def _bearer(self, c: httpx.AsyncClient) -> str:
        if self._token and time.time() < self._exp - 60:
            return self._token
        r = await c.post(self.IAM, data={
            "grant_type": "urn:ibm:params:oauth:grant-type:apikey", "apikey": self.apikey},
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        r.raise_for_status()
        obj = r.json()
        self._token, self._exp = obj["access_token"], time.time() + obj.get("expires_in", 3600)
        return self._token
    async def chat(self, role: str, system: str, user: str, tier: str = "micro") -> tuple[str, int]:
        model = self.small if tier == "small" else self.micro
        async with httpx.AsyncClient(timeout=120) as c:
            tok = await self._bearer(c)
            r = await c.post(
                f"{self.url}/ml/v1/text/chat?version=2024-05-31",
                headers={"Authorization": f"Bearer {tok}"},
                json={"model_id": model, "project_id": self.project,
                      "messages": [{"role": "system", "content": system},
                                   {"role": "user", "content": user}],
                      "max_tokens": 2000})
            r.raise_for_status()
            obj = r.json()
        choice = obj["choices"][0]["message"]["content"]
        usage = obj.get("usage", {}).get("total_tokens", len(choice) // 4)
        return choice, usage

class Router:
    """Primary/fallback routing + a global rate limiter (watsonx Lite = 2 rps)."""
    def __init__(self, primary, fallback=None, rps: float = 2.0):
        self.primary, self.fallback = primary, fallback
        self._min_gap = 1.0 / rps
        self._last = 0.0
        self._lock = asyncio.Lock()
        self.total_tokens = 0
    async def chat(self, role: str, system: str, user: str, tier: str = "micro") -> tuple[str, int]:
        async with self._lock:
            wait = self._min_gap - (time.monotonic() - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()
        try:
            text, toks = await self.primary.chat(role, system, user, tier)
        except Exception:
            if self.fallback is None:
                raise
            text, toks = await self.fallback.chat(role, system, user, tier)
        self.total_tokens += toks
        return text, toks
