from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional


DEFAULT_BASE_URL = os.environ.get("Z0BDBG_LLM_BASE_URL", "http://127.0.0.1:8080")
DEFAULT_MODEL = os.environ.get("Z0BDBG_LLM_MODEL", "local-model")


class LocalLlmClient:
    def __init__(self, base_url: str = DEFAULT_BASE_URL, model: str = DEFAULT_MODEL, timeout: float = 20.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def status(self) -> Dict[str, Any]:
        health_url = self.base_url + "/health"
        try:
            with urllib.request.urlopen(health_url, timeout=2.0) as response:
                body = response.read().decode("utf-8", "replace")
            return {"ok": True, "baseUrl": self.base_url, "model": self.model, "health": body[:200]}
        except Exception as exc:
            return {"ok": False, "baseUrl": self.base_url, "model": self.model, "error": str(exc)}

    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.2, max_tokens: int = 512) -> str:
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            self.base_url + "/v1/chat/completions",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            raise RuntimeError("llm http error %s: %s" % (exc.code, detail[:500]))
        result = json.loads(raw)
        choices = result.get("choices") or []
        if not choices:
            return raw
        message = choices[0].get("message") or {}
        return str(message.get("content") or "")


def build_debug_analysis_prompt(context: Dict[str, Any], matches: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, str]]:
    compact = json.dumps(context, ensure_ascii=False, indent=2)[:12000]
    match_text = json.dumps(matches or [], ensure_ascii=False, indent=2)[:4000]
    return [
        {
            "role": "system",
            "content": (
                "You are a local debugging assistant for Z0BDbg. "
                "Be concise. Prefer concrete next debugger actions. "
                "Do not invent facts that are not present in the context."
            ),
        },
        {
            "role": "user",
            "content": (
                "Analyze this debug state and recommend the next steps.\n\n"
                "Debug context:\n%s\n\nSimilar local cases:\n%s"
            )
            % (compact, match_text),
        },
    ]
