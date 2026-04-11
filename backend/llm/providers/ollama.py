"""
Ollama provider adapter.
Streams from the Ollama /api/chat endpoint (newline-delimited JSON).
No API key required — just a base URL (default: http://localhost:11434).
"""

from __future__ import annotations
import json
import logging
import urllib.request
import urllib.error
from typing import Iterator

from .base import ProviderAdapter

logger = logging.getLogger("swifteye.llm.ollama")

_DEFAULT_BASE_URL = "http://localhost:11434"


class OllamaAdapter(ProviderAdapter):

    def stream_chat(
        self,
        system_prompt: str,
        user_content: str,
        config,
    ) -> Iterator[str]:
        base_url = (config.base_url or _DEFAULT_BASE_URL).rstrip("/")
        url = f"{base_url}/api/chat"

        payload = {
            "model": config.model,
            "stream": True,
            "options": {
                "temperature": config.temperature,
                "num_predict": config.max_tokens,
            },
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_content},
            ],
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                for raw_line in resp:
                    line = raw_line.decode("utf-8").strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    delta = obj.get("message", {}).get("content", "")
                    if delta:
                        yield delta
                    if obj.get("done"):
                        break
        except urllib.error.URLError as e:
            raise ConnectionError(f"Ollama connection failed ({url}): {e}") from e
