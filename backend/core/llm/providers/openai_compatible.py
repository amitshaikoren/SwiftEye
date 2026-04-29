"""
OpenAI-compatible provider adapter.
Works with OpenAI itself and any gateway that speaks the OpenAI chat/completions API.
Streams via the standard SSE "data: {...}" format.
"""

from __future__ import annotations
import json
import logging
import urllib.request
import urllib.error
from typing import Iterator

from .base import ProviderAdapter

logger = logging.getLogger("swifteye.llm.openai_compatible")

_DEFAULT_BASE_URL = "https://api.openai.com/v1"


class OpenAICompatibleAdapter(ProviderAdapter):

    def stream_chat(
        self,
        system_prompt: str,
        user_content: str,
        config,
    ) -> Iterator[str]:
        base_url = (config.base_url or _DEFAULT_BASE_URL).rstrip("/")
        url = f"{base_url}/chat/completions"

        payload = {
            "model": config.model,
            "stream": True,
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_content},
            ],
        }

        headers = {"Content-Type": "application/json"}
        if config.api_key:
            headers["Authorization"] = f"Bearer {config.api_key}"

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                for raw_line in resp:
                    line = raw_line.decode("utf-8").strip()
                    if not line or line == "data: [DONE]":
                        continue
                    if line.startswith("data: "):
                        line = line[len("data: "):]
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    choices = obj.get("choices", [])
                    if not choices:
                        continue
                    delta = choices[0].get("delta", {}).get("content", "")
                    if delta:
                        yield delta
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise ConnectionError(f"OpenAI API error {e.code}: {body}") from e
        except urllib.error.URLError as e:
            raise ConnectionError(f"Provider connection failed ({url}): {e}") from e

    def supports_json_mode(self) -> bool:
        return True
