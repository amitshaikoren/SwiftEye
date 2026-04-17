"""
LLM key store — persists provider configuration (including API keys) to a
local JSON file on the server rather than browser localStorage.

File location: <backend_dir>/llm_keys.json
This file is gitignored. It is never included in exports or uploads.

Schema (all fields optional, merged over defaults on load):
  {
    "provider":    "ollama" | "openai" | "openai_compatible",
    "model":       "<model name>",
    "base_url":    "<url or empty string>",
    "api_key":     "<key or empty string>",
    "temperature": 0.2,
    "max_tokens":  1400
  }
"""

from __future__ import annotations
import json
import logging
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger("swifteye.llm.key_store")

_KEY_FILE = Path(__file__).resolve().parent.parent / "llm_keys.json"

_DEFAULTS: Dict[str, Any] = {
    "provider":    "ollama",
    "model":       "qwen2.5:14b-instruct",
    "base_url":    "",
    "api_key":     "",
    "temperature": 0.2,
    "max_tokens":  1400,
}


def load() -> Dict[str, Any]:
    """Return stored config merged over defaults. Never raises."""
    if not _KEY_FILE.exists():
        return dict(_DEFAULTS)
    try:
        with _KEY_FILE.open("r", encoding="utf-8") as f:
            stored = json.load(f)
        return {**_DEFAULTS, **{k: v for k, v in stored.items() if k in _DEFAULTS}}
    except Exception as e:
        logger.warning(f"Could not read llm_keys.json: {e}")
        return dict(_DEFAULTS)


def save(config: Dict[str, Any]) -> None:
    """Persist config to file. Only known keys are saved."""
    current = load()
    for k in _DEFAULTS:
        if k in config:
            current[k] = config[k]
    try:
        with _KEY_FILE.open("w", encoding="utf-8") as f:
            json.dump(current, f, indent=2)
    except Exception as e:
        logger.warning(f"Could not write llm_keys.json: {e}")
