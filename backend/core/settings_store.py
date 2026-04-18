"""
App-level settings store — persists cross-cutting single-machine
preferences to a JSON file on the server (not browser localStorage).

File: <backend_dir>/settings.json. Gitignored. Never included in exports.

Separate from `core/llm/key_store.py` — that one holds LLM-provider
credentials; this one holds application state (currently: which
workspace the user selected). Kept apart so an LLM reset doesn't nuke
workspace selection and vice versa.

Schema (all fields optional, merged over defaults on load):
  {
    "active_workspace": "network" | "forensic" | null
  }
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("swifteye.settings_store")

_FILE = Path(__file__).resolve().parent.parent / "settings.json"

_DEFAULTS: Dict[str, Any] = {
    "active_workspace": None,
}


def load() -> Dict[str, Any]:
    """Return stored settings merged over defaults. Never raises."""
    if not _FILE.exists():
        return dict(_DEFAULTS)
    try:
        with _FILE.open("r", encoding="utf-8") as f:
            stored = json.load(f)
        return {**_DEFAULTS, **{k: v for k, v in stored.items() if k in _DEFAULTS}}
    except Exception as e:
        logger.warning(f"Could not read settings.json: {e}")
        return dict(_DEFAULTS)


def save(patch: Dict[str, Any]) -> None:
    """Merge `patch` into stored settings. Only known keys are saved."""
    current = load()
    for k in _DEFAULTS:
        if k in patch:
            current[k] = patch[k]
    try:
        with _FILE.open("w", encoding="utf-8") as f:
            json.dump(current, f, indent=2)
    except Exception as e:
        logger.warning(f"Could not write settings.json: {e}")


def get_active_workspace() -> Optional[str]:
    return load().get("active_workspace")


def set_active_workspace(name: Optional[str]) -> None:
    save({"active_workspace": name})
