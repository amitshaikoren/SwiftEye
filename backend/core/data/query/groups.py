"""
Per-capture group store — tag / color / cluster / set snapshots.

Parallel to `NamedSetStore`, but stores ALL four group-producing verbs
(`tag`, `color`, `cluster`, `save_as_set`) together with the slice of the
recipe that produced them, so the frontend "Groups" tab can show both the
members and the recipe context.

Lifetime: in-memory, per-capture. Cleared on fresh capture load and on
server restart. Not persisted to disk.

Shape (`list_all`):
    {
        "tag":     {name: entry, ...},
        "color":   {name: entry, ...},
        "cluster": {name: entry, ...},
        "set":     {name: entry, ...},
    }

Entry:
    {
        "target":     "nodes" | "edges",
        "members":    [id, ...],
        "recipe":     [step_payload, ...],   # steps 0..N where N produced this group
        "group_args": dict | None,           # e.g. {"color": "#79c0ff"} for the color verb
        "created_at": float,                 # unix seconds
    }
"""

from __future__ import annotations

import time
from typing import Iterable, Optional


KINDS = ("tag", "color", "cluster", "set")

# Map pipeline verbs → store kinds. `save_as_set` is stored under "set".
VERB_TO_KIND = {
    "tag": "tag",
    "color": "color",
    "cluster": "cluster",
    "save_as_set": "set",
}


class GroupStore:
    def __init__(self):
        self._groups: dict[str, dict[str, dict]] = {k: {} for k in KINDS}

    def _next_suffixed(self, kind: str, base: str) -> str:
        """Find `base (2)`, `base (3)`, ... that isn't taken. Used by manual PUT."""
        bucket = self._groups.setdefault(kind, {})
        if base not in bucket:
            return base
        n = 2
        while f"{base} ({n})" in bucket:
            n += 1
        return f"{base} ({n})"

    def record(self, kind: str, name: str, target: str,
               members: Iterable, recipe: list, group_args: Optional[dict] = None) -> str:
        """Upsert a group from pipeline run. Overwrites on duplicate name.

        Returns the name actually used (equal to `name` in the pipeline path
        since we don't suffix there; callers that want suffix behavior should
        call `record_suffixed`).
        """
        if kind not in KINDS:
            raise ValueError(f"unknown kind {kind!r}; want one of {KINDS}")
        if not name:
            raise ValueError("group requires a non-empty name")
        if target not in ("nodes", "edges", "sessions"):
            raise ValueError(f"target must be 'nodes', 'edges', or 'sessions', got {target!r}")
        entry = {
            "target": target,
            "members": [str(m) for m in members],
            "recipe": list(recipe or []),
            "group_args": dict(group_args) if group_args else None,
            "created_at": time.time(),
        }
        self._groups.setdefault(kind, {})[name] = entry
        return name

    def record_suffixed(self, kind: str, name: str, target: str,
                        members: Iterable, recipe: list,
                        group_args: Optional[dict] = None) -> str:
        """Like `record`, but if `name` exists, append `(2)`, `(3)`, ... instead."""
        actual = self._next_suffixed(kind, name)
        return self.record(kind, actual, target, members, recipe, group_args)

    def get(self, kind: str, name: str) -> Optional[dict]:
        """Lookup by (kind, name). Returns None if missing."""
        if kind not in KINDS or not name:
            return None
        return self._groups.get(kind, {}).get(name)

    def delete(self, kind: str, name: str) -> bool:
        if kind not in KINDS:
            return False
        return self._groups.get(kind, {}).pop(name, None) is not None

    def clear(self) -> None:
        self._groups = {k: {} for k in KINDS}

    def list_all(self) -> dict:
        """Deep-ish snapshot safe to serialise."""
        out = {}
        for kind in KINDS:
            out[kind] = {
                name: {
                    "target": e["target"],
                    "members": list(e["members"]),
                    "recipe": list(e["recipe"]),
                    "group_args": dict(e["group_args"]) if e.get("group_args") else None,
                    "created_at": e["created_at"],
                }
                for name, e in self._groups.get(kind, {}).items()
            }
        return out
