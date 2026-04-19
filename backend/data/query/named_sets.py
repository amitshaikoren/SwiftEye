"""
Per-capture named-set store.

A *named set* is a snapshot of matched IDs saved under an `@name` so that
later pipeline steps — in the same recipe or a future session — can refer
to the group by name via the `in_set` operator (`IN @name` in Cypher/SQL).

Shape on disk and over the wire:
    {name: {"target": "nodes"|"edges", "members": [id, ...]}}

Scope:
    Lives on `CaptureStore` and is cleared whenever a new capture loads —
    named sets are meaningful only for the capture they were defined on.
    On-disk persistence is not wired yet; `to_dict` / `from_dict` expose
    the shape the eventual persistence layer will use.
"""

from typing import Iterable


class NamedSetStore:
    """In-memory `@name → {target, members}` map, one instance per capture."""

    def __init__(self):
        self._sets: dict[str, dict] = {}

    def set(self, name: str, target: str, members: Iterable) -> dict:
        """Create or replace the set `name`. Members are coerced to a unique list of str."""
        if not name:
            raise ValueError("Named set requires a non-empty name")
        if target not in ("nodes", "edges"):
            raise ValueError(f"target must be 'nodes' or 'edges', got {target!r}")
        seen = set()
        unique_members: list[str] = []
        for m in members:
            s = str(m)
            if s not in seen:
                seen.add(s)
                unique_members.append(s)
        entry = {"target": target, "members": unique_members}
        self._sets[name] = entry
        return entry

    def get(self, name: str) -> dict | None:
        return self._sets.get(name)

    def delete(self, name: str) -> bool:
        return self._sets.pop(name, None) is not None

    def clear(self) -> None:
        self._sets.clear()

    def list_all(self) -> dict[str, dict]:
        """Snapshot of all sets. Returns a shallow copy safe to serialise."""
        return {k: {"target": v["target"], "members": list(v["members"])}
                for k, v in self._sets.items()}

    def as_context(self) -> dict[str, dict]:
        """Shape consumed by `resolve_query(..., named_sets=...)`."""
        return self._sets

    def to_dict(self) -> dict:
        return self.list_all()

    def from_dict(self, data: dict) -> None:
        self._sets.clear()
        for name, entry in (data or {}).items():
            if isinstance(entry, dict) and "target" in entry and "members" in entry:
                self.set(name, entry["target"], entry["members"])
