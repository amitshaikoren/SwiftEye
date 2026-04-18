"""
Workspace ABC + registry.

A workspace is a self-contained data-domain pack: parser(s), schema, aggregation
policies, plugins, research charts, and (frontend side) node/edge field
renderers. The engine consumes whatever the active workspace declares.

Phase 1 usage: `NetworkWorkspace` is the only registered workspace and is
resolved by default. Phases 2+ introduce typed schema, a workspace selector,
and additional workspaces (forensic first).

See `llm_docs/plans/active/forensic-workspace.md` for the full architecture.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, Optional

from core.schema import WorkspaceSchema


class Workspace(ABC):
    """Abstract base for a data-domain workspace.

    Concrete subclasses live under `backend/workspaces/<name>/__init__.py` and
    call `register(MyWorkspace())` at import time. Phase 2 adds the `schema`
    property: every workspace must declare its node/edge field catalog so that
    core code (display filter evaluator, FilterBar) can stay domain-agnostic.
    """

    #: Short stable identifier used in URLs, settings, and doc mirrors.
    name: str = ""

    #: Human-readable label for UI.
    label: str = ""

    @abstractmethod
    def activate(self) -> None:
        """Called when this workspace becomes active. Wire up parser + store."""
        raise NotImplementedError

    @property
    @abstractmethod
    def schema(self) -> WorkspaceSchema:
        """Typed declaration of this workspace's node- and edge-field catalog."""
        raise NotImplementedError


_WORKSPACES: Dict[str, Workspace] = {}
_ACTIVE_NAME: Optional[str] = None


def register(ws: Workspace) -> None:
    """Register a workspace by its `name`. Idempotent on the same instance."""
    if not ws.name:
        raise ValueError("Workspace must declare a non-empty name")
    existing = _WORKSPACES.get(ws.name)
    if existing is not None and existing is not ws:
        raise ValueError(f"Workspace '{ws.name}' already registered with a different instance")
    _WORKSPACES[ws.name] = ws


def get_workspace(name: str) -> Workspace:
    try:
        return _WORKSPACES[name]
    except KeyError as e:
        raise KeyError(f"Unknown workspace '{name}'. Registered: {sorted(_WORKSPACES)}") from e


def list_workspaces() -> Dict[str, Workspace]:
    return dict(_WORKSPACES)


def set_active(name: str) -> Workspace:
    global _ACTIVE_NAME
    ws = get_workspace(name)
    _ACTIVE_NAME = name
    ws.activate()
    return ws


def get_active_workspace() -> Workspace:
    if _ACTIVE_NAME is None:
        raise RuntimeError("No active workspace. Call set_active(name) during server startup.")
    return _WORKSPACES[_ACTIVE_NAME]


def active_name() -> Optional[str]:
    return _ACTIVE_NAME
