"""
Workspace routes.

GET  /api/workspace/schema
    Returns the active workspace's typed schema (node types, edge types,
    and their field catalogs). The frontend fetches this once on app load
    and caches it in WorkspaceProvider; the display-filter evaluator and
    FilterBar suggestions read from it instead of hardcoding field names.
    Returns 409 if no workspace is active (selector hasn't run yet).

GET  /api/workspace/current
    Returns `{active, available}`. `active` is the selected workspace name
    or `null` if the user hasn't picked one yet. `available` lists every
    registered workspace (`{name, label}` rows) so the frontend can render
    the selector.

POST /api/workspace/select
    Body: `{"name": "network" | "forensic"}`. Sets the active workspace,
    calls its `activate()` hook, and persists the choice to `settings.json`
    so subsequent server boots land directly on that workspace (sticky).
    Switching at runtime is intentionally not supported in Phase 3 — the
    frontend only POSTs this on first-boot selection. Returns the new
    `current` payload.

Static / control-plane endpoints — no `_require_capture()` guard.
"""

from __future__ import annotations

import logging
from dataclasses import asdict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core import settings_store
from core.workspace import (
    active_name,
    get_active_workspace,
    get_workspace,
    list_workspaces,
    set_active,
)

logger = logging.getLogger("swifteye.routes.workspace")
router = APIRouter()


class WorkspaceSelectRequest(BaseModel):
    name: str


def _current_payload() -> dict:
    return {
        "active": active_name(),
        "available": [
            {"name": ws.name, "label": ws.label}
            for ws in list_workspaces().values()
        ],
    }


@router.get("/api/workspace/current")
async def get_current_workspace() -> dict:
    """Return the active workspace name (or null) + the list of registered workspaces."""
    return _current_payload()


@router.post("/api/workspace/select")
async def select_workspace(req: WorkspaceSelectRequest) -> dict:
    """Pick a workspace. Persists to settings.json so future boots auto-load it."""
    try:
        get_workspace(req.name)  # validate before mutating
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown workspace: {req.name!r}")
    set_active(req.name)
    settings_store.set_active_workspace(req.name)
    logger.info(f"Active workspace set to '{req.name}' (persisted)")
    return _current_payload()


@router.get("/api/workspace/schema")
async def get_workspace_schema() -> dict:
    """Return the active workspace's schema as JSON."""
    try:
        ws = get_active_workspace()
    except RuntimeError:
        raise HTTPException(status_code=409, detail="No active workspace. Call /api/workspace/select first.")
    return asdict(ws.schema)
