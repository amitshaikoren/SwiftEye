"""
Workspace routes.

GET /api/workspace/schema
    Returns the active workspace's typed schema (node types, edge types, and
    their field catalogs). The frontend fetches this once on app load and
    caches it in WorkspaceProvider; the display-filter evaluator and
    FilterBar suggestions read from it instead of hardcoding field names.

Static startup data — no `_require_capture()` guard.
"""

import logging
from dataclasses import asdict

from fastapi import APIRouter

from core.workspace import get_active_workspace

logger = logging.getLogger("swifteye.routes.workspace")
router = APIRouter()


@router.get("/api/workspace/schema")
async def get_workspace_schema() -> dict:
    """Return the active workspace's schema as JSON."""
    ws = get_active_workspace()
    return asdict(ws.schema)
