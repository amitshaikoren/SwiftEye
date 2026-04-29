"""
Animation route — /api/node-animation endpoint.

Provides session start/end events for a set of spotlight nodes,
used by the frontend AnimationPane for temporal playback.
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from workspaces.network.store import store, _require_capture
from workspaces.network.analysis import build_node_animation_response
from workspaces.network.plugins import get_global_results
from core.models import NodeAnimationResponse

logger = logging.getLogger("swifteye.routes.animation")
router = APIRouter()


@router.get("/api/node-animation", response_model=NodeAnimationResponse)
async def get_node_animation(
    nodes: str = Query(..., description="Comma-separated spotlight node IPs"),
    protocols: Optional[str] = Query(None, description="Comma-separated protocol filter"),
):
    """
    Get animation events (session starts/ends) for the given spotlight nodes.

    Returns a sorted event list and metadata for all involved nodes
    (spotlight + neighbours).
    """
    _require_capture()

    node_ids = set(n.strip() for n in nodes.split(",") if n.strip())
    if not node_ids:
        raise HTTPException(400, "No node IPs provided")

    proto_set = None
    if protocols:
        proto_set = set(p.strip() for p in protocols.split(",") if p.strip())

    dns_results = get_global_results().get("dns_resolver", {})
    hostname_map = dns_results.get("dns_hostnames", {})

    result = build_node_animation_response(
        store.sessions,
        node_ids,
        protocols=proto_set,
        hostname_map=hostname_map,
    )

    return NodeAnimationResponse(**result)
