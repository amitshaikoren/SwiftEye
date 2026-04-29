"""
Forensic workspace API routes.

POST /api/forensic/upload     — ingest an EVTX file into ForensicStore.
GET  /api/forensic/status     — is a forensic capture loaded?
GET  /api/forensic/graph      — nodes + edges from the loaded forensic capture.
GET  /api/forensic/events     — event list for a specific edge (by edge_key).
GET  /api/forensic/animation  — animation event stream for spotlight nodes.
"""

import tempfile
import time
import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, UploadFile, File
from pydantic import BaseModel
from typing import Any, Dict, List

from core.models import NodeAnimationResponse
from workspaces.forensic.store import forensic_store
from workspaces.forensic.parser.adapters import detect_adapter, ADAPTERS
from workspaces.forensic.plugins import run_all_forensic_plugins, ForensicAnalysisContext
from workspaces.forensic.analysis.animation import build_forensic_animation_response

logger = logging.getLogger("swifteye.routes.forensic")
router = APIRouter()

_MAX_FILE_SIZE = 512 * 1024 * 1024  # 512 MB


class ForensicUploadResponse(BaseModel):
    success: bool
    file_name: str
    event_count: int
    node_count: int
    edge_count: int
    parse_time_ms: int


class ForensicStatusResponse(BaseModel):
    loaded: bool
    file_name: str
    event_count: int


class ForensicGraphResponse(BaseModel):
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    event_count: int


class ForensicEventsResponse(BaseModel):
    edge_key: str
    events: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_forensic_capture():
    if not forensic_store.is_loaded:
        raise HTTPException(status_code=400, detail="No forensic capture loaded")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/api/forensic/upload", response_model=ForensicUploadResponse)
async def upload_forensic(file: UploadFile = File(...)):
    """Upload an EVTX (or other supported forensic) file and parse it."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    content = await file.read()
    file_size = len(content)
    if file_size == 0:
        raise HTTPException(status_code=400, detail="File is empty")
    if file_size > _MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail=f"File exceeds {_MAX_FILE_SIZE // (1024*1024)} MB limit")

    tmp_path = None
    try:
        suffix = Path(file.filename).suffix.lower() or ".evtx"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix, prefix="swifteye_fx_") as f:
            f.write(content)
            tmp_path = Path(f.name)

        adapter = detect_adapter(tmp_path)
        if adapter is None:
            supported = sorted({ext for cls in ADAPTERS for ext in cls.file_extensions})
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type '{suffix}'. Supported: {', '.join(supported)}",
            )

        t0 = time.time()
        events = adapter.parse(tmp_path)
        parse_ms = int((time.time() - t0) * 1000)

        if not events:
            raise HTTPException(status_code=400, detail="No events found in uploaded file")

        forensic_store.load(events, file.filename)

        graph = forensic_store.graph_cache
        logger.info(
            f"Forensic upload complete: {file.filename} → {len(events)} events, "
            f"{len(graph['nodes'])} nodes, {len(graph['edges'])} edges in {parse_ms}ms"
        )

        return ForensicUploadResponse(
            success=True,
            file_name=file.filename,
            event_count=len(events),
            node_count=len(graph["nodes"]),
            edge_count=len(graph["edges"]),
            parse_time_ms=parse_ms,
        )

    finally:
        if tmp_path and tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


@router.get("/api/forensic/status", response_model=ForensicStatusResponse)
async def forensic_status():
    return ForensicStatusResponse(
        loaded=forensic_store.is_loaded,
        file_name=forensic_store.file_name,
        event_count=len(forensic_store.events),
    )


@router.get("/api/forensic/graph", response_model=ForensicGraphResponse)
async def forensic_graph():
    _require_forensic_capture()
    return ForensicGraphResponse(
        nodes=forensic_store.graph_cache.get("nodes", []),
        edges=forensic_store.graph_cache.get("edges", []),
        event_count=len(forensic_store.events),
    )


@router.get("/api/forensic/events", response_model=ForensicEventsResponse)
async def forensic_events(edge_key: str = ""):
    _require_forensic_capture()
    if not edge_key:
        raise HTTPException(status_code=400, detail="edge_key is required")
    events = forensic_store.get_events_for_edge(edge_key)
    return ForensicEventsResponse(edge_key=edge_key, events=events)


# ---------------------------------------------------------------------------
# Plugin routes
# ---------------------------------------------------------------------------

@router.get("/api/forensic/plugins")
async def forensic_plugins():
    """
    Run all registered forensic classifier plugins against the loaded capture.

    Returns:
      slots   — UI slot metadata (plugin, slot_id, title, priority, default_open)
      results — plugin name -> {node_id -> slot_data}
    """
    _require_forensic_capture()
    from workspaces.forensic.plugins import get_forensic_plugins
    ctx = ForensicAnalysisContext(
        events=forensic_store.events,
        nodes=forensic_store.graph_cache.get("nodes", []),
        edges=forensic_store.graph_cache.get("edges", []),
    )
    results = run_all_forensic_plugins(ctx)
    slots = []
    for name, plugin in get_forensic_plugins().items():
        for s in plugin.get_ui_slots():
            slots.append({
                "plugin": name,
                "slot_id": s.slot_id,
                "slot_type": s.slot_type,
                "title": s.title,
                "priority": s.priority,
                "default_open": s.default_open,
            })
    slots.sort(key=lambda s: s["priority"])
    return {"slots": slots, "results": results}


# ---------------------------------------------------------------------------
# Research chart routes (forensic-local registry)
# ---------------------------------------------------------------------------

@router.get("/api/forensic/research")
async def list_forensic_research_charts():
    """List all registered forensic research charts (no capture required)."""
    from workspaces.forensic.research import get_charts
    return {"charts": [c.to_info() for c in get_charts().values()]}


@router.post("/api/forensic/research/{chart_name}")
async def run_forensic_research_chart(chart_name: str, body: dict):
    """
    Run a forensic research chart and return a Plotly figure dict.

    Requires a forensic capture to be loaded.
    Body: { "_filter_*": ... }  — reserved for future filter params.
    Response: { "figure": { "data": [...], "layout": {...} }, "filter_schema": {} }
    """
    _require_forensic_capture()
    from workspaces.forensic.research import get_chart, run_chart, ForensicContext
    chart = get_chart(chart_name)
    if not chart:
        raise HTTPException(status_code=404, detail=f"Forensic chart '{chart_name}' not found")
    try:
        ctx = ForensicContext(
            events=forensic_store.events,
            nodes=forensic_store.graph_cache.get("nodes", []),
            edges=forensic_store.graph_cache.get("edges", []),
        )
        chart_params = {k: v for k, v in body.items() if not k.startswith("_")}
        filter_params = {k: v for k, v in body.items() if k.startswith("_filter_")}
        return run_chart(chart_name, ctx, chart_params, filter_params=filter_params)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error(f"Forensic chart '{chart_name}' failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Animation
# ---------------------------------------------------------------------------

@router.get("/api/forensic/animation", response_model=NodeAnimationResponse)
async def forensic_animation(
    nodes: Optional[str] = Query(None, description="Comma-separated spotlight node IDs (empty = all)"),
):
    """
    Return animation events for the given spotlight nodes (or all nodes).

    Events are sorted by timestamp. Each event maps to one forensic action
    (process_create, network_connect, etc.) and carries src/dst node IDs plus
    the edge schema color so AnimationPane can colour edges correctly.
    """
    _require_forensic_capture()
    node_ids: set = set()
    if nodes:
        node_ids = {n.strip() for n in nodes.split(",") if n.strip()}

    result = build_forensic_animation_response(forensic_store.graph_cache, node_ids)
    return NodeAnimationResponse(**result)
