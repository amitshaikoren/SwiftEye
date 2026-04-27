"""
Forensic workspace API routes.

POST /api/forensic/upload  — ingest an EVTX file into ForensicStore.
GET  /api/forensic/status  — is a forensic capture loaded?
GET  /api/forensic/graph   — nodes + edges from the loaded forensic capture.
GET  /api/forensic/events  — event list for a specific edge (by edge_key).
"""

import tempfile
import time
import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel
from typing import Any, Dict, List

from workspaces.forensic.store import forensic_store
from workspaces.forensic.parser.adapters import detect_adapter, ADAPTERS

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
