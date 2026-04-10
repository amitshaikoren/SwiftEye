"""
Schema negotiation routes.

POST /api/upload/confirm-schema
  Phase 2 of the two-phase upload flow.  Accepts a staging token and the
  user-confirmed column mapping, then resumes ingestion using the remapped
  column names.

The frontend calls this after the user has reviewed the SchemaDialog and
confirmed how detected columns map to the fields this adapter expects.
"""

import time
import logging

from fastapi import APIRouter, HTTPException

from store import store
from plugins.analyses import clear_analysis_results
from services.capture import run_plugins, build_analysis_graph_and_run
from parser.adapters import ADAPTERS
from parser.schema import get_staged, clear_staged
from models import SchemaNegotiationRequest, UploadResponse

logger = logging.getLogger("swifteye.routes.schema")
router = APIRouter()


def _find_adapter_by_name(name: str):
    for cls in ADAPTERS:
        if cls.name == name:
            return cls()
    return None


@router.post("/api/upload/confirm-schema", response_model=UploadResponse)
async def confirm_schema(body: SchemaNegotiationRequest):
    """Complete a staged upload using the user-confirmed column mapping."""
    staged = get_staged(body.staging_token)
    if not staged:
        raise HTTPException(404, "Staging token not found or expired")

    adapter = _find_adapter_by_name(staged.adapter_name)
    if not adapter:
        raise HTTPException(500, f"Adapter '{staged.adapter_name}' not found in registry")

    from pathlib import Path
    staged_path = Path(staged.staged_path)
    if not staged_path.exists():
        raise HTTPException(410, "Staged file no longer exists")

    t0 = time.time()
    try:
        packets = adapter.parse_with_mapping(staged_path, body.mapping)
    except Exception as e:
        logger.exception("parse_with_mapping failed for token %s", body.staging_token)
        raise HTTPException(500, f"Parse error with confirmed mapping: {e}")
    finally:
        clear_staged(body.staging_token)

    if not packets:
        raise HTTPException(400, "No packets found after applying column mapping")

    packets.sort(key=lambda p: p.timestamp)
    parse_ms = int((time.time() - t0) * 1000)

    store.load(packets, staged.original_filename, source_files=[staged.original_filename])
    clear_analysis_results()
    run_plugins()
    build_analysis_graph_and_run()

    return UploadResponse(
        success=True,
        capture_id=store.capture_id,
        file_name=staged.original_filename,
        source_files=[staged.original_filename],
        packet_count=len(packets),
        parse_time_ms=parse_ms,
        file_size_bytes=staged_path.stat().st_size if staged_path.exists() else 0,
    )
