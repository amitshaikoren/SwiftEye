"""
LLM interpretation routes.

POST /api/llm/chat
    Accepts a ChatRequest, streams NDJSON events.

POST /api/llm/context-preview   (dev/debug only)
    Returns the built context packet without calling a provider.
    Useful for prompt iteration, debugging, and backend tests.
"""

from __future__ import annotations
import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from llm.service import stream_chat, build_context_only
from llm.contracts import (
    ChatRequest, ScopeSpec, ViewerState, SelectionState,
    ProviderConfig, ChatOptions, Message,
)

router = APIRouter()
logger = logging.getLogger("swifteye.routes.llm")


# ── Pydantic request models ───────────────────────────────────────────────────

class MessageIn(BaseModel):
    role: str
    content: str


class ScopeIn(BaseModel):
    mode: str = "full_capture"
    entity_type: Optional[str] = None
    entity_id: Optional[str] = None


class ViewerStateIn(BaseModel):
    time_start: Optional[float] = None
    time_end: Optional[float] = None
    protocols: Optional[List[str]] = None
    search: str = ""
    include_ipv6: bool = True
    subnet_grouping: bool = False
    subnet_prefix: int = 24
    merge_by_mac: bool = False
    cluster_algorithm: Optional[str] = None
    cluster_resolution: float = 1.0


class SelectionIn(BaseModel):
    node_ids: List[str] = []
    edge_id: Optional[str] = None
    session_id: Optional[str] = None
    alert_id: Optional[str] = None


class ProviderIn(BaseModel):
    kind: str = "ollama"
    model: str = "qwen2.5:14b-instruct"
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    temperature: float = 0.2
    max_tokens: int = 1400


class ChatOptionsIn(BaseModel):
    intent: str = "qa"
    allow_context_expansion: bool = True
    debug_return_context: bool = False


class ChatRequestIn(BaseModel):
    messages: List[MessageIn]
    scope: ScopeIn = ScopeIn()
    viewer_state: ViewerStateIn = ViewerStateIn()
    selection: SelectionIn = SelectionIn()
    provider: ProviderIn = ProviderIn()
    options: ChatOptionsIn = ChatOptionsIn()


# ── Route helpers ─────────────────────────────────────────────────────────────

def _to_domain(req_in: ChatRequestIn) -> ChatRequest:
    """Convert Pydantic input model to domain dataclass."""
    return ChatRequest(
        messages=[Message(role=m.role, content=m.content) for m in req_in.messages],
        scope=ScopeSpec(
            mode=req_in.scope.mode,
            entity_type=req_in.scope.entity_type,
            entity_id=req_in.scope.entity_id,
        ),
        viewer_state=ViewerState(
            time_start=req_in.viewer_state.time_start,
            time_end=req_in.viewer_state.time_end,
            protocols=req_in.viewer_state.protocols,
            search=req_in.viewer_state.search,
            include_ipv6=req_in.viewer_state.include_ipv6,
            subnet_grouping=req_in.viewer_state.subnet_grouping,
            subnet_prefix=req_in.viewer_state.subnet_prefix,
            merge_by_mac=req_in.viewer_state.merge_by_mac,
            cluster_algorithm=req_in.viewer_state.cluster_algorithm,
            cluster_resolution=req_in.viewer_state.cluster_resolution,
        ),
        selection=SelectionState(
            node_ids=req_in.selection.node_ids,
            edge_id=req_in.selection.edge_id,
            session_id=req_in.selection.session_id,
            alert_id=req_in.selection.alert_id,
        ),
        provider=ProviderConfig(
            kind=req_in.provider.kind,
            model=req_in.provider.model,
            base_url=req_in.provider.base_url,
            api_key=req_in.provider.api_key,
            temperature=req_in.provider.temperature,
            max_tokens=req_in.provider.max_tokens,
        ),
        options=ChatOptions(
            intent=req_in.options.intent,
            allow_context_expansion=req_in.options.allow_context_expansion,
            debug_return_context=req_in.options.debug_return_context,
        ),
    )


def _event_stream(request: ChatRequest):
    """Generator that yields NDJSON lines for each stream event."""
    for event in stream_chat(request):
        try:
            yield json.dumps(event, default=str) + "\n"
        except Exception as e:
            logger.warning(f"Event serialisation error: {e}")
            yield json.dumps({"type": "error", "message": f"Serialisation error: {e}"}) + "\n"


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/api/llm/chat")
async def llm_chat(body: ChatRequestIn):
    """
    Stream an LLM answer for a researcher question about the current capture.
    Response: application/x-ndjson — one JSON event per line.
    """
    if not body.messages:
        raise HTTPException(400, "messages must contain at least one user message")

    user_msgs = [m for m in body.messages if m.role == "user"]
    if not user_msgs:
        raise HTTPException(400, "messages must contain at least one user message")

    request = _to_domain(body)

    return StreamingResponse(
        _event_stream(request),
        media_type="application/x-ndjson",
        headers={"X-Accel-Buffering": "no"},
    )


@router.post("/api/llm/context-preview")
async def llm_context_preview(body: ChatRequestIn):
    """
    Dev/debug endpoint — returns the built context packet without calling a provider.
    Useful for prompt iteration, tests, and debugging retrieval quality.
    """
    if not body.messages:
        raise HTTPException(400, "messages must contain at least one user message")

    request = _to_domain(body)
    try:
        result = build_context_only(request)
    except Exception as e:
        logger.exception("Context preview failed")
        raise HTTPException(500, f"Context build error: {e}")

    return result
