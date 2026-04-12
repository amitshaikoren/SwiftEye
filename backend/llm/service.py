"""
LLM service — orchestrates the full chat pipeline.

Pipeline:
  1. Resolve scope (determine effective entity from scope + selection)
  2. Tag the question (question_tags.py)
  3. Build context packet (context_builder.py)
  4. Assemble system prompt (prompts.py)
  5. Call provider (providers/)
  6. Stream normalised NDJSON events to caller

Caller receives an iterator of dicts (pre-serialised event objects).
The route layer converts them to JSON lines.
"""

from __future__ import annotations
import json
import logging
import uuid
from typing import Any, Dict, Generator, Iterator, List, Optional

import store as _store

from .contracts import (
    ChatRequest, ScopeSpec, SelectionState,
    MetaEvent, ContextEvent, DeltaEvent, WarningEvent, FinalEvent, ErrorEvent,
)
from .question_tags import tag_question
from .context_builder import build_context_packet
from .prompts import build_system_prompt, build_user_content
from .providers import get_provider

logger = logging.getLogger("swifteye.llm.service")


def stream_chat(request: ChatRequest) -> Iterator[Dict[str, Any]]:
    """
    Main entry point for the LLM chat pipeline.
    Yields serialisable event dicts (type, ...) as they arrive.
    """
    request_id = str(uuid.uuid4())[:12]
    snapshot_id = str(uuid.uuid4())[:12]

    # ── 1. Resolve scope ───────────────────────────────────────────────────────
    scope_result = _resolve_scope(request.scope, request.selection)
    if scope_result.get("error"):
        yield {"type": "error", "message": scope_result["error"]}
        return

    # ── 2. Tag the question ────────────────────────────────────────────────────
    st = _store.store
    question = _get_question_text(request)

    known_node_ids  = {n["id"] for n in (st.graph_cache.get("nodes") or [])}
    known_edge_ids  = {e["id"] for e in (st.graph_cache.get("edges") or [])}
    known_session_ids = {s["id"] for s in (st.sessions or []) if s.get("id")}
    known_alert_ids = {
        (a.get("id") if isinstance(a, dict) else getattr(a, "id", None))
        for a in (st.alerts or [])
    } - {None}

    sel = request.selection
    tags = tag_question(
        question=question,
        selection_node_ids=sel.node_ids or [],
        selection_edge_id=sel.edge_id,
        selection_session_id=sel.session_id,
        selection_alert_id=sel.alert_id,
        scope_mode=request.scope.mode,
        known_node_ids=known_node_ids,
        known_edge_ids=known_edge_ids,
        known_session_ids=known_session_ids,
        known_alert_ids=known_alert_ids,
    )

    logger.info(f"[{request_id}] tags={tags} scope={request.scope.mode}")

    # ── 3. Build context packet ────────────────────────────────────────────────
    try:
        context_packet = build_context_packet(request, tags)
    except Exception as e:
        logger.exception(f"[{request_id}] Context build failed")
        yield {"type": "error", "message": f"Context build error: {e}"}
        return

    # ── 4. Emit meta + context events ─────────────────────────────────────────
    yield {
        "type": "meta",
        "request_id": request_id,
        "provider": request.provider.kind,
        "model": request.provider.model,
    }

    surfaces = list(context_packet.get("retrieval_manifest", {}).get("already_retrieved", []))
    yield {
        "type": "context",
        "scope_mode": request.scope.mode,
        "snapshot_id": snapshot_id,
        "surfaces": surfaces,
        "tags": tags,
    }

    # ── Limitations warnings ───────────────────────────────────────────────────
    limitations = context_packet.get("limitations", {}).get("items", [])
    for lim in limitations:
        yield {"type": "warning", "message": lim}

    # ── Debug: return context only ────────────────────────────────────────────
    if request.options.debug_return_context:
        yield {
            "type": "final",
            "snapshot_id": snapshot_id,
            "answer_markdown": f"```json\n{json.dumps(context_packet, indent=2, default=str)}\n```",
            "usage": {"input_tokens": 0, "output_tokens": 0},
        }
        return

    # ── 5. Assemble prompt ────────────────────────────────────────────────────
    system_prompt = build_system_prompt(tags, context_packet, model_name=request.provider.model)
    user_content  = build_user_content(request.messages)

    # ── 6. Call provider ──────────────────────────────────────────────────────
    try:
        provider_cls = get_provider(request.provider.kind)
        adapter = provider_cls()
    except ValueError as e:
        yield {"type": "error", "message": str(e)}
        return

    full_answer = ""
    try:
        for delta in adapter.stream_chat(system_prompt, user_content, request.provider):
            full_answer += delta
            yield {"type": "delta", "text": delta}
    except ConnectionError as e:
        logger.warning(f"[{request_id}] Provider connection error: {e}")
        yield {"type": "error", "message": str(e)}
        return
    except Exception as e:
        logger.exception(f"[{request_id}] Provider stream error")
        yield {"type": "error", "message": f"Provider error: {e}"}
        return

    # ── 7. Final event ────────────────────────────────────────────────────────
    yield {
        "type": "final",
        "snapshot_id": snapshot_id,
        "answer_markdown": full_answer,
        "usage": {"input_tokens": 0, "output_tokens": 0},
    }


def build_context_only(request: ChatRequest) -> Dict[str, Any]:
    """
    Build and return the context packet without calling a provider.
    Used by POST /api/llm/context-preview for debugging and tests.
    """
    question = _get_question_text(request)
    st = _store.store

    known_node_ids  = {n["id"] for n in (st.graph_cache.get("nodes") or [])}
    known_edge_ids  = {e["id"] for e in (st.graph_cache.get("edges") or [])}
    known_session_ids = {s["id"] for s in (st.sessions or []) if s.get("id")}
    known_alert_ids = {
        (a.get("id") if isinstance(a, dict) else getattr(a, "id", None))
        for a in (st.alerts or [])
    } - {None}

    sel = request.selection
    tags = tag_question(
        question=question,
        selection_node_ids=sel.node_ids or [],
        selection_edge_id=sel.edge_id,
        selection_session_id=sel.session_id,
        selection_alert_id=sel.alert_id,
        scope_mode=request.scope.mode,
        known_node_ids=known_node_ids,
        known_edge_ids=known_edge_ids,
        known_session_ids=known_session_ids,
        known_alert_ids=known_alert_ids,
    )

    context_packet = build_context_packet(request, tags)
    return {"tags": tags, "context_packet": context_packet}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_question_text(request: ChatRequest) -> str:
    user_msgs = [m for m in request.messages if m.role == "user"]
    return user_msgs[-1].content if user_msgs else ""


def _resolve_scope(scope: ScopeSpec, sel: SelectionState) -> Dict[str, Any]:
    """
    Validate scope/selection consistency.
    Returns {"ok": True} or {"error": "...message..."}.
    """
    if scope.mode == "selected_entity":
        has_selection = (
            sel.node_ids or sel.edge_id or sel.session_id or sel.alert_id
            or (scope.entity_id and scope.entity_type)
        )
        if not has_selection:
            return {
                "error": (
                    "scope_mismatch: selected_entity scope requested but no entity is selected. "
                    "Please select a node, edge, session, or alert first, or change scope to "
                    "current_view or full_capture."
                )
            }
    return {"ok": True}
