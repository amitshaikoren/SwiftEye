"""
LLM contracts — dataclasses for the /api/llm/chat request and stream events.
These are the stable wire-format types. Keep deployment-neutral.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class Message:
    role: str       # "user" | "assistant" | "system"
    content: str


@dataclass
class ScopeSpec:
    mode: str                          # "full_capture" | "current_view" | "selected_entity"
    entity_type: Optional[str] = None  # "node" | "edge" | "session" | "alert"
    entity_id: Optional[str] = None    # ID string for the selected entity


@dataclass
class ViewerState:
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


@dataclass
class SelectionState:
    node_ids: List[str] = field(default_factory=list)
    edge_id: Optional[str] = None
    session_id: Optional[str] = None
    alert_id: Optional[str] = None


@dataclass
class ProviderConfig:
    kind: str                           # "ollama" | "openai" | "openai_compatible"
    model: str
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    temperature: float = 0.2
    max_tokens: int = 1400


@dataclass
class ChatOptions:
    intent: str = "qa"                     # "qa" | "explain"
    allow_context_expansion: bool = True
    debug_return_context: bool = False
    is_simple_question: bool = False       # True when sent via a starter chip (suppresses Next Steps)


@dataclass
class ChatRequest:
    messages: List[Message]
    scope: ScopeSpec
    viewer_state: ViewerState
    selection: SelectionState
    provider: ProviderConfig
    options: ChatOptions = field(default_factory=ChatOptions)


# ── Stream event types ────────────────────────────────────────────────────────

@dataclass
class MetaEvent:
    type: str = "meta"
    request_id: str = ""
    provider: str = ""
    model: str = ""


@dataclass
class ContextEvent:
    type: str = "context"
    scope_mode: str = ""
    snapshot_id: str = ""
    surfaces: List[str] = field(default_factory=list)


@dataclass
class DeltaEvent:
    type: str = "delta"
    text: str = ""


@dataclass
class WarningEvent:
    type: str = "warning"
    message: str = ""


@dataclass
class FinalEvent:
    type: str = "final"
    snapshot_id: str = ""
    answer_markdown: str = ""
    usage: dict = field(default_factory=lambda: {"input_tokens": 0, "output_tokens": 0})


@dataclass
class ErrorEvent:
    type: str = "error"
    message: str = ""
