"""
Workspace schema dataclasses.

A `WorkspaceSchema` declares, for one workspace, the `NodeType`s and
`EdgeType`s it produces and the `Field`s that are filterable / displayable
on each. Core code (display filter evaluator, FilterBar suggestions,
NodeDetail field lists) consumes this schema instead of hardcoding the
network field catalog.

Phase 2 rationale: see `llm_docs/plans/active/workspace-phase2-execution.md`.
Q1 sign-off (2026-04-18): **rich framework, minimal population.** NodeType
carries color/shape/icon/label_field; EdgeType carries src_type/dst_type;
Field has description; `timestamp` is in the type enum. Deferred attributes
(cardinality / indexed / unit / examples / nullable) land only when a
concrete consumer forces them.

Pure data — no imports beyond stdlib, no registration side effects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Literal, Optional


FieldType = Literal[
    "ip",
    "mac",
    "port",
    "protocol",
    "string",
    "string-array",
    "int",
    "bool",
    "enum",
    "timestamp",
]

NodeShape = Literal["circle", "square", "diamond", "rounded", "hex"]


@dataclass(frozen=True)
class Field:
    """A queryable / filterable / displayable attribute on a node or edge type.

    `name` is the wire key on the graph dict (what the backend writes);
    `filter_path` is the display-filter syntax (often shorter, may differ
    from `name`). `type` drives the evaluator — a forensic `process_name`
    of type `string` reuses the same matching code as a network `hostname`.

    `sources` declares additional wire keys to read from; the evaluator
    unions the values. Defaults to `[name]`. Used when one logical field
    is OR'd across multiple dict keys (e.g. flow `port` reads from both
    `src_ports` and `dst_ports`). Dotted paths are supported per key.
    """

    name: str
    display_name: str
    filter_path: str
    type: FieldType
    multi: bool = False
    renderer: Optional[str] = None
    bare_flag: Optional[str] = None
    description: str = ""
    sources: Optional[List[str]] = None


@dataclass(frozen=True)
class NodeType:
    """A kind of entity this workspace produces (network: `host` only)."""

    name: str
    label: str
    color: str
    shape: NodeShape
    label_field: str
    fields: List[Field] = field(default_factory=list)
    icon: Optional[str] = None
    description: str = ""


@dataclass(frozen=True)
class EdgeType:
    """A kind of relationship. `src_type` / `dst_type` reference NodeType names."""

    name: str
    label: str
    color: str
    src_type: str
    dst_type: str
    fields: List[Field] = field(default_factory=list)
    description: str = ""


@dataclass(frozen=True)
class WorkspaceSchema:
    """The full schema declared by one workspace."""

    workspace: str
    node_types: List[NodeType] = field(default_factory=list)
    edge_types: List[EdgeType] = field(default_factory=list)
