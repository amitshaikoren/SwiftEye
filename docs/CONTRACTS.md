# SwiftEye — Extension Contracts

> Reference for contributors. Each section describes one extension point:
> what it is, where to put the file, what you must implement, and a minimal example.
>
> **Architecture rule:** parser → data/analysis → plugins → research. Each contract
> belongs to exactly one layer. Never reach across layers.

---

## Table of Contents

1. [Ingestion Adapter](#1-ingestion-adapter)
2. [Protocol Field Module](#2-protocol-field-module)
3. [Edge Field Entry](#3-edge-field-entry)
4. [Source Capability Declaration](#4-source-capability-declaration)
5. [Session Section (Frontend)](#5-session-section-frontend)
6. [Insight Plugin (PluginBase)](#6-insight-plugin-pluginbase)
7. [Alert Detector](#7-alert-detector)
8. [Analysis Plugin](#8-analysis-plugin)
9. [Research Chart](#9-research-chart)
10. [LLM Provider Adapter](#10-llm-provider-adapter)
11. [Query Contract (JSON)](#11-query-contract-json)
12. [LLM Wire Types](#12-llm-wire-types)

---

## 1. Ingestion Adapter

**Layer:** parser  
**File location:** `backend/parser/adapters/<format>/my_adapter.py`  
**Registry:** `@register_adapter` decorator — auto-discovers on startup  
**Base class:** `IngestionAdapter` (`backend/parser/adapters/__init__.py`)

An ingestion adapter reads one file format and produces `List[PacketRecord]`. The adapter
is auto-selected via extension sniffing + magic-byte/header detection.

### Required attributes

| Attribute | Type | Description |
|---|---|---|
| `name` | `str` | Human-readable name, e.g. `"my format"` |
| `file_extensions` | `List[str]` | e.g. `[".myext"]` |
| `granularity` | `str` | `"packet"` or `"session"` |
| `source_type` | `str` | Injected into `pkt.extra["source_type"]`. Used by protocol field modules to change accumulation behaviour (e.g. `"zeek"` skips direction logic). |

### Required methods

```python
def can_handle(self, path: Path, header: bytes) -> bool:
    """Return True if this adapter can parse the file."""

def parse(self, path: Path, **opts) -> List[PacketRecord]:
    """Return all packets as PacketRecords."""
```

### Optional: schema negotiation (text-format adapters)

Override these three methods and set `declared_fields` to enable the schema negotiation
flow (SwiftEye shows a column-mapping dialog when the file's columns don't match):

```python
declared_fields: List[SchemaField] = [...]

def get_header_columns(self, path: Path) -> List[str]: ...
def get_raw_rows(self, path: Path) -> List[Dict[str, str]]: ...
def _rows_to_packets(self, rows: List[Dict[str, str]]) -> List[PacketRecord]: ...
```

`parse()` is then provided by the base class (calls `get_raw_rows` → `_rows_to_packets`).

### Registration

```python
from parser.adapters import IngestionAdapter, register_adapter

@register_adapter
class MyAdapter(IngestionAdapter):
    name = "my format"
    file_extensions = [".myext"]
    granularity = "packet"
    source_type = "myformat"

    def can_handle(self, path, header):
        return path.suffix.lower() == ".myext"

    def parse(self, path, **opts):
        ...
        return packets  # List[PacketRecord]
```

Then import the file in your subdirectory's `__init__.py` so it registers at startup.

**New `source_type` values:** Document the string in `backend/data/protocol_fields/__init__.py`
under the `source_type` docstring so protocol modules know to handle it.

---

## 2. Protocol Field Module

**Layer:** data  
**File location:** `backend/data/protocol_fields/myproto.py`  
**Registry:** auto-discovered by `pkgutil.iter_modules` on package import — no manual registration

A protocol field module adds per-session fields for one application protocol. It is
initialized **lazily** — only when a session's packets contain relevant data.

### Required functions

```python
def init() -> dict:
    """Return the blank session dict for this protocol."""

def accumulate(s: dict, ex: dict, is_fwd: bool, source_type: str) -> None:
    """Mutate session dict s from one packet's extra fields.

    s           — the session dict (mutable)
    ex          — pkt.extra from the current packet (read-only)
    is_fwd      — True if the packet is from the session initiator
    source_type — which adapter produced this packet (None, "zeek", ...)
    """

def serialize(s: dict) -> None:
    """Convert working types (sets, etc.) to JSON-safe output in-place."""
```

### Optional functions

```python
def check_boundary(flow_state: dict, ex: dict, ts: float) -> bool:
    """Return True to split the current session at this packet.

    flow_state — mutable dict preserved across packets in the same 5-tuple.
                 Use it to track inactivity timers, request/response pairing, etc.
    ex         — pkt.extra from the current packet
    ts         — packet timestamp (Unix seconds)
    """
```

### Lazy init contract

`accumulate()` **must not** call `init()` itself. The registry calls `init()` automatically
on `KeyError` (the first time your accumulator tries to read a field that doesn't exist).
This means: access `ex.get(...)` before accessing `s[...]`. The first `s["my_key"]` that
raises `KeyError` triggers init. After that, your module is marked active for this session.

### Serialize caps

Use the provided `cap_list(s, key)` helper from `from . import cap_list` to truncate
large lists before they reach the frontend. When a list is truncated, a `_total` key is
added automatically so the frontend can show "Showing X of Y".

### Example (minimal)

```python
from . import cap_list

def init():
    return {
        "myproto_queries": [],
        "myproto_flags": set(),
    }

def accumulate(s, ex, is_fwd, source_type):
    if not ex.get("myproto_query"):
        return
    s["myproto_queries"].append(ex["myproto_query"])  # KeyError → init → retry
    if ex.get("myproto_flag"):
        s["myproto_flags"].add(ex["myproto_flag"])

def serialize(s):
    s["myproto_flags"] = sorted(s["myproto_flags"])
    cap_list(s, "myproto_queries")
```

Drop the file into `backend/data/protocol_fields/` and it is active on next startup.

---

## 3. Edge Field Entry

**Layer:** data  
**File location:** `backend/data/edge_fields.py` → `EDGE_FIELD_REGISTRY` list  
**Registry:** static list — no file needed, just add an entry

An edge field entry causes one `pkt.extra` key to be accumulated (as a set) onto every
graph edge that carries matching packets. Use this for values that are meaningful across
an entire flow pair, not just one session (e.g. JA3 hashes, TLS SNIs, DNS queries).

### Entry schema

```python
{
    "extra_key":    str,          # key read from pkt.extra
    "edge_key":     str,          # key stored on the edge dict (always a set during accumulation)
    "multi":        bool,         # True if pkt.extra[extra_key] is a list
    "acc_cap":      int | None,   # max items consumed per-packet from a multi list (None = all)
    "ser_cap":      int | None,   # max items in the serialised HTTP response (None = no cap)
    "lazy":         bool,         # True = detail-only (excluded from /api/graph summary)
    "hint_keyword": str | List[str],  # search bar keywords that imply this field's presence
}
```

### Example

```python
{
    "extra_key":    "myproto_token",
    "edge_key":     "myproto_tokens",
    "multi":        False,
    "acc_cap":      None,
    "ser_cap":      20,
    "lazy":         True,
    "hint_keyword": ["myproto"],
},
```

No other backend changes are needed — `aggregator.py` reads the registry dynamically.
If you want a search-bar keyword hint, the entry's `hint_keyword` is picked up by
`/api/meta/edge-fields` automatically.

---

## 4. Source Capability Declaration

**Layer:** frontend  
**File location:** `frontend/src/capabilities.js` → `SOURCE_CAPS` object  
**Registry:** static object — add a key for your new `source_type`

When you add a new ingestion adapter, register its UI capabilities here so that
`SessionDetail` tabs and sections show or hide correctly based on what the source provides.

### Capability tokens

| Token | What it gates |
|---|---|
| `raw_packets` | Packets tab in SessionDetail |
| `payload` | Payload tab (hex dump + entropy) |
| `charts` | Charts tab (seq/ack, bytes/time) |
| `l3_headers` | IP header detail rows |
| `tcp_options` | TCP options section |
| `window_size` | TCP window size tracking |
| `seq_ack` | Sequence/ack number tracking |
| `tcp_reliability` | Retransmits, out-of-order, dup-ACKs |
| `zeek_conn` | Zeek connection state section |

### Example

```javascript
// In SOURCE_CAPS:
mysource: [
  'raw_packets',   // if your adapter produces per-packet records
  'zeek_conn',     // if your adapter produces connection-level metadata
],
```

Capability checks in components use `hasCap(session, 'token')`. If a section checks a
capability your source doesn't declare, the section simply won't render.

---

## 5. Session Section (Frontend)

**Layer:** frontend  
**File location:** `frontend/src/components/session_sections/myproto.jsx`  
**Registry:** auto-discovered via `import.meta.glob('./*.jsx', { eager: true })` — no registration

A session section renders protocol-specific data inside `SessionDetail` under the
Application (L5+) group. Drop a `.jsx` file here and it appears automatically.

### Required exports

```javascript
export const hasData = (s) => Boolean(s.myproto_queries?.length);
// Returns false → section is hidden entirely when the session has no myproto data.

export const title = (s) => `My Protocol`;
// String or function returning string. Shown as the section header.

export const order = 50;
// Number. Lower = higher up. Existing values: dns=10, http=20, tls=30, smb=40, ...

export const prefix = 'myproto_';
// String or string[]. Declares which session field prefixes this section "owns".
// Unclaimed prefixes with data get a generic fallback renderer — own yours explicitly.

export const defaultOpen = false;
// Whether the Collapse is open by default.

export default function MyProtoSection({ s }) {
  // s is the full session dict.
  return <div>...</div>;
}
```

### Layer export (optional)

```javascript
export const layer = 'application';  // or 'transport', 'network' — affects grouping
```

### Utility components

`Row` and `Collapse` are available from sibling directories:

```javascript
import Row from '../Row';
import Collapse from '../Collapse';
```

---

## 6. Insight Plugin (PluginBase)

**Layer:** plugins  
**File location:** `backend/plugins/<category>/my_plugin.py`  
**Registry:** manual — call `register_plugin(MyPlugin())` in `server.py`

Insight plugins annotate capture data: they run after a pcap loads and inject results
into node/edge/session detail panels and the stats panel. A plugin can render generically
using `_display` lists — no frontend code needed for basic output.

### Required methods

```python
class MyPlugin(PluginBase):
    name = "my_plugin"
    description = "One sentence"
    version = "0.1.0"

    def get_ui_slots(self) -> List[UISlot]:
        """Declare where your output appears."""
        return [
            UISlot(
                slot_type="node_detail_section",  # see slot types below
                slot_id="my_slot",
                title="My Section Title",
                priority=50,       # lower = higher up
                default_open=False,
            ),
        ]

    def analyze_global(self, ctx: AnalysisContext) -> Dict[str, Any]:
        """Run once after pcap load. Return dict keyed by slot_id."""
        return {
            "my_slot": {
                "some_data": ...,
                "_display": [
                    *display_rows({"Key": "value", "Count": 42}),
                    display_text("Explanatory note"),
                ],
            },
        }
```

### Optional targeted methods

```python
def analyze_node(self, ctx: AnalysisContext) -> Dict[str, Any]:
    # ctx.target_node_id is set. Return dict keyed by slot_id.
    ...

def analyze_edge(self, ctx: AnalysisContext) -> Dict[str, Any]:
    # ctx.target_edge_id is set.
    ...

def analyze_session(self, ctx: AnalysisContext) -> Dict[str, Any]:
    # ctx.target_session_id is set.
    ...
```

### UI slot types

| `slot_type` | Renders in |
|---|---|
| `node_detail_section` | Node detail right panel |
| `edge_detail_section` | Edge detail right panel |
| `session_detail_section` | Session detail panel |
| `stats_section` | Stats / overview panel |
| `right_panel` | Full panel tab in right sidebar |
| `graph_overlay` | Overlay on graph canvas |
| `toolbar_widget` | Top toolbar widget |

### `_display` element types

```python
display_rows({"Label": "value", ...})          # key-value rows
display_tags([("tag text", "#hexcolor"), ...]) # colored badge chips
display_list([("label", "value"), ...])        # two-column list
display_text("Some note", color="#8b949e")     # freeform text
display_table(["Col A", "Col B"], [["r1c1", "r1c2"], ...])  # table
```

All helpers are importable from `plugins`: `from plugins import display_rows, ...`

### AnalysisContext fields

```python
ctx.packets         # List[PacketRecord] — all packets in the capture
ctx.sessions        # List[dict]         — session dicts from sessions.py
ctx.nodes           # List[dict]         — graph nodes (if available)
ctx.edges           # List[dict]         — graph edges (if available)
ctx.time_range      # (t_start, t_end)   — Unix seconds, or None
ctx.target_node_id  # str | None         — set by analyze_node()
ctx.target_edge_id  # str | None         — set by analyze_edge()
ctx.target_session_id  # str | None      — set by analyze_session()
ctx.node_map        # Dict[id, node]     — lazy O(1) index
ctx.edge_map        # Dict[id, edge]     — lazy O(1) index
```

---

## 7. Alert Detector

**Layer:** plugins  
**File location:** `backend/plugins/alerts/my_detector.py`  
**Registry:** manual — call `register_detector(MyDetector())` in `server.py`

Alert detectors scan capture data for security patterns and emit `AlertRecord` objects.
They run after the graph is built, using the same `AnalysisContext` as plugins.

> **Philosophy:** SwiftEye is a viewer, not a judge. Alerts surface patterns to
> investigate. Descriptions must say "may indicate X", never "this is X".

### Required method

```python
from plugins.alerts import AlertPluginBase, AlertRecord
import uuid

class MyDetector(AlertPluginBase):
    name = "my_detector"
    version = "1.0"

    def detect(self, ctx) -> List[AlertRecord]:
        alerts = []
        # ... scan ctx.packets / ctx.sessions / ctx.nodes / ctx.edges ...
        alerts.append(AlertRecord(
            id=str(uuid.uuid4())[:8],
            title="My Pattern",
            subtitle="One-line description of this finding",
            severity="high",      # "high" | "medium" | "low" | "info"
            detector=self.name,
            source="detector",
            source_name=self.name,
            timestamp=first_ts,   # epoch of first triggering packet
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",    # or None
            evidence=[
                {"key": "MAC", "value": mac, "note": "first seen at 1.23"},
            ],
            node_ids=["10.0.0.1"],
            edge_ids=[],
            session_ids=[],
        ))
        return alerts
```

**Never raise** from `detect()` — catch internally and return `[]`. The runner logs errors
and continues with other detectors.

### AlertRecord fields

| Field | Type | Description |
|---|---|---|
| `id` | `str` | Short unique ID (uuid4 first 8 chars) |
| `title` | `str` | Detector type, e.g. `"ARP Spoofing"` |
| `subtitle` | `str` | One-line finding, e.g. `"IP claimed by 2 MACs"` |
| `severity` | `str` | `"high"` / `"medium"` / `"low"` / `"info"` |
| `detector` | `str` | Plugin name |
| `source` | `str` | `"detector"` (or `"external"` for Suricata etc.) |
| `source_name` | `str` | Human-readable source name |
| `timestamp` | `float \| None` | Epoch of first triggering packet |
| `src_ip` | `str \| None` | Primary involved IP |
| `dst_ip` | `str \| None` | Secondary involved IP |
| `evidence` | `list` | List of `{"key", "value", "note"}` dicts |
| `node_ids` | `list` | IPs involved → graph highlight |
| `edge_ids` | `list` | Edge IDs involved |
| `session_ids` | `list` | Session IDs involved |

---

## 8. Analysis Plugin

**Layer:** plugins  
**File location:** `backend/plugins/analyses/my_analysis.py`  
**Registry:** manual — call `register_analysis(MyAnalysis())` in `server.py`'s `_register_analyses()`

Analysis plugins compute graph-wide metrics (centrality, traffic characterisation, etc.)
on demand. Unlike insight plugins they are **not** run at pcap load time — they run when
the user visits the Analysis page or triggers them via `/api/analysis/run`.

### Required method

```python
from plugins.analyses import AnalysisPluginBase

class MyAnalysis(AnalysisPluginBase):
    name        = "my_analysis"
    title       = "My Analysis"
    description = "One sentence on what this answers"
    icon        = "📊"
    version     = "1.0"

    def compute(self, ctx) -> dict:
        """
        ctx has: packets, sessions, nodes, edges, time_range

        Return a dict with:
          - Any structured data fields
          - A "_display" list for generic card rendering
        """
        result = {}
        # ... compute over ctx.nodes, ctx.edges, ctx.sessions ...
        result["_display"] = [
            *display_rows({"Metric": value}),
            display_table(["Node", "Score"], rows),
        ]
        return result
```

The runner wraps the return value in a result envelope with `title`, `icon`, `description`,
and `badge` before caching it. Your `compute()` only needs to return the data dict.

---

## 9. Research Chart

**Layer:** research  
**File location:** `backend/research/my_chart.py`  
**Registry:** manual — call `register_chart(MyChart())` in `server.py`'s `_register_charts()`

Research charts are on-demand, parameterised Plotly visualisations. They run per-user-request
with specific params, return a Plotly figure dict, and are rendered on the Research page.

### Preferred pattern: `build_data` + `build_figure`

```python
from research import ResearchChart, Param, AnalysisContext
import plotly.graph_objects as go

class MyChart(ResearchChart):
    name        = "my_chart"
    title       = "My Chart Title"
    description = "One sentence on what question this answers"
    category    = "host"   # "host" | "session" | "capture" | "alerts" | "other"

    params = [
        Param(name="target_ip", label="Target IP", type="ip"),
    ]

    entry_schema = {
        "peer":     "ip",       # frontend shows a text filter
        "protocol": "list",     # frontend shows multi-select (options collected at runtime)
        "bytes":    "numeric",  # frontend shows min/max number inputs
        "note":     "string",   # frontend shows a contains text input
    }

    def build_data(self, ctx: AnalysisContext, params: dict) -> List[dict]:
        ip = params["target_ip"]
        return [
            {"peer": pkt.dst_ip, "protocol": pkt.protocol,
             "bytes": pkt.orig_len, "ts": pkt.timestamp * 1000}
            for pkt in ctx.packets if pkt.src_ip == ip
        ]

    def build_figure(self, entries: List[dict], params: dict) -> go.Figure:
        # entries are already filtered by _filter_* params
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=[e["ts"] for e in entries],
            y=[e["bytes"] for e in entries],
            mode="markers",
        ))
        return fig
        # SWIFTEYE_LAYOUT is applied by the framework — do not call update_layout yourself
```

The framework: normalises `entry_schema` → enriches `list` options from data →
applies `_filter_*` params → calls `build_figure` → applies `SWIFTEYE_LAYOUT` → returns
`{"figure": ..., "filter_schema": ...}`.

### Legacy pattern: `compute`

```python
def compute(self, ctx: AnalysisContext, params: dict) -> go.Figure:
    # Full control, no auto-filter support.
    fig = go.Figure(...)
    fig.update_layout(SWIFTEYE_LAYOUT)
    return fig
```

### `entry_schema` field types

| Type string | Filter rendered | Match logic |
|---|---|---|
| `"ip"` | Text input | Prefix/exact match |
| `"string"` | Text input | Case-insensitive contains |
| `"numeric"` | Min + max inputs | Inclusive range |
| `"list"` | Multi-select chips | Exact value in selected set |

Shorthand: `"ip"` is equivalent to `{"type": "ip"}`. Supply `{"type": "list", "options": [...]}` for a static known set (shown before first run).

### `Param` fields

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | `str` | — | Key in `params` dict |
| `label` | `str` | — | Input label in the UI |
| `required` | `bool` | `True` | Frontend validates before submit |
| `default` | `str` | `""` | Pre-filled value |
| `type` | `str` | `"text"` | `"text"` / `"ip"` / `"integer"` / `"float"` |
| `placeholder` | `str` | `""` | Hint text inside the input |

---

## 10. LLM Provider Adapter

**Layer:** llm  
**File location:** `backend/llm/providers/my_provider.py`  
**Registry:** manual — add a case to `service.py`'s `_get_provider()` dispatch

An LLM provider adapter wraps one inference backend (Ollama, OpenAI-compatible API, etc.)
and exposes a single streaming interface.

### Required method

```python
from llm.providers.base import ProviderAdapter
from typing import Iterator

class MyProvider(ProviderAdapter):

    def stream_chat(
        self,
        system_prompt: str,
        user_content: str,
        config,              # llm.contracts.ProviderConfig
    ) -> Iterator[str]:
        """
        Yield text delta strings as they arrive.
        Raises on connection/auth errors (caller handles).
        """
        # config.model, config.base_url, config.api_key,
        # config.temperature, config.max_tokens are available
        for chunk in my_api.stream(...):
            yield chunk.text
```

### Optional overrides

```python
def supports_tools(self) -> bool:
    return True   # default False

def supports_json_mode(self) -> bool:
    return True   # default False
```

### Wire config (`ProviderConfig`)

```python
@dataclass
class ProviderConfig:
    kind: str               # "ollama" | "openai" | "openai_compatible" | your new kind
    model: str
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    temperature: float = 0.2
    max_tokens: int = 1400
```

To activate your provider, add a branch in `service.py`:

```python
def _get_provider(config: ProviderConfig) -> ProviderAdapter:
    if config.kind == "my_kind":
        return MyProvider()
    ...
```

---

## 11. Query Contract (JSON)

**Consumed by:** `backend/data/query/query_engine.py` → `resolve_query()`  
**Produced by:** `backend/data/query/query_parser.py` (Cypher / SQL / Spark SQL / PySpark)  
**Also usable:** frontend query builder sends this directly

This is the stable intermediate representation for all graph queries. The text parsers
translate query languages into this format; the engine evaluates it against NetworkX.

```json
{
    "target": "nodes",
    "conditions": [
        {"field": "total_bytes", "op": ">",        "value": 1000000},
        {"field": "protocols",   "op": "contains", "value": "DNS"}
    ],
    "logic": "AND",
    "action": "highlight"
}
```

### Fields

| Field | Values | Description |
|---|---|---|
| `target` | `"nodes"` / `"edges"` | What to query against |
| `conditions` | `List[Condition]` | One or more filter conditions |
| `logic` | `"AND"` / `"OR"` | How conditions are combined |
| `action` | `"highlight"` | What to do with matched IDs (currently only `"highlight"`) |

### Condition `op` values

| Category | `op` | Notes |
|---|---|---|
| Numeric | `>` `<` `=` `!=` `>=` `<=` | Coerces to float |
| Count | `count_gt` `count_lt` `count_eq` | Operates on `len(field)` |
| Set | `contains` `contains_all` `contains_any` `is_empty` `not_empty` | Works on sets and lists |
| String | `equals` `starts_with` `matches` | `matches` uses regex |
| Boolean | `is_true` `is_false` | For bool-typed fields |

---

## 12. LLM Wire Types

**Location:** `backend/llm/contracts.py`  
**Purpose:** Stable types for the `/api/llm/chat` request/response boundary.  
Do not add interpretation or business logic here — these are pure data containers.

### Request types

```python
ChatRequest(
    messages=[Message(role="user", content="...")],
    scope=ScopeSpec(
        mode="full_capture",           # "full_capture" | "current_view" | "selected_entity"
        entity_type="node",            # "node" | "edge" | "session" | "alert" | None
        entity_id="10.0.0.1",          # entity ID string | None
    ),
    viewer_state=ViewerState(
        time_start=None,
        time_end=None,
        protocols=["DNS", "TLS"],
        search="",
        include_ipv6=True,
        subnet_grouping=False,
        subnet_prefix=24,
        merge_by_mac=False,
        cluster_algorithm=None,
        cluster_resolution=1.0,
    ),
    selection=SelectionState(
        node_ids=["10.0.0.1"],
        edge_id=None,
        session_id=None,
        alert_id=None,
    ),
    provider=ProviderConfig(
        kind="ollama",
        model="llama3.2",
        base_url="http://localhost:11434",
        temperature=0.2,
        max_tokens=1400,
    ),
    options=ChatOptions(
        intent="qa",                   # "qa" | "explain"
        allow_context_expansion=True,
        debug_return_context=False,
        is_simple_question=False,
    ),
)
```

### Stream event types (NDJSON)

The `/api/llm/chat` endpoint emits a stream of newline-delimited JSON events:

| `type` | Fields | Description |
|---|---|---|
| `"meta"` | `request_id`, `provider`, `model` | First event; identifies the request |
| `"context"` | `scope_mode`, `snapshot_id`, `surfaces` | What context was assembled |
| `"delta"` | `text` | Incremental text token from the model |
| `"warning"` | `message` | Non-fatal issue (e.g. context truncation) |
| `"final"` | `snapshot_id`, `answer_markdown`, `usage` | Last event; full answer + token counts |
| `"error"` | `message` | Fatal error; stream ends after this |

`delta` events arrive in order; concatenating all `text` fields produces the full answer
(also available in `final.answer_markdown`).
