"""
SwiftEye Research Chart System

Research charts are on-demand, parameterized data visualizations for
exploring a capture. Unlike plugins (which run once on load and annotate
the graph), research charts run on user request with specific parameters
and return a Plotly figure dict that the frontend renders directly.

== Writing a research chart ==

  1. Create backend/research/my_chart.py
  2. Subclass ResearchChart
  3. Declare params (what inputs the user must provide)
  4. Implement compute() — return a standard Plotly figure dict
  5. Register in _register_charts() in server.py

The returned dict is passed directly to Plotly.js on the frontend:
  Plotly.react(div, figure["data"], figure["layout"])

So the full Plotly API is available. Use plotly.graph_objects, build
the dict manually, or mix both. The developer is responsible for
styling consistently with SwiftEye's dark theme — see SWIFTEYE_LAYOUT
in this file for the base layout dict to merge into.

== Example ==

  from research import ResearchChart, Param, AnalysisContext
  import plotly.graph_objects as go

  class MyChart(ResearchChart):
      name        = "my_chart"
      title       = "My chart title"
      description = "One sentence on what question this answers"
      params = [
          Param(name="target_ip", label="Target IP"),
      ]

      def compute(self, ctx: AnalysisContext, params: dict) -> dict:
          ip = params["target_ip"]
          packets = [p for p in ctx.packets if p.src_ip == ip or p.dst_ip == ip]
          fig = go.Figure()
          fig.add_trace(go.Scatter(
              x=[p.timestamp for p in packets],
              y=[p.ttl for p in packets],
              mode="markers",
          ))
          fig.update_layout(SWIFTEYE_LAYOUT)
          return fig.to_dict()

== Params ==

  Param(name, label, required, default, type, placeholder)

  name        : key used in the params dict passed to compute()
  label       : shown as the input label in the UI
  required    : if True, frontend validates before submitting
  default     : pre-filled value (optional)
  type        : "text" | "ip" | "integer" | "float" (used for UI validation)
  placeholder : hint text shown in the input field

== Architecture notes ==

  - compute() is called per-request. It receives the full CaptureStore
    packets and sessions from RAM — no disk reads.
  - compute() must be deterministic and side-effect free.
  - Heavy computation is fine — it runs in Python, not the browser.
  - The browser receives only the final Plotly JSON (~50KB typical).
    Zero computation happens client-side beyond rendering.
"""

import logging
from abc import ABC
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
import plotly.graph_objects as go
from constants import PROTOCOL_COLORS, SWIFTEYE_LAYOUT

logger = logging.getLogger("swifteye.research")


# ── Per-chart filter helpers ─────────────────────────────────────────

def _normalize_schema(raw: dict) -> Dict[str, Any]:
    """
    Normalize entry_schema shorthand to full dicts.

    'ip'      → {'type': 'ip'}
    'string'  → {'type': 'string'}
    'numeric' → {'type': 'numeric'}
    'list'    → {'type': 'list'}            # options populated at runtime from entries
    {'type': 'list', 'options': [...]}      # static options — passed through unchanged
    """
    result = {}
    for k, v in raw.items():
        result[k] = {'type': v} if isinstance(v, str) else dict(v)
    return result


def _enrich_list_options(schema: Dict[str, Any], entries: List[dict]) -> Dict[str, Any]:
    """
    For 'list' fields that have no static options, collect unique values from entries.
    Returns a new schema dict with options filled in.
    """
    if not entries:
        return schema
    enriched = {}
    for k, spec in schema.items():
        if spec['type'] == 'list' and 'options' not in spec:
            unique = sorted({str(e[k]) for e in entries if k in e and e[k] is not None})
            enriched[k] = {**spec, 'options': unique}
        else:
            enriched[k] = spec
    return enriched


def _apply_filters(entries: List[dict], filter_params: dict, schema: Dict[str, Any]) -> List[dict]:
    """
    Apply _filter_<field> params to entries based on detected schema types.

    filter_params keys:
      _filter_<field>          — ip / string / list value
      _filter_<field>_min      — numeric lower bound (inclusive)
      _filter_<field>_max      — numeric upper bound (inclusive)
      _filter_<field>          — for list: comma-separated selected values

    Returns filtered entries (original list if no filters active).
    """
    if not filter_params or not entries:
        return entries

    result = entries

    for key, spec in schema.items():
        t = spec["type"]

        if t == "ip":
            val = filter_params.get(f"_filter_{key}", "").strip()
            if val:
                result = [e for e in result if str(e.get(key, "")).startswith(val)]

        elif t == "string":
            val = filter_params.get(f"_filter_{key}", "").strip().lower()
            if val:
                result = [e for e in result if val in str(e.get(key, "")).lower()]

        elif t == "numeric":
            raw_min = filter_params.get(f"_filter_{key}_min")
            raw_max = filter_params.get(f"_filter_{key}_max")
            if raw_min is not None and raw_min != "":
                try:
                    lo = float(raw_min)
                    result = [e for e in result if e.get(key, 0) >= lo]
                except (ValueError, TypeError):
                    pass
            if raw_max is not None and raw_max != "":
                try:
                    hi = float(raw_max)
                    result = [e for e in result if e.get(key, 0) <= hi]
                except (ValueError, TypeError):
                    pass

        elif t == "list":
            raw = filter_params.get(f"_filter_{key}")
            if raw:
                if isinstance(raw, list):
                    selected = set(raw)
                else:
                    selected = set(str(raw).split(","))
                if selected:
                    result = [e for e in result if str(e.get(key, "")) in selected]

    return result


# ── Param ────────────────────────────────────────────────────────────

@dataclass
class Param:
    """
    Declares a user-facing input for a research chart.

    name        : key in the params dict passed to compute()
    label       : shown as the input label in the UI
    required    : frontend validates before submitting
    default     : pre-filled value shown in the input
    type        : "text" | "ip" | "integer" | "float"
    placeholder : hint text inside the input
    """
    name:        str
    label:       str
    required:    bool = True
    default:     str  = ""
    type:        str  = "text"
    placeholder: str  = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name":        self.name,
            "label":       self.label,
            "required":    self.required,
            "default":     self.default,
            "type":        self.type,
            "placeholder": self.placeholder,
        }


# ── AnalysisContext ───────────────────────────────────────────────────
# Single canonical class — defined in plugins/__init__.py.
# Re-exported here so chart authors can import from either location.
from plugins import AnalysisContext  # noqa: F401


# ── ResearchChart base class ─────────────────────────────────────────

class ResearchChart(ABC):
    """
    Base class for SwiftEye research charts.

    == Preferred pattern: build_data + build_figure ==

    Declare entry_schema to describe the shape of your data entries, then
    split your logic into two methods:

      entry_schema = {
          'peer':      'ip',
          'protocol':  'list',                              # options collected at runtime
          'direction': {'type': 'list', 'options': ['in', 'out']},  # static options
          'bytes':     'numeric',
          'uri':       'string',
      }

      def build_data(self, ctx, params) -> List[dict]:
          # Return one dict per plotted point/bar.
          # Keys must match entry_schema.
          # Use "ts" for the time axis (excluded from filters).
          return [{"ts": pkt.timestamp * 1000, "peer": peer, ...}, ...]

      def build_figure(self, entries, params) -> go.Figure:
          # Receives the already-filtered entries list.
          # Build and return a go.Figure.
          fig = go.Figure()
          ...
          return fig

    The framework: normalises entry_schema → enriches list options from entries
    → applies _filter_* params → calls build_figure → applies SWIFTEYE_LAYOUT
    → returns figure + filter_schema.

    == entry_schema field types ==

      'ip'      — IPv4 address; frontend renders a text input (prefix/exact match)
      'string'  — free text; frontend renders a contains text input
      'numeric' — int or float; frontend renders min / max number inputs
      'list'    — categorical; frontend renders multi-select chips
                  Omit 'options' and the framework collects unique values at runtime.
                  Supply 'options' for a static known set (shown before first run).

    Shorthand: just write the type as a string when you have no extra keys.
      'ip'  is equivalent to  {'type': 'ip'}

    == Legacy pattern: compute ==

    If you only implement compute(), it works unchanged (no filter support).

      def compute(self, ctx, params) -> go.Figure | dict:
          ...

    == Class attributes ==
    """
    name:        str = ""       # unique slug, used in URL: /api/research/{name}
    title:       str = ""       # shown in the UI chart picker
    description: str = ""       # one sentence — what question does this answer?
    category:    str = "capture"  # "host" | "session" | "capture" | "alerts" | "other"
    params: List[Param] = []
    entry_schema: dict = {}     # declares filterable fields — see class docstring

    # ── New pattern ───────────────────────────────────────────────────

    def build_data(self, ctx: AnalysisContext, params: dict) -> List[dict]:
        """
        Return one flat dict per plotted point or bar.

        Keys should match entry_schema. Use "ts" for the time axis.
        """
        return NotImplemented  # sentinel: not overridden

    def build_figure(self, entries: List[dict], params: dict) -> go.Figure:
        """
        Build and return a Plotly figure from the already-filtered entries.

        entries: list of dicts returned by build_data(), after _filter_* applied.
        params:  original user params (Param values, not filter params).
        """
        raise NotImplementedError

    # ── Legacy pattern ────────────────────────────────────────────────

    def compute(self, ctx: AnalysisContext, params: dict):
        """
        Legacy: implement this if you want full control over compute().

        Return a go.Figure or a raw Plotly dict.
        No auto-filter support when using this path.
        """
        raise NotImplementedError

    # ── Metadata ──────────────────────────────────────────────────────

    def to_info(self) -> Dict[str, Any]:
        """Serialise chart metadata for /api/research endpoint."""
        return {
            "name":         self.name,
            "title":        self.title,
            "description":  self.description,
            "category":     self.category,
            "params":       [p.to_dict() for p in self.params],
            "entry_schema": _normalize_schema(self.entry_schema),
        }


# ── Registry ─────────────────────────────────────────────────────────

_charts: Dict[str, ResearchChart] = {}


def register_chart(chart: ResearchChart):
    _charts[chart.name] = chart
    logger.info(f"Registered research chart: {chart.name}")


def get_charts() -> Dict[str, ResearchChart]:
    return _charts


def get_chart(name: str) -> Optional[ResearchChart]:
    return _charts.get(name)


def run_chart(name: str, ctx: AnalysisContext, params: dict,
              filter_params: Optional[dict] = None) -> dict:
    """
    Run a chart by name.

    Returns {"figure": <plotly dict>, "filter_schema": <schema dict>}.

    filter_params: dict of _filter_<field> / _filter_<field>_min/max keys.
                   Passed to _apply_filters() for charts using build_data/build_figure.
                   Ignored for legacy compute() charts.

    Raises KeyError if chart not found, ValueError on param errors.
    """
    chart = _charts.get(name)
    if not chart:
        raise KeyError(f"Research chart '{name}' not found")

    for p in chart.params:
        if p.required and not params.get(p.name, "").strip():
            raise ValueError(f"Required param '{p.name}' ({p.label}) is missing")

    try:
        # ── New path: build_data + build_figure ───────────────────────
        entries = chart.build_data(ctx, params)
        if entries is not NotImplemented:
            schema = _normalize_schema(chart.entry_schema)
            schema = _enrich_list_options(schema, entries)
            filtered = _apply_filters(entries, filter_params or {}, schema)
            fig = chart.build_figure(filtered, params)
            if isinstance(fig, go.Figure):
                fig.update_layout(SWIFTEYE_LAYOUT)
                return {"figure": fig.to_dict(), "filter_schema": schema}
            # build_figure returned a raw dict (allowed for edge cases)
            return {"figure": fig, "filter_schema": schema}

        # ── Legacy path: compute() ────────────────────────────────────
        result = chart.compute(ctx, params)
        if isinstance(result, go.Figure):
            result.update_layout(SWIFTEYE_LAYOUT)
            return {"figure": result.to_dict(), "filter_schema": {}}
        return {"figure": result, "filter_schema": {}}

    except Exception as e:
        logger.error(f"Research chart '{name}' failed: {e}", exc_info=True)
        raise
