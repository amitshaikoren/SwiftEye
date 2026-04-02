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
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
import plotly.graph_objects as go
from constants import PROTOCOL_COLORS, SWIFTEYE_LAYOUT

logger = logging.getLogger("swifteye.research")



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

    Subclass this, set the class attributes, implement compute().
    See module docstring for a full example.
    """
    name:        str = ""   # unique slug, used in URL: /api/research/{name}
    title:       str = ""   # shown in the UI chart picker
    description: str = ""   # one sentence — what question does this answer?
    category:    str = "capture"  # palette category: "host" | "session" | "capture" | "alerts" | "other"
    params: List[Param] = []

    @abstractmethod
    def compute(self, ctx: AnalysisContext, params: dict) -> go.Figure:
        """
        Compute the chart for the given params.

        params: dict keyed by Param.name → user-supplied value (always str)

        Return a go.Figure. The framework applies SWIFTEYE_LAYOUT and calls
        .to_dict() before sending to the frontend — do not do either yourself.
        """
        pass

    def to_info(self) -> Dict[str, Any]:
        """Serialise chart metadata for /api/research endpoint."""
        return {
            "name":        self.name,
            "title":       self.title,
            "description": self.description,
            "category":    self.category,
            "params":      [p.to_dict() for p in self.params],
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


def run_chart(name: str, ctx: AnalysisContext, params: dict) -> dict:
    """
    Run a chart by name. Returns Plotly figure dict.
    Raises KeyError if chart not found, ValueError on param errors.
    """
    chart = _charts.get(name)
    if not chart:
        raise KeyError(f"Research chart '{name}' not found")

    # validate required params
    for p in chart.params:
        if p.required and not params.get(p.name, "").strip():
            raise ValueError(f"Required param '{p.name}' ({p.label}) is missing")

    try:
        result = chart.compute(ctx, params)
        if isinstance(result, go.Figure):
            result.update_layout(SWIFTEYE_LAYOUT)
            return result.to_dict()
        return result  # backwards compat: existing charts that return raw dicts
    except Exception as e:
        logger.error(f"Research chart '{name}' compute failed: {e}", exc_info=True)
        raise
