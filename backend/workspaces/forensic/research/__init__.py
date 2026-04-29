"""
ForensicResearchChart — workspace-local research chart base for forensic data.

Mirrors the network workspace's ResearchChart infrastructure but operates on
forensic events/graph rather than network packets/sessions.

Charts:
  - build_data(ctx, params) -> List[dict]  (filterable path)
  - build_figure(entries, params) -> go.Figure
"""

import logging
from abc import ABC
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from workspaces.network.constants import SWIFTEYE_LAYOUT

try:
    import plotly.graph_objects as go
    _PLOTLY_AVAILABLE = True
except ImportError:
    go = None  # type: ignore[assignment]
    _PLOTLY_AVAILABLE = False

logger = logging.getLogger("swifteye.forensic.research")
if not _PLOTLY_AVAILABLE:
    logger.warning("plotly not installed — forensic research charts disabled. pip install plotly")


@dataclass
class ForensicContext:
    """Data available to forensic research charts."""
    events: List[Any]         # List[Event] from ForensicStore
    nodes:  List[Dict[str, Any]] = field(default_factory=list)
    edges:  List[Dict[str, Any]] = field(default_factory=list)


class ForensicResearchChart(ABC):
    name:        str = ""
    title:       str = ""
    description: str = ""
    category:    str = "capture"
    params:      list = []

    def build_data(self, ctx: ForensicContext, params: dict) -> List[dict]:
        return NotImplemented

    def build_figure(self, entries: List[dict], params: dict):
        raise NotImplementedError

    def to_info(self) -> Dict[str, Any]:
        return {
            "name":         self.name,
            "title":        self.title,
            "description":  self.description,
            "category":     self.category,
            "params":       [],
            "entry_schema": {},
        }


_charts: Dict[str, ForensicResearchChart] = {}


def register_chart(chart: ForensicResearchChart) -> None:
    _charts[chart.name] = chart
    logger.info(f"Registered forensic research chart: {chart.name}")


def get_charts() -> Dict[str, ForensicResearchChart]:
    return _charts


def get_chart(name: str) -> Optional[ForensicResearchChart]:
    return _charts.get(name)


def run_chart(name: str, ctx: ForensicContext, params: dict,
              filter_params: Optional[dict] = None) -> dict:
    chart = _charts.get(name)
    if not chart:
        raise KeyError(f"Forensic research chart '{name}' not found")
    if not _PLOTLY_AVAILABLE:
        raise RuntimeError("plotly not installed — pip install plotly")
    try:
        entries = chart.build_data(ctx, params)
        if entries is not NotImplemented:
            fig = chart.build_figure(entries, params)
            if go is not None and isinstance(fig, go.Figure):
                fig.update_layout(SWIFTEYE_LAYOUT)
                return {"figure": fig.to_dict(), "filter_schema": {}}
            return {"figure": fig, "filter_schema": {}}
        raise NotImplementedError(f"Chart '{name}' has no build_data implementation")
    except Exception as e:
        logger.error(f"Forensic chart '{name}' failed: {e}", exc_info=True)
        raise
