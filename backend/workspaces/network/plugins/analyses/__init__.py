"""
SwiftEye Analysis Plugins — graph-wide computation.

Analyses compute over the entire graph structure: centrality metrics,
traffic classification, protocol hierarchies. Unlike insights (which
interpret individual entities), analyses produce ranked/aggregated results
across all nodes or sessions.

Architecture:
  - Each analysis plugin subclasses AnalysisPluginBase
  - Implements compute(ctx) → dict with _display lists for generic rendering
  - Registered in server.py via register_analysis()
  - Frontend fetches /api/analysis/results and renders cards generically

The _display protocol is identical to insight plugins — same element types
(row, tags, list, text, table), same generic renderer on the frontend.

Writing a new analysis:
  1. Create backend/plugins/analyses/my_analysis.py
  2. Subclass AnalysisPluginBase
  3. Set name, title, description
  4. Implement compute(ctx) → dict with _display
  5. Register in server.py _register_analyses()
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

logger = logging.getLogger("swifteye.plugins.analyses")


class AnalysisPluginBase(ABC):
    """
    Base class for graph-wide analysis plugins.

    Unlike insight plugins (PluginBase), analysis plugins:
      - Always operate on the full graph (nodes + edges + sessions)
      - Return a single AnalysisResult, not keyed by UI slot
      - Are run on-demand via /api/analysis/run, not at pcap load time
      - Are rendered as expandable cards on the Analysis page
    """
    name: str = ""
    title: str = ""
    description: str = ""
    icon: str = "📊"
    version: str = "1.0"

    @abstractmethod
    def compute(self, ctx) -> dict:
        """
        Run the analysis.

        ctx has: packets, sessions, nodes, edges, time_range

        Returns dict with:
          - Any structured data
          - A "_display" list for generic rendering
        """
        pass


# ── Registry ────────────────────────────────────────────────────────

_analyses: Dict[str, AnalysisPluginBase] = {}
_analysis_results: Dict[str, dict] = {}


def register_analysis(plugin: AnalysisPluginBase):
    _analyses[plugin.name] = plugin
    logger.info(f"Registered analysis: {plugin.name} v{plugin.version}")


def get_analyses() -> Dict[str, AnalysisPluginBase]:
    return _analyses


def get_analysis(name: str) -> Optional[AnalysisPluginBase]:
    return _analyses.get(name)


def run_all_analyses(ctx) -> Dict[str, dict]:
    """Run all registered analyses against the current capture."""
    _analysis_results.clear()
    for name, plugin in _analyses.items():
        try:
            result = plugin.compute(ctx)
            _analysis_results[name] = {
                "title": plugin.title,
                "icon": plugin.icon,
                "description": plugin.description,
                "badge": "LIVE",
                "data": result,
            }
            logger.info(f"Analysis '{name}' complete")
        except Exception as e:
            logger.error(f"Analysis '{name}' failed: {e}", exc_info=True)
            _analysis_results[name] = {
                "title": plugin.title,
                "icon": plugin.icon,
                "description": plugin.description,
                "badge": "ERROR",
                "data": {"error": str(e)},
            }
    return _analysis_results


def get_analysis_results() -> Dict[str, dict]:
    return _analysis_results


def clear_analysis_results():
    """Clear cached results. Call on new capture upload."""
    _analysis_results.clear()
