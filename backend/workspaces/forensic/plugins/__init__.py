"""
Forensic workspace plugin system.

Plugins add classification and enrichment capabilities to forensic graph nodes.
Each plugin implements analyze_global(ctx) -> dict keyed by slot_id.

Writing a new classifier:
  1. Create backend/workspaces/forensic/plugins/classifiers/my_classifier.py
  2. Subclass ForensicPluginBase, implement analyze_global(ctx)
  3. Call register_forensic_plugin(MyClassifier()) at module level
  4. Import the module in classifiers/__init__.py

Display helpers (display_rows, display_tags, display_list, display_text) build
_display lists that the generic frontend renderer handles automatically.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("swifteye.forensic.plugins")


# ── Display helpers ──────────────────────────────────────────────────────────

def display_rows(pairs: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [{"type": "row", "label": str(k), "value": str(v)} for k, v in pairs.items() if v is not None]


def display_tags(items: List[tuple]) -> Dict[str, Any]:
    return {"type": "tags", "items": [{"text": str(t), "color": c} for t, c in items]}


def display_list(items: List[tuple]) -> Dict[str, Any]:
    return {"type": "list", "items": [{"label": str(l), "value": str(v)} for l, v in items]}


def display_text(text: str, color: str = "#8b949e") -> Dict[str, Any]:
    return {"type": "text", "value": text, "color": color}


# ── Context ──────────────────────────────────────────────────────────────────

@dataclass
class ForensicAnalysisContext:
    """Data available to forensic plugins."""
    events: list                                    # List[Event]
    nodes: list                                     # graph node dicts
    edges: list                                     # graph edge dicts
    target_node_id: Optional[str] = None

    _node_map: Optional[dict] = field(default=None, repr=False)

    @property
    def node_map(self) -> dict:
        if self._node_map is None:
            self._node_map = {n["id"]: n for n in self.nodes} if self.nodes else {}
        return self._node_map


# ── Base class ───────────────────────────────────────────────────────────────

@dataclass
class UISlot:
    slot_type: str
    slot_id: str
    title: str
    priority: int = 50
    default_open: bool = False


class ForensicPluginBase(ABC):
    name: str = ""
    description: str = ""
    version: str = "0.1.0"

    def get_ui_slots(self) -> List[UISlot]:
        return []

    @abstractmethod
    def analyze_global(self, ctx: ForensicAnalysisContext) -> Dict[str, Any]:
        """
        Classify/enrich all relevant nodes.
        Returns dict keyed by slot_id -> {node_id -> slot_data}.
        Each slot_data may include a "_display" list for generic rendering.
        """


# ── Registry ─────────────────────────────────────────────────────────────────

_plugins: Dict[str, ForensicPluginBase] = {}


def register_forensic_plugin(plugin: ForensicPluginBase) -> None:
    _plugins[plugin.name] = plugin
    logger.info(f"Registered forensic plugin: {plugin.name} v{plugin.version}")


def get_forensic_plugins() -> Dict[str, ForensicPluginBase]:
    return _plugins


def run_all_forensic_plugins(ctx: ForensicAnalysisContext) -> Dict[str, Any]:
    """
    Run all registered forensic plugins and merge results.
    Returns dict keyed by plugin name -> slot results.
    """
    results: Dict[str, Any] = {}
    for name, plugin in _plugins.items():
        try:
            results[name] = plugin.analyze_global(ctx)
        except Exception as e:
            logger.error(f"Forensic plugin '{name}' failed: {e}", exc_info=True)
    return results


# Import classifiers so they self-register at server startup
from workspaces.forensic.plugins import classifiers  # noqa: E402, F401
