"""
SwiftEye Plugin System

Plugins add analysis capabilities independently of the core viewer.
Each plugin can provide:
  - Backend analysis: runs on packets/sessions, produces structured results
  - UI slots: declares where its output appears in the frontend

== Rendering Protocol ==

Plugin results are returned as dicts keyed by slot_id. Each slot's data
can include a "_display" list that tells the frontend how to render it
generically, WITHOUT any custom frontend code.

Display element types:
  {"type": "row",   "label": "Guess", "value": "Linux 5.x"}
  {"type": "tags",  "items": [{"text": "MSS", "color": "#bc8cff"}, ...]}
  {"type": "list",  "items": [{"label": "10.0.0.1", "value": "42"}, ...]}
  {"type": "text",  "value": "Some explanatory note", "color": "#8b949e"}
  {"type": "table", "headers": ["IP", "Count"], "rows": [["10.0.0.1", "5"], ...]}

If "_display" is present, the generic renderer handles it.
If a frontend developer wants a richer UI for a specific plugin, they can
register a dedicated renderer that takes priority over the generic one.

Helper functions are provided so plugin developers don't need to build
_display lists manually:

  display_rows({"Guess": "Linux 5.x", "Confidence": "75%"})
  display_tags([("MSS", "#bc8cff"), ("WScale", "#bc8cff")])
  display_list([("10.0.0.1", "42 pkts"), ("10.0.0.2", "31 pkts")])
  display_text("Based on first SYN packet")
  display_table(["IP", "Count"], [["10.0.0.1", "5"], ["10.0.0.2", "3"]])

== UI Slot Types ==

  "node_detail_section"   : collapsible section in node detail panel
  "edge_detail_section"   : collapsible section in edge detail panel
  "session_detail_section" : section in session detail panel
  "stats_section"         : section in the stats/overview panel
  "right_panel"           : full panel tab in the right sidebar
  "graph_overlay"         : overlay rendered on the graph canvas
  "toolbar_widget"        : widget in the top toolbar
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

logger = logging.getLogger("swifteye.plugins")


# ── Display helpers ──────────────────────────────────────────────────
# Plugin developers use these to build _display lists without knowing
# the rendering format details.

def display_rows(pairs: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Key-value rows. Usage: display_rows({"Guess": "Linux", "TTL": 64})"""
    return [{"type": "row", "label": str(k), "value": str(v)} for k, v in pairs.items() if v is not None]


def display_tags(items: List[Tuple[str, str]]) -> Dict[str, Any]:
    """Colored tag badges. Usage: display_tags([("MSS", "#bc8cff"), ...])"""
    return {"type": "tags", "items": [{"text": str(t), "color": c} for t, c in items]}


def display_list(items: List[Tuple[str, Any]], clickable: bool = False) -> Dict[str, Any]:
    """Labeled list. Usage: display_list([("10.0.0.1", "42 pkts"), ...])"""
    return {
        "type": "list",
        "clickable": clickable,
        "items": [{"label": str(l), "value": str(v)} for l, v in items],
    }


def display_text(text: str, color: str = "#8b949e") -> Dict[str, Any]:
    """Freeform text note. Usage: display_text("Based on SYN packets")"""
    return {"type": "text", "value": text, "color": color}


def display_table(headers: List[str], rows: List[List[str]]) -> Dict[str, Any]:
    """Table with headers. Usage: display_table(["IP", "Count"], [["10.0.0.1", "5"]])"""
    return {"type": "table", "headers": headers, "rows": rows}


# ── Core classes ─────────────────────────────────────────────────────

@dataclass
class UISlot:
    """Declares a UI slot that this plugin fills."""
    slot_type: str          # e.g. "node_detail_section", "right_panel"
    slot_id: str            # unique ID for this slot instance
    title: str              # display title
    icon: str = ""          # optional icon name
    priority: int = 50      # ordering (lower = higher)
    default_open: bool = False  # for collapsible sections


@dataclass
class AnalysisContext:
    """Data available to plugins and analyses.

    This is the canonical context class. research/__init__.py aliases it
    as ResearchContext — they are the same type. Do NOT create a second class.
    """
    packets: list           # List[PacketRecord]
    sessions: list          # List[dict] - session dicts from sessions.py
    nodes: list = field(default_factory=list)    # graph nodes (if available)
    edges: list = field(default_factory=list)    # graph edges (if available)
    time_range: tuple = None                     # (t_start, t_end) Unix seconds if scoped

    # Query helpers
    target_node_id: Optional[str] = None   # if analysis is for a specific node
    target_edge_id: Optional[str] = None   # if analysis is for a specific edge
    target_session_id: Optional[str] = None  # if analysis is for a specific session


class PluginBase(ABC):
    """
    Base class for SwiftEye analysis plugins.
    
    To create a plugin:
      1. Subclass PluginBase
      2. Set name, description, version
      3. Implement get_ui_slots() — declare where your output appears
      4. Implement analyze_global() — return data keyed by slot_id
      5. Include "_display" lists in your slot data for automatic rendering
      6. Add to plugin_specs in server.py
    
    The "_display" key is optional but recommended. Without it, your data
    won't render in the frontend unless a dedicated renderer exists for
    your plugin. With it, the generic renderer handles everything.
    """

    name: str = "unnamed"
    description: str = ""
    version: str = "0.1.0"

    @abstractmethod
    def get_ui_slots(self) -> List[UISlot]:
        """Declare which UI slots this plugin fills."""
        pass

    @abstractmethod
    def analyze_global(self, ctx: AnalysisContext) -> Dict[str, Any]:
        """
        Run global analysis (on full capture).
        Returns dict keyed by slot_id -> slot data.
        Each slot_id's data can include a "_display" list for generic rendering.
        Called once after pcap load.
        """
        pass

    def analyze_node(self, ctx: AnalysisContext) -> Dict[str, Any]:
        """Run per-node analysis. ctx.target_node_id is set."""
        return {}

    def analyze_edge(self, ctx: AnalysisContext) -> Dict[str, Any]:
        """Run per-edge analysis. ctx.target_edge_id is set."""
        return {}

    def analyze_session(self, ctx: AnalysisContext) -> Dict[str, Any]:
        """Run per-session analysis. ctx.target_session_id is set."""
        return {}


# ── Plugin Registry ──────────────────────────────────────────────────

_plugins: Dict[str, PluginBase] = {}
_global_results: Dict[str, Dict[str, Any]] = {}  # plugin_name -> results


def register_plugin(plugin: PluginBase):
    """Register a plugin instance."""
    _plugins[plugin.name] = plugin
    logger.info(f"Registered plugin: {plugin.name} v{plugin.version}")


def get_plugins() -> Dict[str, PluginBase]:
    return _plugins


def get_plugin(name: str) -> Optional[PluginBase]:
    return _plugins.get(name)


def run_global_analysis(ctx: AnalysisContext):
    """Run all plugins' global analysis. Call after pcap load."""
    _global_results.clear()
    for name, plugin in _plugins.items():
        try:
            results = plugin.analyze_global(ctx)
            _global_results[name] = results
            logger.info(f"Plugin '{name}' global analysis complete")
        except Exception as e:
            logger.error(f"Plugin '{name}' global analysis failed: {e}")
            _global_results[name] = {"error": str(e)}


def get_global_results() -> Dict[str, Dict[str, Any]]:
    return _global_results


def get_node_analysis(node_id: str, ctx: AnalysisContext) -> Dict[str, Dict[str, Any]]:
    """Run all plugins' per-node analysis."""
    ctx.target_node_id = node_id
    results = {}
    for name, plugin in _plugins.items():
        try:
            results[name] = plugin.analyze_node(ctx)
        except Exception as e:
            logger.error(f"Plugin '{name}' node analysis failed: {e}")
    return results


def get_edge_analysis(edge_id: str, ctx: AnalysisContext) -> Dict[str, Dict[str, Any]]:
    ctx.target_edge_id = edge_id
    results = {}
    for name, plugin in _plugins.items():
        try:
            results[name] = plugin.analyze_edge(ctx)
        except Exception as e:
            logger.error(f"Plugin '{name}' edge analysis failed: {e}")
    return results


def get_all_ui_slots() -> List[Dict[str, Any]]:
    """Get all UI slot declarations from all plugins."""
    slots = []
    for name, plugin in _plugins.items():
        for slot in plugin.get_ui_slots():
            slots.append({
                "plugin": name,
                "slot_type": slot.slot_type,
                "slot_id": slot.slot_id,
                "title": slot.title,
                "icon": slot.icon,
                "priority": slot.priority,
                "default_open": slot.default_open,
            })
    return sorted(slots, key=lambda s: s["priority"])
