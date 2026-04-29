import logging

from fastapi import APIRouter, HTTPException

from workspaces.network.store import store, _require_capture
from workspaces.network.plugins import AnalysisContext, get_node_analysis, get_global_results, get_plugins, get_all_ui_slots
from workspaces.network.plugins.analyses import get_analyses, get_analysis_results, clear_analysis_results
from core.services.capture import build_analysis_graph_and_run

logger = logging.getLogger("swifteye.routes.plugins")
router = APIRouter()


@router.get("/api/plugins")
async def get_plugins_info():
    """
    Get registered plugins and their UI slot declarations.

    Does NOT require a capture — plugin registration happens at server startup.
    The UI uses slot declarations to know where to render plugin sections;
    this metadata is independent of what is loaded. Plugin *results* (from
    GET /api/plugins/results) still require a capture.
    """
    plugins_info = []
    for name, plugin in get_plugins().items():
        plugins_info.append({
            "name": name,
            "description": plugin.description,
            "version": plugin.version,
            "ui_slots": [{"slot_type": s.slot_type, "slot_id": s.slot_id, "title": s.title, "priority": s.priority, "default_open": s.default_open} for s in plugin.get_ui_slots()],
        })
    return {"plugins": plugins_info, "ui_slots": get_all_ui_slots()}


@router.get("/api/plugins/results")
async def get_plugin_results():
    """Get all global plugin analysis results."""
    _require_capture()
    return {"results": get_global_results()}


@router.get("/api/plugins/node/{node_id}")
async def get_plugin_node_results(node_id: str):
    """Get plugin analysis for a specific node."""
    _require_capture()
    ctx = AnalysisContext(packets=store.packets, sessions=store.sessions)
    return {"results": get_node_analysis(node_id, ctx)}


@router.get("/api/analysis")
async def get_analysis_info():
    """Get registered analysis plugins (metadata only, no capture required)."""
    return {
        "analyses": [
            {
                "name": a.name,
                "title": a.title,
                "description": a.description,
                "icon": a.icon,
                "version": a.version,
            }
            for a in get_analyses().values()
        ]
    }


@router.get("/api/analysis/results")
async def get_analysis_results_endpoint():
    """
    Get all analysis results. Analyses run lazily after the first graph build.
    Returns empty results if no capture is loaded.
    """
    results = get_analysis_results()
    if not results and store.is_loaded:
        build_analysis_graph_and_run()
        results = get_analysis_results()
    return {"results": results}


@router.post("/api/analysis/rerun")
async def rerun_analyses():
    """Force re-run all analyses on the unfiltered graph."""
    _require_capture()
    build_analysis_graph_and_run()
    return {"results": get_analysis_results()}
