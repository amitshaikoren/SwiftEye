import logging

from fastapi import APIRouter, HTTPException

from workspaces.network.store import store, _require_capture
from workspaces.network.analysis import filter_packets
from workspaces.network.plugins import AnalysisContext
from workspaces.network.research import get_charts, get_chart, run_chart
from workspaces.network.research.custom_chart import sources_info, source_has_data, build_figure
from workspaces.network.constants import SWIFTEYE_LAYOUT

logger = logging.getLogger("swifteye.routes.research")
router = APIRouter()


@router.get("/api/research")
async def get_research_charts():
    """
    List all registered research charts with their param declarations.

    Does NOT require a capture — chart registration happens at server startup
    and is independent of what is loaded. The run endpoint (POST) still requires
    a capture because it needs packets to compute against.
    """
    return {"charts": [c.to_info() for c in get_charts().values()]}


# ── Custom chart endpoints ────────────────────────────────────────────────────
# IMPORTANT: these must be declared BEFORE the wildcard /{chart_name} route.
# FastAPI matches routes in declaration order; if /{chart_name} came first,
# "custom" would be matched as a chart_name and raise a 404.

@router.get("/api/research/custom/schema")
async def get_custom_chart_schema():
    """
    Return the available data sources and their fields for the custom chart builder.

    When a capture is loaded the field lists are extended with any extra keys
    discovered from actual packet data (new dissectors auto-appear).
    The has_data flags indicate which sources have matching packets in the capture.

    Does NOT require a capture — returns static schema with has_data=False when empty.
    """
    loaded = store.is_loaded
    pkts   = store.packets   if loaded else []
    sess   = store.sessions  if loaded else []
    result = []
    for src in sources_info(pkts, sess):
        src["has_data"] = source_has_data(src["id"], pkts, sess) if loaded else False
        result.append(src)
    return {"sources": result}


@router.post("/api/research/custom")
async def run_custom_chart(body: dict):
    """
    Build and return a custom Plotly figure from a field-mapping payload.

    Body: {
      source, chart_type, x_field, y_field, color_field, size_field,
      hover_fields, title,
      _timeStart, _timeEnd, _filterProtocols, _filterSearch, _filterIncludeIpv6
    }

    Response: { "figure": { "data": [...], "layout": {...} } }
    """
    _require_capture()
    try:
        t_start = body.get("_timeStart")
        t_end   = body.get("_timeEnd")
        f_protocols    = body.get("_filterProtocols")
        f_search       = body.get("_filterSearch", "")
        f_include_ipv6 = body.get("_filterIncludeIpv6", True)

        pkts = filter_packets(
            store.packets,
            time_range=(t_start, t_end) if t_start is not None and t_end is not None else None,
            protocols=set(f_protocols.split(",")) if f_protocols else None,
            search_query=f_search,
            include_ipv6=f_include_ipv6,
        )
        sess = store.sessions
        if t_start is not None and t_end is not None or f_protocols or f_search or not f_include_ipv6:
            active_keys = {p.session_key for p in pkts}
            sess = [s for s in sess if s.get("id") in active_keys]

        payload = {k: v for k, v in body.items() if not k.startswith("_")}
        fig = build_figure(payload, pkts, sess)
        fig.update_layout(SWIFTEYE_LAYOUT)
        return {"figure": fig.to_dict()}
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error(f"Custom chart failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ── Built-in research chart run endpoint ─────────────────────────────────────
# Must come AFTER the /custom routes above.

@router.post("/api/research/{chart_name}")
async def run_research_chart(chart_name: str, body: dict):
    """
    Run a research chart and return a Plotly figure dict plus a filter schema.

    Body keys:
      "param_name": "value"    — user params declared by the chart (Param instances)
      "_timeStart": float      — Unix seconds; used to pre-filter packets/sessions
      "_timeEnd":   float      — Unix seconds
      "_filterProtocols": str  — comma-separated protocol names for SCOPED mode
      "_filterSearch": str     — keyword search for SCOPED mode
      "_filterIncludeIpv6": bool
      "_filter_<field>": any   — per-chart data filter (passed to build_data/filter path)
      "_filter_<field>_min/max": numeric bounds for numeric fields

    Response: { "figure": { "data": [...], "layout": {...} },
                "filter_schema": { "field": { "type": ..., ["options": [...]] } } }

    filter_schema is empty ({}) for legacy charts that implement compute() directly.
    """
    _require_capture()
    chart = get_chart(chart_name)
    if not chart:
        raise HTTPException(status_code=404, detail=f"Research chart '{chart_name}' not found")
    try:
        # User params (non-underscore keys)
        chart_params = {k: v for k, v in body.items() if not k.startswith('_')}

        # Stream-level filters (applied before compute / build_data)
        t_start = body.get('_timeStart')
        t_end   = body.get('_timeEnd')
        f_protocols    = body.get('_filterProtocols')
        f_search       = body.get('_filterSearch', '')
        f_include_ipv6 = body.get('_filterIncludeIpv6', True)

        # Per-chart data filters (applied to entries after build_data)
        filter_params = {k: v for k, v in body.items() if k.startswith('_filter_')}

        pkts = filter_packets(
            store.packets,
            time_range=(t_start, t_end) if t_start is not None and t_end is not None else None,
            protocols=set(f_protocols.split(',')) if f_protocols else None,
            search_query=f_search,
            include_ipv6=f_include_ipv6,
        )

        sess = store.sessions
        if t_start is not None and t_end is not None or f_protocols or f_search or not f_include_ipv6:
            active_keys = {p.session_key for p in pkts}
            sess = [s for s in sess if s.get('id') in active_keys]

        ctx = AnalysisContext(
            packets=pkts, sessions=sess,
            time_range=(t_start, t_end) if t_start is not None and t_end is not None else None,
        )
        result = run_chart(chart_name, ctx, chart_params, filter_params=filter_params)
        return result
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error(f"Research chart '{chart_name}' failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
