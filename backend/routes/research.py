import logging

from fastapi import APIRouter, HTTPException

from store import store, _require_capture
from data import filter_packets
from plugins import AnalysisContext
from research import get_charts, get_chart, run_chart
from research.custom_chart import sources_info, source_has_data, build_figure

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


@router.post("/api/research/{chart_name}")
async def run_research_chart(chart_name: str, body: dict):
    """
    Run a research chart and return a Plotly figure dict.

    Body: { "param_name": "value", ..., "_timeStart": float, "_timeEnd": float }
    Reserved keys _timeStart / _timeEnd (Unix seconds) are stripped before
    passing to the chart and used to filter packets and sessions by time window.

    Response: { "figure": { "data": [...], "layout": {...} } }
    """
    _require_capture()
    chart = get_chart(chart_name)
    if not chart:
        raise HTTPException(status_code=404, detail=f"Research chart '{chart_name}' not found")
    try:
        chart_params = {k: v for k, v in body.items() if not k.startswith('_')}
        t_start = body.get('_timeStart')
        t_end   = body.get('_timeEnd')

        f_protocols    = body.get('_filterProtocols')
        f_search       = body.get('_filterSearch', '')
        f_include_ipv6 = body.get('_filterIncludeIpv6', True)

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

        ctx    = AnalysisContext(packets=pkts, sessions=sess,
                                time_range=(t_start, t_end) if t_start is not None and t_end is not None else None)
        figure = run_chart(chart_name, ctx, chart_params)
        return {"figure": figure}
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error(f"Research chart '{chart_name}' failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ── Custom chart endpoints ────────────────────────────────────────────────────

@router.get("/api/research/custom/schema")
async def get_custom_chart_schema():
    """
    Return the available data sources and their fields for the custom chart builder.
    Also returns which sources have data in the current capture (if one is loaded).

    Does NOT require a capture — the schema is static. The `has_data` flags will
    all be False when no capture is loaded.
    """
    loaded = store.is_loaded
    result = []
    for src in sources_info():
        src["has_data"] = source_has_data(src["id"], store.packets, store.sessions) if loaded else False
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

        # Strip internal keys before passing payload to builder
        payload = {k: v for k, v in body.items() if not k.startswith("_")}
        figure = build_figure(payload, pkts, sess)
        return {"figure": figure}
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error(f"Custom chart failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
