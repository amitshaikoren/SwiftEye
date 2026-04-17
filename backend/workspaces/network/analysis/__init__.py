"""Network workspace — analysis modules (aggregation, sessions, stats, edge fields).

Re-exports the public surface that used to live at `data/__init__.py`.
"""

from .aggregator import (
    build_time_buckets,
    build_graph,
    build_analysis_graph,
    get_subnets,
    filter_packets,
    build_node_session_events,
    build_node_animation_response,
)
from .sessions import build_sessions
from .stats import compute_global_stats

__all__ = [
    "build_time_buckets",
    "build_graph",
    "build_analysis_graph",
    "filter_packets",
    "build_sessions",
    "compute_global_stats",
    "get_subnets",
    "build_node_session_events",
    "build_node_animation_response",
]
