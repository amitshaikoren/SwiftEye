"""
Capture orchestration — plugin/analysis pipeline run after a capture loads.

This is the server's concern, separate from CaptureStore (viewer layer).
Removing all plugins leaves CaptureStore fully functional.
"""

import time
import logging

from data import build_graph
from plugins import AnalysisContext, run_global_analysis, get_global_results
from plugins.analyses import run_all_analyses
from plugins.alerts import run_all_detectors
from store import store

logger = logging.getLogger("swifteye.services")


def run_plugins():
    """Run all registered insight plugins against the current capture."""
    if not store.is_loaded:
        return
    logger.info("Running plugin analysis...")
    t0 = time.time()
    ctx = AnalysisContext(packets=store.packets, sessions=store.sessions)
    run_global_analysis(ctx)
    logger.info(f"  Insights completed in {time.time()-t0:.2f}s")


def build_analysis_graph_and_run():
    """
    Build an unfiltered graph and run all analyses against it.
    Analyses always see the full capture — never a filtered subset.
    The unfiltered graph is cached in store.graph_cache.
    """
    if not store.is_loaded:
        return
    logger.info("Building unfiltered graph for analyses...")
    t0 = time.time()

    dns_results = get_global_results().get("dns_resolver", {})
    hostname_map = dns_results.get("dns_hostnames", {})

    unfiltered = build_graph(
        store.packets,
        hostname_map=hostname_map,
        metadata_map=store.metadata_map,
    )
    enrich_nodes_with_plugins(unfiltered["nodes"], get_global_results())
    store.graph_cache = {"nodes": unfiltered["nodes"], "edges": unfiltered["edges"]}
    # Propagate plugin-enriched fields to the analysis graph so the query engine can filter on them.
    if store.analysis_graph is not None:
        for node in unfiltered["nodes"]:
            nid = node.get("id")
            if nid and store.analysis_graph.has_node(nid):
                if "os_guess" in node:
                    store.analysis_graph.nodes[nid]["os_guess"] = node["os_guess"]
                if "plugin_data" in node:
                    store.analysis_graph.nodes[nid]["plugin_data"] = node["plugin_data"]
                    role = (node["plugin_data"] or {}).get("network_role", {})
                    if isinstance(role, dict) and role.get("role") == "gateway":
                        store.analysis_graph.nodes[nid]["is_gateway"] = True
    logger.info(f"  Unfiltered graph: {len(unfiltered['nodes'])} nodes, {len(unfiltered['edges'])} edges in {time.time()-t0:.2f}s")

    run_analyses()
    run_alert_detectors()


def run_alert_detectors():
    """Run all registered alert detectors against the current capture."""
    if not store.is_loaded or not store.graph_cache:
        return
    logger.info("Running alert detectors...")
    t0 = time.time()
    ctx = AnalysisContext(
        packets=store.packets,
        sessions=store.sessions,
        nodes=store.graph_cache.get("nodes", []),
        edges=store.graph_cache.get("edges", []),
    )
    store.alerts = run_all_detectors(ctx)
    logger.info(f"  Alert detectors: {len(store.alerts)} findings in {time.time()-t0:.2f}s")


def run_analyses():
    """Run all registered analysis plugins against the cached unfiltered graph."""
    if not store.is_loaded or not store.graph_cache:
        return
    logger.info("Running analyses...")
    t0 = time.time()
    ctx = AnalysisContext(
        packets=store.packets,
        sessions=store.sessions,
        nodes=store.graph_cache.get("nodes", []),
        edges=store.graph_cache.get("edges", []),
    )
    run_all_analyses(ctx)
    logger.info(f"  Analyses completed in {time.time()-t0:.2f}s")


def enrich_nodes_with_plugins(nodes: list, plugin_results: dict):
    """
    Attach per-node plugin data to graph nodes generically.

    Also extracts a flat `os_guess` string from the OS fingerprint plugin
    (if present) so the display filter and OS dropdown can use it directly
    without digging into plugin_data.
    """
    ip_maps = {}  # (plugin_name, slot_id) → {ip: data}
    for plugin_name, results in plugin_results.items():
        if not isinstance(results, dict):
            continue
        for slot_id, slot_data in results.items():
            if isinstance(slot_data, dict) and _looks_like_ip_keyed(slot_data):
                ip_maps[(plugin_name, slot_id)] = slot_data

    os_fp_map = {}
    os_fp_slot = plugin_results.get("os_fingerprint", {}).get("os_fingerprint", {})
    if isinstance(os_fp_slot, dict):
        for ip, fp in os_fp_slot.items():
            if isinstance(fp, dict) and "guess" in fp:
                os_fp_map[ip] = fp["guess"]

    for node in nodes:
        node_plugin_data = {}
        for ip in node.get("ips", [node.get("id")]):
            for (plugin_name, slot_id), ip_data in ip_maps.items():
                if ip in ip_data:
                    node_plugin_data[slot_id] = ip_data[ip]
        if node_plugin_data:
            node["plugin_data"] = node_plugin_data

        for ip in node.get("ips", [node.get("id")]):
            if ip in os_fp_map:
                node["os_guess"] = os_fp_map[ip]
                break

        role_data = node.get("plugin_data", {}).get("network_role", {})
        if isinstance(role_data, dict) and role_data.get("role") == "gateway":
            node["os_guess"] = "Network device (gateway)"


def _looks_like_ip_keyed(d: dict) -> bool:
    """Check if a dict looks like it's keyed by IP addresses (sample first few keys)."""
    if not d:
        return False
    sample = list(d.keys())[:5]
    for key in sample:
        if isinstance(key, str) and ("." in key or ":" in key):
            return True
    return False
