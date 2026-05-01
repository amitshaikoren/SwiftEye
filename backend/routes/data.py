import os
import shutil
import tempfile
import time
import uuid
import logging
from pathlib import Path
from typing import Optional, List

from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Query
from pydantic import BaseModel

from workspaces.network.store import store, _require_capture
from workspaces.network.analysis import build_time_buckets, build_graph, filter_packets, compute_global_stats, get_subnets
from workspaces.network.analysis.aggregator import get_edge_detail
from core.data.algorithms import compute_clusters, find_paths
from workspaces.network.plugins import get_global_results
from workspaces.network.plugins.insights.node_merger import build_entity_map
from workspaces.network.plugins.analyses import get_analysis_results, clear_analysis_results
from workspaces.network.parser import read_pcap, PacketRecord, MAX_FILE_SIZE
from workspaces.network.parser.adapters import detect_adapter, find_adapter_by_name, ADAPTERS
from workspaces.network.parser.schema import inspect_schema, stage_file
from workspaces.network.parser.parallel_reader import prescan_capture
from workspaces.network.load_filter import LoadFilter, apply_post_parse_filter
from workspaces.network.constants import PROTOCOL_COLORS
from core.models import (
    UploadResponse, StatsResponse, TimelineResponse, GraphResponse,
    SessionsResponse, SessionDetailResponse, ProtocolsResponse, SubnetsResponse,
)
from core.services.capture import run_plugins, build_analysis_graph_and_run, enrich_nodes_with_plugins, _looks_like_ip_keyed

logger = logging.getLogger("swifteye.routes.data")
router = APIRouter()

# ── Prescan cache ─────────────────────────────────────────────────────────────
# Maps token → {"tmp_dir": str, "tmp_path": str, "expires": float}
_PRESCAN_CACHE: dict = {}
_PRESCAN_TTL = 30 * 60  # 30 minutes


def _cleanup_prescan_cache() -> None:
    now = time.time()
    expired = [k for k, v in _PRESCAN_CACHE.items() if v["expires"] < now]
    for k in expired:
        entry = _PRESCAN_CACHE.pop(k)
        shutil.rmtree(entry["tmp_dir"], ignore_errors=True)


# ── Pydantic models for two-phase load ───────────────────────────────────────

class _FilterSpec(BaseModel):
    ts_start:       Optional[float] = None
    ts_end:         Optional[float] = None
    protocols:      Optional[List[str]] = None
    ip_whitelist:   Optional[List[str]] = None
    ip_blacklist:   Optional[List[str]] = None
    port_whitelist: Optional[List[str]] = None
    port_blacklist: Optional[List[str]] = None
    top_k_nodes:    Optional[int] = None
    max_packets:    int = 2_000_000
    component_ids:  Optional[List[int]] = None  # prescan component indices → resolved to ip_whitelist


class _PrescanLoadRequest(BaseModel):
    token:  str
    filter: _FilterSpec = _FilterSpec()


@router.post("/api/upload", response_model=UploadResponse)
async def upload_pcap(files: List[UploadFile] = File(...), force_adapter: Optional[str] = Form(None)):
    """Upload and parse capture files or log files. Multiple files are merged by timestamp."""
    if not files:
        raise HTTPException(400, "No files provided")

    supported_exts = set()
    for adapter_cls in ADAPTERS:
        supported_exts.update(adapter_cls.file_extensions)

    all_packets: list[PacketRecord] = []
    total_size  = 0
    file_names  = []
    t0 = time.time()

    tmp_dir = tempfile.mkdtemp(prefix="swifteye_upload_")
    tmp_files: list[Path] = []
    # Tracks whether we moved a file into staging — if so, don't clean tmp_dir.
    needs_staging = False

    try:
        for file in files:
            if not file.filename:
                continue

            content   = await file.read()
            file_size = len(content)
            if file_size == 0:
                raise HTTPException(400, f"File is empty: {file.filename}")
            if file_size > MAX_FILE_SIZE:
                raise HTTPException(413, f"File too large: {file.filename} "
                                         f"({file_size/1024/1024:.1f}MB, max {MAX_FILE_SIZE//1024//1024}MB)")

            total_size += file_size
            file_names.append(file.filename)

            safe_name = Path(file.filename).name
            tmp_path = Path(tmp_dir) / safe_name
            tmp_path.write_bytes(content)
            tmp_files.append(tmp_path)

        for tmp_path in tmp_files:
            try:
                if force_adapter:
                    adapter = find_adapter_by_name(force_adapter)
                    if not adapter:
                        raise HTTPException(400, f"Unknown adapter: {force_adapter!r}")
                else:
                    adapter = detect_adapter(tmp_path)
                if not adapter:
                    parse_ms = int((time.time() - t0) * 1000)
                    return UploadResponse(
                        success=False,
                        capture_id="",
                        file_name=tmp_path.name,
                        source_files=[tmp_path.name],
                        packet_count=0,
                        parse_time_ms=parse_ms,
                        file_size_bytes=total_size,
                        detection_failed=True,
                        available_adapters=[cls.name for cls in ADAPTERS if cls.name],
                    )

                # ── Schema negotiation (phase 1) ──────────────────────────
                # Only applies to adapters that declare a schema.
                # For multi-file uploads we only negotiate when there is
                # exactly one file — negotiating mid-merge is ambiguous.
                if adapter.declared_fields and len(tmp_files) == 1:
                    report = inspect_schema(adapter, tmp_path)
                    if not report.is_clean:
                        # Stage the file so phase 2 can resume ingestion.
                        needs_staging = True
                        token = stage_file(
                            tmp_path,
                            adapter_name=adapter.name,
                            original_filename=tmp_path.name,
                        )
                        parse_ms = int((time.time() - t0) * 1000)

                        # Serialise the report into a plain dict for JSON.
                        report_dict = {
                            "adapter_name": report.adapter_name,
                            "detected_columns": report.detected_columns,
                            "declared_fields": [
                                {
                                    "name": f.name,
                                    "required": f.required,
                                    "description": f.description,
                                }
                                for f in report.declared_fields
                            ],
                            "missing_required": report.missing_required,
                            "missing_optional": report.missing_optional,
                            "unknown_columns": report.unknown_columns,
                            "suggested_mappings": report.suggested_mappings,
                        }
                        return UploadResponse(
                            success=False,
                            capture_id="",
                            file_name=tmp_path.name,
                            source_files=[tmp_path.name],
                            packet_count=0,
                            parse_time_ms=parse_ms,
                            file_size_bytes=total_size,
                            schema_negotiation_required=True,
                            staging_token=token,
                            schema_report=report_dict,
                        )

                logger.info(f"Parsing {tmp_path.name} ({tmp_path.stat().st_size/1024/1024:.1f}MB) with {adapter.name}...")
                packets = adapter.parse(tmp_path)
                logger.info(f"  {len(packets)} records from {tmp_path.name}")
                all_packets.extend(packets)
            except HTTPException:
                raise
            except ValueError as e:
                raise HTTPException(400, str(e))
            except Exception as e:
                logger.exception(f"Parse error on {tmp_path.name}")
                raise HTTPException(500, f"Parse error: {e}")
    finally:
        if not needs_staging:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    if not all_packets:
        raise HTTPException(400, "No packets found in uploaded file(s)")

    if len(files) > 1:
        logger.info(f"Merging {len(all_packets):,} packets from {len(file_names)} files...")
        all_packets.sort(key=lambda p: p.timestamp)

    parse_ms = int((time.time() - t0) * 1000)

    display_name = file_names[0] if len(file_names) == 1 else f"{len(file_names)} files"

    store.load(all_packets, display_name, source_files=file_names)
    clear_analysis_results()
    run_plugins()

    return UploadResponse(
        success=True,
        capture_id=store.capture_id,
        file_name=display_name,
        source_files=file_names,
        packet_count=len(all_packets),
        parse_time_ms=parse_ms,
        file_size_bytes=total_size,
    )


# ── Two-phase prescan + filtered load ────────────────────────────────────────

@router.post("/api/upload/prescan")
async def prescan_upload(file: UploadFile = File(...)):
    """
    Phase 1 of two-phase load: save the file and return a rich summary
    (IP inventory, protocol breakdown, time range, graph complexity estimate).
    Returns a token the client passes back to /api/upload/load.

    Only valid pcap files are supported; pcapng falls back to /api/upload.
    """
    _cleanup_prescan_cache()

    content = await file.read()
    if not content:
        raise HTTPException(400, "File is empty")

    tmp_dir = tempfile.mkdtemp(prefix="swifteye_prescan_")
    safe_name = Path(file.filename or "capture.pcap").name
    tmp_path = Path(tmp_dir) / safe_name
    tmp_path.write_bytes(content)

    try:
        stats = prescan_capture(str(tmp_path))
    except Exception as exc:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise HTTPException(500, f"Prescan failed: {exc}")

    if stats is None:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise HTTPException(422, "Not a valid pcap or pcapng file")

    # Strip backend-only field before sending to client
    comp_ip_sets = stats.pop("_component_ips", [])

    token = str(uuid.uuid4())
    _PRESCAN_CACHE[token] = {
        "tmp_dir":       tmp_dir,
        "tmp_path":      str(tmp_path),
        "expires":       time.time() + _PRESCAN_TTL,
        "component_ips": comp_ip_sets,  # full IP sets indexed by component id
    }

    duration = (stats["ts_last"] - stats["ts_first"]) if stats["ts_first"] and stats["ts_last"] else 0.0

    return {
        "token":            token,
        "filename":         safe_name,
        "file_size_mb":     round(len(content) / 1024 / 1024, 2),
        "packet_count":     stats["packet_count"],
        "ts_first":         stats["ts_first"],
        "ts_last":          stats["ts_last"],
        "duration_seconds": round(duration, 3),
        "node_count":       stats["node_count"],
        "edge_count":       stats["edge_count"],
        "protocols":        stats["protocols"],
        "top_ips":          stats["top_ips"],
        "components":       stats.get("components", []),
    }


@router.post("/api/upload/load", response_model=UploadResponse)
async def load_with_filter(req: _PrescanLoadRequest):
    """
    Phase 2 of two-phase load: parse the pre-uploaded file with the given
    filter and load it into the active capture store.

    Filter dimensions:
      ts_start / ts_end  — applied inside parse workers (fast path)
      protocols          — L4 (TCP/UDP/ICMP) or L7 (DNS/TLS/HTTP) names
      ip_whitelist       — bare IPs or CIDR subnets
      port_whitelist     — port numbers or ranges ("80", "8000-9000")
      top_k_nodes        — keep only packets involving the K busiest IPs
      max_packets        — hard cap
    """
    _cleanup_prescan_cache()

    entry = _PRESCAN_CACHE.get(req.token)
    if not entry:
        raise HTTPException(404, "Prescan token not found or expired — re-upload the file")

    tmp_path = entry["tmp_path"]
    if not os.path.exists(tmp_path):
        _PRESCAN_CACHE.pop(req.token, None)
        raise HTTPException(404, "Prescan file no longer available — re-upload the file")

    t0 = time.time()
    f = req.filter

    # Resolve component selection → ip_whitelist before building LoadFilter
    if f.component_ids:
        comp_ip_sets = entry.get("component_ips", [])
        selected: set = set()
        for cid in f.component_ids:
            if 0 <= cid < len(comp_ip_sets):
                selected.update(comp_ip_sets[cid])
        if selected:
            if f.ip_whitelist:
                # Intersection: user wants specific IPs within selected components
                selected &= set(f.ip_whitelist)
            f.ip_whitelist = list(selected)

    try:
        packets = read_pcap(
            tmp_path,
            max_packets=f.max_packets,
            ts_start=f.ts_start,
            ts_end=f.ts_end,
        )
        lf = LoadFilter(
            protocols=f.protocols,
            ip_whitelist=f.ip_whitelist,
            ip_blacklist=f.ip_blacklist,
            port_whitelist=f.port_whitelist,
            port_blacklist=f.port_blacklist,
            top_k_nodes=f.top_k_nodes,
            max_packets=f.max_packets,
        )
        packets = apply_post_parse_filter(packets, lf)
    except Exception as exc:
        raise HTTPException(500, f"Parse error: {exc}")
    finally:
        _PRESCAN_CACHE.pop(req.token, None)
        shutil.rmtree(entry["tmp_dir"], ignore_errors=True)

    if not packets:
        raise HTTPException(400, "No packets matched the filter — broaden the criteria and try again")

    file_name = Path(tmp_path).name
    parse_ms = int((time.time() - t0) * 1000)

    store.load(packets, file_name, source_files=[file_name])
    clear_analysis_results()
    run_plugins()

    return UploadResponse(
        success=True,
        capture_id=store.capture_id,
        file_name=file_name,
        source_files=[file_name],
        packet_count=len(packets),
        parse_time_ms=parse_ms,
        file_size_bytes=0,
    )


@router.get("/api/stats", response_model=StatsResponse)
async def get_stats(
    time_start: Optional[float] = None,
    time_end:   Optional[float] = None,
):
    """Get capture statistics, optionally scoped to a time range."""
    _require_capture()
    if time_start is not None and time_end is not None:
        scoped_pkts = [p for p in store.packets if time_start <= p.timestamp <= time_end]
        active_keys = {p.session_key for p in scoped_pkts}
        scoped_sess = [s for s in store.sessions if s.get('id') in active_keys]
        stats = compute_global_stats(scoped_pkts, scoped_sess)
    else:
        stats = dict(store.stats)

    all_results = get_global_results()
    plugin_sections = {}
    for plugin_name, results in all_results.items():
        if isinstance(results, dict):
            for slot_id, slot_data in results.items():
                if isinstance(slot_data, dict) and not _looks_like_ip_keyed(slot_data):
                    plugin_sections[slot_id] = slot_data
                elif isinstance(slot_data, dict) and slot_id.endswith("_summary"):
                    plugin_sections[slot_id] = slot_data

    if plugin_sections:
        stats["plugin_sections"] = plugin_sections

    return StatsResponse(stats=stats)


@router.get("/api/timeline", response_model=TimelineResponse)
async def get_timeline(bucket_seconds: int = Query(default=15, ge=1, le=3600)):
    """Get time-bucketed packet counts."""
    _require_capture()
    if bucket_seconds != 15:
        buckets = build_time_buckets(store.packets, bucket_seconds)
    else:
        buckets = store.time_buckets
    return TimelineResponse(buckets=buckets, bucket_seconds=bucket_seconds)


@router.get("/api/graph", response_model=GraphResponse)
async def get_graph(
    time_start: Optional[float] = None,
    time_end: Optional[float] = None,
    protocols: Optional[str] = None,
    protocol_filters: Optional[str] = None,
    ip_filter: str = "",
    port_filter: str = "",
    flag_filter: str = "",
    search: str = "",
    subnet_grouping: bool = False,
    subnet_prefix: int = 24,
    merge_by_mac: bool = False,
    include_ipv6: bool = True,
    show_hostnames: bool = True,
    exclude_broadcasts: bool = False,
    subnet_exclusions: Optional[str] = None,
    cluster_algorithm: Optional[str] = None,
    cluster_resolution: float = 1.0,
):
    """Get filtered graph data (nodes + edges)."""
    _require_capture()

    time_range = None
    if time_start is not None and time_end is not None:
        time_range = (time_start, time_end)

    proto_set = None
    if protocols:
        proto_set = set(protocols.split(","))

    pf_set = None
    if protocol_filters:
        pf_set = set(protocol_filters.split(","))

    entity_map = {}
    if merge_by_mac:
        try:
            entity_map = build_entity_map(store.packets, merge_by_mac=merge_by_mac)
        except Exception as _em_err:
            logger.error(f"Node merger failed, continuing without merging: {_em_err}")

    dns_results = get_global_results().get("dns_resolver", {})
    hostname_map = dns_results.get("dns_hostnames", {})

    result = build_graph(
        store.packets,
        time_range=time_range,
        protocols=proto_set,
        protocol_filters=pf_set,
        ip_filter=ip_filter,
        port_filter=port_filter,
        flag_filter=flag_filter,
        search_query=search,
        subnet_grouping=subnet_grouping,
        subnet_prefix=subnet_prefix,
        hostname_map=hostname_map if show_hostnames else {},
        metadata_map=store.metadata_map,
        entity_map=entity_map,
        include_ipv6=include_ipv6,
        subnet_exclusions=set(subnet_exclusions.split(',')) if subnet_exclusions else None,
        exclude_broadcasts=exclude_broadcasts,
    )

    all_results = get_global_results()
    enrich_nodes_with_plugins(result["nodes"], all_results)

    if cluster_algorithm:
        try:
            params = {}
            if cluster_algorithm == 'louvain':
                params['resolution'] = cluster_resolution
            result["clusters"] = compute_clusters(
                result["nodes"], result["edges"], algorithm=cluster_algorithm, params=params,
            )
        except Exception as _cl_err:
            logger.error(f"Clustering [{cluster_algorithm}] failed: {_cl_err}")
            result["clusters"] = {}

    if not get_analysis_results():
        build_analysis_graph_and_run()

    # Enrich edges with initiator direction from sessions
    if store.sessions:
        _ses_by_pair: dict = {}
        for s in store.sessions:
            sip, dip = s.get("src_ip", ""), s.get("dst_ip", "")
            init = s.get("initiator_ip", "")
            if not sip or not dip or not init:
                continue
            pair = (min(sip, dip), max(sip, dip))
            _ses_by_pair.setdefault(pair, set()).add(init)
        for e in result["edges"]:
            src_id, tgt_id = e["source"], e["target"]
            if "/" in src_id or "/" in tgt_id:
                continue
            pair = (min(src_id, tgt_id), max(src_id, tgt_id))
            inits = _ses_by_pair.get(pair)
            if not inits:
                continue
            if len(inits) == 1:
                e["initiator"] = next(iter(inits))
            else:
                e["initiator"] = "both"

    if store.synthetic:
        syn_nodes = [s for s in store.synthetic.values() if s["type"] == "node"]
        syn_edges = [s for s in store.synthetic.values() if s["type"] == "edge"]
        if syn_nodes:
            result["nodes"] = result["nodes"] + syn_nodes
        if syn_edges:
            result["edges"] = result["edges"] + syn_edges

    return GraphResponse(**result)


@router.get("/api/paths")
async def get_paths(
    source: str,
    target: str,
    cutoff: int = 5,
    max_paths: int = 10,
    directed: bool = False,
):
    """Find simple paths between two nodes on the raw graph."""
    _require_capture()
    result = build_graph(store.packets)
    return find_paths(
        result["nodes"], result["edges"],
        source=source, target=target,
        cutoff=cutoff, max_paths=max_paths,
        directed=directed,
    )


@router.get("/api/edge-sessions", response_model=SessionsResponse)
async def get_edge_sessions(
    edge_id: str = Query(..., description="Edge ID: 'src|dst|protocol'"),
    sort_by: str = Query(default="bytes", enum=["bytes", "packets", "duration", "time"]),
    limit: int = Query(default=500, ge=1, le=10000),
    src_members: Optional[str] = Query(default=None, description="Comma-separated member IPs for synthetic src node"),
    dst_members: Optional[str] = Query(default=None, description="Comma-separated member IPs for synthetic dst node"),
):
    """
    Get sessions belonging to a specific edge.

    Single canonical endpoint for session↔edge matching.
    Handles directional edges, subnet grouping, MAC-split nodes,
    protocol/transport matching, and cluster/subnet synthetic nodes
    (pass src_members/dst_members as comma-separated IP lists).
    """
    _require_capture()

    parts = edge_id.split("|")
    if len(parts) != 3:
        raise HTTPException(400, f"Invalid edge_id format: expected 'src|dst|protocol', got '{edge_id}'")

    edge_src, edge_dst, edge_protocol = parts
    src_set = set(src_members.split(",")) if src_members else None
    dst_set = set(dst_members.split(",")) if dst_members else None
    sessions, total = store.backend.get_sessions_for_edge(
        edge_src=edge_src,
        edge_dst=edge_dst,
        edge_protocol=edge_protocol,
        sort_by=sort_by,
        limit=limit,
        src_members=src_set,
        dst_members=dst_set,
    )
    return SessionsResponse(sessions=sessions, total=total)


@router.get("/api/edge/{edge_id:path}/detail")
async def get_edge_detail_route(
    edge_id: str,
    time_start:         Optional[float] = None,
    time_end:           Optional[float] = None,
    protocols:          Optional[str] = None,
    protocol_filters:   Optional[str] = None,
    ip_filter:          str = "",
    port_filter:        str = "",
    flag_filter:        str = "",
    search:             str = "",
    subnet_grouping:    bool = False,
    subnet_prefix:      int = 24,
    merge_by_mac:       bool = False,
    include_ipv6:       bool = True,
    exclude_broadcasts: bool = False,
    subnet_exclusions:  Optional[str] = None,
):
    """
    Lazy detail fields for a single edge (TLS/HTTP/DNS/JA3/JA4).

    Accepts the same filter params as /api/graph so the detail reflects
    the same filtered view the user was looking at when they clicked.
    Returns 404 if the edge_id is not found in the filtered packet set.
    """
    _require_capture()

    time_range = None
    if time_start is not None and time_end is not None:
        time_range = (time_start, time_end)

    proto_set = set(protocols.split(",")) if protocols else None
    pf_set    = set(protocol_filters.split(",")) if protocol_filters else None

    entity_map = {}
    if merge_by_mac:
        try:
            entity_map = build_entity_map(store.packets, merge_by_mac=merge_by_mac)
        except Exception as _em_err:
            logger.error(f"Node merger failed for edge detail: {_em_err}")

    detail = get_edge_detail(
        edge_id,
        store.packets,
        time_range=time_range,
        protocols=proto_set,
        protocol_filters=pf_set,
        ip_filter=ip_filter,
        port_filter=port_filter,
        flag_filter=flag_filter,
        search_query=search,
        include_ipv6=include_ipv6,
        subnet_grouping=subnet_grouping,
        subnet_prefix=subnet_prefix,
        subnet_exclusions=set(subnet_exclusions.split(",")) if subnet_exclusions else None,
        entity_map=entity_map,
        exclude_broadcasts=exclude_broadcasts,
    )

    if detail is None:
        raise HTTPException(404, f"Edge '{edge_id}' not found in filtered packet set")

    return detail


@router.get("/api/sessions", response_model=SessionsResponse)
async def get_sessions(
    sort_by: str = Query(default="bytes", enum=["bytes", "packets", "duration", "time"]),
    limit: int = Query(default=200, ge=1, le=100000),
    offset: int = Query(default=0, ge=0),
    search: str = "",
    time_start: Optional[float] = None,
    time_end:   Optional[float] = None,
):
    """Get session list, optionally scoped to a time range."""
    _require_capture()

    sessions, total = store.backend.get_sessions(
        sort_by=sort_by,
        limit=limit,
        offset=offset,
        search=search,
        time_start=time_start,
        time_end=time_end,
    )
    return SessionsResponse(sessions=sessions, total=total)


@router.get("/api/session_detail")
async def get_session_detail(
    session_id: str = Query(...),
    packet_limit: int = Query(default=1000, ge=1, le=50000),
    packet_offset: int = Query(default=0, ge=0),
):
    """Get detailed session info including packets."""
    _require_capture()

    session = store.backend.get_session(session_id)
    if not session:
        raise HTTPException(404, f"Session {session_id!r} not found")

    packets = store.backend.get_packets_for_session(
        session_id, limit=packet_limit, offset=packet_offset
    )
    return SessionDetailResponse(session=session, packets=packets)


@router.get("/api/protocols", response_model=ProtocolsResponse)
async def get_protocols():
    """Get list of protocols in current capture with colors."""
    _require_capture()
    return ProtocolsResponse(protocols=sorted(store.protocols), colors=PROTOCOL_COLORS)


@router.get("/api/subnets", response_model=SubnetsResponse)
async def get_subnets_api(prefix: int = Query(default=24, ge=8, le=32)):
    """Get subnet groupings."""
    _require_capture()
    if prefix != 24:
        subnets = get_subnets(store.packets, prefix)
    else:
        subnets = store.subnets
    return SubnetsResponse(subnets=subnets)


@router.get("/api/hostnames")
async def get_hostnames():
    """Get DNS-resolved hostnames for all IPs (from dns_resolver plugin)."""
    _require_capture()
    dns_results = get_global_results().get("dns_resolver", {})
    hostname_map = dns_results.get("dns_hostnames", {})
    return {"hostnames": hostname_map, "total_ips": len(hostname_map)}


@router.get("/api/status")
async def get_status():
    """Server status and current capture info."""
    return {
        "status": "ok",
        "capture_loaded": store.is_loaded,
        "capture_id": store.capture_id,
        "file_name": store.file_name,
        "packet_count": len(store.packets) if store.is_loaded else 0,
    }
