import shutil
import tempfile
import time
import logging
from pathlib import Path
from typing import Optional, List

from fastapi import APIRouter, HTTPException, UploadFile, File, Query

from store import store, _require_capture
from data import build_time_buckets, build_graph, filter_packets, compute_global_stats, get_subnets
from data.algorithms import compute_clusters, find_paths
from plugins import get_global_results
from plugins.insights.node_merger import build_entity_map
from plugins.analyses import get_analysis_results, clear_analysis_results
from parser import read_pcap, PacketRecord, MAX_FILE_SIZE
from parser.adapters import detect_adapter, ADAPTERS
from constants import PROTOCOL_COLORS
from models import (
    UploadResponse, StatsResponse, TimelineResponse, GraphResponse,
    SessionsResponse, SessionDetailResponse, ProtocolsResponse, SubnetsResponse,
)
from services.capture import run_plugins, build_analysis_graph_and_run, enrich_nodes_with_plugins, _looks_like_ip_keyed

logger = logging.getLogger("swifteye.routes.data")
router = APIRouter()


@router.post("/api/upload", response_model=UploadResponse)
async def upload_pcap(files: List[UploadFile] = File(...)):
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
                adapter = detect_adapter(tmp_path)
                if not adapter:
                    raise HTTPException(400, f"Unsupported file type: {tmp_path.name}")

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


@router.get("/api/sessions", response_model=SessionsResponse)
async def get_sessions(
    sort_by: str = Query(default="bytes", enum=["bytes", "packets", "duration", "time"]),
    limit: int = Query(default=200, ge=1, le=5000),
    search: str = "",
    time_start: Optional[float] = None,
    time_end:   Optional[float] = None,
):
    """Get session list, optionally scoped to a time range."""
    _require_capture()

    sessions = store.sessions

    if time_start is not None and time_end is not None:
        active_keys = {p.session_key for p in store.packets
                       if time_start <= p.timestamp <= time_end}
        sessions = [s for s in sessions if s.get('id') in active_keys]

    if search:
        q = search.lower()
        sessions = [s for s in sessions if (
            q in s["src_ip"].lower() or
            q in s["dst_ip"].lower() or
            q in s["protocol"].lower() or
            q in str(s["src_port"]) or
            q in str(s["dst_port"])
        )]

    if sort_by == "packets":
        sessions = sorted(sessions, key=lambda s: s["packet_count"], reverse=True)
    elif sort_by == "duration":
        sessions = sorted(sessions, key=lambda s: s["duration"], reverse=True)
    elif sort_by == "time":
        sessions = sorted(sessions, key=lambda s: s.get("start_time", 0))

    return SessionsResponse(sessions=sessions[:limit], total=len(sessions))


@router.get("/api/session_detail")
async def get_session_detail(session_id: str = Query(...), packet_limit: int = Query(default=200, ge=1, le=1000)):
    """Get detailed session info including packets."""
    _require_capture()

    session = None
    for s in store.sessions:
        if s["id"] == session_id:
            session = s
            break

    if not session:
        raise HTTPException(404, "Session not found")

    packets = store.get_packets_for_session(session_id, limit=packet_limit)
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
