"""
SwiftEye Backend Server

FastAPI server that handles pcap uploads, parsing, and serves the analysis API.
Also serves the frontend as a single HTML file.

Usage:
    python server.py
    # Then open http://localhost:8642
"""

import os
import sys
import time
import uuid
import json
import logging
from logging.handlers import RotatingFileHandler
import io
import math
import re
import base64
import datetime
import tempfile
from pathlib import Path
from typing import Optional, List
from collections import Counter

# Ensure backend/ is on sys.path so imports work regardless of CWD
_backend_dir = Path(__file__).resolve().parent
if str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))

import uvicorn
from fastapi import FastAPI, UploadFile, File, Query, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware

from parser import read_pcap, PacketRecord, MAX_FILE_SIZE
from parser.adapters import detect_adapter, ADAPTERS
from constants import PROTOCOL_COLORS
from analysis import build_time_buckets, build_graph, filter_packets, build_sessions, compute_global_stats, get_subnets, build_mac_split_map
from plugins.insights.node_merger import build_entity_map
from plugins import (
    register_plugin, run_global_analysis, get_global_results,
    get_node_analysis, get_all_ui_slots, AnalysisContext, get_plugins,
)
from plugins.analyses import (
    register_analysis, run_all_analyses, get_analysis_results, get_analyses,
    clear_analysis_results,
)
from research import register_chart, get_charts, get_chart, run_chart
from models import (
    UploadResponse, StatsResponse, TimelineResponse, GraphResponse,
    SessionsResponse, SessionDetailResponse, ProtocolsResponse,
    SubnetsResponse, ErrorResponse,
)

# ── Logging ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("swifteye")

# Rotating file handler: 10MB max per file, keep 5 backups
_log_file = Path(__file__).parent / "swifteye.log"
_rfh = RotatingFileHandler(_log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
_rfh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
_rfh.setLevel(logging.INFO)
logging.getLogger("swifteye").addHandler(_rfh)
logging.getLogger("uvicorn.error").addHandler(_rfh)

# ── App ──────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SwiftEye",
    description="Network Traffic Visualization Platform",
    version="0.10.5",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Dynamic registration helper ─────────────────────────────────────
import importlib

def _dynamic_register(specs, register_fn, label="component"):
    """Load modules dynamically and register instances. Failures log a warning and are skipped."""
    for module_path, class_name in specs:
        try:
            mod = importlib.import_module(module_path)
            cls = getattr(mod, class_name)
            register_fn(cls())
        except Exception as e:
            logger.warning(f"Could not load {label} {module_path}.{class_name}: {e}")


# ── Register plugins, analyses, charts ───────────────────────────────
_dynamic_register([
    ("plugins.insights.os_fingerprint", "OSFingerprintPlugin"),
    ("plugins.insights.network_map",    "NetworkMapPlugin"),
    ("plugins.insights.tcp_flags",      "TCPFlagsPlugin"),
    ("plugins.insights.dns_resolver",   "DNSResolverPlugin"),
], register_plugin, "insight plugin")

_dynamic_register([
    ("plugins.analyses.node_centrality",           "NodeCentralityAnalysis"),
    ("plugins.analyses.traffic_characterisation",   "TrafficCharacterisationAnalysis"),
], register_analysis, "analysis plugin")

_dynamic_register([
    ("research.conversation_timeline", "ConversationTimeline"),
    ("research.ttl_over_time",         "TTLOverTime"),
    ("research.session_gantt",         "SessionGantt"),
    ("research.seq_ack_timeline",      "SeqAckTimelineChart"),
    ("research.dns_timeline",          "DNSTimeline"),
    ("research.ja3_timeline",          "JA3Timeline"),
    ("research.ja4_timeline",          "JA4Timeline"),
    ("research.http_ua_timeline",       "HTTPUserAgentTimeline"),
], register_chart, "research chart")

# ── Payload preview helpers ─────────────────────────────────────────────────

def _payload_hexdump(data: bytes) -> str:
    """
    Format raw bytes as a unified Wireshark-style hex dump.
    Each row: offset  hex-bytes (padded to 16)  ascii
    Example:  0000  16 03 01 00 f1 01 00 00  .......
    Returned as a single string with newline-separated rows.
    The frontend renders this in a single <pre> block — no column splitting needed.
    """
    if not data:
        return ""
    rows = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part  = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(f"{i:04x}  {hex_part:<47}  {ascii_part}")
    return "\n".join(rows)


# Keep old names as aliases for any callers — both now point to the unified dump
def _payload_hex(data: bytes) -> str:
    return _payload_hexdump(data)

def _payload_ascii(data: bytes) -> str:
    return ""  # ASCII is now embedded in the hex dump rows; no longer served separately


def _payload_entropy(data: bytes) -> dict:
    """
    Compute Shannon entropy of payload bytes and classify it.

    Returns {value, label, min_bytes} or empty dict if too few bytes.
    Minimum 16 bytes for a meaningful reading.
    """
    if not data or len(data) < 16:
        return {}
    counts = Counter(data)
    length = len(data)
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    entropy = round(entropy, 2)

    if entropy < 1.0:
        label = "Structured/repetitive"
    elif entropy < 3.5:
        label = "Low entropy (structured binary)"
    elif entropy < 5.0:
        label = "Text/markup"
    elif entropy < 6.5:
        label = "Mixed/encoded"
    elif entropy < 7.5:
        label = "High entropy (compressed)"
    else:
        label = "Likely encrypted/compressed"

    return {"value": entropy, "label": label, "byte_count": length}


# ── Capture State (in-memory, single-user) ───────────────────────────────
class CaptureStore:
    """
    Holds the current loaded capture and its core viewer data.
    
    This is strictly viewer-layer: sessions, stats, time buckets, subnets.
    It does NOT run plugins — that's the server's orchestration concern.
    Removing all plugins should leave CaptureStore fully functional.
    """
    
    def __init__(self):
        self.capture_id: Optional[str] = None
        self.file_name: str = ""
        self.source_files: list[str] = []   # all uploaded filenames (multi-pcap)
        self.packets: list[PacketRecord] = []
        self.sessions: list[dict] = []
        self.stats: dict = {}
        self.time_buckets: list[dict] = []
        self.protocols: set[str] = set()
        self.subnets: dict = {}
        self.metadata_map: dict = {}       # IP → researcher-provided metadata
        self.annotations: dict = {}        # uuid → {id, x, y, label, color, node_id?, edge_id?, created_at}
        self.synthetic: dict = {}          # uuid → {id, type:"node"|"edge", ...fields}
        self.graph_cache: dict = {}        # last built graph: {"nodes": [...], "edges": [...]}
        self.investigation: dict = {"markdown": "", "images": {}}  # investigation notebook
    
    def load(self, packets: list[PacketRecord], file_name: str, source_files: list[str] = None):
        """
        Load a new capture, computing all core viewer data.
        
        Does NOT run plugins — call run_plugins() separately after this.
        """
        self.capture_id = str(uuid.uuid4())[:8]
        self.file_name = file_name
        self.source_files = source_files or [file_name]
        self.packets = packets

        # Clear per-capture state that is specific to the previous capture.
        # Annotations, synthetic elements, and researcher metadata are tied to
        # the loaded capture — they should not bleed over to a new one.
        self.annotations = {}
        self.synthetic = {}
        self.metadata_map = {}
        self.graph_cache = {}
        self.investigation = {"markdown": "", "images": {}}
        
        logger.info(f"Building sessions...")
        t0 = time.time()
        self.sessions = build_sessions(packets)
        logger.info(f"  {len(self.sessions)} sessions in {time.time()-t0:.2f}s")
        
        logger.info(f"Computing stats...")
        t0 = time.time()
        self.stats = compute_global_stats(packets, self.sessions)
        logger.info(f"  Stats computed in {time.time()-t0:.2f}s")
        
        logger.info(f"Building time buckets...")
        t0 = time.time()
        self.time_buckets = build_time_buckets(packets)
        logger.info(f"  {len(self.time_buckets)} buckets in {time.time()-t0:.2f}s")
        
        self.protocols = {p.protocol for p in packets if p.protocol and p.protocol.strip()}
        self.subnets = get_subnets(packets)
        
        logger.info(f"Capture '{file_name}' loaded: {len(packets)} packets, "
                     f"{len(self.sessions)} sessions, {len(self.protocols)} protocols")
    
    def get_packets_for_session(self, session_id: str, limit: int = 200) -> list[dict]:
        """Get packets belonging to a specific session, with full detail."""
        # Find the session
        session = None
        for s in self.sessions:
            if s["id"] == session_id:
                session = s
                break
        if not session:
            return []
        
        result = []
        count = 0
        for pkt in self.packets:
            if pkt.session_key == session_id:
                result.append({
                    "timestamp": pkt.timestamp,
                    "src_ip": pkt.src_ip,
                    "dst_ip": pkt.dst_ip,
                    "src_port": pkt.src_port,
                    "dst_port": pkt.dst_port,
                    "protocol": pkt.protocol,
                    "transport": pkt.transport,
                    "length": pkt.orig_len,
                    "payload_len": pkt.payload_len,
                    "ttl": pkt.ttl,
                    "tcp_flags_str": pkt.tcp_flags_str,
                    "tcp_flags_list": pkt.tcp_flags_list,
                    "seq_num": pkt.seq_num,
                    "ack_num": pkt.ack_num,
                    "window_size": pkt.window_size,
                    "tcp_options": pkt.tcp_options,
                    # IP header fields
                    "ip_version": pkt.ip_version,
                    "dscp": pkt.dscp,
                    "ecn": pkt.ecn,
                    "ip_id": pkt.ip_id,
                    "ip_flags": pkt.ip_flags,   # int: bit0=reserved, bit1=DF, bit2=MF
                    "frag_offset": pkt.frag_offset,
                    "ip_checksum": pkt.ip_checksum,
                    "ip6_flow_label": pkt.ip6_flow_label,
                    "tcp_checksum": pkt.tcp_checksum,
                    "extra": pkt.extra,
                    "payload_hex":   _payload_hex(pkt.payload_preview),
                    "payload_ascii": _payload_ascii(pkt.payload_preview),
                    "payload_bytes": pkt.payload_preview.hex() if pkt.payload_preview else "",
                    "payload_entropy": _payload_entropy(pkt.payload_preview),
                })
                count += 1
                if count >= limit:
                    break
        return result
    
    @property
    def is_loaded(self) -> bool:
        return len(self.packets) > 0


store = CaptureStore()


def _run_plugins():
    """
    Run all registered insight plugins against the current capture.
    
    This is server-level orchestration — separate from CaptureStore
    so the core viewer works even if all plugins are removed.
    Analysis plugins are run separately by _run_analyses().
    """
    if not store.is_loaded:
        return
    logger.info("Running plugin analysis...")
    t0 = time.time()
    plugin_ctx = AnalysisContext(packets=store.packets, sessions=store.sessions)
    run_global_analysis(plugin_ctx)
    logger.info(f"  Insights completed in {time.time()-t0:.2f}s")


def _build_analysis_graph_and_run():
    """
    Build an unfiltered graph and run all analyses against it.
    Analyses always see the full capture — never a filtered subset.
    The unfiltered graph is cached in store.graph_cache.
    """
    if not store.is_loaded:
        return
    logger.info("Building unfiltered graph for analyses...")
    t0 = time.time()

    # Get hostname map from DNS resolver plugin results
    dns_results = get_global_results().get("dns_resolver", {})
    hostname_map = dns_results.get("dns_hostnames", {})

    unfiltered = build_graph(
        store.packets,
        hostname_map=hostname_map,
        metadata_map=store.metadata_map,
    )
    _enrich_nodes_with_plugins(unfiltered["nodes"], get_global_results())
    store.graph_cache = {"nodes": unfiltered["nodes"], "edges": unfiltered["edges"]}
    logger.info(f"  Unfiltered graph: {len(unfiltered['nodes'])} nodes, {len(unfiltered['edges'])} edges in {time.time()-t0:.2f}s")

    _run_analyses()


def _run_analyses():
    """
    Run all registered analysis plugins against the cached unfiltered graph.
    Called after _build_analysis_graph_and_run() builds graph_cache.
    """
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


# ── Frontend ─────────────────────────────────────────────────────────────
# Prefer Vite build output (frontend/dist/), fall back to legacy single-file
FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
VITE_DIST = FRONTEND_DIR / "dist"
LEGACY_INDEX = FRONTEND_DIR / "index-legacy.html"


@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """Serve the frontend SPA (Vite build or legacy single-file)."""
    vite_index = VITE_DIST / "index.html"
    if vite_index.exists():
        return HTMLResponse(content=vite_index.read_text(encoding="utf-8"))
    if LEGACY_INDEX.exists():
        return HTMLResponse(content=LEGACY_INDEX.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>SwiftEye</h1><p>Frontend not found. Run 'npm run build' in frontend/ or place index.html there.</p>")


# Serve Vite static assets (JS, CSS chunks)
if VITE_DIST.exists():
    from fastapi.staticfiles import StaticFiles
    app.mount("/assets", StaticFiles(directory=str(VITE_DIST / "assets")), name="vite-assets")


# ── Upload API ───────────────────────────────────────────────────────────

@app.post("/api/upload", response_model=UploadResponse)
async def upload_pcap(files: List[UploadFile] = File(...)):
    """Upload and parse capture files or log files. Multiple files are merged by timestamp."""
    if not files:
        raise HTTPException(400, "No files provided")

    # Build set of all supported extensions from registered adapters
    supported_exts = set()
    for adapter_cls in ADAPTERS:
        supported_exts.update(adapter_cls.file_extensions)

    all_packets: list[PacketRecord] = []
    total_size  = 0
    file_names  = []
    t0 = time.time()

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

        ext = Path(file.filename).suffix.lower()
        tmp = tempfile.NamedTemporaryFile(suffix=ext, delete=False)
        try:
            tmp.write(content)
            tmp.close()

            # Detect adapter by extension + header sniffing
            tmp_path = Path(tmp.name)
            adapter = detect_adapter(tmp_path)
            if not adapter:
                raise HTTPException(400, f"Unsupported file type: {file.filename}")

            logger.info(f"Parsing {file.filename} ({file_size/1024/1024:.1f}MB) with {adapter.name}...")
            packets = adapter.parse(tmp_path)
            logger.info(f"  {len(packets)} records from {file.filename}")
            all_packets.extend(packets)
        except HTTPException:
            raise
        except ValueError as e:
            raise HTTPException(400, str(e))
        except Exception as e:
            logger.exception(f"Parse error on {file.filename}")
            raise HTTPException(500, f"Parse error: {e}")
        finally:
            os.unlink(tmp.name)

    if not all_packets:
        raise HTTPException(400, "No packets found in uploaded file(s)")

    # Merge: sort by timestamp so sessions reconstruct correctly across files
    if len(files) > 1:
        logger.info(f"Merging {len(all_packets):,} packets from {len(file_names)} files...")
        all_packets.sort(key=lambda p: p.timestamp)

    parse_ms = int((time.time() - t0) * 1000)

    # Display name: single file = filename, multiple = "N files"
    display_name = file_names[0] if len(file_names) == 1 else f"{len(file_names)} files"

    store.load(all_packets, display_name, source_files=file_names)
    clear_analysis_results()
    _run_plugins()

    return UploadResponse(
        success=True,
        capture_id=store.capture_id,
        file_name=display_name,
        source_files=file_names,
        packet_count=len(all_packets),
        parse_time_ms=parse_ms,
        file_size_bytes=total_size,
    )


# ── Data API ─────────────────────────────────────────────────────────────

def _require_capture():
    if not store.is_loaded:
        raise HTTPException(404, "No capture loaded. Upload a pcap first.")


@app.get("/api/stats", response_model=StatsResponse)
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
    
    # Merge plugin results that declare stats_section slots (generic — no plugin names)
    all_results = get_global_results()
    plugin_sections = {}
    for plugin_name, results in all_results.items():
        if isinstance(results, dict):
            for slot_id, slot_data in results.items():
                # Include non-IP-keyed data as stats sections
                if isinstance(slot_data, dict) and not _looks_like_ip_keyed(slot_data):
                    plugin_sections[slot_id] = slot_data
                elif isinstance(slot_data, dict) and slot_id.endswith("_summary"):
                    plugin_sections[slot_id] = slot_data
    
    if plugin_sections:
        stats["plugin_sections"] = plugin_sections
    
    return StatsResponse(stats=stats)


@app.get("/api/timeline", response_model=TimelineResponse)
async def get_timeline(bucket_seconds: int = Query(default=15, ge=1, le=3600)):
    """Get time-bucketed packet counts."""
    _require_capture()
    if bucket_seconds != 15:
        buckets = build_time_buckets(store.packets, bucket_seconds)
    else:
        buckets = store.time_buckets
    return TimelineResponse(buckets=buckets, bucket_seconds=bucket_seconds)


@app.get("/api/graph", response_model=GraphResponse)
async def get_graph(
    time_start: Optional[float] = None,
    time_end: Optional[float] = None,
    protocols: Optional[str] = None,
    protocol_filters: Optional[str] = None,  # composite keys: "4/TCP/HTTPS,6/UDP/DNS,..."
    ip_filter: str = "",
    port_filter: str = "",
    flag_filter: str = "",
    search: str = "",
    subnet_grouping: bool = False,
    subnet_prefix: int = 24,
    merge_by_mac: bool = False,
    include_ipv6: bool = True,
    show_hostnames: bool = True,
    subnet_exclusions: Optional[str] = None,   # comma-separated subnet strings to un-cluster
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

    # Build entity map from node merger if any strategy is active
    entity_map = {}
    if merge_by_mac:
        try:
            entity_map = build_entity_map(
                store.packets,
                merge_by_mac=merge_by_mac,
            )
        except Exception as _em_err:
            logger.error(f"Node merger failed, continuing without merging: {_em_err}")

    # Detect IPs with multiple distinct source MACs (same IP, different physical host)
    # This runs always — it's a data-correctness step, not a user toggle.
    try:
        mac_split_map = build_mac_split_map(store.packets)
        if mac_split_map:
            logger.debug(f"MAC split map: {len(mac_split_map)} IPs with multiple MACs")
    except Exception as _ms_err:
        logger.error(f"build_mac_split_map failed: {_ms_err}")
        mac_split_map = {}

    # Get hostname map from DNS resolver plugin results
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
        mac_split_map=mac_split_map,
    )

    # Enrich nodes with plugin data + os_guess shortcut field
    all_results = get_global_results()
    _enrich_nodes_with_plugins(result["nodes"], all_results)

    # Run analyses lazily on first graph build — use an UNFILTERED graph
    # so analyses always see the full capture, not a filtered subset.
    if not get_analysis_results():
        _build_analysis_graph_and_run()

    # Inject synthetic nodes and edges
    if store.synthetic:
        syn_nodes = [s for s in store.synthetic.values() if s["type"] == "node"]
        syn_edges = [s for s in store.synthetic.values() if s["type"] == "edge"]
        if syn_nodes:
            result["nodes"] = result["nodes"] + syn_nodes
        if syn_edges:
            result["edges"] = result["edges"] + syn_edges

    return GraphResponse(**result)


def _enrich_nodes_with_plugins(nodes: list, plugin_results: dict):
    """
    Attach per-node plugin data to graph nodes generically.

    Also extracts a flat `os_guess` string from the OS fingerprint plugin
    (if present) so the display filter and OS dropdown can use it directly
    without digging into plugin_data.
    """
    # Build lookup: for each plugin, find result dicts that look like IP→data maps
    ip_maps = {}  # (plugin_name, slot_id) → {ip: data}
    for plugin_name, results in plugin_results.items():
        if not isinstance(results, dict):
            continue
        for slot_id, slot_data in results.items():
            if isinstance(slot_data, dict) and _looks_like_ip_keyed(slot_data):
                ip_maps[(plugin_name, slot_id)] = slot_data

    # Build OS fingerprint IP→guess map for quick lookup
    os_fp_map = {}
    os_fp_slot = plugin_results.get("os_fingerprint", {}).get("os_fingerprint", {})
    if isinstance(os_fp_slot, dict):
        for ip, fp in os_fp_slot.items():
            if isinstance(fp, dict) and "guess" in fp:
                os_fp_map[ip] = fp["guess"]

    # Attach matching data to each node
    for node in nodes:
        node_plugin_data = {}
        for ip in node.get("ips", [node.get("id")]):
            for (plugin_name, slot_id), ip_data in ip_maps.items():
                if ip in ip_data:
                    node_plugin_data[slot_id] = ip_data[ip]
        if node_plugin_data:
            node["plugin_data"] = node_plugin_data

        # Flat os_guess: start from OS fingerprint, then let network role override.
        for ip in node.get("ips", [node.get("id")]):
            if ip in os_fp_map:
                node["os_guess"] = os_fp_map[ip]
                break

        # Gateway override: if the network_map plugin identified this node as a
        # gateway/router, os_guess becomes "Network device (gateway)" regardless
        # of what the OS fingerprint found. Rationale: a Linux-based Ubiquiti or
        # OpenWrt router should filter as "Network device", not "Linux". The OS
        # fingerprint details remain in the plugin section for researchers who
        # want to see the underlying stack.
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


@app.get("/api/sessions", response_model=SessionsResponse)
async def get_sessions(
    sort_by: str = Query(default="bytes", enum=["bytes", "packets", "duration"]),
    limit: int = Query(default=200, ge=1, le=5000),
    search: str = "",
    time_start: Optional[float] = None,
    time_end:   Optional[float] = None,
):
    """Get session list, optionally scoped to a time range."""
    _require_capture()

    sessions = store.sessions

    if time_start is not None and time_end is not None:
        # Use packet-level filtering so only sessions with actual packets
        # inside the window are included — not sessions that merely overlap.
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
    # default is bytes, already sorted

    return SessionsResponse(sessions=sessions[:limit], total=len(sessions))


@app.get("/api/session_detail")
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


@app.get("/api/protocols", response_model=ProtocolsResponse)
async def get_protocols():
    """Get list of protocols in current capture with colors."""
    _require_capture()
    return ProtocolsResponse(
        protocols=sorted(store.protocols),
        colors=PROTOCOL_COLORS,
    )


@app.get("/api/subnets", response_model=SubnetsResponse)
async def get_subnets_api(prefix: int = Query(default=24, ge=8, le=32)):
    """Get subnet groupings."""
    _require_capture()
    if prefix != 24:
        subnets = get_subnets(store.packets, prefix)
    else:
        subnets = store.subnets
    return SubnetsResponse(subnets=subnets)


# ── Metadata API ─────────────────────────────────────────────────────

@app.post("/api/metadata")
async def upload_metadata(file: UploadFile = File(...)):
    """
    Upload researcher metadata JSON mapping IPs to known info.
    
    Expected format:
    {
        "10.0.0.1": {"name": "DC01", "role": "Domain Controller", "owner": "IT"},
        "192.168.1.100": {"name": "workstation-3", "notes": "Suspected compromised"}
    }
    
    Keys can be IPs or MACs. Values are arbitrary metadata dicts.
    """
    _require_capture()
    
    content = await file.read()
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise HTTPException(400, f"Invalid JSON: {e}")
    
    if not isinstance(data, dict):
        raise HTTPException(400, "Expected a JSON object mapping IPs/MACs to metadata dicts")
    
    store.metadata_map = data
    count = len(data)
    logger.info(f"Loaded researcher metadata: {count} entries from {file.filename}")
    
    return {"success": True, "entries": count, "file_name": file.filename}


@app.delete("/api/metadata")
async def clear_metadata():
    """Clear researcher metadata overlay."""
    store.metadata_map = {}
    logger.info("Researcher metadata cleared")
    return {"success": True}


@app.get("/api/metadata")
async def get_metadata():
    """Get current researcher metadata."""
    return {"metadata": store.metadata_map, "count": len(store.metadata_map)}


@app.get("/api/hostnames")
async def get_hostnames():
    """Get DNS-resolved hostnames for all IPs (from dns_resolver plugin)."""
    _require_capture()
    dns_results = get_global_results().get("dns_resolver", {})
    hostname_map = dns_results.get("dns_hostnames", {})
    return {"hostnames": hostname_map, "total_ips": len(hostname_map)}


# ── Plugin API ───────────────────────────────────────────────────────

@app.get("/api/plugins")
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


@app.get("/api/plugins/results")
async def get_plugin_results():
    """Get all global plugin analysis results."""
    _require_capture()
    return {"results": get_global_results()}


@app.get("/api/plugins/node/{node_id}")
async def get_plugin_node_results(node_id: str):
    """Get plugin analysis for a specific node."""
    _require_capture()
    ctx = AnalysisContext(packets=store.packets, sessions=store.sessions)
    return {"results": get_node_analysis(node_id, ctx)}


# ── Analysis endpoints ────────────────────────────────────────────────────

@app.get("/api/analysis")
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


@app.get("/api/analysis/results")
async def get_analysis_results_endpoint():
    """
    Get all analysis results. Analyses run lazily after the first graph build.
    Returns empty results if no capture is loaded.
    """
    results = get_analysis_results()
    if not results and store.is_loaded:
        _build_analysis_graph_and_run()
        results = get_analysis_results()
    return {"results": results}


@app.post("/api/analysis/rerun")
async def rerun_analyses():
    """Force re-run all analyses on the unfiltered graph."""
    _require_capture()
    _build_analysis_graph_and_run()
    return {"results": get_analysis_results()}


# ── Investigation notebook ────────────────────────────────────────────────────
# Markdown-based investigation notes with embedded screenshots.
# Persisted per-capture in CaptureStore.investigation.

@app.get("/api/investigation")
async def get_investigation():
    """Get investigation notebook content."""
    _require_capture()
    return store.investigation


@app.put("/api/investigation")
async def update_investigation(body: dict):
    """Update investigation notebook. Body: { markdown: str }"""
    _require_capture()
    if "markdown" in body:
        store.investigation["markdown"] = body["markdown"]
    return store.investigation


@app.post("/api/investigation/image")
async def upload_investigation_image(file: UploadFile = File(...)):
    """Upload an image for the investigation notebook. Returns an image ID for embedding."""
    _require_capture()
    content = await file.read()
    img_id = f"img_{uuid.uuid4().hex[:8]}"
    media_type = file.content_type or "image/png"
    b64 = base64.b64encode(content).decode()
    store.investigation["images"][img_id] = f"data:{media_type};base64,{b64}"
    return {"id": img_id, "url": store.investigation["images"][img_id]}


@app.get("/api/investigation/image/{img_id}")
async def get_investigation_image(img_id: str):
    """Get a specific investigation image by ID."""
    _require_capture()
    url = store.investigation.get("images", {}).get(img_id)
    if not url:
        raise HTTPException(404, "Image not found")
    return {"id": img_id, "url": url}


@app.post("/api/investigation/export")
async def export_investigation_pdf():
    """Export the investigation notebook as a PDF."""
    _require_capture()
    md = store.investigation.get("markdown", "")
    images = store.investigation.get("images", {})
    if not md.strip():
        raise HTTPException(400, "Investigation notebook is empty")

    try:
        pdf_path = _generate_investigation_pdf(md, images, store.file_name)
        return FileResponse(pdf_path, media_type="application/pdf",
                          filename=f"investigation_{store.file_name.replace(' ', '_')}.pdf")
    except Exception as e:
        logger.error(f"PDF export failed: {e}", exc_info=True)
        raise HTTPException(500, f"PDF generation failed: {str(e)}")


def _generate_investigation_pdf(markdown: str, images: dict, capture_name: str) -> str:
    """Generate a PDF from markdown and embedded images."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image as RLImage, HRFlowable, Preformatted
    from reportlab.lib.enums import TA_LEFT, TA_CENTER

    pdf_path = os.path.join(tempfile.gettempdir(), f"investigation_{uuid.uuid4().hex[:8]}.pdf")

    doc = SimpleDocTemplate(pdf_path, pagesize=A4,
                           leftMargin=20*mm, rightMargin=20*mm,
                           topMargin=20*mm, bottomMargin=20*mm)

    # Styles
    styles = {
        'title': ParagraphStyle('title', fontName='Helvetica-Bold', fontSize=18, spaceAfter=6*mm, textColor=HexColor('#1a1a2e')),
        'h1': ParagraphStyle('h1', fontName='Helvetica-Bold', fontSize=14, spaceBefore=5*mm, spaceAfter=3*mm, textColor=HexColor('#0d1117')),
        'h2': ParagraphStyle('h2', fontName='Helvetica-Bold', fontSize=12, spaceBefore=4*mm, spaceAfter=2*mm, textColor=HexColor('#1a1a2e')),
        'h3': ParagraphStyle('h3', fontName='Helvetica-Bold', fontSize=10, spaceBefore=3*mm, spaceAfter=2*mm, textColor=HexColor('#30363d')),
        'body': ParagraphStyle('body', fontName='Helvetica', fontSize=10, leading=14, spaceAfter=2*mm, textColor=HexColor('#1a1a2e')),
        'code': ParagraphStyle('code', fontName='Courier', fontSize=8, leading=10, spaceAfter=2*mm, backColor=HexColor('#f6f8fa'), textColor=HexColor('#24292f'), leftIndent=5*mm, rightIndent=5*mm),
        'bullet': ParagraphStyle('bullet', fontName='Helvetica', fontSize=10, leading=14, spaceAfter=1*mm, leftIndent=8*mm, bulletIndent=3*mm, textColor=HexColor('#1a1a2e')),
        'meta': ParagraphStyle('meta', fontName='Helvetica', fontSize=8, textColor=HexColor('#8b949e'), spaceAfter=4*mm),
    }

    story = []

    # Header
    story.append(Paragraph("SwiftEye Investigation Report", styles['title']))
    now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    story.append(Paragraph(f"Capture: {capture_name}  |  Exported: {now}", styles['meta']))
    story.append(HRFlowable(width="100%", thickness=0.5, color=HexColor('#d0d7de')))
    story.append(Spacer(1, 4*mm))

    # Parse markdown line by line
    lines = markdown.split('\n')
    in_code_block = False
    code_lines = []

    for line in lines:
        # Code blocks
        if line.strip().startswith('```'):
            if in_code_block:
                code_text = '\n'.join(code_lines)
                story.append(Preformatted(code_text, styles['code']))
                code_lines = []
                in_code_block = False
            else:
                in_code_block = True
            continue
        if in_code_block:
            code_lines.append(line)
            continue

        stripped = line.strip()

        # Empty line
        if not stripped:
            story.append(Spacer(1, 2*mm))
            continue

        # Headings
        if stripped.startswith('### '):
            story.append(Paragraph(stripped[4:], styles['h3']))
            continue
        if stripped.startswith('## '):
            story.append(Paragraph(stripped[3:], styles['h2']))
            continue
        if stripped.startswith('# '):
            story.append(Paragraph(stripped[2:], styles['h1']))
            continue

        # Horizontal rule
        if stripped in ('---', '***', '___'):
            story.append(HRFlowable(width="100%", thickness=0.5, color=HexColor('#d0d7de')))
            continue

        # Bullet points
        if stripped.startswith('- ') or stripped.startswith('* '):
            text = _md_inline(stripped[2:])
            story.append(Paragraph(f"&bull; {text}", styles['bullet']))
            continue

        # Images: ![alt](url) or ![alt](img_id)
        img_match = re.match(r'!\[([^\]]*)\]\(([^)]+)\)', stripped)
        if img_match:
            alt, src = img_match.group(1), img_match.group(2)
            img_data = images.get(src, src)  # resolve img_id to data URL
            if img_data.startswith('data:'):
                try:
                    header, b64data = img_data.split(',', 1)
                    img_bytes = base64.b64decode(b64data)
                    img_buf = io.BytesIO(img_bytes)
                    img = RLImage(img_buf, width=150*mm, height=90*mm, kind='proportional')
                    story.append(img)
                    if alt:
                        story.append(Paragraph(f"<i>{alt}</i>", styles['meta']))
                except Exception:
                    story.append(Paragraph(f"[Image: {alt}]", styles['body']))
            continue

        # Regular paragraph
        text = _md_inline(stripped)
        story.append(Paragraph(text, styles['body']))

    doc.build(story)
    return pdf_path


def _md_inline(text: str) -> str:
    """Convert inline markdown (bold, italic, code) to reportlab XML."""
    text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
    text = re.sub(r'__(.+?)__', r'<b>\1</b>', text)
    text = re.sub(r'\*(.+?)\*', r'<i>\1</i>', text)
    text = re.sub(r'_(.+?)_', r'<i>\1</i>', text)
    text = re.sub(r'`(.+?)`', r'<font face="Courier" size="9">\1</font>', text)
    return text



# ── Synthetic nodes/edges ────────────────────────────────────────────────────
# Researcher hypothesis toolkit: fake nodes and edges that render distinctly.
# Stored in CaptureStore.synthetic, included in /api/graph with synthetic=True.

@app.get("/api/synthetic")
async def get_synthetic():
    """Return all synthetic nodes and edges."""
    _require_capture()
    return {"synthetic": list(store.synthetic.values())}


@app.post("/api/synthetic")
async def create_synthetic(body: dict):
    """
    Create a synthetic node or edge.
    Node body: { id, type:"node", ip, label?, color?, metadata? }
    Edge body: { id, type:"edge", source, target, protocol?, label?, color? }
    """
    _require_capture()
    syn_id = body.get("id")
    syn_type = body.get("type")
    if not syn_id:
        raise HTTPException(400, "id is required")
    if syn_type not in ("node", "edge"):
        raise HTTPException(400, "type must be 'node' or 'edge'")
    if syn_type == "node":
        obj = {
            "id": syn_id,
            "type": "node",
            "synthetic": True,
            "label": str(body.get("label", syn_id)),
            "ip": str(body.get("ip", "")),
            "color": str(body.get("color", "#f0883e")),
            "size": int(body.get("size", 14)),  # explicit size; gR() uses this for synthetic nodes
            "metadata": body.get("metadata", {}),
            "ips": [body.get("ip", syn_id)] if body.get("ip") else [syn_id],
            "macs": [],
            "protocols": [],
            "total_bytes": 0,
            "packet_count": 0,
            "hostnames": [],
            "is_private": False,
            "is_subnet": False,
            "ttls_out": [],
            "ttls_in": [],
            "created_at": datetime.datetime.utcnow().isoformat(),
        }
    else:
        source = body.get("source", "")
        target = body.get("target", "")
        if not source or not target:
            raise HTTPException(400, "source and target are required for edge type")
        obj = {
            "id": syn_id,
            "type": "edge",
            "synthetic": True,
            "source": source,
            "target": target,
            "protocol": str(body.get("protocol", "SYNTHETIC")),
            "label": str(body.get("label", "")),
            "color": str(body.get("color", "#f0883e")),
            "total_bytes": 0,
            "packet_count": 0,
            "ports": [],
            "tls_snis": [],
            "tls_versions": [],
            "tls_ciphers": [],
            "tls_selected_ciphers": [],
            "http_hosts": [],
            "dns_queries": [],
            "ja3_hashes": [],
            "ja4_hashes": [],
            "created_at": datetime.datetime.utcnow().isoformat(),
        }
    store.synthetic[syn_id] = obj
    logger.info(f"Synthetic {syn_type} created: {syn_id!r}")
    return {"synthetic": obj}


@app.put("/api/synthetic/{syn_id}")
async def update_synthetic(syn_id: str, body: dict):
    """Update a synthetic node or edge (label, color, metadata, ip, protocol)."""
    _require_capture()
    if syn_id not in store.synthetic:
        raise HTTPException(404, f"Synthetic '{syn_id}' not found")
    obj = store.synthetic[syn_id]
    for field in ("label", "color", "metadata", "ip", "protocol", "size", "notes"):
        if field in body:
            obj[field] = body[field]
    # Keep ips list in sync with ip field for nodes
    if obj.get("type") == "node" and "ip" in body and body["ip"]:
        obj["ips"] = [body["ip"]]
    return {"synthetic": obj}


@app.delete("/api/synthetic/{syn_id}")
async def delete_synthetic(syn_id: str):
    """Delete a synthetic node or edge."""
    _require_capture()
    store.synthetic.pop(syn_id, None)
    return {"deleted": syn_id}


@app.delete("/api/synthetic")
async def clear_synthetic():
    """Clear all synthetic elements."""
    _require_capture()
    store.synthetic.clear()
    return {"cleared": True}


# ── Annotations ──────────────────────────────────────────────────────────────

@app.get("/api/annotations")
async def get_annotations():
    """Return all annotations for the current capture."""
    _require_capture()
    return {"annotations": list(store.annotations.values())}


@app.post("/api/annotations")
async def create_annotation(body: dict):
    """
    Create a new annotation.
    Body: { id, x, y, label, color? }
    """
    _require_capture()
    ann_id = body.get("id")
    if not ann_id:
        raise HTTPException(400, "Annotation id is required")
    annotation = {
        "id":              ann_id,
        "x":               float(body.get("x", 0)),
        "y":               float(body.get("y", 0)),
        "label":           str(body.get("label", "")).strip(),
        "color":           str(body.get("color", "#f0883e")),
        "annotation_type": str(body.get("annotation_type", "label")),  # "label" | "note"
        "text":            str(body.get("text", "")),                   # free-text note body
        "created_at":      datetime.datetime.utcnow().isoformat(),
    }
    # Optional node/edge association — annotations keyed by node/edge ID
    # survive graph re-fetches (position becomes relative, not absolute)
    if body.get("node_id"):
        annotation["node_id"] = str(body["node_id"])
    if body.get("edge_id"):
        annotation["edge_id"] = str(body["edge_id"])
    store.annotations[ann_id] = annotation
    logger.info(f"Annotation created: {ann_id!r} — {annotation['label']!r}")
    return {"annotation": annotation}


@app.put("/api/annotations/{ann_id}")
async def update_annotation(ann_id: str, body: dict):
    """Update an existing annotation (label, x, y, color)."""
    _require_capture()
    if ann_id not in store.annotations:
        raise HTTPException(404, f"Annotation '{ann_id}' not found")
    ann = store.annotations[ann_id]
    if "label"           in body: ann["label"]           = str(body["label"]).strip()
    if "text"            in body: ann["text"]            = str(body["text"])
    if "annotation_type" in body: ann["annotation_type"] = str(body["annotation_type"])
    if "x"               in body: ann["x"]               = float(body["x"])
    if "y"               in body: ann["y"]               = float(body["y"])
    if "color"           in body: ann["color"]           = str(body["color"])
    if "node_id"         in body: ann["node_id"]         = str(body["node_id"]) if body["node_id"] else None
    if "edge_id"         in body: ann["edge_id"]         = str(body["edge_id"]) if body["edge_id"] else None
    return {"annotation": ann}


@app.delete("/api/annotations/{ann_id}")
async def delete_annotation(ann_id: str):
    """Delete an annotation by id."""
    _require_capture()
    store.annotations.pop(ann_id, None)
    return {"deleted": ann_id}


@app.delete("/api/annotations")
async def clear_annotations():
    """Clear all annotations."""
    _require_capture()
    store.annotations.clear()
    return {"cleared": True}


@app.get("/api/status")
async def get_status():
    """Server status and current capture info."""
    return {
        "status": "ok",
        "capture_loaded": store.is_loaded,
        "capture_id": store.capture_id,
        "file_name": store.file_name,
        "packet_count": len(store.packets) if store.is_loaded else 0,
    }


# ── Log buffer for frontend ──────────────────────────────────────────
_log_buffer = []
_max_log_lines = 200

class FrontendLogHandler(logging.Handler):
    def emit(self, record):
        msg = self.format(record)
        _log_buffer.append(msg)
        if len(_log_buffer) > _max_log_lines:
            _log_buffer.pop(0)

_fh = FrontendLogHandler()
_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%H:%M:%S"))
logging.getLogger("swifteye").addHandler(_fh)
logging.getLogger("uvicorn.error").addHandler(_fh)

@app.get("/api/slice")
async def slice_pcap(
    time_start: Optional[float] = None,
    time_end:   Optional[float] = None,
    protocols:  Optional[str]   = None,
    search:     str             = "",
    include_ipv6: bool          = True,
):
    """
    Export a filtered subset of the current capture as a new pcap file.
    Applies the same filter_packets() logic as /api/graph.
    Returns the pcap as a binary file download.
    """
    _require_capture()

    pkts = filter_packets(
        store.packets,
        time_range=(time_start, time_end) if time_start is not None and time_end is not None else None,
        protocols=set(protocols.split(",")) if protocols else None,
        search_query=search,
        include_ipv6=include_ipv6,
    )

    if not pkts:
        raise HTTPException(400, "No packets match the current filters")

    # Write filtered packets to a temp pcap using scapy
    try:
        from scapy.all import wrpcap, Ether, IP, IPv6, TCP, UDP, ICMP, Raw
        import struct

        tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        tmp.close()

        # Rebuild minimal scapy packets from PacketRecord fields
        scapy_pkts = []
        for p in pkts:
            try:
                if p.ip_version == 6:
                    ip = IPv6(src=p.src_ip, dst=p.dst_ip, hlim=p.ttl or 64)
                else:
                    ip = IP(src=p.src_ip or "0.0.0.0", dst=p.dst_ip or "0.0.0.0",
                            ttl=p.ttl or 64, id=p.ip_id or 0)

                if p.transport == "TCP":
                    l4 = TCP(sport=p.src_port or 0, dport=p.dst_port or 0,
                             flags=p.tcp_flags or 0, seq=p.seq_num or 0, ack=p.ack_num or 0,
                             window=p.window_size or 0)
                elif p.transport == "UDP":
                    l4 = UDP(sport=p.src_port or 0, dport=p.dst_port or 0)
                elif p.transport == "ICMP":
                    l4 = ICMP(type=p.icmp_type or 0, code=p.icmp_code or 0)
                else:
                    continue

                pkt_layers = ip / l4
                if p.payload_preview:
                    pkt_layers = pkt_layers / Raw(load=p.payload_preview)

                pkt_layers.time = p.timestamp
                scapy_pkts.append(pkt_layers)
            except Exception:
                continue

        if not scapy_pkts:
            raise HTTPException(400, "Could not reconstruct any packets for export")

        wrpcap(tmp.name, scapy_pkts)

        base = store.file_name or "capture"
        base = base.rsplit(".", 1)[0]
        download_name = f"{base}_filtered_{len(scapy_pkts)}pkts.pcap"

        return FileResponse(
            tmp.name,
            media_type="application/vnd.tcpdump.pcap",
            filename=download_name,
            background=None,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"PCAP slice error: {e}")
        raise HTTPException(500, f"Export failed: {e}")


@app.get("/api/logs")
async def get_logs(last: int = Query(default=50, ge=1, le=200)):
    """Get recent server log lines."""
    return {"logs": _log_buffer[-last:]}


# ── Main ─────────────────────────────────────────────────────────────────

LOG_FILE = Path(__file__).parent / "swifteye.log"

def _save_crash_log():
    """Save buffered logs to file on shutdown."""
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"SwiftEye shutdown at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'='*60}\n")
            for line in _log_buffer[-100:]:
                f.write(line + "\n")
        print(f"\nLogs saved to {LOG_FILE}")
    except Exception as e:
        print(f"Could not save logs: {e}")


# ── Research Chart Endpoints ─────────────────────────────────────────────

@app.get("/api/research")
async def get_research_charts():
    """
    List all registered research charts with their param declarations.

    Does NOT require a capture — chart registration happens at server startup
    and is independent of what is loaded. The run endpoint (POST) still requires
    a capture because it needs packets to compute against.
    """
    return {"charts": [c.to_info() for c in get_charts().values()]}


@app.post("/api/research/{chart_name}")
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
        # Extract reserved keys (not forwarded to chart compute())
        chart_params = {k: v for k, v in body.items() if not k.startswith('_')}
        t_start = body.get('_timeStart')
        t_end   = body.get('_timeEnd')

        # _filter_* keys carry the graph filter state from the Timeline page,
        # so the Gantt sees the same subset as the current graph view.
        # Filtering is delegated to analysis.filter_packets() — same function
        # used by build_graph — so there is no duplicated filter logic here.
        # _filter_* keys carry the active filter state from the Timeline/Research page.
        # _filterSearch replaces the old _filterIp/_filterPort — it is a general substring
        # match against IPs, MACs, protocols, ports, and flags (same as /api/graph search).
        f_protocols    = body.get('_filterProtocols')   # comma-sep string
        f_search       = body.get('_filterSearch', '')
        f_include_ipv6 = body.get('_filterIncludeIpv6', True)

        pkts = filter_packets(
            store.packets,
            time_range=(t_start, t_end) if t_start is not None and t_end is not None else None,
            protocols=set(f_protocols.split(',')) if f_protocols else None,
            search_query=f_search,
            include_ipv6=f_include_ipv6,
        )

        # Scope sessions to flows that have packets in the filtered set.
        # This is the authoritative filter — if a session has no packets in the
        # window, it doesn't belong in the chart regardless of its start/end times.
        sess = store.sessions
        if t_start is not None and t_end is not None or f_protocols or f_search or not f_include_ipv6:
            active_keys = {p.session_key for p in pkts}
            sess = [s for s in sess if s.get('id') in active_keys]

        # NOTE: nodes/edges not passed — they are built on-demand by /api/graph
        # and not cached on the store. Charts needing graph topology should call
        # build_graph() directly in their compute() method.
        ctx    = AnalysisContext(packets=pkts, sessions=sess,
                                time_range=(t_start, t_end) if t_start is not None and t_end is not None else None)
        figure = run_chart(chart_name, ctx, chart_params)
        return {"figure": figure}
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error(f"Research chart '{chart_name}' failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import signal
    import atexit
    
    atexit.register(_save_crash_log)
    
    def _handle_signal(sig, frame):
        logger.info(f"Received signal {sig}, shutting down...")
        _save_crash_log()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)
    
    port = int(os.environ.get("SWIFTEYE_PORT", 8642))
    logger.info(f"Starting SwiftEye on http://localhost:{port}")
    logger.info(f"Log file: {LOG_FILE}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
