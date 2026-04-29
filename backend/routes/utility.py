import json
import logging
import tempfile

from fastapi import APIRouter, HTTPException, Query, UploadFile, File
from fastapi.responses import FileResponse

from workspaces.network.store import store, _require_capture
from workspaces.network.analysis import filter_packets
from workspaces.network.analysis.edge_fields import meta_for_api as _edge_fields_meta

from scapy.all import wrpcap, Ether, IP, IPv6, TCP, UDP, ICMP, Raw as ScapyRaw  # type: ignore

logger = logging.getLogger("swifteye.routes.utility")
router = APIRouter()


# ── Log buffer for frontend ──────────────────────────────────────────────────

_log_buffer = []
_max_log_lines = 200


class FrontendLogHandler(logging.Handler):
    def emit(self, record):
        msg = self.format(record)
        _log_buffer.append(msg)
        if len(_log_buffer) > _max_log_lines:
            _log_buffer.pop(0)


def setup_log_handler():
    """Install the frontend log handler. Called once at app startup."""
    _fh = FrontendLogHandler()
    _fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%H:%M:%S"))
    logging.getLogger("swifteye").addHandler(_fh)
    logging.getLogger("uvicorn.error").addHandler(_fh)


# ── Edge field registry (for frontend search hints) ──────────────────────────

@router.get("/api/meta/edge-fields")
async def get_edge_field_meta():
    """
    Return the edge field registry so the frontend can build dynamic
    keyword hints for the search bar without hardcoding field names.
    """
    return {"fields": _edge_fields_meta()}


# ── Metadata ─────────────────────────────────────────────────────────────────

@router.post("/api/metadata")
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


@router.delete("/api/metadata")
async def clear_metadata():
    """Clear researcher metadata overlay."""
    store.metadata_map = {}
    logger.info("Researcher metadata cleared")
    return {"success": True}


@router.get("/api/metadata")
async def get_metadata():
    """Get current researcher metadata."""
    return {"metadata": store.metadata_map, "count": len(store.metadata_map)}


# ── PCAP slice/export ─────────────────────────────────────────────────────────

@router.get("/api/slice")
async def slice_pcap(
    time_start: float = None,
    time_end:   float = None,
    protocols:  str   = None,
    search:     str   = "",
    include_ipv6: bool = True,
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

    try:
        tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        tmp.close()

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
                    pkt_layers = pkt_layers / ScapyRaw(load=p.payload_preview)

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


# ── Logs ──────────────────────────────────────────────────────────────────────

@router.get("/api/logs")
async def get_logs(last: int = Query(default=50, ge=1, le=200)):
    """Get recent server log lines."""
    return {"logs": _log_buffer[-last:]}
