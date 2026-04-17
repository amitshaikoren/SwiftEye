"""
Tshark HTTP CSV ingestion adapters.

Two adapters for http_request.csv and http_response.csv. Each joins with
metadata.csv (sibling file) by frameNumber to get the 5-tuple, then adds
HTTP-specific fields to extra.

http_request.csv fields:
  frameNumber, ts, httpRequestMethod, httpRequestUri, httpRequestVersion,
  httpRequestHeaders, responseIn

http_response.csv fields:
  frameNumber, ts, httpResponseVersion, httpResponseCode, httpResponsePhrase,
  httpResponseHeaders, requestIn
"""

import ast
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from workspaces.network.parser.packet import PacketRecord
from .. import IngestionAdapter, register_adapter
from .common import (
    parse_tshark_csv, safe_int, safe_float, is_tshark_csv,
    load_metadata_index, meta_to_network,
)

logger = logging.getLogger("swifteye.adapters.tshark_http")


def _parse_headers_dict(raw: str) -> Dict[str, str]:
    """Parse a Python dict literal from the headers field."""
    if not raw:
        return {}
    # Strip surrounding quotes if present
    raw = raw.strip('"')
    try:
        return ast.literal_eval(raw)
    except Exception:
        return {}


@register_adapter
class TsharkHttpRequestAdapter(IngestionAdapter):
    name = "tshark HTTP request CSV"
    file_extensions = [".csv"]
    granularity = "packet"
    source_type = "tshark"

    def can_handle(self, path: Path, header: bytes) -> bool:
        if path.suffix.lower() != ".csv":
            return False
        return is_tshark_csv(header, "httpRequestMethod", "httpRequestUri", "httpRequestVersion")

    def parse(self, path: Path, **opts) -> List[PacketRecord]:
        rows = parse_tshark_csv(path)
        if not rows:
            return []

        meta_index = load_metadata_index(path.parent)
        packets = []
        skipped = 0
        for row in rows:
            pkt = self._row_to_packet(row, meta_index)
            if pkt:
                packets.append(pkt)
            else:
                skipped += 1

        packets.sort(key=lambda p: p.timestamp)
        logger.info("Parsed %d HTTP requests from %s (skipped %d)", len(packets), path.name, skipped)
        return packets

    def _row_to_packet(self, row: Dict[str, str], meta_index) -> Optional[PacketRecord]:
        frame = row.get("frameNumber", "")
        timestamp = safe_float(row.get("ts", "0"))
        if timestamp == 0:
            return None

        net = None
        if meta_index and frame in meta_index:
            net = meta_to_network(meta_index[frame])
        if not net or not net["src_ip"] or not net["dst_ip"]:
            return None

        method = row.get("httpRequestMethod", "")
        uri = row.get("httpRequestUri", "")
        version = row.get("httpRequestVersion", "")
        headers = _parse_headers_dict(row.get("httpRequestHeaders", ""))

        host = headers.get("Host", "").rstrip("\\r\\n").strip()
        user_agent = headers.get("User-Agent", "").strip()
        content_type = headers.get("Content-Type", "").strip()
        cookie = headers.get("Cookie", "").rstrip("\\r\\n").strip()

        extra: Dict[str, Any] = {
            "source_type": "tshark",
            "http_method": method,
            "http_uri": uri,
            "http_version": version,
            "http_is_request": True,
        }
        if host:
            extra["http_host"] = host
        if user_agent:
            extra["http_user_agent"] = user_agent
        if content_type:
            extra["http_content_type"] = content_type
        if cookie:
            extra["http_cookie"] = cookie[:500]

        pkt = PacketRecord(
            timestamp=timestamp,
            src_ip=net["src_ip"],
            dst_ip=net["dst_ip"],
            src_port=net["src_port"],
            dst_port=net["dst_port"],
            src_mac=net["src_mac"],
            dst_mac=net["dst_mac"],
            transport=net["transport"],
            protocol="HTTP",
            ip_version=4,
            ttl=net["ttl"],
            ip_proto=net["ip_proto"],
        )
        pkt.extra = extra
        return pkt


@register_adapter
class TsharkHttpResponseAdapter(IngestionAdapter):
    name = "tshark HTTP response CSV"
    file_extensions = [".csv"]
    granularity = "packet"
    source_type = "tshark"

    def can_handle(self, path: Path, header: bytes) -> bool:
        if path.suffix.lower() != ".csv":
            return False
        return is_tshark_csv(header, "httpResponseVersion", "httpResponseCode", "httpResponsePhrase")

    def parse(self, path: Path, **opts) -> List[PacketRecord]:
        rows = parse_tshark_csv(path)
        if not rows:
            return []

        meta_index = load_metadata_index(path.parent)
        packets = []
        skipped = 0
        for row in rows:
            pkt = self._row_to_packet(row, meta_index)
            if pkt:
                packets.append(pkt)
            else:
                skipped += 1

        packets.sort(key=lambda p: p.timestamp)
        logger.info("Parsed %d HTTP responses from %s (skipped %d)", len(packets), path.name, skipped)
        return packets

    def _row_to_packet(self, row: Dict[str, str], meta_index) -> Optional[PacketRecord]:
        frame = row.get("frameNumber", "")
        timestamp = safe_float(row.get("ts", "0"))
        if timestamp == 0:
            return None

        net = None
        if meta_index and frame in meta_index:
            net = meta_to_network(meta_index[frame])
        if not net or not net["src_ip"] or not net["dst_ip"]:
            return None

        code = safe_int(row.get("httpResponseCode", "0"))
        phrase = row.get("httpResponsePhrase", "")
        version = row.get("httpResponseVersion", "")
        headers = _parse_headers_dict(row.get("httpResponseHeaders", ""))

        server = headers.get("Server", "").strip()
        content_type = headers.get("Content-Type", "").strip()
        set_cookie = headers.get("Set-Cookie", "").rstrip("\\r\\n").strip()

        extra: Dict[str, Any] = {
            "source_type": "tshark",
            "http_status_code": code,
            "http_status_phrase": phrase,
            "http_version": version,
            "http_is_request": False,
        }
        if server:
            extra["http_server"] = server
        if content_type:
            extra["http_resp_content_type"] = content_type
        if set_cookie:
            extra["http_set_cookie"] = set_cookie[:500]

        pkt = PacketRecord(
            timestamp=timestamp,
            src_ip=net["src_ip"],
            dst_ip=net["dst_ip"],
            src_port=net["src_port"],
            dst_port=net["dst_port"],
            src_mac=net["src_mac"],
            dst_mac=net["dst_mac"],
            transport=net["transport"],
            protocol="HTTP",
            ip_version=4,
            ttl=net["ttl"],
            ip_proto=net["ip_proto"],
        )
        pkt.extra = extra
        return pkt
