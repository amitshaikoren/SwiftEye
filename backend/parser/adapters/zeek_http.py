"""
Zeek http.log ingestion adapter.

Reads Zeek HTTP logs and produces PacketRecords with HTTP-specific extra
fields that sessions.py already accumulates (http_host, http_method,
http_uri, http_user_agent, http_status, etc.).

Each http.log row represents one HTTP transaction (request + response).
The packet's src_ip is id.orig_h (the client/initiator). Since Zeek
provides both request and response fields in one row, sessions.py
uses the source_type="zeek" flag to add both directions from a
single packet.
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from parser.packet import PacketRecord
from . import IngestionAdapter, register_adapter
from .zeek_common import parse_zeek_log, safe_int, safe_float, is_zeek_log

logger = logging.getLogger("swifteye.adapters.zeek_http")


@register_adapter
class ZeekHttpAdapter(IngestionAdapter):
    name = "Zeek http.log"
    file_extensions = [".log"]
    granularity = "session"
    source_type = "zeek"

    def can_handle(self, path: Path, header: bytes) -> bool:
        if path.suffix.lower() != ".log":
            return False
        # http.log has "status_code" and "user_agent" fields
        return is_zeek_log(header, "user_agent") and is_zeek_log(header, "status_code")

    def parse(self, path: Path, **opts) -> List[PacketRecord]:
        rows = parse_zeek_log(path)
        if not rows:
            logger.warning("No data rows in %s", path.name)
            return []

        packets = []
        for row in rows:
            pkt = self._row_to_packet(row)
            if pkt:
                packets.append(pkt)

        packets.sort(key=lambda p: p.timestamp)
        logger.info("Parsed %d HTTP transactions from Zeek http.log (%s)", len(packets), path.name)
        return packets

    def _row_to_packet(self, row: Dict[str, str]) -> Optional[PacketRecord]:
        src_ip = row.get("id.orig_h", "")
        dst_ip = row.get("id.resp_h", "")
        if not src_ip or not dst_ip:
            return None

        src_port = safe_int(row.get("id.orig_p", "0"))
        dst_port = safe_int(row.get("id.resp_p", "0"))
        timestamp = safe_float(row.get("ts", "0"))
        if timestamp == 0:
            return None

        ip_version = 6 if ":" in src_ip else 4

        # Request + response bytes for total size
        req_bytes = safe_int(row.get("request_body_len", "0"))
        resp_bytes = safe_int(row.get("response_body_len", "0"))

        extra: Dict[str, Any] = {
            "source_type": "zeek",
        }

        # Request fields (initiator →)
        host = row.get("host", "-")
        if host and host != "-":
            extra["http_host"] = host

        method = row.get("method", "-")
        if method and method != "-":
            extra["http_method"] = method

        uri = row.get("uri", "-")
        if uri and uri != "-":
            extra["http_uri"] = uri

        ua = row.get("user_agent", "-")
        if ua and ua != "-":
            extra["http_user_agent"] = ua

        referrer = row.get("referrer", "-")
        if referrer and referrer != "-":
            extra["http_referer"] = referrer

        username = row.get("username", "-")
        if username and username != "-":
            extra["http_authorization"] = True

        # Response fields (responder ←)
        status = safe_int(row.get("status_code", "0"))
        if status > 0:
            extra["http_status"] = status

        resp_mime = row.get("resp_mime_types", "-")
        if resp_mime and resp_mime != "-":
            # Zeek may comma-separate multiple MIME types
            extra["http_content_type"] = resp_mime.split(",")[0].strip()

        status_msg = row.get("status_msg", "-")
        if status_msg and status_msg != "-":
            extra["http_status_msg"] = status_msg

        # Detect redirects (3xx with location-like info)
        if 300 <= status < 400:
            # Zeek http.log doesn't have Location header directly,
            # but the redirect target is often in the uri of the next request
            pass

        # Zeek UID
        uid = row.get("uid", "")
        if uid and uid != "-":
            extra["uid"] = uid

        # HTTP version
        version = row.get("version", "-")
        if version and version != "-":
            extra["http_version"] = version

        pkt = PacketRecord(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            transport="TCP",
            protocol="HTTP",
            ip_version=ip_version,
            orig_len=req_bytes + resp_bytes,
        )
        pkt.extra = extra

        return pkt
