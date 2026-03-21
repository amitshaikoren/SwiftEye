"""
Zeek ssl.log ingestion adapter.

Reads Zeek SSL/TLS logs and produces PacketRecords with TLS-specific
extra fields that sessions.py already accumulates (tls_sni, tls_versions,
tls_selected_cipher, ja3, etc.).

Each ssl.log row represents one TLS connection. When uploaded alongside
conn.log, packets join existing sessions by 5-tuple session key. The
conn.log provides base metadata; ssl.log enriches with TLS negotiation
details, certificates, and JA3 fingerprints.
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from parser.packet import PacketRecord
from . import IngestionAdapter, register_adapter
from .zeek_common import parse_zeek_log, safe_int, safe_float, is_zeek_log

logger = logging.getLogger("swifteye.adapters.zeek_ssl")


@register_adapter
class ZeekSslAdapter(IngestionAdapter):
    name = "Zeek ssl.log"
    file_extensions = [".log"]
    granularity = "session"
    source_type = "zeek"

    def can_handle(self, path: Path, header: bytes) -> bool:
        if path.suffix.lower() != ".log":
            return False
        # ssl.log has "cipher" and "server_name" fields
        return is_zeek_log(header, "cipher") and is_zeek_log(header, "server_name")

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
        logger.info("Parsed %d TLS sessions from Zeek ssl.log (%s)", len(packets), path.name)
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

        extra: Dict[str, Any] = {
            "source_type": "zeek",
        }

        # SNI
        sni = row.get("server_name", "-")
        if sni and sni != "-":
            extra["tls_sni"] = sni

        # TLS version (negotiated)
        version = row.get("version", "-")
        if version and version != "-":
            extra["tls_hello_version"] = version
            extra["tls_selected_version"] = version

        # Selected cipher
        cipher = row.get("cipher", "-")
        if cipher and cipher != "-":
            extra["tls_selected_cipher"] = cipher

        # Curve (key exchange)
        curve = row.get("curve", "-")
        if curve and curve != "-":
            extra["tls_key_exchange_group"] = curve

        # Session resumption
        resumed = row.get("resumed", "-")
        if resumed == "T":
            extra["tls_session_resumption"] = "resumed"
        elif resumed == "F":
            extra["tls_session_resumption"] = "none"

        # ALPN (next_protocol in Zeek)
        next_proto = row.get("next_protocol", "-")
        if next_proto and next_proto != "-":
            extra["tls_alpn_selected"] = next_proto

        # JA3 (client fingerprint)
        ja3 = row.get("ja3", "-")
        if ja3 and ja3 != "-":
            extra["ja3"] = ja3

        # JA3S (server fingerprint) — stored alongside JA3
        ja3s = row.get("ja3s", "-")
        if ja3s and ja3s != "-":
            extra["ja3s"] = ja3s

        # Certificate subject/issuer
        subject = row.get("subject", "-")
        issuer = row.get("issuer", "-")
        if subject and subject != "-":
            cert_info = {"subject_cn": subject}
            if issuer and issuer != "-":
                cert_info["issuer"] = issuer
            extra["tls_cert"] = cert_info
            extra["tls_cert_chain"] = [cert_info]

        # Validation status
        validation = row.get("validation_status", "-")
        if validation and validation != "-":
            extra["tls_validation_status"] = validation

        # Established
        established = row.get("established", "-")
        if established and established != "-":
            extra["tls_established"] = established == "T"

        # Zeek UID
        uid = row.get("uid", "")
        if uid and uid != "-":
            extra["uid"] = uid

        pkt = PacketRecord(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            transport="TCP",
            protocol="TLS",
            ip_version=ip_version,
        )
        pkt.extra = extra

        return pkt
