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
from parser.schema.contracts import SchemaField
from .. import IngestionAdapter, register_adapter
from .common import parse_zeek_log, get_zeek_columns, safe_int, safe_float, is_zeek_log

logger = logging.getLogger("swifteye.adapters.zeek_ssl")


@register_adapter
class ZeekSslAdapter(IngestionAdapter):
    name = "Zeek ssl.log"
    file_extensions = [".log"]
    granularity = "session"
    source_type = "zeek"

    declared_fields = [
        SchemaField("ts",           required=True,  description="Connection timestamp"),
        SchemaField("id.orig_h",    required=True,  description="Client IP"),
        SchemaField("id.orig_p",    required=True,  description="Client port"),
        SchemaField("id.resp_h",    required=True,  description="Server IP"),
        SchemaField("id.resp_p",    required=True,  description="Server port"),
        SchemaField("version",      required=False, description="TLS/SSL version string"),
        SchemaField("cipher",       required=False, description="Negotiated cipher suite"),
        SchemaField("server_name",  required=False, description="TLS SNI (server_name extension)"),
        SchemaField("subject",      required=False, description="Certificate subject"),
        SchemaField("issuer",       required=False, description="Certificate issuer"),
        SchemaField("ja3",          required=False, description="JA3 client fingerprint"),
        SchemaField("ja3s",         required=False, description="JA3S server fingerprint"),
        SchemaField("established",  required=False, description="True if handshake completed"),
        SchemaField("uid",          required=False, description="Unique connection identifier"),
    ]

    def can_handle(self, path: Path, header: bytes) -> bool:
        if path.suffix.lower() != ".log":
            return False
        return is_zeek_log(header, "cipher") and is_zeek_log(header, "server_name")

    def get_header_columns(self, path: Path) -> List[str]:
        return get_zeek_columns(path)

    def get_raw_rows(self, path: Path) -> List[Dict[str, str]]:
        return parse_zeek_log(path)

    def _rows_to_packets(self, rows: List[Dict[str, str]]) -> List[PacketRecord]:
        if not rows:
            return []
        packets = []
        for row in rows:
            pkt = self._row_to_packet(row)
            if pkt:
                packets.append(pkt)
        packets.sort(key=lambda p: p.timestamp)
        logger.info("Parsed %d TLS sessions from Zeek ssl.log", len(packets))
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
