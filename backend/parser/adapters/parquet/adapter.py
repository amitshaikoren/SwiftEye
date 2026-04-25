"""
Parquet ingestion adapter.

Reads Parquet files via pyarrow and produces one PacketRecord per row.
Each row is treated as a session record (granularity = "session"), matching
the Zeek conn.log shape used as the baseline column declaration.

Column mapping
--------------
declared_fields uses Zeek conn.log names (ts, id.orig_h, id.orig_p, …) so
a Parquet file exported from Zeek maps without negotiation. Files with
different column names are handled transparently via schema negotiation:
get_header_columns() returns the actual names; the upload UI suggests renames;
parse_with_mapping() remaps keys before _rows_to_packets() is called.

Value types
-----------
pyarrow to_pylist() yields native Python types (int, float, str, None,
datetime.datetime). The _safe_int / _safe_float helpers accept all of these,
including the string form used by Zeek text logs, so a single _rows_to_packets
implementation handles both sources.
"""

import datetime
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import pyarrow.parquet as pq

from parser.packet import PacketRecord
from parser.schema.contracts import SchemaField
from .. import IngestionAdapter, register_adapter

logger = logging.getLogger("swifteye.adapters.parquet")

PARQUET_MAGIC = b"PAR1"

# Application-layer service name → SwiftEye protocol label.
# Kept in sync with zeek/conn.py SERVICE_MAP.
SERVICE_MAP = {
    "http": "HTTP",
    "ssl": "TLS",
    "tls": "TLS",
    "dns": "DNS",
    "ssh": "SSH",
    "ftp": "FTP",
    "ftp-data": "FTP-DATA",
    "smtp": "SMTP",
    "smb": "SMB",
    "dhcp": "DHCP",
    "ntp": "NTP",
    "irc": "IRC",
    "rdp": "RDP",
    "sip": "SIP",
    "snmp": "SNMP",
    "ldap": "LDAP",
    "krb": "Kerberos",
    "kerberos": "Kerberos",
    "syslog": "Syslog",
    "mysql": "MySQL",
    "dce_rpc": "DCE/RPC",
}


def _safe_int(v: Any, default: int = 0) -> int:
    if v is None or v == "-":
        return default
    try:
        return int(v)
    except (ValueError, TypeError):
        return default


def _safe_float(v: Any, default: float = 0.0) -> float:
    if v is None or v == "-":
        return default
    if isinstance(v, datetime.datetime):
        return v.timestamp()
    try:
        return float(v)
    except (ValueError, TypeError):
        return default


def _safe_str(v: Any, default: str = "") -> str:
    if v is None:
        return default
    s = str(v).strip()
    return default if s == "-" else s


@register_adapter
class ParquetAdapter(IngestionAdapter):
    name = "Parquet"
    file_extensions = [".parquet"]
    granularity = "session"
    source_type = "parquet"

    # Zeek conn.log column shape as baseline — covers the most common parquet
    # export format. Files with different column names are handled via schema
    # negotiation (get_header_columns + parse_with_mapping).
    declared_fields = [
        SchemaField("ts",             required=True,  description="Session start timestamp (Unix epoch or datetime)"),
        SchemaField("id.orig_h",      required=True,  description="Originating host IP"),
        SchemaField("id.orig_p",      required=True,  description="Originating port"),
        SchemaField("id.resp_h",      required=True,  description="Responding host IP"),
        SchemaField("id.resp_p",      required=True,  description="Responding port"),
        SchemaField("proto",          required=True,  description="Transport protocol (tcp/udp/icmp)"),
        SchemaField("conn_state",     required=False, description="Connection state (SF, S0, REJ, …)"),
        SchemaField("service",        required=False, description="Application-layer service"),
        SchemaField("duration",       required=False, description="Session duration in seconds"),
        SchemaField("orig_bytes",     required=False, description="Payload bytes sent by originator"),
        SchemaField("resp_bytes",     required=False, description="Payload bytes sent by responder"),
        SchemaField("orig_ip_bytes",  required=False, description="IP-level bytes sent by originator"),
        SchemaField("resp_ip_bytes",  required=False, description="IP-level bytes sent by responder"),
        SchemaField("orig_pkts",      required=False, description="Packets sent by originator"),
        SchemaField("resp_pkts",      required=False, description="Packets sent by responder"),
        SchemaField("history",        required=False, description="TCP state history string"),
        SchemaField("uid",            required=False, description="Unique session identifier"),
    ]

    def can_handle(self, path: Path, header: bytes) -> bool:
        if path.suffix.lower() == ".parquet":
            return True
        return header[:4] == PARQUET_MAGIC

    def get_header_columns(self, path: Path) -> List[str]:
        """Read Parquet schema without loading row data."""
        schema = pq.read_schema(path)
        return schema.names

    def get_raw_rows(self, path: Path) -> List[Dict[str, Any]]:
        """Read all rows as dicts with native Python values."""
        table = pq.read_table(path)
        return table.to_pylist()

    def _rows_to_packets(self, rows: List[Dict[str, Any]]) -> List[PacketRecord]:
        if not rows:
            return []
        packets = []
        for row in rows:
            pkt = self._row_to_packet(row)
            if pkt:
                packets.append(pkt)
        packets.sort(key=lambda p: p.timestamp)
        logger.info("Parsed %d sessions from Parquet file", len(packets))
        return packets

    def _row_to_packet(self, row: Dict[str, Any]) -> Optional[PacketRecord]:
        src_ip = _safe_str(row.get("id.orig_h", ""))
        dst_ip = _safe_str(row.get("id.resp_h", ""))
        if not src_ip or not dst_ip:
            return None

        timestamp = _safe_float(row.get("ts", 0))
        if timestamp == 0.0:
            return None

        src_port = _safe_int(row.get("id.orig_p", 0))
        dst_port = _safe_int(row.get("id.resp_p", 0))

        proto_raw = _safe_str(row.get("proto", "")).upper()
        transport = proto_raw if proto_raw in ("TCP", "UDP", "ICMP") else ""

        service_raw = _safe_str(row.get("service", ""))
        if service_raw:
            primary = service_raw.split(",")[0].strip()
            protocol = SERVICE_MAP.get(primary.lower(), primary.upper())
        else:
            protocol = transport or "OTHER"

        orig_bytes    = _safe_int(row.get("orig_bytes", 0))
        resp_bytes    = _safe_int(row.get("resp_bytes", 0))
        orig_ip_bytes = _safe_int(row.get("orig_ip_bytes", 0))
        resp_ip_bytes = _safe_int(row.get("resp_ip_bytes", 0))
        total_bytes = (
            orig_ip_bytes + resp_ip_bytes
            if (orig_ip_bytes or resp_ip_bytes)
            else orig_bytes + resp_bytes
        )

        duration = _safe_float(row.get("duration", 0))
        ip_version = 6 if ":" in src_ip else 4

        conn_state = _safe_str(row.get("conn_state", ""))
        has_handshake = conn_state in ("SF", "S1", "S2", "S3", "RSTO", "RSTR")

        extra: Dict[str, Any] = {
            "source_type": "parquet",
            "has_handshake": has_handshake,
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "duration": duration,
        }
        for field in ("uid", "conn_state", "history", "orig_ip_bytes", "resp_ip_bytes",
                      "orig_pkts", "resp_pkts"):
            val = row.get(field)
            if val is not None and str(val) not in ("", "-"):
                extra[field] = val
        if service_raw:
            extra["service"] = service_raw

        pkt = PacketRecord(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            transport=transport,
            protocol=protocol,
            ip_version=ip_version,
            orig_len=total_bytes,
        )
        pkt.extra = extra
        return pkt
