"""
Zeek dns.log ingestion adapter.

Reads Zeek DNS logs and produces PacketRecords with DNS-specific extra
fields that sessions.py already knows how to accumulate (dns_query,
dns_qtype_name, dns_answers, dns_rcode, etc.).

When uploaded alongside conn.log, these packets join existing sessions
by matching on the 5-tuple session key (sorted IPs + sorted ports +
transport). The conn.log provides the base session metadata; dns.log
enriches it with per-query detail.

When uploaded alone (no conn.log), dns.log still creates valid sessions
— each unique 5-tuple becomes a session with DNS query details.
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from workspaces.network.parser.packet import PacketRecord
from workspaces.network.parser.schema.contracts import SchemaField
from .. import IngestionAdapter, register_adapter
from .common import parse_zeek_log, get_zeek_columns, safe_int, safe_float, is_zeek_log

logger = logging.getLogger("swifteye.adapters.zeek_dns")


@register_adapter
class ZeekDnsAdapter(IngestionAdapter):
    name = "Zeek dns.log"
    file_extensions = [".log"]
    granularity = "session"
    source_type = "zeek"

    declared_fields = [
        SchemaField("ts",          required=True,  description="Query timestamp (Unix epoch)"),
        SchemaField("id.orig_h",   required=True,  description="Client IP"),
        SchemaField("id.orig_p",   required=True,  description="Client port"),
        SchemaField("id.resp_h",   required=True,  description="DNS server IP"),
        SchemaField("id.resp_p",   required=True,  description="DNS server port"),
        SchemaField("proto",       required=True,  description="Transport protocol"),
        SchemaField("qtype_name",  required=True,  description="Query type name (A, AAAA, MX, …)"),
        SchemaField("query",       required=False, description="DNS query name"),
        SchemaField("qtype",       required=False, description="Query type integer"),
        SchemaField("qclass_name", required=False, description="Query class (IN, CH, …)"),
        SchemaField("rcode",       required=False, description="Response code integer"),
        SchemaField("rcode_name",  required=False, description="Response code name (NOERROR, NXDOMAIN, …)"),
        SchemaField("answers",     required=False, description="Comma-separated answer RRs"),
        SchemaField("TTLs",        required=False, description="Comma-separated TTL values"),
        SchemaField("AA",          required=False, description="Authoritative answer flag"),
        SchemaField("TC",          required=False, description="Truncated flag"),
        SchemaField("RD",          required=False, description="Recursion desired flag"),
        SchemaField("RA",          required=False, description="Recursion available flag"),
        SchemaField("trans_id",    required=False, description="DNS transaction ID"),
        SchemaField("rtt",         required=False, description="Round-trip time"),
        SchemaField("uid",         required=False, description="Unique connection identifier"),
        SchemaField("rejected",    required=False, description="True if the query was rejected"),
    ]

    def can_handle(self, path: Path, header: bytes) -> bool:
        if path.suffix.lower() != ".log":
            return False
        return is_zeek_log(header, "qtype_name")

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
        logger.info("Parsed %d DNS queries from Zeek dns.log", len(packets))
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

        proto = row.get("proto", "").upper()
        transport = proto if proto in ("TCP", "UDP") else "UDP"
        ip_version = 6 if ":" in src_ip else 4

        # Parse Zeek answers field — comma-separated list
        answers_raw = row.get("answers", "-")
        answers = []
        if answers_raw and answers_raw != "-":
            answers = [a.strip() for a in answers_raw.split(",") if a.strip()]

        # Parse TTLs field — comma-separated floats
        ttls_raw = row.get("TTLs", "-")
        ttls = []
        if ttls_raw and ttls_raw != "-":
            for t in ttls_raw.split(","):
                t = t.strip()
                if t:
                    try:
                        ttls.append(float(t))
                    except ValueError:
                        pass

        # Build answer_records in the format sessions.py expects
        qtype_name = row.get("qtype_name", "")
        answer_records = []
        for i, ans in enumerate(answers):
            record = {
                "rrname": row.get("query", ""),
                "rrtype": qtype_name,
                "rdata": ans,
            }
            if i < len(ttls):
                record["ttl"] = int(ttls[i])
            answer_records.append(record)

        # Determine qr (query vs response)
        # If we have answers or rcode, this is a response record
        rcode = safe_int(row.get("rcode", "-1"))
        has_response = len(answers) > 0 or rcode >= 0
        qr = "response" if has_response else "query"

        # Build extra dict matching what sessions.py expects for DNS
        extra: Dict[str, Any] = {
            "source_type": "zeek",
            "dns_query": row.get("query", ""),
            "dns_qtype": safe_int(row.get("qtype", "0")),
            "dns_qtype_name": qtype_name,
            "dns_qclass_name": row.get("qclass_name", "IN"),
            "dns_qr": qr,
            "dns_rcode": rcode if rcode >= 0 else 0,
            "dns_rcode_name": row.get("rcode_name", ""),
            "dns_answers": answers,
            "dns_answer_records": answer_records,
            "dns_id": safe_int(row.get("trans_id", "0")),
        }

        # DNS flags
        for field, key in [("AA", "dns_aa"), ("TC", "dns_tc"),
                           ("RD", "dns_rd"), ("RA", "dns_ra")]:
            val = row.get(field, "-")
            if val == "T":
                extra[key] = True

        # Zeek UID for cross-log correlation
        uid = row.get("uid", "")
        if uid and uid != "-":
            extra["uid"] = uid

        # RTT if available
        rtt = row.get("rtt", "-")
        if rtt and rtt != "-":
            extra["dns_rtt"] = safe_float(rtt)

        rejected = row.get("rejected", "-")
        if rejected == "T":
            extra["dns_rejected"] = True

        pkt = PacketRecord(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            transport=transport,
            protocol="DNS",
            ip_version=ip_version,
        )
        pkt.extra = extra

        return pkt
