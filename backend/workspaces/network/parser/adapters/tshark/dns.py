"""
Tshark DNS CSV ingestion adapters.

Two adapters for dns_request.csv and dns_response.csv. Each joins with
metadata.csv (sibling file) by frameNumber to get the 5-tuple, then adds
DNS-specific fields to extra.

dns_request.csv fields:
  frameNumber, ts, transId, flags, queriesCount, answersCount,
  authRRCount, addRRCount, query, responseAt

dns_response.csv fields:
  frameNumber, ts, transId, flags, queriesCount, answersCount,
  authRRCount, addRRCount, query, answers, requestAt
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

logger = logging.getLogger("swifteye.adapters.tshark_dns")


def _parse_query_dict(raw: str) -> Dict[str, Any]:
    """Parse a Python dict literal from tshark CSV (e.g. {'qname': '...', 'qtype': 1.0})."""
    if not raw or raw == "{}":
        return {}
    try:
        return ast.literal_eval(raw)
    except Exception:
        return {}


def _parse_answers_list(raw: str) -> List[Dict[str, Any]]:
    """Parse a Python list of dicts from tshark CSV."""
    if not raw or raw == "[]":
        return []
    try:
        return ast.literal_eval(raw)
    except Exception:
        return []


# DNS query type number → name
DNS_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS",
    46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 65: "HTTPS", 255: "ANY",
}


def _build_dns_packet(
    row: Dict[str, str],
    meta_index: Optional[Dict[str, Dict[str, str]]],
    is_response: bool,
) -> Optional[PacketRecord]:
    """Build a PacketRecord from a DNS request or response row."""
    frame = row.get("frameNumber", "")
    timestamp = safe_float(row.get("ts", "0"))
    if timestamp == 0:
        return None

    # Get network info from metadata
    net = None
    if meta_index and frame in meta_index:
        net = meta_to_network(meta_index[frame])

    if not net or not net["src_ip"] or not net["dst_ip"]:
        return None

    # Parse query field
    query = _parse_query_dict(row.get("query", ""))
    qname = query.get("qname", "")
    qtype_num = int(query.get("qtype", 0) or 0)
    qtype_name = DNS_QTYPES.get(qtype_num, str(qtype_num))

    extra: Dict[str, Any] = {
        "source_type": "tshark",
        "dns_query": qname,
        "dns_qtype": qtype_name,
        "dns_trans_id": safe_int(row.get("transId", "0")),
        "dns_is_response": is_response,
    }

    if is_response:
        answers = _parse_answers_list(row.get("answers", "[]"))
        if answers:
            extra["dns_answers"] = []
            for ans in answers:
                a = {
                    "name": ans.get("rname", ""),
                    "type": DNS_QTYPES.get(int(ans.get("rtype", 0) or 0), str(ans.get("rtype", ""))),
                    "data": ans.get("answer", ""),
                    "ttl": int(ans.get("ttl", 0) or 0),
                }
                extra["dns_answers"].append(a)
            extra["dns_answer_count"] = len(answers)
        # Response code from flags
        flags = safe_int(row.get("flags", "0"))
        rcode = flags & 0x000F
        rcode_names = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}
        extra["dns_rcode"] = rcode_names.get(rcode, str(rcode))

    pkt = PacketRecord(
        timestamp=timestamp,
        src_ip=net["src_ip"],
        dst_ip=net["dst_ip"],
        src_port=net["src_port"],
        dst_port=net["dst_port"],
        src_mac=net["src_mac"],
        dst_mac=net["dst_mac"],
        transport=net["transport"],
        protocol="DNS",
        ip_version=4,
        ttl=net["ttl"],
        ip_proto=net["ip_proto"],
    )
    pkt.extra = extra
    return pkt


@register_adapter
class TsharkDnsRequestAdapter(IngestionAdapter):
    name = "tshark DNS request CSV"
    file_extensions = [".csv"]
    granularity = "packet"
    source_type = "tshark"

    def can_handle(self, path: Path, header: bytes) -> bool:
        if path.suffix.lower() != ".csv":
            return False
        return is_tshark_csv(header, "transId", "queriesCount", "query", "responseAt")

    def parse(self, path: Path, **opts) -> List[PacketRecord]:
        rows = parse_tshark_csv(path)
        if not rows:
            return []

        meta_index = load_metadata_index(path.parent)
        packets = []
        skipped = 0
        for row in rows:
            pkt = _build_dns_packet(row, meta_index, is_response=False)
            if pkt:
                packets.append(pkt)
            else:
                skipped += 1

        packets.sort(key=lambda p: p.timestamp)
        logger.info("Parsed %d DNS requests from %s (skipped %d)", len(packets), path.name, skipped)
        return packets


@register_adapter
class TsharkDnsResponseAdapter(IngestionAdapter):
    name = "tshark DNS response CSV"
    file_extensions = [".csv"]
    granularity = "packet"
    source_type = "tshark"

    def can_handle(self, path: Path, header: bytes) -> bool:
        if path.suffix.lower() != ".csv":
            return False
        # dns_response has 'answers' and 'requestAt' (not 'responseAt')
        return is_tshark_csv(header, "transId", "queriesCount", "answers", "requestAt")

    def parse(self, path: Path, **opts) -> List[PacketRecord]:
        rows = parse_tshark_csv(path)
        if not rows:
            return []

        meta_index = load_metadata_index(path.parent)
        packets = []
        skipped = 0
        for row in rows:
            pkt = _build_dns_packet(row, meta_index, is_response=True)
            if pkt:
                packets.append(pkt)
            else:
                skipped += 1

        packets.sort(key=lambda p: p.timestamp)
        logger.info("Parsed %d DNS responses from %s (skipped %d)", len(packets), path.name, skipped)
        return packets
