"""
Tshark metadata CSV ingestion adapter.

Reads the main tshark packet metadata export (tab-separated) and produces
PacketRecords with full L2-L4 fields. This is the base adapter for tshark
datasets — protocol-specific CSVs (dns, http, smb, dce_rpc) enrich these
records via session merging.

Expected tshark export command:
  tshark -r capture.pcap -T fields \
    -e frame.number -e frame.time_epoch \
    -e eth.dst -e eth.src -e eth.type \
    -e ip.version -e ip.hdr_len -e ip.len -e ip.id -e ip.flags \
    -e ip.frag_offset -e ip.ttl -e ip.proto -e ip.checksum \
    -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
    -e udp.length -e udp.checksum \
    -e tcp.seq -e tcp.ack -e tcp.hdr_len -e tcp.flags \
    -e tcp.window_size -e tcp.checksum -e tcp.urgent_pointer \
    -e icmp.type -e icmp.code -e icmp.checksum \
    -e data.len > metadata.csv

Header fields (tab-separated):
  frameNumber, ts, destMac, sourceMac, etherType, ipVersion, ipHeaderLength,
  ipTotalLength, ipId, ipFlags, ipfragmentOffset, ipTtl, ipProtoType,
  ipChecksum, sourceIp, destIp, sourcePort, destPort, udpLength, udpChecksum,
  tcpSeqNumber, tcpAckNumber, tcpHeaderLength, tcpFlags, tcpWindowSize,
  tcpChecksum, tcpUrgentPointer, icmpType, icmpCode, icmpChecksum,
  layerFiveLength
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from workspaces.network.parser.packet import PacketRecord
from workspaces.network.parser.protocols import resolve_protocol
from workspaces.network.parser.schema.contracts import SchemaField
from .. import IngestionAdapter, register_adapter
from .common import parse_tshark_csv, get_tshark_columns, safe_int, safe_float, is_tshark_csv

logger = logging.getLogger("swifteye.adapters.tshark_metadata")

IP_PROTO_MAP = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}

# TCP flag bit positions (same as constants.TCP_FLAG_BITS)
_FLAG_NAMES = [
    (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
    (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"),
]


def _flags_to_str(flags: int) -> str:
    """Convert TCP flag byte to space-separated names."""
    parts = [name for bit, name in _FLAG_NAMES if flags & bit]
    return " ".join(parts)


def _flags_to_list(flags: int) -> list:
    return [name for bit, name in _FLAG_NAMES if flags & bit]


@register_adapter
class TsharkMetadataAdapter(IngestionAdapter):
    name = "tshark metadata CSV"
    file_extensions = [".csv"]
    granularity = "packet"
    source_type = "tshark"

    declared_fields = [
        SchemaField("frameNumber",       required=True,  description="Frame/packet sequence number"),
        SchemaField("ts",                required=True,  description="Packet timestamp (Unix epoch)"),
        SchemaField("sourceIp",          required=True,  description="Source IP address"),
        SchemaField("destIp",            required=True,  description="Destination IP address"),
        SchemaField("ipProtoType",       required=True,  description="IP protocol number (6=TCP, 17=UDP, 1=ICMP)"),
        SchemaField("sourceMac",         required=True,  description="Source MAC address"),
        SchemaField("destMac",           required=True,  description="Destination MAC address"),
        SchemaField("sourcePort",        required=False, description="Source port"),
        SchemaField("destPort",          required=False, description="Destination port"),
        SchemaField("ipVersion",         required=False, description="IP version (4 or 6)"),
        SchemaField("ipTotalLength",     required=False, description="IP total length in bytes"),
        SchemaField("ipTtl",             required=False, description="IP time-to-live"),
        SchemaField("ipId",              required=False, description="IP identification field"),
        SchemaField("ipFlags",           required=False, description="IP flags"),
        SchemaField("ipfragmentOffset",  required=False, description="IP fragment offset"),
        SchemaField("ipChecksum",        required=False, description="IP header checksum"),
        SchemaField("tcpSeqNumber",      required=False, description="TCP sequence number"),
        SchemaField("tcpAckNumber",      required=False, description="TCP acknowledgement number"),
        SchemaField("tcpHeaderLength",   required=False, description="TCP header length"),
        SchemaField("tcpFlags",          required=False, description="TCP flags bitmask"),
        SchemaField("tcpWindowSize",     required=False, description="TCP window size"),
        SchemaField("tcpChecksum",       required=False, description="TCP checksum"),
        SchemaField("tcpUrgentPointer",  required=False, description="TCP urgent pointer"),
        SchemaField("udpLength",         required=False, description="UDP datagram length"),
        SchemaField("udpChecksum",       required=False, description="UDP checksum"),
        SchemaField("icmpType",          required=False, description="ICMP type"),
        SchemaField("icmpCode",          required=False, description="ICMP code"),
        SchemaField("icmpChecksum",      required=False, description="ICMP checksum"),
        SchemaField("layerFiveLength",   required=False, description="Application-layer payload length"),
        SchemaField("etherType",         required=False, description="Ethernet type field"),
        SchemaField("ipHeaderLength",    required=False, description="IP header length"),
    ]

    def can_handle(self, path: Path, header: bytes) -> bool:
        if path.suffix.lower() != ".csv":
            return False
        # Catch-all for tshark metadata CSVs — checked last, so specific protocol
        # adapters (dns/http/smb/arp) have already been tried.  Column names may be
        # renamed; detect by structure: tab-separated first line with ≥15 columns.
        try:
            first_line = header.split(b"\n", 1)[0].decode("utf-8", errors="replace").strip()
            return "\t" in first_line and len(first_line.split("\t")) >= 15
        except Exception:
            return False

    def get_header_columns(self, path: Path) -> List[str]:
        return get_tshark_columns(path)

    def get_raw_rows(self, path: Path) -> List[Dict[str, str]]:
        return parse_tshark_csv(path)

    def _rows_to_packets(self, rows: List[Dict[str, str]]) -> List[PacketRecord]:
        if not rows:
            return []
        packets = []
        for row in rows:
            pkt = self._row_to_packet(row)
            if pkt:
                packets.append(pkt)
        packets.sort(key=lambda p: p.timestamp)
        logger.info("Parsed %d packets from tshark metadata CSV", len(packets))
        return packets

    def _row_to_packet(self, row: Dict[str, str]) -> Optional[PacketRecord]:
        src_ip = row.get("sourceIp", "")
        dst_ip = row.get("destIp", "")
        _SKIP_IPS = ("", "0.0.0.0", "255.255.255.255")
        if src_ip in _SKIP_IPS or dst_ip in _SKIP_IPS:
            return None

        timestamp = safe_float(row.get("ts", "0"))
        if timestamp == 0:
            return None

        ip_proto = int(safe_float(row.get("ipProtoType", "0")))
        transport = IP_PROTO_MAP.get(ip_proto, "")

        # ICMP error messages encapsulate the original packet header — tshark
        # extracts the inner packet's ports into sourcePort/destPort. Ignore
        # those for ICMP; use 0 ports and skip port-based protocol resolution.
        is_icmp = ip_proto in (1, 58)
        src_port = 0 if is_icmp else int(safe_float(row.get("sourcePort", "0")))
        dst_port = 0 if is_icmp else int(safe_float(row.get("destPort", "0")))

        protocol = resolve_protocol(transport, src_port, dst_port) if transport and not is_icmp else transport

        tcp_flags_raw = int(safe_float(row.get("tcpFlags", "0")))

        pkt = PacketRecord(
            timestamp=timestamp,
            src_mac=row.get("sourceMac", ""),
            dst_mac=row.get("destMac", ""),
            src_ip=src_ip,
            dst_ip=dst_ip,
            ip_version=int(safe_float(row.get("ipVersion", "4"))),
            ttl=int(safe_float(row.get("ipTtl", "0"))),
            ip_proto=ip_proto,
            ip_id=int(safe_float(row.get("ipId", "0"))),
            ip_flags=int(safe_float(row.get("ipFlags", "0"))),
            frag_offset=int(safe_float(row.get("ipfragmentOffset", "0"))),
            ip_checksum=safe_int(row.get("ipChecksum", "0").replace("0x", "")) if "0x" in row.get("ipChecksum", "") else int(safe_float(row.get("ipChecksum", "0"))),
            src_port=src_port,
            dst_port=dst_port,
            transport=transport,
            protocol=protocol,
            protocol_by_port=protocol if protocol != transport else "",
            protocol_confidence="port" if protocol != transport else "",
            tcp_flags=tcp_flags_raw,
            tcp_flags_str=_flags_to_str(tcp_flags_raw) if transport == "TCP" else "",
            tcp_flags_list=_flags_to_list(tcp_flags_raw) if transport == "TCP" else [],
            seq_num=int(safe_float(row.get("tcpSeqNumber", "0"))),
            ack_num=int(safe_float(row.get("tcpAckNumber", "0"))),
            window_size=int(safe_float(row.get("tcpWindowSize", "0"))),
            tcp_data_offset=int(safe_float(row.get("tcpHeaderLength", "0"))),
            tcp_checksum=safe_int(row.get("tcpChecksum", "0").replace("0x", "")) if "0x" in row.get("tcpChecksum", "") else int(safe_float(row.get("tcpChecksum", "0"))),
            urg_ptr=int(safe_float(row.get("tcpUrgentPointer", "0"))),
            icmp_type=int(safe_float(row.get("icmpType", "-1"))) if row.get("icmpType", "") else -1,
            icmp_code=int(safe_float(row.get("icmpCode", "-1"))) if row.get("icmpCode", "") else -1,
            orig_len=int(safe_float(row.get("ipTotalLength", "0"))),
            payload_len=int(safe_float(row.get("layerFiveLength", "0"))),
        )
        pkt.extra = {"source_type": "tshark"}

        return pkt
