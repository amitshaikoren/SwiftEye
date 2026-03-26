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

from parser.packet import PacketRecord
from parser.protocols import resolve_protocol
from .. import IngestionAdapter, register_adapter
from .common import parse_tshark_csv, safe_int, safe_float, is_tshark_csv

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

    def can_handle(self, path: Path, header: bytes) -> bool:
        if path.suffix.lower() != ".csv":
            return False
        return is_tshark_csv(
            header, "frameNumber", "sourceIp", "destIp", "ipProtoType",
            "sourceMac", "destMac"
        )

    def parse(self, path: Path, **opts) -> List[PacketRecord]:
        rows = parse_tshark_csv(path)
        if not rows:
            logger.warning("No data rows in %s", path.name)
            return []

        packets = []
        for row in rows:
            pkt = self._row_to_packet(row)
            if pkt:
                packets.append(pkt)

        packets.sort(key=lambda p: p.timestamp)
        logger.info("Parsed %d packets from tshark metadata CSV (%s)", len(packets), path.name)
        return packets

    def _row_to_packet(self, row: Dict[str, str]) -> Optional[PacketRecord]:
        src_ip = row.get("sourceIp", "")
        dst_ip = row.get("destIp", "")
        if not src_ip or not dst_ip:
            return None

        timestamp = safe_float(row.get("ts", "0"))
        if timestamp == 0:
            return None

        ip_proto = int(safe_float(row.get("ipProtoType", "0")))
        transport = IP_PROTO_MAP.get(ip_proto, "")

        src_port = int(safe_float(row.get("sourcePort", "0")))
        dst_port = int(safe_float(row.get("destPort", "0")))

        protocol = resolve_protocol(transport, src_port, dst_port) if transport else ""

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
