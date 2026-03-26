"""
Tshark ARP CSV ingestion adapter.

Reads tshark ARP field exports (tab-separated) and produces PacketRecords
with ARP-specific extra fields. ARP packets create edges between the
source IP and destination IP, with MAC addresses preserved for the
network_map plugin.

Expected tshark export command:
  tshark -r capture.pcap -Y arp -T fields \
    -e frame.number -e frame.time_epoch \
    -e arp.hw.type -e arp.proto.type -e arp.hw.size -e arp.proto.size \
    -e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4 \
    -e arp.dst.hw_mac -e arp.dst.proto_ipv4 > arp.csv

Header fields (tab-separated):
  frameNumber, ts, arp.hw.type, arpProtoType, arpHwSize, arpProtoSize,
  arpOpcode, arpSourceMac, arpSourceIp, arpDestMac, arpDestIp
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from parser.packet import PacketRecord
from .. import IngestionAdapter, register_adapter
from .common import parse_tshark_csv, safe_int, safe_float, is_tshark_csv

logger = logging.getLogger("swifteye.adapters.tshark_arp")

ARP_OPCODES = {
    1: "request",
    2: "reply",
    3: "RARP request",
    4: "RARP reply",
}


@register_adapter
class TsharkArpAdapter(IngestionAdapter):
    name = "tshark ARP CSV"
    file_extensions = [".csv"]
    granularity = "packet"
    source_type = "tshark"

    def can_handle(self, path: Path, header: bytes) -> bool:
        if path.suffix.lower() != ".csv":
            return False
        # ARP CSV has these distinctive field names
        return is_tshark_csv(header, "arpOpcode", "arpSourceMac", "arpSourceIp", "arpDestIp")

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
        logger.info("Parsed %d ARP packets from tshark CSV (%s)", len(packets), path.name)
        return packets

    def _row_to_packet(self, row: Dict[str, str]) -> Optional[PacketRecord]:
        src_ip = row.get("arpSourceIp", "")
        dst_ip = row.get("arpDestIp", "")
        # Skip non-routable IPs (ARP probes use 0.0.0.0, broadcasts use 255.255.255.255)
        _SKIP_IPS = ("", "0.0.0.0", "255.255.255.255")
        if src_ip in _SKIP_IPS or dst_ip in _SKIP_IPS:
            return None

        timestamp = safe_float(row.get("ts", "0"))
        if timestamp == 0:
            return None

        src_mac = row.get("arpSourceMac", "")
        dst_mac = row.get("arpDestMac", "")
        opcode = safe_int(row.get("arpOpcode", "0"))
        opcode_name = ARP_OPCODES.get(opcode, f"opcode_{opcode}")

        extra: Dict[str, Any] = {
            "source_type": "tshark",
            "arp_opcode": opcode,
            "arp_opcode_name": opcode_name,
        }

        if src_mac:
            extra["arp_src_mac"] = src_mac
            extra["src_mac"] = src_mac
        if dst_mac:
            extra["arp_dst_mac"] = dst_mac
            extra["dst_mac"] = dst_mac

        # Broadcast detection (00:00:00:00:00:00 or ff:ff:ff:ff:ff:ff)
        if dst_mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            extra["arp_broadcast"] = True

        pkt = PacketRecord(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=0,
            dst_port=0,
            transport="ARP",
            protocol="ARP",
            ip_version=4,
            src_mac=src_mac,
            dst_mac=dst_mac,
        )
        pkt.extra = extra

        return pkt
