"""
Tshark DCE/RPC CSV ingestion adapter.

Reads dce_rpc.csv and joins with metadata.csv by frameNumber to get the 5-tuple.

dce_rpc.csv fields:
  frameNumber, ts, endpoint, operation
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from parser.packet import PacketRecord
from .. import IngestionAdapter, register_adapter
from .common import (
    parse_tshark_csv, safe_int, safe_float, is_tshark_csv,
    load_metadata_index, meta_to_network,
)

logger = logging.getLogger("swifteye.adapters.tshark_dcerpc")

# Well-known DCE/RPC endpoint names → interface UUIDs
# Same mapping as the Zeek DCE/RPC adapter
ENDPOINT_UUIDS = {
    "EPM":      "e1af8308-5d1f-11c9-91a4-08002b14a0fa",
    "DRSUAPI":  "e3514235-4b06-11d1-ab04-00c04fc2dcd2",
    "SAMR":     "12345778-1234-abcd-ef00-0123456789ac",
    "LSARPC":   "12345778-1234-abcd-ef00-0123456789ab",
    "NETLOGON": "12345678-1234-abcd-ef00-01234567cffb",
    "SVCCTL":   "367abb81-9844-35f1-ad32-98f038001003",
    "WINREG":   "338cd001-2244-31f1-aaaa-900038001003",
    "SRVSVC":   "4b324fc8-1670-01d3-1278-5a47bf6ee188",
    "WKSSVC":   "6bffd098-a112-3610-9833-46c3f87e345a",
    "ATSVC":    "1ff70682-0a51-30e8-076d-740be8cee98b",
    "IRemoteWinspool": "76f03f96-cdfd-44fc-a22c-64950a001209",
    "SPOOLSS":  "12345678-1234-abcd-ef00-0123456789ab",
}


@register_adapter
class TsharkDceRpcAdapter(IngestionAdapter):
    name = "tshark DCE/RPC CSV"
    file_extensions = [".csv"]
    granularity = "packet"
    source_type = "tshark"

    def can_handle(self, path: Path, header: bytes) -> bool:
        if path.suffix.lower() != ".csv":
            return False
        # dce_rpc.csv has exactly: frameNumber, ts, endpoint, operation
        return is_tshark_csv(header, "endpoint", "operation") and \
               not is_tshark_csv(header, "smbCmd")  # exclude smb.csv

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
        logger.info("Parsed %d DCE/RPC packets from %s (skipped %d)", len(packets), path.name, skipped)
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

        endpoint = row.get("endpoint", "")
        operation = row.get("operation", "")
        opnum = safe_int(operation) if operation.isdigit() else 0

        extra: Dict[str, Any] = {
            "source_type": "tshark",
            "dcerpc_interface_name": endpoint,
            "dcerpc_opnum": opnum,
            "dcerpc_packet_type": "request",
        }

        # Resolve UUID from endpoint name
        uuid = ENDPOINT_UUIDS.get(endpoint, "")
        if uuid:
            extra["dcerpc_interface_uuid"] = uuid

        pkt = PacketRecord(
            timestamp=timestamp,
            src_ip=net["src_ip"],
            dst_ip=net["dst_ip"],
            src_port=net["src_port"],
            dst_port=net["dst_port"],
            src_mac=net["src_mac"],
            dst_mac=net["dst_mac"],
            transport=net["transport"],
            protocol="DCE/RPC",
            ip_version=4,
            ttl=net["ttl"],
            ip_proto=net["ip_proto"],
        )
        pkt.extra = extra
        return pkt
