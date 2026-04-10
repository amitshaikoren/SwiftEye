"""
Zeek dce_rpc.log ingestion adapter.

Reads Zeek DCE/RPC logs and produces PacketRecords with DCE/RPC-specific
extra fields that the dcerpc protocol_fields module already accumulates
(dcerpc_packet_type, dcerpc_interface_uuid, dcerpc_interface_name, dcerpc_opnum).

Each dce_rpc.log row represents one RPC operation.  The packet's src_ip
is id.orig_h (the client/initiator).

Standard Zeek dce_rpc.log fields:
  ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
  rtt, named_pipe, endpoint, operation
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from parser.packet import PacketRecord
from parser.schema.contracts import SchemaField
from .. import IngestionAdapter, register_adapter
from .common import parse_zeek_log, get_zeek_columns, safe_int, safe_float, is_zeek_log

logger = logging.getLogger("swifteye.adapters.zeek_dce_rpc")

# Map well-known Zeek endpoint names to interface UUIDs.
# Zeek resolves these from the IDL interface UUID in the bind packet,
# so we reverse-map for compatibility with the pcap dissector's output.
ENDPOINT_TO_UUID = {
    "drsuapi":   "e3514235-4b06-11d1-ab04-00c04fc2dcd2",
    "samr":      "12345778-1234-abcd-ef00-0123456789ac",
    "lsarpc":    "12345778-1234-abcd-ef00-0123456789ab",
    "netlogon":  "12345678-1234-abcd-ef00-01234567cffb",
    "svcctl":    "367abb81-9844-35f1-ad32-98f038001003",
    "winreg":    "338cd001-2244-31f1-aaaa-900038001003",
    "srvsvc":    "4b324fc8-1670-01d3-1278-5a47bf6ee188",
    "wkssvc":    "6bffd098-a112-3610-9833-46c3f87e345a",
    "atsvc":     "1ff70682-0a51-30e8-076d-740be8cee98b",
    "epm":       "e1af8308-5d1f-11c9-91a4-08002b14a0fa",
    "spoolss":   "12345678-1234-abcd-ef00-0123456789ab",
    "IRemoteWinspool": "76f03f96-cdfd-44fc-a22c-64950a001209",
}


@register_adapter
class ZeekDceRpcAdapter(IngestionAdapter):
    name = "Zeek dce_rpc.log"
    file_extensions = [".log"]
    granularity = "session"
    source_type = "zeek"

    declared_fields = [
        SchemaField("ts",         required=True,  description="Operation timestamp"),
        SchemaField("id.orig_h",  required=True,  description="Client IP"),
        SchemaField("id.orig_p",  required=True,  description="Client port"),
        SchemaField("id.resp_h",  required=True,  description="Server IP"),
        SchemaField("id.resp_p",  required=True,  description="Server port"),
        SchemaField("named_pipe", required=False, description="Named pipe used"),
        SchemaField("endpoint",   required=False, description="RPC endpoint/interface name"),
        SchemaField("operation",  required=False, description="RPC operation name"),
        SchemaField("rtt",        required=False, description="Round-trip time"),
        SchemaField("uid",        required=False, description="Connection UID"),
    ]

    def can_handle(self, path: Path, header: bytes) -> bool:
        if path.suffix.lower() != ".log":
            return False
        return is_zeek_log(header, "endpoint") and is_zeek_log(header, "named_pipe")

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
        logger.info("Parsed %d DCE/RPC operations from Zeek dce_rpc.log", len(packets))
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

        # Endpoint = the RPC interface name (Zeek resolves from UUID)
        endpoint = row.get("endpoint", "-")
        if endpoint and endpoint != "-":
            extra["dcerpc_interface_name"] = endpoint
            # Reverse-map to UUID for compatibility with pcap dissector
            uuid = ENDPOINT_TO_UUID.get(endpoint.lower(), "")
            if uuid:
                extra["dcerpc_interface_uuid"] = uuid

        # Operation = the RPC function name
        operation = row.get("operation", "-")
        if operation and operation != "-":
            extra["dcerpc_operation"] = operation
            # Zeek doesn't give numeric opnum directly, but the operation
            # name is more useful.  Set packet_type to "request" since
            # Zeek logs represent completed RPCs.
            extra["dcerpc_packet_type"] = "request"

        # Named pipe (e.g. \pipe\samr, \pipe\lsarpc)
        named_pipe = row.get("named_pipe", "-")
        if named_pipe and named_pipe != "-":
            extra["dcerpc_named_pipe"] = named_pipe

        # RTT (round-trip time of the RPC call)
        rtt = row.get("rtt", "-")
        if rtt and rtt != "-":
            extra["dcerpc_rtt"] = safe_float(rtt)

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
            protocol="DCE/RPC",
            ip_version=ip_version,
        )
        pkt.extra = extra

        return pkt
