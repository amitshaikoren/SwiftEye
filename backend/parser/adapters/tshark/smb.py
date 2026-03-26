"""
Tshark SMB CSV ingestion adapter.

Reads smb.csv and joins with metadata.csv by frameNumber to get the 5-tuple.

smb.csv fields:
  frameNumber, ts, smbCmd, smbStatus, smbFlags, smb1Flags2, smbSignature,
  smbReserved, smbTid, smbPid, smb1Uid, smbVersion, smb2Sesid, smbCmdName
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

logger = logging.getLogger("swifteye.adapters.tshark_smb")


@register_adapter
class TsharkSmbAdapter(IngestionAdapter):
    name = "tshark SMB CSV"
    file_extensions = [".csv"]
    granularity = "packet"
    source_type = "tshark"

    def can_handle(self, path: Path, header: bytes) -> bool:
        if path.suffix.lower() != ".csv":
            return False
        return is_tshark_csv(header, "smbCmd", "smbStatus", "smbCmdName", "smbVersion")

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
        logger.info("Parsed %d SMB packets from %s (skipped %d)", len(packets), path.name, skipped)
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

        cmd_name = row.get("smbCmdName", "")
        cmd_hex = row.get("smbCmd", "")
        status = row.get("smbStatus", "")
        version = safe_int(row.get("smbVersion", "0"))
        tid = safe_int(row.get("smbTid", "0"))
        flags = row.get("smbFlags", "")

        extra: Dict[str, Any] = {
            "source_type": "tshark",
            "smb_command": cmd_name,
            "smb_cmd_hex": cmd_hex,
            "smb_version": version,
        }
        if status and status != "0x00000000":
            extra["smb_status"] = status
        if tid:
            extra["smb_tid"] = tid
        if flags:
            extra["smb_flags"] = flags

        pkt = PacketRecord(
            timestamp=timestamp,
            src_ip=net["src_ip"],
            dst_ip=net["dst_ip"],
            src_port=net["src_port"],
            dst_port=net["dst_port"],
            src_mac=net["src_mac"],
            dst_mac=net["dst_mac"],
            transport=net["transport"],
            protocol="SMB",
            ip_version=4,
            ttl=net["ttl"],
            ip_proto=net["ip_proto"],
        )
        pkt.extra = extra
        return pkt
