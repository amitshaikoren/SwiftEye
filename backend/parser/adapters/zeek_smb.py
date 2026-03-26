"""
Zeek SMB log ingestion adapter.

Handles two Zeek SMB log types:
  - smb_files.log  — file access operations (open, read, write, delete, rename)
  - smb_mapping.log — share tree connects (path, service, share_type)

Both produce PacketRecords with SMB-specific extra fields that the
smb protocol_fields module already accumulates (smb_command, smb_version,
smb_tree_path, smb_filename).

Standard Zeek smb_files.log fields:
  ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
  fuid, action, path, name, size,
  times.modified, times.accessed, times.created, times.changed

Standard Zeek smb_mapping.log fields:
  ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
  path, service, native_file_system, share_type
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from parser.packet import PacketRecord
from . import IngestionAdapter, register_adapter
from .zeek_common import parse_zeek_log, safe_int, safe_float, is_zeek_log

logger = logging.getLogger("swifteye.adapters.zeek_smb")


@register_adapter
class ZeekSmbFilesAdapter(IngestionAdapter):
    name = "Zeek smb_files.log"
    file_extensions = [".log"]
    granularity = "session"
    source_type = "zeek"

    def can_handle(self, path: Path, header: bytes) -> bool:
        if path.suffix.lower() != ".log":
            return False
        # smb_files.log has "fuid" (file UID) and "action" fields
        return is_zeek_log(header, "fuid") and is_zeek_log(header, "action")

    def parse(self, path: Path, **opts) -> List[PacketRecord]:
        rows = parse_zeek_log(path)
        if not rows:
            logger.warning("No data rows in %s", path.name)
            return []

        packets = []
        for row in rows:
            pkt = self._row_to_packet(row)
            if pkt:
                packets.append(pkt)

        packets.sort(key=lambda p: p.timestamp)
        logger.info("Parsed %d SMB file operations from Zeek smb_files.log (%s)", len(packets), path.name)
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

        # Action = SMB file operation (SMB::FILE_OPEN, SMB::FILE_READ, etc.)
        action = row.get("action", "-")
        if action and action != "-":
            # Zeek prefixes with "SMB::" — strip for cleaner display
            cmd = action.replace("SMB::", "").replace("FILE_", "")
            extra["smb_command"] = cmd

        # Path = share path (e.g. \\server\share\subdir)
        smb_path = row.get("path", "-")
        if smb_path and smb_path != "-":
            extra["smb_tree_path"] = smb_path

        # Name = filename within the share
        name = row.get("name", "-")
        if name and name != "-":
            extra["smb_filename"] = name

        # File size
        size = row.get("size", "-")
        if size and size != "-":
            extra["smb_file_size"] = safe_int(size)

        # File timestamps (Zeek provides these as epoch floats)
        for zeek_field, extra_key in [
            ("times.modified", "smb_file_modified"),
            ("times.accessed", "smb_file_accessed"),
            ("times.created", "smb_file_created"),
        ]:
            val = row.get(zeek_field, "-")
            if val and val != "-":
                extra[extra_key] = safe_float(val)

        # Zeek UID
        uid = row.get("uid", "")
        if uid and uid != "-":
            extra["uid"] = uid

        # SMB version — Zeek doesn't put version in smb_files.log,
        # but we know it's SMBv2+ if the log exists (Zeek's SMB analyzer)
        extra["smb_version"] = "SMBv2+"

        pkt = PacketRecord(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            transport="TCP",
            protocol="SMB",
            ip_version=ip_version,
        )
        pkt.extra = extra

        return pkt


@register_adapter
class ZeekSmbMappingAdapter(IngestionAdapter):
    name = "Zeek smb_mapping.log"
    file_extensions = [".log"]
    granularity = "session"
    source_type = "zeek"

    def can_handle(self, path: Path, header: bytes) -> bool:
        if path.suffix.lower() != ".log":
            return False
        # smb_mapping.log has "share_type" and "native_file_system"
        return is_zeek_log(header, "share_type") and is_zeek_log(header, "native_file_system")

    def parse(self, path: Path, **opts) -> List[PacketRecord]:
        rows = parse_zeek_log(path)
        if not rows:
            logger.warning("No data rows in %s", path.name)
            return []

        packets = []
        for row in rows:
            pkt = self._row_to_packet(row)
            if pkt:
                packets.append(pkt)

        packets.sort(key=lambda p: p.timestamp)
        logger.info("Parsed %d SMB tree connects from Zeek smb_mapping.log (%s)", len(packets), path.name)
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

        # Path = share UNC path (e.g. \\10.0.0.1\IPC$)
        smb_path = row.get("path", "-")
        if smb_path and smb_path != "-":
            extra["smb_tree_path"] = smb_path

        # Service type (e.g. IPC, DISK, PRINTER)
        service = row.get("service", "-")
        if service and service != "-":
            extra["smb_service"] = service

        # Share type (e.g. DISK, PIPE, PRINT)
        share_type = row.get("share_type", "-")
        if share_type and share_type != "-":
            extra["smb_share_type"] = share_type

        # Native file system (e.g. NTFS)
        native_fs = row.get("native_file_system", "-")
        if native_fs and native_fs != "-":
            extra["smb_native_fs"] = native_fs

        # The operation is a TREE_CONNECT
        extra["smb_command"] = "TREE_CONNECT"

        # SMB version
        extra["smb_version"] = "SMBv2+"

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
            protocol="SMB",
            ip_version=ip_version,
        )
        pkt.extra = extra

        return pkt
