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

from workspaces.network.parser.packet import PacketRecord
from workspaces.network.parser.schema.contracts import SchemaField
from .. import IngestionAdapter, register_adapter
from .common import parse_zeek_log, get_zeek_columns, safe_int, safe_float, is_zeek_log

logger = logging.getLogger("swifteye.adapters.zeek_smb")


@register_adapter
class ZeekSmbFilesAdapter(IngestionAdapter):
    name = "Zeek smb_files.log"
    file_extensions = [".log"]
    granularity = "session"
    source_type = "zeek"

    declared_fields = [
        SchemaField("ts",           required=True,  description="Operation timestamp"),
        SchemaField("id.orig_h",    required=True,  description="Client IP"),
        SchemaField("id.orig_p",    required=True,  description="Client port"),
        SchemaField("id.resp_h",    required=True,  description="Server IP"),
        SchemaField("id.resp_p",    required=True,  description="Server port"),
        SchemaField("fuid",         required=False, description="File UID"),
        SchemaField("action",       required=False, description="SMB file action (SMB::FILE_OPEN, …)"),
        SchemaField("path",         required=False, description="Share UNC path"),
        SchemaField("name",         required=False, description="Filename within share"),
        SchemaField("size",         required=False, description="File size in bytes"),
        SchemaField("uid",          required=False, description="Connection UID"),
    ]

    def can_handle(self, path: Path, header: bytes) -> bool:
        if path.suffix.lower() != ".log":
            return False
        return is_zeek_log(header, "fuid") and is_zeek_log(header, "action")

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
        logger.info("Parsed %d SMB file operations from Zeek smb_files.log", len(packets))
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

    declared_fields = [
        SchemaField("ts",                  required=True,  description="Connection timestamp"),
        SchemaField("id.orig_h",           required=True,  description="Client IP"),
        SchemaField("id.orig_p",           required=True,  description="Client port"),
        SchemaField("id.resp_h",           required=True,  description="Server IP"),
        SchemaField("id.resp_p",           required=True,  description="Server port"),
        SchemaField("path",                required=False, description="Share UNC path"),
        SchemaField("service",             required=False, description="Share service type"),
        SchemaField("share_type",          required=False, description="Share type (DISK, PIPE, PRINT)"),
        SchemaField("native_file_system",  required=False, description="Native filesystem (NTFS, …)"),
        SchemaField("uid",                 required=False, description="Connection UID"),
    ]

    def can_handle(self, path: Path, header: bytes) -> bool:
        if path.suffix.lower() != ".log":
            return False
        return is_zeek_log(header, "share_type") and is_zeek_log(header, "native_file_system")

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
        logger.info("Parsed %d SMB tree connects from Zeek smb_mapping.log", len(packets))
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
