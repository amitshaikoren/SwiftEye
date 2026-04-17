"""
SMB dissector — extracts version, command, status, tree paths, and filenames.

SMB (Server Message Block) runs on TCP 445 (direct) or 139 (NetBIOS).
SMBv1, SMBv2, and SMBv3 all share the same port but have different magic bytes:

  SMBv1: \xffSMB  (0xFF 0x53 0x4D 0x42)
  SMBv2: \xfeSMB  (0xFE 0x53 0x4D 0x42)  — also SMBv3

SMBv1 commands (single byte):
  0x72 NEGOTIATE, 0x73 SESSION_SETUP, 0x75 TREE_CONNECT
  0x2f TREE_DISCONNECT, 0x04 CLOSE, 0x25 TRANS2, 0xa2 NT_CREATE
  0x2e READ, 0x2f WRITE, etc.

SMBv2 commands (uint16):
  0x0000 NEGOTIATE, 0x0001 SESSION_SETUP, 0x0002 LOGOFF
  0x0003 TREE_CONNECT, 0x0004 TREE_DISCONNECT, 0x0005 CREATE
  0x0006 CLOSE, 0x0008 READ, 0x0009 WRITE, 0x000e IOCTL
  0x000f QUERY_DIRECTORY, 0x0011 QUERY_INFO, 0x0012 SET_INFO
  0x0013 CHANGE_NOTIFY, etc.

Fields extracted:
  smb_version       — "SMBv1", "SMBv2", "SMBv3" (v3 detected by SMBv2 dialect 0x0311)
  smb_command       — command name (NEGOTIATE, SESSION_SETUP, etc.)
  smb_status        — NT status code (0 = success)
  smb_status_name   — human-readable status ("STATUS_SUCCESS", "STATUS_ACCESS_DENIED", etc.)
  smb_tree_path     — tree connect path (\\\\server\\share format)
  smb_filename      — CREATE/OPEN filename
  smb_dialect       — highest negotiated dialect (for SMBv2 NEGOTIATE response)
  smb_is_request    — True if this is a request packet
"""

from typing import Dict, Any
import struct
from . import register_dissector, register_payload_signature


_SMB1_COMMANDS = {
    0x04: "CLOSE", 0x06: "DELETE", 0x08: "RENAME", 0x09: "QUERY_INFO",
    0x0a: "SET_INFO", 0x0b: "LOCK_BYTE_RANGE", 0x24: "TRANS",
    0x25: "TRANS2", 0x2e: "READ", 0x2f: "WRITE", 0x32: "TRANS2",
    0x50: "CHECK_DIR", 0x70: "TREE_CONNECT", 0x71: "TREE_DISCONNECT",
    0x72: "NEGOTIATE", 0x73: "SESSION_SETUP", 0x74: "LOGOFF",
    0x75: "TREE_CONNECT_ANDX", 0x76: "DISCONNECT", 0xa2: "NT_CREATE",
    0xa4: "NT_CANCEL", 0xb2: "OPEN2", 0xd0: "OPEN_PRINT_FILE",
}

_SMB2_COMMANDS = {
    0x0000: "NEGOTIATE", 0x0001: "SESSION_SETUP", 0x0002: "LOGOFF",
    0x0003: "TREE_CONNECT", 0x0004: "TREE_DISCONNECT", 0x0005: "CREATE",
    0x0006: "CLOSE", 0x0007: "FLUSH", 0x0008: "READ", 0x0009: "WRITE",
    0x000a: "LOCK", 0x000b: "IOCTL", 0x000c: "CANCEL", 0x000d: "ECHO",
    0x000e: "QUERY_DIRECTORY", 0x000f: "CHANGE_NOTIFY", 0x0010: "QUERY_INFO",
    0x0011: "SET_INFO", 0x0012: "OPLOCK_BREAK",
}

_NT_STATUS = {
    0x00000000: "SUCCESS",
    0xC0000001: "UNSUCCESSFUL",
    0xC0000022: "ACCESS_DENIED",
    0xC0000034: "OBJECT_NAME_NOT_FOUND",
    0xC0000035: "OBJECT_NAME_COLLISION",
    0xC000006D: "LOGON_FAILURE",
    0xC000006E: "ACCOUNT_RESTRICTION",
    0xC0000064: "NO_SUCH_USER",
    0xC000006C: "PASSWORD_EXPIRED",
    0xC0000073: "NONE_MAPPED",
    0xC0000101: "NOT_EMPTY",
    0xC0000103: "NO_MORE_FILES",
    0xC000000D: "INVALID_PARAMETER",
    0xC00000BB: "NOT_SUPPORTED",
    0x00000103: "PENDING",
    0x00000105: "MORE_PROCESSING_REQUIRED",
}

_SMB1_MAGIC = b"\xffSMB"
_SMB2_MAGIC = b"\xfeSMB"


@register_payload_signature("SMB", priority=15)
def _detect_smb(payload: bytes) -> bool:
    # SMB can arrive with a 4-byte NetBIOS session header
    if len(payload) < 8:
        return False
    if payload[4:8] in (_SMB1_MAGIC, _SMB2_MAGIC):
        return True
    if payload[:4] in (_SMB1_MAGIC, _SMB2_MAGIC):
        return True
    return False


@register_dissector("SMB")
def dissect_smb(pkt) -> Dict[str, Any]:
    if pkt.haslayer("Raw"):
        return _extract(bytes(pkt["Raw"].load))
    return {}


def _extract(payload: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        # Strip optional 4-byte NetBIOS session header
        off = 0
        if len(payload) < 4:
            return info
        if payload[4:8] in (_SMB1_MAGIC, _SMB2_MAGIC):
            off = 4
        elif payload[:4] in (_SMB1_MAGIC, _SMB2_MAGIC):
            off = 0
        else:
            return info

        magic = payload[off:off + 4]

        if magic == _SMB2_MAGIC:
            _extract_smb2(payload, off, info)
        elif magic == _SMB1_MAGIC:
            _extract_smb1(payload, off, info)

    except Exception:
        pass
    return info


def _extract_smb1(payload: bytes, off: int, info: Dict[str, Any]):
    # SMBv1 header: magic(4) command(1) status(4) flags(1) flags2(2) ...
    if off + 32 > len(payload):
        return
    info["smb_version"] = "SMBv1"
    cmd = payload[off + 4]
    info["smb_command"] = _SMB1_COMMANDS.get(cmd, f"CMD_0x{cmd:02x}")
    status = struct.unpack_from("<I", payload, off + 5)[0]
    info["smb_status"] = status
    if status in _NT_STATUS:
        info["smb_status_name"] = "STATUS_" + _NT_STATUS[status]
    flags = payload[off + 9]
    info["smb_is_request"] = not bool(flags & 0x80)


def _extract_smb2(payload: bytes, off: int, info: Dict[str, Any]):
    # SMBv2 header: magic(4) structSize(2) creditCharge(2) status(4)
    #   command(2) credits(2) flags(4) nextCommand(4) messageId(8)
    #   processId(4) treeId(4) sessionId(8) signature(16) = 64 bytes total
    if off + 64 > len(payload):
        return

    struct_size = struct.unpack_from("<H", payload, off + 4)[0]
    status  = struct.unpack_from("<I", payload, off + 8)[0]
    command = struct.unpack_from("<H", payload, off + 12)[0]
    flags   = struct.unpack_from("<I", payload, off + 16)[0]

    is_response = bool(flags & 0x00000001)
    info["smb_is_request"] = not is_response
    info["smb_status"] = status
    info["smb_command"] = _SMB2_COMMANDS.get(command, f"CMD_0x{command:04x}")
    if status in _NT_STATUS:
        info["smb_status_name"] = "STATUS_" + _NT_STATUS[status]

    body_off = off + 64

    # Detect SMBv3 via dialect in NEGOTIATE response
    if command == 0x0000 and is_response and body_off + 6 <= len(payload):
        dialect = struct.unpack_from("<H", payload, body_off + 4)[0]
        if dialect == 0x0311:
            info["smb_version"] = "SMBv3"
            info["smb_dialect"] = "3.1.1"
        elif dialect == 0x0300:
            info["smb_version"] = "SMBv3"
            info["smb_dialect"] = "3.0"
        elif dialect == 0x0210:
            info["smb_version"] = "SMBv2"
            info["smb_dialect"] = "2.1"
        elif dialect == 0x0202:
            info["smb_version"] = "SMBv2"
            info["smb_dialect"] = "2.0.2"
        else:
            info["smb_version"] = "SMBv2"
            info["smb_dialect"] = f"0x{dialect:04x}"
    else:
        info["smb_version"] = "SMBv2"

    # TREE_CONNECT request: extract share path
    if command == 0x0003 and not is_response and body_off + 8 <= len(payload):
        try:
            path_offset = struct.unpack_from("<H", payload, body_off + 4)[0]
            path_length = struct.unpack_from("<H", payload, body_off + 6)[0]
            abs_off = off + path_offset
            if abs_off + path_length <= len(payload):
                path = payload[abs_off:abs_off + path_length].decode("utf-16-le", errors="replace")
                info["smb_tree_path"] = path
        except Exception:
            pass

    # CREATE request: extract filename
    if command == 0x0005 and not is_response and body_off + 56 <= len(payload):
        try:
            name_offset = struct.unpack_from("<H", payload, body_off + 44)[0]
            name_length = struct.unpack_from("<H", payload, body_off + 46)[0]
            abs_off = off + name_offset
            if name_length > 0 and abs_off + name_length <= len(payload):
                filename = payload[abs_off:abs_off + name_length].decode("utf-16-le", errors="replace")
                info["smb_filename"] = filename
        except Exception:
            pass
