"""
DCE/RPC dissector — extracts packet type, interface UUID, and service name
via payload fingerprinting. Works on any port (not just 135).

DCE/RPC (Distributed Computing Environment / Remote Procedure Call) is the
RPC mechanism used by Microsoft for most Windows services: Active Directory
replication (DRSUAPI), user management (SAMR), security policy (LSARPC),
service control (SVCCTL), remote registry, WMI, DCOM, and more.

The wire format has a fixed header starting with version bytes 05 00 (v5.0)
or 05 01 (v5.1, Windows extension). Byte 2 is the packet type. This is a
reliable payload signature that works on ephemeral ports without needing to
track the Endpoint Mapper conversation.

Bind and Bind-Ack packets contain the interface UUID which identifies the
specific RPC service. The UUID → service mapping is well-known.

Fields extracted:
  dcerpc_version        — "5.0" or "5.1"
  dcerpc_packet_type    — human name: "bind", "request", "response", etc.
  dcerpc_call_id        — call ID (uint32, correlates request/response)
  dcerpc_interface_uuid — interface UUID from bind context (hex string)
  dcerpc_interface_name — human service name if UUID is known
  dcerpc_opnum          — operation number from request packets
"""

from typing import Dict, Any
from . import register_dissector, register_payload_signature
import struct


# ── Packet types ──
_PACKET_TYPES = {
    0:  "request",
    1:  "ping",
    2:  "response",
    3:  "fault",
    4:  "working",
    5:  "nocall",
    6:  "reject",
    7:  "ack",
    8:  "cl_cancel",
    9:  "fack",
    10: "cancel_ack",
    11: "bind",
    12: "bind_ack",
    13: "bind_nak",
    14: "alter_context",
    15: "alter_context_resp",
    16: "auth3",
    17: "shutdown",
    18: "co_cancel",
    19: "orphaned",
}

# ── Well-known interface UUIDs → service names ──
# These are the UUIDs that identify which RPC service is being called.
# Format: lowercase hex without dashes, first 16 bytes of the UUID.
_INTERFACE_UUIDS = {
    "e1af8308-5d1f-11c9-91a4-08002b14a0fa": "EPM",              # Endpoint Mapper
    "12345778-1234-abcd-ef00-0123456789ab": "SAMR",             # Security Account Manager
    "12345778-1234-abcd-ef00-0123456789ac": "LSARPC",           # Local Security Authority
    "e3514235-4b06-11d1-ab04-00c04fc2dcd2": "DRSUAPI",          # Directory Replication
    "367abb81-9844-35f1-ad32-98f038001003": "SVCCTL",           # Service Control Manager
    "338cd001-2244-31f1-aaaa-900038001003": "WINREG",           # Remote Registry
    "4b324fc8-1670-01d3-1278-5a47bf6ee188": "SRVSVC",           # Server Service
    "6bffd098-a112-3610-9833-46c3f87e345a": "WKSSVC",           # Workstation Service
    "12345678-1234-abcd-ef00-01234567cffb": "NETLOGON",         # Netlogon
    "1ff70682-0a51-30e8-076d-740be8cee98b": "ATSVC",            # Task Scheduler (AT)
    "378e52b0-c0a9-11cf-822d-00aa0051e40f": "SASEC",            # Task Scheduler (SA)
    "86d35949-83c9-4044-b424-db363231fd0c": "ITaskScheduler",   # Task Scheduler (new)
    "3919286a-b10c-11d0-9ba8-00c04fd92ef5": "DSSETUP",          # DS Setup
    "ecec0d70-a603-11d0-96b1-00a0c91ece30": "DSROLE",           # DS Role
    "00000143-0000-0000-c000-000000000046": "DCOM/IRemUnknown", # DCOM
    "000001a0-0000-0000-c000-000000000046": "DCOM/IRemUnknown2",# DCOM v2
    "4d9f4ab8-7d1c-11cf-861e-0020af6e7c57": "DCOM/IActivation", # DCOM Activation
    "99fcfec4-5260-101b-bbcb-00aa0021347a": "DCOM/IOxidResolver",# DCOM OXID
    "d95afe70-a6d5-4259-822e-2c84da1ddb0d": "WMI",              # Windows Management
    "8bc3f05e-d86b-11d0-a075-00c04fb68820": "WMI/IWbemLevel1Login",
    "f6beaff7-1e19-4fbb-9f8f-b89e2018337c": "EventLog",        # Event Log (new)
    "82273fdc-e32a-18c3-3f78-827929dc23ea": "EventLog6",        # Event Log v6
    "894de0c0-0d55-11d3-a322-00c04fa321a1": "WinRM",            # Windows Remote Mgmt
    "6b5bdd1e-528c-422c-af8c-a4079be4fe48": "RemoteFW",         # Remote Firewall
    "50abc2a4-574d-40b3-9d66-ee4fd5fba076": "DNS",              # DNS Server
    "6bffd098-a112-3610-9833-012892020162": "BROWSER",           # Browser
    "afa8bd80-7d8a-11c9-bef4-08002b102989": "MGMT",             # RPC Management
    "4fc742e0-4a10-11cf-8273-00aa004ae673": "DFSNM",            # DFS Namespace
    "f5cc5a18-4264-101a-8c59-08002b2f8426": "FRSRPC",           # File Replication
    "d049b186-814f-11d1-9a3c-00c04fc9b232": "NtFrs",            # NT File Replication
    "c681d488-d850-11d0-8c52-00c04fd90f7e": "EFSRPC",           # Encrypting File System
    "c9378ff1-16f7-11d0-a0b2-00aa0061426a": "PRINTERRPC",       # Print System
    "76f03f96-cdfd-44fc-a22c-64950a001209": "PRINTERRPC2",      # Print System v2
    "12a81514-4b9e-11df-a8f8-005056c00008": "FSRVP",            # File Server Shadow Copy
}


def _uuid_from_bytes(data: bytes) -> str:
    """Parse a DCE/RPC UUID from 16 bytes (little-endian mixed format)."""
    if len(data) < 16:
        return ""
    # DCE/RPC UUIDs are mixed-endian:
    #   time_low (4 bytes LE), time_mid (2 bytes LE), time_hi (2 bytes LE),
    #   clock_seq (2 bytes BE), node (6 bytes BE)
    a = struct.unpack_from("<IHH", data, 0)
    b = data[8:10]
    c = data[10:16]
    return f"{a[0]:08x}-{a[1]:04x}-{a[2]:04x}-{b[0]:02x}{b[1]:02x}-{c[0]:02x}{c[1]:02x}{c[2]:02x}{c[3]:02x}{c[4]:02x}{c[5]:02x}"


@register_payload_signature("DCE/RPC", priority=12)
def _detect_dcerpc(payload: bytes) -> bool:
    """DCE/RPC: version 5.x, valid packet type."""
    if len(payload) < 16:
        return False
    # Version major = 5, minor = 0 or 1
    if payload[0] != 0x05 or payload[1] not in (0x00, 0x01):
        return False
    # Packet type must be in valid range
    ptype = payload[2]
    if ptype > 19:
        return False
    # Byte order: byte 4 bits indicate endianness (0x10 = LE)
    # Frag length (bytes 8-9) should be reasonable
    drep = payload[4]
    if drep & 0x10:  # little-endian
        frag_len = struct.unpack_from("<H", payload, 8)[0]
    else:
        frag_len = struct.unpack_from(">H", payload, 8)[0]
    # Frag length should be at least 16 (header) and not absurdly large
    if frag_len < 16 or frag_len > 65535:
        return False
    return True


@register_dissector("DCE/RPC")
def dissect_dcerpc(pkt) -> Dict[str, Any]:
    if pkt.haslayer("Raw"):
        return _extract(bytes(pkt["Raw"].load))
    return {}


def _extract(payload: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        if len(payload) < 16:
            return info

        if payload[0] != 0x05 or payload[1] not in (0x00, 0x01):
            return info

        version = f"5.{payload[1]}"
        ptype = payload[2]
        ptype_name = _PACKET_TYPES.get(ptype, f"type_{ptype}")
        drep = payload[4]
        little_endian = bool(drep & 0x10)

        info["dcerpc_version"] = version
        info["dcerpc_packet_type"] = ptype_name

        # Call ID at offset 12 (4 bytes)
        if len(payload) >= 16:
            if little_endian:
                call_id = struct.unpack_from("<I", payload, 12)[0]
            else:
                call_id = struct.unpack_from(">I", payload, 12)[0]
            info["dcerpc_call_id"] = call_id

        # ── Bind (type 11): extract interface UUID ──
        if ptype == 11 and len(payload) >= 60:
            # Bind header: 16 bytes common header
            # + 2 bytes max_xmit_frag, 2 bytes max_recv_frag, 4 bytes assoc_group
            # + context list: 1 byte num_ctx_items, 3 bytes padding
            # + per context: 2 bytes context_id, 1 byte num_transfer_syntaxes, 1 pad
            # + 16 bytes abstract_syntax UUID + 4 bytes version
            offset = 24  # skip common header (16) + bind fields (8)
            if offset + 4 <= len(payload):
                num_ctx = payload[offset]
                # First context item starts at offset + 4
                ctx_offset = offset + 4
                if num_ctx >= 1 and ctx_offset + 20 <= len(payload):
                    # Skip context_id (2) + num_transfer_syntaxes (1) + pad (1)
                    uuid_offset = ctx_offset + 4
                    if uuid_offset + 16 <= len(payload):
                        uuid_str = _uuid_from_bytes(payload[uuid_offset:uuid_offset + 16])
                        info["dcerpc_interface_uuid"] = uuid_str
                        svc = _INTERFACE_UUIDS.get(uuid_str, "")
                        if svc:
                            info["dcerpc_interface_name"] = svc

        # ── Bind-Ack (type 12): also has context results, but the UUID
        #    is from the corresponding bind. We just note it's a bind_ack.

        # ── Request (type 0): extract opnum ──
        if ptype == 0 and len(payload) >= 24:
            # Request header: common (16) + alloc_hint (4) + context_id (2) + opnum (2)
            if little_endian:
                opnum = struct.unpack_from("<H", payload, 22)[0]
            else:
                opnum = struct.unpack_from(">H", payload, 22)[0]
            info["dcerpc_opnum"] = opnum

        # ── Response (type 2): extract status from fault if present ──
        # (faults have a status code at offset 24)

    except Exception:
        pass
    return info
