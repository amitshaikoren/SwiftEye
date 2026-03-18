"""
DHCP dissector — extracts hostname, vendor class, message type, and IP addresses.

DHCP runs on UDP 67/68. It's one of the richest sources of device fingerprinting
data in a capture:

  Option 12 (Hostname)          — device hostname as configured
  Option 50 (Requested IP)      — IP the client wants (renewal hint)
  Option 53 (Message Type)      — DISCOVER/OFFER/REQUEST/ACK/NAK/RELEASE/INFORM
  Option 55 (Parameter Request) — which options the client is requesting (OS fingerprint)
  Option 60 (Vendor Class ID)   — vendor/OS string ("MSFT 5.0", "dhcpcd-5.5.6", etc.)
  Option 61 (Client ID)         — hardware type + MAC
  Option 67 (Bootfile)          — PXE boot file path
  Option 15 (Domain Name)       — domain the client belongs to

Fields extracted:
  dhcp_msg_type       — human-readable message type (DISCOVER, OFFER, etc.)
  dhcp_hostname       — Option 12 hostname
  dhcp_vendor_class   — Option 60 vendor class string
  dhcp_requested_ip   — Option 50 requested IP
  dhcp_server_ip      — siaddr field (next server IP)
  dhcp_client_ip      — ciaddr field (client IP during renewal)
  dhcp_param_list     — Option 55 parameter request list (list of ints, for OS fingerprinting)
  dhcp_domain         — Option 15 domain name
  dhcp_bootfile       — Option 67 boot file name
"""

from typing import Dict, Any
import struct
from . import register_dissector, register_payload_signature


_DHCP_MSG_TYPES = {
    1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
    5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM",
}

# DHCP magic cookie
_MAGIC = b"\x63\x82\x53\x63"


@register_payload_signature("DHCP", priority=18)
def _detect_dhcp(payload: bytes) -> bool:
    """DHCP: UDP payload starts with BOOTP op byte 1 or 2, and has magic cookie at offset 236."""
    if len(payload) < 240:
        return False
    if payload[0] not in (1, 2):
        return False
    return payload[236:240] == _MAGIC


@register_dissector("DHCP")
def dissect_dhcp(pkt) -> Dict[str, Any]:
    if pkt.haslayer("Raw"):
        return _extract(bytes(pkt["Raw"].load))
    return {}


def _extract(payload: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        if len(payload) < 240 or payload[236:240] != _MAGIC:
            return info

        # Fixed fields
        # op=1 client→server, op=2 server→client
        # ciaddr=12, yiaddr=16, siaddr=20, giaddr=24, chaddr=28
        ciaddr = payload[12:16]
        yiaddr = payload[16:20]
        siaddr = payload[20:24]

        if ciaddr != b"\x00\x00\x00\x00":
            info["dhcp_client_ip"] = ".".join(str(b) for b in ciaddr)
        if yiaddr != b"\x00\x00\x00\x00":
            info["dhcp_offered_ip"] = ".".join(str(b) for b in yiaddr)
        if siaddr != b"\x00\x00\x00\x00":
            info["dhcp_server_ip"] = ".".join(str(b) for b in siaddr)

        # Parse options
        options_seen = []
        off = 240
        while off + 1 < len(payload):
            opt = payload[off]
            if opt == 255:  # END
                break
            if opt == 0:    # PAD
                off += 1
                continue
            if off + 2 > len(payload):
                break
            length = payload[off + 1]
            val = payload[off + 2: off + 2 + length]
            off += 2 + length
            options_seen.append(opt)

            if opt == 53 and length == 1:  # Message Type
                info["dhcp_msg_type"] = _DHCP_MSG_TYPES.get(val[0], f"Type{val[0]}")
            elif opt == 12:  # Hostname
                info["dhcp_hostname"] = val.decode(errors="replace").strip()
            elif opt == 60:  # Vendor Class ID
                info["dhcp_vendor_class"] = val.decode(errors="replace").strip()
            elif opt == 50 and length == 4:  # Requested IP
                info["dhcp_requested_ip"] = ".".join(str(b) for b in val)
            elif opt == 55:  # Parameter Request List
                info["dhcp_param_list"] = list(val)
            elif opt == 15:  # Domain Name
                info["dhcp_domain"] = val.decode(errors="replace").strip()
            elif opt == 67:  # Bootfile Name
                info["dhcp_bootfile"] = val.decode(errors="replace").strip()
            elif opt == 51 and length == 4:  # Lease Time
                info["dhcp_lease_time"] = struct.unpack("!I", val)[0]
            elif opt == 54 and length == 4:  # Server Identifier
                info["dhcp_server_id"] = ".".join(str(b) for b in val)
            elif opt == 1 and length == 4:  # Subnet Mask
                info["dhcp_subnet_mask"] = ".".join(str(b) for b in val)
            elif opt == 3 and length >= 4:  # Router
                info["dhcp_router"] = ".".join(str(b) for b in val[:4])
            elif opt == 6 and length >= 4:  # DNS Servers
                dns_servers = []
                for i in range(0, min(length, 16), 4):
                    dns_servers.append(".".join(str(b) for b in val[i:i+4]))
                info["dhcp_dns_servers"] = dns_servers
            elif opt == 82 and length > 0:  # Relay Agent Information
                info["dhcp_relay_agent"] = val.hex()
            elif opt == 61 and length > 1:  # Client Identifier
                info["dhcp_client_id"] = val[1:].hex() if val[0] == 1 else val.hex()

        if options_seen:
            info["dhcp_options_seen"] = options_seen

    except Exception:
        pass
    return info
