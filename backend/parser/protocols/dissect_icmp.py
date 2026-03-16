"""
ICMP / ICMPv6 dissector — resolves type/code to human-readable names.

ICMPv4 (RFC 792) and ICMPv6 (RFC 4443) are handled by separate code paths
because they have different type spaces, but both write to the same field names
so the rest of the pipeline treats them uniformly.

ICMPv4 fields: icmp_type, icmp_code, icmp_type_name, icmp_code_name, icmp_id, icmp_seq
ICMPv6 fields: icmp_type, icmp_code, icmp_type_name, icmp_code_name, icmp_id, icmp_seq
               icmpv6_target (for NS/NA — the IPv6 address being resolved)
"""

from typing import Dict, Any
from . import register_dissector
from .ports import ICMP_TYPES, ICMP_DEST_UNREACH_CODES


# ── ICMPv6 type names (RFC 4443 + NDP RFC 4861) ──────────────────────────────
_ICMPV6_TYPES: Dict[int, str] = {
    # Error messages
    1:   "Destination Unreachable",
    2:   "Packet Too Big",
    3:   "Time Exceeded",
    4:   "Parameter Problem",
    # Informational
    128: "Echo Request",
    129: "Echo Reply",
    # NDP (RFC 4861)
    130: "MLD Query",
    131: "MLD Report",
    132: "MLD Done",
    133: "Router Solicitation",
    134: "Router Advertisement",
    135: "Neighbor Solicitation",
    136: "Neighbor Advertisement",
    137: "Redirect",
    # MLDv2
    143: "MLDv2 Report",
}

_ICMPV6_DEST_UNREACH: Dict[int, str] = {
    0: "No route to destination",
    1: "Communication administratively prohibited",
    2: "Beyond scope of source address",
    3: "Address unreachable",
    4: "Port unreachable",
    5: "Source address failed ingress/egress policy",
    6: "Reject route to destination",
}

_ICMPV6_TIME_EXCEEDED: Dict[int, str] = {
    0: "Hop limit exceeded in transit",
    1: "Fragment reassembly time exceeded",
}


@register_dissector("ICMP")
def dissect_icmp(pkt) -> Dict[str, Any]:
    # Try scapy ICMP layer first, then fall back to manual
    try:
        from scapy.all import ICMP as ScapyICMP
        if pkt.haslayer(ScapyICMP):
            return _extract_icmpv4_scapy(pkt[ScapyICMP])
    except Exception:
        pass
    # Manual fallback via Raw layer
    if pkt.haslayer("Raw"):
        return _extract_icmpv4_manual(bytes(pkt["Raw"].load))
    return {}


@register_dissector("ICMPv6")
def dissect_icmpv6(pkt) -> Dict[str, Any]:
    try:
        from scapy.all import ICMPv6EchoRequest, ICMPv6EchoReply
        from scapy.layers.inet6 import ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RA, ICMPv6ND_RS
        info: Dict[str, Any] = {}

        for cls, t in [
            (ICMPv6EchoRequest, 128), (ICMPv6EchoReply, 129),
            (ICMPv6ND_NS, 135), (ICMPv6ND_NA, 136),
            (ICMPv6ND_RA, 134), (ICMPv6ND_RS, 133),
        ]:
            if pkt.haslayer(cls):
                layer = pkt[cls]
                icmp_type = getattr(layer, "type", t)
                icmp_code = getattr(layer, "code", 0)
                info["icmp_type"] = icmp_type
                info["icmp_code"] = icmp_code
                info["icmp_type_name"] = _ICMPV6_TYPES.get(icmp_type, f"Type {icmp_type}")
                if hasattr(layer, "id"):
                    info["icmp_id"] = layer.id
                if hasattr(layer, "seq"):
                    info["icmp_seq"] = layer.seq
                # NDP target address
                if hasattr(layer, "tgt") and layer.tgt:
                    info["icmpv6_target"] = str(layer.tgt)
                return info

        # Generic ICMPv6 fallback
        try:
            from scapy.layers.inet6 import _ICMPv6
            if pkt.haslayer(_ICMPv6):
                layer = pkt[_ICMPv6]
                icmp_type = getattr(layer, "type", 0)
                info["icmp_type"] = icmp_type
                info["icmp_code"] = getattr(layer, "code", 0)
                info["icmp_type_name"] = _ICMPV6_TYPES.get(icmp_type, f"Type {icmp_type}")
                return info
        except Exception:
            pass
    except Exception:
        pass
    return {}


def _extract_icmpv4_scapy(icmp) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    icmp_type = icmp.type
    icmp_code = icmp.code
    info["icmp_type"]      = icmp_type
    info["icmp_code"]      = icmp_code
    info["icmp_type_name"] = ICMP_TYPES.get(icmp_type, f"Type {icmp_type}")

    if icmp_type == 3:
        info["icmp_code_name"] = ICMP_DEST_UNREACH_CODES.get(icmp_code, f"Code {icmp_code}")
    elif icmp_type == 11:
        info["icmp_code_name"] = "TTL Exceeded in Transit" if icmp_code == 0 else "Fragment Reassembly Exceeded"
    elif icmp_type == 5:
        redirect = {0: "Network", 1: "Host", 2: "ToS+Network", 3: "ToS+Host"}
        info["icmp_code_name"] = f"Redirect for {redirect.get(icmp_code, 'Unknown')}"
    elif icmp_type == 12:
        pointer = {0: "Version/IHL", 8: "TTL", 9: "Protocol", 10: "Header Checksum"}
        info["icmp_code_name"] = pointer.get(icmp_code, f"Pointer={icmp_code}")

    if icmp_type in (0, 8):
        info["icmp_id"]  = icmp.id
        info["icmp_seq"] = icmp.seq

    return info


def _extract_icmpv4_manual(payload: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    if len(payload) < 4:
        return info
    icmp_type = payload[0]
    icmp_code = payload[1]
    info["icmp_type"]      = icmp_type
    info["icmp_code"]      = icmp_code
    info["icmp_type_name"] = ICMP_TYPES.get(icmp_type, f"Type {icmp_type}")
    if icmp_type in (0, 8) and len(payload) >= 8:
        import struct
        info["icmp_id"]  = struct.unpack_from("!H", payload, 4)[0]
        info["icmp_seq"] = struct.unpack_from("!H", payload, 6)[0]
    return info
