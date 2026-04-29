"""
<PROTOCOL> dissector — <brief description>.

This is a template for writing new protocol dissectors in SwiftEye.
Copy this file, rename to dissect_<protocol>.py, and follow the steps below.

SETUP CHECKLIST (do all of these):
  1. Copy this file → dissect_<protocol>.py
  2. Add port mapping in backend/constants.py WELL_KNOWN_PORTS
  3. Add color in backend/constants.py PROTOCOL_COLORS
  4. Register the import in protocols/__init__.py:
       from . import dissect_<protocol>  # noqa: F401
  5. If your protocol has a recognizable byte signature, add a payload
     signature below (uncomment the @register_payload_signature block)
  6. Add protocol_fields accumulator if fields should appear in sessions:
       backend/analysis/protocol_fields/<protocol>.py

Fields extracted:
  <protocol>_field1   — description
  <protocol>_field2   — description
"""

from typing import Dict, Any
from . import register_dissector  # , register_payload_signature


# ── Payload signature (optional) ─────────────────────────────────────────────
# Uncomment to enable detection on non-standard ports.
# Priority guide: 10-15 = magic bytes, 20-30 = banner, 40-60 = heuristic
#
# @register_payload_signature("MYPROTO", priority=25)
# def _detect(payload: bytes) -> bool:
#     """Return True if payload looks like this protocol."""
#     return len(payload) >= 4 and payload[:4] == b"MY\x01\x00"


# ── Dissector ────────────────────────────────────────────────────────────────
# Most dissectors should NOT set scapy_layer — they receive a lightweight
# proxy with haslayer("Raw") / pkt["Raw"].load and parse raw bytes.
# This is fast (no scapy overhead per packet).
#
# Only set scapy_layer if your dissector needs a real scapy-parsed object:
#   from scapy.layers.dns import DNS
#   @register_dissector("mDNS", scapy_layer=DNS)
#
# Currently only DNS, mDNS, LLMNR use scapy_layer (all with DNS class).

@register_dissector("MYPROTO")
def dissect_myproto(pkt) -> Dict[str, Any]:
    """
    Extract protocol-specific fields from a packet.

    Args:
        pkt: Either a lightweight _L5Proxy (default) or a scapy object
             (if scapy_layer was declared). Use pkt.haslayer("Raw") and
             pkt["Raw"].load to access the raw payload bytes.

    Returns:
        Dict of extra fields to attach to the PacketRecord.
        Return {} on any parse failure — never raise.
    """
    info: Dict[str, Any] = {}

    if not pkt.haslayer("Raw"):
        return info

    try:
        payload = bytes(pkt["Raw"].load)
        if len(payload) < 4:
            return info

        # ── Parse your protocol here ──────────────────────────────────
        # Example: read a 2-byte command code from the payload
        # cmd = (payload[0] << 8) | payload[1]
        # info["myproto_command"] = cmd

    except Exception:
        pass

    return info
