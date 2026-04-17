"""
SSDP dissector — extracts service discovery headers from UPnP/SSDP traffic.

SSDP (Simple Service Discovery Protocol) runs on UDP port 1900 with multicast
address 239.255.255.250. It's the discovery layer for UPnP devices.

Two message types:
  M-SEARCH (request)  — client searching for devices/services
  NOTIFY   (announce) — device announcing its presence

Fields extracted:
  ssdp_method          — "M-SEARCH" or "NOTIFY" or "HTTP/1.1 200 OK" (response)
  ssdp_st              — Search Target (M-SEARCH: what to find; response: what was found)
  ssdp_usn             — Unique Service Name (device identity)
  ssdp_location        — URL to device description XML
  ssdp_server          — Server header (OS + UPnP version + product)
  ssdp_nts             — Notification Sub-Type: ssdp:alive, ssdp:byebye, ssdp:update
  ssdp_nt              — Notification Type (what the device is advertising)
  ssdp_mx              — Maximum wait time for M-SEARCH responses
  ssdp_user_agent      — User-Agent from M-SEARCH requests
"""

from typing import Dict, Any
from . import register_dissector


@register_dissector("SSDP/UPnP")
def dissect_ssdp(pkt) -> Dict[str, Any]:
    if pkt.haslayer("Raw"):
        return _extract(bytes(pkt["Raw"].load))
    return {}


def _extract(payload: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        # SSDP is HTTP-like: first line is method/status, then headers
        text = payload.decode(errors="replace")
        lines = text.split("\r\n")
        if len(lines) <= 1:
            lines = text.split("\n")

        if not lines:
            return info

        # First line: method
        first = lines[0].strip()
        if first.upper().startswith("M-SEARCH"):
            info["ssdp_method"] = "M-SEARCH"
        elif first.upper().startswith("NOTIFY"):
            info["ssdp_method"] = "NOTIFY"
        elif first.upper().startswith("HTTP/"):
            info["ssdp_method"] = "RESPONSE"
        else:
            return info

        # Parse headers (case-insensitive)
        for line in lines[1:20]:
            line = line.strip()
            if not line or ":" not in line:
                continue
            colon = line.index(":")
            key = line[:colon].strip().upper()
            val = line[colon + 1:].strip()

            if not val:
                continue

            if key == "ST":
                info["ssdp_st"] = val[:300]
            elif key == "USN":
                info["ssdp_usn"] = val[:300]
            elif key == "LOCATION":
                info["ssdp_location"] = val[:500]
            elif key == "SERVER":
                info["ssdp_server"] = val[:200]
            elif key == "NTS":
                info["ssdp_nts"] = val[:100]
            elif key == "NT":
                info["ssdp_nt"] = val[:300]
            elif key == "MX":
                try:
                    info["ssdp_mx"] = int(val)
                except ValueError:
                    pass
            elif key == "USER-AGENT":
                info["ssdp_user_agent"] = val[:300]

    except Exception:
        pass
    return info
