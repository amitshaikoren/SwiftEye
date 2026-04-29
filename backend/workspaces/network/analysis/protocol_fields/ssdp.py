"""
SSDP session field accumulation.

Key variables:
    s           — session dict (mutable)
    ex          — pkt.extra from current packet (read-only)
    is_fwd      — unused (SSDP is multicast/broadcast)
    source_type — unused
"""

from . import cap_list


def init():
    return {
        "ssdp_methods": set(),
        "ssdp_sts": set(),
        "ssdp_usns": set(),
        "ssdp_locations": set(),
        "ssdp_servers": set(),
    }


def accumulate(s, ex, is_fwd, source_type):
    if ex.get("ssdp_method"):
        s["ssdp_methods"].add(ex["ssdp_method"])
    if ex.get("ssdp_st"):
        s["ssdp_sts"].add(ex["ssdp_st"])
    if ex.get("ssdp_usn"):
        s["ssdp_usns"].add(ex["ssdp_usn"])
    if ex.get("ssdp_location"):
        s["ssdp_locations"].add(ex["ssdp_location"])
    if ex.get("ssdp_server"):
        s["ssdp_servers"].add(ex["ssdp_server"])


def serialize(s):
    s["ssdp_methods"] = sorted(s["ssdp_methods"])
    s["ssdp_sts"] = sorted(s["ssdp_sts"])
    cap_list(s, "ssdp_sts")
    s["ssdp_usns"] = sorted(s["ssdp_usns"])
    cap_list(s, "ssdp_usns")
    s["ssdp_locations"] = sorted(s["ssdp_locations"])
    cap_list(s, "ssdp_locations")
    s["ssdp_servers"] = sorted(s["ssdp_servers"])


def catalog():
    return [
        {"name": "ssdp_methods",   "type": "set", "description": "SSDP methods seen (M-SEARCH, NOTIFY, etc.)"},
        {"name": "ssdp_sts",       "type": "set", "description": "SSDP search targets or notification types"},
        {"name": "ssdp_usns",      "type": "set", "description": "SSDP unique service names (USN)"},
        {"name": "ssdp_locations", "type": "set", "description": "SSDP service location URLs"},
        {"name": "ssdp_servers",   "type": "set", "description": "SSDP server strings"},
    ]
