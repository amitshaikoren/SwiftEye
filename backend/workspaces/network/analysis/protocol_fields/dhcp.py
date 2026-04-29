"""
DHCP session field accumulation.

Extracts DHCP fields from pkt.extra and aggregates them at the session level.
No direction splitting — DHCP is client/server by nature (not initiator/responder).

Key variables:
    s        — session dict (mutable)
    ex       — pkt.extra from current packet (read-only)
    is_fwd      — unused for DHCP (no direction split)
    source_type — unused for DHCP (no Zeek DHCP adapter yet)
"""


DHCP_INACTIVITY_TIMEOUT = 10.0  # seconds — Zeek default for DHCP

def check_boundary(flow_state, ex, ts):
    """Split on DHCP transaction ID change or inactivity timeout.

    Order matters: inactivity check runs first and short-circuits before the
    xid check. If both timeout AND xid change, timeout wins and updates the
    stored xid. Do not reorder without verifying both paths still update state.
    """
    # Inactivity timeout (Zeek-style)
    last_dhcp_ts = flow_state.get("last_dhcp_ts", 0)
    if ex.get("dhcp_msg_type") or ex.get("dhcp_xid"):
        if last_dhcp_ts > 0 and (ts - last_dhcp_ts) > DHCP_INACTIVITY_TIMEOUT:
            flow_state["last_dhcp_ts"] = ts
            flow_state["last_dhcp_xid"] = ex.get("dhcp_xid")
            return True
        flow_state["last_dhcp_ts"] = ts

    # Transaction ID change
    xid = ex.get("dhcp_xid")
    if not xid:
        return False
    last = flow_state.get("last_dhcp_xid")
    flow_state["last_dhcp_xid"] = xid
    return last is not None and xid != last


def init():
    """Return initial session fields for DHCP."""
    return {
        "dhcp_hostnames": set(),
        "dhcp_vendor_classes": set(),
        "dhcp_msg_types": set(),
        "dhcp_lease_time": None,
        "dhcp_server_ids": set(),
        "dhcp_dns_servers": set(),
        "dhcp_routers": set(),
        "dhcp_options_seen": set(),
    }


def accumulate(s, ex, is_fwd, source_type):
    """Accumulate DHCP fields from one packet's extra dict."""
    if ex.get("dhcp_hostname"):
        s["dhcp_hostnames"].add(ex["dhcp_hostname"])
    if ex.get("dhcp_vendor_class"):
        s["dhcp_vendor_classes"].add(ex["dhcp_vendor_class"])
    if ex.get("dhcp_msg_type"):
        s["dhcp_msg_types"].add(ex["dhcp_msg_type"])
    if ex.get("dhcp_lease_time") and s["dhcp_lease_time"] is None:
        s["dhcp_lease_time"] = ex["dhcp_lease_time"]
    if ex.get("dhcp_server_id"):
        s["dhcp_server_ids"].add(ex["dhcp_server_id"])
    if ex.get("dhcp_dns_servers"):
        for dns in ex["dhcp_dns_servers"]:
            s["dhcp_dns_servers"].add(dns)
    if ex.get("dhcp_router"):
        s["dhcp_routers"].add(ex["dhcp_router"])
    if ex.get("dhcp_options_seen"):
        for opt in ex["dhcp_options_seen"]:
            s["dhcp_options_seen"].add(opt)


def serialize(s):
    """Convert DHCP working fields to JSON-safe output."""
    s["dhcp_hostnames"] = sorted(s["dhcp_hostnames"])
    s["dhcp_vendor_classes"] = sorted(s["dhcp_vendor_classes"])
    s["dhcp_msg_types"] = sorted(s["dhcp_msg_types"])
    s["dhcp_server_ids"] = sorted(s["dhcp_server_ids"])
    s["dhcp_dns_servers"] = sorted(s["dhcp_dns_servers"])
    s["dhcp_routers"] = sorted(s["dhcp_routers"])
    s["dhcp_options_seen"] = sorted(s["dhcp_options_seen"])


def catalog():
    return [
        {"name": "dhcp_hostnames",     "type": "set",     "description": "Hostnames requested by DHCP clients"},
        {"name": "dhcp_vendor_classes","type": "set",     "description": "DHCP vendor class identifiers"},
        {"name": "dhcp_msg_types",     "type": "set",     "description": "DHCP message types (Discover, Offer, Request…)"},
        {"name": "dhcp_lease_time",    "type": "numeric", "description": "Lease time offered by the server (seconds)"},
        {"name": "dhcp_server_ids",    "type": "set",     "description": "DHCP server IP addresses"},
        {"name": "dhcp_dns_servers",   "type": "set",     "description": "DNS servers provided by DHCP"},
        {"name": "dhcp_routers",       "type": "set",     "description": "Default gateways provided by DHCP"},
        {"name": "dhcp_options_seen",  "type": "set",     "description": "DHCP option codes observed"},
    ]
