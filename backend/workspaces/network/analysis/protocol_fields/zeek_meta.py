"""
Zeek metadata session field accumulation.

Populated only for packets from Zeek log adapters. These fields are
Zeek-specific connection metadata (UID, conn_state, history, etc.)
that don't exist in pcap data.

Key variables:
    s           — session dict (mutable)
    ex          — pkt.extra from current packet (read-only)
    is_fwd      — unused
    source_type — checked: only accumulates when source_type == "zeek"
"""


def init():
    return {
        "zeek_uid": None,
        "zeek_conn_state": None,
        "zeek_history": None,
        "zeek_duration": None,
        "zeek_service": None,
        "source_type": None,
    }


def accumulate(s, ex, is_fwd, source_type):
    if source_type != "zeek":
        return
    s["source_type"] = "zeek"
    if ex.get("uid"):
        s["zeek_uid"] = ex["uid"]
    if ex.get("conn_state"):
        s["zeek_conn_state"] = ex["conn_state"]
    if ex.get("history"):
        s["zeek_history"] = ex["history"]
    if ex.get("duration"):
        s["zeek_duration"] = ex["duration"]
    if ex.get("service"):
        s["zeek_service"] = ex["service"]


def serialize(s):
    # Zeek metadata are scalars — no conversion needed
    pass
