"""
mDNS session field accumulation.

Key variables:
    s           — session dict (mutable)
    ex          — pkt.extra from current packet (read-only)
    is_fwd      — unused (mDNS is multicast, no direction concept)
    source_type — unused
"""

from analysis.protocol_fields import cap_list


def init():
    return {
        "mdns_queries": set(),
        "mdns_service_types": set(),
        "mdns_service_names": set(),
        "mdns_hostnames": set(),
        "mdns_txt_records": [],
    }


def accumulate(s, ex, is_fwd, source_type):
    if ex.get("mdns_query"):
        s["mdns_queries"].add(ex["mdns_query"])
    if ex.get("mdns_service_type"):
        s["mdns_service_types"].add(ex["mdns_service_type"])
    if ex.get("mdns_service_name"):
        s["mdns_service_names"].add(ex["mdns_service_name"])
    if ex.get("mdns_hostname"):
        s["mdns_hostnames"].add(ex["mdns_hostname"])
    if ex.get("mdns_txt_records"):
        for t in ex["mdns_txt_records"]:
            if t not in s["mdns_txt_records"]:
                s["mdns_txt_records"].append(t)


def serialize(s):
    s["mdns_queries"] = sorted(s["mdns_queries"])
    s["mdns_service_types"] = sorted(s["mdns_service_types"])
    s["mdns_service_names"] = sorted(s["mdns_service_names"])
    s["mdns_hostnames"] = sorted(s["mdns_hostnames"])
    cap_list(s, "mdns_txt_records")
