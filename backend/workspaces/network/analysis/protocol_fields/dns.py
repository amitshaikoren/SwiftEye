"""
DNS session field accumulation.

Custom accumulation: DNS queries are structured entries built from multiple
pkt.extra keys, not simple field-to-field mappings.

Note: DNS accumulation reads from pkt.extra directly (not through the 'ex'
variable in the if-ex block), so this handler checks for dns_query presence.

Key variables:
    s           — session dict (mutable)
    ex          — pkt.extra from current packet (read-only)
    is_fwd      — unused for DNS
    source_type — unused for DNS currently
"""

from . import cap_list

DNS_INACTIVITY_TIMEOUT = 10.0  # seconds — Zeek default for DNS


def check_boundary(flow_state, ex, ts):
    """Split DNS session on inactivity timeout."""
    if not ex.get("dns_query") and not ex.get("dns_qr"):
        return False  # not a DNS packet
    last_dns_ts = flow_state.get("last_dns_ts", 0)
    flow_state["last_dns_ts"] = ts
    if last_dns_ts > 0 and (ts - last_dns_ts) > DNS_INACTIVITY_TIMEOUT:
        return True
    return False


def init():
    return {
        "dns_queries": [],
        "dns_qclass_names": set(),
    }


def accumulate(s, ex, is_fwd, source_type):
    if ex.get("dns_qclass_name"):
        s["dns_qclass_names"].add(ex["dns_qclass_name"])
    if not ex.get("dns_query"):
        return
    dns_entry = {
        "query": ex["dns_query"],
        "type": ex.get("dns_qtype", 0),
        "type_name": ex.get("dns_qtype_name", ""),
        "qclass_name": ex.get("dns_qclass_name", "IN"),
        "qr": ex.get("dns_qr", "query"),
        "rcode": ex.get("dns_rcode", 0),
        "rcode_name": ex.get("dns_rcode_name", ""),
        "answers": ex.get("dns_answers", []),
        "answer_records": ex.get("dns_answer_records", []),
        "authority_records": ex.get("dns_authority_records", []),
        "additional_records": ex.get("dns_additional_records", []),
        "flags": {},
        "tx_id": ex.get("dns_id"),
    }
    for flag_key in ("dns_aa", "dns_tc", "dns_rd", "dns_ra"):
        if ex.get(flag_key):
            dns_entry["flags"][flag_key.replace("dns_", "")] = True
    s["dns_queries"].append(dns_entry)


def serialize(s):
    s["dns_qclass_names"] = sorted(s["dns_qclass_names"])
    cap_list(s, "dns_queries")


def catalog():
    return [
        {"name": "dns_queries",      "type": "set", "description": "DNS query records (name, type, responses) seen on this session"},
        {"name": "dns_qclass_names", "type": "set", "description": "DNS query class names (e.g. IN)"},
    ]
