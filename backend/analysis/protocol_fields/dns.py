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

CAP_DNS_QUERIES = 50


def init():
    return {
        "dns_queries": [],
        "dns_qclass_names": set(),
    }


def accumulate(s, ex, is_fwd, source_type):
    if ex.get("dns_qclass_name"):
        s["dns_qclass_names"].add(ex["dns_qclass_name"])
    if not ex.get("dns_query") or len(s["dns_queries"]) >= CAP_DNS_QUERIES:
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
    # dns_queries stays as list of dicts — no sorting needed
