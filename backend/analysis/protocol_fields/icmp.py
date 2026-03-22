"""
ICMP session field accumulation.

Direction-aware: types, identifiers, payload sizes/samples split by fwd/rev.
Custom serialize: type entries are counted and sorted by frequency.

Key variables:
    s           — session dict (mutable)
    ex          — pkt.extra from current packet (read-only)
    is_fwd      — True if packet is from the session initiator
    source_type — unused for ICMP currently
"""

CAP_ICMP_PAYLOAD_SAMPLES = 10


def init():
    return {
        "icmp_fwd_types": [],
        "icmp_rev_types": [],
        "icmp_fwd_identifiers": set(),
        "icmp_rev_identifiers": set(),
        "icmp_fwd_payload_sizes": [],
        "icmp_rev_payload_sizes": [],
        "icmp_fwd_payload_samples": [],
        "icmp_rev_payload_samples": [],
    }


def accumulate(s, ex, is_fwd, source_type):
    if ex.get("icmp_type") is None:
        return
    d = "fwd" if is_fwd else "rev"
    type_entry = f"{ex.get('icmp_type_name', '')}:{ex.get('icmp_code_name', ex.get('icmp_code', ''))}"
    s[f"icmp_{d}_types"].append(type_entry)
    if ex.get("icmp_id") is not None:
        s[f"icmp_{d}_identifiers"].add(ex["icmp_id"])
    if ex.get("icmp_payload_size") is not None:
        s[f"icmp_{d}_payload_sizes"].append(ex["icmp_payload_size"])
    if ex.get("icmp_payload_hex") and len(s[f"icmp_{d}_payload_samples"]) < CAP_ICMP_PAYLOAD_SAMPLES:
        hex_val = ex["icmp_payload_hex"]
        if hex_val not in s[f"icmp_{d}_payload_samples"]:
            s[f"icmp_{d}_payload_samples"].append(hex_val)


def _type_counts(type_list):
    """Aggregate type entries by frequency, most common first."""
    counts = {}
    for t in type_list:
        counts[t] = counts.get(t, 0) + 1
    return [{"type_desc": k, "count": v} for k, v in sorted(counts.items(), key=lambda x: -x[1])]


def serialize(s):
    s["icmp_fwd_types"] = _type_counts(s["icmp_fwd_types"])
    s["icmp_rev_types"] = _type_counts(s["icmp_rev_types"])
    s["icmp_fwd_identifiers"] = sorted(s["icmp_fwd_identifiers"])
    s["icmp_rev_identifiers"] = sorted(s["icmp_rev_identifiers"])
