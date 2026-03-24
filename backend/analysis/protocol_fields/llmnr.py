"""
LLMNR session field accumulation.

Key variables:
    s           — session dict (mutable)
    ex          — pkt.extra from current packet (read-only)
    is_fwd      — unused (LLMNR is multicast)
    source_type — unused
"""

from analysis.protocol_fields import cap_list


def init():
    return {
        "llmnr_queries": set(),
        "llmnr_answers": [],
    }


def accumulate(s, ex, is_fwd, source_type):
    if ex.get("llmnr_query"):
        s["llmnr_queries"].add(ex["llmnr_query"])
    if ex.get("llmnr_answers"):
        for a in ex["llmnr_answers"]:
            if a not in s["llmnr_answers"]:
                s["llmnr_answers"].append(a)


def serialize(s):
    s["llmnr_queries"] = sorted(s["llmnr_queries"])
    cap_list(s, "llmnr_answers")
