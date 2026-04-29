"""
LDAP session field accumulation.

Key variables:
    s           — session dict (mutable)
    ex          — pkt.extra from current packet (read-only)
    is_fwd      — unused (LDAP ops are session-wide)
    source_type — unused
"""

from . import cap_list


def init():
    return {
        "ldap_ops": set(),
        "ldap_bind_dns": set(),
        "ldap_bind_mechanisms": set(),
        "ldap_search_bases": set(),
        "ldap_result_codes": [],
        "ldap_entry_dns": set(),
    }


def accumulate(s, ex, is_fwd, source_type):
    if ex.get("ldap_op"):
        s["ldap_ops"].add(ex["ldap_op"])
    if ex.get("ldap_bind_dn"):
        s["ldap_bind_dns"].add(ex["ldap_bind_dn"])
    if ex.get("ldap_bind_mechanism"):
        s["ldap_bind_mechanisms"].add(ex["ldap_bind_mechanism"])
    if ex.get("ldap_search_base"):
        s["ldap_search_bases"].add(ex["ldap_search_base"])
    if ex.get("ldap_result_code") is not None:
        s["ldap_result_codes"].append({"code": ex["ldap_result_code"], "name": ex.get("ldap_result_name", "")})
    if ex.get("ldap_entry_dn"):
        s["ldap_entry_dns"].add(ex["ldap_entry_dn"])


def serialize(s):
    s["ldap_ops"] = sorted(s["ldap_ops"])
    s["ldap_bind_dns"] = sorted(s["ldap_bind_dns"])
    s["ldap_bind_mechanisms"] = sorted(s["ldap_bind_mechanisms"])
    s["ldap_search_bases"] = sorted(s["ldap_search_bases"])
    cap_list(s, "ldap_result_codes")
    s["ldap_entry_dns"] = sorted(s["ldap_entry_dns"])
    cap_list(s, "ldap_entry_dns")


def catalog():
    return [
        {"name": "ldap_ops",               "type": "set",  "description": "LDAP operation types seen (e.g. bind, search, modify)"},
        {"name": "ldap_bind_dns",          "type": "set",  "description": "Distinguished names used in LDAP bind requests"},
        {"name": "ldap_bind_mechanisms",   "type": "set",  "description": "LDAP bind authentication mechanisms (e.g. NTLM, GSSAPI)"},
        {"name": "ldap_search_bases",      "type": "set",  "description": "LDAP search base distinguished names"},
        {"name": "ldap_result_codes",      "type": "list", "description": "LDAP result codes and names"},
        {"name": "ldap_entry_dns",         "type": "set",  "description": "Entry distinguished names returned by the server"},
    ]
