"""
LDAP session field accumulation.

Key variables:
    s           — session dict (mutable)
    ex          — pkt.extra from current packet (read-only)
    is_fwd      — unused (LDAP ops are session-wide)
    source_type — unused
"""

from analysis.protocol_fields import cap_list


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
