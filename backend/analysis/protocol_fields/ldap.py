"""
LDAP session field accumulation.

Key variables:
    s           — session dict (mutable)
    ex          — pkt.extra from current packet (read-only)
    is_fwd      — unused (LDAP ops are session-wide)
    source_type — unused
"""

CAP_LDAP_RESULT_CODES = 20
CAP_LDAP_ENTRY_DNS = 20


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
    if ex.get("ldap_result_code") is not None and len(s["ldap_result_codes"]) < CAP_LDAP_RESULT_CODES:
        s["ldap_result_codes"].append({"code": ex["ldap_result_code"], "name": ex.get("ldap_result_name", "")})
    if ex.get("ldap_entry_dn"):
        s["ldap_entry_dns"].add(ex["ldap_entry_dn"])


def serialize(s):
    s["ldap_ops"] = sorted(s["ldap_ops"])
    s["ldap_bind_dns"] = sorted(s["ldap_bind_dns"])
    s["ldap_bind_mechanisms"] = sorted(s["ldap_bind_mechanisms"])
    s["ldap_search_bases"] = sorted(s["ldap_search_bases"])
    s["ldap_entry_dns"] = sorted(s["ldap_entry_dns"])[:CAP_LDAP_ENTRY_DNS]
