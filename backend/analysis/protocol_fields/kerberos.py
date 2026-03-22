"""
Kerberos session field accumulation.

Key variables:
    s           — session dict (mutable)
    ex          — pkt.extra from current packet (read-only)
    is_fwd      — unused (Kerberos is request/reply, not direction-split)
    source_type — unused
"""

CAP_KRB_ERROR_CODES = 20


def init():
    return {
        "krb_msg_types": set(),
        "krb_realms": set(),
        "krb_cnames": set(),
        "krb_snames": set(),
        "krb_etypes": set(),
        "krb_error_codes": [],
    }


def accumulate(s, ex, is_fwd, source_type):
    if ex.get("krb_msg_type"):
        s["krb_msg_types"].add(ex["krb_msg_type"])
    if ex.get("krb_realm"):
        s["krb_realms"].add(ex["krb_realm"])
    if ex.get("krb_cname"):
        s["krb_cnames"].add(ex["krb_cname"])
    if ex.get("krb_sname"):
        s["krb_snames"].add(ex["krb_sname"])
    if ex.get("krb_etypes"):
        for e in ex["krb_etypes"]:
            s["krb_etypes"].add(e)
    if ex.get("krb_error_code") is not None and len(s["krb_error_codes"]) < CAP_KRB_ERROR_CODES:
        s["krb_error_codes"].append({"code": ex["krb_error_code"], "name": ex.get("krb_error_name", "")})


def serialize(s):
    s["krb_msg_types"] = sorted(s["krb_msg_types"])
    s["krb_realms"] = sorted(s["krb_realms"])
    s["krb_cnames"] = sorted(s["krb_cnames"])
    s["krb_snames"] = sorted(s["krb_snames"])
    s["krb_etypes"] = sorted(s["krb_etypes"])
