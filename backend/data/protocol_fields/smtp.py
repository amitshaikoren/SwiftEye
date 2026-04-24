"""
SMTP session field accumulation.

Key variables:
    s           — session dict (mutable)
    ex          — pkt.extra from current packet (read-only)
    is_fwd      — unused (SMTP fields are session-wide)
    source_type — unused
"""


def init():
    return {
        "smtp_ehlo_domains": set(),
        "smtp_mail_from": set(),
        "smtp_rcpt_to": set(),
        "smtp_banner": None,
        "smtp_auth_mechanisms": set(),
        "smtp_has_auth": False,
        "smtp_has_starttls": False,
        "smtp_response_codes": set(),
    }


def accumulate(s, ex, is_fwd, source_type):
    if ex.get("smtp_ehlo_domain"):
        s["smtp_ehlo_domains"].add(ex["smtp_ehlo_domain"])
    if ex.get("smtp_mail_from"):
        s["smtp_mail_from"].add(ex["smtp_mail_from"])
    if ex.get("smtp_rcpt_to"):
        s["smtp_rcpt_to"].add(ex["smtp_rcpt_to"])
    if ex.get("smtp_banner") and s["smtp_banner"] is None:
        s["smtp_banner"] = ex["smtp_banner"]
    if ex.get("smtp_auth_mechanism"):
        s["smtp_auth_mechanisms"].add(ex["smtp_auth_mechanism"])
    if ex.get("smtp_has_auth"):
        s["smtp_has_auth"] = True
    if ex.get("smtp_has_starttls"):
        s["smtp_has_starttls"] = True
    if ex.get("smtp_response_code"):
        s["smtp_response_codes"].add(ex["smtp_response_code"])


def serialize(s):
    s["smtp_ehlo_domains"] = sorted(s["smtp_ehlo_domains"])
    s["smtp_mail_from"] = sorted(s["smtp_mail_from"])
    s["smtp_rcpt_to"] = sorted(s["smtp_rcpt_to"])
    s["smtp_auth_mechanisms"] = sorted(s["smtp_auth_mechanisms"])
    s["smtp_response_codes"] = sorted(s["smtp_response_codes"])


def catalog():
    return [
        {"name": "smtp_ehlo_domains",      "type": "set",     "description": "EHLO/HELO domain names"},
        {"name": "smtp_mail_from",         "type": "set",     "description": "SMTP MAIL FROM addresses"},
        {"name": "smtp_rcpt_to",           "type": "set",     "description": "SMTP RCPT TO addresses"},
        {"name": "smtp_banner",            "type": "string",  "description": "SMTP server banner"},
        {"name": "smtp_auth_mechanisms",   "type": "set",     "description": "AUTH mechanisms offered or used"},
        {"name": "smtp_has_auth",          "type": "boolean", "description": "True if authentication was attempted"},
        {"name": "smtp_has_starttls",      "type": "boolean", "description": "True if STARTTLS upgrade occurred"},
        {"name": "smtp_response_codes",    "type": "set",     "description": "SMTP response codes seen"},
    ]
