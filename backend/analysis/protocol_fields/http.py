"""
HTTP session field accumulation.

Direction-aware with Zeek special handling: Zeek http.log records contain both
request and response fields in a single record, so when source_type == "zeek",
both fwd and rev fields are populated from every packet.

Key variables:
    s           — session dict (mutable)
    ex          — pkt.extra from current packet (read-only)
    is_fwd      — True if packet is from the session initiator
    source_type — "zeek" triggers both-direction accumulation
"""

CAP_HTTP_URIS = 30
CAP_HTTP_STATUS_CODES = 50


def init():
    return {
        "http_hosts": set(),
        "http_fwd_user_agents": set(),
        "http_fwd_methods": set(),
        "http_fwd_uris": [],
        "http_fwd_referers": set(),
        "http_fwd_has_cookies": False,
        "http_fwd_has_auth": False,
        "http_fwd_auth_types": set(),
        "http_fwd_usernames": set(),
        "http_rev_servers": set(),
        "http_rev_status_codes": [],
        "http_rev_content_types": set(),
        "http_rev_redirects": set(),
        "http_rev_has_set_cookies": False,
    }


def accumulate(s, ex, is_fwd, source_type):
    _zeek = source_type == "zeek"
    if ex.get("http_host"):
        s["http_hosts"].add(ex["http_host"])
    if is_fwd or _zeek:
        if ex.get("http_user_agent"):
            s["http_fwd_user_agents"].add(ex["http_user_agent"])
        if ex.get("http_method"):
            s["http_fwd_methods"].add(ex["http_method"])
        if ex.get("http_uri") and len(s["http_fwd_uris"]) < CAP_HTTP_URIS:
            s["http_fwd_uris"].append(ex["http_uri"])
        if ex.get("http_referer"):
            s["http_fwd_referers"].add(ex["http_referer"])
        if ex.get("http_cookie"):
            s["http_fwd_has_cookies"] = True
        if ex.get("http_authorization"):
            s["http_fwd_has_auth"] = True
            auth_val = ex["http_authorization"]
            if isinstance(auth_val, str) and auth_val is not True:
                auth_type = auth_val.split()[0] if ' ' in auth_val else auth_val
                s["http_fwd_auth_types"].add(auth_type)
            if ex.get("http_username"):
                s["http_fwd_usernames"].add(ex["http_username"])
    if not is_fwd or _zeek:
        if ex.get("http_server"):
            s["http_rev_servers"].add(ex["http_server"])
        if ex.get("http_status") and len(s["http_rev_status_codes"]) < CAP_HTTP_STATUS_CODES:
            s["http_rev_status_codes"].append(ex["http_status"])
        if ex.get("http_content_type"):
            s["http_rev_content_types"].add(ex["http_content_type"])
        if ex.get("http_location"):
            s["http_rev_redirects"].add(ex["http_location"])
        if ex.get("http_set_cookie"):
            s["http_rev_has_set_cookies"] = True


def serialize(s):
    s["http_hosts"] = sorted(s["http_hosts"])
    s["http_fwd_user_agents"] = sorted(s["http_fwd_user_agents"])
    s["http_fwd_methods"] = sorted(s["http_fwd_methods"])
    s["http_fwd_uris"] = list(dict.fromkeys(s["http_fwd_uris"]))[:CAP_HTTP_URIS]
    s["http_fwd_referers"] = sorted(s["http_fwd_referers"])
    s["http_rev_servers"] = sorted(s["http_rev_servers"])
    s["http_rev_status_codes"] = s["http_rev_status_codes"][:CAP_HTTP_STATUS_CODES]
    s["http_rev_content_types"] = sorted(s["http_rev_content_types"])
    s["http_rev_redirects"] = sorted(s["http_rev_redirects"])
    s["http_fwd_auth_types"] = sorted(s["http_fwd_auth_types"])
    s["http_fwd_usernames"] = sorted(s["http_fwd_usernames"])
