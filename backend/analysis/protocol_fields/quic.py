"""
QUIC session field accumulation.

Key variables:
    s           — session dict (mutable)
    ex          — pkt.extra from current packet (read-only)
    is_fwd      — unused (QUIC fields are session-wide)
    source_type — unused
"""

from analysis.protocol_fields import cap_list


def init():
    return {
        "quic_versions": set(),
        "quic_dcids": set(),
        "quic_scids": set(),
        "quic_snis": set(),
        "quic_alpn": set(),
        "quic_packet_types": set(),
        "quic_tls_versions": set(),
        "quic_tls_ciphers": set(),
    }


def accumulate(s, ex, is_fwd, source_type):
    if ex.get("quic_version_name"):
        s["quic_versions"].add(ex["quic_version_name"])
    if ex.get("quic_dcid"):
        s["quic_dcids"].add(ex["quic_dcid"])
    if ex.get("quic_scid"):
        s["quic_scids"].add(ex["quic_scid"])
    if ex.get("quic_sni"):
        s["quic_snis"].add(ex["quic_sni"])
    if ex.get("quic_alpn"):
        for p in ex["quic_alpn"]:
            s["quic_alpn"].add(p)
    if ex.get("quic_packet_type"):
        s["quic_packet_types"].add(ex["quic_packet_type"])
    if ex.get("quic_tls_versions"):
        for v in ex["quic_tls_versions"]:
            s["quic_tls_versions"].add(v)
    if ex.get("quic_tls_ciphers"):
        for c in ex["quic_tls_ciphers"]:
            s["quic_tls_ciphers"].add(c)


def serialize(s):
    s["quic_versions"] = sorted(s["quic_versions"])
    s["quic_dcids"] = sorted(s["quic_dcids"])
    cap_list(s, "quic_dcids")
    s["quic_scids"] = sorted(s["quic_scids"])
    cap_list(s, "quic_scids")
    s["quic_snis"] = sorted(s["quic_snis"])
    s["quic_alpn"] = sorted(s["quic_alpn"])
    s["quic_packet_types"] = sorted(s["quic_packet_types"])
    s["quic_tls_versions"] = sorted(s["quic_tls_versions"])
    s["quic_tls_ciphers"] = sorted(s["quic_tls_ciphers"])
    cap_list(s, "quic_tls_ciphers")
