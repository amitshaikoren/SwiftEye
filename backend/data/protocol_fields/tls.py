"""
TLS session field accumulation (includes JA3/JA4 fingerprints).

JA3/JA4 hashes are TLS ClientHello fingerprints computed at the parser
layer and stored in pkt.extra.  The lookup_ja3 enrichment (mapping hashes
to known applications) runs during serialize.

Key variables:
    s           — session dict (mutable)
    ex          — pkt.extra from current packet (read-only)
    is_fwd      — True if packet is from the session initiator
    source_type — adapter source (e.g. "zeek", None for pcap)
"""

from parser.ja3_db import lookup_ja3
from . import cap_list


def init():
    return {
        "tls_snis": set(),
        "tls_versions": set(),
        "tls_ciphers": set(),
        "tls_selected_ciphers": set(),
        "tls_cert": None,
        "tls_fwd_alpn_offered": set(),
        "tls_fwd_supported_versions": set(),
        "tls_fwd_extensions": set(),
        "tls_fwd_compression_methods": set(),
        "tls_rev_alpn_selected": None,
        "tls_rev_selected_version": None,
        "tls_rev_key_exchange_group": None,
        "tls_rev_session_resumption": None,
        "tls_cert_chain": [],
        # JA3/JA4 fingerprints
        "ja3_hashes": set(),
        "ja4_hashes": set(),
        "ja3_apps": [],
    }


def accumulate(s, ex, is_fwd, source_type):
    if ex.get("tls_sni"):
        s["tls_snis"].add(ex["tls_sni"])
    if ex.get("tls_hello_version"):
        s["tls_versions"].add(ex["tls_hello_version"])
    if ex.get("tls_selected_cipher"):
        s["tls_selected_ciphers"].add(ex["tls_selected_cipher"])
    if ex.get("tls_cipher_suites"):
        for cs in ex["tls_cipher_suites"]:
            s["tls_ciphers"].add(cs)
    if ex.get("tls_cert") and s["tls_cert"] is None:
        s["tls_cert"] = ex["tls_cert"]
    if ex.get("tls_cert_chain"):
        if not s["tls_cert_chain"]:
            s["tls_cert_chain"] = ex["tls_cert_chain"]
    # TLS directional (ClientHello = initiator, ServerHello = responder)
    if ex.get("tls_alpn_offered"):
        for p in ex["tls_alpn_offered"]:
            s["tls_fwd_alpn_offered"].add(p)
    if ex.get("tls_supported_versions"):
        for v in ex["tls_supported_versions"]:
            s["tls_fwd_supported_versions"].add(v)
    if ex.get("tls_extensions"):
        for e_id in ex["tls_extensions"]:
            s["tls_fwd_extensions"].add(e_id)
    if ex.get("tls_compression_methods"):
        for cm in ex["tls_compression_methods"]:
            s["tls_fwd_compression_methods"].add(cm)
    if ex.get("tls_alpn_selected") and s["tls_rev_alpn_selected"] is None:
        s["tls_rev_alpn_selected"] = ex["tls_alpn_selected"]
    if ex.get("tls_selected_version") and s["tls_rev_selected_version"] is None:
        s["tls_rev_selected_version"] = ex["tls_selected_version"]
    if ex.get("tls_key_exchange_group") and s["tls_rev_key_exchange_group"] is None:
        s["tls_rev_key_exchange_group"] = ex["tls_key_exchange_group"]
    if ex.get("tls_session_resumption") and s["tls_rev_session_resumption"] is None:
        s["tls_rev_session_resumption"] = ex["tls_session_resumption"]
    # JA3/JA4
    if ex.get("ja3"):
        s["ja3_hashes"].add(ex["ja3"])
    if ex.get("ja4"):
        s["ja4_hashes"].add(ex["ja4"])


def serialize(s):
    s["tls_snis"] = sorted(s["tls_snis"])
    s["tls_versions"] = sorted(s["tls_versions"])
    s["tls_ciphers"] = sorted(s["tls_ciphers"])
    cap_list(s, "tls_ciphers")
    s["tls_selected_ciphers"] = sorted(s["tls_selected_ciphers"])
    s["tls_fwd_alpn_offered"] = sorted(s["tls_fwd_alpn_offered"])
    s["tls_fwd_supported_versions"] = sorted(s["tls_fwd_supported_versions"])
    s["tls_fwd_extensions"] = sorted(s["tls_fwd_extensions"])
    s["tls_fwd_compression_methods"] = sorted(s["tls_fwd_compression_methods"])
    # tls_rev_* scalars stay as-is (str or None)
    # tls_cert_chain stays as list of dicts
    # JA3/JA4
    s["ja3_hashes"] = sorted(s["ja3_hashes"])
    s["ja4_hashes"] = sorted(s["ja4_hashes"])
    ja3_apps = []
    for h in s["ja3_hashes"]:
        info = lookup_ja3(h)
        if info:
            ja3_apps.append({"hash": h, **info})
    s["ja3_apps"] = ja3_apps


def catalog():
    return [
        {"name": "tls_snis",                   "type": "set",     "description": "TLS SNI values seen on this session"},
        {"name": "tls_versions",               "type": "set",     "description": "TLS versions seen in handshakes"},
        {"name": "tls_ciphers",                "type": "set",     "description": "Cipher suites offered by the client"},
        {"name": "tls_selected_ciphers",       "type": "set",     "description": "Cipher suites selected by the server"},
        {"name": "tls_cert",                   "type": "string",  "description": "Server certificate subject (leaf)"},
        {"name": "tls_cert_chain",             "type": "set",     "description": "Certificate chain subjects"},
        {"name": "tls_fwd_alpn_offered",       "type": "set",     "description": "ALPN protocols offered by the client"},
        {"name": "tls_fwd_supported_versions", "type": "set",     "description": "TLS versions supported by the client"},
        {"name": "tls_fwd_extensions",         "type": "set",     "description": "TLS extensions in the ClientHello"},
        {"name": "tls_fwd_compression_methods","type": "set",     "description": "Compression methods offered by client"},
        {"name": "tls_rev_alpn_selected",      "type": "string",  "description": "ALPN protocol selected by the server"},
        {"name": "tls_rev_selected_version",   "type": "string",  "description": "TLS version agreed by the server"},
        {"name": "tls_rev_key_exchange_group", "type": "string",  "description": "Key exchange group (e.g. x25519)"},
        {"name": "tls_rev_session_resumption", "type": "boolean", "description": "True if session resumption was used"},
        {"name": "ja3_hashes",                 "type": "set",     "description": "JA3 TLS client fingerprint hashes"},
        {"name": "ja4_hashes",                 "type": "set",     "description": "JA4 TLS client fingerprint hashes"},
        {"name": "ja3_apps",                   "type": "set",     "description": "Known applications matched via JA3 lookup"},
    ]
