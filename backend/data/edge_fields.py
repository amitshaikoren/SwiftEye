"""
Edge field registry for SwiftEye.

Single source of truth for:
  - Which pkt.extra fields get accumulated onto graph edges
  - Accumulation type (set vs multi-value list)
  - Per-accumulation caps (limit items taken from each packet's list)
  - Per-serialization caps (limit items in the response payload)
  - Whether a field is "lazy" (detail-only, not included in graph summary)

Usage
-----
  aggregator.py          — edge init, accumulation loop, summary/detail serialisation
  routes/data.py         — /api/edge/{id}/detail endpoint
  routes/utility.py      — /api/meta/edge-fields endpoint (used by frontend hints)

Adding a new edge-accumulated field
------------------------------------
1. Add an entry to EDGE_FIELD_REGISTRY below.
2. No other backend changes needed — aggregator uses the registry dynamically.
3. Update the frontend /api/meta/edge-fields consumer if the field needs a
   keyword hint in the search bar.
"""

from typing import Optional

# ── View-layer caps ──────────────────────────────────────────────────────────
# These cap the number of unique values serialised into each response.
# Raw packet data is never truncated — only the HTTP response payload.
EDGE_TLS_CIPHER_SUITES = 10   # items taken from each handshake's list
EDGE_TLS_CIPHERS       = 15   # items in the serialised detail response
EDGE_DNS_QUERIES       = 30   # items in the serialised detail response

# ── Registry ─────────────────────────────────────────────────────────────────
# Each entry describes one extra-field → edge-field accumulation.
#
# extra_key   : key read from pkt.extra
# edge_key    : key accumulated on the edge dict (a set)
# multi       : True when pkt.extra[extra_key] is a list (iterate + add each item)
# acc_cap     : max items consumed from a multi-value list per packet (None = all)
# ser_cap     : max items in the serialised response (None = no cap)
# lazy        : if True, excluded from the /api/graph summary; only in /api/edge detail
# hint_keyword: keyword(s) the frontend search bar associates with this field's presence
#               (drives /api/meta/edge-fields; may be a list for aliases)

EDGE_FIELD_REGISTRY: list = [
    {
        "extra_key":    "tls_sni",
        "edge_key":     "tls_snis",
        "multi":        False,
        "acc_cap":      None,
        "ser_cap":      None,
        "lazy":         True,
        "hint_keyword": ["tls", "sni"],
    },
    {
        "extra_key":    "tls_hello_version",
        "edge_key":     "tls_versions",
        "multi":        False,
        "acc_cap":      None,
        "ser_cap":      None,
        "lazy":         True,
        "hint_keyword": ["tls"],
    },
    {
        "extra_key":    "tls_selected_cipher",
        "edge_key":     "tls_selected_ciphers",
        "multi":        False,
        "acc_cap":      None,
        "ser_cap":      None,
        "lazy":         True,
        "hint_keyword": ["tls", "cipher"],
    },
    {
        "extra_key":    "tls_cipher_suites",
        "edge_key":     "tls_ciphers",
        "multi":        True,
        "acc_cap":      EDGE_TLS_CIPHER_SUITES,
        "ser_cap":      EDGE_TLS_CIPHERS,
        "lazy":         True,
        "hint_keyword": ["tls", "cipher"],
    },
    {
        "extra_key":    "http_host",
        "edge_key":     "http_hosts",
        "multi":        False,
        "acc_cap":      None,
        "ser_cap":      None,
        "lazy":         True,
        "hint_keyword": ["http"],
    },
    {
        "extra_key":    "http_user_agent",
        "edge_key":     "http_fwd_user_agents",
        "multi":        False,
        "acc_cap":      None,
        "ser_cap":      20,
        "lazy":         True,
        "hint_keyword": ["http"],
    },
    {
        "extra_key":    "dns_query",
        "edge_key":     "dns_queries",
        "multi":        False,
        "acc_cap":      None,
        "ser_cap":      EDGE_DNS_QUERIES,
        "lazy":         True,
        "hint_keyword": ["dns"],
    },
    {
        "extra_key":    "ja3",
        "edge_key":     "ja3_hashes",
        "multi":        False,
        "acc_cap":      None,
        "ser_cap":      None,
        "lazy":         True,
        "hint_keyword": ["ja3", "tls"],
    },
    {
        "extra_key":    "ja4",
        "edge_key":     "ja4_hashes",
        "multi":        False,
        "acc_cap":      None,
        "ser_cap":      None,
        "lazy":         True,
        "hint_keyword": ["ja4", "tls"],
    },
]

# Pre-computed index: edge_key → registry entry (for fast lookup)
_BY_EDGE_KEY: dict = {f["edge_key"]: f for f in EDGE_FIELD_REGISTRY}

# All edge_keys that belong to "has_tls" summary hint
_TLS_KEYS = frozenset(
    f["edge_key"] for f in EDGE_FIELD_REGISTRY
    if "tls" in f.get("hint_keyword", [])
)
_HTTP_KEYS = frozenset(
    f["edge_key"] for f in EDGE_FIELD_REGISTRY
    if "http" in f.get("hint_keyword", [])
)
_DNS_KEYS = frozenset(
    f["edge_key"] for f in EDGE_FIELD_REGISTRY
    if "dns" in f.get("hint_keyword", [])
)


# ── Helpers used by aggregator ────────────────────────────────────────────────

def init_detail_sets() -> dict:
    """Return a blank {edge_key: set()} dict for all registry fields."""
    return {f["edge_key"]: set() for f in EDGE_FIELD_REGISTRY}


def accumulate_from_extra(detail_sets: dict, extra: Optional[dict]) -> None:
    """
    Read pkt.extra and accumulate values into *detail_sets* in-place.
    No-op when extra is None or empty.
    """
    if not extra:
        return
    for f in EDGE_FIELD_REGISTRY:
        val = extra.get(f["extra_key"])
        if not val:
            continue
        if f["multi"]:
            cap = f["acc_cap"]
            for item in (val[:cap] if cap else val):
                detail_sets[f["edge_key"]].add(item)
        else:
            detail_sets[f["edge_key"]].add(val)


def serialize_detail(detail_sets: dict) -> dict:
    """
    Convert {edge_key: set} → {edge_key: sorted-list} with per-field caps applied.
    Used by the /api/edge/{id}/detail endpoint.
    """
    result = {}
    for f in EDGE_FIELD_REGISTRY:
        vals = sorted(detail_sets[f["edge_key"]])
        cap = f["ser_cap"]
        result[f["edge_key"]] = vals[:cap] if cap else vals
    return result


def has_tls(detail_sets: dict) -> bool:
    return any(detail_sets.get(k) for k in _TLS_KEYS)


def has_http(detail_sets: dict) -> bool:
    return any(detail_sets.get(k) for k in _HTTP_KEYS)


def has_dns(detail_sets: dict) -> bool:
    return any(detail_sets.get(k) for k in _DNS_KEYS)


def meta_for_api() -> list:
    """
    Return a JSON-safe summary of the registry for /api/meta/edge-fields.
    Frontend uses this to build dynamic search keyword hints.
    """
    return [
        {
            "edge_key":     f["edge_key"],
            "hint_keyword": f["hint_keyword"],
            "lazy":         f["lazy"],
        }
        for f in EDGE_FIELD_REGISTRY
    ]
