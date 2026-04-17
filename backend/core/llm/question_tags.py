"""
Deterministic rule-based question tagger.

Tags are applied in strict precedence order:
  1. Explicit frontend selection (strongest signal)
  2. Scope mode
  3. Entity resolution against loaded capture data
  4. Protocol keywords (DNS / TLS / HTTP / credentials)
  5. Attribution risk keywords
  6. Background / unrelated detection
  7. Default: broad_overview

Multiple tags may be returned (e.g. entity_node + tls).
"""

from __future__ import annotations
import re
from typing import List, Optional, Set

# ── Tag constants ─────────────────────────────────────────────────────────────

TAG_BROAD_OVERVIEW    = "broad_overview"
TAG_ENTITY_NODE       = "entity_node"
TAG_ENTITY_EDGE       = "entity_edge"
TAG_ENTITY_SESSION    = "entity_session"
TAG_ALERT_EVIDENCE    = "alert_evidence"
TAG_DNS               = "dns"
TAG_TLS               = "tls"
TAG_HTTP              = "http"
TAG_CREDENTIALS       = "credentials"
TAG_ATTRIBUTION_RISK  = "attribution_risk"
TAG_BACKGROUND        = "capture_adjacent_background_question"
TAG_MIXED             = "mixed_question"
TAG_UNRELATED         = "unrelated_question"

# ── Protocol keyword sets ─────────────────────────────────────────────────────

_PROTO_DNS   = {"dns", "domain", "resolver", "nameserver", "nxdomain", "dnsbl", "ptr"}
_PROTO_TLS   = {"tls", "ssl", "https", "certificate", "cert", "ja3", "ja4", "sni", "handshake", "cipher"}
_PROTO_HTTP  = {"http", "url", "uri", "user-agent", "useragent", "referer", "host header", "web request"}
_PROTO_CREDS = {"credential", "password", "username", "login", "auth", "ftp", "smtp auth",
                "basic auth", "cleartext", "plain text", "plaintext"}

# ── Attribution risk keywords ─────────────────────────────────────────────────

_ATTRIB_RISK = {
    "attacker", "compromise", "compromised", "malware", "exfiltrat",
    "who is responsible", "c2", "command and control", "beaconing",
    "threat actor", "adversary", "lateral movement", "ransomware",
    "who did", "who caused",
}

# ── Background knowledge keywords ────────────────────────────────────────────

_BACKGROUND_MARKERS = {
    "what is ", "what are ", "explain ", "define ", "how does ", "how do ",
    "describe ", "tell me about ", "what does ", " mean?", " work?",
}

# ── Self-referential capture markers ─────────────────────────────────────────
# Questions about the user's own data in the capture — NOT background knowledge.
# If any of these appear the question is capture-grounded even without an IP literal.

_SELF_REF_CAPTURE = {
    "my ip", "my i.p", "my address", "my computer", "my machine",
    "my device", "my traffic", "my mac", "my host", "my network",
    "which ip is mine", "which ip am i", "am i the",
}

# ── Capture-context directional markers ───────────────────────────────────────
# General "situation" phrases that indicate the question is about the current
# capture rather than abstract background knowledge.

_CAPTURE_CONTEXT_MARKERS = {
    "going on", "happening", "stand out", "stands out", "unusual",
    "this capture", "this pcap", "this traffic", "this file",
    "in here", "in this", "this session", "this network",
}

# ── Explicit off-topic patterns ───────────────────────────────────────────────

_UNRELATED_EXACT = {
    "tell me about cats", "who won the world cup", "what is the weather",
    "tell me a joke", "write a poem",
}

_UNRELATED_PREFIX = (
    "what is your name", "who are you", "how are you", "write me a",
    "create a story", "tell me about sports",
)

# ── IP address pattern ────────────────────────────────────────────────────────

_IP_RE = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'              # IPv4
    r'|'
    r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b'  # IPv6
)


def _lower(text: str) -> str:
    return text.lower()


def tag_question(
    question: str,
    selection_node_ids: List[str],
    selection_edge_id: Optional[str],
    selection_session_id: Optional[str],
    selection_alert_id: Optional[str],
    scope_mode: str,
    known_node_ids: Optional[Set[str]] = None,
    known_edge_ids: Optional[Set[str]] = None,
    known_session_ids: Optional[Set[str]] = None,
    known_alert_ids: Optional[Set[str]] = None,
) -> List[str]:
    """
    Return a list of tags describing the question, in priority order.
    Always returns at least one tag. Never returns an empty list.

    Parameters
    ----------
    question            : the user's question text
    selection_*         : explicit frontend selection state (strongest signal)
    scope_mode          : "full_capture" | "current_view" | "selected_entity"
    known_*             : sets of IDs present in the current capture (for entity resolution)
    """
    tags: List[str] = []
    q = _lower(question.strip())

    # ── 1. Explicit selection ────────────────────────────────────────────────
    if selection_alert_id:
        tags.append(TAG_ALERT_EVIDENCE)
    elif selection_edge_id:
        tags.append(TAG_ENTITY_EDGE)
    elif selection_session_id:
        tags.append(TAG_ENTITY_SESSION)
    elif selection_node_ids:
        tags.append(TAG_ENTITY_NODE)

    # ── 2. Scope mode ────────────────────────────────────────────────────────
    # Scope mode refines but does not override selection signal.
    if scope_mode == "selected_entity" and not tags:
        # User intends a scoped answer but nothing is selected — leave for fallback
        pass

    # ── 3. Entity resolution against capture ─────────────────────────────────
    if not tags:
        # Check if any IP/hostname in the question matches a known node
        if known_node_ids:
            # Extract IPs from question
            found_ips = _IP_RE.findall(question)
            for ip in found_ips:
                if ip in known_node_ids:
                    tags.append(TAG_ENTITY_NODE)
                    break
        if not tags and known_edge_ids:
            # Edge IDs are "src|dst|protocol" — not typically typed by users,
            # but check for explicit edge references
            for eid in (known_edge_ids or set()):
                if eid.lower() in q:
                    tags.append(TAG_ENTITY_EDGE)
                    break
        if not tags and known_alert_ids:
            for aid in (known_alert_ids or set()):
                if aid.lower() in q:
                    tags.append(TAG_ALERT_EVIDENCE)
                    break

    # ── 4. Protocol keywords ─────────────────────────────────────────────────
    # Stackable on top of entity tags
    if any(kw in q for kw in _PROTO_DNS):
        tags.append(TAG_DNS)
    if any(kw in q for kw in _PROTO_TLS):
        tags.append(TAG_TLS)
    if any(kw in q for kw in _PROTO_HTTP):
        tags.append(TAG_HTTP)
    if any(kw in q for kw in _PROTO_CREDS):
        tags.append(TAG_CREDENTIALS)

    # ── 5. Attribution risk ───────────────────────────────────────────────────
    if any(kw in q for kw in _ATTRIB_RISK):
        tags.append(TAG_ATTRIBUTION_RISK)

    # ── 6. Background / unrelated ────────────────────────────────────────────
    # Also fires when tags contains only protocol keywords — a background question
    # like "What is DNS tunneling?" legitimately carries a protocol tag but still
    # needs to be classified as background/mixed, not just DNS.
    _PROTO_TAGS = {TAG_DNS, TAG_TLS, TAG_HTTP, TAG_CREDENTIALS}
    proto_only = bool(tags) and all(t in _PROTO_TAGS for t in tags)
    if not tags or tags == [TAG_ATTRIBUTION_RISK] or proto_only:
        # Check unrelated first (harder gate)
        if _is_unrelated(q):
            return [TAG_UNRELATED]

        # Background: general knowledge question with no capture references
        has_capture_ref = bool(
            selection_node_ids or selection_edge_id or selection_session_id or selection_alert_id
            or _IP_RE.search(question)
            or (known_node_ids and any(nid in q for nid in known_node_ids))
            or any(marker in q for marker in _SELF_REF_CAPTURE)
            or any(marker in q for marker in _CAPTURE_CONTEXT_MARKERS)
        )
        is_background_phrasing = any(q.startswith(marker) or marker in q for marker in _BACKGROUND_MARKERS)

        if is_background_phrasing and not has_capture_ref:
            # Could be mixed (background question + capture context possible)
            # Check if there's any capture-relevant protocol in the question
            has_proto = bool(set(tags) & {TAG_DNS, TAG_TLS, TAG_HTTP, TAG_CREDENTIALS})
            if has_proto:
                # "What is DNS tunneling?" + current DNS capture → mixed
                tags.insert(0, TAG_MIXED)
                return list(dict.fromkeys(tags))  # dedup, preserve order
            else:
                return [TAG_BACKGROUND]

    # ── 7. Default fallback ───────────────────────────────────────────────────
    if not tags:
        return [TAG_BROAD_OVERVIEW]

    # Deduplicate, preserve order
    return list(dict.fromkeys(tags))


def _is_unrelated(q: str) -> bool:
    """Return True if the question is clearly off-topic."""
    if q.strip("?. ") in _UNRELATED_EXACT:
        return True
    if any(q.startswith(prefix) for prefix in _UNRELATED_PREFIX):
        return True
    return False
