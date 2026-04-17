"""
LDAP dissector — extracts operation type, DN, filter, result code, and attributes.

LDAP runs on TCP port 389 (cleartext) and 636 (LDAPS/TLS). The protocol uses
ASN.1 BER encoding. Each LDAP message is a SEQUENCE containing:
  - messageID (INTEGER)
  - protocolOp (APPLICATION tagged, identifies the operation)
  - optional controls

APPLICATION tags for protocolOp:
  0  = BindRequest        10 = SearchRequest
  1  = BindResponse       11 = SearchResultEntry
  2  = UnbindRequest      12 = SearchResultDone
  3  = SearchRequest      13 = SearchResultReference
  4  = SearchResultEntry  14 = ModifyRequest
  5  = SearchResultDone   15 = ModifyResponse
  6  = ModifyRequest      16 = AddRequest
  7  = ModifyResponse     17 = AddResponse
  8  = AddRequest         18 = DelRequest
  9  = AddResponse        19 = DelResponse

  Actually per RFC 4511:
  0  = BindRequest       7  = ModifyResponse
  1  = BindResponse      8  = AddRequest
  2  = UnbindRequest     9  = AddResponse
  3  = SearchRequest    10  = DelRequest
  4  = SearchResEntry   11  = DelResponse
  5  = SearchResDone    12  = ModDNRequest
  6  = ModifyRequest    13  = ModDNResponse
                        14  = CompareRequest
                        15  = CompareResponse
                        19  = SearchResRef
                        23  = ExtendedRequest
                        24  = ExtendedResponse
                        25  = IntermediateResponse

Fields extracted:
  ldap_op              — operation name (BindRequest, SearchRequest, etc.)
  ldap_op_num          — numeric operation tag
  ldap_message_id      — LDAP message ID
  ldap_result_code     — result code (for response messages)
  ldap_result_name     — human-readable result name
  ldap_bind_dn         — DN from BindRequest
  ldap_bind_mechanism  — SASL mechanism name (GSSAPI, PLAIN, etc.)
  ldap_search_base     — base DN from SearchRequest
  ldap_search_filter   — search filter string (simplified)
  ldap_search_scope    — scope: base/one/sub
  ldap_entry_dn        — DN from SearchResultEntry
  ldap_attributes      — list of attribute names from SearchResultEntry
"""

from typing import Dict, Any, List
from . import register_dissector, register_payload_signature


_OP_NAMES = {
    0: "BindRequest",     1: "BindResponse",
    2: "UnbindRequest",   3: "SearchRequest",
    4: "SearchResEntry",  5: "SearchResDone",
    6: "ModifyRequest",   7: "ModifyResponse",
    8: "AddRequest",      9: "AddResponse",
    10: "DelRequest",     11: "DelResponse",
    12: "ModDNRequest",   13: "ModDNResponse",
    14: "CompareRequest", 15: "CompareResponse",
    19: "SearchResRef",
    23: "ExtendedRequest", 24: "ExtendedResponse",
    25: "IntermediateResponse",
}

_RESULT_CODES = {
    0: "success",
    1: "operationsError",
    2: "protocolError",
    3: "timeLimitExceeded",
    4: "sizeLimitExceeded",
    7: "authMethodNotSupported",
    8: "strongerAuthRequired",
    10: "referral",
    11: "adminLimitExceeded",
    13: "confidentialityRequired",
    14: "saslBindInProgress",
    16: "noSuchAttribute",
    32: "noSuchObject",
    34: "invalidDNSyntax",
    48: "inappropriateAuthentication",
    49: "invalidCredentials",
    50: "insufficientAccessRights",
    51: "busy",
    52: "unavailable",
    53: "unwillingToPerform",
    65: "objectClassViolation",
    68: "entryAlreadyExists",
    80: "other",
}

_SEARCH_SCOPES = {0: "base", 1: "one", 2: "sub"}


@register_payload_signature("LDAP", priority=22)
def _detect_ldap(payload: bytes) -> bool:
    """Detect LDAP by checking for ASN.1 SEQUENCE wrapping an INTEGER messageID
    followed by an APPLICATION-tagged protocolOp."""
    if len(payload) < 7:
        return False
    # Outer SEQUENCE
    if payload[0] != 0x30:
        return False
    off = 1
    length, off = _asn1_length(payload, off)
    if length <= 0 or off >= len(payload):
        return False
    # messageID should be an INTEGER
    if payload[off] != 0x02:
        return False
    off += 1
    id_len, off = _asn1_length(payload, off)
    off += id_len
    if off >= len(payload):
        return False
    # protocolOp should be APPLICATION tagged (0x60-0x7f)
    tag = payload[off]
    return 0x60 <= tag <= 0x7f


@register_dissector("LDAP")
def dissect_ldap(pkt) -> Dict[str, Any]:
    if pkt.haslayer("Raw"):
        return _extract(bytes(pkt["Raw"].load))
    return {}


@register_dissector("LDAPS")
def dissect_ldaps(pkt) -> Dict[str, Any]:
    # LDAPS is LDAP over TLS — the Raw layer will be encrypted
    # We can only extract from the TLS-decrypted content, which scapy usually can't do
    # So this dissector won't produce much for encrypted traffic
    if pkt.haslayer("Raw"):
        return _extract(bytes(pkt["Raw"].load))
    return {}


def _extract(payload: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        if len(payload) < 7 or payload[0] != 0x30:
            return info

        off = 1
        length, off = _asn1_length(payload, off)
        if length <= 0:
            return info

        # messageID (INTEGER)
        if off >= len(payload) or payload[off] != 0x02:
            return info
        off += 1
        id_len, off = _asn1_length(payload, off)
        msg_id = int.from_bytes(payload[off:off + id_len], "big")
        info["ldap_message_id"] = msg_id
        off += id_len

        if off >= len(payload):
            return info

        # protocolOp (APPLICATION tagged)
        op_tag = payload[off]
        op_num = op_tag & 0x1f
        info["ldap_op_num"] = op_num
        info["ldap_op"] = _OP_NAMES.get(op_num, f"Op-{op_num}")
        off += 1
        op_len, off = _asn1_length(payload, off)
        op_end = min(off + op_len, len(payload))

        # Parse specific operations
        if op_num == 0:  # BindRequest
            _parse_bind_request(payload, off, op_end, info)
        elif op_num == 1:  # BindResponse
            _parse_ldap_result(payload, off, op_end, info)
        elif op_num == 3:  # SearchRequest
            _parse_search_request(payload, off, op_end, info)
        elif op_num == 4:  # SearchResultEntry
            _parse_search_entry(payload, off, op_end, info)
        elif op_num in (5, 7, 9, 11, 13, 15, 24):  # Various *Response / *Done
            _parse_ldap_result(payload, off, op_end, info)

    except Exception:
        pass
    return info


def _parse_bind_request(data: bytes, off: int, end: int, info: Dict[str, Any]):
    """BindRequest: version(INT), name(OCTET STRING), auth(CHOICE)."""
    try:
        # version
        if off >= end or data[off] != 0x02:
            return
        off += 1
        vlen, off = _asn1_length(data, off)
        off += vlen
        # name (DN)
        if off >= end or data[off] != 0x04:
            return
        off += 1
        nlen, off = _asn1_length(data, off)
        dn = data[off:off + nlen].decode(errors="replace")
        if dn:
            info["ldap_bind_dn"] = dn
        off += nlen
        # auth: context tag 0 = simple, 3 = SASL
        if off < end:
            auth_tag = data[off]
            if (auth_tag & 0x1f) == 3:  # SASL
                off += 1
                auth_len, off = _asn1_length(data, off)
                # mechanism is first OCTET STRING
                if off < end and data[off] == 0x04:
                    off += 1
                    mlen, off = _asn1_length(data, off)
                    info["ldap_bind_mechanism"] = data[off:off + mlen].decode(errors="replace")
            elif (auth_tag & 0x1f) == 0:  # simple bind
                info["ldap_bind_mechanism"] = "simple"
    except Exception:
        pass


def _parse_ldap_result(data: bytes, off: int, end: int, info: Dict[str, Any]):
    """LDAPResult: resultCode(ENUM), matchedDN(OCTET STRING), diagnosticMessage(OCTET STRING)."""
    try:
        # resultCode (ENUMERATED, tag 0x0a)
        if off >= end or data[off] != 0x0a:
            return
        off += 1
        rlen, off = _asn1_length(data, off)
        code = int.from_bytes(data[off:off + rlen], "big")
        info["ldap_result_code"] = code
        info["ldap_result_name"] = _RESULT_CODES.get(code, f"code-{code}")
    except Exception:
        pass


def _parse_search_request(data: bytes, off: int, end: int, info: Dict[str, Any]):
    """SearchRequest: baseObject, scope, derefAliases, sizeLimit, timeLimit, typesOnly, filter, attributes."""
    try:
        # baseObject (OCTET STRING)
        if off >= end or data[off] != 0x04:
            return
        off += 1
        blen, off = _asn1_length(data, off)
        base = data[off:off + blen].decode(errors="replace")
        if base:
            info["ldap_search_base"] = base
        off += blen
        # scope (ENUMERATED)
        if off >= end or data[off] != 0x0a:
            return
        off += 1
        slen, off = _asn1_length(data, off)
        scope = data[off]
        info["ldap_search_scope"] = _SEARCH_SCOPES.get(scope, f"scope-{scope}")
        off += slen
    except Exception:
        pass


def _parse_search_entry(data: bytes, off: int, end: int, info: Dict[str, Any]):
    """SearchResultEntry: objectName (OCTET STRING), attributes (SEQUENCE)."""
    try:
        # objectName
        if off >= end or data[off] != 0x04:
            return
        off += 1
        nlen, off = _asn1_length(data, off)
        dn = data[off:off + nlen].decode(errors="replace")
        if dn:
            info["ldap_entry_dn"] = dn
        off += nlen
        # attributes: SEQUENCE OF SEQUENCE { type, vals }
        if off < end and data[off] == 0x30:
            off += 1
            alen, off = _asn1_length(data, off)
            aend = min(off + alen, end)
            attrs = []
            while off < aend and len(attrs) < 20:
                if data[off] != 0x30:
                    break
                off += 1
                item_len, off = _asn1_length(data, off)
                item_end = min(off + item_len, aend)
                # attribute type (OCTET STRING)
                if off < item_end and data[off] == 0x04:
                    off += 1
                    tlen, off = _asn1_length(data, off)
                    attrs.append(data[off:off + tlen].decode(errors="replace"))
                off = item_end
            if attrs:
                info["ldap_attributes"] = attrs
    except Exception:
        pass


def _asn1_length(data: bytes, off: int):
    """Parse ASN.1 length and return (length, new_offset)."""
    if off >= len(data):
        return 0, off
    b = data[off]
    off += 1
    if b < 0x80:
        return b, off
    num_bytes = b & 0x7f
    if num_bytes == 0 or off + num_bytes > len(data):
        return 0, off
    length = int.from_bytes(data[off:off + num_bytes], "big")
    return length, off + num_bytes
