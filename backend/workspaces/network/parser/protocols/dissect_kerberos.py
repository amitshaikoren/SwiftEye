"""
Kerberos dissector — extracts message type, principal names, encryption types, realm.

Kerberos runs on TCP/UDP port 88. The protocol uses ASN.1 DER encoding.
The outer structure is an APPLICATION tag that identifies the message type:

  Tag 10 (0x6a) = AS-REQ   (client → KDC: initial authentication request)
  Tag 11 (0x6b) = AS-REP   (KDC → client: authentication reply with TGT)
  Tag 12 (0x6c) = TGS-REQ  (client → KDC: service ticket request)
  Tag 13 (0x6d) = TGS-REP  (KDC → client: service ticket reply)
  Tag 14 (0x6e) = AP-REQ   (client → service: authenticate with ticket)
  Tag 15 (0x6f) = AP-REP   (service → client: authentication confirmation)
  Tag 20 (0x74) = KRB-SAFE  (integrity-protected user data)
  Tag 21 (0x75) = KRB-PRIV  (encrypted user data)
  Tag 22 (0x76) = KRB-CRED  (forwarded credentials)
  Tag 30 (0x7e) = KRB-ERROR (error response)

Fields extracted:
  krb_msg_type      — human-readable message type (AS-REQ, TGS-REP, etc.)
  krb_msg_type_num  — numeric message type
  krb_realm         — Kerberos realm (e.g. "EXAMPLE.COM")
  krb_cname         — client principal name (from AS-REQ/TGS-REQ)
  krb_sname         — service principal name (e.g. "krbtgt/EXAMPLE.COM")
  krb_error_code    — error code from KRB-ERROR messages
  krb_error_name    — human-readable error name
  krb_etypes        — list of encryption types offered (from REQ messages)
"""

from typing import Dict, Any, List
import struct
from . import register_dissector, register_payload_signature


_MSG_TYPES = {
    10: "AS-REQ",    11: "AS-REP",
    12: "TGS-REQ",   13: "TGS-REP",
    14: "AP-REQ",    15: "AP-REP",
    20: "KRB-SAFE",  21: "KRB-PRIV",
    22: "KRB-CRED",  30: "KRB-ERROR",
}

_ERROR_CODES = {
    0: "KDC_ERR_NONE",
    6: "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    7: "KDC_ERR_S_PRINCIPAL_UNKNOWN",
    12: "KDC_ERR_POLICY",
    13: "KDC_ERR_BADOPTION",
    14: "KDC_ERR_ETYPE_NOSUPP",
    17: "KDC_ERR_KEY_EXPIRED",
    18: "KDC_ERR_PREAUTH_FAILED",
    23: "KDC_ERR_PREAUTH_REQUIRED",
    24: "KDC_ERR_SERVER_NOMATCH",
    25: "KDC_ERR_MUST_USE_USER2USER",
    31: "KRB_AP_ERR_BAD_INTEGRITY",
    32: "KRB_AP_ERR_TKT_EXPIRED",
    33: "KRB_AP_ERR_TKT_NYV",
    34: "KRB_AP_ERR_REPEAT",
    36: "KRB_AP_ERR_MODIFIED",
    37: "KRB_AP_ERR_BADORDER",
    41: "KRB_AP_ERR_BADKEYVER",
    44: "KRB_AP_ERR_NOKEY",
    60: "KRB_ERR_GENERIC",
    68: "KDC_ERR_WRONG_REALM",
}

_ETYPE_NAMES = {
    1: "des-cbc-crc", 3: "des-cbc-md5", 17: "aes128-cts-hmac-sha1-96",
    18: "aes256-cts-hmac-sha1-96", 23: "rc4-hmac", 24: "rc4-hmac-exp",
    -128: "rc4-hmac-old",
}


@register_payload_signature("Kerberos", priority=16)
def _detect_kerberos(payload: bytes) -> bool:
    """Detect Kerberos by ASN.1 APPLICATION tags."""
    if len(payload) < 4:
        return False
    tag = payload[0]
    # APPLICATION CONSTRUCTED tags for Kerberos message types
    # AS-REQ=0x6a, AS-REP=0x6b, TGS-REQ=0x6c, TGS-REP=0x6d,
    # AP-REQ=0x6e, AP-REP=0x6f, KRB-ERROR=0x7e
    return tag in (0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x74, 0x75, 0x76, 0x7e)


@register_dissector("Kerberos")
def dissect_kerberos(pkt) -> Dict[str, Any]:
    if pkt.haslayer("Raw"):
        return _extract(bytes(pkt["Raw"].load))
    return {}


def _extract(payload: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        if len(payload) < 4:
            return info

        tag = payload[0]
        # APPLICATION tag encodes message type: tag & 0x1f
        msg_type = tag & 0x1f
        info["krb_msg_type_num"] = msg_type
        info["krb_msg_type"] = _MSG_TYPES.get(msg_type, f"MSG-{msg_type}")

        # Parse ASN.1 length
        off = 1
        length, off = _asn1_length(payload, off)
        if length <= 0 or off >= len(payload):
            return info

        # Inner SEQUENCE
        if off < len(payload) and payload[off] == 0x30:
            off += 1
            seq_len, off = _asn1_length(payload, off)

            # Walk context-tagged fields in the SEQUENCE
            end = min(off + seq_len, len(payload))
            while off < end:
                if off >= len(payload):
                    break
                ctx_tag = payload[off]
                off += 1
                field_len, off = _asn1_length(payload, off)
                field_end = min(off + field_len, len(payload))

                ctx_num = ctx_tag & 0x1f

                if msg_type in (10, 12):  # AS-REQ, TGS-REQ
                    if ctx_num == 1:  # req-body
                        _parse_kdc_req_body(payload[off:field_end], info)
                elif msg_type in (11, 13):  # AS-REP, TGS-REP
                    if ctx_num == 3:  # crealm
                        realm = _asn1_string(payload, off, field_end)
                        if realm:
                            info["krb_realm"] = realm
                    elif ctx_num == 4:  # cname
                        name = _parse_principal(payload[off:field_end])
                        if name:
                            info["krb_cname"] = name
                elif msg_type == 30:  # KRB-ERROR
                    if ctx_num == 6:  # error-code
                        code = _asn1_int(payload, off, field_end)
                        if code is not None:
                            info["krb_error_code"] = code
                            info["krb_error_name"] = _ERROR_CODES.get(code, f"ERR-{code}")
                    elif ctx_num == 7:  # crealm
                        realm = _asn1_string(payload, off, field_end)
                        if realm:
                            info["krb_realm"] = realm
                    elif ctx_num == 9:  # sname
                        name = _parse_principal(payload[off:field_end])
                        if name:
                            info["krb_sname"] = name
                    elif ctx_num == 11:  # e-text
                        text = _asn1_string(payload, off, field_end)
                        if text:
                            info["krb_error_text"] = text

                off = field_end

    except Exception:
        pass
    return info


def _parse_kdc_req_body(data: bytes, info: Dict[str, Any]):
    """Parse KDC-REQ-BODY to extract realm, cname, sname, etypes."""
    try:
        off = 0
        if off >= len(data) or data[off] != 0x30:
            return
        off += 1
        seq_len, off = _asn1_length(data, off)
        end = min(off + seq_len, len(data))

        while off < end:
            if off >= len(data):
                break
            ctx_tag = data[off]
            off += 1
            field_len, off = _asn1_length(data, off)
            field_end = min(off + field_len, len(data))
            ctx_num = ctx_tag & 0x1f

            if ctx_num == 1:  # cname
                name = _parse_principal(data[off:field_end])
                if name:
                    info["krb_cname"] = name
            elif ctx_num == 2:  # realm
                realm = _asn1_string(data, off, field_end)
                if realm:
                    info["krb_realm"] = realm
            elif ctx_num == 3:  # sname
                name = _parse_principal(data[off:field_end])
                if name:
                    info["krb_sname"] = name
            elif ctx_num == 8:  # etype (SEQUENCE OF INTEGER)
                etypes = _parse_etypes(data[off:field_end])
                if etypes:
                    info["krb_etypes"] = etypes

            off = field_end
    except Exception:
        pass


def _parse_etypes(data: bytes) -> List[str]:
    """Parse SEQUENCE OF INTEGER for encryption types."""
    etypes = []
    try:
        off = 0
        if off >= len(data) or data[off] != 0x30:
            return etypes
        off += 1
        seq_len, off = _asn1_length(data, off)
        end = min(off + seq_len, len(data))
        while off < end:
            if data[off] != 0x02:  # INTEGER
                break
            off += 1
            int_len, off = _asn1_length(data, off)
            val = int.from_bytes(data[off:off + int_len], "big", signed=True)
            etypes.append(_ETYPE_NAMES.get(val, f"etype-{val}"))
            off += int_len
    except Exception:
        pass
    return etypes


def _parse_principal(data: bytes) -> str:
    """Parse PrincipalName SEQUENCE to extract name-string."""
    try:
        off = 0
        if off >= len(data) or data[off] != 0x30:
            return ""
        off += 1
        seq_len, off = _asn1_length(data, off)
        end = min(off + seq_len, len(data))
        parts = []
        while off < end:
            ctx_tag = data[off]
            off += 1
            field_len, off = _asn1_length(data, off)
            field_end = min(off + field_len, len(data))
            ctx_num = ctx_tag & 0x1f
            if ctx_num == 1:  # name-string: SEQUENCE OF GeneralString
                soff = off
                if soff < field_end and data[soff] == 0x30:
                    soff += 1
                    sseq_len, soff = _asn1_length(data, soff)
                    send = min(soff + sseq_len, field_end)
                    while soff < send:
                        if data[soff] == 0x1b:  # GeneralString
                            soff += 1
                            slen, soff = _asn1_length(data, soff)
                            parts.append(data[soff:soff + slen].decode(errors="replace"))
                            soff += slen
                        else:
                            break
            off = field_end
        return "/".join(parts) if parts else ""
    except Exception:
        return ""


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


def _asn1_string(data: bytes, off: int, end: int) -> str:
    """Extract a string from a GeneralString/UTF8String/IA5String at off."""
    try:
        if off >= end:
            return ""
        tag = data[off]
        off += 1
        slen, off = _asn1_length(data, off)
        return data[off:off + slen].decode(errors="replace")
    except Exception:
        return ""


def _asn1_int(data: bytes, off: int, end: int):
    """Extract an INTEGER value."""
    try:
        if off >= end or data[off] != 0x02:
            return None
        off += 1
        ilen, off = _asn1_length(data, off)
        return int.from_bytes(data[off:off + ilen], "big", signed=True)
    except Exception:
        return None
