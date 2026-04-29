"""
Payload signature matchers for protocol detection on non-standard ports.

Each signature is registered with @register_payload_signature and checked
automatically during packet parsing. To add a new one, just add a function here.

Priority guidelines:
  10-15: High confidence, magic bytes (TLS 0x16, SSH "SSH-")
  20-30: Banner detection (SMTP "220...ESMTP", FTP "220...FTP")
  40-60: Heuristic matches (content patterns, statistical)
"""

from . import register_payload_signature


@register_payload_signature("TLS", priority=10)
def _detect_tls(payload: bytes) -> bool:
    """TLS handshake: content type 0x16 + valid version."""
    if len(payload) < 6:
        return False
    return payload[0] == 0x16 and (payload[1], payload[2]) in (
        (0x03, 0x00), (0x03, 0x01), (0x03, 0x02), (0x03, 0x03), (0x03, 0x04),
    )


@register_payload_signature("HTTP", priority=15)
def _detect_http_request(payload: bytes) -> bool:
    """HTTP request: starts with a method verb."""
    return payload[:8].startswith((
        b"GET ", b"POST ", b"PUT ", b"DELETE ",
        b"HEAD ", b"PATCH ", b"OPTIONS ", b"CONNECT ",
    ))


@register_payload_signature("HTTP", priority=16)
def _detect_http_response(payload: bytes) -> bool:
    """HTTP response: starts with HTTP/."""
    return payload[:5] == b"HTTP/"


@register_payload_signature("SSH", priority=20)
def _detect_ssh(payload: bytes) -> bool:
    """SSH banner: starts with SSH-."""
    return payload[:4] == b"SSH-"


@register_payload_signature("SMTP", priority=25)
def _detect_smtp(payload: bytes) -> bool:
    """SMTP greeting: starts with 220 and contains SMTP or ESMTP."""
    if not payload[:3] == b"220":
        return False
    first_line = payload.split(b"\r\n")[0].upper()
    return b"SMTP" in first_line or b"ESMTP" in first_line


@register_payload_signature("FTP", priority=25)
def _detect_ftp(payload: bytes) -> bool:
    """FTP greeting: starts with 220 and contains FTP."""
    if not payload[:3] == b"220":
        return False
    first_line = payload.split(b"\r\n")[0].upper()
    return b"FTP" in first_line
