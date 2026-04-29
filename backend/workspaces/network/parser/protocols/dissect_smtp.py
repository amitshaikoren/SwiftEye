"""
SMTP dissector — extracts envelope data, capabilities, and credential indicators.

SMTP is cleartext (unless upgraded via STARTTLS). Commands flow client→server,
responses flow server→client. The dissector handles both directions.

Commands (client→server):
  EHLO/HELO <domain>     — client greeting (domain identifies the client)
  MAIL FROM:<addr>       — envelope sender
  RCPT TO:<addr>         — envelope recipient
  DATA                   — start of message body
  AUTH <mechanism>        — authentication attempt (credential indicator)
  STARTTLS               — upgrade to TLS (subsequent packets are encrypted)
  QUIT                   — session end

Responses (server→client):
  220 <domain> ESMTP      — server greeting (banner)
  250 OK                  — success
  354 Start mail input    — ready for DATA
  5xx                     — error

Fields extracted:
  smtp_command           — last command verb
  smtp_ehlo_domain       — domain from EHLO/HELO
  smtp_mail_from         — envelope sender address
  smtp_rcpt_to           — envelope recipient address
  smtp_response_code     — response code (int)
  smtp_banner            — server software from 220 greeting
  smtp_auth_mechanism    — PLAIN, LOGIN, CRAM-MD5, etc.
  smtp_has_auth          — True if AUTH command seen
  smtp_has_starttls      — True if STARTTLS command seen
  smtp_ehlo_capabilities — capability from EHLO 250- response lines
"""

from typing import Dict, Any
from . import register_dissector


_SMTP_COMMANDS = {
    b"EHLO", b"HELO", b"MAIL", b"RCPT", b"DATA", b"RSET",
    b"VRFY", b"EXPN", b"HELP", b"NOOP", b"QUIT", b"AUTH",
    b"STARTTLS", b"TURN", b"BDAT", b"ATRN", b"ETRN",
}


@register_dissector("SMTP")
def dissect_smtp(pkt) -> Dict[str, Any]:
    if pkt.haslayer("Raw"):
        return _extract(bytes(pkt["Raw"].load))
    return {}


@register_dissector("SMTP-SUB")
def dissect_smtp_sub(pkt) -> Dict[str, Any]:
    if pkt.haslayer("Raw"):
        return _extract(bytes(pkt["Raw"].load))
    return {}


def _extract_address(s: str) -> str:
    """Extract email address from MAIL FROM:<addr> or RCPT TO:<addr>."""
    start = s.find("<")
    end = s.find(">")
    if start >= 0 and end > start:
        return s[start + 1:end].strip()
    # No angle brackets — take everything after the colon
    colon = s.find(":")
    if colon >= 0:
        return s[colon + 1:].strip()
    return s.strip()


def _extract(payload: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        lines = payload.split(b"\r\n")
        if len(lines) <= 1:
            lines = payload.split(b"\n")

        for line in lines[:10]:
            line = line.strip()
            if not line:
                continue

            # Server response: starts with 3-digit code
            if len(line) >= 3 and line[:3].isdigit():
                code = int(line[:3])
                sep = line[3:4]  # '-' for continuation, ' ' for last line
                msg = line[4:].decode(errors="replace").strip() if len(line) > 3 else ""
                info["smtp_response_code"] = code

                # 220 banner
                if code == 220 and "smtp_banner" not in info:
                    info["smtp_banner"] = msg[:200]

                # 250 EHLO capability lines (250-PIPELINING, 250-STARTTLS, etc.)
                if code == 250 and sep == b"-" and msg:
                    cap = msg.split()[0].upper() if msg else ""
                    if cap:
                        info["smtp_ehlo_capability"] = cap
                continue

            # Client command
            upper = line.upper()
            space_pos = line.find(b" ")
            verb = upper[:space_pos] if space_pos > 0 else upper
            arg_raw = line[space_pos + 1:] if space_pos > 0 else b""

            if verb in _SMTP_COMMANDS or verb.startswith(b"MAIL") or verb.startswith(b"RCPT"):
                info["smtp_command"] = verb.decode(errors="replace")

                if verb in (b"EHLO", b"HELO"):
                    domain = arg_raw.decode(errors="replace").strip()
                    info["smtp_ehlo_domain"] = domain[:200]

                elif upper.startswith(b"MAIL FROM"):
                    full = line.decode(errors="replace")
                    addr = _extract_address(full[len("MAIL FROM"):])
                    info["smtp_mail_from"] = addr[:200]

                elif upper.startswith(b"RCPT TO"):
                    full = line.decode(errors="replace")
                    addr = _extract_address(full[len("RCPT TO"):])
                    info["smtp_rcpt_to"] = addr[:200]

                elif verb == b"AUTH":
                    mechanism = arg_raw.decode(errors="replace").strip().split()[0] if arg_raw.strip() else "unknown"
                    info["smtp_auth_mechanism"] = mechanism.upper()[:50]
                    info["smtp_has_auth"] = True

                elif verb == b"STARTTLS":
                    info["smtp_has_starttls"] = True

                break

    except Exception:
        pass
    return info
