"""
LLMNR dissector — extracts name resolution queries and responses.

LLMNR (Link-Local Multicast Name Resolution, RFC 4795) runs on UDP port 5355
with multicast address 224.0.0.252 (IPv4) or ff02::1:3 (IPv6). It uses the
same wire format as DNS but is used for local name resolution when DNS fails.

LLMNR is commonly abused in Windows networks for credential relay attacks
(e.g. Responder, NTLM relay). Seeing LLMNR traffic to unexpected responders
is a red flag.

Fields extracted:
  llmnr_query         — queried hostname
  llmnr_qtype         — query type (A, AAAA, ANY, etc.)
  llmnr_qr            — "query" or "response"
  llmnr_answers       — list of answer strings (name → IP)
  llmnr_tc            — True if truncated (TC flag set)
"""

from typing import Dict, Any, List
from . import register_dissector

_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR",
           15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}


@register_dissector("LLMNR")
def dissect_llmnr(pkt) -> Dict[str, Any]:
    """LLMNR uses the same wire format as DNS — try scapy DNS layer first."""
    info: Dict[str, Any] = {}
    try:
        if pkt.haslayer("DNS"):
            dns = pkt["DNS"]
            qr = "response" if getattr(dns, "qr", 0) else "query"
            info["llmnr_qr"] = qr

            # TC flag — truncated responses
            if getattr(dns, "tc", 0):
                info["llmnr_tc"] = True

            # Query
            if dns.qdcount and dns.qd:
                q = dns.qd
                qname = getattr(q, "qname", b"")
                if isinstance(qname, bytes):
                    qname = qname.decode(errors="replace").rstrip(".")
                info["llmnr_query"] = qname
                qtype = getattr(q, "qtype", 0)
                info["llmnr_qtype"] = _QTYPES.get(qtype, str(qtype))

            # Answers (responses)
            answers: List[str] = []
            if dns.ancount and dns.an:
                rr = dns.an
                for _ in range(min(dns.ancount, 10)):
                    if not rr or not hasattr(rr, "rrname"):
                        break
                    rrname = getattr(rr, "rrname", b"")
                    if isinstance(rrname, bytes):
                        rrname = rrname.decode(errors="replace").rstrip(".")
                    rtype = getattr(rr, "type", 0)
                    rdata = getattr(rr, "rdata", None)
                    if rdata:
                        tname = _QTYPES.get(rtype, str(rtype))
                        rdata_str = rdata if isinstance(rdata, str) else str(rdata)
                        answers.append(f"{tname} {rrname} → {rdata_str}")
                    rr = getattr(rr, "payload", None)

            if answers:
                info["llmnr_answers"] = answers[:10]

        elif pkt.haslayer("Raw"):
            _extract_raw(bytes(pkt["Raw"].load), info)

    except Exception:
        # Fall back to raw
        try:
            if pkt.haslayer("Raw"):
                _extract_raw(bytes(pkt["Raw"].load), info)
        except Exception:
            pass
    return info


def _extract_raw(payload: bytes, info: Dict[str, Any]) -> None:
    """Parse LLMNR from raw DNS wire format."""
    if len(payload) < 12:
        return
    flags = (payload[2] << 8) | payload[3]
    qr = "response" if (flags & 0x8000) else "query"
    info["llmnr_qr"] = qr

    if flags & 0x0200:  # TC bit
        info["llmnr_tc"] = True

    qdcount = (payload[4] << 8) | payload[5]
    if qdcount > 0:
        pos = 12
        labels = []
        while pos < len(payload) and payload[pos] != 0:
            llen = payload[pos]
            if llen & 0xC0:
                break
            pos += 1
            if pos + llen > len(payload):
                break
            labels.append(payload[pos:pos + llen].decode(errors="replace"))
            pos += llen
        if labels:
            info["llmnr_query"] = ".".join(labels)
            # Read qtype after null terminator
            pos += 1  # skip null
            if pos + 2 <= len(payload):
                qtype = (payload[pos] << 8) | payload[pos + 1]
                info["llmnr_qtype"] = _QTYPES.get(qtype, str(qtype))
