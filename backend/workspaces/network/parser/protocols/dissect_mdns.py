"""
mDNS dissector — extracts service discovery data from multicast DNS.

mDNS (RFC 6762) runs on UDP port 5353 with multicast address 224.0.0.251
(IPv4) or ff02::fb (IPv6). It uses the same wire format as DNS but serves
local network service discovery. Often paired with DNS-SD (RFC 6763).

Fields extracted:
  mdns_query          — queried name (e.g. "_http._tcp.local")
  mdns_qtype          — query type (A, AAAA, PTR, SRV, TXT, ANY)
  mdns_qr             — "query" or "response"
  mdns_answers        — list of answer strings (name → data)
  mdns_service_type   — service type from PTR answers (e.g. "_http._tcp")
  mdns_service_name   — service instance name (e.g. "My Printer._http._tcp.local")
  mdns_txt_records    — TXT record key=value pairs
  mdns_hostname       — target hostname from SRV records
  mdns_port           — port from SRV records
"""

from typing import Dict, Any, List
from scapy.layers.dns import DNS
from . import register_dissector

_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
           15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 47: "NSEC", 255: "ANY"}


@register_dissector("mDNS", scapy_layer=DNS)
def dissect_mdns(pkt) -> Dict[str, Any]:
    """Try scapy DNS layer first (mDNS uses DNS wire format), fall back to raw."""
    info: Dict[str, Any] = {}
    try:
        if pkt.haslayer("DNS"):
            dns = pkt["DNS"]
            qr = "response" if getattr(dns, "qr", 0) else "query"
            info["mdns_qr"] = qr

            # Queries
            if dns.qdcount and dns.qd:
                q = dns.qd
                qname = getattr(q, "qname", b"")
                if isinstance(qname, bytes):
                    qname = qname.decode(errors="replace").rstrip(".")
                info["mdns_query"] = qname
                qtype = getattr(q, "qtype", 0)
                info["mdns_qtype"] = _QTYPES.get(qtype, str(qtype))

                # Detect service type from query name
                if "._tcp" in qname or "._udp" in qname:
                    info["mdns_service_type"] = qname

            # Answers
            answers: List[str] = []
            txt_records: List[str] = []
            for section_name in ("an", "ar"):
                section = getattr(dns, section_name, None)
                if not section:
                    continue
                rr = section
                while rr:
                    rrname = getattr(rr, "rrname", b"")
                    if isinstance(rrname, bytes):
                        rrname = rrname.decode(errors="replace").rstrip(".")
                    rtype = getattr(rr, "type", 0)
                    rdata = getattr(rr, "rdata", None)

                    if rtype == 12:  # PTR
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode(errors="replace").rstrip(".")
                        if rdata:
                            answers.append(f"PTR {rrname} → {rdata}")
                            if "._tcp" in str(rdata) or "._udp" in str(rdata):
                                info["mdns_service_name"] = str(rdata)
                            if "._tcp" in rrname or "._udp" in rrname:
                                info["mdns_service_type"] = rrname

                    elif rtype == 33:  # SRV
                        target = getattr(rr, "target", b"")
                        if isinstance(target, bytes):
                            target = target.decode(errors="replace").rstrip(".")
                        port = getattr(rr, "port", 0)
                        if target:
                            answers.append(f"SRV {rrname} → {target}:{port}")
                            info["mdns_hostname"] = target
                            info["mdns_port"] = port

                    elif rtype == 16:  # TXT
                        # TXT records can be in rdata as bytes or list
                        txt_data = rdata
                        if isinstance(txt_data, bytes):
                            # Parse length-prefixed TXT strings
                            pos = 0
                            while pos < len(txt_data):
                                tlen = txt_data[pos]
                                pos += 1
                                if tlen > 0 and pos + tlen <= len(txt_data):
                                    txt_str = txt_data[pos:pos + tlen].decode(errors="replace")
                                    txt_records.append(txt_str)
                                pos += tlen
                        elif isinstance(txt_data, (list, tuple)):
                            for t in txt_data:
                                if isinstance(t, bytes):
                                    txt_records.append(t.decode(errors="replace"))
                                else:
                                    txt_records.append(str(t))
                        if txt_records:
                            answers.append(f"TXT {rrname}: {'; '.join(txt_records[:5])}")

                    elif rtype in (1, 28):  # A / AAAA
                        if rdata:
                            tname = "A" if rtype == 1 else "AAAA"
                            rdata_str = rdata if isinstance(rdata, str) else str(rdata)
                            answers.append(f"{tname} {rrname} → {rdata_str}")

                    rr = getattr(rr, "payload", None)
                    if rr and not hasattr(rr, "rrname"):
                        break

            if answers:
                info["mdns_answers"] = answers[:20]
            if txt_records:
                info["mdns_txt_records"] = txt_records[:20]

    except Exception:
        # Fall back to raw parsing for basic query extraction
        try:
            if pkt.haslayer("Raw"):
                _extract_raw(bytes(pkt["Raw"].load), info)
        except Exception:
            pass
    return info


def _extract_raw(payload: bytes, info: Dict[str, Any]) -> None:
    """Minimal raw DNS wire format extraction for mDNS."""
    if len(payload) < 12:
        return
    flags = (payload[2] << 8) | payload[3]
    qr = "response" if (flags & 0x8000) else "query"
    info["mdns_qr"] = qr
    qdcount = (payload[4] << 8) | payload[5]

    if qdcount > 0:
        # Parse first query name
        pos = 12
        labels = []
        while pos < len(payload) and payload[pos] != 0:
            llen = payload[pos]
            if llen & 0xC0:  # compression pointer
                break
            pos += 1
            if pos + llen > len(payload):
                break
            labels.append(payload[pos:pos + llen].decode(errors="replace"))
            pos += llen
        if labels:
            info["mdns_query"] = ".".join(labels)
