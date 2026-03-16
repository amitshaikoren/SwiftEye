"""DNS dissector — extracts query/response info using scapy's DNS layer."""

from typing import Dict, Any
from . import register_dissector


@register_dissector("DNS")
def dissect_dns(pkt) -> Dict[str, Any]:
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    info = {}
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        info["dns_id"] = dns.id
        info["dns_qr"] = "response" if dns.qr else "query"
        info["dns_opcode"] = dns.opcode
        info["dns_rcode"] = dns.rcode
        if dns.qd and hasattr(dns.qd, "qname"):
            info["dns_query"] = dns.qd.qname.decode(errors="replace").rstrip(".")
            info["dns_qtype"] = dns.qd.qtype
        if dns.an:
            answers = []
            rr = dns.an
            for _ in range(min(dns.ancount, 10)):
                if rr is None:
                    break
                if hasattr(rr, "rdata"):
                    answers.append(str(rr.rdata))
                rr = rr.payload if hasattr(rr, "payload") and not isinstance(rr.payload, type(None)) else None
            info["dns_answers"] = answers
    return info
