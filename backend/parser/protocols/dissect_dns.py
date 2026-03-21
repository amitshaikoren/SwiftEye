"""DNS dissector — extracts query/response info using scapy's DNS layer."""

from typing import Dict, Any, List
from scapy.layers.dns import DNS, DNSQR, DNSRR
from . import register_dissector


# DNS record type number → human name
_QTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS",
    46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3",
    52: "TLSA", 64: "SVCB", 65: "HTTPS", 99: "SPF", 255: "ANY",
    257: "CAA",
}

# DNS response code number → name
_RCODE_NAMES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET",
    8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE",
}

# DNS opcode number → name
_OPCODE_NAMES = {
    0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE",
}


def _qtype_name(qtype: int) -> str:
    return _QTYPE_NAMES.get(qtype, f"TYPE{qtype}")


def _rcode_name(rcode: int) -> str:
    return _RCODE_NAMES.get(rcode, f"RCODE{rcode}")


def _decode_name(raw) -> str:
    """Decode a DNS name field from bytes or string."""
    if isinstance(raw, bytes):
        return raw.decode(errors="replace").rstrip(".")
    return str(raw).rstrip(".")


def _parse_rr_section(rr, max_count: int) -> List[Dict[str, Any]]:
    """Walk a chain of DNS resource records and extract structured data."""
    records = []
    for _ in range(max_count):
        if rr is None:
            break
        rec = {}
        if hasattr(rr, "rrname"):
            rec["name"] = _decode_name(rr.rrname)
        if hasattr(rr, "type"):
            rec["type"] = rr.type
            rec["type_name"] = _qtype_name(rr.type)
        if hasattr(rr, "ttl"):
            rec["ttl"] = rr.ttl
        if hasattr(rr, "rdata"):
            rdata = rr.rdata
            if isinstance(rdata, bytes):
                try:
                    rec["data"] = rdata.decode("utf-8").rstrip(".")
                except Exception:
                    rec["data"] = rdata.hex()
            else:
                rec["data"] = str(rdata).rstrip(".")
        if hasattr(rr, "rclass"):
            rec["class"] = rr.rclass
        if rec:
            records.append(rec)
        rr = rr.payload if hasattr(rr, "payload") and not isinstance(rr.payload, type(None)) else None
        if rr is not None and rr.__class__.__name__ == "NoPayload":
            break
    return records


@register_dissector("DNS")
def dissect_dns(pkt) -> Dict[str, Any]:
    info = {}
    if not pkt.haslayer(DNS):
        return info

    dns = pkt[DNS]

    # Header fields
    info["dns_id"] = dns.id
    info["dns_qr"] = "response" if dns.qr else "query"
    info["dns_opcode"] = dns.opcode
    info["dns_opcode_name"] = _OPCODE_NAMES.get(dns.opcode, f"OP{dns.opcode}")
    info["dns_rcode"] = dns.rcode
    info["dns_rcode_name"] = _rcode_name(dns.rcode)

    # Flags
    info["dns_aa"] = bool(dns.aa)  # authoritative answer
    info["dns_tc"] = bool(dns.tc)  # truncated
    info["dns_rd"] = bool(dns.rd)  # recursion desired
    info["dns_ra"] = bool(dns.ra)  # recursion available

    # Section counts
    info["dns_qdcount"] = dns.qdcount
    info["dns_ancount"] = dns.ancount
    info["dns_nscount"] = dns.nscount
    info["dns_arcount"] = dns.arcount

    # Question section
    if dns.qd and hasattr(dns.qd, "qname"):
        info["dns_query"] = _decode_name(dns.qd.qname)
        info["dns_qtype"] = dns.qd.qtype
        info["dns_qtype_name"] = _qtype_name(dns.qd.qtype)
        if hasattr(dns.qd, "qclass"):
            info["dns_qclass"] = dns.qd.qclass
            _qclass_names = {1: "IN", 3: "CH", 4: "HS", 254: "NONE", 255: "ANY"}
            info["dns_qclass_name"] = _qclass_names.get(dns.qd.qclass, f"CLASS{dns.qd.qclass}")

    # Answer section (structured records)
    if dns.an and dns.ancount > 0:
        answer_records = _parse_rr_section(dns.an, min(dns.ancount, 20))
        info["dns_answer_records"] = answer_records
        # Flat list of answer data strings for backwards compat
        info["dns_answers"] = [r.get("data", "") for r in answer_records if r.get("data")]

    # Authority section (NS, SOA)
    if dns.ns and dns.nscount > 0:
        info["dns_authority_records"] = _parse_rr_section(dns.ns, min(dns.nscount, 10))

    # Additional section (e.g. EDNS0 OPT, glue records)
    if dns.ar and dns.arcount > 0:
        info["dns_additional_records"] = _parse_rr_section(dns.ar, min(dns.arcount, 10))

    return info
