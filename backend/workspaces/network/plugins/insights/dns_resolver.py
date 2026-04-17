"""
DNS Hostname Resolver Plugin for SwiftEye.

Correlates DNS response packets with IP addresses to build an IP → hostname map.
This is analysis (interpretation of packet relationships), not raw viewing,
so it belongs in the plugin layer rather than the core aggregator.

The resolved hostnames are made available:
  - Globally: a full IP → hostnames map
  - Per-node: hostnames for that node's IPs
  - As a graph enrichment: the server passes plugin results to the graph builder
"""

from typing import Dict, Any, List, Set
from collections import defaultdict
from .. import PluginBase, UISlot, AnalysisContext, display_rows, display_list, display_text


class DNSResolverPlugin(PluginBase):
    name = "dns_resolver"
    description = "Resolve IP addresses to hostnames from captured DNS responses"
    version = "0.1.0"

    def get_ui_slots(self) -> List[UISlot]:
        return [
            UISlot(
                slot_type="node_detail_section",
                slot_id="dns_hostnames",
                title="DNS Hostnames",
                priority=10,
                default_open=True,
            ),
            UISlot(
                slot_type="stats_section",
                slot_id="dns_summary",
                title="DNS Resolution Summary",
                priority=70,
            ),
        ]

    def analyze_global(self, ctx: AnalysisContext) -> Dict[str, Any]:
        """
        Scan all packets for DNS responses and build IP → hostname mappings.
        
        For each DNS response that contains A/AAAA records, maps the resolved
        IP addresses back to the queried domain name.
        """
        ip_to_names: Dict[str, Set[str]] = defaultdict(set)
        total_responses = 0
        total_queries = 0

        for pkt in ctx.packets:
            ex = pkt.extra
            if not ex:
                continue

            qr = ex.get("dns_qr")
            if qr == "query":
                total_queries += 1
            elif qr == "response":
                total_responses += 1
                query = ex.get("dns_query", "")
                answers = ex.get("dns_answers", [])
                if not query or not answers:
                    continue
                for answer in answers:
                    ans = str(answer).strip()
                    if _looks_like_ip(ans):
                        ip_to_names[ans].add(query)

        # Build serializable result
        hostname_map = {ip: sorted(names) for ip, names in ip_to_names.items()}

        # Build summary: top resolved domains
        domain_counts: Dict[str, int] = defaultdict(int)
        for names in ip_to_names.values():
            for name in names:
                domain_counts[name] += 1
        top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:20]

        return {
            "dns_hostnames": hostname_map,
            "dns_summary": {
                "total_queries": total_queries,
                "total_responses": total_responses,
                "resolved_ips": len(hostname_map),
                "unique_domains": len(domain_counts),
                "top_domains": top_domains,
                "_display": [
                    *display_rows({
                        "DNS queries": total_queries,
                        "DNS responses": total_responses,
                        "Resolved IPs": len(hostname_map),
                        "Unique domains": len(domain_counts),
                    }),
                    *(
                        [display_text("Top resolved domains:"),
                         display_list([(d, f"{c}×") for d, c in top_domains[:10]])]
                        if top_domains else []
                    ),
                ],
            },
        }

    def analyze_node(self, ctx: AnalysisContext) -> Dict[str, Any]:
        """Get hostnames for a specific node's IPs."""
        global_results = self.analyze_global(ctx)
        hostname_map = global_results.get("dns_hostnames", {})

        node_id = ctx.target_node_id
        hostnames = set()

        # Direct lookup
        if node_id in hostname_map:
            hostnames.update(hostname_map[node_id])

        if hostnames:
            return {
                "dns_hostnames": {
                    "hostnames": sorted(hostnames),
                    "_display": [
                        *display_rows({"Hostnames": ", ".join(sorted(hostnames))}),
                    ],
                },
            }
        return {"dns_hostnames": None}


def _looks_like_ip(s: str) -> bool:
    """Quick check if string is an IPv4 or IPv6 address."""
    if not s:
        return False
    # IPv4
    parts = s.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    # IPv6 (contains colons)
    if ":" in s:
        return True
    return False
