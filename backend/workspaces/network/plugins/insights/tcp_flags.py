"""
TCP Flags Analysis Plugin for SwiftEye.

Provides meaningful context for TCP flags:
- Who initiated connections (SYN senders)
- Who closed connections (FIN senders)  
- Who reset connections (RST senders)
- Per-IP flag breakdown
"""

from typing import Dict, Any, List
from collections import defaultdict
from .. import PluginBase, UISlot, AnalysisContext, display_rows, display_list, display_text


class TCPFlagsPlugin(PluginBase):
    name = "tcp_flags"
    description = "TCP flag analysis with sender attribution"
    version = "0.1.0"
    
    def get_ui_slots(self) -> List[UISlot]:
        return [
            UISlot(
                slot_type="stats_section",
                slot_id="tcp_flags_detail",
                title="TCP Flags",
                priority=15,
                default_open=True,
            ),
        ]
    
    def analyze_global(self, ctx: AnalysisContext) -> Dict[str, Any]:
        """Analyze TCP flags with sender attribution."""
        syn_senders = defaultdict(int)
        synack_senders = defaultdict(int)
        fin_senders = defaultdict(int)
        rst_senders = defaultdict(int)
        
        total_flags = defaultdict(int)
        
        for pkt in ctx.packets:
            flags = pkt.tcp_flags_list
            if not flags:
                continue
            
            for f in flags:
                total_flags[f] += 1
            
            has_syn = "SYN" in flags
            has_ack = "ACK" in flags
            has_fin = "FIN" in flags
            has_rst = "RST" in flags
            
            if has_syn and not has_ack:
                syn_senders[pkt.src_ip] += 1
            if has_syn and has_ack:
                synack_senders[pkt.src_ip] += 1
            if has_fin:
                fin_senders[pkt.src_ip] += 1
            if has_rst:
                rst_senders[pkt.src_ip] += 1
        
        def top_n(d, n=10):
            return sorted(d.items(), key=lambda x: x[1], reverse=True)[:n]
        
        connections_initiated = sum(syn_senders.values())
        connections_accepted = sum(synack_senders.values())
        connections_closed = sum(fin_senders.values())
        connections_reset = sum(rst_senders.values())
        
        # Build _display for generic rendering
        display = [
            *display_rows({
                "Connections initiated (SYN)": connections_initiated or None,
                "Connections accepted (SYN+ACK)": connections_accepted or None,
                "Connections closed (FIN)": connections_closed or None,
                "Connections reset (RST)": connections_reset or None,
            }),
        ]
        if syn_senders:
            display.append(display_text("Top SYN senders:"))
            display.append(display_list([(ip, f"{cnt}×") for ip, cnt in top_n(syn_senders, 5)], clickable=True))
        if rst_senders:
            display.append(display_text("Top RST senders:"))
            display.append(display_list([(ip, f"{cnt}×") for ip, cnt in top_n(rst_senders, 5)], clickable=True))
        
        return {
            "tcp_flags_detail": {
                "total_flags": dict(total_flags),
                "summary": [
                    {"label": "Connections initiated", "count": connections_initiated, "flag": "SYN", "senders": top_n(syn_senders)},
                    {"label": "Connections accepted", "count": connections_accepted, "flag": "SYN+ACK", "senders": top_n(synack_senders)},
                    {"label": "Connections closed", "count": connections_closed, "flag": "FIN", "senders": top_n(fin_senders)},
                    {"label": "Connections reset", "count": connections_reset, "flag": "RST", "senders": top_n(rst_senders)},
                ],
                "_display": display,
            },
        }
