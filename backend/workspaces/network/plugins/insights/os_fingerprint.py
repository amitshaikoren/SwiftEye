"""
OS Fingerprint Plugin for SwiftEye.

Passive OS detection based on TCP/IP stack characteristics from SYN packets.
Shows evidence (TTL, window size, MSS, TCP options) so researchers can verify.
"""

from typing import Dict, Any, List
from .. import PluginBase, UISlot, AnalysisContext, display_rows, display_tags, display_text, display_list


# ── Signature database ───────────────────────────────────────────────
# Each sig: (name, ttl_range, window_range, mss_hint, notes)
OS_SIGNATURES = [
    # Windows family
    {"name": "Windows 10/11", "ttl": (120, 128), "win": (8192, 65535), "mss": (1460, 1460), "opts": ["MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK"]},
    {"name": "Windows 7/8", "ttl": (120, 128), "win": (8192, 65535), "mss": (1460, 1460)},
    {"name": "Windows (generic)", "ttl": (100, 128), "win": (1024, 65535)},
    # Linux family  
    {"name": "Linux 4.x/5.x", "ttl": (50, 64), "win": (26000, 65535), "mss": (1460, 1460), "opts_must_have": ["SAckOK", "Timestamp"]},
    {"name": "Linux (generic)", "ttl": (50, 64), "win": (1024, 65535)},
    # macOS/iOS
    {"name": "macOS/iOS", "ttl": (50, 64), "win": (65535, 65535)},
    # Network devices
    {"name": "Cisco IOS", "ttl": (250, 255), "win": (4128, 4128)},
    {"name": "Network device", "ttl": (250, 255)},
    # BSD
    {"name": "FreeBSD", "ttl": (50, 64), "win": (65535, 65535), "mss": (1460, 1460)},
    # Solaris
    {"name": "Solaris", "ttl": (250, 255), "win": (8760, 65535)},
]


def _match_sig(ttl, win, mss, opts_seen):
    """Match against signature database. Returns (name, confidence, evidence)."""
    if not ttl:
        return None, 0, {}
    
    best = None
    best_score = 0
    
    for sig in OS_SIGNATURES:
        score = 0
        tmin, tmax = sig.get("ttl", (0, 255))
        if tmin <= ttl <= tmax:
            score += 3
        else:
            continue  # TTL must match
        
        if "win" in sig:
            wmin, wmax = sig["win"]
            if win and wmin <= win <= wmax:
                score += 2
        
        if "mss" in sig:
            mmin, mmax = sig["mss"]
            if mss and mmin <= mss <= mmax:
                score += 1
        
        if "opts_must_have" in sig and opts_seen:
            if all(o in opts_seen for o in sig["opts_must_have"]):
                score += 2
        
        if score > best_score:
            best_score = score
            best = sig["name"]
    
    # Fallback heuristics
    if not best:
        if 50 <= ttl <= 64:
            best = "Unix-like (Linux/macOS/BSD)"
        elif 100 <= ttl <= 128:
            best = "Windows (likely)"
        elif 200 <= ttl <= 255:
            best = "Network device (likely)"
        else:
            best = f"Unknown (TTL={ttl})"
        best_score = 1
    
    confidence = min(100, int(best_score / 8 * 100))
    return best, confidence, {"ttl": ttl, "window": win, "mss": mss, "options": opts_seen}


class OSFingerprintPlugin(PluginBase):
    name = "os_fingerprint"
    description = "Passive OS detection from TCP/IP stack characteristics"
    version = "0.1.0"
    
    def get_ui_slots(self) -> List[UISlot]:
        return [
            UISlot(
                slot_type="node_detail_section",
                slot_id="os_fingerprint",
                title="OS Fingerprint",
                priority=20,
                default_open=True,
            ),
            UISlot(
                slot_type="stats_section",
                slot_id="os_summary",
                title="OS Distribution",
                priority=60,
            ),
        ]
    
    def analyze_global(self, ctx: AnalysisContext) -> Dict[str, Any]:
        """Build per-IP OS fingerprint map from SYN and SYN+ACK packets."""
        ip_fps = {}

        # Two-pass: first collect SYN (initiators), then SYN+ACK (responders)
        # SYN fingerprints are more reliable — they take priority if both exist.
        for pass_num in range(2):
            for pkt in ctx.packets:
                if not pkt.src_ip:
                    continue
                is_syn    = "SYN" in pkt.tcp_flags_list and "ACK" not in pkt.tcp_flags_list
                is_synack = "SYN" in pkt.tcp_flags_list and "ACK" in pkt.tcp_flags_list

                # Pass 0: SYN only  |  Pass 1: SYN+ACK only (fills in responders)
                if pass_num == 0 and not is_syn:
                    continue
                if pass_num == 1 and not is_synack:
                    continue
                if pkt.src_ip in ip_fps:
                    continue  # already have a fingerprint for this IP

                ttl = pkt.ttl
                win = pkt.window_size
                mss = None
                wscale = None
                opts_seen = []

                for opt in pkt.tcp_options:
                    kind = opt.get("kind", "")
                    opts_seen.append(kind)
                    if kind == "MSS":
                        mss = opt.get("value")
                    elif kind == "WScale":
                        wscale = opt.get("value")

                guess, confidence, evidence = _match_sig(ttl, win, mss, opts_seen)
                ip_fps[pkt.src_ip] = {
                    "guess": guess,
                    "confidence": confidence,
                    "ttl": ttl,
                    "window_size": win,
                    "mss": mss,
                    "wscale": wscale,
                    "tcp_options": opts_seen,
                    "evidence": evidence,
                    "source": "SYN" if is_syn else "SYN+ACK",
                }
        
        # Build summary
        os_counts = {}
        for fp in ip_fps.values():
            g = fp["guess"]
            os_counts[g] = os_counts.get(g, 0) + 1
        
        return {
            "os_fingerprint": ip_fps,
            "os_summary": {
                "distribution": sorted(os_counts.items(), key=lambda x: x[1], reverse=True),
                "total_fingerprinted": len(ip_fps),
                "_display": [
                    *display_rows({"Fingerprinted hosts": len(ip_fps)}),
                    display_list(
                        [(os, str(cnt)) for os, cnt in sorted(os_counts.items(), key=lambda x: x[1], reverse=True)]
                    ),
                ],
            },
        }
    
    def analyze_node(self, ctx: AnalysisContext) -> Dict[str, Any]:
        """Get OS fingerprint for a specific node."""
        global_results = self.analyze_global(ctx)
        fps = global_results.get("os_fingerprint", {})
        
        node_id = ctx.target_node_id
        fp = fps.get(node_id)
        if fp:
            return {"os_fingerprint": {
                **fp,
                "_display": [
                    *display_rows({
                        "Guess": fp.get("guess", "Unknown"),
                        "Confidence": f"{fp['confidence']}%" if fp.get("confidence") is not None else None,
                        "Initial TTL": fp.get("ttl"),
                        "Window size": fp.get("window_size"),
                        "MSS": fp.get("mss"),
                        "Window Scale": fp.get("wscale"),
                    }),
                    *(
                        [display_tags([(o, "#bc8cff") for o in fp["tcp_options"]])]
                        if fp.get("tcp_options") else []
                    ),
                    display_text("Based on first SYN packet from this host"),
                ],
            }}
        
        return {"os_fingerprint": None}
