"""
Traffic Characterisation Analysis

Classifies sessions as foreground (interactive), background (automated),
or ambiguous based on session metrics: duration, packet rate, bytes per
packet, TCP handshake/close patterns.

This replaces the client-side JavaScript classifier that was in
AnalysisPage.jsx — same heuristics, but runs in Python.
"""

from collections import Counter
from workspaces.network.plugins.analyses import AnalysisPluginBase
from workspaces.network.plugins import display_table, display_text


def _classify_session(s):
    """Classify a single session. Returns (label, fg_score, bg_score, evidence)."""
    dur = s.get("duration") or 0
    pkts = s.get("packet_count") or 0
    total_bytes = s.get("total_bytes") or 0

    if not pkts:
        return "unknown", 0, 0, []

    fg = 0
    bg = 0
    evidence = []
    pps = pkts / dur if dur > 0 else pkts
    bpp = total_bytes / pkts

    protocol = (s.get("protocol") or "").upper()

    # ARP is always background
    if protocol == "ARP":
        return "background", 0, 10, ["ARP — address resolution / network discovery"]

    # Duration signals
    if dur < 2:
        fg += 2
        evidence.append(f"Short session ({dur:.1f}s)")
    elif dur < 30:
        fg += 1
        evidence.append(f"Medium session ({dur:.1f}s)")
    elif dur > 300:
        bg += 2
        evidence.append(f"Long-running ({dur:.0f}s)")
    else:
        bg += 1
        evidence.append(f"Extended session ({dur:.0f}s)")

    # Packet rate signals
    if pps > 10:
        fg += 2
        evidence.append(f"High pps ({pps:.1f})")
    elif pps > 2:
        fg += 1
        evidence.append(f"Moderate pps ({pps:.1f})")
    else:
        bg += 1
        evidence.append(f"Low pps ({pps:.2f})")

    # Bytes per packet
    if bpp > 500:
        fg += 1
        evidence.append(f"Large avg pkt ({bpp:.0f} B)")
    elif bpp < 80:
        bg += 2
        evidence.append(f"Tiny avg pkt ({bpp:.0f} B)")

    # TCP state
    if s.get("has_handshake"):
        fg += 2
        evidence.append("TCP handshake complete")
    if s.get("has_reset"):
        bg += 1
        evidence.append("TCP RST")
    if s.get("has_fin") and dur < 10:
        fg += 1
        evidence.append("Clean FIN on short session")

    label = "foreground" if fg > bg else "background" if bg > fg else "ambiguous"
    return label, fg, bg, evidence


class TrafficCharacterisationAnalysis(AnalysisPluginBase):
    name        = "traffic_characterisation"
    title       = "Traffic Characterisation"
    description = "Classifies sessions as foreground / background / ambiguous."
    icon        = "⚡"
    version     = "1.0"

    def compute(self, ctx) -> dict:
        sessions = ctx.sessions or []

        if not sessions:
            return {
                "_display": [display_text("No sessions available.")],
                "summary": {},
                "classified": [],
            }

        classified = []
        counts = Counter()
        for s in sessions:
            label, fg, bg, evidence = _classify_session(s)
            counts[label] += 1
            classified.append({
                "id": s.get("id", ""),
                "src_ip": s.get("src_ip", "?"),
                "dst_ip": s.get("dst_ip", "?"),
                "dst_port": s.get("dst_port", 0),
                "protocol": s.get("protocol", "?"),
                "label": label,
                "fg_score": fg,
                "bg_score": bg,
                "evidence": evidence,
                "packet_count": s.get("packet_count", 0),
                "total_bytes": s.get("total_bytes", 0),
                "duration": s.get("duration", 0),
            })

        total = len(sessions)
        summary = {
            "foreground": counts.get("foreground", 0),
            "background": counts.get("background", 0),
            "ambiguous": counts.get("ambiguous", 0),
            "unknown": counts.get("unknown", 0),
            "total": total,
        }

        # Sort by total_bytes descending
        classified.sort(key=lambda c: c["total_bytes"], reverse=True)

        # Build display table — top 50
        headers = ["Class", "Session", "Pkts", "Bytes", "Dur", "Evidence"]
        rows = []
        for c in classified[:50]:
            session_label = f"{c['protocol']} {c['src_ip']}→{c['dst_ip']}:{c['dst_port']}"
            dur_str = f"{c['duration']:.0f}s" if c["duration"] >= 1 else "<1s"
            rows.append([
                c["label"],
                session_label,
                str(c["packet_count"]),
                _fmt_bytes(c["total_bytes"]),
                dur_str,
                "; ".join(c["evidence"][:3]),
            ])

        fg_pct = round(summary["foreground"] / total * 100) if total else 0
        bg_pct = round(summary["background"] / total * 100) if total else 0
        amb_pct = round(summary["ambiguous"] / total * 100) if total else 0

        return {
            "_display": [
                display_text(
                    f"Foreground: {summary['foreground']} ({fg_pct}%) · "
                    f"Background: {summary['background']} ({bg_pct}%) · "
                    f"Ambiguous: {summary['ambiguous']} ({amb_pct}%) · "
                    f"Total: {total}"
                ),
                display_table(headers, rows),
            ],
            "summary": summary,
            "classified": classified,
        }


def _fmt_bytes(b):
    if b < 1024:
        return f"{b} B"
    if b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    if b < 1024 * 1024 * 1024:
        return f"{b / (1024 * 1024):.1f} MB"
    return f"{b / (1024 * 1024 * 1024):.2f} GB"
