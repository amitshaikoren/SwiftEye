"""
Suspicious HTTP user-agent detector.

Detection 1 — Known scripting tool / scanner UAs:
  Matches user-agent strings against a list of known automation tools.
  Groups by (src_ip, dst_ip) pair — one alert per pair, not per session.

Detection 2 — Empty user-agent:
  HTTP sessions with no UA string set. One alert per src_ip.
"""

import uuid
from plugins.alerts import AlertPluginBase, AlertRecord

_UA_RULES = [
    ("python-requests", "python-requests"),
    ("python-urllib",   "python-urllib"),
    ("curl/",           "curl"),
    ("Wget/",           "wget"),
    ("zgrab",           "zgrab"),
    ("masscan",         "masscan"),
    ("nikto",           "nikto"),
    ("nmap",            "nmap"),
    ("sqlmap",          "sqlmap"),
    ("go-http-client",  "go-http-client"),
    ("gobuster",        "gobuster"),
    ("dirbuster",       "dirbuster"),
    ("hydra",           "hydra"),
    ("scrapy",          "scrapy"),
]


class SuspiciousUADetector(AlertPluginBase):
    name = "suspicious_ua"
    version = "1.0"

    def detect(self, ctx):
        alerts = []

        # -- Detection 1: Known tool UAs --
        # pair_key -> {uas: set(), sessions: [], first_ts}
        pair_matches = {}

        for s in ctx.sessions:
            if s.get("protocol") != "HTTP":
                continue
            uas = s.get("http_fwd_user_agents", [])
            src = s.get("src_ip")
            dst = s.get("dst_ip")
            if not src or not dst:
                continue

            matched_rules = []
            for ua in uas:
                ua_lower = ua.lower()
                for pattern, rule_name in _UA_RULES:
                    if pattern.lower() in ua_lower:
                        matched_rules.append((ua, rule_name))
                        break

            if matched_rules:
                key = (src, dst)
                if key not in pair_matches:
                    pair_matches[key] = {"uas": set(), "rules": set(), "sessions": [], "first_ts": s.get("start_time")}
                for ua, rule in matched_rules:
                    pair_matches[key]["uas"].add(ua)
                    pair_matches[key]["rules"].add(rule)
                pair_matches[key]["sessions"].append(s.get("session_id", ""))
                ts = s.get("start_time")
                if ts and (pair_matches[key]["first_ts"] is None or ts < pair_matches[key]["first_ts"]):
                    pair_matches[key]["first_ts"] = ts

        for (src, dst), info in pair_matches.items():
            evidence = []
            for ua in sorted(info["uas"]):
                matching_rules = [r for u, r in [(u, r) for u in [ua] for _, r in _UA_RULES if _.lower() in ua.lower()] if r]
                note = f"rule: {matching_rules[0]}" if matching_rules else ""
                evidence.append({"key": "User-Agent", "value": ua, "note": note})
            evidence.append({"key": "Sessions", "value": str(len(info["sessions"])), "note": ""})

            alerts.append(AlertRecord(
                id=uuid.uuid4().hex[:8],
                title="Suspicious User-Agent",
                subtitle=f"Scripting tool UA detected: {', '.join(sorted(info['rules']))}",
                severity="medium",
                detector=self.name,
                source="detector",
                source_name=self.name,
                timestamp=info["first_ts"],
                src_ip=src,
                dst_ip=dst,
                evidence=evidence,
                node_ids=[src, dst],
                session_ids=info["sessions"][:20],
            ))

        # -- Detection 2: Empty UA --
        # src_ip -> {count, first_ts, dst_ips, sessions}
        empty_ua_by_src = {}

        for s in ctx.sessions:
            if s.get("protocol") != "HTTP":
                continue
            uas = s.get("http_fwd_user_agents", [])
            if uas and uas != [""]:
                continue
            src = s.get("src_ip")
            if not src:
                continue
            if src not in empty_ua_by_src:
                empty_ua_by_src[src] = {"count": 0, "first_ts": s.get("start_time"), "dst_ips": set(), "sessions": []}
            empty_ua_by_src[src]["count"] += 1
            if s.get("dst_ip"):
                empty_ua_by_src[src]["dst_ips"].add(s["dst_ip"])
            empty_ua_by_src[src]["sessions"].append(s.get("session_id", ""))
            ts = s.get("start_time")
            if ts and (empty_ua_by_src[src]["first_ts"] is None or ts < empty_ua_by_src[src]["first_ts"]):
                empty_ua_by_src[src]["first_ts"] = ts

        for src, info in empty_ua_by_src.items():
            alerts.append(AlertRecord(
                id=uuid.uuid4().hex[:8],
                title="Empty User-Agent",
                subtitle=f"HTTP requests with no User-Agent from {src}",
                severity="low",
                detector=self.name,
                source="detector",
                source_name=self.name,
                timestamp=info["first_ts"],
                src_ip=src,
                dst_ip=None,
                evidence=[
                    {"key": "Sessions", "value": str(info["count"]), "note": "with empty or missing UA"},
                    {"key": "Destinations", "value": ", ".join(sorted(info["dst_ips"])[:5]), "note": ""},
                ],
                node_ids=[src],
                session_ids=info["sessions"][:20],
            ))

        return alerts
