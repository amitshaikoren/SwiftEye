"""
SwiftEye Insight Plugins — per-node / per-session interpretation.

Insights interpret individual entities: mapping an IP to a hostname,
guessing an OS from TTL + window size, attributing TCP flag patterns.
They run once on pcap load and annotate nodes/edges/sessions.
"""
