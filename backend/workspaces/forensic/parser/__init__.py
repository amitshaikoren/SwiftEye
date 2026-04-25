"""
Forensic parser package.

Mirrors the structure of `workspaces/network/parser/` — one reader per
source format (evtx_reader, …), one adapter per format in `adapters/`,
and one dissector per event-id in `dissectors/`. Dissectors emit
normalized `Event` records that downstream phases (5+) fold into the graph.
"""
