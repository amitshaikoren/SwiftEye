<p align="center">
  <img src="frontend/public/logo_full.png" alt="SwiftEye" width="200" />
</p>

<h1 align="center">SwiftEye</h1>
<p align="center">Network traffic visualization for security researchers.</p>

---

Drop a `.pcap`, `.pcapng`, or Zeek log set and get an interactive force-directed graph of who talked to whom, over what protocols — with full session reconstruction, protocol dissection, and a Wireshark-style display filter. Everything runs locally.

---

## Quick Start

**Requirements:** Python 3.10+

```bash
pip install -r requirements.txt
cd backend && python server.py
```

Open **http://localhost:8642** and drop a capture file.

Node.js is not required to run SwiftEye. The frontend is pre-built.

---

## What It Does

**Graph** — nodes are IPs, edges are connections coloured by protocol. Click any node or edge for full detail. Right-click for investigation mode, pathfinding, clustering, and annotations.

**Sessions** — bidirectional flow reconstruction with initiator tracking, directional bytes, retransmits, TCP window stats, seq/ack numbers, and payload preview.

**Protocol dissection** — TLS (SNI, version, cipher suites, JA3/JA4 with known-malware flagging), HTTP, DNS, SSH, FTP, DHCP, SMB, QUIC, ICMP, and more. Non-standard ports resolved by payload inspection.

**Research panel** — parameterized Plotly charts computed server-side against the loaded capture. Drag charts into a slot canvas, apply per-chart filters (time window, protocols, search), and expand any chart to fill the panel.

**Analysis** — graph-wide computations: node centrality ranking, traffic characterisation (foreground/background/ambiguous sessions with per-session evidence).

**Filtering** — three independent layers: backend filters (IP, port, protocol, time range), a Wireshark-style display filter bar evaluated client-side, and per-node investigation mode.

**Visualize** — upload any CSV/TSV/JSON and map columns to a force-directed graph. No capture needed. Useful for AD trust relationships, firewall rules, certificate chains, BGP paths, or any relational data.

**Investigation notebook** — markdown editor with live preview. Paste screenshots, embed images, export as a PDF report.

---

## Features

- **Passive OS fingerprinting** — inferred from SYN/SYN-ACK characteristics (TTL, window size, MSS, TCP options). No active probing.
- **Louvain community detection** — automatic graph clustering with expandable hex mega-nodes. Also supports k-core, hub-spoke, and shared-neighbor algorithms.
- **Betweenness centrality** — Brandes algorithm ranking of nodes by structural importance, alongside degree and traffic-weighted scores.
- **PDF report export** — export the investigation notebook as a formatted PDF directly from the browser.
- **Synthetic graph elements** — add hypothesis nodes and edges to the live graph. Rendered distinctly, persisted to backend.

---

## Input Formats

| Format | Notes |
|--------|-------|
| `.pcap` / `.pcapng` | Standard capture files |
| Zeek logs | `conn.log` required; `dns.log`, `http.log`, `ssl.log`, `smb_*.log`, `dce_rpc.log` optional |
| tshark CSV | `tshark -T fields` tab-separated exports; `metadata.csv` auto-joins protocol CSVs by frame number |

---

## Extending SwiftEye

SwiftEye is designed to be extended without touching core code.

- **Dissectors** — drop a file in `parser/protocols/`, add an import. New fields are automatically searchable.
- **Insight plugins** — annotate graph nodes with computed properties (OS fingerprint, hostname, role).
- **Analysis plugins** — graph-wide computations that render on the Analysis page automatically.
- **Research charts** — subclass `ResearchChart`, implement `compute()`, register in `server.py`. The full Plotly API is available.

See `DEVELOPERS.md` for full extension documentation.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
