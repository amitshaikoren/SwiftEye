<p align="center">
  <img src="frontend/public/logo_full.png" alt="SwiftEye" width="200" />
</p>

<h1 align="center">SwiftEye</h1>
<p align="center">Network traffic visualization for security researchers.</p>

---

Drop a `.pcap` or `.pcapng` file, get an interactive force-directed graph of who talked to whom, over what protocols — with full session reconstruction, protocol dissection, TLS fingerprinting, an extensible plugin system, and a Wireshark-style display filter.

## Quick Start

**Prerequisites:** Python 3.10+, Node.js 18+

```bash
cd swifteye
pip install -r requirements.txt

cd backend
python server.py
```

Open **http://localhost:8642** and drop a pcap file.

---

## What You See

- **Force-directed graph** — nodes are IPs/subnets, edges coloured by protocol. Each unique protocol between two nodes gets its own edge. Click a node or edge for detail, shift+click for multi-select with scoped statistics.
- **Protocol detection** — ~90 well-known port mappings plus payload-based detection for TLS, HTTP, SSH, SMTP, FTP, DHCP, SMB, and more on non-standard ports. Conflicts between port and payload are flagged with a warning.
- **Protocol dissection** — SSH banner version, FTP credentials/filenames, DHCP hostname/vendor class, SMB share paths/filenames, ICMPv4/ICMPv6 type names, DNS queries/answers, HTTP host/method/URI, TLS SNI/version/ciphers, QUIC version/connection IDs/SNI.
- **Session reconstruction** — bidirectional flows with initiator tracking (SYN-based), directional traffic bytes, retransmit detection, TCP window stats, seq/ack numbers.
- **TLS details** — SNI, versions, cipher suites, JA3 and JA4 fingerprints. Known JA3 hashes resolved to application names (Firefox, Chrome, curl, Cobalt Strike, etc.) with a red ⚠ badge for known malware.
- **Seq/Ack Timeline** — inline chart in the Session Detail SEQ/ACK tab. Click Run to compute a Plotly scatter of sequence numbers over time — shows retransmits, reordering, and throughput shape.
- **Timeline sparkline** — adjustable bucket size (5s/15s/30s/60s) with range sliders for time filtering. Shared across graph, research, and timeline views.
- **Connection Gantt** — full-width Plotly Gantt of all sessions in the Timeline page. Click Run to render.
- **Search** — universal keyword search filters both the graph and Sessions panel. Matches IPs, MACs, hostnames, protocols, ports, and TCP flags simultaneously.
- **Display filter bar** — Wireshark-style expression filter. Supports `ip`, `ip.src`, `ip.dst`, `mac`, `hostname`, `protocol`, `port`, `bytes`, `packets`, `tls.sni`, `http.host`, `dns`, `os`, `private`, `subnet` fields with `==`, `!=`, `>`, `<`, `contains`, `matches`, `&&`, `||`, `!`, `()` and CIDR notation. Client-side, instant feedback.
- **Graph clustering** — Louvain, k-core, hub-spoke, shared-neighbor algorithms. Clusters render as hexagon mega-nodes. Expand/collapse, rename, lasso-group to create manual clusters.
- **Pathfinding** — right-click a node → "Find paths to..." → click a target. Results show BFS hop layers and all edges across discovered paths. Directed/undirected toggle. IP text inputs for manual entry.
- **Graph Options** — Subnet grouping (/8–/32 prefix), Merge by MAC (dual-stack IPv4+IPv6 hosts become one node), Show IPv6 toggle, Show hostnames toggle. Right-click any subnet node → **Uncluster subnet** to expand just that subnet.
- **Node detail** — IPs, MACs with vendor name (Apple, Cisco, Intel, Espressif, etc.), TTLs, OS fingerprint, DNS hostnames, connections by direction, plugin sections.
- **MAC vendor lookup** — ~700 OUI prefixes covering major vendors.
- **OS filter** — Clickable OS chips in the FilterBar inject `os contains "..."` expressions.
- **Annotations** — Right-click empty canvas, node, or edge → Add annotation. Pinned HTML labels, persist across reloads.
- **Research page** — full-screen parameterized Plotly charts computed server-side. Scoped by shared time slider.
- **Analysis page** — graph-wide analyses: Node Centrality (ranked table with degree, betweenness, traffic score) and Traffic Characterisation (foreground/background/ambiguous session classification with evidence). Additional researcher analyses render automatically.
- **Investigation notebook** — markdown editor with live preview for documenting findings. Paste screenshots from clipboard, embed images, export as a formatted PDF report.
- **Visualize (BETA)** — upload any CSV/TSV/JSON data and map columns to a force-directed graph. Supports edge label/color/weight, node color/size/group, hover data, and optional timestamp filtering. Works without a loaded capture.
- **Synthetic nodes/edges** — Right-click canvas → Add synthetic node/edge. Hypothesis elements with dashed rendering and ✦ markers. Persisted to backend.
- **Payload preview** — hex+ASCII dump of the first payload bytes per packet in the Session Detail Payload tab.
- **PCAP export** — "Export pcap" button downloads the current filtered view.
- **Dark / light mode.**

---

## Insight Plugins

| Plugin | What It Does |
|--------|-------------|
| **OS Fingerprint** | Passive OS detection from SYN/SYN+ACK characteristics (TTL, window size, MSS, TCP options). |
| **TCP Flags** | Sender attribution — who initiated, accepted, closed, and reset each connection. |
| **DNS Resolver** | Maps IPs to hostnames from captured DNS responses. Hostnames become node labels (cyan). |
| **Network Map** | ARP table reconstruction, gateway detection (diamond node shape), LAN host identification, hop estimation. |
| **Node Merger** | Merges IPs sharing a MAC address (including IPv4+IPv6 dual-stack pairs) into one node before graph building. |

**Writing insight plugins requires Python only.** See developer docs.

---

## Analysis Plugins

Graph-wide computations on the **Analysis ✦** page. Researchers add new analyses by writing a Python file — no frontend needed.

| Analysis | What It Does |
|----------|-------------|
| **Node Centrality** | Degree, betweenness (Brandes), and traffic-weighted ranking. Dedicated interactive panel with sort, search, click-to-select. |
| **Traffic Characterisation** | Classifies sessions as foreground (interactive) / background (automated) / ambiguous. Evidence-based scoring with expandable per-session explanation. |

---

## Visualize (BETA)

Upload any **CSV, TSV, or JSON** tabular data and map columns to a force-directed graph. No capture needed — accessible from the upload screen.

Map columns to: source node, target node, edge label/color/weight, node color/size/group, hover data, and an optional timestamp for time-based filtering. Useful for certificate chains, AD trust relationships, firewall rules, BGP paths, or any relational data.

---

## Research Charts

Click **Research** in the left panel. Use the time scope slider to restrict to a window, then click **Run** on each chart.

| Chart | Question answered |
|-------|-----------------|
| **Conversation timeline** | Who talked to this IP, when, and on what protocol? |
| **TTL over time** | Did the TTL between two peers stay consistent? |
| **Seq/Ack Timeline** | What do sequence numbers look like over the session? (also in Session Detail → SEQ/ACK tab) |
| **HTTP User-Agent timeline** | Which source IPs made HTTP requests, when, and with what User-Agent? |

The Session Gantt lives in the **Timeline** nav entry.

**Tip:** Right-click any node → **Investigate** — the investigated IP pre-fills all Research chart IP fields automatically.

---

## Filtering — Three Layers

1. **Backend filters** — IP, port, search, protocol checkboxes, time range, subnet grouping, merge options. Each change re-fetches from the server.
2. **Display filter bar** — Wireshark-style expressions evaluated client-side. Non-matching nodes/edges dim to 5% opacity. No re-fetch.
3. **Investigation mode** — Right-click a node → Investigate. Dims everything outside the connected component.

---

## Researcher Metadata

Click **META** in the toolbar to upload a JSON file:

```json
{
    "10.0.0.1":          { "name": "DC01",       "role": "Domain Controller" },
    "192.168.1.50":      { "name": "web-server",  "notes": "DMZ host" },
    "aa:bb:cc:dd:ee:ff": { "name": "Unknown NIC", "notes": "First seen 2026-03-01" }
}
```

The `name` field becomes the node label. All other fields appear in Node Detail. Metadata is cleared when a new pcap is uploaded.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full version history.
