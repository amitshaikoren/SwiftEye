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

cd frontend
npm install
npm run build
cd ..

cd backend
python server.py
```

Open **http://localhost:8642** and drop a pcap file.

---

## What You See

- **Force-directed graph** — nodes are IPs/subnets, edges coloured by protocol. Each unique protocol between two nodes gets its own edge. Click a node or edge for detail, shift+click for multi-select with scoped statistics.
- **Protocol detection** — ~90 well-known port mappings plus payload-based detection for TLS, HTTP, SSH, SMTP, FTP, DHCP, SMB, and more on non-standard ports. Conflicts between port and payload are flagged with a warning.
- **Protocol dissection** — SSH banner version, FTP credentials/filenames, DHCP hostname/vendor class, SMB share paths/filenames, ICMPv4/ICMPv6 type names, DNS queries/answers, HTTP host/method/URI, TLS SNI/version/ciphers.
- **Session reconstruction** — bidirectional flows with initiator tracking (SYN-based), directional traffic bytes, retransmit detection, TCP window stats, seq/ack numbers.
- **TLS details** — SNI, versions, cipher suites, JA3 and JA4 fingerprints. Known JA3 hashes resolved to application names (Firefox, Chrome, curl, Cobalt Strike, etc.) with a red ⚠ badge for known malware.
- **Seq/Ack Timeline** — inline chart in the Session Detail SEQ/ACK tab. Click Run to compute a Plotly scatter of sequence numbers over time — shows retransmits, reordering, and throughput shape.
- **Timeline sparkline** — adjustable bucket size (5s/15s/30s/60s) with range sliders for time filtering. Shared across graph, research, and timeline views.
- **Connection Gantt** — full-width Plotly Gantt of all sessions in the Timeline page. Click Run to render.
- **Search** — universal keyword search filters both the graph and Sessions panel. Matches IPs, MACs, hostnames, protocols, ports, and TCP flags simultaneously.
- **Display filter bar** — Wireshark-style expression filter. Supports `ip`, `ip.src`, `ip.dst`, `mac`, `hostname`, `protocol`, `port`, `bytes`, `packets`, `tls.sni`, `http.host`, `dns`, `os`, `private`, `subnet` fields with `==`, `!=`, `>`, `<`, `contains`, `matches`, `&&`, `||`, `!`, `()` and CIDR notation. Client-side, instant feedback.
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

### v0.9.38 — March 2026
- **Backend gap collapsing** — `build_time_buckets()` now replaces large empty runs (>1 day AND >20% of capture duration) with a single `is_gap=True` marker bucket. A 3-day gap between two pcaps becomes one bucket instead of 260,000.
- **Sparkline gap rendering** — `is_gap` buckets are drawn as diagonal `////` hatch lines instead of bars.
- **Burst detection uses gap markers** — `detectBursts()` splits on `is_gap` buckets directly, no gap-scanning loop needed.
- **Bucket size restrictions removed** — no longer needed since the backend never returns excessive buckets.

### v0.9.38 — March 2026
- **Timeline: gap-split sparkline.** Burst segments fill real screen space; large gaps show as //// hatch with duration. No bucket selector, no state. Sliders span global range. Full DD/MM/YYYY timestamps.

### v0.9.37 — March 2026
- **Timeline: fine bucket sizes disabled in All view when capture is too long.** A 3-day capture at 1s = 260,000 buckets — crashes backend + frontend. Bucket buttons that would produce >5000 buckets in All view are now dimmed and unclickable. Burst view is never restricted (bursts span minutes at most).

### v0.9.36 — March 2026
- **Timeline: burst view slices sparkline.** Clicking Burst N now shows only that burst's bars filling the full sparkline width. Sliders go 0→N_burst, reset to full range on burst click.
- **Timeline: full date+time** — timestamps now show DD/MM/YYYY HH:MM:SS.
- **Timeline: 1s crash fixed** — burst detection loop moved into TimelineStrip component, runs only when timeline changes, not on every parent render.

### v0.9.35 — March 2026
- **Timeline: full revert to original architecture.** Deleted `TimelineStrip.jsx`. Logic is now inline in `App.jsx` inside an IIFE — same as the original v0.9.0 strip, with two additions: (1) timestamps on sliders, (2) burst snap buttons. No state, no effects, no components, nothing to crash.

### v0.9.34 — March 2026
- **Timeline: Option B** — full sparkline always visible, sliders span full 0..N-1, burst buttons snap sliders. No viewport state, no useEffect, nothing to crash.
- **Burst detection: real-time thresholds** — gap must be >20% of total capture duration AND >60 seconds. A 20s capture never splits; two pcaps hours apart always produce two bursts.
- **Burst buttons only shown when 2+ bursts** — single-session captures show no burst UI at all.

### v0.9.33 — March 2026
- **Timeline rewrite (stable)** — replaced viewport state with `activeBurst` index. No state that calls `setTimeRange` inside effects. No feedback loops possible. Burst buttons, All button, and bucket-size changes all update `activeBurst`; viewport is purely derived.

### v0.9.32 — March 2026
- **Black screen fix** — `useEffect([timeline])` caused an infinite loop: clicking "All" triggered a re-render → new timeline reference → effect fired again → `setTimeRange` → re-render → repeat. Fixed by using `N` (bucket count) as dep with a `prevN` ref guard that skips the initial mount.

### v0.9.31 — March 2026
- **Timeline: viewport resets on bucket size change** — changing 1s/5s/15s etc. now re-snaps viewport and range to first burst.
- **Timeline: All button always visible** — no longer hidden when in full view; has active styling when selected.
- **Timeline: black screen fix** — Sparkline now guards against zero/invalid width and viewport values.

### v0.9.30 — March 2026
- **Timeline redesign** — burst detection + zoom view + original Start/End sliders combined. Burst buttons zoom the sparkline to that region; sliders operate within the zoomed viewport; "All" resets both.

### v0.9.29 — March 2026
- **Sparkline: viewport auto-pan while dragging** — when painting a range by dragging near the canvas edge, the viewport now scrolls automatically so you can reach burst 2 from burst 1 without releasing.
- **"Full" renamed to "Overview"** — always visible alongside burst buttons; highlights when active.
- **Timeline timestamps fixed** — container set to overflow:hidden, preventing layout overflow from hiding the timestamp row.

### v0.9.28 — March 2026
- **Traffic panel: show all rows** — searching by IP no longer hard-caps at 30 rows. "Show all N" button appears when results exceed the default limit.
- **Traffic panel: filtered percentages** — fg/bg/ambiguous counts update to reflect the current IP filter. Shows `filtered/global` when a filter is active.
- **ARP = background** — ARP sessions are now unconditionally classified as background (address resolution, always automated).
- **Node Centrality: global rank preserved** — the `#` column always shows the original score rank regardless of the active filter or sort order. Score column added.
- **Sparkline fixed** — was treating bucket objects as raw numbers instead of reading `.packet_count`. Now renders correctly.

### v0.9.27 — March 2026
- **Timeline A+B+E** — scroll-to-zoom main view, minimap overview, burst detection + jump buttons, auto-crop to first burst on load, right-click to reset.
- **Analysis IP search** — both Node Centrality and Traffic Characterisation have an IP filter bar with optional second IP for session filtering.
- **Traffic evidence rows** — click any session row in Traffic Characterisation to expand and see the exact signals (fg/bg scores + per-signal explanation) that drove the classification.
- **Help panel updated** — Analysis panel documented, lasso/relayout/cluster added to Graph Interactions, new Timeline Strip section.

### v0.9.26 — March 2026
- **Hotfix** — `build_graph()` was missing `mac_split_map` from its parameter list (added to internal code but not the `def` signature), causing `TypeError` on every `/api/graph` request.

### v0.9.25 — March 2026
- **Interactive timeline** — click directly on the sparkline to set start, drag to paint a range, drag handles to adjust boundaries, right-click to reset to full. Start handle is blue, end handle is green. Range timestamps shown top-right of strip.

### v0.9.24 — March 2026
- **Freehand lasso** — Shift+right-drag now draws a freehand polygon (not a box). Point-in-polygon hit test on release.
- **Relayout button moved** — bottom-right to avoid overlapping the "N nodes hidden" badge.
- **Timeline resolution** — added 1s bucket size. Slider now shows actual timestamps (HH:MM:SS) instead of bucket indices.
- **Node label threshold** — new Graph Options slider. Hide labels below 1KB/10KB/100KB/1MB/10MB of traffic. Hover always shows label.
- **Roadmap** — added: IP address type annotation in NodeDetail (private/APIPA/multicast/etc), NetworkX backend for large-graph centrality.

### v0.9.23 — March 2026
- **Same IP, different MACs = different nodes** — `build_mac_split_map()` detects IPs seen with multiple distinct source MACs; those hosts get `ip::mac` node IDs so they render separately instead of collapsing.
- **Node Centrality panel** — live computation: degree, Brandes betweenness, traffic volume. Sortable table, click row to select node on graph.
- **Traffic Characterisation panel** — classifies every session as foreground/background/ambiguous using duration, pps, bytes-per-packet, and TCP flags. Filter + stacked summary bar.
- **Analysis panel redesign** — panels expand to half-page on click, side by side. LLM section clearly labelled as the only external-API feature.

### v0.9.22 — March 2026
- **Playback fully removed** — all playback state, tick effect, and control functions removed from `useCapture.js`. Timeline strip is the original Start/End range sliders only.

### v0.9.21 — March 2026
- **Architecture audit** — hooks ordering, dead code removal, AnalysisContext parity, API key persistence.

### v0.9.20 — March 2026
- **Code audit** — hooks ordering fixes (StatsPanel, EdgeDetail), lasso+contextmenu conflict fix, README backfilled.

### v0.9.19 — March 2026
- **Investigate split** — "Investigate neighbours" (depth-1) and "Investigate component" (full BFS).
- **Relayout button** — unpins all nodes and reheats force simulation for a clean layout.
- **Lasso select** — Shift+right-drag to draw a selection rectangle.
- **Synthetic cluster** — cluster selected nodes into one visual node; edges rerouted automatically.

### v0.9.18 — March 2026
- **Analysis panel** — "Analysis ✦" nav item with Coming Soon cards and LLM interpretation skeleton (API key input, model selector, disabled button).
- **Subnet recluster bug fixed** — exclusions now cleared when subnet grouping is toggled off.

### v0.9.17 — March 2026
- **Timeline strip reverted** — playback controls removed, original Start/End sliders restored.

### v0.9.16 — March 2026
- **Gateway filter** — new display filter fields: `gateway` (bare flag) and `role == "gateway"/"lan"/"external"` sourced from Network Map plugin.

### v0.9.15 — March 2026
- **Multi-pcap** — drop or select multiple .pcap files; merged by timestamp.
- **dpkt parity** — raw-byte DNS, FTP, DHCP, SMB dissectors for ≥500MB files.

### v0.9.14 — March 2026
- **TLS version in session title** — TLS collapse now reads "TLS 1.2 — milvus.io".
- **Help panel tabbed** — Guide + Plugins & Protocols tabs.

### v0.9.13 — March 2026
- **Black screen on node click fixed** — `useEffect` missing from NodeDetail imports.

### v0.9.12 — March 2026
- **TLS Certificate extraction fixed** — loop now walks full handshake chain.
- **JA3 smaller dots**, initiator/responder in tooltip. **JA4 timeline** added.

### v0.9.11 — March 2026
- **Network Map plugin crash fixed**, notes not persisting fixed, notes moved to bottom.

### v0.9.10 — March 2026
- **Canvas theme not updating fixed** — `theme` prop + 20ms delay useEffect.
- **Pastel theme**, **gateway diamond nodes**, **legend theme-aware**.

### v0.9.10 — March 2026
- **Pastel theme** — soft lavender/violet UI, mint/rose accent colors, easy on the eyes.
- **Gateway nodes as diamonds** — routers/gateways detected by the Network Map plugin render as diamonds in the graph, with their own legend entry and per-theme color.
- **Legend theme-aware** — legend swatches now use CSS variables, always in sync with the active theme.

### v0.9.9 — March 2026
- **Full theme system** — themes now affect the graph canvas, node colors (private/external/subnet), and edge colors, not just the UI chrome. Each theme has its own node palette. Canvas reads CSS variables at render time.
- **Canvas vignette** — subtle radial gradient gives the canvas depth.

### v0.9.8 — March 2026
- **Network Map plugin** — passive topology detection: gateways (via dst_mac analysis), LAN hosts (ARP + TTL), hop counts (TTL-based), ARP table. Shows "Network Role" in NodeDetail with coloured badge.
- **IPv4 Header fields split by direction** — initiator and responder shown separately with all flags, IP ID range, DSCP, ECN per side.

### v0.9.7 — March 2026
- **Session navigator** — ‹ / › arrows in SessionDetail to move between sessions on the same edge, ordered by start time with `#N / #M` index.
- **TLS Certificate extraction** — subject CN, issuer, validity dates, SANs, serial number extracted from Certificate handshake and shown in TLS collapse.
- **Two new research charts** — DNS Query Timeline (domain × time, colour = rcode) and JA3 Fingerprint Timeline (remote IP × time, colour = JA3, size = bytes).
- **Charts tab** — renamed from `seq/ack`, moved after Payload.
- **Settings panel** — ⚙ button opens persistent settings. Seven themes: Dark, Dark Blue, OLED Black, Colorblind, Blood, Amber, Synthwave.

### v0.9.6 — March 2026
- **IPv4 Header section enriched** — DF/MF flags, fragmentation observed, IP ID range (hex + decimal), DSCP/QoS with named values. Shown for every IPv4 session, not just when values are non-zero.

### v0.9.5 — March 2026
- **Notes on every node** — collapsible Notes section in NodeDetail for all nodes. Free-text, persisted as annotations with `annotation_type: "note"`, survive graph re-fetches.
- **Synthetic node editing** — inline editable label, IP, and color in NodeDetail when a synthetic node is selected. PUTs immediately.
- **Synthetic node size fixed** — synthetic nodes now render at a meaningful size (default 14px radius) instead of the minimum.

### v0.9.4 — March 2026
- **Seq/Ack chart: Bytes/time + SEQ/ACK modes** — toggle between throughput view (lines, slope = throughput) and SEQ-vs-ACK scatter. Legend moved below chart.
- **SEQ/ACK tab auto-widens panel** to 500px for readability.
- **IPv4/IPv6 Header collapse** in session overview — DF flag, DSCP (named), ECN (decoded), IPv6 flow label. Aggregated from all packets in session.
- **Payload tab redesigned** — ASCII-only by default, Hex toggle, per-packet copy buttons (ASCII / Hex / Raw).
- **IP header fields per packet** — TTL, DF/MF, DSCP, ECN, TCP checksum inline on each payload packet row.
- **ISN per direction** in Advanced section.
- New `PacketRecord` fields: `ecn`, `ip_checksum`, `tcp_checksum`, `ip6_flow_label`.

### v0.9.3 — March 2026
- **Payload tab "Raw bytes" toggle** — hex dump hidden by default, toggle to reveal. Each packet row shows IP header fields inline: TTL, DF/MF, DSCP, ECN, flow label (IPv6), TCP checksum.
- **IP/IPv6 header fields extracted** — ECN, DSCP, IP checksum, TCP checksum, IPv6 flow label now in `PacketRecord` and exposed via the session detail API.
- **ISN per direction in Advanced** — initial sequence numbers for initiator and responder shown in Overview → Advanced, giving context for the relative seq/ack chart.
- **Seq/Ack chart redesigned** — relative SEQ vs time instead of raw SEQ vs ACK. Readable chart showing throughput slope, stalls, retransmits.
- **Empty protocol swatch fixed** — nameless protocol entry in left panel removed.
- **FLAGS tab removed** — flag counts consolidated into Overview → Advanced.

### v0.9.2 — March 2026
- **Merge-by-MAC gateway bug fixed** — external connections no longer collapse after merge. Root cause: `dst_mac` (the gateway MAC) was used in merge groups, causing all external IPs to union-find together. Fixed with src_mac-only + router vendor OUI check + group size cap at 8.
- **NodeDetail: IPs and MACs always visible** — no longer hidden in Advanced. MACs show vendor inline: `c4:d0:e3:8f:6b:69 (Apple)`.
- **JA3/JA4 inline** — app name on the same line as the hash. SessionDetail now uses `JA3Badge` (previously plain text, no app lookup).

### v0.9.1 — March 2026
- **App.jsx refactor** — All state/logic extracted to `useCapture()` hook. App.jsx is pure layout. Eliminates root cause of spurious re-renders (graph wiggle on click).
- **Single version source** — `version.js` is the only place to update version. No more drift.
- **Seq/Ack Timeline in Session Detail** — New SEQ/ACK tab with Run button. Plotly chart inline, no need to navigate to Research.
- **Show Hostnames toggle** — Graph Options toggle to switch between DNS names and raw IPs on node labels.
- **IPv6 connections preserved after merge** — Fixed: `include_ipv6=False` filter was applied before entity resolution, dropping merged-IPv6→IPv4 source packets. Now resolved IPs are checked.
- **scapy used for all files <500MB** — Previously dpkt was used for files ≥20MB, silently breaking DNS hostname resolution, TLS dissection, and all scapy-layer dissectors. dpkt is now only a fallback for files ≥500MB.
- **mac_vendors fixed** — Was never populated due to lookup never being called. Now derived from sorted MACs at serialisation time — parallel array guaranteed correct.
- **JA3 duplicate hashes fixed** — 10 hashes were listed twice: once as a browser/library, once as malware. Real browser hashes (Chrome, Safari, LibreSSL, Tor) were being overwritten with malware labels.
- **8 malformed OUI keys removed** — Keys with 7–8 hex digits that would never match.
- **Annotations/synthetic/metadata cleared on new upload** — Previously bled over from the previous capture.
- **Upload screen larger** — Drop zone 460px, logo 120px.
- **Dozens of smaller bug fixes** — See HANDOFF.md for the full list.

### v0.9.0 — March 2026
- **Dual-stack merge preserves all connections** — IPv4+IPv6 addresses sharing a MAC correctly merge into one node. EdgeDetail session matching now checks all IPs of a merged node.
- **Seq/Ack Timeline chart** — New Research chart.
- **Research panel error boundary** — ChartErrorBoundary prevents one chart crash from blanking the panel.

### v0.8.8 — March 2026
- **Graph no longer wiggles on click** — Memoised `visibleNodes`/`visibleEdges` so simulation doesn't restart on selection changes.

### v0.8.7 — March 2026
- **MAC vendor lookup** — NodeDetail shows vendor name after each MAC (Apple, Cisco, Intel, VMware, Espressif, etc.).
- **JA3 → app name** — Known JA3 hashes resolved to application names. Green badge for legit apps, red ⚠ for known malware.
- **Error isolation** — Dissector and node merger exceptions logged, never crash the graph endpoint.

### v0.8.6 — March 2026
- **SSH dissector** — Banner version and software fingerprint.
- **FTP dissector** — Commands, usernames, filenames, credential detection.
- **DHCP dissector** — Hostname (Option 12), vendor class (Option 60), message type.
- **SMB dissector** — SMBv1/v2/v3, share paths, filenames, NT status codes.
- **ICMPv6 dissector** — NDP types (NS/NA/RA/RS), echo, errors. ICMPv6 no longer classified as OTHER.

### v0.8.5 — March 2026
- **Sessions panel local search** — Independent search inside the Sessions panel.
- **Search scope badge** — Sessions nav item shows `12/381` when search is active.

### v0.8.4 — March 2026
- **Merge-by-MAC fixed** — Multicast IPs/MACs excluded from merging.

### v0.8.3 — March 2026
- **Payload preview** — Hex+ASCII dump in Session Detail Payload tab.
- **Hide node** — Right-click → Hide node. Badge with Unhide all.
- **Retransmission detection** — Retransmits, out-of-order, dup-ACK per session and globally.
- **PCAP export** — "Export pcap" button for the current filtered view.
- **Seq/Ack Timeline** — Research chart and Session Detail link.

### v0.8.0–v0.8.2 — March 2026
- Help page, payload preview, research IP pre-fill, annotation/synthetic fixes.

### v0.7.x — March 2026
- JA3/JA4 fingerprinting, dpkt fallback, Wireshark display filter, investigation mode, subnet uncluster, Timeline page, annotations, synthetic nodes/edges, universal search.
