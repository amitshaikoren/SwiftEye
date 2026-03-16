/**
 * HelpPanel — full right-panel view accessible via LeftPanel nav.
 * Tabs: Guide | Plugins & Protocols
 */
import React, { useState } from 'react';
import Collapse from './Collapse';
import { VERSION } from '../version.js';

// ── Shared primitives ────────────────────────────────────────────────

function KbRow({ keys, desc }) {
  return (
    <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, padding: '4px 0', borderBottom: '1px solid var(--bd)' }}>
      <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
        {keys.map(k => (
          <span key={k} style={{
            fontFamily: 'var(--fn)', fontSize: 10, color: 'var(--tx)',
            background: 'var(--bgC)', border: '1px solid var(--bdL)',
            borderRadius: 4, padding: '1px 6px',
          }}>{k}</span>
        ))}
      </div>
      <span style={{ fontSize: 11, color: 'var(--txM)' }}>{desc}</span>
    </div>
  );
}

function Section({ title, children, open = true }) {
  return (
    <Collapse title={title} open={open}>
      <div style={{ paddingBottom: 6 }}>{children}</div>
    </Collapse>
  );
}

function P({ children }) {
  return <p style={{ fontSize: 11, color: 'var(--txM)', lineHeight: 1.7, marginBottom: 8 }}>{children}</p>;
}

function FieldRow({ field, desc }) {
  return (
    <div style={{ display: 'flex', gap: 8, padding: '4px 0', borderBottom: '1px solid var(--bd)', alignItems: 'baseline' }}>
      <code style={{ fontFamily: 'var(--fn)', fontSize: 10, color: 'var(--ac)', flexShrink: 0, minWidth: 120 }}>{field}</code>
      <span style={{ fontSize: 10, color: 'var(--txM)', lineHeight: 1.5 }}>{desc}</span>
    </div>
  );
}

function Card({ name, nameColor = 'var(--ac)', badge, badgeColor, children }) {
  return (
    <div style={{ background: 'var(--bgC)', border: '1px solid var(--bd)', borderRadius: 6, padding: '10px 12px', marginBottom: 8 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 600, color: nameColor }}>{name}</span>
        {badge && (
          <span style={{
            fontSize: 8, padding: '1px 6px', borderRadius: 8, letterSpacing: '.04em',
            background: (badgeColor || 'var(--acP)') + '22',
            color: badgeColor || 'var(--acP)',
            border: `1px solid ${badgeColor || 'var(--acP)'}44`,
          }}>{badge}</span>
        )}
      </div>
      <div style={{ fontSize: 10, color: 'var(--txM)', lineHeight: 1.6 }}>{children}</div>
    </div>
  );
}

// ── Guide tab ────────────────────────────────────────────────────────

function GuideTab() {
  return (
    <>
      <Section title="What SwiftEye Is">
        <P>SwiftEye is a <strong style={{ color: 'var(--tx)' }}>viewing tool, not an analysis tool</strong>. It shows what is in the captured traffic — you bring the expertise. It never makes security judgments or flags threats.</P>
        <P>Drop a <code style={{ fontFamily: 'var(--fn)', fontSize: 10, color: 'var(--ac)' }}>.pcap</code> or <code style={{ fontFamily: 'var(--fn)', fontSize: 10, color: 'var(--ac)' }}>.pcapng</code> file on the splash screen. Everything is computed in memory — nothing leaves your machine.</P>
      </Section>

      <Section title="Keyboard Shortcuts">
        <KbRow keys={['Esc']}             desc="Deselect node / edge / session — return to Overview" />
        <KbRow keys={['Shift', 'click']}  desc="Add node to multi-selection (scoped stats in right panel)" />
        <KbRow keys={['Double-click']}    desc="Unpin a dragged node — returns it to simulation forces" />
        <KbRow keys={['Enter']}           desc="Apply display filter (when filter bar is focused)" />
        <KbRow keys={['Esc']}             desc="Clear display filter (when filter bar is focused)" />
        <KbRow keys={['Tab']}             desc="Autocomplete current field name in display filter" />
        <KbRow keys={['↑', '↓']}          desc="Navigate autocomplete suggestions" />
      </Section>

      <Section title="Graph Interactions">
        <KbRow keys={['Click node']}          desc="Select node — opens Node Detail in right panel" />
        <KbRow keys={['Click edge']}          desc="Select edge — opens Edge Detail with sessions" />
        <KbRow keys={['Click canvas']}        desc="Deselect" />
        <KbRow keys={['Right-click node']}    desc="Context menu: Investigate neighbours / component, Node detail, Add annotation, Uncluster (subnets), Delete (synthetic)" />
        <KbRow keys={['Right-click edge']}    desc="Context menu: Edge detail, Add annotation, Delete (synthetic)" />
        <KbRow keys={['Right-click canvas']}  desc="Context menu: Add annotation, Add synthetic node/edge, Cluster selected (when 2+ nodes selected)" />
        <KbRow keys={['Shift', 'right-drag']} desc="Lasso select — draw freehand polygon, all nodes inside are selected on release" />
        <KbRow keys={['Drag node']}           desc="Pin node to position — double-click to unpin" />
        <KbRow keys={['Scroll / pinch']}      desc="Zoom in/out" />
        <KbRow keys={['Drag canvas']}         desc="Pan" />
        <KbRow keys={['↺ Relayout']}          desc="Bottom-right button — unpins all nodes and reheats force simulation" />
      </Section>

      <Section title="Timeline Strip" open={false}>
        <KbRow keys={['Drag on bars']}        desc="Paint a new time range — drag across the activity you want" />
        <KbRow keys={['Drag start handle']}   desc="Move start boundary (blue line)" />
        <KbRow keys={['Drag end handle']}     desc="Move end boundary (green line)" />
        <KbRow keys={['Drag inside range']}   desc="Shift the whole selection window" />
        <KbRow keys={['Scroll']}              desc="Zoom in/out on the main view" />
        <KbRow keys={['Right-click']}         desc="Reset viewport and range to full capture" />
        <KbRow keys={['Burst buttons']}       desc="Jump to detected activity regions (shown when 2+ bursts found)" />
        <KbRow keys={['Minimap']}             desc="Click or drag the small overview strip to pan the viewport" />
      </Section>

      <Section title="Three Filter Layers">
        <P>Filters stack. Apply all three simultaneously for precise scoping.</P>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 4 }}>
          {[
            ['1 — Search bar (toolbar)', 'var(--ac)', 'Broad keyword match: IPs, MACs, protocols, ports, flags. Re-fetches graph and sessions from server on each change.'],
            ['2 — Display filter bar', 'var(--acG)', 'Wireshark-style expressions evaluated client-side. Non-matching nodes/edges dim to 5% opacity. No re-fetch. See field reference below.'],
            ['3 — Investigate mode', 'var(--acP)', 'Right-click node → Investigate. Dims everything outside the connected component. BFS-based — follows all hops. Exit banner to clear.'],
          ].map(([title, color, desc]) => (
            <div key={title} style={{ background: 'var(--bgC)', border: '1px solid var(--bd)', borderRadius: 6, padding: '8px 10px' }}>
              <div style={{ fontSize: 10, fontWeight: 600, color, marginBottom: 4 }}>{title}</div>
              <div style={{ fontSize: 10, color: 'var(--txM)', lineHeight: 1.6 }}>{desc}</div>
            </div>
          ))}
        </div>
      </Section>

      <Section title="Display Filter Field Reference" open={false}>
        <P>Syntax: <code style={{ fontFamily: 'var(--fn)', fontSize: 10, color: 'var(--ac)' }}>field op value</code> — combine with <code style={{ fontFamily: 'var(--fn)', fontSize: 10, color: 'var(--ac)' }}>&amp;&amp;</code> <code style={{ fontFamily: 'var(--fn)', fontSize: 10, color: 'var(--ac)' }}>||</code> <code style={{ fontFamily: 'var(--fn)', fontSize: 10, color: 'var(--ac)' }}>!</code></P>
        <P>Operators: <code style={{ fontFamily: 'var(--fn)', fontSize: 10, color: 'var(--ac)' }}>== != &gt; &lt; &gt;= &lt;= contains matches</code></P>
        {[
          ['ip', 'Any IP on a node, or either endpoint of an edge. Supports CIDR: ip == 10.0.0.0/24'],
          ['ip.src / ip.dst', 'Source or destination IP of an edge specifically'],
          ['mac', 'MAC address on a node'],
          ['hostname', 'Resolved DNS hostname on a node'],
          ['protocol', 'Protocol name on node or edge'],
          ['port', 'Any port seen on an edge'],
          ['bytes / packets', 'Traffic volume on a node or edge'],
          ['tls.sni', 'TLS Server Name Indication on an edge'],
          ['http.host', 'HTTP Host header on an edge'],
          ['dns', 'DNS query name on an edge'],
          ['os', 'OS fingerprint guess on a node (e.g. os contains "Linux")'],
          ['role', 'Network role: "gateway", "lan", "external" — from Network Map plugin'],
          ['gateway', 'Boolean — node is a router/gateway (no operator needed, like private/subnet)'],
          ['private', 'Boolean — node has a private IP (no operator needed)'],
          ['subnet', 'Boolean — node is a grouped subnet (no operator needed)'],
        ].map(([f, d]) => <FieldRow key={f} field={f} desc={d} />)}
      </Section>

      <Section title="Panels" open={false}>
        {[
          ['Overview', 'Global capture overview: total packets/bytes, protocol hierarchy, top talkers, plugin sections (OS fingerprint summary, DNS hostnames, TCP flags).'],
          ['Sessions', 'All reconstructed bidirectional flows. Sortable by bytes, packets, duration. Click to open Session Detail with directional stats, TLS fingerprints, DNS queries, payload preview.'],
          ['Timeline', 'Full-width Plotly Gantt of all sessions. Adjust time scope then click Run. Respects active protocol and search filters.'],
          ['Research', 'On-demand charts: Conversation Timeline, TTL Over Time, DNS Query Timeline, JA3/JA4 Fingerprint Timeline, SEQ/ACK charts. Pre-fills target IP from Investigate mode.'],
          ['Analysis ✦', 'Graph-wide analyses computed in the backend. Each card is a Python plugin — researchers add new analyses without touching frontend code. Currently: Node Centrality (degree, betweenness, traffic-weighted score) and Traffic Characterisation (foreground vs background sessions). LLM Interpretation coming in a future release.'],
          ['Investigation', 'Markdown notebook for documenting findings. Split-pane editor with live preview. Paste screenshots with Ctrl+V or drag-and-drop images. Auto-saves to the backend. Export as PDF with embedded images for reports.'],
          ['Visualize', 'Upload any tabular data (CSV, TSV, JSON) and map columns to a force-directed graph. Supports edge label/color/weight, node color/size, hover data, and an optional timestamp column for time-based filtering. Entirely frontend — data never touches the server.'],
          ['Server Logs', 'Live server log stream. Useful for debugging parse errors.'],
          ['Node Detail', 'IPs, MACs, hostnames, researcher metadata, TTLs, OS fingerprint, network role, connections split by direction.'],
          ['Edge Detail', 'Traffic volume, ports, TLS details (SNI, version, ciphers, certificate, JA3/JA4), HTTP hosts, DNS queries, linked sessions.'],
        ].map(([name, desc]) => (
          <div key={name} style={{ padding: '6px 0', borderBottom: '1px solid var(--bd)' }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--tx)', marginBottom: 2 }}>{name}</div>
            <div style={{ fontSize: 10, color: 'var(--txM)', lineHeight: 1.6 }}>{desc}</div>
          </div>
        ))}
      </Section>

      <Section title="Graph Options" open={false}>
        {[
          ['Subnet /N', 'Group IPs into /N subnets. Right-click a subnet node → Uncluster to expand just that one. Toggling off clears all exclusions.'],
          ['Merge by MAC', 'IPs sharing a source MAC are merged into one node. IPs with multiple distinct MACs (IP conflict / cloned VMs) are kept separate automatically.'],
          ['Show IPv6', 'When off, hides IPv6 nodes (link-local, multicast). Reduces noise in dual-stack captures.'],
          ['Show hostnames', 'Show DNS-resolved hostnames as node labels (cyan). Toggle off to always show raw IPs.'],
          ['Label threshold', 'Hide node labels below a traffic threshold (off / 1 KB / 10 KB / 100 KB / 1 MB / 10 MB). Hovering a node always shows its label.'],
        ].map(([name, desc]) => (
          <div key={name} style={{ padding: '5px 0', borderBottom: '1px solid var(--bd)' }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--ac)', marginBottom: 1 }}>{name}</div>
            <div style={{ fontSize: 10, color: 'var(--txM)', lineHeight: 1.5 }}>{desc}</div>
          </div>
        ))}
      </Section>

      <Section title="Researcher Tools" open={false}>
        {[
          ['META button', 'Upload a JSON file mapping IPs or MACs to labels and notes. The "name" field becomes the node label on the graph.'],
          ['Annotations', 'Right-click empty canvas, or a node/edge → Add annotation. Pinned labels on the graph, persisted per-session.'],
          ['Synthetic nodes/edges', 'Right-click canvas → Add synthetic node / edge. Hypothesis elements: dashed rendering, ✦ marker, custom colour.'],
          ['Synthetic cluster', 'Select 2+ nodes (Shift+click or lasso), then right-click canvas → Cluster selected. Creates a single purple cluster node; external edges are rerouted automatically.'],
          ['Investigate neighbours', 'Right-click node → Investigate neighbours. Dims everything except the node and its direct peers (depth-1).'],
          ['Investigate component', 'Right-click node → Investigate component. Dims everything outside the full connected component (BFS).'],
          ['Lasso select', 'Shift + right-click-drag draws a freehand polygon. All nodes inside are selected on release.'],
          ['Relayout', 'Bottom-right ↺ button. Unpins all manually dragged nodes and reheats the force simulation for a clean layout.'],
          ['Notes', 'Free-text note on any node (bottom of Node Detail). Persisted across selections.'],
          ['Themes', 'Settings panel (⚙) — 8 themes: Dark, Dark Blue, OLED, Colorblind, Blood, Amber, Synthwave, Pastel. Saved across sessions.'],
        ].map(([name, desc]) => (
          <div key={name} style={{ padding: '5px 0', borderBottom: '1px solid var(--bd)' }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--acG)', marginBottom: 1 }}>{name}</div>
            <div style={{ fontSize: 10, color: 'var(--txM)', lineHeight: 1.5 }}>{desc}</div>
          </div>
        ))}
      </Section>

      <div style={{ marginTop: 20, fontSize: 9, color: 'var(--txD)', lineHeight: 1.7 }}>
        File limits: 500 MB max. Files ≥ 500 MB use dpkt (fast); smaller files use scapy (richer dissection).<br />
        Supported: .pcap, .pcapng, .cap
      </div>
    </>
  );
}

// ── Plugins & Protocols tab ──────────────────────────────────────────

function PluginsTab() {
  return (
    <>
      {/* Plugins */}
      <Section title="Plugins" open={true}>
        <P>Plugins run automatically after every pcap load. Results appear in Node Detail, Edge Detail, and the Stats panel.</P>

        <Card name="OS Fingerprint" badge="node" badgeColor="var(--acP)">
          Passively identifies the operating system of each host from TCP SYN and SYN+ACK packets. Uses TTL, window size, MSS, and TCP option order as signals. Detects Windows 10/11, Linux 4.x/5.x, macOS/iOS, Cisco IOS, FreeBSD, and more. Confidence score included. No packets are sent — read-only.
        </Card>

        <Card name="Network Map" badge="node" badgeColor="var(--acG)">
          Passively reconstructs the local topology. Builds an ARP table (IP → MAC) from ARP requests and replies. Identifies gateways by finding the MAC that appears as destination for traffic to external IPs. Estimates hop counts to remote hosts via TTL analysis (observed TTL subtracted from nearest standard initial value: 64, 128, or 255). Gateway nodes render as diamonds on the graph.
        </Card>

        <Card name="DNS Resolver" badge="node" badgeColor="var(--ac)">
          Extracts hostnames from captured DNS response packets and attaches them to the corresponding IP nodes. Hostnames appear as node labels and are searchable via the search bar and <code style={{ fontFamily: 'var(--fn)', fontSize: 9, color: 'var(--ac)' }}>hostname</code> display filter field.
        </Card>

        <Card name="TCP Flags" badge="stats" badgeColor="var(--acO)">
          Analyses TCP flag distribution across all sessions. Counts SYN, SYN+ACK, FIN, RST, PSH, URG packets and attributes them to initiator or responder. Surfaces in the Stats panel as a flag frequency breakdown. Useful for spotting half-open scans (SYN floods), abrupt resets, or unusual flag combinations.
        </Card>

        <Card name="Retransmission Detector" badge="session" badgeColor="var(--acR)">
          Identifies TCP retransmissions and out-of-order packets per session by tracking sequence numbers. Retransmission count and rate appear in Session Detail. High retransmission rates indicate packet loss, congestion, or a network path quality issue.
        </Card>
      </Section>

      {/* Protocol dissectors */}
      <Section title="Protocol Dissectors" open={true}>
        <P>Dissectors extract application-layer fields from packet payloads. Fields appear in Edge Detail, Session Detail, and the display filter. All dissection is passive (read-only).</P>
        <P style={{ fontSize: 9, color: 'var(--txD)', fontStyle: 'italic' }}>
          Note: full dissection requires files under 500 MB (scapy path). Larger files use dpkt which extracts fewer fields.
        </P>

        <Card name="TLS / HTTPS" badge="port 443 + others" badgeColor="var(--acG)">
          Extracts: TLS record version, ClientHello/ServerHello message type, negotiated version (TLS 1.0–1.3), offered cipher suites, selected cipher, SNI (Server Name Indication). Also parses the Certificate handshake message to extract subject CN, issuer, validity dates, SANs, and serial number — visible in the TLS collapse in Session Detail. Certificates are only available in TLS 1.2 and earlier; TLS 1.3 certificates are encrypted.
          <br /><br />
          JA3 and JA4 fingerprints are computed from the ClientHello and shown in Edge Detail and Session Detail with known-app lookups.
        </Card>

        <Card name="DNS" badge="port 53" badgeColor="var(--ac)">
          Extracts: query name, query type (A, AAAA, MX, etc.), response code (NOERROR, NXDOMAIN, SERVFAIL, REFUSED), and resolved answers. DNS responses feed the DNS Resolver plugin for hostname labeling. Available in Edge Detail and the DNS Query Timeline research chart.
        </Card>

        <Card name="HTTP" badge="port 80 + others" badgeColor="var(--acO)">
          Extracts: request method (GET, POST, etc.), Host header, URL path, response status code, content type. Available in Edge Detail and searchable via <code style={{ fontFamily: 'var(--fn)', fontSize: 9, color: 'var(--ac)' }}>http.host</code> display filter.
        </Card>

        <Card name="SSH" badge="port 22" badgeColor="var(--acP)">
          Extracts: client and server software version strings (e.g. OpenSSH_8.9, libssh-0.9). Visible in Session Detail under the SSH section. Useful for identifying outdated SSH implementations or non-standard clients.
        </Card>

        <Card name="FTP" badge="port 21" badgeColor="var(--acO)">
          Extracts: FTP commands and responses, including USER, PASS (plaintext credentials), RETR/STOR filenames, server banner. Credentials appear in Session Detail. Note: FTP sends passwords in cleartext — this dissector surfaces them as-found in the capture.
        </Card>

        <Card name="SMB" badge="port 445" badgeColor="var(--acR)">
          Extracts: SMB dialect version (SMB1, SMB2, SMB3), command type, tree connect paths (share names), file operation commands (READ, WRITE, CREATE). Useful for mapping lateral movement, share enumeration, or file staging.
        </Card>

        <Card name="ICMP" badge="protocol 1" badgeColor="var(--txM)">
          Extracts: ICMP type and code with human-readable names (Echo Request/Reply, Destination Unreachable, Time Exceeded, Redirect, etc.). Useful for spotting ping sweeps, traceroute traffic, or path MTU discovery.
        </Card>

        <Card name="DHCP" badge="ports 67/68" badgeColor="var(--acG)">
          Extracts: DHCP message type (Discover, Offer, Request, ACK, NAK, Release), offered IP, client MAC, hostname option (option 12), and lease duration. Useful for mapping which IPs were dynamically assigned and to which hosts.
        </Card>
      </Section>

      {/* Research charts */}
      <Section title="Research Charts" open={true}>
        <P>Available in the Research panel. Charts run on-demand — click Run after entering parameters.</P>

        <Card name="Conversation Timeline" badge="target IP" badgeColor="var(--ac)">
          All peers of a target IP plotted over time. X = time, Y = peer IP, colour = protocol, size = bytes. Shows which peers are persistent vs transient and which protocol dominates each relationship.
        </Card>

        <Card name="DNS Query Timeline" badge="no params" badgeColor="var(--ac)">
          Every DNS query in the capture plotted as domain × time. Colour = response code: green = NOERROR, red = NXDOMAIN, orange = SERVFAIL, purple = REFUSED. Useful for DGA detection (spray of NXDOMAINs) and C2 beaconing (periodic queries to same domain).
        </Card>

        <Card name="JA3 Fingerprint Timeline" badge="target IP" badgeColor="var(--acP)">
          TLS sessions for a target IP. X = session start time, Y = remote IP, colour = JA3 hash (with known-app name in legend), size = bytes. Shows which TLS fingerprint was used per connection. An unusual JA3 among otherwise normal browser traffic is a C2 signal.
        </Card>

        <Card name="JA4 Fingerprint Timeline" badge="target IP" badgeColor="var(--acP)">
          Same layout as JA3 timeline but using JA4 hashes. JA4 encodes TLS version, cipher count, and extension list — more stable across minor client updates and less prone to false-positive matches than JA3.
        </Card>

        <Card name="TTL Over Time" badge="two IPs" badgeColor="var(--acO)">
          Plots the TTL of packets between two IPs over the session duration. A mid-session TTL change can indicate route changes, MITM, or load balancer failover.
        </Card>

        <Card name="Session Gantt" badge="no params" badgeColor="var(--acG)">
          All sessions as a Gantt chart — one bar per session, sorted by start time. Width = duration, colour = protocol. Quickly shows session overlap and whether connections were sequential or parallel.
        </Card>

        <Card name="SEQ/ACK Timeline" badge="session ID" badgeColor="var(--txM)">
          TCP sequence and acknowledgement numbers over time for a single session. Two modes: Bytes/Time (data throughput shape) and SEQ/ACK (raw sequence number progression). Useful for identifying retransmission bursts, slow-start behaviour, or abrupt resets.
        </Card>
      </Section>
    </>
  );
}

// ── Main component ───────────────────────────────────────────────────

export default function HelpPanel() {
  const [tab, setTab] = useState('guide');

  const tabs = [
    { id: 'guide',    label: 'Guide' },
    { id: 'plugins',  label: 'Plugins & Protocols' },
  ];

  return (
    <div className="fi" style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      {/* Header */}
      <div style={{ padding: '16px 16px 0', flexShrink: 0 }}>
        <div style={{ fontSize: 14, fontWeight: 700, fontFamily: 'var(--fd)', marginBottom: 2 }}>Help</div>
        <div style={{ fontSize: 10, color: 'var(--txD)', marginBottom: 12 }}>SwiftEye v{VERSION} — Network traffic visualization for security researchers</div>

        {/* Tabs */}
        <div style={{ display: 'flex', gap: 4, borderBottom: '1px solid var(--bd)', marginBottom: 0 }}>
          {tabs.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className="btn"
              style={{
                fontSize: 10, padding: '4px 12px', borderRadius: '4px 4px 0 0',
                borderBottom: tab === t.id ? '2px solid var(--ac)' : '2px solid transparent',
                color: tab === t.id ? 'var(--ac)' : 'var(--txM)',
                fontWeight: tab === t.id ? 600 : 400,
              }}>
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '12px 16px 16px' }}>
        {tab === 'guide'   && <GuideTab />}
        {tab === 'plugins' && <PluginsTab />}
      </div>
    </div>
  );
}
