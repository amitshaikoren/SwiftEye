# Roadmap — AI Reference

**v0.26.1 | 2026-04-11** · Source of truth: `ROADMAP.md`. Mirrors main state only — branch-local work is not reflected until after merge.
Detail blocks (design notes, files-touched, depends) live in `ROADMAP.md` per item — read by anchor (`#item-id`) only when picking up that item.

---

## Status values
`pending` · `in-progress` · `blocked` · `done` (done items move to `COMPLETED.md`)

## Legend
- **Term:** `short` (next few sessions) · `medium` (weeks–months) · `long` (architectural / multi-month)
- **Priority:** `critical` · `high` · `medium` · `low`
- **Effort:** `low` (<1 session) · `medium` (1–3) · `high` (3+)
- **Opus?:** marked **yes** for items in `docs/plans/persistent/FOR_OPUS.md`. Tell the user to switch to Opus.

---

## Status table

| ID | Status | Pri | Effort | Term | Opus? | Summary |
|---|---|---|---|---|---|---|
| `docs-audit` | pending | critical | low | short | — | Audit docs for gaps/outdated since v0.15 |
| `edge-node-refactor-tests` | pending | critical | medium | short | — | Tests for v0.20.0 directional edges, cross-refs, Zeek has_handshake |
| `codebase-health-audit` | pending | critical | medium | short | — | Audit last 6 minors for bottlenecks/coupling/violations |
| `alerts-live-load-bug` | done | critical | low | short | — | Fixed v0.24.0 — re-fetch after first graph response. |
| `qa-test-suite` | pending | high | medium | short | — | Comprehensive pytests + human QA checklists. Human UI scenarios in `audits/codex_audits/2026-04-09/13_human_ui_qa_checklist.md` (10 scenarios: graph discoverability, animation comprehension, right-panel reading, research workflow, alerts-to-graph flow, keyboard nav, small-screen sanity, loading/error states, overall polish). Run after any significant UI change. Key items from audit-06: interaction hints for undiscoverable gestures (right-click, lasso, double-click); filter-system labeling (which filter is active?); keyboard panel switching; font/touch target sizes. |
| `event-type-system` | done | high | high | long | **yes** | Phase 1 shipped v0.21.0 + v0.21.1 on main. Phase 2 tracked as `event-suggested-edges-pluggable`. |
| `timeline-graph-phase2` | done | high | medium | medium | — | All 8 items shipped v0.22.0–v0.22.7 on main. |
| `investigation-panel-redesign` | blocked | high | high | medium | — | Depends on event-type-system |
| `event-suggested-edges-pluggable` | pending | medium | medium | medium | — | Phase 2: pluggable suggested-edge logic so researchers can define custom connection reasons |
| `save-load-workspaces` | pending | high | medium | short | — | Serialize annotations/synthetics/positions to JSON |
| `usecapture-decomposition` | pending | high | high | medium | **yes** | Split 970-line god hook into domain slices |
| `alerts-edge-detectors` | pending | high | medium | short | — | Refactor detectors to use edge/node graph data + triage |
| `animation-pane-timeline-sync` | pending | high | low | short | — | Timeline strip shows capture-relative position of frame |
| `animation-direction-mismatch` | done | high | low | short | — | Fixed v0.24.0 — uses initiator_ip/responder_ip. |
| `animation-node-persistence-stability` | pending | high | low | short | — | Persist dragged positions across panel switches |
| `detail-panel-polish` | done | high | low | short | — | Fixed v0.24.0 — Flag text removed, icon only. |
| `timeline-graph-phase3` | done | high | low | short | — | Both items fixed in v0.24.0. Moved to COMPLETED.md. |
| `timeline-graph-multi-select-features` | pending | high | medium | short | — | Extend timeline-graph multi-selection: box-select, select-by-protocol, edge count badge, bulk graph-filter action |
| `timeline-to-research-gantt` | pending | medium | medium | short | — | Remove Timeline panel tab; move session Gantt into Research as a first-class chart |
| `d3-force-tuning` | pending | high | low | short | — | GraphCanvas force sim too strong; review charge/distanceMax, discuss whether to add a slider |
| `subnet-node-visual-redesign` | pending | high | low | short | — | Subnets don't look distinct from regular nodes |
| `query-topology-phase2` | pending | high | medium | medium | — | Topology operators: connects_to, degree, same_neighbors_as |
| `ui-capabilities-system` | pending | high | medium | medium | — | Hide UI sections when source doesn't provide that data |
| `adapter-schema-negotiation` | done | high | medium | medium | — | Shipped v0.23.0 — two-phase upload, schema/ package, SchemaDialog.jsx. Moved to COMPLETED.md. |
| `schema-dialog-in-app` | done | high | low | short | — | Fixed v0.24.0 — SchemaDialog rendered in loaded app view. |
| `manual-type-override` | done | high | low | short | — | Fixed v0.24.0 — TypePickerDialog + force_adapter backend param. |
| `parquet-ingestion` | pending | high | medium | medium | — | Ingest .parquet (Splunk, AWS VPC, Databricks) |
| `llm-interpretation-panel` | pending | high | medium | medium | — | Capture summary → LLM → plain explanation |
| `post-parse-pipeline-opt` | pending | high | medium | medium | — | Profile build_sessions/build_graph/plugins (~20s for 440K) |
| `graceful-optional-deps` | pending | medium | low | short | — | Optional deps (plotly, sqlglot) should degrade gracefully on import failure rather than aborting startup; research charts would be disabled not fatal |
| `lazy-post-parse-audit` | pending | high | low | short | — | Decide what runs at load vs on-demand |
| `large-pcap-support` | pending | high | high | medium | **yes** | Streaming parse, background load, indexed store |
| `spark-connector` | pending | high | high | long | **yes** | Spark/Databricks SQL connector (enterprise mode) |
| `graph-db-backend` | pending | high | high | long | **yes** | Neo4j / LadybugDB / Postgres+AGE persistent graph |
| `notebook-integration` | pending | high | medium | long | — | swifteye-sdk Python package |
| `centrality-backend-migration` | pending | medium | medium | short | — | Move client-side Brandes (AnalysisPage.jsx:12-59) to `GET /api/analysis/centrality`; reuses existing `node_centrality.py` plugin. Plan: `docs/plans/active/centrality-backend.md`. Does NOT require graph-db-backend. |
| `analysis-traffic-characterisation` | pending | low | medium | short | — | Foreground/background classification |
| `graphcanvas-extraction` | pending | medium | medium | medium | — | Extract render helpers from 1300-line GraphCanvas |
| `react-contexts` | pending | medium | medium | medium | — | Replace prop drilling with context |
| `pcapng-battle-test` | pending | medium | medium | medium | — | Validate dpkt.pcapng on real-world captures |
| `alerts-adapter-compat` | pending | medium | medium | short | — | Detector source_type awareness + AlertsPanel filtering |
| `logo-home-button` | pending | medium | low | short | — | Logo/home button fails to navigate home from some panels (e.g. Research) |
| `animation-back-button` | pending | medium | low | short | — | "Back to animation" affordance |
| `session-detail-sticky-header` | pending | medium | low | short | — | Connection header stays anchored on scroll |
| `graph-direction-viz` | pending | medium | medium | short | — | Show traffic direction (particles/arrowheads) |
| `edge-custom-hover-fields` | pending | medium | medium | medium | — | Researcher-configurable edge hover fields |
| `edge-port-pairs` | pending | medium | low | short | — | Restructure edge ports as paired data |
| `timeline-playback` | pending | medium | low | short | — | Play button auto-advances time window |
| `credential-viewing` | pending | medium | medium | medium | — | HTTP Basic, FTP, Telnet, SMTP AUTH credentials |
| `zeek-files-log` | pending | medium | low | medium | — | Surface Zeek files.log (hashes, MIME types) |
| `sql-query-layer` | pending | medium | medium | medium | — | SELECT * FROM sessions WHERE... endpoint |
| `multi-source-search` | pending | medium | medium | medium | — | Zeek UID, conn_state, service in display filter |
| `app-layer-enrichment` | pending | medium | high | medium | — | Richer per-packet HTTP/TLS/SSH/FTP/SMB/ICMP/DHCP |
| `sysmon-ingestion` | pending | medium | medium | medium | — | Sysmon Event ID 3/22/1 adapter |
| `interactive-research-dashboard` | pending | medium | high | medium | — | Cross-filtering Plotly charts |
| `custom-chart-scalable-sources` | pending | medium | medium | medium | — | Auto-derive custom chart sources from protocol_fields |
| `research-per-chart-filters` | pending | medium | low | short | — | Per-chart filter declarations |
| `centralized-filter-state` | pending | medium | medium | medium | — | Single filter store across all panels |
| `insight-plugin-graph-ctx` | pending | medium | medium | medium | — | Insights receive empty nodes/edges (graph runs after) |
| `node-agnostic-algorithm-contract` | pending | medium | medium | medium | — | Algorithms work on any node type |
| `aggregator-plugin-tier` | pending | medium | medium | medium | — | Pre-aggregation plugins returning IP→canonical |
| `graph-by-field-mode` | pending | medium | medium | medium | — | Graph by port/protocol as node identity |
| `export-html-enriched-hover` | pending | medium | low | short | — | Richer hover in exported HTML |
| `capture-schema-viewer` | pending | medium | medium | medium | — | Post-ingestion schema panel |
| `multi-capture-comparison` | pending | medium | high | long | — | Side-by-side / overlay of two captures |
| `suricata-ingestion` | pending | low | high | medium | — | Ingest Suricata eve.json |
| `graph-layout-modes` | pending | low | high | medium | — | Hierarchical/radial/geographic layouts |
| `graph-legend-sync` | pending | low | low | short | — | Canvas legend reflects active color mode |
| `analysis-hostname-cert-grouping` | pending | low | medium | medium | — | Cluster external IPs by cert/TLD/hostname |
| `l2-protocol-support` | pending | medium | high | long | — | LLDP, 802.1Q VLAN, CDP, STP — currently dropped |
| `graph-algorithm-plugin-registry` | pending | low | low | long | — | Auto-discovery for graph algorithm modules |
| `geolocation` | pending | low | medium | long | — | IP geolocation overlay |

---

## Sections (in `ROADMAP.md` for design details)

| Section | Items |
|---|---|
| Graph & Visualization | graph-direction-viz, edge-port-pairs, graph-by-field-mode, graph-layout-modes, export-html-enriched-hover, graph-legend-sync, subnet-node-visual-redesign, capture-schema-viewer, graph-db-backend |
| Session & Data Display | session-detail-sticky-header, edge-custom-hover-fields, animation-* |
| Query System | query-topology-phase2, sql-query-layer, multi-source-search |
| Analysis Panel | llm-interpretation-panel, analysis-hostname-cert-grouping, analysis-traffic-characterisation |
| Data Ingestion & Protocols | adapter-schema-negotiation, parquet-ingestion, sysmon-ingestion, suricata-ingestion, l2-protocol-support, app-layer-enrichment, zeek-files-log, credential-viewing, pcapng-battle-test |
| Scale & Performance | post-parse-pipeline-opt, lazy-post-parse-audit, large-pcap-support, centrality-backend-migration |
| Investigation & Events | event-type-system, investigation-panel-redesign, event-suggested-edges-pluggable, timeline-graph-phase2, timeline-graph-multi-select-features, timeline-to-research-gantt |
| Enterprise Mode | spark-connector, notebook-integration, multi-capture-comparison |
| Save & Workspaces | save-load-workspaces |
| Frontend Refactors | usecapture-decomposition, graphcanvas-extraction, react-contexts, centralized-filter-state |
| Housekeeping | docs-audit, edge-node-refactor-tests, codebase-health-audit, qa-test-suite, alerts-edge-detectors, alerts-adapter-compat |

To get an item's design notes: `grep -n "^### <item-id>" ROADMAP.md` then read the next ~30 lines.
