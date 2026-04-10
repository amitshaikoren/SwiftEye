# Session State

**Last updated:** 2026-04-10 · **Current version:** v0.24.0
**Current branch:** main
**Mirror sync state:** all mirrors current as of v0.24.0

> Live, per-session cache. Read first after `CLAUDE.md`.
> Write here during the session. Flush to human docs only at merge — not mid-session.

---

## Shipped this session

- v0.24.0 (branch: fix/qol-bugs) — QOL bug batch: alerts live-load bug, schema-dialog-in-app, manual-type-override (TypePickerDialog), detail-panel flag button polish, animation direction mismatch (initiator_ip), timeline-graph drag-render bug (setTick in onNodePointerMove).

- v0.23.0 — **adapter-schema-negotiation** merged to main. New `backend/parser/schema/` package (contracts, inspector, staging) sits as its own layer before any adapter. All Zeek + tshark metadata adapters declare `declared_fields` and implement `get_header_columns()` / `get_raw_rows()` / `_rows_to_packets()` / `parse_with_mapping(mapping)`. Upload is two-phase: detect → inspect schema → if clean proceed; if mismatch, stage file (UUID token), return `schema_negotiation_required: true` + `schema_report` + `staging_token`. `POST /api/upload/confirm-schema` accepts token + confirmed mapping → resumes ingestion. Frontend: `SchemaDialog.jsx` (mapping table, required-field warnings, suggested-mapping pre-fill, Confirm & Ingest). Detection is now format-based (Zeek conn = catch-all with `#fields` marker only, no extension required; tshark metadata = catch-all with `.csv` + ≥15 tab-separated columns). 25 backend tests. Test fixtures gitignored.

---

## Do next

- `d3-force-tuning` — discuss slider vs constant tweak first
- `timeline-graph-multi-select-features` — box-select, protocol-select, bulk filter
- `timeline-to-research-gantt` — remove Timeline panel, move Gantt to Research
- `save-load-workspaces` — serialize annotations/synthetics/positions
- `subnet-node-visual-redesign` — subnets need distinct look

---

## Known issues (not fixed, not blocking)

- **Post-parse pipeline bottleneck** — `build_sessions + build_graph + plugins` ~20s for 440K packets. Roadmap: `post-parse-pipeline-opt`.
- **"Size by" graph option** — user considers it poor quality, needs review pass.
- **ICMPv6 dissector** — no raw fallback. Extra stays `{}`.
- **scapy DNS deprecation** — `dns.qd` → `dns.qd[0]`. 39K warnings per test run.
- **dpkt `IP.off` deprecation** — should use new field name.

## Deferred

- **Alerts Phase 2** — design complete in `docs/plans/ALERTS_PHASE2_PLAN.md`. Deprioritized.

---

## Blocked on

- Nothing.

---

## Pending ROADMAP.md flush

- [ ] `ROADMAP.md` — append new item `timeline-graph-multi-select-features` to category "Investigation & Events":
  <details>
  <summary>Detail block to insert</summary>

  ### timeline-graph-multi-select-features
  Extend the shift-select multi-selection already present in the timeline graph (v0.22.7) with additional selection modes and actions. Planned features: (1) box-select by dragging on the canvas background; (2) select-all-edges-by-protocol (right-click a protocol badge → "Select all [DNS]"); (3) a selection count/edge badge shown while multiple edges are selected; (4) a "Filter graph to selection" bulk action that scopes the main graph view to only the selected node pair(s). Key files: `InvestigationPage.jsx` (TimelineGraph host), `TimelineGraph.jsx` or equivalent component in `frontend/src/components/`. Multi-select state currently lives in `useCapture.js` timeline edge state — extending it should follow the existing `selectedEdgePair` pattern.
  `status: pending` · `priority: high` · `term: short` · `effort: medium` · `depends: timeline-graph-phase2`
  </details>

- [ ] `ROADMAP.md` — append new item `timeline-to-research-gantt` to category "Investigation & Events":
  <details>
  <summary>Detail block to insert</summary>

  ### timeline-to-research-gantt
  Remove the dedicated Timeline panel tab from the left-panel nav and move the session Gantt chart into the Research panel as a first-class chart entry (category: "session" or "capture"). The Timeline tab currently hosts `TimelinePanel.jsx` which renders the Gantt and the bucket-sec slider. At flush: (1) delete or repurpose `TimelinePanel.jsx` as a `ResearchChart` subclass in `backend/research/`; (2) remove the `timeline` nav entry from `LeftPanel.jsx` and `App.jsx`; (3) keep bucket-sec state in `useCapture.js` but only render the control inside the Research chart's filter bar. The `timeRange` / `setTimeRange` props used by other panels (sessions, stats, graph) must remain untouched — only the Gantt display moves. Confirm with user whether the timeline slider in the top bar should also be removed or kept.
  `status: pending` · `priority: medium` · `term: short` · `effort: medium` · `depends: none`
  </details>
