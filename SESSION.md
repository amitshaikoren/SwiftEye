# Session State

**Last updated:** 2026-04-11 · **Current version:** v0.25.0
**Current branch:** main
**Mirror sync state:** all mirrors current as of v0.25.0

> Live, per-session cache. Read first after `CLAUDE.md`.
> Write here during the session. Flush to human docs only at merge — not mid-session.

---

## Shipped this session

- v0.25.0 (branch: refactor/usecapture-decomposition) — useCapture.js decomposition. Split 1143-line monolith hook into 5 domain slices + coordinator. Pure refactor, identical return object. Phase 3 item #1 complete.

- v0.24.0 (branch: fix/qol-bugs) — QOL bug batch: alerts live-load bug, schema-dialog-in-app, manual-type-override (TypePickerDialog), detail-panel flag button polish, animation direction mismatch (initiator_ip), timeline-graph drag-render bug (setTick in onNodePointerMove).

- v0.23.0 — **adapter-schema-negotiation** merged to main. New `backend/parser/schema/` package (contracts, inspector, staging) sits as its own layer before any adapter. All Zeek + tshark metadata adapters declare `declared_fields` and implement `get_header_columns()` / `get_raw_rows()` / `_rows_to_packets()` / `parse_with_mapping(mapping)`. Upload is two-phase: detect → inspect schema → if clean proceed; if mismatch, stage file (UUID token), return `schema_negotiation_required: true` + `schema_report` + `staging_token`. `POST /api/upload/confirm-schema` accepts token + confirmed mapping → resumes ingestion. Frontend: `SchemaDialog.jsx` (mapping table, required-field warnings, suggested-mapping pre-fill, Confirm & Ingest). Detection is now format-based (Zeek conn = catch-all with `#fields` marker only, no extension required; tshark metadata = catch-all with `.csv` + ≥15 tab-separated columns). 25 backend tests. Test fixtures gitignored.

---

## Audit plan: code_readability / maintainability (audit 02)

Source: `audits/codex_audits/2026-04-09/02_code_readability_scalability_maintainability_audit.md`
Second-pass: `09_second_pass_frontend_hotspots.md`, `10_second_pass_backend_hotspots.md`

### Phase 1 — Backend bugs (safe, targeted) ✅ done this session
- [x] Remove duplicate `IPv4Address` import in `backend/data/aggregator.py:23`
- [x] Fix bucket cap comment drift: comment said 5000, constant is 15000 (`aggregator.py:67`)
- [x] Fix sort field mismatch: `memory.py` sorted on `bytes_total`, sessions use `total_bytes`

### Phase 2 — Backend architecture ✅ done this session (branch: fix/audit-02-backend-arch)
- [x] Extract `_session_matches_edge` + helpers into `data/session_match.py`; removes storage import from data layer
- [x] Consolidate `flag_filter` + `search_query` into `filter_packets`; removed duplicate handling in `build_graph`
- [x] Add view-layer-limit comment on edge field caps

### Phase 3 — Frontend splits (large, multiple sessions, Opus for useCapture — each on its own branch)

**Recon pass complete (Sonnet, 2026-04-10):** Full dependency map written to `docs/plans/active/usecapture-decomposition.md`. Covers all state/ref/effect inventory, 12 cross-slice dependency points with resolutions, proposed 5-slice breakdown with coordinator, stale closure traps, and implementation order. Ready for Opus to execute from that doc.

**GraphCanvas recon complete (Sonnet, 2026-04-11):** Full dependency map written to `docs/plans/active/graphcanvas-decomposition.md`. 1665 lines. Covers all 32 refs, 7 state vars, ~24 prop-sync effects + 3 major effects, 10 cross-slice wiring points, 7 issues found, proposed 4-hook + 5-component split, implementation order, and expected coordinator shape (~100 lines). Ready for Opus.

| Priority | Target | Split into | Opus? |
|---|---|---|---|
| 1 | `useCapture.js` | `useCaptureLoad`, `useCaptureFilters`, `useCaptureData`, `useSelectionAndNavigation`, `useAnnotationsAndSynthetic` + coordinator | ✅ Done (Opus, v0.25.0) |
| 2 | `GraphCanvas.jsx` | `useGraphSim` · `useGraphViewSync` · `useGraphInteraction` · `useGraphResizePolling` · `GraphContextMenu` · `GraphAnnotationOverlay` · `GraphEventDots` · `SyntheticNodeForm` · `SyntheticEdgeForm` · `graphColorUtils` | Yes — **recon done, plan at `docs/plans/graphcanvas-decomposition.md`** |
| 3 | `ResearchPage.jsx` | `ResearchPage` · `ResearchSlotBoard` · `PlacedCard` · `CustomChartBuilder` · persistence helpers | — |
| 4 | `AnimationPane.jsx` | renderer · interaction · history/options · state adapters | — |
| 5 | `SessionDetail.jsx` | packet loader hook · payload/stream viewers · charts panel | — |
| 6 | `App.jsx` | Defer — stable mess, low urgency | — |

---

## Audit-driven work queue (priority over roadmap items)

Batch: `audits/codex_audits/2026-04-09/`. Each session covers one audit. Read companion from `claude/` subfolder first. After all audits are addressed, return to roadmap queue below.

| # | Audit | Status | Session focus |
|---|---|---|---|
| 02 | code_readability / maintainability | **in progress** (this session) | backend fixes + frontend split plan |
| 03 | computational_efficiency | pending | — |
| 04 | storage_efficiency | pending | — |
| 05 | architecture_principles | pending | — |
| 06 | ui_ux_accessibility | pending | — |
| 14 | directory_refactor | pending | — |

Second-pass files (07–13) are companions to the above — read alongside relevant audit.

**Rule for future sessions:** before picking up a roadmap item, check this table. If any audit row is "in progress" or "pending," continue it first. Mark "done" when changes are committed.

---

## Do next (roadmap — after audit queue is cleared)

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

- **Alerts Phase 2** — design complete in `docs/plans/active/ALERTS_PHASE2_PLAN.md`. Deprioritized.

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
