# SwiftEye — Completed Roadmap Items

> Items that shipped and are no longer in active development. Kept for dependency tracing.
> When an item is done: move its table row and detail block from `ROADMAP.md` here.

---

## Shipped

| ID | Shipped | Notes |
|----|---------|-------|
| `timeline-graph-phase2` | v0.22.0–v0.22.7 (2026-04-10) | All 8 items done. See detail block below. |
| `event-type-system` | v0.21.0+v0.21.1 (2026-04-09) | Phase 1 done. Phase 2 tracked as `event-suggested-edges-pluggable`. |
| `adapter-schema-negotiation` | v0.23.0 (2026-04-10) | Two-phase upload + `backend/parser/schema/` package + `SchemaDialog.jsx`. |

---

### timeline-graph-phase2

Phase 2 batch of Timeline Graph UX improvements, all descending from v0.21.0 Phase 1 (`event-type-system`). All 8 items shipped across v0.22.0–v0.22.7 on `main`.

| Item | Shipped |
|------|---------|
| Zoom + pan canvas (d3.zoom, `scaleExtent [0.3,3]`, `canvasPoint()` inversion) | v0.22.0 |
| Reject → removes suggested edge (`rejectedSuggestions` Set in `useEvents`) | v0.22.1 |
| Layout persistence (lift `rulerOn` to `useEvents`, lock `fx`/`fy`, stop sim) | v0.22.2 |
| Entity color coding + legend (node blue, edge purple, session green, ~13% alpha) | v0.22.3 |
| Show-in-graph highlight (reused `queryHighlight`, panel-switch-first ordering) | v0.22.4 |
| Back-to-investigation breadcrumb (lifted `tab` state, `returnToInvestigationTab`) | v0.22.5 |
| Multi-edge parallel arcs (`pairOffsets` memo, `arcPath` helper, 22px offset) | v0.22.6 |
| Shift-select → operations popover (Draw edge / Clear, screen-anchored to midpoint) | v0.22.7 |

(Originally also bundled "Flag button in all detail panel headers" — completed early in v0.21.1 as `ui-events-polish`.)

---

### event-type-system

First-class flagged-event primitive for threat-hunt narratives. Phase 1 shipped across v0.21.0 (core) and v0.21.1 (polish). Full Opus design plan: `docs/plans/event-type-system.md`.

Phase 1 shipped: `useEvents` hook, `EventFlagModal`, `EventsPanel` + `EventCard`, `TimelineGraph` SVG canvas, `InvestigationPage` tab bar, ref-chip drag-to-insert in markdown editor, `GraphCanvas` indicator dots + context menu, `SessionDetail`/`EdgeDetail`/`NodeDetail` Flag buttons.

Phase 2 deferred: backend persistence (workspace save), pluggable suggested-edge logic (see `event-suggested-edges-pluggable`), Phenomena templates (needs real-usage data), edge-label edit in TimelineGraph.

---

### adapter-schema-negotiation
Shipped v0.23.0. New `backend/parser/schema/` package (contracts, inspector, staging) sits as its own layer before any adapter. All Zeek adapters (conn, dns, http, ssl, smb_files, smb_mapping, dce_rpc) and tshark metadata adapter now declare `declared_fields` and implement `get_header_columns()` / `get_raw_rows()` / `_rows_to_packets()` / `parse_with_mapping(mapping)`. Upload is two-phase: detect adapter → inspect schema → if clean proceed; if mismatch, stage the file (UUID token), return `schema_negotiation_required: true` + `schema_report` + `staging_token`. `POST /api/upload/confirm-schema` accepts confirmed mapping → `parse_with_mapping` → full ingest. Frontend: `SchemaDialog.jsx` renders detected-vs-expected columns as a mapping table with dropdowns, required-field warnings, suggested-mapping pre-population, and Confirm & Ingest button disabled until all required fields are mapped. Detection made format-based: Zeek conn is a catch-all (checked last, requires only `#fields` marker, no extension required); tshark metadata is a catch-all (checked last, requires `.csv` + tab-separated first line with ≥15 columns). 25 backend tests.
`status: done` · `shipped: v0.23.0`
