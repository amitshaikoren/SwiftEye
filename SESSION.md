# Session State

**Last updated:** 2026-04-10 · **Current version:** v0.23.0
**Current branch:** main
**Mirror sync state:** all mirrors current as of v0.23.0

> Live, per-session cache. Read first after `CLAUDE.md`.
> Write here during the session. Flush to human docs only at merge — not mid-session.

---

## Shipped this session

- v0.23.0 — **adapter-schema-negotiation** merged to main. New `backend/parser/schema/` package (contracts, inspector, staging) sits as its own layer before any adapter. All Zeek + tshark metadata adapters declare `declared_fields` and implement `get_header_columns()` / `get_raw_rows()` / `_rows_to_packets()` / `parse_with_mapping(mapping)`. Upload is two-phase: detect → inspect schema → if clean proceed; if mismatch, stage file (UUID token), return `schema_negotiation_required: true` + `schema_report` + `staging_token`. `POST /api/upload/confirm-schema` accepts token + confirmed mapping → resumes ingestion. Frontend: `SchemaDialog.jsx` (mapping table, required-field warnings, suggested-mapping pre-fill, Confirm & Ingest). Detection is now format-based (Zeek conn = catch-all with `#fields` marker only, no extension required; tshark metadata = catch-all with `.csv` + ≥15 tab-separated columns). 25 backend tests. Test fixtures gitignored.

---

## Do next (next session: low-effort bug + QOL fixes from roadmap)

Priority queue for next session — all low-effort, no dependencies:
- `alerts-live-load-bug` — critical, investigate `loadAll()` / `fetchAlerts()` wiring
- `schema-dialog-in-app` — SchemaDialog missing when uploading from inside app
- `manual-type-override` — fallback to manual type selection when detection fails
- `detail-panel-polish` — remove "Flag" text, fix header layout
- `timeline-graph-phase3` — drag-render bug + node-click detail card
- `animation-direction-mismatch` — confirmed real
- `d3-force-tuning` — discuss slider vs constant tweak first

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
