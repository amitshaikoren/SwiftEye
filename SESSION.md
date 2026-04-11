# Session State

**Last updated:** 2026-04-11 · **Current version:** v0.26.5
**Current branch:** feat/audit-06-p1-p2 (not yet merged)
**Mirror sync state:** all mirrors current as of v0.26.3 — ARCHITECTURE.ai.md (v0.26.1→v0.26.1 header, Philosophy exceptions), DEVELOPERS.ai.md (v0.26.2 header, §16 pointer), ROADMAP.ai.md (graceful-optional-deps added), CHANGELOG.ai.md (compressed v0.25.1 and below)

> Live, per-session cache. Read first after `CLAUDE.md`.
> Write here during the session. Flush to human docs only at merge — not mid-session.

---

## Shipped this session

> Keep max 3 entries. Drop the oldest when adding a new one. Full history in `CHANGELOG.ai.md`.

- v0.26.5 — Audit-03 P3: session list virtualized with react-window (FixedSizeList, ResizeObserver height tracking). Audit-04 P2: storageKeys.js created — all localStorage keys centralized; 5 files updated. Audit-14 P3: component reorg mapping doc written in audit-14 plan (50-file table). Admin: centrality task deferred, plan at `docs/plans/active/centrality-backend.md`; audit-06 P3–P5 deferred to `qa-test-suite` checklist.
- v0.26.4 — Audit-06 P1+P2: left panel nav grouped into 4 sections (Data/Analysis/Workspace/Settings); project-wide font size floor — 7px/8px bumped to 9px minimum, interactive buttons (All/None) lifted to 10px.
- v0.26.3 — Batch: audit-05 P3 discovery smoke tests (33 tests, 33 pass); requirements.txt fix (plotly promoted to required, sqlglot + pytest added); audit-04 P1 state lifetime table (§16 in docs/DEVELOPERS.md); graceful-optional-deps roadmap item.
- v0.26.2 — Audit-05 Phase 2: add Philosophy exceptions table to ARCHITECTURE.ai.md.

---

## Audit-driven work queue (priority over roadmap items)

Batch: `audits/codex_audits/2026-04-09/`. Each session covers one audit. Read companion from `claude/` subfolder first. After all audits are addressed, return to roadmap queue below.

| # | Audit | Status | Notes |
|---|---|---|---|
| 02 | code_readability / maintainability | **done** (v0.24.1–v0.25.4) | All Phase 3 frontend splits complete. |
| 03 | computational_efficiency | **in progress** | Phase 2 done (v0.26.1). Remaining: P1 (centrality→backend), P3 (virtualize lists), P4 (search optim), P5 (lazy loading). |
| 04 | storage_efficiency | **in progress** | Plan: `docs/plans/active/audit-04-storage-efficiency.md`. P1 done (v0.26.3, state lifetime §16). Remaining: P2 (storageKeys.js), P3 (lazy edge detail). |
| 05 | architecture_principles | **in progress** | Plan: `docs/plans/active/audit-05-architecture-principles.md`. P2+P3 done (v0.26.2+v0.26.3). Remaining: P1 (edge field registry, medium effort). |
| 06 | ui_ux_accessibility | **P1+P2 done, P3–P5 deferred** | P1 (nav grouping) + P2 (font floor) shipped v0.26.4. P3–P5 (hints, filter labels, keyboard nav) deferred — checklist added to `qa-test-suite` roadmap item. Plan: `docs/plans/active/audit-06-ui-ux-accessibility.md`. |
| 14 | directory_refactor | **in progress** | Phase 1+2 done (v0.26.0). Remaining: P3 (component reorg plan), P4 (execute reorg). |

Second-pass files (07–13) are companions to the above — read alongside relevant audit.

**No audit requires Opus.** All plans are scoped for Sonnet.

### Next batch (priority order — pick low-effort + high-impact first)

| Priority | Audit | Phase | What | Effort |
|---|---|---|---|---|
| ~~1~~ | ~~05~~ | ~~P2~~ | ~~Document philosophy exceptions in `ARCHITECTURE.ai.md`~~ | **done v0.26.2** |
| ~~2~~ | ~~05~~ | ~~P3~~ | ~~Discovery smoke tests (`backend/tests/test_discovery_smoke.py`)~~ | **done v0.26.3** |
| ~~3~~ | ~~04~~ | ~~P1~~ | ~~State lifetime table in `docs/DEVELOPERS.md`~~ | **done v0.26.3** |
| ~~4~~ | ~~06~~ | ~~P1~~ | ~~Left panel navigation grouping (`LeftPanel.jsx`)~~ | **done v0.26.4** |
| ~~5~~ | ~~06~~ | ~~P2~~ | ~~Minimum font size floor (fix 7–8px offenders)~~ | **done v0.26.4** |
| ~~6~~ | ~~03~~ | ~~P1~~ | ~~Centrality → backend endpoint~~ | **deferred** — plan at `docs/plans/active/centrality-backend.md`, roadmap: `centrality-backend-migration` |
| 7 | 03 | P3 | Virtualize session list + packet table (`react-window`) | low risk |
| 8 | 04 | P2 | localStorage key constants + cleanup (`storageKeys.js`) | medium |
| 9 | 14 | P3 | Component reorg plan (design doc only, no code moves) | low, unblocked |
| 10 | 14 | P4 | Execute component reorg (import churn, do last) | high |

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

