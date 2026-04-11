# Session State

**Last updated:** 2026-04-11 · **Current version:** v0.26.5
**Current branch:** main
**Mirror sync state:** all mirrors current as of v0.26.5 — CHANGELOG.ai.md current, HANDOFF.ai.md bumped to v0.26.5, ROADMAP.ai.md bumped to v0.26.5, ARCHITECTURE.ai.md (v0.26.1, no content change since), DEVELOPERS.ai.md (v0.26.2, no content change since)

> Live, per-session cache. Read first after `CLAUDE.md`.
> Write here during the session. Flush to human docs only at merge — not mid-session.

---

## Shipped this session (branch feat/audit-06-p1-p2 → merged v0.26.5)

> Keep max 3 entries. Drop the oldest when adding a new one. Full history in `CHANGELOG.ai.md`.

- v0.26.5 — Audit-03 P3: session list virtualized with react-window. Audit-04 P2: storageKeys.js — all localStorage keys centralized. Audit-14 P3: component reorg mapping written. Centrality plan deferred, audit-06 P3–P5 to qa-test-suite.
- v0.26.4 — Audit-06 P1+P2: left panel nav grouped into 4 sections; font size floor 7/8px → 9px minimum.
- v0.26.3 — Audit-05 P3 smoke tests (33/33); requirements.txt fix; audit-04 P1 state lifetime §16; graceful-optional-deps roadmap.

---

## Audit-driven work queue (priority over roadmap items)

Batch: `audits/codex_audits/2026-04-09/`. Each session covers one audit. Read companion from `claude/` subfolder first.

| # | Audit | Status | Notes |
|---|---|---|---|
| 02 | code_readability / maintainability | **done** (v0.24.1–v0.25.4) | All Phase 3 frontend splits complete. |
| 03 | computational_efficiency | **in progress** | P1 deferred (centrality, plan: `docs/plans/active/centrality-backend.md`). P2+P3 done. Remaining: P4 (search optim), P5 (lazy loading). |
| 04 | storage_efficiency | **in progress** | P1+P2 done. Remaining: P3 (lazy edge detail). Plan: `docs/plans/active/audit-04-storage-efficiency.md`. |
| 05 | architecture_principles | **in progress** | P2+P3 done. Remaining: P1 (edge field registry). Plan: `docs/plans/active/audit-05-architecture-principles.md`. |
| 06 | ui_ux_accessibility | **P1+P2 done, P3–P5 deferred** | P3–P5 added to `qa-test-suite` checklist. Plan: `docs/plans/active/audit-06-ui-ux-accessibility.md`. |
| 14 | directory_refactor | **P1–P3 done, P4 deferred** | P4 (execute reorg) blocked on audit-02 Phase 3 splits. Do after remaining audits. |

Second-pass files (07–13) are companions to the above — read alongside relevant audit.

**No audit requires Opus.** All plans are scoped for Sonnet.

### Remaining audit items (next session)

| Priority | Audit | Phase | What | Effort |
|---|---|---|---|---|
| 1 | — | — | Review `post-parse-pipeline-opt` roadmap plan — profile build_sessions/build_graph/plugins | high impact |
| 2 | 05 | P1 | Edge field registry (medium effort) | Plan: `docs/plans/active/audit-05-architecture-principles.md` |
| 3 | 04 | P3 | Lazy edge detail loading | Plan: `docs/plans/active/audit-04-storage-efficiency.md` |
| 4 | 03 | P4 | Client-side search optimization (pre-indexed search) | low-medium |
| 5 | 03 | P5 | Lazy loading boundaries (`React.lazy` for heavy panels) | low |
| — | 14 | P4 | Execute component reorg | **do last** — blocked on audit-02 splits, high churn |

---

## Do next (roadmap — after audit queue is cleared)

- `d3-force-tuning` — discuss slider vs constant tweak first

---

## Known issues (not fixed, not blocking)

- **Post-parse pipeline bottleneck** — `build_sessions + build_graph + plugins` ~20s for 440K packets. Roadmap: `post-parse-pipeline-opt`.
- **"Size by" graph option** — user considers it poor quality, needs review pass.
- **ICMPv6 dissector** — no raw fallback. Extra stays `{}`.
- **scapy DNS deprecation** — `dns.qd` → `dns.qd[0]`. 39K warnings per test run.
- **dpkt `IP.off` deprecation** — should use new field name.

## Deferred

- **Alerts Phase 2** — design complete in `docs/plans/active/ALERTS_PHASE2_PLAN.md`. Deprioritized.
- **Centrality backend migration** — plan at `docs/plans/active/centrality-backend.md`. Not urgent.

---

## Blocked on

- Nothing.

---
