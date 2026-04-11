# Session State

**Last updated:** 2026-04-12 · **Current version:** v0.26.7
**Current branch:** main
**Mirror sync state:** All mirrors current at v0.26.7. Human docs flushed (CHANGELOG.md, HANDOFF.md, ROADMAP.md).

> Live, per-session cache. Read first after `CLAUDE.md`.
> Write here during the session. Flush to human docs only at merge — not mid-session.

---

## Shipped this session (branch feat/llm-interpretation)

> Keep max 3 entries. Drop the oldest when adding a new one. Full history in `CHANGELOG.ai.md`.

- v0.26.7 — LLM interpretation panel Phase 1: POST /api/llm/chat (streaming NDJSON), context-preview debug endpoint, backend/llm/ package (question_tags, translators, context_builder, prompts, service, Ollama+OpenAI providers), LLMInterpretationPanel.jsx (scope selector, streaming transcript, tag badges), useLlmChat.js, settings extended, AnalysisPage placeholder replaced, 4 test files.
- v0.26.6 — Audit-05 P1+P2+P3 done; Audit-04 P3 done; Audit-03 P4+P5 done. Edge field registry (`edge_fields.py`), lazy edge detail (`/api/edge/{id}/detail`), pre-indexed search, React.lazy panels, boolean edge hints (has_tls/has_http/has_dns).
- v0.26.5 — Audit-03 P3: session list virtualized with react-window. Audit-04 P2: storageKeys.js — all localStorage keys centralized. Audit-14 P3: component reorg mapping written.

---

## Audit-driven work queue (priority over roadmap items)

Batch: `audits/codex_audits/2026-04-09/`. Each session covers one audit. Read companion from `claude/` subfolder first.

| # | Audit | Status | Notes |
|---|---|---|---|
| 02 | code_readability / maintainability | **done** (v0.24.1–v0.25.4) | All Phase 3 frontend splits complete. |
| 03 | computational_efficiency | **in progress** | P1 deferred (centrality, plan: `docs/plans/active/centrality-backend.md`). P2–P5 done (v0.26.5/v0.26.6). |
| 04 | storage_efficiency | **in progress** | P1–P3 done. Remaining: P4 (memory monitoring). Plan: `docs/plans/active/audit-04-storage-efficiency.md`. |
| 05 | architecture_principles | **done** (v0.26.3/v0.26.6) | P1+P2+P3 all done. `edge_fields.py` registry ships. |
| 06 | ui_ux_accessibility | **P1+P2 done, P3–P5 deferred** | P3–P5 added to `qa-test-suite` checklist. Plan: `docs/plans/active/audit-06-ui-ux-accessibility.md`. |
| 14 | directory_refactor | **P1–P3 done, P4 deferred** | P4 (execute reorg) high churn — do last. |

Second-pass files (07–13) are companions to the above — read alongside relevant audit.

### Remaining audit items (next session)

| Priority | Audit | Phase | What | Effort |
|---|---|---|---|---|
| 1 | 04 | P4 | Memory pressure monitoring (`/api/status/memory` + status bar indicator) | low |
| 2 | 03 | P1 | Client-side centrality → backend endpoint | medium, plan: `docs/plans/active/centrality-backend.md` |
| — | 14 | P4 | Execute component reorg | **do last** — high churn |

---

## Do next

**Next up:** roadmap items — `docs-pass` (full doc reality check, see ROADMAP.ai.md), audit-04 P4 (memory monitoring `/api/status/memory` + status bar indicator), audit-03 P1 (centrality → backend), `d3-force-tuning`

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
