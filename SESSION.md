# Session State

**Last updated:** 2026-04-12 · **Current version:** v0.27.0
**Current branch:** main (feat/llm-phase2 merged)
**Mirror sync state:** All mirrors current at v0.27.0. Human docs flushed (CHANGELOG.md updated, HANDOFF.ai.md + ROADMAP.ai.md bumped to v0.27.0).

> Live, per-session cache. Read first after `CLAUDE.md`.
> Write here during the session. Flush to human docs only at merge — not mid-session.

---

## Shipped this session (branch feat/llm-phase2)

> Keep max 3 entries. Drop the oldest when adding a new one. Full history in `CHANGELOG.ai.md`.

- v0.27.0 — version bump to minor (next session: server API keys, LLM docs, left-panel cleanup, quick-wins list)
- v0.26.9 — node role fix + starter prompts: translate_node() now includes os_guess and network_role; is_simple_question flag in ChatOptions; _OUTPUT_FORMAT_SIMPLE (no Next Steps) wired through prompts.py+service.py; starter chip row in LLMInterpretationPanel (empty-state, context-aware). 69/69 unit tests pass.
- v0.26.8 — Phase 1 bug fixes: self-ref capture markers + capture-context markers + proto-only step-6 gate in question_tags.py; is_small_model() + compact-mode prompt override in prompts.py; model_name wired through service.py. 31/31 tests pass.
- v0.26.7 — LLM interpretation panel Phase 1: POST /api/llm/chat (streaming NDJSON), context-preview debug endpoint, backend/llm/ package (question_tags, translators, context_builder, prompts, service, Ollama+OpenAI providers), LLMInterpretationPanel.jsx (scope selector, streaming transcript, tag badges), useLlmChat.js, settings extended, AnalysisPage placeholder replaced, 4 test files.
- v0.26.6 — Audit-05 P1+P2+P3 done; Audit-04 P3 done; Audit-03 P4+P5 done. Edge field registry (`edge_fields.py`), lazy edge detail (`/api/edge/{id}/detail`), pre-indexed search, React.lazy panels, boolean edge hints (has_tls/has_http/has_dns).

---

## Audit-driven work queue (deprioritised — deferred until after LLM phases)

Batch: `audits/codex_audits/2026-04-09/`. Each session covers one audit. Read companion from `claude/` subfolder first.

| # | Audit | Status | Notes |
|---|---|---|---|
| 02 | code_readability / maintainability | **done** (v0.24.1–v0.25.4) | All Phase 3 frontend splits complete. |
| 03 | computational_efficiency | **deferred** | P1 deferred (centrality, plan: `docs/plans/active/centrality-backend.md`). P2–P5 done (v0.26.5/v0.26.6). |
| 04 | storage_efficiency | **deferred** | P1–P3 done. Remaining: P4 (memory monitoring). Plan: `docs/plans/active/audit-04-storage-efficiency.md`. |
| 05 | architecture_principles | **done** (v0.26.3/v0.26.6) | P1+P2+P3 all done. `edge_fields.py` registry ships. |
| 06 | ui_ux_accessibility | **deferred** | P3–P5 added to `qa-test-suite` checklist. Plan: `docs/plans/active/audit-06-ui-ux-accessibility.md`. |
| 14 | directory_refactor | **deferred** | P4 (execute reorg) high churn — do last, after LLM work settles. |

Second-pass files (07–13) are companions to the above — read alongside relevant audit.

### Deferred audit items (resume after LLM Phase 2 + 3)

| Priority | Audit | Phase | What | Effort |
|---|---|---|---|---|
| 1 | 04 | P4 | Memory pressure monitoring (`/api/status/memory` + status bar indicator) | low |
| 2 | 03 | P1 | Client-side centrality → backend endpoint | medium, plan: `docs/plans/active/centrality-backend.md` |
| — | 14 | P4 | Execute component reorg | **do last** — high churn |

---

## Do next

1. ~~**Fix Phase 1 bugs — done (v0.26.8)**~~
2. ~~**Node role fix + starter prompts — done (v0.26.9)**~~

> **START OF NEXT SESSION — work these in order before LLM Phase 2:**

3. **Wire API keys from server.** Settings panel currently only stores keys client-side (localStorage). Need server-side key store: backend endpoint to set/get/delete keys per provider (Ollama base_url, OpenAI key, etc.) so keys are not exposed in browser storage. Design: `GET/POST /api/llm/keys` persisted in a local config file (not in the pcap dir). Frontend settings reads from server on load, saves to server on change.

4. **Document LLM section in docs/DEVELOPERS.md.** Write the LLM architecture section: providers, contracts, context_builder, question_tags, translators, prompts, service — what each file does, extension points (adding a provider, adding a tag), the streaming NDJSON wire format, and how to test locally with Ollama. Flush directly to `docs/DEVELOPERS.md` (this is a merge-flush-style doc write, user has approved). Read `DEVELOPERS.ai.md` first for existing doc structure.

5. **Remove mini-categories from left-hand panel.** User dislikes the category labels/groupings in the left sidebar. Find the component rendering them and remove. Quick UI change — grep for the category label render, delete the grouping wrapper, keep the items flat.

6. **Quick-wins list from roadmap (5–10 items).** Read `ROADMAP.ai.md`, identify 5–10 smallest-effort/highest-value items that aren't blocked by LLM Phase 2/3. Write the list here in SESSION.md as a ranked table so next session can pick from it without re-reading the roadmap.

7. **LLM Phase 2 — Sonnet.** Branch: `feat/llm-phase2`. Plan: `docs/plans/active/llm-interpretation-phase2-3.md § Phase 2`.
   Order: 2.2 (conversation history) → 2.3 (protocol translators) → 2.4 (source-type awareness) → 2.5 (adaptive budgeting).

8. **LLM Phase 3 — mixed.** New branch: `feat/llm-phase3`. Plan § Phase 3.
   - 3.1 tool-use loop → **Opus** (architectural change to service loop + provider layer)
   - 3.2 report mode + 3.3 payload inspection → Sonnet once 3.1 is stable

---

## LLM panel — observed issues

- **Both answers could be one line** — context packet probably has enough info; issue is prompt verbosity instructions + small model compliance. Compact-mode override added (v0.26.8) — retest with qwen2.5:3b after merge.

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
