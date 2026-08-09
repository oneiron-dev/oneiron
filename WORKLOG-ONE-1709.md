# WORKLOG — ONE-1709 (CB-B stack B3, layer 2/3)

Team-lead seeded agent definition: recursive delegation, attenuating ceilings, `ask(lead, panel-spec)`.

Base: `049cde369` (ONE-1708 merged). Branch `ONE-1709`.

## Verified dep facts on base

- `SystemAgentPreset` / `TeamLeadPreset`: **0 matches** repo-wide → ONE-1890 landed, enum path gone.
- `AgentDispatchTarget` has exactly one variant `Custom(EntityId)`; `TARGET_SYSTEM` survives only as a
  decoder-private compat arm.
- Seed manifest `crates/oneiron/src/data/system_agent_definitions.v1.json` exists with 6 rows
  (`sys.scout|keeper|creative|herald|guide|default`), pinned ids `0xa1..0xa6` repeated.
- `ConsultPayload` = `{question_ref, context_refs, correlation_ref}` + ONE-1888's three optional
  fields; `ConsultPayloadRef::{Claim,Turn}` only. Consumed read-only.
- `AgentCeiling::widens_beyond(bound)` exists in `agent_def.rs` (untouched).

## Decisions

### D1 — seed row field mapping (rebase onto ONE-1890's actual schema)

The blueprint skeleton names `verb_allowances`, `source: "generated"`, `confidence`. The landed
manifest adapter (`AgentDefinitionManifestFields`, `#[serde(deny_unknown_fields)]`) has no
`verb_allowances` key and pairs `source`/`generated`/`human_authored` as a checked triple.
Adding a manifest key = an `agent_def.rs` edit, which is explicitly out of scope.

→ Verb allowances ride the row's free-form `provenance` map under `verbAllowances`, which IS a
manifest field and IS carried onto the stored row. Source stays `imported` + `human_authored: true`
(matching the six sibling seed rows); the row is hand-authored data, not model output, and
`generated: true` would contradict the encoder's authorship invariant. Semantic fields (prompt,
`auto` ceiling, narrow verb allowances, no connectors/skills/mcps) are all preserved.

Pinned row id: `a7a7…a7` (next in the roster's `0xaN` sequence), `actor_entity_id == entity_id`
as schema v1 requires.

### D2 — narrowing is defined against the RESOLVED parent projection

`ResolvedContextProjection`'s pinned fields carry no spec, so "child ⊆ parent" is checked against
what the parent actually resolved. Memory section tokens are therefore `"<domain>:cl_<hex>"` so a
child's requested domains are checkable against the parent's resolution; chat tokens are `tn_<hex>`.

Because `MemoryProjection::Default` *inherits*, resolving a parent's spec standalone could be wider
than what the parent actually got. So the dispatcher walks the ancestor chain (bounded) and folds
root→down before validating the child. `CONTEXT_PROJECTION_MAX_ANCESTORS = 16`.

### D3 — `context_from` carries settled RESULT artifacts, not TASK rows

`TaskVerbBody` is private to `task_verb.rs` (not claimed), so `context_projection.rs` cannot read a
TASK's terminal state. It does not need to: a `result_ref` only *exists* after `land_task_result`
mints it, so "supplied only after settlement" is structural. Resolution therefore requires every
`context_from` ref to resolve durably and **rejects `ENTITY_TYPE_TASK` refs outright** — you may
inject a settled result artifact, never a live TASK row.

### D4 — code_run PACKET_AMEND blast radius

"One additive `SelfCall` variant + dispatch arm" forces four mechanically-implied additions in the
same file: `SelfEffect::Context` (the `effect()` match is exhaustive), a `self_call_request_value`
arm, a `SelfDispatchOutcome::Context` variant, and its replay codec arm. No new gate call, no
budget consumption, no vault read on the arm. `code_sandbox.rs` untouched.

## Plan / INTENT

1. seed manifest row + seed tests (agent_dispatch/tests.rs)            — done
2. NEW `context_projection.rs` + lib.rs registration                   — done
3. `agent_dispatch.rs`: additive codec fields, live attenuation, depth  — done
4. `code_run.rs` PACKET_AMEND: `SelfCall::Context`                      — done
5. `context_board/agents.rs`: lead/worker labels over existing presence — done
6. `tests/cb_oracle_agents.rs`: both ONE-1709 arms un-ignored           — done
