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

## Recovery close-out (2026-08-10)

Native Opus resumed at c9af65d8a and errored on an OAuth expiry mid-leg, leaving the
+771/-4 oracle diff uncommitted. K3 impl leaf verified the WIP as-is (no rebase, no
reset, no greenfield):

- dirty diff touched only `crates/oneiron/tests/cb_oracle_agents.rs` (allowed);
- no `SystemAgentPreset`/`TeamLeadPreset`/workflow-DSL restore anywhere in the diff;
- both ONE-1709 oracle arms were un-ignored in the dirty tree.

Committed the arms as `30362e329` (unsigned, no push). ONE-1710/1711 arms remain
`#[ignore]`d and untouched.

## Verification

- `cargo check -p oneiron -j6 --all-features` — green
- `cargo test -p oneiron --lib agent_dispatch -j6 --all-features --no-fail-fast` — 42 passed, 0 failed
- `cargo test -p oneiron --lib context_projection -j6 --all-features --no-fail-fast` — 14 passed, 0 failed
- `cargo test -p oneiron --test cb_oracle_agents -j6 --all-features --no-fail-fast` — 5 passed, 0 failed, 5 ignored
  - `cb_a::team_lead_recursive_delegation_ceilings_attenuate` … ok
  - `cb_a::ask_lead_panel_spec_runs_blind_panel_judge_synthesis` … ok

Tip: `30362e329` on branch `ONE-1709` (base `049cde369`, 6 branch commits).

---

## F5 mechanical fix (post-reducer)

Accepted finding F5 only: `register_attenuated_fork` now requires full
`AgentDefinition` equality on deterministic-id hit (not just ceiling +
`forked_from`). Sibling test
`attenuated_fork_reuse_rejects_matching_ceiling_and_parent_with_foreign_composition`
covers the squat path. F1–F4, F6 rejected — not implemented.

---

## Second (final) fix cycle — owner ruling v3b `AUTHORIZE_BLUEPRINT_AMENDMENT_AND_FIX`

Ruling: `k3-owner-ruling-v3b.json` (sha256 bbd1fd8a…07b62). One exceptional
second cycle: blueprint amendment + seven bounded fixes, confined to
`context_projection.rs`, `agent_dispatch.rs`, `agent_dispatch/tests.rs`, and
exactly one additive read-only seam in `task_verb.rs`.

### Blueprint amendment (exactly two sentences)

- §10 keeps the `ConsultPayload`/`TaskCreateSpec` re-shape ban verbatim and
  carves out: PACKET_AMEND — one additive `pub(crate)` READ-ONLY
  settled-sibling-result query seam in `task_verb.rs` (no
  payload/verb/wire/write-path change), consumed by the `contextFrom`
  validator in `context_projection.rs`.
- §7 gains the enforcement sentence: `contextFrom` admission is enforced at
  dispatch (terminal disposition + result_ref equality + same-parent/run
  lineage), failing closed with a typed `InvalidAgentDispatchInput`-class
  error.

### D4 — `contextFrom` binds SETTLED COMPLETED sibling TASK results (FIX-SRV)

`resolve_sibling_results` previously accepted ANY durable non-TASK row; the
implementer's structural-settlement argument was factually broken
(`land_task_result` resolves the caller artifact BEFORE the terminal write,
task_verb.rs:1280/:1331 — the pre-settlement window). Admission is now
two-stage, fail-closed at both doors:

1. Settlement + binding (context_projection): the new
   `task_verb::settled_task_result_binding` seam returns the terminal
   `(disposition, result_ref)`; only `Completed` resolves, to the RESULT ref
   (not the TASK row). Unsettled-but-durable artifacts, arbitrary non-TASK
   rows, non-Completed terminals, unresolved refs, and duplicates all error.
2. Lineage (agent_dispatch): `require_sibling_result_lineage` proves each
   named TASK's recorded create-owner equals the parent attempt's dispatched
   row and that the spawn rides the parent attempt's exact run. Root spawns
   naming siblings, foreign parents, and foreign runs error typed and enqueue
   nothing.

### D5 — the six bounded fixes

- FIX-1: `scan_memory_sections` applies the canonical
  `crate::claim::claim_surfaceable` gate (the crate's only surfacing test) —
  Proposed/Rejected/Superseded/Retracted/stale claims never reach a memory
  projection and never count against limits.
- FIX-2: the dedupe Existing arm compares the persisted spawn context
  (`context_spec` + `context_from` + `depth_remaining`); a mismatch is a
  typed error, never a silent reuse.
- FIX-3: `attenuated_fork_id` mixes the source row's content fingerprint
  into fork identity and records it in fork provenance: an in-place source
  update mints a distinct fork instead of dying against the stale occupant;
  the F5 squat guard (full-body equality) is unchanged.
- FIX-4: a root's persisted `depth_remaining` clamps at
  `CONTEXT_PROJECTION_MAX_ANCESTORS` (16) at admission, so no stored lineage
  outlives the ancestor-projection walk.
- FIX-5: the chat projection admits only CONVERSATIONAL turns (speaker
  marker + text payload, `spkr`/`txt` legacy arm included) before `last_n`;
  panel-spec and consult-expiry artifact TURNs can neither surface nor
  displace chat under the bounded over-scan.
- FIX-6: the descriptor normalizes exactly once at admission, before
  resolution/comparison/persist, so stored payloads are canonical and
  byte-stable for dedupe.

### Verification (this cycle)

- `cargo check -p oneiron --all-features` — green (exit 0)
- `cargo test -p oneiron --all-features --lib agent_dispatch` — 48 passed, 0 failed (exit 0)
- `cargo test -p oneiron --all-features --lib context_projection` — 16 passed, 0 failed (exit 0)
- `cargo test -p oneiron --all-features --lib task_verb` — 81 passed, 0 failed, 1 ignored (exit 0)
- `cargo test -p oneiron --all-features --test cb_oracle_agents` — 5 passed, 0 failed, 5 ignored (exit 0);
  both ONE-1709 arms green (`team_lead_recursive_delegation_ceilings_attenuate`,
  `ask_lead_panel_spec_runs_blind_panel_judge_synthesis`); ONE-1710/ONE-1711 arms stay ignored.

Full suite remains the merge-candidate gate and was deliberately not run in
this cycle (doctrine #7 / ruling evidence_economy).

## Opus third cycle (2026-08-11)
- Implemented A-1167 witnessed TURN classification, B-1183 Peer-only panel validation, and C-1171 AgentScope world clamp.
- D-1166 remains follow-up only; no task_verb changes.
- Validation: `cargo check -p oneiron --all-features` passed. Targeted lib test command is blocked by pre-existing unrelated test compilation errors (`put_replicated`).
