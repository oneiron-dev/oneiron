# WORKLOG — ONE-1763 [ED-07] routing loop projection

Branch `ONE-1763` off `origin/main` 16c125b3e. Worktree `/Volumes/Cinema/w5-lt/ed-1761`.
Blueprint: `/Users/olety/.claude-wave5/blueprints/ED/ONE-1763.md` (keystone skeletons content-ratified).

## Gates

- `cargo fmt --all -- --check` — clean
- `cargo clippy -p oneiron --all-features --all-targets -- -D warnings` — clean
- `cargo test -p oneiron --all-features` — **47/47 binaries green, 3867 lib tests, 0 failed**
  (18 new `edit_distance::routing::tests`)

Full-suite green is also the done-means evidence for *"with everything Shadow (default),
routing behavior byte-identical to pre-ticket"*: `RoleModelDefaults::resolve` is untouched.

## Files

| file | action |
|---|---|
| `crates/oneiron/src/edit_distance/routing.rs` | CREATE |
| `crates/oneiron/src/edit_distance/routing/tests.rs` | CREATE (18 tests) |
| `crates/oneiron/src/edit_distance.rs` | `pub mod routing;` (append, alphabetical) |
| `crates/oneiron/src/lib.rs` | re-export block (append) |
| `crates/oneiron/src/llm.rs` | ONE hint-read call site + 3 imports |
| `crates/oneiron/src/store.rs` | **NOT TOUCHED** — see D8 |

`Cargo.toml` / `Cargo.lock` / `settings.rs` / `engine_executor.rs`: untouched, as specified.

## PACKET

**No PACKET_AMEND candidates.** Every change landed inside the declared packet.
`git diff --name-only origin/main` ⊆ packet.

## Blueprint deviations (declared, none silently absorbed)

### D1 — `record_judged_amendment` takes `&str`, not `&EntityId` (SHAPE deviation)

Ratified skeleton: `pub fn record_judged_amendment(vault: &Vault, delta_receipt: &EntityId)`.
Landed: `(vault: &Vault, delta_receipt: &str)`.

Grounding — an `&EntityId` cannot join the ledger this projection is defined over:

- `receipt.rs:2626` mints proposal-outcome receipt ids as
  `format!("proposal_outcome:{}", event_id.to_hex())` — a PREFIXED string, not a bare hex id.
- `delta.rs:611` `pub fn amendment_delta(vault: &Vault, receipt_id: &str)`.
- `attribution.rs:279` `AmendmentJudgment.receipt_id: String`; the whole ED-01→ED-03 join key
  chain is `&str`.

The load-bearing half of the hard shape — **receipt-BOUND: one argument, and scope / d_norm /
outcome all derive INSIDE from receipt + judgment, never from caller scalars** — is preserved
exactly. Only the id's Rust type moved, and it moved to the one the substrate actually uses.

### D2 — membership ledger added (`edit_distance/routing_member/v1`)

Not in the skeleton; forced by the swap law. Which generation a run belongs to is **not
re-derivable** from the judgment ledger (judgments carry no model). A rebuild that re-folded
judgments against the *currently* serving version would re-attribute every historical run to
the newest generation — destroying "old rows retained, never merged" on the very door meant to
prove the projection is rebuildable. So `record_judged_amendment` writes a receipt→version
binding, and `rebuild_routing_projection` folds judgments against those bindings.

Side benefit that earns its keep: rebuild becomes a real correction path, not ceremony — a
re-judged receipt folds its new mass/class, and a WITHDRAWN judgment drops its run and its
binding (two tests).

### D3 — `set_serving_model` / `serving_model_version` added

Not in the skeleton; forced by a substrate fact. **Amendment receipts carry no model
provenance**: `receipt.rs:2591 proposal_outcome_receipt` writes `proposal_ref`, `op_kind`,
`target_class`, `scope_actor`, `claim_source`, `seq`, `amended_body` — no `model`. (`FIELD_MODEL`
is private and only projected on emit-adjacent kinds, `receipt.rs:257 is_emit_adjacent` =
`Outbound` only.) The record side therefore cannot derive a `ModelId` from the receipt.

Landed minimum: one vault_meta pointer naming the generation now serving, set through a door
that takes a **`ModelId`** and resolves the `ModelStack` identity inside `routing.rs` — which is
verbatim the ratified *"model_version = ModelStack identity resolved INSIDE routing.rs from
ModelId via ModelStackRegistry, settings read-only"*. House pattern (per-feature key const over
vault_meta, `inbox::INBOX_REVIEW_DIAL_KEY`); `settings.rs` untouched.

Unset default = the drafting role's compiled default token, so an unconfigured vault **records
and reads under the same key** rather than silently missing itself (test:
`an_unconfigured_vault_records_where_the_router_reads`).

> **KNOWN HOLE (follow-up candidate):** once amendment receipts carry a model stamp,
> `record_judged_amendment` should prefer the receipt's own model over the serving pointer.
> That is a receipt.rs field-set change, out of this packet.

### D4 — `set_rollout_rung` added

Skeleton lists only the getter, but the done-means *"Rung changes via settings only"* needs a
door. Owner-controlled; nothing in the module auto-promotes. The rung is a dial, not a ratchet —
demotion works too (asserted).

### D5 — `routing_data_bar` + `RoutingScopeStats` added

Required by the done-means *"DataBar → visible in read surface, hint still None"*. Shadow scopes
are deliberately absent from it — that is what shadow means. `RoutingScopeStats` carries the full
`WeightHint`, so the Goodhart pairing holds on the informational surface too. No absolute mean is
exposed anywhere: absolute cost is exactly the Goodhart-able number.

### D6 — model version token is namespaced `stack:<id>` / `model:<id>`

The compiled role defaults are **not** in the compiled stack registry
(`llm.rs` `openai/gpt-4.1@2026-07-02` vs `model_versioning.rs` `oneiron/orchestrator-default@2026-07-06`).
An unregistered `ModelId` still needs a collision-free generation identity, so the token is
namespaced rather than a bare `ModelStackId`. Registered models resolve through the real
`ModelStackRegistry` reverse lookup (current-default preferred, then highest generation) — the
swap NEG test drives `stack:default-v1` → `stack:default-v2` to exercise that path, not the
fallback.

### D7 — llm.rs call site is an additive sibling, not a change to `resolve`

`RoleModelDefaults::resolve(&self, role) -> ModelId` is pure and vault-free; a hint read needs a
`&Vault`. Landed `resolve_with_routing_hint(&self, vault, role, task_class) -> Result<(ModelId,
Option<WeightHint>)>` immediately beside it (the llm.rs:581 region). It returns **exactly** what
`resolve` returns plus the hint — it cannot swap or veto a model (asserted). `resolve` itself is
byte-identical, which is why the full suite is the byte-identical-routing proof.

Declaring the import: llm.rs had **zero** `Vault` references before this ticket; it gains
`use crate::Vault`, `crate::error::Result`, and the two routing types. Its header says "no
provider implementation or inference dependency" — a Vault import is neither, but it is a new
dependency direction for that file and a screener should see it named.

### D8 — store.rs claimed but not touched

CLAIMS.md grants `store.rs` "vault_meta prefix only". store.rs has **no** ED prefix registry —
every sibling ED module (`attribution.rs`, `graduation.rs`, `escalation.rs`, `delta.rs`) declares
its own `vault_meta` prefix in-module, and none of them touches store.rs. Claim held, unused.
This removes a shared-file seam from the lane rather than adding one.

### D9 — `edit_distance.rs` mod line placement

`pub mod routing;` appended after the `#[cfg(feature = "sync")] pub mod proposal_text;` line
(true alphabetical order, matching the existing list). ED-04/1760 (`miner`) and ED-08/1764
(`publisher`) append to the same list; `publisher` sorts immediately before `routing`, so a
textual conflict there is expected — merge-in law resolves.

## Design decisions worth a screener's eye

**Outcome derivation (the Goodhart pair).** `sound = class ∈ {Environment, PreferenceShift}` —
the two classes that mean *the proposal was not wrong*. `Discovery` counts as UNSOUND: it charges
nobody, but it routes from `AmendmentCause::ProposalWrong`, so the draft did not stand. This is
what makes the pair genuinely independent of edit mass — the test
`the_hint_always_carries_the_paired_outcome` folds two amendments of *identical* mass whose
outcome scores differ, so cost alone provably cannot distinguish them.

**Peer set includes self.** A lone generation therefore scores exactly `1.0` (par). Excluding
self would leave an empty denominator and force the code to invent a verdict for "compared to
what". Documented at the fn and asserted.

**Aggregate rows are separate; only the SCORE compares across versions.** The NEG assert is on
the stored row (`old.runs == 2` after a swap, and no row anywhere holds 3) — the relative score
spanning generations within a task class is the PGR relativity the ticket asks for, not a blend.

**Known cost:** `record_judged_amendment` finds its judgment via `amendment_judgments(vault)`
(full ledger scan) because `attribution.rs` exposes no receipt-keyed judgment accessor and is
out of packet. Same posture as `project_edit_cost_claims`, which already full-scans per pass.
A `pub fn amendment_judgment(vault, receipt_id)` in attribution.rs would make it O(1) — banked,
not taken.

**Goodhart guard, structurally:** `WeightHint` has two `pub` fields and no accessor yielding one
alone; `routing_weight_hint` returns `Option<WeightHint>`, `None` unless `Graduated`. No
`is_banned`, no exclusion API, no door that removes a model from consideration — asserted by the
call-site test that the returned `ModelId` is unchanged whether or not a hint exists.

## Commits

- `bf3965076` WIP: module + call site
- `0d6358bdb` routing loop projection — aggregates, ladder, rebuild, 18 tests

Not pushed (workers never push; CY orchestrator publishes).
