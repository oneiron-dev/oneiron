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

## Merge-in with ONE-1764 (+ a main-red finding for the orchestrator)

Base was `16c125b3e`. While this lane built, main advanced twice, so the lane was merged in
(merge-in law: merge main INTO the lane, first parent = old tip, no history rewrite, no push).

Two conflicts, both the predicted D9 append collisions, both resolved by keeping BOTH sides in
alphabetical order (`publisher` then `routing`):

- `crates/oneiron/src/edit_distance.rs` — `pub mod publisher;` / `pub mod routing;`
- `crates/oneiron/src/lib.rs` — the two ED re-export blocks

### ⚠ FINDING — main was RED, and the shared `origin/main` ref moved mid-merge

The first merge attempt resolved cleanly and then failed to compile, in a file this lane does
not own:

```
error[E0004]: non-exhaustive patterns: `AttributionVerdict::Environment` and
              `AttributionVerdict::PreferenceShift` not covered
   --> crates/oneiron/src/edit_distance/publisher.rs:160:15
```

That is **ONE-1764 (#619) × ONE-1759 (#618) semantic merge skew with zero textual conflict** —
#619's `IssueCategory::from_verdict` was exhaustive over the 3-variant `AttributionVerdict` it
was cut against; #618 had since taken it to 5. Not caused by this lane, and reproducible on
`0aab5fa44` alone.

It was already being fixed: `6fb57ca44 HOTFIX: IssueCategory gains Environment/PreferenceShift
parity arms (#620)` landed **while this merge was in progress**. Because git worktrees share
`.git/refs`, `origin/main` moved underneath the merge — the merge had captured `0aab5fa44`
(red), while `git show origin/main:...` was already answering from `6fb57ca44` (green). That
mismatch is what made the failure look impossible at first read.

Handled by `git merge --abort` and re-merging against the fixed tip. **Nothing was worked around
and no arm was added by this lane** — the parity arms in the merged tree are #620's.

Process note worth banking: **a worker cannot treat `origin/main` as stable within a single
turn.** Any lane doing a merge-in should pin the tip (`git rev-parse origin/main`) before
merging and verify `MERGE_HEAD` against that pin afterwards, or it can silently integrate a red
tip and spend the debugging budget on someone else's defect.

## Commits

- `bf3965076` WIP: module + call site
- `0d6358bdb` routing loop projection — aggregates, ladder, rebuild, 18 tests
- `08ee389d6` worklog
- `6aef17807` merge `origin/main` (`6fb57ca44`) into the lane — first parent `08ee389d6`

## SIMPLIFY pass (K3, on the merged tip)

One edit, deletion-only: `routing_data_bar` dropped its per-task-class rung memo cache
(`BTreeMap<String, RolloutRung>` + entry-match, 11 lines) for a straight per-row
`rung_in_txn` read (2 lines). The cache memoized at most one read per task class in a
loop whose per-class row count is the number of model generations ever serving (≤ a
handful) — speculative optimization on a bounded-tiny scan, and the stored task class
is already normalized at write, so the direct read builds the identical key. Behavior
unchanged; no public API, no test, no assertion touched. Goodhart guard, rung ladder,
and the swap hard-reset untouched.

Everything else read as already at simplify-pass quality — no dead helpers, no
duplicated layers, no defensive branches without a reachable case (the
`peer_mean > 0.0` guard in `hint_of` covers the real all-zero-edit-mass class, not a
theoretical one). NO further edit warranted.

Gates after the pass: `cargo fmt --all -- --check` clean ·
`cargo clippy -p oneiron --all-features --all-targets -- -D warnings` clean ·
`cargo test -p oneiron --all-features edit_distance::routing` 18/18 green.
`Cargo.lock` still modified in the worktree, never staged.

Gates re-run green on the MERGED tree: fmt clean, clippy `-D warnings` clean,
`cargo test -p oneiron --all-features` **47/47 binaries, 3880 lib tests, 0 failed**.

## VERDICT-FIX (Opus, on the simplify tip `9a0cf80c0`)

Finder returned 4 items; the verdict leg confirmed **one** REAL and banked/rejected the rest
with derivations. Only the confirmed item was fixed — nothing relitigated.

### FIXED — P2 `concurrency`, `routing.rs` (first-fold-wins was not atomic)

`record_judged_amendment` decided first-fold-wins in a read transaction it then dropped
(`routing.rs:424-429`) and never re-checked inside `with_write_txn` (`:443`). LMDB's single
writer serializes the two *writes*, but it does not make either fold's decision *to* write
correct: two folds of one receipt both read the binding as absent, then commit in turn, and
one receipt counts as two runs. That silently breaks the module's stated contract and, because
the second fold samples the serving pointer again, it can also charge the extra run to a
generation that did not produce it.

Fix, at the chokepoint and nowhere else: the binding read moved INTO the write transaction as
its first statement, with the early `Ok(())` there. The pre-check outside was deleted rather
than kept as a fast path — one check, in the only place it is decisive; the duplicate-fold
path is the rare one and does not deserve a second code path to be wrong in.

**Mutation-verified.** New test `concurrent_folds_of_one_receipt_still_count_one_run`:

- **RED before** (check restored to its pre-fix position): `left: 2, right: 1`, 3/3 runs.
- **GREEN after**: 3/3 runs.

The interleaving is *forced*, not raced. The test opens a write transaction and holds it, then
spawns both folds: each reaches its binding read while the lock is held, so neither can observe
the other's write, and dropping the gate lets them commit one at a time. That makes the red
deterministic before the fix and the green deterministic after it — after the fix no ordering
exists in which the second fold can commit before the first, so the assertion cannot be raced.
Test fixture `fold` split into `judge` (ED-01 → ED-03, stopping before the routing fold) and
`fold` (`judge` + `record_judged_amendment`), so a judged-but-unfolded receipt is available;
no existing assertion or fixture value changed.

### NOT FIXED — carried to the deviation board as banked items

- **BANK-1** (finder P1 `model-version-keying`, rejected): an owner swap between draft and
  judgment misattributes the run, and withdraw → rebuild → swap → re-judge loses the original
  binding. Unfixable in packet — `AmendmentJudgment` carries no producing-model identity, so
  the serving pointer plus the membership ledger is the ratified shape's only realization.
  Needs receipt-carried `ModelStack` identity (a receipt-format change). Same hole D3 already
  banks above.
- **BANK-2** (finder P1 `rebuildability` sub-point b, rejected): skeleton says
  `record_judged_amendment(delta_receipt: &EntityId)`, landed `&str`. Justified deviation,
  already written up as **D1**; surfaced for the GATE-2 board.
- **BANK-3** (finder P1 `routing-integration`, rejected): the hint-read landed as the sibling
  door `resolve_with_routing_hint` with no in-crate caller. Accepted because `resolve` itself
  has zero production callers and `engine_executor.rs` is packet-forbidden — but **ONE-1765
  (layer 2) must wire a live consumer or the graduated rung stays decorative.** Already
  written up as **D7**.

### Gates after the fix

- `cargo fmt --all -- --check` — clean
- `cargo clippy -p oneiron --all-features --all-targets` (workspace `-D warnings`) — clean
- `cargo test -p oneiron --all-features --no-fail-fast` — **47/47 binaries, 3881 lib tests,
  0 failed** (3880 → 3881: the one new race test)

Flake note, charged to no lane: the first full run failed
`embed::tests::partial_remote_completion_is_logged_when_local_batch_fails`
("completed remote work must surface in a warning, got []"). Green 3/3 in isolation and green
on the identical full re-run. Thread-local `WarnCapture` over a timing-sensitive remote-rung
path, no dependency on `edit_distance` in either direction — pre-existing flake, not this fix.

Diff ⊆ packet: `routing.rs` + `routing/tests.rs` only. `Cargo.toml` / `Cargo.lock` /
`settings.rs` / `engine_executor.rs` / `store.rs` untouched.

Commit: `a9b8a0c3b` VERDICT-FIX — first-fold-wins decided inside the write transaction.

Not pushed (workers never push; CY orchestrator publishes). `Cargo.lock` modified in the
worktree, never staged.
