# WORKLOG — ONE-1739 [SK-06] actor.* claim writes

Lane SKILLS · stack SK layer 3 of 3 (1737 → 1738 → **1739**) · branch `ONE-1739`
cut off `origin/main` @ `d852449` (1738's merge).
Blueprint: `/Users/olety/.claude-wave5/blueprints/SKILLS/ONE-1739.md`.

## What landed

**`crates/oneiron/src/actor_claims.rs` (new, + `actor_claims/tests.rs`)** — the
`actor.*` ledger.

- Four §G.1 rows: `actor.lesson` / `actor.failure_mode` / `actor.scope_note`
  (SET, keyed on the normalized note) and `actor.skill_fit` (fit `0..=1`, ONE
  per `(actor, skill)`, superseding; the pair rides `scope = {skill}`, which IS
  the conflict-set key).
- `write_actor_claim(vault, row, evidence)` — THE chokepoint. The claim body is
  built inside the writer (`dreamer_promotion:114` house law), so approval /
  confidence / source / evidence are never caller-supplied. SET rows dedupe and
  return the standing id; fit rows supersede EVERY active head sharing their
  scope (post-sync two-head convergence), with the `at.max(head_start)` clamp
  the scan-verdict precedent uses.
- TASK inlet `project_actor_claims_from_judgments` — SK-04 `ExecutionLapse`
  judgments → one `actor.failure_mode` row. Every judgment is re-grounded, not
  trusted (must BE the persisted row at that sequence, subject must be a real
  actor entity, citation must resolve to a stamped pack receipt); ungrounded
  rows are skipped, not fatal.
- CHAT inlet `run_session_end_actor_distill(vault, session, distiller)` —
  consumes the SessionEnd distill job, builds the brief from the sitting's
  turns, and lands the distiller's notes through the same door. Mints no TASK.
- `register_session_end_distill_in_txn` is called from
  `Vault::end_session_with_wake_and_hint` in the close transaction, so
  "ended and unlearned-from" is durable, not a live process's intention.
- Read path `skill_fit_for(vault, actor, skill)` — the ED-07 / SK-05 bandit
  join point, newest-head-wins on `(valid_from, claim id)`.

**`claim.rs`** — `actor.*` joins the reserved namespaces. `is_reserved_predicate`
now covers `edge | skill | actor`; the private lifecycle door is renamed
`reserved_claim_for_lifecycle_in` and admits the two ENGINE-driven namespaces
(`skill.*`, `actor.*`) while still rejecting `edge.*`. A predicate-aware
structural branch routes the four rows to `validate_actor_claim_structure`.

**`provider_confidence.rs`** — `write_provider_prior` moves to the engine doors
(`put_reserved_claim_in_txn` / `supersede_reserved_claim_in_txn`), which the
namespace reservation requires. This CLOSES the KNOWN HOLE that file documented
on `actor.confidence_prior` ("a policy-authorized generic `put_claim` can plant
a head that this read then honors… NOT closed on this branch") — the comment is
rewritten to state the closed posture.

**`skills_epic_oracle.rs`** — the four `#[ignore]`d arms owned by this ticket are
armed (`sk06_actor_row_cardinalities_are_pinned`,
`sk06_two_inlets_one_ledger_both_through_the_write_gate`,
`sk06_chat_lane_mints_no_task_until_work_spawns`, and the re-pointed
`sk04_attribution_routes_defect_to_skill_and_lapse_to_actor`). Every count
assert is untouched. The oracle is now FULLY ARMED — 16 tests, 0 ignored — so
the dead `unarmed()` seam helper is removed.

## Rulings (deviations from the blueprint, each with its reason)

1. **`src` is `Observed`; the evidence meet rides `ACTOR_CLAIM_LINEAGE_KEY`.**
   The blueprint asked for `src = ToolOutput` on TASK-lane rows. The engine
   refuses that composition: `gate::check_source_trust` (reached for reserved
   writes via `check_reserved_claim_policy`) rejects `Auto` approval on a source
   that `requires_explicit_auto_permit` (Imported/ToolOutput/Generated), and the
   oracle pins these rows `Auto`. `src` here is the CONSENT axis plus the
   federation boundary (restamp → `Imported` → refused), which is exactly the
   posture the sibling `actor.confidence_prior` and `skill.reliability` rows
   carry. The lineage the blueprint actually wants protected — "never a
   trivially-Generated restamp of derived evidence" — is stamped as the evidence
   meet inside the evidence map (`tool_output` / `generated`), derived in the
   writer and **enforced by the structural validator on every write path,
   replication included**. `actor_claim_lineage(&ClaimBody)` is the public read
   ED-03 consumes. `with_lineage` (DREAMER 1314) is not on main; this shape
   composes with it when it lands.
2. **The TASK lane writes `actor.failure_mode` only — no lesson.** Oracle
   `sk04_…` pins `total_claims(actor) == 1` for one lapse, which the blueprint's
   two-row wording contradicts. Ruled in favour of the count (arming law: counts
   never weaken), and it is the better shape: `ExecutionLapse` is a routing
   BOOLEAN, so the class token (`LAPSE_FAILURE_MODE`) is derivable and a craft
   note is not. Inventing a house sentence to fill the lesson slot would be the
   engine writing content it has no evidence for. Lessons come from a distiller.
3. **`run_session_end_actor_distill` takes a `SessionActorDistiller`** (the
   blueprint's 2-arg signature + one seam param). Turning a sitting into prose
   is generative; the engine mints no LLM client, exactly as
   `run_attribution_projector_with_judge` does on the routing side. Budgeted
   under `actor_distill_call_purpose()`.
4. **`gate.rs` NOT touched** (blueprint listed it; CLAIMS.md flags it as a
   contested GATE-lane wall). Reserved-predicate writes bypass the policy gate
   by construction (`batch.rs` gates only `!allow_reserved_predicate` claim
   puts), so axis rows for `actor.*` would be unreachable configuration —
   which is why ONE-1738 added none for `skill.reliability` either. Skipping
   also avoids a needless rebase collision with DREAMER 1314.
5. **`dreamer_consolidation.rs` NOT touched.** The blueprint offered
   "`dreamer_consolidation.rs` (+/or `session_lifecycle.rs`)"; the close
   transaction is the precise hook point, so the whole wiring is 4 lines in
   `session_lifecycle.rs` and the DREAMER lane's file is left alone.
6. **`skill_attribution.rs` NOT touched.** The judgment→row wire lives in the
   new module (it consumes the landed `attribution_judgments` seam), so layer 1
   needs no edit.

## PACKET

⊆ CLAIMS.md ONE-1739 rows, with one amendment:

| file | status |
|---|---|
| `crates/oneiron/src/actor_claims.rs` + `actor_claims/tests.rs` | new, claimed |
| `crates/oneiron/src/claim.rs` | claimed (reservation + 1 validator branch) |
| `crates/oneiron/src/session_lifecycle.rs` | claimed (additive distill hook) |
| `crates/oneiron/tests/skills_epic_oracle.rs` | claimed (arming) |
| `crates/oneiron/src/lib.rs` | claimed (module + re-exports) |
| `crates/oneiron/src/provider_confidence.rs` | **PACKET_AMEND** |

**PACKET_AMEND — `provider_confidence.rs`:** two call sites move to the engine
doors. Unavoidable: reserving `actor.*` without it would break the very path the
blueprint requires to keep working. No collision — no other lane's CLAIMS.md
names this file. Not claimed, so surfaced here for ratification.

## Gates

- `cargo fmt -p oneiron -- --check`: clean except the pre-existing base defect
  `surface_event/tests.rs:733` (mech lane's; reverted after each format run,
  never touched).
- `cargo clippy -p oneiron --all-features --all-targets`: no finding in any file
  this lane touches. Remaining are base defects on main —
  `identity_topology/tests.rs:4203` (redundant clone),
  `surface_event/tests.rs:736` (redundant closure),
  `campaign_claim_gate_oracle.rs:87` (needless borrow).
- `cargo test -p oneiron --all-features`: **42/42 suites ok, 0 failed.**
  New: 14 unit tests in `actor_claims::tests`, 4 oracle arms armed
  (`skills_epic_oracle` 16 passed / 0 ignored).

## SIMPLIFY (K3, 2026-08-06)

Deletion-biased pass over the tip. Three cuts, all in `actor_claims.rs`;
no test assertion, fixture, or exercised public API touched:

1. **`ActorNoteKind::predicate()` deleted** — dead surface: zero callers
   (grep-verified across src + oracle), and not in the keystone skeleton. The
   note kind only ever becomes a row through the private `row()` arm.
2. **`ActorClaimEvidence::at()` deleted** — dead accessor; the one reader
   (`write_actor_claim`) is in-module and reads the field directly.
3. **Fit-range check deduplicated into `valid_skill_fit(fit)`** — the
   `is_finite && (0.0..=1.0).contains` pair appeared verbatim in
   `value_and_scope` and `validate_actor_claim_structure`; the NaN-trap
   comment moved to the helper so the subtlety lives in one place.

Considered and rejected: sharing `dreamer_consolidation::decode_turn_body`
for the CHAT-lane turn parse. It is DREAMER's private surface mid-wave, its
`TurnBodyFacts` carries two fields this lane never reads, and exposing it is
structure-addition across a claimed seam — the 18-line tolerant-read
duplication (same `spkr`/`txt` spelling tolerance, house precedent) is the
cheaper shape.

Gates after the cuts: `cargo fmt -p oneiron -- --check` — only the known
base defect `surface_event/tests.rs:733` · clippy `--all-features
--all-targets` — only the three documented base defects
(`identity_topology/tests.rs:4203`, `surface_event/tests.rs:736`,
`campaign_claim_gate_oracle.rs:87`), nothing in lane files ·
`cargo nextest run -p oneiron --all-features`: **3802 passed, 0 failed**.
