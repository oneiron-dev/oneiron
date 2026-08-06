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

## VERDICT-FIX (Opus, on tip `e382614`)

Six verdict-verified findings, all fixed at their chokepoints. No
re-adjudication: the notes below record the SHAPE chosen and the bounds that
stay honest, not a second opinion on whether the findings were real. F2 was
rejected-with-derivation upstream and is not revisited.

Packet: `actor_claims.rs` (+ `actor_claims/tests.rs`), `skills_epic_oracle.rs`,
this worklog. **No `claim.rs` edit was needed** — the anticipated "validator
permit" turned out to live in this module's own
`validate_actor_claim_structure`, and `claim.rs` already routes `actor.*`
bodies to it (`claim.rs:1535`). No `session_lifecycle.rs` edit either: F5 is a
consume-ordering fix inside the distill runner, and the close transaction's
job registration was already correct. No `Cargo.toml`/`lock`.

### F1 — the CHAT lane read a shape production never writes (P1)

`session_turns` walked `TURN -ChildOf-> SESSION` edges and read `spkr`/`txt`
out of the TURN body. **Ground-checked: no production writer emits either
half of that on a witnessed sitting.** There are exactly two TURN writers:

| writer | TURN body | linkage it writes |
|---|---|---|
| `MemoryFacade::witness` (`facade.rs:1732`, `:1881`) | EMPTY container map | MESSAGE `PartOf` TURN, MESSAGE `BelongsTo` CONVERSATION |
| core turn door (`oneiron-server` `conversations.rs:210`) | `{spkr, txt, at}` | TURN edge into CONVERSATION |

Neither writes a SESSION edge at all. The lane therefore mined nothing in
production: `session_turns` returned empty, `run_session_end_actor_distill`
exited at its `turns.is_empty()` guard, and the chat inlet minted zero rows.

Fixed by deriving the sitting's turns from what production DOES record:

1. **Linkage is TIME.** The witness door bumps the open sitting's activity
   clock inside the turn's own write transaction, and at most one sitting is
   open per vault, so the sitting's `[started_at, ended_at]` window names
   exactly the turns learned during it. The scan is the `temporal_learned`
   range `dreamer_consolidation` already walks to find turns to dream about —
   the same index, the same key layout, for the same reason.
2. **Words come from both shapes.** `turn_utterance` reads the core door's
   `spkr`/`txt` body; when the body says nothing — as the witness door's empty
   container always does — `turn_message_utterances` folds the turn's MESSAGE
   children (`author`/`content`, ordered by the `order` field then id).
3. `SessionDistillTurn` now carries `said: Vec<SessionDistillUtterance>`
   instead of one `(speaker, text)` pair. A witnessed turn can hold a question
   and its answer under one `turn_ref`, and flattening those into a single
   speaker would attribute half the turn to the wrong actor — which matters
   more here than anywhere, since the rows are ABOUT actors.
4. The scan is bounded by `ACTOR_CLAIM_MAX_CITED_EVIDENCE`, keeping the LAST
   turns. The brief and the citation list are the same set by construction, so
   a 200-turn sitting can no longer build a brief the 64-entry evidence bound
   then refuses to cite (which would have failed the whole pass).

**Fixtures re-pointed through the real door.** Both `actor_claims/tests.rs`
and the oracle now open a sitting, call `MemoryFacade::witness`, and close
through `end_session_with_wake`. All four sk06 oracle arms pass on that path;
before this fix they passed only because the hand-built fixture happened to
write turns in the right window with the core door's body shape.

Honest bounds, stated rather than hidden: a turn witnessed with a BACKDATED
`occurred_at` falls outside the window and is not distilled (its `learned_at`
is the timestamp the caller supplied), and a sitting longer than the citation
bound is distilled from its tail. Both are recorded in the module doc.

### F3 — the door resolved nothing it was told (P1)

`write_actor_claim` authored reserved truth from `ActorClaimEvidence`, which is
built out of caller-owned strings and ids. The house adjudicated this exact
class REAL at the sibling door (1738-F1); the same answer applies.

`ground_actor_claim` is the one predicate now: the actor resolves, a fit row's
skill resolves, EVERY cited receipt resolves through
`receipt::attempt_pack_receipt`, and every cited session/turn resolves to an
entity of that type. Split from the write so the two inlets keep their own
policy without differing on the check — the door REFUSES an ungrounded row,
while both inlets SKIP one (the 1738 posture: one forged row must not deny a
whole pass, and a bad note must not poison a distill job into failing every
retry identically).

The TASK projector's old check resolved only `evidence_receipts.first()`; it
now grounds the whole citation list through the shared predicate.

### F4 — the lineage rode a channel no trust code reads (P1)

`ACTOR_CLAIM_LINEAGE_KEY` was a private `"lineage"` key inside the evidence
map. `claim_evidence_taint` and `claim_generated_origin` (`claim.rs:928-954`)
never look there, so GATE-11 corroboration and the `tool_output` consolidation
block both saw an unstamped row. A meet nothing enforces is a label.

Fixed onto the channel the lattice reads, per the ONE-1314 precedent: the meet
is stamped as a `CLAIM_SCOPE_EVIDENCE_TAINT_KEY` SCOPE entry, and
`ACTOR_CLAIM_LINEAGE_KEY` is now *defined as* that key — one fact, one channel,
no public-surface churn. `actor_claim_lineage` became a narrowing read over
`claim_evidence_taint`, so it inherits the engine's fail-closed answers (a
duplicated or unparseable stamp reads `Imported`, which this ledger never
mints, hence `None`, hence refused).

Three consequences handled at the same chokepoint:
- The validator PERMITS the taint entry and now polices the scope map key for
  key: exactly the lineage entry, plus the pair key on a fit row, nothing else
  (a peer cannot smuggle a `sensitivity` or federation stamp in beside it).
  It also gained an explicit `evidence.is_none()` refusal, which the old
  lineage-lives-in-evidence check had been providing as a side effect.
- A fit row's scope now carries TWO entries, so every pair read matches on the
  pair ENTRY rather than on whole-map equality — otherwise two lanes' estimates
  of one pair would look like estimates of two different pairs, and
  supersession would stop firing.
- Verified with teeth, not just a read-back: an `actor.failure_mode` row is now
  `claim_evidence_taint == ToolOutput` AND `!claim_consolidatable`.

### F5 — the distill job was spent before the work (P1)

`take_distill_job` deleted and COMMITTED the job, then ran the distiller. The
distiller is a host-supplied LLM tier — the one step in the pass that fails for
reasons that pass — so a transient error permanently lost that sitting's
distillation, and each note committed in its own transaction left partial
helpings behind.

Now: read the job → build the brief → run the distiller → write every row and
DELETE THE JOB in one transaction. The consume is identity-bound like the
session close it descends from (ONE-1685): the row is re-read inside the
transaction and must still be the job this pass planned against, so two runners
racing one sitting cannot both commit their notes. A sitting with no turns
still spends its job — it is closed, its turns are what they are, and nothing
can arrive later.

### F6 — SET rows never converged, and dropped cross-inlet evidence (P1)

The SET path did `heads.iter().find(...)` and returned — the 1738-F2/F3/F8
class exactly. Two replicas that each observed the same note hold two distinct
claim entities (`EntityId::now()` is per-replica unique) and after a sync both
are Active forever, since the door that should collapse them returns the first
one it finds.

The write chokepoint now computes a CONFLICT SET (by value for SET rows, by
pair for fit rows) and closes every member, with the ONE-1314 R3 taint fold:
each closed head's meet folds into the row that closes it. `lineage_meet` makes
`Generated` this ledger's bottom — a note resting even partly on model-written
prose is prose-derived — so the fold runs DOWN in both directions:
- task-observed head + chat re-observation ⇒ a new `generated` row closes it;
- chat-observed head + task re-observation ⇒ NO-OP. The head already carries
  the meet, and minting a `tool_output` row over it would walk a model-written
  note UP the lattice on the strength of a receipt that says nothing about its
  words. That was the laundering direction, and it is the one that needed the
  fold rather than the value comparison.

The single-head no-op survives (`one standing head that already carries this
meet` re-returns its id), so SET dedupe and the projector's replay idempotence
are unchanged. Honest bound: a re-observation that cannot improve the meet does
not rewrite the standing row's citation list; the closed heads keep their own
evidence, and merging citation lists across lanes would need a third evidence
shape and would race the 64-entry bound.

### F7 — supersede-all ignored event time (P2)

Conflicting heads are partitioned on `head_event_time(head, occurred_start) =
valid_from.unwrap_or(occurred_start)`: a head stamped LATER than the write is
not that write's to close, so a backfill at 50 leaves the estimate the ledger
holds at 100 standing, and `skill_fit_for` still resolves to it. The
`at.max(head_start)` clamp stays for the heads that ARE closed.

The SET path needed one extra rule to keep its cardinality: when a LATER head
already stands for this note, the backfill adds no row (the value is the key)
and instead collapses the older duplicates ONTO that standing head — converging
the fork without minting a row it must not mint.

### Mutation verification

Every fix was reverted in place and its naming test re-run; all eight mutations
were KILLED.

| mutation | test that died |
|---|---|
| read only the TURN body, drop the MESSAGE-children fold | `the_brief_carries_the_witnessed_words_in_scan_order` |
| skip receipt + turn resolution in `ground_actor_claim` | `a_row_citing_evidence_that_resolves_to_nothing_is_refused` |
| keep the meet off the `evidence_taint` scope entry | `the_lineage_meet_is_the_taint_the_trust_lattice_reads` |
| consume the distill job before the distiller runs | `a_failing_distiller_leaves_the_job_standing` |
| one transaction per note instead of one per pass | `a_pass_that_fails_midway_commits_no_partial_notes` |
| SET returns `supersedable.first()` and writes nothing | `a_duplicate_head_fork_collapses_on_the_next_write` |
| drop the `lineage_meet` fold over closed heads | `a_note_reobserved_from_the_other_lane_folds_the_meet_down` |
| partition every conflicting head as supersedable | `a_backfilled_fit_never_closes_a_later_head` |

The F1 premise is additionally pinned by a standing assertion rather than a
transient mutation: `the_brief_carries_the_witnessed_words_in_scan_order`
asserts the witnessed sitting has NO inbound `ChildOf` edge, so the old
derivation is provably empty on production's own output.

One mutation attempt deadlocked instead of failing — writing each note through
a nested `vault.with_write_txn` inside the pass transaction hangs LMDB rather
than producing separate commits. The M5b mutation was re-expressed as the real
pre-fix shape (each note through the public `write_actor_claim` door, before
the job-consume transaction), which fails cleanly.

### Gates (post-fix)

- `rustfmt --check` on all three packet files — clean.
- `cargo clippy -p oneiron --all-features --all-targets` — **zero diagnostics
  on every packet file**. The three pre-existing main defects still reproduce
  unchanged (`identity_topology/tests.rs:4203` redundant-clone is still the
  hard error, `surface_event/tests.rs:736` and
  `campaign_claim_gate_oracle.rs:87` warn). Not touched: reformatting or
  fixing a file this lane does not own is a packet violation.
- `cargo test -p oneiron --all-features --lib actor_claims` — **21 passed**
  (was 14; +7 verdict-fix tests, one renamed).
- `cargo test -p oneiron --all-features --test skills_epic_oracle` — 16 passed,
  0 ignored. No count-assert weakened; the only edit is the fixture's route
  through the witness door.
- `cargo test -p oneiron --all-features --lib` — **3500 passed, 0 failed, 17
  ignored** (was 3496 + the 4 net-new here).
- `git status --porcelain` — exactly the four packet files, no `Cargo.lock`.

### Deltas a reviewer should look at first

`write_actor_claim_in_txn` (the conflict-set partition and the meet fold) and
`session_turns` (the temporal derivation). Everything else follows from those
two.
