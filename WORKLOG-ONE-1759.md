# WORKLOG — ONE-1759 [ED-03] `edit_cost` claims + attribution judge

Branch `ONE-1759` off `origin/main` @ `9137bfc7d` (ED-A complete + ONE-1762 #613 merged).
Blueprint: `~/.claude-wave5/blueprints/ED/ONE-1759.md` · Claims: `~/.claude-wave5/blueprints/ED/CLAIMS.md`.
Cross-lane gate satisfied: SK-04 (ONE-1737) and SK-06 (ONE-1739) are both merged at base.

## What landed

| file | change |
|---|---|
| `crates/oneiron/src/edit_distance/attribution.rs` | **NEW** — the amendment judge, the judgment ledger, the `*.edit_cost` write door, the preference-proposal inlet, the held-out audit |
| `crates/oneiron/src/edit_distance/attribution/tests.rs` | **NEW** — 15 tests |
| `crates/oneiron/src/edit_distance.rs` | `pub mod attribution;` |
| `crates/oneiron/src/claim.rs` | additive consts `PREDICATE_ACTOR_EDIT_COST`, `PREDICATE_SKILL_EDIT_COST` (registry untouched) |
| `crates/oneiron/src/skill_attribution.rs` | 2 additive `AttributionVerdict` variants (`Environment`, `PreferenceShift`) + their `as_str`/`parse`/`verdict_subject` arms |
| `crates/oneiron/src/actor_claims.rs` | additive `ActorClaimRow::EditCost` arm, additive `ActorClaimEvidence::amendment` lane, scope consts, validator arms |
| `crates/oneiron/src/lib.rs` | re-exports |
| `crates/oneiron/src/edit_distance/escalation/tests.rs` | **PACKET_AMEND A** — one-line pre-existing main-red fix (below) |

Shape actually built:

```
Δ RECEIPT (ED-01/02)  +  routing facts (record_amendment_evidence)
  └─ judge_amendment ──> AmendmentJudgment  (persisted, keyed by receipt id)
       ├─ skill_defect     → skill.edit_cost   (put_reserved_claim_in_txn)
       ├─ execution_lapse  → actor.edit_cost   (write_actor_claim chokepoint)
       ├─ discovery        → nothing here; SK-04 owns its consequence
       ├─ environment      → nothing at all; the judgment row IS the record
       └─ preference_shift → a PreferenceProposal row for ED-04's miner
```

`classify_amendment` pre-filters the two amendment-only causes and hands the
`ProposalWrong` arm **verbatim** to SK-04's `AttributionJudge`. That is the
no-fork proof: one trait, one rule table, one `CallPurpose`, zero LLM clients
in `edit_distance/`.

## Blueprint deviations (all declared, none silently absorbed)

1. **`judge_amendment(vault, receipt_id: &str) -> Result<Option<AmendmentJudgment>>`**
   — blueprint sketched `(vault, delta_receipt: &EntityId) -> Result<AmendmentJudgment>`.
   Two changes: (a) receipts are RS1 **String** ids on the landed spine
   (`amendment_delta(vault, receipt_id: &str)`, `AttributionJudgment.evidence_receipts:
   Vec<String>`) — there is no `EntityId` for a receipt; (b) abstention must be
   representable, or the audit's abstention arm has nothing to measure.
2. **`project_edit_cost_claims` returns `Result<Vec<EntityId>>`**, not `Result<()>` —
   matches SK-06's `project_actor_claims_from_judgments`, and makes the "read-back
   verifies the citation list" done-means checkable.
3. **`AmendmentJudgment` carries `receipt_id`, `subject`, `d_norm`, `at`** beyond the
   blueprint's `{class, scope, evidence_receipts}`. A judgment with no subject cannot
   route a claim, and the aggregate has to fold the Δ it was judged from.
4. **`AmendmentCause` is new** (not in the blueprint). It is the ONE fact the amendment
   lane needs that the attempt lane gets for free: a failed attempt is wrong by
   construction, an *approved* amendment is not. Without it `Environment` and
   `PreferenceShift` are unreachable, and the pre-filter/delegate split — which is what
   makes "extends, never forks" structural rather than aspirational — has nothing to
   filter on.
5. **`skill_attribution.rs`'s footprint is SMALLER than the blueprint's
   "additive evidence-inlet arms".** Amendment evidence never enters SK-04's evidence
   LEDGER — it rides SK-04's *judge* seam only, so `OutcomeEvidence`,
   `record_attribution_evidence`, `validate_evidence` and the SK-04 codec are
   byte-identical. The SKILLS-owned module takes the 2 enum variants and their pinned
   arms, and nothing else. Smaller blast radius on another lane's merged file, same
   no-fork property. **Screener: this is the one place I deliberately did less than the
   blueprint asked.**
6. **`Discovery` is reachable in the amendment lane and earns no cost row.** ARCH-0056
   names four amendment classes; `Discovery` is SK-04's fifth and arrives through the
   delegated arm. Charging a skill for content it never claimed to have would
   double-book a signal that already has a consequence (SK-04's edit proposal).
7. **`skill.edit_cost` gets no `claim.rs` structural validator** — consistent with its
   sibling `skill.reliability`, which has none either, and it keeps `claim.rs` to
   additive consts exactly as CLAIMS.md line 29 requires. `actor.edit_cost` DOES get one
   (via `is_actor_claim_predicate` → `validate_actor_claim_structure`, in
   `actor_claims.rs`, not `claim.rs`).
8. **Audit rows land in ED's own `vault_meta` prefix, not an RS1 receipt.** SK-04's
   landed header already pins this reading ("`receipted` here = persisted audit rows at
   the audited prefix, NOT RS1 receipt rows"). `AttributionAuditReport` is REUSED so ops
   reads one metric shape across both evidence classes. No new `ReceiptKind`,
   `receipt.rs` untouched.
9. **ctx open-question 8 resolved, no work needed:** SK-06 already reserved `actor.*`
   (`RESERVED_ACTOR_PREDICATE_NAMESPACE`, `claim.rs:741`; `is_engine_owned_reserved_predicate`).
   Both new predicates are refused by the public API on arrival — asserted in
   `public_writes_of_both_cost_predicates_are_reserved`.
10. **`tests/skills_epic_oracle.rs` NOT touched.** The PACKET made it conditional; the
    condition did not fire. The oracle only *compares* and *constructs*
    `AttributionVerdict` — it has no exhaustive match — so the two new variants need no
    arming note there.

## PACKET_AMEND candidates

**A — APPLIED, needs ratification.** `crates/oneiron/src/edit_distance/escalation/tests.rs`,
one line: `approx: false` added to an `OpsSummary` literal.

*Pre-existing main-red at `9137bfc7d`, charged to no lane.* ED-02 (ONE-1758) added
`OpsSummary::approx`; ED-06 (ONE-1762)'s test fixture predates the field and merged
without a rebase-test. `cargo check -p oneiron --all-features --all-targets` fails on
**clean HEAD** with `E0063: missing field 'approx'`. Verified against `git show HEAD:`
before touching anything. Same lane (ED), zero semantic content, and ED-03 cannot run its
own final gate without it. Classic 1758×1762 merge-skew — worth a note at the
postmortem: sibling-ticket test fixtures inside one lane's stack are not covered by the
per-lane cheap gate when the earlier ticket's field lands after the later ticket's tests
were written.

**B — in-packet, but larger than "additive arm", so naming it.** `actor_claims.rs`:

- `write_actor_claim_in_txn`'s conflict logic was generalized from the landed
  `pair`/`skill_fit_scope_skill` pair into a `ConflictKey` enum (`Value` / `Skill` /
  `Scope`). Behaviour for all four landed rows is unchanged — `ConflictKey::from_scope(None)`
  is `Value`, which is exactly the landed `pair.is_none()` branch.
- `validate_actor_claim_structure`'s `fit_row: bool` became `pair_key: Option<&str>`,
  and `actor_scope_is_exact` takes it. Same three checks, one more row kind.
- private helper `valid_skill_fit` → `valid_unit_interval` (3 call sites) — the same
  predicate now governs two rows, and the old name would read as a lie at the new one.

No public API of SK-06 changed shape; no landed test needed editing (SK-06's own suite
passes untouched, which is the evidence that the generalization is behaviour-preserving).

## Design notes for the screener

- **Cost is recomputed, never accumulated.** `project_edit_cost_claims` folds the WHOLE
  persisted judgment ledger for the row's `(subject, scope)` pair on every pass, so a
  re-run is idempotent and an interrupted pass leaves a stale row the next pass corrects
  (the `project_skill_reliability` posture). Asserted in
  `the_cost_row_supersedes_and_averages_its_judgments`.
- **The amendment evidence lane grounds on the Δ side-ledger.** `ActorClaimEvidence::amendment`
  cites amendment receipts, which are NOT attempt pack receipts — the task lane's
  `attempt_pack_receipt` lookup would answer "no such receipt" for a citation that is
  plainly readable. Grounding is `amendment_delta(...).is_some()`, which also means an
  **uncaptured** Δ grounds nothing: an unmeasured edit has no cost to charge.
- **Re-judging replaces the receipt's row and withdraws a stale preference proposal.**
  Freezing the first verdict would keep a wrong one forever, which is the exact failure
  the Blind Curator audit exists to provoke a fix for.
- **`AlwaysDefectJudge` drops the audit pass-rate from 1.0 to 0.67 and its abstentions to
  the pre-filter's one.** That is the "the metric moves visibly" done-means; the
  `SilentJudge` test pins the other end (abstaining on everything cannot score full
  marks).

## Gates

- `cargo fmt -p oneiron` — clean
- `cargo clippy -p oneiron --all-features --all-targets -- -D warnings` — clean
- `cargo test -p oneiron --all-features` — **exit 0; 45/45 test-result sections ok; 3784
  lib + all integration targets, 0 failed** (new module: 15/15). Log:
  `/tmp/ed03-final-suite.log`.
- **Flake, guarded and cleared:** one run out of six reported `3783 passed; 1 failed` in the
  lib target. It happened in the one invocation where two full suites were launched
  back-to-back in a single shell command (against the house "never two concurrent full
  suites on one Mac" rule); the failing name was lost to a grep. Four subsequent
  full-suite runs on the same tree — three `--lib`, one complete — are green, so it is
  charged to the doubled invocation, not to this lane. Flagged here rather than quietly
  re-run.
- `Cargo.lock` modified by `--all-features` resolution; **never staged, never committed**
  (restored to HEAD; working tree clean).
- `git merge-tree HEAD origin/main` (now `98195c3b8`, ONE-1823 [BK-00] landed after this
  branch was cut): **no textual conflict**. Base drift is textually clean, `claim.rs` is
  the only file both touch and the regions are far apart. Rebase stays script-owned.

## SIMPLIFY pass (K3, on tip)

Three deletions, no additions, no test/assertion/public-API touches:

1. **`attribution.rs`: deleted `cost_scope_name` + `skill_cost_scope`** — exact duplicates
   of the helpers this lane itself added to `actor_claims.rs` (`edit_cost_scope_name`,
   `edit_cost_scope`). Those two are now `pub(crate)` (visibility only; no signature or
   behaviour change) and `attribution.rs` imports them. The scope-map reader/writer for
   `*.edit_cost` rows now has ONE home, in the module that owns the row shape. The
   "one scope entry, duplicated key reads as none" rationale moved onto the shared
   helper's doc.
2. **`attribution.rs`: dropped the intermediate `PreferenceProposal` construction** in
   `judge_amendment_with` — it was built only to be immediately re-destructured into
   `StoredPreference`; the stored row is now built directly. `PreferenceProposal` stays
   as the READ type (`pending_preference_proposals`), which is its only real use.
3. Considered and REJECTED: folding `attribution::normalized_scope` into
   `escalation`'s same-named helper — escalation's returns `Error::InvalidConsentBound`,
   this module's returns `Error::InvalidClaimBody`; unifying would change a landed error
   variant on an error path for ~8 lines. Not worth it.

Net: -52/+22 across the two files (incl. doc moves). Gates after the pass: `cargo fmt
-p oneiron` clean · `cargo clippy -p oneiron --all-features --all-targets -- -D warnings`
clean · `cargo test -p oneiron --all-features --lib` **3784/3784 ok**. One unrelated
wall-clock flake (`batch::tests::authority_fold_backfills_legacy_missing_first_seen_sidecars_once`,
"first-seen must be the local observation, not learned_at") fired once mid-sweep, passed
in isolated re-run and in the confirming full lib run; batch authority-fold shares no
code with this diff — charged to no lane, noted for the flake ledger.

## VERDICT-FIX (Opus, on the simplify tip)

Finder returned 5 items; the verdict leg confirmed 4 REAL (1 P1 + 3 P2) and REJECTED 1 as a
maximalism wall. All 4 fixed at their chokepoints, all inside the lane's own packet
(`attribution.rs` + two `pub(crate)` visibility lifts in `actor_claims.rs`, no behaviour
change to 1739-merged code). **Every fix is mutation-verified: the five new tests were
written FIRST and each failed at its own new assertion on the pre-fix tip
(`15 passed; 5 failed`), then passed after the fix (`20 passed; 0 failed`).**

### 1. P1 `stale-edit-cost-retraction` — the projector now reconciles before it writes

The judgment ledger is overwrite-by-receipt, but `project_edit_cost_claims` derived its
targets ONLY from each input judgment's CURRENT `(class, subject, scope)`. Re-judge receipt
R from `SkillDefect(skill A, scope X)` to `Environment` (or another subject, or another
scope) and nothing in the new judgment names the old tuple — the active `skill.edit_cost`
head for `(A, X)` was orphaned forever and `edit_cost_for(A, X)` kept returning a charge no
persisted judgment supported. Directly contradicted the module's own docstring.

Fix: the projector keeps its landed tuples as their own small ledger
(`TARGET_KEY_PREFIX`, `StoredTarget`), and every pass now starts with
`retract_unsupported_targets` — any recorded `(predicate, subject, scope)` whose
`aggregate_for` over the whole persisted ledger is `None` has its active heads RETRACTED
(`ClaimLifecycleStatus::Retracted`, `valid_to` stamped) and its tuple forgotten, in one
transaction. Retraction, not deletion: the row stays readable as history.

Mechanics note for the screener: `Vault::retract_claim` refuses a reserved predicate by
design (`claim_for_lifecycle_in`, `claim.rs:2568`), and `claim.rs` is const-only in this
packet, so the closed body is re-put through `put_reserved_claim_in_txn` — the same
engine-owned door that wrote it, exactly the shape `supersede_reserved_claim_in_txn` uses
for its own closed body, and the shape `provenance.rs` uses for its namespace's retraction.
`record_target` runs BEFORE the head it describes (the merged write door owns its own
transaction, so the two cannot land atomically): a tuple recorded without a head is
reconciled away harmlessly, a head landed without its tuple would be unreachable forever.

Test: `a_reclassified_receipt_retracts_the_head_it_orphaned`.

### 2. P2 `stale-derived-state-on-abstention` — a withdrawn answer is deleted, not kept

The `classify → None` early return (and the no-subject arm) exited before the write
transaction, so a re-judging pass whose honest answer was ABSTENTION left the previous
judgment row AND its preference proposal live and queryable — and the projector could keep
charging from it. New `withdraw_judgment` deletes the receipt's judgment + preference rows
in one transaction on every post-evidence-load no-land path (missing Δ, abstention,
subject-less cost class). It reads first and only opens a write txn if there is something
to withdraw — abstention is the common case and must not cost a transaction.

Composes with fix 1: withdrawal removes the ledger support, the next projection pass
retracts the head. Tests: `an_abstaining_re_judgment_withdraws_the_answer_it_replaced`,
`a_withdrawn_judgment_stops_charging_on_the_next_pass` (the second projects an EMPTY batch
— reconciliation is not conditional on having something to write).

### 3. P2 `replay-non-idempotence` — an unchanged pass re-returns its own head

Both writers mint `EntityId::now()` and supersede unconditionally, so an identical second
pass forked a fresh claim entity, superseded the prior head and returned a different id —
unbounded phantom supersession history and sync traffic despite the docstring's idempotence
claim. New `write_cost_head` reads the tuple's active heads first: if there is exactly ONE
and it already carries the same value, the same `valid_from` and the same evidence payload,
it is returned without a write. TWO active heads is a post-sync fork that must collapse, so
that case still falls through to the writers on purpose. The check is in `attribution.rs`,
never in the merged 1739 door.

Test: `a_replayed_pass_re_returns_the_head_it_already_landed` (asserts id equality AND
`superseded_count == 0`).

**One landed test changed shape, deliberately, and is recorded here rather than quietly.**
`the_cost_row_supersedes_and_averages_its_judgments` recorded BOTH judgments and only then
projected twice — but the value is recomputed from the whole ledger, so its first pass
already landed the final aggregate and its second pass was a genuine replay. Its
`superseded_count == 1` assertion was therefore only ever passing on the churn this fix
removes. The test now projects as the judgments ARRIVE (first pass sees one judgment,
second sees two), which makes the value actually move and exercises the supersession path
for real. No assertion was weakened or deleted — same four asserts, on a scenario that
tests what they claim to.

### 4. P2 `evidence-inlet-type-validation` — the door enforces the actor matrix

`record_amendment_evidence` checked actor EXISTENCE only (`get_raw`), so a TURN or MESSAGE
was accepted, judged `ExecutionLapse`, and persisted — and then `project_edit_cost_claims`
failed at `require_actor_entity` inside the write door, a persistent wedge on durable state
the engine had already accepted. The door now asks the downstream door's own question
(`require_actor_entity`, the D13 matrix), at the point of observation. Chokepoint fix: no
new wedge can be recorded, so the projector needs no second guard.

Test: `the_evidence_door_refuses_a_subject_that_cannot_act`.

### 5. REJECTED item — banked, not relitigated

P1 `projector-chokepoint-bypass` (`actor_claims.rs:543`) was rejected with derivation by the
verdict leg: `ActorClaimRow::EditCost` has exactly one construction site tree-wide (inside
the projector), the blueprint's done-means is an API-shape invariant that HOLDS, and the
demanded fix would refactor 1739-merged chokepoint semantics (forbidden by packet) and by
symmetry gut the merged `SkillFit` arm too. No code written for it.

### Packet + gates

Diff is exactly three files: `edit_distance/attribution.rs`,
`edit_distance/attribution/tests.rs`, and `actor_claims.rs` — the latter carrying ONLY two
`pub(crate)` visibility lifts with their rationale docs (`require_actor_entity`,
`ActorClaimEvidence::to_value`), the same additive move CLAIMS.md line 32 already sanctions
for `llm.rs::canonical_json_bytes`. No `claim.rs`, no `skill_attribution.rs`, no
`settings.rs`, no `Cargo.toml`; `Cargo.lock` was touched by `--all-features` resolution and
restored to HEAD twice (never staged).

- `cargo fmt --all` — clean
- `cargo clippy -p oneiron --all-features --all-targets -- -D warnings` — clean
- `cargo test -p oneiron --all-features` — **45/45 test-result sections ok, 0 failed**
  (lib: 3789 passed, 17 ignored; attribution module 20/20)
