# WORKLOG — ONE-1760 [ED-04] recurring-substitution miner

Branch `ONE-1760` off `origin/main` @ `16c125b3e` (ED-B L1 = 1759 #618 merged).
Blueprint: `/Users/olety/.claude-wave5/blueprints/ED/ONE-1760.md`.

## Landed

| file | change |
|---|---|
| `crates/oneiron/src/edit_distance/miner.rs` | **NEW** — the pass, the clustering, the chooser, both emissions, the dials |
| `crates/oneiron/src/edit_distance/miner/tests.rs` | **NEW** — 28 tests |
| `crates/oneiron/src/edit_distance.rs` | `pub mod miner;` (one line, append-only) |
| `crates/oneiron/src/dreamer_consolidation.rs` | `DREAMER_SUBSTITUTION_MINE_ATTEMPT_TYPE` const beside `DREAMER_GAP_SCAN_ATTEMPT_TYPE` (line 64) + ONE additive executor arm |
| `crates/oneiron/src/lib.rs` | re-export block |

**NOT touched** (per PACKET/CLAIMS): `settings.rs` · `Cargo.toml` · `Cargo.lock` · `claim.rs` ·
`myers.rs` · `delta.rs` · `attribution.rs` · `skill_attribution.rs` · `session_lifecycle.rs` ·
`inbox.rs`. **PACKET_AMEND candidates: none.**

## Gates

* `cargo fmt -p oneiron --check` clean
* `cargo clippy -p oneiron --all-features --all-targets` clean (`-D` set from `[workspace.lints]`)
* `cargo clippy -p oneiron` (default features) clean — the 5 dead-code warnings are pre-existing
  (`batch.rs`, `gate/tests.rs`, `identity_topology.rs`, `store.rs`), none in ED files
* `cargo test -p oneiron --all-features` — **3877 passed, 0 failed** (lib) + every integration
  suite green; `edit_distance::miner` = 28/28

## Blueprint deviations — declared, none silent

### D1 · `receipt_refs: Vec<EntityId>` → `Vec<String>`
The ratified skeleton types receipt refs as `EntityId`. A receipt id in this engine is a STRING
(`gate:<hex>`, `proposal_outcome:<hex>`, `receipt.rs:2337/2626`), and both ledgers the miner joins
— ED-01's Δ side-ledger and ED-03's `AmendmentJudgment.evidence_receipts` — key on `String`.
`EntityId::from_hex` on a real receipt id cannot succeed.

### D2 · `SubstitutionCluster` gains `actor`, `skill`, `at`
`actor` is in the bucket KEY; `skill` and `at` are derived.
* `actor` — the preference arm writes a claim, and a claim needs a `ClaimSubject::Entity`. A cluster
  spanning two actors would force a guess, which the house forbids (cf. `OpAttribution::DevicePeer`).
  ARCH-0056 §5 already pins the scope as the `op × target class × skill/agent` cross, so keying on
  the actor is that cross made mechanical, not new structure.
* `skill` — the content arm's proposal names a SKILL; `None` on a split vote, so no skill is edited
  on disagreement.
* `at` — the emitted claim's `valid_from` / event time.

### D3 · `run_substitution_miner(vault, &SessionRef)` → `(vault, &MinerRun)`
`MinerRun { session: EntityId, run_id: String, agent: WriteActor }`. Three groundings, the last two
found by the engine REFUSING the ratified shape, not by preference:
1. `SessionRef` does not exist in the engine — a sitting is an `EntityId`
   (`session_lifecycle.rs::end_session_with_wake`).
2. `WriteActor::new(session, System)` was rejected at the write door:
   `ActorClassMismatch { actor_entity_type: 2, actor_class: 2 }` — `provenance.rs::validate_actor_class`
   (D13) admits `System` only for a MACHINE and `Agent` only for a PERSON/AGENT_DEF, and a SESSION is
   neither. `dreamer_runner.rs:2900` states that WHICH actor a deployment trusts is deployment
   policy, so the caller supplies it exactly as `DreamerRunContext::agent_actor` does.
3. `gate.rs::dreamer_run_id_from_provenance` derives a Proposed claim's INBOX GROUP KEY only from an
   `Agent`-class `Generated` write whose provenance names the dreamer surface AND a run id. Without
   both, the mined proposal lands Proposed in a tray with no group — **reviewable by nobody**. So the
   run id is a required field, and the pass REFUSES rather than landing a dead-end proposal
   (`a_pass_with_no_review_surface_is_refused`, `a_mined_proposal_is_reviewable_in_its_run_group`).

### D4 · Inlet is ED-03's judgment ledger, not a raw Δ-receipt scan
The blueprint says "amendment Δ receipts since last pass". ED-01's Δ prefix and ED-03's evidence
prefix are private to SIBLING modules with no enumerator, and widening either is out of packet.
`amendment_judgments()` is the public stack seam 1759 landed for exactly this (ED-B layer 2 of 2), and
it carries the receipt id, the scope and `at`. Canon §4 also says the ≥K route goes "through
attribution". **Declared consequence:** an amendment whose routing facts never settled a cause
(ED-03 abstains, no judgment) contributes nothing — test `an_unjudged_amendment_contributes_nothing`.

### D5 · The watermark is a WORK GATE, not a counting boundary
Clusters are recomputed over the FULL judgment ledger every pass (doc-13 r1, "never a counter in a
struct"). Clustering only the post-watermark slice would reset the count each pass, so a habit spread
over three sittings could never reach K — test `recurrence_accumulates_across_passes`. The watermark
therefore answers one question: did anything NEWER arrive? Strict `>`, with the residual documented
in code: a judgment stamped in the same second as the previous pass's newest is folded in by the next
pass that has anything newer, so second-granularity delays a proposal and can never drop one.

### D6 · The changed run widens to whole TOKENS
§4 and the blueprint both say "token pairs". Raw affix trimming cuts inside words: `regards` →
`cheers` shares a trailing `s`, so the raw pair is `regard` → `cheer`, which is in no lexicon and
would misroute every sign-off swap to the content arm. `token_aligned` widens both ends to whitespace
in lockstep (the affixes guarantee they move together). Emptiness is judged BEFORE widening, so
`hello` → `hello there` stays a pure insertion rather than becoming a fake substitution.
Tests: `the_changed_run_widens_to_whole_tokens`, `a_pure_insertion_or_deletion_is_not_a_substitution`.

### D7 · Reconstructed-lane line pairing is local
`myers::myers_line_diff` returns COUNTS only — it never names the lines it paired — and widening
1758's API for one consumer is out of packet. `line_substitutions` therefore does its own trim, with
a deliberately narrow rule: after common leading/trailing lines are trimmed the two middles must have
the SAME length, else nothing is paired. Pairing across a length change would cluster unrelated lines,
and a wrong cluster is worse than a missing one because it can reach K.

### D8 · No `session_tag` on the mined claim
Attempted (review bundling), and the inbox ACCEPT door refused it:
`InvalidClaimBody("sess requires an envelope-bound producer actor")` — `batch.rs:3284`. A
`sess`-carrying body may only be written by the envelope actor that PRODUCED the session, and accept
re-puts the reviewed body raw, so the tag would make the mined claim impossible to accept. The run
group already bundles the pass's proposals. Asserted in
`a_lexical_cluster_lands_a_proposed_scope_tagged_preference_claim`.

### D9 · `preference.phrasing` const lives in `miner.rs`
`claim.rs` is out of packet, and a `core.*` registry entry would bump `CLAIM_PREDICATE_REGISTRY`'s
`[&str; 4]` arity (CLAIMS.md: coordinated with MS 1746 + SKILLS). `preference.*` is already a
recognized public family — `serialize.rs:927` treats it as manifest-critical — and the registry is a
documented well-known list, not a write allowlist. Precedent for an out-of-`claim.rs` predicate const:
`identity_topology::PREDICATE_ENTITY_DISTINCT_FROM`.

### D10 · Hysteresis reads the ledger, not `ClaimBody.approval`
The first implementation read `approval == Rejected` and would have been DEAD CODE: the inbox reject
door closes the tray row and appends a `rejected` gate decision, leaving the body Proposed
(`store.rs::close_pending_gate_consent_in_txn`). `preference_is_stale` therefore assembles the answer
from the three places it lives — claim present, pending gate consent, newest `rejected` gate decision
— and the cooldown clock is the closing decision's `created_at`. Asserted in
`a_rejected_proposal_is_silent_inside_its_cooldown_and_speaks_after_it` (which also asserts the body
stays Proposed, so the trap cannot silently return).

### D11 · Crash-replay fixture asserts the observable invariant
The harness has no transaction-abort seam, so the test does not kill mid-txn. It asserts what the
single `with_write_txn` buys, across three passes each seeing genuinely new evidence: exactly one live
proposal, and a mark that names it — `a_replayed_pass_emits_once_and_leaves_no_half_state`.

### D12 · The chooser's rationale is receipted on the artifact, not a receipt kind
The miner mints no receipt kind (a new receipt projector is out of packet). The pinned rationale rides
the claim VALUE map and the proposal ROW, which is the durable record a reader quotes.

## Known holes (bank for the deviation board / postmortem)

* **H1 — `field_diff` amendments are unminable.** The inbox approve-with-edit door (ONE-1757, the
  main amendment door today) measures its Δ on the FIELD-DIFF lane, whose refs are blake3 of two
  MessagePack BODIES — and those bodies are not retained. So such a Δ resolves to no text pair and
  the miner is silent on it by construction (documented at `amendment_source`). Mining claim-body
  amendments needs a retention decision inside 1757's module (an ED-00-style proposed/approved pair
  row). Banked, not built — out of packet.
* **H2 — no production ENQUEUE of the miner attempt.** The executor arm is the registration the
  blueprint asked for; the SessionEnd enqueue site is `session_lifecycle.rs`, which CLAIMS.md keeps
  out of this lane ("one additive registration hook" in dreamer files). The payload shape is owned by
  `miner.rs` and round-trip tested; a host or a later lane enqueues
  `DREAMER_SUBSTITUTION_MINE_ATTEMPT_TYPE` with `miner_attempt_input(&run)`.
* **H3 — no production writer of `FinalizedProposalText`.** ED-00 landed the substrate; nothing opens
  a `ProposalTextArtifact` in production yet. The same greenfield state ED-09's reservoir inherits —
  noted, not a 1760 gap.
* **H4 — `preference.phrasing` is not in `CLAIM_PREDICATE_REGISTRY`** (see D9; arity coordination).
* **H5 — two unmeasured dials.** `MAX_SUBSTITUTION_TOKENS = 8` and the 74-entry `TONE_LEXICON` are
  pinned on judgment, not on a corpus (there is none yet). Both fail SAFE: an over-long run or an
  unlisted word routes to the content arm, where a human reads the proposal, never to a preference
  claim that silently shapes later drafts.

## Done-means

- [x] K=3 identical substitutions across 3 receipts in one scope → exactly one emission; 2 receipts →
      `BelowThreshold`; K read from settings (`miner_k` / `set_miner_k`, zero refused)
- [x] Lexical → preference claim (Proposed, gated, scope-tagged in `edit_cost_scope`'s shape);
      content → skill-edit proposal (gated, `content_hash` + `version` asserted untouched); chooser
      rationale receipted on both
- [x] Cross-scope isolation: same pair in two scopes = two clusters, independent counts
- [x] Dedup on re-run; post-rejection cooldown honoured (through the real inbox door); replay fixture
      per D11
- [x] Runs as a consolidation-scope job on the landed SessionEnd wake inlet; zero writes outside the
      gate (the skill-edit row is a proposal, never an application)
- [x] fmt · clippy `-D warnings` · `cargo test -p oneiron --all-features`

## SIMPLIFY (K3, tip after impl leg)

One deletion, no additions: `StoredMintMark` shed its `scope` / `from` / `to` / `at` fields. They
were written on every emission and read by NO consumer — the dedup/hysteresis path reads `kind` +
`reference` only (miner.rs `cluster_is_eligible`; tests assert the same two), and the cluster content
the fields duplicated is already durably stored in the claim body (`from`/`to`/`class`/`rationale`) or
the skill-edit row (`scope`/`from`/`to`/`evidence_receipts`). Stored redundancy = speculative
generality; the mark is now what the law needs it to be: a dedup POINTER. Constructor dropped the
`cluster` param; both call sites shortened. Same-txn watermark/mint-mark atomicity, hysteresis,
public API, tests: untouched.

Gates re-run: `cargo fmt -p oneiron --check` clean · `cargo clippy -p oneiron --all-features
--all-targets` clean · `cargo nextest run -p oneiron --all-features edit_distance::miner` 28/28 ·
full `cargo nextest run -p oneiron --all-features` green.

## VERDICT-FIX (Opus, tip after simplify)

Five verdict-verified findings, each fixed at its chokepoint and mutation-verified (the named test
goes RED when the fix alone is reverted, GREEN with it).

### P1 · `session-end-miner-attempt-never-enqueued`

The executor arm was a dispatcher with nothing to dispatch: no production caller ever created a
`dreamer.edit_distance.substitution_mine` attempt, so the pass ran only when a human called
`run_substitution_miner`. Fixed at the inlet, not the arm — new
`dreamer_consolidation::register_substitution_mine_in_txn` enqueues the attempt on the Meso
consolidation queue INSIDE `end_session_with_wake`'s close transaction, dedupe-keyed on the sitting,
beside the ONE-1739 distill registration and for the same reason ((f) in that door's contract).

Two shape consequences fell out of the inlet, and both are corrections rather than costs:

* **The payload shrank to the sitting.** `miner_attempt_input` took a whole `MinerRun` — a write
  actor and a run id the session-close transaction has no business knowing. The executor now supplies
  the actor from `ConsolidationExecutor::actor` (the deployment's claim-authoring policy, exactly
  where the milestone-envelope rule puts it) and the group key from the attempt's own `run_id`.
  `miner_run_from_input` → `miner_session_from_input`; `MinerRun` itself is unchanged.
* **A per-sitting fallback group key** (`miner_run_id`): the session-end enqueue carries no run id,
  the same way the partition attempts it sits beside do not, and a Proposed claim with no inbox group
  is a claim nobody can answer.

Test: `ending_a_session_registers_the_miner_pass_on_the_meso_queue`.

### P1 · `partial-pass-watermark-permanently-skips-clusters`

Both emit paths committed the PASS-WIDE watermark inside their per-cluster transaction, so the first
cluster's commit spoke for clusters the pass had not reached. A pass dying between two eligible
clusters stranded the second one behind a bound it never earned. The watermark now advances ONCE,
after the loop; the mint-marks (which are per-cluster and already in the emission transaction) are
what make the replay emit once. Blueprint's "same txn" guarantee is intact where it lives — the
dedup half — and is now stronger, not weaker.

Test: `a_pass_that_dies_between_clusters_leaves_the_unreached_one_minable` (two eligible clusters,
the second one's skill deleted between the corrections and the pass).

### P2 · `mint-mark-dedup-check-outside-write-transaction`

`cluster_is_eligible` opened its own read transaction before either emission opened its write one, so
two callers could both read "eligible" and both commit. It now takes the caller's transaction and is
called INSIDE the emission's write transaction (as are `preference_is_stale`, the new
`skill_edit_is_stale`, and the skill-existence check `emit_skill_edit` used to do outside). Both emit
functions return `Option<EntityId>` and decline in-transaction.

Test: `the_dedup_check_sees_the_mark_written_in_its_own_transaction`.

### P2 · `second-granularity-watermark-strands-new-evidence`

Judgment stamps are second-granular, and a strict `at > watermark` gate could not see a receipt
landing in the boundary second — the comment's "can never drop one" was wrong in the terminal case
where no later judgment ever arrives. The watermark is now `MinerWatermark { at, boundary }`, where
`boundary` counts the judgments stamped exactly `at`; work exists iff the stamp advanced OR the
boundary second gained a member. Exact in both directions, and the short-circuit survives (a `>=`
gate would have made the watermark dead weight). `miner_watermark` returns the struct; the
`watermark == 0` special case is gone, since an empty gate is `(0, 0)` and any judgment beats it.

Test: `a_receipt_landing_in_the_boundary_second_is_still_new_evidence`.

### P2 · `skill-edit-hysteresis-seam` (item 2's surviving half)

Banked per the verdict: no gate envelope on the proposal row — ONE-1737's ratified "minting is not
applying" posture, and this lane defines the seam ONE-1448 consumes. What was real is that
eligibility-by-row-existence cannot express a cooldown: retaining a rejected row silences the cluster
forever, deleting it re-opens instantly, and neither is the ratified dial-not-wall. The proposal row
now carries a `decision: Option<MinedSkillEditDecision>` and `resolve_mined_skill_edit` is the door
ONE-1448 answers through, so `skill_edit_is_stale` is the same three-way question
`preference_is_stale` already answers — open / landed / rejected-and-cooling. Symmetry, not new
machinery: `pending_substitution_skill_edits` now means "unanswered", and an answered proposal stays
readable by id, which is where the cooldown reads it.

Test: `a_rejected_skill_edit_is_silent_inside_its_cooldown_and_speaks_after_it`.

### PACKET_AMEND (3 files, additive, no collision)

* `crates/oneiron/src/session_lifecycle.rs` — the fix's chokepoint IS the close transaction; one
  import word, one call, one doc bullet. Nothing else in the door moves.
* `crates/oneiron/src/session_lifecycle/tests.rs` — `meso_attempt_count` counted queue KIND, which no
  longer names a partition round on its own; split into `meso_attempt_payloads` /
  `meso_partition_payloads` so the three assertions keep meaning what they said.
* `crates/oneiron/src/actor_claims/tests.rs` — `stamped_pack_receipt` used the untyped
  `AttemptQueue::claim`, and a fresh row's ready key is `(0, attempt_id)`, so it took the oldest row
  in the vault rather than its own once a fixture's session close registered one. Claims BY KIND now,
  like every production worker. Pre-existing fragility, surfaced not caused.

`Cargo.toml` / `Cargo.lock` / `settings.rs`: untouched.

Gates: `cargo fmt -p oneiron` · `cargo clippy -p oneiron --all-features --all-targets -- -D warnings`
clean · `cargo test -p oneiron --all-features` green (3882 lib + every integration target), miner
suite 33/33.
