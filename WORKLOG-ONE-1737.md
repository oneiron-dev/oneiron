# WORKLOG — ONE-1737 · SK-04 pack-manifest receipt fields + attribution projector

Lane SKILLS · layer 1 of 3 (1737 → 1738 → 1739). Branch `ONE-1737`, base `main`.

## Ratified shape (blueprint `/Users/olety/.claude-wave5/blueprints/SKILLS/ONE-1737.md`)

1. Attempt-alive pack manifest: additive `#[serde(default)] manifest: Vec<ManifestEntry>` on
   `AttemptRecord` + `append_manifest_entry` door + accessor. `AttemptEvent` /
   `AttemptInterventionKind` untouched. NOT the events drain: the cap REFUSES, never drops.
2. Attribution projector: new `crates/oneiron/src/skill_attribution.rs`
   (ARCH-0035 projector posture, `comm.rs::run_comm_projector` house shape).
3. Defect-injection audit (Blind Curator guard): held-out ground-truth fixtures,
   receipted pass-rate, harness generic over the judge.

**Stack law (dispatch brief):** this layer PERSISTS routed verdict records only.
Claim-write calls are deliberately absent — 1738 (skill.reliability) and 1739
(actor.*) open the write doors. `claim.rs` is NOT in 1737's packet.

## Commits

1. `954b676` — **attempt-alive pack manifest**: append-only `AttemptRecord.manifest` field +
   `append_manifest_entry` door + accessor + two additive receipt field keys.
   `attempt_queue.rs` · `attempt_queue/tests.rs` · `receipt.rs` · `receipt/tests.rs` ·
   `run_tree/tests.rs` (literal) · `lib.rs` · `skills_epic_oracle.rs` (arms the manifest oracle).
2. `3bbc931` — **attribution projector**: new `skill_attribution.rs` + tests (13) — verdict
   taxonomy, evidence door, cursor-idempotent projector pass, defect-injection audit.
   `lib.rs` · `skills_epic_oracle.rs` (arms discovery, re-points routing to 1739).

Each commit's tree was gated independently (fmt · clippy `-D warnings` · full nextest).

## Rebase check vs real upstream main (`f478ea92`, post-#575)

Base here is `e9d9e9a`; the lane's `origin` is a file-remote whose `main` lags. Fetched the
real ref and ran `git merge-tree --write-tree` against my HEAD: **exit 0, no conflicts.**

- `receipt.rs` — MS-05 (ONE-1747, `#569`) landed its `proposal_ref`/`op_kind`/`target_class`
  block; my two keys (`manifest.skills`, `manifest.actor_claims`) are disjoint. The blueprint's
  receipt.rs ordering pin (1747 → 1737) is satisfied. Zero duplicate consts/fns in the merged file.
- `lib.rs` — upstream added `pub mod calendar` + `pub mod consent`; mine adds
  `pub mod skill_attribution` at a different alphabetical slot. Merged file has all three, no
  duplicate mod decls, no duplicate export blocks introduced. (The four `pub use` names that
  appear twice — `dreamer_runner`, `dreamer_wake`, `embed`, `error` — are split export blocks
  present identically on BOTH sides at HEAD; pre-existing, not a merge artifact.)
- `claim.rs` — **not in this lane's packet.** CAL's `calendar.*` family landed there; 1737 writes
  no claims and reserves no predicates, so there is nothing to re-validate. The `actor.*`
  reservation is ONE-1739's, and it will need to coordinate with CAL's rows under the
  alphabetical law.
- `attempt_queue.rs` · `attempt_queue/tests.rs` · `run_tree/tests.rs` · `skills_epic_oracle.rs` —
  untouched by the five Phase-B lanes.

No wholesale pull from main; all edits additive on my own files.

## Oracle arming

- `sk04_attempt_manifest_grows_mid_run_and_stays_append_only` — ARMED.
- `sk04_discovery_outcome_mints_edit_proposal_not_claim` — ARMED (discovery is
  deliberately not a claim, so 1737 satisfies it end to end).
- `sk04_attribution_routes_defect_to_skill_and_lapse_to_actor` — **NOT armable in
  1737**: its count-asserts require `actor.failure_mode` / skill claim ROWS, and the
  claim-write doors + the `actor.*` predicate reservation belong to ONE-1739
  (CLAIMS.md: `claim.rs` → 1739). Arming it here would need claim writes the stack
  shape forbids, and the arming law forbids weakening the counts. Re-pointed to
  ONE-1739 with the 1737 half recorded. The 1737-scoped half of that contract
  (verdict ROUTING: defect→skill subject, lapse→actor subject, zero claims written)
  is covered live by `skill_attribution` unit tests. **Deviation-board item.**

## Gates

`cargo fmt --check` · `cargo clippy -p oneiron --all-features --all-targets -- -D warnings` ·
`cargo nextest run -p oneiron --all-features` — green per commit.

Final tree: **3442 tests run, 3442 passed, 98 skipped.** Suite grew by 26 (13 attribution,
8 attempt-queue manifest, 6 receipt manifest, minus the 1 sk04 oracle that moved from
`skipped` to `run`, twice).

## Done-means

- [x] `sk04_attempt_manifest_grows_mid_run_and_stays_append_only` armed + green.
- [ ] `sk04_attribution_routes_defect_to_skill_and_lapse_to_actor` — **re-pointed to ONE-1739**
      (see above); 1737's routing half green under `skill_attribution::tests`.
- [x] `sk04_discovery_outcome_mints_edit_proposal_not_claim` armed + green.
- [x] Audit: a broken judge moves the receipted pass-rate (`a_broken_judge_moves_the_receipted_pass_rate`);
      an all-abstain judge scores zero, not one.
- [x] Receipt plumbing extended not forked: no new receipt kind, no new store; ES oracle green.
- [x] Gates green.

## K3 simplify pass (commit `972bafd`, `SIMPLIFY: ONE-1737`)

Deletion-biased polish over the two impl commits; no restructuring, no API change,
no assertion/fixture edits. Full-tree read of `skill_attribution.rs` (892 lines),
both impl diffs on `attempt_queue.rs`/`receipt.rs`, `skill_attribution/tests.rs`,
and the oracle diff. Findings: the impl was already house-shaped — every candidate
deletion was deliberate (audit-sequence reuse on `next_evidence_sequence_in_txn`,
blanket validate-on-decode posture via `validate_attempt_manifest`, defensive
`(sequence, at)` audit key, `let _ = context` mirroring `expect_map`'s idle-param,
receipt.rs module-level doors matching the `eiri_memory_board_state_ref` precedent).
**One polish landed:** `decode_u64`'s explicit `let _ = context;` suppression folded
into an idiomatic `_context` parameter rename (+1 / −2 lines). Gates after the edit:
`cargo fmt --check` ✓ · `cargo clippy -p oneiron --all-targets --all-features --
-D warnings` ✓ · `cargo test -p oneiron --all-features --lib` → **3177 passed, 0
failed, 24 ignored** ✓. Porcelain clean apart from pre-existing `WORKLOG-LANE-BOOT.md`.

## Round-2 fix leg (5 findings, 5 bounded commits on top of `c288a9f`)

Sol-max re-fire returned F1–F5; the K3 re-verdict revised CY-CLOSED →
FIX-REQUIRED (3 real P1 + 1 real P2 + 1 doc-only P2). One commit per finding,
each carrying only that finding's work. Gates green per commit
(`cargo fmt --check` · `cargo clippy -p oneiron --all-targets --all-features --
-D warnings` · `cargo test -p oneiron --all-features --lib`).

| # | Commit | Finding |
|---|---|---|
| F1 | `ebc3079` | dead/missing production wiring at the attempts layer |
| F2 | `9a38440` | unbound attribution evidence (`skill_attribution.rs:592`) |
| F3 | `7d87d2c` | missing edit proposal (`skill_attribution.rs:435`) |
| F4 | `b730199` | receipt-spine wording (P2, by-design — doc line only) |
| F5 | `a8292b5` | ineffective defect-injection audit (`skill_attribution.rs:560`) |

### F1 — surface trace (2 candidates, one chosen)

`append_pack_manifest_fields` had no production caller: the field-set existed
and nothing ever stamped it.

- **(A) `receipt::persist_send_receipt`** — the durable connector-send
  chokepoint. REJECTED: TASK-keyed, reached only by the connector-send lane,
  holds no attempt handle (task→attempt needs an O(N) `AttemptQueue::list`
  scan), and would leave `dreamer_runner` / `task_verb` / `agent_dispatch` /
  `companion` unstamped — exactly the lanes attribution routes.
- **(B) `AttemptQueue::complete` + `AttemptQueue::fail`** — CHOSEN. The two
  doors every execute leaves through; stamping there needs zero call-site
  edits, cannot be forgotten by a later lane, and runs in the transition's own
  write txn (terminal-with-manifest-but-no-receipt is unreachable).

Row lands in `vault_meta` under `attempt_receipt:v1:` keyed by the receipt id
(`attempt:<hex>`), so a cited `receipt_ref` point-reads instead of scanning,
and projects into the RS1 family via `collect_receipt_records` — no new
receipt kind, no new store. Narrow by construction: an attempt whose pack
loaded nothing mints no row. Cancellation (operator intervention, not an
execute) deliberately does not stamp.

**Remaining seam (deviation-board item):** the pack→manifest half —
`append_manifest_entry` called by a real pack loader — cannot be wired in
1737's packet because no skill-pack assembly path exists in the crate yet
(SK-02 / ONE-1736 lands it). The chain from `append_manifest_entry` onward is
now automatic; the loader end belongs to the lane that owns pack assembly.

### F2 — evidence grounding

`validate_evidence(vault, …)` now resolves `receipt_ref` on the pack-receipt
ledger, requires the actor entity to exist, requires the skill entity to exist
and be a SKILL record when named, and — when the resolved receipt carries a
manifest — requires the skill to appear in it. A receipt predating the
field-set carries no manifest and cannot answer membership: absent fact, not
failed check, so it admits. Typed refusals reuse `Error::InvalidClaimBody`
(`error.rs` is out of packet, and the taxonomy already fits).

Consequence: fixtures can no longer hand-write receipt strings. Module tests
and the oracle now run a real attempt under a real pack to its terminal door
and cite what the close stamped.

### F3 — minted proposals

`pending_edit_proposals` was a filter over judgments, which made the oracle's
proposal count a restatement of its verdict count (structurally unable to
fail). Discovery now mints a typed `SkillEditProposal` in the projector's write
txn under `skill_attribution:edit_proposal:v1:`, keyed by the SOURCE JUDGMENT
SEQUENCE — so re-projection re-mints the same row rather than duplicating. The
oracle's count assert is untouched (arming law) and is now backed by shape
asserts: target skill, cited judgment sequence, carried-forward receipts.

### F5 — audit made unspoofable

Fixture ids were the answer key (`audit:skill_defect`, …); a string-matching
judge would have scored 100% while judging nothing. Ids are now opaque
(`audit:case:1..5`) with a mechanical guard test asserting no fixture id
contains any verdict wire string. `AuditFixture.expected` became
`Option<AttributionVerdict>`: the held-out set carries an unsettled case where
abstention is the RIGHT answer and naming a verdict is WRONG. The rule tier
still scores 5/5; `AlwaysDefect` now fails the opaque case; an all-abstain
judge earns exactly the abstention fixture (0.2), so "nothing was checked is
not everything was right" holds with a sharper edge than the old zero.

`an_abstaining_judge_does_not_score_a_perfect_pass_rate` was re-shaped (its
old assert was `pass_rate == 0`, impossible once abstention can be correct);
the contract it guards is preserved and strengthened.

### Mutation verification (every new behavioural test)

| Mutation | Test that failed |
|---|---|
| drop the stamp call from `complete()` | `completing_an_attempt_under_a_pack_stamps_its_terminal_receipt` |
| skip ledger resolution in `validate_evidence` | `fabricated_evidence_references_are_refused_at_the_door` |
| skip manifest-membership check | `fabricated_evidence_references_are_refused_at_the_door` |
| suppress proposal minting | oracle `sk04_discovery_outcome_mints_edit_proposal_not_claim` + 2 module tests |
| re-introduce `audit:skill_defect` fixture id | `audit_fixture_ids_leak_no_verdict_signal` |
| score abstention as never-correct | `labelling_judges_fail_the_opaque_unsettled_case` (+3) |

All mutations restored; final tree is the unmutated code.

### Final gates

`cargo fmt --check` ✓ · `cargo clippy -p oneiron --all-targets --all-features
-- -D warnings` ✓ · `cargo nextest run -p oneiron --all-features` →
**3453 tests run, 3453 passed, 98 skipped** (baseline 3442, +11: 4 pack-receipt
wiring, 3 evidence grounding, 2 edit-proposal, 2 audit-spoof).

Flake noted (charged to no lane): `embed::tests::partial_remote_completion_is_
logged_when_local_batch_fails` failed once under the full `--lib` run and
passed alone and on the immediate re-run — global-tracing-subscriber
contention class, untouched by this packet.

## Notes for the stack

- **1738** reads `attribution_judgments(vault)` and folds the `SkillDefect` rows into the Beta
  posterior. The judgment carries `sequence`, `subject`, `evidence_receipts` — the citation the
  superseding `skill.reliability` claim needs.
- **1739** reads the same rows, takes the `ExecutionLapse` ones, and opens the `actor.*` doors.
  Its oracle work includes finishing `sk04_attribution_routes_defect_to_skill_and_lapse_to_actor`:
  the ARM seam sits directly below live routing asserts, so only the claim writes are missing.
- **ED-03 (1759)** extends this module; `run_attribution_audit_with_judge` is already generic over
  the fixture set and the judge so the harness needs no reshaping for amendment evidence. Its
  `AuditFixture.expected` is `Option<Verdict>` after F5 — amendment fixtures get the same
  honest-abstention arm for free.
- **1738/1739 evidence door:** `record_attribution_evidence` now REFUSES ungrounded rows (F2).
  Any layer feeding it must cite a receipt the attempt's terminal actually stamped
  (`attempt_pack_receipt_id`), not a synthesized string.
- The LLM tier is a `trait AttributionJudge` seam, not a client. A host implementation stamps
  `attribution_call_purpose()` on its `llm.rs` call; the projector takes `&dyn AttributionJudge`.

## POST-MERGE SWEEP — F1 (P2, unbounded-receipt-scan)

Post-merge sweep `wf_aad7b48f-8b4` returned one confirmed REAL P2 against the
merge-in tip `3ebfb1a`. This section records its close.

### The finding

`attempt_pack_receipts` (`crates/oneiron/src/receipt.rs`) walked
`vault_meta.prefix_iter(ATTEMPT_PACK_RECEIPT_KEY_PREFIX)` with NO bound,
decoded every row, and collected the lot into a `Vec`. Every sibling collector
in `collect_receipt_records` is already capped at `MAX_RECEIPT_QUERY_SCAN`
(gate paging, identity-topology, access-grant, federation, settle), so this was
the one uncapped member of the family. Two multipliers made it more than a
theoretical scan:

- **`job_ref` queries scan the family TWICE.** `receipt_family_query` re-runs
  `collect_receipt_records` under `lineage_scan_query()` to build the lineage
  index, so a lineage query re-collected the same unbounded set.
- **Pack receipt rows never drain.** The attempt EVENTS they project from are
  consumed; the receipt ledger persists for the life of the vault. Latency
  therefore degrades monotonically with total attempt history, and the backlog
  is caller-growable.

### The fix

Three parts, all inside `attempt_pack_receipts` and its two new helpers:

1. **Bounded.** The walk takes `MAX_RECEIPT_QUERY_SCAN + 1` rows and stops at
   the cap. The one row past the cap is READ but never decoded — it is exactly
   what distinguishes a ledger holding the cap from one the cap truncated.
2. **Newest-first, not oldest-first.** The key embeds the UUIDv7 attempt id, so
   lexicographic key order IS mint order; a forward cap would have permanently
   hidden every RECENT receipt behind an old backlog, on a family query whose
   contract is newest-first. `OverlayDb` has no reverse prefix iterator, so the
   walk uses `rev_range` over the prefix's half-open range —
   `attempt_pack_receipt_key_range_end()` names the exclusive bound by bumping
   the ASCII prefix's final byte. This is the same shape
   `identity_topology_receipts` already uses (`rev_range` + `.take(cap)`).
   Below the cap the returned SET is unchanged, and callers sort newest-first
   downstream regardless, so nothing else moves.
3. **Not silent.** `note_attempt_pack_scan_capped()` fires when the cap trips:
   `tracing::warn!` for operators, plus the file's existing test-observability
   idiom (a `#[cfg(test)]` thread-local counter beside
   `GATE_RECEIPT_PAGES_SCANNED`). The discarded remainder is unbounded by
   construction and is deliberately NOT counted — the fact worth reporting is
   that the answer came from a prefix, and counting the rest would undo the cap.

Support change: `overwrite_attempt_pack_receipt_for_test` was split so its
transaction-scoped half (`put_attempt_pack_receipt_for_test`) can be called
inside one write txn — a cap-sized fixture cannot afford a transaction per row.

### The test

`receipt::tests::the_pack_receipt_scan_stops_at_the_family_cap_and_signals_it`
builds `MAX_RECEIPT_QUERY_SCAN + 1` pack receipt rows — the smallest ledger
that MUST truncate — with attempt ids carrying a big-endian index in their
leading bytes, so ledger key order reproduces real mint order. It asserts the
scan returns exactly the cap, the signal fired exactly once, the NEWEST row
survived, the OLDEST row is the one discarded, and that the public
`vault.receipts()` door is bounded by the same cap and still answers
newest-first from the capped set. Runtime 1.44s (the fixture needs a 256 MiB
map; the 16 MiB default test map returns `MapFull`).

### Mutation verification

| Mutation | Assertion that failed |
|---|---|
| lift the cap floor to `MAX * 4` | `left: 100001, right: 100000` — "the scan terminates at the family work cap" |
| `rev_range` → forward `range` | "the cap keeps the newest row" |
| delete the `note_attempt_pack_scan_capped()` call | `left: 0, right: 1` — "a truncated scan raises the cap signal exactly once" |

All mutations restored; the committed tree is the unmutated code.

### Gates

`cargo fmt -p oneiron --check` ✓ · `cargo test -p oneiron --all-features --lib
receipt` → **122 passed, 0 failed**.

Full `cargo test -p oneiron --all-features` → **3359 passed, 3 failed** in
275.96s. All three failures are BASE-RED and belong to another lane — see
"Base defects" below. Zero failures in this packet.

`cargo clippy -p oneiron --all-features --all-targets -D warnings` reports
**zero** hits in `src/receipt*`.

### Base defects found while gating (NOT this packet — charge elsewhere)

**B1 — `origin/main` regression: the calendar claim validator has no call
site.** `validate_calendar_claim_structure` is defined at
`crates/oneiron/src/calendar/claims.rs:563`, and its own module doc at line 10
says it is "wired into" the write door. It is not: `git grep` finds ZERO call
sites anywhere in `crates/`, so the compiler also emits a `dead_code` warning
for it. Three tests consequently get `Ok(())` where they assert
`Err(Error::InvalidClaimBody(..))`:

- `calendar::claims::tests::calendar_claim_validator_rejects_malformed_shapes`
- `calendar::claims::tests::calendar_claims_require_event_subjects`
- `claim::tests::write_door_validates_calendar_claim_structure`

Attribution is airtight: both failing files last changed in `8fb98e6`
(ONE-1782 [CAL], the redo of sandbagged #561, PR #573), the call site is
absent at HEAD~1 `3ebfb1a` AND on `origin/main` (only 2 hits there, both
inside the defining file), and this packet touches neither file. Reads as a
sandbag-redo defect — the redo landed the validator but dropped its wire, so
calendar claim structure validation is currently DEAD on main.

**B2 — pre-existing clippy errors, another lane's file.** Present verbatim at
HEAD `3ebfb1a`:

- `crates/oneiron/src/secret_custody/tests.rs:156` — `field_reassign_with_default`
- `crates/oneiron/src/secret_custody/tests.rs:256` — `items_after_statements`

Both left untouched (out of packet); flagged for the orchestrator to charge.

### PACKET_AMEND — `crates/oneiron/src/lib.rs`

`cargo fmt -p oneiron` re-wrapped a 4-line `pub use crate::receipt::{...}`
export list in `lib.rs`. The un-wrapped line was introduced by this lane's own
merge-in commit `3ebfb1a` (`git log -L 752,760` attributes it there): the merge
resolution combined main's and ONE-1737's receipt exports without re-running
rustfmt, leaving the branch fmt-dirty. The hunk is pure whitespace, touches
only receipt exports, and is required for `cargo fmt --check` to pass. Kept,
and recorded here as an amendment rather than silently absorbed.
