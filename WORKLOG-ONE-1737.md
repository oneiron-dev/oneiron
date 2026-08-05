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

## Notes for the stack

- **1738** reads `attribution_judgments(vault)` and folds the `SkillDefect` rows into the Beta
  posterior. The judgment carries `sequence`, `subject`, `evidence_receipts` — the citation the
  superseding `skill.reliability` claim needs.
- **1739** reads the same rows, takes the `ExecutionLapse` ones, and opens the `actor.*` doors.
  Its oracle work includes finishing `sk04_attribution_routes_defect_to_skill_and_lapse_to_actor`:
  the ARM seam sits directly below live routing asserts, so only the claim writes are missing.
- **ED-03 (1759)** extends this module; `run_attribution_audit_with_judge` is already generic over
  the fixture set and the judge so the harness needs no reshaping for amendment evidence.
- The LLM tier is a `trait AttributionJudge` seam, not a client. A host implementation stamps
  `attribution_call_purpose()` on its `llm.rs` call; the projector takes `&dyn AttributionJudge`.
