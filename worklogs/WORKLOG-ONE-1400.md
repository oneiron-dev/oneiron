# WORKLOG — ONE-1400 [RET-02] Hybrid clustering-as-tool contract

lane: RETRIEVAL-API · seat: standard · branch: `ONE-1400` · base: `main` (flat, no stack parent)
blueprint: `/Users/olety/.claude-wave5/blueprints/RETRIEVAL-API/ONE-1400.md`
claims: `/Users/olety/.claude-wave5/blueprints/RETRIEVAL-API/CLAIMS.md`

## What landed

A pure, deterministic clustering module plus a read-only Dreamer adapter. The tool
takes already-decoded claim descriptors + embeddings and returns cohort assignments.
It holds no vault handle, opens no write txn, calls no gate, and emits no merge/split/
topology op. The Dreamer keeps every merge/split/accumulate/escalate decision.

### Files

| File | Change |
|---|---|
| `crates/oneiron/src/cluster.rs` | CREATE — two-stage algorithm + public contract |
| `crates/oneiron/src/cluster/tests.rs` | CREATE — 18 tests: determinism, authority boundary, frozen `v1_parity` |
| `crates/oneiron/src/dreamer_runner.rs` | +17 — one additive `propose_claim_cohorts` adapter |
| `crates/oneiron/src/dreamer_runner/tests.rs` | +160 — `propose_claim_cohorts_returns_assignments`, `dreamer_decides_not_tool` |
| `crates/oneiron/src/lib.rs` | +5 — `pub mod cluster` + re-exports |

`git diff --name-only` ⊆ packet. No stray files. `Cargo.lock` untouched.

### Algorithm (blueprint contract, unchanged)

- **Stage 1** — exact partition on the canonical Dreamer bucket
  `(subject, predicate_root(predicate), world, facet)`. `facet` is caller-resolved;
  `None` is valid and is its own bucket.
- **Stage 2** — complete-link cosine grouping inside each partition at the pinned
  `CLUSTER_COHESION_THRESHOLD = 0.82`. Inputs sort by claim-id bytes first; a
  candidate joins a cohort only when its cosine to **every** existing member clears
  the floor. Single-link/connected-components stays rejected (chaining).
- **Determinism** — id-sort before grouping ⇒ permutation-invariant output.
  `CohortId` = domain-separated BLAKE3 (`CLUSTER_ID_DOMAIN`) over the partition key
  plus ascending member ids, with length prefixes and presence tags so no two
  distinct cohorts share a preimage.
- Cosine math is `crate::distance::cosine_similarity` — not forked.

### Rejections (typed, before any grouping)

`validate_cluster_input` runs first, so a bad input can never yield partial output:
threshold outside `[-1, 1]` or NaN → `InvalidConfig`; empty embedding → `InvalidConfig`;
mixed dimensions → `DimensionMismatch`; NaN/±inf component → `InvalidVector`.

## Deviations from the blueprint

One, mechanical:

- **`complete_link_cohesion` returns `f32`, not `Result<f32>`.** The blueprint sketched
  `-> Result<f32>`, but every caller path is already past `validate_cluster_input`, so
  the function is infallible by construction and the always-`Ok` wrapper trips the
  workspace `clippy::unnecessary_wraps = "deny"` lint. Signature narrowed, rationale
  recorded in a doc comment at the fn. Private fn — no public-API impact.

`validate_cluster_input` and `cohort_id` match their blueprint signatures exactly.

## Done-means → evidence

1. claims+embeddings in, deterministic assignments out, no write/decision authority — `claims_in_clusters_out_no_decision`, `dreamer_decides_not_tool`
2. stage-1 exact partition; stage-2 complete-link at 0.82 — `identical_embeddings_never_cross_a_partition_boundary`, `predicate_leaf_is_dropped_so_siblings_share_a_partition`, `complete_link_refuses_the_chain_single_link_would_build`, `default_threshold_is_the_pinned_v1_contract`
3. adapter is pure; no enqueue/write/topology call — `dreamer_decides_not_tool` (before/after snapshot of `data.mdb` length + `entities`/`vault_meta`/`attempt_records`/`attempt_ready`/`attempt_dedupe`/`type_index`/`edges_out` rows, over a **populated** vault, across 3 success calls and 1 failing call)
4. matches the frozen parity fixture incl. stable ids across permutations — `v1_parity`, `cohort_ids_and_ordering_survive_input_permutation`, `cohort_id_separates_partitions_that_share_members`
5. structure is assignments + diagnostics only — `claims_in_clusters_out_no_decision` destructures every public output field, so adding an op/verb/suggestion field breaks it at **compile** time
6. no clustering call changes vault bytes/attempts/claims/topology — `dreamer_decides_not_tool`
7. `v1_parity` covers exact partitioning, complete-link grouping, singletons, deterministic tie-breaking
8. typed errors, no panics, no partial output — `mixed_dimensions_fail_with_dimension_mismatch`, `non_finite_components_fail_with_invalid_vector`, `an_empty_embedding_is_rejected`, `out_of_range_thresholds_are_rejected`, `validation_precedes_grouping_so_no_partial_output_escapes`
9. `cargo test -p oneiron cluster` / `dreamer_runner` — green
10. `cargo clippy -p oneiron --all-targets --all-features -- -D warnings` — clean

Per done-means #4 and the CLAIMS read-only note, `v1_parity` asserts cohort **membership
and ordering**, never exact-bit cosine values: `cosine_similarity` SIMD-dispatches per
target arch (AVX2 / NEON / scalar). The fixture is self-contained — local vectors, local
expectations, no external legacy code, runtime data, or shared fixture file.

## Fixture-hygiene notes

- All generic test ids route through the band-asserting `test_util::entity(seed)`; seeds
  used are `0x01`–`0x06`, `0x70`, `0x71`, `0x80`, `0x90` — none in `PINNED_ID_BYTES`.
- `complete_link_refuses_the_chain_single_link_would_build` and
  `reported_cohesion_is_the_worst_pair_in_the_cohort` assert their intended geometry
  against the threshold up front, so a later edit to the `axis` helper cannot silently
  turn them into different tests.
- `v1_parity` shuffles its input before clustering: the frozen expectation is
  order-independent by construction.

## Claim/seam compliance

- **`S-AUTH4` carve-out (CLAIMS §w4-1604):** honored. The `dreamer_runner.rs` diff is a
  single additive read-only method appended after the read/advisory helpers
  (`latest_durable_milestone`, `progress_snapshot`). It touches no actor-binding,
  write-envelope, authority, or admission code. Diff is +17 lines, all inside that zone
  — no hard wait needed.
- **In-lane sequencing:** this lands before ONE-218, which adds the durable
  `signal_extraction` enqueue path to the same file. Adapter is additive, so 218 rebases
  cleanly.
- **FLAT ticket / claims law:** no `pipeline.rs`, `fusion.rs`, or `context_pack.rs` edit —
  confirmed by `git diff --name-only`. No read-path or claim-write edit of any kind.
- New module `cluster` is RETRIEVAL-API-exclusive for wave-5 per CLAIMS §Owned zones.

## Gates

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy -p oneiron --all-targets --all-features -- -D warnings` | clean |
| `cargo test -p oneiron --all-features --lib cluster` | 19 passed, 0 failed |
| `cargo test -p oneiron --all-features --lib dreamer_runner` | 39 passed, 0 failed |
| `cargo test -p oneiron --all-features --lib` (full regression) | see commit trailer |

`--all-features` used throughout per the wave recipe-defect rule.

## SIMPLIFY pass (K3, on bf36a07)

Deletion-biased polish only; no restructuring, no public-API change, no test-assertion
edits beyond the blueprint pins.

- Tightened the `ClusterPartitionKey::predicate_root` doc with an explicit
  `PARTITION:` marker — the impl-flagged think-to-watch-for
  ("predicate_root drops the leaf") is now pinned at the exact seam where
  blueprint text consumers read it: `person.name.given` and
  `person.name.family` share the `person.name` bucket.
- Tightened the `ClusterClaim::predicate` doc to note the leaf is dropped.
- Hardened the frozen `v1_parity` fixture: four up-front
  `predicate_root("person.name.given") == "person.name"`-style assertions
  (blueprint pinned-derivation, not new assertions) so a future predicate
  vocabulary change fails loudly one line above the fixture it invalidates,
  instead of as five cryptic cohort mismatches. Mirrors the geometry-pin
  pattern already used by `complete_link_refuses_the_chain_single_link_would_build`.

Nothing else material survived the deletion-bias check — the impl was already
tight (no dead code, no duplication, no stale comments, fmt clean at entry).

Gates after pass: `cargo fmt --all -- --check` clean · `cargo clippy -p oneiron
--all-targets --all-features -- -D warnings` clean · `cargo test -p oneiron
--all-features --lib` 3169 passed, 0 failed.

Diffstat: **+14 / -4** across `cluster.rs` (+8/-2) and `cluster/tests.rs` (+10/-2).

---

## FIX round 1 — dup-`claim_id` chokepoint (K3 round-1 verdict on dab4446)

ONE verdict-pinned item: **P2, class=determinism, chokepoint-not-call-site**,
`crates/oneiron/src/cluster.rs:205` (`validate_cluster_input`). Every verdict
fact re-derived before editing rather than trusted:

- `sort_by_key(claim_id)` at `cluster.rs:157` is `slice::sort_by_key` =
  **stable** → tied ids keep caller order. Confirmed.
- The traced triple is **geometrically realizable**: for cos(A1,B)=0.955 and
  cos(A1,A2)=0.622 the planar range for cos(A2,B) is [0.6203, 0.9555], and the
  realized value is **0.8263 — above the 0.82 floor by 0.0063**, while
  cos(A1,A2)=0.622 is **below** it by 0.198. So B clears the floor against BOTH
  tied claims but the tied claims do not clear it against each other: cohort
  membership and reported cohesion (0.955 vs 0.826) genuinely hinged on input
  order, breaking the permutation-invariance contract documented at
  `cluster.rs:142` and in the module doc.
  (Note: the verdict's stated sufficiency test `0.622 >= 2*0.82^2-1 = 0.3448`
  is a weaker bound than the true planar range, but the conclusion holds.)
- Two orthogonal same-id entries in one partition → two singleton cohorts both
  with `member_ids = [A]` → **one `CohortId` for two distinct cohorts**, since
  the preimage at `cluster.rs:255` is partition + ascending member ids.
  The "no two distinct cohorts share a preimage" doc claim was therefore false
  exactly on the duplicate-id input.
- `validate_cluster_input` had **no** uniqueness check, at a `pub` re-exported
  boundary (`lib.rs` exports `cluster`; `DreamerRunnerStore::propose_claim_cohorts`
  is a second public door onto the same function).

**Fix (a) — chokepoint, not call sites.** `validate_cluster_input` now rejects
duplicate `claim_id`s inside its existing per-claim loop via a `BTreeSet`, with
`Error::InvalidConfig` naming the duplicated id (`to_hex`). Error-taxonomy check
per the blueprint: **no new variant minted.** `Error::DuplicateKey` /
`WorldDuplicateKey` are sync-selector-scoped (`error.rs:401,405`) and would be
dishonest here; `InvalidConfig(String)` is already this same function's variant
for input-shape rejection (empty embedding, out-of-range threshold), so the
closest existing typed variant honestly carries it. The check is global over the
input, not per-partition, because the sort that needs uniqueness runs *before*
partitioning.

**Fix (b) — two regression tests** in `cluster/tests.rs`:
- `duplicate_claim_ids_are_rejected_and_the_error_names_the_id` — asserts the
  typed error surfaces AND that the message contains the duplicated id's hex;
  second half pins that duplicates are caught **across** partition boundaries.
- `the_permissive_duplicate_shape_that_broke_permutation_invariance_is_gone` —
  the traced counterexample kept as a pin. Asserts the geometry itself
  (B clears the floor vs both tied claims; the tied claims do not clear it vs
  each other) so a future edit cannot silently neuter the test, then asserts
  **both** orderings of the shape are now rejected identically — which is what
  restores the invariance contract.
- No existing test assertion or fixture was touched (fixture-sync law): a scan
  confirmed no pre-existing test passes duplicate seeds, so nothing else moved.

**Fix (c) — docs.** The `# Errors` list on `cluster_claims` presented validation
as complete; it now lists the duplicate-id rejection under `InvalidConfig`. The
module-level Determinism paragraph now states uniqueness as the precondition it
is, explaining *why* (stable sort + tied ids ⇒ order-dependent output).

**Gates (d)** — all green on the **first** run, no rerun consumed, no flake hit:
- `cargo fmt --all --check` → clean (exit 0)
- `cargo clippy -p oneiron --all-targets --all-features -- -D warnings` → clean (exit 0)
- `cargo test -p oneiron --all-features --lib` → **3171 passed, 0 failed**, 24
  ignored (3169 baseline + the 2 new tests). Cluster suite: 19/19.

Diffstat: **+100 / -6** across `cluster.rs` (+29/-6... net +23) and
`cluster/tests.rs` (+77). Packet-clean: `git diff --name-only` = exactly
`crates/oneiron/src/cluster.rs` + `crates/oneiron/src/cluster/tests.rs`, both
lane-claimed. No other edits.
