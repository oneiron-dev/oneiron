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
