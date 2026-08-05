# WORKLOG — ONE-1792 (SPINE-COMM lane head)

Comm projection convergence: deterministic claim IDs, cache rebuild-on-miss,
offline-twin merge through ARCH-0055/MS-01.

Worktree: `/Volumes/Cinema/w5-lt/spine-comm` · branch `ONE-1792`
Blueprint: `/Users/olety/.claude-wave5/blueprints/SPINE-COMM/ONE-1792.md`

## Scope taken

Engine only. The blueprint's §4 canon rider (the ARCH-0035 three-sentence
paragraph in `oneiron-docs`) is **orchestrator-owned** per the lane brief and is
NOT touched from this leg.

Claimed files actually edited:
- `crates/oneiron/src/comm.rs`
- `crates/oneiron/src/comm/tests.rs`

## Commits

### 1. Deterministic projected-claim identity
Source event id now flows `project_event` → `apply_projector_rule_in_txn` (as a
`ProjectedCommEvent` bundle, so the arity stays under the clippy threshold) →
`put_projected_comm_claim_in_txn`. Projected `comm.*` claim IDs derive from
`BLAKE3(domain ‖ source_event_id ‖ len(predicate) ‖ predicate ‖ len(key) ‖ key)`
with the UUIDv7 version/variant nibbles set exactly as `connector_actor_id`.
Writer split into `put_comm_claim_with_id_in_txn` (explicit id) and the
projected wrapper. Resident derived id is accepted only as a byte-identical
CLAIM with the same decoded value and a live `claim_of` subject edge; anything
else fails closed. Replay is a no-op (no rewrite, so a closed lifecycle is never
resurrected), the self-supersession edge is skipped when the active head IS the
derived id, and the retroactive-close arms skip an already-closed row.

### 2. Party index rebuild-on-miss
`PARTY_INDEX_PREFIX` demoted to a pure shortcut. One validator
(`active_comm_party_key_in_txn`) decides "active comm-owned PERSON with exactly
this `party_key`" and powers both the index check and the synced-truth scan, so
the two can't disagree. `resolve_party_in_txn` validates the hit, else scans
type-4 rows, picks the lexicographically smallest active match, repairs the
shortcut, and returns without minting. `resolve_party` keeps a read-only fast
path and escalates to the same write-transaction helper on a miss.
`resolve_or_create_party_in_txn` mints only on `None`. Malformed/unrelated
PERSON bodies are ignored; merged shells are stale despite the PERSON type.

### 3. Offline-twin reconciliation through MS-01
`run_comm_projector` tail groups active comm-owned PERSON rows by exact
`party_key`; groups of ≥2 go through the existing door —
`IdentityTopologyOp::Merge` + `SurvivorshipPlan::ReadThrough` +
`IdentityOpWrite::auto(ClaimSource::Inferred)` — with the sorted twin ids as
evidence refs and the stable token `comm.party_key_offline_twin` as rationale.
Lowest id survives; the cache is repointed at the survivor in a short write
transaction after the door applies. No claim subject is rewritten and no
`merged_into` edge is authored here. Different `party_key` values are never
merged.

### 4. Test strengthening
The cross-vault convergence test originally compared claim COUNTS, which would
have passed against random ids. It now plants the same party row at an explicit
id in two fresh vaults, projects one source event per slot, and asserts id
equality across vaults and distinctness within one.

## Gates

| Gate | Result |
|---|---|
| `cargo fmt --all --check` | clean |
| `cargo clippy --workspace --all-targets --all-features -D warnings` | clean (one pre-existing `sha1` deprecation warning in `oneiron-seal`, untouched by this diff) |
| `cargo test -p oneiron --all-features` (lib + all integration suites) | 3164 lib + all integration suites pass |
| comm module | 45 tests, 0 failures (31 pre-existing + 14 new) |

**Mutation-checked** — each feature area was reverted in turn and the suite
re-run, confirming the new tests actually bite:
- disable the reconciler → 4 twin tests fail
- cache-miss-as-absence → 4 rebuild tests fail
- `EntityId::now()` for projected claims → 4 determinism tests fail

### Pre-existing flake (NOT from this lane)
Parallel full-suite runs intermittently fail ONE tracing-capture test, a
different one each run (`embed::…partial_remote_completion…`,
`attempt_queue::…cleanup_log_span…`, `batch::…authority_fold_backfills…`).
Cause: `tracing::subscriber::with_default` is thread-local, so parallel tests
emitting spans pollute each other's captures. Evidence it is not this lane's:
- reproduces on the clean base commit `e9d9e9a` in a separate worktree;
- `--test-threads=1` is fully green (**3164 passed, 0 failed**);
- each test passes in isolation, repeatedly;
- this diff contains zero tracing/logging lines and touches only `comm.rs` +
  `comm/tests.rs`.

## Blueprint deltas

- `put_projected_comm_claim_in_txn`, `projected_comm_claim_id`,
  `projected_comm_conflict_key`, `resolve_party_in_txn`,
  `active_comm_persons_by_party_key_in_txn`, `reconcile_comm_party_twins` land
  with the blueprinted signatures verbatim.
- `apply_projector_rule_in_txn` takes a `&ProjectedCommEvent` bundle instead of
  a 9th positional argument (clippy `too_many_arguments`). The blueprint only
  required that `project_event` pass its `event_id` through; it does.
- Canon rider deferred to the orchestrator (see Scope).

## K3 simplify pass (post-impl, pre-screen)

Scope exercised: whitespace/blank-line rebalance, stale-comment sweep,
dead-code scan over the new surface. Result: **no edit warranted** —
nothing material landed; no SIMPLIFY commit.

- Blank-line balance: zero runs of 3+ blank lines in `comm.rs` /
  `comm/tests.rs`; `cargo fmt -p oneiron` is a no-op on the working tree.
- Line-width: both files are within the repo's effective ~100-column norm
  (only >100-col lines are two pre-existing duplicated "L0 sweep-8 ruling"
  comments at `comm/tests.rs:536,723`, both above the lane's diff base —
  not this lane's to churn; codebase carries ~90 similar unpinned test
  comments).
- Stale comments: none found — no comment contradicts the code it sits on;
  no TODO/FIXME introduced or removed by this lane.
- Semantic sweep (performed to look for dead material, not to change it):
  every new symbol (`ProjectedCommEvent`, `PartyLookup`, both `put_*` claim
  writers, party-scan/lookup/repair set, `reconcile_comm_party_twins`) has
  ≥2 call sites or one load-bearing one; the three new constants
  (`KEY_PARTY_KEY`, `PARTY_KEY_TWIN_RATIONALE`,
  `PROJECTED_COMM_CLAIM_ID_DOMAIN`) are each multiply referenced. All
  candidate merges (three call sites of `put_projected_comm_claim_in_txn`,
  the Predicate-RefOr-argument pairs in `projected_comm_conflict_key`)
  rejected — each would trade two flat branches for an allocation or a
  tuple of separated fields, neither smaller nor clearer. Destructure at
  `apply_projector_rule_in_txn` entry is deliberate, not decorative:
  `rule` `Copy`-out lets the later `Err(rule)` path name the failed rule.
- Doc comments are dense but each carries load-bearing semantics
  (replay-as-no-op, fail-closed on collision, shell staleness); trimming
  would cut meaning, not fat.
- Helpers `clear_party_index` / `point_party_index` / `mint_comm_person` /
  `count_person_rows` / `count_identity_topology_events`: all used ≥2 test
  bodies except `count_identity_topology_events` (used 4×).
