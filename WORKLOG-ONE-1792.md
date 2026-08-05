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

## Blueprint deltas

- `put_projected_comm_claim_in_txn`, `projected_comm_claim_id`,
  `projected_comm_conflict_key`, `resolve_party_in_txn`,
  `active_comm_persons_by_party_key_in_txn`, `reconcile_comm_party_twins` land
  with the blueprinted signatures verbatim.
- `apply_projector_rule_in_txn` takes a `&ProjectedCommEvent` bundle instead of
  a 9th positional argument (clippy `too_many_arguments`). The blueprint only
  required that `project_event` pass its `event_id` through; it does.
- Canon rider deferred to the orchestrator (see Scope).
