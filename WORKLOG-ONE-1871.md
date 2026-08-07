# WORKLOG — ONE-1871 [L1-ENTITY flat] F5 concurrent ChildOf convergence

Lane: `ONE-1871`, flat off `origin/main` `4f5360daa` (post-E1: `validate_child_of_batch`
carries the final-state existence + role matrix + cycle checks; ONE-1375 streak tail
consumes the winning projection; ONE-1731 post-fence tree).

Seat: Opus impl (VERIFY-FIRST, `opus-watch` binding).
PACKET: `crates/oneiron/src/batch.rs` · `crates/oneiron/src/sync/quarantine.rs` ·
`crates/oneiron/tests/sync_quarantine.rs` · `crates/oneiron/tests/sync_convergence_props.rs`.
`crates/oneiron/src/sync/bridge.rs` read-only (L1-SPINE owned) — untouched.

---

## 1. Step 1 (VERIFY-FIRST): pre-fix divergence evidence

A throwaway probe (`one_1871_prefix_divergence_probe`, deleted after the evidence was
captured — the shipped regressions replace it) ran the blueprint's two-replica shape on
UNMODIFIED `main`:

* four non-TASK entities (`child`, `root`, `a_parent`, `b_parent`) authored on node-a and
  exchanged, plus `child --ChildOf--> root` at `T0+10`;
* both replicas go offline and reparent the SAME single-parent slot:
  node-a deletes `child→root` and adds `child→a_parent` at `created_at = T0+100`;
  node-b deletes `child→root` and adds `child→b_parent` at `created_at = T0+200`;
* one bidirectional `exchange` (2 rounds, inside the ARCH-0023b cap).

Observed on `4f5360daa` + probe only:

```
CRDT edges equal: true
CRDT edge keys: ["<child>:06:<a_parent>", "<child>:06:<b_parent>"]
child      = 019fdb3ecf207780857f7c3f3bbd4df2
root       = 019fdb3ecf207780857f7c41c6595c9c
a_parent   = 019fdb3ecf207780857f7c5be77e7dde
b_parent   = 019fdb3ecf207780857f7c6d98fd11ce
node-a LMDB parents: ["019fdb3ecf207780857f7c5be77e7dde"]   <- a_parent
node-b LMDB parents: ["019fdb3ecf207780857f7c6d98fd11ce"]   <- b_parent
quarantine rows a=1 b=1
```

**F5 CONFIRMED, and confirmed as a REAL divergence, not a by-design quarantine.**

* The CRDT `edges` map is byte-identical on both replicas (both candidate `ChildOf` keys
  survive, `EdgeKind::ChildOf = 6`) — the CRDT layer converged.
* The deterministic LMDB projection did NOT: each replica keeps the parent IT authored
  locally, i.e. opposite winners for the same slot from the same converged input.
* Each replica wrote exactly one `x:` quarantine row, reason `ChildOfCardinality`, for a
  VALID replicated reparent. The mechanism is exactly the one recorded in
  `oneiron-wave2/AUDIT-FINDINGS-2026-07-22.md` F5: `sync/bridge.rs::apply_materialized_edge_ops`
  sorts and component-groups incoming ops deterministically, but the already-STORED parent
  is not part of that ordering — it wins by being on disk first; the incoming valid edge
  then reaches `batch.rs::validate_child_of_batch`, sees `parents.len() == 2`, and is
  rejected `ChildOfCardinality` → quarantine-and-continue (ONE-1124).
* The result is *order-dependent by local history*, not by delivery order — which is why
  the sort in `apply_materialized_edge_ops` cannot fix it and why the repair belongs at
  the batch-validation entry, where stored state and incoming candidates are both visible.

Park was therefore NOT taken: divergence reproduces on current `main`, and the same-slot
quarantine is a defect of the projection, not an intentional design outcome.

## 2. Discriminator verdict: VARIANT holds (not call-path)

The blueprint required verifying, at implement time, whether the public
`PublicEdgeWithCreatedAt` surface lowers into the replicated `BatchOp::EdgeWithCreatedAt`
variant on the same code path. **It does not — the variant discriminator is sound.**
Grounding (all of `crates/oneiron`):

* `BatchOp::PublicEdgeWithCreatedAt` and `BatchOp::EdgeWithCreatedAt` are two SEPARATE
  enum variants (`batch.rs:240` / `batch.rs:248`).
* Every public timestamped builder pushes `PublicEdgeWithCreatedAt`:
  `BatchBuilder::edge_with_created_at` / `edge_with_created_at_and_vad` (`batch.rs:653`,
  `:675`) and the `TxnBatchBuilder` twins (`batch.rs:1291`, `:1313`). `BatchOp::Edge` is
  the untimestamped public arm.
* The ONLY producers of `BatchOp::EdgeWithCreatedAt` are crate-internal:
  `BatchBuilder::edge_with_value_fields` / `TxnBatchBuilder::edge_with_value_fields`
  (`batch.rs:691`, `:1331`; consumers = `sync/window.rs:1687` forward-remat healing,
  `ppr/tests.rs`, `batch/tests.rs`), `sync/bridge.rs:969` (Observer B), and the
  fixed-kind identity/claim/affect/repo effect stampers
  (`identity_topology.rs` FacetOf/MergedInto/SplitInto/HasFacet + reserved topology kinds,
  `affect.rs`/`claim.rs`/`repo_mutation.rs` `Supersedes`). None of the fixed-kind stampers
  can emit `EdgeKind::ChildOf`; the two `edge_with_value_fields` consumers that CAN carry
  ChildOf are both sync replay/heal paths, which is precisely the intended scope.
* The one place that REWRITES an op into a timestamped form —
  `session_overlay.rs::promotion_replay_op` (`:559`) — lowers `BatchOp::Edge` into
  `PublicEdgeWithCreatedAt` (`:585`) and explicitly REJECTS a journaled
  `EdgeWithCreatedAt` with `InvariantViolation` (`:600`). There is no public→replicated
  lowering anywhere.

So no new sync-origin flag and no public mode were introduced: normalization keys on the
`BatchOp::EdgeWithCreatedAt` variant alone.

## 3. Citation correction — ARCH-0016 **I6**, not I7

The ticket cites ARCH-0016 I7 for concurrent-reparent LWW. The correct anchor is **I6** in
`/Users/olety/Desktop/code/oneiron-docs/generated/oneiron/backend/oneiron-arch-0016-productivity-plugin-v1.md`;
I7 is derived-state repair. The off-by-one is recorded in the production comment on
`resolve_replicated_child_of_slots` and on the named regressions.

## 4. Change shape

*(filled in below as the fix lands)*
