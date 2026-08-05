# WORKLOG — ONE-1924 (TASK typed `blocked_by` edge)

Lane L1-ENTITY · stack E1 · layer 1 of 3 · branch `ONE-1924` · base `main` (e9d9e9a).
Blueprint: `/Users/olety/.claude-wave5/blueprints/L1-ENTITY/ONE-1924.md` (the contract).
Worktree: `/Volumes/Cinema/w5-lt/l1-entity`.

## Segment 0 — marker RELAY-ONE-1924-impl-seg0

### Ground survey (what main actually looks like)

- `crates/oneiron/src/edge.rs:24` — `EdgeKind` `#[repr(u8)] #[non_exhaustive]`, 22 variants,
  highest discriminant `SplitInto = 22`. Byte 20 is explicitly commented as the
  ONE-1414 `SameAs` parking spot inside `try_from_u8` (`edge.rs:143`) — no arm, so
  `try_from_u8(20)` already returns `None`. Confirmed 21/22 = `MergedInto`/`SplitInto`.
- `crates/oneiron/src/edge.rs:249` — `edge_value_layout_for_kind` is an EXHAUSTIVE
  two-arm match (structural list | semantic list). Adding a variant forces an edit here;
  `BlockedBy` joins the structural arm (12 B).
- `crates/oneiron/src/edge.rs:92` — `default_weight` exhaustive; `ChildOf`/`AssignedTo`
  are the existing `None` precedent. `BlockedBy` follows them.
- `crates/oneiron/src/ppr.rs:113` — `lambda_for_kind` exhaustive; `ChildOf`/`AssignedTo`
  are `None`. `BlockedBy` follows.
- `crates/oneiron/src/context_pack.rs:2197` — the read-time walk gate is
  `matches!(edge.kind, EdgeKind::ChildOf | EdgeKind::AssignedTo)`. NOT exhaustive, so
  it does NOT force an edit — but a `lambda: null` kind that is not in this list WOULD
  neighbor-expand. See the ruling below.
- `crates/oneiron/src/facade.rs:1261` / `:3496` — `edge_kind_from_str` /
  `edge_kind_name`, snake_case both directions, `merged_into`/`split_into` present.
- `crates/oneiron/src/tests.rs:540` `CONTRACT_EDGE_VALUE_LAYOUTS: [_; 20]`,
  `:6202` `PINNED_EDGE_KIND_DISCRIMINANTS: [_; 20]`, `:9921` the `default_weight`
  contract-literal table `[_; 20]` — all three stop at byte 19 (they never absorbed
  21/22). Blueprint asks for byte 23 specifically, without renumbering.
- Docs contract row already canonical:
  `oneiron-docs/site/src/data/oneiron-contracts.ts:423` — u8 23, structural, 12 B,
  `pprWeight: null`, `lambda: null`. Engine is being made to MATCH it; docs untouched.
  (Row 424 `blocks` u8 24 also exists in canon — NOT this ticket, not minted here.)

### Rulings taken this segment

1. **context_pack walk gate must include `BlockedBy`.** Blueprint done-means:
   "context-pack neighbor expansion omits its target", and Shape line: "PPR/context-pack
   expansion therefore skips the edge". `lambda_for_kind` gates PPR only; the
   context-pack walk has its own `matches!` list at `context_pack.rs:2197`. Leaving
   `BlockedBy` out of that list would leave the done-means unmet AND make the new
   `sync_edge_kind_gating` assertion fail. `context_pack.rs` is not on the blueprint
   claim list — logging as a PACKET_AMEND candidate (one `matches!` arm, additive,
   no other lane declares this file). Cheapest correct chokepoint; no call-site
   special-casing.
2. **`code_run.rs::ensure_public_memory_edge_kind` (`:1718`) is exhaustive** and will
   not compile without a `BlockedBy` arm. It sorts kinds into
   semantic-allowed / structural-rejected for `self.memory.put_edge`. `BlockedBy` is
   structural → the reject arm, beside `ChildOf`/`AssignedTo`/`MergedInto`/`SplitInto`.
   Compile-forced, one identifier, zero behavior change for existing kinds.
   `code_run.rs` IS a declared lane file (CLAIMS.md, 1936 partition) — different fn,
   no overlap with `HostSelfDispatcher` supersede/retract validation.
3. **`ppr/tests.rs` NOT edited.** Its `lambda_table_matches_contract_literals` iterates a
   literal `[_; 20]` array, not an exhaustive match, so it stays green untouched.
   `ppr/tests.rs` is not on this ticket's claim list; `lambda_for_kind(BlockedBy) == None`
   is covered from `crates/oneiron/src/tests.rs` (claimed) instead.
4. **Pinned tables get byte 23 only, not 21/22.** They currently stop at 19; back-filling
   `MergedInto`/`SplitInto` is real coverage debt but is another ticket's scope. Done-means
   says "include `BlockedBy` without renumbering any existing kind" — nothing more.
5. **`validate_public_edge_kind` (`edge.rs:459`) untouched.** Its `_ => Ok(())` catch-all
   already admits `BlockedBy`; `blocked_by` is an ordinary caller-writable edge, unlike the
   door-reserved `merged_into`/`split_into`.

### Edits (in-scope, per claim list)

- [x] `crates/oneiron/src/edge.rs` — variant, `default_weight`, `try_from_u8`, layout
- [x] `crates/oneiron/src/ppr.rs` — `lambda_for_kind` row + doc
- [x] `crates/oneiron/src/facade.rs` — `edge_kind_from_str` + `edge_kind_name`
- [x] `crates/oneiron/src/facade/tests.rs` — both-directions round-trip test
- [x] `crates/oneiron/src/tests.rs` — 3 pinned tables + dedicated BlockedBy contract test
- [x] `crates/oneiron/tests/sync_edge_kind_gating.rs` — BlockedBy target in the seam-7 pin
- [x] `crates/oneiron/src/context_pack.rs` — walk-gate arm (ruling 1, PACKET_AMEND)
- [x] `crates/oneiron/src/code_run.rs` — compile-forced reject arm (ruling 2)

### Explicitly NOT done (done-means negative space)

No readiness field, no `blocked` stored status, no readiness LMDB DB, no counter, no
projector, no materialized index, no DB manifest entry, no `store.rs` touch, no TASK body
schema or status transition change, no sync-admission special case, no subtree/ancestors
change, no docs-contract edit, no `Cargo.lock`.

### NEXT INTENT

Cheap gate: `cargo test -p oneiron --all-features -j 6`, then fmt+clippy, then commit.
