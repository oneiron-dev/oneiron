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

### Cheap gate — GREEN (segment 0 close)

Machine was contended (3 sibling lanes cycling cargo); ran at `-j 4` per the
serial-cargo law, backing off between attempts. Log: `/tmp/l1924-seg0-test.log`.

- `cargo check -p oneiron --all-features --all-targets` — clean. This is the
  real exhaustive-match proof: `--all-targets` compiles every test module, so
  any uncovered `match kind` arm would have failed here. None did beyond the
  two already handled (rulings 1–2).
- `cargo fmt --all -- --check` — clean.
- `cargo clippy -p oneiron --all-features --all-targets` — zero warnings
  (forced a real 24.8s run after a 0.24s cached no-op; the cached result was
  not trusted as evidence).
- `cargo test -p oneiron --all-features` — `3153 passed; 0 failed` on the lib
  target plus 34 green integration binaries; zero `FAILED`/`panicked` lines.
  The four ONE-1924 tests are confirmed PRESENT and `ok` in the log, not merely
  implied by the exit code:
  `facade::tests::edge_kind_names_round_trip_including_blocked_by`,
  `tests::blocked_by_mint_preserves_edge_byte_frontier`,
  `tests::blocked_by_matches_structural_non_traversed_contract_row`,
  `sync_ships_all_edge_kinds_and_context_pack_walk_gates_at_read_time`.

### Exhaustive-match sweep (done before the gate, confirmed by it)

Swept every `EdgeKind` match in the workspace. Only two are exhaustive over the
enum beyond the claimed files: `code_run.rs:1719` (ruling 2, handled) and
`edge.rs::edge_value_layout_for_kind` (claimed). Everything else is either
string-keyed (`identity_topology.rs:983` matches an event-kind `&str`;
`code_run.rs:1034` likewise), catch-all'd (`edge.rs::validate_public_edge_kind`
`_ => Ok(())` — ruling 5), or a literal array (`ppr/tests.rs:318` — ruling 3).
`crates/oneiron-server/**` has no exhaustive `EdgeKind` match at all.

### Packet + done-means verification (mechanical)

- `git diff --name-only e9d9e9a..HEAD` = 8 source files + this worklog. Zero
  hits against `store.rs` / `gate.rs` / `off_record/` / `sync/window.rs` /
  `sync/bridge.rs` / `embed.rs` / `hnsw.rs` / `distance.rs` / `authority.rs` /
  `Cargo.lock` / any `Cargo.toml`. `store.rs` untouched = done-means satisfied
  directly, and no DB manifest entry exists to add.
- Grepped the added lines for `readiness|blocked_status|is_blocked|
  blocked_count|projection|DB_NAME|db_manifest`: only doc-comment prose hits,
  no code surface. No counter, no `blocked` stored status, no projector.
- Docs contract untouched: `oneiron-contracts.ts:423` still reads u8 23 /
  structural / 12 B / `pprWeight: null` / `lambda: null`, and no row was added
  or duplicated. NOTE for the reviewer: line 424 carries a `blocks` u8-24
  complement row minted into canon 2026-08-05 — it is NOT this ticket's scope
  and was deliberately left unminted in the engine.

### Segment status

Blueprint done-means: ALL MET. Implementation complete, cheap gate green,
committed. Two PACKET_AMEND items for the board (both additive one-liners,
neither claimed by another lane — see rulings 1 and 2): `context_pack.rs`
walk-gate arm, `code_run.rs` structural-reject arm.

### NEXT INTENT

Nothing left for impl. Hand off to K3 simplify → Sol finder (max) → K3 verdict.
Simplify note: the diff is deliberately thin — additive enum arms plus tests;
there is little to delete. Do NOT "simplify" the pinned test tables into loops
over `EdgeKind`; their whole value is being hand-written contract literals that
fail on drift. ONE-1375 (layer 2) rebases on this branch next.

## Segment 1 — marker RELAY-ONE-1924-simplify-seg0 (SIMPLIFY pass)

Deletion-biased review of the full `origin/main...HEAD` diff (8 files, +355/−34
including this worklog; +218/−32 source). Every impl "simplify-confess" below
carries its verdict.

| Impl note / confess | Verdict |
|---|---|
| "Do NOT simplify the pinned test tables into loops over `EdgeKind`" | **HELD — no change.** The tables are hand-written contract literals (`CONTRACT_EDGE_VALUE_LAYOUTS`, `PINNED_EDGE_KIND_DISCRIMINANTS`, `default_weight` literal table); their entire value is drift-on-pin failure. Not defensive code — load-bearing by design. |
| `code_run.rs` structural-reject arm (compile-forced) | **Minimum already.** One identifier in an existing alternation; nothing to delete. |
| `context_pack.rs` walk-gate arm (`matches!` + `BlockedBy`) | **Minimum already.** Added one alternative to an existing macro; the comment re-wrap was forced by the rustfmt line. |
| `edge.rs` variant + 3 arm sites + `try_from_u8` row | **Minimum already.** Enum variant, `default_weight` None, `try_from_u8(23)`, layout alternation — each is a single additive line at its chokepoint. |
| `ppr.rs` / `facade.rs` rows | **Minimum already.** One row per site; doc lines updated, not added. |
| Test additions (facade round-trip, 3 pinned-table extensions, 2 contract tests, gating extension) | **Untouched per hard rule** (never touch test assertions/fixtures). No speculative tests found — each pins a distinct contract literal (byte frontier, contract row, round-trip, sync-ship). |

**Sweep for the four simplify demons:**
- Layers: none added (all edits are in-place arms/rows).
- Duplication: none. `BlockedBy` appears once per required site — no helper
  introduced, no repeated literal that a single constant would kill. The
  facade/`tests.rs` "blocked_by" string appears at exactly the from_str/name
  seam and their test — intentional contract pinning, not duplication.
- Defensive branches: none. Negative-space done-means (no readiness DB / no
  counter / no projector) were *honored*, so there is no unused guard to strip.
- Speculative generality: none. No trait, no generic, no config knob, no
  "future kind" hook.

**Diff accounting this segment: 0 source lines added, 0 deleted** (worklog
only). The impl segment was already the simplification of itself — additive, no
scaffolding left behind, no dead code.

**Cheap gate re-ran (segment 1 close):** `cargo check -p oneiron
--all-features --all-targets -j 6` clean (11.59s) · `cargo clippy -p oneiron
--all-features --all-targets -j 6` zero warnings on a forced real run (25.75s,
after `touch src/lib.rs` defeated the 0.22s cached no-op — cached result not
trusted as evidence, per seg-0's own precedent). No code changed, so the seg-0
test evidence (3153 passed, 0 failed) stands un-invalidated.

### NEXT INTENT

Simplify complete, zero edits warranted. Hand to Sol finder (max) → K3 verdict.
Simplify has nothing to land; do NOT manufacture a change to justify the stage.
`WORKLOG-ONE-1924.md` segment-1 section is the verdict record for the finder.
