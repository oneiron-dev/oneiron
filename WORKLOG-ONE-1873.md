# ONE-1873 — paged TASK presence (CB-B flat)

Base: `049cde369` (post ONE-1708). Claimed files: `crates/oneiron/src/task_verb.rs`,
`crates/oneiron/src/context_board/tasks.rs` (+ inline `#[cfg(test)]` in both).

## Phase 1 — re-verify the audit candidate against the live base

All four checks from the blueprint's Shape §1 repeated on `049cde369`:

1. `task_verb.rs:4437` (inside `task_presence`) still calls unpaged
   `vault.entities_by_type(ENTITY_TYPE_TASK)?`. The remaining hits in that file are all
   `> 4711`, i.e. inside `#[cfg(test)] mod tests`.
2. `vault.rs:1677` `entities_by_type` still returns `Err(Error::IndexOverflow("entities_by_type"))`
   once a type-index scan would exceed `MAX_TYPE_QUERY_RESULTS = 100_000` (`vault.rs:68`).
3. `vault.rs:1696` `entities_by_type_page(entity_type, after: Option<&EntityId>, limit)` retains
   the exclusive `after` cursor (`Bound::Excluded` at 1713), clamps `limit` to
   `MAX_TYPE_QUERY_RESULTS`, and never returns `IndexOverflow`.
4. `tasks_check` (1983), `tasks_expand` (1991), `tasks_ack` (2013) all entered `task_presence`,
   so the cliff was permanent for all three reads.

Finding is real, not by design. ARCH-0067 §2 pins the board as the session's *dynamic tail*,
"re-rendered from typed state every turn and never cached"; §6 pins the claim FACT
(`TASK.assignee` / `status` / `started_at`) as "authoritative and synced, so every device sees
who is doing what, live". A permanently failing `tasks.check` breaks a ratified read surface —
it is not accepted large-vault behaviour. §3's shed order (`TASKS to counts`) and §8's additive
overflow grammar (`goal: +4` = four more beyond what's shown) supply the honest-truncation
shape used here.

## Decisions

- **`context_board/mod.rs` is NOT touched.** It is a shared re-export chokepoint with no CB-B
  claim (CLAIMS.md §"Shared/additive chokepoints"). `mod tasks;` is private, so anything new in
  `tasks.rs` is unreachable from `task_verb.rs` unless it rides an *already re-exported* type.
  Consequence: the bounded renderer and the shared render-state read are **associated items on
  `TasksSection` / `TaskIntentPresence`** rather than free functions. Blueprint's free-function
  skeleton (`render_tasks_section_bounded`, `task_render_state_in`) is followed in substance;
  only the reach path differs, and it differs to respect the claim boundary.
  `TASKS_RENDER_ROW_CAP` stays a named `pub const` (done-means grep) with
  `TasksSection::RENDER_ROW_CAP` as the crate-reachable alias, so the cross-file invariant
  `0 < TASKS_RENDER_ROW_CAP < TASK_PRESENCE_SCAN_CAP` is a compile-time assert, not a comment.
- **No nested LMDB read transactions.** heed's env is opened without `MDB_NOTLS`
  (`store.rs:1813`), so one thread must not hold two `RoTxn`s. Everything hydrated inside a page
  transaction therefore uses `_in` variants (`task_verb_body_in` already existed;
  `task_entity_role_in` and `peer_handle_in` added here).
- **The connector-send shape is resolved after the page transaction closes.**
  `Vault::connector_send_task` opens its own txn and `has_connector_send_subkind` is private to
  `outbound.rs` (not my file), so a non-typed `Task`-role row becomes a `TaskPageSlot::Untyped`
  inside the txn and is finished afterwards **in its original slot position** — type-index row
  order is preserved exactly.
- Scan cap bounds WORK (inspected entity ids); render cap bounds TOKENS. Kept separate, per
  the blueprint, so a malformed/filtered prefix cannot starve the visible board.
- `source_exhausted` is load-bearing: a scan-capped result is a lower bound and says so; leftover
  linked jobs are **not** drained as bare when the scan stopped early ("not scanned" ≠ "dangling").
- Loop exits that land exactly on the scan cap with a full page do ONE bounded 1-row probe past
  the cursor, so an exact census is not mis-reported as truncated.

- **Test-side censuses swapped to the bounded primitive.** Done-means requires
  `rg 'entities_by_type\(ENTITY_TYPE_TASK\)' task_verb.rs` to return no match. Ten inline
  `#[cfg(test)]` call sites (all tiny 0–3-row censuses belonging to the 1699/1888/1700/1708 arms)
  now go through one `task_entity_census` helper over `entities_by_type_page`. No assertion
  changed; the unpaged call is gone from the file entirely, so it cannot creep back.

## Residue to flag in handoff (NOT actioned here)

- Retention/GC for Done TASK rows + attempt records: no TASK GC module or ratified policy exists;
  deletion touches sync/erase territory. Batch author records it in `_parked.md`.
- `outbound.rs::connector_send_tasks` (~L1766 on this base) carries the same unpaged
  `entities_by_type(ENTITY_TYPE_TASK)` twin. SPINE-COMM-owned — noted, not touched.

## Progress

- [x] Phase 1 re-verification
- [x] `context_board/tasks.rs`: render cap, `TasksOverflow`, `TasksSection::render_bounded`,
      shared render-state read
- [x] `task_verb.rs`: bounded cursor loop, page hydration, snapshot, direct-by-id verbs
- [x] Inline regression + property tests in both files
- [x] Scoped tests + clippy green

## Verification run

- `cargo clippy -p oneiron -j6 --all-features` — clean
- `cargo clippy -p oneiron -j6 --all-features --all-targets` — clean
- `cargo test -p oneiron --lib task_verb -j6 --all-features --no-fail-fast` — 94 passed, 0 failed,
  1 pre-existing ignored
- `cargo test -p oneiron --lib context_board -j6 --all-features --no-fail-fast` — 29 passed,
  0 failed
- Relevant oracle binaries (compile+run, not the full suite): `--test cb_oracle_tasks` 15 passed,
  `--test cb_oracle_frame` 11 passed — the named done-means arms
  (`tasks_section_renders_one_line_rows_over_intent_and_bare_jobs`,
  `failed_rows_stay_surfaced_until_acked`, `expand_unfolds_realizing_jobs_under_intent_row`)
  are all green.
- Scope guards: `vault.rs`, `outbound.rs`, `context_board/mod.rs` byte-identical to `049cde369`;
  `Cargo.lock` not committed.

## INTENT (next step)

Done — nothing outstanding. The verdict leg owns the full suite.
