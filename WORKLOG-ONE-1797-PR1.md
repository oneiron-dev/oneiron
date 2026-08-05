# WORKLOG — ONE-1797 PR 1 (CB-A lane root: mechanical split, zero behavior change)

Worktree: `/Volumes/Cinema/w5-lt/cb-a` · base `e9d9e9a` · blueprint
`/Users/olety/.claude-wave5/blueprints/CB-A/ONE-1797.md` (PR 1 section is the contract).

## State: PR 1 COMPLETE, committed, cheap gate green.

## Decisions taken during the split

1. **`one_line_token` lives in `mod.rs`, imported by children via `use super::one_line_token;`.**
   The blueprint pins it as the private shared helper in `mod.rs`; `tasks.rs`, `agents.rs`, and
   `frame.rs` all consume it. Body is byte-identical to the flat file's. CLAIMS.md §Shared says
   no later ticket changes its semantics; PR 2 layers XML escaping *on top* in `frame.rs`, it
   does not edit this function.

2. **`TASK_ACK_KEY_PREFIX` / `TASK_CANCELLED_KEY_PREFIX` stay module-private in `tasks.rs`**
   (plain `const`, not `pub(super)`). Nothing outside `tasks.rs` reads them; widening visibility
   would have been a behavior-adjacent change PR 1 has no license for. Byte values unchanged —
   the persisted key bytes `context_board.task.ack.v1\0` / `.cancelled.v1\0` are on-disk state.

3. **`test_support` is a `#[cfg(test)] mod` inside `mod.rs`** holding both `run_tree_node` and
   `run_tree_node_with_worker_kind`, byte-identical bodies, exposed `pub(super)`. The blueprint
   allowed `run_tree_node` (agents-only) to ride along or move to `agents.rs`; it rides along so
   both helpers stay in one place and `agents.rs`/`tasks.rs` each import exactly what they use
   (`agents.rs` both; `tasks.rs` only `run_tree_node_with_worker_kind`).

4. **`status_token` went to `agents.rs`, `task_status_precedence_rank` + `run_tree_board_status`
   to `tasks.rs`** — each private helper follows its only caller, per the blueprint's table.

5. **Oracle split is line-exact, proven mechanically.** Every original line of
   `tests/context_board_oracle.rs` was extracted by `sed` line range into exactly one destination
   and reassembled: `diff` against `HEAD:...context_board_oracle.rs` is **empty**. No arm body,
   assertion, `#[ignore]`, `#[cfg(feature = "sync")]`, test name, or module-local observation
   struct was retyped by hand. Only the per-file preamble (byte-identical `//!` block +
   `#![allow(dead_code)]`, verified by `diff` against the original's lines 1-23), the section
   banner comment, and the `mod cb_t {` / `mod cb_a {` / `mod cb_s {` / `mod cb_x {` opener and
   its `}` closer are authored fresh — those are the structural frame the split necessarily
   re-mints. Banner *text* was retitled per file to name only that file's tickets.

6. **`cb_oracle_agents.rs` keeps `mod cb_a` and `mod cb_x` as separate blocks**, and
   `cb_oracle_tasks.rs` keeps `mod cb_t` + `mod cb_a` — per blueprint ("retain local
   `mod cb_a` / `mod cb_x` boundaries"), so test-qualified names (`cb_a::…`, `cb_x::…`) stay
   recognizable across the split.

7. **`tests/cb_oracle_common/mod.rs` is comment-only.** The extraction produced **zero**
   cross-file fixtures: every `arm_*` seam carries its own module-local `use` block and builds
   its own state, so no helper met the blueprint's "imported by at least two extracted files"
   bar. Per the blueprint that means: fixture-policy comment only. It is FROZEN (additive-only;
   signature change ⇒ PACKET_AMEND). Note it is not currently referenced by any test binary —
   cargo only auto-discovers `tests/*.rs`, so a directory module compiles only once a file
   `mod cb_oracle_common;`s it. That is the same shape as the existing `tests/common/`.

8. **`mcp_oracle.rs` gets its own crate-appropriate `//!` header**, not a copy of the engine
   oracle's — it now lives in `oneiron-server` and names only ONE-1704/1705. Arm bodies,
   observation structs, `#[ignore]`s, and assertions are the byte-exact relocation.

## Verified

- `crates/oneiron/src/lib.rs` — **untouched** (`git diff HEAD` empty); `pub mod context_board;`
  now resolves to `context_board/mod.rs`.
- `crates/oneiron/src/task_verb.rs` — **untouched** (`git diff HEAD` empty). Its four
  crate-private imports (`ack_task_in_txn`, `cancel_task_in_txn`, `task_is_acked`,
  `task_is_cancelled`) resolve through the `pub(crate) use tasks::{…}` line in `mod.rs`.
- Test inventory conserved: 41 `arm_*`, 41 `#[test]`, 29 `#[ignore]` before and after;
  `diff` of the sorted fn-name and struct-name inventories is empty.
- `stream.rs` / `plugin.rs` are behavior-empty (module doc comment only).

## Gate results (all green)

| Command | Result |
|---|---|
| `cargo test -p oneiron --lib context_board` | 16 passed, 0 failed |
| `cargo test -p oneiron --test cb_oracle_frame` | 1 passed |
| `cargo test -p oneiron --test cb_oracle_tasks` | 7 passed, 7 ignored |
| `cargo test -p oneiron --test cb_oracle_tasks --all-features` | 8 passed, 7 ignored (the `sync`-gated `task_syncs_job_stays_node_local_linked_by_task_ref` arm lands) |
| `cargo test -p oneiron --test cb_oracle_stream` | 0 passed, 8 ignored (as expected) |
| `cargo test -p oneiron --test cb_oracle_plugin` | 0 passed, 4 ignored (as expected) |
| `cargo test -p oneiron --test cb_oracle_agents` | 3 passed, 7 ignored |
| `cargo test -p oneiron-server --test mcp_oracle` | 0 passed, 3 ignored (as expected) |
| `cargo fmt --all -- --check` | clean |
| `cargo clippy -p oneiron --all-targets --all-features` | clean |

## NEXT-STEP INTENT (PR 2 — frame behavior; do not start until PR 1 is the committed baseline)

PR 2 touches **only** `context_board/frame.rs`, `context_board/mod.rs` (re-export lines only),
`tests/cb_oracle_frame.rs`, and one doc-comment in `tests/cb_oracle_plugin.rs`.
`tasks.rs` / `agents.rs` / `task_verb.rs` stay byte-identical — that cut is CB-B's and the
blueprint restates it twice.

Order I intend to build PR 2 in:

1. `frame.rs` types first, in the blueprint's Keystone-skeleton order: `CANONICAL_BOARD_LEGEND`,
   `MAX_BOARD_ROW_BYTES`, `PLUGIN_SECTION_BUDGET_POLICY_REF`, `BoardLegend`, `BudgetPolicyRef`,
   `BoardBudgetRequest`/`Source`/`BoardBudget`, `ShedRank` + `SHED_ORDER`/`CORE_SHED_ORDER`,
   `SectionPolicy`, `BoardFrameError`. `thiserror` + `serde` are already crate deps — **do not
   edit `Cargo.toml`** (`proptest` is already there too, needed for the fuzz golden).
2. `BoardSection` becomes the validated typed shape (private fields + `new()` enforcing the
   byte ceiling BEFORE any tokenize, the count-fallback presence check, the non-reducing-count
   check, and the pinned-vs-shed_rank check). This is the breaking-change point for
   `cb_oracle_frame.rs`'s `arm_render_board_block`, whose fixture currently builds
   `BoardSection { name, rows }` literals — that fixture is CB-A-owned and updates with it.
3. `resolve_board_budget` (the ONLY place `min(...)` or an override is applied), then `shed`
   (pure; starts from all-`Full`, flips to `Counts` by rank in `SHED_ORDER`, records the applied
   prefix, sets `floor_exceeds_cap` only after all five ranks are spent), then
   `render_board_block` re-signatured to `(&BoardFrame, BoardBudgetRequest) -> Result<BoardRender>`.
4. `xml_attr_token` / `xml_text_token` layered over `one_line_token` — **escape `&` first**.
   Wrapper attribute order is golden: `surface`, `epoch`, `scope`, `budget_tok`; `budget_tok`
   carries the effective `cap_tok`, never the rendered count.
5. `assemble_task_agent_sections` last — the only bridge from the landed `TasksSection` /
   `AgentsSection` producers; derives only the engine-owned `count: N` fallback and never
   reads domain meaning out of row text.
6. Tests: migrate `frame.rs::tests::board_block_envelope_is_exactly_one_open_one_close` and
   `cb_oracle_frame.rs::cb_t::board_block_opens_with_context_board_render_tag` to the new
   wrapper (**keep both function names** — the blueprint pins the second one's stale-but-landed
   identity), then add the eight live `one_1797::*` tests in `cb_oracle_frame.rs`.
   The `cb_oracle_plugin.rs` change is a comment-only edit to `cb_x::arm_renderer_fuzz_coverage`'s
   doc-comment (drop `[/CONTEXT_BOARD]`, name `</memory>`); the arm stays ignored for ONE-1706.

Hazards to watch in PR 2:
- `render_board_block`'s signature change ripples to `cb_oracle_frame.rs::arm_render_board_block`
  only — `rg -l 'render_board_block'` before and after to confirm no other call site appeared.
- The `#[cfg(feature = "sync")]` arm in `cb_oracle_tasks.rs` must keep passing under
  `--all-features`; run that binary with `--all-features` in the PR-2 gate too.
- Do NOT create the gh-stack layer here. The orchestrator's publish verb is `gh stack sync` and
  it runs after simplify / finder / verdict close.
