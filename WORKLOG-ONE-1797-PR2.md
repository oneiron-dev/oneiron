# WORKLOG — ONE-1797 PR 2 (frame behavior)

Lane CB-A · worktree `/Volumes/Cinema/w5-lt/cb-a` · branch `ONE-1797-PR1` (PR-2 commits ride on
the PR-1 split commit `4225115`; orchestrator owns the branch/stack split at publish time).

## State

PR-2 implementation **complete and cheap-gate green**. Not pushed — orchestrator owns `gh stack`.

Claim surface touched, exactly the blueprint's PR-2 set, nothing else:

- `crates/oneiron/src/context_board/frame.rs` — the whole implementation
- `crates/oneiron/src/context_board/mod.rs` — re-export line only
- `crates/oneiron/tests/cb_oracle_frame.rs` — migrated wrapper test + new `one_1797` module
- `crates/oneiron/tests/cb_oracle_plugin.rs` — fuzz-arm doc-comment only

`tasks.rs`, `agents.rs`, `task_verb.rs`, `lib.rs`, `tokenizer.rs`, `Cargo.toml` are byte-identical.

## Gates

- `cargo fmt -p oneiron -- --check` clean
- `cargo clippy -p oneiron --all-targets --all-features` clean (workspace lints are deny-heavy:
  `unwrap_used`, `unnecessary_wraps`, `uninlined_format_args`, `redundant_clone` all bite here)
- `cargo test -p oneiron --all-features` — 3150 passed, 0 failed, 24 ignored (the pre-existing
  forward-oracle arms); `cb_oracle_frame` 11/11 live
- `cargo test -p oneiron-server --test mcp_oracle` — 3 ignored, unchanged from the split

## Decisions

**1. `shed_and_render` is one private infallible helper, not two render passes.**
The blueprint pins public `shed()` and `render_board_block()` separately. A naive reading renders
the settled frame twice (once inside `shed`, once after). Instead one private
`fn shed_and_render(&BoardFrame, &BoardBudget) -> (ShedOutcome, String)` returns the outcome *and*
the exact text it was counted over; `render_board_block` reuses that string, so
`rendered_tok == count_context_pack_tokens(final_text)` is true by construction rather than by a
second, potentially divergent, render. It is infallible because every failure mode
(`RowExceedsByteLimit`, policy incoherence) is already rejected at `BoardSection::new` — the
public seams keep their `Result` signatures per the blueprint, but the ladder itself cannot fail.
Note `unnecessary_wraps` is `deny` in this workspace, so a phantom-fallible private helper would
not have compiled anyway.

**2. `NonReducingCountFallback` skips the empty-detail case.** A section with zero detail rows and
a `count: 0` fallback would otherwise be rejected: the count row tokenizes larger than an empty
detail view. That is a legitimate honest floor (an empty TASKS section), not an inconsistent
policy. The check now reads: *a populated detail view must not be grown by collapsing it*. This
surfaced live — the first fuzz-fixture run failed with `NonReducingCountFallback { section:
"TASKS" }` for a single-detail-row fixture, which is the validator working correctly; the fixture
was widened to 4 detail rows against a `count: 4` fallback.

**3. `xml_attr_token` / `xml_text_token` share one `XmlLeaf`-parameterized pass.** The blueprint
asks for two helpers differing only in whether quotes are escaped. Two near-identical escape loops
is the duplication the simplify pass would delete, so both are thin wrappers over
`xml_leaf_token(value, XmlLeaf::{Attribute,Text})`. The "escape `&` first" requirement is
satisfied structurally rather than by ordering: the single pass emits entities into a *separate*
output buffer and never rescans them, so double-escaping is impossible by construction.

**4. Hostile-input assertion strengthened away from string-matching dead wrappers.** My first cut
asserted `matches("[CONTEXT_BOARD").count() == 0` on hostile renders. That failed — correctly:
`[CONTEXT_BOARD` is no longer *structure*, it is just text, and a hostile leaf containing it is
harmless the moment the wrapper is XML. Asserting its absence would have made the test assert the
wrong contract (that data cannot contain a string) rather than the real one. Replaced with the
much stronger bracket-counting invariant: the entire render contains exactly **2 `<` and 2 `>`** —
the four the renderer itself wrote. Every hostile angle bracket left the escaper as an entity, so
no interpolation path can satisfy this accidentally. That is the fuzzed structure-invariance
keystone in its sharpest form.

**5. `proptest` regression persistence disabled for this integration test.**
`FileFailurePersistence::SourceParallel` cannot find a crate root from `tests/`, and the fixture is
fully deterministic from the generated leaf (the failing input prints in the panic). Persisting
would also have written `cb_oracle_frame.proptest-regressions`, a file outside the ticket's claim
table.

**6. Pinned whole-sections carry no count rows in fixtures.** `BoardSection::new` rejects
`pinned: true` with a shed rank, and a pinned section never collapses, so its count view is dead
weight. The migrated `cb_t::arm_render_board_block` fixture models WORLDS/MEMORIES/TASKS as pinned
sections with pinned rows only — the smallest fixture that still renders the same three sections
the pre-split test rendered.

## Contract points worth re-checking at screen time

- Attribute order `surface, epoch, scope, budget_tok` is asserted as exact first-line equality in
  both the unit test and the oracle test.
- `budget_tok` in the wrapper is the effective `cap_tok`, never `rendered_tok` — asserted in
  `explicit_override_is_honoured_and_recorded_in_metadata` (override 60000 appears in the wrapper
  while the render is ~200 tokens).
- `floor_exceeds_cap` is set only after all five ranks are applied; at cap 1 the board still emits
  legend + every pinned row + every section name + every count fallback.
- `progressive_budget_squeeze_uses_canonical_shed_order` sweeps every integer cap from
  `floor_tok - 4` to `full_tok + 4` and asserts `applied` is a `SHED_ORDER` prefix at each.

## Next-step intent

Nothing outstanding for PR-2 implementation. The natural next legs, in order:

1. **Simplify pass** (build-side, deletion-biased) over `frame.rs` — it is a fresh ~470-line
   module; the candidates I would look at first are whether `ShedSection::of` and `collapse_rank`
   want to fold together, and whether the accessor block earns its keep at PR-2's single consumer
   count (it does not yet, but ONE-1701/1706 are the declared consumers, so deleting would be
   premature).
2. **Cross-model screen** (pairing law: this was built on the opus seat, so screen elsewhere).
3. Orchestrator splits PR-1/PR-2 into the stack and publishes via `gh stack sync`.
